"""The generated repo primer and file index (B-199): one read at a session's start instead of many.

Every fresh agent re-read the same repo files to orient itself (which command does X, where is Y, what
is that 7,000-line file). These two files answer that once, generated from the tree:

    docs/PRIMER.md       the brief: where to start, how to read this repo cheaply, the layout, the ctf
                         packages, and the large files (read them by symbol, never in slices)
    docs/FILE-INDEX.md   every `python -m ctf` command with its HELP line, every ctf and tools module with
                         the first sentence of its docstring, and the solver lanes; grep it

Both are regenerated with the engine-derived files (`python -m ctf engines generate`, which the
merge queue runs after every merge; ctf/engines/derived.py), `--check` fails when either is stale,
and tests/test_primer.py fails when the committed files differ from a fresh render. Deterministic: no
dates, no counts that move with every edit (a large file's size is rounded to the thousand lines).
Nothing is imported or run: summaries come from `ast` (ctf.engines.capabilities.summary). The tree is
the gate's file list (ctf.gate.impact.list_files: tracked plus untracked-not-ignored), so a gitignored
scratch module in a checkout never changes the output (a tree with no `.git` has no ignore rules: every
file counts; see repo_files).

The per-event agent rules (templates/event/agent-rules.md.tmpl, B-189) point agents here; the
rules text itself is `rules_md()` below, so it lives in one place.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

from . import paths

__all__ = ["PRIMER_REL", "INDEX_REL", "LARGE_LINES", "LAYOUT", "START_HERE", "render_primer",
           "render_index", "repo_files", "write", "is_stale", "stale_files", "write_primer", "write_index", "primer_stale",
           "index_stale", "commands", "modules", "large_files",
           "rules_md"]

PRIMER_REL = "docs/PRIMER.md"
INDEX_REL = "docs/FILE-INDEX.md"
LARGE_LINES = 2000          # a module this long is read by symbol, never in slices (all in the index)
HUGE_LINES = 4000           # ... and one this long is also named in the brief
_SKIP_DIRS = {"__pycache__", "node_modules"}

# Top-level folders, in reading order. Only the ones present in the tree are listed.
LAYOUT = (
    ("ctf", "the platform client, CLI (`python -m ctf`), orchestration, policy, gate and every shared service"),
    ("solvers", "the solving engines, one folder per lane; each engine has a `*.manifest.toml` beside it"),
    ("tools", "operator tools and launchers (`tools/ctfpy` runs engine code with the right interpreter)"),
    ("tests", "the suite (`.venv/bin/python -m pytest`); `tests/gate.toml` maps files to tests"),
    ("docs", "contracts, build logs, capabilities, coverage, runbooks and playbooks"),
    ("events", "one folder per event: `event.toml` and the generated CLAUDE.md / AGENTS.md"),
    ("templates", "templates rendered by commands (event agent rules, write-ups, hand-offs)"),
    ("workflows", "shipped Workflow-tool scripts (B-194)"),
    ("openers", "armed Layer-1 opener and reader tables (B-014, B-139)"),
    ("speedrun", "the speed-run harness and its solvers"),
    ("corpus", "the rehearsal corpus index"),
    ("docker", "the sandbox images: untrusted artifacts run only in these"),
)

# A lane whose package has no docstring of its own.
LANE_NOTES = {
    "binary": "reverse engineering and binary analysis engines",
    "common": "shared engine libraries (codecs, crypto, evidence, proposers) imported by the other lanes",
    "metadata-forensics": "file-format readers and metadata / forensics engines",
    "mobile-android": "APK / DEX / Android engines",
    "script-analysis": "script, deobfuscation and codec-plan engines",
    "toolkits": "per-topic toolkits (network, windows, web, crypto, cloud, stego, ...)",
    "warmups": "warm-up and classical decoding engines",
    "web": "web exploitation engines (live targets)",
}

# Files to read first, in order (listed only when present).
START_HERE = (
    ("CLAUDE.md", "the rules for working on the master itself"),
    ("BUILD-PLAN.md", "the build plan and order (B-ids)"),
    ("docs/CONTRACTS.md", "the interfaces every builder codes against (the code wins where they differ)"),
    ("docs/BUILDING.md", "how to add an engine: manifest, router, runner"),
    ("docs/CAPABILITIES.md", "every engine, what it does and when triage suggests it (generated)"),
    ("docs/OPERATIONS.md", "running an event"),
    (INDEX_REL, "every command and module in one line each (generated; grep it)"),
)


def _root(root: Path | None) -> Path:
    return paths.repo_root() if root is None else Path(root)


def _summary(path: Path) -> str:
    from .engines.capabilities import summary
    return summary(path).replace("|", "\\|")


def repo_files(root: Path | None = None) -> frozenset[str]:
    """The tree's files, repo-relative. In a git checkout (`root/.git` exists: a folder, or a file in a
    linked worktree) it is the gate's list (tracked plus untracked-not-ignored, present on disk), so a
    gitignored file never changes the output; git failing there raises GateError. A tree with no `.git`
    (an exported copy, a synthetic test tree) has no ignore rules to apply: every file is listed (dot-
    and _SKIP_DIRS folders left out, as everywhere here)."""
    r = _root(root)
    if (r / ".git").exists():
        from .gate import impact
        return frozenset(impact.list_files(r))
    out = []
    for dirpath, dirnames, filenames in os.walk(r):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIRS]
        base = Path(dirpath)
        out += [(base / f).relative_to(r).as_posix() for f in filenames]
    return frozenset(out)


def _files(root: Path, files: frozenset[str] | None) -> frozenset[str]:
    return repo_files(root) if files is None else files


def _py_files(root: Path, top: str, files: frozenset[str]) -> list[Path]:
    """The listed .py files under `top`, skipping dot-folders, dot-files and _SKIP_DIRS."""
    out = []
    for rel in files:
        parts = rel.split("/")
        if parts[0] != top or len(parts) < 2 or not rel.endswith(".py"):
            continue
        if any(x.startswith(".") or x in _SKIP_DIRS for x in parts[1:-1]) or parts[-1].startswith("."):
            continue
        out.append(root / rel)
    return sorted(out)


def _has_dir(files: frozenset[str], d: str) -> bool:
    pre = d.rstrip("/") + "/"
    return any(f.startswith(pre) for f in files)


def _line_count(path: Path) -> int:
    with open(path, "rb") as f:
        data = f.read()
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _help(path: Path) -> str | None:
    """The module's HELP string constant, or None when it has none (or it is not a literal)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HELP" for t in node.targets):
            try:
                v = ast.literal_eval(node.value)
            except ValueError:
                return None
            return " ".join(v.split()) if isinstance(v, str) else None
    return None


def commands(root: Path | None = None, *, files: frozenset[str] | None = None
             ) -> tuple[list[str], list[tuple[str, str]]]:
    """(built-ins, [(command, HELP)]): the `cmd_*` functions of ctf/cli/__init__.py, and every command
    module ctf/cli/<name>.py (underscores become dashes; `_`-prefixed modules are not commands)."""
    r = _root(root)
    fs = _files(r, files)
    cli = r / "ctf" / "cli"
    builtins: list[str] = []
    init = cli / "__init__.py"
    if "ctf/cli/__init__.py" in fs:
        try:
            tree = ast.parse(init.read_text(encoding="utf-8", errors="replace"))
            builtins = sorted(n.name[4:].replace("_", "-") for n in tree.body
                              if isinstance(n, ast.FunctionDef) and n.name.startswith("cmd_"))
        except SyntaxError:
            builtins = []
    mods = []
    for rel in sorted(fs):
        parts = rel.split("/")
        if len(parts) == 3 and parts[:2] == ["ctf", "cli"] and rel.endswith(".py"):
            p = r / rel
            if p.name.startswith(("_", ".")):
                continue
            h = _help(p)
            mods.append((p.stem.replace("_", "-"), h if h is not None else "(no literal HELP string)"))
    return builtins, mods


def modules(root: Path | None = None, top: str = "ctf", *, files: frozenset[str] | None = None
            ) -> list[tuple[str, str]]:
    """[(repo-relative path, docstring first sentence)] for every .py file under `top`, the CLI
    command modules left out (they are listed as commands)."""
    r = _root(root)
    out = []
    for p in _py_files(r, top, _files(r, files)):
        rel = p.relative_to(r).as_posix()
        if rel.startswith("ctf/cli/") and rel != "ctf/cli/__init__.py":
            continue
        out.append((rel, _summary(p)))
    return out


def large_files(root: Path | None = None, *, min_lines: int = LARGE_LINES,
                files: frozenset[str] | None = None) -> list[tuple[str, str]]:
    """[(path, "~Nk")] for every ctf / solvers / tools module of `min_lines` lines or more, biggest
    first (ties by path). The size is rounded to the thousand so an edit rarely moves it."""
    r = _root(root)
    fs = _files(r, files)
    got = []
    for top in ("ctf", "solvers", "tools"):
        for p in _py_files(r, top, fs):
            n = _line_count(p)
            if n >= min_lines:
                got.append((p.relative_to(r).as_posix(), max(2, round(n / 1000))))
    got.sort(key=lambda x: (-x[1], x[0]))
    return [(rel, f"~{k}k") for rel, k in got]


def _lanes(root: Path, files: frozenset[str]) -> list[tuple[str, str]]:
    """Every solvers/<lane>/ folder holding a listed file (an ignored-only folder is not a lane)."""
    names = sorted({f.split("/")[1] for f in files if f.startswith("solvers/") and f.count("/") >= 2})
    out = []
    for name in names:
        if name.startswith((".", "_")):
            continue
        init_rel = f"solvers/{name}/__init__.py"
        what = _summary(root / init_rel) if init_rel in files else ""
        out.append((f"solvers/{name}/", what or LANE_NOTES.get(name, "-")))
    return out


_HEADER = ("<!-- GENERATED FILE, do not edit. Rendered by ctf/primer.py; regenerate with "
           "`python -m ctf engines generate` (B-199). -->")


def rules_md() -> str:
    """The reading rules the per-event agent rules carry (one source; the event template inserts it)."""
    return "\n".join([
        "## Reading the repo and files",
        "",
        "Every tool result is re-read on every later turn, so read once and narrowly.",
        "",
        f"- **Orient from the primer.** At the start of a session run `python -m ctf primer` (it prints",
        f"  `{PRIMER_REL}`, generated: where to start, the layout, the large files) instead of opening",
        "  files to find your way.",
        f"  `{INDEX_REL}` lists every command and module in one line each: query it with",
        f"  `python -m ctf read {INDEX_REL} --grep <word>`, do not read it whole.",
        "- **Read by query, not by window.** `python -m ctf read PATH --grep PATTERN`, `--lines A-B` (under",
        "  150 lines) or `--symbol NAME` (exactly one function or class). It caps the output and tells you",
        "  when another agent already read the same thing. No `cat`, `sed -n` windows or whole-file reads.",
        "- **Large modules by symbol.** `python -m ctf symbols PATH` lists a module's functions and classes",
        "  with line ranges, its imports and its importers; `python -m ctf symbols --find NAME` finds where a",
        "  name is defined. Then `python -m ctf read PATH --symbol NAME`. Never page through a large file.",
        "- **Binaries: `ctf read` first.** `python -m ctf read FILE` on a binary prints its type, size,",
        "  hash, entropy, a hex head and its strings with offsets; `--strings` lists every string and",
        "  `--bytes N` is a longer hex view. Do not open a binary with a text reader, `cat` or `xxd`.",
        "- **Research once per event.** Before a web or standards look-up run",
        "  `python -m ctf research get \"<query or URL>\" --claim`. Exit 0 prints the answer another agent",
        "  stored. Exit 1 means it was a miss and you now hold the claim: look it up, then store what you",
        "  found with `python -m ctf research put \"<query or URL>\" --answer \"<summary>\" --source <url>`",
        "  (or `python -m ctf research release \"<query or URL>\"` if you give up). Exit 3 means another",
        "  agent is looking it up now: do other work and ask again; do not fetch it in parallel. Store a",
        "  summary with its sources, never a secret.",
    ])


def render_primer(root: Path | None = None) -> str:
    r = _root(root)
    fs = repo_files(r)
    out = [_HEADER, "", "# Repo primer", "",
           "Read this once at the start of a session instead of opening files to orient. It is generated",
           f"from the tree; `{INDEX_REL}` has one line for every command and module.", "",
           "## Start here", ""]
    # the index is generated with this file, so it is listed whether or not it is on disk yet (otherwise
    # the primer would render differently before and after the index is first written)
    out += [f"- `{rel}`: {what}" for rel, what in START_HERE if rel == INDEX_REL or rel in fs]
    out += ["", rules_md().replace("## Reading the repo and files", "## Reading this repo cheaply"), "",
            "## Layout", "", "| folder | what |", "|---|---|"]
    out += [f"| `{d}/` | {what} |" for d, what in LAYOUT if _has_dir(fs, d)]
    pk = sorted((r / f).parent for f in fs
                if f.startswith("ctf/") and f.count("/") == 2 and f.endswith("/__init__.py"))
    out += ["", "## ctf packages", "", "| package | what |", "|---|---|"]
    out += [f"| `{p.relative_to(r).as_posix()}/` | {_summary(p / '__init__.py')} |" for p in pk]
    lanes = _lanes(r, fs)
    if lanes:
        out += ["", "## Solver lanes", "", "Engines, their routes and needs: `docs/CAPABILITIES.md`.", "",
                "| lane | what |", "|---|---|"]
        out += [f"| `{rel}` | {what} |" for rel, what in lanes]
    out += ["", "## Large files", "",
            f"Read a module of {LARGE_LINES}+ lines by symbol, never in slices: `python -m ctf symbols PATH`, then",
            f"`python -m ctf read PATH --symbol NAME`. `{INDEX_REL}` lists every one; the largest:", ""]
    out += _size_groups(large_files(r, min_lines=HUGE_LINES, files=fs)) or ["None."]
    return "\n".join(out) + "\n"


def _size_groups(big: list[tuple[str, str]]) -> list[str]:
    """One line per size: `- ~7k lines: `a`, `b``, biggest first."""
    groups: dict[str, list[str]] = {}
    for rel, k in big:
        groups.setdefault(k, []).append(f"`{rel}`")
    return [f"- {k} lines: {', '.join(v)}" for k, v in groups.items()]


def render_index(root: Path | None = None) -> str:
    r = _root(root)
    fs = repo_files(r)
    builtins, cmds = commands(r, files=fs)
    out = [_HEADER, "", "# File index", "",
           "One line per command and module, from the tree. Query it (`python -m ctf read "
           f"{INDEX_REL} --grep WORD`);", f"do not read it whole. The brief is `{PRIMER_REL}`.", "",
           "## Commands (`python -m ctf <command>`)", ""]
    if builtins:
        out.append("Built in (`ctf/cli/__init__.py`): " + ", ".join(f"`{b}`" for b in builtins) + ".")
        out.append("")
    out += [f"- `{name}`: {h.replace('|', chr(92) + '|')}" for name, h in cmds]
    for top, title in (("ctf", "ctf modules"), ("tools", "tools modules")):
        mods = modules(r, top, files=fs)
        if mods:
            out += ["", f"## {title}", ""]
            out += [f"- `{rel}`: {s}" if s else f"- `{rel}`" for rel, s in mods]
    lanes = _lanes(r, fs)
    if lanes:
        out += ["", "## Solver lanes", "", "Each engine is listed with its routes in `docs/CAPABILITIES.md`.", ""]
        out += [f"- `{rel}`: {what}" for rel, what in lanes]
    out += ["", f"## Large files (>= {LARGE_LINES} lines)", "",
            "Read these by symbol (`python -m ctf symbols PATH`, `python -m ctf read PATH --symbol NAME`).", ""]
    out += _size_groups(large_files(r, files=fs)) or ["None."]
    return "\n".join(out) + "\n"


_RENDER = {PRIMER_REL: render_primer, INDEX_REL: render_index}


def _write_one(rel: str, root: Path | None) -> Path:
    r = _root(root)
    p = r / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_RENDER[rel](r), encoding="utf-8")
    return p


def _stale_one(rel: str, root: Path | None) -> bool:
    r = _root(root)
    p = r / rel
    return not p.is_file() or p.read_text(encoding="utf-8") != _RENDER[rel](r)


def write_primer(root: Path | None = None) -> Path:
    return _write_one(PRIMER_REL, root)


def write_index(root: Path | None = None) -> Path:
    return _write_one(INDEX_REL, root)


def primer_stale(root: Path | None = None) -> bool:
    return _stale_one(PRIMER_REL, root)


def index_stale(root: Path | None = None) -> bool:
    return _stale_one(INDEX_REL, root)


def write(root: Path | None = None) -> list[Path]:
    """Write both files."""
    return [_write_one(rel, root) for rel in _RENDER]


def stale_files(root: Path | None = None) -> list[str]:
    """The primer files that are missing or differ from a fresh render."""
    return [rel for rel in _RENDER if _stale_one(rel, root)]


def is_stale(root: Path | None = None) -> bool:
    return bool(stale_files(root))
