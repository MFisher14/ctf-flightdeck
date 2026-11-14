"""R-08: docs/CONTRACTS.md stays current with the code, both ways.

Code to doc: every public function and class of the contract modules appears in code (a backtick
span or a fenced block) inside the section that documents it; every CLI command and sub-command
appears in section 8; every manifest key, enum and runner tag in section 6; every event profile
field in section 1; every `CTF_*` name the core reads through ctf.env in section 3.

Doc to code: every `module.name(` call and `module.Name` class or constant the doc's code writes
resolves to an attribute of that module (or of the object an instance alias names), and every
`name=` keyword such a call passes is a parameter of what it calls; every ledger record the core
writes (with all optional arguments, and again with none) has exactly the fields of its section 10
row (no unlisted field, no missing required field, each optional field left out somewhere), every
row is written by the test, and every writer it names exists.

Plus the ledger count-key rule (a token count is spelled "tok").
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib
import importlib.util
import inspect
import re
import sys
from pathlib import Path

import pytest

from ctf import cli, event, ledger, paths

DOC = paths.repo_root() / "docs" / "CONTRACTS.md"

# module -> the CONTRACTS.md section that documents it
MODULE_SECTIONS = {
    "ctf.event": 1,
    "ctf.paths": 2,
    "ctf.env": 3,
    "ctf.flagfmt": 4,
    "ctf.platform": 5,
    "ctf.platform.base": 5,
    "ctf.platform.policy": 5,
    "ctf.platform.rules": 5,
    "ctf.engines.manifest": 6,
    "ctf.engines.router": 6,
    "ctf.engines.runner": 6,
    "ctf.result": 7,
    "ctf.budget": 10,
    "ctf.ledger": 10,
    "ctf.packs": 12,
    "ctf.scope": 13,
    "ctf.fence": 14,
    "ctf.fence_launch": 14,
    "ctf.fence_report": 14,
    "ctf.fence_selftest": 14,
    "ctf.eventscaffold": 15,
    "ctf.eventrules": 15,
    "ctf.platform.ctfd": 5,
    "ctf.platform.gamemaster": 5,
    "ctf.platform.halloffame": 5,
    "ctf.platform.manual": 5,
    "ctf.platform.legacy": 5,
    "ctf.testing.pytest_plugin": 9,
    "ctf.buildplan": 16,
    "ctf.preevent": 16,
    "ctf.toolbox": 16,
    "ctf.engines.layout": 6,
    "ctf.engines.lint": 6,
    "ctf.engines.generate": 6,
    "ctf.engines.coverage": 6,
    "ctf.engines.usage": 6,
    "ctf.config": 17,
    "ctf.client": 17,
    "ctf.submit": 17,
    "ctf.workspace": 17,
    "ctf.triage": 17,
    "ctf.dynamic": 17,
    "ctf.fastlane": 17,
    "ctf.instances": 17,
    "ctf.intake": 19,
    "ctf.intake.engines": 19,
    "ctf.intake.guard": 19,
    "ctf.intake.report": 19,
    "ctf.eventpolicy": 25,
    "ctf.quota": 10,
    "ctf.slate": 44,
    "ctf.compaction": 30,
    "ctf.codec": 41,
    "ctf.codec.graph": 41,
    "ctf.codec.oracle": 41,
    "ctf.codec.records": 41,
    "ctf.codec.pack": 41,
    "ctf.hygiene": 34,
    "ctf.readmap": 34,
    "ctf.toolchain.images": 37,
    "ctf.toolchain.assets": 37,
    "ctf.toolchain.lanes": 37,
    "ctf.toolchain.versions": 37,
    "ctf.toolchain.wheels": 37,
    "ctf.flagcheck": 40,
    "ctf.failover": 49,
    "ctf.router": 67,
    "ctf.testing.capabilities": 9,
    "ctf.build_sandbox": 69,
}

# short names the doc uses for modules that are not in MODULE_SECTIONS
EXTRA_ALIASES = {"cli": "ctf.cli"}

_HEADING = re.compile(r"^## (\d+)\. ", re.M)
_FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.M | re.S)
_SPAN = re.compile(r"`([^`\n]+)`")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*")


# ----------------------------------------------------------------------------------------- helpers

def sections(text: str) -> dict[int, str]:
    """{section number: its text up to the next numbered heading}."""
    marks = list(_HEADING.finditer(text))
    return {int(m.group(1)): text[m.start(): (marks[i + 1].start() if i + 1 < len(marks) else len(text))]
            for i, m in enumerate(marks)}


def code_pieces(section: str) -> list[str]:
    """Each fenced block and each backtick span, separately (prose does not count)."""
    blocks = _FENCE.findall(section)
    rest = _FENCE.sub("", section)
    return blocks + _SPAN.findall(rest)


def code_text(section: str) -> str:
    """Only what is in code: fenced blocks and backtick spans (prose does not count)."""
    return "\n".join(code_pieces(section))


def idents(section: str) -> set[str]:
    return set(_IDENT.findall(code_text(section)))


def block_idents(section: str) -> set[str]:
    """Identifiers in the section's fenced code blocks only (spans do not count)."""
    return set(_IDENT.findall("\n".join(_FENCE.findall(section))))


def words(section: str) -> set[str]:
    """Code tokens that may carry dashes (command names, tags like legacy-output)."""
    return set(_WORD.findall(code_text(section)))


def public_names(mod) -> list[str]:
    """`__all__` when the module declares it, else every function and class defined in it whose
    name does not start with "_" (nor "pytest_": a pytest hook is pytest's interface, not ours)."""
    if hasattr(mod, "__all__"):
        return list(mod.__all__)
    return sorted(n for n, o in vars(mod).items()
                  if not n.startswith(("_", "pytest_")) and (inspect.isfunction(o) or inspect.isclass(o))
                  and getattr(o, "__module__", None) == mod.__name__)


def missing_names(mod, section: str) -> list[str]:
    have = idents(section)
    return [n for n in public_names(mod) if n not in have]


# ---- doc -> code: every `module.name(` / `module.Name` the doc writes must exist in the code

# a dotted chain not preceded by a word char or a dot, and whether a "(" follows it
_CHAIN = re.compile(r"(?<![\w.])((?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*)(\s*\()?")
_FROM_IMPORT = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+([^\n#]+)", re.M)

# instance variables the code blocks use for an object of a contract class, per section
INSTANCE_ALIASES = {
    5: {"gate": "ctf.platform.policy:SubmitGate", "att": "ctf.platform.halloffame:TimedAttempt"},
    10: {"m": "ctf.budget:LedgerMeter"},
    14: {"f": "ctf.fence:Fence", "rep": "ctf.fence_report:Report"},
}


def module_aliases(modnames) -> dict[str, str]:
    """{short name: module}: the last component of each module name (`ctf.platform.rules` -> rules)."""
    return {m.rsplit(".", 1)[-1]: m for m in modnames}


def section_aliases(section: str) -> dict[str, str]:
    """`from X import a as b, c` lines in the section's code: {b: X.a, c: X.c}."""
    out = {}
    for pkg, names in _FROM_IMPORT.findall(code_text(section)):
        for part in names.split(","):
            bits = part.split()
            if not bits:
                continue
            out[bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]] = f"{pkg}.{bits[0]}"
    return out


def _resolve_root(spec: str):
    """`pkg.mod` (a module, or a module attribute) or `pkg.mod:Class`."""
    if ":" in spec:
        mod, attr = spec.split(":")
        return getattr(importlib.import_module(mod), attr)
    try:
        return importlib.import_module(spec)
    except ModuleNotFoundError:
        mod, attr = spec.rsplit(".", 1)
        return getattr(importlib.import_module(mod), attr)


def _has(obj, name: str) -> bool:
    if hasattr(obj, name):
        return True
    if dataclasses.is_dataclass(obj) and name in {f.name for f in dataclasses.fields(obj)}:
        return True
    if inspect.ismodule(obj):   # a sub-module not imported yet
        try:
            importlib.import_module(f"{obj.__name__}.{name}")
            return True
        except ModuleNotFoundError:
            return False
    return False


def _walk(chain: str, call: bool, aliases: dict[str, str]):
    """None when the chain is not checked; else (exists, the object it names or None)."""
    parts = chain.split(".")
    if parts[0] == "ctf":
        obj, rest = importlib.import_module("ctf"), parts[1:]
    elif parts[0] in aliases and (call or parts[-1][0].isupper()):
        obj, rest = _resolve_root(aliases[parts[0]]), parts[1:]
    else:
        return None
    for p in rest:
        if not _has(obj, p):
            return False, None
        obj = getattr(obj, p, None)
        if obj is None:              # a dataclass field: nothing further to walk
            return True, None
    return True, obj


def _calls(section: str, aliases: dict[str, str]):
    """(chain, exists, object, piece, index just past the chain, called) for every checked chain."""
    for piece in code_pieces(section):
        for m in _CHAIN.finditer(piece):
            w = _walk(m.group(1), bool(m.group(2)), aliases)
            if w is not None:
                yield m.group(1), w[0], w[1], piece, m.end(), bool(m.group(2))


def references(section: str, aliases: dict[str, str]) -> dict[str, bool]:
    """{dotted name: exists} for the names in the section's code that point into a contract module
    (or a known instance). Checked: every `ctf.`-rooted chain, and every alias-rooted chain that is
    called (`x.f(`) or names a class or constant (`x.Name`, `x.NAME`). A lowercase attribute that is
    not called (`rules.flag_sharing`, `event.toml`) is ambiguous with profile fields and file names,
    so it is not checked."""
    out = {}
    for chain, ok, *_ in _calls(section, aliases):
        out[chain] = out.get(chain, True) and ok
    return out


def stale_references(section: str, aliases: dict[str, str]) -> list[str]:
    return sorted(c for c, ok in references(section, aliases).items() if not ok)


_KEYWORD = re.compile(r"^\*{0,2}([A-Za-z_]\w*)\s*=(?!=)")


def call_args(text: str, open_at: int) -> list[str] | None:
    """The top-level argument texts of the call whose "(" is at `open_at` (string and comment aware),
    or None when the parentheses do not close inside `text`."""
    depth, quote, cur, args, i = 0, None, [], [], open_at
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                cur.append(text[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
            cur.append(c)
        elif c in "\"'":
            quote = c
            cur.append(c)
        elif c == "#":
            nl = text.find("\n", i)
            i = len(text) if nl < 0 else nl
            continue
        elif c in "([{":
            depth += 1
            if depth > 1:
                cur.append(c)
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return [a.strip() for a in args if a.strip()]
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return None


def keyword_names(args: list[str]) -> list[str]:
    """`name=` keywords among call arguments (`name=`, `name=None`); not `a == b`, not `**opts`."""
    return [m.group(1) for a in args if not a.startswith("**") and (m := _KEYWORD.match(a))]


def unknown_keywords(obj, kws: list[str]) -> list[str]:
    """Keywords the callable does not accept. A `**kwargs` callable accepts any; an object with no
    readable signature is not checked."""
    try:
        params = inspect.signature(obj).parameters
    except (TypeError, ValueError):
        return []
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return []
    return [k for k in kws if k not in params or params[k].kind is inspect.Parameter.POSITIONAL_ONLY]


def stale_keywords(section: str, aliases: dict[str, str]) -> list[str]:
    """Doc to code, signatures: every `name=` the doc passes in a call to a checked function or class
    must be a parameter of it (`scope.check_host(..., what=...)` fails once `what` is renamed)."""
    out = set()
    for chain, ok, obj, piece, end, called in _calls(section, aliases):
        if not (ok and called and callable(obj)):
            continue
        args = call_args(piece, piece.index("(", end - 1))
        for k in unknown_keywords(obj, keyword_names(args or [])):
            out.add(f"{chain}({k}=)")
    return sorted(out)


def doc_aliases(n: int, section: str) -> dict[str, str]:
    """The names a section's code may use for a contract module or object."""
    al = module_aliases(MODULE_SECTIONS)
    al.update(EXTRA_ALIASES)
    al.update(INSTANCE_ALIASES.get(n, {}))
    al.update(section_aliases(section))
    return al


@pytest.fixture(scope="module")
def doc() -> dict[int, str]:
    return sections(DOC.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------ the helpers work

def test_helpers_count_only_code_in_the_right_section(tmp_path):
    md = ("## 1. One\n\nprose mentions alpha and beta.\n\n`gamma()` is code.\n\n"
          "```python\ndelta(x)\n```\n\n## 2. Two\n\n`alpha` lives here, `legacy-output` too.\n")
    sec = sections(md)
    assert set(sec) == {1, 2}
    assert idents(sec[1]) == {"gamma", "delta", "x"}          # prose words alpha/beta do not count
    assert "alpha" in idents(sec[2]) and "alpha" not in idents(sec[1])
    assert "legacy-output" in words(sec[2]) and "legacy-output" not in idents(sec[2])
    assert block_idents(sec[1]) == {"delta", "x"}             # the `gamma()` span is not a block

    mod_file = tmp_path / "r08_probe_mod.py"
    mod_file.write_text("import os\nclass Gamma: pass\ndef delta(): pass\ndef alpha(): pass\n"
                        "def _hidden(): pass\nCONST = 1\n")
    spec = importlib.util.spec_from_file_location("r08_probe_mod", mod_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert public_names(mod) == ["Gamma", "alpha", "delta"]   # no import, no _private, no constant
    assert missing_names(mod, sec[1]) == ["Gamma", "alpha"]   # `gamma` is not `Gamma`; alpha is prose
    mod.__all__ = ["delta", "CONST"]
    assert public_names(mod) == ["delta", "CONST"]


# ----------------------------------------------------------------------------- the doc is current

def test_reference_checker_finds_stale_names(tmp_path, monkeypatch):
    mod_file = tmp_path / "r08_ref_mod.py"
    mod_file.write_text("class Thing:\n    def go(self): pass\nLIMIT = 3\ndef make(): pass\n")
    spec = importlib.util.spec_from_file_location("r08_ref_mod", mod_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setitem(sys.modules, "r08_ref_mod", mod)
    md = ("## 1. One\n\n```python\nfrom r08_ref_mod import make as mk\nr08_ref_mod.make(); r08_ref_mod.gone(x)\n"
          "r08_ref_mod.Thing.go(); r08_ref_mod.Thing.stop(); r08_ref_mod.LIMIT; r08_ref_mod.MAX\n"
          "mk(); t.go(); t.fly(); r08_ref_mod.field; other.missing()\n```\n\n"
          "prose r08_ref_mod.vanished() does not count; `r08_ref_mod.lost()` does.\n")
    sec = sections(md)[1]
    al = {"r08_ref_mod": "r08_ref_mod", "t": "r08_ref_mod:Thing"}
    al.update(section_aliases(sec))
    assert al["mk"] == "r08_ref_mod.make"
    refs = references(sec, al)
    # a lowercase attribute that is not called is not checked; an unknown root is not checked
    assert "r08_ref_mod.field" not in refs and "other.missing" not in refs
    assert "r08_ref_mod.vanished" not in refs                  # prose does not count
    assert stale_references(sec, al) == ["r08_ref_mod.MAX", "r08_ref_mod.Thing.stop", "r08_ref_mod.gone",
                                         "r08_ref_mod.lost", "t.fly"]
    assert refs["r08_ref_mod.make"] and refs["r08_ref_mod.Thing.go"] and refs["t.go"]


def test_every_doc_reference_exists_in_the_code(doc):
    """Doc to code: a `module.name(` or `module.Name` in a section's code that the module lacks
    (renamed, removed, or never written) fails."""
    total, stale = 0, []
    for n, sec in sorted(doc.items()):
        refs = references(sec, doc_aliases(n, sec))
        total += len(refs)
        stale += [f"section {n}: {c}" for c, ok in sorted(refs.items()) if not ok]
    assert total >= 150, f"only {total} references checked: the checker no longer sees the doc"
    for n, name in ((12, "packs.load_module"), (13, "scope.pin"), (10, "m.check"), (14, "f.claude_settings"),
                    (15, "sc.validate"), (16, "buildplan.require_build"), (9, "pytest_plugin.tool_available"),
                    (5, "gamemaster.is_timed"), (6, "runner.record_run")):
        assert name in references(doc[n], doc_aliases(n, doc[n])), f"section {n}: {name} is not checked"
    assert not stale, "docs/CONTRACTS.md names what the code does not have:\n" + "\n".join(stale)


def test_keyword_checker_finds_renamed_parameters(tmp_path, monkeypatch):
    mod_file = tmp_path / "r08_kw_mod.py"
    mod_file.write_text("def go(host, port=None, *, what=None): pass\n"
                        "def anyk(a, **opts): pass\n"
                        "def pos(a, /, b=1): pass\n"
                        "class Box:\n    def __init__(self, size, *, color='red'): pass\n"
                        "    def put(self, item, *, at=0): pass\n")
    spec = importlib.util.spec_from_file_location("r08_kw_mod", mod_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setitem(sys.modules, "r08_kw_mod", mod)
    assert call_args('f(a, b=", )", c=g(1, 2), d=[1, 2])  # x=(', 1) == ["a", 'b=", )"', "c=g(1, 2)", "d=[1, 2]"]
    assert call_args("f(a, b  # c=(\n, d=1)", 1) == ["a", "b", "d=1"]      # a comment inside is skipped
    assert call_args("f(a, b", 1) is None
    assert keyword_names(["a", "b=", "c = 1", "d == e", "**opts", "x"]) == ["b", "c"]
    md = ("## 1. One\n\n```python\nr08_kw_mod.go(h, 1, what='x')    # fine\n"
          "r08_kw_mod.go(h, label='x', port=2)\nr08_kw_mod.anyk(1, whatever=2)\n"
          "r08_kw_mod.pos(a=1, b=2)\nr08_kw_mod.Box(3, colour='b')\nb.put(1, at=2, where=3)\n"
          "r08_kw_mod.go(h,  # what=1 here is a comment\n    wat=1)\nr08_kw_mod.gone(z=1)\nr08_kw_mod.go(h)  # see r08_kw_mod.go(nope=1)\n```\n\n"
          "prose r08_kw_mod.go(prose=1); `r08_kw_mod.go(span=1)` is code.\n")
    sec = sections(md)[1]
    al = {"r08_kw_mod": "r08_kw_mod", "b": "r08_kw_mod:Box"}
    # a call written in a comment is documentation too, so it is checked like any other
    assert stale_keywords(sec, al) == ["b.put(where=)", "r08_kw_mod.Box(colour=)", "r08_kw_mod.go(label=)",
                                       "r08_kw_mod.go(nope=)", "r08_kw_mod.go(span=)", "r08_kw_mod.go(wat=)",
                                       "r08_kw_mod.pos(a=)"]
    assert stale_references(sec, al) == ["r08_kw_mod.gone"]     # a missing name is the other test's job


def test_every_doc_keyword_is_a_parameter_in_the_code(doc):
    """Doc to code, signatures: a `name=` the doc passes to a contract function that the function
    no longer takes (renamed or removed) fails."""
    stale = []
    for n, sec in sorted(doc.items()):
        stale += [f"section {n}: {k}" for k in stale_keywords(sec, doc_aliases(n, sec))]
    seen = {(n, chain, k) for n, s in doc.items()
            for chain, ok, o, p, e, c in _calls(s, doc_aliases(n, s)) if ok and c and callable(o)
            for k in keyword_names(call_args(p, p.index("(", e - 1)) or [])}
    assert len(seen) >= 90, f"only {len(seen)} doc keywords checked: the checker no longer sees the doc"
    for want in ((13, "scope.check_host", "what"), (10, "m.stop", "by"), (6, "runner.record_run", "challenge_id"),
                 (16, "buildplan.check_build", "log")):
        assert want in seen, f"{want} is not checked"
    assert not stale, "docs/CONTRACTS.md passes keywords the code does not take:\n" + "\n".join(stale)


def test_status_table_lists_every_section(doc):
    head = DOC.read_text(encoding="utf-8").split("\n---\n", 1)[0]
    rows = {int(m.group(1)) for m in re.finditer(r"^\| (\d+) \|", head, re.M)}
    assert rows == set(doc), f"status table rows {sorted(rows)} vs sections {sorted(doc)}"
    assert set(doc) == set(range(1, max(doc) + 1)), "sections are numbered without gaps"


@pytest.mark.parametrize("modname", sorted(MODULE_SECTIONS))
def test_every_public_name_is_documented_in_its_section(doc, modname):
    mod = importlib.import_module(modname)
    sec = MODULE_SECTIONS[modname]
    assert public_names(mod), f"{modname} exports nothing: the mapping is stale"
    missing = missing_names(mod, doc[sec])
    assert not missing, f"docs/CONTRACTS.md section {sec} does not name {modname}: {', '.join(missing)}"


@pytest.mark.parametrize("modname", sorted(MODULE_SECTIONS))
def test_every_public_function_is_in_a_code_block_of_its_section(doc, modname):
    """The code blocks are the signature listing: a function named only in a prose span (`pin()`)
    does not count, so dropping its line from the block fails."""
    mod = importlib.import_module(modname)
    sec = MODULE_SECTIONS[modname]
    have = block_idents(doc[sec])
    fns = [n for n in public_names(mod) if inspect.isfunction(getattr(mod, n, None))]
    missing = [n for n in fns if n not in have]
    assert not missing, (f"docs/CONTRACTS.md section {sec} has no code-block line for {modname}: "
                         f"{', '.join(missing)}")


def _help_choices(capsys, argv) -> list[str]:
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 0
    out = capsys.readouterr().out
    m = re.search(r"\{([a-z0-9,\-]+)\}", out)
    assert m, out
    return m.group(1).split(",")


def test_every_cli_command_is_in_section_8(doc, capsys):
    commands = _help_choices(capsys, ["--help"])
    assert {"submit", "event", "run", "fence"} <= set(commands)   # built-in and discovered both seen
    missing = [c for c in commands if c not in words(doc[8])]
    assert not missing, f"section 8 lacks command(s): {', '.join(missing)}"


def _subcommands(mod) -> list[str]:
    p = argparse.ArgumentParser()
    mod.add_arguments(p)
    out = []
    for a in p._actions:
        if isinstance(a, argparse._SubParsersAction):
            out.extend(a.choices)
    return out


def test_every_cli_subcommand_is_in_section_8(doc):
    have = words(doc[8])
    seen, missing = 0, []
    for name, mod, err in cli.discover():
        assert err is None, f"ctf {name} is broken: {err}"
        for sub in _subcommands(mod):
            seen += 1
            if sub not in have:
                missing.append(f"{name} {sub}")
    assert seen >= 20, "expected the engines/fence/budget/event/build-plan sub-commands"
    assert not missing, f"section 8 lacks sub-command(s): {', '.join(missing)}"


def test_manifest_keys_enums_and_runner_tags_are_in_section_6(doc):
    from ctf.engines import generate, manifest
    have = words(doc[6])
    boot = (paths.repo_root() / "ctf" / "engines" / "_boot.py").read_text(encoding="utf-8")
    runner_tags = set(re.findall(r'\.has\("([a-z0-9_.+-]+)"\)', boot))
    assert {"library", "legacy-output"} <= runner_tags
    want = (set(manifest._TOP_KEYS) | set(manifest._ROUTE_KEYS) | set(manifest.STATUSES)
            | set(manifest.COST_CLASSES) | set(manifest.FILE_MATCH_KINDS) | set(generate.CLASS_TAGS)
            | runner_tags | set(manifest.ENGINE_ROOTS))
    missing = sorted(want - have)
    assert not missing, f"section 6 lacks: {', '.join(missing)}"
    assert f"default {manifest.DEFAULT_PRIORITY}" in doc[6]


def test_every_event_profile_field_is_in_section_1(doc):
    have = idents(doc[1])
    want = set()
    for cls in (event.EventProfile, event.Platform, event.FlagSpec, event.ProofSpec, event.Rules,
                event.Writeups, event.Budget, event.Allowance):
        want |= {f.name for f in dataclasses.fields(cls)}
    missing = sorted(want - have)
    assert not missing, f"section 1 lacks profile field(s): {', '.join(missing)}"


def test_every_ctf_env_name_read_by_the_core_is_in_section_3(doc):
    rx = re.compile(r'env\.(?:get|get_bool|get_int|require)\(\s*"(CTF_[A-Z0-9_]+)"')
    names = set()
    for f in (paths.repo_root() / "ctf").rglob("*.py"):
        names |= set(rx.findall(f.read_text(encoding="utf-8")))
    assert {"CTF_EVENT", "CTF_ENGINE_LEDGER"} <= names
    missing = sorted(names - idents(doc[3]))
    assert not missing, f"section 3 lacks: {', '.join(missing)}"


def test_fence_config_keys_are_in_section_14(doc):
    from ctf import fence
    missing = sorted(set(fence._CONFIG_KEYS) - idents(doc[14]))
    assert not missing, f"section 14 lacks fence.toml key(s): {', '.join(missing)}"


# ------------------------------------------------------------------------------- ledger records

def _fields(rec: dict) -> set[str]:
    return set(rec) - {"ts", "event"}


_LEDGER_ROW = re.compile(r"^\| `([a-z0-9_.]+)` \| ([^|\n]+) \| ([^|\n]+) \|\s*$", re.M)


@dataclasses.dataclass(frozen=True)
class LedgerRow:
    writers: tuple[str, ...]
    required: frozenset[str]
    optional: frozenset[str]


def ledger_rows(section: str) -> dict[str, LedgerRow]:
    """The section 10 record table: {event: LedgerRow}. In the fields column a `name`? is optional,
    and anything in parentheses is a note (values, cross-references), not a field."""
    out = {}
    for ev, writers, fields in _LEDGER_ROW.findall(section):
        names = re.findall(r"`(\w+)`(\??)", re.sub(r"\([^)]*\)", "", fields))
        assert ev not in out, f"ledger event {ev} has two rows"
        out[ev] = LedgerRow(tuple(re.findall(r"`([\w.]+)`", writers)),
                            frozenset(n for n, q in names if not q), frozenset(n for n, q in names if q))
    return out


def row_problems(rec: dict, row: LedgerRow) -> list[str]:
    """How a written record and its documented row disagree, both ways."""
    got = _fields(rec)
    out = [f"field {f!r} is written but not in the row" for f in sorted(got - row.required - row.optional)]
    out += [f"required field {f!r} is in the row but not written" for f in sorted(row.required - got)]
    return out


def _resolve_writer(name: str):
    """A writer column entry: `ctf.x.y` from the root, else a name in ctf.budget (`LedgerMeter.stop`)."""
    from ctf import budget
    obj = importlib.import_module("ctf") if name.startswith("ctf.") else budget
    for p in (name.split(".")[1:] if name.startswith("ctf.") else name.split(".")):
        assert _has(obj, p), f"section 10 names writer {name!r}, which does not exist"
        obj = getattr(obj, p)
    return obj


def _write_every_core_record(tmp_path) -> list[dict]:
    """Drive every core ledger writer (both flag_sharing modes, all three stop writers) into a temp
    workdir and return what the ledger holds. Each writer with optional arguments runs twice: once
    with all of them and once with none, so a field the doc marks required must be in both."""
    from ctf import budget, buildplan
    from ctf.engines import runner
    from ctf.platform import base, policy, rules

    runner.record_run("common.x", exit_code=0, seconds=1.0, via="ctf-run", status="none",
                      challenge_id="7", workdir=tmp_path)
    prof = event.load("csctf")
    caps = []
    m = budget.LedgerMeter(prof, workdir=tmp_path, on_cap=lambda st, path: caps.append(path))
    m.add_spend("7", 1.0, 10, source="test")
    m.register("7", points=100, solves=3, opened_at=1_700_000_000, tail=True, name="x")
    m.extend("7", 5.0, by="max", reason="close")
    m.stop("7", "manual", by="max", note="pause")
    m.resume("7", by="max")
    m.mark_progress("7", note="n")
    # the same writers with only their required arguments
    runner.record_run("common.y", exit_code=1, seconds=0.5, via="ctfpy", workdir=tmp_path)
    m.add_spend("m1", 0.5, 3)
    m.register("m1")
    m.stop("m1", "manual")
    m.mark_progress("m1")
    assert budget.on_team_solve("m2", workdir=tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("8", 1_000_000.0, 1)                     # far past any cap: budget_checkpoint
    with pytest.raises(budget.BudgetExceeded):
        m.check("8")                                         # same cap: no second checkpoint
    assert len(caps) == 1 and caps[0].is_file()
    assert budget.on_team_solve("9", solver="teammate", workdir=tmp_path)
    for share in ("allowed", "forbidden"):
        p = dataclasses.replace(prof, rules=dataclasses.replace(prof.rules, flag_sharing=share))
        rules.EventRules(p, tmp_path).record(
            p, policy.SubmitRequest("7", "CSCTF{x}", "test"), base.SubmitResult(base.SubmitStatus.INCORRECT))
    # the submit queue (B-006): a send that raises writes an "error" platform.submit and a submit.done
    from ctf.platform import queue

    class _Raises:
        kind = "ctfd"

        def submit(self, challenge_id, flag):
            raise base.PlatformError("submit: POST failed (Timeout)")
    g = policy.SubmitGate(_Raises(), prof)
    rules.install(g, tmp_path)
    queue.install(g, tmp_path)
    with pytest.raises(base.PlatformError):
        g.submit("7", "CSCTF{y}", provenance="test")
    rules.EventRules(prof, tmp_path).grant("7", "player: one more", 1)
    # B-173: a sweep authorization, a sweep send's record, and pointed services with and without a port
    from ctf import eventpolicy
    rules.EventRules(prof, tmp_path).authorize_sweep("7", 2, "player: sweep")
    rules.EventRules(prof, tmp_path).record(
        prof, policy.SubmitRequest("7", "CSCTF{s}", "test", guess=True, sweep="abc"),
        base.SubmitResult(base.SubmitStatus.INCORRECT))
    pp = dataclasses.replace(prof, rules=dataclasses.replace(prof.rules, pointed_services="allowed"))
    eventpolicy.point(pp, "7", "chal.svc.example:1337", "player gave it", workdir=tmp_path)
    eventpolicy.point(pp, "7", "chal.svc.example", "player gave it", workdir=tmp_path)
    eventpolicy.unpoint(pp, "chal.svc.example:1337", "done", workdir=tmp_path)
    eventpolicy.unpoint(pp, "chal.svc.example", "done", workdir=tmp_path)
    # B-044: a timed start, a batch naming its attempt (partly banked, a ranked retry), its result
    from ctf.platform import halloffame
    hp = event.load("huntress")
    halloffame.record_start(hp, "w-day-01/time_trial", {"attempt_id": "a1"},
                            halloffame.StartOrigin("fresh", "a1", 0.1, 0.1, "test"), workdir=tmp_path)
    breq = policy.SubmitRequest("w-day-01/time_trial", policy.batch_flag({"q": "v"}), "test",
                                answers=(("q", "v"),), attempt=policy.AttemptRef("a1", deadline=1.0,
                                                                                 ranked_retry=True))
    bres = base.SubmitResult(base.SubmitStatus.CORRECT, reply={"result": "accepted", "remaining": 1})
    rules.EventRules(hp, tmp_path).record(hp, breq, bres)
    halloffame.record_result(hp, breq, bres, halloffame.eligibility(breq.challenge_id, bres.reply),
                             workdir=tmp_path)
    items = [buildplan.parse_item({"id": "B-1", "lane": "ops", "effort": "S", "closes": ["r"]})]
    buildplan.record(buildplan.rank(items, prof, effort_budget=1), workdir=tmp_path)
    buildplan.check_build("B-1", prof, workdir=tmp_path)
    from ctf import intake
    from ctf.result import SolverResult
    intake.record(intake.Report("7", None, SolverResult("none"), stages={"download": 0.1}), workdir=tmp_path)
    # the intake auto-submit (B-012): one judged send, and one whose gate raised (status error)
    from ctf.intake import autosubmit

    class _Answers:
        kind = "ctfd"

        def submit(self, challenge_id, flag):
            return base.SubmitResult(base.SubmitStatus.INCORRECT)
    autosubmit.auto_submit("8", "solved", ["CSCTF{auto}"], policy.SubmitGate(_Answers(), prof), profile=prof,
                           provenance="test", workdir=tmp_path)
    autosubmit.auto_submit("9", "solved", ["CSCTF{auto}"], policy.SubmitGate(_Raises(), prof), profile=prof,
                           provenance="test", workdir=tmp_path)
    # B-171: a quota reading with every optional field, and one with none
    from ctf import quota
    quota.record(tmp_path, "claude", "weekly", used_pct=40.0, resets_at=1_700_000_000.0, by="max", note="screen")
    quota.record(tmp_path, "codex", "session", exhausted=True, by="max")
    # B-202: spend governors, each optional field written once and left out once
    from ctf import spendgov
    spendgov.set_cap("build", 5.0, by="max", reason="r", workdir=tmp_path)
    spendgov.decide_mode("speedrun", 5.0, by="max", reason="r", minutes=60, workdir=tmp_path)
    spendgov.decide_mode("polish", 5.0, by="max", reason="r", challenges=["hof/*"], value="v", workdir=tmp_path)
    (tmp_path / "rv").mkdir()
    (tmp_path / "rv" / "a.py").write_text("a")
    spendgov.record_round("s", tmp_path / "rv", ["a.py"], {"low": 1}, by="max", workdir=tmp_path)
    spendgov.record_round("s", tmp_path / "rv", ["a.py"], {}, workdir=tmp_path)
    for i, note in (("i1", "n"), ("i2", None)):
        spendgov.open_investigation(i, "q", metric="m", threshold=1, minutes=1, usd=1, by="max", workdir=tmp_path)
        spendgov.close_investigation(i, 2, by="max", note=note, workdir=tmp_path)
    # B-036: the adaptation loop's lane gate, chain step, close mark and attempt (with and without options)
    from ctf.adapt import chain as adapt_chain
    from ctf.adapt import regress as adapt_regress
    adapt_regress.record_gate(adapt_regress.LaneGate("warmups", adapt_regress.YES, "", "k" * 64, (), 0.5, 60.0, 1.0),
                              workdir=tmp_path)
    adapt_chain.plan("w-day-02", "warmups", workdir=tmp_path)            # base not closed: a "wait" step
    adapt_chain.mark_closed("w-day-02", by="teammate", workdir=tmp_path)
    adapt_chain.record_attempt("w-day-02/time_trial", "incorrect", lane_key="k" * 64, note="n", workdir=tmp_path)
    adapt_chain.record_attempt("w-day-02/time_trial", "not_submitted", workdir=tmp_path)
    # B-174: a look-ahead gate verdict, and a forecast score with and without the day's gate report
    from ctf.lookahead import forecast as la_forecast
    from ctf.lookahead import gate as la_gate
    la_gate.record(la_gate.LaneReport("binary", (), (), (), 0.5), workdir=tmp_path)
    fc = la_forecast.Forecast("d2", {"binary": la_forecast.LaneForecast(("b*",), ("b",))})
    prev, day = [{"id": "a"}], [{"id": "a"}, {"id": "b"}]
    la_forecast.score(fc, "binary", prev, day, workdir=tmp_path)
    la_forecast.score(fc, "binary", prev, day, report={"lane": "binary", "gaps": []}, workdir=tmp_path)
    return list(ledger.read(tmp_path))


def test_ledger_row_parser_and_checker_work():
    md = ("| event | writer | fields |\n|---|---|---|\n"
          "| `a.run` | `ctf.x.y` | `one`, `two`? (note `three`) |\n"
          "| `b` | `W.f`, `g` | `k` (values `v1` / `v2`), `x`? or `y`? |\n")
    rows = ledger_rows(md)
    assert rows == {"a.run": LedgerRow(("ctf.x.y",), frozenset({"one"}), frozenset({"two"})),
                    "b": LedgerRow(("W.f", "g"), frozenset({"k"}), frozenset({"x", "y"}))}
    ok = {"ts": 1, "event": "a.run", "one": 1}
    assert row_problems(ok, rows["a.run"]) == []
    assert row_problems({**ok, "two": 2}, rows["a.run"]) == []
    assert row_problems({**ok, "three": 3}, rows["a.run"]) == ["field 'three' is written but not in the row"]
    assert row_problems({"ts": 1, "event": "a.run", "two": 2}, rows["a.run"]) == [
        "required field 'one' is in the row but not written"]


def test_ledger_records_match_their_rows_both_ways(doc, tmp_path):
    rows = ledger_rows(doc[10])
    recs = _write_every_core_record(tmp_path)
    written = {r["event"] for r in recs}
    assert {"engine.run", "spend", "budget_challenge", "budget_extend", "budget_checkpoint", "stop",
            "budget_resume", "progress", "platform.submit", "build_plan.rank", "build_plan.check"} <= written
    assert not written - set(rows), f"section 10 has no row for {sorted(written - set(rows))}"
    assert not set(rows) - written, (f"section 10 lists {sorted(set(rows) - written)}, which this test "
                                     "does not write: write it here, or drop a row the code no longer writes")
    problems = []
    for rec in recs:
        problems += [f"{rec['event']}: {p}" for p in row_problems(rec, rows[rec["event"]])]
    assert not problems, "section 10 and the written records disagree:\n" + "\n".join(problems)
    subs = [r for r in recs if r["event"] == "platform.submit"]
    assert [len({"flag", "flag_sha256"} & set(r)) for r in subs] == [1] * len(subs)
    assert {"flag", "flag_sha256"} <= set().union(*subs)
    stops = [r for r in recs if r["event"] == "stop"]
    assert {r["reason"] for r in stops} == {"manual", "team_solve"}
    # every field a row marks optional is left out by some written record of that event: the test
    # writes the minimal records, and an always-written field is not documented as optional
    for ev, row in rows.items():
        for f in sorted(row.optional):
            assert any(f not in r for r in recs if r["event"] == ev), (
                f"section 10 marks {ev}.{f} optional, but every written {ev} record has it")
    for ev, row in rows.items():
        assert row.writers, f"section 10 row {ev} names no writer"
        for w in row.writers:
            _resolve_writer(w)


# ------------------------------------------------------------------------------- count-key rule

@pytest.mark.parametrize("key", ["tokens", "input_tokens", "Token_count"])
def test_ledger_refuses_token_count_keys_and_names_tok(tmp_path, key):
    with pytest.raises(ValueError) as e:
        ledger.append("spend", workdir=tmp_path, **{key: 5})
    assert key in str(e.value) and "'tok'" in str(e.value)
    assert not ledger.path(tmp_path).exists()


def test_ledger_secret_refusal_without_token_has_no_count_hint(tmp_path):
    with pytest.raises(ValueError) as e:
        ledger.append("x", workdir=tmp_path, cookie_jar="a")
    assert "cookie_jar" in str(e.value) and "tok" not in str(e.value)


@pytest.mark.parametrize("key", ["tok", "in_tok", "out_tok", "cache_tok"])
def test_ledger_accepts_tok_count_keys(tmp_path, key):
    rec = ledger.append("spend", workdir=tmp_path, **{key: 5})
    assert rec[key] == 5
    assert [r[key] for r in ledger.read(tmp_path)] == [5]


def test_spend_records_use_tok_and_the_doc_says_so(doc, tmp_path):
    from ctf import budget
    budget.LedgerMeter(event.load("csctf"), workdir=tmp_path).add_spend("7", 2.0, 1234)
    (rec,) = list(ledger.read(tmp_path))
    assert rec["tok"] == 1234 and not any("token" in k for k in rec)
    assert "`tok`" in doc[10] and "spelled `tok`" in doc[10]
