"""Capability preservation (B-196): known solve paths keep a live test, and it runs before a merge.

At CSCTF over-correcting fix lanes lost known solve paths (JWT alg:none, RFC 7797 b64=false); verification
caught it after the fact and the fixes were reverted and redone. tests/known_solves.toml names each known
solve path and the tests that prove it still works:

    [[solve]]
    id     = "jwt-alg-none"                              # unique, [a-z0-9-]
    what   = "a token re-signed with alg none is accepted: forge and live sweep"
    tests  = ["tests/test_web_jwt_forge_live.py::test_live_alg_none", ...]   # pytest node ids
    engines = ["web.jwt_forge_live"]                     # optional: engine ids that must still exist

`check(root)` (static, the CI half): every node id is a test function of a collected test file (a
parametrized id `test_x[p]` names `test_x`), no test of the set is hollow (tools/test_audit.py finds
nothing on it), and every engine id still has a manifest. `run(root)` (the oracle half, `--run`): each
file's node ids run in one pytest child through the gate's runner, strict not-run (a skipped known-solve
test is NOT preserved): every one must pass.

Event solve paths (the inputs of accepted runs, recorded with `ctf adapt record` /
ctf.adapt.regress.record_case into the workdir, never the repo) are preserved by the lane gate:
`run_lanes(lanes)` replays each lane's regression set (ctf.adapt.regress.gate) and requires YES.
"""
from __future__ import annotations

import importlib.util
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import IntegrityError
from .testfiles import collected_test_files, parse

REGISTRY = "tests/known_solves.toml"
_ID = re.compile(r"[a-z0-9][a-z0-9-]*\Z")


@dataclass(frozen=True)
class Solve:
    id: str
    what: str
    tests: tuple
    engines: tuple = ()


@dataclass
class PreserveResult:
    solves: list
    findings: list = field(default_factory=list)      # static problems (check)
    runs: list = field(default_factory=list)          # (node ids, Row) from run()
    lanes: list = field(default_factory=list)         # LaneGate per lane from run_lanes()

    @property
    def ok(self) -> bool:
        return not self.findings and all(r.status == "PASS" for _, r in self.runs) \
            and all(g.ok for g in self.lanes)


def load(root: Path) -> list[Solve]:
    path = Path(root) / REGISTRY
    if not path.is_file():
        raise IntegrityError(f"{REGISTRY} not found: the known solve paths have no registry")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise IntegrityError(f"{REGISTRY}: not valid TOML: {e}") from e
    if set(raw) - {"solve"}:
        raise IntegrityError(f"{REGISTRY}: unknown key(s) {sorted(set(raw) - {'solve'})}")
    out, seen = [], set()
    for i, e in enumerate(raw.get("solve", [])):
        where = f"{REGISTRY} [[solve]] #{i + 1}"
        if not isinstance(e, dict):
            raise IntegrityError(f"{where}: must be a table")
        extra = set(e) - {"id", "what", "tests", "engines"}
        if extra:
            raise IntegrityError(f"{where}: unknown key(s) {sorted(extra)}")
        sid, what, tests, engines = e.get("id"), e.get("what"), e.get("tests"), e.get("engines", [])
        if not isinstance(sid, str) or not _ID.match(sid):
            raise IntegrityError(f"{where}: id must match [a-z0-9][a-z0-9-]*")
        if sid in seen:
            raise IntegrityError(f"{where}: duplicate id {sid!r}")
        seen.add(sid)
        if not isinstance(what, str) or not what.strip():
            raise IntegrityError(f"{where} ({sid}): 'what' must say which solve path this is")
        for name, v in (("tests", tests), ("engines", engines)):
            if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
                raise IntegrityError(f"{where} ({sid}): {name} must be a list of strings")
        if not tests:
            raise IntegrityError(f"{where} ({sid}): a known solve path needs at least one test")
        for t in tests:
            if "::" not in t:
                raise IntegrityError(f"{where} ({sid}): {t!r} is not a pytest node id (<file>::<test>)")
        out.append(Solve(sid, what.strip(), tuple(tests), tuple(engines)))
    if not out:
        raise IntegrityError(f"{REGISTRY}: no [[solve]] entry")
    return out


def _test_audit(root: Path):
    p = Path(root) / "tools" / "test_audit.py"
    if not p.is_file():
        raise IntegrityError(f"tools/test_audit.py not found under {root}: the hollow-test audit is required")
    import sys
    name = "_ctf_integrity_test_audit"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod                  # dataclasses look their module up while the class is built
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(name, None)
    return mod


def _split(node: str) -> tuple[str, str]:
    """(file, test label as test_audit names it: `Class.test` or `test`) of a node id."""
    file, rest = node.split("::", 1)
    rest = re.sub(r"\[.*\]\Z", "", rest)
    return file, rest.replace("::", ".")


def _defined(tree, label: str) -> bool:
    import ast
    parts = label.split(".")
    body = tree.body
    for i, name in enumerate(parts):
        last = i == len(parts) - 1
        hit = next((n for n in body if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) if last
                                        else isinstance(n, ast.ClassDef)) and n.name == name), None)
        if hit is None:
            return False
        body = getattr(hit, "body", [])
    return True


def check(root: Path, solves: list[Solve] | None = None, *, engine_ids: set | None = None) -> PreserveResult:
    root = Path(root)
    solves = load(root) if solves is None else solves
    collected = set(collected_test_files(root))
    res = PreserveResult(solves)
    files = sorted({_split(t)[0] for s in solves for t in s.tests})
    hollow: dict = {}
    present = [root / f for f in files if f in collected and (root / f).is_file()]
    if present:
        findings, _notes, _errors = _test_audit(root).audit(present, display_base=root)
        for x in findings:
            hollow.setdefault((x.path, x.test), []).append(x.rule)
    if engine_ids is None and any(s.engines for s in solves):
        from ..engines import manifest as _manifest
        engine_ids = {m.id for m in _manifest.discover(root)}
    for s in solves:
        for t in s.tests:
            f, label = _split(t)
            if f not in collected:
                res.findings.append(f"{s.id}: {t}: {f} is not a collected test file")
                continue
            tree = parse(root / f)
            if tree is None or not _defined(tree, label):
                res.findings.append(f"{s.id}: {t}: no such test in {f}")
                continue
            rules = hollow.get((f, label))
            if rules:
                res.findings.append(f"{s.id}: {t}: hollow test ({', '.join(sorted(set(rules)))}, tools/test_audit.py)")
        for e in s.engines:
            if e not in (engine_ids or set()):
                res.findings.append(f"{s.id}: engine {e} has no manifest any more")
    return res


def run(root: Path, res: PreserveResult, *, out_dir: Path, wall: float = 600.0, python: str | None = None,
        allow_not_run=(), emit: Callable[[str], None] = print, run_file: Callable | None = None) -> PreserveResult:
    """Run every registry test, one pytest child per test file (its node ids together), strict not-run."""
    from ..gate import runner as grunner
    run_file = run_file or grunner.run_file
    by_file: dict[str, list] = {}
    for s in res.solves:
        for t in s.tests:
            by_file.setdefault(_split(t)[0], [])
            if t not in by_file[_split(t)[0]]:
                by_file[_split(t)[0]].append(t)
    for f, nodes in sorted(by_file.items()):
        row = run_file(Path(root), nodes[0], out_dir=out_dir, wall=wall, python=python,
                       pytest_args=tuple(nodes[1:]), allow_not_run=tuple(allow_not_run))
        res.runs.append((nodes, row))
        emit(grunner.format_row(row))
    return res


def run_lanes(lanes, res: PreserveResult, *, gate: Callable | None = None, emit: Callable[[str], None] = print,
              **kw) -> PreserveResult:
    """Replay each lane's regression set (opener cases + event cases from record_case); YES required."""
    if gate is None:
        from ..adapt import regress
        gate = regress.gate
    for lane in lanes:
        g = gate(lane, **kw)
        res.lanes.append(g)
        emit(f"{'YES' if g.ok else g.verdict:<7} lane {lane}: {g.reason}")
    return res
