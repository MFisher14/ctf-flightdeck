"""New-engine audit (B-196): the adversarial pass a new engine batch used to get by hand, as a check.

At CSCTF every batch of bulk-built engines got a hand-run audit-and-fix pass, and the bug backlog still
carried regressions. `audit(root, base)` takes every engine manifest added since the git ref `base`
(committed, staged, unstaged or untracked) and checks, per engine:

    manifest    it loads (ctf.engines.manifest) and its entry file exists
    tested      at least one test file reaches the entry file through its imports (the gate's dependency
                graph; a [[scan]] test that walks the whole tree does not count)
    hollow      tools/test_audit.py finds nothing in those test files
    fakes       the entry file has no fake branch (CTF_TESTING) without a non-fake test (integrity.fakes)

and prints the mutation command for the entry file (`python -m ctf integrity mutate <entry> --max 40`):
mutation runs the tests, so it is the operator's call, not part of the static audit.

    audit(root, base, state=...) -> list[EngineAudit]
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import IntegrityError

SUFFIX = ".manifest.toml"


@dataclass
class EngineAudit:
    manifest: str                    # repo-relative manifest path
    engine: str = ""                 # engine id (when it loads)
    entry: str = ""                  # repo-relative entry file
    tests: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def mutate_command(self) -> str:
        return f"python -m ctf integrity mutate {self.entry} --max 40" if self.entry else ""


def added_manifests(root: Path, base: str) -> list[str]:
    """Manifest files added since `base`: added in the diff to the working tree, or untracked."""
    def git(*a):
        try:
            r = subprocess.run(["git", "-C", str(root), *a], capture_output=True, timeout=120)
        except FileNotFoundError as e:
            raise IntegrityError("git is not on PATH: the new-engine audit diffs against a ref") from e
        if r.returncode != 0:
            raise IntegrityError(f"git {' '.join(a[:2])} failed: {r.stderr.decode(errors='replace').strip()}")
        return r.stdout.decode("utf-8", "surrogateescape")
    try:
        git("rev-parse", "--verify", "--quiet", base + "^{commit}")
    except IntegrityError:
        raise IntegrityError(f"unknown git ref {base!r} in {root}") from None
    out = set()
    diff = git("diff", "--name-status", "-z", "--no-renames", base).split("\0")
    for status, path in zip(diff[0::2], diff[1::2]):
        if status.startswith("A") and path.endswith(SUFFIX):
            out.add(path)
    for path in git("ls-files", "-z", "--others", "--exclude-standard").split("\0"):
        if path.endswith(SUFFIX):
            out.add(path)
    return sorted(p for p in out if (Path(root) / p).is_file())


def audit(root: Path, base: str, *, state: Path | None = None, manifests: list | None = None,
          config: Path | None = None) -> list[EngineAudit]:
    """One EngineAudit per manifest added since `base` (or per `manifests`, repo-relative)."""
    from ..engines import manifest as _manifest
    from ..gate import GateError
    from ..gate import config as gconfig
    from ..gate.impact import Graph
    from ..gate.warm import checkout_state
    from . import fakes
    from .preserve import _test_audit
    root = Path(root).resolve()
    rels = added_manifests(root, base) if manifests is None else list(manifests)
    if not rels:
        return []
    if state is None:
        from .. import paths
        try:
            state = paths.gate_state(root)
        except FileNotFoundError as e:
            raise IntegrityError(str(e)) from e
    try:
        graph = Graph(root, gconfig.load(root, config), checkout_state(state, root))
    except GateError as e:
        raise IntegrityError(f"gate: {e}") from e
    ta = _test_audit(root)
    out = []
    for rel in rels:
        a = EngineAudit(rel)
        out.append(a)
        try:
            m = _manifest.load(root / rel)
        except (_manifest.ManifestError, OSError) as e:
            a.findings.append(f"manifest does not load: {e}")
            continue
        a.engine = m.id
        target = m.entry.target_file(root)
        if target is None:
            target = m.module_path
        try:
            a.entry = Path(target).resolve().relative_to(root).as_posix()
        except ValueError:
            a.findings.append(f"entry {m.entry_raw!r} is outside the checkout")
            continue
        if not (root / a.entry).is_file():
            a.findings.append(f"entry file {a.entry} does not exist")
            continue
        sel = graph.select([a.entry])
        # a scan rule (a test that walks the whole tree) is not a test of this engine: only an import counts
        a.tests = [t for t in sel.tests if a.entry in graph.closure(t)] if sel.mode == "impact" else []
        if sel.mode != "impact" and a.entry in sel.unmapped:
            a.findings.append(f"no test file reaches {a.entry}: write one")
        elif sel.mode != "impact":
            a.findings.append(f"the gate cannot map the entry file to tests ({'; '.join(sel.reasons)})")
        elif not a.tests:
            a.findings.append(f"no test file reaches {a.entry}: write one")
        if a.tests:
            # a test file reaches the entry only through its parsed imports, so every one here parses
            found, _notes, _errors = ta.audit([root / t for t in a.tests], display_base=root)
            for x in found:
                a.findings.append(f"hollow test {x.path}:{x.line} {x.test}: {x.rule}")
        fa = fakes.audit(root, only=[a.entry])
        a.findings += fa.findings
    return out
