"""The files generated from the engine manifests, regenerated together (R-10).

    python -m ctf engines generate            new manifests, then every file below
    python -m ctf engines generate --check    exit 1 when a manifest is missing or a file below is stale

| file | module | read by |
|---|---|---|
| ctf/engines/route_table.jsonl | routetable.py | ctf/triage.py (routing) |
| docs/CAPABILITIES.md | capabilities.py | people: what triage can suggest, and when |
| docs/coverage/ENGINES.md | coverage.py | people: class, status, cost, needs, tests per engine |
| docs/PRIMER.md, docs/FILE-INDEX.md | ctf/primer.py | agents: the repo brief and file index (B-199) |

None is ever edited by hand; each has a currency test. After merging branches that touch engines,
regenerate instead of resolving conflicts in these files.
"""
from __future__ import annotations

from pathlib import Path

from .. import primer
from . import capabilities, coverage, routetable

# (repo-relative path, write(root) -> Path, is_stale(root) -> bool)
DERIVED = (
    (routetable.TABLE_REL, routetable.write, routetable.is_stale),
    (capabilities.CAPABILITIES_REL, capabilities.write, capabilities.is_stale),
    (coverage.MATRIX_REL, coverage.write, coverage.is_stale),
    # B-199: not engine-derived, but regenerated here so the merge queue's `engines generate` keeps them
    # current after every merge (they index the whole tree: commands, modules, large files)
    (primer.PRIMER_REL, primer.write_primer, primer.primer_stale),
    (primer.INDEX_REL, primer.write_index, primer.index_stale),
)


def stale(root: Path | None = None) -> list[str]:
    """The generated files that differ from a fresh render (or are missing)."""
    return [rel for rel, _, is_stale in DERIVED if is_stale(root)]


def write_all(root: Path | None = None) -> list[str]:
    """Rewrite every generated file; returns the ones whose content changed."""
    changed = []
    for rel, write, is_stale in DERIVED:
        if is_stale(root):
            write(root)
            changed.append(rel)
    return changed
