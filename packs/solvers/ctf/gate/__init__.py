"""The regression gate (B-195): impact-selected test files, exact-hash warm reuse, load-scaled walls.

    python -m ctf gate plan  --base REF | --changed F ... | --lane L | --batch ID | --full   [--json]
    python -m ctf gate run   (the same selectors) [--jobs N] [--no-warm] [--wall-base S]
    python -m ctf gate inventory                                  refresh the dependency inventory

Pieces (each its own module):

    config     tests/gate.toml: test globs, import roots, global/inert inputs, scan rules, lanes, walls
    inventory  content-hash incremental inventory: per-file sha256 (re-hashed only when the file's stat
               changes) and per-content parse results (re-parsed only when the content hash changes)
    impact     the static dependency graph (imports, dotted-module strings, file and directory references)
               and the selection: which test files a set of changed files can affect, or why a full run
    warm       exact-hash warm results: a test file's key hashes every input in its closure plus the
               global inputs, interpreter and environment knobs; a green result under that key is reused
    runner     one pytest child per test file, --jobs at a time, each under a wall scaled by host load;
               one summary line per file and one GATE line at the end
    budget     B-153: per-lane time budgets (300 s at most), load-independent file costs, timings store
    baseline   B-153: the tracked baseline ledger; splits every red into new and baseline reds
    prearm     B-153: the pre-arm full gate's preflight checks

Contract: docs/CONTRACTS.md section 19.
"""
from __future__ import annotations


class GateError(RuntimeError):
    """A usage or configuration problem the gate refuses to paper over (exit 2 on the CLI)."""


__all__ = ["GateError"]
