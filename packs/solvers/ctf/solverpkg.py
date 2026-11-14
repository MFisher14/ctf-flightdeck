"""The namespaced solver package: import an engine as ``solvers.<lane>.<module>`` (B-187 remainder).

Every carried engine is imported flat (its lane folder on ``sys.path``, ``import network``) and that is
unchanged. On top of that the same modules may be imported by their dotted path from the repo root —
``solvers.<lane>.<module>`` — the form the engine manifests name and the form a test or operator script
uses without a per-file ``sys.path`` hack. For the lanes whose directory name is already a valid Python
identifier (``web``, ``warmups``, ``binary``, ``toolkits``, ``common``) this needs nothing: ``solvers`` is
a namespace package and ``solvers.toolkits.memory_depth`` resolves through the ordinary path machinery.

``solvers`` is deliberately NOT a regular package here (no ``solvers/__init__.py``): the speedrun worker
relies on it staying a namespace package so the checkout's copy is the one that loads (SH-06,
tests/test_speedrun_shadowed_tests_sh06.py). So the alias layer for the three dash-named lanes is a
``sys.meta_path`` finder, not an ``__init__``.

Three lane directories carry a dash and cannot be a dotted import name:

    solvers.script_analysis.<mod>    ->  solvers/script-analysis/<mod>.py
    solvers.metadata_forensics.<mod> ->  solvers/metadata-forensics/<mod>.py
    solvers.mobile_android.<mod>     ->  solvers/mobile-android/<mod>.py

:func:`install` adds a finder that answers the three underscore package names with a package spec whose
search path is the dashed directory; Python's own path machinery then finds every submodule under it, so
sibling flat imports and ``from . import x`` inside those modules work exactly as under a real package.
Renaming the directories is refused by design: it would break every flat import and every manifest path
(the manifest ``entry`` keeps the dash, ``solvers.metadata-forensics.x``, resolved by file not by import).

``install()`` runs when ``ctf`` is imported (ctf/__init__.py), which covers the test suite (its conftest
imports ctf) and engine runs (ctf/engines/_boot imports ctf), and is idempotent and safe to call again.
Without ``import ctf`` first, the three underscore names do not resolve (the five identifier lanes do).

Caveat — two module objects for one file. The dotted and the flat import of the same file are separate
modules (``solvers.metadata_forensics.file_properties`` and ``file_properties`` are each executed once),
so module-level state (a registry, a cache, a counter) exists twice when both forms are used in one
process. Inside a dotted-imported module, a flat sibling import (``import helper``) still binds the flat
top-level copy, not ``solvers.<lane>.helper``. Pick one form per process for any module that keeps state;
the engines themselves and the runner use the flat form.
"""
from __future__ import annotations

import importlib.machinery
import sys
from pathlib import Path

# underscore package name (full dotted) -> the dash-named directory under solvers/ it stands for.
ALIASES = {
    "solvers.script_analysis": "script-analysis",
    "solvers.metadata_forensics": "metadata-forensics",
    "solvers.mobile_android": "mobile-android",
}

# solvers/ in this same checkout: the fallback search root when the import machinery gives no parent path
# (it always does for a submodule of the `solvers` namespace package, but a direct find_spec may not).
_SOLVERS_DIR = Path(__file__).resolve().parent.parent / "solvers"


class DashedLaneFinder:
    """A ``sys.meta_path`` finder for exactly the three dash-named lane packages, and nothing else.

    It resolves the dashed directory against the parent package's search path (``solvers.__path__``,
    passed as ``path``) so it points at the same checkout ``solvers`` itself resolved to; only when no
    parent path is given does it fall back to this module's own ``solvers`` directory.
    """

    def find_spec(self, fullname, path=None, target=None):
        dashed = ALIASES.get(fullname)
        if dashed is None:
            return None
        for base in (list(path) if path else [str(_SOLVERS_DIR)]):
            laned = Path(base) / dashed
            if laned.is_dir():
                spec = importlib.machinery.ModuleSpec(fullname, None, is_package=True)
                spec.submodule_search_locations = [str(laned)]
                return spec
        return None      # loud: a real import then raises ModuleNotFoundError naming the alias

    def __eq__(self, other):
        return isinstance(other, DashedLaneFinder)

    def __hash__(self):
        return hash(DashedLaneFinder)


def installed() -> bool:
    return any(isinstance(f, DashedLaneFinder) for f in sys.meta_path)


def install() -> None:
    """Register the dashed-lane finder on ``sys.meta_path`` once. Idempotent."""
    if not installed():
        sys.meta_path.append(DashedLaneFinder())


def uninstall() -> None:
    """Remove the finder (for tests that assert the un-aliased behaviour)."""
    sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, DashedLaneFinder)]
