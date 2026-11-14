"""R-17: the namespaced solver package — engines importable as solvers.<lane>.<module>, with the three
dash-named lanes reached through the ctf.solverpkg meta path finder, and no solvers/__init__.py (SH-06).

These tests fail if the alias finder is not installed, aims at the wrong directory, hijacks a non-aliased
name, or if uninstall leaves the alias resolvable.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

from ctf import paths, solverpkg

REPO = paths.repo_root()
# (alias package, dashed directory, a leaf module that imports with only the repo root + lane dirs on
# sys.path — the suite's layout, which conftest.py provides)
DASHED = [
    ("solvers.script_analysis", "script-analysis", "analyze"),
    ("solvers.metadata_forensics", "metadata-forensics", "file_properties"),
    ("solvers.mobile_android", "mobile-android", "apk_facts"),
]


@pytest.fixture(autouse=True)
def _finder_installed():
    """Every test here starts with the finder installed (ctf import installs it; be explicit)."""
    solverpkg.install()
    yield


def test_solvers_has_no_init_so_it_stays_a_namespace_package():
    """SH-06 depends on solvers being a namespace package; a solvers/__init__.py would break it."""
    assert not (REPO / "solvers" / "__init__.py").exists()
    import solvers  # the namespace package imports
    assert getattr(solvers, "__file__", None) is None


@pytest.mark.parametrize("alias, dashed, _leaf", DASHED)
def test_alias_finds_the_dashed_lane_directory(alias, dashed, _leaf):
    spec = importlib.util.find_spec(alias)
    assert spec is not None, f"{alias} did not resolve (finder not answering)"
    assert spec.submodule_search_locations is not None
    locs = [Path(p).resolve() for p in spec.submodule_search_locations]
    assert (REPO / "solvers" / dashed).resolve() in locs


@pytest.mark.parametrize("alias, dashed, leaf", DASHED)
def test_namespaced_leaf_loads_the_dashed_file_and_matches_the_flat_module(alias, dashed, leaf):
    full = f"{alias}.{leaf}"
    pkg_mod = importlib.import_module(full)
    assert pkg_mod.__name__ == full
    assert Path(pkg_mod.__file__).resolve() == (REPO / "solvers" / dashed / f"{leaf}.py").resolve()
    # The flat import (the lane folder is on sys.path in the suite) resolves to the same file.
    flat = importlib.import_module(leaf)
    assert Path(flat.__file__).resolve() == Path(pkg_mod.__file__).resolve()
    # Documented caveat (ctf/solverpkg.py): the two forms are two module objects for one file.
    assert flat is not pkg_mod


def test_finder_does_not_hijack_a_non_aliased_name():
    f = solverpkg.DashedLaneFinder()
    assert f.find_spec("solvers.toolkits") is None
    assert f.find_spec("solvers.common.no_such_module") is None
    assert f.find_spec("solvers.script-analysis") is None   # only the underscore spelling is an alias
    assert f.find_spec("os") is None
    # and the real namespaced import of a non-dashed lane still works. The leaf name is held in a
    # variable so the coverage matrix does not credit this namespace test to that engine (it tests the
    # import path, not the engine).
    leaf = "memory_depth"
    md = importlib.import_module(f"solvers.toolkits.{leaf}")
    assert Path(md.__file__).resolve() == (REPO / "solvers" / "toolkits" / f"{leaf}.py").resolve()


@pytest.mark.parametrize("alias, dashed, _leaf", DASHED)
def test_alias_resolves_against_the_given_parent_path_in_order(alias, dashed, _leaf, tmp_path):
    """The alias follows the search path it is handed (solvers.__path__: the checkout `solvers` itself
    resolved to), in order, skipping a portion that lacks the dashed lane -- never its own checkout."""
    without = tmp_path / "a" / "solvers"
    without.mkdir(parents=True)                       # a `solvers` portion with no dashed lane
    with_lane = tmp_path / "b" / "solvers"
    (with_lane / dashed).mkdir(parents=True)
    f = solverpkg.DashedLaneFinder()
    spec = f.find_spec(alias, [str(without), str(with_lane)])
    assert spec is not None
    assert spec.name == alias
    assert spec.submodule_search_locations == [str(with_lane / dashed)]
    # a search path where no portion has the lane: None (a real import then fails loudly)
    assert f.find_spec(alias, [str(without)]) is None
    # order: when two portions both have the lane, the FIRST one wins (as for any namespace portion)
    later = tmp_path / "c" / "solvers"
    (later / dashed).mkdir(parents=True)
    spec = f.find_spec(alias, [str(without), str(with_lane), str(later)])
    assert spec.submodule_search_locations == [str(with_lane / dashed)]
    spec = f.find_spec(alias, [str(later), str(with_lane)])
    assert spec.submodule_search_locations == [str(later / dashed)]


def test_uninstall_makes_the_alias_unresolvable_again():
    alias = "solvers.mobile_android"
    saved_meta = list(sys.meta_path)
    saved_mods = {k: v for k, v in sys.modules.items() if k == alias or k.startswith(alias + ".")}
    for k in list(saved_mods):
        del sys.modules[k]
    try:
        solverpkg.uninstall()
        assert not solverpkg.installed()
        assert importlib.util.find_spec(alias) is None
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(alias)
    finally:
        sys.meta_path[:] = saved_meta
        sys.modules.update(saved_mods)
        solverpkg.install()
    # and it resolves once more after reinstall
    assert importlib.util.find_spec(alias) is not None


def test_install_is_idempotent():
    solverpkg.install()
    before = sum(isinstance(f, solverpkg.DashedLaneFinder) for f in sys.meta_path)
    solverpkg.install()
    after = sum(isinstance(f, solverpkg.DashedLaneFinder) for f in sys.meta_path)
    assert before == after == 1
