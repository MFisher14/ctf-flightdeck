"""SH-06: the checkout's `tests` package is not shadowed by an installed top-level `tests` package.

ecoji 0.1.1 (pinned in requirements.in) installs site-packages/tests/__init__.py. The checkout's tests/ has no
__init__.py, so it is a namespace package, and a regular package anywhere on sys.path wins over it: a plain
`import tests.test_speedrun_pools_hm13` then fails or, worse, serves another module of that name. These tests
build such a stray package in a temp dir, put it ahead on the path (in this process and in real pool workers),
and check the speed reader is still the checkout's own module. The stray copy answers "STRAY", so a worker that
imported it would give the wrong answers.
"""
from __future__ import annotations

import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from speedrun import common
from speedrun.solvers import script_pool, script_worker

ROOT = Path(__file__).resolve().parent.parent
MOD = "tests.test_speedrun_pools_hm13"
PLUG = MOD + ":fast_read"
REPO_FILE = (ROOT / "tests" / "test_speedrun_pools_hm13.py").resolve()

STRAY_READER = '''
def fast_read(member, text, qs):
    return {q["qid"]: "STRAY" for q in qs}
'''


def make_stray(base: Path) -> Path:
    """<base>/site/tests: a regular top-level `tests` package with its own test_speedrun_pools_hm13 and a
    module the checkout does not have. Returns <base>/site (the directory to put on sys.path)."""
    site = base / "site"
    pkg = site / "tests"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("# stray top-level tests package (SH-06 fixture)\n")
    (pkg / "test_speedrun_pools_hm13.py").write_text(STRAY_READER)
    (pkg / "only_in_stray_sh06.py").write_text("def read(member, text, qs):\n    return 'from-stray'\n")
    return site


@pytest.fixture
def clean_tests_modules():
    """Drop every `tests` / `tests.*` entry from sys.modules for the test and put the originals back after."""
    def ours(k):
        return k == "tests" or k.startswith("tests.")
    saved = {k: v for k, v in sys.modules.items() if ours(k)}
    for k in saved:
        del sys.modules[k]
    yield
    for k in [k for k in sys.modules if ours(k)]:
        del sys.modules[k]
    sys.modules.update(saved)


def test_stray_package_shadows_a_plain_import(tmp_path):
    """The scenario is real: with the checkout root FIRST on the path, a plain import still gets the stray
    module, because a regular package beats the checkout's namespace tests/."""
    site = make_stray(tmp_path)
    code = ("import importlib, sys; sys.path[:0] = [sys.argv[1], sys.argv[2]]; "
            "print(importlib.import_module(sys.argv[3]).__file__)")
    out = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(site), MOD],
                         capture_output=True, text=True, timeout=60, cwd=str(tmp_path))
    assert out.returncode == 0, out.stderr
    assert Path(out.stdout.strip()).resolve() == (site / "tests" / "test_speedrun_pools_hm13.py").resolve(), (
        "the stray package no longer shadows the checkout's tests/ (did tests/ become a regular package?): "
        "this test reproduces SH-06 only while it does")


def test_checkout_module_lookup(tmp_path, monkeypatch):
    assert script_worker.checkout_module(MOD) == (REPO_FILE, (ROOT / "tests").resolve())
    assert script_worker.checkout_module("speedrun.common") == (
        (ROOT / "speedrun" / "common.py").resolve(), (ROOT / "speedrun").resolve())
    assert script_worker.checkout_module("run") == (
        (ROOT / "tools" / "run.py").resolve(), (ROOT / "tools" / "run.py").resolve())
    assert script_worker.checkout_module("json") is None
    assert script_worker.checkout_module("tests.no_such_module_sh06") is None
    assert script_worker.checkout_module("not-a.name") is None
    # A package defined by its __init__.py, under a monkeypatched checkout root.
    (tmp_path / "pkg_sh06" / "sub").mkdir(parents=True)
    (tmp_path / "pkg_sh06" / "sub" / "__init__.py").write_text("")
    monkeypatch.setattr(script_worker, "ROOT", tmp_path)
    assert script_worker.checkout_module("pkg_sh06.sub") == (
        (tmp_path / "pkg_sh06" / "sub" / "__init__.py").resolve(), (tmp_path / "pkg_sh06").resolve())


def test_reader_comes_from_the_checkout_despite_a_stray_package(tmp_path, monkeypatch, clean_tests_modules):
    site = make_stray(tmp_path)
    monkeypatch.syspath_prepend(str(site))
    fn = script_worker.load_fast_reader(PLUG)
    assert Path(fn.__code__.co_filename).resolve() == REPO_FILE
    assert fn("m", "ANSWER=z", [{"qid": "q"}]) == {"q": "z:q"}
    assert Path(sys.modules[MOD].__file__).resolve() == REPO_FILE
    assert script_worker.load_fast_reader(PLUG) is fn            # loaded once, then reused


def test_reader_comes_from_the_checkout_when_the_stray_package_is_already_imported(
        tmp_path, monkeypatch, clean_tests_modules):
    site = make_stray(tmp_path)
    monkeypatch.syspath_prepend(str(site))
    import importlib
    stray = importlib.import_module("tests")
    assert Path(stray.__file__).resolve() == (site / "tests" / "__init__.py").resolve()
    fn = script_worker.load_fast_reader(PLUG)
    assert Path(fn.__code__.co_filename).resolve() == REPO_FILE
    assert fn("m", "ANSWER=y", [{"qid": "q"}]) == {"q": "y:q"}
    assert sys.modules["tests"] is stray, "the already-imported top-level module was replaced under its importer"


def test_stray_copy_already_imported_under_the_same_name_fails_loudly(tmp_path, monkeypatch, clean_tests_modules):
    site = make_stray(tmp_path)
    monkeypatch.syspath_prepend(str(site))
    import importlib
    importlib.import_module(MOD)                                  # the stray one, by a plain import
    with pytest.raises(script_worker.FastReaderError) as ei:
        script_worker.load_fast_reader(PLUG)
    msg = str(ei.value)
    assert script_worker.FAST_ENV in msg and str(REPO_FILE) in msg
    assert str((site / "tests").resolve()) in msg or str(site / "tests") in msg


def test_module_the_checkout_lacks_still_imports_normally(tmp_path, monkeypatch, clean_tests_modules):
    site = make_stray(tmp_path)
    monkeypatch.syspath_prepend(str(site))
    fn = script_worker.load_fast_reader("tests.only_in_stray_sh06:read")
    assert fn(None, "", []) == "from-stray"
    assert script_worker.load_fast_reader("json:dumps") is __import__("json").dumps


def test_unshadowed_checkout_module_is_the_imported_one():
    assert script_worker.load_fast_reader("speedrun.common:open_zip") is common.open_zip


# ---- a fake checkout (ROOT monkeypatched) whose namespace package `shpkg_sh06` a stray regular one shadows ------

FAKE_TOP = "shpkg_sh06"


@pytest.fixture
def fake_checkout(tmp_path, monkeypatch):
    """(checkout root, stray site): ROOT points at <tmp>/checkout, whose shpkg_sh06/ is a namespace package, and
    <tmp>/site, first on sys.path, holds a regular shpkg_sh06 package that shadows it. sys.modules entries for
    shpkg_sh06 are dropped before and after."""
    checkout, site = tmp_path / "checkout", tmp_path / "site"
    (checkout / FAKE_TOP).mkdir(parents=True)
    (site / FAKE_TOP).mkdir(parents=True)
    (site / FAKE_TOP / "__init__.py").write_text("# stray regular package (SH-06 fixture)\n")
    monkeypatch.setattr(script_worker, "ROOT", checkout)
    monkeypatch.syspath_prepend(str(site))

    def drop():
        for k in [k for k in sys.modules if k == FAKE_TOP or k.startswith(FAKE_TOP + ".")]:
            del sys.modules[k]
    drop()
    yield checkout, site
    drop()


def test_reader_that_fails_to_import_is_not_left_half_initialised(fake_checkout):
    """A checkout reader loaded by path that raises while it runs is dropped from sys.modules, so a second load
    runs it again and fails the same way instead of handing back the half-run module."""
    checkout, _site = fake_checkout
    (checkout / FAKE_TOP / "broken.py").write_text(
        "def read(member, text, qs):\n    return 'half-initialised'\n"
        "import no_such_module_sh06_broken\n")
    plug, mod = FAKE_TOP + ".broken:read", FAKE_TOP + ".broken"
    for _ in range(2):
        with pytest.raises(script_worker.FastReaderError) as ei:
            script_worker.load_fast_reader(plug)
        assert "no_such_module_sh06_broken" in str(ei.value)
        assert mod not in sys.modules


@pytest.mark.parametrize("stray_top_imported", [False, True])
def test_package_reader_named_by_its_init_imports_its_checkout_sibling(fake_checkout, stray_top_imported):
    """A shadowed checkout package (shpkg_sh06/sub/__init__.py) is a package: its relative import of a sibling
    submodule loads the checkout's sibling. Both routes: the checkout's top registered first (top not yet
    imported), and sub/__init__.py loaded by path (the stray top already imported)."""
    checkout, _site = fake_checkout
    assert not script_worker._top_resolves_to(FAKE_TOP, (checkout / FAKE_TOP).resolve()), (
        "precondition: a plain import of the top-level name lands on the stray package")
    if stray_top_imported:
        import importlib
        importlib.import_module(FAKE_TOP)
    sub = checkout / FAKE_TOP / "sub"
    sub.mkdir()
    (sub / "__init__.py").write_text("from .helper import VALUE\n\ndef read(member, text, qs):\n    return VALUE\n")
    (sub / "helper.py").write_text("VALUE = 'checkout-sibling'\n")
    fn = script_worker.load_fast_reader(FAKE_TOP + ".sub:read")
    assert fn(None, "", []) == "checkout-sibling"
    assert Path(sys.modules[FAKE_TOP + ".sub.helper"].__file__).resolve() == (sub / "helper.py").resolve()


def test_top_resolves_to_trusts_an_imported_module_over_the_path(tmp_path, monkeypatch):
    """What is already in sys.modules decides, not what the path finder would find now."""
    import types
    name = "shtop_sh06"
    checkout, stray = tmp_path / "checkout" / name, tmp_path / "stray" / name
    checkout.mkdir(parents=True)
    stray.mkdir(parents=True)
    (stray / "__init__.py").write_text("")
    loc = checkout.resolve()
    # The path finder sees only the checkout's namespace package; the imported module is the stray one.
    monkeypatch.syspath_prepend(str(checkout.parent))
    assert importlib_find(name) == [str(checkout)]
    imported = types.ModuleType(name)
    imported.__file__ = str(stray / "__init__.py")
    monkeypatch.setitem(sys.modules, name, imported)
    assert script_worker._top_resolves_to(name, loc) is False
    # The reverse: the path finder sees a stray regular package; the imported module is the checkout's.
    monkeypatch.syspath_prepend(str(stray.parent))
    ns = types.ModuleType(name)
    ns.__path__ = [str(checkout)]
    monkeypatch.setitem(sys.modules, name, ns)
    assert script_worker._top_resolves_to(name, loc) is True
    monkeypatch.delitem(sys.modules, name)
    assert script_worker._top_resolves_to(name, loc) is False        # now the path finder decides: the stray


def importlib_find(name):
    import importlib.machinery
    found = importlib.machinery.PathFinder.find_spec(name)
    return None if found is None else list(found.submodule_search_locations or [])


@pytest.fixture
def own_tops(tmp_path, monkeypatch):
    """A fake checkout <tmp>/checkout as ROOT, and a dropper: names(*tops) removes those top-level names and
    their submodules from sys.modules now and again after the test."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.setattr(script_worker, "ROOT", checkout)
    tops: list[str] = []

    def drop():
        for k in [k for k in sys.modules if k.split(".")[0] in tops]:
            del sys.modules[k]

    def names(*more):
        tops.extend(more)
        drop()
    yield checkout, names
    drop()


def test_unshadowed_checkout_module_goes_through_the_normal_import(tmp_path, monkeypatch, own_tops):
    """An unshadowed checkout namespace package is imported the normal way, not pinned to the checkout: its
    other portions on sys.path stay visible, and the parent package is imported with the module bound on it."""
    checkout, names = own_tops
    top = "nsplain_sh06"
    names(top)
    other = tmp_path / "other"
    (checkout / top).mkdir()
    (checkout / top / "mod.py").write_text("def read(member, text, qs):\n    return 'checkout mod'\n")
    (other / top).mkdir(parents=True)
    (other / top / "extra.py").write_text("WHERE = 'other portion'\n")
    monkeypatch.syspath_prepend(str(other))
    monkeypatch.syspath_prepend(str(checkout))
    assert script_worker._top_resolves_to(top, (checkout / top).resolve()), "precondition: not shadowed"
    fn = script_worker.load_fast_reader(top + ".mod:read")
    assert fn(None, "", []) == "checkout mod"
    parent, module = sys.modules[top], sys.modules[top + ".mod"]
    assert parent.mod is module
    assert sorted(Path(p).resolve() for p in parent.__path__) == sorted(
        [(checkout / top).resolve(), (other / top).resolve()]), "a normal namespace import sees every portion"
    import importlib
    assert importlib.import_module(top + ".extra").WHERE == "other portion"


def test_top_resolves_to_is_false_for_a_name_the_path_cannot_find(tmp_path):
    assert script_worker._top_resolves_to("no_such_top_sh06_zz", tmp_path.resolve()) is False


def test_checkout_module_off_the_path_is_loaded_from_the_checkout(own_tops):
    """A checkout module whose top-level name the path finder cannot see at all (ROOT not on sys.path) is still
    the checkout's: it is not handed to a plain import, which would raise ModuleNotFoundError."""
    checkout, names = own_tops
    top = "offpath_sh06"
    names(top)
    (checkout / top).mkdir()
    (checkout / top / "mod.py").write_text("def read(member, text, qs):\n    return 'checkout offpath'\n")
    assert importlib_find(top) is None, "precondition: the path finder does not see the fake checkout"
    assert script_worker.load_fast_reader(top + ".mod:read")(None, "", []) == "checkout offpath"


def test_shadowed_reader_imports_its_checkout_siblings(fake_checkout):
    """A reader in a shadowed checkout package that imports its siblings, relatively and absolutely, gets the
    checkout's siblings, not the stray package's modules of the same names."""
    checkout, site = fake_checkout
    for where, base in (("checkout", checkout), ("stray", site)):
        (base / FAKE_TOP / "helper.py").write_text(f"WHERE = '{where} helper'\n")
        (base / FAKE_TOP / "helper2.py").write_text(f"WHERE = '{where} helper2'\n")
    (checkout / FAKE_TOP / "reader.py").write_text(
        "from . import helper\n"
        f"import {FAKE_TOP}.helper2 as helper2\n"
        "def read(member, text, qs):\n    return (helper.WHERE, helper2.WHERE)\n")
    fn = script_worker.load_fast_reader(FAKE_TOP + ".reader:read")
    assert fn(None, "", []) == ("checkout helper", "checkout helper2")
    assert [Path(p).resolve() for p in sys.modules[FAKE_TOP].__path__] == [(checkout / FAKE_TOP).resolve()]


def test_shadowed_regular_checkout_package_runs_its_own_init(tmp_path, monkeypatch, own_tops):
    """A shadowed checkout top-level package that is a regular package (with __init__.py) is executed from the
    checkout, and its submodule reader loads from it."""
    checkout, names = own_tops
    top = "regpkg_sh06"
    names(top)
    site = tmp_path / "site"
    for where, base in (("checkout", checkout), ("stray", site)):
        (base / top).mkdir(parents=True)
        (base / top / "__init__.py").write_text(f"INIT = '{where}'\n")
        (base / top / "reader.py").write_text(f"def read(member, text, qs):\n    return '{where} reader'\n")
    monkeypatch.syspath_prepend(str(checkout))
    monkeypatch.syspath_prepend(str(site))
    assert not script_worker._top_resolves_to(top, (checkout / top).resolve()), "precondition: shadowed"
    assert script_worker.load_fast_reader(top + ".reader:read")(None, "", []) == "checkout reader"
    assert sys.modules[top].INIT == "checkout"
    assert Path(sys.modules[top].__file__).resolve() == (checkout / top / "__init__.py").resolve()


def test_shadowed_plain_top_level_checkout_module(tmp_path, monkeypatch, own_tops):
    """A shadowed checkout reader that is a plain top-level .py module is loaded from the checkout's file."""
    checkout, names = own_tops
    top = "plainmod_sh06"
    names(top)
    site = tmp_path / "site"
    site.mkdir()
    for where, base in (("checkout", checkout), ("stray", site)):
        (base / (top + ".py")).write_text(f"def read(member, text, qs):\n    return '{where} plain'\n")
    monkeypatch.syspath_prepend(str(checkout))
    monkeypatch.syspath_prepend(str(site))
    assert script_worker.load_fast_reader(top + ":read")(None, "", []) == "checkout plain"
    assert Path(sys.modules[top].__file__).resolve() == (checkout / (top + ".py")).resolve()


# ---- the worker's own namespace packages (speedrun, solvers) --------------------------------------------------

def test_pin_checkout_namespaces(tmp_path, monkeypatch):
    """pin_checkout_namespaces registers the checkout's namespace package for a shadowed name that is not yet
    imported, leaves an unshadowed one alone, and fails loudly when a stray copy is already imported."""
    checkout, site = tmp_path / "checkout", tmp_path / "site"
    for top in ("pinned_sh06", "plain_sh06", "taken_sh06"):
        (checkout / top).mkdir(parents=True)
        (checkout / top / "mod.py").write_text(f"WHERE = 'checkout {top}'\n")
    for top in ("pinned_sh06", "taken_sh06"):
        (site / top).mkdir(parents=True)
        (site / top / "__init__.py").write_text("")
        (site / top / "mod.py").write_text(f"WHERE = 'stray {top}'\n")
    monkeypatch.setattr(script_worker, "ROOT", checkout)
    monkeypatch.syspath_prepend(str(checkout))
    monkeypatch.syspath_prepend(str(site))
    for k in [k for k in sys.modules if k.split(".")[0] in ("pinned_sh06", "plain_sh06", "taken_sh06")]:
        monkeypatch.delitem(sys.modules, k)
    import importlib
    try:
        script_worker.pin_checkout_namespaces(("pinned_sh06", "plain_sh06", "absent_sh06"))
        assert importlib.import_module("pinned_sh06.mod").WHERE == "checkout pinned_sh06"
        assert "plain_sh06" not in sys.modules                       # it already resolved to the checkout
        assert importlib.import_module("plain_sh06.mod").WHERE == "checkout plain_sh06"
        assert "absent_sh06" not in sys.modules                      # the checkout has no such folder
        importlib.import_module("taken_sh06")                        # the stray, by a plain import
        with pytest.raises(ImportError) as ei:
            script_worker.pin_checkout_namespaces(("taken_sh06",))
        assert str((checkout / "taken_sh06").resolve()) in str(ei.value)
        assert "site" in str(ei.value)
    finally:
        for k in [k for k in sys.modules if k.split(".")[0] in ("pinned_sh06", "plain_sh06", "taken_sh06")]:
            del sys.modules[k]


STRAY_OWN = {
    "speedrun/__init__.py": "",
    "speedrun/common.py": "raise ImportError('SH06-STRAY speedrun.common was imported')\n",
    "solvers/__init__.py": "",
    "solvers/common/__init__.py": "raise ImportError('SH06-STRAY solvers.common was imported')\n",
}


def test_stray_own_packages_shadow_a_plain_import(tmp_path):
    """The scenario is real: regular `speedrun` and `solvers` packages anywhere on the path beat the checkout's
    namespace packages, even with the checkout root first."""
    site = make_stray(tmp_path)
    for rel, body in STRAY_OWN.items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_text(body)
    code = ("import importlib, sys; sys.path[:0] = [sys.argv[1], sys.argv[2]]; "
            "print(importlib.import_module('speedrun').__file__); print(importlib.import_module('solvers').__file__)")
    out = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(site)],
                         capture_output=True, text=True, timeout=60, cwd=str(tmp_path))
    assert out.returncode == 0, out.stderr
    assert [Path(x).resolve() for x in out.stdout.split()] == [
        (site / "speedrun" / "__init__.py").resolve(), (site / "solvers" / "__init__.py").resolve()]


# ---- real pool workers with the stray package ahead on their path -----------------------------------

def _stored_zip(members: dict) -> bytes:
    out, cd = bytearray(), bytearray()
    for name, body in members.items():
        n, crc = name.encode(), zlib.crc32(body)
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, crc, len(body), len(body),
                           len(n), 0) + n + body
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, len(body), len(body),
                          len(n), 0, 0, 0, 0, 0, off) + n
    cd_off = len(out)
    out += cd + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(cd), cd_off, 0)
    return bytes(out)


def _launcher(tmp_path: Path, site: Path, marks: Path) -> Path:
    """An executable that stands in for sys.executable: run as `<it> -I script_worker.py`, it puts the stray
    package first on the path, leaves a mark, and runs the worker as __main__."""
    script = tmp_path / "launch_sh06.py"
    script.write_text(
        f"#!{sys.executable} -I\n"
        "import os, runpy, sys\n"
        f"sys.path.insert(0, {str(site)!r})\n"
        "argv = sys.argv[1:]\n"
        "if argv and argv[0] == '-I':\n"
        "    argv = argv[1:]\n"
        "sys.argv = argv\n"
        f"open(os.path.join({str(marks)!r}, str(os.getpid())), 'w').write(repr(sys.path))\n"
        "runpy.run_path(argv[0], run_name='__main__')\n")
    script.chmod(0o755)
    return script


def test_pool_workers_import_the_checkout_reader_with_a_stray_package_ahead(tmp_path, monkeypatch):
    _pool_answers_with_stray_site(make_stray(tmp_path), tmp_path, monkeypatch)


def test_pool_workers_boot_with_stray_speedrun_and_solvers_packages_ahead(tmp_path, monkeypatch):
    """Stray regular `speedrun` and `solvers` packages whose `common` modules raise: the workers still boot,
    because they pin their own namespace packages to the checkout, and answer with the checkout reader."""
    site = make_stray(tmp_path)
    for rel, body in STRAY_OWN.items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_text(body)
    _pool_answers_with_stray_site(site, tmp_path, monkeypatch)


def _pool_answers_with_stray_site(site, tmp_path, monkeypatch):
    marks = tmp_path / "marks"
    marks.mkdir()
    monkeypatch.setattr(script_pool.sys, "executable", str(_launcher(tmp_path, site, marks)))
    monkeypatch.setenv("CTF_SPEED_SCRIPT_FAST", PLUG)
    script_pool.stop()
    monkeypatch.setattr(script_pool, "_ready", __import__("threading").Event())
    members = {f"m{i:02d}.ps1": b"ANSWER=v%d" % i for i in range(6)}
    data = _stored_zip(members)
    qs = [{"id": f"set0.{m}-x", "artifact": f"outer.zip -> {m}", "question": "q?"} for m in members]
    attempt = {"questions": qs, "answer_ids": [q["id"] for q in qs]}
    try:
        script_pool.start(2)
        script_pool.wait_ready(120)
        seen = sorted(marks.iterdir())
        assert len(seen) == 2, "the launcher did not start both workers"
        for f in seen:
            assert f.read_text().startswith(repr([str(site)])[:-1]), "stray package not first on the child's path"
        assert len(script_pool.alive()) == 2, "workers did not boot"
        got = script_pool.solve(attempt, [common.Delivery(0, "outer.zip", data)], {})
        assert len(script_pool.LAST) == 2 and all(x and x[1] > 0 for x in script_pool.LAST)
        for i in range(6):
            assert got[f"set0.m{i:02d}.ps1-x"] == f"v{i}:m{i:02d}.ps1-x"
        assert "STRAY" not in got.values()
    finally:
        script_pool.stop()
