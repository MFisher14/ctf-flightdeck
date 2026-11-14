"""ctf/packs.py: loading a pack by path, with a named error for every miss (B-001b). Also the metadata
lane's reader packs (properties_strict.py) and the lanes' override guard, which now load through it.

Every pack file here is written by the test; the metadata check runs on a temp copy of the lane.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import packs
from ctf.packs import PackError, PackLoadError, PackMissing, RegistryLoadError

REPO = Path(__file__).resolve().parent.parent


def test_missing_file_raises_pack_missing_naming_pack_and_path(tmp_path):
    with pytest.raises(PackMissing) as e:
        packs.load_module("b001b_absent", tmp_path / "absent.py", pack="reader pack absent")
    assert e.value.pack == "reader pack absent" and e.value.path == tmp_path / "absent.py"
    assert "reader pack absent" in str(e.value) and str(tmp_path / "absent.py") in str(e.value)
    assert isinstance(e.value, PackError) and "b001b_absent" not in sys.modules


def test_a_pack_that_raises_is_a_pack_load_error_with_its_cause_and_is_not_left_cached(tmp_path):
    f = tmp_path / "broken.py"
    f.write_text("import nonexistent_module_for_b001b\n")
    with pytest.raises(PackLoadError, match="ModuleNotFoundError") as e:
        packs.load_module("b001b_broken", f)
    assert isinstance(e.value.__cause__, ModuleNotFoundError)
    assert "b001b_broken" not in sys.modules


def test_sys_exit_at_import_is_a_load_error(tmp_path):
    f = tmp_path / "exits.py"
    f.write_text("raise SystemExit(3)\n")
    with pytest.raises(PackLoadError, match="SystemExit"):
        packs.load_module("b001b_exits", f)


def test_a_runner_stop_passes_through_unchanged(tmp_path):
    f = tmp_path / "stops.py"
    f.write_text("class Stop(BaseException):\n    pass\nraise Stop('clock')\n")
    with pytest.raises(BaseException) as e:
        packs.load_module("b001b_stops", f)
    assert type(e.value).__name__ == "Stop" and not isinstance(e.value, PackError)
    assert "b001b_stops" not in sys.modules


def test_cache_true_loads_once_cache_false_loads_fresh_and_outside_sys_modules(tmp_path):
    f = tmp_path / "counter.py"
    f.write_text("X = object()\n")
    a = packs.load_module("b001b_counter", f)
    try:
        assert sys.modules["b001b_counter"] is a and packs.load_module("b001b_counter", f) is a
    finally:
        sys.modules.pop("b001b_counter", None)
    fresh1 = packs.load_module("b001b_fresh", f, cache=False)
    fresh2 = packs.load_module("b001b_fresh", f, cache=False)
    assert fresh1 is not fresh2 and fresh1.X is not fresh2.X and "b001b_fresh" not in sys.modules


def test_toolkit_registry_missing_is_a_registry_load_error(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, packs.REGISTRY_MODULE, raising=False)
    with pytest.raises(RegistryLoadError, match="toolkit registry.*file not there"):
        packs.toolkit_registry(tmp_path)


def test_toolkit_registry_broken_is_a_registry_load_error(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, packs.REGISTRY_MODULE, raising=False)
    d = tmp_path / "solvers" / "toolkits"
    d.mkdir(parents=True)
    (d / "registry.py").write_text("raise ImportError('half-written registry')\n")
    with pytest.raises(RegistryLoadError, match="half-written registry"):
        packs.toolkit_registry(tmp_path)
    assert packs.REGISTRY_MODULE not in sys.modules


# ------------------------------------------------------------------------------------------ metadata reader packs

def _metadata_copy(tmp_path) -> Path:
    """A temp tree with the metadata lane, solvers/common and ctf/ (properties_strict needs all three)."""
    ignore = shutil.ignore_patterns("__pycache__")
    for rel in ("ctf", "solvers/common", "solvers/metadata-forensics"):
        shutil.copytree(REPO / rel, tmp_path / rel, ignore=ignore)
    return tmp_path


def _import_properties_strict(root: Path):
    code = ("import sys\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\nimport properties_strict as P\n"
            "print(len(P.MORE_LOADED), sorted(P.MAIL_LOADED), len(P.MORE_FILES))\n") % str(root / "solvers" / "metadata-forensics")
    return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=180,
                          cwd=str(root))


@pytest.mark.slow
def test_metadata_lane_raises_pack_missing_for_a_missing_reader_pack(tmp_path):
    root = _metadata_copy(tmp_path)
    ok = _import_properties_strict(root)
    assert ok.returncode == 0, ok.stderr[-600:]                          # the copy is whole: every pack loads
    loaded, files = ok.stdout.split()[0], ok.stdout.split()[-1]
    assert loaded == files and int(files) >= 24, ok.stdout              # every listed pack (24 since B-162's riff pack)
    (root / "solvers" / "metadata-forensics" / "readers_msi.py").unlink()
    gone = _import_properties_strict(root)
    assert gone.returncode != 0
    assert "PackMissing" in gone.stderr and "metadata reader pack readers_msi.py" in gone.stderr, gone.stderr[-600:]


@pytest.mark.slow
def test_metadata_lane_raises_pack_load_error_for_a_pack_that_does_not_register(tmp_path):
    root = _metadata_copy(tmp_path)
    (root / "solvers" / "metadata-forensics" / "readers_mail.py").write_text(
        "def register(m):\n    raise KeyError('mail pack refuses')\n")
    r = _import_properties_strict(root)
    assert r.returncode != 0
    assert "PackLoadError" in r.stderr and "register() raised KeyError" in r.stderr, r.stderr[-600:]


def test_metadata_lazy_packs_load_through_the_named_loader():
    sys.path.insert(0, str(REPO / "solvers" / "metadata-forensics"))
    import properties_strict as P
    for loader in (P._fc_mod, P._fallback_mod, P._stated_mod, P._synthesis_mod, P._relation_mod, P._graph_mod):
        mod = loader()
        assert mod is not None and Path(mod.__file__).parent == REPO / "solvers" / "metadata-forensics"
    with pytest.raises(PackMissing, match="metadata reader pack no_such_pack.py"):
        P._load_beside("metadata_no_such_pack", "no_such_pack.py")


# ------------------------------------------------------------------------------------------ the override guard

@pytest.mark.parametrize("lane", ["binary", "mobile-android", "script-analysis"])
def test_each_lane_loads_the_carried_override_guard(lane):
    respell = packs.load_module(f"b001b_respell_{lane.replace('-', '_')}",
                                REPO / "solvers" / lane / "respell.py", cache=False)
    og = respell._og()
    assert Path(og.__file__) == REPO / "tools" / "override_guard.py"
    # The guard itself: a judge-accepted plain answer is never replaced; an unjudged one is.
    value, blocked, note = og.guard("k", "judged", "other", {"name"})
    assert value == "judged" and blocked and "override refused" in note
    assert og.guard("k", "plain", "fix", set()) == ("fix", False, "")


def test_override_guard_missing_raises_instead_of_applying_the_override_unguarded(tmp_path):
    shutil.copytree(REPO / "ctf", tmp_path / "ctf", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(REPO / "solvers" / "common", tmp_path / "solvers" / "common",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "solvers" / "binary").mkdir()
    shutil.copy2(REPO / "solvers" / "binary" / "respell.py", tmp_path / "solvers" / "binary" / "respell.py")
    code = ("import sys\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\nimport respell\nrespell._og()\n"
            % str(tmp_path / "solvers" / "binary"))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120)
    assert r.returncode != 0
    assert "PackMissing" in r.stderr and "tools/override_guard.py" in r.stderr, r.stderr[-600:]
