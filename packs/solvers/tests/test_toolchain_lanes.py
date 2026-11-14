"""B-188: the per-lane env-check and exports (ctf/toolchain/lanes.py, tools/lanes.toml).

Each test builds a small synthetic checkout (solvers/<lane>/ engines with their sidecars, a local
helper, tools/lanes.toml). Module lookups run the real interpreter of this venv with -I, against
module names that do or cannot exist; no network, nothing installed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import paths
from ctf.engines import layout
from ctf.toolchain import assets, images, lanes
from toolchain_stubs import write

NOPE = "ctf_b188_no_such_module_xyz"


def engine(root: Path, lane: str, name: str, src: str, *, needs: str = "[]", status: str = "active") -> Path:
    py = write(root / "solvers" / lane / f"{name}.py", src)
    write(root / "solvers" / lane / f"{name}.manifest.toml", f"""\
        id = "{lane.replace('-', '_')}.{name}"
        lane = "{lane}"
        entry = "solvers.{lane}.{name}:solve"
        capabilities = ["analysis"]
        needs_tools = {needs}
        status = "{status}"
        """)
    return py


def mk_root(tmp_path: Path, spec: str = "") -> Path:
    root = tmp_path / "root"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "lanes.toml").write_text(textwrap.dedent(spec))
    return root


# --------------------------------------------------------------------------------------- imports

def test_scan_imports_splits_required_from_optional_and_skips_stdlib(tmp_path):
    root = mk_root(tmp_path)
    eng = engine(root, "binary", "eng", f"""\
        import os, json
        import {NOPE}
        from capstone import Cs
        try:
            import lief
        except ImportError:
            lief = None
        def solve(d, p):
            import pefile
            return None
        """)
    uses, bad = lanes.scan_imports([eng], root)
    assert set(uses) == {NOPE, "capstone", "lief", "pefile"} and bad == []
    assert uses[NOPE].required_by == ("solvers/binary/eng.py",) and uses["capstone"].required_by
    assert uses["lief"].required_by == () and uses["lief"].optional_by == ("solvers/binary/eng.py",)
    assert uses["pefile"].optional_by and not uses["pefile"].required_by


def test_scan_imports_follows_local_modules_and_keeps_the_weakest_link(tmp_path):
    root = mk_root(tmp_path)
    write(root / "solvers" / "common" / "helper.py", "import hard_dep_mod\n")
    write(root / "solvers" / "common" / "lazy_helper.py", "import lazy_dep_mod\n")
    write(root / "solvers" / "common" / "pkg" / "__init__.py", "")
    write(root / "solvers" / "common" / "pkg" / "sub.py", "import pkg_dep_mod\nfrom . import sibling\n")
    write(root / "solvers" / "common" / "pkg" / "sibling.py", "import sibling_dep_mod\n")
    eng = engine(root, "common", "eng", """\
        import helper
        from pkg import sub
        def solve(d, p):
            import lazy_helper
        """)
    uses, _ = lanes.scan_imports([eng], root)
    assert set(uses) == {"hard_dep_mod", "lazy_dep_mod", "pkg_dep_mod", "sibling_dep_mod"}
    assert uses["hard_dep_mod"].required_by == ("solvers/common/eng.py",)
    assert uses["pkg_dep_mod"].required_by and uses["sibling_dep_mod"].required_by
    assert uses["lazy_dep_mod"].optional_by and not uses["lazy_dep_mod"].required_by


def test_a_module_reached_hard_by_one_engine_is_required_even_if_another_is_lazy(tmp_path):
    root = mk_root(tmp_path)
    a = engine(root, "web", "a", "import shared_mod\n")
    b = engine(root, "web", "b", "def solve(d, p):\n    import shared_mod\n")
    uses, _ = lanes.scan_imports([a, b], root)
    assert uses["shared_mod"].required_by == ("solvers/web/a.py",)
    assert uses["shared_mod"].optional_by == ("solvers/web/b.py",)


def test_unparseable_sources_are_listed(tmp_path):
    root = mk_root(tmp_path)
    eng = engine(root, "web", "old", "print 'python 2'\n")
    uses, bad = lanes.scan_imports([eng], root)
    assert uses == {} and bad == ["solvers/web/old.py"]


# ------------------------------------------------------------------------------------ find_modules

def test_find_modules_asks_the_interpreter_without_importing():
    got = lanes.find_modules(["json", NOPE], sys.executable)
    assert got == {"json": True, NOPE: False}
    assert lanes.find_modules([], sys.executable) == {}


def test_find_modules_fails_loudly_when_the_interpreter_does_not_answer(tmp_path):
    with pytest.raises(lanes.LaneError, match="did not answer"):
        lanes.find_modules(["json"], str(tmp_path / "no-python"))
    bad = write(tmp_path / "py", "#!/bin/sh\necho nothing useful\n", 0o755)
    with pytest.raises(lanes.LaneError, match="no module lookup result"):
        lanes.find_modules(["json"], str(bad))
    err = write(tmp_path / "py2", "#!/bin/sh\nexit 4\n", 0o755)
    with pytest.raises(lanes.LaneError, match="exited 4"):
        lanes.find_modules(["json"], str(err))


# ------------------------------------------------------------------------------------------- check

def test_check_reports_a_missing_hard_import_and_the_lane_spec(tmp_path):
    root = mk_root(tmp_path, f"""\
        [lane.binary]
        modules = ["json", "{NOPE}_listed"]
        bins = ["lane-tool"]
        image = "toolkit"
        """)
    engine(root, "binary", "eng", f"import {NOPE}\ndef solve(d, p):\n    import {NOPE}_lazy\n",
           needs='["advisory-tool", "py:json"]')
    engine(root, "binary", "gone", f"import {NOPE}_retired\n", status="retired")
    bindir = tmp_path / "bin"
    write(bindir / "lane-tool", "#!/bin/sh\n", 0o755)
    rep = lanes.check("binary", root=root, environ={"PATH": str(bindir)}, pins=False)
    by = {(i.kind, i.name): i for i in rep.items}
    assert (("module", f"{NOPE}_retired")) not in by                  # a retired engine is not the lane's
    assert by[("module", NOPE)].required and not by[("module", NOPE)].ok
    assert "loaded by solvers/binary/eng.py" in by[("module", NOPE)].detail
    assert not by[("module", f"{NOPE}_lazy")].required
    assert by[("module", f"{NOPE}_listed")].required and "tools/lanes.toml" in by[("module", f"{NOPE}_listed")].detail
    assert by[("module", "json")].ok and "needs_tools of binary.eng" in by[("module", "json")].detail
    assert by[("bin", "lane-tool")].ok and by[("bin", "lane-tool")].required
    assert not by[("bin", "advisory-tool")].ok and not by[("bin", "advisory-tool")].required
    assert sorted(i.name for i in rep.problems()) == [NOPE, f"{NOPE}_listed"]
    assert not rep.passed and rep.image == "toolkit"
    assert rep.to_dict()["passed"] is False


def test_check_passes_when_everything_is_there_and_finds_bins_in_the_venv(tmp_path):
    root = mk_root(tmp_path, '[lane.web]\nbins = ["venv-only-tool"]\n')
    engine(root, "web", "eng", "import json\n")
    vbin = tmp_path / "venv" / "bin"
    write(vbin / "venv-only-tool", "#!/bin/sh\n", 0o755)
    fake_py = vbin / "python"
    fake_py.symlink_to(sys.executable)
    rep = lanes.check("web", root=root, python=str(fake_py), environ={"PATH": str(tmp_path / "empty")}, pins=False)
    assert rep.passed, [i.line() for i in rep.items]
    assert [(i.kind, i.name, i.ok) for i in rep.items] == [("bin", "venv-only-tool", True)]


def test_check_resolves_the_lane_assets(tmp_path):
    root = mk_root(tmp_path, '[lane.toolkits]\nassets = ["wl"]\n')
    engine(root, "toolkits", "eng", "import json\n")
    wl = assets.Asset(name="wl", kind="file", role="optional", candidates=(str(tmp_path / "wl.txt"),),
                      export=("CTF_ASSET_WL",))
    rep = lanes.check("toolkits", root=root, environ={}, pins=False, asset_items=[wl])
    item, = [i for i in rep.items if i.kind == "asset"]
    assert item.required and not item.ok and not rep.passed           # the lane needs it, whatever its role
    (tmp_path / "wl.txt").write_text("x")
    assert lanes.check("toolkits", root=root, environ={}, pins=False, asset_items=[wl]).passed


def test_check_runs_the_venv_pin_check(tmp_path):
    root = mk_root(tmp_path)
    engine(root, "web", "eng", "import json\n")
    write(root / "tools" / "venv_pins.py", """\
        import sys
        print("MISMATCH foo==1.0: 0.9 installed")
        print("FIX  uv pip install --python X foo==1.0")
        sys.exit(1)
        """)
    rep = lanes.check("web", root=root, environ={})
    pins, = [i for i in rep.items if i.kind == "pins"]
    assert not pins.ok and pins.required and "MISMATCH foo==1.0" in pins.detail
    assert pins.fix == "uv pip install --python X foo==1.0" and not rep.passed
    write(root / "tools" / "venv_pins.py", "print('OK every pin')\n")
    pins, = [i for i in lanes.check("web", root=root, environ={}).items if i.kind == "pins"]
    assert pins.ok and pins.detail == "OK every pin"


def test_check_refuses_an_unknown_lane_and_bad_manifests(tmp_path):
    root = mk_root(tmp_path)
    engine(root, "web", "eng", "import json\n")
    with pytest.raises(lanes.LaneError, match="unknown lane 'nope'"):
        lanes.check("nope", root=root, pins=False)
    write(root / "solvers" / "web" / "bad.py", "x = 1\n")
    write(root / "solvers" / "web" / "bad.manifest.toml", 'id = "web.bad"\n')
    with pytest.raises(lanes.LaneError, match="engine manifests"):
        lanes.check("web", root=root, pins=False)


def test_parse_specs_refuses_bad_entries():
    with pytest.raises(lanes.LaneError, match="unknown key"):
        lanes.parse_specs({"lane": {"web": {"colour": 1}}})
    with pytest.raises(lanes.LaneError, match="top-level import names"):
        lanes.parse_specs({"lane": {"web": {"modules": ["a.b"]}}})
    with pytest.raises(lanes.LaneError, match="distinct"):
        lanes.parse_specs({"lane": {"web": {"bins": ["x", "x"]}}})
    with pytest.raises(lanes.LaneError, match="unknown top-level"):
        lanes.parse_specs({"lanes": {}})
    assert lanes.parse_specs({"lane": {"web": {"image": "toolkit"}}})["web"].image == "toolkit"


def test_exports_give_the_engine_path_the_interpreter_and_the_assets(tmp_path):
    root = mk_root(tmp_path)
    engine(root, "web", "eng", "import json\n")
    f = tmp_path / "wl.txt"
    f.write_text("x")
    wl = assets.Asset(name="wl", kind="file", role="core", candidates=(str(f),), export=("CTF_ASSET_WL", "WL"))
    values, prepend = lanes.exports(root=root, python="/v/bin/python", environ={}, asset_items=[wl])
    assert values["CTF_PYTHON"] == "/v/bin/python"
    assert values["PYTHONPATH"].split(os.pathsep) == layout.sys_path(root)
    assert values["CTF_ASSET_WL"] == values["WL"] == str(f) and prepend == ["/v/bin"]


# ------------------------------------------------------------------------------------ the real tree

def test_real_lane_specs_name_real_lanes_images_and_assets():
    specs = lanes.load_specs()
    assert set(specs) <= set(layout.lanes())
    image_names = {i.name for i in images.load()}
    asset_names = {a.name for a in assets.load()}
    for s in specs.values():
        assert s.image is None or s.image in image_names, s
        assert set(s.assets) <= asset_names, s
    assert {"capstone", "lief", "pefile", "unicorn"} <= set(specs["binary"].modules)


def test_real_engine_files_resolve_for_every_lane():
    for lane in layout.lanes():
        files = lanes.engine_files(lane)
        assert files and all(f.is_file() and f.suffix == ".py" for f in files), lane


def test_cli_envcheck_on_a_synthetic_lane(tmp_path):
    root = mk_root(tmp_path)
    engine(root, "web", "eng", f"import {NOPE}\n")
    r = subprocess.run([sys.executable, "-m", "ctf", "toolchain", "--root", str(root), "envcheck", "web", "--no-pins"],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and f"MISSING  module {NOPE}" in r.stdout and "ENVCHECK MISSING" in r.stdout
    write(root / "solvers" / "web" / "eng.py", "import json\n")
    r = subprocess.run([sys.executable, "-m", "ctf", "toolchain", "--root", str(root), "envcheck", "web", "--no-pins"],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "ENVCHECK OK" in r.stdout, r.stdout + r.stderr
    r = subprocess.run([sys.executable, "-m", "ctf", "toolchain", "--root", str(root), "envcheck", "nope"],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 2 and "unknown lane" in r.stderr
