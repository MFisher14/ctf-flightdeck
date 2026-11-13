"""SH-03: the format and protocol test imports are pinned, installed and locked.

Checkpoint 0 found the 41 carried CSCTF test modules in MODULES failing collection, and two tests of
tests/test_harden_doc_email.py failing at runtime (it loads test_harden_doc_office.py, which imports docx),
on 27 packages no requirements file pinned (crccheck, reedsolo, pdf417gen, fontTools, psd_tools, docx,
wasmtime, bincopy, cantools, fdt, msal, redis, dns, pillow_heif, sqlglot, dissect.esedb, jawa, bson, hl7apy,
ishneholterlib, liblzfse, asterix, pyModeS, pydifact, google.transit, pynmea2, graphql). Behind those the
same modules, and the engines they import, use a second layer (xlrd, xlwt, pymodbus, pymysql, pg8000,
hyperframe, msgpack, intelhex, ubireader, texture2ddecoder, dissect.jffs/squashfs) and a few packages that
were installed but never pinned (lief, pefile, dnfile, mutf8). This test fails when:

  * one of the modules is missing, or a third-party package it (or an engine it imports) uses is not
    installed, not pinned in requirements.in, or pinned at another version than .venv has;
  * an SH-03 pin disagrees between requirements.in, requirements.txt, requirements.lock.txt and .venv;
  * the lock misses a package in the dependency closure of an SH-03 pin, or locks it at another version;
  * `bson` is provided by anything but the standalone bson package the wire-decode test is written against
    (pymongo ships a different `bson` module with no dumps/loads, and installs over the same directory);
  * the modules do not collect (one subprocess `pytest --collect-only`).

The import and pin checkers are B-240's (tests/test_carry_checklist.py), reused rather than copied; the
closure checkers are tested on synthetic data at the end.
"""
from __future__ import annotations

import ast
import importlib.metadata as md
import re
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from test_carry_checklist import ENGINE_DIRS, _canon, _child_env, _local_names, read_pins, unpinned

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

# The 41 module keys from the SH-03 brief (collection errors at checkpoint 0), with the package each one
# first failed on.
MODULES = {
    "tests/test_ff_iwork_inspect.py": "crccheck",
    "tests/test_harden_hashecc_checksums.py": "crccheck",
    "tests/test_harden_ics_protocols.py": "crccheck",
    "tests/test_harden_ics_scada.py": "crccheck",
    "tests/test_harden_rf_rf_demod_full.py": "crccheck",
    "tests/test_harden_rf_sdr_protocols.py": "crccheck",
    "tests/test_health2_scp.py": "crccheck",
    "tests/test_sec_gnss_nav.py": "crccheck",
    "tests/test_harden_barcode_matrix.py": "reedsolo",
    "tests/test_harden_barcode_qr.py": "reedsolo",
    "tests/test_harden_hashecc_rs.py": "reedsolo",
    "tests/test_harden_barcode_wrappers.py": "pdf417gen",
    "tests/test_ff_woff_inspect.py": "fontTools",
    "tests/test_harden_ff_media_fonts.py": "fontTools",
    "tests/test_ff_psd_inventory.py": "psd_tools",
    "tests/test_harden_doc_metadata.py": "docx",
    "tests/test_harden_doc_office.py": "docx",
    "tests/test_harden_binfmt_core.py": "wasmtime",
    "tests/test_harden_binfmt_reverse.py": "wasmtime",
    "tests/test_harden_binfmt_firmware.py": "bincopy",
    "tests/test_harden_bus_hardware_depth.py": "cantools",
    "tests/test_transport_can.py": "cantools",
    "tests/test_fwboot_inventory.py": "fdt",
    "tests/test_foridepth_cloudcache.py": "msal",
    "tests/test_harden_net_dbproto.py": "redis",
    "tests/test_harden_net_forensics.py": "dns",
    "tests/test_harden_net_network.py": "dns",
    "tests/test_harden_r3mob_messenger_media.py": "pillow_heif",
    "tests/test_harden_sqli_builders.py": "sqlglot",
    "tests/test_harden_winart_ese_reader.py": "dissect.esedb",
    "tests/test_harden_wire_java_deser.py": "jawa",
    "tests/test_harden_wire_wire_decode.py": "bson",
    "tests/test_health2_hl7.py": "hl7apy",
    "tests/test_health2_ishne.py": "ishneholterlib",
    "tests/test_mobile2_ios_media.py": "liblzfse",
    "tests/test_sec_airsurv_asterix.py": "asterix",
    "tests/test_sec_airsurv_modes.py": "pyModeS",
    "tests/test_transport_edifact.py": "pydifact",
    "tests/test_transport_gtfs.py": "google.transit",
    "tests/test_transport_nmea0183.py": "pynmea2",
    "tests/test_webdepth_graphql_cost.py": "graphql",
}
# The two runtime-failure keys live here (test_cfb_and_msg_vector_lock_against_olefile and
# test_valid_cfb_truncations_and_bitflips_fail_closed load test_harden_doc_office by path).
RUNTIME_MODULE = "tests/test_harden_doc_email.py"
EXPECTED_MODULE_COUNT = 41

# The pins SH-03 owns (requirements.in, requirements.txt, requirements.lock.txt and .venv agree on each),
# with what imports them. Versions are the ones the CSCTF .venv validated these tests against.
SH03_PINS = {
    "bincopy": "20.1.1",                 # test_harden_binfmt_firmware
    "bson": "0.5.10",                    # test_harden_wire_wire_decode (standalone bson: dumps/loads)
    "cantools": "45.1.2",                # test_harden_bus_hardware_depth, test_transport_can
    "cbor2": "6.2.0.post2",              # test_harden_wire_wire_decode (also an SH-02 pin)
    "crccheck": "1.3.1",                 # 8 modules (ICS, RF, GNSS, SCP, iWork, checksums)
    "dissect.esedb": "3.18",             # test_harden_winart_ese_reader, binfmt engines
    "dissect.jffs": "1.6",               # test_harden_binfmt_firmware
    "dissect.squashfs": "1.12",          # test_harden_binfmt_firmware
    "dnfile": "0.18.0",                  # test_harden_binfmt_reverse
    "dnspython": "2.9.2",                # test_harden_net_forensics, _network
    "fdt": "0.3.3",                      # test_fwboot_inventory, test_harden_binfmt_firmware
    "fonttools": "4.68.0",               # test_ff_woff_inspect, test_harden_ff_media_fonts
    "graphql-core": "3.3.1",             # test_webdepth_graphql_cost
    "gtfs-realtime-bindings": "3.0.0",   # test_transport_gtfs (google.transit)
    "hl7apy": "1.3.5",                   # test_health2_hl7 and its engine
    "hyperframe": "6.1.0",               # test_harden_net_forensics
    "intelhex": "2.3.0",                 # test_harden_binfmt_firmware
    "ishneholterlib": "2020.5.29",       # test_health2_ishne
    "jawa": "2.2.0",                     # test_harden_wire_java_deser, test_harden_binfmt_core
    "libasterix": "0.36.3",              # test_sec_airsurv_asterix (asterix)
    "lief": "1.0.0",                     # test_harden_binfmt_core
    "lxml": "6.1.3",                     # test_harden_sqli_builders (also an SH-02 pin)
    "msal": "1.39.0",                    # test_foridepth_cloudcache
    "msgpack": "1.2.4",                  # test_harden_wire_wire_decode
    "mutf8": "1.1.0",                    # test_harden_wire_java_deser
    "pdf417gen": "0.8.1",                # test_harden_barcode_wrappers, _matrix
    "pefile": "2024.8.26",               # test_harden_binfmt_core
    "pg8000": "1.31.6",                  # test_harden_net_dbproto
    "pillow-heif": "1.8.1",              # test_harden_r3mob_messenger_media, mobile2_ios_media engine
    "psd-tools": "1.26.0",               # test_ff_psd_inventory, test_harden_ff_media_fonts
    "pydifact": "0.2.3",                 # test_transport_edifact
    "pyelftools": "0.33",                # test_harden_binfmt_core, _reverse (also an SH-02 pin)
    "pyliblzfse": "0.4.1",               # test_mobile2_ios_media (liblzfse)
    "pymodbus": "3.16.2",                # test_harden_ics_protocols
    "pyModeS": "3.6.1",                  # test_sec_airsurv_modes
    "PyMySQL": "1.2.3",                  # test_harden_net_dbproto (pymysql)
    "pynmea2": "1.19.0",                 # test_transport_nmea0183
    "python-docx": "1.2.0",              # test_harden_doc_metadata, _office (and _email through _office)
    "redis": "8.1.0",                    # test_harden_net_dbproto
    "reedsolo": "1.7.0",                 # test_harden_barcode_matrix, _qr, test_harden_hashecc_rs
    "sqlglot": "30.29.0",                # test_harden_sqli_builders
    "texture2ddecoder": "1.0.6",         # mobile2_ios_media engine (ASTC decode)
    "ubi-reader": "0.8.16",              # test_harden_binfmt_firmware (ubireader)
    "wasmtime": "50.0.1",                # test_harden_binfmt_core, _reverse
    "xlrd": "2.0.2",                     # test_harden_doc_office
    "xlwt": "1.3.0",                     # test_harden_doc_office
}


def target_files(root: Path) -> list:
    return sorted(MODULES) + [RUNTIME_MODULE]


def engine_files(root: Path, rel: str) -> list:
    """Repo files of the local modules `rel` imports, resolved the way conftest's sys.path does."""
    tree = ast.parse((root / rel).read_text(errors="replace"))
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            names.add(n.module.split(".")[0])
    out = []
    for name in sorted(names & _local_names(root)):
        for d in reversed(ENGINE_DIRS):        # later ENGINE_DIRS entries are searched first
            cand = root / d / f"{name}.py"
            if cand.is_file():
                out.append(cand.relative_to(root).as_posix())
                break
    return out


def requires_of(dist: str) -> list:
    """Installed `dist`'s unconditional requirements (and those whose marker holds here), as dist names."""
    out = []
    for spec in md.requires(dist) or ():
        req = Requirement(spec)
        if req.marker is None or req.marker.evaluate({"extra": ""}):
            out.append(req.name)
    return out


def closure(roots, requires) -> set:
    """Canonical names of `roots` and everything they require, transitively (`requires(name) -> [names]`)."""
    seen, todo = set(), [_canon(r) for r in roots]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo += [_canon(r) for r in requires(name)]
    return seen


def lock_gaps(names, lock: dict, version_of) -> list:
    """Problems: a name the lock does not pin, or pins at a version other than `version_of(name)`."""
    out = []
    for name in sorted(names):
        have = version_of(name)
        if name not in lock:
            out.append(f"{name}=={have} is not in requirements.lock.txt")
        elif lock[name] != have:
            out.append(f"requirements.lock.txt pins {name}=={lock[name]}, .venv has {have}")
    return out


def bson_problems(providers: list, module) -> list:
    """Why the importable `bson` is not the standalone package test_harden_wire_wire_decode needs."""
    out = []
    if providers != ["bson"]:
        out.append(f"`bson` is provided by {providers}, expected only the standalone bson distribution "
                   "(pymongo's bson installs over it and has no dumps/loads)")
    missing = [n for n in ("dumps", "loads") if not callable(getattr(module, n, None))]
    if missing:
        out.append(f"the importable bson module lacks {missing}: not the standalone bson package")
    return out


# ============================================================================================= the real tree
def test_the_brief_modules_are_all_present():
    assert len(MODULES) == EXPECTED_MODULE_COUNT
    missing = [rel for rel in target_files(ROOT) if not (ROOT / rel).is_file()]
    assert not missing, missing


@pytest.mark.parametrize("rel", target_files(ROOT))
def test_module_and_its_engines_import_only_pinned_packages(rel):
    problems = {f: unpinned(ROOT, f) for f in [rel] + engine_files(ROOT, rel)}
    assert not {f: p for f, p in problems.items() if p}, problems


@pytest.mark.parametrize("dist", sorted(SH03_PINS))
def test_sh03_pin_agrees_everywhere(dist):
    ver = SH03_PINS[dist]
    for name in ("requirements.in", "requirements.txt", "requirements.lock.txt"):
        assert read_pins(ROOT / name).get(_canon(dist)) == ver, f"{name}: {dist} must be =={ver}"
    assert md.version(dist) == ver, f".venv has {dist}=={md.version(dist)}, pinned {ver}"


def test_lock_holds_the_dependency_closure_of_the_sh03_pins():
    names = closure(SH03_PINS, requires_of)
    assert names >= {_canon(d) for d in SH03_PINS}
    assert not lock_gaps(names, read_pins(ROOT / "requirements.lock.txt"), md.version)


def test_bson_is_the_standalone_package_not_pymongo():
    import bson
    assert not bson_problems(md.packages_distributions().get("bson"), bson)


@pytest.mark.slow
def test_the_brief_modules_collect(tmp_path):
    mods = target_files(ROOT)
    proc = subprocess.run([PY, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "no:xdist",
                           *mods], cwd=ROOT, env=_child_env(tmp_path), capture_output=True, text=True, timeout=600)
    text = proc.stdout + proc.stderr
    assert proc.returncode == 0, text[-3000:]
    assert not re.search(r"\b\d+ errors?\b|^ERROR ", text, re.M), text[-3000:]
    m = re.search(r"(\d+) tests? collected", text)
    assert m and int(m.group(1)) >= len(mods), text[-1500:]


# ============================================================================================= the checkers, tested
_GRAPH = {"a": ["b", "C_d"], "b": ["c-d"], "c-d": [], "lone": []}


def test_closure_follows_requirements_transitively_and_canonicalises():
    assert closure(["a"], lambda n: _GRAPH[n]) == {"a", "b", "c-d"}
    assert closure(["lone"], lambda n: _GRAPH[n]) == {"lone"}


def test_closure_terminates_on_a_cycle():
    graph = {"x": ["y"], "y": ["x"]}
    assert closure(["x"], lambda n: graph[n]) == {"x", "y"}


def test_lock_gaps_reports_missing_and_mismatched():
    versions = {"a": "1.0", "b": "2.0", "c": "3.0"}
    lock = {"a": "1.0", "b": "2.1"}
    assert lock_gaps({"a", "b", "c"}, lock, versions.__getitem__) == [
        "requirements.lock.txt pins b==2.1, .venv has 2.0", "c==3.0 is not in requirements.lock.txt"]
    assert lock_gaps({"a"}, lock, versions.__getitem__) == []


def test_requires_of_keeps_plain_and_true_marker_requirements_only():
    # cantools 45.1.2: plain bitstruct/python-can/textparser/argparse_addons/crccheck; diskcache, mypy,
    # matplotlib ... only under extras a plain install never pulls in
    got = {_canon(r) for r in requires_of("cantools")}
    assert got == {"bitstruct", "python-can", "textparser", "argparse-addons", "crccheck"}, got
    # pymodbus 3.16.2 declares only extras (serial, simulator, documentation, development, all)
    assert requires_of("pymodbus") == []


def test_engine_files_resolves_local_imports_to_engine_dirs(tmp_path):
    root = tmp_path / "repo"
    (root / "solvers" / "toolkits").mkdir(parents=True)
    (root / "solvers" / "web").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "solvers/toolkits/eng.py").write_text("import json\n")
    (root / "solvers/web/eng.py").write_text("import json\n")       # solvers/web is searched before toolkits
    (root / "solvers/toolkits/other.py").write_text("X = 1\n")
    (root / "tests/test_x.py").write_text("import eng\nfrom other import X\nimport numpy\n")
    assert engine_files(root, "tests/test_x.py") == ["solvers/web/eng.py", "solvers/toolkits/other.py"]


def test_unpinned_catches_an_unpinned_and_an_absent_package(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "requirements.in").write_text(f"pytest=={md.version('pytest')}\n")
    (root / "tests/test_y.py").write_text("import pytest\nimport crccheck\nimport sh03_absent_pkg_xyz\n")
    got = unpinned(root, "tests/test_y.py")
    assert any(g.startswith("crccheck: crccheck==") and "not pinned" in g for g in got), got
    assert any(g.startswith("sh03_absent_pkg_xyz: imported but no installed distribution") for g in got), got
    assert not any(g.startswith("pytest") for g in got), got


class _Mod:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


def test_bson_problems_names_pymongo_and_a_dumpsless_module():
    standalone = _Mod(dumps=lambda o: b"", loads=lambda b: {})
    pymongo_like = _Mod(encode=lambda o: b"", decode=lambda b: {})
    assert bson_problems(["bson"], standalone) == []
    both = bson_problems(["bson", "pymongo"], standalone)
    assert len(both) == 1 and "['bson', 'pymongo']" in both[0], both
    only_pymongo = bson_problems(["pymongo"], pymongo_like)
    assert len(only_pymongo) == 2 and "lacks ['dumps', 'loads']" in only_pymongo[1], only_pymongo
    assert len(bson_problems(None, standalone)) == 1
