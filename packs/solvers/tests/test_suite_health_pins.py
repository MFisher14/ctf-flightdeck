"""SH-02: the chain, crypto, math and web-auth test imports are pinned, installed and locked.

Checkpoint 0 found the carried CSCTF hardening tests listed in MODULES failing collection: they import
packages (eth_utils, eth_abi, rlp, solders, bip32, antlr4, cbor2, pycipher, scipy, jwcrypto, and behind
those eth_keys, eth_account, eth_keyfile, mnemonic, python-bitcoinlib, pyevmasm, solidity_parser) that no
requirements file pinned. This test fails when:

  * one of the modules is missing, or a third-party package it (or an engine it imports) uses is not
    installed, not pinned in requirements.in, or pinned at another version than .venv has;
  * an SH-02 pin disagrees between requirements.in, requirements.txt, requirements.lock.txt and .venv;
  * the lock misses a package in the dependency closure of an SH-02 pin, or locks it at another version;
  * the modules do not collect (one subprocess `pytest --collect-only`).

The import and pin checkers are B-240's (tests/test_carry_checklist.py), reused rather than copied; the
closure checker is tested on synthetic data at the end.
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

# The module keys from the SH-02 brief: the CSCTF hardening tests whose imports were never pinned.
MODULE_PATTERNS = ("test_chain2_*.py", "test_harden_chain_*.py", "test_harden_r3chain_*.py",
                   "test_harden_classical_*.py", "test_harden_compress_chain_formats.py",
                   "test_harden_dbwp_webauth.py", "test_harden_ml_*.py", "test_harden_webauth2_oracles.py",
                   "test_webauth_webauthn.py")
# What the brief's globs matched when SH-02 was built; a module disappearing fails the test.
EXPECTED_MODULE_COUNT = 27

# The pins SH-02 owns (requirements.in, requirements.txt, requirements.lock.txt and .venv agree on each),
# with what imports them.
SH02_PINS = {
    "antlr4-python3-runtime": "4.9.3",   # test_harden_chain_evm (solidity lexer)
    "bip32": "5.0.0",                    # test_harden_chain_wallet
    "cbor2": "6.2.0.post2",              # test_harden_chain_blockchain_reports, _dbwp_webauth, webauth_webauthn
    "eth-abi": "6.0.0",                  # chain2_evm_formats engine, the chain/r3chain/compress tests
    "eth-account": "0.14.0",             # test_harden_chain_wallet
    "eth-hash": "0.8.0",                 # test_harden_chain_abi, _core, _wallet
    "eth-keyfile": "0.10.0",             # test_harden_chain_wallet
    "eth-keys": "0.8.0",                 # test_harden_chain_core, _wallet
    "eth-utils": "6.0.0",                # chain2/chain/r3chain/compress tests
    "jwcrypto": "1.6.1",                 # test_harden_webauth2_oracles
    "lxml": "6.1.3",                     # test_harden_dbwp_webauth
    "mnemonic": "0.21",                  # test_harden_chain_wallet
    "pycipher": "0.5.2",                 # test_harden_classical_common, _recovery, _toolkit
    "pyelftools": "0.33",                # test_harden_ml_dl_runtime
    "pyevmasm": "0.2.3",                 # test_harden_chain_blockchain_reports, _evm
    "python-bitcoinlib": "0.12.2",       # test_harden_chain_wallet
    "pyzipper": "0.4.0",                 # archive_passwords / archive_expand, reached from these tests
    "rlp": "5.0.0",                      # chain2/chain/r3chain evm-format tests
    "scipy": "1.18.1",                   # test_harden_classical_stats, ml integrity/vector-store tests
    "solders": "0.29.0",                 # test_harden_chain_multichain, _r3chain_solana_idl
    "solidity-parser": "0.1.1",          # test_harden_chain_evm
}


def target_modules(root: Path) -> list:
    found = set()
    for pat in MODULE_PATTERNS:
        found |= {p.relative_to(root).as_posix() for p in (root / "tests").glob(pat)}
    return sorted(found)


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


# ============================================================================================= the real tree
def test_the_brief_modules_are_all_present():
    mods = target_modules(ROOT)
    assert len(mods) == EXPECTED_MODULE_COUNT, mods


@pytest.mark.parametrize("rel", target_modules(ROOT))
def test_module_and_its_engines_import_only_pinned_packages(rel):
    problems = {f: unpinned(ROOT, f) for f in [rel] + engine_files(ROOT, rel)}
    assert not {f: p for f, p in problems.items() if p}, problems


@pytest.mark.parametrize("dist", sorted(SH02_PINS))
def test_sh02_pin_agrees_everywhere(dist):
    ver = SH02_PINS[dist]
    for name in ("requirements.in", "requirements.txt", "requirements.lock.txt"):
        assert read_pins(ROOT / name).get(_canon(dist)) == ver, f"{name}: {dist} must be =={ver}"
    assert md.version(dist) == ver, f".venv has {dist}=={md.version(dist)}, pinned {ver}"


def test_lock_holds_the_dependency_closure_of_the_sh02_pins():
    names = closure(SH02_PINS, requires_of)
    assert names >= {_canon(d) for d in SH02_PINS}
    assert not lock_gaps(names, read_pins(ROOT / "requirements.lock.txt"), md.version)


@pytest.mark.slow
def test_the_brief_modules_collect(tmp_path):
    mods = target_modules(ROOT)
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
    # eth-utils 6.0.0: plain eth-hash/eth-typing/pydantic, cytoolz only on CPython, toolz only on PyPy,
    # and dev/docs/test extras (pytest, sphinx, tox, ...) that a plain install never pulls in
    got = {_canon(r) for r in requires_of("eth-utils")}
    assert got == {"eth-hash", "eth-typing", "pydantic", "cytoolz"}, got


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


def test_unpinned_catches_a_package_missing_from_requirements_in(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "requirements.in").write_text(f"pytest=={md.version('pytest')}\n")
    (root / "tests/test_y.py").write_text("import pytest\nimport cbor2\nimport sh02_absent_pkg_xyz\n")
    got = unpinned(root, "tests/test_y.py")
    assert any(g.startswith("cbor2: cbor2==") and "not pinned" in g for g in got), got
    assert any(g.startswith("sh02_absent_pkg_xyz: imported but no installed distribution") for g in got), got
    assert not any(g.startswith("pytest") for g in got), got
