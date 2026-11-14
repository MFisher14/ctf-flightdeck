"""solvers/common/_shadowed.py and the callers R-10 moved onto it: a shared basename loads the intended
file whichever folder a flat import would pick (docs/coverage/duplicate-basenames.toml)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import paths

SHADOWED = paths.repo_root() / "solvers" / "common" / "_shadowed.py"


@pytest.fixture
def sh():
    spec = importlib.util.spec_from_file_location("r10_shadowed_under_test", SHADOWED)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def two_copies(tmp_path, monkeypatch):
    for lane, tag in (("first", "FIRST"), ("second", "SECOND")):
        d = tmp_path / lane
        d.mkdir()
        (d / "r10twin.py").write_text(f"WHO = {tag!r}\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path / "second"))
    monkeypatch.syspath_prepend(str(tmp_path / "first"))        # "first" wins a flat import
    for k in ("r10twin", "second_twin"):
        monkeypatch.delitem(sys.modules, k, raising=False)
    yield tmp_path
    for k in ("r10twin", "second_twin"):
        sys.modules.pop(k, None)


def test_module_at_loads_the_named_file_when_the_flat_name_is_another(sh, two_copies):
    import r10twin
    assert r10twin.WHO == "FIRST"
    got = sh.module_at(two_copies / "second" / "r10twin.py", "second_twin")
    assert got.WHO == "SECOND" and got is not r10twin
    assert sys.modules["second_twin"] is got
    assert sh.module_at(two_copies / "second" / "r10twin.py", "second_twin") is got     # cached


def test_module_at_reuses_the_module_already_imported_for_that_file(sh, two_copies):
    import r10twin
    assert sh.module_at(two_copies / "first" / "r10twin.py", "first_alias") is r10twin
    assert "first_alias" not in sys.modules


def test_module_at_fails_loudly(sh, tmp_path):
    with pytest.raises(ModuleNotFoundError, match="nope.py"):
        sh.module_at(tmp_path / "nope.py", "r10_nope")
    bad = tmp_path / "bad.py"
    bad.write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="boom"):
        sh.module_at(bad, "r10_bad")
    assert "r10_bad" not in sys.modules                          # no half-initialised module left behind


def test_common_module_names_solvers_common(sh):
    mod = sh.common_module("modern_crypto")
    assert Path(mod.__file__).resolve() == (paths.repo_root() / "solvers/common/modern_crypto.py").resolve()
    assert hasattr(mod, "ecdsa_nonce_reuse")


PROBE = r"""
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from ctf.engines import layout
sys.path[:0] = layout.sys_path(root)        # the engine sys.path: toolkits before common, script-analysis before binary
flat = __import__("modern_crypto").__file__  # before any engine edits sys.path
flat_cl = __import__("classical").__file__
import crypto_faults, crypto_malleability, rsa_attacks, oracle_aead, codec_classical, structural_recover
import crib_decode
import exotic, transposition, formats_more
out = {
    "crypto_faults": crypto_faults.modern_crypto.__file__,
    "crypto_malleability": crypto_malleability.modern_crypto.__file__,
    "rsa_attacks": rsa_attacks._mc.__file__,
    "oracle_aead": oracle_aead._modern.__file__,
    "codec_classical": codec_classical.K.__file__,
    "crib_decode": crib_decode.K.__file__,
    "exotic": exotic.K.__file__,
    "transposition": transposition.K.__file__,
    "formats_more": formats_more.K.__file__,
    "flat_classical": flat_cl,
    "structural_recover": structural_recover.generic.__file__,
    "flat_modern_crypto": flat,
}
print(json.dumps(out))
"""


def test_fixed_callers_get_the_intended_file_on_the_engine_sys_path():
    root = paths.repo_root()
    r = subprocess.run([sys.executable, "-I", "-c", PROBE, str(root)], capture_output=True, text=True,
                       timeout=120, cwd=str(root / "tests"))
    assert r.returncode == 0, r.stderr[-2000:]
    got = {k: Path(v).resolve().relative_to(root.resolve()).as_posix() for k, v in json.loads(r.stdout).items()}
    assert got["flat_modern_crypto"] == "solvers/toolkits/modern_crypto.py"       # the hazard is real
    for k in ("crypto_faults", "crypto_malleability", "rsa_attacks", "oracle_aead"):
        assert got[k] == "solvers/common/modern_crypto.py", (k, got[k])
    assert got["codec_classical"] == "solvers/common/classical.py"
    assert got["crib_decode"] == "solvers/common/classical.py"
    assert got["flat_classical"] == "solvers/toolkits/classical.py"             # the hazard is real here too
    for k in ("exotic", "transposition", "formats_more"):                        # R-10 round 1
        assert got[k] == "solvers/common/classical.py", (k, got[k])
    assert got["structural_recover"] == "solvers/binary/generic.py"
