"""B-058: pyc-vs-source differential (solvers/binary/pyc_diff.py).

Every pyc here is built inside the test: by py_compile from a source the test writes (the host
interpreter's own magic), or as a hand-made header in front of junk bytes for the magics of other
interpreters. The source-hash oracle is importlib.util.source_hash for the host magic, the values a real
3.9, 3.11 and 3.14 interpreter printed for the pinned table below, and, when those interpreters are on
PATH, the interpreters themselves (needs_tool, so a missing one is reported as not run).
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import py_compile
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import event
from ctf.engines import manifest as _manifest
from ctf.engines import router
from ctf.intake import engines as E
from ctf.intake import guard as G
from ctf.result import SolverResult

import pyc_diff as PD

REPO = Path(__file__).resolve().parents[1]
CSCTF = event.load("csctf")
HOST_MAGIC = importlib.util.MAGIC_NUMBER
HOST_TAG = sys.implementation.cache_tag            # cpython-312
FLAG = "CSCTF{" + "0123456789abcdef" * 2 + "}"

CLEAN = b'import hashlib\n\ndef beacon(order_id):\n    return hashlib.sha256(b"x").digest()[:16]\n'
TROJAN = (b'import hashlib\n_PICK = 1\n\ndef beacon(order_id):\n    if order_id % 5 == 0:\n'
          b'        return b"secret-key-bytes"\n    return hashlib.sha256(b"x").digest()[:16]\n')

# source_hash values printed by real interpreters (importlib.util.source_hash, run by hand on 2026-11-12
# with /usr/bin/python3 3.9.6, python3.11 3.11.15 and python3.14 3.14.7): magic -> {source: hash}
SOURCES = (b"", b"abc", b"x = 1\n" * 100)
PINNED = {
    "610d0d0a": ("ac0bb7c83e5b1c5f", "361f0027dbc6db99", "7dde71cc2fe0a0ff"),   # 3.9  SipHash-2-4
    "a70d0d0a": ("738d9cd5d5e87f73", "c7af82e77c1da4f5", "16e01f325ed33127"),   # 3.11 SipHash-1-3
    "cb0d0d0a": ("baf18eedc9387a25", "a00f5731f8bafd32", "be65d4377b619aee"),   # 3.12
    "2b0e0d0a": ("61f5b7cb653a6aa4", "6e461bf6a5e97b4a", "7dd0c4cea5e6c00b"),   # 3.14
}


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))


def _magic(number: int) -> bytes:
    return number.to_bytes(2, "little") + b"\r\n"


def _hash_pyc(magic: bytes, stored_hash: bytes, *, checked: bool = False, body: bytes = b"\xe3junk") -> bytes:
    return magic + (3 if checked else 1).to_bytes(4, "little") + stored_hash + body


def _ts_pyc(magic: bytes, size: int, mtime: int = 0, body: bytes = b"\xe3junk") -> bytes:
    return magic + b"\0\0\0\0" + mtime.to_bytes(4, "little") + size.to_bytes(4, "little") + body


def _compiled(tmp_path: Path, source: bytes, mode=py_compile.PycInvalidationMode.UNCHECKED_HASH) -> bytes:
    """A real pyc of `source`, compiled by the host interpreter (our own synthetic source)."""
    work = tmp_path / "build"
    work.mkdir(exist_ok=True)
    src = work / "m.py"
    src.write_bytes(source)
    out = work / "m.pyc"
    py_compile.compile(str(src), cfile=str(out), doraise=True, invalidation_mode=mode)
    return out.read_bytes()


def _package(root: Path, name: str, pyc: bytes, source: bytes | None, tag: str = HOST_TAG) -> Path:
    cache = root / "__pycache__"
    cache.mkdir(parents=True, exist_ok=True)
    p = cache / f"{name}.{tag}.pyc"
    p.write_bytes(pyc)
    if source is not None:
        (root / f"{name}.py").write_bytes(source)
    return p


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data)
    return buf.getvalue()


def _layer(tmp_path, source_in_pyc: bytes, source_beside: bytes) -> bytes:
    """A Lambda layer zip: python/_authlog.py and its unchecked-hash pyc, built from source_in_pyc."""
    pyc = _compiled(tmp_path, source_in_pyc)
    return _zip({f"python/__pycache__/_authlog.{HOST_TAG}.pyc": pyc, "python/_authlog.py": source_beside})


# ------------------------------------------------------------------ SipHash and the source hash

def test_siphash24_matches_the_reference_vector():
    """SipHash paper, Appendix A: key 00..0f, message 00..0e."""
    k0 = int.from_bytes(bytes(range(8)), "little")
    k1 = int.from_bytes(bytes(range(8, 16)), "little")
    assert PD.siphash(k0, k1, bytes(range(15)), 2, 4) == 0xA129CA6149BE45E5


@pytest.mark.parametrize("length", list(range(0, 18)) + [63, 64, 65, 1000])
def test_source_hash_equals_importlib_for_the_host_magic(length):
    data = bytes((i * 37 + 11) & 0xFF for i in range(length))
    assert PD.source_hash(data, HOST_MAGIC) == importlib.util.source_hash(data)


@pytest.mark.parametrize("magic_hex", sorted(PINNED))
def test_source_hash_equals_what_each_interpreter_printed(magic_hex):
    magic = bytes.fromhex(magic_hex)
    assert [PD.source_hash(s, magic).hex() for s in SOURCES] == list(PINNED[magic_hex])


def _interpreter_hashes(exe: str) -> tuple[bytes, list[str]]:
    code = ("import importlib.util as u,sys;sys.stdout.write(u.MAGIC_NUMBER.hex()+'\\n');"
            "[sys.stdout.write(u.source_hash(bytes.fromhex(h)).hex()+'\\n') for h in sys.argv[1:]]")
    out = subprocess.run([exe, "-I", "-c", code, *[s.hex() for s in SOURCES]], capture_output=True, text=True,
                         check=True).stdout.split()
    return bytes.fromhex(out[0]), out[1:]


@pytest.mark.needs_tool("python3.11")
def test_source_hash_equals_a_live_python311():
    magic, hashes = _interpreter_hashes("python3.11")
    assert magic != HOST_MAGIC
    assert [PD.source_hash(s, magic).hex() for s in SOURCES] == hashes


@pytest.mark.needs_tool("python3.14")
def test_source_hash_equals_a_live_python314():
    magic, hashes = _interpreter_hashes("python3.14")
    assert magic != HOST_MAGIC
    assert [PD.source_hash(s, magic).hex() for s in SOURCES] == hashes


def test_hash_algorithm_switches_at_python_311():
    assert PD.hash_algorithm(_magic(3439)) == "siphash24"       # 3.10
    assert PD.hash_algorithm(_magic(3449)) == "siphash24"
    assert PD.hash_algorithm(_magic(3450)) == "siphash13"       # first 3.11 magic
    assert PD.hash_algorithm(_magic(3531)) == "siphash13"
    assert PD.hash_algorithm(_magic(3392)) == "siphash24"
    with pytest.raises(PD.PycDiffError, match="predates hash-based"):
        PD.hash_algorithm(_magic(3379))                          # 3.6
    with pytest.raises(PD.PycDiffError, match="not a pyc magic"):
        PD.source_hash(b"", b"\x00\x00\x00\x00")


def test_magic_version_header_size_and_tag_version():
    assert PD.magic_version(_magic(3531)) == "3.12"
    assert PD.magic_version(_magic(3425)) == "3.9"
    assert PD.magic_version(_magic(62211)) == "2.7"
    assert PD.magic_version(_magic(3519)) == "3.12 (pre-release magic 3519)"
    assert PD.magic_version(_magic(3700)) is None
    assert [PD.header_size(_magic(m)) for m in (3531, 3394, 3392, 3379, 3190, 3180, 62211)] == [16, 16, 16, 12, 12, 8, 8]
    assert PD.tag_version("cpython-312") == "3.12" and PD.tag_version("cpython-39") == "3.9"
    assert PD.tag_version("pypy310") is None and PD.tag_version(None) is None


def test_source_for_pairs_cache_and_legacy_names():
    assert PD.source_for("a/b/__pycache__/m.cpython-312.pyc") == "a/b/m.py"
    assert PD.source_for("__pycache__/m.cpython-312.opt-2.pyc") == "m.py"
    assert PD.source_for("pkg/m.pyc") == "pkg/m.py"
    assert PD.source_for("pkg/m.pyo") == "pkg/m.py"
    assert PD.source_for("pkg/m.py") is None
    assert PD.source_for("pkg/m.txt") is None


# ------------------------------------------------------------------ one pair

def test_unchecked_hash_pyc_built_from_another_source_is_a_mismatch(tmp_path):
    pyc = _compiled(tmp_path, TROJAN)
    verdict, method, version, magic_hex, flags, detail = PD.check_pair(f"m.{HOST_TAG}.pyc", pyc, CLEAN)
    assert (verdict, method, flags, magic_hex) == ("mismatch", "hash", 1, HOST_MAGIC.hex())
    assert "unchecked" in detail and importlib.util.source_hash(CLEAN).hex() in detail
    assert pyc[8:16].hex() in detail
    assert PD.check_pair(f"m.{HOST_TAG}.pyc", pyc, TROJAN)[0] == "match"


def test_checked_hash_pyc_is_compared_the_same_way(tmp_path):
    pyc = _compiled(tmp_path, TROJAN, py_compile.PycInvalidationMode.CHECKED_HASH)
    got = PD.check_pair("m.pyc", pyc, CLEAN)
    assert got[0] == "mismatch" and got[4] == 3 and "(checked)" in got[5]
    assert PD.check_pair("m.pyc", pyc, TROJAN)[:2] == ("match", "hash")


def test_timestamp_pyc_compares_the_source_size(tmp_path):
    pyc = _compiled(tmp_path, TROJAN, py_compile.PycInvalidationMode.TIMESTAMP)
    got = PD.check_pair("m.pyc", pyc, CLEAN)
    assert got[:2] == ("mismatch", "size") and f"header source size {len(TROJAN)}" in got[5]
    same_length = TROJAN.replace(b"_PICK = 1", b"_PICK = 2")
    ok = PD.check_pair("m.pyc", pyc, same_length)
    assert ok[:2] == ("match", "size") and "size only" in ok[5]


class _Sized:
    """A source whose length is past 2**32 without allocating it: check_pair reads only len() of a
    timestamp pyc's source."""

    def __init__(self, n: int):
        self.n = n

    def __len__(self):
        return self.n


def test_timestamp_size_is_taken_mod_2_to_the_32():
    huge = _Sized((1 << 32) + 10)             # CPython stores len & 0xFFFFFFFF in the 4-byte field
    got = PD.check_pair("m.pyc", _ts_pyc(_magic(3531), 10), huge)
    assert got[:2] == ("match", "size") and f"{(1 << 32) + 10} bytes, 10 mod 2**32" in got[5]
    off = PD.check_pair("m.pyc", _ts_pyc(_magic(3531), 11), huge)
    assert off[:2] == ("mismatch", "size") and "header source size 11" in off[5]
    with pytest.raises(OverflowError):        # the field cannot hold the unreduced length
        _ts_pyc(_magic(3531), (1 << 32) + 10)


@pytest.mark.parametrize("magic_hex", sorted(PINNED))
def test_other_interpreters_pycs_are_checked_without_that_interpreter(magic_hex):
    magic = bytes.fromhex(magic_hex)
    stored = bytes.fromhex(PINNED[magic_hex][1])                # the hash of b"abc"
    pyc = _hash_pyc(magic, stored)
    assert PD.check_pair("m.pyc", pyc, b"abc")[:2] == ("match", "hash")
    assert PD.check_pair("m.pyc", pyc, b"abd")[:2] == ("mismatch", "hash")


def test_a_cache_tag_that_disagrees_with_the_magic_is_a_mismatch():
    pyc = _hash_pyc(bytes.fromhex("a70d0d0a"), bytes.fromhex(PINNED["a70d0d0a"][1]))     # a 3.11 pyc
    got = PD.check_pair("m.cpython-312.pyc", pyc, b"abc")
    assert got[:2] == ("mismatch", "tag") and "3.12" in got[5] and "3.11" in got[5]
    assert PD.check_pair("m.cpython-311.pyc", pyc, b"abc")[0] == "match"


def test_malformed_and_unreadable_headers():
    reserved = _magic(3531) + (4).to_bytes(4, "little") + bytes(8)
    assert PD.check_pair("m.pyc", reserved, b"")[:2] == ("mismatch", "header")
    assert PD.check_pair("m.pyc", _magic(3531) + b"\x01\0\0\0", b"")[:2] == ("mismatch", "header")   # truncated
    assert PD.check_pair("m.pyc", b"MZ\x90\x00" + bytes(12), b"")[:2] == ("mismatch", "header")
    assert PD.check_pair("m.pyc", b"\xcb", b"")[:2] == ("mismatch", "header")


def test_headers_that_keep_no_size_or_hash_are_unverifiable_and_unknown_magics_never_claim_a_mismatch():
    py27 = _magic(62211) + (12345).to_bytes(4, "little") + b"c\0\0"
    assert PD.check_pair("m.pyc", py27, b"anything")[:2] == ("unverifiable", "none")
    unknown = _magic(3700)
    assert PD.check_pair("m.pyc", _hash_pyc(unknown, bytes(8)), b"abc")[:2] == ("unverifiable", "hash")
    right = PD.source_hash(b"abc", unknown)
    assert PD.check_pair("m.pyc", _hash_pyc(unknown, right), b"abc")[0] == "match"
    py36 = _magic(3379) + (0).to_bytes(4, "little") + (3).to_bytes(4, "little")
    assert PD.check_pair("m.pyc", py36, b"abc")[:2] == ("match", "size")
    assert PD.check_pair("m.pyc", py36, b"abcd")[:2] == ("mismatch", "size")


@pytest.mark.parametrize("number", [3700, 9999])
def test_unknown_magics_never_claim_a_timestamp_or_header_mismatch(number):
    """The 16-byte layout is only assumed for a magic no CPython line used (header_size maps
    3392-19999 to 16), so its size field and flags cannot confirm a mismatch."""
    unknown = _magic(number)
    got = PD.check_pair("m.pyc", _ts_pyc(unknown, 99), b"abc")
    assert got[:2] == ("unverifiable", "size") and f"magic {number} is no known CPython magic" in got[5]
    assert PD.check_pair("m.pyc", _ts_pyc(unknown, 3), b"abc")[:2] == ("match", "size")
    reserved = unknown + (4).to_bytes(4, "little") + bytes(8)
    assert PD.check_pair("m.pyc", reserved, b"")[:2] == ("unverifiable", "header")
    assert PD.check_pair("m.pyc", unknown + b"\1\0\0\0", b"")[:2] == ("unverifiable", "header")
    # the same shapes under a released magic are mismatches
    assert PD.check_pair("m.pyc", _ts_pyc(_magic(3531), 99), b"abc")[:2] == ("mismatch", "size")
    assert PD.check_pair("m.pyc", _magic(3531) + (4).to_bytes(4, "little") + bytes(8), b"")[0] == "mismatch"


def test_nothing_is_unmarshalled_imported_or_compiled(tmp_path, monkeypatch):
    """The payload after the header is junk here; touching it any way but as bytes would fail."""
    import builtins
    import marshal

    def refuse(*_a, **_k):
        raise AssertionError("pyc_diff must not load or compile code")

    root = tmp_path / "ch"
    _package(root / "pkg", "a", _hash_pyc(HOST_MAGIC, importlib.util.source_hash(b"x = 1\n")), b"x = 1\n")
    _package(root / "pkg", "b", _hash_pyc(HOST_MAGIC, bytes(8)), b"y = 2\n")
    monkeypatch.setattr(marshal, "loads", refuse)
    monkeypatch.setattr(builtins, "compile", refuse)
    monkeypatch.setattr(importlib.util, "source_hash", refuse)
    scan = PD.scan_path(root)
    assert sorted((c.pyc, c.verdict) for c in scan.checks) == [
        (f"pkg/__pycache__/a.{HOST_TAG}.pyc", "match"), (f"pkg/__pycache__/b.{HOST_TAG}.pyc", "mismatch")]


# ------------------------------------------------------------------ walking a handout

def test_folder_scan_pairs_reports_orphans_and_skips_ctf_git_recon_and_symlinks(tmp_path):
    root = tmp_path / "ch"
    good = _compiled(tmp_path, CLEAN)
    _package(root / "files" / "app", "ok", good, CLEAN)
    _package(root / "files" / "app", "bad", _compiled(tmp_path, TROJAN), CLEAN)
    _package(root / "files" / "app", "lonely", good, None)
    (root / "files" / "app" / "legacy.pyc").write_bytes(_ts_pyc(_magic(3531), 99))
    (root / "files" / "app" / "legacy.py").write_bytes(b"short\n")
    for hidden in (".ctf", ".git", "recon"):
        _package(root / hidden, "secret", _compiled(tmp_path, TROJAN), CLEAN)
    _package(root / "files" / "deep" / "recon", "nested", _compiled(tmp_path, TROJAN), CLEAN)   # recon below the top is read
    link = root / "files" / "linked"
    (link / "__pycache__").mkdir(parents=True)
    (link / "__pycache__" / f"s.{HOST_TAG}.pyc").symlink_to(root / "files" / "app" / "__pycache__" / f"bad.{HOST_TAG}.pyc")
    (link / "s.py").write_bytes(CLEAN)
    scan = PD.scan_path(root)
    verdicts = {c.pyc: c.verdict for c in scan.checks}
    assert verdicts == {
        f"files/app/__pycache__/ok.{HOST_TAG}.pyc": "match",
        f"files/app/__pycache__/bad.{HOST_TAG}.pyc": "mismatch",
        "files/app/legacy.pyc": "mismatch",
        f"files/deep/recon/__pycache__/nested.{HOST_TAG}.pyc": "mismatch",
    }
    assert scan.orphans == [f"files/app/__pycache__/lonely.{HOST_TAG}.pyc"]
    bad = next(c for c in scan.checks if c.pyc.endswith(f"bad.{HOST_TAG}.pyc"))
    assert bad.source == "files/app/bad.py" and bad.path == bad.pyc


def test_nested_layer_zips_report_only_the_trojaned_layer(tmp_path):
    """The Shadow-Dispatch shape: a handout zip of layer zips, one pyc swapped under a clean source."""
    layers = {f"bundle/layers/auth-utils-{i}.zip": _layer(tmp_path, CLEAN, CLEAN) for i in (1, 2, 3)}
    layers["bundle/layers/auth-utils-4.zip"] = _layer(tmp_path, TROJAN, CLEAN)
    layers["bundle/README.txt"] = b"no unauthorized changes"
    root = tmp_path / "ch"
    (root / "files").mkdir(parents=True)
    (root / "files" / "bundle.zip").write_bytes(_zip(layers))
    scan = PD.scan_path(root)
    bad = [c for c in scan.checks if c.verdict == "mismatch"]
    assert [c.pyc for c in bad] == [f"files/bundle.zip!bundle/layers/auth-utils-4.zip!python/__pycache__/_authlog.{HOST_TAG}.pyc"]
    assert bad[0].source == "files/bundle.zip!bundle/layers/auth-utils-4.zip!python/_authlog.py"
    assert bad[0].path == "files/bundle.zip"
    assert len([c for c in scan.checks if c.verdict == "match"]) == 1 and scan.repeats == 2
    assert "2 more pair(s) were the same bytes" in PD.summary(scan)


def test_an_archive_and_its_unpacked_copy_are_one_finding(tmp_path):
    layer = _layer(tmp_path, TROJAN, CLEAN)
    root = tmp_path / "ch"
    (root / "files").mkdir(parents=True)
    (root / "files" / "layer.zip").write_bytes(layer)
    unpacked = root / "unpacked" / "layer.zip.unpacked"
    with zipfile.ZipFile(io.BytesIO(layer)) as z:
        z.extractall(unpacked)
    scan = PD.scan_path(root)
    assert len(scan.checks) == 1 and scan.checks[0].verdict == "mismatch"
    assert scan.checks[0].also == [f"unpacked/layer.zip.unpacked/python/__pycache__/_authlog.{HOST_TAG}.pyc"]


def test_a_zip_found_by_magic_wheels_and_depth_limit(tmp_path, monkeypatch):
    root = tmp_path / "ch"
    root.mkdir()
    (root / "blob.bin").write_bytes(_layer(tmp_path, TROJAN, CLEAN))            # a zip without a zip name
    (root / "pkg.whl").write_bytes(_layer(tmp_path, TROJAN, TROJAN + b"#"))
    inner = _layer(tmp_path, TROJAN, CLEAN)
    (root / "deep.zip").write_bytes(_zip({"a.zip": _zip({"b.zip": inner})}))
    monkeypatch.setattr(PD, "MAX_DEPTH", 2)
    scan = PD.scan_path(root)
    labels = sorted(c.pyc.split("!")[0] for c in scan.checks if c.verdict == "mismatch")
    assert labels == ["blob.bin", "pkg.whl"]
    assert any("deep.zip!a.zip!b.zip: archive not opened (nesting over MAX_DEPTH=2)" in n for n in scan.notes)


def test_broken_and_encrypted_archives_are_named_in_the_notes(tmp_path):
    root = tmp_path / "ch"
    root.mkdir()
    (root / "broken.zip").write_bytes(b"PK\x03\x04 not really a zip")
    data = bytearray(_zip({f"__pycache__/m.{HOST_TAG}.pyc": _hash_pyc(HOST_MAGIC, bytes(8)), "m.py": b"x"}))
    # set the "encrypted" bit of the pyc member in its central directory entry
    cd = data.find(b"PK\x01\x02")
    data[cd + 8] |= 1
    (root / "locked.zip").write_bytes(bytes(data))
    scan = PD.scan_path(root)
    assert any(n.startswith("broken.zip: archive not read (BadZipFile") for n in scan.notes), scan.notes
    assert f"locked.zip!__pycache__/m.{HOST_TAG}.pyc: encrypted member, not read" in scan.notes
    assert not scan.checks and not scan.orphans
    assert scan.skipped == [f"locked.zip!__pycache__/m.{HOST_TAG}.pyc"] and scan.unopened == ["broken.zip"]
    assert not scan.complete


def _encrypt(zip_bytes: bytes, member: str) -> bytes:
    """Set the "encrypted" bit of one member in its central directory entry."""
    data = bytearray(zip_bytes)
    at = 0
    while True:
        cd = data.find(b"PK\x01\x02", at)
        assert cd >= 0, member
        n = int.from_bytes(data[cd + 28:cd + 30], "little")
        if data[cd + 46:cd + 46 + n].decode() == member:
            data[cd + 8] |= 1
            return bytes(data)
        at = cd + 4


def test_an_encrypted_source_or_nested_archive_is_named_not_orphaned(tmp_path):
    root = tmp_path / "ch"
    root.mkdir()
    pyc = _hash_pyc(HOST_MAGIC, importlib.util.source_hash(b"x"))
    (root / "src.zip").write_bytes(_encrypt(_zip({f"__pycache__/m.{HOST_TAG}.pyc": pyc, "m.py": b"x"}), "m.py"))
    (root / "outer.zip").write_bytes(_encrypt(_zip({"inner.zip": _layer(tmp_path, TROJAN, CLEAN)}), "inner.zip"))
    scan = PD.scan_path(root)
    assert not scan.checks and not scan.orphans
    assert scan.skipped == [f"src.zip!__pycache__/m.{HOST_TAG}.pyc"]
    assert f"src.zip!__pycache__/m.{HOST_TAG}.pyc: not checked (src.zip!m.py: encrypted member, not read)" in scan.notes
    assert scan.unopened == ["outer.zip!inner.zip"] and "outer.zip!inner.zip: encrypted member, not read" in scan.notes


def test_a_member_that_fails_its_crc_is_a_skipped_pair(tmp_path):
    pyc = _hash_pyc(HOST_MAGIC, importlib.util.source_hash(b"x"), body=b"\xe3" + b"Q" * 64)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"__pycache__/m.{HOST_TAG}.pyc", pyc)
        z.writestr("m.py", b"x")
    data = buf.getvalue().replace(b"Q" * 64, b"R" * 64)
    root = tmp_path / "ch"
    root.mkdir()
    (root / "crc.zip").write_bytes(data)
    scan = PD.scan_path(root)
    assert not scan.checks and scan.skipped == [f"crc.zip!__pycache__/m.{HOST_TAG}.pyc"]
    assert any(n.startswith(f"crc.zip!__pycache__/m.{HOST_TAG}.pyc: not read (BadZipFile") for n in scan.notes)


def test_the_read_budget_stops_the_scan_and_says_so(tmp_path, monkeypatch):
    root = tmp_path / "ch"
    _package(root, "a", _compiled(tmp_path, TROJAN), CLEAN)
    monkeypatch.setattr(PD, "MAX_TOTAL", 10)
    scan = PD.scan_path(root)
    assert not scan.checks
    assert scan.notes == ["stopped early: read budget MAX_TOTAL=10 bytes spent"]


def test_caps_on_pairs_sizes_files_and_repeated_members_are_named(tmp_path, monkeypatch):
    root = tmp_path / "ch"
    for name in ("a", "b", "c"):
        _package(root, name, _compiled(tmp_path, TROJAN + name.encode()), CLEAN)
    monkeypatch.setattr(PD, "MAX_PAIRS", 2)
    scan = PD.scan_path(root)
    assert len(scan.checks) == 2 and scan.notes == [f"__pycache__/c.{HOST_TAG}.pyc: not checked (over MAX_PAIRS=2)"]
    monkeypatch.setattr(PD, "MAX_PAIRS", 20_000)
    monkeypatch.setattr(PD, "MAX_PAIR_BYTES", len(CLEAN) - 1)
    scan = PD.scan_path(root)
    assert not scan.checks and len(scan.notes) == 3
    assert scan.notes[0].startswith(f"__pycache__/a.{HOST_TAG}.pyc: ") and "over MAX_PAIR_BYTES" in scan.notes[0]
    assert scan.skipped == [f"__pycache__/{n}.{HOST_TAG}.pyc" for n in "abc"]
    assert PD.solve(root, CSCTF).status == "unsure"
    monkeypatch.setattr(PD, "MAX_PAIR_BYTES", 32 << 20)
    monkeypatch.setattr(PD, "MAX_FILES", 2)
    scan = PD.scan_path(root)
    assert "more than MAX_FILES=2 files: the rest were not looked at" in scan.notes
    assert not scan.checks and not scan.orphans          # the first two files walked are a.py and b.py


def test_a_member_stored_twice_reads_the_first_copy_and_says_so(tmp_path):
    first = _compiled(tmp_path, TROJAN)
    buf = io.BytesIO()
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"__pycache__/m.{HOST_TAG}.pyc", first)
        z.writestr(f"__pycache__/m.{HOST_TAG}.pyc", _compiled(tmp_path, CLEAN))
        z.writestr("m.py", CLEAN)
    root = tmp_path / "ch"
    root.mkdir()
    (root / "dup.zip").write_bytes(buf.getvalue())
    scan = PD.scan_path(root)
    assert f"dup.zip!__pycache__/m.{HOST_TAG}.pyc: stored twice; the first copy is read" in scan.notes
    assert [c.verdict for c in scan.checks] == ["mismatch"]


def test_a_sibling_that_differs_only_in_case_pairs_and_an_exact_one_wins(tmp_path):
    """Read from a zip so the test does not depend on the file system's case sensitivity."""
    pyc = _hash_pyc(HOST_MAGIC, importlib.util.source_hash(b"exact"))
    root = tmp_path / "ch"
    root.mkdir()
    (root / "folded.zip").write_bytes(_zip({f"pkg/__pycache__/foo.{HOST_TAG}.pyc": pyc, "pkg/Foo.py": b"other"}))
    (root / "both.zip").write_bytes(_zip({f"__pycache__/foo.{HOST_TAG}.pyc": pyc, "Foo.py": b"other",
                                          "foo.py": b"exact"}))
    scan = PD.scan_path(root)
    got = sorted((c.pyc, c.source, c.verdict) for c in scan.checks)
    assert got == [(f"both.zip!__pycache__/foo.{HOST_TAG}.pyc", "both.zip!foo.py", "match"),
                   (f"folded.zip!pkg/__pycache__/foo.{HOST_TAG}.pyc", "folded.zip!pkg/Foo.py", "mismatch")]
    assert not scan.orphans


def test_optimized_pycs_pair_with_the_same_source(tmp_path):
    root = tmp_path / "ch"
    _package(root, "m", _compiled(tmp_path, CLEAN), CLEAN, tag=f"{HOST_TAG}.opt-2")
    scan = PD.scan_path(root)
    assert [(c.pyc, c.source, c.verdict) for c in scan.checks] == [
        (f"__pycache__/m.{HOST_TAG}.opt-2.pyc", "m.py", "match")]


def test_a_pyc_named_by_hand_finds_its_source(tmp_path):
    root = tmp_path / "pkg"
    p = _package(root, "m", _compiled(tmp_path, TROJAN), CLEAN)
    scan = PD.scan_path(p)
    assert [(c.pyc, c.source, c.verdict) for c in scan.checks] == [
        (f"__pycache__/m.{HOST_TAG}.pyc", "m.py", "mismatch")]


# ------------------------------------------------------------------ the contract entry

def _challenge(tmp_path, files: dict) -> Path:
    ch = tmp_path / "challenge"
    for name, body in files.items():
        p = ch / "files" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    (ch / "files").mkdir(parents=True, exist_ok=True)
    return ch


def test_solve_reports_mismatches_as_unsure_with_evidence(tmp_path):
    ch = _challenge(tmp_path, {"layer-1.zip": _layer(tmp_path, CLEAN, CLEAN),
                               "layer-2.zip": _layer(tmp_path, TROJAN, CLEAN)})
    r = PD.solve(ch, CSCTF)
    assert isinstance(r, SolverResult) and r.status == "unsure" and not r.flags and r.engine == PD.ENGINE
    assert [e.kind for e in r.evidence] == ["pyc-mismatch"]
    assert r.evidence[0].path == "files/layer-2.zip"
    assert r.evidence[0].detail.startswith(f"files/layer-2.zip!python/__pycache__/_authlog.{HOST_TAG}.pyc vs "
                                           "files/layer-2.zip!python/_authlog.py: hash-based (unchecked")
    assert "1 pyc(s) disagree" in r.notes and "checked 2 pyc/source pair(s): 1 match" in r.notes
    assert SolverResult.from_json(r.to_json()) == r


def test_solve_flag_text_in_a_mismatching_pyc_is_a_candidate_but_not_in_a_matching_one(tmp_path):
    flagged = TROJAN + f'KEY = "{FLAG}"\n'.encode()
    ch = _challenge(tmp_path, {"bad.zip": _layer(tmp_path, flagged, CLEAN)})
    r = PD.solve(ch, CSCTF)
    assert r.status == "candidate" and r.flags == (FLAG,)
    assert [e.kind for e in r.evidence] == ["pyc-mismatch", "match"]
    clean = _challenge(tmp_path / "c", {"ok.zip": _layer(tmp_path, flagged, flagged)})
    r2 = PD.solve(clean, CSCTF)
    assert r2.status == "none" and not r2.flags and "1 match" in r2.notes


def test_solve_none_unsure_and_blocked(tmp_path):
    empty = _challenge(tmp_path / "e", {"notes.txt": b"hello"})
    r = PD.solve(empty, CSCTF)
    assert r.status == "none" and r.notes == "no pyc with a sibling .py in the handout"
    py27 = _challenge(tmp_path / "o", {"m.pyc": _magic(62211) + bytes(4) + b"c", "m.py": b"print 1\n"})
    r = PD.solve(py27, CSCTF)
    assert r.status == "unsure" and "1 pair(s) could not be checked: files/m.pyc" in r.notes
    orphan = _challenge(tmp_path / "x", {"m.pyc": _compiled(tmp_path, CLEAN)})
    r = PD.solve(orphan, CSCTF)
    assert r.status == "none" and "1 pyc(s) with no sibling source (files/m.pyc)" in r.notes
    r = PD.solve(tmp_path / "missing", CSCTF)
    assert r.status == "blocked" and "not a folder" in r.notes


def test_solve_is_unsure_when_the_read_budget_cuts_the_scan_short(tmp_path, monkeypatch):
    ch = _challenge(tmp_path, {f"__pycache__/m.{HOST_TAG}.pyc": _hash_pyc(HOST_MAGIC, bytes(8)), "m.py": CLEAN})
    monkeypatch.setattr(PD, "MAX_TOTAL", 5)
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and not r.evidence
    assert "the scan was cut short (stopped early: read budget MAX_TOTAL=5 bytes spent)" in r.notes
    assert "no pyc with a sibling" not in r.notes
    monkeypatch.setattr(PD, "MAX_TOTAL", 1 << 30)              # with the budget the same handout mismatches
    full = PD.solve(ch, CSCTF)
    assert full.status == "unsure" and [e.kind for e in full.evidence] == ["pyc-mismatch"]


def test_solve_is_unsure_when_max_files_stops_the_walk(tmp_path, monkeypatch):
    ch = _challenge(tmp_path, {f"a{i}.py": b"x" for i in range(3)})
    monkeypatch.setattr(PD, "MAX_FILES", 2)
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and "more than MAX_FILES=2 files" in r.notes and "no pyc with a sibling" not in r.notes
    monkeypatch.setattr(PD, "MAX_FILES", 50_000)
    assert PD.solve(ch, CSCTF).status == "none"


def test_exactly_max_files_files_is_a_whole_walk(tmp_path, monkeypatch):
    """The boundary: a handout of exactly MAX_FILES files was seen whole, so it is not cut short."""
    ch = _challenge(tmp_path, {f"a{i}.py": b"x" for i in range(3)})
    monkeypatch.setattr(PD, "MAX_FILES", 3)
    scan = PD.scan_path(ch)
    assert scan.stopped is None and scan.complete
    r = PD.solve(ch, CSCTF)
    assert r.status == "none" and "MAX_FILES" not in r.notes


def test_solve_is_unsure_naming_pairs_over_max_pairs(tmp_path, monkeypatch):
    ok = _compiled(tmp_path, CLEAN)
    ch = _challenge(tmp_path, {f"__pycache__/a.{HOST_TAG}.pyc": ok, "a.py": CLEAN,
                               f"__pycache__/b.{HOST_TAG}.pyc": ok + b"\0", "b.py": CLEAN})
    monkeypatch.setattr(PD, "MAX_PAIRS", 1)
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and not r.evidence
    assert f"1 pair(s) were not read: files/__pycache__/b.{HOST_TAG}.pyc" in r.notes
    assert "checked 1 pyc/source pair(s): 1 match" in r.notes and "1 pair(s) not checked" in r.notes
    monkeypatch.setattr(PD, "MAX_PAIRS", 20_000)
    assert PD.solve(ch, CSCTF).status == "none"


def test_solve_is_unsure_for_an_encrypted_pyc_and_none_for_an_unopened_archive(tmp_path):
    pyc = _hash_pyc(HOST_MAGIC, importlib.util.source_hash(b"x"))
    locked = _encrypt(_zip({f"__pycache__/m.{HOST_TAG}.pyc": pyc, "m.py": b"x"}), f"__pycache__/m.{HOST_TAG}.pyc")
    r = PD.solve(_challenge(tmp_path / "l", {"locked.zip": locked}), CSCTF)
    assert r.status == "unsure" and f"were not read: files/locked.zip!__pycache__/m.{HOST_TAG}.pyc" in r.notes
    assert "no pyc with a sibling" not in r.notes
    r = PD.solve(_challenge(tmp_path / "b", {"broken.zip": b"PK\x03\x04 not really a zip"}), CSCTF)
    assert r.status == "none"
    assert r.notes.startswith("no pyc with a sibling .py in what could be read (1 archive(s) not opened); "
                              "files/broken.zip: archive not read (BadZipFile")


def _nest(inner: bytes, names: list[str]) -> bytes:
    """`inner` wrapped in one zip per name, innermost first: _nest(x, ["l1.zip", "l2.zip"]) holds l2.zip,
    which holds l1.zip, which is x."""
    for name in names:
        inner = _zip({name: inner})
    return inner


def test_solve_is_unsure_when_max_depth_keeps_a_trojaned_archive_shut(tmp_path, monkeypatch):
    """The default MAX_DEPTH=4 opens outer(1), l4(2), l3(3), l2(4) and leaves l1 shut: its trojaned pair is
    never seen, so the answer is unsure, never none."""
    deep = _nest(_layer(tmp_path, TROJAN, CLEAN), ["l1.zip", "l2.zip", "l3.zip", "l4.zip"])
    ch = _challenge(tmp_path, {"outer.zip": deep})
    assert PD.MAX_DEPTH == 4
    scan = PD.scan_path(ch / "files")
    assert not scan.checks and scan.capped == ["outer.zip!l4.zip!l3.zip!l2.zip!l1.zip"] and not scan.complete
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and not r.evidence
    assert ("1 archive(s) were kept shut by a cap or encryption, so their pairs were never seen: "
            "files/outer.zip!l4.zip!l3.zip!l2.zip!l1.zip") in r.notes
    assert "no pyc with a sibling" not in r.notes
    monkeypatch.setattr(PD, "MAX_DEPTH", 5)                     # one more level and the mismatch shows
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["pyc-mismatch"]


def test_solve_is_unsure_when_max_member_keeps_a_nested_archive_shut(tmp_path, monkeypatch):
    inner = _layer(tmp_path, CLEAN, CLEAN)                      # clean: only the cap can make it unsure
    ch = _challenge(tmp_path, {"outer.zip": _zip({"inner.zip": inner})})
    assert PD.solve(ch, CSCTF).status == "none"
    monkeypatch.setattr(PD, "MAX_MEMBER", len(inner) - 1)
    r = PD.solve(ch, CSCTF)
    assert r.status == "unsure" and "were never seen: files/outer.zip!inner.zip" in r.notes
    assert f"over MAX_MEMBER={len(inner) - 1}, not opened" in r.notes


def test_solve_is_unsure_for_an_encrypted_nested_archive_but_none_for_a_junk_one(tmp_path):
    clean = _layer(tmp_path, CLEAN, CLEAN)
    locked = _encrypt(_zip({"inner.zip": clean}), "inner.zip")
    r = PD.solve(_challenge(tmp_path / "l", {"outer.zip": locked}), CSCTF)
    assert r.status == "unsure" and "were never seen: files/outer.zip!inner.zip" in r.notes
    assert "files/outer.zip!inner.zip: encrypted member, not read" in r.notes
    # a member that is named like an archive but is not one hides no pairs: none, and named in the notes
    r = PD.solve(_challenge(tmp_path / "j", {"outer.zip": _zip({"inner.zip": b"just text, not a zip"})}), CSCTF)
    assert r.status == "none"
    assert "files/outer.zip!inner.zip: archive not read (BadZipFile" in r.notes


# ------------------------------------------------------------------ by hand

def test_cli_exit_codes_and_json(tmp_path, capsys):
    root = tmp_path / "ch"
    _package(root, "a", _compiled(tmp_path, CLEAN), CLEAN)
    assert PD.main([str(root)]) == 0
    assert capsys.readouterr().out == ""
    _package(root, "b", _compiled(tmp_path, TROJAN), CLEAN)
    assert PD.main([str(root), "--json"]) == 1
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(r["pyc"], r["verdict"]) for r in rows] == [(f"__pycache__/b.{HOST_TAG}.pyc", "mismatch")]
    assert PD.main([str(root), "--all"]) == 1
    assert len(capsys.readouterr().out.splitlines()) == 2
    assert PD.main([str(tmp_path / "nope")]) == 2


def test_the_documented_by_hand_command_runs(tmp_path):
    """The module docstring's `tools/ctfpy solvers/binary/pyc_diff.py <path>` (its cross-lane imports need
    the engine sys.path that ctfpy sets; a bare `python solvers/binary/pyc_diff.py` does not have it)."""
    assert "tools/ctfpy solvers/binary/pyc_diff.py <file-or-folder>" in PD.__doc__
    root = tmp_path / "ch"
    _package(root, "b", _compiled(tmp_path, TROJAN), CLEAN)
    env = dict(os.environ, CTF_PYTHON=sys.executable)
    run = subprocess.run([str(REPO / "tools" / "ctfpy"), "--no-ledger", str(REPO / "solvers" / "binary" / "pyc_diff.py"),
                          str(root), "--json"], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=300)
    assert run.returncode == 1, run.stderr[-800:]
    assert [json.loads(ln)["verdict"] for ln in run.stdout.splitlines()] == ["mismatch"]


# ------------------------------------------------------------------ manifest, routing and intake

def _mine():
    return [m for m in _manifest.discover() if m.id == PD.ENGINE]


def test_the_manifest_is_a_cheap_contract_engine_that_intake_runs_on_a_pyc():
    m = _manifest.load(REPO / "solvers" / "binary" / "pyc_diff.manifest.toml")
    assert m.id == PD.ENGINE and m.entry.kind == "function" and m.entry.function == "solve"
    assert m.cost_class == "cheap" and m.status == "active" and not m.needs_tools
    assert m.intake.select == "files" and m.intake.run == "challenge" and not m.intake.spawns
    assert "ext:.pyc" in m.intake.match


def test_the_router_sends_a_pyc_handout_here(tmp_path):
    ch = _challenge(tmp_path, {f"app/__pycache__/m.{HOST_TAG}.pyc": _compiled(tmp_path, CLEAN), "app/m.py": CLEAN})
    assert PD.ENGINE in [h.manifest.id for h in router.route("reverse", "", ch / "files")]
    assert PD.ENGINE in [h.manifest.id for h in router.route("misc", "the build had no unchecked-hash surprises")]
    plain = _challenge(tmp_path / "p", {"app/m.py": CLEAN})
    assert PD.ENGINE not in [h.manifest.id for h in router.route("reverse", "", plain / "files")]


def test_intake_plans_it_for_a_pyc_and_not_for_other_files(tmp_path):
    hook = G.Guard("hook", (), "test: audit hook only")
    ch = _challenge(tmp_path, {f"__pycache__/m.{HOST_TAG}.pyc": _compiled(tmp_path, CLEAN), "m.py": CLEAN})
    plan = E.plan(_mine(), "forensics", "", ch / "files", guard=hook)
    assert [j.engine for j in plan.jobs] == [PD.ENGINE] and plan.jobs[0].files == ()
    other = _challenge(tmp_path / "o", {"m.py": CLEAN})
    assert not E.plan(_mine(), "forensics", "", other / "files", guard=hook).jobs


def test_intake_runs_it_under_the_audit_hook_guard(tmp_path):
    """The real intake run: a child process under the Python audit hook (no network, no program started)."""
    hook = G.Guard("hook", (), "test: audit hook only")
    ch = _challenge(tmp_path, {"layer.zip": _layer(tmp_path, TROJAN, CLEAN)})
    unpacked = ch / "files" / "layer.zip.unpacked"            # what the sweep's member walk gives intake
    with zipfile.ZipFile(ch / "files" / "layer.zip") as z:
        z.extractall(unpacked)
    plan = E.plan(_mine(), "forensics", "", ch / "files", guard=hook)
    ctx = E.Context(challenge_dir=ch, folder=ch / "files", out_root=ch / "recon" / "engines", profile=CSCTF,
                    guard=hook, root=REPO, python=sys.executable, challenge_id="b058", record=False,
                    workdir=tmp_path / "work")
    run = E.run_job(plan.jobs[0], ctx, timeout=120)
    out = (ch / run.output).read_text()
    assert run.status == "ok" and run.result_status == "unsure", (run, (ch / run.errors).read_text()[-800:])
    result = json.loads([ln for ln in out.splitlines() if ln.strip()][-1])
    details = [e["detail"] for e in result["evidence"]]
    assert len(details) == 1 and details[0].startswith(f"files/layer.zip!python/__pycache__/_authlog.{HOST_TAG}.pyc")
    assert "the same pair also at files/layer.zip.unpacked/python/__pycache__" in details[0]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
