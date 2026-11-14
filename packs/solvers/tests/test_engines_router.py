"""Routing from manifests (B-186): conditions, file matchers, ranking (R-10: one rank() for both
routers)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf import triage
from ctf.engines import manifest as M
from ctf.engines import router


def _eng(root: Path, lane: str, name: str, body: str):
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text("def solve(d, p): pass\n", encoding="utf-8")
    (d / f"{name}.manifest.toml").write_text(
        f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n' + body, encoding="utf-8")


@pytest.fixture
def root(tmp_path):
    _eng(tmp_path, "crypto", "rsa", '[[routes]]\ncategory = ["crypto"]\nkeywords = ["modulus"]\npriority = 70\n'
                                    '[[routes]]\ncategory = ["crypto"]\npriority = 30\n')
    _eng(tmp_path, "crypto", "pem", '[[routes]]\nfiles = ["magic:-----BEGIN PUBLIC KEY"]\npriority = 80\n')
    _eng(tmp_path, "net", "pcap", '[[routes]]\nkeywords = [" hci"]\nfiles = ["ext:.pcapng", "name:capture_*"]\n')
    _eng(tmp_path, "net", "old", 'status = "retired"\n[[routes]]\nkeywords = ["modulus"]\n')
    return tmp_path


def _ids(hits):
    return [h.manifest.id for h in hits]


def test_category_and_keyword_conditions_and_priority_order(root):
    assert _ids(router.route("Cryptography", "", root=root)) == ["crypto.rsa"]          # alias canonicalised
    hits = router.route("crypto", "Find the MODULUS", root=root)
    assert _ids(hits) == ["crypto.rsa"] and hits[0].priority == 70 and "modulus" in hits[0].reason
    assert router.route("web", "modulus", root=root) == []                               # category gate, retired skipped


def test_file_matchers_magic_ext_name(root, tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "key.txt").write_bytes(b"-----BEGIN PUBLIC KEY-----\nMII...")
    assert _ids(router.route("misc", "", files, root=root)) == ["crypto.pem"]
    # keyword AND file: both must hold
    (files / "dump.PCAPNG").write_bytes(b"\x0a\x0d\x0d\x0a")
    assert "net.pcap" not in _ids(router.route("misc", "", files, root=root))
    assert _ids(router.route("misc", "ble hci log", files, root=root)) == ["crypto.pem", "net.pcap"]
    (files / "dump.PCAPNG").unlink()
    (files / "capture_1.bin").write_bytes(b"x")
    assert "net.pcap" in _ids(router.route("misc", "ble hci log", files, root=root))


def test_a_match_all_route_never_matches(tmp_path):
    _eng(tmp_path, "x", "all", "[[routes]]\npriority = 99\n")
    assert router.route("crypto", "anything", root=tmp_path) == []


def test_hex_magic_matchers_match_bytes_not_their_spelling(tmp_path):
    """The generator writes non-printable magic as `magic:0x<hex>`: it must match the bytes."""
    _eng(tmp_path, "x", "dex", '[[routes]]\nfiles = ["magic:0x6465780a"]\npriority = 30\n')
    files = tmp_path / "files"
    files.mkdir()
    (files / "a").write_bytes(b"0x6465780a")                  # the spelling, not the bytes
    assert router.route("misc", "", files, root=tmp_path) == []
    (files / "b").write_bytes(b"dex\n035\x00")
    hits = router.route("misc", "", files, root=tmp_path)
    assert _ids(hits) == ["x.dex"] and "b starts with" in hits[0].reason
    assert router.magic_bytes("0x89504e47") == b"\x89PNG" and router.magic_bytes("%PDF-") == b"%PDF-"
    assert router.magic_bytes("0xabc") == b"0xabc"            # odd length: text, not hex


def test_rank_scores_an_entry_by_its_best_matching_route():
    lo = M.Route(category=("crypto",), priority=20)
    hi = M.Route(keywords=("rsa",), priority=70)
    ranked = router.rank([("b", [lo, hi]), ("a", [M.Route(category=("crypto",), priority=20)])],
                         "crypto", "an RSA key")
    assert [(k, p) for k, p, _ in ranked] == [("b", 70), ("a", 20)]
    ranked = router.rank([("b", [lo]), ("a", [M.Route(category=("crypto",), priority=20)])], "crypto")
    assert [k for k, _, _ in ranked] == ["a", "b"]           # equal priority: by key


def test_repo_routes_every_carried_category_engine():
    """Every category the triage playbooks know has at least one engine its manifests always suggest."""
    cats = {c for m in M.discover() for r in m.routes if not (r.keywords or r.files) for c in r.category}
    assert set(triage.CATEGORIES) <= cats, sorted(set(triage.CATEGORIES) - cats)
