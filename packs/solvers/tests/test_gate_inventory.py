"""B-195: the content-hash incremental inventory (ctf/gate/inventory.py)."""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from ctf.gate.inventory import ContentHashes, Inventory


def test_hashes_are_sha256_and_reused_until_the_file_changes(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"one")
    store = tmp_path / "state" / "hashes.json"
    h = ContentHashes(store)
    assert h.sha(f) == hashlib.sha256(b"one").hexdigest()
    assert h.hashed == 1
    h.save()
    h2 = ContentHashes(store)                      # a later run: stat unchanged -> no read
    assert h2.sha(f) == hashlib.sha256(b"one").hexdigest()
    assert (h2.hashed, h2.reused) == (0, 1)
    f.write_bytes(b"two")                          # same size, new content
    st = os.stat(f)
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    h3 = ContentHashes(store)
    assert h3.sha(f) == hashlib.sha256(b"two").hexdigest()
    assert h3.hashed == 1


def test_a_stale_stat_signature_never_returns_the_old_hash(tmp_path):
    """The stored signature includes ctime, which a rewrite always moves, so restoring the mtime after a
    rewrite (a checkout tool, an editor) cannot fake a match."""
    f = tmp_path / "a.txt"
    f.write_bytes(b"AAAA")
    store = tmp_path / "hashes.json"
    h = ContentHashes(store)
    h.sha(f)
    h.save()
    st = os.stat(f)
    f.write_bytes(b"BBBB")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))     # same size, same mtime, new bytes
    assert ContentHashes(store).sha(f) == hashlib.sha256(b"BBBB").hexdigest()


def test_missing_file_has_no_hash(tmp_path):
    assert ContentHashes(tmp_path / "h.json").sha(tmp_path / "nope") is None


def test_inventory_recomputes_only_changed_keys_and_drops_removed(tmp_path):
    calls = []

    def compute(key):
        calls.append(key)
        return {"v": key.upper()}

    path = tmp_path / "inv.json"
    inv = Inventory(path, "v1")
    s = inv.refresh({"a": "h1", "b": "h2"}, compute)
    assert (s.computed, s.reused, s.removed, s.total) == (2, 0, 0, 2)
    inv.save()
    inv = Inventory(path, "v1")
    calls.clear()
    s = inv.refresh({"a": "h1", "b": "h2-new", "c": "h3"}, compute)
    assert sorted(calls) == ["b", "c"]
    assert (s.computed, s.reused, s.removed) == (2, 1, 0)
    assert inv.get("b") == {"v": "B"}
    s = inv.refresh({"c": "h3"}, compute)
    assert (s.removed, s.total) == (2, 1) and "a" not in inv


def test_inventory_rebuilds_a_corrupt_or_old_file_and_says_so(tmp_path):
    path = tmp_path / "inv.json"
    path.write_text("{not json")
    inv = Inventory(path, "v1")
    assert "unreadable" in inv.stats.rebuilt
    s = inv.refresh({"a": "h"}, lambda k: 1)
    assert s.computed == 1 and s.rebuilt
    inv.save()
    other = Inventory(path, "v2")                  # a new parser version never reuses old values
    assert "format version" in other.stats.rebuilt
    assert other.refresh({"a": "h"}, lambda k: 2).computed == 1


def test_inventory_refuses_an_item_without_a_hash(tmp_path):
    with pytest.raises(ValueError, match="no content hash"):
        Inventory(tmp_path / "i.json", "v1").refresh({"a": None}, lambda k: 1)


def test_saved_file_is_complete_json_and_no_temp_left(tmp_path):
    path = tmp_path / "d" / "inv.json"
    inv = Inventory(path, "v1")
    inv.refresh({"k": "h"}, lambda k: [1, 2])
    inv.save()
    d = json.loads(path.read_text())
    assert d == {"version": "v1", "entries": {"k": ["h", [1, 2]]}}
    assert [p.name for p in path.parent.iterdir()] == ["inv.json"]
