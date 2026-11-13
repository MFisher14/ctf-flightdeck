"""Unit tests for the OT corpus fetcher (B-204), with no network.

They prove the operator-step guarantees: a row is pinned only with a 40-hex commit and a sha256; the
fetcher refuses to write under the read-only source corpus (paths.DEFAULT_REALDATA); the public-fetch
is gated by rules.public_fetch_allow; --check makes no request; a fetched file whose sha256 differs is
not kept; and SOURCES.md records the licence. http_get is monkeypatched: no socket is opened.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "real"))
import event_pin  # noqa: E402

event_pin.pin(globals(), "csctf")

import fetch_ot  # noqa: E402
from ctf import scope  # noqa: E402

GOOD_REV = "0" * 40
BYTES = b"\xd4\xc3\xb2\xa1 synthetic capture bytes"
DIGEST = hashlib.sha256(BYTES).hexdigest()


def test_is_pinned_requires_commit_and_sha():
    assert fetch_ot.is_pinned({"rev": GOOD_REV, "sha256": DIGEST})[0] is True
    assert fetch_ot.is_pinned({"rev": "", "sha256": DIGEST})[0] is False
    assert fetch_ot.is_pinned({"rev": "main", "sha256": DIGEST})[0] is False  # branch, not a commit
    assert fetch_ot.is_pinned({"rev": GOOD_REV, "sha256": ""})[0] is False


def test_path_of_is_under_ot_proto(tmp_path):
    p = fetch_ot.path_of({"proto": "modbus", "name": "modbus.pcap"}, tmp_path)
    assert p == tmp_path / "ot" / "modbus" / "modbus.pcap"


def test_writable_root_refuses_default_realdata(monkeypatch):
    forbidden = fetch_ot.default_realdata()
    monkeypatch.setenv("CTF_REALDATA", str(forbidden))
    with pytest.raises(SystemExit) as exc:
        fetch_ot.writable_root()
    assert "DEFAULT_REALDATA" in str(exc.value)


def test_writable_root_refuses_subpath_of_default_realdata(monkeypatch):
    forbidden = fetch_ot.default_realdata()
    monkeypatch.setenv("CTF_REALDATA", str(forbidden / "ot"))
    with pytest.raises(SystemExit):
        fetch_ot.writable_root()


def test_writable_root_accepts_a_cache_outside_the_repo(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path))
    assert fetch_ot.writable_root().expanduser().resolve() == tmp_path.resolve()


def test_check_refuses_fetch_when_profile_does_not_allow_mirror():
    # csctf ships no rules.public_fetch_allow, so the raw mirror host is refused by name
    with pytest.raises(scope.OutOfScope) as exc:
        fetch_ot.check_fetch_allowed()
    assert fetch_ot.RAW_HOST in str(exc.value)


def test_check_mode_makes_no_request_and_reports_unpinned(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path))
    monkeypatch.setattr(fetch_ot, "http_get", lambda url: pytest.fail("network in --check"))
    rc = fetch_ot.main(["--check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "UNPINNED" in out  # every shipped row has an empty rev until the operator pins it
    assert "FETCH_OT" in out


def _one_row_manifest(sha):
    return {"files": [{"proto": "modbus", "name": "modbus.pcap", "github": "x/y", "rev": GOOD_REV,
                       "path": "M/modbus.pcap", "sha256": sha, "licence": "CC0", "engine": "ics_capture",
                       "note": "unit"}], "missing": []}


def test_fetch_writes_a_matching_file_and_sources(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path))
    monkeypatch.setattr(fetch_ot, "load", lambda: _one_row_manifest(DIGEST))
    monkeypatch.setattr(fetch_ot, "check_fetch_allowed", lambda: None)
    monkeypatch.setattr(fetch_ot, "http_get", lambda url: BYTES)
    rc = fetch_ot.main([])
    assert rc == 0
    dest = tmp_path / "ot" / "modbus" / "modbus.pcap"
    assert dest.read_bytes() == BYTES
    sources = (tmp_path / "ot" / "modbus" / "SOURCES.md").read_text()
    assert "CC0" in sources and "sha256" in sources


def test_fetch_discards_a_hash_mismatch(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path))
    wrong = "f" * 64
    monkeypatch.setattr(fetch_ot, "load", lambda: _one_row_manifest(wrong))
    monkeypatch.setattr(fetch_ot, "check_fetch_allowed", lambda: None)
    monkeypatch.setattr(fetch_ot, "http_get", lambda url: BYTES)
    rc = fetch_ot.main([])
    assert rc == 1  # a mismatch is a bad row
    assert not (tmp_path / "ot" / "modbus" / "modbus.pcap").exists()


def test_manifest_on_disk_is_valid_and_unpinned():
    doc = json.loads((Path(fetch_ot.__file__).parent / "manifest_ot.json").read_text())
    assert doc["files"], "manifest lists no protocols"
    for row in doc["files"]:
        for key in ("proto", "name", "engine", "expect", "licence"):
            assert key in row, f"row {row.get('proto')} missing {key}"
        # ships unpinned: the operator pins rev + sha256 at fetch time
        assert not fetch_ot.is_pinned(row)[0]
