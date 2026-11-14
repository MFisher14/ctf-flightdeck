"""Merge batch 904 route fixes. B-248's residual readers (metadata_forensics.readers_residuals) shipped with no
route, so triage never suggested them; it now routes the members of the formats it reads, as readers_longtail
does. B-085's WAL-wording route tied toolkits.sqlite_timetravel (B-075) on "wal file" at priority 61; it now
sits one below, so the general commit-timeline reader leads on that wording and both are still offered."""
from __future__ import annotations

from ctf.engines import router

RESIDUALS = "metadata_forensics.readers_residuals"


def _ids(hits):
    return [h.manifest.id for h in hits]


def test_a_member_of_a_residual_format_routes_to_the_residual_readers(tmp_path):
    for name in ("photo.heic", "scan.tiff", "bundle.a", "tool.obj"):
        folder = tmp_path / name.replace(".", "_")
        folder.mkdir()
        (folder / name).write_bytes(b"\x00" * 64)
        assert RESIDUALS in _ids(router.route("misc", "", folder)), name
    other = tmp_path / "other"
    other.mkdir()
    (other / "notes.txt").write_text("nothing here\n")
    assert RESIDUALS not in _ids(router.route("misc", "", other))


def test_the_wal_wording_leads_with_the_timeline_reader_and_still_offers_the_backup_engine():
    ids = _ids(router.route("forensics", "we got the database and wal file of the app"))
    assert "toolkits.sqlite_timetravel" in ids and "mobile_android.android_backup_sqlite" in ids
    assert ids.index("toolkits.sqlite_timetravel") < ids.index("mobile_android.android_backup_sqlite")
