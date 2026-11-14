"""B-075: SQLite WAL per-commit time travel (solvers/toolkits/sqlite_timetravel.py and the commit list
in sqlite_artifacts.Pages). Every database here is written by the sqlite3 library in a temp folder
(tests/sqlite_wal_fixtures.py); the library's own view after each commit is the ground truth."""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import sqlite3
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

import sqlite_artifacts as sa
import sqlite_timetravel as st
import sqlite_wal_fixtures as fx
from ctf import event, flagfmt
from ctf.engines import manifest as engine_manifest
from ctf.engines import router
from ctf.intake import engines as intake_engines
from ctf.intake import guard as intake_guard

REPO = Path(__file__).resolve().parents[1]
FF = flagfmt.for_profile(event.load("csctf"))
PROFILE = event.load("csctf")


@pytest.fixture(scope="module")
def reg(tmp_path_factory):
    """The land registry: five commits in the WAL, nothing checkpointed."""
    return fx.build(tmp_path_factory.mktemp("reg"))


@pytest.fixture(scope="module")
def tt(reg):
    return st.TimeTravel(reg.data, reg.wal, reg.shm, name="registry.db")


def as_state(tables: dict) -> dict:
    """{table: sorted rows} of read_tables() output, comparable with fixture states."""
    return {n: sorted(t.rows.values()) for n, t in tables.items()}


def want_state(state: dict) -> dict:
    return {n: sorted(tuple(r) for r in rows) for n, rows in state.items()}


def step_clock(step: float = 1.0):
    """A clock that moves `step` each time it is read (no wall time involved)."""
    counter = itertools.count()
    return lambda: next(counter) * step


# ---------------------------------------------------------------- the commit list (sqlite_artifacts.Pages)
def test_pages_list_each_commit_with_its_frames_pages_and_size(reg):
    pg = sa.Pages(reg.data, reg.wal)
    commits = pg.commits()
    assert [c["index"] for c in commits] == [1, 2, 3, 4, 5]
    # frames in order, one run per transaction, no gap and no overlap
    assert commits[0]["first"] == 0 and commits[-1]["last"] == len(pg.frames) - 1
    for a, b in zip(commits, commits[1:]):
        assert b["first"] == a["last"] + 1
    # commit 4 only touched the jobs table: a single frame for its one page
    assert commits[3]["first"] == commits[3]["last"]
    assert commits[3]["pages"] == [pg.frames[commits[3]["last"]]["page"]]
    for c in commits:
        assert c["pages"] == sorted({f["page"] for f in pg.frames[c["first"]:c["last"] + 1]})
        assert c["size"] == pg.frames[c["last"]]["commit"] == pg.count
    # a copy: changing it changes nothing inside
    commits[0]["pages"].append(999)
    assert 999 not in pg.commits()[0]["pages"]


def test_image_at_holds_the_frames_up_to_that_commit_only(reg):
    pg = sa.Pages(reg.data, reg.wal)
    assert pg.image_at(0) == {}
    for k, c in enumerate(pg.commits(), 1):
        want = {}
        for fr in pg.frames[:c["last"] + 1]:
            want[fr["page"]] = fr["data"]
        assert pg.image_at(k) == want
    assert pg.final == pg.image_at(5)
    for bad in (-1, 6, "2", 1.0, True):
        with pytest.raises(ValueError, match="commits 0 .* to 5"):
            pg.image_at(bad)
        with pytest.raises(ValueError):
            pg.size_at(bad)
    assert pg.size_at(0) == pg.count


def test_image_bytes_is_a_whole_database_that_the_library_reads_at_each_commit(reg):
    pg = sa.Pages(reg.data, reg.wal)
    for k in range(6):
        raw = pg.image_bytes(k)
        assert len(raw) == pg.size_at(k) * pg.page_size
        assert raw[18] == 2                          # every page byte as it is: the header still says WAL
        con = sqlite3.connect(":memory:")
        con.deserialize(st.standalone(raw))
        assert fx.dump(con) == reg.states[k]
        con.close()


def test_frames_carry_their_own_salt_and_checksums_and_the_checksum_is_the_wal_one(reg):
    pg = sa.Pages(reg.data, reg.wal)
    endian = "<" if reg.wal[:4] == bytes.fromhex("377f0682") else ">"
    assert pg.wal_endian == endian
    assert pg.wal_salt == struct.unpack_from(">II", reg.wal, 16)
    for fr in pg.frames:
        assert fr["salt"] == pg.wal_salt
        assert fr["sums"] == struct.unpack_from(">II", reg.wal, 32 + fr["frame"] * (24 + pg.page_size) + 16)
    data = os.urandom(64)
    for order in "<>":
        assert sa.wal_checksum(data, (5, 7), order) == fx._sum(data, (5, 7), order)
    assert sa.wal_checksum(data, (0, 0), "<") != sa.wal_checksum(data, (0, 0), ">")


def test_a_big_endian_wal_gives_the_same_commits(reg):
    flipped = fx.rebuild(reg.wal, big_endian=reg.wal[:4] != bytes.fromhex("377f0683"))
    a, b = sa.Pages(reg.data, reg.wal), sa.Pages(reg.data, flipped)
    assert a.wal_endian != b.wal_endian
    assert [(c["first"], c["last"], c["pages"]) for c in a.commits()] == \
           [(c["first"], c["last"], c["pages"]) for c in b.commits()]
    assert b.final == a.final


def test_frames_after_the_last_commit_frame_belong_to_no_commit(reg):
    frames = fx.frames_of(reg.wal)
    frames[-1][1] = 0                               # the last transaction never committed
    wal = fx.rebuild(reg.wal, frames)
    pg = sa.Pages(reg.data, wal)
    assert len(pg.commits()) == 4
    assert pg.final == pg.image_at(4)
    t = st.TimeTravel(reg.data, wal)
    assert t.uncommitted == 2                       # commit 5 wrote two frames
    assert as_state(t.snapshot("final").tables()) == want_state(reg.states[4])


def test_a_frame_with_a_bad_checksum_ends_the_valid_frames(reg):
    frames = fx.frames_of(reg.wal)
    wal = bytearray(fx.rebuild(reg.wal, frames))
    ps = struct.unpack_from(">I", wal, 8)[0]
    off = 32 + 6 * (24 + ps) + 24 + 200            # inside frame 6 (commit 4)
    wal[off] ^= 0xFF
    pg = sa.Pages(reg.data, bytes(wal))
    assert len(pg.commits()) == 3
    assert [f["valid"] for f in pg.frames] == [True] * 6 + [False] * 3


# ---------------------------------------------------------------- snapshots
def test_every_snapshot_is_the_database_the_library_saw_after_that_commit(reg, tt):
    assert len(tt.snapshots) == 6 and tt.stale == [] and tt.uncommitted == 0
    for k, s in enumerate(tt.snapshots):
        assert s.index == k and s.exact, s.note
        assert as_state(s.tables()) == want_state(reg.states[k])


def test_a_snapshot_image_opens_alone_and_names_its_size(tt, reg):
    img = tt.snapshot(3).image()
    assert img[18] == img[19] == 1                  # rollback-journal versions: opens with no WAL
    assert struct.unpack_from(">I", img, 28)[0] == tt.snapshot(3).size
    assert img[92:96] == img[24:28]
    raw = tt.snapshot(3).image(as_standalone=False)
    assert raw[18] == 2 and len(raw) == len(img)
    diff = [i for i in range(len(img)) if img[i] != raw[i]]
    assert set(diff) <= {18, 19} | set(range(28, 32)) | set(range(92, 96))
    con = sqlite3.connect(":memory:")
    con.deserialize(img)
    assert fx.dump(con) == reg.states[3]
    con.close()


def test_standalone_leaves_a_short_buffer_alone():
    assert st.standalone(b"x" * 50) == b"x" * 50


def test_snapshot_references(tt):
    assert tt.snapshot("base") is tt.snapshots[0]
    assert tt.snapshot("final") is tt.snapshots[-1]
    assert tt.snapshot(" 3 ") is tt.snapshots[3]
    assert tt.snapshot(2) is tt.snapshots[2]
    with pytest.raises(st.TimeTravelError, match="commits 0 to 5"):
        tt.snapshot("6")
    with pytest.raises(st.TimeTravelError, match="no commit 's1'"):
        tt.snapshot("s1")


def test_no_wal_or_an_unreadable_wal_is_a_named_error(reg):
    with pytest.raises(st.TimeTravelError, match="no WAL given"):
        st.TimeTravel(reg.data, b"")
    bad = bytearray(reg.wal)
    bad[24] ^= 1                                    # the header checksum
    with pytest.raises(st.TimeTravelError, match="the WAL does not read"):
        st.TimeTravel(reg.data, bytes(bad))
    with pytest.raises(st.TimeTravelError, match="registry.db: not a SQLite database"):
        st.TimeTravel(b"not sqlite" * 20, reg.wal, name="registry.db")


# ---------------------------------------------------------------- the timeline and its diffs
def test_timeline_diffs_follow_the_commits(tt):
    steps = tt.timeline()
    assert [s.snapshot.ref for s in steps] == ["0", "1", "2", "3", "4", "5"]
    assert steps[1].against == "commit 0 (the main file alone)" and steps[2].against == "commit 1"
    by = {(st_.snapshot.ref, d.table): d for st_ in steps for d in st_.diffs}
    assert [k for k, _ in by[("1", "jobs")].added] == [1, 2]
    assert by[("3", "jobs")].changed == [(1, ("LR-731", "QUEUED"), ("LR-731", "RUNNING"))]
    assert ("3", "settings") not in by and ("4", "parcels") not in by
    d5 = by[("5", "parcels")]
    assert d5.removed == [(3, (3, "carol", None))]
    assert d5.changed == [(1, (1, "mallory", fx.DEED), (1, "alice", None))]
    # a WITHOUT ROWID table is keyed by its primary key
    assert by[("5", "settings")].changed == [(("mode",), ("mode", "normal"), ("mode", "clean"))]
    assert tt.timeline() is steps                  # computed once
    assert steps[0].rows == {"jobs": 0, "parcels": 0, "settings": 0}


def test_diff_tables_keeps_types_apart_and_names_created_and_dropped():
    old = {"t": st.Table("t", ["a"], {1: (1,), 2: ("x",)}), "gone": st.Table("gone", ["a"], {})}
    new = {"t": st.Table("t", ["a"], {1: (1.0,), 2: ("x",)}), "made": st.Table("made", ["b"], {1: (5,)})}
    out = {d.table: d for d in st.diff_tables(old, new)}
    assert out["t"].changed == [(1, (1,), (1.0,))]   # 1 and 1.0 are different cells
    assert out["made"].note == "created" and out["made"].added == [(1, (5,))]
    assert out["gone"].note == "dropped"
    same = {"t": st.Table("t", ["a"], {1: (1,)})}
    assert st.diff_tables(same, {"t": st.Table("t", ["a"], {1: (1,)})}) == []
    unread = st.diff_tables(same, {"t": st.Table("t", ["a"], {}, error="boom")})
    assert unread[0].note == "not read: boom" and unread[0].removed == []
    cols = st.diff_tables(same, {"t": st.Table("t", ["a", "b"], {1: (1, 2)})})
    assert cols[0].note == "columns changed"


def test_timeline_text_shows_each_change(tt):
    text = "\n".join(st.timeline_text(tt))
    assert "WAL: 9 valid frame(s) in 5 commit(s)" in text
    assert "~ row 1: status: 'QUEUED' -> 'RUNNING'" in text
    assert "- row 3: parcel=3, owner='carol', deed=NULL" in text
    assert "APPROXIMATE" not in text and "INCOMPLETE" not in text


def test_a_spent_budget_stops_the_timeline_and_says_where(reg):
    t = st.TimeTravel(reg.data, reg.wal)
    steps = t.timeline(budget=0, clock=step_clock())
    assert steps == [] and "budget is spent" in t.stopped
    assert "INCOMPLETE" in "\n".join(st.timeline_text(t))


# ---------------------------------------------------------------- transitions and value search
def test_the_commit_where_a_row_reaches_a_state(tt):
    hits = tt.transitions("jobs", "status", "COMPLETED", {"job_id": "LR-731"})
    assert [(h.snapshot.ref, h.kind, h.key, h.before, h.after) for h in hits] == [("4", "enter", 1, "RUNNING", "COMPLETED")]
    assert hits[0].row == {"job_id": "LR-731", "status": "COMPLETED"}
    every = tt.transitions("jobs", "status", "COMPLETED")
    assert [(h.snapshot.ref, h.key) for h in every] == [("1", 2), ("4", 1)]
    assert "jobs.status of row 1 becomes 'COMPLETED' at commit 4 (frames 6-6)" == st.transition_text(hits[0])


def test_leaving_a_state_and_a_state_already_in_the_main_file(tmp_path):
    w = fx.build(tmp_path, steps=(
        (("UPDATE jobs SET status = 'DONE' WHERE job_id = 'a'", ()),),
        (("UPDATE jobs SET status = 'OPEN' WHERE job_id = 'b'", ()),),
        (("DELETE FROM jobs WHERE job_id = 'a'", ()),),
    ), pre=((("INSERT INTO jobs VALUES('a', 'OPEN')", ()), ("INSERT INTO jobs VALUES('b', 'DONE')", ())),))
    t = st.TimeTravel(w.data, w.wal)
    got = [(h.snapshot.ref, h.kind, h.row["job_id"]) for h in t.transitions("jobs", "status", "DONE")]
    assert got == [("0", "base", "b"), ("1", "enter", "a"), ("2", "leave", "b"), ("3", "leave", "a")]
    assert "stops being 'DONE' at commit 3" in st.transition_text(t.transitions("jobs", "status", "DONE")[-1])
    assert "is already 'DONE' at commit 0" in st.transition_text(t.transitions("jobs", "status", "DONE")[0])


def kept_owner_fixture(tmp_path):
    """Parcel 1 is alice's in the main file and stays alice's; commit 1 changes only its deed, commit 2
    hands parcel 2 to alice."""
    return fx.build(tmp_path, steps=(
        (("UPDATE parcels SET deed = X'beef' WHERE parcel = 1", ()),),
        (("UPDATE parcels SET owner = 'alice' WHERE parcel = 2", ()),),
    ), pre=((("INSERT INTO parcels VALUES(1, 'alice', X'00')", ()), ("INSERT INTO parcels VALUES(2, 'bob', NULL)", ())),))


def test_a_row_already_in_the_state_does_not_enter_it_again_when_another_column_changes(tmp_path):
    t = st.TimeTravel(*_files(kept_owner_fixture(tmp_path)))
    # commit 1 changed parcel 1 (its deed): it is a changed row, but it was alice's before and after
    assert any(d.table == "parcels" and [k for k, *_ in d.changed] == [1]
               for s in t.timeline() if s.snapshot.ref == "1" for d in s.diffs)
    got = [(h.snapshot.ref, h.kind, h.key) for h in t.transitions("parcels", "owner", "alice")]
    assert got == [("0", "base", 1), ("2", "enter", 2)]


def test_find_value_says_base_for_the_main_file_and_skips_a_cell_that_keeps_its_value(tmp_path):
    t = st.TimeTravel(*_files(kept_owner_fixture(tmp_path)))
    got = [(h.snapshot.ref, h.kind, h.key, h.before) for h in t.find_value("alice")]
    assert got == [("0", "base", 1, None), ("2", "enter", 2, "bob")]


def _files(w):
    return w.data, w.wal, w.shm


def test_transitions_name_what_is_missing(tt):
    with pytest.raises(st.TimeTravelError, match="no table 'job'.*jobs, parcels, settings"):
        tt.transitions("job", "status", "X")
    with pytest.raises(st.TimeTravelError, match="no column 'state'; columns: job_id, status"):
        tt.transitions("jobs", "state", "X")
    with pytest.raises(st.TimeTravelError, match="no column 'who'"):
        tt.transitions("jobs", "status", "X", {"who": "y"})


def test_cell_matches_reads_command_line_text_against_typed_cells():
    assert st.cell_matches(None, "NULL") and not st.cell_matches(None, "")
    assert st.cell_matches(42, "42") and st.cell_matches("42", "42")
    assert st.cell_matches(b"ab", "ab") and not st.cell_matches(b"ab", "6162")
    assert st.cell_matches(42, 42) and not st.cell_matches("42", 42) and not st.cell_matches(42.0, 42)


def test_find_value_lists_every_cell_that_becomes_it(tt):
    hits = tt.find_value("mallory")
    assert [(h.snapshot.ref, h.table, h.column, h.key, h.before) for h in hits] == [("3", "parcels", "owner", 1, "alice")]
    alice = tt.find_value("alice")
    assert [(h.snapshot.ref, h.kind, h.before) for h in alice] == [("2", "enter", None), ("5", "enter", "mallory")]
    assert tt.find_value("nobody") == []


# ---------------------------------------------------------------- earlier WAL cycles and checkpoints
def test_frames_of_an_earlier_wal_cycle_are_stale_commits_with_their_old_rows(tmp_path):
    # checkpoint after commit 3 restarts the WAL at commit 4; a second checkpoint after 5 copies the
    # new cycle into the main file, so only the stale frames still hold the commit-3 rows
    w = fx.build(tmp_path, checkpoint_after=(3, 5))
    t = st.TimeTravel(w.data, w.wal, w.shm)
    assert len(t.commits) == 2 and len(t.stale) == 2
    assert all(not s.exact and s.index is None for s in t.stale)
    assert [s.ref for s in t.stale] == ["s1", "s2"] and t.snapshot("s2") is t.stale[1]
    assert "an earlier WAL cycle (other salts)" in t.stale[1].note
    old = as_state(t.snapshot("s2").tables())
    assert ("LR-731", "RUNNING") in old["jobs"] and (1, "mallory", fx.DEED) in old["parcels"]
    assert as_state(t.snapshot("final").tables()) == want_state(w.states[5])
    # commit 0 is the main file after the second checkpoint: approximate, and it says so
    assert not t.snapshots[0].exact and "checkpoint" in t.snapshots[0].note
    steps = {s.snapshot.ref: s for s in t.timeline()}
    assert steps["s2"].against == "commit 0 (the main file alone)"
    jobs = [d for d in steps["s2"].diffs if d.table == "jobs"][0]
    assert jobs.changed == [(1, ("LR-731", "COMPLETED"), ("LR-731", "RUNNING"))]
    assert [h.snapshot.ref for h in t.transitions("jobs", "status", "RUNNING")] == []   # stale ones are not searched
    values = {v for _, table, col, v in t.cells(recovered=False)}
    assert "mallory" in values and fx.DEED in values


def test_a_checkpoint_held_back_by_a_reader_marks_only_the_older_snapshots_approximate(tmp_path):
    w = fx.build(tmp_path, reader_after=2, checkpoint_after=(4,))
    t = st.TimeTravel(w.data, w.wal, w.shm)
    assert t.backfilled == 4                        # frames 0-3 (commits 1 and 2) copied
    assert set(t.checkpointed.values()) <= {0, 1, 2, 3}
    assert [s.exact for s in t.snapshots] == [False, False, True, True, True, True]
    for k in (2, 3, 4, 5):
        assert as_state(t.snapshots[k].tables()) == want_state(w.states[k])
    assert "its -shm says a checkpoint copied the frames below 4" in t.snapshots[0].note
    text = "\n".join(st.timeline_text(t))
    assert "APPROXIMATE: " in text and "NOTE 2 page(s) of the main file" in text
    # without the -shm the same pages are found from the main file's own bytes
    alone = st.TimeTravel(w.data, w.wal, None)
    assert alone.backfilled is None and alone.checkpointed == t.checkpointed
    assert "no -shm beside it to confirm" in alone.snapshots[0].note


def test_a_page_first_written_right_after_a_commit_makes_that_commit_approximate(tmp_path):
    # commit 1 writes table a's page (frame 0), commit 2 table b's page (frame 1); the checkpoint copies
    # both. Commit 1's image takes b's page from the main file, which now holds frame 1's bytes: the
    # frame directly after commit 1's last frame still counts as "not yet written at commit 1"
    w = fx.build(tmp_path, schema=("CREATE TABLE a(x)", "CREATE TABLE b(x)"),
                 steps=((("INSERT INTO a VALUES('one')", ()),), (("INSERT INTO b VALUES('two')", ()),)),
                 checkpoint_after=(2,))
    t = st.TimeTravel(w.data, w.wal, w.shm)
    assert [(c["first"], c["last"]) for c in t.commits] == [(0, 0), (1, 1)]
    assert t.backfilled == 2 and sorted(t.checkpointed.values()) == [0, 1]
    assert [s.exact for s in t.snapshots] == [False, False, True]
    assert t.snapshots[1].note.startswith("1 page(s) not yet written at this commit")
    assert t.snapshots[0].note.startswith("2 page(s) not yet written at this commit")
    # what the note warns about: commit 1's image shows b's row, which the library saw only at commit 2
    assert w.states[1]["b"] == [] and as_state(t.snapshots[1].tables())["b"] == [("two",)]
    assert as_state(t.snapshots[2].tables()) == want_state(w.states[2])


def test_stale_commits_of_two_earlier_cycles_come_oldest_first(tmp_path):
    # cycle 1: one commit writing six pages (frames 0-5); cycle 2: commits of frames 0-1 and 2;
    # cycle 3: one frame. The file then holds cycle 3's frame 0, cycle 2's frames 1-2 and cycle 1's 3-5
    schema = tuple(f"CREATE TABLE t{i}(x)" for i in range(1, 7))
    w = fx.build(tmp_path, schema=schema, checkpoint_after=(1, 3), steps=(
        tuple((f"INSERT INTO t{i} VALUES('c1-{i}')", ()) for i in range(1, 7)),
        (("INSERT INTO t1 VALUES('c2-1')", ()), ("INSERT INTO t2 VALUES('c2-2')", ())),
        (("INSERT INTO t3 VALUES('c2-3')", ()),),
        (("INSERT INTO t1 VALUES('c3-1')", ()),),
    ))
    t = st.TimeTravel(w.data, w.wal, w.shm)
    assert [(c["first"], c["last"]) for c in t.commits] == [(0, 0)]
    assert [(s.ref, s.frames) for s in t.stale] == [("s1", (3, 5)), ("s2", (1, 1)), ("s3", (2, 2))]
    assert t.stale[0].note.startswith("frames 3-5 of an earlier WAL cycle (other salts)")
    assert all("checksums link frame to frame" in s.note for s in t.stale)
    assert ("c1-5",) in as_state(t.snapshot("s1").tables())["t5"]


def test_a_broken_checksum_inside_a_stale_run_is_named(reg):
    # frame 6 (commit 4) damaged in a byte its page does not use: frames 6-8 are no longer valid and
    # become stale commits of this cycle's salts, whose chain breaks at frame 6
    wal = bytearray(reg.wal)
    ps = struct.unpack_from(">I", wal, 8)[0]
    off = 32 + 6 * (24 + ps) + 24
    page = bytes(wal[off:off + ps])
    gap = page.index(bytes(16), 20) + 8                     # inside the free space between pointers and cells
    wal[off + gap] ^= 0xFF
    t = st.TimeTravel(reg.data, bytes(wal))
    assert [c["index"] for c in t.commits] == [1, 2, 3]
    assert [(s.ref, s.frames) for s in t.stale] == [("s1", (6, 6)), ("s2", (7, 8))]
    for s in t.stale:
        assert "this cycle's salts, after the checksum chain broke" in s.note
        assert s.note.endswith("checksum chain broken at frame 6"), s.note
    # the damaged byte is free space: the stale commits still read as commits 4 and 5 did
    assert as_state(t.snapshot("s2").tables())["parcels"] == want_state(reg.states[5])["parcels"]


def test_shm_backfill_only_for_this_wal(tmp_path, reg):
    w = fx.build(tmp_path, reader_after=2, checkpoint_after=(4,))
    assert st.shm_backfill(w.shm, w.wal) == 4
    assert st.shm_backfill(w.shm, reg.wal) is None           # another WAL's salts
    assert st.shm_backfill(None, w.wal) is None
    assert st.shm_backfill(b"\0" * 200, w.wal) is None       # not initialised
    flat = bytearray(w.shm)
    flat[12] = 0
    assert st.shm_backfill(bytes(flat), w.wal) is None


def test_with_a_shm_that_says_nothing_was_copied_identical_bytes_are_not_called_checkpointed(reg):
    # a commit can rewrite a page with the bytes it already has; with the -shm saying 0 frames were
    # copied, that page is not mistaken for a checkpointed one
    frames = fx.frames_of(reg.wal)
    pg = sa.Pages(reg.data, reg.wal)
    p = frames[0][0]
    frames[0][2] = pg.page(p, {})                       # frame 0 holds the main file's page as it is
    wal = fx.rebuild(reg.wal, frames)
    assert st.TimeTravel(reg.data, wal, reg.shm).checkpointed == {}
    assert st.TimeTravel(reg.data, wal, None).checkpointed == {p: 0}


# ---------------------------------------------------------------- the read-only SELECT
def test_a_select_runs_as_of_any_commit(tt):
    for k in range(6):
        cols, rows = tt.query(k, "SELECT job_id, status FROM jobs ORDER BY job_id")
        assert cols == ["job_id", "status"] and rows == sorted(tuple(r) for r in fx_rows(tt, k))
    assert tt.query("final", "VALUES (1), (2)") == (["column1"], [(1,), (2,)])
    assert tt.query(3, "/* lead */ -- comment\n select count(*) from parcels") == (["count(*)"], [(3,)])
    assert tt.query(2, "SELECT * FROM pragma_table_info('jobs')")[1][0][1] == "job_id"


def fx_rows(tt, k):
    return [(r[0], r[1]) for r in tt.snapshot(k).tables()["jobs"].rows.values()]


@pytest.mark.parametrize("sql, reason", [
    ("ATTACH ':memory:' AS x", "starts with 'ATTACH'"),
    ("PRAGMA journal_mode = DELETE", "starts with 'PRAGMA'"),
    ("DELETE FROM jobs", "starts with 'DELETE'"),
    ("", "starts with 'nothing'"),
    ("WITH a AS (SELECT 1) INSERT INTO jobs VALUES ('x', 'y')", "read-only copy: INSERT"),
    ("WITH a AS (SELECT 1) DELETE FROM jobs", "read-only copy: DELETE"),
    ("WITH a AS (SELECT 1) UPDATE jobs SET status = 'x'", "read-only copy: UPDATE"),
    ("SELECT load_extension('evil')", "read-only copy: function load_extension()"),
    ("SELECT fts3_tokenizer('simple')", "read-only copy: function fts3_tokenizer()"),
    ("SELECT * FROM pragma_writable_schema", "read-only copy: PRAGMA writable_schema"),
    ("SELECT * FROM pragma_integrity_check", "read-only copy: PRAGMA integrity_check"),
    ("SELECT 1; DROP TABLE jobs", "one statement only"),
])
def test_anything_but_one_select_is_refused(tt, sql, reason):
    with pytest.raises(st.SqlRefused, match=reason.replace("(", r"\(").replace(")", r"\)")):
        tt.query(2, sql)


def test_the_authorizer_itself_denies_writes_attach_and_pragma_writes(tt):
    """check_select() names the plain cases early; this drives the authorizer behind it."""
    with st.ReadOnly(tt.snapshot(2).image()) as ro:
        for sql, named in [("ATTACH ':memory:' AS x", "ATTACH"), ("INSERT INTO jobs VALUES ('x', 'y')", r"INSERT \(jobs\)"),
                           ("PRAGMA user_version = 7", "PRAGMA user_version = 7"),
                           ("PRAGMA writable_schema = ON", "PRAGMA writable_schema"),
                           ("CREATE TABLE t(a)", r"INSERT \(sqlite_master\)"),
                           ("DROP TABLE jobs", "DELETE \\(sqlite_master\\)|DROP_TABLE \\(jobs\\)"),
                           ("UPDATE jobs SET status = 1", r"UPDATE \(jobs\)"),
                           ("BEGIN", "TRANSACTION")]:
            with pytest.raises(st.SqlRefused, match=named):
                ro._run(sql)
        assert ro._run("PRAGMA user_version")[1] == [(0,)]          # a read pragma is fine
        assert ro._run("SELECT count(*) FROM jobs")[1] == [(2,)]


def test_a_select_never_changes_the_snapshot_and_the_copy_is_query_only(tt):
    img = tt.snapshot(2).image()
    before = bytes(img)
    st.run_select(img, "SELECT * FROM jobs")
    assert img == before
    with st.ReadOnly(img) as ro:
        assert ro.con.execute("PRAGMA query_only").fetchone() == (1,)
        assert ro.con.getlimit(sqlite3.SQLITE_LIMIT_ATTACHED) == 0
        assert ro.con.getconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE) is True
        assert ro.con.getconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA) is False
        assert ro.con.getconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION) is False


def test_a_runaway_select_is_stopped_by_its_step_budget(tt):
    # (long but finite, so a copy without the progress handler finishes and fails here instead of hanging)
    endless = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 3000000) SELECT count(*) FROM c"
    with pytest.raises(st.QueryTimeout, match="past its 5 s budget"):
        tt.query(1, endless, budget=5, clock=step_clock())
    # the same clock with room for a bounded query lets it finish
    cols, rows = tt.query(1, "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 50) "
                             "SELECT count(*) FROM c", budget=1000, clock=step_clock())
    assert rows == [(50,)]


@pytest.mark.parametrize("sql", ["SELECT zeroblob(999999999)", "SELECT length(randomblob(100000000))",
                                 "SELECT length(hex(zeroblob(40000000)))"])
def test_a_select_cannot_make_a_value_past_the_cap(tt, sql):
    # one VM step allocates the whole value, so the step budget cannot stop it: the length limit does
    with pytest.raises(st.TimeTravelError, match="past the 64 MiB value cap"):
        tt.query(1, sql)
    with st.ReadOnly(tt.snapshot(1).image()) as ro:
        assert ro.con.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == st.MAX_VALUE == 64 << 20
        assert ro.select("SELECT length(zeroblob(1000))")[1] == [(1000,)]


BIG = (64 << 20) + (6 << 20)          # a stored BLOB past the 64 MiB cap on values a SELECT makes


def test_a_stored_blob_past_the_select_cap_keeps_its_table_in_the_diffs(tmp_path):
    # the value cap is for SELECTs; read_tables reads stored cells (bounded by the file) under MAX_BYTES
    w = fx.build(tmp_path, schema=("CREATE TABLE t(id INTEGER PRIMARY KEY, note TEXT, big BLOB)",),
                 pre=((("INSERT INTO t VALUES(1, 'keep', zeroblob(?))", (BIG,)),
                       ("INSERT INTO t VALUES(2, 'flag', NULL)", ())),),
                 steps=((("UPDATE t SET note = 'flag{moved}' WHERE id = 2", ()),),), page_size=4096)
    t = st.TimeTravel(w.data, w.wal)
    steps = t.timeline()
    assert [s.error for s in steps] == ["", ""] and steps[0].rows == {"t": 2}
    (d,) = steps[1].diffs
    assert d.table == "t" and d.note == "" and d.changed == [(2, (2, "flag", None), (2, "flag{moved}", None))]
    assert [(h.snapshot.ref, h.kind, h.key) for h in t.find_value("flag{moved}")] == [("1", "enter", 2)]
    with st.ReadOnly(t.snapshot(0).image()) as ro:
        big = st.read_tables(ro)["t"]
        assert big.error == "" and len(big.rows[1][2]) == BIG and big.rows[2] == (2, "flag", None)
        # the SELECT cap is back in force once the tables are read
        assert ro.con.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == st.MAX_VALUE
        with pytest.raises(st.TimeTravelError, match="past the 64 MiB value cap"):
            ro.select("SELECT big FROM t WHERE id = 1")
        assert ro.select("SELECT note FROM t ORDER BY id")[1] == [("keep",), ("flag",)]


def test_a_stored_value_past_max_bytes_is_named_with_the_cap_in_force(monkeypatch):
    src = sqlite3.connect(":memory:")
    src.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, b BLOB)")
    src.execute("INSERT INTO t VALUES(1, zeroblob(3 << 20))")
    img = st.standalone(src.serialize())
    src.close()
    monkeypatch.setattr(st, "MAX_BYTES", 2 << 20)
    with st.ReadOnly(img) as ro:
        tables = st.read_tables(ro)
        assert ro.con.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == st.MAX_VALUE
    assert tables["t"].rows == {} and "past the 2 MiB value cap" in tables["t"].error


def test_virtual_generated_columns_are_not_computed_on_read_and_are_named(tmp_path):
    # a crafted schema could make a VIRTUAL column zeroblob(N) in every row: only stored cells are read
    w = fx.build(tmp_path, schema=("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, "
                                   "g BLOB AS (zeroblob(1 << 20)) VIRTUAL, s TEXT AS (upper(a)) STORED)",),
                 pre=((("INSERT INTO t(id, a) VALUES(1, 'x')", ()),),),
                 steps=((("UPDATE t SET a = 'flag' WHERE id = 1", ()),),))
    t = st.TimeTravel(w.data, w.wal)
    tables = t.snapshot(1).tables()
    assert tables["t"].columns == ["id", "a", "s"] and tables["t"].computed == ["g"]
    assert tables["t"].rows == {1: (1, "flag", "FLAG")}
    steps = t.timeline()
    assert steps[1].diffs[0].changed == [(1, (1, "x", "X"), (1, "flag", "FLAG"))]
    text = "\n".join(st.timeline_text(t))
    assert "t: VIRTUAL generated column(s) g computed on read, not in the file: not read" in text


def test_a_result_past_the_row_cap_is_an_error_not_a_cut(tt):
    img = tt.snapshot(1).image()
    assert st.run_select(img, "SELECT * FROM jobs", max_rows=2)[1] != []
    with pytest.raises(st.TimeTravelError, match="more than 1 rows"):
        st.run_select(img, "SELECT * FROM jobs", max_rows=1)


def test_csv_tables_join_the_snapshot_and_may_not_shadow_it(tt):
    extra = {"owners": (["name", "city"], [("alice", "Oslo"), ("mallory", "Lima")])}
    cols, rows = tt.query(3, "SELECT p.parcel, o.city FROM parcels p JOIN owners o ON o.name = p.owner ORDER BY 1",
                          extra=extra)
    assert rows == [(1, "Lima")]
    with pytest.raises(st.TimeTravelError, match="extra table 'JOBS'"):
        tt.query(3, "SELECT 1", extra={"JOBS": (["a"], [])})


def test_load_csv():
    assert st.load_csv(b"\xef\xbb\xbfa,b\r\n1,2\r\n\r\n3,\"x,y\"\r\n") == (["a", "b"], [("1", "2"), ("3", "x,y")])
    for data, why in [(b"a,a\n1,2\n", "header of distinct"), (b"a,b\n1\n", "line 2 has 1 fields"),
                      (b"", "empty"), (b"\xff\xfe", "not UTF-8"), (b",b\n1,2\n", "header of distinct")]:
        with pytest.raises(st.TimeTravelError, match=why):
            st.load_csv(data, "x.csv")


# ---------------------------------------------------------------- BLOB cells
def test_decode_cell_inflates_and_decodes_blobs():
    flag = b"CSCTF{wal_blob_1}"
    found = st.decode_cell(zlib.compress(b"note: " + flag), FF)
    assert found[0]["via"] == "zlib" and found[0]["flags"] == [flag.decode()]
    b64 = st.decode_cell(b"\x00\x01payload=" + base64.b64encode(b"secret " + flag) + b"\xff", FF)
    assert any(f["via"] == "blob > base64" and f["flags"] == [flag.decode()] for f in b64)
    nested = st.decode_cell(zlib.compress(base64.b64encode(flag + b" padding")), FF)
    assert any(f["via"] == "zlib > base64" and f["flags"] for f in nested)
    utf16 = st.decode_cell("hello CSCTF{wide}".encode("utf-16-le"), FF)
    assert utf16[0]["text"] == "hello CSCTF{wide}" and utf16[0]["flags"] == ["CSCTF{wide}"]
    assert st.decode_cell(bytes(range(200, 256)) * 4, FF) == []          # noise: nothing claimed
    # starts with zlib's 0x78 but is no stream: the failed inflate is skipped, the blob still read
    plain = st.decode_cell(b"xylophone CSCTF{x_is_not_zlib}", FF)
    assert [(f["via"], f["flags"]) for f in plain] == [("blob", ["CSCTF{x_is_not_zlib}"])]
    assert st.decode_cell(b"\x78\x9c\xff\xfe\x00\x01", FF) == []


def test_decode_cell_reads_text_only_for_encoded_flags():
    assert st.decode_cell("just words", FF) == []
    assert st.decode_cell(base64.b64encode(b"a harmless sentence here").decode(), FF) == []
    hit = st.decode_cell("token " + base64.b64encode(b"CSCTF{inside_a_text_cell}").decode(), FF)
    assert hit[0]["via"] == "text > base64" and hit[0]["flags"] == ["CSCTF{inside_a_text_cell}"]
    assert st.decode_cell(12345, FF) == []


def test_cell_findings_cover_rows_that_a_later_commit_deleted(tmp_path):
    secret = base64.b64encode(b"CSCTF{gone_but_not_lost}")
    w = fx.build(tmp_path, steps=(
        (("INSERT INTO parcels VALUES(7, 'eve', ?)", (zlib.compress(secret),)),),
        (("DELETE FROM parcels WHERE parcel = 7", ()),),
    ))
    t = st.TimeTravel(w.data, w.wal)
    findings = st.cell_findings(t, FF)
    flagged = [f for f in findings if f["flags"]]
    assert flagged and flagged[0]["flags"] == ["CSCTF{gone_but_not_lost}"]
    assert flagged[0]["table"] == "parcels" and flagged[0]["column"] == "deed"
    assert flagged[0]["where"] == "commit 1, row 7" and flagged[0]["via"] == "zlib > base64"
    assert t.snapshot("final").tables()["parcels"].rows == {}


def test_cells_include_rows_recovered_from_stale_frames(tmp_path):
    """recovered=True adds what sqlite_artifacts carves; recovered=False is the snapshots alone."""
    w = fx.build(tmp_path, checkpoint_after=(3, 5))
    t = st.TimeTravel(w.data, w.wal)
    plain = t.cells(recovered=False)
    every = t.cells(recovered=True)
    assert len(every) >= len(plain) and every[:len(plain)] == plain
    assert all(not where.startswith("recovered") for where, *_ in plain)


# ---------------------------------------------------------------- SQL from a handout
def test_sql_blocks_of_a_handout_profile():
    text = ("# Export profile\n\nRun this:\n\n```sql\nSELECT job_id FROM jobs\nWHERE status = 'COMPLETED';\n```\n\n"
            "```\nselect 1\n```\n\n```python\nprint('SELECT nothing')\n```\n\n"
            "~~~sqlite\nDELETE FROM jobs\n~~~\n\n```\nrm -rf /\n```\n\n````sql\nWITH x AS (SELECT 2) SELECT * FROM x\n````\n")
    blocks = st.sql_blocks(text)
    assert [(b["line"], b["lang"], b["refused"] != "") for b in blocks] == \
           [(5, "sql", False), (10, "", False), (18, "sqlite", True), (26, "sql", False)]
    assert blocks[0]["sql"] == "SELECT job_id FROM jobs\nWHERE status = 'COMPLETED';"
    assert "starts with 'DELETE'" in blocks[2]["refused"]


def test_render_and_its_variants():
    cols, rows = ["a", "b"], [(1, None), ("x,y", b"\x01\xff")]
    assert st.render(cols, rows) == b"1\t\nx,y\t01ff\n"
    assert st.render(cols, rows, fmt="csv", header=True, newline="\r\n", trailing_newline=False, null="NULL") == \
        b'a,b\r\n1,NULL\r\n"x,y",01ff'
    assert st.render(cols, []) == b""
    with pytest.raises(st.TimeTravelError, match="tsv or csv"):
        st.render(cols, rows, fmt="json")
    v = st.variants(cols, rows)
    assert len(v) == 16 and len({d for _, d in v}) == 16
    assert dict(v)["tsv, no header, LF, trailing newline"] == hashlib.sha256(st.render(cols, rows)).hexdigest()
    assert dict(v)["csv, header, CRLF, no trailing newline"] == hashlib.sha256(
        st.render(cols, rows, fmt="csv", header=True, newline="\r\n", trailing_newline=False)).hexdigest()


# ---------------------------------------------------------------- finding the files
def test_find_pairs_by_name_by_page_size_and_once(tmp_path, reg):
    hand = tmp_path / "files"
    reg.write(hand)                                         # registry.db + registry.db-wal
    reg.write(hand / "unpacked")                            # the sweep's copy: same bytes, listed once
    reg.write(hand / "recon")                               # recon/ is ours, never the handout
    other = tmp_path / "other"
    reg.write(other, name="app.sqlite", wal_name="journal.bin")
    pairs, problems = st.find_pairs(hand)
    assert [(p[0].name, p[1].name, p[3]) for p in pairs] == [("registry.db", "registry.db-wal", "by name")]
    assert problems == []
    pairs, _ = st.find_pairs(other)
    assert pairs[0][0].name == "app.sqlite" and "page size 1024" in pairs[0][3]
    (other / "twin.db").write_bytes(reg.data)
    pairs, problems = st.find_pairs(other)
    assert pairs == [] and "2 SQLite files with page size 1024" in problems[0]
    (hand / "empty.db-wal").write_bytes(b"")
    assert "empty.db-wal: named like a WAL but its magic is not one" in st.find_pairs(hand)[1][0]


def test_find_pairs_takes_the_shm_beside_the_wal(tmp_path, reg):
    reg.write(tmp_path, shm=True)
    (pair,) = st.find_pairs(tmp_path)[0]
    assert pair[2] is not None and pair[2].name == "registry.db-shm"


# ---------------------------------------------------------------- the contract entry
def write_handout(folder: Path, reg, profile_text: str = None) -> Path:
    reg.write(folder)
    if profile_text is not None:
        (folder / "export-profile.md").write_text(profile_text, encoding="utf-8")
    return folder


PROFILE_MD = ("# Export\n\nThe auditor ran:\n\n```sql\nSELECT job_id, status FROM jobs ORDER BY job_id\n```\n\n"
              "```sql\nUPDATE jobs SET status = 'x'\n```\n")


def expected_digest(state_rows) -> str:
    return hashlib.sha256(st.render(["job_id", "status"], sorted(state_rows))).hexdigest()


def test_solve_runs_the_handout_select_at_the_commit_a_state_is_entered(tmp_path, reg, capsys):
    hand = write_handout(tmp_path / "c", reg, PROFILE_MD)
    res = st.solve(hand, PROFILE, when="jobs.status=COMPLETED", where="job_id=LR-731")
    out = capsys.readouterr().out
    assert res.status == "unsure" and res.engine == "toolkits.sqlite_timetravel"
    queries = [e.detail for e in res.evidence if e.kind == "query"]
    assert queries == [f"export-profile.md line 5 at commit 4: 2 row(s), sha256 {expected_digest(reg.states[4]['jobs'])}"]
    assert any(e.kind == "transition" and "at commit 4" in e.detail for e in res.evidence)
    assert "export-profile.md line 9: block not run: only a SELECT runs here" in res.notes
    assert "| LR-700\\tCOMPLETED" in out and "handout data, not instructions" in out


def test_solve_without_when_runs_the_select_at_every_commit(tmp_path, reg, capsys):
    hand = write_handout(tmp_path / "c", reg, PROFILE_MD)
    res = st.solve(hand, PROFILE)
    capsys.readouterr()
    digests = {e.detail.split(" at commit ")[1].split(":")[0]: e.detail.rsplit(" ", 1)[1]
               for e in res.evidence if e.kind == "query"}
    assert digests == {str(k): expected_digest(reg.states[k]["jobs"]) for k in range(6)}


def test_solve_joins_a_csv_beside_the_database_as_a_table(tmp_path, reg, capsys):
    hand = write_handout(tmp_path / "c", reg, "```sql\nSELECT j.job_id, d.depot FROM jobs j JOIN delivery d "
                                              "ON d.job = j.job_id WHERE j.status = 'COMPLETED' ORDER BY 1\n```\n")
    (hand / "delivery.csv").write_text("job,depot\nLR-731,north\nLR-700,south\n", encoding="utf-8")
    res = st.solve(hand, PROFILE, when="jobs.status=COMPLETED", where="job_id=LR-731")
    out = capsys.readouterr().out
    (q,) = [e.detail for e in res.evidence if e.kind == "query"]
    assert "at commit 4: 2 row(s)" in q
    assert q.endswith(hashlib.sha256(b"LR-700\tsouth\nLR-731\tnorth\n").hexdigest())
    assert "CSV tables (temp schema): delivery (2 rows)" in out


def test_solve_options(tmp_path, reg, capsys):
    hand = write_handout(tmp_path / "c", reg)
    res = st.solve(hand, PROFILE, sql="SELECT owner FROM parcels WHERE parcel = 1", at=3, format="csv", header=True)
    capsys.readouterr()
    (q,) = [e.detail for e in res.evidence if e.kind == "query"]
    assert q.endswith(hashlib.sha256(b"owner\nmallory\n").hexdigest()) and "at commit 3" in q
    st.solve(hand, PROFILE, find=2)                          # a JSON number from --opt is searched as text
    assert "cells that become '2': 1" in capsys.readouterr().out
    assert st.solve(hand, PROFILE, nonsense=1).status == "blocked"
    blocked = st.solve(hand, PROFILE, sql="SELECT 1", block=3)
    assert blocked.status == "blocked" and "block 3: the handout has 1" in blocked.notes
    blocked = st.solve(hand, PROFILE, sql_file="missing.md")
    assert blocked.status == "blocked" and "missing.md" in blocked.notes
    (hand / "export-profile.md").write_text(PROFILE_MD, encoding="utf-8")
    res = st.solve(hand, PROFILE, sql_file="export-profile.md", at=1)
    capsys.readouterr()
    assert [e.detail.rsplit(" ", 1)[1] for e in res.evidence if e.kind == "query"] == [expected_digest(reg.states[1]["jobs"])]
    assert st.solve(hand, PROFILE, sql="SELECT 1", at="99").status == "unsure"
    assert "no commit '99'" in capsys.readouterr().out


def test_solve_returns_a_flag_found_in_a_blob_as_a_candidate(tmp_path):
    w = fx.build(tmp_path / "make", steps=(
        (("INSERT INTO parcels VALUES(9, 'zed', ?)", (zlib.compress(b"CSCTF{last_commit_blob}"),)),),
        (("DELETE FROM parcels WHERE parcel = 9", ()),),
    ))
    res = st.solve(write_handout(tmp_path / "c", w), PROFILE)
    assert res.status == "candidate" and list(res.flags) == ["CSCTF{last_commit_blob}"]
    assert any(e.kind == "decode" and "parcels.deed" in e.detail for e in res.evidence)


def test_solve_with_no_wal_is_none_and_names_a_broken_one(tmp_path, reg):
    (tmp_path / "plain.db").write_bytes(reg.data)
    res = st.solve(tmp_path, PROFILE)
    assert res.status == "none" and "no SQLite database with a WAL" in res.notes
    (tmp_path / "x.db-wal").write_bytes(b"")
    assert "x.db-wal: named like a WAL" in st.solve(tmp_path, PROFILE).notes


# ---------------------------------------------------------------- the command line
def test_cli_image_out_and_exit_codes(tmp_path, reg, capsys):
    db = reg.write(tmp_path / "h")
    img = tmp_path / "at3.db"
    out = tmp_path / "res.tsv"
    rc = st.main([str(db), "--image", "3", str(img), "--sql", "SELECT status FROM jobs ORDER BY job_id", "--at", "4",
                  "--out", str(out), "--no-flag-search"])
    assert rc == 0, capsys.readouterr()
    con = sqlite3.connect(img)
    assert fx.dump(con) == reg.states[3]
    con.close()
    assert out.read_bytes() == b"COMPLETED\nCOMPLETED\n"
    # given the WAL itself, its database is found by name
    assert st.main([str(db) + "-wal", "--no-flag-search", "--when", "jobs.status=RUNNING"]) == 0
    assert "jobs.status of row 1 becomes 'RUNNING' at commit 3" in capsys.readouterr().out
    assert st.main([str(db), "--no-flag-search", "--sql", "DELETE FROM jobs"]) == 1
    assert st.main([str(db), "--no-flag-search", "--sql", "SELECT 1", "--at", "all", "--out", str(out)]) == 1
    assert "--out needs exactly one result" in capsys.readouterr().err
    assert st.main([str(tmp_path / "h" / "nope.db"), "--no-flag-search"]) == 1
    assert st.main([str(db), "--event", "no-such-event"]) == 2


def test_cli_profile_block(tmp_path, reg, capsys):
    db = reg.write(tmp_path / "h")
    prof = tmp_path / "h" / "export-profile.md"
    prof.write_text(PROFILE_MD, encoding="utf-8")
    assert st.main([str(db), "--no-flag-search", "--profile", str(prof), "--block", "1", "--at", "1", "--variants"]) == 0
    text = capsys.readouterr().out
    assert expected_digest(reg.states[1]["jobs"]) in text and "csv, header, CRLF, no trailing newline" in text
    assert st.main([str(db), "--no-flag-search", "--profile", str(prof), "--block", "5"]) == 1


# ---------------------------------------------------------------- wiring
def test_manifest_routes_and_intake_plan(tmp_path, reg):
    ours = [m for m in engine_manifest.discover() if m.id == "toolkits.sqlite_timetravel"]
    assert len(ours) == 1 and ours[0].intake is not None and ours[0].cost_class == "cheap"
    folder = tmp_path / "unpacked"
    reg.write(folder)
    plan = intake_engines.plan(ours, "forensics", "the auditor's export", folder,
                               guard=intake_guard.Guard("hook", (), "test: hook only"))
    assert [job.engine for job in plan.jobs] == ["toolkits.sqlite_timetravel"]
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "plain.db").write_bytes(reg.data)                # a database without a WAL: not this engine's
    plan = intake_engines.plan(ours, "forensics", "the auditor's export", lone,
                               guard=intake_guard.Guard("hook", (), "test: hook only"))
    assert plan.jobs == []
    by_file = {h.manifest.id for h in router.route("misc", "", folder)}
    assert "toolkits.sqlite_timetravel" in by_file
    by_words = [h.manifest.id for h in router.route("forensics", "we got the database and wal file of the app")]
    assert "toolkits.sqlite_timetravel" in by_words
    assert "toolkits.sqlite_timetravel" not in {h.manifest.id for h in router.route("misc", "bypass the firewall")}


def test_ctf_run_calls_the_entry(tmp_path, reg):
    hand = write_handout(tmp_path / "c", reg, PROFILE_MD)
    env = dict(os.environ, CTF_EVENT="csctf", CTF_WORKDIR=str(tmp_path / "wd"))
    proc = subprocess.run([sys.executable, "-m", "ctf", "run", "toolkits.sqlite_timetravel", str(hand),
                           "--opt", "when=jobs.status=COMPLETED", "--opt", "where=job_id=LR-731"],
                          cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    last = [ln for ln in proc.stdout.splitlines() if ln.strip()][-1]
    res = json.loads(last)
    assert res["status"] == "unsure" and res["engine"] == "toolkits.sqlite_timetravel"
    assert any(e["kind"] == "query" and "at commit 4" in e["detail"] for e in res["evidence"])
