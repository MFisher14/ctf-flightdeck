"""The search of the challenge's own text for the one flag a lane claims (agent/owntext.py):
the whole of it, as bytes, never through a symlink, and a search that cannot cover all of
it holds the flag (Found.held) as a hit does, saying why."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent import owntext
from ctf_flightdeck.agent.owntext import Found, forms, look_for, search

FLAG = "t{stand_in}"


def look(handout: Path | None, flag: str = FLAG, description: str = "", seconds: float = 30.0) -> Found:
    return search(description, handout, flag, seconds=seconds)


def board(tmp_path: Path, files: dict[str, bytes | str]) -> Path:
    folder = tmp_path / "handout"
    folder.mkdir()
    for name, data in files.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
    return folder


def test_a_flag_in_the_description_or_in_any_handout_file_is_found_and_one_nowhere_is_not(tmp_path):
    folder = board(tmp_path, {"a.txt": "nothing\n", "sub/deeper/b.bin": b"\x00\x01" + FLAG.encode() + b"\xff"})
    assert look(folder) == Found(where="sub/deeper/b.bin")
    assert look(folder, description=f"Flags look like {FLAG}.") == Found(where="the description")
    assert look(folder, "t{elsewhere}") == Found() and not Found().held and Found().says() == ""
    assert look(folder).held and look(folder).says() == owntext.OWN_TEXT


def test_the_whole_of_a_big_file_is_searched_and_a_flag_cut_by_a_chunk_is_found(tmp_path, monkeypatch):
    big = b"\x00" * (3 * 1024 * 1024) + FLAG.encode()  # past the first 1 MB, the start-up search's limit
    assert look(board(tmp_path, {"disk.img": big})) == Found(where="disk.img")
    monkeypatch.setattr(owntext, "CHUNK", 4)
    for cut in range(len(FLAG) + 4):  # every place a chunk can end in the flag
        folder = tmp_path / f"cut{cut}"
        folder.mkdir()
        (folder / "x.bin").write_bytes(b"\x00" * cut + FLAG.encode() + b"\x00")
        assert look(folder) == Found(where="x.bin"), cut
        assert look(folder, "t{stand_ix}") == Found(), cut


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "latin-1"])
def test_the_flag_is_found_in_the_encodings_a_file_keeps_text_in(tmp_path, encoding):
    flag = "t{café}"  # Latin-1 has é: its byte there is not UTF-8's
    folder = board(tmp_path, {"strings.bin": b"MZ\x00\x00" + flag.encode(encoding) + b"\x00\x00"})
    assert look(folder, flag) == Found(where="strings.bin")


def test_the_flag_is_found_as_json_writes_it_in_a_challenge_json(tmp_path):
    flag = 't{a"b\\c_é}'
    for escaped in (True, False):
        folder = tmp_path / f"json-{escaped}"
        folder.mkdir()
        (folder / "challenge.json").write_text(json.dumps({"hint": f"try {flag}"}, ensure_ascii=escaped))
        assert flag.encode() not in (folder / "challenge.json").read_bytes()
        assert look(folder, flag) == Found(where="challenge.json")


def test_the_forms_are_the_flags_own_text_never_an_encoding_a_challenge_asks_a_player_to_undo():
    assert forms("t{x}") == (b"t{x}", "t{x}".encode("utf-16-le"), "t{x}".encode("utf-16-be"))


def test_a_symlink_is_never_followed_and_a_fifo_is_never_opened(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "flag.txt").write_text(FLAG)
    folder = board(tmp_path, {"readme.txt": "hello\n"})
    (folder / "flag.txt").symlink_to(outside / "flag.txt")
    (folder / "elsewhere").symlink_to(outside)
    os.mkfifo(folder / "pipe")
    done: list[Found] = []
    worker = threading.Thread(target=lambda: done.append(look(folder)), daemon=True)
    worker.start()
    worker.join(10)
    assert done == [Found()]  # nothing the copy of the handout holds; no hang on the FIFO


def test_a_handout_nested_deeper_than_any_walk_limit_is_searched_to_its_bottom(tmp_path):
    folder = board(tmp_path, {"top.txt": "x\n"})
    deep = folder
    for _ in range(300):  # past the snapshot's 64 levels; at most two descriptors are open at a time
        deep = deep / "d"
    deep.mkdir(parents=True)
    (deep / "flag.txt").write_text(FLAG)
    found = look(folder)
    assert found.where.startswith("…") and found.where.endswith("/d/d/flag.txt")  # cut for showing, never for searching
    assert len(found.where) == owntext.SHOWN


def test_a_file_or_folder_that_cannot_be_read_holds_the_flag_and_says_which(tmp_path):
    folder = board(tmp_path, {"a.txt": "fine\n", "b-locked.bin": b"\x00secret", "c/inner.txt": "x"})
    locked = folder / "b-locked.bin"
    locked.chmod(0)
    try:
        try:
            locked.read_bytes()
        except PermissionError:
            pass
        else:
            pytest.skip("not run: this user can read a file with mode 000 (root), so no file is unreadable here")
        found = look(folder, "t{not_there}")
        assert found == Found(problem="b-locked.bin could not be opened: Permission denied") and found.held
        assert found.says() == ("may be written in the challenge's own text: flightdeck could not search all of it "
                                "(b-locked.bin could not be opened: Permission denied)")
    finally:
        locked.chmod(0o644)
    (folder / "c").chmod(0)
    try:
        assert look(folder, "t{not_there}").problem.startswith("the folder c/ could not be")
    finally:
        (folder / "c").chmod(0o755)


def test_a_handout_folder_that_is_gone_or_not_named_holds_the_flag(tmp_path):
    gone = look(tmp_path / "nowhere", "t{x}")
    assert gone.held and gone.problem.startswith("the handout folder ") and "could not be opened" in gone.problem
    assert look(None, "t{x}") == Found(problem="this lane's workspace names no handout folder")


LONE = "t{\udcff}"  # a lone surrogate: a model's unpaired JSON escape (\udcff), a byte decoded with surrogateescape


def test_a_flag_utf8_cannot_write_waits_for_the_player_and_its_search_never_raises(tmp_path):
    """A flag that holds a lone surrogate has no UTF-8 bytes, so no byte search can tell that
    the handout does not hold it (this one does, as the byte surrogateescape stands for): it
    waits, and says why. The description is text, and is searched as before."""
    folder = board(tmp_path, {"a.bin": b"\x00t{\xff}\x00", "b.txt": "nothing\n"})
    assert forms(LONE) == ()
    held = Found(problem="the flag holds a lone surrogate, which UTF-8 cannot write")
    assert look(folder, LONE) == held and held.held
    assert asyncio.run(look_for("", folder, LONE)) == held
    assert look(folder, LONE, description=f"Flags look like {LONE}.") == Found(where="the description")


def test_a_search_that_breaks_holds_the_flag_and_names_the_error_made_safe_to_show(tmp_path, monkeypatch):
    """An error no part of the search expects (not an OSError: a path no system call takes,
    or a flightdeck bug) never reaches the lane: the flag waits, and the error is named."""
    found = look(tmp_path / "hand\x00out")
    assert found.held and found.problem.startswith("the search failed: ValueError: "), found
    assert asyncio.run(look_for("", tmp_path / "hand\x00out", FLAG)) == found

    def broken(root, parts):
        raise RuntimeError("bad \x1b[2J\nnews " + "x" * 500)

    monkeypatch.setattr(owntext, "open_dir", broken)
    found = look(board(tmp_path, {"a.txt": "x\n"}))
    assert found.held and found.problem.startswith("the search failed: RuntimeError: bad ^[[2J \u23ce news xxx")
    assert "\x1b" not in found.problem and "\n" not in found.problem
    assert len(found.problem) == len("the search failed: ") + owntext.SHOWN and found.problem.endswith("x…")


def test_a_search_out_of_time_holds_the_flag(tmp_path):
    folder = board(tmp_path, {"a.txt": "nothing\n"})
    assert look(folder, "t{x}", seconds=-1.0) == Found(problem="the search took longer than -1 s")
    assert look(folder, "t{x}", description="t{x}", seconds=-1.0) == Found(where="the description")  # it holds it anyway


def test_a_handout_name_is_made_safe_to_show(tmp_path):
    folder = board(tmp_path, {"evil\x1b[2J\nname.bin": FLAG})
    found = look(folder)
    assert found.held and "\x1b" not in found.where and "\n" not in found.where


def test_a_stopped_search_ends_at_its_next_chunk(tmp_path, monkeypatch):
    folder = board(tmp_path, {"big.bin": b"\x00" * (4 * 1024 * 1024)})
    monkeypatch.setattr(owntext, "CHUNK", 1)  # a read of millions of steps: many seconds
    stop = threading.Event()
    done: list[Found] = []
    worker = threading.Thread(target=lambda: done.append(search("", folder, FLAG, seconds=300, stop=stop)), daemon=True)
    worker.start()
    time.sleep(0.05)
    stop.set()
    worker.join(5)
    assert done == [Found(problem="the search was stopped")]


def test_a_lanes_halt_ends_its_search_under_way_and_a_cancelled_search_never_sets_that_halt(tmp_path, monkeypatch):
    """The lane's halt (set when it stops) ends a search under way at its next chunk; a search
    whose caller is cancelled stops by an event of its own, so the halt stays unset and the
    lane's next search runs to its end."""
    folder = board(tmp_path, {"big.bin": b"\x00" * (4 * 1024 * 1024)})
    small = tmp_path / "small"
    small.mkdir()
    (small / "flag.txt").write_text(FLAG)
    monkeypatch.setattr(owntext, "CHUNK", 1)  # a read of millions of steps: many seconds
    ended: list[Found] = []
    real_late = owntext._late

    def late(*args):
        found = real_late(*args)
        if found is not None:
            ended.append(found)
        return found

    monkeypatch.setattr(owntext, "_late", late)

    async def main():
        halt = threading.Event()
        task = asyncio.ensure_future(look_for("", folder, FLAG, halt=halt))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        for _ in range(500):  # the thread ends at its next chunk
            if ended:
                break
            await asyncio.sleep(0.01)
        assert ended == [Found(problem="the search was stopped")] and not halt.is_set()
        assert await look_for("", small, FLAG, halt=halt) == Found(where="flag.txt")  # the lane's next search runs
        task = asyncio.ensure_future(look_for("", folder, FLAG, halt=halt))
        await asyncio.sleep(0.05)
        halt.set()  # the lane stopped
        assert await asyncio.wait_for(task, 5) == Found(problem="the search was stopped")

    asyncio.run(main())


def test_the_search_runs_off_the_event_loop_and_a_cancelled_caller_stops_it(tmp_path, monkeypatch):
    folder = board(tmp_path, {"a.bin": b"\x00"})
    started, release = threading.Event(), threading.Event()
    real_late = owntext._late
    seen: list[threading.Event | None] = []

    def late(deadline, seconds, stop):  # the search, held up in its thread until the test lets it go
        seen.append(stop)
        started.set()
        release.wait(10)
        return real_late(deadline, seconds, stop)

    monkeypatch.setattr(owntext, "_late", late)

    async def main():
        task = asyncio.ensure_future(look_for("", folder, FLAG))
        begun = time.monotonic()
        while not started.is_set():
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        assert time.monotonic() - begun < 5  # the loop ran while the search was held up: it is in a thread
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert seen[0] is not None and seen[0].is_set()  # the cancel stopped it
        release.set()

    try:
        asyncio.run(main())
    finally:
        release.set()
