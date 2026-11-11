"""Lane workspaces, driven with real processes in tmp_path.

The host runtime always runs. The docker runtime runs only when docker answers and the image
debian:bookworm-slim is already on this machine (tests never pull, and use no other image);
otherwise those tests are skipped with the reason, so they report as not run. Every
container a test starts is removed afterwards, even when the test fails.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from ctf_flightdeck.agent import workspace as workspace_module
from ctf_flightdeck.agent.workspace import (
    HASH_LIMIT,
    OUTPUT_CAP,
    SNAPSHOT_FILES,
    TEXT_LIMIT,
    DockerWorkspace,
    HostWorkspace,
    RunResult,
    ShellSpec,
    WorkspaceError,
    changed_files,
    docker_unavailable,
    open_inside,
    take_snapshot,
    write_inside,
)

IMAGE = "debian:bookworm-slim"
FAKE_KEY = "fake-key-value-for-the-env-test"
BASH_OWN = {"PWD", "SHLVL", "_", "OLDPWD"}  # bash sets these itself
ALLOWED = {"PATH", "LANG", "LC_ALL", "TERM", "HOME", "TMPDIR"}


def run(coro):
    return asyncio.run(coro)


def assert_dies(pid: int, within: float = 5.0) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail(f"process {pid} is still alive after {within} s")


@pytest.fixture
def handout(tmp_path: Path) -> Path:
    """A synthetic handout: text, binary, a subdirectory, a file with an executable mode (never
    run), symlinks out of and inside the handout, a FIFO, and a planted .flightdeck."""
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("not for the lane\n")
    h = tmp_path / "handout"
    (h / "docs").mkdir(parents=True)
    (h / "challenge.json").write_text('{"name": "Demo", "category": "misc", "points": 50}\n')
    (h / "notes.txt").write_text("the key is somewhere\n")
    (h / "blob.bin").write_bytes(bytes(range(256)))
    (h / "docs" / "readme.md").write_text("# readme\n")
    (h / "run.sh").write_text("#!/bin/sh\necho never run\n")
    (h / "run.sh").chmod(0o755)
    os.symlink(outside, h / "leak")
    os.symlink("../../outside-secret.txt", h / "docs" / "up")
    os.symlink("notes.txt", h / "alias")
    os.mkfifo(h / "pipe")
    (h / ".flightdeck" / "home").mkdir(parents=True)
    (h / ".flightdeck" / "home" / ".bashrc").write_text("echo planted\n")
    old = time.time() - 400 * 86400
    os.utime(h / "notes.txt", (old, old))
    return h


def tree_state(top: Path) -> dict[str, tuple]:
    """Everything about a tree that a write would change, read without opening FIFOs or following links."""
    state = {".": (os.lstat(top).st_mode, os.lstat(top).st_mtime_ns)}
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                extra = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                extra = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                extra = ""
            state[str(path.relative_to(top))] = (info.st_mode, info.st_size, info.st_mtime_ns, extra)
    return state


@pytest.fixture
def lane(tmp_path: Path, handout: Path):
    ws = HostWorkspace(tmp_path / "lane", handout)
    run(ws.prepare())
    yield ws
    run(ws.close())


# ---------------------------------------------------------------- prepare


def test_prepare_copies_the_handout_with_its_times_and_modes_and_makes_the_lane_dirs(tmp_path, handout):
    (tmp_path / "lane").mkdir()  # an existing empty directory is fine
    ws = HostWorkspace(tmp_path / "lane", handout)
    run(ws.prepare())
    root = ws.root
    assert (root / "challenge.json").read_text() == (handout / "challenge.json").read_text()
    assert (root / "blob.bin").read_bytes() == bytes(range(256))
    assert (root / "docs" / "readme.md").read_text() == "# readme\n"
    assert os.stat(root / "notes.txt").st_mtime_ns == os.stat(handout / "notes.txt").st_mtime_ns
    assert stat.S_IMODE(os.stat(root / "run.sh").st_mode) & 0o111 == 0o111
    assert (root / ".flightdeck" / "home").is_dir() and (root / ".flightdeck" / "tmp").is_dir()


def test_prepare_skips_symlinks_special_files_and_a_planted_flightdeck_and_logs_each(tmp_path, handout):
    ws = HostWorkspace(tmp_path / "lane", handout)
    run(ws.prepare())
    for name in ("leak", "alias", "docs/up", "pipe"):
        assert not os.path.lexists(ws.root / name), name
    assert not (ws.root / ".flightdeck" / "home" / ".bashrc").exists()
    copied = [p for p in ws.root.rglob("*") if p.is_file() and ".flightdeck" not in p.parts]
    assert all("not for the lane" not in p.read_text(errors="replace") for p in copied)
    log = (ws.root / ".flightdeck" / "prepare.log").read_text().splitlines()
    size = sum(os.path.getsize(handout / n) for n in ("challenge.json", "notes.txt", "blob.bin", "docs/readme.md", "run.sh"))
    assert log[0] == f"copied 5 files ({size} bytes) from the handout"
    skipped = sorted(line.split(":")[0] for line in log[1:])
    assert skipped == ['skipped ".flightdeck"', 'skipped "alias"', 'skipped "docs/up"', 'skipped "leak"', 'skipped "pipe"']
    assert any(line.startswith('skipped "leak": a symlink (to ') for line in log)


def test_prepare_and_the_lane_never_write_to_the_handout(tmp_path, handout):
    before = tree_state(handout)

    async def scenario():
        ws = HostWorkspace(tmp_path / "lane", handout)
        await ws.prepare()
        await ws.run("rm -rf ./* && echo changed > notes.txt && chmod 000 notes.txt", timeout=10)
        await ws.close()

    run(scenario())
    assert tree_state(handout) == before


@pytest.mark.parametrize("where", ["inside", "same", "around"])
def test_prepare_refuses_a_root_that_overlaps_the_handout(tmp_path, handout, where):
    root = {"inside": handout / "lane", "same": handout, "around": tmp_path}[where]
    before = tree_state(handout)
    with pytest.raises(WorkspaceError, match="overlap"):
        run(HostWorkspace(root, handout).prepare())
    assert tree_state(handout) == before


def test_prepare_refuses_a_root_that_is_not_empty(tmp_path, handout):
    (tmp_path / "lane").mkdir()
    (tmp_path / "lane" / "left-over.txt").write_text("from an earlier lane\n")
    with pytest.raises(WorkspaceError, match="not an empty directory"):
        run(HostWorkspace(tmp_path / "lane", handout).prepare())


def test_prepare_names_a_missing_handout(tmp_path):
    with pytest.raises(WorkspaceError, match="handout .*nowhere is not a directory"):
        run(HostWorkspace(tmp_path / "lane", tmp_path / "nowhere").prepare())


# ---------------------------------------------------------------- host commands


def test_run_merges_stdout_and_stderr_in_order_and_reports_the_exit_code(lane):
    result = run(lane.run("echo one; echo two >&2; echo three; exit 3", timeout=10))
    assert result == RunResult(3, b"one\ntwo\nthree\n")


def test_run_works_in_the_lane_directory(lane):
    out = run(lane.run("pwd -P; cat notes.txt", timeout=10)).output.decode().splitlines()
    assert out == [str(lane.root.resolve()), "the key is somewhere"]


def test_stdin_is_piped_when_given_and_at_end_of_file_otherwise(lane):
    assert run(lane.run("cat", timeout=10, stdin=b"abc\x00def")).output == b"abc\x00def"
    assert run(lane.run("wc -c", timeout=10, stdin=b"x" * 1_000_000)).output.split() == [b"1000000"]
    started = time.monotonic()
    assert run(lane.run("cat", timeout=30)) == RunResult(0, b"")
    assert time.monotonic() - started < 10


def test_commands_see_only_the_allowlisted_environment(lane, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    monkeypatch.setenv("GITHUB_TOKEN", FAKE_KEY + "-2")
    monkeypatch.setenv("LC_CTYPE", "UTF-8")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "C")
    out = run(lane.run("env", timeout=10)).output.decode()
    assert FAKE_KEY not in out
    env = dict(line.split("=", 1) for line in out.splitlines())
    assert set(env) - BASH_OWN == ALLOWED
    assert env["PATH"] == os.environ["PATH"]
    assert (env["LANG"], env["LC_ALL"], env["TERM"]) == ("C.UTF-8", "C", "dumb")
    assert env["HOME"] == str(lane.root / ".flightdeck" / "home")
    assert env["TMPDIR"] == str(lane.root / ".flightdeck" / "tmp")


def test_unset_optional_variables_stay_unset(lane, monkeypatch):
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    out = run(lane.run("env", timeout=10)).output.decode()
    assert set(dict(line.split("=", 1) for line in out.splitlines())) - BASH_OWN == {"PATH", "TERM", "HOME", "TMPDIR"}


def test_home_and_tmp_come_back_if_the_lane_deletes_them(lane):
    run(lane.run("rm -rf .flightdeck", timeout=10))
    assert run(lane.run('touch "$HOME/h" "$TMPDIR/t" && echo ok', timeout=10)).output == b"ok\n"


BREAKAGES = {
    "a file at .flightdeck": "rm -rf .flightdeck && touch .flightdeck",
    "a symlink at .flightdeck": "rm -rf .flightdeck && ln -s {elsewhere} .flightdeck",
    "a file at .flightdeck/home": "rm -rf .flightdeck/home && echo x > .flightdeck/home",
    "a symlink at .flightdeck/tmp": "rm -rf .flightdeck/tmp && ln -s {elsewhere} .flightdeck/tmp",
    "a fifo at .flightdeck/home": "rm -rf .flightdeck/home && mkfifo .flightdeck/home",
}


def assert_private_dirs_are_real(root: Path) -> None:
    for sub in (".flightdeck", ".flightdeck/home", ".flightdeck/tmp"):
        assert stat.S_ISDIR(os.lstat(root / sub).st_mode), sub


@pytest.mark.parametrize("breakage", list(BREAKAGES))
def test_a_lane_that_puts_something_else_at_flightdeck_gets_the_directories_back(lane, tmp_path, breakage):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert run(lane.run(BREAKAGES[breakage].format(elsewhere=elsewhere), timeout=10)).exit_code == 0
    assert run(lane.run('touch "$HOME/h" "$TMPDIR/t" && echo ok', timeout=10)) == RunResult(0, b"ok\n")
    assert_private_dirs_are_real(lane.root)
    assert list(elsewhere.iterdir()) == []  # the symlink itself went; nothing was made where it pointed


@pytest.mark.parametrize("breakage", ["a file at .flightdeck", "a symlink at .flightdeck"])
def test_the_take_over_shell_opens_after_the_lane_broke_flightdeck(lane, tmp_path, breakage):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    run(lane.run(BREAKAGES[breakage].format(elsewhere=elsewhere), timeout=10))
    spec = lane.interactive_shell()
    assert (spec.argv, spec.cwd) == (["bash", "-i"], lane.root)
    assert spec.env["HOME"] == str(lane.root / ".flightdeck" / "home")
    assert_private_dirs_are_real(lane.root)
    assert list(elsewhere.iterdir()) == []


def test_flightdeck_that_cannot_be_repaired_gives_an_error_result_and_the_take_over_still_opens(lane):
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions, so this cannot make the repair fail")
    run(lane.run("chmod 000 .flightdeck", timeout=10))
    try:
        result = run(lane.run("touch ran.txt", timeout=10))
        spec = lane.interactive_shell()
    finally:
        os.chmod(lane.root / ".flightdeck", 0o755)
    assert (result.exit_code, result.timed_out) == (126, False)
    assert result.output.startswith(b"flightdeck: cannot set up .flightdeck/home and .flightdeck/tmp: [Errno 13] Permission denied")
    assert b"the command was not run" in result.output and b"take over the lane" in result.output
    assert not (lane.root / "ran.txt").exists()
    assert spec.cwd == lane.root
    assert run(lane.run("echo ok", timeout=10)) == RunResult(0, b"ok\n")  # and it works again once it can be repaired


def test_a_timeout_kills_the_whole_process_group_and_keeps_the_partial_output(lane):
    started = time.monotonic()
    result = run(lane.run("sleep 300 & echo $! > bg.pid; echo partial; sleep 300", timeout=1))
    assert (result.exit_code, result.timed_out) == (None, True)
    assert result.output == b"partial\n"
    assert time.monotonic() - started < 10
    assert_dies(int((lane.root / "bg.pid").read_text()))


def test_a_background_child_holding_the_output_keeps_the_command_running_until_the_timeout(lane):
    started = time.monotonic()
    result = run(lane.run("sleep 300 & echo $!", timeout=1))
    assert result.timed_out and time.monotonic() - started < 10
    assert_dies(int(result.output))


def test_output_over_10_mb_is_dropped_with_a_note(lane):
    result = run(lane.run("head -c 11000000 /dev/zero | tr '\\0' a", timeout=120))
    assert result.exit_code == 0
    assert result.output[:OUTPUT_CAP] == b"a" * OUTPUT_CAP
    assert result.output[OUTPUT_CAP:] == f"\n[output over 10 MB: {11_000_000 - OUTPUT_CAP} more bytes dropped]\n".encode()


def test_a_command_killed_by_a_signal_reports_128_plus_the_signal(lane):
    assert run(lane.run("kill -SEGV $$", timeout=10)).exit_code == 139


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
def test_a_timeout_must_be_a_positive_finite_number(lane, bad):
    with pytest.raises(ValueError, match="timeout"):
        run(lane.run("true", timeout=bad))


def test_a_command_with_a_nul_character_is_refused(lane):
    with pytest.raises(ValueError, match="NUL"):
        run(lane.run("echo a\0b", timeout=5))


def test_close_kills_what_the_lane_left_running_and_can_be_called_twice(lane):
    pid = int(run(lane.run("nohup sleep 300 >/dev/null 2>&1 & echo $!", timeout=10)).output)
    os.kill(pid, 0)  # still running after its command returned
    run(lane.close())
    run(lane.close())
    assert_dies(pid)
    with pytest.raises(WorkspaceError, match="closed"):
        run(lane.run("true", timeout=5))


def test_close_stops_a_command_that_is_still_running(tmp_path, handout):
    async def scenario():
        ws = HostWorkspace(tmp_path / "lane", handout)
        await ws.prepare()
        task = asyncio.create_task(ws.run("sleep 300", timeout=120))
        await asyncio.sleep(0.5)
        await ws.close()
        return await asyncio.wait_for(task, 10)

    result = run(scenario())
    assert (result.exit_code, result.timed_out) == (None, False)


def test_run_before_prepare_fails_loudly(tmp_path, handout):
    ws = HostWorkspace(tmp_path / "lane", handout)
    with pytest.raises(WorkspaceError, match="not prepared"):
        run(ws.run("true", timeout=5))
    with pytest.raises(WorkspaceError, match="not prepared"):
        ws.interactive_shell()


def test_the_host_take_over_shell_opens_in_the_lane_dir_with_the_allowlisted_environment(lane, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    monkeypatch.setenv("TERM", "xterm-256color")
    spec = lane.interactive_shell()
    assert (spec.argv, spec.cwd) == (["bash", "-i"], lane.root)
    assert FAKE_KEY not in json.dumps(spec.env)
    assert set(spec.env) <= ALLOWED | {"HISTFILE"}
    assert spec.env["HISTFILE"] == str(lane.root / ".flightdeck" / "takeover_history")
    assert spec.env["HOME"] == str(lane.root / ".flightdeck" / "home")
    assert spec.env["TERM"] == "xterm-256color"  # the player's terminal, not the commands' dumb one
    assert HostWorkspace(lane.root, lane.handout, shell="zsh").shell == "zsh"


# ---------------------------------------------------------------- flightdeck's own reads and writes


def test_flightdeck_never_reads_or_writes_through_a_symlink_in_a_workspace(tmp_path):
    root = tmp_path / "ws"
    (root / "real").mkdir(parents=True)
    (root / "real" / "f.txt").write_text("mine\n")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("host file\n")
    os.symlink(tmp_path / "outside" / "secret.txt", root / "leak")
    os.symlink(tmp_path / "outside", root / "dirlink")
    fd = open_inside(root, ["real", "f.txt"])
    assert os.read(fd, 100) == b"mine\n"
    os.close(fd)
    for parts in (["leak"], ["dirlink", "secret.txt"]):
        with pytest.raises(OSError):
            open_inside(root, parts)
    with pytest.raises(OSError):
        write_inside(root, "dirlink/new.txt", b"x")
    write_inside(root, "leak", b"replaced")  # the link is replaced, never written through
    assert (root / "leak").read_bytes() == b"replaced" and not (root / "leak").is_symlink()
    assert sorted(os.listdir(tmp_path / "outside")) == ["secret.txt"]
    assert (tmp_path / "outside" / "secret.txt").read_text() == "host file\n"
    with pytest.raises(ValueError):
        write_inside(root, "../escape.txt", b"x")


# ---------------------------------------------------------------- snapshots and diffs


def snapshot_within(root: Path, seconds: float = 10.0):
    """take_snapshot in a thread, so a hang (say, on a FIFO) fails the test instead of the suite."""
    box: dict = {}
    worker = threading.Thread(target=lambda: box.setdefault("snapshot", take_snapshot(root)), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "take_snapshot hung"
    return box["snapshot"]


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def test_a_snapshot_lists_files_with_size_time_and_hash_and_keeps_small_texts(tmp_path):
    root = tmp_path / "ws"
    (root / "d" / ".flightdeck").mkdir(parents=True)
    (root / ".flightdeck").mkdir()
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("host file\n")
    (root / "a.txt").write_text("hello\n")
    (root / "d" / "b.bin").write_bytes(b"\x00\x01\x02")
    (root / "big.txt").write_bytes(b"x" * (TEXT_LIMIT + 1))
    (root / "huge.bin").write_bytes(b"y" * (HASH_LIMIT + 1))
    (root / "latin1.txt").write_bytes("café\n".encode("latin-1"))
    (root / ".flightdeck" / "ours.txt").write_text("flightdeck's own\n")
    (root / "d" / ".flightdeck" / "y.txt").write_text("the lane's\n")  # only the top one is flightdeck's
    os.symlink(root / "a.txt", root / "link")
    os.symlink(tmp_path / "outside", root / "dirlink")
    os.mkfifo(root / "fifo")
    snap = snapshot_within(root)
    assert set(snap.files) == {"a.txt", "d/b.bin", "big.txt", "huge.bin", "latin1.txt", "d/.flightdeck/y.txt"}
    assert snap.files["a.txt"] == (6, os.stat(root / "a.txt").st_mtime_ns, sha1(b"hello\n"))
    assert snap.files["big.txt"][2] == sha1(b"x" * (TEXT_LIMIT + 1))
    assert snap.files["huge.bin"] == (HASH_LIMIT + 1, os.stat(root / "huge.bin").st_mtime_ns, "")
    assert snap.texts == {"a.txt": "hello\n", "d/.flightdeck/y.txt": "the lane's\n"}
    assert not snap.truncated


def test_a_snapshot_stops_after_5000_files_in_name_order(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    for i in range(SNAPSHOT_FILES + 1):
        (root / f"f{i:05d}").write_bytes(b"")
    snap = take_snapshot(root)
    assert snap.truncated and len(snap.files) == SNAPSHOT_FILES
    assert "f04999" in snap.files and "f05000" not in snap.files
    (root / "f05000").unlink()
    exact = take_snapshot(root)
    assert not exact.truncated and len(exact.files) == SNAPSHOT_FILES


def test_a_snapshot_of_a_missing_root_fails_loudly(tmp_path):
    with pytest.raises(WorkspaceError, match="cannot snapshot"):
        take_snapshot(tmp_path / "gone")


def test_changed_files_reports_added_modified_and_deleted_files_with_unified_diffs(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "keep.txt").write_text("same\n")
    (root / "edit.txt").write_text("one\ntwo\n")
    (root / "gone.txt").write_text("bye\n")
    before = take_snapshot(root)
    (root / "edit.txt").write_text("one\n2\n")
    (root / "gone.txt").unlink()
    (root / "new.txt").write_text("hi\n")
    (root / "empty").write_bytes(b"")
    changes = changed_files(before, take_snapshot(root), root)
    assert [(c.path, c.status) for c in changes] == [
        ("edit.txt", "modified"),
        ("empty", "added"),
        ("gone.txt", "deleted"),
        ("new.txt", "added"),
    ]
    edit, empty, gone, new = changes
    assert edit.diff == "--- a/edit.txt\n+++ b/edit.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+2"
    assert empty.diff == "--- /dev/null\n+++ b/empty"
    assert gone.diff == "--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye"
    assert new.diff == "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+hi"
    assert (edit.added, edit.removed, gone.removed, new.added) == (1, 1, 1, 1)
    assert all(c.turn == 0 and c.at == 0.0 for c in changes)


def test_a_change_is_judged_by_content_not_by_time(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "touched.txt").write_text("abc\n")
    (root / "sneaky.txt").write_text("abc\n")
    before = take_snapshot(root)
    then = os.stat(root / "sneaky.txt").st_mtime_ns
    (root / "sneaky.txt").write_text("abd\n")  # same size, same time, new content
    os.utime(root / "sneaky.txt", ns=(then, then))
    os.utime(root / "touched.txt", ns=(then + 60 * 10**9, then + 60 * 10**9))  # new time, same content
    assert [c.path for c in changed_files(before, take_snapshot(root), root)] == ["sneaky.txt"]


def test_files_over_1_mb_are_compared_by_size_and_time(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    big = root / "big.bin"
    big.write_bytes(b"\0" * (HASH_LIMIT + 10))
    before = take_snapshot(root)
    then = os.stat(big).st_mtime_ns
    big.write_bytes(b"\1" + b"\0" * (HASH_LIMIT + 9))
    os.utime(big, ns=(then, then))
    assert changed_files(before, take_snapshot(root), root) == []  # no hash: same size and time look the same
    os.utime(big, ns=(then + 10**9, then + 10**9))
    [change] = changed_files(before, take_snapshot(root), root)
    assert (change.status, change.diff) == ("modified", f"binary file, {HASH_LIMIT + 10} bytes")


def test_binary_and_large_files_get_a_one_line_summary_instead_of_a_diff(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    empty = take_snapshot(root)
    (root / "small.bin").write_bytes(b"\x00\x01" * 10)
    (root / "latin1.txt").write_bytes("café\n".encode("latin-1"))
    (root / "log.txt").write_text("line\n" * 20_000)
    (root / "big.bin").write_bytes(b"\x00" * (TEXT_LIMIT + 1))
    first = take_snapshot(root)
    summaries = {c.path: c.diff for c in changed_files(empty, first, root)}
    assert summaries == {
        "big.bin": f"binary file, {TEXT_LIMIT + 1} bytes",
        "latin1.txt": "binary file, 5 bytes",
        "log.txt": "text file over 64 KB, 100000 bytes",
        "small.bin": "binary file, 20 bytes",
    }
    (root / "small.bin").write_bytes(b"\x00" * 30)
    (root / "log.txt").unlink()
    later = {c.path: (c.status, c.diff) for c in changed_files(first, take_snapshot(root), root)}
    assert later == {
        "small.bin": ("modified", "binary file, 20 -> 30 bytes"),
        "log.txt": ("deleted", "file over 64 KB, 100000 bytes"),
    }


def test_a_last_line_without_a_newline_is_marked_like_git_does(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "f").write_text("a\nb")
    before = take_snapshot(root)
    (root / "f").write_text("a\nb\n")
    [change] = changed_files(before, take_snapshot(root), root)
    assert change.diff == "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b"
    assert (change.added, change.removed) == (1, 1)


def test_a_file_name_cannot_fake_lines_of_a_diff(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    before = take_snapshot(root)
    name = "x\n@@ -0,0 +1 @@\n+flag{fake}"
    (root / name).write_text("hi\n")
    [change] = changed_files(before, take_snapshot(root), root)
    assert change.path == name
    assert change.diff.splitlines() == ["--- /dev/null", '+++ "b/x\\n@@ -0,0 +1 @@\\n+flag{fake}"', "@@ -0,0 +1 @@", "+hi"]


def test_a_truncated_snapshot_does_not_report_files_past_its_end(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    for i in range(SNAPSHOT_FILES):
        (root / f"f{i:05d}").write_bytes(b"")
    full = take_snapshot(root)
    (root / "a-new.txt").write_text("new\n")  # sorts first and pushes f04999 past the limit
    pushed = take_snapshot(root)
    assert pushed.truncated and "f04999" not in pushed.files
    assert [(c.path, c.status) for c in changed_files(full, pushed, root)] == [("a-new.txt", "added")]
    (root / "a-new.txt").unlink()
    assert [(c.path, c.status) for c in changed_files(pushed, take_snapshot(root), root)] == [("a-new.txt", "deleted")]


# ---------------------------------------------------------------- docker, without a container


def test_docker_unavailable_names_a_missing_docker(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # an empty directory: no docker on it
    assert docker_unavailable() == "docker not found on PATH"


def test_docker_unavailable_names_a_daemon_that_is_not_running(monkeypatch, tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("the docker CLI is not installed here")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path}/no-daemon.sock")
    reason = docker_unavailable()
    assert reason is not None and reason.startswith("docker daemon not running")


def test_a_docker_lane_without_docker_fails_loudly_and_writes_nothing(monkeypatch, tmp_path, handout):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name="flightdeck-test-no-docker")
    with pytest.raises(WorkspaceError, match="docker not found on PATH"):
        run(ws.prepare())
    assert not (tmp_path / "lane").exists()
    run(ws.close())  # nothing was started, so nothing to remove


def test_the_container_is_started_from_a_local_image_only_with_limits(tmp_path, handout):
    ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name="flightdeck-test-args", memory="1g", cpus="1.5", pids_limit=64)
    args = ws.run_args()
    assert args[args.index("--pull") + 1] == "never"
    assert "--init" in args and "--rm" in args
    for flag, value in [("--memory", "1g"), ("--cpus", "1.5"), ("--pids-limit", "64"), ("--network", "bridge"), ("--name", "flightdeck-test-args")]:
        assert args[args.index(flag) + 1] == value
    assert args[args.index("-v") + 1] == f"{(tmp_path / 'lane').resolve()}:/work"
    assert args[args.index("--entrypoint") + 1] == "sleep" and args[-2:] == [IMAGE, "infinity"]


FAKE_DOCKER = r"""#!/bin/bash
# A stand-in for the docker CLI. It answers what DockerWorkspace asks while it prepares; on a
# lane's command (exec -i) it records its pid and hangs, the way a stuck docker would.
last=${!#}
case "$1" in
  version) echo 99.0.0-fake ;;
  image) echo sha256:fake ;;
  container) echo "Error: No such container: $last" >&2; exit 1 ;;
  run) echo fake-container-id ;;
  rm) exit 0 ;;
  exec)
    if [ "$2" = "-i" ]; then echo $$ > "$(dirname "$0")/exec.pid"; exec sleep 300; fi
    case "$last" in
      "command -v "*) echo "/usr/bin/${last#command -v }" ;;
      *) exit 1 ;;
    esac ;;
  *) echo "fake docker: unexpected call: $*" >&2; exit 2 ;;
esac
"""


def test_a_docker_exec_client_that_hangs_is_killed_by_the_backstop(tmp_path, handout, monkeypatch):
    """The real DockerWorkspace against a fake docker that never returns from a lane's command:
    the client is killed DOCKER_BACKSTOP seconds after the command's own timeout."""
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text(FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(workspace_module, "DOCKER_BACKSTOP", 1.0)
    ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name="flightdeck-test-fake-docker")

    async def scenario():
        await ws.prepare()
        started = time.monotonic()
        try:
            return await asyncio.wait_for(ws.run("sleep 300", timeout=0.5), 10), time.monotonic() - started
        finally:
            await ws.close()

    result, took = run(scenario())
    assert result == RunResult(None, b"", timed_out=True)
    assert took < 5
    assert_dies(int((fake_bin / "exec.pid").read_text()), within=2)


@pytest.mark.parametrize(
    "change",
    [{"name": "-x"}, {"name": "a b"}, {"image": "--privileged"}, {"image": ""}, {"memory": "lots"}, {"cpus": "two"}, {"pids_limit": 0}, {"network": "--x"}],
)
def test_docker_settings_are_checked(tmp_path, handout, change):
    settings = {"image": IMAGE, "name": "flightdeck-test-ok"} | change
    with pytest.raises(ValueError):
        DockerWorkspace(tmp_path / "lane", handout, **settings)


# ---------------------------------------------------------------- docker, with a container


def _docker_skip_reason() -> str | None:
    reason = docker_unavailable()
    if reason:
        return reason
    probe = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, timeout=60)
    if probe.returncode != 0:
        return f"image {IMAGE} is not present locally (these tests never pull it)"
    return None


@pytest.fixture(scope="module")
def docker_ready():
    reason = _docker_skip_reason()
    if reason:
        pytest.skip(reason)


@pytest.fixture
def container_name(docker_ready):
    """A fresh container name, removed after the test whatever happened in it."""
    name = f"flightdeck-test-{uuid.uuid4().hex[:12]}"
    yield name
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


@pytest.fixture
def box(tmp_path, handout, container_name):
    ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name=container_name)
    run(ws.prepare())
    yield ws
    run(ws.close())


def docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)


def test_a_docker_lane_runs_in_work_on_its_copy_of_the_handout(box):
    out = run(box.run("pwd; ls; cat notes.txt; echo made > made.txt", timeout=30)).output.decode().splitlines()
    assert out[0] == "/work"
    assert {"blob.bin", "challenge.json", "docs", "notes.txt", "run.sh"} <= set(out[1:-1])
    assert out[-1] == "the key is somewhere"
    assert (box.root / "made.txt").read_text() == "made\n"


def test_a_docker_command_merges_its_output_takes_stdin_and_reports_its_exit_code(box):
    assert run(box.run("cat; echo err >&2; exit 4", timeout=30, stdin=b"in\n")) == RunResult(4, b"in\nerr\n")
    assert run(box.run("cat", timeout=30)) == RunResult(0, b"")


def test_a_docker_timeout_kills_the_command_inside_the_container(box):
    started = time.monotonic()
    result = run(box.run("sleep 300 & echo started; sleep 301", timeout=1))
    assert (result.exit_code, result.timed_out, result.output) == (None, True, b"started\n")
    assert time.monotonic() - started < 10
    left = run(box.run("cat /proc/[0-9]*/cmdline | tr '\\0' ' '", timeout=30)).output.decode()
    assert "sleep 300" not in left and "sleep 301" not in left


def test_commands_killed_on_timeout_leave_no_zombies(box):
    for _ in range(4):
        assert run(box.run("sleep 30 & sleep 30", timeout=0.3)).timed_out
    time.sleep(0.5)
    zombies = run(box.run("cat /proc/[0-9]*/stat | awk '{print $3}' | grep -c Z || true", timeout=30)).output
    assert zombies.strip() == b"0"


def test_the_container_has_the_limits_an_init_and_the_bind_mount(box):
    info = json.loads(docker("container", "inspect", box.name).stdout)[0]
    host = info["HostConfig"]
    assert host["Memory"] == 2 * 1024**3
    assert host["NanoCpus"] == 2 * 10**9
    assert host["PidsLimit"] == 512
    assert host["NetworkMode"] == "bridge"
    assert host["Init"] is True and host["AutoRemove"] is True
    assert [(m["Source"], m["Destination"]) for m in info["Mounts"]] == [(str(box.root.resolve()), "/work")]


def test_a_docker_lane_sees_none_of_the_players_environment(box, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    assert FAKE_KEY.encode() not in run(box.run("env", timeout=30)).output


def test_docker_close_removes_the_container_and_can_be_called_twice(box):
    run(box.close())
    assert docker("container", "inspect", box.name).returncode != 0
    run(box.close())
    with pytest.raises(WorkspaceError, match="closed"):
        run(box.run("true", timeout=5))


def test_a_container_name_in_use_is_refused_and_the_other_container_is_left_alone(box, tmp_path, handout):
    other = DockerWorkspace(tmp_path / "other", handout, image=IMAGE, name=box.name)
    with pytest.raises(WorkspaceError, match="already in use"):
        run(other.prepare())
    run(other.close())
    assert not (tmp_path / "other").exists()
    assert run(box.run("echo still here", timeout=30)).output == b"still here\n"


def test_a_missing_image_is_refused_by_name_and_never_pulled(docker_ready, container_name, tmp_path, handout):
    missing = "flightdeck-test-missing-image:never"
    ws = DockerWorkspace(tmp_path / "lane", handout, image=missing, name=container_name)
    with pytest.raises(WorkspaceError, match=f"image {missing} is not present locally"):
        run(ws.prepare())
    assert docker("image", "inspect", missing).returncode != 0
    assert docker("container", "inspect", container_name).returncode != 0
    assert not (tmp_path / "lane").exists()


def test_a_container_removed_outside_flightdeck_fails_loudly(box):
    docker("rm", "-f", box.name)
    with pytest.raises(WorkspaceError, match="not running"):
        run(box.run("true", timeout=30))


def test_the_docker_take_over_shell_is_docker_exec_in_work(box):
    assert box.interactive_shell() == ShellSpec(["docker", "exec", "-it", "-w", "/work", box.name, "bash", "-i"], None, None)


def test_a_snapshot_never_follows_a_symlink_the_container_planted(box):
    run(box.run("ln -s /etc/passwd leak && mkdir real && echo mine > real/f && ln -s /etc linked", timeout=30))
    snap = take_snapshot(box.root)
    assert "real/f" in snap.files
    assert not any(p.startswith(("leak", "linked")) for p in snap.files)
