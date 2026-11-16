"""Sessions (P82): long-lived processes a lane talks to across turns, through the toolbox.

Every process here is synthetic: bash, cat, sleep and a shell loop, never a challenge's
binary. The host runtime always runs. The docker tests run only when docker answers and
debian:bookworm-slim is already on this machine (tests never pull), and the docker terminal
session's also needs python:3.12-slim (a container with python3); otherwise they are
skipped with the reason, so they report as not run. Each test runs in one event loop, since
a session lives across calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from ctf_flightdeck.agent import sessions as sessions_module
from ctf_flightdeck.agent.held import Secrets
from ctf_flightdeck.agent.sessions import Sessions
from ctf_flightdeck.agent.terminal import ESCAPE_LIMIT, TERMINAL_LINE, TerminalText
from ctf_flightdeck.agent.tools import TOOLS, Toolbox, ToolResult
from ctf_flightdeck.agent.workspace import NO_TERMINAL_PYTHON, DockerWorkspace, HostWorkspace, docker_unavailable
from l1_kit import docker_not_run

IMAGE = "debian:bookworm-slim"
KEY = "sk-held-secret-value-1234"


@pytest.fixture
def handout(tmp_path: Path) -> Path:
    h = tmp_path / "handout"
    h.mkdir()
    (h / "challenge.json").write_text('{"name": "Demo", "category": "pwn", "points": 50}\n')
    (h / "notes.txt").write_text("hello\n")
    return h


async def host_box(tmp_path: Path, handout: Path, **kwargs) -> Toolbox:
    ws = HostWorkspace(tmp_path / "lane", handout)
    await ws.prepare()
    return Toolbox(ws, **kwargs)


async def call(box: Toolbox, name: str, args: dict, *, turn: int = 1, index: int = 0) -> ToolResult:
    return await box.call(name, json.dumps(args), turn=turn, index=index)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def gone_soon(pid: int, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return False


# ---------------------------------------------------------------- the schemas


def test_the_session_tools_are_offered_with_their_arguments():
    schemas = {t["function"]["name"]: t["function"]["parameters"] for t in TOOLS}
    assert schemas["session_start"]["required"] == ["command"]
    assert set(schemas["session_start"]["properties"]) == {"command", "terminal", "wait_seconds"}
    assert set(schemas["session_send"]["properties"]) == {"session", "input", "newline", "until", "wait_seconds"}
    assert schemas["session_send"]["required"] == ["session"]
    assert schemas["session_close"]["required"] == ["session"]


# ---------------------------------------------------------------- on the host


def test_a_session_keeps_its_state_across_calls(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        started = await call(box, "session_start", {"command": "bash", "wait_seconds": 0.2})
        assert not started.error and started.content.startswith("session s1: running")
        await call(box, "session_send", {"session": "s1", "input": "secret_number=41"})
        answer = await call(box, "session_send", {"session": "s1", "input": "echo $((secret_number + 1)) $(cat notes.txt)"})
        await box.workspace.close()
        return started, answer

    started, answer = asyncio.run(go())
    status, output = answer.content.split("\n", 1)
    assert status.startswith("session s1: running; quiet after") and output == "42 hello\n"
    assert answer.action == "session s1 < echo $((secret_number + 1)) $(cat notes.txt)"


def test_until_ends_the_read_as_soon_as_the_text_appears(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        # a line, a pause past QUIET, then a prompt with no newline and a long silence: until
        # waits through the pause, and not through the silence
        await call(box, "session_start", {"command": "sleep 0.3; printf 'loading\\n'; sleep 1; printf 'ready> '; sleep 60",
                                          "wait_seconds": 0})
        begun = time.monotonic()
        result = await call(box, "session_send", {"session": "s1", "until": "ready> ", "wait_seconds": 20})
        took = time.monotonic() - begun
        await box.close_sessions("test over")
        await box.workspace.close()
        return result, took

    result, took = asyncio.run(go())
    assert result.content == "session s1: running; 'ready> ' appeared\nloading\nready> "
    assert took < 5


def test_without_until_a_read_ends_once_the_output_is_quiet(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        begun = time.monotonic()
        result = await call(box, "session_start", {"command": "echo first; sleep 60", "wait_seconds": 30})
        took = time.monotonic() - begun
        silent = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        await box.close_sessions("test over")
        await box.workspace.close()
        return result, took, silent

    result, took, silent = asyncio.run(go())
    assert result.content.startswith("session s1: running; quiet after") and result.content.endswith("\nfirst\n")
    assert took < 5  # quiet after QUIET seconds, not the 30 asked
    assert silent.content == "session s1: running; no output in 0.3 s\n(no output)"
    assert silent.action == "session s1 read"


def test_output_from_before_a_send_does_not_end_the_read_of_its_reply(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        # a program still loading when the start's read ends: what it writes then waits unread
        await call(box, "session_start", {"command": "sleep 0.3; echo first; cat", "wait_seconds": 0.1})
        await asyncio.sleep(1.0)
        reply = await call(box, "session_send", {"session": "s1", "input": "hi", "wait_seconds": 10})
        await box.close_sessions("test over")
        await box.workspace.close()
        return reply

    reply = asyncio.run(go())
    assert reply.content.startswith("session s1: running; quiet after")
    assert reply.content.endswith("\nfirst\nhi\n")  # the old line comes too, and the reply with it, not a call late


def test_until_is_looked_for_only_in_what_came_after_the_send(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        command = "printf '(gdb) '; while read -r line; do sleep 0.3; echo \"got $line\"; printf '(gdb) '; done"
        await call(box, "session_start", {"command": command, "wait_seconds": 0})
        await asyncio.sleep(0.5)  # the first prompt waits unread
        reply = await call(box, "session_send", {"session": "s1", "input": "break main", "until": "(gdb) ", "wait_seconds": 10})
        await box.close_sessions("test over")
        await box.workspace.close()
        return reply

    reply = asyncio.run(go())
    assert reply.content == "session s1: running; '(gdb) ' appeared\n(gdb) got break main\n(gdb) "


def test_a_session_that_ends_says_its_status_and_is_gone_after(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        ended = await call(box, "session_start", {"command": "echo bye; exit 3", "wait_seconds": 5})
        again = await call(box, "session_send", {"session": "s1", "input": "anything"})
        await box.workspace.close()
        return ended, again

    ended, again = asyncio.run(go())
    assert ended.content == "session s1: ended, exit 3\nbye\n"
    assert again.error and again.content == "error: session s1 is gone: it ended (exit 3)"


def test_newline_false_sends_the_input_as_it_is(tmp_path, handout):
    # A reader that waits for all six bytes, on every system (GNU head -c writes what it has
    # read at once, so "abc" would come in the first read on Linux and not on a Mac).
    async def go():
        box = await host_box(tmp_path, handout)
        await call(box, "session_start", {"command": "python3 -c \"import sys; sys.stdout.write(sys.stdin.buffer.read(6).decode() + '|\\n')\"",
                                          "wait_seconds": 0})
        await call(box, "session_send", {"session": "s1", "input": "abc", "newline": False, "wait_seconds": 0.2})
        done = await call(box, "session_send", {"session": "s1", "input": "def", "newline": False, "wait_seconds": 5})
        await box.workspace.close()
        return done

    done = asyncio.run(go())
    assert done.content == "session s1: ended, exit 0\nabcdef|\n"


def test_at_most_three_sessions_are_open_and_names_are_never_reused(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        for _ in range(3):
            assert not (await call(box, "session_start", {"command": "cat", "wait_seconds": 0})).error
        refused = await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        closed = await call(box, "session_close", {"session": "s2"})
        fourth = await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        old = await call(box, "session_send", {"session": "s2", "input": "x"})
        unknown = await call(box, "session_send", {"session": "s9", "input": "x"})
        await box.close_sessions("test over")
        await box.workspace.close()
        return refused, closed, fourth, old, unknown

    refused, closed, fourth, old, unknown = asyncio.run(go())
    assert sessions_module.MAX_SESSIONS == 3
    assert refused.error and refused.content == (
        "error: 3 sessions are open already (s1 (running: cat), s2 (running: cat), s3 (running: cat)); "
        "close one with session_close first"
    )
    assert closed.content == "session s2 closed" and not closed.error
    assert fourth.content.startswith("session s4: running")
    assert old.content == "error: session s2 is gone: you closed it"
    assert unknown.content == "error: no session named s9; open now: s1, s3, s4"


def test_close_kills_the_process_and_everything_it_started(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        started = await call(box, "session_start", {"command": "sleep 300 & echo $!; cat", "wait_seconds": 5})
        child = int(started.content.splitlines()[1])
        assert alive(child)
        await call(box, "session_close", {"session": "s1"})
        await box.workspace.close()
        return child

    assert gone_soon(asyncio.run(go()))


def test_closing_the_lanes_sessions_kills_every_one(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        pids = []
        for _ in range(2):
            started = await call(box, "session_start", {"command": "sleep 300 & echo $!; wait", "wait_seconds": 5})
            pids.append(int(started.content.splitlines()[1]))
        names = await box.close_sessions("the lane ended")
        after = await call(box, "session_send", {"session": "s1"})
        await box.workspace.close()
        return pids, names, after

    pids, names, after = asyncio.run(go())
    assert names == ["s1", "s2"]
    assert all(gone_soon(pid) for pid in pids)
    assert after.content == "error: session s1 is gone: the lane ended"


def test_the_workspace_close_kills_a_session_nobody_closed(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        started = await call(box, "session_start", {"command": "echo $$; sleep 300", "wait_seconds": 5})
        await box.workspace.close()
        return int(started.content.splitlines()[1])

    assert gone_soon(asyncio.run(go()))


def test_a_session_unused_past_the_idle_time_is_closed(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        box.sessions = Sessions(box.workspace.open_session, idle=0.4)
        started = await call(box, "session_start", {"command": "echo $$; cat", "wait_seconds": 5})
        pid = int(started.content.splitlines()[1])
        kept = await call(box, "session_send", {"session": "s1", "input": "still here", "wait_seconds": 0.3})  # use resets it
        await asyncio.sleep(1.0)
        late = await call(box, "session_send", {"session": "s1", "input": "too late"})
        await box.workspace.close()
        return pid, kept, late

    pid, kept, late = asyncio.run(go())
    assert kept.content.endswith("\nstill here\n")
    assert late.error and late.content == "error: session s1 is gone: it was closed after 0.4 s unused"
    assert gone_soon(pid)


def test_output_past_the_buffer_is_dropped_oldest_first_and_counted(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        box.sessions = Sessions(box.workspace.open_session, cap=1000)
        await call(box, "session_start", {"command": "head -c 4000 /dev/zero | tr '\\0' a; printf END; sleep 30", "wait_seconds": 0})
        await asyncio.sleep(0.5)
        result = await call(box, "session_send", {"session": "s1", "wait_seconds": 2})
        await box.close_sessions("test over")
        await box.workspace.close()
        return result

    result = asyncio.run(go())
    lines = result.content.split("\n")
    assert lines[1] == "[3003 earlier bytes dropped: a session keeps at most 1000 bytes unread]"
    assert lines[2] == "a" * 997 + "END"


def test_dropping_the_oldest_bytes_never_cuts_a_secret_in_two(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        box.sessions = Sessions(box.workspace.open_session, cap=1000, unfinished=box.scrub.unfinished)
        # the key, then 990 bytes: a cut at the cap would land 15 bytes into the key
        await call(box, "session_start", {"command": f"printf {KEY}; head -c 990 /dev/zero | tr '\\0' a; sleep 30",
                                          "wait_seconds": 0})
        await asyncio.sleep(0.5)
        result = await call(box, "session_send", {"session": "s1", "wait_seconds": 2})
        await box.close_sessions("test over")
        await box.workspace.close()
        return result

    result = asyncio.run(go())
    assert KEY[15:] not in result.content
    assert result.content.endswith("\n[API_KEY]" + "a" * 990)  # kept whole, so found


def test_dropping_the_oldest_bytes_never_cuts_the_rest_of_a_secret_whose_start_a_read_showed(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        box.sessions = Sessions(box.workspace.open_session, cap=1000, unfinished=box.scrub.unfinished)
        # the key's start, released by a read; then its rest and 984 bytes: a cut at the cap
        # would land 2 bytes into the rest
        await call(box, "session_start", {"command": f"printf 'half={KEY[:7]}'; sleep 2; printf -- '{KEY[7:]}'; "
                                                     "head -c 984 /dev/zero | tr '\\0' a; sleep 30", "wait_seconds": 0.3})
        released = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        await asyncio.sleep(2.5)
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 2})
        await box.close_sessions("test over")
        await box.workspace.close()
        return released, rest

    released, rest = asyncio.run(go())
    assert released.content.endswith("\n" + KEY[:7])
    for text in (rest.content, rest.output, rest.excerpt):
        assert KEY[9:] not in text
    assert rest.content.endswith("\n[API_KEY]" + "a" * 984)  # kept whole with the shown start, so found


def test_long_output_is_cut_and_saved_like_the_shells(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, max_chars=500)
        result = await call(box, "session_start", {"command": "seq 1 2000; sleep 30", "wait_seconds": 5}, turn=4, index=1)
        await box.close_sessions("test over")
        await box.workspace.close()
        return box, result

    box, result = asyncio.run(go())
    assert len(result.content) <= 500
    assert "full output in .flightdeck/out/turn4-1.txt" in result.content
    saved = (box.workspace.root / ".flightdeck/out/turn4-1.txt").read_text()
    assert saved.splitlines()[-1] == "2000"


def test_a_held_secret_never_leaves_a_session_even_written_across_two_reads(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        whole = await call(box, "session_send", {"session": "s1", "input": f"key={KEY}"})
        first = await call(box, "session_send", {"session": "s1", "input": "half=" + KEY[:10], "newline": False, "wait_seconds": 1})
        rest = await call(box, "session_send", {"session": "s1", "input": KEY[10:]})
        await box.close_sessions("test over")
        await box.workspace.close()
        return whole, first, rest

    whole, first, rest = asyncio.run(go())
    for result in (whole, first, rest):  # what the session wrote; an action is what the model itself sent
        for text in (result.content, result.output, result.excerpt):
            assert KEY not in text and KEY[:10] not in text and KEY[10:] not in text
    assert KEY not in whole.action and "[API_KEY]" in whole.action
    assert whole.content.endswith("\nkey=[API_KEY]\n")
    assert first.content.endswith("\nhalf=")  # the start of the key waits for the rest
    assert rest.content.endswith("\n[API_KEY]\n")


def test_output_that_ends_like_a_secret_starts_is_held_once_and_said_then_released(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        first = await call(box, "session_start", {"command": 'printf "Are you sure? yes"; sleep 30', "wait_seconds": 5})
        second = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        third = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        await box.close_sessions("test over")
        await box.workspace.close()
        return first, second, third

    first, second, third = asyncio.run(go())
    assert first.content.split("\n")[-1] == "Are you sure? ye"  # the "s" could start the key
    assert "[1 more bytes held for the next read" in first.content
    assert second.content.split("\n")[-1] == "s"  # nothing came after it: released, not held for good
    assert "held" not in second.content and "no output" not in second.content
    assert third.content.endswith("running; no output in 0.3 s\n(no output)")


def test_a_read_that_matched_until_shows_the_match_whole(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        result = await call(box, "session_send", {"session": "s1", "input": "yes", "newline": False, "until": "yes"})
        await box.close_sessions("test over")
        await box.workspace.close()
        return result

    result = asyncio.run(go())
    assert result.content == "session s1: running; 'yes' appeared\nyes"


def test_a_secret_whose_start_a_matched_until_showed_is_still_scrubbed_in_the_next_read(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        await call(box, "session_start", {"command": f"printf 'key: {KEY[:10]}'; sleep 1; printf '{KEY[10:]}\\n'; sleep 30",
                                          "wait_seconds": 0})
        matched = await call(box, "session_send", {"session": "s1", "until": "sk-", "wait_seconds": 5})
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 5})
        await box.close_sessions("test over")
        await box.workspace.close()
        return matched, rest

    matched, rest = asyncio.run(go())
    assert matched.content.split("\n")[-1] == "key: sk-" and "appeared" in matched.content  # what matched is shown whole, the rest of what may be the key held
    for text in (rest.content, rest.output, rest.excerpt):
        assert KEY[3:] not in text and KEY[10:] not in text
    assert rest.content.endswith("\n[API_KEY]\n")


def test_the_file_of_a_cut_read_holds_a_secret_cut_between_two_reads_whole(tmp_path, handout):
    """A read too long to show is saved to a file; the file starts with what the last read carried,
    so a secret whose start that read showed is whole in it, and reading the file scrubs it."""
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}), max_chars=300)
        await call(box, "session_start", {"command": f"printf 'key: {KEY[:10]}'; sleep 1; printf '{KEY[10:]}'; "
                                                     "printf 'x%.0s' $(seq 1 600); printf '\\n'; sleep 30",
                                          "wait_seconds": 0})
        await call(box, "session_send", {"session": "s1", "until": "sk-", "wait_seconds": 5})
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 5}, turn=2)
        saved = (box.workspace.root / ".flightdeck" / "out" / "turn2-0.txt").read_bytes()
        again = await call(box, "read_file", {"path": ".flightdeck/out/turn2-0.txt"}, turn=3)
        await box.close_sessions("test over")
        await box.workspace.close()
        return rest, saved, again

    rest, saved, again = asyncio.run(go())
    assert "characters cut" in rest.content
    assert KEY.encode() in saved  # whole, so the scrubber can find it
    assert KEY[10:] not in again.content and "[API_KEY]" in again.content


def test_a_secret_whose_start_was_released_after_a_pause_is_still_scrubbed_after(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        await call(box, "session_start", {"command": f"printf 'half={KEY[:7]}'; sleep 2; printf -- '{KEY[7:]}\\n'; sleep 30",
                                          "wait_seconds": 0.3})
        released = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})  # nothing new: the held start comes
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 5})
        await box.close_sessions("test over")
        await box.workspace.close()
        return released, rest

    released, rest = asyncio.run(go())
    assert released.content.endswith("\n" + KEY[:7])
    for text in (rest.content, rest.output, rest.excerpt):
        assert KEY[7:] not in text
    assert rest.content.endswith("\n[API_KEY]\n")


def test_what_a_read_carries_over_is_not_shown_twice_when_no_secret_follows(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout, scrub=Secrets({"API_KEY": KEY}))
        await call(box, "session_start", {"command": "printf 'Are you sure? yes'; sleep 1; printf '\\nok\\n'; sleep 30",
                                          "wait_seconds": 0.3})
        released = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 5})
        await box.close_sessions("test over")
        await box.workspace.close()
        return released, rest

    released, rest = asyncio.run(go())
    assert released.content.endswith("\ns")
    assert rest.content.split("\n", 1)[1] == "\nok\n"


def test_what_a_read_carries_over_is_not_shown_twice_when_it_held_a_shorter_secret_or_half_a_character(tmp_path, handout):
    async def go():
        short, long = "abcdefgh", "abcdefghXYZ12345"  # the start of the long one holds the short one
        box = await host_box(tmp_path, handout, scrub=Secrets({"SHORT": short, "LONG": long}))
        await call(box, "session_start", {"command": "printf abcdefghXY; sleep 1; printf '\\nok\\n'; sleep 30",
                                          "wait_seconds": 0.3})
        released = await call(box, "session_send", {"session": "s1", "wait_seconds": 0.3})
        rest = await call(box, "session_send", {"session": "s1", "wait_seconds": 5})
        await box.close_sessions("test over")
        await box.workspace.close()
        return box, released, rest

    box, released, rest = asyncio.run(go())
    assert released.content.endswith("\n[SHORT]XY")
    assert rest.content.split("\n", 1)[1] == "\nok\n"
    # a carry that ends inside a character: the last read showed U+FFFD, the character now comes whole, once
    assert box._session_text("abcdefgh\u00e9".encode()[:-1], "\u00e9!".encode()[1:]) == "\u00e9!"


def test_what_the_model_gets_wrong_comes_back_as_an_error(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        results = [
            await call(box, "session_start", {"command": "  "}),
            await call(box, "session_start", {"command": "cat", "wait_seconds": "soon"}),
            await call(box, "session_send", {"session": "s1"}),
        ]
        await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        results += [
            await call(box, "session_send", {"session": "s1", "input": "x" * (64 * 1024)}),
            await call(box, "session_send", {"session": "s1", "input": "x", "newline": "yes"}),
            await call(box, "session_send", {"session": "s1", "until": ""}),
        ]
        await box.close_sessions("test over")
        await box.workspace.close()
        return results

    results = asyncio.run(go())
    assert all(r.error for r in results)
    assert [r.content for r in results] == [
        "error: command is empty",
        "error: wait_seconds must be a number",
        "error: no session named s1; open now: none",
        f"error: the input is {64 * 1024 + 1} bytes; one send takes at most {64 * 1024}: write it to a file and send a command that reads it",
        "error: newline must be true or false",
        "error: until is empty; leave it out to read until the session is quiet",
    ]


def test_a_workspace_without_sessions_says_so(tmp_path):
    class Plain:
        root = tmp_path

    async def go():
        return await call(Toolbox(Plain()), "session_start", {"command": "cat"})

    result = asyncio.run(go())
    assert result.error and result.content == "error: sessions are not available in this lane's workspace; use shell"


# ---------------------------------------------------------------- on a terminal (P87)


def test_the_terminal_filter_takes_escapes_out_even_split_across_chunks():
    text = TerminalText()
    stream = (b"\x1b[?2004h>>> \x1b[31mred\x1b[0m\r\n\x1b]0;title\x07ok\x1b]8;;http://x\x1b\\link\x1b(B\x1b=\a"
              b"\x1b[1;2Hend\r\n")
    whole = TerminalText().feed(stream)
    assert whole == b">>> red\noklinkend\n"
    pieces = b"".join(text.feed(stream[i:i + 1]) for i in range(len(stream)))  # one byte at a time
    assert pieces + text.flush() == whole


def test_an_escape_that_never_ends_gives_its_bytes_back_and_hides_nothing():
    text = TerminalText()
    out = text.feed(b"\x1b]" + b"F" * ESCAPE_LIMIT) + text.feed(b"LAG{x}\n")
    assert out.endswith(b"FLAG{x}\n") and b"\x1b" not in out
    unfinished = TerminalText()
    assert unfinished.feed(b"before \x1b[12") == b"before "
    assert unfinished.flush() == b"[12"  # the stream ended inside it: the bytes come back, the ESC does not
    assert TerminalText().feed(b"a\x1b\nb") == b"a\nb"  # an ESC that starts no sequence goes alone


def test_a_terminal_session_runs_on_a_tty_and_reads_back_as_plain_text(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        piped = await call(box, "session_start", {"command": "bash", "wait_seconds": 0.2})
        tty = await call(box, "session_start", {"command": "PS1= bash --norc", "terminal": True, "wait_seconds": 0.2})  # on a tty bash prompts
        probe = "test -t 0 && test -t 1 && echo tty $TERM || echo pipe"
        on_pipe = await call(box, "session_send", {"session": "s1", "input": probe})
        on_tty = await call(box, "session_send", {"session": "s2", "input": probe})
        coloured = await call(box, "session_send", {"session": "s2", "input": r"printf '\033[31mred\033[0m\r\nnext\n'"})
        group = os.getpgid(box.sessions.open["s2"].process.proc.pid)
        child = await call(box, "session_send", {"session": "s2", "input": "ps -o pgid= -p $$"})
        await box.close_sessions("test over")
        await box.workspace.close()
        return piped, tty, on_pipe, on_tty, coloured, group, child

    piped, tty, on_pipe, on_tty, coloured, group, child = asyncio.run(go())
    assert piped.action == "session s1 start: bash" and tty.action == "session s2 start (terminal): PS1= bash --norc"
    assert on_pipe.content.split("\n", 1)[1] == "pipe\n"
    assert on_tty.content.split("\n", 1)[1] == "tty dumb\n"  # no echo of what was sent
    assert coloured.content.split("\n", 1)[1] == "red\nnext\n"  # no escape and no carriage return reaches the model
    assert int(child.content.split("\n", 1)[1]) == group  # no session of its own: the group flightdeck kills holds it


def test_closing_a_terminal_session_kills_what_runs_on_its_terminal(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        started = await call(box, "session_start", {"command": "sleep 300 & echo child $!; cat", "terminal": True,
                                                    "wait_seconds": 1})
        await call(box, "session_close", {"session": "s1"})
        await box.workspace.close()
        return started

    started = asyncio.run(go())
    pid = int(started.content.split("child ", 1)[1].split()[0])
    assert gone_soon(pid)


def test_a_terminal_session_ends_with_its_programs_status(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        ended = await call(box, "session_start", {"command": "echo bye; exit 3", "terminal": True, "wait_seconds": 5})
        await box.workspace.close()
        return ended

    ended = asyncio.run(go())
    assert ended.content == "session s1: ended, exit 3\nbye\n"


def test_a_line_too_long_for_a_terminal_is_refused_not_cut(tmp_path, handout):
    async def go():
        box = await host_box(tmp_path, handout)
        await call(box, "session_start", {"command": "cat", "terminal": True, "wait_seconds": 0})
        await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        refused = await call(box, "session_send", {"session": "s1", "input": "x" * TERMINAL_LINE})
        fits = await call(box, "session_send", {"session": "s1", "input": "y" * (TERMINAL_LINE - 1), "until": "\n"})
        piped = await call(box, "session_send", {"session": "s2", "input": "z" * TERMINAL_LINE, "until": "\n"})
        wrong = await call(box, "session_start", {"command": "cat", "terminal": "yes"})
        await box.close_sessions("test over")
        await box.workspace.close()
        return refused, fits, piped, wrong

    refused, fits, piped, wrong = asyncio.run(go())
    assert refused.error and refused.content == (
        f"error: a line of the input is {TERMINAL_LINE} bytes; a terminal takes at most {TERMINAL_LINE - 1} in one line: "
        "write it to a file and send a command that reads it")
    assert fits.content.split("\n", 1)[1] == "y" * (TERMINAL_LINE - 1) + "\n"  # the longest line it takes, whole
    assert not piped.error  # pipes have no such limit
    assert wrong.error and wrong.content == "error: terminal must be true or false"


def test_a_terminal_session_hands_the_program_its_bytes_as_sent(tmp_path, handout):
    """The pty's line discipline would erase on DEL, kill on ctrl+u and ctrl+w, quote on ctrl+v,
    stop on ctrl+s, signal on ctrl+c and ctrl+z and turn a carriage return into a newline: a
    payload would reach the program changed. The relay turns that off; ctrl+d, which still ends
    the input, is refused rather than taken."""
    read_line = "python3 -c 'import sys; print(repr(sys.stdin.buffer.readline()))'"
    payload = "AB\x7fC\x15DE\x17F\rG\x16H\x08I\x13J\x11K\x03L\x1aM\x19N\x12O\x0fP\x14Q\x00R"

    async def go():
        box = await host_box(tmp_path, handout)
        await call(box, "session_start", {"command": read_line, "terminal": True, "wait_seconds": 0})
        read = await call(box, "session_send", {"session": "s1", "input": payload, "until": "\n", "wait_seconds": 10})
        await call(box, "session_start", {"command": "cat", "terminal": True, "wait_seconds": 0})
        await call(box, "session_start", {"command": "cat", "wait_seconds": 0})
        refused = await call(box, "session_send", {"session": "s2", "input": "a\x04b"})
        piped = await call(box, "session_send", {"session": "s3", "input": "a\x04b", "until": "b"})
        await box.close_sessions("test over")
        await box.workspace.close()
        return read, refused, piped

    read, refused, piped = asyncio.run(go())
    assert read.content.split("\n", 1)[1] == repr((payload + "\n").encode()) + "\n"
    assert refused.error and refused.content == (
        "error: the input holds ctrl+d (\\x04), which a terminal takes as the end of the input, not as a byte: "
        "write it to a file and send a command that reads it, or use a session without a terminal")
    assert not piped.error  # pipes take it as a byte


# ---------------------------------------------------------------- in a container


def _docker_skip_reason() -> str | None:
    reason = docker_unavailable()
    if reason:
        return reason
    probe = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, timeout=60)
    if probe.returncode != 0:
        return f"image {IMAGE} is not present locally (these tests never pull it)"
    return None


@pytest.fixture
def container_name():
    reason = _docker_skip_reason()
    if reason:
        docker_not_run(f"not run: {reason}")
    name = f"flightdeck-test-{uuid.uuid4().hex[:12]}"
    yield name
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


def test_a_docker_session_keeps_its_state_and_close_kills_it_in_the_container(tmp_path, handout, container_name):
    async def go():
        ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name=container_name)
        await ws.prepare()
        box = Toolbox(ws)
        started = await call(box, "session_start", {"command": "sleep 300 & echo child $!; bash", "wait_seconds": 5})
        pid = box.sessions.open["s1"].pid
        await call(box, "session_send", {"session": "s1", "input": "n=6; cd /work"})
        answer = await call(box, "session_send", {"session": "s1", "input": "echo $((n * 7)) $(pwd) >&2"})
        await call(box, "session_close", {"session": "s1"})
        left = (await ws.run("cat /proc/[0-9]*/cmdline | tr '\\0' ' '", timeout=30)).output.decode()
        await ws.close()
        return started, pid, answer, left

    started, pid, answer, left = asyncio.run(go())
    assert started.content.splitlines()[1].startswith("child ")  # the workspace's pid line is not output
    assert isinstance(pid, int) and pid > 1
    assert answer.content.endswith("\n42 /work\n")  # stderr comes through, merged
    assert "sleep 300" not in left


def test_a_docker_terminal_session_runs_on_a_tty_in_the_container(tmp_path, handout, container_name):
    """The relay runs on the container's python3; debian:bookworm-slim has none, so the session
    says so and ends, and nothing is started without the terminal that was asked for."""
    async def go():
        ws = DockerWorkspace(tmp_path / "lane", handout, image=IMAGE, name=container_name)
        await ws.prepare()
        box = Toolbox(ws)
        started = await call(box, "session_start", {"command": "bash", "terminal": True, "wait_seconds": 10})
        await ws.close()
        return started

    started = asyncio.run(go())
    assert started.content == f"session s1: ended, exit 127\n{NO_TERMINAL_PYTHON}\n"


PY_IMAGE = "python:3.12-slim"


def test_a_docker_terminal_session_with_python_in_the_container_is_a_tty_and_close_kills_it(tmp_path, handout):
    reason = docker_unavailable()
    if not reason and subprocess.run(["docker", "image", "inspect", PY_IMAGE], capture_output=True, timeout=60).returncode:
        reason = f"image {PY_IMAGE} is not present locally (these tests never pull it)"
    if reason:
        docker_not_run(f"not run: {reason}")
    name = f"flightdeck-test-{uuid.uuid4().hex[:12]}"

    async def go():
        ws = DockerWorkspace(tmp_path / "lane", handout, image=PY_IMAGE, name=name)
        await ws.prepare()
        box = Toolbox(ws)
        await call(box, "session_start", {"command": "sleep 300 & PS1= bash --norc", "terminal": True, "wait_seconds": 5})
        answer = await call(box, "session_send", {"session": "s1", "input": "test -t 0 && echo tty $TERM; printf 'a\\033[1mb\\r\\n'",
                                                  "wait_seconds": 5})
        await call(box, "session_close", {"session": "s1"})
        left = (await ws.run("cat /proc/[0-9]*/cmdline | tr '\\0' ' '", timeout=30)).output.decode()
        await ws.close()
        return answer, left

    try:
        answer, left = asyncio.run(go())
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
    assert answer.content.split("\n", 1)[1] == "tty dumb\nab\n"
    assert "sleep 300" not in left
