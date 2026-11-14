"""Sessions (P82): long-lived processes a lane talks to across turns, through the toolbox.

Every process here is synthetic: bash, cat, sleep and a shell loop, never a challenge's
binary. The host runtime always runs. The docker tests run only when docker answers and
debian:bookworm-slim is already on this machine (tests never pull); otherwise they are
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
from ctf_flightdeck.agent.tools import TOOLS, Toolbox, ToolResult
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace, docker_unavailable
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
    async def go():
        box = await host_box(tmp_path, handout)
        await call(box, "session_start", {"command": "head -c 6; echo '|'", "wait_seconds": 0})
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
