"""The real lane image: a Python L1 engine end to end, and the debugger and the decompiler a
lane's shell has in it.

debian:bookworm-slim, the image the other container tests use, has no python3, so there a
Python engine only gets as far as its missing-python3 note (test_l1_container.py). The lane
image flightdeck ships (lane/Dockerfile, built by `flightdeck image build`) has python3: the
first test runs a Python engine in a container of it, through the L1 stage a run uses. The
others start a lane's own container of it (DockerWorkspace, with the limits and the default
seccomp profile a lane runs under) and use gdb and radare2's Ghidra decompiler there, on a
program of the image itself: never on a challenge's.

They run only when docker answers and today's lane image is on this machine (no test builds
or pulls it): an image that is absent, or that another Dockerfile built (the label `flightdeck
image build` writes says which), skips them with the reason, so they report as not run. With FLIGHTDECK_REQUIRE_LANE_IMAGE=1
(CI's lane-image job, which builds the image first) they fail instead. The containers have
no network, and they are removed even when a test fails.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from ctf_flightdeck import lane as lane_module
from ctf_flightdeck.agent.l1stage import L1Stage
from ctf_flightdeck.agent.prompts import shell_tools
from ctf_flightdeck.agent.workspace import SHELL_TOOLS, DockerWorkspace
from ctf_flightdeck.l1.manifest import discover
from ctf_flightdeck.lane import IMAGE

from l1_kit import (
    FLAG,
    REQUIRE_LANE_IMAGE,
    challenge,
    challenge_dir,
    containers,
    docker_not_run,
    docker_skip_reason,
    python_engine,
    remove_containers,
    run,
)


@pytest.fixture
def run_name():
    reason = docker_skip_reason(IMAGE)
    if reason:
        docker_not_run(f"not run: {reason} (`flightdeck image build` builds it)", require=REQUIRE_LANE_IMAGE)
    if lane_module.built_from(IMAGE) != lane_module.fingerprint():
        docker_not_run(f"not run: {IMAGE} on this machine was not built from this checkout's lane/Dockerfile (an older one "
                       "built it); `flightdeck image build` builds today's", require=REQUIRE_LANE_IMAGE)
    name = f"t{uuid.uuid4().hex[:10]}"
    yield name
    remove_containers(name)


@pytest.fixture
def lane(tmp_path, run_name):
    """A lane's own container of the lane image, as a run starts one: no network, the lane's
    limits, and asked which analysis programs the image has."""
    (tmp_path / "handout").mkdir()
    box = DockerWorkspace(tmp_path / "lane", tmp_path / "handout", image=IMAGE, name=f"flightdeck-test-{run_name}", probe_tools=True)
    asyncio.run(box.prepare())
    yield box
    asyncio.run(box.close())


def shell(box: DockerWorkspace, command: str) -> str:
    result = asyncio.run(box.run(command, timeout=120))
    assert result.exit_code == 0 and not result.timed_out, result
    return result.output.decode()


# The engine says where it ran and what it could reach, then gives the flag it read from its
# copy of the handout. Cryptodome (Debian's name for pycryptodome: python3-pycryptodome has no
# `Crypto` module) and requests are packages of the lane image: the engine imports them the
# way a player's solver would.
ENGINE = """
    import os
    import sys
    from pathlib import Path

    from ctf_flightdeck.l1.result import Evidence, SolverResult


    def solve(challenge_dir):
        import Cryptodome.Cipher.AES
        import requests

        seen = ["python-%d.%d" % sys.version_info[:2]]
        if Path("/.dockerenv").exists():
            seen.append("in-docker")
        if Path.cwd() == Path("/work"):
            seen.append("at-work")
        if not Path("/sys/class/net/eth0").exists():
            seen.append("no-network")
        if "FLIGHTDECK_TEST_SECRET" not in os.environ:
            seen.append("no-secret")
        try:
            (Path(__file__).parent / "planted").write_text("x")
        except OSError:
            seen.append("pack-read-only")
        flag = (challenge_dir / "note.txt").read_text().split()[-1]
        return SolverResult("solved", flags=[flag], notes=" ".join(seen),
                            evidence=[Evidence("read", "the note says so", "note.txt", 0)])
    """


def test_a_python_engine_runs_in_the_lane_image_end_to_end(tmp_path, run_name, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_TEST_SECRET", "not-for-engines")
    pack = tmp_path / "pack"
    python_engine(pack, "reader", ENGINE)
    handout = challenge_dir(tmp_path / "board", "demo", {"note.txt": "the flag is t{read_in_the_lane_image}\n"}, id="demo")
    stage = L1Stage(discover(pack), {"demo": handout}, tmp_path / run_name, FLAG, image=IMAGE, pack=pack)
    (only,) = run(stage.run("L01", challenge("Demo", description="a demo challenge")))
    result = only.result
    assert (result.status, result.flags) == ("solved", ("t{read_in_the_lane_image}",)), result.notes
    assert (result.engine, result.challenge_id, only.scraped) == ("reader", "demo", False)
    assert [(e.kind, e.path) for e in result.evidence] == [("read", "note.txt")]
    seen = result.notes.split()
    assert seen[0] == "python-3.13", result.notes  # Debian 13's python3, the lane image's
    assert seen[1:] == ["in-docker", "at-work", "no-network", "no-secret", "pack-read-only"], result.notes
    assert not (pack / "planted").exists()
    assert containers(run_name) == []  # removed
    assert list((tmp_path / run_name / "l01" / "l1").iterdir()) == []  # the copy too


def test_the_lane_image_says_it_has_a_debugger_and_a_decompiler_so_the_brief_names_them(lane):
    assert lane.shell_tools == SHELL_TOOLS == ("gdb", "gdb-multiarch", "r2", "pdg")
    said = shell_tools(lane.shell_tools)
    assert "gdb, a debugger" in said and "radare2 with the Ghidra decompiler" in said
    assert "did not say" not in (lane.root / ".flightdeck" / "prepare.log").read_text()


def test_gdb_runs_and_stops_a_process_inside_a_lanes_container(lane):
    """A debugger is only one when it can trace: gdb starts the image's own /bin/true, stops it
    at its first instruction and reads a register, then runs it to its end, all inside the
    container a lane gets (no added capability, Docker's default seccomp profile). The one
    thing that profile refuses gdb is switching address randomisation off: gdb says so and
    carries on, which the guide tells the player."""
    out = shell(lane, "gdb -q -batch -ex starti -ex 'info registers pc' -ex continue --args /bin/true 2>&1")
    assert "Program stopped." in out, out
    assert any(line.split()[:1] == ["pc"] or line.split()[:1] == ["rip"] for line in out.splitlines()), out
    assert "exited normally" in out, out
    assert "ptrace: Operation not permitted" not in out and "Cannot create process" not in out, out
    # the form the brief shows: commands on the command line, a program with its arguments
    again = shell(lane, "gdb -q -batch -ex run --args /bin/echo traced 2>&1")
    assert "traced" in again.splitlines() and "exited normally" in again, again


def test_the_decompiler_prints_a_function_of_a_binary_as_c(lane):
    """radare2 with the r2ghidra plugin loaded: `pdg` prints C for the entry function of the
    image's own /bin/true, which hands over to the C library's start routine."""
    out = shell(lane, "r2 -q -e scr.color=0 -c 'aa; afl; pdg @ entry0' /bin/true 2>/dev/null")
    assert any(line.split()[-1:] == ["entry0"] for line in out.splitlines()), out  # afl: the function list
    body = out[out.index("entry0("):]
    assert "{" in body and "}" in body and "__libc_start_main" in body, out
    assert "You need to install the plugin" not in out


def test_gdb_multiarch_reads_a_binary_and_the_shell_still_has_what_it_had(lane):
    """gdb-multiarch opens a binary without running it, and the move to Debian 13 kept the
    programs a lane had before (7z among them: the package that brings it was renamed)."""
    out = shell(lane, "gdb-multiarch -q -batch -ex 'info files' /bin/true 2>&1")
    assert "file type elf" in out, out
    have = shell(lane, "for t in python3 pip3 file xxd objdump strings unzip 7z bzip2 xz zstd curl nc jq git sqlite3 exiftool; "
                       "do command -v $t >/dev/null || echo missing:$t; done; echo done")
    assert have.split() == ["done"], have
