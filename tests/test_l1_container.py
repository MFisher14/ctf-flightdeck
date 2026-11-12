"""L1 engines in Docker (D17): when lanes run in Docker, each engine run gets a container of
its own, from the lane image, with the pack and flightdeck's boot script mounted read-only at
the paths they have here, and no network unless the lane may reach the challenge's instance
at once.

The tests with a container run only when docker answers and debian:bookworm-slim is already
on this machine (tests never pull, and use no other image); otherwise they are skipped with
the reason, so they report as not run (they fail instead where FLIGHTDECK_REQUIRE_DOCKER=1).
That image has bash but no python3: its engines here are bash scripts, and a python engine
is blocked, naming python3 (test_l1_lane_image.py runs one in the lane image). No test starts a container
with a network. Every container a test starts is removed, even when the test fails. The
tests with a fake docker script start no container and run everywhere.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import pytest

from ctf_flightdeck.agent.l1stage import L1Stage
from ctf_flightdeck.agent.workspace import WorkspaceError
from ctf_flightdeck.l1.container import MAX_NAME, PACKAGE, EngineContainer, container_name, engine_mounts
from ctf_flightdeck.l1.manifest import discover
from ctf_flightdeck.l1.runner import BOOT

from l1_kit import DOCKER_IMAGE as IMAGE
from l1_kit import (
    FAKE_IMAGE,
    FLAG,
    challenge,
    challenge_dir,
    cli_engine,
    containers,
    docker_not_run,
    docker_skip_reason,
    install_fake_docker,
    python_engine,
    remove_containers,
    run,
)


@pytest.fixture(scope="module")
def docker_ready():
    reason = docker_skip_reason()
    if reason:
        docker_not_run(reason)


@pytest.fixture
def run_name(docker_ready):
    """A run name no other test uses: every container of this test has it in its name, and
    is removed afterwards whatever happened."""
    name = f"t{uuid.uuid4().hex[:10]}"
    yield name
    remove_containers(name)


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    p = tmp_path / "pack"
    p.mkdir()
    return p


@pytest.fixture
def board(tmp_path: Path) -> Path:
    return tmp_path / "board"


@pytest.fixture
def handout(board: Path) -> Path:
    return challenge_dir(board, "demo", {"note.txt": "the flag is t{in_the_note}\n"}, id="demo")


def stage(tmp_path: Path, pack: Path, handout: Path, run_name: str, **kw) -> L1Stage:
    return L1Stage(discover(pack), {"demo": handout}, tmp_path / run_name, FLAG, image=IMAGE, pack=pack, **kw)


LOOK_AROUND = """
    notes=""
    [ -f /.dockerenv ] && notes="$notes in-docker"
    [ "$(pwd)" = /work ] && notes="$notes at-work"
    grep -q "t{{in_the_note}}" note.txt && notes="$notes has-the-copy"
    notes="$notes routes=$(( $(wc -l < /proc/net/route) - 1 ))"
    [ -e /sys/class/net/eth0 ] && notes="$notes eth0"
    touch "{pack}/planted" 2>/dev/null || notes="$notes pack-read-only"
    [ -e "{handout}/note.txt" ] || notes="$notes handout-not-there"
    [ -e "{package}/run.py" ] || notes="$notes only-l1-of-flightdeck"
    [ "$HOME" = /root ] && notes="$notes image-home"
    notes="$notes path=$PATH term=$TERM"
    env | grep -q FLIGHTDECK_TEST_SECRET && notes="$notes SAW-THE-SECRET"
    printf '{{"schema": 1, "status": "candidate", "flags": ["t{{from_docker}}"], "notes": "%s"}}\\n' "$notes" > "$FLIGHTDECK_L1_RESULT"
    """


def test_an_engine_runs_in_a_container_of_its_own_on_its_copy_with_no_network_and_the_pack_read_only(
        tmp_path, pack, handout, run_name, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_TEST_SECRET", "not-for-engines")
    cli_engine(pack, "look", LOOK_AROUND.format(pack=pack, handout=handout, package=PACKAGE), output="result",
               route='keywords = ["demo"]')
    runs = run(stage(tmp_path, pack, handout, run_name).run("L01", challenge("Demo", description="a demo challenge")))
    (only,) = runs
    result = only.result
    assert (result.status, result.flags) == ("candidate", ("t{from_docker}",)), result.notes
    seen = result.notes.split()
    for word in ("in-docker", "at-work", "has-the-copy", "routes=0", "pack-read-only", "handout-not-there",
                 "only-l1-of-flightdeck", "image-home", "term=dumb"):
        assert word in seen, result.notes
    assert "eth0" not in seen and "SAW-THE-SECRET" not in seen  # no network, none of this machine's environment
    path = next(word for word in seen if word.startswith("path="))[len("path="):]
    assert path == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # the image's own PATH
    assert not (pack / "planted").exists() and only.scraped is False
    assert containers(run_name) == []  # removed
    assert list((tmp_path / run_name / "l01" / "l1").iterdir()) == []  # the copy too


def test_a_text_engine_in_docker_gives_the_flags_it_printed_as_scraped(tmp_path, pack, handout, run_name):
    cli_engine(pack, "say", "cat note.txt\necho 'and t{also_this}' >&2\n", route='keywords = ["demo"]')
    (only,) = run(stage(tmp_path, pack, handout, run_name).run("L01", challenge("Demo", description="a demo challenge")))
    assert (only.result.status, only.result.flags, only.scraped) == ("candidate", ("t{in_the_note}",), True)  # stdout only


def test_a_python_engine_needs_python3_in_the_lane_image_and_is_blocked_naming_it(tmp_path, pack, handout, run_name):
    python_engine(pack, "py", """
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            return SolverResult("candidate", flags=["t{never}"])
        """, route='keywords = ["demo"]')
    (only,) = run(stage(tmp_path, pack, handout, run_name).run("L01", challenge("Demo", description="a demo challenge")))
    assert only.result.status == "blocked"
    assert only.result.notes == (
        f"missing tools: python3 (not in the lane image {IMAGE}, where engines run when lanes run in Docker) "
        "(`flightdeck image build` builds the lane image, which has python3); nothing ran"
    )
    assert containers(run_name) == [] and list((tmp_path / run_name / "l01" / "l1").iterdir()) == []


def test_an_engine_in_docker_that_runs_too_long_is_unsure_and_its_container_goes(tmp_path, pack, handout, run_name):
    cli_engine(pack, "slow", "sleep 60\n", extra="timeout_seconds = 1", route='keywords = ["demo"]')
    began = time.monotonic()
    (only,) = run(stage(tmp_path, pack, handout, run_name).run("L01", challenge("Demo", description="a demo challenge")))
    assert (only.result.status, only.result.notes) == ("unsure", "timed out after 1s")
    assert time.monotonic() - began < 60
    assert containers(run_name) == [] and list((tmp_path / run_name / "l01" / "l1").iterdir()) == []


def test_a_cancelled_engine_in_docker_leaves_no_container_and_no_copy(tmp_path, pack, handout, run_name):
    cli_engine(pack, "sleeper", "touch started.marker\nsleep 60\n", route='keywords = ["demo"]')
    work = tmp_path / run_name / "l01" / "l1"

    async def scenario():
        task = asyncio.ensure_future(stage(tmp_path, pack, handout, run_name).run("L01", challenge("Demo", description="a demo challenge")))
        deadline = time.monotonic() + 60
        while not (work / "sleeper" / "started.marker").exists():
            assert time.monotonic() < deadline, "the engine never started"
            await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())
    assert containers(run_name) == [] and list(work.iterdir()) == []


def test_wipe_empties_the_copy_from_inside_the_container_whatever_the_engine_made_there(tmp_path, handout, pack, run_name):
    box = EngineContainer(tmp_path / "e", handout, image=IMAGE, name=container_name(run_name, "l01", "e"), network="none",
                          pack=pack)

    async def scenario():
        await box.prepare()
        try:
            made = await box.run("mkdir -p a/b shut && touch a/b/c .hidden shut/f && chmod 000 shut && ln -s /etc/hostname link",
                                 timeout=30)
            assert made.exit_code == 0, made.output
            assert await box.wipe() == ""
            return await box.run("cat /etc/hostname > /dev/null && echo the-link-target-is-still-there", timeout=30)
        finally:
            await box.close()

    after = run(scenario())
    assert after.output.decode().strip() == "the-link-target-is-still-there"  # the link went, never what it named
    assert list((tmp_path / "e").iterdir()) == []
    assert containers(run_name) == []
    assert run(box.wipe()) == ""  # closed: nothing to do it in


# ---------------------------------------------------------------- without a container


def test_an_engine_container_mounts_the_pack_and_the_boot_script_read_only_where_they_are_here(tmp_path, handout, pack):
    box = EngineContainer(tmp_path / "e", handout, image=IMAGE, name="flightdeck-test-l1", network="none", pack=pack)
    args = box.box.run_args()
    mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "-v"]
    assert mounts == [
        f"{(tmp_path / 'e').resolve()}:/work",
        f"{pack.resolve()}:{pack}:ro",
        f"{PACKAGE / '__init__.py'}:{PACKAGE / '__init__.py'}:ro",
        f"{PACKAGE / 'l1'}:{PACKAGE / 'l1'}:ro",
    ]
    assert BOOT.is_relative_to(PACKAGE / "l1")  # the boot script a python engine runs is in a mounted folder
    assert args[args.index("--network") + 1] == "none"
    assert engine_mounts(pack)[0] == (pack, str(pack))


def test_container_names_are_dockers_and_bounded():
    assert container_name("20261111-093000", "l01", "decode.base64_layers") == "flightdeck-20261111-093000-l01-l1-decode.base64_layers"
    long = container_name("run", "l01", "x" * 300)
    other = container_name("run", "l01", "x" * 299 + "y")
    assert len(long) == len(other) == MAX_NAME and long != other
    assert container_name("a run/name", "l01", "e") == "flightdeck-a-run-name-l01-l1-e"


def test_an_l1_stage_in_docker_needs_the_pack(tmp_path, handout):
    with pytest.raises(ValueError, match="pack"):
        L1Stage([], {"demo": handout}, tmp_path, FLAG, image=IMAGE)


@pytest.fixture
def fake_docker(tmp_path, monkeypatch) -> Path:
    return install_fake_docker(tmp_path, monkeypatch)


@pytest.mark.parametrize("online", [False, True])
def test_an_engine_container_is_online_only_when_the_stage_is_told_so_and_then_on_a_fenced_network(
        tmp_path, pack, handout, fake_docker, online):
    cli_engine(pack, "e", "echo t{x}\n", route='keywords = ["demo"]')
    demo = challenge("Demo", description="a demo challenge")
    run(L1Stage(discover(pack), {"demo": handout}, tmp_path / "run", FLAG, image=FAKE_IMAGE, pack=pack,
                urls={demo.id: ("tcp://chal.example.test:1337",)}, labels={"flightdeck.run": "run"})
        .run("L01", demo, online=online))
    (started,) = fake_docker.read_text().splitlines()
    words = started.split()
    fence = "flightdeck-run-l01-l1net"
    assert words[words.index("--network") + 1] == (f"{fence}-net" if online else "none") and "bridge" not in words
    assert f"{pack.resolve()}:{pack}:ro" in words
    log = fake_docker.parent
    if not online:  # nothing made for an engine with no network
        assert not (log / "network.log").exists() and not (log / "proxies.log").exists()
        return
    calls = (log / "network.log").read_text().splitlines()
    assert calls[0] == ("network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated "
                        f"--label flightdeck.run=run {fence}-net")
    assert f"network connect --alias chal.example.test {fence}-net {fence}-egress-1" in calls
    assert calls[-1] == f"network rm {fence}-net"  # gone once the engines are
    (proxy,) = (log / "proxies.log").read_text().splitlines()
    assert f"--name {fence}-egress-1 --label flightdeck.run=run --network bridge " in proxy and f" {FAKE_IMAGE} " in proxy
    assert proxy.endswith('{"routes": [{"listen": 1337, "host": "chal.example.test", "port": 1337}]}')
    removed = (log / "rm.log").read_text().splitlines()
    assert removed.index(f"rm -f {container_name('run', 'l01', 'e')}") < removed.index(f"rm -f {fence}-egress-1")


def test_online_engines_do_not_run_at_all_when_their_fence_cannot_be_made(tmp_path, pack, handout, fake_docker):
    """Never on an open network instead: the stage fails with docker's reason and starts no engine."""
    cli_engine(pack, "e", "echo t{x}\n", route='keywords = ["demo"]')
    demo = challenge("Demo", description="a demo challenge")
    (fake_docker.parent / "create.fail").write_text("Error response from daemon: all predefined address pools have been fully subnetted\n")
    stage_ = L1Stage(discover(pack), {"demo": handout}, tmp_path / "run", FLAG, image=FAKE_IMAGE, pack=pack,
                     urls={demo.id: ("tcp://chal.example.test:1337",)})
    with pytest.raises(WorkspaceError, match="docker network create flightdeck-run-l01-l1net-net failed: .*address pools"):
        run(stage_.run("L01", demo, online=True))
    assert not fake_docker.exists() and not (fake_docker.parent / "proxies.log").exists()
    with pytest.raises(ValueError, match="no instance to reach"):  # online with nothing to reach is a flightdeck bug, said
        run(L1Stage(discover(pack), {"demo": handout}, tmp_path / "run2", FLAG, image=FAKE_IMAGE, pack=pack).run("L01", demo, online=True))


def test_engines_on_this_machine_have_no_container(tmp_path, pack, handout, fake_docker):
    cli_engine(pack, "e", "echo t{on_the_host}\n", route='keywords = ["demo"]')
    stage_ = L1Stage(discover(pack), {"demo": handout}, tmp_path / "run", FLAG)  # the host runtime: no image
    (only,) = run(stage_.run("L01", challenge("Demo", description="a demo challenge"), online=False))
    assert only.result.flags == ("t{on_the_host}",) and not fake_docker.exists()
