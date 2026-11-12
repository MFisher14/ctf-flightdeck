"""A Python L1 engine in the real lane image, end to end.

debian:bookworm-slim, the image the other container tests use, has no python3, so there a
Python engine only gets as far as its missing-python3 note (test_l1_container.py). The lane
image flightdeck ships (lane/Dockerfile, built by `flightdeck image build`) has python3: this
test runs a Python engine in a container of it, through the L1 stage a run uses.

It runs only when docker answers and the lane image is already on this machine (no test
builds or pulls it); otherwise it is skipped with the reason, so it reports as not run. With
FLIGHTDECK_REQUIRE_LANE_IMAGE=1 (CI's lane-image job, which builds the image first) it fails
instead. The container has no network, and it is removed even when the test fails.
"""

from __future__ import annotations

import uuid

import pytest

from ctf_flightdeck.agent.l1stage import L1Stage
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
    name = f"t{uuid.uuid4().hex[:10]}"
    yield name
    remove_containers(name)


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
    assert seen[0] == "python-3.11", result.notes  # Debian 12's python3, the lane image's: not the one running this test
    assert seen[1:] == ["in-docker", "at-work", "no-network", "no-secret", "pack-read-only"], result.notes
    assert not (pack / "planted").exists()
    assert containers(run_name) == []  # removed
    assert list((tmp_path / run_name / "l01" / "l1").iterdir()) == []  # the copy too
