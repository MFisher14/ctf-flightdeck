"""FLIGHTDECK_REQUIRE_DOCKER and FLIGHTDECK_REQUIRE_LANE_IMAGE: where one is 1, a test that
needs Docker and cannot run fails instead of being skipped, so a CI job that has Docker never
passes with those tests left out. Every Docker test reports "cannot run here" through
l1_kit.docker_not_run, which these tests call."""

from __future__ import annotations

from pathlib import Path

import pytest

from l1_kit import REQUIRE_DOCKER, REQUIRE_LANE_IMAGE, docker_not_run

SKIPPED, FAILED = pytest.skip.Exception, pytest.fail.Exception


@pytest.mark.parametrize("value", [None, "", "0"])
def test_without_the_variable_a_docker_test_that_cannot_run_is_skipped_with_its_reason(monkeypatch, value):
    monkeypatch.delenv(REQUIRE_DOCKER, raising=False)
    if value is not None:
        monkeypatch.setenv(REQUIRE_DOCKER, value)
    with pytest.raises(SKIPPED) as caught:
        docker_not_run("not run: docker not found on PATH")
    assert str(caught.value) == "not run: docker not found on PATH"


def test_with_the_variable_at_1_it_fails_naming_the_variable_and_the_reason(monkeypatch):
    monkeypatch.setenv(REQUIRE_DOCKER, "1")
    with pytest.raises(FAILED) as caught:
        docker_not_run("not run: docker not found on PATH")
    assert str(caught.value) == ("FLIGHTDECK_REQUIRE_DOCKER=1, and a test that needs Docker could not run: "
                                 "not run: docker not found on PATH")


def test_a_value_that_is_neither_0_nor_1_fails_rather_than_being_read_as_off(monkeypatch):
    monkeypatch.setenv(REQUIRE_DOCKER, "true")
    with pytest.raises(FAILED, match="FLIGHTDECK_REQUIRE_DOCKER is 'true': set it to 1"):
        docker_not_run("not run: docker not found on PATH")


def test_each_variable_covers_its_own_tests_only(monkeypatch):
    monkeypatch.setenv(REQUIRE_DOCKER, "1")
    monkeypatch.delenv(REQUIRE_LANE_IMAGE, raising=False)
    with pytest.raises(SKIPPED):  # the Linux job has the test image, not the lane image
        docker_not_run("not run: no lane image", require=REQUIRE_LANE_IMAGE)
    monkeypatch.setenv(REQUIRE_LANE_IMAGE, "1")
    monkeypatch.delenv(REQUIRE_DOCKER)
    with pytest.raises(FAILED, match="^FLIGHTDECK_REQUIRE_LANE_IMAGE=1, and "):
        docker_not_run("not run: no lane image", require=REQUIRE_LANE_IMAGE)
    with pytest.raises(SKIPPED):
        docker_not_run("not run: no test image")


def test_no_test_skips_for_docker_any_other_way():
    """A Docker test with a plain pytest.skip would pass the variable by. The one skip left
    near the word docker or image is not about a missing Docker: that test wants the lane
    image absent."""
    found = []
    for path in sorted(Path(__file__).parent.glob("*.py")):
        if path.name in (Path(__file__).name, "l1_kit.py"):
            continue
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            near = " ".join(lines[max(0, number - 4):number + 1]).lower()
            if "pytest.skip(" in line and ("docker" in near or "image" in near):
                found.append(f"{path.name}: {line.strip()}")
    assert found == ['test_run.py: pytest.skip(f"not run: {IMAGE} is built on this machine, so it is not missing")']
