"""Opt-in runtime proof for an existing payload-builder family left static in Round 5.

Nothing is pulled or installed. The exact ERB candidate emitted by ``ssti_helper`` is rendered only
inside an already-local, networkless, read-only, capability-dropped sacrificial container.
"""
from __future__ import annotations

import itertools
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "solvers" / "web"
if str(WEB) not in sys.path:
    sys.path.insert(0, str(WEB))

import ssti_helper  # noqa: E402


VERIFY = os.environ.get("CTF_R5A_DOCKER_VERIFY") == "1"
DOCKER = pytest.mark.skipif(not VERIFY, reason="set CTF_R5A_DOCKER_VERIFY=1 for local sacrificial runtime")
_SEQUENCE = itertools.count()


def _docker_argv(image: str, command: list[str]) -> tuple[str, list[str]]:
    if not image or not command:
        raise ValueError("image and command are required")
    name = f"csctf-r5a-payload-{os.getpid()}-{next(_SEQUENCE)}"
    return name, [
        "docker", "run", "--pull=never", "--rm", "--network", "none",
        "--name", name, "--stop-timeout", "1", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m",
        image, *command,
    ]


def _run(image: str, command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    name, argv = _docker_argv(image, command)
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "stop", "--time", "1", name], capture_output=True,
                       text=True, timeout=5, check=False)
        subprocess.run(["docker", "rm", "--force", name], capture_output=True,
                       text=True, timeout=5, check=False)
        raise


def test_restricted_docker_command_has_every_required_guard():
    _name, argv = _docker_argv("csctf-sandbox:2", ["ruby", "-v"])
    rendered = " ".join(argv)
    for required in ("--pull=never", "--network none", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--pids-limit 32", "--memory 128m"):
        assert required in rendered


@DOCKER
def test_existing_erb_ssti_builder_round_trips_exact_candidate_in_sacrificial_ruby():
    marker = "R5A_ERB_RUNTIME_MARKER"
    rows = ssti_helper.build_payloads("erb", command=f"printf {marker}")
    row = next(item for item in rows if item["primitive"] == "Ruby IO.popen")
    ruby = "require 'erb'; template=ARGV.fetch(0); print ERB.new(template).result(binding)"
    result = _run("csctf-sandbox:2", ["ruby", "-e", ruby, row["payload"]])
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker
    assert row["offline"] is True
    assert row["note"].startswith("candidate only")
