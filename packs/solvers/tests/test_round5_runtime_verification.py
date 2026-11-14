"""Round-5 local-runtime verification for deserialization plans.

Opt in with ``CTF_DOCKER_VERIFY=1``. Every generated command-bearing value is
handled only by an already-local Docker image with no network, a read-only root,
all capabilities dropped, no-new-privileges, and hard PID/memory/time limits.
No test pulls or installs a dependency.
"""
from __future__ import annotations

import base64
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import deser_gadgets  # noqa: E402


VERIFY = os.environ.get("CTF_DOCKER_VERIFY") == "1"
DOCKER = pytest.mark.skipif(not VERIFY, reason="set CTF_DOCKER_VERIFY=1 for sacrificial runtimes")
_SEQUENCE = itertools.count()


def _docker(image: str, command: list[str], *, timeout: int = 45):
    if not image or not command or not 1 <= timeout <= 90:
        raise ValueError("invalid verifier arguments")
    name = f"csctf-r5-runtime-{os.getpid()}-{next(_SEQUENCE)}"
    argv = [
        "docker", "run", "--pull=never", "--rm", "--network", "none",
        "--name", name, "--stop-timeout", "1", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "48", "--memory", "256m",
        image, *command,
    ]
    try:
        return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "stop", "--time", "1", name], check=False,
                       capture_output=True, text=True, timeout=5)
        subprocess.run(["docker", "rm", "--force", name], check=False,
                       capture_output=True, text=True, timeout=5)
        raise


def _candidate(language: str, name: str, command: str):
    source = {
        "python": "import jsonpickle, yaml; yaml.load(x, Loader=yaml.UnsafeLoader)",
        "ruby": "Marshal.load(blob); ERB.new(template)",
        "dotnet": "JsonConvert.DeserializeObject(x); TypeNameHandling.All; ObjectDataProvider x;",
    }[language]
    report = deser_gadgets.synthesize(source, command, [language])
    return next(row for row in report["candidates"] if row["name"] == name)


def test_deserialization_candidates_stay_static_review_values():
    report = deser_gadgets.synthesize(
        "import jsonpickle; yaml.load(x); Marshal.load(x); ERB.new(x); "
        "JsonConvert.DeserializeObject(x); ObjectDataProvider x",
        "printf CSCTF_R5_STATIC", ["python", "ruby", "dotnet"],
    )
    assert report["offline"] and report["executed"] is report["deserialized"] is False
    assert report["network_requests"] == 0
    assert all(row["candidate_only"] and row["executed"] is False
               and row["network_requests"] == 0 for row in report["candidates"])


@DOCKER
def test_ruby_plan_is_invoked_by_a_source_supported_marshal_load_wrapper():
    """Prove the plan contract, not a universal Ruby standard-library gadget."""
    marker = "CSCTF_R5_RUBY_MARSHAL_ERB"
    row = _candidate("ruby", "marshal_erb_build_plan", f"printf {marker}")
    encoded = base64.b64encode(row["value"].encode()).decode()
    script = r'''
require "base64"
require "erb"
require "json"
class ReviewedERBPlan
  def initialize(plan); @plan = plan; end
  def marshal_dump; @plan; end
  def marshal_load(plan)
    abort "bad plan" unless plan.fetch("root") == "ERB"
    abort "bad template" unless plan.fetch("ivars").fetch("@src").include?("system")
    ARGV.replace([plan.fetch("argument")])
    ERB.new(plan.fetch("ivars").fetch("@src")).result(binding)
  end
end
plan = JSON.parse(Base64.strict_decode64(ARGV.fetch(0)))
wire = Marshal.dump(ReviewedERBPlan.new(plan))
abort "bad marshal version" unless wire.start_with?("\x04\x08".b)
Marshal.load(wire)
'''
    result = _docker("csctf-sandbox:2", ["ruby", "-e", script, encoded])
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker
    assert row["format"] == "build-plan-json" and row["candidate_only"] is True
    assert "compatible Ruby/ERB gadget path" in row["requirement"]


@DOCKER
def test_jsonpickle_exact_candidate_if_any_permitted_local_image_has_runtime():
    images = ("csctf-sandbox:2", "huntress-sandbox:2", "python:3.11-slim", "python:3.12-slim")
    available = []
    probe = "import importlib.util; print(int(importlib.util.find_spec('jsonpickle') is not None))"
    for image in images:
        result = _docker(image, ["python3", "-I", "-c", probe])
        assert result.returncode == 0, f"{image}: {result.stderr}"
        if result.stdout.strip() == "1":
            available.append(image)
    if not available:
        pytest.skip("jsonpickle absent from fixed already-local images; no package was fetched")
    marker = "CSCTF_R5_JSONPICKLE"
    row = _candidate("python", "jsonpickle_reduce", f"printf {marker}")
    encoded = base64.b64encode(row["value"].encode()).decode()
    script = r'''
import base64, jsonpickle, sys
value = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
jsonpickle.decode(value, safe=False)
'''
    result = _docker(available[0], ["python3", "-I", "-c", script, encoded])
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker


@DOCKER
def test_objectdataprovider_runtime_is_honestly_unavailable_on_local_linux_dotnet():
    marker = "CSCTF_R5_DOTNET_STATIC"
    row = _candidate("dotnet", "jsonnet_object_data_provider", f"printf {marker}")
    payload = json.loads(row["value"])
    assert payload["$type"].endswith(", PresentationFramework")
    script = r'''
newton=$(find /usr/share/dotnet -type f -name Newtonsoft.Json.dll -print -quit)
presentation=$(find /usr/share/dotnet -type f -name PresentationFramework.dll -print -quit)
test -n "$newton"
test -z "$presentation"
printf 'JSONNET_PRESENT|PRESENTATIONFRAMEWORK_ABSENT'
'''
    result = _docker("mcr.microsoft.com/dotnet/sdk:8.0", ["sh", "-ec", script])
    assert result.returncode == 0, result.stderr
    assert result.stdout == "JSONNET_PRESENT|PRESENTATIONFRAMEWORK_ABSENT"
    assert row["candidate_only"] is True and row["executed"] is False
