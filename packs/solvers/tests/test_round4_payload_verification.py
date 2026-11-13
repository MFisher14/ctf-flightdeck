"""Sacrificial runtime verification for Round-4 deserialization candidates.

These tests are opt-in because they execute generated command-bearing fixtures.
Every execution is confined to an already-local Docker image with networking
disabled, a read-only root, dropped capabilities, bounded memory/PIDs/time, and
``--pull=never``.  Nothing here runs a generated payload on the host.

Run with::

    CTF_DOCKER_VERIFY=1 .venv/bin/python -m pytest \
        tests/test_round4_payload_verification.py -q

The pinned sandbox contains PyYAML and Ruby/ERB.  It does not contain
jsonpickle, and the local Linux .NET SDK has Json.NET but (correctly) lacks the
Windows-only PresentationFramework assembly required by ObjectDataProvider.
Those two unavailable runtime prerequisites are reported honestly rather than
installed from the network.
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


DOCKER_VERIFY = os.environ.get("CTF_DOCKER_VERIFY") == "1"
DOCKER_SKIP = pytest.mark.skipif(
    not DOCKER_VERIFY,
    reason="set CTF_DOCKER_VERIFY=1 for networkless sacrificial runtime checks",
)
_SEQUENCE = itertools.count()


def _docker(image: str, command: list[str], *, mounts=(), tmpfs=(), env=(), timeout=45):
    """Run one bounded foreground verifier in an already-local image."""
    if not image or not command or not 1 <= timeout <= 90:
        raise ValueError("invalid Docker verifier arguments")
    name = f"csctf-r4-deser-{os.getpid()}-{next(_SEQUENCE)}"
    argv = [
        "docker", "run", "--pull", "never", "--rm", "--network", "none",
        "--name", name, "--stop-timeout", "1", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "96", "--memory", "512m",
    ]
    for source, destination in mounts:
        argv.extend(("--mount", f"type=bind,src={source},dst={destination},readonly"))
    for value in tmpfs:
        argv.extend(("--tmpfs", value))
    for key, value in env:
        argv.extend(("--env", f"{key}={value}"))
    argv.append(image)
    argv.extend(command)
    try:
        return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # The explicit name refers only to this test's ephemeral verifier.
        subprocess.run(["docker", "stop", "--time", "1", name], check=False,
                       capture_output=True, text=True, timeout=5)
        subprocess.run(["docker", "rm", "--force", name], check=False,
                       capture_output=True, text=True, timeout=5)
        raise


def _candidate(language: str, name: str, command: str):
    source = {
        "python": "import jsonpickle, yaml; yaml.load(value, Loader=yaml.UnsafeLoader)",
        "ruby": "blob = Marshal.load(input); ERB.new(template)",
        "dotnet": "JsonConvert.DeserializeObject(data, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }); ObjectDataProvider x;",
    }[language]
    report = deser_gadgets.synthesize(source, command, [language])
    return next(row for row in report["candidates"] if row["name"] == name)


@DOCKER_SKIP
def test_pyyaml_candidate_executes_only_in_networkless_sandbox():
    marker = "CSCTF_PYYAML_RUNTIME_MARKER"
    row = _candidate("python", "pyyaml_object_apply", f"printf {marker}")
    payload = base64.b64encode(row["value"].encode()).decode()
    script = r'''
import base64, sys, yaml
value = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
try:
    yaml.safe_load(value)
except yaml.constructor.ConstructorError:
    pass
else:
    raise SystemExit("SafeLoader unexpectedly accepted the object/apply tag")
yaml.load(value, Loader=yaml.UnsafeLoader)
'''
    result = _docker(
        "csctf-sandbox:2", ["python3", "-c", script, payload],
        tmpfs=("/tmp:rw,noexec,nosuid,size=8m",),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker
    assert row["executed"] is False and row["network_requests"] == 0


@DOCKER_SKIP
def test_jsonpickle_candidate_when_matching_local_runtime_exists():
    """Run the exact candidate if local; otherwise preserve it as a static plan.

    Exit 77 is produced *inside the networkless pinned image* when jsonpickle is
    absent.  The test never attempts pip/apt or an image pull to fill that gap.
    """
    marker = "CSCTF_JSONPICKLE_RUNTIME_MARKER"
    row = _candidate("python", "jsonpickle_reduce", f"printf {marker}")
    payload = base64.b64encode(row["value"].encode()).decode()
    script = r'''
import base64, importlib.util, sys
if importlib.util.find_spec("jsonpickle") is None:
    raise SystemExit(77)
import jsonpickle
value = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
jsonpickle.decode(value, safe=False)
'''
    result = _docker(
        "csctf-sandbox:2", ["python3", "-c", script, payload],
        tmpfs=("/tmp:rw,noexec,nosuid,size=8m",),
    )
    if result.returncode == 77:
        pytest.skip("jsonpickle is not installed in an already-local sacrificial image")
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker


@DOCKER_SKIP
def test_ruby_marshal_plan_roundtrips_then_erb_evaluates_in_sandbox():
    """Verify every concrete value in the Ruby build plan with Ruby 3.3.

    A bare ERB instance is deliberately not claimed as a Marshal.load gadget:
    modern Ruby stores an undumpable singleton-class initializer and requires a
    source-supported wrapper to invoke ERB.  The emitted plan itself is Marshal
    round-tripped here, then its template/argument are evaluated exactly as a
    compatible wrapper would do.
    """
    marker = "CSCTF_RUBY_MARSHAL_ERB_MARKER"
    row = _candidate("ruby", "marshal_erb_build_plan", f"printf {marker}")
    plan = base64.b64encode(row["value"].encode()).decode()
    script = r'''
require "base64"
require "erb"
require "json"
plan = JSON.parse(Base64.strict_decode64(ARGV.fetch(0)))
abort "unexpected plan" unless plan.fetch("root") == "ERB" && plan.fetch("encode").include?("Marshal.dump")
wire = Marshal.dump(plan)
loaded = Marshal.load(wire)
abort "Marshal mismatch" unless loaded == plan
ARGV.replace([loaded.fetch("argument")])
ERB.new(loaded.fetch("ivars").fetch("@src")).result
'''
    result = _docker(
        "csctf-sandbox:2", ["ruby", "-e", script, plan],
        tmpfs=("/tmp:rw,noexec,nosuid,size=8m",),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker
    assert row["format"] == "build-plan-json" and row["candidate_only"] is True


@DOCKER_SKIP
def test_dotnet_jsonnet_candidate_reaches_real_type_resolution_but_stays_static(tmp_path):
    """Exercise the exact Json.NET candidate in the local Linux .NET SDK.

    Json.NET accepts the ``$type`` metadata and attempts to resolve
    ObjectDataProvider.  It then fails closed because PresentationFramework is
    Windows-only and absent.  A harmless source-supported class is deserialized
    in the same process as a positive TypeNameHandling control.
    """
    marker = "CSCTF_DOTNET_JSONNET_MARKER"
    row = _candidate("dotnet", "jsonnet_object_data_provider", f"printf {marker}")
    payload = base64.b64encode(row["value"].encode()).decode()
    (tmp_path / "Verify.csproj").write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup>
  <ItemGroup><Reference Include="Newtonsoft.Json"><HintPath>Newtonsoft.Json.dll</HintPath></Reference></ItemGroup>
</Project>
""", encoding="utf-8")
    (tmp_path / "NuGet.Config").write_text(
        """<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /></packageSources></configuration>""",
        encoding="utf-8")
    (tmp_path / "Program.cs").write_text(
        r'''using Newtonsoft.Json;
using System.Text;

public sealed class MarkerGadget { public string? Marker { get; set; } }
public static class Program {
  public static int Main(string[] args) {
    string candidate = Encoding.UTF8.GetString(Convert.FromBase64String(args[0]));
    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
    bool expectedFailure = false;
    try {
        JsonConvert.DeserializeObject<object>(candidate, settings);
    } catch (JsonSerializationException error) {
        expectedFailure = error.Message.Contains("PresentationFramework", StringComparison.Ordinal);
    }
    if (!expectedFailure) return 41;
    string control = JsonConvert.SerializeObject(new MarkerGadget { Marker = "CSCTF_DOTNET_JSONNET_MARKER" }, settings);
    object? decoded = JsonConvert.DeserializeObject<object>(control, settings);
    if (decoded is not MarkerGadget gadget || gadget.Marker != "CSCTF_DOTNET_JSONNET_MARKER") return 42;
    Console.Write(gadget.Marker + "|PRESENTATIONFRAMEWORK_ABSENT_STATIC_PLAN");
    return 0;
  }
}
''', encoding="utf-8")
    shell = r'''
set -eu
mkdir -p /tmp/verify
cp /work/Verify.csproj /work/NuGet.Config /work/Program.cs /tmp/verify/
dll=$(find /usr/share/dotnet -type f -name Newtonsoft.Json.dll | head -n 1)
test -n "$dll"
test -z "$(find /usr/share/dotnet -type f -name PresentationFramework.dll -print -quit)"
cp "$dll" /tmp/verify/Newtonsoft.Json.dll
cd /tmp/verify
dotnet restore --configfile NuGet.Config --ignore-failed-sources >/tmp/restore.log
dotnet build --no-restore >/tmp/build.log
dotnet bin/Debug/net8.0/Verify.dll "$1"
'''
    result = _docker(
        "mcr.microsoft.com/dotnet/sdk:8.0", ["sh", "-ec", shell, "verify", payload],
        mounts=((tmp_path, "/work"),), tmpfs=("/tmp:rw,nosuid,size=384m",),
        env=(("DOTNET_CLI_HOME", "/tmp"), ("HOME", "/tmp"),
             ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1"), ("DOTNET_CLI_TELEMETRY_OPTOUT", "1")),
        timeout=75,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert marker + "|PRESENTATIONFRAMEWORK_ABSENT_STATIC_PLAN" in result.stdout
    assert row["requirement"].startswith("Json.NET TypeNameHandling")


def test_runtime_candidates_remain_review_only_without_opt_in_execution():
    """Ordinary suite proof: synthesis itself never deserializes or executes."""
    report = deser_gadgets.synthesize(
        "yaml.load(x, Loader=yaml.UnsafeLoader); Marshal.load(x); ERB.new(x); "
        "JsonConvert.DeserializeObject(x); ObjectDataProvider x; import jsonpickle",
        "printf CSCTF_INERT_ROUND4", ["python", "ruby", "dotnet"],
    )
    assert report["deserialized"] is report["executed"] is False
    assert report["network_requests"] == 0
    assert all(row["candidate_only"] and row["executed"] is False
               and row["network_requests"] == 0 for row in report["candidates"])
