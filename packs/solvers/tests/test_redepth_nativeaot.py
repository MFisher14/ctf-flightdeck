"""Real-toolchain and fail-closed tests for the NativeAOT/R2R inventory engine."""
from __future__ import annotations

import ast
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import redepth_nativeaot as native  # noqa: E402


SOURCE = """\
using System;

namespace TotalWarfare.Analysis;

internal static class CriticalGridProbe
{
    private const string Marker = "NATIVEAOT_SENTINEL_7F21";
    public static void Main() => Console.WriteLine(Marker);
}
"""

PROJECT = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>GridProbe</AssemblyName>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"""


def _runtime_identifier() -> str | None:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        return None
    if sys.platform == "darwin":
        return f"osx-{arch}"
    if sys.platform.startswith("linux"):
        return f"linux-{arch}"
    if os.name == "nt":
        return f"win-{arch}"
    return None


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None,
         timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)


@pytest.fixture(scope="session")
def dotnet_project(tmp_path_factory):
    dotnet = shutil.which("dotnet")
    rid = _runtime_identifier()
    if dotnet is None or rid is None:
        pytest.skip("a supported local dotnet toolchain is unavailable")
    versions = _run([dotnet, "--list-sdks"], cwd=REPO, timeout=30)
    if versions.returncode or not any(line.lstrip().startswith("10.")
                                      for line in versions.stdout.splitlines()):
        pytest.skip("the authoritative .NET 10 SDK oracle is unavailable")

    root = tmp_path_factory.mktemp("redepth_nativeaot_dotnet")
    (root / "GridProbe.csproj").write_text(PROJECT, encoding="utf-8")
    (root / "Program.cs").write_text(SOURCE, encoding="utf-8")
    built = _run([dotnet, "build", "GridProbe.csproj", "-c", "Release", "--nologo"], cwd=root)
    if built.returncode:
        pytest.skip(f"the local .NET 10 compiler is unusable: {built.stdout[-800:]}")
    managed = root / "bin" / "Release" / "net10.0" / "GridProbe.dll"
    if not managed.is_file():
        pytest.skip("dotnet build did not produce its documented managed assembly")
    oracle_dir = root / "oracle"
    oracle_dir.mkdir()
    managed_copy = oracle_dir / "managed.dll"
    shutil.copy2(managed, managed_copy)
    return {"dotnet": dotnet, "rid": rid, "root": root, "managed": managed_copy}


@pytest.fixture(scope="session")
def managed_binary(dotnet_project) -> Path:
    return dotnet_project["managed"]


@pytest.fixture(scope="session")
def r2r_binary(dotnet_project) -> Path:
    root, dotnet, rid = (dotnet_project[key] for key in ("root", "dotnet", "rid"))
    output = root / "r2r"
    published = _run([
        dotnet, "publish", "GridProbe.csproj", "-c", "Release", "-r", rid,
        "-p:PublishReadyToRun=true", "-p:SelfContained=false", "--nologo", "-o", str(output),
    ], cwd=root)
    artifact = output / "GridProbe.dll"
    if published.returncode or not artifact.is_file():
        pytest.skip(f"crossgen2 ReadyToRun oracle is unavailable: {published.stdout[-800:]}")
    return artifact


@pytest.fixture(scope="session")
def nativeaot_binary(dotnet_project) -> Path:
    root, dotnet, rid = (dotnet_project[key] for key in ("root", "dotnet", "rid"))
    output = root / "nativeaot"
    env = os.environ.copy()
    # Homebrew keeps these keg-only on macOS.  Supplying their existing library
    # paths makes the SDK's own NativeAOT link command usable without installation.
    if sys.platform == "darwin":
        library_dirs = [
            path for path in (Path("/opt/homebrew/opt/openssl@3/lib"),
                              Path("/opt/homebrew/opt/brotli/lib")) if path.is_dir()
        ]
        if library_dirs:
            existing = env.get("LIBRARY_PATH")
            env["LIBRARY_PATH"] = os.pathsep.join(
                [*(str(path) for path in library_dirs), *([existing] if existing else [])],
            )
    published = _run([
        dotnet, "publish", "GridProbe.csproj", "-c", "Release", "-r", rid,
        "-p:PublishAot=true", "-p:SelfContained=true", "--nologo", "-o", str(output),
    ], cwd=root, env=env)
    artifact = output / ("GridProbe.exe" if os.name == "nt" else "GridProbe")
    if published.returncode or not artifact.is_file():
        pytest.skip(f"NativeAOT compiler/linker oracle is unavailable: {published.stdout[-800:]}")
    return artifact


def _values(report: dict) -> list[str]:
    return [row["value"] for row in report["strings"]]


def test_dotnet_managed_il_is_not_overclassified(managed_binary):
    report = native.analyze(managed_binary.read_bytes(), source_name=str(managed_binary))
    assert report is not None
    assert report["classification"] == "managed_il"
    assert report["image"]["format"] == "PE"
    assert report["cli_header"]["metadata"]["signature"] == "BSJB"
    assert report["cli_header"]["managed_native_header"] is None
    assert report["readytorun_headers"] == []
    assert any("NATIVEAOT_SENTINEL_7F21" in value for value in _values(report))


def test_crossgen2_readytorun_uses_cli_pointer_and_typed_directory(r2r_binary):
    data = r2r_binary.read_bytes()
    report = native.analyze(data, source_name=str(r2r_binary))
    assert report is not None and report["classification"] == "readytorun"
    assert report["cli_header"]["managed_native_header"]["validated_kind"] == "coreclr_readytorun"
    headers = [row for row in report["readytorun_headers"]
               if row["kind"] == "coreclr_readytorun"]
    assert len(headers) == 1 and headers[0]["source"] == "cli_managed_native_header"
    sections = {row["type"]: row for row in headers[0]["sections"]}
    assert {100, 101, 102, 103}.issubset(sections)
    assert sections[100]["compiler_identifier"].startswith("Crossgen2 ")
    compiler = sections[100]
    assert data[compiler["file_offset"]:compiler["file_offset"] + compiler["size"]].startswith(
        b"Crossgen2 ",
    )
    assert report["unvalidated_rtr_signature_offsets"] == []


def test_publish_aot_recovers_real_header_sections_and_known_strings(nativeaot_binary):
    report = native.analyze(nativeaot_binary.read_bytes(), source_name=str(nativeaot_binary))
    assert report is not None and report["classification"] == "nativeaot"
    assert report["image"]["format"] in {"PE", "ELF", "Mach-O"}
    headers = [row for row in report["readytorun_headers"] if row["kind"] == "nativeaot"]
    assert len(headers) == 1
    header = headers[0]
    assert header["entry_type"] == 1
    assert header["entry_size"] in {12, 16, 24}
    section_types = {row["type"] for row in header["sections"]}
    assert section_types & {201, 202, 204, 205, 206, 207}
    assert any(300 <= value < 400 for value in section_types)
    assert all(row["size"] >= 0 and row["virtual_address"] >= 0
               for row in header["sections"])
    assert report["nativeaot_evidence"]["strong_count"] >= 1
    values = _values(report)
    assert any("NATIVEAOT_SENTINEL_7F21" in value for value in values)
    assert any("GridProbe.dll" in value for value in values)


def test_signature_alone_is_reported_but_never_called_readytorun(managed_binary):
    fake = (managed_binary.read_bytes() + b"padding-RTR\0" +
            struct.pack("<HHII", 16, 0, 0, 1) + struct.pack("<III", 100, 1, 0))
    report = native.analyze(fake)
    assert report is not None and report["classification"] == "managed_il"
    assert report["unvalidated_rtr_signature_offsets"]
    assert report["readytorun_headers"] == []


def test_mutated_native_directory_fails_closed_without_overclaim(nativeaot_binary):
    mutated = bytearray(nativeaot_binary.read_bytes())
    offset = mutated.find(native.RTR_SIGNATURE)
    assert offset >= 0
    mutated[offset + 12:offset + 14] = b"\xff\xff"
    report = native.analyze(bytes(mutated))
    assert report is not None
    assert report["classification"] != "nativeaot"
    assert offset in report["unvalidated_rtr_signature_offsets"]


@pytest.mark.parametrize("blob", [
    b"MZ",
    b"MZ" + b"\0" * 62,
    b"\x7fELF\x02\x01" + b"\0" * 8,
    b"\xcf\xfa\xed\xfe" + b"\0" * 8,
])
def test_truncated_known_containers_raise_only_declared_error(blob):
    with pytest.raises(native.NativeAotError):
        native.analyze(blob)


def test_deterministic_mutations_never_leak_stdlib_exceptions(managed_binary):
    original = managed_binary.read_bytes()
    samples = [original[:cut] for cut in (2, 63, 128, min(1024, len(original) - 1))]
    samples.extend(bytes(bytearray(original[:index]) + b"\xff" + original[index + 1:])
                   for index in (0x3C, min(0x80, len(original) - 1)))
    for sample in samples:
        try:
            native.analyze(sample)
        except Exception as exc:  # the assertion checks the public exception boundary
            assert isinstance(exc, native.NativeAotError)

    with pytest.raises(native.NativeAotError):
        native.analyze("not bytes")  # type: ignore[arg-type]
    assert native.analyze(b"not a recognized container") is None


def test_json_cli_and_guarded_argparse(nativeaot_binary, capsys):
    assert native.main([str(nativeaot_binary)]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["classification"] == "nativeaot"
    assert native.main([]) == 2


def test_module_is_static_offline_and_declares_one_error_type():
    tree = ast.parse((REPO / "solvers" / "binary" / "redepth_nativeaot.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    assert not imports & {"socket", "requests", "urllib", "subprocess", "ctypes", "marshal", "pickle"}
    errors = [node for node in tree.body if isinstance(node, ast.ClassDef)
              and any(isinstance(base, ast.Name) and base.id.endswith("Error") for base in node.bases)]
    assert [node.name for node in errors] == ["NativeAotError"]

