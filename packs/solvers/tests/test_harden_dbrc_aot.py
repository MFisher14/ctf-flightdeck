"""Independent vector locks and fail-closed fuzz for AOT metadata engines.

The format fixtures are not generated from engine output:

* NativeAOT is compiled by the installed .NET SDK and its Mach-O header is
  decoded directly according to ``mach-o/loader.h`` before engine assertions.
* Dart's raw snapshot is packed from the SDK Snapshot header layout.
* IL2CPP metadata is packed from Unity/LibCpp2IL's documented global metadata
  header, whose directory values are byte offsets and byte counts.
"""
from __future__ import annotations

import os
import platform
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

import redepth_dart_snapshot as dart
import redepth_il2cpp_modern as il2cpp
import redepth_nativeaot as nativeaot


_DART_VERSION = b"a1b2c3d4e5f60718293a4b5c6d7e8f90"
_DART_FEATURES = b"release arm64-sysv product no-code_comments"
_DART_PAYLOAD = b"\x01GridFailoverController\0CSCTF{independent_dart_vector}\0\xff"


def _dart_snapshot(*, kind: int = 2) -> bytes:
    """Reference encoder for magic, int64 length/kind, hash, and features."""
    body = _DART_VERSION + _DART_FEATURES + b"\0" + _DART_PAYLOAD
    total = 20 + len(body)
    return struct.pack("<Iqq", 0xDCDCF5F5, total - 4, kind) + body


_IL2CPP_FIELDS = 31
_IL2CPP_HEADER_SIZE = 8 + _IL2CPP_FIELDS * 8


def _il2cpp_literal_metadata(version: int = 29) -> bytes:
    """Pack a coherent literal-only metadata file from the published header."""
    literal = b"CSCTF{il2cpp_byte_count_oracle}"
    literal_record = struct.pack("<II", len(literal), 0)
    table_offset = _IL2CPP_HEADER_SIZE
    data_offset = table_offset + len(literal_record)
    output = bytearray(data_offset + len(literal))
    struct.pack_into("<Ii", output, 0, 0xFAB11BAF, version)
    # stringLiteral and stringLiteralData are the first two directory pairs.
    struct.pack_into("<ii", output, 8, table_offset, len(literal_record))
    struct.pack_into("<ii", output, 16, data_offset, len(literal))
    output[table_offset:data_offset] = literal_record
    output[data_offset:] = literal
    return bytes(output)


def _rid() -> str | None:
    machine = platform.machine().lower()
    architecture = {"arm64": "arm64", "aarch64": "arm64",
                    "x86_64": "x64", "amd64": "x64"}.get(machine)
    if architecture is None:
        return None
    if sys_platform := {"Darwin": "osx", "Linux": "linux"}.get(platform.system()):
        return f"{sys_platform}-{architecture}"
    if os.name == "nt":
        return f"win-{architecture}"
    return None


@pytest.fixture(scope="module")
def nativeaot_vector(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    """Compile a trusted tiny NativeAOT program using the local SDK packs."""
    dotnet = shutil.which("dotnet")
    rid = _rid()
    if dotnet is None or rid is None:
        pytest.skip("supported local .NET SDK is unavailable")
    sdk = subprocess.run(
        [dotnet, "--list-sdks"], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    if sdk.returncode or not any(line.lstrip().startswith("10.") for line in sdk.stdout.splitlines()):
        pytest.skip(".NET 10 SDK NativeAOT oracle is unavailable")

    root = tmp_path_factory.mktemp("harden-dbrc-nativeaot")
    (root / "AotGrid.csproj").write_text(
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <AssemblyName>AotGrid</AssemblyName><PublishAot>true</PublishAot>
    <InvariantGlobalization>true</InvariantGlobalization>
  </PropertyGroup>
</Project>
""",
        encoding="utf-8",
    )
    (root / "Program.cs").write_text(
        """using System;
namespace TotalWarfare.NativeVector;
internal static class GridFailover {
  private const string Marker = "HARDEN_DBRC_NATIVEAOT_71E4";
  public static void Main() => Console.WriteLine(Marker);
}
""",
        encoding="utf-8",
    )
    nuget_config = root / "NuGet.Config"
    nuget_config.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /></packageSources></configuration>
""",
        encoding="utf-8",
    )
    output = root / "publish"
    environment = os.environ.copy()
    environment.update({"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})
    if platform.system() == "Darwin":
        libraries = [path for path in (
            Path("/opt/homebrew/opt/openssl@3/lib"),
            Path("/opt/homebrew/opt/brotli/lib"),
        ) if path.is_dir()]
        if libraries:
            environment["LIBRARY_PATH"] = os.pathsep.join(
                [*(str(path) for path in libraries), environment.get("LIBRARY_PATH", "")],
            ).rstrip(os.pathsep)
    process = subprocess.run(
        [dotnet, "publish", "AotGrid.csproj", "-c", "Release", "-r", rid,
         "--self-contained", "true", "-p:PublishAot=true",
         f"-p:RestoreConfigFile={nuget_config}", "-p:RestoreNoCache=true",
         "--nologo", "-o", str(output)],
        cwd=root, env=environment, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
    )
    artifact = output / ("AotGrid.exe" if os.name == "nt" else "AotGrid")
    if process.returncode or not artifact.is_file():
        pytest.skip(f"local NativeAOT publish unavailable: {process.stdout[-500:]}")
    return artifact.read_bytes()


def _clean_or_declared(function, exception_type, blob: bytes) -> None:
    try:
        result = function(blob)
        assert result is None or isinstance(result, dict)
    except Exception as exc:  # noqa: BLE001 - the public boundary is the assertion
        assert type(exc) is exception_type, (type(exc), blob[:16].hex())


def test_real_nativeaot_macho_or_elf_structure_is_recovered(nativeaot_vector: bytes) -> None:
    # The output identity is independently visible in the native string table;
    # managed strings use the runtime's own encoded data representation.
    assert b"AotGrid" in nativeaot_vector
    if platform.system() == "Darwin":
        # Independent mach-o/loader.h decoding: MH_MAGIC_64, CPU type, executable.
        magic, cpu_type, _subtype, file_type = struct.unpack_from("<IiiI", nativeaot_vector)
        assert magic == 0xFEEDFACF
        assert cpu_type in {0x0100000C, 0x01000007}  # arm64 or x86_64
        assert file_type == 2  # MH_EXECUTE
        expected_container = "Mach-O"
    elif platform.system() == "Linux":
        assert nativeaot_vector.startswith(b"\x7fELF")
        assert nativeaot_vector[4] in {1, 2}
        expected_container = "ELF"
    else:
        assert nativeaot_vector.startswith(b"MZ")
        expected_container = "PE"

    report = nativeaot.analyze(nativeaot_vector, source_name="AotGrid")
    assert report is not None
    assert report["classification"] == "nativeaot"
    assert report["image"]["format"] == expected_container
    assert any(header["kind"] == "nativeaot" for header in report["readytorun_headers"])
    assert any("HARDEN_DBRC_NATIVEAOT_71E4" in row["value"] for row in report["strings"])


def test_published_dart_snapshot_header_and_payload_are_recovered() -> None:
    fixture = _dart_snapshot()
    assert fixture[:4] == bytes.fromhex("f5f5dcdc")
    assert struct.unpack_from("<q", fixture, 4)[0] == len(fixture) - 4
    assert struct.unpack_from("<q", fixture, 12)[0] == 2

    report = dart.inspect_dart_snapshot(fixture)
    assert report is not None and report["container"] == "raw"
    snapshot = report["snapshots"][0]
    assert snapshot["total_length"] == len(fixture)
    assert snapshot["kind_name"] == "full-aot"
    assert snapshot["version"] == _DART_VERSION.decode("ascii")
    assert snapshot["feature_tokens"] == _DART_FEATURES.decode("ascii").split()
    assert "CSCTF{independent_dart_vector}" in {
        row["value"] for row in snapshot["strings"]
    }


def test_published_il2cpp_byte_count_directories_recover_literal() -> None:
    fixture = _il2cpp_literal_metadata()
    assert struct.unpack_from("<I", fixture)[0] == 0xFAB11BAF
    assert struct.unpack_from("<i", fixture, 4)[0] == 29
    assert struct.unpack_from("<ii", fixture, 8) == (_IL2CPP_HEADER_SIZE, 8)

    report = il2cpp.inspect_metadata(fixture, source_name="global-metadata.dat")
    assert report is not None and report["supported"] is True
    assert report["header_size"] == 256
    assert report["directories"][0]["record_count"] == 1
    assert report["directories"][0]["count_source"] == "derived_from_byte_count"
    assert report["string_literals"] == [{
        "index": 0,
        "data_index": 0,
        "byte_length": len(b"CSCTF{il2cpp_byte_count_oracle}"),
        "file_offset": _IL2CPP_HEADER_SIZE + 8,
        "text": "CSCTF{il2cpp_byte_count_oracle}",
        "bytes_hex": b"CSCTF{il2cpp_byte_count_oracle}".hex(),
        "oversized": False,
    }]


def test_nativeaot_fail_closed_fuzz(nativeaot_vector: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    rng = random.Random(0xA071)
    samples = [b"", *(rng.randbytes(size) for size in (1, 2, 3, 7, 31, 127))]
    for magic in (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe"):
        samples.extend(magic[:cut] for cut in range(1, len(magic) + 1))
    samples.extend(nativeaot_vector[:cut] for cut in (1, 2, 4, 16, 32, 63, 128, 1024))
    for offset in (0, 1, 2, 3, 16, 31, min(len(nativeaot_vector) - 1, 0x1000)):
        changed = bytearray(nativeaot_vector)
        changed[offset] ^= 0x80
        samples.append(bytes(changed))
    for blob in samples:
        _clean_or_declared(nativeaot.analyze, nativeaot.NativeAotError, blob)

    monkeypatch.setattr(nativeaot, "MAX_INPUT", 64)
    with pytest.raises(nativeaot.NativeAotError):
        nativeaot.analyze(b"A" * 65)


def test_dart_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _dart_snapshot()
    rng = random.Random(0xDA47)
    samples = [b"", *(rng.randbytes(size) for size in (1, 2, 3, 7, 19, 53, 127))]
    samples.extend(fixture[:cut] for cut in (1, 2, 3, 4, 5, 12, 19, 20, 51, len(fixture) - 1))
    for offset in (0, 3, 4, 11, 12, 19, 20, 35, 51, len(fixture) - 1):
        changed = bytearray(fixture)
        changed[offset] ^= 1 << (offset % 8)
        samples.append(bytes(changed))
    for blob in samples:
        _clean_or_declared(dart.inspect_dart_snapshot, dart.DartSnapshotError, blob)

    monkeypatch.setattr(dart, "MAX_INPUT", 64)
    with pytest.raises(dart.DartSnapshotError):
        dart.inspect_dart_snapshot(b"A" * 65)


def test_il2cpp_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _il2cpp_literal_metadata()
    magic = struct.pack("<I", 0xFAB11BAF)
    rng = random.Random(0x1C2)
    samples = [b"", *(rng.randbytes(size) for size in (1, 2, 3, 7, 31, 127))]
    samples.extend(magic[:cut] for cut in range(1, len(magic) + 1))
    samples.extend(fixture[:cut] for cut in (4, 5, 7, 8, 31, 128, 255, len(fixture) - 1))
    for offset in (0, 3, 4, 7, 8, 12, 64, 127, 255, len(fixture) - 1):
        changed = bytearray(fixture)
        changed[offset] ^= 0xA5
        samples.append(bytes(changed))
    for blob in samples:
        _clean_or_declared(il2cpp.inspect_metadata, il2cpp.ModernIl2CppError, blob)

    monkeypatch.setattr(il2cpp, "MAX_INPUT", 64)
    with pytest.raises(il2cpp.ModernIl2CppError):
        il2cpp.inspect_metadata(b"A" * 65)
