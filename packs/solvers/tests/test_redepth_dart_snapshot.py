"""Published Dart snapshot layout and native-symbol tests for redepth_dart_snapshot.

The fixture encoder below is deliberately independent of the engine.  It is a
direct transcription of Dart SDK ``runtime/vm/snapshot.h`` and
``Serializer::WriteVersionAndFeatures``: magic, signed int64 length excluding
the magic, signed int64 kind, a 32-byte MD5 snapshot hash, then NUL-terminated
features.  The native oracle is produced by clang and is never loaded.
"""
from __future__ import annotations

import json
import random
import shutil
import struct
import subprocess
import sys

import pytest

import redepth_dart_snapshot as dart_snapshot


VERSION = b"0123456789abcdef0123456789abcdef"
FEATURES = b"release no-code_comments x64-sysv"
PAYLOAD = (
    b"\x01\x97\x00GridController\x00package:warfare/grid.dart\x00"
    b"CSCTF{dart_snapshot_static_lead}\x00\xff\x02"
)


def reference_snapshot(*, byte_order="little", kind=2, payload=PAYLOAD,
                       features=FEATURES):
    """Hand-written reference encoder from the published SDK field layout."""
    endian = "<" if byte_order == "little" else ">"
    body = VERSION + features + b"\0" + payload
    total_length = 20 + len(body)
    magic = (0xDCDCF5F5).to_bytes(4, byteorder=byte_order, signed=False)
    return magic + struct.pack(endian + "qq", total_length - 4, kind) + body


def _c_array(data):
    return ", ".join(f"0x{byte:02x}" for byte in data)


def _compile_native(compiler, root, name, declarations):
    source = root / f"{name}.c"
    output = root / (f"{name}.dylib" if sys.platform == "darwin" else f"{name}.so")
    source.write_text(
        "#define EXPORT __attribute__((used, visibility(\"default\")))\n"
        + declarations,
        encoding="ascii",
    )
    if sys.platform == "darwin":
        command = [compiler, "-dynamiclib", "-O0", str(source), "-o", str(output)]
    else:
        command = [compiler, "-shared", "-fPIC", "-O0", str(source), "-o", str(output)]
    process = subprocess.run(
        command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=60,
    )
    assert process.returncode == 0, process.stderr
    return output, output.read_bytes()


@pytest.fixture(scope="module")
def compiled_native_oracles(tmp_path_factory):
    compiler = shutil.which("clang") or shutil.which("cc")
    if compiler is None or sys.platform not in {"darwin", "linux"}:
        pytest.skip("clang/cc native symbol oracle is unavailable")
    root = tmp_path_factory.mktemp("dart-native-oracle")
    snapshot = reference_snapshot()
    current_source = f"""
EXPORT const unsigned char _kDartSnapshotData[] = {{{_c_array(snapshot)}}};
EXPORT const unsigned char _kDartSnapshotText[] = {{0x90, 0xc3, 0x00, 0x7f}};
EXPORT const unsigned char _kDartSnapshotBuildId[] = {{
  0x44, 0x41, 0x52, 0x54, 0x2d, 0x42, 0x55, 0x49,
  0x4c, 0x44, 0x2d, 0x49, 0x44, 0x00
}};
EXPORT unsigned char _kDartSnapshotBss[32];
"""
    legacy_source = f"""
EXPORT const unsigned char _kDartVmSnapshotData[] = {{{_c_array(snapshot)}}};
EXPORT const unsigned char _kDartVmSnapshotInstructions[] = {{0x56, 0x4d, 0x00}};
EXPORT unsigned char _kDartVmSnapshotBss[16];
EXPORT const unsigned char _kDartIsolateSnapshotData[] = {{{_c_array(snapshot)}}};
EXPORT const unsigned char _kDartIsolateSnapshotInstructions[] = {{0x49, 0x53, 0x4f}};
EXPORT unsigned char _kDartIsolateSnapshotBss[24];
"""
    current = _compile_native(compiler, root, "current", current_source)
    legacy = _compile_native(compiler, root, "legacy", legacy_source)
    # A header-free C translation unit can usually be emitted as a cross-target
    # ELF relocatable object even on Darwin.  This independently exercises
    # ELF ET_REL section-relative symbol values; skip only if this clang lacks
    # the backend.
    elf_output = root / "current-x86_64.o"
    elf_process = subprocess.run(
        [compiler, "--target=x86_64-unknown-linux-gnu", "-c", "-O0",
         str(root / "current.c"), "-o", str(elf_output)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=60,
    )
    elf = (elf_output, elf_output.read_bytes()) if elf_process.returncode == 0 else None
    return current, legacy, elf


def test_published_raw_header_layout_and_bounded_inventory():
    fixture = reference_snapshot()
    # The first twenty bytes are independently decoded, not emitted by the
    # engine: magic, length excluding magic, and Snapshot::kFullAOT (2).
    assert fixture[:4] == bytes.fromhex("f5f5dcdc")
    assert struct.unpack_from("<q", fixture, 4)[0] == len(fixture) - 4
    assert struct.unpack_from("<q", fixture, 12)[0] == 2

    row = dart_snapshot.parse_snapshot(fixture)
    assert row is not None
    assert row["magic"] == "0xdcdcf5f5"
    assert row["stored_length"] == len(fixture) - 4
    assert row["total_length"] == len(fixture)
    assert row["kind"] == 2
    assert row["kind_name"] == "full-aot"
    assert row["includes_code"] and row["is_aot"]
    assert row["version"] == VERSION.decode()
    assert row["features"] == FEATURES.decode()
    assert row["feature_tokens"] == ["release", "no-code_comments", "x64-sysv"]
    assert not row["clustered_objects_parsed"]
    values = [item["value"] for item in row["strings"]]
    assert "GridController" in values
    assert "package:warfare/grid.dart" in values
    assert "CSCTF{dart_snapshot_static_lead}" in values

    report = dart_snapshot.inspect_dart_snapshot(fixture)
    assert report is not None
    assert report["format"] == "dart-snapshot"
    assert report["container"] == "raw"
    assert report["layout"] == "raw"
    assert report["snapshots"][0] == row


def test_big_endian_module_and_embedded_available_region():
    fixture = reference_snapshot(byte_order="big", kind=3)
    wrapper = b"PREFIX!" + fixture + b"TRAILING"
    row = dart_snapshot.parse_snapshot(
        wrapper, offset=7, available_size=len(fixture) + 8,
    )
    assert row is not None
    assert row["offset"] == 7
    assert row["byte_order"] == "big"
    assert row["kind_name"] == "module"
    assert row["available_trailing_bytes"] == 8

    bounded = dart_snapshot.parse_snapshot(
        wrapper, offset=7, available_size=len(fixture),
    )
    assert bounded is not None
    assert bounded["available_trailing_bytes"] == 0


def test_string_report_cap_is_explicit():
    payload = b"AlphaLead\0BravoLead\0CharlieLead\0"
    row = dart_snapshot.parse_snapshot(
        reference_snapshot(payload=payload), max_strings=1,
    )
    assert row is not None
    assert len(row["strings"]) == 1
    assert row["strings_truncated"]


def test_consolidated_native_symbols_and_snapshot_are_recovered(compiled_native_oracles):
    (path, data), _, _ = compiled_native_oracles
    report = dart_snapshot.inspect_dart_snapshot(data)
    assert report is not None
    assert report["format"] == "dart-aot-native"
    assert report["container"] == ("mach-o" if sys.platform == "darwin" else "elf")
    assert report["layout"] == "consolidated"
    symbols = {row["name"]: row for row in report["symbols"]}
    assert {
        "_kDartSnapshotData", "_kDartSnapshotText",
        "_kDartSnapshotBuildId", "_kDartSnapshotBss",
    } <= set(symbols)
    assert symbols["_kDartSnapshotData"]["file_offset"] is not None
    assert symbols["_kDartSnapshotBss"]["role"] == "snapshot_bss"
    # Mach-O prepends another underscore to the C identifier; normalization
    # must preserve the actual nlist spelling while yielding the SDK name.
    if sys.platform == "darwin":
        assert symbols["_kDartSnapshotData"]["raw_name"] == "__kDartSnapshotData"
    assert len(report["snapshots"]) == 1
    recovered = report["snapshots"][0]
    assert recovered["symbol"] == "_kDartSnapshotData"
    assert recovered["version"] == VERSION.decode()
    assert recovered["kind_name"] == "full-aot"
    assert any(row["source"] == "_kDartSnapshotBuildId"
               and row["hex"].startswith(b"DART-BUILD-ID\0".hex())
               for row in report["build_ids"])
    assert path.exists()


def test_legacy_vm_and_isolate_split_symbols_are_recovered(compiled_native_oracles):
    _, (path, data), _ = compiled_native_oracles
    report = dart_snapshot.inspect_dart_snapshot(data)
    assert report is not None
    assert report["layout"] == "legacy"
    names = {row["name"] for row in report["symbols"]}
    assert names == {
        "_kDartVmSnapshotData", "_kDartVmSnapshotInstructions",
        "_kDartVmSnapshotBss", "_kDartIsolateSnapshotData",
        "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotBss",
    }
    assert {row["symbol"] for row in report["snapshots"]} == {
        "_kDartVmSnapshotData", "_kDartIsolateSnapshotData",
    }
    assert all(row["version"] == VERSION.decode() for row in report["snapshots"])
    assert path.exists()


def test_cross_target_elf_relocatable_symbol_mapping(compiled_native_oracles):
    _, _, elf = compiled_native_oracles
    if elf is None:
        pytest.skip("host clang cannot emit the x86_64 ELF oracle")
    path, data = elf
    assert data.startswith(b"\x7fELF")
    report = dart_snapshot.inspect_dart_snapshot(data)
    assert report is not None
    assert report["container"] == "elf"
    assert report["metadata"]["elf_type"] == 1  # ET_REL
    assert report["layout"] == "consolidated"
    assert report["snapshots"][0]["version"] == VERSION.decode()
    assert report["snapshots"][0]["kind"] == 2
    symbols = {row["name"]: row for row in report["symbols"]}
    assert symbols["_kDartSnapshotData"]["file_offset"] is not None
    assert symbols["_kDartSnapshotBss"]["file_offset"] is None
    assert path.exists()


def test_non_format_and_malformed_snapshots_fail_closed():
    assert dart_snapshot.inspect_dart_snapshot(b"not a snapshot") is None
    assert dart_snapshot.parse_snapshot(b"not a snapshot") is None
    fixture = reference_snapshot()
    for stop in (4, 12, 19, 20, 51, len(fixture) - 1):
        with pytest.raises(dart_snapshot.DartSnapshotError):
            dart_snapshot.inspect_dart_snapshot(fixture[:stop])

    mutations = []
    negative = bytearray(fixture)
    struct.pack_into("<q", negative, 4, -1)
    mutations.append(negative)
    too_large = bytearray(fixture)
    struct.pack_into("<q", too_large, 4, len(fixture) + 100)
    mutations.append(too_large)
    bad_kind = bytearray(fixture)
    struct.pack_into("<q", bad_kind, 12, 4)
    mutations.append(bad_kind)
    bad_version = bytearray(fixture)
    bad_version[20] = ord("z")
    mutations.append(bad_version)
    bad_features = bytearray(fixture)
    bad_features[52] = 1
    mutations.append(bad_features)
    unterminated = fixture[:52] + FEATURES + PAYLOAD
    unterminated = bytearray(unterminated)
    struct.pack_into("<q", unterminated, 4, len(unterminated) - 4)
    mutations.append(unterminated)
    for malformed in mutations:
        with pytest.raises(dart_snapshot.DartSnapshotError):
            dart_snapshot.inspect_dart_snapshot(malformed)

    for bad in (None, 7, "snapshot", [], {}):
        with pytest.raises(dart_snapshot.DartSnapshotError):
            dart_snapshot.inspect_dart_snapshot(bad)
    with pytest.raises(dart_snapshot.DartSnapshotError):
        dart_snapshot.parse_snapshot(fixture, offset=-1)
    with pytest.raises(dart_snapshot.DartSnapshotError):
        dart_snapshot.inspect_dart_snapshot(fixture, min_string_length=2)


def test_native_truncation_and_deterministic_mutations_never_leak(compiled_native_oracles):
    (_, data), _, _ = compiled_native_oracles
    with pytest.raises(dart_snapshot.DartSnapshotError):
        dart_snapshot.inspect_dart_snapshot(data[:len(data) // 2])

    rng = random.Random(0xDA47)
    for offset in sorted({rng.randrange(len(data)) for _ in range(80)}):
        mutated = bytearray(data)
        mutated[offset] ^= 1 << rng.randrange(8)
        try:
            dart_snapshot.inspect_dart_snapshot(mutated)
        except dart_snapshot.DartSnapshotError:
            pass


def test_json_cli_and_guarded_argparse(tmp_path, capsys):
    path = tmp_path / "isolate_snapshot_data.bin"
    path.write_bytes(reference_snapshot())
    assert dart_snapshot.main([str(path), "--max-strings", "32"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["snapshots"][0]["kind_name"] == "full-aot"

    assert dart_snapshot.main([]) == 2
    assert "usage:" in capsys.readouterr().err
    assert dart_snapshot.main(["--help"]) == 0
    assert "statically inspect" in capsys.readouterr().out
    assert dart_snapshot.main([str(path), "--min-string", "2"]) == 2
    assert "min_string_length" in capsys.readouterr().err
