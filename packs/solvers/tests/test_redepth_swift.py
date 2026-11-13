"""Swift 6 compiler oracle and malformed-input checks for redepth_swift."""
from __future__ import annotations

import json
import random
import shutil
import struct
import subprocess
import sys

import pytest

import redepth_swift as swift


SOURCE = r"""
struct GridNode {
    let voltage: Int
    var label: String
}

final class RelayController {
    var enabled: Bool
    let node: GridNode

    init(enabled: Bool, node: GridNode) {
        self.enabled = enabled
        self.node = node
    }
}

enum GridState {
    case stable
    case fault(code: Int)
}

@inline(never)
func describe(_ relay: RelayController, _ state: GridState) -> String {
    switch state {
    case .stable:
        return relay.enabled ? relay.node.label : "disabled"
    case .fault(let code):
        return "fault-\(code)-\(relay.node.voltage)"
    }
}

let node = GridNode(voltage: 230, label: "substation")
let relay = RelayController(enabled: true, node: node)
print(describe(relay, .fault(code: 7)))
"""


@pytest.fixture(scope="module")
def compiled_swift(tmp_path_factory):
    compiler = shutil.which("swiftc")
    if sys.platform != "darwin" or compiler is None:
        pytest.skip("the Mach-O Swift compiler oracle is available only on Darwin")
    root = tmp_path_factory.mktemp("swift-oracle")
    source = root / "GridFixture.swift"
    output = root / "grid-fixture"
    source.write_text(SOURCE, encoding="utf-8")
    process = subprocess.run(
        [compiler, "-Onone", "-g", "-module-name", "GridFixture",
         str(source), "-o", str(output)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert process.returncode == 0, process.stderr
    data = output.read_bytes()
    assert data[:4] in swift._MACHO_MAGICS
    return output, data


def _types_by_name(report):
    return {row["name"]: row for row in report["types"]}


def _fields_by_name(type_row):
    return {row["name"]: row for row in type_row["fields"]}


def test_compiler_oracle_recovers_nominal_types_and_parent_module(compiled_swift):
    _, data = compiled_swift
    report = swift.extract_swift_metadata(data)
    assert report is not None
    assert report["format"] == "mach-o-swift"
    assert report["bits"] == 64
    assert report["byte_order"] == "little"

    types = _types_by_name(report)
    assert {"GridNode", "RelayController", "GridState"} <= set(types)
    assert types["GridNode"]["kind"] == "struct"
    assert types["RelayController"]["kind"] == "class"
    assert types["GridState"]["kind"] == "enum"
    for name in ("GridNode", "RelayController", "GridState"):
        row = types[name]
        assert row["module"] == "GridFixture"
        assert row["qualified_name"] == f"GridFixture.{name}"
        assert row["parent_chain"][0]["kind"] == "module"
        assert row["parent_chain"][0]["name"] == "GridFixture"
        assert row["descriptor_file_offset"] >= 0


def test_compiler_oracle_recovers_source_fields_cases_and_raw_types(compiled_swift):
    _, data = compiled_swift
    report = swift.extract_swift_metadata(data)
    assert report is not None
    types = _types_by_name(report)

    node = _fields_by_name(types["GridNode"])
    assert list(node) == ["voltage", "label"]
    assert node["voltage"]["mangled_type_raw"] == "Si"
    assert node["voltage"]["mangled_type_hex"] == b"Si".hex()
    assert node["label"]["mangled_type_raw"] == "SS"
    assert node["label"]["mangled_type_hex"] == b"SS".hex()
    assert not node["voltage"]["is_var"]
    assert node["label"]["is_var"]

    relay = _fields_by_name(types["RelayController"])
    assert list(relay) == ["enabled", "node"]
    assert relay["enabled"]["mangled_type_raw"] == "Sb"
    assert relay["enabled"]["mangled_type_hex"] == b"Sb".hex()
    assert relay["enabled"]["is_var"]
    assert not relay["node"]["is_var"]
    # A user type is encoded with a binary symbolic reference.  The hex/raw
    # pair must remain lossless even when its four-byte operand contains NULs.
    encoded_node = relay["node"]
    assert bytes.fromhex(encoded_node["mangled_type_hex"]).decode("latin-1") == encoded_node["mangled_type_raw"]
    assert encoded_node["mangled_type_hex"].startswith("01")

    state = _fields_by_name(types["GridState"])
    assert set(state) == {"stable", "fault"}
    assert state["stable"]["mangled_type_raw"] is None
    # The source payload is a one-element labelled tuple ``(code: Int)``.
    assert state["fault"]["mangled_type_raw"] == "Si4code_t"
    assert types["GridState"]["declared_field_count"] == 2

    assert types["GridNode"]["field_descriptor"]["kind"] == "struct"
    assert types["RelayController"]["field_descriptor"]["kind"] == "class"
    assert types["GridState"]["field_descriptor"]["kind"] == "enum"


def test_symtab_inventory_and_va_mapping(compiled_swift):
    _, data = compiled_swift
    image = swift.parse_macho(data)
    assert image is not None
    type_section = next(section for section in image.sections
                        if section.name == "__swift5_types")
    assert image.va_to_file_offset(type_section.address, 4) == type_section.file_offset
    with pytest.raises(swift.SwiftMetadataError):
        image.va_to_file_offset(1 << image.bits)

    report = swift.extract_swift_metadata(data)
    assert report is not None
    symbols = report["swift_symbols"]
    assert symbols
    assert any(row["raw"].startswith("_$s") for row in symbols)
    assert all(row["normalized"].startswith(("$s", "$S", "_T")) for row in symbols)
    assert any("GridFixture" in row["normalized"] for row in symbols)
    assert all(row["scheme"] in {"swift5", "swift4", "legacy"} for row in symbols)


def test_non_format_and_recognized_truncations_fail_closed(compiled_swift):
    _, data = compiled_swift
    assert swift.extract_swift_metadata(b"not a Mach-O") is None
    assert swift.parse_macho(b"\x7fELF" + b"\0" * 64) is None
    for bad in (None, 7, "Mach-O", [], {}):
        with pytest.raises(swift.SwiftMetadataError):
            swift.extract_swift_metadata(bad)
    for stop in (4, 16, 27, 31, len(data) // 2):
        with pytest.raises(swift.SwiftMetadataError):
            swift.extract_swift_metadata(data[:stop])


def test_corrupt_commands_and_relative_type_pointer_raise_declared_error(compiled_swift):
    _, data = compiled_swift
    corrupt_commands = bytearray(data)
    struct.pack_into("<I", corrupt_commands, 16, swift.MAX_LOAD_COMMANDS + 1)
    with pytest.raises(swift.SwiftMetadataError):
        swift.extract_swift_metadata(corrupt_commands)

    image = swift.parse_macho(data)
    assert image is not None
    type_section = next(section for section in image.sections
                        if section.name == "__swift5_types")
    corrupt_relative = bytearray(data)
    struct.pack_into("<i", corrupt_relative, type_section.file_offset, 0x7FFFFFFF)
    with pytest.raises(swift.SwiftMetadataError):
        swift.extract_swift_metadata(corrupt_relative)

    assert image.symtab is not None
    corrupt_symtab = bytearray(data)
    symtab_command = next(command for command in image.load_commands
                          if command.command == swift.LC_SYMTAB)
    struct.pack_into("<I", corrupt_symtab, symtab_command.file_offset + 8,
                     len(corrupt_symtab) - 1)
    with pytest.raises(swift.SwiftMetadataError):
        swift.extract_swift_metadata(corrupt_symtab)


def test_deterministic_mutations_never_leak_stdlib_exceptions(compiled_swift):
    _, data = compiled_swift
    rng = random.Random(0x5A17)
    offsets = {rng.randrange(len(data)) for _ in range(80)}
    for offset in sorted(offsets):
        mutated = bytearray(data)
        mutated[offset] ^= 1 << rng.randrange(8)
        try:
            swift.extract_swift_metadata(mutated)
        except swift.SwiftMetadataError:
            pass


def test_json_cli_and_guarded_argparse(compiled_swift, tmp_path, capsys):
    path, _ = compiled_swift
    assert swift.main([str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {"GridNode", "RelayController", "GridState"} <= set(_types_by_name(report))

    assert swift.main(["--help"]) == 0
    capsys.readouterr()
    assert swift.main(["--not-an-option"]) == 2
    capsys.readouterr()
    assert swift.main([]) == 2
    capsys.readouterr()

    missing = tmp_path / "missing"
    assert swift.main([str(missing)]) == 2
    assert "cannot read input" in capsys.readouterr().err

    other = tmp_path / "other.bin"
    other.write_bytes(b"not Mach-O")
    assert swift.main([str(other)]) == 2
    assert "not a Swift thin Mach-O" in capsys.readouterr().err
