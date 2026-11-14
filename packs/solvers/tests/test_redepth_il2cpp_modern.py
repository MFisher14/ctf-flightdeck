"""Independent fixtures for the strict modern IL2CPP metadata inspector.

The fixture packer below directly follows Unity/LibCpp2IL's published metadata
structures; it deliberately does not call, import, or copy constants from the
engine under test.  Relevant upstream definitions are:

* LibCpp2IL/Metadata/Il2CppGlobalMetadataHeader.cs
* LibCpp2IL/Metadata/Il2CppTypeDefinition.cs
* LibCpp2IL/Metadata/Il2CppMethodDefinition.cs
* LibCpp2IL/Metadata/Il2CppImageDefinition.cs
* LibCpp2IL/Metadata/Il2CppAssemblyDefinition.cs
"""
from __future__ import annotations

import ast
import json
import struct
from pathlib import Path

import pytest

import redepth_il2cpp_modern as modern


# The 31 pre-v38 section headers, independently transcribed in published read
# order.  Their second word is a byte count, never a record count.
_SECTIONS = (
    "stringLiteral",
    "stringLiteralData",
    "string",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "fieldRefs",
    "referencedAssemblies",
    "attributeData",
    "attributeDataRange",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
    "exportedTypeDefinitions",
)
_HEADER_SIZE = 8 + 31 * 8


def _sample(version: int) -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Hand-pack one coherent metadata image without using engine output."""
    assert version in (29, 31)
    heap = bytearray(b"\0")
    indices: dict[str, int] = {"": 0}

    def add_string(value: str) -> int:
        indices[value] = len(heap)
        heap.extend(value.encode("utf-8") + b"\0")
        return indices[value]

    for value in (
        "Assembly-CSharp",
        "Assembly-CSharp.dll",
        "CriticalGrid",
        "TotalWarfare",
        "TripBreaker",
        "tripCode",
    ):
        add_string(value)

    literal = f"IL2CPP_MODERN_SENTINEL_{version}".encode("ascii")

    # Il2CppMethodDefinition: v31 inserts returnParameterToken after returnType.
    if version == 29:
        method = struct.pack(
            "<iiiiiIHHHH",
            indices["TripBreaker"], 0, 0, 0, -1, 0x06000001,
            0x0016, 0, 0, 1,
        )
        assert len(method) == 32
    else:
        method = struct.pack(
            "<iiiIiiIHHHH",
            indices["TripBreaker"], 0, 0, 0x08000001, 0, -1,
            0x06000001, 0x0016, 0, 0, 1,
        )
        assert len(method) == 36

    parameter = struct.pack("<iIi", indices["tripCode"], 0x08000001, 0)
    field = struct.pack("<iiI", indices["tripCode"], 0, 0x04000001)

    # Il2CppTypeDefinition v29/v31: sixteen 32-bit words, eight 16-bit
    # counts, then bitfield and token.  It owns the sole field and method.
    type_definition = bytearray(88)
    struct.pack_into(
        "<iiiiiiiiiiiiiiii",
        type_definition,
        0,
        indices["CriticalGrid"], indices["TotalWarfare"],
        0, -1, -1, -1, -1, 0x00100001,
        0, 0, -1, -1, -1, -1, -1, -1,
    )
    struct.pack_into("<HHHHHHHH", type_definition, 64, 1, 0, 1, 0, 0, 0, 0, 0)
    struct.pack_into("<II", type_definition, 80, 0, 0x02000001)

    image = struct.pack(
        "<iiiIiIiIiI",
        indices["Assembly-CSharp.dll"], 0, 0, 1,
        -1, 0, -1, 0x20000001, -1, 0,
    )
    assert len(image) == 40

    assembly = bytearray(64)
    struct.pack_into("<iIii", assembly, 0, 0, 0x20000001, -1, 0)
    struct.pack_into(
        "<iii",
        assembly,
        16,
        indices["Assembly-CSharp"], indices[""], -1,
    )
    struct.pack_into("<IiIiiii", assembly, 28, 0, 0, 0, 1, 0, 0, 0)
    struct.pack_into("<Q", assembly, 56, 0)

    payloads: dict[str, bytes] = {
        "stringLiteral": struct.pack("<Ii", len(literal), 0),
        "stringLiteralData": literal,
        "string": bytes(heap),
        "methods": method,
        "parameters": parameter,
        "fields": field,
        "typeDefinitions": bytes(type_definition),
        "images": image,
        "assemblies": bytes(assembly),
    }

    output = bytearray(_HEADER_SIZE)
    layout: dict[str, tuple[int, int]] = {}
    for name in _SECTIONS:
        chunk = payloads.get(name, b"")
        if not chunk:
            layout[name] = (0, 0)
            continue
        while len(output) % 4:
            output.append(0)
        layout[name] = (len(output), len(chunk))
        output.extend(chunk)

    struct.pack_into("<Ii", output, 0, 0xFAB11BAF, version)
    for index, name in enumerate(_SECTIONS):
        struct.pack_into("<ii", output, 8 + index * 8, *layout[name])
    return bytes(output), layout


def _replace_pair(data: bytes, section_index: int, offset: int, size: int) -> bytes:
    changed = bytearray(data)
    struct.pack_into("<ii", changed, 8 + section_index * 8, offset, size)
    return bytes(changed)


@pytest.mark.parametrize("version,method_bytes", [(29, 32), (31, 36)])
def test_published_v29_v31_structures_are_recovered(version: int, method_bytes: int) -> None:
    data, _layout = _sample(version)
    result = modern.inspect_metadata(data, source_name="global-metadata.dat")

    assert result is not None
    assert result["supported"] is True
    assert result["version"] == version
    assert result["profile"] == f"v{version}/v{version}.1"
    assert result["header_size"] == 256
    assert result["directory_entry_semantics"] == "offset_and_byte_count"
    assert len(result["directories"]) == 31

    method_directory = result["directories"][5]
    assert method_directory["byte_count"] == method_bytes
    assert method_directory["record_stride"] == method_bytes
    assert method_directory["record_count"] == 1
    assert method_directory["count_source"] == "derived_from_byte_count"
    assert result["directories"][2]["record_count"] is None

    assert result["assemblies"][0]["name"] == "Assembly-CSharp"
    assert result["images"][0]["name"] == "Assembly-CSharp.dll"
    assert result["types"][0]["full_name"] == "TotalWarfare.CriticalGrid"
    assert result["types"][0]["method_count"] == 1
    assert result["types"][0]["field_count"] == 1
    assert result["methods"][0]["qualified_name"] == (
        "TotalWarfare.CriticalGrid.TripBreaker"
    )
    assert result["methods"][0]["parameter_count"] == 1
    assert result["string_literals"][0]["text"] == f"IL2CPP_MODERN_SENTINEL_{version}"
    if version == 31:
        assert result["methods"][0]["return_parameter_token"] == 0x08000001
    else:
        assert "return_parameter_token" not in result["methods"][0]


@pytest.mark.parametrize(
    "version,reason_fragment",
    [
        (27, "classic metadata version"),
        (35, "removes string-literal length"),
        (38, "explicit record count"),
        (104, "Unity 6 profile"),
        (777, "no exact modern profile"),
    ],
)
def test_unsupported_profiles_are_reported_without_guessing(
    version: int,
    reason_fragment: str,
) -> None:
    data = struct.pack("<Ii", 0xFAB11BAF, version)
    result = modern.inspect_metadata(data)
    assert result is not None
    assert result["supported"] is False
    assert reason_fragment in result["unsupported_reason"]
    assert "directories" not in result


def test_non_format_and_recognized_truncation_contract() -> None:
    assert modern.inspect_metadata(b"") is None
    assert modern.inspect_metadata(b"MZ\x90\x00not metadata") is None
    with pytest.raises(modern.ModernIl2CppError):
        modern.inspect_metadata(struct.pack("<I", 0xFAB11BAF))
    with pytest.raises(modern.ModernIl2CppError):
        modern.inspect_metadata(struct.pack("<Ii", 0xFAB11BAF, 29))


def test_directory_byte_counts_bounds_and_overlap_are_strict() -> None:
    data, layout = _sample(29)
    method_offset, method_size = layout["methods"]

    with pytest.raises(modern.ModernIl2CppError, match="byte count"):
        modern.inspect_metadata(_replace_pair(data, 5, method_offset, method_size - 1))
    with pytest.raises(modern.ModernIl2CppError, match="overlap"):
        modern.inspect_metadata(_replace_pair(data, 11, method_offset, 12))
    with pytest.raises(modern.ModernIl2CppError, match="truncated string"):
        modern.inspect_metadata(_replace_pair(data, 2, len(data) + 4, 1))


def test_cross_table_references_and_literal_spans_are_strict() -> None:
    data, layout = _sample(31)

    bad_string = bytearray(data)
    struct.pack_into("<i", bad_string, layout["methods"][0], 0x7FFFFFFF)
    with pytest.raises(modern.ModernIl2CppError, match="string index"):
        modern.inspect_metadata(bytes(bad_string))

    bad_owner = bytearray(data)
    struct.pack_into("<i", bad_owner, layout["methods"][0] + 4, -1)
    with pytest.raises(modern.ModernIl2CppError, match="declaring type"):
        modern.inspect_metadata(bytes(bad_owner))

    bad_type_range = bytearray(data)
    struct.pack_into("<H", bad_type_range, layout["typeDefinitions"][0] + 64, 0)
    with pytest.raises(modern.ModernIl2CppError, match="do not cover"):
        modern.inspect_metadata(bytes(bad_type_range))

    bad_literal = bytearray(data)
    struct.pack_into("<i", bad_literal, layout["stringLiteral"][0] + 4, 0x7FFFFFFF)
    with pytest.raises(modern.ModernIl2CppError, match="literal"):
        modern.inspect_metadata(bytes(bad_literal))


def test_mutations_never_leak_a_stdlib_exception() -> None:
    data, _layout = _sample(29)
    for offset in range(4, len(data), 13):
        changed = bytearray(data)
        changed[offset] ^= 0xA5
        try:
            modern.inspect_metadata(bytes(changed))
        except Exception as exc:  # noqa: BLE001 - this is the contract assertion
            assert type(exc) is modern.ModernIl2CppError


def test_cli_json_and_guarded_argparse(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data, _layout = _sample(31)
    artifact = tmp_path / "global-metadata.dat"
    artifact.write_bytes(data)

    assert modern.main([str(artifact)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["methods"][0]["name"] == "TripBreaker"

    assert modern.main([]) == 2
    assert "required" in capsys.readouterr().err

    foreign = tmp_path / "foreign.bin"
    foreign.write_bytes(b"ELF")
    assert modern.main([str(foreign)]) == 2
    assert "does not have" in capsys.readouterr().err


def test_engine_is_static_and_has_one_declared_error() -> None:
    source = Path(modern.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert classes == ["ModernIl2CppError"]
    assert not ({"socket", "subprocess", "requests", "urllib", "http"} & imports)
    assert (
        "return exc.code if isinstance(exc.code, int) else 2"
        in source
    )
