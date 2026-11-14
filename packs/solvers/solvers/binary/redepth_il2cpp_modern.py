#!/usr/bin/env python3
"""Strict offline inspector for modern Unity IL2CPP metadata v29 and v31.

This complements ``solvers/toolkits/il2cpp.py`` (classic v24/v27).  Layouts are
limited to the fixed-width, pre-v35 definitions published by LibCpp2IL:

* ``Il2CppGlobalMetadataHeader`` has 31 ``(offset, size-in-bytes)`` pairs;
* all indices are signed 32-bit before metadata v38;
* v29 method definitions are 32 bytes and v31 adds a return-parameter token,
  making them 36 bytes;
* type, image, and assembly definitions are respectively 88, 40, and 64 bytes.

Versions 35+ are reported as unsupported.  In particular, v35 removes the
literal length and a type field, while v38 adds a separate record count to each
section header.  Applying v29 strides to either would manufacture structure.
Nothing here reads a paired native binary, loads metadata, or executes input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Iterable


MAGIC = 0xFAB11BAF
MAX_INPUT = 512 << 20
MAX_RECORDS = 1_000_000
MAX_OUTPUT = 4096
MAX_STRING = 4096
MAX_LITERAL = 1 << 20


class ModernIl2CppError(ValueError):
    """A recognized IL2CPP metadata file violates the selected published layout."""


# Exact read order in LibCpp2IL's Il2CppGlobalMetadataHeader for v29/v31.
HEADER_FIELDS = (
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
HEADER_SIZE = 8 + len(HEADER_FIELDS) * 8

# Strides below follow the field order and v29/v31 version gates in current
# LibCpp2IL metadata definitions.  A missing stride means the directory is
# still bounds/overlap validated, but no record count is invented for it.
COMMON_STRIDES = {
    "stringLiteral": 8,
    "events": 24,
    "properties": 20,
    "parameterDefaultValues": 12,
    "fieldDefaultValues": 12,
    "parameters": 12,
    "fields": 12,
    "genericParameterConstraints": 4,
    "nestedTypes": 4,
    "interfaces": 4,
    "vtableMethods": 4,
    "interfaceOffsets": 8,
    "typeDefinitions": 88,
    "images": 40,
    "assemblies": 64,
    "fieldRefs": 8,
    "referencedAssemblies": 4,
    "unresolvedVirtualCallParameterTypes": 4,
    "unresolvedVirtualCallParameterRanges": 8,
    "windowsRuntimeTypeNames": 8,
    "exportedTypeDefinitions": 4,
}
PROFILES = {
    29: {"name": "v29/v29.1", "method_stride": 32, "return_parameter_token": False},
    31: {"name": "v31/v31.1", "method_stride": 36, "return_parameter_token": True},
}


def _unsupported_reason(version: int) -> str:
    if version in (24, 27):
        return "classic metadata version; use solvers/toolkits/il2cpp.py"
    if version == 35:
        return "v35 removes string-literal length and Il2CppTypeDefinition.elementTypeIndex"
    if version in (38, 39):
        return "v38+ section headers add an explicit record count and use variable-width indices"
    if version in (104, 105, 106):
        return "Unity 6 profile uses additional directories and version-dependent variable-width indices"
    return "no exact modern profile is implemented for this metadata version"


def _span(data: bytes, offset: int, size: int, label: str) -> None:
    if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 0:
        raise ModernIl2CppError(f"invalid {label} span")
    if offset > len(data) or size > len(data) - offset:
        raise ModernIl2CppError(f"truncated {label}")


def _unpack(data: bytes, fmt: str, offset: int, label: str) -> tuple:
    size = struct.calcsize("<" + fmt)
    _span(data, offset, size, label)
    try:
        return struct.unpack_from("<" + fmt, data, offset)
    except (struct.error, OverflowError) as exc:
        raise ModernIl2CppError(f"malformed {label}") from exc


def _table_count(directory: dict[str, dict], name: str) -> int:
    count = directory[name]["record_count"]
    if count is None:
        raise ModernIl2CppError(f"internal profile has no stride for {name}")
    return count


def _parse_directories(data: bytes, profile: dict) -> tuple[list[dict], dict[str, dict]]:
    strides = dict(COMMON_STRIDES)
    strides["methods"] = profile["method_stride"]
    rows: list[dict] = []
    by_name: dict[str, dict] = {}
    nonempty: list[tuple[int, int, str]] = []
    for index, name in enumerate(HEADER_FIELDS):
        offset, byte_count = _unpack(data, "ii", 8 + index * 8, f"{name} directory")
        if offset < 0 or byte_count < 0:
            raise ModernIl2CppError(f"{name} has a negative offset or byte count")
        if byte_count:
            if offset < HEADER_SIZE:
                raise ModernIl2CppError(f"{name} overlaps the complete metadata header")
            _span(data, offset, byte_count, name)
            nonempty.append((offset, offset + byte_count, name))
        elif offset > len(data):
            raise ModernIl2CppError(f"empty {name} offset lies outside the file")
        stride = strides.get(name)
        record_count = None
        if stride is not None:
            if byte_count % stride:
                raise ModernIl2CppError(
                    f"{name} byte count {byte_count} is not divisible by documented stride {stride}",
                )
            record_count = byte_count // stride
            if record_count > MAX_RECORDS:
                raise ModernIl2CppError(f"{name} record count exceeds cap")
        row = {"index": index, "name": name, "offset": offset,
               "byte_count": byte_count, "record_stride": stride,
               "record_count": record_count,
               "count_source": "derived_from_byte_count" if stride else None}
        rows.append(row)
        by_name[name] = row
    nonempty.sort()
    for previous, current in zip(nonempty, nonempty[1:]):
        if current[0] < previous[1]:
            raise ModernIl2CppError(
                f"metadata directories {previous[2]} and {current[2]} overlap",
            )
    return rows, by_name


def _string_reader(data: bytes, directory: dict[str, dict]):
    row = directory["string"]
    heap_start, heap_size = row["offset"], row["byte_count"]
    heap_end = heap_start + heap_size

    def read(index: int, label: str, *, allow_empty: bool = False) -> str:
        if index < 0 or index >= heap_size:
            raise ModernIl2CppError(f"{label} string index is outside the metadata string heap")
        start = heap_start + index
        end = data.find(b"\0", start, heap_end)
        if end < 0:
            raise ModernIl2CppError(f"{label} string is not NUL terminated inside the heap")
        raw = data[start:end]
        if len(raw) > MAX_STRING or (not raw and not allow_empty):
            raise ModernIl2CppError(f"{label} string is empty or exceeds cap")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ModernIl2CppError(f"{label} string is not UTF-8") from exc
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
            raise ModernIl2CppError(f"{label} string contains control characters")
        return text

    return read


def _valid_token(token: int, table: int, label: str) -> None:
    if token and token >> 24 != table:
        raise ModernIl2CppError(f"{label} has an implausible metadata token")


def _range(start: int, count: int, total: int, label: str) -> tuple[int, int] | None:
    if count < 0:
        raise ModernIl2CppError(f"{label} has a negative count")
    if not count:
        if start < -1 or start > total:
            raise ModernIl2CppError(f"empty {label} has an invalid start")
        return None
    if start < 0 or start > total or count > total - start:
        raise ModernIl2CppError(f"{label} exceeds its referenced table")
    return start, start + count


def _owners(total: int, ranges: list[tuple[int, int, int]], label: str,
            *, require_complete: bool = True) -> list[int]:
    owner = [-1] * total
    for start, end, index in ranges:
        for item in range(start, end):
            if owner[item] != -1:
                raise ModernIl2CppError(f"{label} ranges overlap")
            owner[item] = index
    if require_complete and any(index < 0 for index in owner):
        raise ModernIl2CppError(f"{label} ranges do not cover the complete table")
    return owner


def _parse_assemblies(data: bytes, directory: dict[str, dict], read_string) -> list[dict]:
    row = directory["assemblies"]
    count = _table_count(directory, "assemblies")
    referenced_count = _table_count(directory, "referencedAssemblies")
    out: list[dict] = []
    for index in range(count):
        base = row["offset"] + index * 64
        image_index, token, referenced_start, referenced_length = _unpack(
            data, "iIii", base, f"assembly {index}",
        )
        name_index, culture_index, public_key_index = _unpack(
            data, "iii", base + 16, f"assembly-name {index}",
        )
        hash_algorithm, hash_length, flags, major, minor, build, revision = _unpack(
            data, "IiIiiii", base + 28, f"assembly-name details {index}",
        )
        public_key_token = _unpack(data, "Q", base + 56, f"assembly public-key token {index}")[0]
        _valid_token(token, 0x20, f"assembly {index}")
        _range(referenced_start, referenced_length, referenced_count,
               f"assembly {index} referenced-assembly range")
        out.append({
            "index": index,
            "name": read_string(name_index, f"assembly {index} name"),
            "culture": read_string(culture_index, f"assembly {index} culture", allow_empty=True),
            "image_index": image_index,
            "token": token,
            "referenced_assembly_start": referenced_start,
            "referenced_assembly_count": referenced_length,
            "public_key_index": public_key_index,
            "hash_algorithm": hash_algorithm,
            "hash_length": hash_length,
            "flags": flags,
            "version": f"{major}.{minor}.{build}.{revision}",
            "public_key_token": f"{public_key_token:016x}",
        })
    return out


def _parse_types(data: bytes, directory: dict[str, dict], read_string) -> tuple[list[dict], dict[str, list[int]]]:
    row = directory["typeDefinitions"]
    count = _table_count(directory, "typeDefinitions")
    totals = {
        "methods": _table_count(directory, "methods"),
        "fields": _table_count(directory, "fields"),
        "events": _table_count(directory, "events"),
        "properties": _table_count(directory, "properties"),
        "nestedTypes": _table_count(directory, "nestedTypes"),
        "interfaces": _table_count(directory, "interfaces"),
        "vtableMethods": _table_count(directory, "vtableMethods"),
        "interfaceOffsets": _table_count(directory, "interfaceOffsets"),
    }
    range_rows: dict[str, list[tuple[int, int, int]]] = {name: [] for name in totals}
    out: list[dict] = []
    for index in range(count):
        base = row["offset"] + index * 88
        name_index, namespace_index = _unpack(data, "ii", base, f"type {index} names")
        (byval_type, declaring_type, parent_type, element_type, generic_container,
         flags, field_start, method_start, event_start, property_start,
         nested_start, interfaces_start, vtable_start, interface_offsets_start) = _unpack(
            data, "iiiiiiiii iiiii".replace(" ", ""), base + 8, f"type {index} body",
        )
        counts = _unpack(data, "HHHHHHHH", base + 64, f"type {index} counts")
        bitfield, token = _unpack(data, "II", base + 80, f"type {index} tail")
        method_count, property_count, field_count, event_count, nested_count, vtable_count, \
            interfaces_count, interface_offsets_count = counts
        starts_counts = {
            "methods": (method_start, method_count),
            "fields": (field_start, field_count),
            "events": (event_start, event_count),
            "properties": (property_start, property_count),
            "nestedTypes": (nested_start, nested_count),
            "interfaces": (interfaces_start, interfaces_count),
            "vtableMethods": (vtable_start, vtable_count),
            "interfaceOffsets": (interface_offsets_start, interface_offsets_count),
        }
        for table, (start, item_count) in starts_counts.items():
            extent = _range(start, item_count, totals[table], f"type {index} {table} range")
            if extent:
                range_rows[table].append((*extent, index))
        _valid_token(token, 0x02, f"type {index}")
        name = read_string(name_index, f"type {index} name")
        namespace = read_string(namespace_index, f"type {index} namespace", allow_empty=True)
        out.append({
            "index": index, "name": name, "namespace": namespace,
            "full_name": f"{namespace}.{name}" if namespace else name,
            "token": token, "flags": flags, "bitfield": bitfield,
            "byval_type_index": byval_type, "declaring_type_index": declaring_type,
            "parent_type_index": parent_type, "element_type_index": element_type,
            "generic_container_index": generic_container,
            "field_start": field_start, "field_count": field_count,
            "method_start": method_start, "method_count": method_count,
            "event_start": event_start, "event_count": event_count,
            "property_start": property_start, "property_count": property_count,
            "nested_types_start": nested_start, "nested_type_count": nested_count,
            "interfaces_start": interfaces_start, "interfaces_count": interfaces_count,
            "vtable_start": vtable_start, "vtable_count": vtable_count,
            "interface_offsets_start": interface_offsets_start,
            "interface_offsets_count": interface_offsets_count,
        })
    owners = {table: _owners(totals[table], ranges, f"type {table}")
              for table, ranges in range_rows.items()}
    return out, owners


def _parse_methods(data: bytes, directory: dict[str, dict], profile: dict,
                   read_string, types: list[dict], method_owners: list[int]) -> list[dict]:
    row = directory["methods"]
    count = _table_count(directory, "methods")
    parameter_total = _table_count(directory, "parameters")
    parameter_ranges: list[tuple[int, int, int]] = []
    out: list[dict] = []
    for index in range(count):
        base = row["offset"] + index * profile["method_stride"]
        name_index, declaring_type, return_type = _unpack(data, "iii", base,
                                                           f"method {index} prefix")
        cursor = base + 12
        return_parameter_token = None
        if profile["return_parameter_token"]:
            return_parameter_token = _unpack(data, "I", cursor,
                                             f"method {index} return token")[0]
            cursor += 4
            _valid_token(return_parameter_token, 0x08, f"method {index} return parameter")
        parameter_start, generic_container, token = _unpack(
            data, "iiI", cursor, f"method {index} body",
        )
        flags, implementation_flags, slot, parameter_count = _unpack(
            data, "HHHH", cursor + 12, f"method {index} tail",
        )
        if not 0 <= declaring_type < len(types):
            raise ModernIl2CppError(f"method {index} declaring type is out of range")
        if method_owners[index] != declaring_type:
            raise ModernIl2CppError(f"method {index} disagrees with its type method range")
        extent = _range(parameter_start, parameter_count, parameter_total,
                        f"method {index} parameter range")
        if extent:
            parameter_ranges.append((*extent, index))
        _valid_token(token, 0x06, f"method {index}")
        name = read_string(name_index, f"method {index} name")
        item = {
            "index": index, "name": name,
            "declaring_type_index": declaring_type,
            "declaring_type": types[declaring_type]["full_name"],
            "qualified_name": f"{types[declaring_type]['full_name']}.{name}",
            "return_type_index": return_type,
            "parameter_start": parameter_start, "parameter_count": parameter_count,
            "generic_container_index": generic_container, "token": token,
            "flags": flags, "implementation_flags": implementation_flags, "slot": slot,
        }
        if return_parameter_token is not None:
            item["return_parameter_token"] = return_parameter_token
        out.append(item)
    _owners(parameter_total, parameter_ranges, "method parameter", require_complete=True)
    return out


def _parse_images(data: bytes, directory: dict[str, dict], read_string,
                  assemblies: list[dict], types: list[dict]) -> list[dict]:
    row = directory["images"]
    count = _table_count(directory, "images")
    method_count = _table_count(directory, "methods")
    exported_count = _table_count(directory, "exportedTypeDefinitions")
    attribute_ranges = directory["attributeDataRange"]["record_count"]
    type_ranges: list[tuple[int, int, int]] = []
    out: list[dict] = []
    for index in range(count):
        base = row["offset"] + index * 40
        (name_index, assembly_index, first_type, type_count,
         exported_start, exported_length, entrypoint, token,
         attribute_start, attribute_count) = _unpack(data, "iiiIiIiIiI", base,
                                                      f"image {index}")
        if not 0 <= assembly_index < len(assemblies):
            raise ModernIl2CppError(f"image {index} assembly index is out of range")
        extent = _range(first_type, type_count, len(types), f"image {index} type range")
        if extent:
            type_ranges.append((*extent, index))
        _range(exported_start, exported_length, exported_count,
               f"image {index} exported-type range")
        if entrypoint != -1 and not 0 <= entrypoint < method_count:
            raise ModernIl2CppError(f"image {index} entrypoint is out of range")
        if attribute_count and attribute_ranges is not None:
            _range(attribute_start, attribute_count, attribute_ranges,
                   f"image {index} custom-attribute range")
        _valid_token(token, 0x20, f"image {index}")
        out.append({
            "index": index, "name": read_string(name_index, f"image {index} name"),
            "assembly_index": assembly_index, "assembly_name": assemblies[assembly_index]["name"],
            "first_type_index": first_type, "type_count": type_count,
            "exported_type_start": exported_start, "exported_type_count": exported_length,
            "entrypoint_index": entrypoint, "token": token,
            "custom_attribute_start": attribute_start,
            "custom_attribute_count": attribute_count,
        })
    _owners(len(types), type_ranges, "image type")
    for assembly in assemblies:
        if not 0 <= assembly["image_index"] < len(out):
            raise ModernIl2CppError(f"assembly {assembly['index']} image index is out of range")
        if out[assembly["image_index"]]["assembly_index"] != assembly["index"]:
            raise ModernIl2CppError("assembly/image indices are not reciprocal")
    return out


def _parse_literals(data: bytes, directory: dict[str, dict]) -> list[dict]:
    table = directory["stringLiteral"]
    blob = directory["stringLiteralData"]
    count = _table_count(directory, "stringLiteral")
    out: list[dict] = []
    for index in range(count):
        length, data_index = _unpack(data, "Ii", table["offset"] + index * 8,
                                     f"string literal {index}")
        if data_index < 0 or length > blob["byte_count"] or data_index > blob["byte_count"] - length:
            raise ModernIl2CppError(f"string literal {index} exceeds its data directory")
        start = blob["offset"] + data_index
        if length > MAX_LITERAL:
            item = {"index": index, "data_index": data_index, "byte_length": length,
                    "file_offset": start, "text": None, "bytes_hex": None, "oversized": True}
        else:
            raw = data[start:start + length]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            item = {"index": index, "data_index": data_index, "byte_length": length,
                    "file_offset": start, "text": text, "bytes_hex": raw.hex(),
                    "oversized": False}
        if len(out) < MAX_OUTPUT:
            out.append(item)
    return out


def _inspect(data: bytes, source_name: str | None) -> dict | None:
    if not isinstance(data, bytes):
        raise ModernIl2CppError("input must be bytes")
    if len(data) > MAX_INPUT:
        raise ModernIl2CppError("metadata exceeds input-size cap")
    if len(data) < 4:
        return None
    magic = _unpack(data, "I", 0, "metadata magic")[0]
    if magic != MAGIC:
        return None
    _span(data, 0, 8, "metadata prefix")
    version = _unpack(data, "i", 4, "metadata version")[0]
    profile = PROFILES.get(version)
    base_report = {
        "format": "unity_il2cpp_global_metadata",
        "source": Path(source_name).name if source_name else None,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": version,
        "supported": profile is not None,
        "supported_versions": sorted(PROFILES),
    }
    if profile is None:
        base_report["unsupported_reason"] = _unsupported_reason(version)
        return base_report
    _span(data, 0, HEADER_SIZE, "complete v29/v31 metadata header")
    directory_rows, directory = _parse_directories(data, profile)
    read_string = _string_reader(data, directory)
    assemblies = _parse_assemblies(data, directory, read_string)
    types, owners = _parse_types(data, directory, read_string)
    methods = _parse_methods(data, directory, profile, read_string, types, owners["methods"])
    images = _parse_images(data, directory, read_string, assemblies, types)
    literals = _parse_literals(data, directory)
    counts = {name: directory[name]["record_count"] for name in HEADER_FIELDS
              if directory[name]["record_count"] is not None}
    base_report.update({
        "profile": profile["name"],
        "header_size": HEADER_SIZE,
        "directory_entry_semantics": "offset_and_byte_count",
        "directories": directory_rows,
        "counts": counts,
        "assemblies": assemblies[:MAX_OUTPUT],
        "images": images[:MAX_OUTPUT],
        "types": types[:MAX_OUTPUT],
        "methods": methods[:MAX_OUTPUT],
        "string_literals": literals,
        "output_truncated": {
            "assemblies": len(assemblies) > MAX_OUTPUT,
            "images": len(images) > MAX_OUTPUT,
            "types": len(types) > MAX_OUTPUT,
            "methods": len(methods) > MAX_OUTPUT,
            "string_literals": counts["stringLiteral"] > MAX_OUTPUT,
        },
    })
    return base_report


def inspect_metadata(data: bytes, *, source_name: str | None = None) -> dict | None:
    """Return a JSON-ready inventory, ``None``, or raise only ``ModernIl2CppError``."""
    try:
        return _inspect(data, source_name)
    except ModernIl2CppError:
        raise
    except (Exception, MemoryError) as exc:
        raise ModernIl2CppError(f"metadata analysis failed closed: {type(exc).__name__}") from exc


def inspect_file(path: str | Path) -> dict | None:
    """Read one metadata artifact within the hard cap and inspect it statically."""
    try:
        file_path = Path(path)
        with file_path.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ModernIl2CppError("metadata exceeds input-size cap")
        return inspect_metadata(data, source_name=str(file_path))
    except ModernIl2CppError:
        raise
    except (OSError, TypeError, ValueError, MemoryError) as exc:
        raise ModernIl2CppError(f"could not read metadata: {exc}") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect Unity IL2CPP global-metadata.dat v29/v31 offline.",
    )
    parser.add_argument("input", help="global-metadata.dat")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = inspect_file(args.input)
        if report is None:
            raise ModernIl2CppError("input does not have the IL2CPP metadata magic")
        print(json.dumps(report, sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except ModernIl2CppError as exc:
        print(f"redepth_il2cpp_modern: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
