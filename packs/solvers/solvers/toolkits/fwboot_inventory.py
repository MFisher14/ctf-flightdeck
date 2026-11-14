#!/usr/bin/env python3
"""Bounded, static inventory for boot-firmware container formats.

The module understands flattened device trees and U-Boot FIT metadata, UEFI
capsules and PI firmware volumes/files/sections, and coreboot CBFS.  Payloads
are hashed and lightly string-scanned, but are never decompressed, verified as
executable code, or run.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid
import zlib


MAX_INPUT = 128 << 20
MAX_FDT_NODES = 16_384
MAX_FDT_PROPERTIES = 65_536
MAX_FDT_DEPTH = 64
MAX_FV_FILES = 8_192
MAX_FV_SECTIONS = 32_768
MAX_CBFS_FILES = 8_192
MAX_CBFS_ATTRIBUTES = 64
MAX_EMBEDDED_STRINGS = 64
MAX_STRING_LENGTH = 256
MAX_VALUE_PREVIEW = 512


class FWBootError(ValueError):
    """The only exception raised for invalid or unsupported input."""


def _fail_closed(function):
    """Convert implementation/stdlib parsing failures into the public error."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FWBootError:
            raise
        except (ArithmeticError, IndexError, KeyError, struct.error, TypeError,
                UnicodeError, ValueError) as exc:
            raise FWBootError(f"invalid {function.__name__} input") from exc

    return wrapped


def _blob(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise FWBootError("input must be immutable bytes")
    if len(data) > MAX_INPUT:
        raise FWBootError("input exceeds the 128 MiB cap")
    return data


def _offset(data: bytes, offset: int, minimum: int, label: str) -> int:
    if (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
            or offset > len(data) or minimum > len(data) - offset):
        raise FWBootError(f"{label} offset is outside the input")
    return offset


def _length(data: bytes, offset: int, length: int | None, label: str) -> int:
    if length is None:
        return len(data) - offset
    if (not isinstance(length, int) or isinstance(length, bool) or length < 0
            or length > len(data) - offset):
        raise FWBootError(f"{label} length is outside the input")
    return length


def _align(value: int, alignment: int) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        raise FWBootError("invalid alignment")
    return (value + alignment - 1) & ~(alignment - 1)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _guid(value: bytes) -> str:
    if len(value) != 16:
        raise FWBootError("truncated UEFI GUID")
    return str(uuid.UUID(bytes_le=value))


def _u24le(value: bytes) -> int:
    if len(value) != 3:
        raise FWBootError("truncated 24-bit integer")
    return value[0] | value[1] << 8 | value[2] << 16


def _cstring(block: bytes, start: int, *, encoding: str, label: str,
             maximum: int = MAX_STRING_LENGTH) -> tuple[str, int]:
    if not 0 <= start < len(block):
        raise FWBootError(f"{label} string offset is outside its block")
    end = block.find(b"\0", start, min(len(block), start + maximum + 1))
    if end < 0:
        raise FWBootError(f"{label} string is unterminated or too long")
    try:
        text = block[start:end].decode(encoding)
    except UnicodeError as exc:
        raise FWBootError(f"{label} string has invalid encoding") from exc
    return text, end + 1


def _string_list(value: bytes) -> list[str] | None:
    if not value or value[-1] != 0:
        return None
    parts = value[:-1].split(b"\0")
    if len(parts) > 256:
        return None
    out = []
    try:
        for part in parts:
            if len(part) > MAX_STRING_LENGTH:
                return None
            text = part.decode("utf-8")
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
                return None
            out.append(text)
    except UnicodeError:
        return None
    return out


def _ascii_strings(value: bytes, base: int, *, cap: int = MAX_EMBEDDED_STRINGS,
                   minimum: int = 4) -> list[dict]:
    """Return a small, bounded inventory of printable ASCII runs."""
    rows: list[dict] = []
    start: int | None = None
    for index in range(len(value) + 1):
        byte = value[index] if index < len(value) else 0
        printable = 0x20 <= byte <= 0x7E
        if printable and start is None:
            start = index
        if not printable and start is not None:
            if index - start >= minimum:
                raw = value[start:min(index, start + MAX_STRING_LENGTH)]
                rows.append({"offset": base + start, "text": raw.decode("ascii"),
                             "truncated": index - start > MAX_STRING_LENGTH})
                if len(rows) >= cap:
                    break
            start = None
    return rows


def _value_summary(value: bytes, absolute_offset: int) -> dict:
    row: dict = {
        "offset": absolute_offset,
        "size": len(value),
        "sha256": _sha256(value),
    }
    if len(value) <= MAX_VALUE_PREVIEW:
        row["hex"] = value.hex()
    else:
        row["preview_hex"] = value[:MAX_VALUE_PREVIEW].hex()
        row["preview_truncated"] = True
    strings = _string_list(value)
    if strings is not None:
        row["strings"] = strings
    if value and len(value) % 4 == 0 and len(value) <= 64:
        row["cells"] = list(struct.unpack(">" + "I" * (len(value) // 4), value))
    return row


# ---- Flattened device tree / FIT ---------------------------------------------------------------

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9


class _FDTProperty:
    __slots__ = ("name", "value", "token_offset", "value_offset", "name_offset")

    def __init__(self, name: str, value: bytes, token_offset: int,
                 value_offset: int, name_offset: int):
        self.name = name
        self.value = value
        self.token_offset = token_offset
        self.value_offset = value_offset
        self.name_offset = name_offset


class _FDTNode:
    __slots__ = ("name", "path", "offset", "end_offset", "properties",
                 "children", "children_started")

    def __init__(self, name: str, path: str, offset: int):
        self.name = name
        self.path = path
        self.offset = offset
        self.end_offset: int | None = None
        self.properties: dict[str, _FDTProperty] = {}
        self.children: list[str] = []
        self.children_started = False


class _FDT:
    __slots__ = ("base", "total_size", "version", "last_compatible",
                 "boot_cpuid", "structure_offset", "structure_size",
                 "strings_offset", "strings_size", "reserve_offset",
                 "reservations", "nodes", "order", "blob")

    def __init__(self):
        self.base = 0
        self.total_size = 0
        self.version = 0
        self.last_compatible = 0
        self.boot_cpuid = 0
        self.structure_offset = 0
        self.structure_size = 0
        self.strings_offset = 0
        self.strings_size = 0
        self.reserve_offset = 0
        self.reservations: list[dict] = []
        self.nodes: dict[str, _FDTNode] = {}
        self.order: list[str] = []
        self.blob = b""


def _parse_fdt(data: bytes, base: int) -> _FDT:
    _offset(data, base, 36, "FDT")
    first = struct.unpack_from(">9I", data, base)
    (magic, total, struct_off, strings_off, reserve_off, version,
     last_compatible, boot_cpuid, strings_size) = first
    if magic != FDT_MAGIC:
        raise FWBootError("FDT magic is absent")
    if not 16 <= version <= 17 or last_compatible > version or last_compatible > 17:
        raise FWBootError("unsupported FDT version")
    header_size = 40 if version >= 17 else 36
    _offset(data, base, header_size, "FDT")
    if total < header_size or total > MAX_INPUT or total > len(data) - base:
        raise FWBootError("FDT total size is truncated or over cap")
    if version >= 17:
        struct_size = struct.unpack_from(">I", data, base + 36)[0]
    else:
        if strings_off <= struct_off:
            raise FWBootError("version-16 FDT blocks are not ordered")
        struct_size = strings_off - struct_off
    if struct_off % 4 or reserve_off % 8:
        raise FWBootError("FDT block alignment is invalid")
    spans = ((struct_off, struct_size, "structure"),
             (strings_off, strings_size, "strings"))
    for start, size, label in spans:
        if start < header_size or size > total or start > total - size:
            raise FWBootError(f"FDT {label} block is outside totalsize")
    ordered = sorted((start, start + size, name) for start, size, name in spans if size)
    if any(ordered[index - 1][1] > ordered[index][0]
           for index in range(1, len(ordered))):
        raise FWBootError("FDT structure and strings blocks overlap")
    next_block = min((start for start, size, _ in spans
                      if size and start > reserve_off), default=total)
    if (reserve_off < header_size or reserve_off + 16 > next_block
            or any(start <= reserve_off < start + size for start, size, _ in spans if size)):
        raise FWBootError("FDT reserve map is outside its block")

    parsed = _FDT()
    parsed.base = base
    parsed.total_size = total
    parsed.version = version
    parsed.last_compatible = last_compatible
    parsed.boot_cpuid = boot_cpuid
    parsed.structure_offset = base + struct_off
    parsed.structure_size = struct_size
    parsed.strings_offset = base + strings_off
    parsed.strings_size = strings_size
    parsed.reserve_offset = base + reserve_off
    parsed.blob = data[base:base + total]

    reserve_cursor = base + reserve_off
    reserve_end = base + next_block
    while reserve_cursor + 16 <= reserve_end:
        address, size = struct.unpack_from(">QQ", data, reserve_cursor)
        if address == size == 0:
            reserve_cursor += 16
            break
        if not size or address > (1 << 64) - size:
            raise FWBootError("FDT reservation range is invalid")
        if len(parsed.reservations) >= MAX_FDT_NODES:
            raise FWBootError("FDT reserve map exceeds entry cap")
        parsed.reservations.append({"offset": reserve_cursor,
                                    "address": address, "size": size})
        reserve_cursor += 16
    else:
        raise FWBootError("FDT reserve map lacks a terminator")

    reserve_relative_end = reserve_cursor - base
    if any(reserve_off < start + size and reserve_relative_end > start
           for start, size, _ in spans if size):
        raise FWBootError("FDT reserve map overlaps another block")
    reservation_ranges = sorted((entry["address"], entry["address"] + entry["size"])
                                for entry in parsed.reservations)
    if any(reservation_ranges[index - 1][1] > reservation_ranges[index][0]
           for index in range(1, len(reservation_ranges))):
        raise FWBootError("FDT memory reservations overlap")

    strings = data[base + strings_off:base + strings_off + strings_size]
    cursor = base + struct_off
    structure_end = cursor + struct_size
    stack: list[_FDTNode] = []
    property_count = 0
    saw_end = False
    saw_root = False
    while cursor + 4 <= structure_end:
        token_offset = cursor
        token = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4
        if token == FDT_BEGIN_NODE:
            relative = cursor - base
            name_bytes_end = data.find(b"\0", cursor, structure_end)
            if name_bytes_end < 0 or name_bytes_end - cursor > MAX_STRING_LENGTH:
                raise FWBootError("FDT node name is unterminated or too long")
            try:
                name = data[cursor:name_bytes_end].decode("utf-8")
            except UnicodeError as exc:
                raise FWBootError("FDT node name is not UTF-8") from exc
            if "/" in name:
                raise FWBootError("FDT node name contains a slash")
            unaligned_cursor = name_bytes_end + 1
            cursor = base + _align(unaligned_cursor - base, 4)
            if cursor > structure_end:
                raise FWBootError("FDT node name padding is truncated")
            if any(data[unaligned_cursor:cursor]):
                raise FWBootError("FDT node-name padding is non-zero")
            if not stack:
                if saw_root or name:
                    raise FWBootError("FDT root node must be unique and unnamed")
                path = "/"
                saw_root = True
            else:
                parent = stack[-1]
                parent.children_started = True
                path = parent.path.rstrip("/") + "/" + name
                if path in parsed.nodes:
                    raise FWBootError("FDT contains duplicate node paths")
                parent.children.append(path)
            node = _FDTNode(name, path, token_offset)
            parsed.nodes[path] = node
            parsed.order.append(path)
            stack.append(node)
            if len(stack) > MAX_FDT_DEPTH or len(parsed.order) > MAX_FDT_NODES:
                raise FWBootError("FDT nesting or node cap exceeded")
            del relative
        elif token == FDT_END_NODE:
            if not stack:
                raise FWBootError("FDT END_NODE is unbalanced")
            stack[-1].end_offset = cursor
            stack.pop()
        elif token == FDT_PROP:
            if not stack or cursor + 8 > structure_end:
                raise FWBootError("FDT property header is truncated or outside a node")
            if stack[-1].children_started:
                raise FWBootError("FDT property follows a child node")
            value_length, name_offset = struct.unpack_from(">II", data, cursor)
            cursor += 8
            if value_length > structure_end - cursor or name_offset >= len(strings):
                raise FWBootError("FDT property range is invalid")
            name, _ = _cstring(strings, name_offset, encoding="ascii",
                               label="FDT property name")
            if not name or name in stack[-1].properties:
                raise FWBootError("FDT property name is empty or duplicated")
            value_offset = cursor
            value = data[cursor:cursor + value_length]
            unaligned_cursor = cursor + value_length
            cursor = base + _align(unaligned_cursor - base, 4)
            if cursor > structure_end:
                raise FWBootError("FDT property padding is truncated")
            if any(data[unaligned_cursor:cursor]):
                raise FWBootError("FDT property padding is non-zero")
            prop = _FDTProperty(name, value, token_offset, value_offset, name_offset)
            stack[-1].properties[name] = prop
            property_count += 1
            if property_count > MAX_FDT_PROPERTIES:
                raise FWBootError("FDT property cap exceeded")
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            if stack or not saw_root or cursor != structure_end:
                raise FWBootError("FDT_END is not the sole final token")
            saw_end = True
            break
        else:
            raise FWBootError(f"unknown FDT token 0x{token:x}")
    if not saw_end:
        raise FWBootError("FDT structure lacks FDT_END")
    return parsed


def _prop_text(prop: _FDTProperty | None, *, required: bool = False) -> str | None:
    if prop is None:
        if required:
            raise FWBootError("required FDT string property is absent")
        return None
    values = _string_list(prop.value)
    if values is None or len(values) != 1:
        raise FWBootError(f"FDT property {prop.name!r} is not one string")
    return values[0]


def _prop_strings(prop: _FDTProperty | None) -> list[str]:
    if prop is None:
        return []
    values = _string_list(prop.value)
    if values is None:
        raise FWBootError(f"FDT property {prop.name!r} is not a string list")
    return values


def _prop_integer(prop: _FDTProperty | None) -> int | None:
    if prop is None:
        return None
    if len(prop.value) not in (4, 8):
        raise FWBootError(f"FDT property {prop.name!r} is not a one/two-cell integer")
    return int.from_bytes(prop.value, "big")


def _fdt_header_report(tree: _FDT) -> dict:
    return {
        "offset": tree.base,
        "size": tree.total_size,
        "end_offset": tree.base + tree.total_size,
        "sha256": _sha256(tree.blob),
        "version": tree.version,
        "last_compatible_version": tree.last_compatible,
        "boot_cpuid": tree.boot_cpuid,
        "structure": {"offset": tree.structure_offset, "size": tree.structure_size},
        "strings": {"offset": tree.strings_offset, "size": tree.strings_size},
        "reserve_map_offset": tree.reserve_offset,
        "reservations": tree.reservations,
    }


def _node_report(node: _FDTNode) -> dict:
    return {
        "path": node.path,
        "name": node.name,
        "offset": node.offset,
        "end_offset": node.end_offset,
        "children": list(node.children),
        "properties": [
            {"name": prop.name, "token_offset": prop.token_offset,
             "name_offset": prop.name_offset,
             **_value_summary(prop.value, prop.value_offset)}
            for prop in node.properties.values()
        ],
    }


def _signature_report(node: _FDTNode) -> dict:
    row: dict = {"node": node.name, "path": node.path, "offset": node.offset,
                 "verification": "not-performed"}
    for name in ("algo", "key-name-hint", "signer-name", "signer-version",
                 "comment", "padding"):
        prop = node.properties.get(name)
        if prop is not None:
            row[name.replace("-", "_")] = _prop_text(prop)
    for name in ("sign-images", "hashed-nodes"):
        prop = node.properties.get(name)
        if prop is not None:
            row[name.replace("-", "_")] = _prop_strings(prop)
    if "hashed-strings" in node.properties:
        prop = node.properties["hashed-strings"]
        if len(prop.value) != 8:
            raise FWBootError("FIT hashed-strings must contain two cells")
        row["hashed_strings"] = list(struct.unpack(">II", prop.value))
    if "timestamp" in node.properties:
        row["timestamp"] = _prop_integer(node.properties["timestamp"])
    if "value" in node.properties:
        prop = node.properties["value"]
        row["value"] = _value_summary(prop.value, prop.value_offset)
    return row


def _child_nodes(tree: _FDT, parent: str) -> list[_FDTNode]:
    prefix = parent.rstrip("/") + "/"
    depth = parent.count("/") + (0 if parent == "/" else 1)
    return [tree.nodes[path] for path in tree.order
            if path.startswith(prefix) and path.count("/") == depth]


@_fail_closed
def parse_dtb(data: bytes, offset: int = 0) -> dict:
    """Parse one DTB and summarize ordinary nodes plus overlay metadata."""
    data = _blob(data)
    tree = _parse_fdt(data, offset)
    overlay: dict = {"is_overlay": False, "fragments": [], "symbols": {},
                     "fixups": {}, "local_fixups": []}
    for node in _child_nodes(tree, "/"):
        if not node.name.startswith("fragment@"):
            continue
        overlay["is_overlay"] = True
        fragment: dict = {"node": node.path, "offset": node.offset}
        if "target" in node.properties:
            fragment["target"] = _prop_integer(node.properties["target"])
        if "target-path" in node.properties:
            fragment["target_path"] = _prop_text(node.properties["target-path"])
        overlay_path = node.path + "/__overlay__"
        fragment["overlay_node"] = overlay_path if overlay_path in tree.nodes else None
        overlay["fragments"].append(fragment)
    symbols = tree.nodes.get("/__symbols__")
    if symbols:
        overlay["is_overlay"] = True
        overlay["symbols"] = {name: _prop_text(prop)
                              for name, prop in symbols.properties.items()}
    fixups = tree.nodes.get("/__fixups__")
    if fixups:
        overlay["is_overlay"] = True
        overlay["fixups"] = {name: _prop_strings(prop)
                             for name, prop in fixups.properties.items()}
    for path in tree.order:
        if path == "/__local_fixups__" or path.startswith("/__local_fixups__/"):
            overlay["is_overlay"] = True
            node = tree.nodes[path]
            for name, prop in node.properties.items():
                if len(prop.value) % 4:
                    raise FWBootError("DT overlay local fixup is not a cell array")
                overlay["local_fixups"].append({
                    "node": path,
                    "property": name,
                    "offsets": list(struct.unpack(">" + "I" * (len(prop.value) // 4),
                                                  prop.value)) if prop.value else [],
                })

    embedded_strings = []
    for path in tree.order:
        for name, prop in tree.nodes[path].properties.items():
            values = _string_list(prop.value)
            if values is not None:
                embedded_strings.append({"node": path, "property": name,
                                         "offset": prop.value_offset, "values": values})
                if len(embedded_strings) >= MAX_EMBEDDED_STRINGS:
                    break
        if len(embedded_strings) >= MAX_EMBEDDED_STRINGS:
            break
    return {
        "kind": "dtb",
        "header": _fdt_header_report(tree),
        "node_count": len(tree.order),
        "property_count": sum(len(node.properties) for node in tree.nodes.values()),
        "nodes": [_node_report(tree.nodes[path]) for path in tree.order],
        "overlay": overlay,
        "embedded_strings": embedded_strings,
    }


_FIT_HASH_LENGTHS = {"crc16-ccitt": 2, "crc32": 4, "md5": 16,
                     "sha1": 20, "sha256": 32,
                     "sha384": 48, "sha512": 64}


def _fit_hash(algorithm: str, payload: bytes) -> bytes | None:
    if algorithm == "crc16-ccitt":
        value = 0
        for byte in payload:
            value ^= byte << 8
            for _ in range(8):
                value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else value << 1
        return struct.pack(">H", value)
    if algorithm == "crc32":
        return struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
    if algorithm in {"md5", "sha1", "sha256", "sha384", "sha512"}:
        return hashlib.new(algorithm, payload).digest()
    return None


def _fit_payload(data: bytes, tree: _FDT, node: _FDTNode) -> tuple[bytes | None, dict]:
    if "data" in node.properties:
        if any(name in node.properties for name in ("data-size", "data-offset", "data-position")):
            raise FWBootError("FIT image mixes embedded and external data properties")
        prop = node.properties["data"]
        return prop.value, {"storage": "embedded", "offset": prop.value_offset,
                            "size": len(prop.value), "end_offset": prop.value_offset + len(prop.value)}
    size = _prop_integer(node.properties.get("data-size"))
    relative = _prop_integer(node.properties.get("data-offset"))
    positioned = _prop_integer(node.properties.get("data-position"))
    if size is None and relative is None and positioned is None:
        return None, {"storage": "none"}
    if size is None or (relative is None) == (positioned is None):
        raise FWBootError("FIT external data needs size and exactly one location")
    if positioned is not None:
        start = tree.base + positioned
        storage = "external-position"
    else:
        start = tree.base + _align(tree.total_size, 4) + int(relative)
        storage = "external-offset"
    if start < 0 or size > len(data) - start:
        raise FWBootError("FIT external image data is truncated")
    if start < tree.base + tree.total_size:
        raise FWBootError("FIT external image data overlaps the FDT")
    return data[start:start + size], {"storage": storage, "offset": start,
                                     "size": size, "end_offset": start + size}


def _fit_signatures(tree: _FDT, parent: str) -> list[dict]:
    rows = []
    for child in _child_nodes(tree, parent):
        if child.name.startswith("signature"):
            rows.append(_signature_report(child))
    return rows


@_fail_closed
def parse_fit(data: bytes, offset: int = 0) -> dict:
    """Parse U-Boot FIT images, configurations, hashes, signatures and keys."""
    data = _blob(data)
    tree = _parse_fdt(data, offset)
    if "/images" not in tree.nodes:
        raise FWBootError("FDT is not a FIT: /images is absent")
    warnings: list[str] = []
    images: list[dict] = []
    image_names: set[str] = set()
    for node in _child_nodes(tree, "/images"):
        image_names.add(node.name)
        row: dict = {"name": node.name, "path": node.path, "offset": node.offset}
        for name in ("description", "type", "arch", "os", "compression"):
            if name in node.properties:
                row[name] = _prop_text(node.properties[name])
        for name in ("load", "entry"):
            if name in node.properties:
                row[name] = _prop_integer(node.properties[name])
        payload, location = _fit_payload(data, tree, node)
        row["data"] = location
        if payload is not None:
            row["data"]["sha256"] = _sha256(payload)
            row["embedded_strings"] = _ascii_strings(payload, location["offset"])
        hashes = []
        for child in _child_nodes(tree, node.path):
            if not child.name.startswith("hash"):
                continue
            algorithm = _prop_text(child.properties.get("algo"), required=True)
            expected_prop = child.properties.get("value")
            if expected_prop is None:
                raise FWBootError("FIT hash node lacks value")
            expected = expected_prop.value
            expected_size = _FIT_HASH_LENGTHS.get(algorithm)
            if expected_size is not None and len(expected) != expected_size:
                raise FWBootError("FIT hash value has the wrong size")
            calculated = _fit_hash(algorithm, payload) if payload is not None else None
            hashes.append({
                "node": child.name,
                "path": child.path,
                "offset": child.offset,
                "algorithm": algorithm,
                "expected": _value_summary(expected, expected_prop.value_offset),
                "calculated_hex": calculated.hex() if calculated is not None else None,
                "valid": calculated == expected if calculated is not None else None,
            })
            if algorithm in {"md5", "sha1"}:
                warnings.append(f"{child.path}: weak hash algorithm {algorithm}")
            if calculated is not None and calculated != expected:
                warnings.append(f"{child.path}: payload hash mismatch")
        row["hashes"] = hashes
        row["signatures"] = _fit_signatures(tree, node.path)
        images.append(row)
    if not images:
        raise FWBootError("FIT /images contains no image nodes")

    configurations: list[dict] = []
    config_root = tree.nodes.get("/configurations")
    default = _prop_text(config_root.properties.get("default")) if config_root else None
    if config_root:
        for node in _child_nodes(tree, "/configurations"):
            row: dict = {"name": node.name, "path": node.path, "offset": node.offset,
                         "default": node.name == default}
            refs: dict[str, list[str]] = {}
            for name in ("kernel", "ramdisk", "fdt", "firmware", "loadables", "script",
                         "standalone", "fpga"):
                if name in node.properties:
                    refs[name] = _prop_strings(node.properties[name])
            row["image_references"] = refs
            row["unresolved_references"] = sorted({value for values in refs.values()
                                                    for value in values if value not in image_names})
            if row["unresolved_references"]:
                warnings.append(f"{node.path}: unresolved image references")
            if "compatible" in node.properties:
                row["compatible"] = _prop_strings(node.properties["compatible"])
            row["signatures"] = _fit_signatures(tree, node.path)
            reconstructed = ["/", "/configurations", node.path, "/images"]
            for values in refs.values():
                for image_name in values:
                    image_path = "/images/" + image_name
                    if image_path not in tree.nodes:
                        continue
                    reconstructed.append(image_path)
                    for child in _child_nodes(tree, image_path):
                        if child.name.startswith(("hash", "cipher", "dm-verity")):
                            reconstructed.append(child.path)
            reconstructed = list(dict.fromkeys(reconstructed))
            for signature in row["signatures"]:
                claimed = signature.get("hashed_nodes", [])
                signature["reconstructed_coverage_nodes"] = reconstructed
                signature["coverage_missing_from_claim"] = [path for path in reconstructed
                                                              if path not in claimed]
                signature["claim_extra_nodes"] = [path for path in claimed
                                                    if path not in reconstructed]
                signature["coverage_note"] = (
                    "claimed hashed-nodes is metadata only; verifier coverage must be "
                    "rebuilt from configuration references")
                if signature["coverage_missing_from_claim"]:
                    warnings.append(f"{signature['path']}: claimed hashed-nodes omits "
                                    "reconstructed coverage")
                span = signature.get("hashed_strings")
                if span and (span[0] > tree.strings_size
                             or span[1] > tree.strings_size - span[0]):
                    warnings.append(f"{signature['path']}: hashed-strings is out of range")
            configurations.append(row)
    if default is not None and default not in {row["name"] for row in configurations}:
        raise FWBootError("FIT default configuration does not exist")

    keys: list[dict] = []
    required_mode = None
    if "/signature" in tree.nodes:
        required_mode = _prop_text(tree.nodes["/signature"].properties.get("required-mode"))
        if required_mode not in (None, "any", "all"):
            warnings.append("/signature: unknown required-mode")
        for node in _child_nodes(tree, "/signature"):
            row: dict = {"name": node.name, "path": node.path, "offset": node.offset,
                         "trust": "metadata-only; trusted only when supplied by the control FDT"}
            for name in ("algo", "key-name-hint", "required", "ecdsa,curve"):
                if name in node.properties:
                    row[name.replace(",", "_").replace("-", "_")] = _prop_text(node.properties[name])
            if "rsa,num-bits" in node.properties:
                row["rsa_num_bits"] = _prop_integer(node.properties["rsa,num-bits"])
            for name in ("rsa,modulus", "rsa,exponent", "rsa,r-squared", "rsa,n0-inverse",
                         "ecdsa,x-point", "ecdsa,y-point"):
                if name in node.properties:
                    prop = node.properties[name]
                    row[name.replace(",", "_").replace("-", "_")] = _value_summary(
                        prop.value, prop.value_offset)
            keys.append(row)

    return {
        "kind": "fit",
        "header": _fdt_header_report(tree),
        "description": _prop_text(tree.nodes["/"].properties.get("description")),
        "timestamp": _prop_integer(tree.nodes["/"].properties.get("timestamp")),
        "images": images,
        "configurations": configurations,
        "default_configuration": default,
        "keys": keys,
        "key_required_mode": required_mode,
        "warnings": warnings,
        "node_count": len(tree.order),
        "property_count": sum(len(node.properties) for node in tree.nodes.values()),
    }


# ---- UEFI capsule / PI firmware volume ---------------------------------------------------------

CAPSULE_FLAGS_PERSIST_ACROSS_RESET = 0x00010000
CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE = 0x00020000
CAPSULE_FLAGS_INITIATE_RESET = 0x00040000

_FFS_FILE_TYPES = {
    0x01: "raw", 0x02: "freeform", 0x03: "security-core", 0x04: "pei-core",
    0x05: "dxe-core", 0x06: "peim", 0x07: "driver", 0x08: "combined-peim-driver",
    0x09: "application", 0x0A: "smm", 0x0B: "firmware-volume-image",
    0x0C: "combined-smm-dxe", 0x0D: "smm-core", 0x0E: "mm-standalone",
    0x0F: "mm-core-standalone", 0xF0: "pad",
}

_SECTION_TYPES = {
    0x01: "compression", 0x02: "guid-defined", 0x03: "disposable",
    0x10: "pe32", 0x11: "pic", 0x12: "te", 0x13: "dxe-depex",
    0x14: "version", 0x15: "user-interface", 0x16: "compatibility16",
    0x17: "firmware-volume-image", 0x18: "freeform-subtype-guid",
    0x19: "raw", 0x1B: "pei-depex", 0x1C: "smm-depex",
}

_FFS2_GUID = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
_FFS3_GUID = "5473c07a-3dcb-4dca-bd6f-1e9689e7349a"


def _utf16z(value: bytes) -> str | None:
    if len(value) < 2 or len(value) % 2 or value[-2:] != b"\0\0":
        return None
    try:
        return value[:-2].decode("utf-16-le")
    except UnicodeError:
        return None


def _parse_section(data: bytes, section_start: int, file_end: int,
                   *, large_file: bool) -> tuple[dict, int]:
    if section_start + 4 > file_end:
        raise FWBootError("UEFI section header is truncated")
    size24 = _u24le(data[section_start:section_start + 3])
    section_type = data[section_start + 3]
    header_size = 4
    if size24 == 0xFFFFFF:
        if not large_file or section_start + 8 > file_end:
            raise FWBootError("extended UEFI section is invalid for this file")
        section_size = struct.unpack_from("<I", data, section_start + 4)[0]
        header_size = 8
        if section_size <= 0xFFFFFF:
            raise FWBootError("extended UEFI section does not require extended size")
    else:
        section_size = size24
    if section_size < header_size or section_size > file_end - section_start:
        raise FWBootError("UEFI section size exceeds its file")
    payload_start = section_start + header_size
    section_end = section_start + section_size
    payload = data[payload_start:section_end]
    row: dict = {
        "offset": section_start,
        "size": section_size,
        "end_offset": section_end,
        "header_size": header_size,
        "type_id": section_type,
        "type": _SECTION_TYPES.get(section_type, f"unknown-0x{section_type:02x}"),
        "sha256": _sha256(data[section_start:section_end]),
        "payload_sha256": _sha256(payload),
        "embedded_strings": _ascii_strings(payload, payload_start),
    }
    if section_type == 0x01:
        if len(payload) < 5:
            raise FWBootError("UEFI compression section header is truncated")
        row["uncompressed_size"] = struct.unpack_from("<I", payload)[0]
        row["compression_type"] = payload[4]
        row["data_offset"] = payload_start + 5
    elif section_type == 0x02:
        if len(payload) < 20:
            raise FWBootError("UEFI GUID-defined section header is truncated")
        data_offset, attributes = struct.unpack_from("<HH", payload, 16)
        if data_offset < header_size + 20 or data_offset > section_size:
            raise FWBootError("UEFI GUID-defined data offset is invalid")
        row["definition_guid"] = _guid(payload[:16])
        row["data_offset"] = section_start + data_offset
        row["attributes"] = attributes
    elif section_type == 0x18:
        if len(payload) < 16:
            raise FWBootError("UEFI freeform GUID section is truncated")
        row["subtype_guid"] = _guid(payload[:16])
        row["data_offset"] = payload_start + 16
    elif section_type == 0x14:
        if len(payload) >= 2:
            row["build_number"] = struct.unpack_from("<H", payload)[0]
            text = _utf16z(payload[2:])
            if text is not None:
                row["version_string"] = text
    elif section_type == 0x15:
        text = _utf16z(payload)
        if text is not None:
            row["user_interface"] = text
    return row, section_end


def _parse_ffs_file(data: bytes, file_start: int, volume_end: int,
                    erased: int, file_system_guid: str) -> tuple[dict, int]:
    if file_start + 24 > volume_end:
        raise FWBootError("UEFI FFS header is truncated")
    raw24 = data[file_start:file_start + 24]
    if raw24 == bytes([erased]) * 24:
        raise FWBootError("erased FFS header is not a file")
    file_guid = _guid(raw24[:16])
    header_checksum, file_checksum, file_type, attributes = raw24[16:20]
    size24 = _u24le(raw24[20:23])
    state = raw24[23]
    large = bool(attributes & 0x01)
    header_size = 32 if large else 24
    if large:
        if (file_system_guid != _FFS3_GUID or size24 != 0
                or file_start + 32 > volume_end):
            raise FWBootError("large FFS file header is malformed")
        file_size = struct.unpack_from("<Q", data, file_start + 24)[0]
        if file_size <= 0xFFFFFF:
            raise FWBootError("large FFS file does not require extended size")
    else:
        file_size = size24
    if file_size < header_size or file_size > volume_end - file_start:
        raise FWBootError("FFS file size exceeds the firmware volume")
    header = bytearray(data[file_start:file_start + header_size])
    header[17] = 0
    header[23] = 0
    header_checksum_ok = sum(header) & 0xFF == 0
    payload_start = file_start + header_size
    file_end = file_start + file_size
    payload = data[payload_start:file_end]
    if attributes & 0x40:
        file_checksum_ok = (sum(payload) + file_checksum) & 0xFF == 0
    else:
        file_checksum_ok = file_checksum == 0xAA
    row: dict = {
        "offset": file_start,
        "size": file_size,
        "end_offset": file_end,
        "header_size": header_size,
        "name_guid": file_guid,
        "type_id": file_type,
        "type": _FFS_FILE_TYPES.get(file_type, f"unknown-0x{file_type:02x}"),
        "attributes": attributes,
        "state": state,
        "logical_state": (~state & 0xFF) if erased == 0xFF else state,
        "header_checksum": header_checksum,
        "header_checksum_ok": header_checksum_ok,
        "file_checksum": file_checksum,
        "file_checksum_ok": file_checksum_ok,
        "sha256": _sha256(data[file_start:file_end]),
        "payload_sha256": _sha256(payload),
        "sections": [],
        "embedded_strings": _ascii_strings(payload, payload_start),
    }
    if file_type not in (0x01, 0xF0) and payload:
        cursor = payload_start
        section_count = 0
        while cursor < file_end:
            # Section padding is relative to the FFS file and uses zero bytes.
            relative = cursor - file_start
            aligned = file_start + _align(relative, 4)
            if any(data[cursor:aligned]):
                raise FWBootError("non-zero UEFI section alignment padding")
            cursor = aligned
            if cursor == file_end:
                break
            section, section_end = _parse_section(data, cursor, file_end, large_file=large)
            row["sections"].append(section)
            section_count += 1
            if section_count > MAX_FV_SECTIONS:
                raise FWBootError("UEFI section cap exceeded")
            cursor = section_end
    return row, file_end


def _parse_firmware_volume(data: bytes, offset: int) -> dict:
    _offset(data, offset, 64, "firmware volume")
    if data[offset + 40:offset + 44] != b"_FVH":
        raise FWBootError("UEFI firmware-volume signature is absent")
    file_system_guid = _guid(data[offset + 16:offset + 32])
    fv_length = struct.unpack_from("<Q", data, offset + 32)[0]
    attributes = struct.unpack_from("<I", data, offset + 44)[0]
    header_length, checksum, ext_offset = struct.unpack_from("<HHH", data, offset + 48)
    reserved, revision = data[offset + 54:offset + 56]
    if (revision != 2 or reserved != 0 or header_length < 64
            or header_length % 2 or fv_length < header_length
            or fv_length > MAX_INPUT or fv_length > len(data) - offset):
        raise FWBootError("UEFI firmware-volume header geometry is invalid")
    header = data[offset:offset + header_length]
    if sum(struct.unpack("<" + "H" * (header_length // 2), header)) & 0xFFFF:
        raise FWBootError("UEFI firmware-volume header checksum is invalid")
    block_map = []
    block_cursor = offset + 56
    while block_cursor + 8 <= offset + header_length:
        count, block_length = struct.unpack_from("<II", data, block_cursor)
        if count == block_length == 0:
            block_cursor += 8
            break
        if not count or not block_length or count > fv_length // block_length:
            raise FWBootError("UEFI firmware-volume block map is invalid")
        block_map.append({"offset": block_cursor, "count": count,
                          "block_length": block_length,
                          "total_length": count * block_length})
        block_cursor += 8
        if len(block_map) > 1024:
            raise FWBootError("UEFI firmware-volume block-map cap exceeded")
    else:
        raise FWBootError("UEFI firmware-volume block map lacks a terminator")
    if sum(entry["total_length"] for entry in block_map) != fv_length:
        raise FWBootError("UEFI firmware-volume block map does not cover the volume")

    ext_header = None
    ext_end = offset + header_length
    if ext_offset:
        ext_start = offset + ext_offset
        if ext_offset % 4 or ext_start + 20 > offset + fv_length:
            raise FWBootError("UEFI FV extension header offset is invalid")
        ext_size = struct.unpack_from("<I", data, ext_start + 16)[0]
        if ext_size < 20 or ext_size > offset + fv_length - ext_start:
            raise FWBootError("UEFI FV extension header size is invalid")
        entries = []
        cursor = ext_start + 20
        while cursor < ext_start + ext_size:
            if cursor + 4 > ext_start + ext_size:
                raise FWBootError("UEFI FV extension entry is truncated")
            entry_size, entry_type = struct.unpack_from("<HH", data, cursor)
            if entry_size < 4 or entry_size > ext_start + ext_size - cursor:
                raise FWBootError("UEFI FV extension entry size is invalid")
            entries.append({"offset": cursor, "size": entry_size, "type": entry_type,
                            "sha256": _sha256(data[cursor:cursor + entry_size])})
            cursor += entry_size
            if len(entries) > 1024:
                raise FWBootError("UEFI FV extension-entry cap exceeded")
        ext_header = {"offset": ext_start, "size": ext_size,
                      "name_guid": _guid(data[ext_start:ext_start + 16]),
                      "entries": entries}
        ext_end = max(ext_end, ext_start + ext_size)

    volume_end = offset + fv_length
    erased = 0xFF if attributes & 0x00000800 else 0x00
    cursor = offset + _align(ext_end - offset, 8)
    files = []
    supported_ffs = file_system_guid in {_FFS2_GUID, _FFS3_GUID}
    while supported_ffs and cursor + 24 <= volume_end:
        aligned = offset + _align(cursor - offset, 8)
        padding = data[cursor:aligned]
        if any(byte != erased for byte in padding):
            raise FWBootError("FFS alignment padding is not erased")
        cursor = aligned
        if cursor + 24 > volume_end:
            break
        if data[cursor:cursor + 24] == bytes([erased]) * 24:
            if any(byte != erased for byte in data[cursor:volume_end]):
                raise FWBootError("non-erased bytes follow free FV space")
            break
        file_row, file_end = _parse_ffs_file(data, cursor, volume_end, erased,
                                             file_system_guid)
        files.append(file_row)
        if len(files) > MAX_FV_FILES:
            raise FWBootError("UEFI FFS file cap exceeded")
        cursor = file_end
    if supported_ffs and any(byte != erased for byte in data[cursor:volume_end]):
        raise FWBootError("non-erased trailing bytes remain in the firmware volume")
    return {
        "kind": "uefi-firmware-volume",
        "offset": offset,
        "size": fv_length,
        "end_offset": volume_end,
        "sha256": _sha256(data[offset:volume_end]),
        "file_system_guid": file_system_guid,
        "file_system_supported": supported_ffs,
        "attributes": attributes,
        "revision": revision,
        "header_length": header_length,
        "header_checksum": checksum,
        "header_checksum_ok": True,
        "erase_polarity": 1 if erased == 0xFF else 0,
        "block_map": block_map,
        "extension_header": ext_header,
        "files": files,
        "file_count": len(files),
    }


@_fail_closed
def parse_firmware_volume(data: bytes, offset: int = 0) -> dict:
    """Parse a PI firmware volume, its FFS files, and section inventory."""
    data = _blob(data)
    return _parse_firmware_volume(data, offset)


@_fail_closed
def parse_uefi_capsule(data: bytes, offset: int = 0) -> dict:
    """Parse an EFI_CAPSULE_HEADER and locate complete PI firmware volumes."""
    data = _blob(data)
    _offset(data, offset, 28, "UEFI capsule")
    capsule_guid = _guid(data[offset:offset + 16])
    header_size, flags, image_size = struct.unpack_from("<III", data, offset + 16)
    if (header_size < 28 or header_size > image_size or image_size > MAX_INPUT
            or image_size > len(data) - offset):
        raise FWBootError("UEFI capsule size fields are invalid")
    if (flags & CAPSULE_FLAGS_INITIATE_RESET
            and not flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET):
        raise FWBootError("UEFI capsule INITIATE_RESET requires PERSIST_ACROSS_RESET")
    if (flags & CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE
            and not flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET):
        raise FWBootError("UEFI capsule POPULATE_SYSTEM_TABLE requires PERSIST_ACROSS_RESET")
    if flags & 0xFFF80000:
        raise FWBootError("UEFI capsule has reserved flag bits set")
    capsule_end = offset + image_size
    payload_start = offset + header_size
    volumes = []
    cursor = payload_start
    candidates = 0
    while True:
        signature = data.find(b"_FVH", cursor + 40, capsule_end)
        if signature < 0:
            break
        candidate = signature - 40
        cursor = signature + 4
        candidates += 1
        if candidates > MAX_FV_FILES:
            raise FWBootError("UEFI capsule FV candidate cap exceeded")
        try:
            volume = _parse_firmware_volume(data, candidate)
        except FWBootError:
            continue
        if volume["end_offset"] <= capsule_end:
            volumes.append(volume)
            cursor = volume["end_offset"]
    payload = data[payload_start:capsule_end]
    return {
        "kind": "uefi-capsule",
        "offset": offset,
        "size": image_size,
        "end_offset": capsule_end,
        "sha256": _sha256(data[offset:capsule_end]),
        "capsule_guid": capsule_guid,
        "header_size": header_size,
        "flags": flags,
        "flag_names": [name for bit, name in (
            (CAPSULE_FLAGS_PERSIST_ACROSS_RESET, "persist-across-reset"),
            (CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE, "populate-system-table"),
            (CAPSULE_FLAGS_INITIATE_RESET, "initiate-reset"),
        ) if flags & bit],
        "vendor_flags": flags & 0xFFFF,
        "extended_header_sha256": _sha256(data[offset + 28:payload_start]),
        "payload_offset": payload_start,
        "payload_size": len(payload),
        "payload_sha256": _sha256(payload),
        "embedded_strings": _ascii_strings(payload, payload_start),
        "firmware_volumes": volumes,
    }


# ---- coreboot CBFS ------------------------------------------------------------------------------

_CBFS_TYPES = {
    0x00000000: "deleted", 0xFFFFFFFF: "null", 0x01: "bootblock",
    0x02: "cbfs-header", 0x10: "legacy-stage", 0x11: "stage", 0x20: "self",
    0x21: "fit-payload", 0x30: "option-rom", 0x40: "bootsplash", 0x50: "raw",
    0x51: "vsa", 0x52: "mbi", 0x53: "microcode", 0x54: "intel-fit",
    0x60: "fsp", 0x61: "mrc", 0x62: "mma", 0x63: "efi", 0x70: "struct",
    0x80: "amd-firmware", 0xAA: "cmos-default", 0xAB: "spd",
    0xAC: "mrc-cache", 0x01AA: "cmos-layout",
}

_CBFS_ATTRS = {
    0x42435A4C: "compression", 0x68736148: "hash", 0x42435350: "position",
    0x42434C41: "alignment", 0x32494242: "ibb", 0x47444150: "padding",
    0x53746748: "stage-header",
}

_CBFS_COMPRESSION = {0: "none", 1: "lzma", 2: "lz4", 3: "zstd"}
_VB2_HASHES = {
    1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha512", 64),
    4: ("sha224", 28), 5: ("sha384", 48),
}

_CBFS_ARCHITECTURES = {
    0xFFFFFFFF: "unknown", 0x00000001: "x86", 0x00000010: "arm",
    0x0000AA64: "aarch64", 0x00000100: "mips",
    0xC001D0DE: "riscv", 0x407570FF: "ppc64",
}


def _legacy_cbfs_header(data: bytes, region_start: int, region_end: int) -> dict | None:
    if region_end - region_start < 36:
        return None
    relative = struct.unpack_from("<i", data, region_end - 4)[0]
    header_start = region_end + relative
    if header_start < region_start or header_start + 32 > region_end:
        return None
    fields = struct.unpack_from(">8I", data, header_start)
    magic, version, rom_size, bootblock_size, alignment, first_file, architecture, pad = fields
    if magic != 0x4F524243:
        return None
    if (version not in (0x31313131, 0x31313132) or alignment != 64
            or not 32 <= rom_size <= region_end - region_start
            or first_file >= rom_size or bootblock_size > rom_size):
        raise FWBootError("legacy CBFS master header is invalid")
    return {
        "offset": header_start,
        "version": bytes.fromhex(f"{version:08x}").decode("ascii"),
        "rom_size": rom_size,
        "bootblock_size": bootblock_size,
        "alignment": alignment,
        "first_file_offset": region_start + first_file,
        "architecture_id": architecture,
        "architecture": _CBFS_ARCHITECTURES.get(architecture,
                                                  f"unknown-0x{architecture:08x}"),
        "padding": pad,
        "tail_pointer_offset": region_end - 4,
        "tail_relative_pointer": relative,
    }


def _parse_cbfs_attributes(metadata: bytes, metadata_base: int, start: int, end: int,
                           payload: bytes) -> list[dict]:
    cursor = start
    rows = []
    while cursor < end:
        remainder = metadata[cursor:end]
        if remainder and (all(byte == 0 for byte in remainder)
                          or all(byte == 0xFF for byte in remainder)):
            break
        if end - cursor < 8:
            raise FWBootError("CBFS attribute header is truncated")
        tag, attr_size = struct.unpack_from(">II", metadata, cursor)
        if tag in (0, 0xFFFFFFFF):
            if not (all(byte == 0 for byte in remainder)
                    or all(byte == 0xFF for byte in remainder)):
                raise FWBootError("CBFS unused attribute has non-padding data")
            break
        if attr_size < 8 or attr_size % 4 or attr_size > end - cursor:
            raise FWBootError("CBFS attribute size is invalid")
        raw = metadata[cursor:cursor + attr_size]
        kind = _CBFS_ATTRS.get(tag, f"unknown-0x{tag:08x}")
        row: dict = {"offset": metadata_base + cursor, "size": attr_size,
                     "tag": f"0x{tag:08x}", "kind": kind,
                     "sha256": _sha256(raw)}
        if tag == 0x42435A4C:
            if attr_size != 16:
                raise FWBootError("CBFS compression attribute has the wrong size")
            algorithm, decompressed_size = struct.unpack_from(">II", raw, 8)
            row.update(algorithm_id=algorithm,
                       algorithm=_CBFS_COMPRESSION.get(algorithm, f"unknown-{algorithm}"),
                       decompressed_size=decompressed_size)
        elif tag == 0x68736148:
            if attr_size < 12:
                raise FWBootError("CBFS hash attribute is truncated")
            algorithm = struct.unpack_from(">I", raw, 8)[0]
            digest = raw[12:]
            known = _VB2_HASHES.get(algorithm)
            if known and len(digest) != known[1]:
                raise FWBootError("CBFS hash attribute digest size is invalid")
            calculated = hashlib.new(known[0], payload).digest() if known else None
            row.update(algorithm_id=algorithm,
                       algorithm=known[0] if known else f"unknown-{algorithm}",
                       digest_hex=digest.hex(),
                       calculated_hex=calculated.hex() if calculated is not None else None,
                       valid=calculated == digest if calculated is not None else None)
        elif tag in (0x42435350, 0x42434C41):
            if attr_size != 12:
                raise FWBootError("CBFS position/alignment attribute has the wrong size")
            row["value"] = struct.unpack_from(">I", raw, 8)[0]
        elif tag == 0x53746748:
            if attr_size != 24:
                raise FWBootError("CBFS stage-header attribute has the wrong size")
            load_address, entry_offset, memory_size = struct.unpack_from(">QII", raw, 8)
            row.update(load_address=load_address, entry_offset=entry_offset,
                       entry_address=load_address + entry_offset, memory_size=memory_size)
        rows.append(row)
        cursor += attr_size
        if len(rows) > MAX_CBFS_ATTRIBUTES:
            raise FWBootError("CBFS attribute cap exceeded")
    return rows


@_fail_closed
def parse_cbfs(data: bytes, offset: int = 0, length: int | None = None) -> dict:
    """Walk one CBFS region without decompressing any file data."""
    data = _blob(data)
    _offset(data, offset, 0, "CBFS")
    region_length = _length(data, offset, length, "CBFS")
    if region_length < 24:
        raise FWBootError("CBFS region is too short")
    region_end = offset + region_length
    legacy_header = _legacy_cbfs_header(data, offset, region_end)
    cursor = offset
    files = []
    while cursor + 24 <= region_end:
        relative = cursor - offset
        if relative % 64:
            cursor = offset + _align(relative, 64)
            continue
        if data[cursor:cursor + 8] != b"LARCHIVE":
            cursor += 64
            continue
        data_length, file_type, attributes_offset, data_offset = struct.unpack_from(
            ">IIII", data, cursor + 8)
        if data_offset < 25 or data_offset > 256 or data_offset > region_end - cursor:
            raise FWBootError("CBFS metadata/data offset is invalid")
        metadata = data[cursor:cursor + data_offset]
        filename_end = metadata.find(b"\0", 24)
        if filename_end < 24:
            raise FWBootError("CBFS filename is unterminated")
        try:
            filename = metadata[24:filename_end].decode("utf-8")
        except UnicodeError as exc:
            raise FWBootError("CBFS filename is not UTF-8") from exc
        if not filename or len(filename.encode("utf-8")) > MAX_STRING_LENGTH:
            raise FWBootError("CBFS filename is empty or too long")
        if data_length > region_end - (cursor + data_offset):
            raise FWBootError("CBFS file data is truncated")
        payload_start = cursor + data_offset
        payload_end = payload_start + data_length
        payload = data[payload_start:payload_end]
        if attributes_offset:
            if not filename_end + 1 <= attributes_offset <= data_offset:
                raise FWBootError("CBFS attributes offset overlaps the filename")
            attributes = _parse_cbfs_attributes(metadata, cursor, attributes_offset,
                                                 data_offset, payload)
        else:
            attributes = []
        row = {
            "name": filename,
            "offset": cursor,
            "metadata_size": data_offset,
            "data_offset": payload_start,
            "data_size": data_length,
            "end_offset": payload_end,
            "type_id": file_type,
            "type": _CBFS_TYPES.get(file_type, f"unknown-0x{file_type:08x}"),
            "sha256": _sha256(payload),
            "attributes": attributes,
            "embedded_strings": _ascii_strings(payload, payload_start),
        }
        files.append(row)
        if len(files) > MAX_CBFS_FILES:
            raise FWBootError("CBFS file cap exceeded")
        cursor = offset + _align(payload_end - offset, 64)
    if not files:
        raise FWBootError("CBFS region contains no valid LARCHIVE file")
    return {
        "kind": "cbfs",
        "offset": offset,
        "size": region_length,
        "end_offset": region_end,
        "sha256": _sha256(data[offset:region_end]),
        "alignment": 64,
        "legacy_master_header": legacy_header,
        "files": files,
        "file_count": len(files),
    }


# ---- dispatcher / CLI --------------------------------------------------------------------------

@_fail_closed
def parse_boot(data: bytes, format: str = "auto", offset: int = 0,
               length: int | None = None) -> dict:
    """Dispatch to a specific boot-format parser; capsule requires an explicit format."""
    data = _blob(data)
    if not isinstance(format, str):
        raise FWBootError("format must be text")
    format = format.lower()
    if format == "fit":
        return parse_fit(data, offset)
    if format == "dtb":
        return parse_dtb(data, offset)
    if format == "capsule":
        return parse_uefi_capsule(data, offset)
    if format == "fv":
        return parse_firmware_volume(data, offset)
    if format == "cbfs":
        return parse_cbfs(data, offset, length)
    if format != "auto":
        raise FWBootError("unknown boot format")
    _offset(data, offset, 0, "boot container")
    if data[offset:offset + 4] == struct.pack(">I", FDT_MAGIC):
        try:
            return parse_fit(data, offset)
        except FWBootError as fit_error:
            try:
                return parse_dtb(data, offset)
            except FWBootError:
                raise fit_error
    if data[offset + 40:offset + 44] == b"_FVH":
        return parse_firmware_volume(data, offset)
    region_length = _length(data, offset, length, "boot container")
    region = data[offset:offset + region_length]
    if any(region[index:index + 8] == b"LARCHIVE"
           for index in range(0, max(0, len(region) - 7), 64)):
        return parse_cbfs(data, offset, region_length)
    raise FWBootError("format cannot be identified; capsules require --format capsule")


def _parse_number(text: str) -> int:
    try:
        value = int(text, 0)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="offline FIT/DTB, UEFI capsule/FV/FFS, and CBFS inventory")
    parser.add_argument("input", help="firmware artifact")
    parser.add_argument("--format", choices=("auto", "fit", "dtb", "capsule", "fv", "cbfs"),
                        default="auto")
    parser.add_argument("--offset", type=_parse_number, default=0)
    parser.add_argument("--length", type=_parse_number)
    parser.add_argument("--compact", action="store_true")
    if argv is not None and not all(isinstance(item, str) for item in argv):
        parser.print_usage(sys.stderr)
        print("fwboot_inventory: argv elements must be strings", file=sys.stderr)
        return 2
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.input)
        with path.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise FWBootError("input exceeds the 128 MiB cap")
        report = parse_boot(data, args.format, args.offset, args.length)
    except (FWBootError, OSError) as exc:
        print(f"fwboot_inventory: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=None if args.compact else 2,
                     separators=(",", ":") if args.compact else None,
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
