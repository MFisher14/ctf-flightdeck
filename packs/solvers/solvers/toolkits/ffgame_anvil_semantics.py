#!/usr/bin/env python3
"""Bounded semantic inspection of Minecraft Anvil chunks; never loads a world.

``research_ff_nbt`` owns the byte-level NBT and ``.mca`` parsing.  This module
deliberately extends that baseline with version-aware chunk semantics: legacy
``Level`` wrappers, modern roots, sections and palettes, entities, coordinates,
and path-aware string/flag evidence.  External ``.mcc`` references are reported
by the baseline and are never opened here.

Format references:

* https://minecraft.wiki/w/Region_file_format
* https://minecraft.wiki/w/Chunk_format
* https://minecraft.wiki/w/Anvil_file_format
* https://github.com/PaperMC/SectorTool/blob/master/SPECIFICATION.MD

Every public boundary raises only :class:`FFGameAnvilError` on invalid input.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import research_ff_nbt as _nbt


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = _nbt.MAX_REGION_INPUT
MAX_VISITED_NODES = min(_nbt.MAX_REGION_TOTAL_TAGS, 250_000)
MAX_EVIDENCE = 4096
MAX_EVIDENCE_CHARS = 1 << 20
MAX_BYTE_SCAN = 1 << 20
MAX_FLAGS = 256
MAX_PATH_CHARS = 512
MAX_PALETTE_IDS = 4096
MAX_ENTITY_IDS = 4096
MAX_REGION_SECTIONS = 8192
MAX_REGION_EVIDENCE = 16384
MAX_REGION_PALETTE_IDS = 16384
MAX_REGION_ENTITY_IDS = 16384
MAX_REGION_FLAGS = 4096

_FLAG_TEXT = flagfmt.TEXT
_PRINTABLE_BYTES = re.compile(rb"[ -~]{4,}")


class FFGameAnvilError(ValueError):
    """Malformed, unsupported, or over-limit Anvil semantic input."""


def _fail(message: str) -> FFGameAnvilError:
    return FFGameAnvilError(message)


def _bounded_bytes(data: object) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _fail("Anvil input must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
    except Exception as exc:
        raise _fail("Anvil input size is unavailable") from exc
    if size > MAX_INPUT:
        raise _fail(f"Anvil input exceeds {MAX_INPUT} byte cap")
    try:
        raw = bytes(data)
    except Exception as exc:
        raise _fail("Anvil input could not be copied safely") from exc
    if len(raw) != size:
        raise _fail("Anvil input size changed while copied")
    return raw


def _path_child(path: str, name: object) -> str:
    text = str(name)
    if len(text) > 80:
        text = text[:77] + "..."
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*", text):
        text = "[" + json.dumps(text, ensure_ascii=True) + "]"
    elif path != "$":
        text = "." + text
    else:
        text = "." + text
    result = path + text
    if len(result) > MAX_PATH_CHARS:
        result = result[:MAX_PATH_CHARS - 3] + "..."
    return result


def _compound_children(node: object) -> list[Any]:
    if not isinstance(node, dict) or node.get("type") != "compound":
        return []
    value = node.get("value")
    if not isinstance(value, list):
        return []
    return value


def _compound_map(node: object) -> tuple[dict[str, dict[str, Any]], list[str]]:
    mapping: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for child in _compound_children(node):
        if not isinstance(child, dict):
            continue
        name = child.get("name")
        if not isinstance(name, str):
            continue
        if name in mapping:
            if name not in duplicates:
                duplicates.append(name)
            continue
        mapping[name] = child
    return mapping, duplicates


def _list_items(node: object) -> list[Any]:
    if not isinstance(node, dict) or node.get("type") != "list":
        return []
    value = node.get("value")
    if not isinstance(value, dict):
        return []
    items = value.get("items")
    if not isinstance(items, list):
        return []
    return items


def _integer(node: object) -> int | None:
    if not isinstance(node, dict) or node.get("type") not in {"byte", "short", "int", "long"}:
        return None
    value = node.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _string(node: object) -> str | None:
    if not isinstance(node, dict) or node.get("type") != "string":
        return None
    value = node.get("value")
    return value if isinstance(value, str) else None


def _array_length(node: object, expected_type: str) -> int | None:
    if not isinstance(node, dict) or node.get("type") != expected_type:
        return None
    value = node.get("value")
    if expected_type == "byte_array" and isinstance(value, dict):
        length = value.get("length")
        return length if isinstance(length, int) and length >= 0 else None
    if expected_type in {"int_array", "long_array"} and isinstance(value, list):
        return len(value)
    return None


def _position_coordinates(node: object) -> tuple[int, int] | None:
    if not isinstance(node, dict) or node.get("type") != "int_array":
        return None
    value = node.get("value")
    if (not isinstance(value, list) or len(value) != 2
            or any(not isinstance(item, int) or isinstance(item, bool) for item in value)):
        return None
    return value[0], value[1]


def _flag_values(text: str) -> list[str]:
    return _FLAG_TEXT.findall(text)


def _walk_evidence(root: dict[str, Any], budget: dict[str, int]) -> dict[str, Any]:
    stack: list[tuple[dict[str, Any], str]] = [(root, "$")]
    evidence: list[dict[str, Any]] = []
    flags: set[str] = set()
    visited = 0
    scanned_bytes = 0
    emitted_chars = 0
    truncated = False
    flags_truncated = False

    def emit(path: str, text: str, source: str) -> None:
        nonlocal emitted_chars, truncated, flags_truncated
        for flag in _flag_values(text):
            if flag in flags:
                continue
            if len(flags) < MAX_FLAGS and budget["flags"] > 0:
                flags.add(flag)
                budget["flags"] -= 1
            else:
                flags_truncated = True
        if (len(evidence) >= MAX_EVIDENCE or emitted_chars >= MAX_EVIDENCE_CHARS
                or budget["evidence"] <= 0):
            truncated = True
            return
        allowance = min(4096, MAX_EVIDENCE_CHARS - emitted_chars)
        if allowance <= 0:
            truncated = True
            return
        shown = text[:allowance]
        evidence.append({"path": path, "source": source, "text": shown,
                         "truncated": len(shown) != len(text)})
        budget["evidence"] -= 1
        emitted_chars += len(shown)
        if len(shown) != len(text):
            truncated = True

    while stack:
        if visited >= MAX_VISITED_NODES:
            truncated = True
            break
        node, path = stack.pop()
        visited += 1
        node_type = node.get("type")
        value = node.get("value")
        if node_type == "string" and isinstance(value, str):
            emit(path, value, "tag_string")
        elif node_type == "byte_array" and isinstance(value, dict):
            encoded = value.get("hex")
            if isinstance(encoded, str) and scanned_bytes < MAX_BYTE_SCAN:
                take = min(len(encoded) // 2, MAX_BYTE_SCAN - scanned_bytes)
                try:
                    raw = bytes.fromhex(encoded[:take * 2])
                except (ValueError, MemoryError):
                    raw = b""
                    truncated = True
                scanned_bytes += len(raw)
                for match in _PRINTABLE_BYTES.finditer(raw):
                    emit(f"{path}@+{match.start()}", match.group().decode("ascii"),
                         "byte_array_ascii")
                if take * 2 < len(encoded):
                    truncated = True
        elif node_type == "compound" and isinstance(value, list):
            allowance = max(0, MAX_VISITED_NODES - visited - len(stack))
            children = []
            for child in value:
                if not isinstance(child, dict):
                    continue
                if len(children) >= allowance:
                    truncated = True
                    break
                children.append(child)
            for child in reversed(children):
                stack.append((child, _path_child(path, child.get("name", "?"))))
        elif node_type == "list" and isinstance(value, dict):
            items = value.get("items")
            if isinstance(items, list):
                allowance = max(0, MAX_VISITED_NODES - visited - len(stack))
                children = []
                for index, child in enumerate(items):
                    if not isinstance(child, dict):
                        continue
                    if len(children) >= allowance:
                        truncated = True
                        break
                    children.append((index, child))
                for index, child in reversed(children):
                    child_path = f"{path}[{index}]"
                    if len(child_path) > MAX_PATH_CHARS:
                        child_path = child_path[:MAX_PATH_CHARS - 3] + "..."
                    stack.append((child, child_path))

    return {"strings": evidence, "flags": sorted(flags),
            "flags_truncated": flags_truncated, "nodes_visited": visited,
            "byte_array_bytes_scanned": scanned_bytes, "truncated": truncated}


def _palette(section_map: dict[str, dict[str, Any]], budget: dict[str, int]
             ) -> tuple[list[str], int, int | None, bool, bool]:
    palette_node = section_map.get("Palette")
    data_node = section_map.get("BlockStates")
    block_states = section_map.get("block_states")
    if block_states is not None:
        block_map, _ = _compound_map(block_states)
        palette_node = block_map.get("palette", palette_node)
        data_node = block_map.get("data", data_node)

    items = _list_items(palette_node)
    ids: list[str] = []
    ids_truncated = False
    scan_truncated = len(items) > MAX_PALETTE_IDS
    for item in items[:MAX_PALETTE_IDS]:
        resource = _string(item)
        if resource is None:
            fields, _ = _compound_map(item)
            resource = _string(fields.get("id")) or _string(fields.get("Name"))
        if resource is not None and resource not in ids:
            if len(ids) < MAX_PALETTE_IDS and budget["palette_ids"] > 0:
                ids.append(resource)
                budget["palette_ids"] -= 1
            else:
                ids_truncated = True
    return (ids, len(items), _array_length(data_node, "long_array"),
            ids_truncated, scan_truncated)


def _section_summary(node: object, index: int,
                     budget: dict[str, int]) -> dict[str, Any]:
    fields, duplicates = _compound_map(node)
    (palette_ids, palette_size, data_longs, palette_ids_truncated,
     palette_scan_truncated) = _palette(fields, budget)
    arrays = {}
    for key in ("Blocks", "Data", "Add", "BlockLight", "SkyLight"):
        length = _array_length(fields.get(key), "byte_array")
        if length is not None:
            arrays[key] = length
    return {"index": index, "y": _integer(fields.get("Y")),
            "palette_size": palette_size, "palette_ids": palette_ids,
            "palette_ids_truncated": palette_ids_truncated,
            "palette_scan_truncated": palette_scan_truncated,
            "block_state_longs": data_longs, "legacy_byte_arrays": arrays,
            "duplicate_fields": duplicates}


def _entity_summary(node: object, budget: dict[str, int]) -> dict[str, Any]:
    items = _list_items(node)
    ids: list[str] = []
    malformed = 0
    ids_truncated = False
    scan_truncated = len(items) > MAX_ENTITY_IDS
    for item in items[:MAX_ENTITY_IDS]:
        if not isinstance(item, dict):
            malformed += 1
            continue
        fields, _ = _compound_map(item)
        if not fields and item.get("type") != "compound":
            malformed += 1
            continue
        entity_id = _string(fields.get("id")) or _string(fields.get("Id"))
        if entity_id is not None:
            if len(ids) < MAX_ENTITY_IDS and budget["entity_ids"] > 0:
                ids.append(entity_id)
                budget["entity_ids"] -= 1
            else:
                ids_truncated = True
    return {"count": len(items), "ids": ids, "malformed_items": malformed,
            "ids_truncated": ids_truncated, "items_scan_truncated": scan_truncated}


def _semantic_chunk(nbt_report: dict[str, Any], *, source: str, slot_index: int | None,
                    sector_offset: int, compression: str | None,
                    stored_size: int | None, timestamp: int | None,
                    region_x: int | None, region_z: int | None,
                    budget: dict[str, int]) -> dict[str, Any]:
    root = nbt_report.get("root")
    if not isinstance(root, dict) or root.get("type") != "compound":
        raise _fail("chunk NBT root must be a compound")
    root_map, root_duplicates = _compound_map(root)
    level = root_map.get("Level")
    legacy_level = isinstance(level, dict) and level.get("type") == "compound"
    payload = level if legacy_level else root
    payload_map, payload_duplicates = _compound_map(payload)

    data_version = _integer(root_map.get("DataVersion"))
    if data_version is None:
        data_version = _integer(payload_map.get("DataVersion"))
    status = _string(payload_map.get("status")) or _string(payload_map.get("Status"))
    x_pos = _integer(payload_map.get("xPos"))
    z_pos = _integer(payload_map.get("zPos"))
    coordinate_source = "xPos/zPos"
    if x_pos is None and z_pos is None:
        position = _position_coordinates(payload_map.get("Position"))
        if position is not None:
            x_pos, z_pos = position
            coordinate_source = "Position"
        else:
            coordinate_source = "missing"
    issues: list[str] = []
    if root_duplicates:
        issues.append("duplicate root fields: " + ", ".join(root_duplicates))
    if payload_duplicates:
        issues.append("duplicate chunk fields: " + ", ".join(payload_duplicates))

    local_x = slot_index & 31 if slot_index is not None else None
    local_z = slot_index >> 5 if slot_index is not None else None
    expected_x = expected_z = None
    if slot_index is not None:
        if x_pos is None:
            issues.append("missing xPos")
        elif x_pos % 32 != local_x:
            issues.append(f"xPos {x_pos} disagrees with slot local_x {local_x}")
        if z_pos is None:
            issues.append("missing zPos")
        elif z_pos % 32 != local_z:
            issues.append(f"zPos {z_pos} disagrees with slot local_z {local_z}")
    if slot_index is not None and region_x is not None and region_z is not None:
        expected_x = region_x * 32 + local_x
        expected_z = region_z * 32 + local_z
        if x_pos is not None and x_pos != expected_x:
            issues.append(f"xPos {x_pos} differs from expected {expected_x}")
        if z_pos is not None and z_pos != expected_z:
            issues.append(f"zPos {z_pos} differs from expected {expected_z}")

    section_node = payload_map.get("sections") or payload_map.get("Sections")
    section_items = _list_items(section_node)
    emitted_sections = min(len(section_items), budget["sections"])
    sections = [_section_summary(item, index, budget)
                for index, item in enumerate(section_items[:emitted_sections])]
    budget["sections"] -= emitted_sections
    sections_truncated = emitted_sections != len(section_items)
    block_entities = _entity_summary(
        payload_map.get("block_entities") or payload_map.get("TileEntities"), budget)
    entities = _entity_summary(
        payload_map.get("entities") or payload_map.get("Entities"), budget)
    evidence = _walk_evidence(root, budget)
    coordinate_match = None if slot_index is None else (
        x_pos is not None and z_pos is not None
        and not any("Pos " in issue for issue in issues)
    )
    return {
        "source": source,
        "slot_index": slot_index,
        "local_x": local_x,
        "local_z": local_z,
        "sector_offset": sector_offset,
        "timestamp": timestamp,
        "compression": compression,
        "stored_size": stored_size,
        "decompressed_size": nbt_report.get("decompressed_size"),
        "tag_count": nbt_report.get("tag_count"),
        "layout": "legacy-level" if legacy_level else "modern-root",
        "data_version": data_version,
        "status": status,
        "x_pos": x_pos,
        "z_pos": z_pos,
        "coordinate_source": coordinate_source,
        "expected_x_pos": expected_x,
        "expected_z_pos": expected_z,
        "coordinate_match": coordinate_match,
        "sections": sections,
        "section_count": len(section_items),
        "sections_truncated": sections_truncated,
        "block_entities": block_entities,
        "entities": entities,
        "strings": evidence["strings"],
        "flags": evidence["flags"],
        "evidence": {key: value for key, value in evidence.items() if key != "strings" and key != "flags"},
        "issues": issues,
    }


def _allocation_slack(slack: object, *, source: str, slot_index: int | None,
                      sector_offset: int, record_file_offset: int,
                      declared_length: object, budget: dict[str, int]
                      ) -> dict[str, Any] | None:
    """Project the bounded baseline slack summary into offset-aware evidence."""
    if not isinstance(slack, dict):
        return None
    length = declared_length if isinstance(declared_length, int) else None
    slack_file_offset = (record_file_offset + 4 + length
                         if length is not None and length >= 0 else None)
    strings: list[dict[str, Any]] = []
    flags: set[str] = set()
    truncated = False
    flags_truncated = False
    runs = slack.get("ascii_runs")
    if not isinstance(runs, list):
        runs = []
    baseline_runs_limit_reached = len(runs) >= 16
    if baseline_runs_limit_reached:
        truncated = True
        flags_truncated = True
    for run in runs:
        if not isinstance(run, dict):
            continue
        relative = run.get("offset")
        text = run.get("text")
        if not isinstance(relative, int) or relative < 0 or not isinstance(text, str):
            continue
        for flag in _flag_values(text):
            if flag in flags:
                continue
            if len(flags) < MAX_FLAGS and budget["flags"] > 0:
                flags.add(flag)
                budget["flags"] -= 1
            else:
                flags_truncated = True
        if budget["evidence"] <= 0:
            truncated = True
            continue
        strings.append({
            "relative_offset": relative,
            "file_offset": None if slack_file_offset is None else slack_file_offset + relative,
            "text": text,
            "truncated": bool(run.get("truncated")),
        })
        if bool(run.get("truncated")):
            truncated = True
        budget["evidence"] -= 1
    return {
        "source": source,
        "slot_index": slot_index,
        "sector_offset": sector_offset,
        "file_offset": slack_file_offset,
        "byte_size": slack.get("size"),
        "nonzero_bytes": slack.get("nonzero_bytes"),
        "sha256": slack.get("sha256"),
        "strings": strings,
        "flags": sorted(flags),
        "flags_truncated": flags_truncated,
        "baseline_runs_limit_reached": baseline_runs_limit_reached,
        "evidence_truncated": truncated,
    }


def _validate_region_coordinates(region_x: object, region_z: object) -> tuple[int | None, int | None]:
    if (region_x is None) != (region_z is None):
        raise _fail("region_x and region_z must be supplied together")
    if region_x is None:
        return None, None
    if (not isinstance(region_x, int) or isinstance(region_x, bool)
            or not isinstance(region_z, int) or isinstance(region_z, bool)):
        raise _fail("region coordinates must be integers")
    if not -(1 << 31) <= region_x < (1 << 31) or not -(1 << 31) <= region_z < (1 << 31):
        raise _fail("region coordinates exceed signed 32-bit range")
    return region_x, region_z


def analyze_region(data: object, *, region_x: int | None = None,
                   region_z: int | None = None) -> dict[str, Any]:
    """Return bounded Anvil structure and semantic summaries for decoded chunks."""
    try:
        region_x, region_z = _validate_region_coordinates(region_x, region_z)
        raw = _bounded_bytes(data)
        parsed = _nbt.inspect_region(raw)
        configured = {
            "sections": MAX_REGION_SECTIONS,
            "evidence": MAX_REGION_EVIDENCE,
            "palette_ids": MAX_REGION_PALETTE_IDS,
            "entity_ids": MAX_REGION_ENTITY_IDS,
            "flags": MAX_REGION_FLAGS,
        }
        budget = dict(configured)
        chunks: list[dict[str, Any]] = []
        slack_records: list[dict[str, Any]] = []
        for entry in parsed["entries"]:
            chunk = entry.get("chunk")
            if not isinstance(chunk, dict):
                continue
            semantic = None
            if chunk.get("status") == "valid":
                nbt_report = chunk.get("nbt")
                if not isinstance(nbt_report, dict):
                    raise _fail("valid chunk is missing its NBT report")
                semantic = _semantic_chunk(
                    nbt_report, source="location-table", slot_index=entry["index"],
                    sector_offset=entry["sector_offset"], compression=chunk.get("compression"),
                    stored_size=chunk.get("declared_length"), timestamp=entry.get("timestamp"),
                    region_x=region_x, region_z=region_z, budget=budget)
            record_offset = chunk.get("file_offset")
            if not isinstance(record_offset, int):
                record_offset = entry["sector_offset"] * parsed["sector_size"]
            slack = _allocation_slack(
                chunk.get("slack"), source="location-table",
                slot_index=entry["index"], sector_offset=entry["sector_offset"],
                record_file_offset=record_offset,
                declared_length=chunk.get("declared_length"), budget=budget)
            slack_index = None
            if slack is not None:
                slack_index = len(slack_records)
                slack_records.append(slack)
            if semantic is not None:
                semantic["allocation_slack_index"] = slack_index
                chunks.append(semantic)
        for orphan in parsed["orphan_chunks"]:
            semantic = _semantic_chunk(
                orphan["nbt"], source="orphan-sector", slot_index=None,
                sector_offset=orphan["sector_offset"], compression=orphan.get("compression"),
                stored_size=orphan.get("declared_length"), timestamp=None,
                region_x=region_x, region_z=region_z, budget=budget)
            record_offset = orphan["sector_offset"] * parsed["sector_size"]
            slack = _allocation_slack(
                orphan.get("slack"), source="orphan-sector", slot_index=None,
                sector_offset=orphan["sector_offset"],
                record_file_offset=record_offset,
                declared_length=orphan.get("declared_length"), budget=budget)
            slack_index = None
            if slack is not None:
                slack_index = len(slack_records)
                slack_records.append(slack)
            semantic["allocation_slack_index"] = slack_index
            chunks.append(semantic)

        all_flags = sorted(
            {flag for chunk in chunks for flag in chunk["flags"]}
            | {flag for slack in slack_records for flag in slack["flags"]})
        total_strings = (sum(len(chunk["strings"]) for chunk in chunks)
                         + sum(len(slack["strings"]) for slack in slack_records))
        sections_truncated = any(chunk["sections_truncated"] for chunk in chunks)
        palette_truncated = any(
            section["palette_ids_truncated"] or section["palette_scan_truncated"]
            for chunk in chunks for section in chunk["sections"])
        entity_truncated = any(
            group["ids_truncated"] or group["items_scan_truncated"]
            for chunk in chunks
            for group in (chunk["block_entities"], chunk["entities"]))
        evidence_truncated = (
            any(chunk["evidence"]["truncated"] for chunk in chunks)
            or any(slack["evidence_truncated"] for slack in slack_records))
        flags_truncated = (
            any(chunk["evidence"]["flags_truncated"] for chunk in chunks)
            or any(slack["flags_truncated"] for slack in slack_records))
        semantic_output = {
            "limits": configured,
            "emitted": {key: configured[key] - budget[key] for key in configured},
            "remaining": budget,
            "truncated": {
                "sections": sections_truncated,
                "evidence": evidence_truncated,
                "palette_ids": palette_truncated,
                "entity_ids": entity_truncated,
                "flags": flags_truncated,
            },
        }
        region_summary = {
            "size": parsed["size"],
            "sector_size": parsed["sector_size"],
            "complete_sectors": parsed["complete_sectors"],
            "partial_sector_bytes": parsed["partial_sector_bytes"],
            "issues": parsed["issues"],
            "present_entries": parsed["present_entries"],
            "valid_inline_chunks": parsed["valid_inline_chunks"],
            "external_chunks": parsed["external_chunks"],
            "external_files_accessed": parsed["external_files_accessed"],
            "allocation": parsed["allocation"],
            "orphan_scan": parsed["orphan_scan"],
        }
        return {"kind": "ffgame-anvil-semantics", "region": region_summary,
                "region_coordinates": None if region_x is None else {"x": region_x, "z": region_z},
                "chunks": chunks, "semantic_chunk_count": len(chunks),
                "allocation_slack": slack_records,
                "string_evidence_count": total_strings, "flags": all_flags,
                "semantic_output": semantic_output,
                "external_files_accessed": False}
    except FFGameAnvilError:
        raise
    except _nbt.ResearchFFNBTError as exc:
        raise _fail(f"Anvil parser rejected input: {exc}") from None
    except Exception as exc:
        raise _fail(f"Anvil semantic analyzer declined input ({type(exc).__name__})") from None


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except (OSError, ValueError) as exc:
        raise _fail(f"could not read artifact: {exc}") from None
    if len(data) > MAX_INPUT:
        raise _fail(f"artifact exceeds {MAX_INPUT} byte cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Minecraft Anvil semantic inspector")
    parser.add_argument("artifact", help="Anvil .mca region file")
    parser.add_argument("--region-x", type=int)
    parser.add_argument("--region-z", type=int)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = analyze_region(_read_bounded(Path(args.artifact)), region_x=args.region_x,
                                region_z=args.region_z)
        json.dump(report, sys.stdout, indent=None if args.compact else 2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except FFGameAnvilError as exc:
        print(f"ffgame_anvil_semantics: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ffgame_anvil_semantics: output failed ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["FFGameAnvilError", "analyze_region", "main"]
