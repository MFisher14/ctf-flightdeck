"""Independent hand-built Anvil/NBT vectors for ffgame_anvil_semantics."""

from __future__ import annotations

import json
import struct
import zlib

import pytest

import ffgame_anvil_semantics as anvil


SECTOR = 4096


def _name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def _tag(tag_id: int, name: str, payload: bytes) -> bytes:
    return bytes([tag_id]) + _name(name) + payload


def _byte(name: str, value: int) -> bytes:
    return _tag(1, name, struct.pack(">b", value))


def _int(name: str, value: int) -> bytes:
    return _tag(3, name, struct.pack(">i", value))


def _string(name: str, value: str) -> bytes:
    raw = value.encode("utf-8")
    return _tag(8, name, struct.pack(">H", len(raw)) + raw)


def _bytes(name: str, value: bytes) -> bytes:
    return _tag(7, name, struct.pack(">i", len(value)) + value)


def _longs(name: str, values: list[int]) -> bytes:
    return _tag(12, name, struct.pack(">i", len(values))
                + b"".join(struct.pack(">q", value) for value in values))


def _ints(name: str, values: list[int]) -> bytes:
    return _tag(11, name, struct.pack(">i", len(values))
                + b"".join(struct.pack(">i", value) for value in values))


def _compound_payload(*children: bytes) -> bytes:
    return b"".join(children) + b"\x00"


def _compound(name: str, *children: bytes) -> bytes:
    return _tag(10, name, _compound_payload(*children))


def _compound_list(name: str, rows: list[bytes]) -> bytes:
    # List payloads contain unnamed compound payloads: no per-item type or name.
    return _tag(9, name, b"\x0a" + struct.pack(">i", len(rows)) + b"".join(rows))


def _root(*children: bytes) -> bytes:
    return b"\x0a\x00\x00" + _compound_payload(*children)


def _modern_chunk(x_pos: int = 35, z_pos: int = -28,
                  include_coordinates: bool = True) -> bytes:
    palettes = _compound_list("palette", [
        _compound_payload(_string("Name", "minecraft:stone")),
        _compound_payload(_string("Name", "minecraft:command_block")),
    ])
    section = _compound_payload(
        _byte("Y", -4),
        _compound("block_states", palettes, _longs("data", [0, 1, 0, 1])),
        _bytes("BlockLight", bytes(2048)),
    )
    sign = _compound_payload(
        _string("id", "minecraft:sign"),
        _int("x", x_pos * 16), _int("y", 64), _int("z", z_pos * 16),
        _string("front_text", '{"text":"CSCTF{ANVIL_WALK}"}'),
    )
    pig = _compound_payload(
        _string("id", "minecraft:pig"), _string("CustomName", "operative"))
    coordinates = ([_int("xPos", x_pos), _int("zPos", z_pos)]
                   if include_coordinates else [])
    return _root(
        _int("DataVersion", 3105), *coordinates,
        _string("Status", "minecraft:full"),
        _compound_list("sections", [section]),
        _compound_list("block_entities", [sign]),
        _compound_list("entities", [pig]),
        _string("Mission", "radio bunker seven"),
        _bytes("Recovered", b"noise RADIO CSCTF{BYTE_ARRAY} tail"),
    )


def _legacy_chunk(x_pos: int = 37, z_pos: int = -28) -> bytes:
    palette = _compound_list("Palette", [
        _compound_payload(_string("Name", "minecraft:grass_block")),
    ])
    section = _compound_payload(
        _byte("Y", 0), palette, _longs("BlockStates", [0, 0]),
        _bytes("Blocks", b"\x01" * 4096), _bytes("Data", bytes(2048)),
        _bytes("SkyLight", b"\xff" * 2048),
    )
    chest = _compound_payload(
        _string("id", "Chest"), _string("Lock", "CSCTF{LEGACY_CHEST}"))
    zombie = _compound_payload(_string("id", "Zombie"))
    return _root(
        _int("DataVersion", 1343),
        _compound("Level", _int("xPos", x_pos), _int("zPos", z_pos),
                  _string("Status", "full"), _compound_list("Sections", [section]),
                  _compound_list("TileEntities", [chest]),
                  _compound_list("Entities", [zombie])),
    )


def _entity_region_chunk(x_pos: int = 35, z_pos: int = -28) -> bytes:
    entity = _compound_payload(
        _string("id", "minecraft:armor_stand"),
        _string("CustomName", "CSCTF{ENTITY_REGION}"),
    )
    return _root(
        _int("DataVersion", 3105), _ints("Position", [x_pos, z_pos]),
        _compound_list("Entities", [entity]),
    )


def _region(records: list[tuple[int, bytes, int]], marker: int = 2) -> bytes:
    header = bytearray(2 * SECTOR)
    sectors: list[bytes] = []
    next_sector = 2
    for slot, nbt, timestamp in records:
        payload = zlib.compress(nbt)
        body = struct.pack(">I", len(payload) + 1) + bytes([marker]) + payload
        count = (len(body) + SECTOR - 1) // SECTOR
        assert count < 256
        header[slot * 4:slot * 4 + 4] = ((next_sector << 8) | count).to_bytes(4, "big")
        timestamp_at = SECTOR + slot * 4
        header[timestamp_at:timestamp_at + 4] = timestamp.to_bytes(4, "big")
        sectors.append(body.ljust(count * SECTOR, b"\x00"))
        next_sector += count
    return bytes(header) + b"".join(sectors)


def _fixture(modern_x: int = 35, include_coordinates: bool = True) -> bytes:
    # region (1,-1), slots (3,4) and (5,4) => chunks (35,-28), (37,-28)
    return _region([(3 + 32 * 4, _modern_chunk(modern_x, -28, include_coordinates),
                     1_700_000_001),
                    (5 + 32 * 4, _legacy_chunk(37, -28), 1_700_000_002)])


def test_modern_and_legacy_full_chunk_walk_against_hand_built_vector():
    report = anvil.analyze_region(_fixture(), region_x=1, region_z=-1)
    assert report["kind"] == "ffgame-anvil-semantics"
    assert report["region"]["valid_inline_chunks"] == 2
    assert report["semantic_chunk_count"] == 2
    assert report["external_files_accessed"] is False
    assert report["flags"] == [
        "CSCTF{ANVIL_WALK}", "CSCTF{BYTE_ARRAY}", "CSCTF{LEGACY_CHEST}"]

    modern, legacy = report["chunks"]
    assert (modern["layout"], modern["data_version"], modern["status"]) == (
        "modern-root", 3105, "minecraft:full")
    assert (modern["x_pos"], modern["z_pos"], modern["coordinate_match"]) == (35, -28, True)
    assert modern["coordinate_source"] == "xPos/zPos"
    assert modern["expected_x_pos"] == 35 and modern["expected_z_pos"] == -28
    assert modern["sections"] == [{
        "index": 0, "y": -4, "palette_size": 2,
        "palette_ids": ["minecraft:stone", "minecraft:command_block"],
        "palette_ids_truncated": False, "palette_scan_truncated": False,
        "block_state_longs": 4, "legacy_byte_arrays": {"BlockLight": 2048},
        "duplicate_fields": [],
    }]
    assert modern["block_entities"] == {
        "count": 1, "ids": ["minecraft:sign"], "malformed_items": 0,
        "ids_truncated": False, "items_scan_truncated": False}
    assert modern["entities"]["ids"] == ["minecraft:pig"]
    byte_evidence = [row for row in modern["strings"] if row["source"] == "byte_array_ascii"]
    assert byte_evidence[0]["text"] == "noise RADIO CSCTF{BYTE_ARRAY} tail"
    assert any(row["path"] == "$.block_entities[0].front_text"
               for row in modern["strings"])

    assert legacy["layout"] == "legacy-level"
    assert legacy["sections"][0]["palette_ids"] == ["minecraft:grass_block"]
    assert legacy["sections"][0]["block_state_longs"] == 2
    assert legacy["sections"][0]["legacy_byte_arrays"] == {
        "Blocks": 4096, "Data": 2048, "SkyLight": 2048}
    assert legacy["block_entities"]["ids"] == ["Chest"]
    assert legacy["entities"]["ids"] == ["Zombie"]


def test_coordinate_tampering_is_reported_without_hiding_content():
    report = anvil.analyze_region(_fixture(modern_x=99), region_x=1, region_z=-1)
    modern = report["chunks"][0]
    assert modern["coordinate_match"] is False
    assert modern["expected_x_pos"] == 35
    assert "xPos 99 differs from expected 35" in modern["issues"]
    assert "CSCTF{ANVIL_WALK}" in modern["flags"]


def test_missing_coordinates_are_not_reported_as_a_match():
    report = anvil.analyze_region(
        _fixture(include_coordinates=False), region_x=1, region_z=-1)
    modern = report["chunks"][0]
    assert modern["x_pos"] is None and modern["z_pos"] is None
    assert modern["coordinate_source"] == "missing"
    assert modern["coordinate_match"] is False
    assert modern["expected_x_pos"] == 35 and modern["expected_z_pos"] == -28
    assert "missing xPos" in modern["issues"]
    assert "missing zPos" in modern["issues"]


def test_entity_region_position_int_array_supplies_chunk_coordinates():
    slot = 3 + 32 * 4
    image = _region([(slot, _entity_region_chunk(), 1_700_000_003)])
    report = anvil.analyze_region(image, region_x=1, region_z=-1)
    chunk = report["chunks"][0]
    assert chunk["coordinate_source"] == "Position"
    assert (chunk["x_pos"], chunk["z_pos"]) == (35, -28)
    assert (chunk["expected_x_pos"], chunk["expected_z_pos"]) == (35, -28)
    assert chunk["coordinate_match"] is True
    assert chunk["entities"]["ids"] == ["minecraft:armor_stand"]
    assert "CSCTF{ENTITY_REGION}" in chunk["flags"]


def test_allocation_slack_strings_flags_and_physical_offsets_are_preserved():
    image = bytearray(_fixture())
    compressed = zlib.compress(_modern_chunk())
    slack_start = 2 * SECTOR + 5 + len(compressed)
    relative = 17
    hidden = b"CSCTF{REGION_SLACK}"
    image[slack_start + relative:slack_start + relative + len(hidden)] = hidden

    report = anvil.analyze_region(bytes(image), region_x=1, region_z=-1)
    slack = next(row for row in report["allocation_slack"]
                 if row["slot_index"] == 3 + 32 * 4)
    assert slack["file_offset"] == slack_start
    assert slack["flags"] == [hidden.decode()]
    assert slack["strings"] == [{
        "relative_offset": relative,
        "file_offset": slack_start + relative,
        "text": hidden.decode(),
        "truncated": False,
    }]
    assert report["allocation_slack"][
        report["chunks"][0]["allocation_slack_index"]] == slack
    assert hidden.decode() in report["flags"]


def test_baseline_slack_run_truncation_and_run_cap_are_propagated():
    image = bytearray(_fixture())
    compressed = zlib.compress(_modern_chunk())
    slack_start = 2 * SECTOR + 5 + len(compressed)
    runs = [b"A" * 200] + [f"RUN{index:02d}".encode() for index in range(1, 18)]
    payload = b"\0".join(runs) + b"\0"
    image[slack_start:slack_start + len(payload)] = payload

    report = anvil.analyze_region(bytes(image), region_x=1, region_z=-1)
    slack = next(row for row in report["allocation_slack"]
                 if row["slot_index"] == 3 + 32 * 4)
    assert len(slack["strings"]) == 16
    assert slack["strings"][0]["text"] == "A" * 160
    assert slack["strings"][0]["truncated"] is True
    assert slack["baseline_runs_limit_reached"] is True
    assert slack["evidence_truncated"] is True
    assert slack["flags_truncated"] is True
    assert report["semantic_output"]["truncated"]["evidence"] is True
    assert report["semantic_output"]["truncated"]["flags"] is True


def test_external_chunk_reference_stays_inert_and_is_not_opened():
    header = bytearray(2 * SECTOR)
    slot = 0
    header[:4] = ((2 << 8) | 1).to_bytes(4, "big")
    body = struct.pack(">I", 1) + b"\x82"
    blob = bytes(header) + body.ljust(SECTOR, b"\x00")
    report = anvil.analyze_region(blob)
    assert report["region"]["external_chunks"] == 1
    assert report["chunks"] == []
    assert report["external_files_accessed"] is False


def test_empty_region_is_valid_and_semantically_empty():
    report = anvil.analyze_region(bytes(2 * SECTOR))
    assert report["semantic_chunk_count"] == 0
    assert report["region"]["present_entries"] == 0
    assert report["flags"] == []


@pytest.mark.parametrize("blob", [
    b"", b"not a region", bytes(2 * SECTOR - 1), b"\xff" * (2 * SECTOR),
    bytes(range(256)) * 32,
])
def test_malformed_inputs_raise_only_declared_error_or_return_cleanly(blob):
    try:
        result = anvil.analyze_region(blob)
    except Exception as exc:  # assertion deliberately checks the public contract
        assert type(exc) is anvil.FFGameAnvilError
    else:
        assert isinstance(result, dict)


def test_truncated_valid_and_bit_flipped_regions_fail_closed():
    valid = _fixture()
    variants = [valid[:8192], valid[:-1], valid[:8500],
                valid[:8192] + bytes([valid[8192] ^ 0x80]) + valid[8193:]]
    for blob in variants:
        try:
            result = anvil.analyze_region(blob, region_x=1, region_z=-1)
        except Exception as exc:
            assert type(exc) is anvil.FFGameAnvilError
        else:
            assert isinstance(result, dict)
            assert result["external_files_accessed"] is False


def test_oversized_and_invalid_coordinates_use_declared_error(monkeypatch):
    monkeypatch.setattr(anvil, "MAX_INPUT", 32)
    with pytest.raises(anvil.FFGameAnvilError, match="exceeds"):
        anvil.analyze_region(b"x" * 33)
    for kwargs in ({"region_x": 1}, {"region_x": "1", "region_z": 0},
                   {"region_x": True, "region_z": 0},
                   {"region_x": 1 << 40, "region_z": 0}):
        with pytest.raises(anvil.FFGameAnvilError):
            anvil.analyze_region(bytes(2 * SECTOR), **kwargs)


def test_evidence_output_cap_is_explicit(monkeypatch):
    monkeypatch.setattr(anvil, "MAX_EVIDENCE", 2)
    report = anvil.analyze_region(_fixture(), region_x=1, region_z=-1)
    assert len(report["chunks"][0]["strings"]) == 2
    assert report["chunks"][0]["evidence"]["truncated"] is True


def test_region_wide_semantic_output_budgets_are_explicit(monkeypatch):
    monkeypatch.setattr(anvil, "MAX_REGION_SECTIONS", 1)
    monkeypatch.setattr(anvil, "MAX_REGION_EVIDENCE", 1)
    monkeypatch.setattr(anvil, "MAX_REGION_PALETTE_IDS", 1)
    monkeypatch.setattr(anvil, "MAX_REGION_ENTITY_IDS", 1)
    monkeypatch.setattr(anvil, "MAX_REGION_FLAGS", 1)
    report = anvil.analyze_region(_fixture(), region_x=1, region_z=-1)
    limits = report["semantic_output"]
    assert limits["emitted"] == {
        "sections": 1, "evidence": 1, "palette_ids": 1,
        "entity_ids": 1, "flags": 1,
    }
    assert limits["truncated"] == {
        "sections": True, "evidence": True, "palette_ids": True,
        "entity_ids": True, "flags": True,
    }
    assert report["chunks"][0]["sections"][0]["palette_ids"] == ["minecraft:stone"]
    assert report["chunks"][0]["sections"][0]["palette_ids_truncated"] is True
    assert report["chunks"][0]["entities"]["ids_truncated"] is True
    assert report["chunks"][1]["sections"] == []
    assert len(report["flags"]) == 1


def test_guarded_cli_and_json_output(tmp_path, capsys):
    assert anvil.main(["--not-an-option"]) == 2
    path = tmp_path / "r.1.-1.mca"
    path.write_bytes(_fixture())
    assert anvil.main([str(path), "--region-x", "1", "--region-z", "-1", "--compact"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["flags"] == [
        "CSCTF{ANVIL_WALK}", "CSCTF{BYTE_ARRAY}", "CSCTF{LEGACY_CHEST}"]
