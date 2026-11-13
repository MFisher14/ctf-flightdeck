"""Independent Minecraft Anvil/NBT vector and fail-closed boundary tests."""

from __future__ import annotations

import json
import random
import zlib

import pytest

import ffgame_anvil_semantics as engine


SECTOR = 4096


def _name(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(2, "big") + encoded


def _named(tag_id: int, name: str, payload: bytes) -> bytes:
    return bytes([tag_id]) + _name(name) + payload


def _byte(name: str, value: int) -> bytes:
    return _named(1, name, value.to_bytes(1, "big", signed=True))


def _int(name: str, value: int) -> bytes:
    return _named(3, name, value.to_bytes(4, "big", signed=True))


def _string(name: str, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _named(8, name, len(encoded).to_bytes(2, "big") + encoded)


def _long_array(name: str, values: list[int]) -> bytes:
    payload = len(values).to_bytes(4, "big", signed=True)
    payload += b"".join(value.to_bytes(8, "big", signed=True) for value in values)
    return _named(12, name, payload)


def _compound_payload(*children: bytes) -> bytes:
    return b"".join(children) + b"\0"


def _compound(name: str, *children: bytes) -> bytes:
    return _named(10, name, _compound_payload(*children))


def _compound_list(name: str, items: list[bytes]) -> bytes:
    # List elements have one shared type byte and no individual names.
    return _named(
        9,
        name,
        b"\x0a" + len(items).to_bytes(4, "big", signed=True) + b"".join(items),
    )


def _chunk_nbt() -> bytes:
    palette_entry = _compound_payload(_string("Name", "minecraft:stone"))
    palette = _compound_list("palette", [palette_entry])
    block_states = _compound("block_states", palette, _long_array("data", [0]))
    section = _compound_payload(_byte("Y", -4), block_states)
    sign = _compound_payload(
        _string("id", "minecraft:sign"),
        _string("Text", "CSCTF{MCA_ORACLE}"),
    )
    root_children = (
        _int("DataVersion", 3105),
        _string("Status", "minecraft:full"),
        _int("xPos", 34),
        _int("zPos", -31),
        _compound_list("sections", [section]),
        _compound_list("block_entities", [sign]),
        _compound_list("entities", []),
    )
    # Root TAG_Compound with an empty name, followed by its children and TAG_End.
    return b"\x0a\x00\x00" + _compound_payload(*root_children)


def _mca_vector() -> bytes:
    slot = 2 + 32 * 1
    sector_offset = 2
    timestamp = 0x65010203
    compressed = zlib.compress(_chunk_nbt())
    record = (
        (len(compressed) + 1).to_bytes(4, "big")
        + b"\x02"
        + compressed
    )
    assert len(record) <= SECTOR

    header = bytearray(2 * SECTOR)
    header[slot * 4 : slot * 4 + 4] = (
        (sector_offset << 8) | 1
    ).to_bytes(4, "big")
    stamp_at = SECTOR + slot * 4
    header[stamp_at : stamp_at + 4] = timestamp.to_bytes(4, "big")
    return bytes(header) + record.ljust(SECTOR, b"\0")


def _returns_or_declared(data, **coordinates) -> None:
    try:
        result = engine.analyze_region(data, **coordinates)
    except Exception as exc:  # Deliberately catches leaked implementation errors.
        assert type(exc) is engine.FFGameAnvilError
    else:
        assert isinstance(result, dict)


def test_real_mca_location_table_zlib_and_nbt_semantics_vector() -> None:
    report = engine.analyze_region(_mca_vector(), region_x=1, region_z=-1)

    assert report["kind"] == "ffgame-anvil-semantics"
    assert report["region_coordinates"] == {"x": 1, "z": -1}
    assert report["region"]["sector_size"] == 4096
    assert report["region"]["complete_sectors"] == 3
    assert report["region"]["present_entries"] == 1
    assert report["region"]["valid_inline_chunks"] == 1
    assert report["semantic_chunk_count"] == 1
    assert report["external_files_accessed"] is False
    assert report["flags"] == ["CSCTF{MCA_ORACLE}"]

    chunk = report["chunks"][0]
    assert {
        "source": chunk["source"],
        "slot_index": chunk["slot_index"],
        "local_x": chunk["local_x"],
        "local_z": chunk["local_z"],
        "sector_offset": chunk["sector_offset"],
        "timestamp": chunk["timestamp"],
        "compression": chunk["compression"],
        "layout": chunk["layout"],
        "data_version": chunk["data_version"],
        "status": chunk["status"],
        "x_pos": chunk["x_pos"],
        "z_pos": chunk["z_pos"],
        "expected_x_pos": chunk["expected_x_pos"],
        "expected_z_pos": chunk["expected_z_pos"],
        "coordinate_match": chunk["coordinate_match"],
    } == {
        "source": "location-table",
        "slot_index": 34,
        "local_x": 2,
        "local_z": 1,
        "sector_offset": 2,
        "timestamp": 0x65010203,
        "compression": "zlib",
        "layout": "modern-root",
        "data_version": 3105,
        "status": "minecraft:full",
        "x_pos": 34,
        "z_pos": -31,
        "expected_x_pos": 34,
        "expected_z_pos": -31,
        "coordinate_match": True,
    }
    assert chunk["sections"] == [{
        "index": 0,
        "y": -4,
        "palette_size": 1,
        "palette_ids": ["minecraft:stone"],
        "palette_ids_truncated": False,
        "palette_scan_truncated": False,
        "block_state_longs": 1,
        "legacy_byte_arrays": {},
        "duplicate_fields": [],
    }]
    assert chunk["block_entities"] == {
        "count": 1,
        "ids": ["minecraft:sign"],
        "malformed_items": 0,
        "ids_truncated": False,
        "items_scan_truncated": False,
    }
    assert chunk["flags"] == ["CSCTF{MCA_ORACLE}"]
    assert chunk["issues"] == []


def test_anvil_analyzer_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    valid = _mca_vector()
    compressed_flip = bytearray(valid)
    compressed_flip[2 * SECTOR + 9] ^= 0x80
    location_flip = bytearray(valid)
    location_flip[34 * 4 + 2] ^= 0x40
    samples = [
        None,
        b"",
        random.Random(0x4D4341).randbytes(8192),
        b"\xff" * 8192,
        valid[:8191],
        valid[:8192],
        valid[:-1],
        bytes(compressed_flip),
        bytes(location_flip),
    ]
    for sample in samples:
        _returns_or_declared(sample, region_x=1, region_z=-1)

    for coordinates in (
        {"region_x": 1},
        {"region_x": True, "region_z": 0},
        {"region_x": 1 << 31, "region_z": 0},
    ):
        _returns_or_declared(valid, **coordinates)

    # Trigger the production cap branch without allocating 256 MiB.
    monkeypatch.setattr(engine, "MAX_INPUT", 64)
    _returns_or_declared(b"X" * 65)


def test_anvil_cli_is_guarded_and_never_opens_external_chunks(
    tmp_path, capsys, monkeypatch
) -> None:
    artifact = tmp_path / "r.1.-1.mca"
    artifact.write_bytes(_mca_vector())

    assert engine.main([
        str(artifact), "--region-x", "1", "--region-z", "-1", "--compact"
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["flags"] == ["CSCTF{MCA_ORACLE}"]
    assert output["external_files_accessed"] is False
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main([str(tmp_path / "missing.mca")]) == 2
    capsys.readouterr()

    def non_integer_system_exit(*_args, **_kwargs):
        raise SystemExit("not-an-integer")

    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_system_exit)
    assert engine.main([]) == 2
