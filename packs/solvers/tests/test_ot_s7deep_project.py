"""Independent synthetic layout fixtures for the deep STEP7 project parser.

The builders below directly transcribe the published MC7, dBASE IV, DBT, and
MDX byte layouts. They never call an encoder or use output from the engine.
"""
import argparse
import json
import random
import struct

import pytest

import ot_s7deep_project as engine


def reference_crc(payload):
    """Bit-at-a-time CRC-16/0x9003 transcription, independent of the engine."""
    crc = 0
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x9003) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def mc7_block(*, kind=0x0A, number=42, language=5, body=b"", descriptors=b"",
              starts=b"", padding=b"", additional=b"", marker=None):
    marker = (0x05 if kind in (0x0A, 0x0B) else 0x01) if marker is None else marker
    sbb = (bytes([marker]) + struct.pack("<HHH", number, len(descriptors), len(starts))
           + descriptors + starts + padding)
    raw = bytearray(36 + len(body) + len(sbb) + len(additional) + 36)
    raw[:6] = bytes([0x70, 0x70, 1, 1, language, kind])
    struct.pack_into(">HI", raw, 6, number, len(raw))
    struct.pack_into(">HHHH", raw, 28, len(sbb), len(additional), 0, len(body))
    raw[36:36 + len(body)] = body
    sbb_at = 36 + len(body)
    raw[sbb_at:sbb_at + len(sbb)] = sbb
    raw[sbb_at + len(sbb):sbb_at + len(sbb) + len(additional)] = additional
    footer = len(raw) - 36
    raw[footer:footer + 8] = b"AUTHOR  "
    raw[footer + 8:footer + 16] = b"FAMILY  "
    raw[footer + 16:footer + 24] = b"BLOCK   "
    raw[footer + 24] = 0x21
    checksum = reference_crc(bytes([kind]) + bytes(raw[34:36]) + body)
    struct.pack_into(">H", raw, footer + 26, checksum)
    return bytes(raw)


def dbf_table(fields, records, *, version=0x03, mdx=False, ldid=0x57):
    """Pack classic 32-byte dBASE descriptors and caller-supplied field bytes."""
    header_length = 32 + 32 * len(fields) + 1
    record_length = 1 + sum(field[2] for field in fields)
    header = bytearray(header_length)
    header[0:4] = bytes([version, 126, 11, 5])
    struct.pack_into("<IHH", header, 4, len(records), header_length, record_length)
    header[28] = int(mdx)
    header[29] = ldid
    for index, (name, kind, width, decimals, indexed) in enumerate(fields):
        offset = 32 + index * 32
        header[offset:offset + 11] = name.encode("ascii").ljust(11, b"\0")
        header[offset + 11] = ord(kind)
        header[offset + 16] = width
        header[offset + 17] = decimals
        header[offset + 31] = int(indexed)
    header[-1] = 0x0D
    rows = []
    for deleted, values in records:
        assert len(values) == len(fields)
        row = (b"*" if deleted else b" ") + b"".join(values)
        assert len(row) == record_length
        rows.append(row)
    return bytes(header) + b"".join(rows) + b"\x1a"


def dbt_file(payloads, *, name=b"SUBBLK", block_size=512):
    extents = {
        pointer: (len(payload) + 8 + block_size - 1) // block_size
        for pointer, payload in payloads.items()
    }
    count = max((pointer + extents[pointer] for pointer in payloads), default=1)
    raw = bytearray(count * block_size)
    struct.pack_into("<I", raw, 0, count)
    raw[8:16] = name[:8].ljust(8, b"\0")
    raw[16] = 0
    struct.pack_into("<H", raw, 20, block_size)
    for pointer, payload in payloads.items():
        assert pointer > 0
        for other, other_extent in extents.items():
            if other != pointer:
                assert not (pointer < other + other_extent and other < pointer + extents[pointer])
        offset = pointer * block_size
        raw[offset:offset + 4] = b"\xff\xff\x08\x00"
        struct.pack_into("<I", raw, offset + 4, len(payload) + 8)
        raw[offset + 8:offset + 8 + len(payload)] = payload
    return bytes(raw)


def mdx_file():
    block_size, pages = 1024, 4
    raw = bytearray(block_size * pages)
    raw[0:4] = bytes([2, 126, 11, 5])
    raw[4:20] = b"BAUSTEIN".ljust(16, b"\0")
    struct.pack_into("<HH", raw, 20, block_size, 2)
    raw[24:27] = bytes([1, 47, 32])
    struct.pack_into("<H", raw, 28, 1)
    struct.pack_into("<I", raw, 32, pages)
    struct.pack_into("<I", raw, 544, 2)
    raw[548:559] = b"ID".ljust(11, b"\0")
    raw[559] = 0x10
    raw[564] = ord("N")
    tag = 2 * block_size
    struct.pack_into("<II", raw, tag, 3, 1)
    raw[tag + 8] = 0x58
    raw[tag + 9] = ord("N")
    struct.pack_into("<HHHHH", raw, tag + 12, 12, 20, 0, 16, 1)
    raw[tag + 20:tag + 23] = bytes.fromhex("341256")
    raw[tag + 23] = 1
    raw[tag + 24:tag + 34] = b"ID\0ACTIVE\0"
    return bytes(raw)


def test_hand_built_fc_locks_sections_metadata_and_independent_crc():
    data = mc7_block(kind=0x0C, number=1, language=2, body=b"INERT!",
                     padding=b"\x20", additional=bytes.fromhex("010004000000"))
    result = engine.parse_mc7_block(data)
    metadata = result["metadata"]
    assert (metadata["block_type"], metadata["block_number"], metadata["language"]) == (
        "FC", 1, "KOP")
    assert (metadata["load_size"], metadata["mc7_size"], metadata["sbb_size"],
            metadata["segment_size"], metadata["local_data_size"]) == (92, 6, 8, 6, 0)
    assert result["sections"]["mc7_code_or_db_values"]["hex"] == b"INERT!".hex()
    assert result["sections"]["sbb"]["hex"] == "0101000000000020"
    assert result["sections"]["additional_info"]["hex"] == "010004000000"
    assert (metadata["author"], metadata["family"], metadata["name"],
            metadata["version"]) == ("AUTHOR", "FAMILY", "BLOCK", "2.1")
    assert result["checksum"] == {"stored": 0x65B2, "calculated": 0x65B2, "valid": True}
    assert result["interface"]["padding_hex"] == "20"
    assert result["segment_table"]["network_count"] == 1
    assert result["segment_table"]["network_offsets"] == [0]


def test_hand_built_db_block_decodes_interface_starts_and_current_values():
    descriptors = bytes([0x05, 0x0C, 0x07, 0x0C, 0x13, 0x04, 5])
    starts = struct.pack("<hi", -123, 0x01020304)
    body = bytes.fromhex("ff85010203040503414243000000")
    data = mc7_block(body=body, descriptors=descriptors, starts=starts, padding=b"\0")
    result = engine.parse_mc7_block(data)
    interface = result["interface"]
    assert interface["reference_number"] == 42
    assert [item["data_type"] for item in interface["descriptors"]] == [
        "INT", "DINT", "STRING"]
    assert [(item["path"], item["value"]) for item in interface["start_values"]] == [
        ("STATIC[0]", -123), ("STATIC[1]", 0x01020304)]
    values = interface["db_values"]
    assert [(item["byte_offset"], item["data_type"], item["value"])
            for item in values[:2]] == [(0, "INT", -123), (2, "DINT", 0x01020304)]
    assert values[2]["byte_offset"] == 6
    assert values[2]["value"] == {"maximum": 5, "length": 3, "text": "ABC"}
    assert interface["db_values_consumed"] == 13
    assert interface["db_value_slack_hex"] == "00"
    assert result["checksum"]["valid"] is True


def test_hand_built_struct_array_word_alignment_and_stable_synthetic_paths():
    # STRUCT STATIC { BYTE STATIC; ARRAY[-1..1] OF INT STATIC }
    descriptor = (bytes([0x11, 0x04, 2, 0x02, 0x04,
                         0x10, 0x04, 1])
                  + struct.pack("<hh", -1, 1) + bytes([0x05, 0x04]))
    actual = b"\x7f\x00\x00\x01\x00\x02\x00\x03"
    sbb = bytes([0x05]) + struct.pack("<HHH", 7, len(descriptor), 0) + descriptor
    result = engine.parse_mc7_interface(sbb, actual)
    root = result["descriptors"][0]
    assert root["data_type"] == "STRUCT" and root["child_count"] == 2
    assert root["children"][1]["dimensions"] == [{"lower": -1, "upper": 1}]
    values = result["db_values"]
    assert [(item["path"], item["byte_offset"], item["value"]) for item in values] == [
        ("STATIC[0].member[0]", 0, 0x7F),
        ("STATIC[0].member[1][-1]", 2, 1),
        ("STATIC[0].member[1][0]", 4, 2),
        ("STATIC[0].member[1][1]", 6, 3),
    ]


def test_extended_string_and_multi_instance_descriptor_layout():
    descriptor = bytes([0x13, 0x14, 0xA5, 8, 0x15, 42, 0])
    sbb = bytes([0x01]) + struct.pack("<HHH", 3, len(descriptor), 0) + descriptor
    parsed = engine.parse_mc7_interface(sbb)
    first, second = parsed["descriptors"]
    assert (first["data_type"], first["extended_flags"], first["max_length"]) == (
        "STRING", 0xA5, 8)
    assert (second["data_type"], second["parameter_type"], second["block_number"]) == (
        "MULTI_INSTANCE_FB", "STATIC", 42)


def test_compact_string_start_value_uses_only_its_used_bytes():
    descriptors = bytes([0x13, 0x0C, 8, 0x05, 0x0C])
    starts = bytes([8, 3]) + b"ABC" + struct.pack("<h", -7)
    sbb = (bytes([0x05]) + struct.pack("<HHH", 1, len(descriptors), len(starts))
           + descriptors + starts)
    parsed = engine.parse_mc7_interface(sbb)
    assert parsed["start_values_complete"] is True
    assert [(item["data_type"], item["offset"], item["size"], item["value"])
            for item in parsed["start_values"]] == [
        ("STRING", 0, 5,
         {"maximum": 8, "length": 3, "text": "ABC"}),
        ("INT", 5, 2, -7),
    ]


def test_multidimensional_array_paths_preserve_declared_coordinates():
    descriptor = (bytes([0x10, 0x04, 2])
                  + struct.pack("<hhhh", -1, 0, 2, 3)
                  + bytes([0x02, 0x04]))
    sbb = bytes([0x05]) + struct.pack("<HHH", 1, len(descriptor), 0) + descriptor
    parsed = engine.parse_mc7_interface(sbb, b"\x0a\x0b\x0c\x0d")
    assert [(item["path"], item["value"]) for item in parsed["db_values"]] == [
        ("STATIC[0][-1,2]", 10), ("STATIC[0][-1,3]", 11),
        ("STATIC[0][0,2]", 12), ("STATIC[0][0,3]", 13),
    ]


def test_unexpanded_multi_instance_and_temp_do_not_shift_db_values():
    for descriptor, reason in ((bytes([0x15, 42, 0, 0x05, 0x04]), "referenced FB"),
                               (bytes([0x05, 0x05, 0x05, 0x04]), "not persistent")):
        sbb = bytes([0x05]) + struct.pack("<HHH", 1, len(descriptor), 0) + descriptor
        parsed = engine.parse_mc7_interface(sbb, b"\x12\x34")
        assert parsed["db_values"] == []
        assert parsed["db_values_complete"] is False
        assert reason in parsed["db_values_stop_reason"]
        assert parsed["db_value_slack_hex"] == "1234"


def test_mc7_strict_geometry_crc_and_interface_corruption_rejected():
    good = bytearray(mc7_block(body=b"\x00\x00", descriptors=bytes([0x05, 0x04])))
    for offset, replacement in ((8, b"\xff\xff\xff\xff"), (28, b"\x00\x01"),
                                (34, b"\xff\xff")):
        changed = bytearray(good)
        changed[offset:offset + len(replacement)] = replacement
        with pytest.raises(engine.S7DeepError):
            engine.parse_mc7_block(changed)
    bad_interface = bytes([5]) + struct.pack("<HHH", 1, 2, 0) + b"\xff\x04"
    with pytest.raises(engine.S7DeepError):
        engine.parse_mc7_interface(bad_interface)

    checksum_changed = bytearray(good)
    checksum_changed[36] ^= 0x80
    parsed = engine.parse_mc7_block(checksum_changed)
    expected = reference_crc(bytes([checksum_changed[5]]) + checksum_changed[34:36]
                             + checksum_changed[36:38])
    assert parsed["checksum"]["stored"] != expected
    assert parsed["checksum"] == {
        "stored": int.from_bytes(checksum_changed[-10:-8], "big"),
        "calculated": expected,
        "valid": False,
    }


def test_documented_dbf_values_deleted_rows_eof_and_memo_pointers():
    fields = [("NAME", "C", 8, 0, False), ("COUNT", "N", 4, 0, True),
              ("ENABLED", "L", 1, 0, False), ("STAMP", "D", 8, 0, False),
              ("MEMO", "M", 10, 0, False)]
    table = dbf_table(fields, [
        (False, [b"DB_MAIN ", b"  42", b"T", b"20261105", b"         3"]),
        (True, [b"OB_OLD  ", b"   1", b"F", b"20200102", b"          "]),
    ], version=0x8B, mdx=True)
    result = engine.parse_dbf(table)
    assert result["version"] == 0x8B
    assert result["last_update"] == "2026-11-05"
    assert result["production_mdx"] is True and result["encoding"] == "cp1252"
    assert result["fields"][1]["indexed"] is True
    assert result["records"][0]["values"] == {
        "NAME": "DB_MAIN", "COUNT": 42, "ENABLED": True,
        "STAMP": "2026-11-05", "MEMO": 3,
    }
    assert result["records"][1]["deleted"] is True
    assert result["records"][1]["values"]["MEMO"] is None
    assert result["eof_marker"] is True and result["section_slack_hex"] == ""


def test_documented_dbt_memo_extent_and_payload_inventory():
    first = bytes(index % 251 for index in range(700))
    data = dbt_file({1: first, 3: bytes.fromhex("deadbeef")})
    result = engine.parse_dbt(data)
    assert result["block_size"] == 512
    assert result["next_free_block"] == 4
    assert [memo["block"] for memo in result["memos"]] == [1, 3]
    assert result["memos"][0]["payload"]["hex"] == first.hex()
    assert result["memos"][1]["payload"]["sha256"] == __import__("hashlib").sha256(
        bytes.fromhex("deadbeef")).hexdigest()


def test_dbt_rejects_dbase_iii_and_nonstandard_extent_headers():
    version_three = bytearray(dbt_file({1: b"payload"}))
    version_three[16] = 3
    with pytest.raises(engine.S7DeepError):
        engine.parse_dbt(version_three)
    bad_extent = bytearray(dbt_file({1: b"payload"}))
    bad_extent[512 + 2:512 + 4] = b"\x09\x00"
    with pytest.raises(engine.S7DeepError):
        engine.parse_dbt(bad_extent)


def test_documented_mdx_header_and_tag_directory_only():
    result = engine.parse_mdx(mdx_file())
    assert (result["file_name"], result["block_size"], result["page_count"]) == (
        "BAUSTEIN", 1024, 4)
    assert result["tag_count"] == 1
    tag = result["tags"][0]
    assert (tag["name"], tag["header_page"], tag["root_page"]) == ("ID", 2, 3)
    assert (tag["entry_key_format"], tag["entry_key_type"], tag["key_type"]) == (
        0x10, "N", "N")
    assert (tag["key_length"], tag["max_keys_per_page"], tag["unique"]) == (
        12, 20, True)
    assert tag["reserved_20_22_hex"] == "341256"
    assert tag["descending"] is True and tag["field_or_string"] is True
    assert "version" not in tag and "distinct" not in tag
    assert tag["key_expression"] == "ID" and tag["for_expression"] == "ACTIVE"


def step7_project_files():
    baustein_fields = [("ID", "N", 5, 0, True), ("TYP", "N", 3, 0, False),
                       ("NUMMER", "N", 5, 0, False), ("UDA", "M", 10, 0, False)]
    baustein = dbf_table(baustein_fields, [
        (False, [b"   42", b" 10", b"    7", b"         1"]),
        (True, [b"   43", b" 12", b"   99", b"          "]),
    ], version=0x8B, mdx=True)
    baustein_dbt = dbt_file({1: bytes.fromhex("0100034b45590556414c5545")},
                            name=b"BAUSTEIN")

    fields = [("OBJECTID", "N", 5, 0, False), ("BLKLANG", "C", 2, 0, False),
              ("SUBBLKTYP", "N", 3, 0, False), ("BLKNUMBER", "N", 5, 0, False),
              ("MC5LEN", "N", 6, 0, False), ("SSBLEN", "N", 6, 0, False),
              ("ADDLEN", "N", 6, 0, False), ("PASSWORD", "N", 1, 0, False),
              ("USERNAME", "C", 8, 0, False), ("BLOCKFNAME", "C", 8, 0, False),
              ("BLOCKNAME", "C", 8, 0, False), ("VERSION", "N", 3, 0, False),
              ("CHECKSUM", "N", 6, 0, False), ("MC5CODE", "M", 10, 0, False),
              ("SSBPART", "M", 10, 0, False), ("ADDINFO", "M", 10, 0, False)]
    descriptor = bytes([0x05, 0x04])
    interface = bytes([0x05]) + struct.pack("<HHH", 7, len(descriptor), 0) + descriptor
    actual = b"\x12\x34"
    values = [b"   42", b"5 ", b" 10", b"    7", b"     2", b"     9",
              b"     0", b"0", b"OPERATOR", b"CTRL    ", b"SETPOINT",
              b" 33", b"  4660", b"         1", b"         2", b"          "]
    subblk = dbf_table(fields, [(False, values)], version=0x8B)
    subblk_dbt = dbt_file({1: actual, 2: interface})
    return {
        "P/BAUSTEIN.DBF": baustein, "P/BAUSTEIN.DBT": baustein_dbt,
        "P/BAUSTEIN.MDX": mdx_file(), "P/SUBBLK.DBF": subblk,
        "P/SUBBLK.DBT": subblk_dbt,
    }


def test_step7_project_join_and_compiled_db_value_recovery():
    result = engine.inventory_project(step7_project_files())
    assert result["file_count"] == 5
    assert result["associations"] == [
        {"table": "P/BAUSTEIN.DBF", "memo": "P/BAUSTEIN.DBT",
         "index": "P/BAUSTEIN.MDX"},
        {"table": "P/SUBBLK.DBF", "memo": "P/SUBBLK.DBT"},
    ]
    assert [(block["block_type"], block["block_number"], block["deleted"])
            for block in result["project_blocks"]] == [("DB", 7, False), ("FC", 99, True)]
    compiled = result["project_blocks"][0]["subblocks"][0]
    assert compiled["subblock_type"] == 10
    assert (compiled["blockname"], compiled["blockfname"], compiled["version_text"]) == (
        "SETPOINT", "CTRL", "2.1")
    assert compiled["mc5code"]["hex"] == "1234"
    assert compiled["ssbpart"]["hex"] == "050700020000000504"
    assert result["project_blocks"][0]["uda"]["hex"] == (
        "0100034b45590556414c5545")
    value = compiled["interface"]["db_values"][0]
    assert (value["data_type"], value["byte_offset"], value["value"]) == (
        "INT", 0, 0x1234)


@pytest.mark.parametrize("value", [None, 1, "bytes", {}, [], object()])
def test_binary_entrypoints_reject_wrong_types_with_declared_error(value):
    for function in (engine.parse_mc7_block, engine.parse_mc7_interface,
                     engine.parse_dbf, engine.parse_dbt, engine.parse_mdx):
        with pytest.raises(engine.S7DeepError):
            function(value)


def test_released_memoryview_fails_closed():
    view = memoryview(b"x")
    view.release()
    for function in (engine.parse_mc7_block, engine.parse_mc7_interface,
                     engine.parse_dbf, engine.parse_dbt, engine.parse_mdx):
        with pytest.raises(engine.S7DeepError):
            function(view)


def test_interface_actual_values_fail_closed():
    interface = bytes([5]) + struct.pack("<HHH", 1, 2, 0) + bytes([5, 4])
    released = memoryview(b"\0\0")
    released.release()
    for actual in (None, 1, "bytes", b"", b"\xff", released):
        if actual is None:
            assert "db_values" not in engine.parse_mc7_interface(interface, actual)
        else:
            with pytest.raises(engine.S7DeepError):
                engine.parse_mc7_interface(interface, actual)


def test_deterministic_truncation_random_bitflip_and_magic_fuzz_fail_closed():
    rng = random.Random(0x57_7DEE)
    fixtures = {
        engine.parse_mc7_block: mc7_block(body=b"\0\0", descriptors=bytes([5, 4])),
        engine.parse_mc7_interface: bytes([5]) + struct.pack("<HHH", 1, 2, 0) + bytes([5, 4]),
        engine.parse_dbf: dbf_table([("X", "N", 2, 0, False)], [(False, [b" 1"])]),
        engine.parse_dbt: dbt_file({1: b"x"}),
        engine.parse_mdx: mdx_file(),
    }
    for function, fixture in fixtures.items():
        samples = [b"", b"\xff" * 64, rng.randbytes(73)]
        samples.extend(fixture[:cut] for cut in range(min(len(fixture), 80)))
        for offset in (0, len(fixture) // 2, len(fixture) - 1):
            changed = bytearray(fixture)
            changed[offset] ^= 0x80
            samples.append(bytes(changed))
        for sample in samples:
            try:
                function(sample)
            except engine.S7DeepError:
                pass


def test_oversized_inputs_fail_closed(monkeypatch):
    # _blob receives its runtime cap explicitly in every public bytes parser.
    monkeypatch.setattr(engine, "MAX_ARTIFACT", 64)
    oversized = b"x" * 65
    for function in (engine.parse_mc7_block, engine.parse_mc7_interface,
                     engine.parse_dbf, engine.parse_dbt, engine.parse_mdx):
        with pytest.raises(engine.S7DeepError):
            function(oversized)
    interface = bytes([5]) + struct.pack("<HHH", 1, 2, 0) + bytes([5, 4])
    with pytest.raises(engine.S7DeepError):
        engine.parse_mc7_interface(interface, oversized)


@pytest.mark.parametrize("entries", [
    None, [None], [{}], [{"path": "x"}], [{"path": None, "data": b""}],
    [{"path": "x", "data": None}], [{"path": "X", "data": b""},
                                       {"path": "x", "data": b""}],
])
def test_project_manifest_malformed_inputs_fail_closed(entries):
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project(entries)


def test_project_entrypoint_known_extension_fuzz_and_bounds(monkeypatch):
    rng = random.Random(0xBA057E1)
    fixtures = step7_project_files()
    samples = [b"", b"\xff" * 64, rng.randbytes(73)]
    for path, fixture in fixtures.items():
        for sample in samples + [fixture[:31], fixture[:-1]]:
            try:
                engine.inventory_project({path: sample})
            except engine.S7DeepError:
                pass
        changed = bytearray(fixture)
        changed[len(changed) // 2] ^= 0x80
        try:
            engine.inventory_project({path: bytes(changed)})
        except engine.S7DeepError:
            pass

    released = memoryview(b"x")
    released.release()
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"P/SUBBLK.DBF": released})
    monkeypatch.setattr(engine, "MAX_FILES", 1)
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"a.bin": b"", "b.bin": b""})
    monkeypatch.setattr(engine, "MAX_TOTAL", 1)
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"a.bin": b"xx"})


def test_cli_valid_modes_and_guarded_argparse(tmp_path, capsys, monkeypatch):
    mc7 = tmp_path / "DB42.mc7"
    mc7.write_bytes(mc7_block(body=b"\x12\x34", descriptors=bytes([5, 4])))
    assert engine.main([str(mc7), "--kind", "mc7"]) == 0
    assert json.loads(capsys.readouterr().out)["metadata"]["block_number"] == 42
    assert engine.main([str(mc7)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "step7-mc7-deep"
    artifacts = {
        "dbf": dbf_table([("X", "N", 2, 0, False)], [(False, [b" 1"])]),
        "dbt": dbt_file({1: b"x"}),
        "mdx": mdx_file(),
    }
    for kind, payload in artifacts.items():
        artifact = tmp_path / f"artifact.{kind}"
        artifact.write_bytes(payload)
        assert engine.main([str(artifact), "--kind", kind]) == 0
        assert json.loads(capsys.readouterr().out)["format"]
    project_paths = []
    for relative, payload in step7_project_files().items():
        artifact = tmp_path / relative.replace("/", "_")
        artifact.write_bytes(payload)
        project_paths.append(str(artifact))
    assert engine.main(project_paths + ["--kind", "project"]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "step7-project-inventory"
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    for argv in ([], ["--bad"], [str(tmp_path / "missing")], [None], "wrong"):
        assert engine.main(argv) == 2
        capsys.readouterr()

    def noninteger_exit(self, argv):
        raise SystemExit("bad")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert engine.main([]) == 2
