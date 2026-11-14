"""Independent hardening vectors for the classic STEP7 project parser.

The fixtures hand-pack the layouts documented by Siemens/Snap7,
DotNetSiemensPLCToolBoxLibrary's MC7 and STEP7 project notes, and the classic
dBASE IV DBF/DBT/MDX descriptions.  They do not call an engine encoder or use
engine output as an oracle.
"""

import random
import struct

import pytest

import ot_s7deep_project as engine


def _reference_mc7_crc(payload):
    """Bit-at-a-time CRC-16/poly-0x9003, init/xorout zero."""
    crc = 0
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x9003) if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


def _mc7_block(*, kind=0x0C, number=1, language=2, body=b"INERT!",
               descriptors=b"", starts=b"", padding=b"\x20",
               additional=bytes.fromhex("010004000000"), marker=None):
    """Pack the published 36-byte header/body/SBB/ADD/36-byte footer layout."""
    if marker is None:
        marker = 0x05 if kind in (0x0A, 0x0B) else 0x01
    sbb = (bytes([marker]) + struct.pack("<HHH", number, len(descriptors), len(starts))
           + descriptors + starts + padding)
    raw = bytearray(36 + len(body) + len(sbb) + len(additional) + 36)
    raw[:6] = bytes([0x70, 0x70, 1, 1, language, kind])
    struct.pack_into(">HI", raw, 6, number, len(raw))
    struct.pack_into(">HHHH", raw, 28, len(sbb), len(additional), 0, len(body))
    raw[36:36 + len(body)] = body
    sbb_offset = 36 + len(body)
    raw[sbb_offset:sbb_offset + len(sbb)] = sbb
    add_offset = sbb_offset + len(sbb)
    raw[add_offset:add_offset + len(additional)] = additional
    footer = len(raw) - 36
    raw[footer:footer + 8] = b"AUTHOR  "
    raw[footer + 8:footer + 16] = b"FAMILY  "
    raw[footer + 16:footer + 24] = b"BLOCK   "
    raw[footer + 24] = 0x21
    checksum = _reference_mc7_crc(bytes([kind]) + bytes(raw[34:36]) + body)
    struct.pack_into(">H", raw, footer + 26, checksum)
    return bytes(raw)


def _typed_interface_fixture():
    # INT STATIC_INIT, DINT STATIC_INIT, STRING[5] STATIC.
    descriptors = bytes([0x05, 0x0C, 0x07, 0x0C, 0x13, 0x04, 5])
    starts = struct.pack("<hi", -123, 0x01020304)
    interface = (b"\x05" + struct.pack("<HHH", 42, len(descriptors), len(starts))
                 + descriptors + starts + b"\x00")
    # S7 DB current values are big-endian and multibyte values are word-aligned.
    actual = bytes.fromhex("ff85010203040503414243000000")
    return interface, actual


def _dbf_table(fields, records, *, version=0x03, mdx=False, ldid=0x57):
    """Pack classic 32-byte DBF field descriptors and fixed-width records."""
    header_length = 32 + 32 * len(fields) + 1
    record_length = 1 + sum(field[2] for field in fields)
    header = bytearray(header_length)
    header[:4] = bytes([version, 126, 11, 5])  # 2026-11-05
    struct.pack_into("<IHH", header, 4, len(records), header_length, record_length)
    header[28] = int(mdx)
    header[29] = ldid
    for index, (name, kind, width, decimals, indexed) in enumerate(fields):
        offset = 32 + index * 32
        header[offset:offset + 11] = name.encode("ascii").ljust(11, b"\x00")
        header[offset + 11] = ord(kind)
        header[offset + 16] = width
        header[offset + 17] = decimals
        header[offset + 31] = int(indexed)
    header[-1] = 0x0D
    packed = []
    for deleted, values in records:
        assert len(values) == len(fields)
        row = (b"*" if deleted else b" ") + b"".join(values)
        assert len(row) == record_length
        packed.append(row)
    return bytes(header) + b"".join(packed) + b"\x1a"


def _typed_dbf_fixture():
    fields = [
        ("NAME", "C", 8, 0, False),
        ("COUNT", "N", 4, 0, True),
        ("ENABLED", "L", 1, 0, False),
        ("STAMP", "D", 8, 0, False),
        ("MEMO", "M", 10, 0, False),
    ]
    return _dbf_table(fields, [
        (False, [b"DB_MAIN ", b"  42", b"T", b"20261105", b"         3"]),
        (True, [b"OB_OLD  ", b"   1", b"F", b"20200102", b"          "]),
    ], version=0x8B, mdx=True)


def _dbt_file(payloads, *, name=b"SUBBLK", block_size=512):
    """Pack dBASE IV memo extents framed by ff ff 08 00."""
    extents = {
        pointer: (len(payload) + 8 + block_size - 1) // block_size
        for pointer, payload in payloads.items()
    }
    count = max((pointer + extents[pointer] for pointer in payloads), default=1)
    raw = bytearray(count * block_size)
    struct.pack_into("<I", raw, 0, count)
    raw[8:16] = name[:8].ljust(8, b"\x00")
    raw[16] = 0
    struct.pack_into("<H", raw, 20, block_size)
    for pointer, payload in payloads.items():
        offset = pointer * block_size
        raw[offset:offset + 4] = b"\xff\xff\x08\x00"
        struct.pack_into("<I", raw, offset + 4, len(payload) + 8)
        raw[offset + 8:offset + 8 + len(payload)] = payload
    return bytes(raw)


def _mdx_fixture():
    """Pack one 32-byte MDX tag-directory entry and its tag header page."""
    block_size, pages = 1024, 4
    raw = bytearray(block_size * pages)
    raw[:4] = bytes([2, 126, 11, 5])
    raw[4:20] = b"BAUSTEIN".ljust(16, b"\x00")
    struct.pack_into("<HH", raw, 20, block_size, 2)
    raw[24:27] = bytes([1, 47, 32])
    struct.pack_into("<H", raw, 28, 1)
    struct.pack_into("<I", raw, 32, pages)
    struct.pack_into("<I", raw, 544, 2)
    raw[548:559] = b"ID".ljust(11, b"\x00")
    raw[559] = 0x10
    raw[564] = ord("N")
    tag = 2 * block_size
    struct.pack_into("<II", raw, tag, 3, 1)
    raw[tag + 8] = 0x58  # descending, field/string, unique
    raw[tag + 9] = ord("N")
    struct.pack_into("<HHHHH", raw, tag + 12, 12, 20, 0, 16, 1)
    raw[tag + 20:tag + 23] = bytes.fromhex("341256")
    raw[tag + 23] = 1
    raw[tag + 24:tag + 34] = b"ID\x00ACTIVE\x00"
    return bytes(raw)


def _project_fixture():
    """Pack a documented BAUSTEIN.ID -> SUBBLK.OBJECTID compiled-DB join."""
    baustein_fields = [
        ("ID", "N", 5, 0, True),
        ("TYP", "N", 3, 0, False),
        ("NUMMER", "N", 5, 0, False),
    ]
    baustein = _dbf_table(
        baustein_fields,
        [(False, [b"   42", b" 10", b"    7"])],
        version=0x8B,
    )
    subblk_fields = [
        ("OBJECTID", "N", 5, 0, False),
        ("SUBBLKTYP", "N", 3, 0, False),
        ("MC5LEN", "N", 6, 0, False),
        ("SSBLEN", "N", 6, 0, False),
        ("MC5CODE", "M", 10, 0, False),
        ("SSBPART", "M", 10, 0, False),
    ]
    descriptor = bytes([0x05, 0x04])  # INT STATIC
    interface = b"\x05" + struct.pack("<HHH", 7, len(descriptor), 0) + descriptor
    subblk = _dbf_table(subblk_fields, [(False, [
        b"   42", b" 10", b"     2", b"     9", b"         1", b"         2",
    ])], version=0x8B)
    return {
        "P/BAUSTEIN.DBF": baustein,
        "P/SUBBLK.DBF": subblk,
        "P/SUBBLK.DBT": _dbt_file({1: b"\x12\x34", 2: interface}),
    }


def test_vector_mc7_interface_locks_endianness_alignment_and_string_layout():
    interface_bytes, actual = _typed_interface_fixture()
    parsed = engine.parse_mc7_interface(interface_bytes, actual)

    assert (parsed["marker"], parsed["reference_number"]) == ("data-block", 42)
    assert [item["data_type"] for item in parsed["descriptors"]] == [
        "INT", "DINT", "STRING",
    ]
    assert [(item["path"], item["value"]) for item in parsed["start_values"]] == [
        ("STATIC[0]", -123),
        ("STATIC[1]", 0x01020304),
    ]
    assert [(item["byte_offset"], item["data_type"], item["value"])
            for item in parsed["db_values"][:2]] == [
        (0, "INT", -123),
        (2, "DINT", 0x01020304),
    ]
    assert parsed["db_values"][2]["byte_offset"] == 6
    assert parsed["db_values"][2]["value"] == {
        "maximum": 5, "length": 3, "text": "ABC",
    }
    assert parsed["db_values_consumed"] == 13
    assert parsed["db_value_slack_hex"] == "00"


def _decode_s5time(raw):
    descriptor = bytes([0x0C, 0x04])  # S5TIME STATIC
    interface = b"\x05" + struct.pack("<HHH", 1, len(descriptor), 0) + descriptor
    return engine.parse_mc7_interface(interface, raw)["db_values"][0]["value"]


def test_vector_s5time_locks_published_bcd_and_time_base_semantics():
    # 0x2127: time base 2 (one second) and packed-BCD magnitude 127.
    assert _decode_s5time(bytes.fromhex("2127")) == {
        "milliseconds": 127_000,
        "valid": True,
    }


def test_vector_s5time_ignores_documented_reserved_high_bits():
    # Siemens documents bits 15-14 as ignored; E127 has the same base/BCD as 2127.
    assert _decode_s5time(bytes.fromhex("e127")) == {
        "milliseconds": 127_000,
        "valid": True,
    }


def _decode_any(raw):
    descriptor = bytes([0x16, 0x04])  # ANY STATIC
    interface = b"\x05" + struct.pack("<HHH", 1, len(descriptor), 0) + descriptor
    return engine.parse_mc7_interface(interface, raw)["db_values"][0]["value"]


def test_vector_any_data_area_locks_documented_bit_address_layout():
    # BYTE[10] at DB10.DBX5.0: bytes 7..9 contain the 24-bit bit address 40.
    assert _decode_any(bytes.fromhex("1002000a000a84000028")) == {
        "syntax_id": 0x10,
        "element_type": 0x02,
        "repeat": 10,
        "db_number": 10,
        "area": 0x84,
        "byte_offset": 5,
        "bit_offset": 0,
    }


def test_vector_any_timer_uses_documented_parameter_number_layout():
    # Siemens: for BLOCK/COUNTER/TIMER, byte 6 repeats the type, byte 7 is
    # zero, and bytes 8..9 are the parameter number rather than a bit address.
    assert _decode_any(bytes.fromhex("101d000100001d000002")) == {
        "syntax_id": 0x10,
        "element_type": 0x1D,
        "repeat": 1,
        "parameter_type": "TIMER",
        "parameter_number": 2,
    }


def test_vector_mc7_block_locks_published_sections_footer_and_crc():
    parsed = engine.parse_mc7_block(_mc7_block())
    metadata = parsed["metadata"]

    assert (metadata["block_type"], metadata["block_number"], metadata["language"]) == (
        "FC", 1, "KOP",
    )
    assert (metadata["load_size"], metadata["mc7_size"], metadata["sbb_size"],
            metadata["segment_size"], metadata["local_data_size"]) == (92, 6, 8, 6, 0)
    assert parsed["sections"]["mc7_code_or_db_values"]["hex"] == "494e45525421"
    assert parsed["sections"]["sbb"]["hex"] == "0101000000000020"
    assert parsed["sections"]["additional_info"]["hex"] == "010004000000"
    assert (metadata["author"], metadata["family"], metadata["name"],
            metadata["version"]) == ("AUTHOR", "FAMILY", "BLOCK", "2.1")
    assert parsed["checksum"] == {
        "stored": 0x65B2, "calculated": 0x65B2, "valid": True,
    }
    assert parsed["segment_table"]["network_offsets"] == [0]


def test_vector_dbf_locks_classic_field_and_record_semantics():
    parsed = engine.parse_dbf(_typed_dbf_fixture())

    assert (parsed["version"], parsed["last_update"], parsed["encoding"]) == (
        0x8B, "2026-11-05", "cp1252",
    )
    assert parsed["production_mdx"] is True
    assert parsed["fields"][1]["indexed"] is True
    assert parsed["records"][0]["values"] == {
        "NAME": "DB_MAIN",
        "COUNT": 42,
        "ENABLED": True,
        "STAMP": "2026-11-05",
        "MEMO": 3,
    }
    assert parsed["records"][1]["deleted"] is True
    assert parsed["records"][1]["values"]["MEMO"] is None
    assert parsed["eof_marker"] is True


def test_vector_dbt_locks_documented_memo_extent():
    payload = b"PLC-PROJECT-MEMO"
    parsed = engine.parse_dbt(_dbt_file({1: payload}))

    assert (parsed["block_size"], parsed["block_count"],
            parsed["next_free_block"], parsed["file_name"]) == (512, 2, 2, "SUBBLK")
    assert [memo["block"] for memo in parsed["memos"]] == [1]
    assert parsed["memos"][0]["payload"]["offset"] == 520
    assert parsed["memos"][0]["payload"]["hex"] == payload.hex()


def test_vector_mdx_locks_tag_directory_and_header_fields():
    parsed = engine.parse_mdx(_mdx_fixture())
    assert (parsed["file_name"], parsed["block_size"], parsed["page_count"],
            parsed["tag_count"]) == ("BAUSTEIN", 1024, 4, 1)
    tag = parsed["tags"][0]
    assert (tag["name"], tag["header_page"], tag["root_page"]) == ("ID", 2, 3)
    assert (tag["entry_key_format"], tag["entry_key_type"], tag["key_type"]) == (
        0x10, "N", "N",
    )
    assert (tag["key_length"], tag["max_keys_per_page"], tag["unique"]) == (
        12, 20, True,
    )
    assert tag["reserved_20_22_hex"] == "341256"
    assert tag["descending"] is True and tag["field_or_string"] is True
    assert (tag["key_expression"], tag["for_expression"]) == ("ID", "ACTIVE")


def test_vector_project_inventory_locks_baustein_subblk_join_and_db_value():
    parsed = engine.inventory_project(_project_fixture())

    assert parsed["file_count"] == 3
    assert parsed["associations"] == [
        {"table": "P/BAUSTEIN.DBF"},
        {"table": "P/SUBBLK.DBF", "memo": "P/SUBBLK.DBT"},
    ]
    assert len(parsed["project_blocks"]) == 1
    block = parsed["project_blocks"][0]
    assert (block["id"], block["block_type_code"], block["block_type"],
            block["block_number"], block["deleted"]) == (42, 10, "DB", 7, False)
    compiled = block["subblocks"][0]
    assert (compiled["subblock_type"], compiled["mc5code"]["hex"],
            compiled["ssbpart"]["hex"]) == (10, "1234", "050700020000000504")
    value = compiled["interface"]["db_values"][0]
    assert (value["data_type"], value["byte_offset"], value["value"]) == (
        "INT", 0, 0x1234,
    )


def _accept_clean_or_declared_error(function, *args):
    try:
        function(*args)
    except engine.S7DeepError:
        pass


@pytest.mark.parametrize("function,fixture", [
    (engine.parse_mc7_interface, _typed_interface_fixture()[0]),
    (engine.parse_mc7_block, _mc7_block()),
    (engine.parse_dbf, _typed_dbf_fixture()),
    (engine.parse_dbt, _dbt_file({1: b"memo"})),
    (engine.parse_mdx, _mdx_fixture()),
])
def test_binary_parsers_fail_closed_on_random_truncation_and_bitflips(function, fixture):
    rng = random.Random(0x573D33 + len(fixture))
    samples = [b"", b"\xff" * 64, rng.randbytes(73)]
    cuts = set(range(min(len(fixture), 80)))
    cuts.update({len(fixture) // 4, len(fixture) // 2, len(fixture) - 1})
    samples.extend(fixture[:cut] for cut in sorted(cuts) if 0 <= cut < len(fixture))
    for offset in (0, len(fixture) // 2, len(fixture) - 1):
        changed = bytearray(fixture)
        changed[offset] ^= 0x80
        samples.append(bytes(changed))

    for sample in samples:
        _accept_clean_or_declared_error(function, sample)


@pytest.mark.parametrize("function", [
    engine.parse_mc7_interface,
    engine.parse_mc7_block,
    engine.parse_dbf,
    engine.parse_dbt,
    engine.parse_mdx,
])
def test_binary_parsers_reject_wrong_types_released_buffers_and_oversize(function,
                                                                          monkeypatch):
    for value in (None, 1, "bytes", {}, [], object()):
        with pytest.raises(engine.S7DeepError):
            function(value)

    released = memoryview(b"x")
    released.release()
    with pytest.raises(engine.S7DeepError):
        function(released)

    monkeypatch.setattr(engine, "MAX_ARTIFACT", 64)
    with pytest.raises(engine.S7DeepError):
        function(b"x" * 65)


def test_interface_actual_values_argument_fails_closed_on_malformed_and_oversize(monkeypatch):
    interface, actual = _typed_interface_fixture()
    rng = random.Random(0xAC7A1)
    samples = [b"", b"\xff" * len(actual), rng.randbytes(len(actual)), actual[:-1]]
    for offset in (0, len(actual) // 2, len(actual) - 1):
        changed = bytearray(actual)
        changed[offset] ^= 0x80
        samples.append(bytes(changed))
    for sample in samples:
        _accept_clean_or_declared_error(engine.parse_mc7_interface, interface, sample)

    released = memoryview(actual)
    released.release()
    with pytest.raises(engine.S7DeepError):
        engine.parse_mc7_interface(interface, released)
    monkeypatch.setattr(engine, "MAX_ARTIFACT", 64)
    with pytest.raises(engine.S7DeepError):
        engine.parse_mc7_interface(interface, b"x" * 65)


def test_project_inventory_fails_closed_on_truncated_and_bitflipped_known_files():
    rng = random.Random(0xBA057E1)
    for path, fixture in _project_fixture().items():
        cuts = {0, 1, 2, 7, 31, len(fixture) // 2, len(fixture) - 1}
        samples = [b"", b"\xff" * 64, rng.randbytes(73)]
        samples.extend(fixture[:cut] for cut in sorted(cuts) if 0 <= cut < len(fixture))
        for offset in (0, len(fixture) // 2, len(fixture) - 1):
            changed = bytearray(fixture)
            changed[offset] ^= 0x80
            samples.append(bytes(changed))
        for sample in samples:
            _accept_clean_or_declared_error(engine.inventory_project, {path: sample})


@pytest.mark.parametrize("entries", [
    None,
    [None],
    [{}],
    [{"path": "x"}],
    [{"path": None, "data": b""}],
    [{"path": "x", "data": None}],
    [{"path": "X", "data": b""}, {"path": "x", "data": b""}],
])
def test_project_inventory_malformed_manifests_raise_only_declared_error(entries):
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project(entries)


def test_project_inventory_released_and_oversized_entries_fail_closed(monkeypatch):
    released = memoryview(b"x")
    released.release()
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"P/SUBBLK.DBF": released})

    monkeypatch.setattr(engine, "MAX_ARTIFACT", 64)
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"P/unknown.bin": b"x" * 65})
    monkeypatch.setattr(engine, "MAX_FILES", 1)
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"a.bin": b"", "b.bin": b""})
    monkeypatch.setattr(engine, "MAX_TOTAL", 1)
    with pytest.raises(engine.S7DeepError):
        engine.inventory_project({"a.bin": b"xx"})
