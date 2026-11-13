"""Independent vectors and fail-closed tests for the non-glibc allocator analyzer."""
from __future__ import annotations

import argparse
import json
import random

import pytest

import pwnalloc_scudo_v8 as alloc


SCUDO = alloc.SCUDO_PROFILE
V8 = alloc.V8_PROFILE
USER = 0x0000700000001000
COOKIE = 0x12345678


def _reference_scudo_word(
    class_id: int,
    state: int,
    origin_or_zeroed: int,
    size_or_unused: int,
    offset: int,
    checksum: int,
) -> int:
    """Direct transcription of LLVM chunk.h's documented LE bit positions."""

    return (
        class_id
        | (state << 8)
        | (origin_or_zeroed << 10)
        | (size_or_unused << 12)
        | (offset << 32)
        | (checksum << 48)
    )


def _reference_bsd_update(total: int, word: int) -> int:
    # Independent transcription of checksum.h::computeBSDChecksum for a 64-bit uptr.
    for byte_index in range(8):
        total = ((total >> 1) | ((total & 1) << 15)) & 0xFFFF
        total = (total + ((word >> (8 * byte_index)) & 0xFF)) & 0xFFFF
    return total


def _reference_bsd(cookie: int, pointer: int, header_without_checksum: int) -> int:
    return _reference_bsd_update(
        _reference_bsd_update(cookie & 0xFFFF, pointer), header_without_checksum
    )


def _reference_crc32c_update(crc: int, word: int) -> int:
    # Reflected Castagnoli operation used by x86 CRC32Q/ARM CRC32CD, without xor wrappers.
    for byte_index in range(8):
        crc ^= (word >> (8 * byte_index)) & 0xFF
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc & 0xFFFFFFFF


def _reference_crc32c(cookie: int, pointer: int, header_without_checksum: int) -> int:
    crc = _reference_crc32c_update(cookie, pointer)
    crc = _reference_crc32c_update(crc, header_without_checksum)
    return (crc ^ (crc >> 16)) & 0xFFFF


def test_scudo_compact_header_matches_llvm_layout_and_bsd_vector() -> None:
    base = _reference_scudo_word(5, 1, 0, 0x123, 2, 0)
    assert base == 0x0000000200123105
    checksum = _reference_bsd(COOKIE, USER, base)
    assert checksum == 0x10BA
    raw = _reference_scudo_word(5, 1, 0, 0x123, 2, checksum).to_bytes(8, "little")
    # Locked hand vector, not produced by the engine.
    assert raw == bytes.fromhex("05 31 12 00 02 00 ba 10")

    report = alloc.decode_scudo_header(
        raw,
        profile=SCUDO,
        cookie=COOKIE,
        user_pointer=USER,
        checksum_algorithm="bsd",
    )
    assert report.class_id == 5
    assert report.backend == "primary"
    assert report.state == "allocated"
    assert report.origin == "malloc"
    assert report.requested_size == 0x123
    assert report.unused_bytes is None
    assert report.offset_units == 2
    assert report.checksum == 0x10BA
    assert report.expected_checksum == 0x10BA
    assert report.checksum_status == "valid"


def test_scudo_crc32c_and_secondary_semantics_match_source_vectors() -> None:
    primary_base = _reference_scudo_word(5, 1, 0, 0x123, 2, 0)
    crc_checksum = _reference_crc32c(COOKIE, USER, primary_base)
    assert crc_checksum == 0x039B
    crc_raw = _reference_scudo_word(5, 1, 0, 0x123, 2, crc_checksum).to_bytes(8, "little")
    assert crc_raw == bytes.fromhex("05 31 12 00 02 00 9b 03")
    crc_report = alloc.decode_scudo_header(
        crc_raw,
        profile=SCUDO,
        cookie=COOKIE,
        user_pointer=USER,
        checksum_algorithm="crc32c",
    )
    assert crc_report.checksum_status == "valid"

    secondary_base = _reference_scudo_word(0, 2, 1, 0x321, 0, 0)
    secondary_checksum = _reference_bsd(COOKIE, USER, secondary_base)
    assert secondary_checksum == 0x5ABA
    secondary_raw = _reference_scudo_word(
        0, 2, 1, 0x321, 0, secondary_checksum
    ).to_bytes(8, "little")
    assert secondary_raw == bytes.fromhex("00 16 32 00 00 00 ba 5a")
    secondary = alloc.decode_scudo_header(
        secondary_raw,
        profile=SCUDO,
        cookie=COOKIE,
        user_pointer=USER,
        checksum_algorithm="bsd",
    )
    assert secondary.backend == "secondary"
    assert secondary.state == "quarantined"
    assert secondary.origin is None
    assert secondary.was_zeroed is True
    assert secondary.requested_size is None
    assert secondary.unused_bytes == 0x321
    assert secondary.checksum_status == "valid"


def test_scudo_integrity_is_never_inferred_and_tampering_is_reported() -> None:
    raw = bytes.fromhex("05 31 12 00 02 00 ba 10")
    assert alloc.decode_scudo_header(raw, profile=SCUDO).checksum_status == "unverified"

    changed = bytearray(raw)
    changed[2] ^= 0x01
    report = alloc.decode_scudo_header(
        bytes(changed),
        profile=SCUDO,
        cookie=COOKIE,
        user_pointer=USER,
        checksum_algorithm="bsd",
    )
    assert report.checksum_status == "invalid"
    assert "checksum mismatch" in report.anomalies


def test_scudo_size_class_reasoning_matches_fixed_map_boundaries() -> None:
    # FixedSizeClassMap parameters in pinned LLVM size_class_map.h:
    # NumBits=3, MinSizeLog=5, MidSizeLog=8, MaxSizeLog=17, delta=0.
    first = alloc.plan_scudo_allocation(16, profile=SCUDO)
    assert (first.needed_size, first.primary_class_id, first.primary_block_size) == (32, 1, 32)
    second = alloc.plan_scudo_allocation(17, profile=SCUDO)
    assert (second.needed_size, second.primary_class_id, second.primary_block_size) == (48, 2, 64)
    assert second.retry_class_ids[0] == 3
    final = alloc.plan_scudo_allocation(131056, profile=SCUDO)
    assert (final.needed_size, final.primary_class_id, final.primary_block_size) == (
        0x20000,
        44,
        0x20000,
    )
    assert final.retry_class_ids == ()
    secondary = alloc.plan_scudo_allocation(131057, profile=SCUDO)
    assert secondary.route == "secondary"
    assert secondary.primary_class_id is None

    caller = alloc.plan_scudo_allocation(
        17,
        profile=SCUDO,
        class_map="caller",
        class_sizes=[0x20, 0x30, 0x50],
    )
    assert (caller.primary_class_id, caller.primary_block_size, caller.retry_class_ids) == (
        2,
        0x30,
        (3,),
    )
    with pytest.raises(alloc.PwnAllocError, match="MaxAllowedMallocSize"):
        alloc.plan_scudo_allocation(1 << 40, profile=SCUDO)
    with pytest.raises(alloc.PwnAllocError, match="MaxAlignment"):
        alloc.plan_scudo_allocation(16, profile=SCUDO, alignment=1 << 25)
    with pytest.raises(alloc.PwnAllocError, match="min_alignment_log"):
        alloc.plan_scudo_allocation(16, profile=SCUDO, min_alignment_log=3)


def test_scudo_primary_and_secondary_chunk_geometry_uses_supplied_facts() -> None:
    primary = alloc.analyze_scudo_chunk(
        bytes.fromhex("05 31 12 00 02 00 ba 10"),
        profile=SCUDO,
        user_pointer=USER,
        min_alignment_log=4,
        class_sizes=[0x20, 0x40, 0x80, 0x100, 0x200],
        cookie=COOKIE,
        checksum_algorithm="bsd",
    )
    assert primary.header_size == 16
    assert primary.packed_header_address == USER - 16
    assert primary.offset_bytes == 32
    assert primary.block_begin == USER - 48
    assert primary.block_end == USER - 48 + 0x200
    assert primary.usable_size == 0x1D0
    assert primary.requested_size == 0x123
    assert primary.slack == 0xAD

    block_end = USER + 0x1000
    secondary = alloc.analyze_scudo_chunk(
        bytes.fromhex("00 16 32 00 00 00 ba 5a"),
        profile=SCUDO,
        user_pointer=USER,
        secondary_block_end=block_end,
        cookie=COOKIE,
        checksum_algorithm="bsd",
    )
    assert secondary.block_begin == USER - 16
    assert secondary.usable_size == 0x1000
    assert secondary.requested_size == 0x1000 - 0x321
    assert secondary.slack == 0x321

    with pytest.raises(alloc.PwnAllocError, match="minimum-alignment"):
        alloc.analyze_scudo_chunk(
            bytes.fromhex("05 31 12 00 02 00 ba 10"),
            profile=SCUDO,
            user_pointer=USER + 1,
            class_sizes=[0x20, 0x40, 0x80, 0x100, 0x200],
        )


def _v8_facts() -> dict[str, object]:
    sandbox = 0x200000000000
    external_pointer = 0x0000123456789000
    external_entry = external_pointer | (0x2A << 49) | (1 << 48)
    return {
        "platform": "x64",
        "sandbox_base": sandbox,
        "object_address": sandbox + 0x1000,
        "object_size": 32,
        "pointer_cage_base": sandbox,
        "external_pointer_table_base": 0x400000000000,
        "trusted_pointer_table_base": 0x500000000000,
        "fields": [
            {
                "name": "backing_store",
                "offset": 0,
                "kind": "sandboxed_pointer",
                "value": 0x123456780 << 24,
            },
            {
                "name": "map",
                "offset": 8,
                "kind": "compressed_tagged",
                "value": 0x12345679,
            },
            {
                "name": "external",
                "offset": 12,
                "kind": "external_handle",
                "value": 0x12345 << 6,
                "entry_word": external_entry,
                "expected_tag": 0x2A,
            },
            {
                "name": "trusted",
                "offset": 16,
                "kind": "trusted_handle",
                "value": 0x123 << 9,
            },
            {
                "name": "length_smi",
                "offset": 20,
                "kind": "compressed_tagged",
                "value": 84,
            },
        ],
    }


def test_v8_pointer_encodings_match_pinned_source_formulas() -> None:
    report = alloc.analyze_v8_layout(_v8_facts(), profile=V8)
    by_name = {field["name"]: field for field in report.fields}
    sandbox = 0x200000000000

    sandboxed = by_name["backing_store"]
    assert sandboxed["encoding_shift"] == 24  # 64 - log2(1 TiB)
    assert sandboxed["decoded_offset"] == 0x123456780
    assert sandboxed["decoded_pointer"] == sandbox + 0x123456780
    assert sandboxed["canonical_encoding"] is True

    compressed = by_name["map"]
    assert compressed["classification"] == "heap-object"
    assert compressed["tagged_address"] == sandbox + 0x12345679
    assert compressed["tag_bits"] == 1
    assert compressed["untagged_address"] == sandbox + 0x12345678
    assert compressed["weak"] is False

    external = by_name["external"]
    assert external["handle_shift"] == 6
    assert external["handle_index"] == 0x12345
    assert external["entry_address"] == 0x400000000000 + 0x12345 * 8
    assert external["entry_tag"] == 0x2A
    assert external["entry_marked"] is True
    assert external["tag_match"] is True
    assert external["resolved_pointer"] == 0x0000123456789000

    trusted = by_name["trusted"]
    assert trusted["handle_shift"] == 9
    assert trusted["handle_index"] == 0x123
    assert trusted["entry_address"] == 0x500000000000 + 0x123 * 8
    assert by_name["length_smi"]["smi_value"] == 42
    assert report.overlaps == ()


def test_v8_tag_mismatch_and_noncanonical_bits_are_evidence_not_resolution() -> None:
    facts = _v8_facts()
    fields = facts["fields"]
    assert isinstance(fields, list)
    fields[0]["value"] |= 0x55
    fields[2]["value"] |= 0x1F
    fields[2]["expected_tag"] = 0x2B
    report = alloc.analyze_v8_layout(facts, profile=V8)
    by_name = {field["name"]: field for field in report.fields}
    assert by_name["backing_store"]["canonical_encoding"] is False
    assert by_name["external"]["canonical_handle"] is False
    assert by_name["external"]["handle_index"] == 0x12345
    assert by_name["external"]["tag_match"] is False
    assert by_name["external"]["resolved_pointer"] is None


def test_v8_android_profile_and_trusted_entry_vectors() -> None:
    sandbox = 0x200000000000
    trusted_pointer = 0x0000123456789001
    trusted_tag = 0x0B
    trusted_entry = trusted_pointer | (trusted_tag << 49) | (1 << 48)
    facts = {
        "platform": "android64",
        "sandbox_base": sandbox,
        "object_address": sandbox + 0x2000,
        "object_size": 16,
        "external_pointer_table_base": 0x400000000000,
        "trusted_pointer_table_base": 0x500000000000,
        "fields": [
            {
                "name": "inside",
                "offset": 0,
                "kind": "sandboxed_pointer",
                "value": 0x1234 << 27,
            },
            {
                "name": "external",
                "offset": 8,
                "kind": "external_handle",
                "value": 0x21 << 7,
            },
            {
                "name": "trusted",
                "offset": 12,
                "kind": "trusted_handle",
                "value": 0x22 << 9,
                "entry_word": trusted_entry,
                "expected_tag": trusted_tag,
            },
        ],
    }
    report = alloc.analyze_v8_layout(facts, profile=V8)
    by_name = {field["name"]: field for field in report.fields}
    assert report.sandbox_size == 1 << 37
    assert by_name["inside"]["encoding_shift"] == 27
    assert by_name["external"]["handle_shift"] == 7
    assert by_name["trusted"]["entry_tag"] == trusted_tag
    assert by_name["trusted"]["entry_kind"] == "trusted-pointer"
    assert by_name["trusted"]["tagged_heap_object"] is True
    assert by_name["trusted"]["outside_sandbox"] is True
    assert by_name["trusted"]["resolved_pointer"] == trusted_pointer

    trusted_field = facts["fields"][2]
    trusted_field["entry_word"] = 0x0000123456789000 | (trusted_tag << 49)
    even = alloc.analyze_v8_layout(facts, profile=V8).fields[2]
    assert even["tagged_heap_object"] is False
    assert even["resolved_pointer"] is None

    trusted_field["entry_word"] = trusted_pointer | (0x7D << 49)
    trusted_field["expected_tag"] = 0x7D
    zapped = alloc.analyze_v8_layout(facts, profile=V8).fields[2]
    assert zapped["entry_kind"] == "zapped"
    assert zapped["tag_match"] is True
    assert zapped["resolved_pointer"] is None


def test_v8_protected_pointer_requires_a_trusted_source_and_target() -> None:
    trusted_cage = 0x500000000000
    facts = {
        "platform": "x64",
        "sandbox_base": 0x200000000000,
        "object_space": "trusted",
        "object_address": trusted_cage + 0x1000,
        "object_size": 8,
        "trusted_cage_base": trusted_cage,
        "fields": [
            {
                "name": "protected",
                "offset": 0,
                "kind": "protected_pointer",
                "value": 0x12345679,
            }
        ],
    }
    report = alloc.analyze_v8_layout(facts, profile=V8)
    protected = report.fields[0]
    assert protected["tagged_address"] == trusted_cage + 0x12345679
    assert protected["inside_sandbox"] is False

    facts["object_space"] = "sandbox"
    facts["object_address"] = 0x200000001000
    with pytest.raises(alloc.PwnAllocError, match="trusted objects"):
        alloc.analyze_v8_layout(facts, profile=V8)

    facts["object_space"] = "trusted"
    facts["object_address"] = 0x200000000000 + (1 << 40) - 4
    with pytest.raises(alloc.PwnAllocError, match="overlaps the sandbox"):
        alloc.analyze_v8_layout(facts, profile=V8)


def test_unknown_versions_and_unsupported_build_modes_are_declined() -> None:
    with pytest.raises(alloc.PwnAllocError, match="unknown Scudo profile"):
        alloc.decode_scudo_header(b"\0" * 8, profile="llvm-6-legacy-scudo")
    with pytest.raises(alloc.PwnAllocError, match="unknown V8 profile"):
        alloc.analyze_v8_layout(_v8_facts(), profile="v8-current")

    facts = _v8_facts()
    facts["platform"] = "old-code-pointer-table"
    with pytest.raises(alloc.PwnAllocError, match="unknown V8 platform"):
        alloc.analyze_v8_layout(facts, profile=V8)
    facts = _v8_facts()
    facts["lsan"] = True
    with pytest.raises(alloc.PwnAllocError, match="LSan"):
        alloc.analyze_v8_layout(facts, profile=V8)
    facts = _v8_facts()
    facts["fields"][0]["kind"] = "code_pointer_handle"
    with pytest.raises(alloc.PwnAllocError, match="unknown V8 field kind"):
        alloc.analyze_v8_layout(facts, profile=V8)

    facts = _v8_facts()
    facts["fields"][3]["entry_word"] = (0x123 << 49) | 0x123456789001
    facts["fields"][3]["expected_tag"] = 0x123
    with pytest.raises(alloc.PwnAllocError, match="expected_tag"):
        alloc.analyze_v8_layout(facts, profile=V8)


def _assert_declared_only(callable_) -> None:
    try:
        callable_()
    except alloc.PwnAllocError:
        return
    except Exception as exc:  # pragma: no cover - the assertion describes the contract
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_public_entrypoints_fail_closed_under_deterministic_fuzz() -> None:
    rng = random.Random(0xC5C7F)
    raw_inputs = [
        b"",
        b"\xff" * 8,
        bytes.fromhex("05 31 12"),
        bytes(rng.randrange(256) for _ in range(7)),
        bytes(rng.randrange(256) for _ in range(8)),
        bytes(rng.randrange(256) for _ in range(9)),
    ]
    for raw in raw_inputs:
        _assert_declared_only(lambda raw=raw: alloc.decode_scudo_header(raw, profile=SCUDO))
        _assert_declared_only(
            lambda raw=raw: alloc.analyze_scudo_chunk(
                raw,
                profile=SCUDO,
                user_pointer=USER,
                class_sizes=[0x20, 0x40],
            )
        )

    planner_values = [None, True, -1, 1 << 65, "x" * 100, rng.getrandbits(64)]
    for value in planner_values:
        _assert_declared_only(
            lambda value=value: alloc.plan_scudo_allocation(value, profile=SCUDO)
        )

    malformed_facts: list[object] = [
        None,
        b"random",
        {},
        {"platform": "x64"},
        {**_v8_facts(), "object_size": 1 << 30},
        {**_v8_facts(), "fields": [{}] * 257},
        {**_v8_facts(), "sandbox_base": UINT64_MAX},
    ]
    for value in malformed_facts:
        _assert_declared_only(
            lambda value=value: alloc.analyze_v8_layout(value, profile=V8)
        )


UINT64_MAX = (1 << 64) - 1


def test_cli_is_bounded_offline_and_argparse_guarded(tmp_path, monkeypatch, capsys) -> None:
    config = tmp_path / "header.json"
    config.write_text(json.dumps({
        "profile": SCUDO,
        "header_hex": "053112000200ba10",
        "cookie": COOKIE,
        "user_pointer": USER,
        "checksum_algorithm": "bsd",
    }))
    assert alloc.main(["scudo-header", str(config)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["checksum_status"] == "valid"
    assert output["offline_only"] is True

    assert alloc.main(["--not-an-action"]) == 2
    capsys.readouterr()

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (1 << 20) + b"}")
    assert alloc.main(["scudo-header", str(oversized)]) == 2
    assert "exceeds 1 MiB" in capsys.readouterr().err

    def non_integer_exit(self, args=None, namespace=None):
        raise SystemExit("not-an-int")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert alloc.main([]) == 2
