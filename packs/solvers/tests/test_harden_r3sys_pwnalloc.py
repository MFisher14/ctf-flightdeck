"""Independent hardening vectors for ``pwnalloc_scudo_v8``.

The reference packers below directly transcribe LLVM Scudo's pinned
``UnpackedHeader`` fields/checksum and V8's pinned sandbox encoding formulas.
They do not call any encoder or private helper from the engine under test.
"""
from __future__ import annotations

import copy
import json
import random

import pytest

import pwnalloc_scudo_v8 as engine


SCUDO_PROFILE = "llvm-fae51e8f227c-scudo-standalone-le64"
V8_PROFILE = "v8-2e8a80edf4ac"


def pack_scudo_header(
    class_id: int,
    state: int,
    origin_or_zeroed: int,
    size_or_unused: int,
    offset_units: int,
    checksum: int,
) -> bytes:
    """Pack documented 8/2/2/20/16/16-bit LE fields by hand."""

    word = (
        class_id
        | (state << 8)
        | (origin_or_zeroed << 10)
        | (size_or_unused << 12)
        | (offset_units << 32)
        | (checksum << 48)
    )
    return word.to_bytes(8, "little")


def bsd_word_reference(checksum: int, word: int) -> int:
    """Direct eight-byte transcription of Scudo ``computeBSDChecksum``."""

    for byte_index in range(8):
        checksum = ((checksum >> 1) | ((checksum & 1) << 15)) & 0xFFFF
        checksum = (checksum + ((word >> (byte_index * 8)) & 0xFF)) & 0xFFFF
    return checksum


def bsd_checksum_reference(cookie: int, pointer: int, header_word: int) -> int:
    checksum = bsd_word_reference(cookie & 0xFFFF, pointer)
    return bsd_word_reference(checksum, header_word)


def test_scudo_full_width_fields_and_bsd_checksum_vector() -> None:
    """Lock chunk.h layout and checksum.h arithmetic at unrelated values."""

    cookie = 0xA5A55A5A
    pointer = 0x0000700012345000
    base_bytes = pack_scudo_header(17, 0, 1, 0xABCDE, 0x1234, 0)
    base_word = int.from_bytes(base_bytes, "little")
    assert base_word == 0x00001234ABCDE411
    checksum = bsd_checksum_reference(cookie, pointer, base_word)
    assert checksum == 0x447A
    raw = pack_scudo_header(17, 0, 1, 0xABCDE, 0x1234, checksum)
    assert raw == bytes.fromhex("11 e4 cd ab 34 12 7a 44")

    report = engine.decode_scudo_header(
        raw,
        profile=SCUDO_PROFILE,
        cookie=cookie,
        user_pointer=pointer,
        checksum_algorithm="bsd",
    )
    assert report.class_id == 17
    assert report.state == "available"
    assert report.origin is None
    assert report.was_zeroed is True
    assert report.size_or_unused_bytes == 0xABCDE
    assert report.offset_units == 0x1234
    assert report.checksum == report.expected_checksum == 0x447A
    assert report.checksum_status == "valid"


def test_scudo_alignment_plan_and_chunk_geometry_from_documented_formulas() -> None:
    # round_up(33, 16) + alignment(64) = 112; default fixed map selects 128.
    plan = engine.plan_scudo_allocation(
        33, profile=SCUDO_PROFILE, alignment=64
    )
    assert (plan.header_size, plan.needed_size) == (16, 112)
    assert (plan.primary_class_id, plan.primary_block_size) == (4, 128)

    # class=2, allocated/new-array, requested=0x50, one 16-byte offset unit.
    raw = pack_scudo_header(2, 1, 2, 0x50, 1, 0)
    pointer = 0x100000
    chunk = engine.analyze_scudo_chunk(
        raw,
        profile=SCUDO_PROFILE,
        user_pointer=pointer,
        class_sizes=[0x80, 0x100],
    )
    assert chunk.packed_header_address == pointer - 16
    assert chunk.offset_bytes == 16
    assert chunk.block_begin == pointer - 32
    assert chunk.block_end == pointer - 32 + 0x100
    assert (chunk.usable_size, chunk.requested_size, chunk.slack) == (224, 80, 144)


def v8_reference_facts() -> dict[str, object]:
    sandbox = 0x200000000000
    target_offset = 0x123456789A
    external_pointer = 0x0000123456789000
    tag = 0x35
    external_entry = external_pointer | (1 << 48) | (tag << 49)
    return {
        "platform": "x64",
        "sandbox_base": sandbox,
        "object_address": sandbox + 0x1000,
        "object_size": 32,
        "pointer_cage_base": sandbox,
        "external_pointer_table_base": 0x400000000000,
        "fields": [
            {
                "name": "buffer",
                "kind": "sandboxed_pointer",
                "offset": 0,
                "value": target_offset << 24,
            },
            {
                "name": "weak",
                "kind": "compressed_tagged",
                "offset": 8,
                "value": 0x2003,
            },
            {
                "name": "negative_smi",
                "kind": "compressed_tagged",
                "offset": 12,
                "value": 0xFFFFFFD6,
            },
            {
                "name": "external",
                "kind": "external_handle",
                "offset": 16,
                "value": 0x345 << 6,
                "entry_word": external_entry,
                "expected_tag": tag,
            },
        ],
    }


def test_v8_sandboxed_weak_smi_and_external_pointer_vectors() -> None:
    """Lock formulas from v8-internal.h and pointer-table entry layouts."""

    facts = v8_reference_facts()
    report = engine.analyze_v8_layout(facts, profile=V8_PROFILE)
    fields = {field["name"]: field for field in report.fields}
    sandbox = 0x200000000000

    assert fields["buffer"]["encoding_shift"] == 24
    assert fields["buffer"]["decoded_offset"] == 0x123456789A
    assert fields["buffer"]["decoded_pointer"] == sandbox + 0x123456789A
    assert fields["buffer"]["canonical_encoding"] is True

    assert fields["weak"]["classification"] == "heap-object"
    assert fields["weak"]["tag_bits"] == 3
    assert fields["weak"]["weak"] is True
    assert fields["weak"]["tagged_address"] == sandbox + 0x2003
    assert fields["weak"]["untagged_address"] == sandbox + 0x2000
    assert fields["negative_smi"]["classification"] == "smi"
    assert fields["negative_smi"]["smi_value"] == -21

    external = fields["external"]
    assert external["handle_shift"] == 6
    assert external["handle_index"] == 0x345
    assert external["entry_address"] == 0x400000000000 + 0x345 * 8
    assert external["entry_tag"] == 0x35
    assert external["entry_marked"] is True
    assert external["tag_match"] is True
    assert external["resolved_pointer"] == 0x0000123456789000


def test_v8_la57_external_and_trusted_table_entry_vectors() -> None:
    sandbox = 0x200000000000
    external_payload = 0x00123456789000
    trusted_payload = 0x00123456789001
    external_tag, trusted_tag = 0x2A, 0x0B
    facts = {
        "platform": "x64",
        "la57": True,
        "sandbox_base": sandbox,
        "object_address": sandbox + 0x2000,
        "object_size": 8,
        "external_pointer_table_base": 0x400000000000,
        "trusted_pointer_table_base": 0x500000000000,
        "fields": [
            {
                "name": "external",
                "kind": "external_handle",
                "offset": 0,
                "value": 0x123 << 6,
                "entry_word": external_payload | (1 << 56) | (external_tag << 57),
                "expected_tag": external_tag,
            },
            {
                "name": "trusted",
                "kind": "trusted_handle",
                "offset": 4,
                "value": 0x321 << 9,
                "entry_word": trusted_payload | (1 << 56) | (trusted_tag << 57),
                "expected_tag": trusted_tag,
            },
        ],
    }
    report = engine.analyze_v8_layout(facts, profile=V8_PROFILE)
    external, trusted = report.fields
    assert (external["entry_tag"], external["entry_marked"]) == (external_tag, True)
    assert external["payload_candidate"] == external_payload
    assert external["resolved_pointer"] == external_payload
    assert (trusted["entry_tag"], trusted["entry_marked"]) == (trusted_tag, True)
    assert trusted["entry_kind"] == "trusted-pointer"
    assert trusted["payload_candidate"] == trusted_payload
    assert trusted["resolved_pointer"] == trusted_payload


def assert_declared_or_clean(callable_) -> None:
    try:
        callable_()
    except engine.PwnAllocError:
        pass
    except Exception as exc:  # pragma: no cover - this is the contract assertion
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_scudo_public_entrypoints_fail_closed_for_bytes_and_scalar_fuzz() -> None:
    valid = pack_scudo_header(2, 1, 2, 0x50, 1, 0)
    rng = random.Random(0xA110C)
    byte_samples: list[object] = [
        b"",
        rng.randbytes(8),
        b"\xff" * 8,
        valid[:3],
        valid[:-1],
        valid + b"\0",
        memoryview(valid),
        None,
        "not bytes",
    ]
    for index in range(len(valid)):
        changed = bytearray(valid)
        changed[index] ^= 1 << (index % 8)
        byte_samples.append(bytes(changed))

    released = memoryview(valid)
    released.release()
    byte_samples.append(released)
    for sample in byte_samples:
        assert_declared_or_clean(
            lambda sample=sample: engine.decode_scudo_header(
                sample, profile=SCUDO_PROFILE
            )
        )
        assert_declared_or_clean(
            lambda sample=sample: engine.analyze_scudo_chunk(
                sample,
                profile=SCUDO_PROFILE,
                user_pointer=0x100000,
                class_sizes=[0x80, 0x100],
            )
        )

    for request in (None, True, -1, 0, 1 << 40, 1 << 65, "x", "9" * 81):
        assert_declared_or_clean(
            lambda request=request: engine.plan_scudo_allocation(
                request, profile=SCUDO_PROFILE
            )
        )
    assert_declared_or_clean(
        lambda: engine.plan_scudo_allocation(
            1,
            profile=SCUDO_PROFILE,
            class_map="caller",
            class_sizes=list(range(256)),
        )
    )


def test_v8_public_entrypoint_fail_closed_for_malformed_and_bitflipped_facts() -> None:
    valid = v8_reference_facts()
    malformed: list[object] = [
        None,
        b"random",
        {},
        {"platform": "x64"},
        {**copy.deepcopy(valid), "fields": []},
        {**copy.deepcopy(valid), "fields": [{}] * 257},
        {**copy.deepcopy(valid), "object_size": (1 << 20) + 1},
        {**copy.deepcopy(valid), "sandbox_base": (1 << 64) - 1},
    ]
    bitflipped = copy.deepcopy(valid)
    bitflipped["fields"][1]["value"] ^= 1 << 31
    malformed.append(bitflipped)
    for facts in malformed:
        assert_declared_or_clean(
            lambda facts=facts: engine.analyze_v8_layout(facts, profile=V8_PROFILE)
        )


def test_cli_dispatches_all_documented_actions_to_vector_locked_results(
        tmp_path, capsys) -> None:
    header = pack_scudo_header(2, 1, 2, 0x50, 1, 0)
    cases = [
        ("scudo-header", {
            "profile": SCUDO_PROFILE,
            "header_hex": header.hex(),
        }, ("class_id", 2)),
        ("scudo-plan", {
            "profile": SCUDO_PROFILE,
            "request_size": 33,
            "alignment": 64,
        }, ("needed_size", 112)),
        ("scudo-chunk", {
            "profile": SCUDO_PROFILE,
            "header_hex": header.hex(),
            "user_pointer": 0x100000,
            "class_sizes": [0x80, 0x100],
        }, ("block_begin", 0x100000 - 32)),
        ("v8-layout", {
            "profile": V8_PROFILE,
            **v8_reference_facts(),
        }, ("sandbox_size", 1 << 40)),
    ]
    for index, (action, config, expected) in enumerate(cases):
        path = tmp_path / f"valid-{index}.json"
        path.write_text(json.dumps(config))
        assert engine.main([action, str(path)]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result[expected[0]] == expected[1]
        assert result["offline_only"] is True


def test_cli_malformed_json_fails_cleanly(tmp_path, capsys) -> None:
    valid = json.dumps({
        "profile": SCUDO_PROFILE,
        "header_hex": pack_scudo_header(2, 1, 2, 0x50, 1, 0).hex(),
    }).encode()
    samples = [
        b"",
        b"\xff" * 32,
        valid[: len(valid) // 2],
        bytes([valid[0] ^ 0x80]) + valid[1:],
        b"{" + b" " * (1 << 20) + b"}",
    ]
    for index, sample in enumerate(samples):
        path = tmp_path / f"malformed-{index}.json"
        path.write_bytes(sample)
        assert engine.main(["scudo-header", str(path)]) == 2
        capsys.readouterr()

    missing = tmp_path / "missing.json"
    for argv in ([], ["unknown", str(missing)], ["scudo-header", str(missing)],
                 [None], "wrong"):
        assert engine.main(argv) == 2
        capsys.readouterr()
