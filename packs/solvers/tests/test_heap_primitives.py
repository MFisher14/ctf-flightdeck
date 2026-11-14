from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import heap_primitives as primitives  # noqa: E402
import pwn_verify as verify  # noqa: E402


def _samples():
    return {
        "heap_primitives.build_heap_groom_plan": primitives.build_heap_groom_plan(
            chunk_size=0x90, live_chunks=5, holes=2, guard_chunks=1),
        "heap_primitives.build_uaf_reuse": primitives.build_uaf_reuse(
            glibc_version="2.35", freed_chunk_addr=0x55555000,
            chunk_size=0x90, replacement_addr=0x404040),
        "heap_primitives.build_double_free": primitives.build_double_free(
            glibc_version="2.31", chunk_addr=0x55555100,
            guard_or_next_addr=0x55555200, chunk_size=0x90),
        "heap_primitives.build_type_confusion": primitives.build_type_confusion(
            object_addr=0x404800, type_tag=3, data_pointer=0x404900,
            logical_length=0x80, call_pointer=0x401176),
        "heap_primitives.build_off_by_one": primitives.build_off_by_one(
            buffer_addr=0x55556000, overwrite_offset=0x40, replacement_byte=0x90),
        "heap_primitives.build_null_byte_poison": primitives.build_null_byte_poison(
            buffer_addr=0x55557000, victim_size_field_addr=0x55557040,
            original_size=0x191),
        "heap_primitives.build_integer_overflow_heap": primitives.build_integer_overflow_heap(
            header_addr=0x404A00, count=0x40000001, element_size=4,
            copy_count=16, integer_bits=32),
        "heap_primitives.build_cpp_vtable": primitives.build_cpp_vtable(
            object_addr=0x404B00, fake_vtable_addr=0x404C00,
            call_targets=(0x401176, 0x401200), original_fields=b"STATE123"),
    }


def test_groom_planner_is_bounded_deterministic_and_guarded() -> None:
    first = primitives.plan_heap_groom(
        chunk_size=0x90, live_chunks=6, holes=3, guard_chunks=2,
    )
    second = primitives.plan_heap_groom(
        chunk_size=0x90, live_chunks=6, holes=3, guard_chunks=2,
    )
    assert first == second
    assert len(first) <= primitives.MAX_GROOM_OPERATIONS
    assert [item.phase for item in first[:2]] == ["left-guard", "left-guard"]
    assert sum(item.opcode == "free" for item in first) == 3
    assert sum(item.phase == "controlled-refill" for item in first) == 3

    build = primitives.build_heap_groom_plan(
        chunk_size=0x90, live_chunks=6, holes=3, guard_chunks=2,
    )
    assert build.payload[:4] == b"R5BG"
    assert int.from_bytes(build.slice("header.count"), "little") == len(first)
    assert len(json.loads(build.metadata["operations"])) == len(first)


def test_uaf_route_switches_from_fastbin_to_tcache_and_preserves_maps() -> None:
    old = primitives.build_uaf_reuse(
        glibc_version="2.23", freed_chunk_addr=0x55555000,
        chunk_size=0x70, replacement_addr=0x404000,
    )
    modern = primitives.build_uaf_reuse(
        glibc_version="2.35", freed_chunk_addr=0x55555000,
        chunk_size=0x70, replacement_addr=0x404000,
    )
    assert "fastbin" in old.strategy
    assert "tcache" in modern.strategy
    assert "poisoned_fastbin_victim.fd" in old.placements
    assert "poisoned_tcache_entry.next" in modern.placements
    assert json.loads(modern.metadata["allocator_profile"])["safe_linking"] is True


def test_double_free_route_models_tcache_key_and_legacy_fastbin() -> None:
    old = primitives.build_double_free(
        glibc_version="2.25", chunk_addr=0x55555000,
        guard_or_next_addr=0x55555100, chunk_size=0x70,
    )
    keyed = primitives.build_double_free(
        glibc_version="2.31", chunk_addr=0x55555000,
        guard_or_next_addr=0x55555100, chunk_size=0x70,
    )
    assert "fastbin-dup" in old.strategy
    assert "tcache-dup" in keyed.strategy
    assert "key" in keyed.metadata["operations"]
    assert json.loads(keyed.metadata["grooming"])


def test_type_confusion_overlay_places_pointer_length_and_call_slot() -> None:
    build = _samples()["heap_primitives.build_type_confusion"]
    assert int.from_bytes(build.slice("type_tag"), "little") == 3
    assert int.from_bytes(build.slice("data_pointer"), "little") == 0x404900
    assert int.from_bytes(build.slice("logical_length"), "little") == 0x80
    assert int.from_bytes(build.slice("call_pointer"), "little") == 0x401176
    addresses = json.loads(build.metadata["address_map"])
    assert addresses["call_pointer"] == 0x404818


def test_off_by_one_and_null_poison_are_exact_distance_payloads() -> None:
    one = primitives.build_off_by_one(
        buffer_addr=0x1000, overwrite_offset=4, replacement_byte=0x90, fill_byte=0x42,
    )
    assert one.payload == b"BBBB\x90"
    assert one.placements["off_by_one"] == 4
    assert one.metadata["overwrite_address"] == "0x1004"

    null = primitives.build_null_byte_poison(
        buffer_addr=0x2000, victim_size_field_addr=0x2010, original_size=0x191,
    )
    assert null.payload == b"A" * 16 + b"\x00"
    assert null.slice("off_by_one") == b"\x00"
    assert "0x191->0x100" in null.metadata["constraints"]


def test_off_by_one_zero_prefix_and_address_space_boundaries() -> None:
    zero = primitives.build_off_by_one(
        buffer_addr=(1 << 64) - 1, overwrite_offset=0,
        replacement_byte=0x7F,
    )
    assert zero.payload == b"\x7f"
    assert dict(zero.placements) == {"off_by_one": 0}
    assert dict(zero.widths) == {"off_by_one": 1}
    assert zero.base_address + len(zero.payload) == 1 << 64

    adjacent = primitives.build_off_by_one(
        buffer_addr=(1 << 64) - 2, overwrite_offset=1,
        replacement_byte=0, fill_byte=0x41,
    )
    assert adjacent.payload == b"A\x00"
    assert adjacent.base_address + len(adjacent.payload) == 1 << 64
    assert adjacent.slice("controlled_prefix") == b"A"

    with pytest.raises(primitives.PrimitiveBuildError, match="crosses the 64-bit"):
        primitives.build_off_by_one(
            buffer_addr=(1 << 64) - 1, overwrite_offset=1,
            replacement_byte=0,
        )


def test_integer_wrap_template_proves_wrapped_allocation_is_smaller_than_copy() -> None:
    build = primitives.build_integer_overflow_heap(
        header_addr=0x404000, count=0x40000001, element_size=4,
        copy_count=16, integer_bits=32,
    )
    assert int.from_bytes(build.slice("count"), "little") == 0x40000001
    assert int.from_bytes(build.slice("wrapped_allocation"), "little") == 4
    assert build.metadata["mathematical_allocation"] == str(0x100000004)
    assert build.metadata["copy_bytes"] == "64"
    assert build.metadata["overflow_bytes"] == "60"


def test_integer_wrap_header_target_range_boundary() -> None:
    adjacent = primitives.build_integer_overflow_heap(
        header_addr=(1 << 64) - 16, count=0x40000001,
        element_size=4, copy_count=16, integer_bits=32,
    )
    assert adjacent.base_address + len(adjacent.payload) == 1 << 64

    with pytest.raises(primitives.PrimitiveBuildError, match="header crosses"):
        primitives.build_integer_overflow_heap(
            header_addr=(1 << 64) - 1, count=0x40000001,
            element_size=4, copy_count=16, integer_bits=32,
        )


def test_cpp_vtable_bundle_maps_discontiguous_target_addresses() -> None:
    build = primitives.build_cpp_vtable(
        object_addr=0x404000, fake_vtable_addr=0x405000,
        call_targets=(0x401000, 0x401100), original_fields=b"ABCDEFGH",
    )
    assert int.from_bytes(build.slice("object.vptr"), "little") == 0x405000
    assert build.slice("object.fields") == b"ABCDEFGH"
    assert int.from_bytes(build.slice("fake_vtable.entry[0]"), "little") == 0x401000
    assert int.from_bytes(build.slice("fake_vtable.entry[1]"), "little") == 0x401100
    address_map = json.loads(build.metadata["address_map"])
    assert address_map["fake_vtable.entry[1]"] == 0x405008


def test_cpp_vtable_refuses_overlapping_target_ranges() -> None:
    with pytest.raises(primitives.PrimitiveBuildError, match="target ranges overlap"):
        primitives.build_cpp_vtable(
            object_addr=0x404000, fake_vtable_addr=0x404008,
            call_targets=(0x401000, 0x401100), original_fields=b"A" * 16,
        )


@pytest.mark.parametrize(
    "call",
    [
        lambda: primitives.build_type_confusion(
            object_addr=0x1000, type_tag=1, data_pointer=0x2000,
            logical_length=4, bits=16),
        lambda: primitives.build_cpp_vtable(
            object_addr=0x1000, fake_vtable_addr=0x2000,
            call_targets=(0x3000,), bits=16),
        lambda: primitives.build_uaf_reuse(
            glibc_version="2.35", freed_chunk_addr=0x1000,
            chunk_size=0x20, replacement_addr=0x2000, bits=16),
    ],
)
def test_heap_object_builders_reject_non_32_64_word_sizes(call) -> None:
    with pytest.raises(primitives.PrimitiveBuildError, match="bits must be 32 or 64"):
        call()


def test_every_public_primitive_builder_has_a_static_roundtrip_sample() -> None:
    manifest = verify.make_manifest((primitives,), _samples())
    assert manifest.complete, manifest.missing
    assert all(record.evidence == "static-roundtrip" for record in manifest.records)


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: primitives.plan_heap_groom(chunk_size=0x91), "aligned"),
        (lambda: primitives.plan_heap_groom(chunk_size=0x90, live_chunks=65), "bounded"),
        (lambda: primitives.build_off_by_one(
            buffer_addr=1, overwrite_offset=primitives.MAX_OVERFLOW,
            replacement_byte=0), "overwrite_offset"),
        (lambda: primitives.build_null_byte_poison(
            buffer_addr=0x2000, victim_size_field_addr=0x2010,
            original_size=0x100), "smaller aligned"),
        (lambda: primitives.build_integer_overflow_heap(
            header_addr=1, count=4, element_size=4, copy_count=5), "does not overflow"),
        (lambda: primitives.build_cpp_vtable(
            object_addr=1, fake_vtable_addr=2, call_targets=()), "1..32"),
    ],
)
def test_invalid_primitive_templates_fail_closed(call, message: str) -> None:
    with pytest.raises(primitives.PrimitiveBuildError, match=message):
        call()
