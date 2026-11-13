"""Independent vectors and fail-closed fuzz for the pwndepth subgroup."""

from __future__ import annotations

import json
from pathlib import Path
import random
import struct
from typing import Callable

import pytest

import pwndepth_fsop_verify as fsop
import pwndepth_heap_plans as heap
import pwndepth_pointer_guard as guard
import pwndepth_ret2dlresolve as dl


MASK64 = (1 << 64) - 1
BASE = 0x555555559000


def _only_declared(call: Callable[[], object], declared: type[Exception]) -> None:
    """A fuzz case may parse or reject, but must not leak another exception."""

    try:
        call()
    except BaseException as exc:  # includes an accidental argparse SystemExit
        assert isinstance(exc, declared), (
            f"leaked {type(exc).__name__}, expected only {declared.__name__}: {exc}"
        )


def _random_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


# ---------------------------------------------------------------------------
# Modern heap plans: published glibc macro and caller-addressed constraints.


def _reference_largebin_index(size: int) -> int:
    """Literal expansion of glibc malloc.c largebin_index_64."""

    if (size >> 6) <= 48:
        return 48 + (size >> 6)
    if (size >> 9) <= 20:
        return 91 + (size >> 9)
    if (size >> 12) <= 10:
        return 110 + (size >> 12)
    if (size >> 15) <= 4:
        return 119 + (size >> 15)
    if (size >> 18) <= 2:
        return 124 + (size >> 18)
    return 126


def _water_config() -> dict[str, object]:
    return {
        "glibc_version": "2.41",
        "tcache_chunk_header_addr": BASE,
        "relative_chunk_addr": BASE + 0x2A0,
        "small_start_addr": BASE + 0x350,
        "small_end_addr": BASE + 0x400,
        "primitive": "uaf",
        "tcache_capacity": 7,
        "guards_present": True,
        "can_forge_chunk_sizes": True,
        "can_restore_chunk_sizes": True,
        "can_corrupt_link_lsb": True,
        "can_free_interior_headers": True,
        "allow_bruteforce": False,
    }


def _large_config(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "glibc_version": "2.39",
        "existing_chunk_addr": 0x555555570000,
        "existing_chunk_size": 0x4E0,
        "victim_chunk_addr": 0x555555572000,
        "victim_chunk_size": 0x4D0,
        "target_addr": 0x7FFFF7FC5000,
        "bin_head_addr": 0x7FFFF7FC4A00,
        "sort_request": 0x4E8,
        "guards_present": True,
        "target_writable": True,
        "arena_managed": True,
    }
    result.update(changes)
    return result


def _banana_layout() -> heap.BananaLayout:
    return heap.BananaLayout(
        size=0x4B8,
        l_addr=0,
        l_real=0x28,
        l_next=0x18,
        l_ns=0x30,
        l_init_called=0x354,
        l_init_called_mask=0x10,
        l_info=0x40,
        l_info_slots=84,
        l_init_called_width=4,
    )


def _banana_config() -> dict[str, object]:
    return {
        "glibc_version": "2.39",
        "large_bin_plan": heap.build_large_bin_plan(**_large_config()),
        "layout": _banana_layout(),
        "fake_link_map_addr": 0x555555572000,
        "loader_link_slot_addr": 0x7FFFF7FC5000,
        "replaced_map_addr": 0x7FFFF7FFD000,
        "replaced_map_next_addr": 0x7FFFF7FFC000,
        "fini_dyn_addr": 0x555555580000,
        "fini_array_size_dyn_addr": 0x555555580020,
        "fini_array_addr": 0x555555580040,
        "call_target": 0x7FFFF7E12340,
        "namespace_nloaded": 4,
        "real_maps_before_fake": 0,
        "real_maps_after_fake": 3,
        "l_addr": 0,
        "namespace_id": 0,
        "cleanup_trigger": "exit",
        "replaces_real_map": True,
        "zeroed_backing": True,
        "sort_dependencies_safe": True,
        "audit_modules_present": False,
    }


def test_heap_vector_lock_glibc_largebin_macro_and_constrained_write() -> None:
    for size in (0x400, 0x430, 0xC00, 0xC40, 0x2800, 0xA000, 0x10000, 0x40000, 0x100000):
        assert heap.largebin_index_64(size) == _reference_largebin_index(size)

    plan = heap.build_large_bin_plan(**_large_config())
    # From glibc's post-2.30 insertion statements: victim->bk_nextsize->fd_nextsize = victim.
    assert plan.computed_dict()["forged_bk_nextsize"] == 0x7FFFF7FC5000 - 0x20
    assert plan.computed_dict()["written_value"] == 0x555555572000
    assert plan.writes[0].address == 0x555555570000 + 0x28
    assert plan.writes[0].value == 0x7FFFF7FC5000 - 0x20


def test_heap_all_public_planners_and_verifier_fail_closed_fuzz() -> None:
    scalar_cases = (None, "", "0x", -1, 0x431, 1 << 80, [], {}, _random_bytes(1, 8))
    for value in scalar_cases:
        _only_declared(lambda value=value: heap.largebin_index_64(value), heap.PwnDepthHeapError)

    builders: tuple[tuple[Callable[..., object], dict[str, object], str], ...] = (
        (heap.build_house_of_water_plan, _water_config(), "relative_chunk_addr"),
        (heap.build_large_bin_plan, _large_config(), "existing_chunk_addr"),
        (heap.build_house_of_banana_plan, _banana_config(), "fake_link_map_addr"),
    )
    mutations = (None, "", _random_bytes(2, 13), 1, 1 << 80)
    for builder, valid, field in builders:
        # empty/random, truncated-valid, bit-flipped, and oversized field values
        _only_declared(lambda builder=builder: builder(**{}), heap.PwnDepthHeapError)
        truncated = dict(valid)
        truncated.pop(field)
        _only_declared(
            lambda builder=builder, truncated=truncated: builder(**truncated),
            heap.PwnDepthHeapError,
        )
        for mutation in mutations:
            changed = dict(valid)
            changed[field] = mutation
            _only_declared(
                lambda builder=builder, changed=changed: builder(**changed),
                heap.PwnDepthHeapError,
            )
        flipped = dict(valid)
        flipped[field] = int(valid[field]) ^ 1
        _only_declared(
            lambda builder=builder, flipped=flipped: builder(**flipped),
            heap.PwnDepthHeapError,
        )

    plan = heap.build_large_bin_plan(**_large_config())
    facts = {fact.address: fact.value for fact in plan.facts if fact.phase == "armed"}
    verifier_cases: tuple[object, ...] = (
        {},
        {1: _random_bytes(3, 8)},
        dict(list(facts.items())[:-1]),
        {**facts, next(iter(facts)): facts[next(iter(facts))] ^ 1},
        {**facts, 1 << 80: 0},
    )
    for memory in verifier_cases:
        _only_declared(
            lambda memory=memory: heap.verify_plan_phase(plan, memory, phase="armed"),
            heap.PwnDepthHeapError,
        )


def test_public_layout_validators_and_profile_lookup_fail_closed() -> None:
    banana_cases = (
        heap.BananaLayout(0, 0, 8, 16, 24, 32, 0x10, 64, 84),
        heap.BananaLayout(0x500, 0, 8, 16, 24, 32, 3, 64, 84),
        heap.BananaLayout(0x500, 0, 8, 16, 24, 32, 0x10, 32, 84),
        heap.BananaLayout(1 << 80, 0, 8, 16, 24, 32, 0x10, 64, 84),
    )
    for layout in banana_cases:
        _only_declared(layout.validate, heap.PwnDepthHeapError)

    offset_cases = (
        fsop.Apple2Offsets(file_size=7),
        fsop.Apple2Offsets(file_size=1 << 40),
        fsop.Apple2Offsets(file_vtable=0xD9),
        fsop.Apple2Offsets(file_lock=0x20, file_write_base=0x20),
    )
    for offsets in offset_cases:
        _only_declared(offsets.validate, fsop.PwnDepthFSOPError)

    profile = dl.inspect_elf(_reference_elf(), plt0=0x400100)
    for tag in (None, "", -1, 1 << 80, [], {}, _random_bytes(17, 8)):
        _only_declared(
            lambda tag=tag: profile.runtime_tag(tag),
            dl.PwnDepthRet2DlError,
        )


def test_heap_json_cli_fuzz_categories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    valid = json.dumps(_large_config()).encode()
    payloads = {
        "empty": b"",
        "random": _random_bytes(4, 41),
        "truncated": valid[:-5],
        "bitflip": valid[:10] + bytes((valid[10] ^ 0x80,)) + valid[11:],
    }
    for name, payload in payloads.items():
        path = tmp_path / f"heap-{name}.json"
        path.write_bytes(payload)
        assert heap.main(["largebin", str(path)]) == 2
    monkeypatch.setattr(heap, "MAX_JSON", 64)
    oversized = tmp_path / "heap-oversized.json"
    oversized.write_bytes(b"{" + b" " * 64 + b"}")
    assert heap.main(["largebin", str(oversized)]) == 2


# ---------------------------------------------------------------------------
# FSOP: hand-packed documented LP64 _IO_FILE/_IO_wide_data semantics.


FILE = 0x404800
WIDE = 0x404900
WVT = 0x404A00
LOCK = 0x404B00
WFILE_JUMPS = 0x7FFFF7FA10C0
TARGET = 0x7FFFF7E12340


def _fsop_offsets() -> fsop.Apple2Offsets:
    # Explicit glibc LP64 offsets, not values read back from an engine report.
    return fsop.Apple2Offsets(
        file_size=0xE0, file_flags=0, file_write_base=0x20,
        file_write_ptr=0x28, file_vtable_offset=0x82, file_lock=0x88,
        file_wide_data=0xA0, file_mode=0xC0, file_vtable=0xD8,
        wide_size=0xE8, wide_write_base=0x18, wide_write_ptr=0x20,
        wide_buf_base=0x30, wide_vtable=0xE0,
        jump_size=0x70, jump_doallocate=0x68, lock_size=0x10,
    )


def _pack_qword(blob: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", blob, offset, value)


def _fsop_candidate() -> dict[str, object]:
    p = _fsop_offsets()
    file_blob = bytearray(p.file_size)
    wide_blob = bytearray(p.wide_size)
    jump_blob = bytearray(p.jump_size)
    struct.pack_into("<I", file_blob, p.file_flags, 0)
    _pack_qword(file_blob, p.file_write_base, 0)
    _pack_qword(file_blob, p.file_write_ptr, 1)
    _pack_qword(file_blob, p.file_lock, LOCK)
    _pack_qword(file_blob, p.file_wide_data, WIDE)
    struct.pack_into("<i", file_blob, p.file_mode, 1)
    _pack_qword(file_blob, p.file_vtable, WFILE_JUMPS)
    _pack_qword(wide_blob, p.wide_write_base, 0)
    _pack_qword(wide_blob, p.wide_write_ptr, 1)
    _pack_qword(wide_blob, p.wide_buf_base, 0)
    _pack_qword(wide_blob, p.wide_vtable, WVT)
    _pack_qword(jump_blob, p.jump_doallocate, TARGET)
    return {
        "glibc_version": "2.39",
        "trigger": "exit_flush",
        "file_blob": bytes(file_blob),
        "file_address": FILE,
        "lock_blob": bytes(p.lock_size),
        "wide_blob": bytes(wide_blob),
        "wide_address": WIDE,
        "wide_vtable_blob": bytes(jump_blob),
        "wide_vtable_address": WVT,
        "io_wfile_jumps": WFILE_JUMPS,
        "vtable_section_start": 0x7FFFF7FA0000,
        "vtable_section_end": 0x7FFFF7FA8000,
        "call_target": TARGET,
        "writable_ranges": ((0x404000, 0x405000),),
        "executable_ranges": ((0x7FFFF7E00000, 0x7FFFF7F00000),),
        "trigger_reachable": True,
        "offsets": p,
    }


def test_fsop_vector_lock_hand_packed_dispatch_chain() -> None:
    result = fsop.verify_apple2(**_fsop_candidate())
    assert result.file_address == FILE
    assert result.lock_address == LOCK
    assert result.file_write_base == 0 and result.file_write_ptr == 1
    assert result.wide_write_base == 0 and result.wide_write_ptr == 1
    assert result.wide_buf_base == 0
    assert result.io_wfile_jumps == WFILE_JUMPS
    assert result.call_target == TARGET


def test_fsop_verify_entrypoint_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    valid = _fsop_candidate()
    cases: list[dict[str, object]] = []
    cases.append({})
    cases.append({"file_blob": _random_bytes(5, 31)})
    truncated = dict(valid)
    truncated["file_blob"] = bytes(valid["file_blob"])[:-1]
    cases.append(truncated)
    flipped = dict(valid)
    file_blob = bytearray(valid["file_blob"])
    file_blob[0xD8] ^= 1
    flipped["file_blob"] = bytes(file_blob)
    cases.append(flipped)
    monkeypatch.setattr(fsop, "MAX_BLOB", 256)
    oversized = dict(valid)
    oversized["file_blob"] = b"A" * 257
    cases.append(oversized)
    for case in cases:
        _only_declared(
            lambda case=case: fsop.verify_apple2(**case),
            fsop.PwnDepthFSOPError,
        )


def test_fsop_json_cli_fuzz_categories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Hex strings exercise only the bounded decoder; the semantic vector is above.
    seed = json.dumps({"file_blob_hex": "00"}).encode()
    payloads = (b"", _random_bytes(6, 29), seed[:-1], bytes((seed[0] ^ 1,)) + seed[1:])
    for index, payload in enumerate(payloads):
        path = tmp_path / f"fsop-{index}.json"
        path.write_bytes(payload)
        assert fsop.main([str(path)]) == 2
    monkeypatch.setattr(fsop, "MAX_JSON", 32)
    path = tmp_path / "fsop-oversized.json"
    path.write_bytes(b"{" + b" " * 32 + b"}")
    assert fsop.main([str(path)]) == 2


# ---------------------------------------------------------------------------
# Pointer guard: direct translation of glibc x86-64 PTR_MANGLE/PTR_DEMANGLE.


def _reference_mangle(pointer: int, pointer_guard: int) -> int:
    value = (pointer ^ pointer_guard) & MASK64
    return ((value << 17) & MASK64) | (value >> 47)


def _reference_demangle(stored: int, pointer_guard: int) -> int:
    rotated = (stored >> 17) | ((stored & ((1 << 17) - 1)) << 47)
    return (rotated ^ pointer_guard) & MASK64


def test_pointer_guard_vector_lock_glibc_formula_and_record_layouts() -> None:
    pointer = 0x7FFFF7E12340
    cookie = 0x0123456789ABCDEF
    expected = _reference_mangle(pointer, cookie)
    assert guard.mangle_pointer(pointer, cookie) == expected
    assert guard.demangle_pointer(expected, cookie) == _reference_demangle(expected, cookie)
    assert guard.demangle_pointer(expected, cookie) == pointer

    exit_plan = guard.build_exit_function_plan(
        glibc_version="2.39", entry_address=0x55555555A000,
        function_address=pointer, pointer_guard=cookie, flavor="ef_cxa",
        argument_address=0x55555555B000, dso_handle=0x7FFFF7FC0000,
    )
    assert exit_plan.payload == struct.pack(
        "<QQQQ", 4, expected, 0x55555555B000, 0x7FFFF7FC0000
    )


def test_pointer_guard_every_public_function_fail_closed_fuzz() -> None:
    pointer = 0x7FFFF7E12340
    cookie = 0x0123456789ABCDEF
    scalar_cases = (None, "", "0x1", -1, 1 << 64, [], {}, _random_bytes(7, 8))
    for value in scalar_cases:
        _only_declared(
            lambda value=value: guard.mangle_pointer(value, cookie),
            guard.PwnDepthPointerGuardError,
        )
        _only_declared(
            lambda value=value: guard.demangle_pointer(value, cookie),
            guard.PwnDepthPointerGuardError,
        )

    slot_args = dict(
        glibc_version="2.39", slot_address=0x55555555A000,
        pointer=pointer, pointer_guard=cookie,
    )
    exit_args = dict(
        glibc_version="2.39", entry_address=0x55555555A000,
        function_address=pointer, pointer_guard=cookie, flavor="ef_cxa",
        argument_address=0x55555555B000, dso_handle=0x7FFFF7FC0000,
    )
    jmp_args = dict(
        glibc_version="2.39", rsp_slot_address=0x55555555C030,
        rip_slot_address=0x55555555C038, saved_rsp=0x7FFFFFFFE000,
        saved_rip=0x555555554320, pointer_guard=cookie,
    )
    for builder, valid, field in (
        (guard.build_mangled_slot_plan, slot_args, "slot_address"),
        (guard.build_exit_function_plan, exit_args, "entry_address"),
        (guard.build_jmpbuf_control_plan, jmp_args, "rsp_slot_address"),
    ):
        for value in (None, "", _random_bytes(8, 9), int(valid[field]) ^ 1, 1 << 80):
            changed = dict(valid)
            changed[field] = value
            _only_declared(
                lambda builder=builder, changed=changed: builder(**changed),
                guard.PwnDepthPointerGuardError,
            )

    slot = struct.pack("<Q", _reference_mangle(pointer, cookie))
    exit_record = struct.pack(
        "<QQQQ", 4, _reference_mangle(pointer, cookie),
        0x55555555B000, 0x7FFFF7FC0000,
    )
    rsp = struct.pack("<Q", _reference_mangle(0x7FFFFFFFE000, cookie))
    rip = struct.pack("<Q", _reference_mangle(0x555555554320, cookie))
    binary_cases = (
        b"", _random_bytes(9, 8), slot[:-1],
        bytes((slot[0] ^ 1,)) + slot[1:], slot + b"X",
    )
    for value in binary_cases:
        _only_declared(
            lambda value=value: guard.verify_mangled_slot(
                value, glibc_version="2.39", slot_address=0x55555555A000,
                expected_pointer=pointer, pointer_guard=cookie,
            ),
            guard.PwnDepthPointerGuardError,
        )
    for value in (b"", _random_bytes(10, 32), exit_record[:-1],
                  bytes((exit_record[0] ^ 1,)) + exit_record[1:], exit_record + b"X"):
        _only_declared(
            lambda value=value: guard.verify_exit_function(
                value, glibc_version="2.39", entry_address=0x55555555A000,
                expected_function=pointer, pointer_guard=cookie, flavor="ef_cxa",
                expected_argument=0x55555555B000, expected_dso_handle=0x7FFFF7FC0000,
            ),
            guard.PwnDepthPointerGuardError,
        )
    for left, right in (
        (b"", b""), (_random_bytes(11, 8), _random_bytes(12, 8)),
        (rsp[:-1], rip), (bytes((rsp[0] ^ 1,)) + rsp[1:], rip),
        (rsp + b"X", rip + b"X"),
    ):
        _only_declared(
            lambda left=left, right=right: guard.verify_jmpbuf_control(
                left, right, glibc_version="2.39",
                rsp_slot_address=0x55555555C030, rip_slot_address=0x55555555C038,
                saved_rsp=0x7FFFFFFFE000, saved_rip=0x555555554320,
                pointer_guard=cookie,
            ),
            guard.PwnDepthPointerGuardError,
        )


def test_pointer_guard_cli_fuzz_never_exits() -> None:
    cases = (
        [], ["mangle"], ["mangle", "", "0"], ["mangle", "0x", "1"],
        ["mangle", str(1 << 80), "0"], ["unknown", "1", "2"],
    )
    for argv in cases:
        result = guard.main(list(argv))
        assert isinstance(result, int) and result in {0, 2}


# ---------------------------------------------------------------------------
# ret2dlresolve: System V ELF64/AMD64 hand encoding, no engine serializer.


def _phdr(ptype: int, flags: int, offset: int, vaddr: int, size: int, memsz: int, align: int) -> bytes:
    return struct.pack("<IIQQQQQQ", ptype, flags, offset, vaddr, vaddr, size, memsz, align)


def _reference_elf() -> bytes:
    tags = (
        (3, 0x404100), (5, 0x404200), (6, 0x404240), (9, 24),
        (11, 24), (20, 7), (23, 0x404300), (2, 0x60),
        (0x6FFFFFF0, 0x404380), (0, 0),
    )
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in tags)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x400100, 64, 0, 0,
        64, 56, 4, 0, 0, 0,
    )
    headers = b"".join((
        _phdr(1, 5, 0, 0x400000, 0x200, 0x200, 0x1000),
        _phdr(1, 6, 0x200, 0x404000, 0x700, 0x1000, 0x1000),
        _phdr(2, 6, 0x200, 0x404000, len(dynamic), len(dynamic), 8),
        _phdr(0x6474E552, 4, 0x200, 0x404000, 0x100, 0x100, 1),
    ))
    result = bytearray(0x900)
    result[:64] = header
    result[64:64 + len(headers)] = headers
    result[0x200:0x200 + len(dynamic)] = dynamic
    return bytes(result)


def _reference_forgery() -> tuple[bytes, dict[str, int]]:
    blob_at = 0x404480
    rela_at = blob_at
    sym_index = 32
    sym_at = 0x404240 + sym_index * 24
    name_at = sym_at + 24
    raw = bytearray(name_at - blob_at + 6)
    struct.pack_into("<QQq", raw, rela_at - blob_at, 0x404780, (sym_index << 32) | 7, 0)
    struct.pack_into(
        "<IBBHQQ", raw, sym_at - blob_at,
        name_at - 0x404200, 0x12, 0, 0, 0, 0,
    )
    raw[name_at - blob_at:] = b"write\x00"
    return bytes(raw), {
        "blob_address": blob_at,
        "rela_address": rela_at,
        "sym_address": sym_at,
        "name_address": name_at,
    }


def test_ret2dl_vector_lock_amd64_abi_records() -> None:
    profile = dl.inspect_elf(_reference_elf(), plt0=0x400100)
    assert profile.feasible
    assert profile.runtime_tag(23) == 0x404300
    blob, addresses = _reference_forgery()
    result = dl.verify_forged_records(
        profile, blob=blob, requested_symbol=b"write", versym_value=0, **addresses,
    )
    assert result.relocation_selector == (0x404480 - 0x404300) // 24 == 16
    assert result.symbol_index == 32
    assert result.symbol == b"write"
    assert result.relocation_target == 0x404780
    assert result.versym_address == 0x404380 + 2 * 32


def test_ret2dl_parser_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    valid = _reference_elf()
    cases = (
        b"",
        _random_bytes(13, 257),
        valid[:63],
        valid[:-1],
        bytes((valid[0] ^ 1,)) + valid[1:],
        valid[:64 + 17],
    )
    for value in cases:
        _only_declared(
            lambda value=value: dl.inspect_elf(value, plt0=0x400100),
            dl.PwnDepthRet2DlError,
        )
    monkeypatch.setattr(dl, "MAX_ELF", 1024)
    _only_declared(
        lambda: dl.inspect_elf(b"A" * 1025, plt0=0x400100),
        dl.PwnDepthRet2DlError,
    )


def test_ret2dl_record_verifier_fail_closed_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = dl.inspect_elf(_reference_elf(), plt0=0x400100)
    valid, addresses = _reference_forgery()
    cases = (
        b"",
        _random_bytes(14, len(valid)),
        valid[:-1],
        bytes((valid[0] ^ 1,)) + valid[1:],
    )
    for value in cases:
        _only_declared(
            lambda value=value: dl.verify_forged_records(
                profile, blob=value, versym_value=0, **addresses,
            ),
            dl.PwnDepthRet2DlError,
        )
    monkeypatch.setattr(dl, "MAX_BLOB", 256)
    _only_declared(
        lambda: dl.verify_forged_records(
            profile, blob=b"A" * 257, versym_value=0, **addresses,
        ),
        dl.PwnDepthRet2DlError,
    )
    malformed_profiles: tuple[object, ...] = (None, {}, [], "", _random_bytes(15, 8))
    for bad_profile in malformed_profiles:
        _only_declared(
            lambda bad_profile=bad_profile: dl.verify_forged_records(
                bad_profile, blob=valid, versym_value=0, **addresses,
            ),
            dl.PwnDepthRet2DlError,
        )


def test_ret2dl_range_methods_and_cli_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    address_range = dl.AddressRange(0x400000, 0x401000, dl.PF_R)
    for address, size in ((None, 1), (0x400000, None), (-1, 1), (0x400000, 1 << 80)):
        _only_declared(
            lambda address=address, size=size: address_range.contains(address, size),
            dl.PwnDepthRet2DlError,
        )

    valid = _reference_elf()
    payloads = (b"", _random_bytes(16, 67), valid[:63], bytes((valid[0] ^ 1,)) + valid[1:])
    for index, payload in enumerate(payloads):
        path = tmp_path / f"elf-{index}"
        path.write_bytes(payload)
        assert dl.main(["inspect", str(path), "--plt0", "0x400100"]) in {1, 2}
    monkeypatch.setattr(dl, "MAX_ELF", 1024)
    path = tmp_path / "elf-oversized"
    path.write_bytes(b"A" * 1025)
    assert dl.main(["inspect", str(path), "--plt0", "0x400100"]) == 2
    assert dl.main([]) == 2
