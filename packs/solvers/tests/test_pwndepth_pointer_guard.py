from __future__ import annotations

import struct

import pytest

import pwndepth_pointer_guard as pg


MASK = (1 << 64) - 1


def reference_mangle(pointer: int, guard: int) -> int:
    """Literal translation of glibc x86-64 pointer_guard.h, independent of engine helpers."""
    value = (pointer ^ guard) & MASK
    return ((value << 17) & MASK) | (value >> 47)


def reference_demangle(stored: int, guard: int) -> int:
    rotated = (stored >> 17) | ((stored & ((1 << 17) - 1)) << 47)
    return (rotated ^ guard) & MASK


def test_published_x86_64_pointer_guard_formula_and_inverse() -> None:
    pointer = 0x00007FFFF7E12340
    guard = 0xA1B2C3D4E5F60718
    expected = reference_mangle(pointer, guard)
    assert pg.mangle_pointer(pointer, guard) == expected
    assert pg.demangle_pointer(expected, guard) == pointer
    assert reference_demangle(expected, guard) == pointer


def test_exit_function_record_matches_hand_packed_reference() -> None:
    entry = 0x55555555A000
    function = 0x7FFFF7E12340
    argument = 0x55555555B000
    guard = 0x0123456789ABCDEF
    plan = pg.build_exit_function_plan(
        glibc_version="2.41", entry_address=entry,
        function_address=function, pointer_guard=guard,
        flavor="ef_cxa", argument_address=argument,
        dso_handle=0x7FFFF7FC0000,
    )
    expected = struct.pack(
        "<QQQQ", 4, reference_mangle(function, guard), argument, 0x7FFFF7FC0000
    )
    assert plan.payload == expected
    assert pg.verify_exit_function(
        expected, glibc_version="2.41", entry_address=entry,
        expected_function=function, pointer_guard=guard,
        flavor="ef_cxa", expected_argument=argument,
        expected_dso_handle=0x7FFFF7FC0000,
    )


def test_exit_flavor_contracts_fail_closed() -> None:
    base = dict(
        glibc_version="2.35", entry_address=0x55555555A000,
        function_address=0x7FFFF7E12340, pointer_guard=0,
    )
    with pytest.raises(pg.PwnDepthPointerGuardError):
        pg.build_exit_function_plan(**base, flavor="ef_at", argument_address=0x55555555B000)
    with pytest.raises(pg.PwnDepthPointerGuardError):
        pg.build_exit_function_plan(**base, flavor="unknown")
    with pytest.raises(pg.PwnDepthPointerGuardError):
        pg.build_exit_function_plan(**{**base, "glibc_version": "2.42"})
    with pytest.raises(pg.PwnDepthPointerGuardError):
        pg.build_exit_function_plan(**{**base, "glibc_version": "2.35.not-a-version"})


def test_jmpbuf_plan_uses_caller_profiled_slots_and_round_trips() -> None:
    guard = 0xF00DBAAD12345678
    plan = pg.build_jmpbuf_control_plan(
        glibc_version="2.39", rsp_slot_address=0x55555555C030,
        rip_slot_address=0x55555555C038, saved_rsp=0x7FFFFFFFE000,
        saved_rip=0x555555554321, pointer_guard=guard,
    )
    assert int.from_bytes(plan.rsp_payload, "little") == reference_mangle(0x7FFFFFFFE000, guard)
    assert int.from_bytes(plan.rip_payload, "little") == reference_mangle(0x555555554321, guard)
    assert pg.verify_jmpbuf_control(
        plan.rsp_payload, plan.rip_payload, glibc_version="2.39",
        rsp_slot_address=plan.rsp_slot_address, rip_slot_address=plan.rip_slot_address,
        saved_rsp=plan.saved_rsp, saved_rip=plan.saved_rip, pointer_guard=guard,
    )


def test_corrupt_or_malformed_slots_raise_only_declared_error() -> None:
    cases = [None, b"", b"A" * 7, b"A" * 9, bytearray(8), "12345678"]
    for value in cases:
        with pytest.raises(pg.PwnDepthPointerGuardError):
            pg.verify_mangled_slot(
                value, glibc_version="2.35", slot_address=0x55555555A000,
                expected_pointer=0x7FFFF7E12340, pointer_guard=0,
            )
    good = struct.pack("<Q", reference_mangle(0x7FFFF7E12340, 0))
    with pytest.raises(pg.PwnDepthPointerGuardError):
        pg.verify_mangled_slot(
            good, glibc_version="2.35", slot_address=0x55555555A001,
            expected_pointer=0x7FFFF7E12340, pointer_guard=0,
        )


def test_guarded_cli_and_import_contract(capsys: pytest.CaptureFixture[str]) -> None:
    assert pg.main(["mangle", "0x1234", "0x5678"]) == 0
    assert int(capsys.readouterr().out.strip(), 0) == reference_mangle(0x1234, 0x5678)
    assert pg.main(["--definitely-not-an-option"]) == 2
    capsys.readouterr()
    assert pg.main(["--help"]) == 0
