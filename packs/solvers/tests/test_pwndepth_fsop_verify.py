"""Independent, hand-packed tests for the pwndepth Apple-2 verifier."""
from __future__ import annotations

import json
import struct

import pytest

import pwndepth_fsop_verify as fsop


FILE = 0x404800
WIDE = 0x404900
WVT = 0x404A00
LOCK = 0x404B00
WFILE_JUMPS = 0x7FFFF7FA10C0
VTABLE_START = 0x7FFFF7FA0000
VTABLE_END = 0x7FFFF7FA8000
TARGET = 0x7FFFF7E12340
WRITABLE = ((0x404000, 0x405000),)
EXECUTABLE = ((0x7FFFF7E00000, 0x7FFFF7F00000),)


def _qword(blob: bytearray, offset: int, value: int) -> None:
    # Hand-written reference encoding; this never calls the engine under test.
    struct.pack_into("<Q", blob, offset, value)


def reference_candidate(
    *,
    write_base: int = 0,
    write_ptr: int = 1,
    wide_write_ptr: int = 1,
    flags: int = 0,
    mode: int = 1,
    offsets: fsop.Apple2Offsets | None = None,
) -> dict:
    p = offsets or fsop.Apple2Offsets()
    file_blob = bytearray(p.file_size)
    wide_blob = bytearray(p.wide_size)
    jump_blob = bytearray(p.jump_size)
    struct.pack_into("<I", file_blob, p.file_flags, flags)
    _qword(file_blob, p.file_write_base, write_base)
    _qword(file_blob, p.file_write_ptr, write_ptr)
    _qword(file_blob, p.file_lock, LOCK)
    _qword(file_blob, p.file_wide_data, WIDE)
    struct.pack_into("<i", file_blob, p.file_mode, mode)
    _qword(file_blob, p.file_vtable, WFILE_JUMPS)
    _qword(wide_blob, p.wide_write_base, 0)
    _qword(wide_blob, p.wide_write_ptr, wide_write_ptr)
    _qword(wide_blob, p.wide_buf_base, 0)
    _qword(wide_blob, p.wide_vtable, WVT)
    _qword(jump_blob, p.jump_doallocate, TARGET)
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
        "vtable_section_start": VTABLE_START,
        "vtable_section_end": VTABLE_END,
        "call_target": TARGET,
        "writable_ranges": WRITABLE,
        "executable_ranges": EXECUTABLE,
        "trigger_reachable": True,
        "offsets": p,
    }


def test_hand_packed_exit_flush_candidate_proves_every_dispatch_link() -> None:
    report = fsop.verify_apple2(**reference_candidate())
    assert report.glibc_version == "2.39"
    assert report.trigger == "exit_flush"
    assert report.lock_address == LOCK
    assert report.io_wfile_jumps == WFILE_JUMPS
    assert report.call_target == TARGET
    assert report.file_write_ptr > report.file_write_base
    assert report.wide_write_ptr > report.wide_write_base
    assert len(report.checked_predicates) >= 8
    rendered = report.as_dict()
    assert rendered["call_target"] == hex(TARGET)
    assert rendered["offsets"]["file_vtable"] == 0xD8


def test_trigger_specific_predicates_follow_glibc_source() -> None:
    request = reference_candidate(write_base=9, write_ptr=0, wide_write_ptr=0, mode=-1)
    request["trigger"] = "direct_wfile_overflow"
    report = fsop.verify_apple2(**request)
    assert report.trigger == "direct_wfile_overflow"

    request["trigger"] = "exit_flush"
    with pytest.raises(fsop.PwnDepthFSOPError, match="mode"):
        fsop.verify_apple2(**request)

    # For a positive wide orientation, _IO_flush_all uses the wide write pointers;
    # the unrelated narrow pair may be in either order.
    request = reference_candidate(write_base=9, write_ptr=0, wide_write_ptr=1, mode=1)
    assert fsop.verify_apple2(**request).file_write_ptr == 0


def test_profile_offsets_are_caller_selected_not_silently_hardcoded() -> None:
    profile = fsop.Apple2Offsets(
        file_size=0xF8,
        file_flags=0x04,
        file_write_base=0x30,
        file_write_ptr=0x40,
        file_vtable_offset=0x90,
        file_lock=0x80,
        file_wide_data=0xA8,
        file_mode=0xC8,
        file_vtable=0xE8,
        wide_size=0xF8,
        wide_write_base=0x28,
        wide_write_ptr=0x38,
        wide_buf_base=0x48,
        wide_vtable=0xE8,
        jump_size=0x90,
        jump_doallocate=0x78,
    )
    request = reference_candidate(offsets=profile)
    report = fsop.verify_apple2(**request)
    assert report.offsets == profile
    assert report.file_write_ptr == 1


@pytest.mark.parametrize("version", ["2.34", "2.42", "3.35", "2.x", True])
def test_version_gate_is_exact(version) -> None:
    request = reference_candidate()
    request["glibc_version"] = version
    with pytest.raises(fsop.PwnDepthFSOPError):
        fsop.verify_apple2(**request)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda req: struct.pack_into("<I", req["file_blob"], 0, fsop.IO_NO_WRITES), "NO_WRITES"),
        (lambda req: struct.pack_into("<I", req["file_blob"], 0, fsop.IO_UNBUFFERED), "UNBUFFERED"),
        (lambda req: struct.pack_into("<B", req["file_blob"], 0x82, 1), "vtable_offset"),
        (lambda req: struct.pack_into("<Q", req["wide_blob"], 0x18, 1), "write_base"),
        (lambda req: struct.pack_into("<Q", req["wide_blob"], 0x30, 1), "buf_base"),
        (lambda req: struct.pack_into("<Q", req["wide_vtable_blob"], 0x68, TARGET + 1), "call_target"),
        (lambda req: struct.pack_into("<Q", req["file_blob"], 0xD8, WFILE_JUMPS + 8), "outer vtable"),
    ],
)
def test_inverse_verifier_rejects_branch_and_pointer_mutations(mutation, message: str) -> None:
    request = reference_candidate()
    request["file_blob"] = bytearray(request["file_blob"])
    request["wide_blob"] = bytearray(request["wide_blob"])
    request["wide_vtable_blob"] = bytearray(request["wide_vtable_blob"])
    mutation(request)
    with pytest.raises(fsop.PwnDepthFSOPError, match=message):
        fsop.verify_apple2(**request)


def test_ranges_outer_bounds_and_object_overlap_fail_closed() -> None:
    request = reference_candidate()
    request["writable_ranges"] = ((FILE, FILE + 0xE0),)
    with pytest.raises(fsop.PwnDepthFSOPError, match="wide data"):
        fsop.verify_apple2(**request)

    request = reference_candidate()
    request["vtable_section_end"] = WFILE_JUMPS
    with pytest.raises(fsop.PwnDepthFSOPError, match="outside"):
        fsop.verify_apple2(**request)

    request = reference_candidate()
    request["wide_address"] = FILE + 0x20
    with pytest.raises(fsop.PwnDepthFSOPError, match="overlap"):
        fsop.verify_apple2(**request)

    request = reference_candidate()
    request["lock_blob"] = b"\x00" * 15 + b"\x01"
    with pytest.raises(fsop.PwnDepthFSOPError, match="all-zero"):
        fsop.verify_apple2(**request)


def test_currently_putting_flag_does_not_block_null_wide_base_branch() -> None:
    request = reference_candidate(flags=fsop.IO_CURRENTLY_PUTTING)
    assert fsop.verify_apple2(**request).flags & fsop.IO_CURRENTLY_PUTTING


def test_malformed_inputs_raise_only_declared_error() -> None:
    malformed = [
        {},
        {**reference_candidate(), "file_blob": b"x"},
        {**reference_candidate(), "offsets": {"file_vtable": []}},
        {**reference_candidate(), "offsets": {"made_up": 1}},
        {**reference_candidate(), "offsets": {1: 0, "x": 1}},
        {**reference_candidate(), "writable_ranges": object()},
        {**reference_candidate(), "executable_ranges": ()},
        {**reference_candidate(), "trigger_reachable": False},
        {**reference_candidate(), "file_address": 0x0000800000000000},
    ]
    for request in malformed:
        with pytest.raises(fsop.PwnDepthFSOPError):
            fsop.verify_apple2(**request)


def test_guarded_cli_valid_invalid_and_help(tmp_path, capsys) -> None:
    request = reference_candidate()
    encoded = {
        key: value for key, value in request.items()
        if key not in {"file_blob", "lock_blob", "wide_blob", "wide_vtable_blob", "offsets"}
    }
    encoded["file_hex"] = request["file_blob"].hex()
    encoded["lock_hex"] = request["lock_blob"].hex()
    encoded["wide_hex"] = request["wide_blob"].hex()
    encoded["wide_vtable_hex"] = request["wide_vtable_blob"].hex()
    encoded["offsets"] = struct_to_plain(request["offsets"])
    path = tmp_path / "apple.json"
    path.write_text(json.dumps(encoded))

    assert fsop.main([str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["trigger"] == "exit_flush"

    assert fsop.main(["--definitely-invalid"]) == 2
    capsys.readouterr()
    assert fsop.main(["--help"]) == 0


def struct_to_plain(profile: fsop.Apple2Offsets) -> dict[str, int]:
    # Kept in the test rather than relying on the engine's own report serialization.
    return {name: getattr(profile, name) for name in profile.__dataclass_fields__}

