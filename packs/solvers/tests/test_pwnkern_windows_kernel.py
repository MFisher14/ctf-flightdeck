"""Independent tests for exact offline Windows kernel wire/layout primitives."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import pwnkern_windows_kernel as windows  # noqa: E402


def test_published_ioctl_constants_and_named_fields():
    # ntdddisk.h: IOCTL_DISK_GET_DRIVE_GEOMETRY =
    # CTL_CODE(FILE_DEVICE_DISK=0x7, 0, METHOD_BUFFERED, FILE_ANY_ACCESS).
    disk = windows.encode_ioctl(0x0007, 0x000, 0, 0)
    assert disk == 0x00070000
    decoded_disk = windows.decode_ioctl(0x00070000)
    assert (
        decoded_disk.device_type,
        decoded_disk.function,
        decoded_disk.method,
        decoded_disk.access,
    ) == (0x7, 0, 0, 0)
    assert decoded_disk.method_name == "METHOD_BUFFERED"
    assert decoded_disk.access_name == "FILE_ANY_ACCESS"

    # ntddstor.h: IOCTL_STORAGE_CHECK_VERIFY =
    # CTL_CODE(IOCTL_STORAGE_BASE=0x2d, 0x0200, METHOD_BUFFERED,
    #          FILE_READ_ACCESS).
    storage = windows.encode_ioctl(0x002D, 0x0200, 0, 1)
    assert storage == 0x002D4800
    decoded_storage = windows.decode_ioctl(storage)
    assert (
        decoded_storage.device_type,
        decoded_storage.function,
        decoded_storage.method,
        decoded_storage.access,
    ) == (0x2D, 0x200, 0, 1)
    assert decoded_storage.access_name == "FILE_READ_ACCESS"


def test_ioctl_vendor_bits_and_manual_arithmetic_are_exact():
    device_type, function, method, access = 0x8337, 0xABC, 3, 3
    independent = (
        device_type * 0x10000
        + access * 0x4000
        + function * 4
        + method
    )
    code = windows.encode_ioctl(device_type, function, method, access)
    assert code == independent
    fields = windows.decode_ioctl(code)
    assert fields.vendor_device_type is True
    assert fields.vendor_function is True
    assert fields.method_name == "METHOD_NEITHER"
    assert fields.access_name == "FILE_READ_ACCESS|FILE_WRITE_ACCESS"
    assert windows.encode_ioctl(
        fields.device_type, fields.function, fields.method, fields.access
    ) == code


def test_device_io_control_contracts_match_published_buffer_semantics():
    buffered = windows.plan_device_io_control(
        windows.encode_ioctl(7, 1, 0, 0), input_length=12, output_length=32
    )
    assert buffered.input_carrier == buffered.output_carrier
    assert buffered.system_buffer_size == 32
    assert buffered.mdl_length == 0
    assert buffered.raw_user_pointers is False

    in_direct = windows.plan_device_io_control(
        windows.encode_ioctl(7, 1, 1, 0), input_length=12, output_length=32
    )
    assert in_direct.system_buffer_size == 12
    assert in_direct.mdl_length == 32
    assert "read access" in in_direct.io_manager_access

    out_direct = windows.plan_device_io_control(
        windows.encode_ioctl(7, 1, 2, 0), input_length=12, output_length=32
    )
    assert out_direct.mdl_length == 32
    assert "write access" in out_direct.io_manager_access

    neither = windows.plan_device_io_control(
        windows.encode_ioctl(7, 1, 3, 0), input_length=12, output_length=32
    )
    assert neither.raw_user_pointers is True
    assert neither.system_buffer_size == neither.mdl_length == 0
    assert neither.input_carrier.endswith("Type3InputBuffer")
    assert neither.output_carrier == "Irp.UserBuffer"


def test_token_transfer_uses_independent_fast_ref_math_and_little_endian_bytes():
    current_eprocess = 0xFFFF800000001000
    system_eprocess = 0xFFFF800000002000
    token_offset = 0x4B8
    current_token = 0xFFFF900000003007
    system_token = 0xFFFF900000004003

    result = windows.build_token_transfer(
        current_eprocess=current_eprocess,
        system_eprocess=system_eprocess,
        token_offset=token_offset,
        current_token_value=current_token,
        system_token_value=system_token,
        ref_bits=4,
    )

    # Independent hand arithmetic: a four-bit EX_FAST_REF occupies low nibble.
    manual_ref_mask = 0xF
    manual_pointer_mask = 0xFFFFFFFFFFFFFFF0
    manual_value = (system_token & manual_pointer_mask) + (current_token & manual_ref_mask)
    manual_bytes = bytes(
        (manual_value >> shift) & 0xFF for shift in range(0, 64, 8)
    )

    assert result.reference_mask == manual_ref_mask
    assert result.pointer_mask == manual_pointer_mask
    assert result.system_token_pointer == 0xFFFF900000004000
    assert result.preserved_reference_bits == 7
    assert result.system_token_address == system_eprocess + token_offset
    assert result.current_token_address == current_eprocess + token_offset
    assert result.write_address == current_eprocess + token_offset
    assert result.write_value == manual_value == 0xFFFF900000004007
    assert result.write_bytes == manual_bytes
    assert result.as_dict()["write_width"] == 8
    assert result.as_dict()["write_endian"] == "little"


@pytest.mark.parametrize(
    "call",
    [
        lambda: windows.encode_ioctl(-1, 0, 0, 0),
        lambda: windows.encode_ioctl(0, 0x1000, 0, 0),
        lambda: windows.encode_ioctl(0, 0, 4, 0),
        lambda: windows.encode_ioctl(0, 0, 0, True),
        lambda: windows.decode_ioctl(1 << 32),
        lambda: windows.plan_device_io_control(0, input_length=-1, output_length=0),
        lambda: windows.build_token_transfer(
            current_eprocess=0x1000,
            system_eprocess=0x2000,
            token_offset=3,
            current_token_value=0x3001,
            system_token_value=0x4001,
            ref_bits=4,
        ),
        lambda: windows.build_token_transfer(
            current_eprocess=0x1000,
            system_eprocess=0x2000,
            token_offset=8,
            current_token_value=0x3001,
            system_token_value=0x4001,
            ref_bits=0,
        ),
        lambda: windows.build_token_transfer(
            current_eprocess=0xFFFFFFFFFFFFFFF8,
            system_eprocess=0x2000,
            token_offset=8,
            current_token_value=0x3001,
            system_token_value=0x4001,
            ref_bits=4,
        ),
    ],
)
def test_malformed_public_inputs_raise_only_declared_error(call):
    with pytest.raises(windows.PwnkernWindowsError):
        call()


def test_cli_success_engine_error_and_guarded_argparse(capsys):
    assert windows.main(["decode", "0x70000"]) == 0
    decoded = json.loads(capsys.readouterr().out)
    assert decoded["code_hex"] == "0x00070000"
    assert decoded["method_name"] == "METHOD_BUFFERED"

    assert windows.main(["encode", "0x2d", "0x200", "0", "1"]) == 0
    encoded = json.loads(capsys.readouterr().out)
    assert encoded["code_hex"] == "0x002d4800"

    assert windows.main(["decode", "0x100000000"]) == 2
    assert capsys.readouterr().err.startswith("pwnkern_windows_kernel: ")

    # argparse's own exits are converted to integer return codes.
    assert windows.main(["decode"]) == 2
    capsys.readouterr()
    assert windows.main(["--help"]) == 0


def test_cli_rejects_non_sequence_argv_without_leaking_typeerror(capsys):
    assert windows.main(42) == 2
    captured = capsys.readouterr()
    assert "malformed argv" in captured.err
    assert "Traceback" not in captured.err
