#!/usr/bin/env python3
"""Fail-closed House-of-Apple-2 semantic verification for glibc 2.35--2.41.

This module deliberately does *not* build another ``_IO_FILE`` payload.  The repository already
contains serializers for those structures.  Instead it inspects caller-supplied bytes using a
caller-selected offset profile and checks the branch predicates needed by the reviewed
``_IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE`` route.  It is offline/static: no
process is launched, no input is delivered, and no address is inferred.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


MAX_JSON = 1 << 20
MAX_BLOB = 1 << 20
UINT64_LIMIT = 1 << 64

IO_UNBUFFERED = 0x0002
IO_NO_WRITES = 0x0008
IO_CURRENTLY_PUTTING = 0x0800


class PwnDepthFSOPError(ValueError):
    """The supplied Apple-2 layout or predicate set is malformed or unsupported."""


@dataclass(frozen=True)
class Apple2Offsets:
    """Offsets and minimum object sizes derived from the caller's exact libc ABI."""

    file_size: int = 0xE0
    file_flags: int = 0x00
    file_write_base: int = 0x20
    file_write_ptr: int = 0x28
    file_vtable_offset: int = 0x82
    file_lock: int = 0x88
    file_wide_data: int = 0xA0
    file_mode: int = 0xC0
    file_vtable: int = 0xD8
    wide_size: int = 0xE8
    wide_write_base: int = 0x18
    wide_write_ptr: int = 0x20
    wide_buf_base: int = 0x30
    wide_vtable: int = 0xE0
    jump_size: int = 0x70
    jump_doallocate: int = 0x68
    lock_size: int = 0x10

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any] | None) -> "Apple2Offsets":
        """Create a strict profile; unknown names and booleans are rejected."""
        try:
            if values is None:
                result = cls()
                result.validate()
                return result
            if not isinstance(values, Mapping):
                raise PwnDepthFSOPError("offsets must be an object")
            if any(not isinstance(name, str) for name in values):
                raise PwnDepthFSOPError("offset field names must be strings")
            allowed = set(cls.__dataclass_fields__)
            unknown = sorted(set(values) - allowed)
            if unknown:
                raise PwnDepthFSOPError("unknown offset fields: " + ", ".join(unknown))
            parsed: dict[str, int] = {}
            for name, value in values.items():
                parsed[name] = _integer(value, name)
            result = cls(**parsed)
            result.validate()
            return result
        except PwnDepthFSOPError:
            raise
        except Exception as exc:
            raise PwnDepthFSOPError(f"invalid offset profile: {exc}") from exc

    def validate(self) -> None:
        """Check all fields fit and no two semantic fields alias one another."""

        for size_name in ("file_size", "wide_size", "jump_size", "lock_size"):
            size = getattr(self, size_name)
            if isinstance(size, bool) or not isinstance(size, int) or not 8 <= size <= MAX_BLOB:
                raise PwnDepthFSOPError(f"{size_name} must be in 8..{MAX_BLOB}")
        groups = (
            ("file", self.file_size, {
                "flags": (self.file_flags, 4), "write_base": (self.file_write_base, 8),
                "write_ptr": (self.file_write_ptr, 8),
                "vtable_offset": (self.file_vtable_offset, 1), "lock": (self.file_lock, 8),
                "wide_data": (self.file_wide_data, 8), "mode": (self.file_mode, 4),
                "vtable": (self.file_vtable, 8),
            }),
            ("wide", self.wide_size, {
                "write_base": (self.wide_write_base, 8),
                "write_ptr": (self.wide_write_ptr, 8),
                "buf_base": (self.wide_buf_base, 8),
                "wide_vtable": (self.wide_vtable, 8),
            }),
            ("jump", self.jump_size, {"doallocate": (self.jump_doallocate, 8)}),
        )
        for prefix, size, fields in groups:
            occupied: list[tuple[str, int, int]] = []
            for name, (offset, width) in fields.items():
                if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= size - width:
                    raise PwnDepthFSOPError(f"{prefix}_{name} is outside {prefix}_size")
                for old_name, old_start, old_end in occupied:
                    if max(offset, old_start) < min(offset + width, old_end):
                        raise PwnDepthFSOPError(
                            f"offset fields overlap: {prefix}_{old_name} and {prefix}_{name}"
                        )
                occupied.append((name, offset, offset + width))


@dataclass(frozen=True)
class Apple2Verification:
    """Immutable proof record for one inspected Apple-2 candidate."""

    glibc_version: str
    trigger: str
    file_address: int
    wide_address: int
    wide_vtable_address: int
    io_wfile_jumps: int
    call_target: int
    lock_address: int
    lock_size: int
    vtable_offset: int
    flags: int
    mode: int
    file_write_base: int
    file_write_ptr: int
    wide_write_base: int
    wide_write_ptr: int
    wide_buf_base: int
    checked_predicates: tuple[str, ...]
    operations: tuple[str, ...]
    offsets: Apple2Offsets

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for name in (
            "file_address", "wide_address", "wide_vtable_address", "io_wfile_jumps",
            "call_target", "lock_address", "flags", "file_write_base", "file_write_ptr",
            "wide_write_base", "wide_write_ptr", "wide_buf_base",
        ):
            value[name] = hex(value[name])
        value["checked_predicates"] = list(self.checked_predicates)
        value["operations"] = list(self.operations)
        return value


def _integer(value: Any, name: str, *, nonzero: bool = False) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PwnDepthFSOPError(f"{name} is not an integer") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < UINT64_LIMIT:
        raise PwnDepthFSOPError(f"{name} must be an unsigned 64-bit integer")
    if nonzero and not value:
        raise PwnDepthFSOPError(f"{name} must be non-zero")
    return value


def _canonical(value: Any, name: str, *, nonzero: bool = True) -> int:
    address = _integer(value, name, nonzero=nonzero)
    upper = address >> 48
    if upper not in (0, 0xFFFF):
        raise PwnDepthFSOPError(f"{name} is not a canonical x86-64 address")
    if upper == 0 and address >= (1 << 47):
        raise PwnDepthFSOPError(f"{name} is not a canonical x86-64 address")
    if upper == 0xFFFF and address < UINT64_LIMIT - (1 << 47):
        raise PwnDepthFSOPError(f"{name} is not a canonical x86-64 address")
    return address


def _version(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 32:
        raise PwnDepthFSOPError("glibc_version must be a short string")
    match = re.fullmatch(r"2\.(\d{2})(?:\.\d+)?", value)
    if match is None:
        raise PwnDepthFSOPError("glibc_version must look like 2.35 through 2.41")
    minor = int(match.group(1))
    if not 35 <= minor <= 41:
        raise PwnDepthFSOPError("House of Apple 2 verifier supports glibc 2.35 through 2.41")
    return value


def _blob(value: Any, name: str, minimum: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PwnDepthFSOPError(f"{name} must be bytes-like")
    raw = bytes(value)
    if len(raw) < minimum or len(raw) > MAX_BLOB:
        raise PwnDepthFSOPError(f"{name} length must be {minimum}..{MAX_BLOB}")
    return raw


def _u32(raw: bytes, offset: int, name: str) -> int:
    if offset < 0 or offset + 4 > len(raw):
        raise PwnDepthFSOPError(f"{name} extends past its blob")
    return int.from_bytes(raw[offset:offset + 4], "little")


def _u8(raw: bytes, offset: int, name: str) -> int:
    if offset < 0 or offset + 1 > len(raw):
        raise PwnDepthFSOPError(f"{name} extends past its blob")
    return raw[offset]


def _s32(raw: bytes, offset: int, name: str) -> int:
    if offset < 0 or offset + 4 > len(raw):
        raise PwnDepthFSOPError(f"{name} extends past its blob")
    return int.from_bytes(raw[offset:offset + 4], "little", signed=True)


def _u64(raw: bytes, offset: int, name: str) -> int:
    if offset < 0 or offset + 8 > len(raw):
        raise PwnDepthFSOPError(f"{name} extends past its blob")
    return int.from_bytes(raw[offset:offset + 8], "little")


def _ranges(values: Any, name: str) -> tuple[tuple[int, int], ...]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise PwnDepthFSOPError(f"{name} must be a sequence")
    if not 1 <= len(values) <= 256:
        raise PwnDepthFSOPError(f"{name} must contain 1..256 intervals")
    result: list[tuple[int, int]] = []
    for index, pair in enumerate(values):
        if isinstance(pair, (str, bytes, bytearray)) or not isinstance(pair, Sequence) or len(pair) != 2:
            raise PwnDepthFSOPError(f"{name}[{index}] must be [start,end]")
        start = _canonical(pair[0], f"{name}[{index}].start")
        end = _integer(pair[1], f"{name}[{index}].end", nonzero=True)
        if not start < end <= UINT64_LIMIT:
            raise PwnDepthFSOPError(f"{name}[{index}] must be increasing")
        _canonical(end - 1, f"{name}[{index}].end-1")
        result.append((start, end))
    return tuple(sorted(result))


def _contained(
    start: int, size: int, ranges: tuple[tuple[int, int], ...],
    name: str, range_name: str = "writable range",
) -> None:
    if size < 0 or start + size > UINT64_LIMIT:
        raise PwnDepthFSOPError(f"{name} crosses the address space")
    if not any(left <= start and start + size <= right for left, right in ranges):
        raise PwnDepthFSOPError(f"{name} is not wholly inside a supplied {range_name}")


def _nonoverlap(segments: Sequence[tuple[str, int, int]]) -> None:
    for index, (name, start, size) in enumerate(segments):
        end = start + size
        if end > UINT64_LIMIT:
            raise PwnDepthFSOPError(f"{name} crosses the address space")
        for other, old_start, old_size in segments[:index]:
            if max(start, old_start) < min(end, old_start + old_size):
                raise PwnDepthFSOPError(f"target objects overlap: {other} and {name}")


def _verify_apple2(
    *,
    glibc_version: str,
    trigger: str,
    file_blob: bytes,
    file_address: int,
    lock_blob: bytes,
    wide_blob: bytes,
    wide_address: int,
    wide_vtable_blob: bytes,
    wide_vtable_address: int,
    io_wfile_jumps: int,
    vtable_section_start: int,
    vtable_section_end: int,
    call_target: int,
    writable_ranges: Sequence[tuple[int, int]],
    executable_ranges: Sequence[tuple[int, int]],
    trigger_reachable: bool,
    offsets: Apple2Offsets | Mapping[str, Any] | None,
) -> Apple2Verification:
    version = _version(glibc_version)
    if trigger not in {"exit_flush", "direct_wfile_overflow"}:
        raise PwnDepthFSOPError("trigger must be exit_flush or direct_wfile_overflow")
    profile = offsets if isinstance(offsets, Apple2Offsets) else Apple2Offsets.from_mapping(offsets)
    profile.validate()
    file_raw = _blob(file_blob, "file_blob", profile.file_size)
    lock_raw = _blob(lock_blob, "lock_blob", profile.lock_size)
    wide_raw = _blob(wide_blob, "wide_blob", profile.wide_size)
    jump_raw = _blob(wide_vtable_blob, "wide_vtable_blob", profile.jump_size)
    file_addr = _canonical(file_address, "file_address")
    wide_addr = _canonical(wide_address, "wide_address")
    jump_addr = _canonical(wide_vtable_address, "wide_vtable_address")
    wfile_jumps = _canonical(io_wfile_jumps, "io_wfile_jumps")
    section_start = _canonical(vtable_section_start, "vtable_section_start")
    section_end = _integer(vtable_section_end, "vtable_section_end", nonzero=True)
    if not section_start < section_end <= UINT64_LIMIT:
        raise PwnDepthFSOPError("__libc_IO_vtables bounds must be increasing")
    _canonical(section_end - 1, "vtable_section_end-1")
    target = _canonical(call_target, "call_target")
    ranges = _ranges(writable_ranges, "writable_ranges")
    executable = _ranges(executable_ranges, "executable_ranges")
    if trigger_reachable is not True:
        raise PwnDepthFSOPError("trigger_reachable must be independently established")

    _contained(file_addr, profile.file_size, ranges, "fake FILE")
    _contained(wide_addr, profile.wide_size, ranges, "fake wide data")
    _contained(jump_addr, profile.jump_size, ranges, "fake wide vtable")

    flags = _u32(file_raw, profile.file_flags, "FILE.flags")
    write_base = _u64(file_raw, profile.file_write_base, "FILE.write_base")
    write_ptr = _u64(file_raw, profile.file_write_ptr, "FILE.write_ptr")
    vtable_offset = _u8(file_raw, profile.file_vtable_offset, "FILE.vtable_offset")
    lock = _canonical(_u64(file_raw, profile.file_lock, "FILE.lock"), "FILE.lock")
    file_wide = _u64(file_raw, profile.file_wide_data, "FILE.wide_data")
    mode = _s32(file_raw, profile.file_mode, "FILE.mode")
    outer = _u64(file_raw, profile.file_vtable, "FILE.vtable")
    wide_write_base = _u64(wide_raw, profile.wide_write_base, "wide.write_base")
    wide_write_ptr = _u64(wide_raw, profile.wide_write_ptr, "wide.write_ptr")
    wide_buf_base = _u64(wide_raw, profile.wide_buf_base, "wide.buf_base")
    inner = _u64(wide_raw, profile.wide_vtable, "wide.wide_vtable")
    dispatched = _u64(jump_raw, profile.jump_doallocate, "wide_vtable.doallocate")

    _nonoverlap((
        ("file", file_addr, profile.file_size),
        ("wide_data", wide_addr, profile.wide_size),
        ("wide_vtable", jump_addr, profile.jump_size),
        ("lock", lock, profile.lock_size),
    ))

    if file_wide != wide_addr:
        raise PwnDepthFSOPError("FILE._wide_data does not select the supplied wide-data object")
    if inner != jump_addr:
        raise PwnDepthFSOPError("wide_data._wide_vtable does not select the supplied wide table")
    if outer != wfile_jumps:
        raise PwnDepthFSOPError("FILE outer vtable is not the supplied genuine _IO_wfile_jumps")
    if not section_start <= outer < section_end:
        raise PwnDepthFSOPError("_IO_wfile_jumps is outside supplied __libc_IO_vtables bounds")
    if dispatched != target:
        raise PwnDepthFSOPError("wide __doallocate slot does not contain call_target")
    _contained(target, 1, executable, "call_target", "executable range")
    _contained(lock, profile.lock_size, ranges, "FILE lock")
    if any(lock_raw[:profile.lock_size]):
        raise PwnDepthFSOPError("FILE lock backing must be an all-zero unlocked object")
    if vtable_offset != 0:
        raise PwnDepthFSOPError("FILE._vtable_offset must be zero for the supplied outer table")
    if flags & IO_NO_WRITES:
        raise PwnDepthFSOPError("_IO_NO_WRITES prevents _IO_wfile_overflow")
    if flags & IO_UNBUFFERED:
        raise PwnDepthFSOPError("_IO_UNBUFFERED prevents the reviewed _IO_WDOALLOCATE branch")
    if wide_write_base != 0:
        raise PwnDepthFSOPError("wide _IO_write_base must be NULL to enter _IO_wdoallocbuf")
    if wide_buf_base != 0:
        raise PwnDepthFSOPError("wide _IO_buf_base must be NULL so _IO_wdoallocbuf dispatches")
    predicates = [
        "glibc version is in reviewed range 2.35..2.41",
        "outer vtable exactly equals genuine _IO_wfile_jumps inside __libc_IO_vtables",
        "FILE lock and all controlled objects lie in supplied writable ranges",
        "_IO_NO_WRITES and _IO_UNBUFFERED are clear",
        "FILE._vtable_offset is zero and the complete supplied lock object is writable and zero",
        "wide _IO_write_base and _IO_buf_base are NULL",
        "wide __doallocate slot exactly equals call_target in a supplied executable range",
        "the selected exit/direct trigger is independently reachable",
    ]
    if trigger == "exit_flush":
        if mode <= 0:
            raise PwnDepthFSOPError("exit_flush requires FILE._mode > 0 for the wide predicate")
        if wide_write_ptr <= wide_write_base:
            raise PwnDepthFSOPError("exit_flush wide stream requires wide write_ptr > write_base")
        predicates.extend((
            "FILE._mode is positive so _IO_flush_all selects the wide-stream predicate",
            "wide write_ptr is greater than wide write_base for the wide flush path",
        ))
        operations = (
            "place the already-serialized FILE, wide data, and wide table at their reviewed addresses",
            "make the fake/replaced stream reachable from the real cleanup list",
            "reach normal libc exit flushing so _IO_wfile_overflow calls _IO_wdoallocbuf",
        )
    else:
        predicates.append("caller supplies a direct, reachable _IO_wfile_overflow dispatch")
        operations = (
            "place the already-serialized FILE, wide data, and wide table at their reviewed addresses",
            "invoke the target's proven direct _IO_wfile_overflow path on this FILE",
        )
    return Apple2Verification(
        glibc_version=version,
        trigger=trigger,
        file_address=file_addr,
        wide_address=wide_addr,
        wide_vtable_address=jump_addr,
        io_wfile_jumps=wfile_jumps,
        call_target=target,
        lock_address=lock,
        lock_size=profile.lock_size,
        vtable_offset=vtable_offset,
        flags=flags,
        mode=mode,
        file_write_base=write_base,
        file_write_ptr=write_ptr,
        wide_write_base=wide_write_base,
        wide_write_ptr=wide_write_ptr,
        wide_buf_base=wide_buf_base,
        checked_predicates=tuple(predicates),
        operations=operations,
        offsets=profile,
    )


def verify_apple2(**config: Any) -> Apple2Verification:
    """Verify a candidate and expose only :class:`PwnDepthFSOPError` on invalid input."""

    try:
        return _verify_apple2(**config)
    except PwnDepthFSOPError:
        raise
    except Exception as exc:  # every malformed public input maps to the declared error
        raise PwnDepthFSOPError(f"invalid Apple-2 request: {exc}") from exc


def _load_config(path: str) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_JSON + 1)
    except OSError as exc:
        raise PwnDepthFSOPError(f"cannot read config: {exc}") from exc
    if len(raw) > MAX_JSON:
        raise PwnDepthFSOPError("JSON input exceeds 1 MiB cap")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PwnDepthFSOPError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PwnDepthFSOPError("JSON root must be an object")
    for source, target in (
        ("file_hex", "file_blob"), ("lock_hex", "lock_blob"),
        ("wide_hex", "wide_blob"),
        ("wide_vtable_hex", "wide_vtable_blob"),
    ):
        if source not in value:
            raise PwnDepthFSOPError(f"missing {source}")
        try:
            value[target] = bytes.fromhex(value.pop(source))
        except (TypeError, ValueError) as exc:
            raise PwnDepthFSOPError(f"{source} must be hexadecimal") from exc
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwndepth_fsop_verify.py")
    parser.add_argument("config", help="bounded JSON Apple-2 verification request")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        request = _load_config(args.config)
        report = verify_apple2(**request)
        print(json.dumps(report.as_dict(), sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except PwnDepthFSOPError as exc:
        print(f"pwndepth_fsop_verify: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # guarded CLI boundary
        print(f"pwndepth_fsop_verify: invalid input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "Apple2Offsets", "Apple2Verification", "IO_CURRENTLY_PUTTING", "IO_NO_WRITES",
    "IO_UNBUFFERED", "PwnDepthFSOPError", "main", "verify_apple2",
]


if __name__ == "__main__":
    raise SystemExit(main())
