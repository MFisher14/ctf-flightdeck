#!/usr/bin/env python3
"""Bounded, offline SNES9x, VBA-GBA, and Gens save-state inventory.

The reader reports framing, source-defined regions, printable strings, and
``CSCTF{...}`` candidates.  It never starts an emulator or executes cartridge,
RAM, VRAM, or Lua bytes.  Public parsing functions raise only
``FFGameStateError`` for malformed, unsupported, or over-limit input.

Layout sources:

* SNES9x ``docs/snapshots.txt``, ``snapshot.h``, and ``snapshot.cpp``.
* VBA-M ``src/core/gba/gba.h`` and ``src/core/gba/gba.cpp``.
* Gens/GS ``save.hpp``, ``save.cpp``, ``gsx_struct.h``, and ``gsx_v7.h``.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import sys
import zlib


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 16 * 1024 * 1024
MAX_DECOMPRESSED = 32 * 1024 * 1024
MAX_BLOCKS = 256
MAX_STRINGS = 256
MAX_FLAGS = 128
MAX_STRING_PREVIEW = 256

SNES9X_MAGIC = b"#!s9xsnp:"
GENS_MAGIC = b"GST\x40\xe0"
GENS_V6_SIZE = 0x22C68
GENS_V7_SIZE = 0x3434E
GENS_SEGACD_SUFFIX = 0xE19A4 + 0x1238B
GENS_32X_SUFFIX = 0x849BF

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_FLAG = flagfmt.BYTES
_SNES_HEADER = re.compile(rb"#!s9xsnp:([0-9]{4})\n")
_SNES_TAG = re.compile(rb"[A-Z0-9]{3}")


class FFGameStateError(ValueError):
    """Malformed, unsupported, or over-limit emulator-state input."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FFGameStateError:
            raise
        except Exception as exc:
            raise FFGameStateError(
                f"{function.__name__}: invalid input ({type(exc).__name__})"
            ) from None

    return guarded


def _as_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise FFGameStateError("state must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except (TypeError, ValueError, BufferError) as exc:
        raise FFGameStateError("state size is unavailable") from exc
    if size > MAX_INPUT:
        raise FFGameStateError(f"state exceeds the {MAX_INPUT}-byte input limit")
    try:
        raw = bytes(value)
    except (TypeError, ValueError, BufferError) as exc:
        raise FFGameStateError("state cannot be copied safely") from exc
    if len(raw) != size:
        raise FFGameStateError("state size changed while it was copied")
    return raw


def _optional_gzip(raw: bytes) -> tuple[bytes, str]:
    if not raw.startswith(b"\x1f\x8b"):
        return raw, "none"
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decoder.decompress(raw, MAX_DECOMPRESSED + 1)
    except zlib.error as exc:
        raise FFGameStateError("invalid gzip state") from exc
    if len(output) > MAX_DECOMPRESSED or decoder.unconsumed_tail:
        raise FFGameStateError("gzip state exceeds the decompressed-size limit")
    if not decoder.eof:
        raise FFGameStateError("truncated gzip state")
    if decoder.unused_data:
        raise FFGameStateError("bytes follow the gzip member")
    try:
        # Limit even the transient tail allocation to one byte beyond the cap.
        tail = decoder.flush(MAX_DECOMPRESSED - len(output) + 1)
    except zlib.error as exc:
        raise FFGameStateError("invalid gzip trailer") from exc
    output += tail
    if len(output) > MAX_DECOMPRESSED:
        raise FFGameStateError("gzip state exceeds the decompressed-size limit")
    return output, "gzip"


def _decode_ascii(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace").rstrip(" ")


def _scan_strings(data: bytes, base: int = 0) -> list[dict]:
    output = []
    for match in _ASCII_RUN.finditer(data):
        raw = match.group(0)
        output.append(
            {
                "offset": base + match.start(),
                "byte_length": len(raw),
                "text": raw[:MAX_STRING_PREVIEW].decode("ascii"),
                "preview_truncated": len(raw) > MAX_STRING_PREVIEW,
            }
        )
        if len(output) >= MAX_STRINGS:
            break
    return output


def _scan_flags(data: bytes, base: int = 0) -> list[dict]:
    output = []
    for match in _FLAG.finditer(data):
        output.append(
            {"offset": base + match.start(), "value": match.group(0).decode("ascii")}
        )
        if len(output) >= MAX_FLAGS:
            break
    return output


def _section(name: str, offset: int, size: int, payload: bytes) -> dict:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise FFGameStateError(f"{name} section falls outside the state")
    data = payload[offset : offset + size]
    return {
        "name": name,
        "offset": offset,
        "byte_size": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "strings": _scan_strings(data, offset),
        "flags": _scan_flags(data, offset),
    }


def _common(payload: bytes, raw: bytes, compression: str) -> dict:
    return {
        "file_size": len(raw),
        "compression": compression,
        "decompressed_size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "strings": _scan_strings(payload),
        "flags": _scan_flags(payload),
    }


_SNES_BLOCK_MEANINGS = {
    "NAM": "ROM filename/compatibility label",
    "CPU": "CPU internal state",
    "REG": "CPU registers",
    "PPU": "picture-processing state",
    "DMA": "DMA/HDMA state",
    "VRA": "VRAM",
    "RAM": "work RAM",
    "SRA": "battery-backed SRAM",
    "FIL": "register backing store",
    "SND": "sound state",
    "CTL": "controller state",
    "TIM": "timing state",
    "SHO": "rendered screenshot",
    "MOV": "movie metadata",
    "MID": "movie input data",
}
_SNES_FIXED_SIZES = {"VRA": 0x10000, "RAM": 0x20000, "FIL": 0x8000}


@_closed
def parse_snes9x(value: object) -> dict:
    """Parse an optionally gzip-wrapped SNES9x named-block snapshot."""
    raw = _as_bytes(value)
    payload, compression = _optional_gzip(raw)
    match = _SNES_HEADER.match(payload)
    if not match:
        raise FFGameStateError("missing or malformed SNES9x snapshot header")
    version = int(match.group(1))
    if version <= 0:
        raise FFGameStateError("invalid SNES9x snapshot version")

    offset = match.end()
    blocks = []
    seen: set[str] = set()
    findings = []
    while offset < len(payload):
        if len(blocks) >= MAX_BLOCKS:
            raise FFGameStateError("SNES9x block count exceeds the limit")
        if len(payload) - offset < 11:
            raise FFGameStateError("truncated SNES9x block header")
        header_offset = offset
        header = payload[offset : offset + 11]
        offset += 11
        if not _SNES_TAG.fullmatch(header[:3]) or header[3] != 0x3A or header[10] != 0x3A:
            raise FFGameStateError("malformed SNES9x block header")
        tag = header[:3].decode("ascii")
        if header[4] == 0x2D:
            if header[5] != 0x2D:
                raise FFGameStateError("malformed binary SNES9x block length")
            size = int.from_bytes(header[6:10], "big")
            length_encoding = "binary_u32_be"
        else:
            if not header[4:10].isdigit():
                raise FFGameStateError("non-decimal SNES9x block length")
            size = int(header[4:10])
            length_encoding = "decimal_6"
        if size <= 0:
            raise FFGameStateError("SNES9x blocks must have positive length")
        if size > len(payload) - offset:
            raise FFGameStateError(f"truncated SNES9x {tag} block")
        block = _section(tag, offset, size, payload)
        block.update(
            header_offset=header_offset,
            length_encoding=length_encoding,
            meaning=_SNES_BLOCK_MEANINGS.get(tag, "unknown/extension block"),
        )
        expected = _SNES_FIXED_SIZES.get(tag)
        if expected is not None:
            block["published_byte_size"] = expected
            block["published_size_matches"] = size == expected
            if size != expected:
                findings.append(
                    f"{tag} size {size} differs from the published {expected}-byte region."
                )
        if tag in seen:
            findings.append(f"Duplicate {tag} block.")
        seen.add(tag)
        blocks.append(block)
        offset += size

    if not blocks:
        raise FFGameStateError("SNES9x snapshot contains no blocks")
    if version > 12:
        findings.append("Snapshot version is newer than the inspected upstream version 12.")
    if blocks[0]["name"] != "NAM":
        findings.append("First block is not NAM as written by upstream SNES9x.")

    result = {
        "format": "snes9x_snapshot",
        "version": version,
        "header_size": match.end(),
        "block_count": len(blocks),
        "blocks": blocks,
        "findings": findings,
    }
    result.update(_common(payload, raw, compression))
    return result


@_closed
def parse_vba_gba(value: object) -> dict:
    """Parse the stable shallow header of an optionally gzip-wrapped VBA GBA state.

    VBA's remaining serialization is version- and build-sensitive.  It is kept
    as one opaque section and scanned, rather than assigned invented offsets.
    """
    raw = _as_bytes(value)
    payload, compression = _optional_gzip(raw)
    if len(payload) < 24:
        raise FFGameStateError("truncated VBA-GBA state header")
    version = int.from_bytes(payload[0:4], "little")
    if version < 1 or version > 11:
        raise FFGameStateError("unsupported VBA-GBA state version")
    identity = payload[4:20]
    uses_bios = int.from_bytes(payload[20:24], "little")
    if uses_bios not in (0, 1):
        raise FFGameStateError("invalid VBA-GBA BIOS flag")

    sections = [_section("header", 0, 24, payload)]
    if len(payload) > 24:
        sections.append(_section("opaque_state_payload", 24, len(payload) - 24, payload))
    findings = []
    if version != 11:
        findings.append("State uses an older VBA-GBA serialization version.")
    result = {
        "format": "vba_gba_state",
        "version": version,
        "rom_identity_hex": identity.hex(),
        "rom_title": _decode_ascii(identity[:12]),
        "game_code": _decode_ascii(identity[12:16]),
        "uses_bios": bool(uses_bios),
        "sections": sections,
        "documented_embedded_region_sizes": {
            "internal_work_ram": 0x8000,
            "palette_ram": 0x400,
            "external_work_ram": 0x40000,
            "vram_buffer": 0x20000,
            "oam": 0x400,
            "io_memory": 0x400,
        },
        "findings": findings,
        "notes": [
            "Only the stable version/ROM-identity/BIOS prefix is interpreted.",
            "The remaining bytes are scanned but deliberately not assigned build-sensitive offsets.",
        ],
    }
    result.update(_common(payload, raw, compression))
    return result


_GENS_BASE_SECTIONS = (
    ("header", 0x0000, 0x0040),
    ("vdp_control", 0x0040, 0x0010),
    ("version", 0x0050, 0x0010),
    ("psg_registers", 0x0060, 0x0010),
    ("m68k_registers", 0x0080, 0x005A),
    ("vdp_registers", 0x00FA, 0x0018),
    ("color_ram", 0x0112, 0x0080),
    ("vertical_scroll_ram", 0x0192, 0x0050),
    ("ym2612_registers", 0x01E4, 0x0200),
    ("z80_registers", 0x0404, 0x003C),
    ("z80_ram", 0x0474, 0x2000),
    ("m68k_ram", 0x2478, 0x10000),
    ("vram", 0x12478, 0x10000),
    ("frame_count", 0x22478, 0x0004),
)


@_closed
def parse_gens(value: object) -> dict:
    """Parse a raw Gens/GS GSX v6 or v7 fixed-layout Mega Drive state."""
    payload = _as_bytes(value)
    if len(payload) < 0x52 or payload[:5] != GENS_MAGIC:
        raise FFGameStateError("missing or truncated Gens GSX header")
    version = payload[0x50]
    if version == 6:
        expected = GENS_V6_SIZE
        extension_name = "gens_v6_extension"
    elif version == 7:
        expected = GENS_V7_SIZE
        extension_name = "gens_v7_extension"
    else:
        raise FFGameStateError("only source-defined Gens GSX versions 6 and 7 are supported")
    if len(payload) < expected:
        raise FFGameStateError("truncated Gens GSX state")

    sections = [_section(name, offset, size, payload) for name, offset, size in _GENS_BASE_SECTIONS]
    sections.append(_section(extension_name, 0x2247C, expected - 0x2247C, payload))
    suffix_size = len(payload) - expected
    platform = "mega_drive"
    findings = []
    if suffix_size:
        sections.append(_section("platform_suffix", expected, suffix_size, payload))
        if suffix_size == GENS_SEGACD_SUFFIX:
            platform = "sega_cd_candidate"
        elif suffix_size == GENS_32X_SUFFIX:
            platform = "32x_candidate"
        elif suffix_size == GENS_SEGACD_SUFFIX + GENS_32X_SUFFIX:
            platform = "sega_cd_plus_32x_candidate"
        else:
            platform = "unknown_extension"
            findings.append("Suffix length does not match a source-defined Sega CD or 32X extension.")

    result = {
        "format": "gens_gsx_state",
        "version": version,
        "emulator_id": payload[0x51],
        "expected_base_bytes": expected,
        "platform": platform,
        "suffix_bytes": suffix_size,
        "sections": sections,
        "findings": findings,
    }
    result.update(_common(payload, payload, "none"))
    return result


@_closed
def inspect_state(value: object, kind: str = "auto") -> dict:
    """Dispatch to ``snes9x``, ``vba-gba``, or ``gens`` by framing."""
    raw = _as_bytes(value)
    if not isinstance(kind, str) or kind not in ("auto", "snes9x", "vba-gba", "gens"):
        raise FFGameStateError("unknown emulator-state kind")
    if kind != "auto":
        return {
            "snes9x": parse_snes9x,
            "vba-gba": parse_vba_gba,
            "gens": parse_gens,
        }[kind](raw)
    if raw.startswith(GENS_MAGIC):
        return parse_gens(raw)
    payload, _compression = _optional_gzip(raw)
    if payload.startswith(SNES9X_MAGIC):
        return parse_snes9x(raw)
    raise FFGameStateError(
        "unrecognized emulator-state framing; VBA-GBA requires explicit kind"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument(
        "--kind", choices=("auto", "snes9x", "vba-gba", "gens"), default="auto"
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        report = inspect_state(data, args.kind)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except (FFGameStateError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
