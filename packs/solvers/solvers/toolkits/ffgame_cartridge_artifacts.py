"""Bounded, static N64/GBA/GB-save and additive PICO-8 artifact inspection.

The module never executes cartridge code or Lua and never resolves PICO-8
``#include`` directives.  N64 physical byte orders are normalized only for
inspection.  PICO-8 decoding is deliberately delegated to ``ff_pico8_cart``;
this engine adds string, flag, static-Lua and slack inventories instead of
reimplementing that parser.

Format references: tool64's N64 header/byte-order definitions, GBATEK's GBA
cartridge header, devkitPro's ``tGBAHeader``, and the official PICO-8 manual.
"""

from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

import ff_pico8_cart as _pico
import ff_rom_headers as _rom


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 64 * 1024 * 1024
MAX_GBA_INPUT = 32 * 1024 * 1024
MAX_SAVE_INPUT = 1024 * 1024
MAX_PICO_INPUT = 4 * 1024 * 1024
MAX_STRINGS = 512
MAX_FLAGS = 128
MAX_LUA_ARTIFACTS = 256
MAX_STRING_BYTES = 512

N64_MAGICS = {
    b"\x80\x37\x12\x40": "z64-big-endian",
    b"\x37\x80\x40\x12": "v64-byte-swapped",
    b"\x40\x12\x37\x80": "n64-little-endian-words",
}

N64_REGIONS = {
    0x37: "Beta",
    0x41: "Asia (NTSC)",
    0x42: "Brazil",
    0x43: "China",
    0x44: "Germany",
    0x45: "North America",
    0x46: "France",
    0x47: "Gateway 64 (NTSC)",
    0x48: "Netherlands",
    0x49: "Italy",
    0x4A: "Japan",
    0x4B: "Korea",
    0x4C: "Gateway 64 (PAL)",
    0x4E: "Canada",
    0x50: "Europe",
    0x53: "Spain",
    0x55: "Australia",
    0x57: "Scandinavia",
    0x58: "Europe",
    0x59: "Europe",
}

# The 156 bytes published in GBATEK and multiple open cartridge tools.
GBA_NINTENDO_LOGO = bytes.fromhex(
    "24ffae51699aa2213d84820a84e409ad11248b98c0817f21a352be199309ce20"
    "10464a4af82731ec58c7e83382e3cebf85f4df94ce4b09c194568ac01372a7fc"
    "9f844d73a3ca9a615897a327fc039876231dc7610304ae56bf38840040a70efd"
    "ff52fe036f9530f197fbc08560d68025a963be03014e38e2f9a234ffbb3e0344"
    "780090cb88113a9465c07c6387f03cafd625e48b380aac7221d4f807"
)

GB_SAVE_SIZES = {
    0: ["empty/no external battery RAM"],
    512: ["MBC2 512 x 4-bit internal RAM, commonly stored as 512 bytes"],
    2048: ["2 KiB raw RAM"],
    8192: ["one 8 KiB external-RAM bank"],
    32768: ["four 8 KiB external-RAM banks"],
    65536: ["eight 8 KiB external-RAM banks"],
    131072: ["sixteen 8 KiB external-RAM banks"],
}

PICO_MEMORY = {
    "gfx": (0x0000, 0x2000),
    "map": (0x2000, 0x3000),
    "gff": (0x3000, 0x3100),
    "music": (0x3100, 0x3200),
    "sfx": (0x3200, 0x4300),
    "lua": (0x4300, 0x8000),
}


class FFGameCartridgeError(ValueError):
    """Malformed, unsupported, or over-limit game cartridge artifact."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FFGameCartridgeError:
            raise
        except Exception as exc:
            raise FFGameCartridgeError(
                f"{function.__name__}: invalid input ({type(exc).__name__})"
            ) from None

    return guarded


def _as_bytes(value: Any, *, cap: int, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise FFGameCartridgeError(f"{label} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > cap:
            raise FFGameCartridgeError(f"{label} exceeds the {cap}-byte limit")
        return bytes(value)
    except FFGameCartridgeError:
        raise
    except (TypeError, ValueError, BufferError) as exc:
        raise FFGameCartridgeError(f"invalid {label}: {exc}") from None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", errors="replace").rstrip(" ")


def _section_name(offset: int, sections: list[dict[str, Any]]) -> str:
    for section in sections:
        start = section["offset"]
        end = start + section["available_bytes"]
        if start <= offset < end:
            return str(section["name"])
    return "outside-available-sections"


def _scan(data: bytes, sections: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    section_rows = sections or []
    strings: list[dict[str, Any]] = []
    strings_truncated = False
    for match in re.finditer(rb"[\x20-\x7e]{4,512}", data):
        if len(strings) >= MAX_STRINGS:
            strings_truncated = True
            break
        offset = match.start()
        row: dict[str, Any] = {
            "offset": offset,
            "byte_length": len(match.group()),
            "text": match.group().decode("ascii"),
        }
        if section_rows:
            row["section"] = _section_name(offset, section_rows)
        strings.append(row)

    flags: list[str] = []
    flag_hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    flags_truncated = False
    for match in flagfmt.BYTES.finditer(data):
        if len(flag_hits) >= MAX_FLAGS:
            flags_truncated = True
            break
        value = match.group().decode("ascii")
        row = {"offset": match.start(), "value": value}
        if section_rows:
            row["section"] = _section_name(match.start(), section_rows)
        flag_hits.append(row)
        if value not in seen:
            seen.add(value)
            flags.append(value)
    return {
        "strings": strings,
        "strings_truncated": strings_truncated,
        "flags": flags,
        "flag_hits": flag_hits,
        "flags_truncated": flags_truncated,
    }


def _fixed_section(name: str, offset: int, size: int, total: int) -> dict[str, Any]:
    available = min(size, max(0, total - offset))
    return {
        "name": name,
        "offset": offset,
        "declared_bytes": size,
        "available_bytes": available,
        "missing_bytes": size - available,
    }


def _n64_normalize(data: bytes) -> tuple[str, bytes]:
    physical = N64_MAGICS.get(data[:4])
    if physical is None:
        raise FFGameCartridgeError("unrecognized N64 byte-order signature")
    if physical == "z64-big-endian":
        return physical, data
    if physical == "v64-byte-swapped":
        if len(data) % 2:
            raise FFGameCartridgeError("v64 input is not a whole number of 16-bit words")
        output = bytearray(len(data))
        output[0::2] = data[1::2]
        output[1::2] = data[0::2]
        return physical, bytes(output)
    if len(data) % 4:
        raise FFGameCartridgeError("n64 input is not a whole number of 32-bit words")
    output = bytearray(len(data))
    for offset in range(0, len(data), 4):
        output[offset:offset + 4] = data[offset:offset + 4][::-1]
    return physical, bytes(output)


@_closed
def parse_n64(value: Any) -> dict[str, Any]:
    """Parse an N64 ROM header after normalizing z64/v64/n64 byte order."""
    data = _as_bytes(value, cap=MAX_INPUT, label="N64 image")
    if len(data) < 0x40:
        raise FFGameCartridgeError("N64 image is shorter than its 64-byte header")
    physical, normalized = _n64_normalize(data)
    sections = [
        _fixed_section("header", 0, 0x40, len(normalized)),
        _fixed_section("ipl3_boot_code", 0x40, 0xFC0, len(normalized)),
        {
            "name": "program_and_data",
            "offset": 0x1000,
            "declared_bytes": None,
            "available_bytes": max(0, len(normalized) - 0x1000),
            "missing_bytes": None,
        },
    ]
    findings: list[str] = []
    if len(normalized) < 0x1000:
        findings.append("IPL3 boot-code area is truncated.")
    if normalized[0x18:0x20] != b"\0" * 8:
        findings.append("Reserved header bytes 0x18..0x1f are nonzero.")
    if normalized[0x34:0x38] != b"\0" * 4:
        findings.append("Reserved header bytes 0x34..0x37 are nonzero.")
    manufacturer = int.from_bytes(normalized[0x38:0x3C], "big")
    region_code = normalized[0x3E]
    if region_code not in N64_REGIONS:
        findings.append("Unknown N64 region/country code.")
    artifacts = _scan(normalized, sections)
    return {
        "format": "n64-rom",
        "physical_format": physical,
        "file_size": len(data),
        "normalized_sha256": _sha256(normalized),
        "header": {
            "pi_domain_word": f"{int.from_bytes(normalized[0:4], 'big'):08x}",
            "clock_rate": int.from_bytes(normalized[4:8], "big"),
            "entry_point": int.from_bytes(normalized[8:12], "big"),
            "release": int.from_bytes(normalized[12:16], "big"),
            "crc1": f"{int.from_bytes(normalized[0x10:0x14], 'big'):08x}",
            "crc2": f"{int.from_bytes(normalized[0x14:0x18], 'big'):08x}",
            "title": _text(normalized[0x20:0x34]),
            "title_raw_hex": normalized[0x20:0x34].hex(),
            "manufacturer_id": manufacturer,
            "manufacturer_ascii": chr(manufacturer & 0xFF)
            if manufacturer <= 0x7F and 0x20 <= manufacturer else None,
            "cartridge_id": _text(normalized[0x3C:0x3E]),
            "region_code": region_code,
            "region_ascii": chr(region_code) if 0x20 <= region_code <= 0x7E else None,
            "region": N64_REGIONS.get(region_code, "unknown"),
            "version": normalized[0x3F],
        },
        "sections": sections,
        "digests": {
            "header_sha256": _sha256(normalized[:0x40]),
            "ipl3_sha256": _sha256(normalized[0x40:0x1000]),
            "program_and_data_sha256": _sha256(normalized[0x1000:]),
        },
        **artifacts,
        "findings": findings,
        "notes": [
            "CRC1/CRC2 are reported as stored values; CIC-dependent verification is not claimed.",
            "Offsets are canonical big-endian logical ROM offsets after byte-order normalization.",
        ],
    }


def _gba_complement(data: bytes) -> int:
    return (-0x19 - sum(data[0xA0:0xBD])) & 0xFF


def _gba_save_markers(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pattern = rb"(?:EEPROM|SRAM(?:_F)?|FLASH(?:512|1M)?)_V[0-9]{3}"
    for match in re.finditer(pattern, data):
        if len(rows) >= MAX_STRINGS:
            break
        marker = match.group().decode("ascii")
        if marker.startswith("EEPROM"):
            medium = "eeprom"
        elif marker.startswith("SRAM"):
            medium = "sram"
        elif marker.startswith("FLASH1M"):
            medium = "flash-1mbit"
        elif marker.startswith("FLASH512"):
            medium = "flash-512kbit"
        else:
            medium = "flash"
        rows.append({"offset": match.start(), "marker": marker, "medium_hint": medium})
    return rows


def _gb_save_banks(data: bytes, flag_hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(data) in (512, 2048):
        bank_size = len(data)
    elif len(data) in (8192, 32768, 65536, 131072):
        bank_size = 8192
    else:
        return []
    rows: list[dict[str, Any]] = []
    for index, offset in enumerate(range(0, len(data), bank_size)):
        bank = data[offset:offset + bank_size]
        hits = [
            {
                "offset": hit["offset"] - offset,
                "absolute_offset": hit["offset"],
                "value": hit["value"],
            }
            for hit in flag_hits
            if offset <= hit["offset"] < offset + len(bank)
        ]
        rows.append({
            "index": index,
            "offset": offset,
            "byte_size": len(bank),
            "sha256": _sha256(bank),
            "flag_hits": hits,
        })
    return rows


@_closed
def parse_gba(value: Any) -> dict[str, Any]:
    """Parse a GBA cartridge header and inventory inert body artifacts."""
    data = _as_bytes(value, cap=MAX_GBA_INPUT, label="GBA image")
    if len(data) < 0xC0:
        raise FFGameCartridgeError("GBA image is shorter than its 192-byte header")
    sections = [
        _fixed_section("header", 0, 0xC0, len(data)),
        {
            "name": "program_and_data",
            "offset": 0xC0,
            "declared_bytes": None,
            "available_bytes": len(data) - 0xC0,
            "missing_bytes": None,
        },
    ]
    logo_matches = data[4:0xA0] == GBA_NINTENDO_LOGO
    calculated = _gba_complement(data)
    stored = data[0xBD]
    findings: list[str] = []
    if not logo_matches:
        findings.append("Nintendo logo bytes differ from the published retail logo.")
    if data[0xB2] != 0x96:
        findings.append("Fixed header byte 0xb2 is not 0x96.")
    if stored != calculated:
        findings.append("GBA header complement checksum mismatch.")
    if any(data[0xB5:0xBC]):
        findings.append("Reserved header bytes 0xb5..0xbb are nonzero.")
    if any(data[0xBE:0xC0]):
        findings.append("Reserved header bytes 0xbe..0xbf are nonzero.")
    save_markers = _gba_save_markers(data)
    if len({row["medium_hint"] for row in save_markers}) > 1:
        findings.append("Multiple save-medium signature families occur in the ROM.")
    artifacts = _scan(data, sections)
    return {
        "format": "gba-rom",
        "file_size": len(data),
        "sha256": _sha256(data),
        "header": {
            "entry_instruction_hex": data[0:4].hex(),
            "entry_instruction_little_endian": int.from_bytes(data[0:4], "little"),
            "logo_matches": logo_matches,
            "logo_sha256": _sha256(data[4:0xA0]),
            "debug_logo_byte_0x9c": data[0x9C],
            "title": _text(data[0xA0:0xAC]),
            "title_raw_hex": data[0xA0:0xAC].hex(),
            "game_code": _text(data[0xAC:0xB0]),
            "maker_code": _text(data[0xB0:0xB2]),
            "fixed_0x96": data[0xB2],
            "unit_code": data[0xB3],
            "device_type": data[0xB4],
            "software_version": data[0xBC],
            "complement": {
                "stored": stored,
                "calculated": calculated,
                "matches": stored == calculated,
            },
        },
        "sections": sections,
        "save_medium_signatures": save_markers,
        **artifacts,
        "findings": findings,
        "notes": [
            "The header has no whole-ROM checksum; body integrity is not claimed.",
            "Save-library strings are hints and do not prove the cartridge hardware.",
        ],
    }


@_closed
def inspect_gb_sav(value: Any, rom: Any | None = None) -> dict[str, Any]:
    """Inventory raw Game Boy battery RAM, optionally correlated to a GB ROM."""
    data = _as_bytes(value, cap=MAX_SAVE_INPUT, label="Game Boy save")
    artifacts = _scan(data)
    banks = _gb_save_banks(data, artifacts["flag_hits"])
    layouts = GB_SAVE_SIZES.get(len(data), [])
    findings: list[str] = []
    if not layouts:
        findings.append("Size is not one of the common raw Game Boy RAM extents.")
    correlation = None
    if rom is not None:
        rom_data = _as_bytes(rom, cap=MAX_INPUT, label="Game Boy ROM")
        try:
            header = _rom.parse_gb(rom_data)
        except _rom.RomError as exc:
            raise FFGameCartridgeError(f"invalid correlation ROM: {exc}") from None
        expected = header.get("ram_bytes")
        basis = "cartridge header RAM-size code"
        if header.get("mbc2_internal_ram_nibbles"):
            expected = 512
            basis = "MBC2 internal 512 x 4-bit RAM, commonly serialized as 512 bytes"
        correlation = {
            "rom_title": header.get("title"),
            "cartridge_type": header.get("cartridge_type"),
            "expected_raw_bytes": expected,
            "basis": basis,
            "matches_exactly": expected == len(data),
            "size_delta": None if expected is None else len(data) - expected,
            "note": "Emulator-specific RTC/footer data is not interpreted.",
        }
        if expected is not None and expected != len(data):
            findings.append("Save size differs from the correlated ROM's raw RAM extent.")
    return {
        "format": "game-boy-battery-save",
        "file_size": len(data),
        "sha256": _sha256(data),
        "sections": [{"name": "raw_battery_ram", "offset": 0, "available_bytes": len(data)}],
        "banks": banks,
        "possible_layouts": layouts,
        "byte_summary": {
            "unique_values": len(set(data)),
            "zero_bytes": data.count(0),
            "ff_bytes": data.count(0xFF),
            "all_zero": bool(data) and not any(data),
            "all_ff": bool(data) and data.count(0xFF) == len(data),
        },
        "rom_correlation": correlation,
        **artifacts,
        "findings": findings,
        "notes": [
            "Raw .sav files have no universal header or game-independent field semantics.",
            "Bytes are inventoried only; no game save logic is executed or inferred.",
        ],
    }


def _blob_bytes(blob: Any, label: str) -> bytes:
    if not isinstance(blob, dict) or not isinstance(blob.get("data_hex"), str):
        raise FFGameCartridgeError(f"PICO-8 baseline omitted {label} bytes")
    try:
        data = bytes.fromhex(blob["data_hex"])
    except ValueError:
        raise FFGameCartridgeError(f"PICO-8 baseline returned invalid {label} hex") from None
    if len(data) > MAX_PICO_INPUT:
        raise FFGameCartridgeError(f"PICO-8 {label} exceeds the inventory limit")
    return data


def _lua_static(data: bytes) -> dict[str, Any]:
    text = data.decode("latin-1")
    comments: list[dict[str, Any]] = []
    for match in re.finditer(r"--[^\r\n]{0,512}", text):
        if len(comments) >= MAX_LUA_ARTIFACTS:
            break
        comments.append({"offset": match.start(), "text": match.group()})

    includes: list[dict[str, Any]] = []
    for match in re.finditer(r"(?m)^[ \t]*#include[ \t]+([^\r\n]{1,512})", text):
        if len(includes) >= MAX_LUA_ARTIFACTS:
            break
        includes.append({"offset": match.start(), "target": match.group(1).strip()})

    literals: list[dict[str, Any]] = []
    index = 0
    while index < len(text) and len(literals) < MAX_LUA_ARTIFACTS:
        quote = text[index]
        if quote not in "\"'":
            index += 1
            continue
        start = index
        index += 1
        escaped = False
        while index < len(text) and index - start <= MAX_STRING_BYTES:
            char = text[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                literals.append({
                    "offset": start,
                    "quote": quote,
                    "raw_content": text[start + 1:index],
                })
                index += 1
                break
            index += 1
        else:
            index = start + 1
    return {"comments": comments, "include_targets": includes, "quoted_literals": literals}


@_closed
def inspect_pico8(value: Any, format: str = "auto") -> dict[str, Any]:
    """Add artifact inventories to the existing bounded PICO-8 decoder."""
    data = _as_bytes(value, cap=MAX_PICO_INPUT, label="PICO-8 cartridge")
    if not isinstance(format, str) or format not in {"auto", "p8", "png"}:
        raise FFGameCartridgeError("unsupported PICO-8 format selector")
    try:
        base = _pico.inspect_cart(data, format)
    except _pico.P8CartError as exc:
        raise FFGameCartridgeError(f"invalid PICO-8 cartridge: {exc}") from None

    section_rows: list[dict[str, Any]] = []
    all_flags: set[str] = set(base.get("flags", []))
    lua_artifacts: dict[str, Any] | None = None
    sections = base.get("sections")
    if not isinstance(sections, dict):
        raise FFGameCartridgeError("PICO-8 baseline returned invalid sections")
    for name, blob in sections.items():
        section_data = _blob_bytes(blob, f"{name} section")
        inventory = _scan(section_data)
        all_flags.update(inventory["flags"])
        row: dict[str, Any] = {
            "name": name,
            "decoded_bytes": len(section_data),
            "sha256": _sha256(section_data),
            "strings": inventory["strings"],
            "strings_truncated": inventory["strings_truncated"],
            "flags": inventory["flags"],
        }
        if base.get("format") == "p8.png" and name in PICO_MEMORY:
            start, end = PICO_MEMORY[name]
            row["location"] = {
                "kind": "decoded-cart-memory",
                "offset": start,
                "capacity_bytes": end - start,
            }
        else:
            row["location"] = {"kind": "decoded-text-section", "offset": None}
        if name == "lua":
            lua_artifacts = _lua_static(section_data)
            row["compression"] = blob.get("compression", "text-section")
            row["stored_bytes"] = blob.get("stored_byte_size", blob.get("text_byte_size"))
        section_rows.append(row)

    slack: list[dict[str, Any]] = []
    lua_blob = sections.get("lua")
    if isinstance(lua_blob, dict) and isinstance(lua_blob.get("unused_storage"), dict):
        unused = _blob_bytes(lua_blob["unused_storage"], "unused Lua storage")
        inventory = _scan(unused)
        all_flags.update(inventory["flags"])
        stored = lua_blob.get("stored_byte_size")
        start = 0x4300 + stored if isinstance(stored, int) else None
        slack.append({
            "name": "unused_lua_storage",
            "location": {"kind": "decoded-cart-memory", "offset": start},
            "byte_size": len(unused),
            "sha256": _sha256(unused),
            "strings": inventory["strings"],
            "flags": inventory["flags"],
        })
    if isinstance(base.get("extra_payload"), dict):
        extra = _blob_bytes(base["extra_payload"], "extra payload")
        inventory = _scan(extra)
        all_flags.update(inventory["flags"])
        slack.append({
            "name": "payload_after_version_byte",
            "location": {"kind": "decoded-png-payload", "offset": 0x8001},
            "byte_size": len(extra),
            "sha256": _sha256(extra),
            "strings": inventory["strings"],
            "flags": inventory["flags"],
        })
    if isinstance(base.get("trailing"), dict):
        trailing = _blob_bytes(base["trailing"], "PNG trailer")
        if trailing:
            inventory = _scan(trailing)
            all_flags.update(inventory["flags"])
            slack.append({
                "name": "bytes_after_png_iend",
                "location": {"kind": "physical-file", "offset": len(data) - len(trailing)},
                "byte_size": len(trailing),
                "sha256": _sha256(trailing),
                "strings": inventory["strings"],
                "flags": inventory["flags"],
            })
    return {
        "format": base.get("format"),
        "version": base.get("version"),
        "file_size": len(data),
        "sha256": _sha256(data),
        "sections": section_rows,
        "slack": slack,
        "lua_static_artifacts": lua_artifacts,
        "flags": sorted(all_flags),
        "notes": [
            "Cart/PNG decoding is reused from ff_pico8_cart and is not duplicated here.",
            "Lua strings, comments, and #include targets are lexical artifacts only.",
            "Lua is never executed and #include targets are never opened or resolved.",
        ],
    }


@_closed
def inspect_cartridge(value: Any, kind: str = "auto", rom: Any | None = None) -> dict[str, Any]:
    """Dispatch to n64, gba, gb-sav, or pico8; raw saves require explicit kind."""
    data = _as_bytes(value, cap=MAX_INPUT, label="cartridge artifact")
    if not isinstance(kind, str) or kind not in {"auto", "n64", "gba", "gb-sav", "pico8"}:
        raise FFGameCartridgeError("unknown cartridge artifact kind")
    selected = kind
    if selected == "auto":
        if data[:4] in N64_MAGICS:
            selected = "n64"
        elif data.startswith(_pico.PNG_MAGIC) or data.startswith(_pico.P8_HEADER):
            selected = "pico8"
        elif len(data) >= 0xC0 and (
            data[4:12] == GBA_NINTENDO_LOGO[:8]
            or (data[0xB2] == 0x96 and data[0xBD] == _gba_complement(data))
        ):
            selected = "gba"
        else:
            raise FFGameCartridgeError(
                "unrecognized artifact; raw Game Boy saves require kind='gb-sav'"
            )
    if selected == "n64":
        return parse_n64(data)
    if selected == "gba":
        return parse_gba(data)
    if selected == "gb-sav":
        return inspect_gb_sav(data, rom)
    return inspect_pico8(data)


@_closed
def inspect_file(path: Any, kind: str = "auto", rom_path: Any | None = None) -> dict[str, Any]:
    """Read a bounded local artifact and optional GB ROM, then inspect it."""
    artifact_path = Path(path)
    with artifact_path.open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    rom = None
    if rom_path is not None:
        with Path(rom_path).open("rb") as stream:
            rom = stream.read(MAX_INPUT + 1)
    return inspect_cartridge(data, kind, rom)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--kind", choices=("auto", "n64", "gba", "gb-sav", "pico8"), default="auto"
    )
    parser.add_argument("--rom", type=Path, help="optional GB ROM for --kind gb-sav correlation")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = inspect_file(args.artifact, args.kind, args.rom)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except FFGameCartridgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
