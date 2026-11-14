"""Structural embedded-architecture and firmware leads from supplied bytes.

The parser validates bounded headers for ELF, U-Boot uImage, flattened device
trees, and SquashFS, then correlates conservative raw-firmware markers.  It
does not unpack, mount, emulate, or execute firmware.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import struct
import zlib


MAX_FIRMWARE = 128 << 20
MAX_COMPONENTS = 256


class FirmwareInputError(ValueError):
    pass


@dataclass(frozen=True)
class FirmwareLead:
    category: str
    name: str
    confidence: int
    offset: int
    evidence: tuple[str, ...]
    next_step: str


@dataclass(frozen=True)
class FirmwareComponent:
    kind: str
    offset: int
    declared_size: int | None
    verified: bool
    details: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class FirmwareReport:
    size: int
    leads: tuple[FirmwareLead, ...]
    components: tuple[FirmwareComponent, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _blob(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("firmware must be immutable bytes")
    if len(data) > MAX_FIRMWARE:
        raise FirmwareInputError("firmware exceeds the 128 MiB cap")
    return data


def _elf(data: bytes) -> tuple[str, int, str, int] | None:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in {1, 2} or data[5] not in {1, 2}:
        return None
    bits = 32 if data[4] == 1 else 64
    endian = "little" if data[5] == 1 else "big"
    order = "<" if endian == "little" else ">"
    expected = 52 if bits == 32 else 64
    ehsize_at = 40 if bits == 32 else 52
    if len(data) < expected or data[6] != 1 or struct.unpack_from(order + "I", data, 20)[0] != 1:
        return None
    if struct.unpack_from(order + "H", data, ehsize_at)[0] != expected:
        return None
    machine = struct.unpack_from(order + "H", data, 18)[0]
    flags_at = 36 if bits == 32 else 48
    flags = struct.unpack_from(order + "I", data, flags_at)[0]
    arch = {8: "mips", 40: "arm", 183: "aarch64", 243: "riscv"}.get(machine)
    return (arch or f"machine-{machine}", bits, endian, flags)


_UIMAGE_ARCH = {
    2: "arm", 5: "mips", 6: "mips64", 7: "ppc", 21: "openrisc",
    22: "aarch64", 23: "arc", 24: "x86_64", 25: "xtensa", 26: "riscv",
}
_UIMAGE_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def parse_uimage(data: bytes, *, offset: int = 0) -> FirmwareComponent:
    data = _blob(data)
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= len(data) - 64:
        raise FirmwareInputError("uImage offset is invalid")
    header = data[offset:offset + 64]
    values = struct.unpack(">7I4B32s", header)
    magic, header_crc, timestamp, size, load, entry, data_crc, os_id, arch_id, image_type, comp_id, raw_name = values
    if magic != 0x27051956:
        raise FirmwareInputError("uImage magic is absent")
    if size > MAX_FIRMWARE or offset + 64 + size > len(data):
        raise FirmwareInputError("uImage payload is truncated or over cap")
    zeroed = bytearray(header)
    zeroed[4:8] = b"\0\0\0\0"
    header_ok = zlib.crc32(zeroed) & 0xFFFFFFFF == header_crc
    payload = data[offset + 64:offset + 64 + size]
    data_ok = zlib.crc32(payload) & 0xFFFFFFFF == data_crc
    name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
    details = (
        ("name", name), ("architecture", _UIMAGE_ARCH.get(arch_id, f"id-{arch_id}")),
        ("compression", _UIMAGE_COMP.get(comp_id, f"id-{comp_id}")),
        ("load", f"0x{load:x}"), ("entry", f"0x{entry:x}"),
        ("timestamp", str(timestamp)), ("os_id", str(os_id)), ("image_type", str(image_type)),
        ("header_crc", "valid" if header_ok else "invalid"),
        ("data_crc", "valid" if data_ok else "invalid"),
    )
    return FirmwareComponent("uimage", offset, 64 + size, header_ok and data_ok, details)


def parse_dtb(data: bytes, *, offset: int = 0) -> FirmwareComponent:
    data = _blob(data)
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= len(data) - 40:
        raise FirmwareInputError("DTB offset is invalid")
    fields = struct.unpack_from(">10I", data, offset)
    magic, total, off_struct, off_strings, off_reserve, version, compatible, boot_cpu, strings_size, struct_size = fields
    if magic != 0xD00DFEED:
        raise FirmwareInputError("DTB magic is absent")
    if total < 40 or total > MAX_FIRMWARE or offset + total > len(data):
        raise FirmwareInputError("DTB total size is truncated or over cap")
    spans = ((off_struct, struct_size, "structure"), (off_strings, strings_size, "strings"))
    if any(start < 40 or size > total or start + size > total for start, size, _name in spans):
        raise FirmwareInputError("DTB block range is invalid")
    ordered_spans = sorted((start, start + size) for start, size, _name in spans if size)
    if any(ordered_spans[index - 1][1] > ordered_spans[index][0] for index in range(1, len(ordered_spans))):
        raise FirmwareInputError("DTB structure/string blocks overlap")
    if off_reserve < 40 or off_reserve + 16 > total or not 1 <= version <= 17 or compatible > version:
        raise FirmwareInputError("DTB version/reservation header is invalid")
    reserve_end = min((start for start, _size, _name in spans if start > off_reserve), default=total)
    reservation_terminated = False
    reservation_end = off_reserve
    for cursor in range(off_reserve, reserve_end - 15, 16):
        address, size = struct.unpack_from(">QQ", data, offset + cursor)
        if address == size == 0:
            reservation_terminated = True
            reservation_end = cursor + 16
            break
    if not reservation_terminated:
        raise FirmwareInputError("DTB reservation map lacks a terminator")
    if any(off_reserve < start + size and reservation_end > start for start, size, _name in spans if size):
        raise FirmwareInputError("DTB reservation map overlaps a data block")
    if struct_size < 4 or data[offset + off_struct + struct_size - 4:offset + off_struct + struct_size] != b"\0\0\0\x09":
        raise FirmwareInputError("DTB structure block lacks the FDT_END token")
    return FirmwareComponent(
        "dtb", offset, total, True,
        (("version", str(version)), ("last_compatible", str(compatible)),
         ("boot_cpu", str(boot_cpu)), ("structure_size", str(struct_size)),
         ("strings_size", str(strings_size))),
    )


def parse_squashfs(data: bytes, *, offset: int = 0) -> FirmwareComponent:
    data = _blob(data)
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= len(data) - 96:
        raise FirmwareInputError("SquashFS offset is invalid")
    magic = data[offset:offset + 4]
    if magic == b"hsqs":
        order, endian = "<", "little"
    elif magic == b"sqsh":
        order, endian = ">", "big"
    else:
        raise FirmwareInputError("SquashFS magic is absent")
    inode_count, mkfs_time, block_size, fragments = struct.unpack_from(order + "4I", data, offset + 4)
    compression, block_log, flags, id_count, major, minor = struct.unpack_from(order + "6H", data, offset + 20)
    bytes_used = struct.unpack_from(order + "Q", data, offset + 40)[0]
    if (major != 4 or minor != 0 or compression not in range(1, 7)
            or not 4096 <= block_size <= (1 << 20) or block_log > 20
            or 1 << block_log != block_size or not 96 <= bytes_used <= MAX_FIRMWARE):
        raise FirmwareInputError("invalid SquashFS v4 superblock")
    available = len(data) - offset
    verified = bytes_used <= available
    details = (
        ("endian", endian), ("version", f"{major}.{minor}"), ("inode_count", str(inode_count)),
        ("block_size", str(block_size)), ("block_log", str(block_log)),
        ("fragments", str(fragments)), ("compression_id", str(compression)),
        ("flags", f"0x{flags:x}"), ("id_count", str(id_count)),
        ("bytes_used", str(bytes_used)), ("mkfs_time", str(mkfs_time)),
    )
    return FirmwareComponent("squashfs", offset, bytes_used, verified, details)


def _marker_offsets(data: bytes, marker: bytes, cap: int = 32) -> tuple[int, ...]:
    rows = []
    start = 0
    while len(rows) < cap:
        offset = data.find(marker, start)
        if offset < 0:
            break
        rows.append(offset)
        start = offset + 1
    return tuple(rows)


def _raw_architecture_leads(data: bytes) -> list[FirmwareLead]:
    rows = []
    if len(data) >= 8:
        initial_sp, reset = struct.unpack_from("<II", data, 0)
        reset_address = reset & ~1
        # Cortex-M images are commonly linked at zero or in internal flash.
        # Requiring the vector to land in one of those bounded ranges avoids
        # treating roughly one in every few hundred random prefixes as a
        # vector table merely because the first word resembles SRAM.
        reset_in_image = 8 <= reset_address < len(data)
        reset_in_flash = 0x08000000 <= reset_address < 0x20000000
        if (0x20000000 <= initial_sp < 0x40000000 and initial_sp % 4 == 0
                and reset & 1 and (reset_in_image or reset_in_flash)):
            rows.append(FirmwareLead(
                "architecture", "arm-cortex-m", 96, 0,
                (f"initial SRAM stack pointer 0x{initial_sp:x}", f"Thumb reset vector 0x{reset:x}"),
                "Map the vector table and follow the reset handler statically.",
            ))
    # Four-byte exact examples plus locality are deliberately conservative.
    # Two-byte prologue fragments become virtually certain to occur somewhere
    # in a large random firmware image and therefore are not evidence alone.
    patterns = (
        ("arm", (b"\xf0\x41\x2d\xe9", b"\x10\xb5\x00\xaf", b"\x10\xbd\x00\xbf"), "ARM/Thumb prologue/epilogue encodings"),
        ("mips-big", (b"\x27\xbd\xff\xe0", b"\xaf\xbf\x00\x1c", b"\x03\xe0\x00\x08"), "big-endian MIPS stack/return encodings"),
        ("mips-little", (b"\xe0\xff\xbd\x27", b"\x1c\x00\xbf\xaf", b"\x08\x00\xe0\x03"), "little-endian MIPS stack/return encodings"),
        ("riscv", (b"\x13\x01\x01\xff", b"\x23\x2e\x11\x00", b"\x67\x80\x00\x00"), "RISC-V stack/save/return encodings"),
    )
    for name, signatures, explanation in patterns:
        found = [(signature.hex(), data.find(signature)) for signature in signatures if data.find(signature) >= 0]
        if len(found) >= 2 and max(offset for _sig, offset in found) - min(offset for _sig, offset in found) <= 0x10000:
            rows.append(FirmwareLead(
                "architecture", name, 82 + min(12, len(found) * 4), min(offset for _sig, offset in found),
                tuple([explanation, *(f"{sig} at 0x{offset:x}" for sig, offset in found)]),
                "Confirm endianness and load address before generating a disassembly plan.",
            ))
    return rows


def analyze_firmware(data: bytes) -> FirmwareReport:
    data = _blob(data)
    leads: list[FirmwareLead] = []
    components: list[FirmwareComponent] = []
    warnings = []
    elf = _elf(data)
    if elf is not None and elf[0] in {"arm", "aarch64", "mips", "riscv"}:
        arch, bits, endian, flags = elf
        confidence = 100 if arch in {"arm", "aarch64", "mips", "riscv"} else 70
        evidence = [f"validated ELF{bits} {endian} header", f"e_flags=0x{flags:x}"]
        if arch == "riscv":
            evidence.append("RVC enabled" if flags & 1 else "RVC flag clear")
        if arch == "arm":
            evidence.append(f"ARM EABI version {(flags >> 24) & 0xff}")
        leads.append(FirmwareLead(
            "architecture", arch, confidence, 0, tuple(evidence),
            "Use the validated architecture/endian tuple for offline disassembly.",
        ))
    scanners = (
        (b"\x27\x05\x19\x56", parse_uimage, "uImage"),
        (b"\xd0\x0d\xfe\xed", parse_dtb, "DTB"),
        (b"hsqs", parse_squashfs, "SquashFS"),
        (b"sqsh", parse_squashfs, "SquashFS"),
    )
    seen_components = set()
    for marker, parser, label in scanners:
        for offset in _marker_offsets(data, marker):
            if len(components) >= MAX_COMPONENTS:
                warnings.append("component cap reached")
                break
            try:
                component = parser(data, offset=offset)
            except FirmwareInputError as exc:
                warnings.append(f"rejected {label} marker at 0x{offset:x}: {exc}")
                continue
            key = (component.kind, component.offset)
            if key not in seen_components:
                components.append(component)
                seen_components.add(key)
                leads.append(FirmwareLead(
                    "container", component.kind, 100 if component.verified else 78, offset,
                    ("bounded structural header validated", f"declared_size={component.declared_size}"),
                    "Carve the declared range and continue with format-specific static analysis.",
                ))
                if component.kind == "uimage":
                    architecture = dict(component.details).get("architecture")
                    if architecture in {"arm", "aarch64", "mips", "mips64", "riscv", "ppc", "openrisc", "arc", "xtensa"}:
                        leads.append(FirmwareLead(
                            "architecture", architecture, 96 if component.verified else 82, offset,
                            ("U-Boot uImage architecture field",),
                            "Use the uImage load/entry addresses with this architecture in an offline disassembly plan.",
                        ))
    raw_markers = (
        (b"UBI#", "ubi", "UBI erase-count header"), (b"HDR0", "trx", "Broadcom TRX header"),
        (b"-rom1fs-", "romfs", "ROMFS volume marker"), (b"\x45\x3d\xcd\x28", "cramfs", "CramFS magic"),
    )
    for marker, name, explanation in raw_markers:
        offset = data.find(marker)
        if offset >= 0:
            leads.append(FirmwareLead(
                "container", name, 82, offset, (explanation,),
                "Validate the full header before carving; treat the marker as a lead only.",
            ))
    ecosystem = (
        (b"U-Boot", "u-boot"), (b"Linux version ", "linux-kernel"),
        (b"BusyBox", "busybox"), (b"OpenWrt", "openwrt"), (b"/dev/mtd", "mtd-layout"),
    )
    for marker, name in ecosystem:
        offset = data.find(marker)
        if offset >= 0:
            leads.append(FirmwareLead(
                "ecosystem", name, 76, offset, (marker.decode("ascii") + " marker",),
                "Correlate nearby printable configuration and partition strings.",
            ))
    leads.extend(_raw_architecture_leads(data))
    unique = {(row.category, row.name, row.offset): row for row in leads}
    ordered = tuple(sorted(unique.values(), key=lambda row: (row.offset, row.category, row.name)))
    return FirmwareReport(len(data), ordered, tuple(sorted(components, key=lambda row: (row.offset, row.kind))),
                          tuple(warnings[:MAX_COMPONENTS]))


__all__ = [
    "FirmwareInputError", "FirmwareLead", "FirmwareComponent", "FirmwareReport",
    "parse_uimage", "parse_dtb", "parse_squashfs", "analyze_firmware",
]
