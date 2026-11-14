"""Checked, bounded filesystem metadata readers for supplied disk bytes.

This module complements :mod:`carving`: it never scans a device, mounts an image, invokes a
tool, or guesses filesystem geometry.  Callers provide boot sectors, records, allocation tables,
or superblocks.  A value is returned only after the relevant signature, bounds, alignment, and
integrity checks pass.

Implemented depth:

* NTFS BPB, update-sequence fixups, MFT attributes/runlists, deleted records, and USN v2/v3;
* FAT12/16/32 BPB, checked cluster chains, LFN/short directory entries, and file recovery;
* ext2/3/4 superblocks, inodes/direct blocks/extents, and JBD2 descriptor/commit/revoke headers;
* APFS Fletcher-64 checked NX superblocks;
* Btrfs CRC32C checked superblocks;
* VSS volume headers and declarative VSS/APFS/Btrfs snapshot reconstruction plans.

The snapshot plans are data only.  They describe later sandbox work and never execute it.
"""

from __future__ import annotations

import datetime as dt
import struct
import uuid
from dataclasses import dataclass


MAX_RECORD = 16 * 1024 * 1024
MAX_RUNS = 1_000_000
MAX_CHAIN = 4_000_000
MAX_FILE = 256 * 1024 * 1024
MAX_U16 = (1 << 16) - 1
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
MAX_I64 = (1 << 63) - 1
UTC = dt.timezone.utc


def _integer(value: object, minimum: int = 0, maximum: int = MAX_U64) -> bool:
    """True only for a bounded integer, deliberately excluding ``bool``."""
    return type(value) is int and minimum <= value <= maximum


def _pow2(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _u16(data: bytes, offset: int, endian: str = "<") -> int | None:
    try:
        return struct.unpack_from(endian + "H", data, offset)[0]
    except struct.error:
        return None


def _u32(data: bytes, offset: int, endian: str = "<") -> int | None:
    try:
        return struct.unpack_from(endian + "I", data, offset)[0]
    except struct.error:
        return None


def _u64(data: bytes, offset: int, endian: str = "<") -> int | None:
    try:
        return struct.unpack_from(endian + "Q", data, offset)[0]
    except struct.error:
        return None


def _filetime(value: int) -> dt.datetime | None:
    if value <= 0:
        return None
    try:
        stamp = dt.datetime(1601, 1, 1, tzinfo=UTC) + dt.timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None
    return stamp if 1601 <= stamp.year <= 9999 else None


# ---------------------------------------------------------------------------
# NTFS


@dataclass(frozen=True)
class NtfsBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_lcn: int
    mft_mirror_lcn: int
    record_size: int
    index_record_size: int
    serial: int


@dataclass(frozen=True)
class DataRun:
    vcn: int
    length: int
    lcn: int | None


@dataclass(frozen=True)
class NtfsAttribute:
    type_code: int
    attribute_id: int
    name: str
    resident: bool
    flags: int
    value: bytes | None
    runs: tuple[DataRun, ...]
    data_size: int
    allocated_size: int
    initialized_size: int


@dataclass(frozen=True)
class NtfsRecord:
    record_number: int
    sequence: int
    in_use: bool
    directory: bool
    hard_links: int
    base_record: int
    names: tuple[str, ...]
    attributes: tuple[NtfsAttribute, ...]


@dataclass(frozen=True)
class UsnRecord:
    major: int
    file_reference: int | str
    parent_reference: int | str
    usn: int
    timestamp: dt.datetime
    reason: int
    source: int
    security_id: int
    file_attributes: int
    name: str


def parse_ntfs_boot(data: object) -> NtfsBoot | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 512 or raw[3:11] != b"NTFS    " or raw[510:512] != b"\x55\xaa":
        return None
    if raw[0] not in (0xEB, 0xE9):
        return None
    bps = _u16(raw, 11)
    spc = raw[13]
    total = _u64(raw, 40)
    mft = _u64(raw, 48)
    mirror = _u64(raw, 56)
    serial = _u64(raw, 72)
    if (bps not in (512, 1024, 2048, 4096) or not _pow2(spc) or spc > 128
            or not total or mft is None or mirror is None or serial is None):
        return None
    clusters = total // spc
    if not clusters or mft >= clusters or mirror >= clusters:
        return None
    cluster_size = bps * spc

    def encoded_size(byte: int) -> int | None:
        signed = byte - 256 if byte & 0x80 else byte
        size = (1 << -signed) if signed < 0 else cluster_size * signed
        return size if 256 <= size <= 65536 and _pow2(size) else None

    record_size = encoded_size(raw[64])
    index_size = encoded_size(raw[68])
    if record_size is None or index_size is None:
        return None
    return NtfsBoot(bps, spc, cluster_size, total, mft, mirror,
                    record_size, index_size, serial)


def apply_ntfs_fixup(record: object, sector_size: int) -> bytes | None:
    if (not isinstance(record, (bytes, bytearray, memoryview))
            or not _integer(sector_size, 512, 4096)
            or sector_size not in (512, 1024, 2048, 4096)):
        return None
    raw = bytes(record)
    if (len(raw) < 48 or len(raw) > MAX_RECORD or len(raw) % sector_size
            or raw[:4] not in (b"FILE", b"INDX", b"RCRD", b"RSTR")):
        return None
    usa_offset = _u16(raw, 4)
    usa_count = _u16(raw, 6)
    expected = len(raw) // sector_size + 1
    if (usa_offset is None or usa_count != expected or usa_offset < 8
            or usa_offset + usa_count * 2 > len(raw)):
        return None
    sequence = raw[usa_offset:usa_offset + 2]
    if sequence == b"\x00\x00":
        return None
    fixed = bytearray(raw)
    for index in range(1, usa_count):
        tail = index * sector_size - 2
        if raw[tail:tail + 2] != sequence:
            return None
        fixed[tail:tail + 2] = raw[usa_offset + index * 2:usa_offset + index * 2 + 2]
    return bytes(fixed)


def decode_ntfs_runlist(data: object, *, start_vcn: int = 0,
                        start_lcn: int = 0) -> tuple[DataRun, ...]:
    if (not isinstance(data, (bytes, bytearray, memoryview))
            or not _integer(start_vcn, maximum=MAX_I64)
            or not _integer(start_lcn, maximum=MAX_I64)):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_RECORD:
        return ()
    position, vcn, lcn = 0, start_vcn, start_lcn
    out: list[DataRun] = []
    while position < len(raw) and len(out) < MAX_RUNS:
        header = raw[position]
        position += 1
        if header == 0:
            return tuple(out) if out and not any(raw[position:]) else ()
        length_size, offset_size = header & 0x0F, header >> 4
        if not 1 <= length_size <= 8 or offset_size > 8 or position + length_size + offset_size > len(raw):
            return ()
        length = int.from_bytes(raw[position:position + length_size], "little")
        position += length_size
        if length <= 0:
            return ()
        if offset_size:
            delta = int.from_bytes(raw[position:position + offset_size], "little", signed=True)
            position += offset_size
            lcn += delta
            if lcn < 0 or lcn > MAX_I64:
                return ()
            physical: int | None = lcn
        else:
            physical = None
        out.append(DataRun(vcn, length, physical))
        vcn += length
        if vcn > MAX_U64:
            return ()
    return ()


def _ntfs_name(value: bytes) -> str | None:
    if len(value) < 66:
        return None
    count = value[64]
    namespace = value[65]
    if namespace > 3 or count == 0 or 66 + count * 2 > len(value):
        return None
    try:
        name = value[66:66 + count * 2].decode("utf-16-le", "strict")
    except UnicodeDecodeError:
        return None
    if not name or "\x00" in name or any(ord(char) < 0x20 for char in name):
        return None
    return name


def parse_ntfs_record(record: object, *, sector_size: int = 512) -> NtfsRecord | None:
    fixed = apply_ntfs_fixup(record, sector_size)
    if fixed is None or fixed[:4] != b"FILE":
        return None
    sequence = _u16(fixed, 16)
    links = _u16(fixed, 18)
    first = _u16(fixed, 20)
    flags = _u16(fixed, 22)
    used = _u32(fixed, 24)
    allocated = _u32(fixed, 28)
    base = _u64(fixed, 32)
    number = _u32(fixed, 44) if len(fixed) >= 48 else 0
    if (None in (sequence, links, first, flags, used, allocated, base)
            or first < 48 or first % 8 or used > allocated or allocated > len(fixed)
            or used < first + 4):
        return None
    attributes: list[NtfsAttribute] = []
    names: list[str] = []
    position = first
    saw_end = False
    while position + 4 <= used and len(attributes) < 4096:
        type_code = _u32(fixed, position)
        if type_code == 0xFFFFFFFF:
            saw_end = True
            break
        length = _u32(fixed, position + 4)
        if length is None or length < 24 or length % 8 or position + length > used:
            return None
        nonresident = fixed[position + 8]
        name_length = fixed[position + 9]
        name_offset = _u16(fixed, position + 10)
        attr_flags = _u16(fixed, position + 12)
        attr_id = _u16(fixed, position + 14)
        if (nonresident not in (0, 1) or name_offset is None or attr_flags is None
                or attr_id is None or attr_flags & ~0xC001):
            return None
        attr_name = ""
        if name_length:
            if name_offset < 16 or name_offset + name_length * 2 > length:
                return None
            try:
                attr_name = fixed[position + name_offset:position + name_offset + name_length * 2].decode("utf-16-le")
            except UnicodeDecodeError:
                return None
        value: bytes | None = None
        runs: tuple[DataRun, ...] = ()
        data_size = 0
        allocated_size = 0
        initialized_size = 0
        if nonresident == 0:
            value_length = _u32(fixed, position + 16)
            value_offset = _u16(fixed, position + 20)
            if (value_length is None or value_offset is None or attr_flags
                    or value_offset < 24
                    or value_offset + value_length > length):
                return None
            value = fixed[position + value_offset:position + value_offset + value_length]
            data_size = value_length
            allocated_size = value_length
            initialized_size = value_length
        else:
            if length < 64:
                return None
            start_vcn = _u64(fixed, position + 16)
            last_vcn = _u64(fixed, position + 24)
            run_offset = _u16(fixed, position + 32)
            compression_unit = _u16(fixed, position + 34)
            allocated_size_value = _u64(fixed, position + 40)
            data_size_value = _u64(fixed, position + 48)
            initialized_size_value = _u64(fixed, position + 56)
            if (None in (start_vcn, last_vcn, run_offset, data_size_value)
                    or compression_unit is None or allocated_size_value is None
                    or initialized_size_value is None or last_vcn < start_vcn
                    or run_offset < 64 or run_offset >= length
                    or initialized_size_value > data_size_value
                    or (attr_flags & 0x0001 and compression_unit == 0)
                    or (not attr_flags & 0x0001 and compression_unit != 0)):
                return None
            runs = decode_ntfs_runlist(fixed[position + run_offset:position + length], start_vcn=start_vcn)
            if not runs or sum(run.length for run in runs) != last_vcn - start_vcn + 1:
                return None
            data_size = data_size_value
            allocated_size = allocated_size_value
            initialized_size = initialized_size_value
        attribute = NtfsAttribute(type_code, attr_id, attr_name, nonresident == 0,
                                  attr_flags, value, runs, data_size,
                                  allocated_size, initialized_size)
        attributes.append(attribute)
        if type_code == 0x30 and value is not None:
            name = _ntfs_name(value)
            if name is None:
                return None
            names.append(name)
        position += length
    if not saw_end:
        return None
    return NtfsRecord(number or 0, sequence, bool(flags & 1), bool(flags & 2),
                      links, base & ((1 << 48) - 1), tuple(dict.fromkeys(names)),
                      tuple(attributes))


def recover_ntfs_attribute(image: object, attribute: NtfsAttribute,
                           cluster_size: int) -> bytes | None:
    """Recover one checked resident or uncompressed nonresident NTFS attribute.

    Sparse runs are materialized as zeroes.  Compressed and EFS-encrypted streams decline rather
    than returning bytes that look like a decoded file but are not one.
    """
    if (not isinstance(image, (bytes, bytearray, memoryview))
            or not _integer(cluster_size, 512, 65536) or not _pow2(cluster_size)
            or not isinstance(attribute, NtfsAttribute)
            or not _integer(attribute.type_code, 1, MAX_U32)
            or not _integer(attribute.attribute_id, maximum=MAX_U16)
            or not isinstance(attribute.name, str) or len(attribute.name) > 255
            or "\x00" in attribute.name
            or type(attribute.resident) is not bool
            or not _integer(attribute.flags, maximum=MAX_U16)
            or not _integer(attribute.data_size, maximum=MAX_FILE)
            or not _integer(attribute.allocated_size, maximum=MAX_FILE + 65536)
            or not _integer(attribute.initialized_size, maximum=MAX_FILE)
            or attribute.initialized_size > attribute.data_size
            or not isinstance(attribute.runs, tuple)):
        return None
    if attribute.resident:
        if (attribute.flags or type(attribute.value) is not bytes or attribute.runs
                or len(attribute.value) != attribute.data_size
                or attribute.allocated_size != attribute.data_size
                or attribute.initialized_size != attribute.data_size):
            return None
        return attribute.value
    if (attribute.value is not None or not attribute.runs or attribute.flags & ~0xC001
            or attribute.flags & 0x4001 or attribute.data_size <= 0):
        return None
    try:
        raw = memoryview(image).cast("B")
    except (TypeError, ValueError):
        return None
    expected_vcn = 0
    capacity = 0
    physical_capacity = 0
    has_sparse_run = False
    for run in attribute.runs:
        if (not isinstance(run, DataRun)
                or not _integer(run.vcn, maximum=MAX_U64)
                or not _integer(run.length, 1, MAX_CHAIN)
                or run.lcn is not None and not _integer(run.lcn, maximum=MAX_I64)
                or run.vcn != expected_vcn):
            return None
        expected_vcn += run.length
        capacity += run.length * cluster_size
        if capacity > MAX_FILE + cluster_size:
            return None
        if run.lcn is None:
            has_sparse_run = True
        else:
            physical_capacity += run.length * cluster_size
            offset = run.lcn * cluster_size
            if offset + run.length * cluster_size > len(raw):
                return None
    if (capacity < attribute.data_size or attribute.allocated_size != physical_capacity
            or has_sparse_run and not attribute.flags & 0x8000
            or not has_sparse_run and physical_capacity != capacity):
        return None
    recovered = bytearray(attribute.data_size)
    for run in attribute.runs:
        logical = run.vcn * cluster_size
        if logical >= attribute.initialized_size:
            break
        take = min(run.length * cluster_size, attribute.initialized_size - logical)
        if run.lcn is not None:
            offset = run.lcn * cluster_size
            recovered[logical:logical + take] = raw[offset:offset + take]
    return bytes(recovered)


def parse_usn_records(data: object) -> tuple[UsnRecord, ...]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_FILE:
        return ()
    out: list[UsnRecord] = []
    position = 0
    while position < len(raw) and len(out) < 2_000_000:
        if raw[position:position + 8] == b"\x00" * min(8, len(raw) - position):
            return tuple(out) if out and not any(raw[position:]) else ()
        length = _u32(raw, position)
        major = _u16(raw, position + 4)
        minor = _u16(raw, position + 6)
        if (length is None or major not in (2, 3) or minor != 0 or length % 8
                or position + length > len(raw)):
            return ()
        if major == 2:
            if length < 60:
                return ()
            file_ref = _u64(raw, position + 8)
            parent_ref = _u64(raw, position + 16)
            usn = _u64(raw, position + 24)
            timestamp = _u64(raw, position + 32)
            reason = _u32(raw, position + 40)
            source = _u32(raw, position + 44)
            security = _u32(raw, position + 48)
            attrs = _u32(raw, position + 52)
            name_length = _u16(raw, position + 56)
            name_offset = _u16(raw, position + 58)
        else:
            if length < 76:
                return ()
            file_ref = raw[position + 8:position + 24].hex()
            parent_ref = raw[position + 24:position + 40].hex()
            usn = _u64(raw, position + 40)
            timestamp = _u64(raw, position + 48)
            reason = _u32(raw, position + 56)
            source = _u32(raw, position + 60)
            security = _u32(raw, position + 64)
            attrs = _u32(raw, position + 68)
            name_length = _u16(raw, position + 72)
            name_offset = _u16(raw, position + 74)
        if (None in (file_ref, parent_ref, usn, timestamp, reason, source, security,
                     attrs, name_length, name_offset) or not name_length or name_length % 2
                or name_offset < (60 if major == 2 else 76)
                or name_offset + name_length > length):
            return ()
        try:
            name = raw[position + name_offset:position + name_offset + name_length].decode("utf-16-le")
        except UnicodeDecodeError:
            return ()
        stamp = _filetime(timestamp)
        if (stamp is None or not name or "\x00" in name
                or any(ord(character) < 0x20 for character in name)):
            return ()
        out.append(UsnRecord(major, file_ref, parent_ref, usn, stamp, reason,
                             source, security, attrs, name))
        position += length
    return tuple(out) if position == len(raw) and out else ()


# ---------------------------------------------------------------------------
# FAT


@dataclass(frozen=True)
class FatBoot:
    fat_type: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    sectors_per_fat: int
    root_entries: int
    root_cluster: int | None
    total_sectors: int
    first_data_sector: int
    cluster_count: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


@dataclass(frozen=True)
class FatDirEntry:
    name: str
    short_name: str
    deleted: bool
    attributes: int
    first_cluster: int
    size: int


def parse_fat_boot(data: object) -> FatBoot | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 512 or raw[510:512] != b"\x55\xaa" or raw[0] not in (0xEB, 0xE9):
        return None
    bps = _u16(raw, 11)
    spc = raw[13]
    reserved = _u16(raw, 14)
    fats = raw[16]
    root_entries = _u16(raw, 17)
    total16 = _u16(raw, 19)
    spf16 = _u16(raw, 22)
    total32 = _u32(raw, 32)
    spf32 = _u32(raw, 36)
    if (bps not in (512, 1024, 2048, 4096) or not _pow2(spc) or spc > 128
            or not reserved or fats not in (1, 2, 3, 4) or root_entries is None
            or total16 is None or spf16 is None or total32 is None or spf32 is None):
        return None
    total = total16 or total32
    spf = spf16 or spf32
    if not total or not spf or total16 and total32:
        return None
    root_sectors = ((root_entries * 32) + bps - 1) // bps
    first_data = reserved + fats * spf + root_sectors
    if first_data >= total:
        return None
    clusters = (total - first_data) // spc
    fat_type = "FAT12" if clusters < 4085 else "FAT16" if clusters < 65525 else "FAT32"
    required_fat_bytes = ((clusters + 2) * 3 + 1) // 2 if fat_type == "FAT12" else (
        (clusters + 2) * (2 if fat_type == "FAT16" else 4))
    if spf * bps < required_fat_bytes:
        return None
    if fat_type == "FAT32":
        root_cluster = _u32(raw, 44)
        if root_entries != 0 or spf16 != 0 or root_cluster is None or not 2 <= root_cluster < clusters + 2:
            return None
    else:
        root_cluster = None
        if root_entries == 0 or spf16 == 0:
            return None
    return FatBoot(fat_type, bps, spc, reserved, fats, spf, root_entries,
                   root_cluster, total, first_data, clusters)


def _fat_lfn_checksum(short: bytes) -> int:
    value = 0
    for byte in short:
        value = ((value & 1) << 7) + (value >> 1) + byte
        value &= 0xFF
    return value


def _fat_lfn_piece(entry: bytes) -> str | None:
    raw = entry[1:11] + entry[14:26] + entry[28:32]
    chars = []
    terminated = False
    for index in range(0, len(raw), 2):
        value = int.from_bytes(raw[index:index + 2], "little")
        if value == 0:
            terminated = True
            continue
        if value == 0xFFFF:
            if not terminated:
                return None
            continue
        if terminated:
            return None
        chars.append(value)
    try:
        return b"".join(value.to_bytes(2, "little") for value in chars).decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def parse_fat_directory(data: object) -> tuple[FatDirEntry, ...]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_FILE or len(raw) % 32:
        return ()
    out: list[FatDirEntry] = []
    lfn: list[tuple[int, str, int]] = []
    for position in range(0, len(raw), 32):
        entry = raw[position:position + 32]
        if entry[0] == 0:
            return tuple(out) if out and not lfn else ()
        attributes = entry[11]
        if attributes == 0x0F:
            sequence = entry[0]
            piece = _fat_lfn_piece(entry)
            if (piece is None or sequence & 0xA0 or entry[12] != 0
                    or entry[26:28] != b"\x00\x00"
                    or not 1 <= (sequence & 0x1F) <= 20):
                return ()
            lfn.append((sequence, piece, entry[13]))
            continue
        deleted = entry[0] == 0xE5
        # 0x05 is a valid first byte: it escapes a real leading 0xE5 (KANJI lead byte) and is
        # converted back to 0xE5 below, so it must not be rejected as a control character here.
        if entry[0] < 0x20 and entry[0] != 0x05 and not deleted:
            return ()
        short_raw = entry[:11]
        display = bytearray(short_raw)
        if deleted:
            display[0] = ord("?")
        elif display[0] == 0x05:
            display[0] = 0xE5
        try:
            base = bytes(display[:8]).decode("cp437").rstrip()
            ext = bytes(display[8:11]).decode("cp437").rstrip()
        except UnicodeDecodeError:
            return ()
        if not base or any(ord(char) < 0x20 for char in base + ext):
            return ()
        short_name = base + (("." + ext) if ext else "")
        name = short_name
        if lfn and not deleted:
            checksum = _fat_lfn_checksum(short_raw)
            if any(item[2] != checksum for item in lfn):
                return ()
            expected = len(lfn)
            numbers = [item[0] & 0x1F for item in lfn]
            if not lfn[0][0] & 0x40 or numbers != list(range(expected, 0, -1)):
                return ()
            name = "".join(item[1] for item in reversed(lfn))
            if not name or "\x00" in name:
                return ()
        lfn.clear()
        high = _u16(entry, 20) or 0
        low = _u16(entry, 26) or 0
        size = _u32(entry, 28)
        if size is None:
            return ()
        cluster = (high << 16) | low
        if ((size or attributes & 0x10) and not attributes & 0x08 and cluster < 2):
            return ()
        out.append(FatDirEntry(name, short_name, deleted, attributes, cluster, size))
    # A directory that exactly fills its allocated cluster(s) has no room for a trailing
    # zero-terminator entry; accept the parsed entries as long as no LFN pieces are dangling.
    return tuple(out) if out and not lfn else ()


def _fat_value(table: bytes, cluster: int, fat_type: str) -> int | None:
    if fat_type == "FAT12":
        offset = cluster + cluster // 2
        if offset + 2 > len(table):
            return None
        pair = int.from_bytes(table[offset:offset + 2], "little")
        return (pair >> 4) & 0xFFF if cluster & 1 else pair & 0xFFF
    if fat_type == "FAT16":
        return _u16(table, cluster * 2)
    if fat_type == "FAT32":
        value = _u32(table, cluster * 4)
        return None if value is None else value & 0x0FFFFFFF
    return None


def follow_fat_chain(table: object, start_cluster: int, fat_type: str,
                     *, max_clusters: int = MAX_CHAIN) -> tuple[int, ...]:
    if (not isinstance(table, (bytes, bytearray, memoryview))
            or not _integer(start_cluster, 2, 0x0FFFFFF6)
            or not isinstance(fat_type, str)
            or fat_type not in {"FAT12", "FAT16", "FAT32"}
            or not _integer(max_clusters, 1, MAX_CHAIN)):
        return ()
    raw = bytes(table)
    eoc = {"FAT12": 0xFF8, "FAT16": 0xFFF8, "FAT32": 0x0FFFFFF8}[fat_type]
    bad = {"FAT12": 0xFF7, "FAT16": 0xFFF7, "FAT32": 0x0FFFFFF7}[fat_type]
    reserved = {"FAT12": 0xFF0, "FAT16": 0xFFF0, "FAT32": 0x0FFFFFF0}[fat_type]
    out, seen, current = [], set(), start_cluster
    while len(out) < max_clusters:
        if current in seen:
            return ()
        seen.add(current)
        out.append(current)
        value = _fat_value(raw, current, fat_type)
        if value is None:
            return ()
        if value >= eoc:
            return tuple(out)
        if value in (0, 1, bad) or value < 2 or reserved <= value < eoc:
            return ()
        current = value
    return ()


def _valid_fat_boot(boot: object) -> bool:
    if (not isinstance(boot, FatBoot) or not isinstance(boot.fat_type, str)
            or boot.fat_type not in {"FAT12", "FAT16", "FAT32"}
            or not _integer(boot.bytes_per_sector, 512, 4096)
            or boot.bytes_per_sector not in (512, 1024, 2048, 4096)
            or not _integer(boot.sectors_per_cluster, 1, 128)
            or not _pow2(boot.sectors_per_cluster)
            or not _integer(boot.reserved_sectors, 1, MAX_U16)
            or not _integer(boot.fat_count, 1, 4)
            or not _integer(boot.sectors_per_fat, 1, MAX_U32)
            or not _integer(boot.root_entries, maximum=MAX_U16)
            or not _integer(boot.total_sectors, 1, MAX_U32)
            or not _integer(boot.first_data_sector, 1, MAX_U32)
            or not _integer(boot.cluster_count, 1, 0x0FFFFFF5)):
        return False
    root_sectors = ((boot.root_entries * 32) + boot.bytes_per_sector - 1) // boot.bytes_per_sector
    first_data = boot.reserved_sectors + boot.fat_count * boot.sectors_per_fat + root_sectors
    if (boot.first_data_sector != first_data or first_data >= boot.total_sectors
            or boot.cluster_count != ((boot.total_sectors - first_data)
                                      // boot.sectors_per_cluster)):
        return False
    expected_type = ("FAT12" if boot.cluster_count < 4085 else
                     "FAT16" if boot.cluster_count < 65525 else "FAT32")
    if boot.fat_type != expected_type:
        return False
    required = ((boot.cluster_count + 2) * 3 + 1) // 2 if expected_type == "FAT12" else (
        (boot.cluster_count + 2) * (2 if expected_type == "FAT16" else 4))
    if boot.sectors_per_fat * boot.bytes_per_sector < required:
        return False
    if expected_type == "FAT32":
        return (boot.root_entries == 0 and _integer(boot.root_cluster, 2,
                                                    boot.cluster_count + 1))
    return boot.root_cluster is None and boot.root_entries > 0


def _valid_fat_entry(entry: object, boot: FatBoot) -> bool:
    return (isinstance(entry, FatDirEntry) and isinstance(entry.name, str) and entry.name != ""
            and len(entry.name) <= 255 and "\x00" not in entry.name
            and isinstance(entry.short_name, str) and entry.short_name != ""
            and len(entry.short_name) <= 12 and "\x00" not in entry.short_name
            and type(entry.deleted) is bool and _integer(entry.attributes, maximum=0xFF)
            and not entry.attributes & 0x18
            and _integer(entry.first_cluster, 2, boot.cluster_count + 1)
            and _integer(entry.size, 1, MAX_FILE))


def recover_fat_file(image: object, boot: FatBoot, fat_table: object,
                     entry: FatDirEntry) -> bytes | None:
    if (not isinstance(image, (bytes, bytearray, memoryview))
            or not isinstance(fat_table, (bytes, bytearray, memoryview))
            or not _valid_fat_boot(boot) or not _valid_fat_entry(entry, boot)):
        return None
    if len(fat_table) < boot.sectors_per_fat * boot.bytes_per_sector:
        return None
    chain = follow_fat_chain(fat_table, entry.first_cluster, boot.fat_type)
    needed = (entry.size + boot.cluster_size - 1) // boot.cluster_size
    if not chain or len(chain) != needed:
        return None
    try:
        raw = memoryview(image).cast("B")
    except (TypeError, ValueError):
        return None
    if len(raw) < boot.total_sectors * boot.bytes_per_sector:
        return None
    data = bytearray()
    for cluster in chain:
        if cluster >= boot.cluster_count + 2:
            return None
        offset = (boot.first_data_sector + (cluster - 2) * boot.sectors_per_cluster) * boot.bytes_per_sector
        if offset + boot.cluster_size > len(raw):
            return None
        data.extend(raw[offset:offset + boot.cluster_size])
        if len(data) >= entry.size:
            return bytes(data[:entry.size])
    return None


# ---------------------------------------------------------------------------
# ext and JBD2


@dataclass(frozen=True)
class ExtSuperblock:
    block_size: int
    blocks_count: int
    inodes_count: int
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    features_compat: int
    features_incompat: int
    features_ro_compat: int
    uuid: str
    volume_name: str
    journal_inode: int
    descriptor_size: int


@dataclass(frozen=True)
class ExtExtent:
    logical_block: int
    physical_block: int
    length: int
    unwritten: bool = False


@dataclass(frozen=True)
class ExtInode:
    mode: int
    uid: int
    gid: int
    size: int
    links: int
    deletion_time: int
    flags: int
    generation: int
    deleted: bool
    extents: tuple[ExtExtent, ...]
    direct_blocks: tuple[int, ...]
    extent_index_blocks: tuple[int, ...]
    inline_data: bytes | None


@dataclass(frozen=True)
class JournalBlock:
    block_type: str
    sequence: int
    referenced_blocks: tuple[int, ...]
    revoke_count: int


def parse_ext_superblock(data: object, *, offset: int | None = None) -> ExtSuperblock | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if offset is not None and not _integer(offset, maximum=MAX_I64):
        return None
    at = (1024 if len(raw) >= 2048 else 0) if offset is None else offset
    if at < 0 or at + 1024 > len(raw):
        return None
    sb = raw[at:at + 1024]
    if _u16(sb, 56) != 0xEF53:
        return None
    inodes = _u32(sb, 0)
    blocks_lo = _u32(sb, 4)
    log_block = _u32(sb, 24)
    blocks_per = _u32(sb, 32)
    inodes_per = _u32(sb, 40)
    revision = _u32(sb, 76)
    inode_size = _u16(sb, 88) if revision else 128
    compat = _u32(sb, 92)
    incompat = _u32(sb, 96)
    rocompat = _u32(sb, 100)
    journal_inode = _u32(sb, 224)
    if None in (inodes, blocks_lo, log_block, blocks_per, inodes_per, revision,
                inode_size, compat, incompat, rocompat, journal_inode):
        return None
    if log_block > 6 or revision not in (0, 1):
        return None
    block_size = 1024 << log_block
    blocks_hi = _u32(sb, 0x150) if incompat & 0x80 else 0
    blocks = blocks_lo | ((blocks_hi or 0) << 32)
    if (not inodes or not blocks or not blocks_per or not inodes_per
            or inode_size < 128 or inode_size > block_size or not _pow2(inode_size)):
        return None
    descriptor_size = (_u16(sb, 254) or 32) if incompat & 0x80 else 32
    if descriptor_size < 32 or descriptor_size > block_size or descriptor_size % 8:
        return None
    try:
        uid = str(uuid.UUID(bytes=sb[104:120]))
        volume = sb[120:136].split(b"\x00", 1)[0].decode("utf-8", "strict")
    except (ValueError, UnicodeDecodeError):
        return None
    return ExtSuperblock(block_size, blocks, inodes, blocks_per, inodes_per,
                         inode_size, compat, incompat, rocompat, uid, volume,
                         journal_inode, descriptor_size)


def _valid_ext_superblock(superblock: object) -> bool:
    if (not isinstance(superblock, ExtSuperblock)
            or not _integer(superblock.block_size, 1024, 65536)
            or not _pow2(superblock.block_size)
            or not _integer(superblock.blocks_count, 1, MAX_U64)
            or not _integer(superblock.inodes_count, 1, MAX_U32)
            or not _integer(superblock.blocks_per_group, 1, MAX_U32)
            or not _integer(superblock.inodes_per_group, 1, MAX_U32)
            or not _integer(superblock.inode_size, 128, superblock.block_size)
            or not _pow2(superblock.inode_size)
            or not _integer(superblock.features_compat, maximum=MAX_U32)
            or not _integer(superblock.features_incompat, maximum=MAX_U32)
            or not _integer(superblock.features_ro_compat, maximum=MAX_U32)
            or not isinstance(superblock.uuid, str)
            or not isinstance(superblock.volume_name, str)
            or len(superblock.volume_name) > 16 or "\x00" in superblock.volume_name
            or not _integer(superblock.journal_inode, maximum=superblock.inodes_count)
            or not _integer(superblock.descriptor_size, 32, superblock.block_size)
            or superblock.descriptor_size % 8):
        return False
    try:
        return str(uuid.UUID(superblock.uuid)) == superblock.uuid.lower()
    except (ValueError, AttributeError):
        return False


def parse_ext_inode(data: object, superblock: ExtSuperblock) -> ExtInode | None:
    if not isinstance(data, (bytes, bytearray, memoryview)) or not _valid_ext_superblock(superblock):
        return None
    raw = bytes(data)
    if len(raw) < superblock.inode_size or len(raw) > MAX_RECORD:
        return None
    inode = raw[:superblock.inode_size]
    mode = _u16(inode, 0)
    uid_lo = _u16(inode, 2)
    size_lo = _u32(inode, 4)
    deletion = _u32(inode, 20)
    gid_lo = _u16(inode, 24)
    links = _u16(inode, 26)
    flags = _u32(inode, 32)
    generation = _u32(inode, 100)
    size_hi = _u32(inode, 108) or 0
    if None in (mode, uid_lo, size_lo, deletion, gid_lo, links, flags, generation):
        return None
    file_type = mode & 0xF000
    if file_type not in {0x1000, 0x2000, 0x4000, 0x6000, 0x8000, 0xA000, 0xC000}:
        return None
    size = size_lo | (size_hi << 32 if file_type == 0x8000 else 0)
    extents: list[ExtExtent] = []
    direct: tuple[int, ...] = ()
    extent_index: tuple[int, ...] = ()
    inline_data: bytes | None = None
    block_area = inode[40:100]
    if file_type == 0xA000 and size <= len(block_area) and not flags & 0x00080000:
        inline_data = bytes(block_area[:size])
        if b"\x00" in inline_data:
            return None
    elif flags & 0x00080000:
        if len(block_area) < 12:
            return None
        magic, entries, maximum, depth, _gen = struct.unpack_from("<HHHHI", block_area)
        capacity = (len(block_area) - 12) // 12
        if (magic != 0xF30A or maximum == 0 or maximum > capacity
                or entries > maximum or depth > 5):
            return None
        if depth != 0:  # index nodes need their referenced extent block supplied separately
            if entries == 0 or 12 + entries * 12 > len(block_area):
                return None
            indexes: list[int] = []
            last_logical = -1
            for index in range(entries):
                logical, leaf_lo, leaf_hi, unused = struct.unpack_from(
                    "<IIHH", block_area, 12 + index * 12)
                leaf = (leaf_hi << 32) | leaf_lo
                if (unused or logical <= last_logical or not leaf
                        or leaf >= superblock.blocks_count):
                    return None
                indexes.append(leaf)
                last_logical = logical
            extent_index = tuple(indexes)
        else:
            if 12 + entries * 12 > len(block_area):
                return None
            last_end = -1
            for index in range(entries):
                logical, raw_len, start_hi, start_lo = struct.unpack_from("<IHHI", block_area, 12 + index * 12)
                # ext4 ee_len: values up to and including 0x8000 are initialized with that exact
                # length; only values strictly above 0x8000 are unwritten (length = ee_len - 0x8000).
                if raw_len <= 0x8000:
                    unwritten, length = False, raw_len
                else:
                    unwritten, length = True, raw_len - 0x8000
                physical = (start_hi << 32) | start_lo
                if (not length or not physical or logical <= last_end
                        or physical + length > superblock.blocks_count):
                    return None
                extents.append(ExtExtent(logical, physical, length, unwritten))
                last_end = logical + length - 1
    else:
        values = struct.unpack_from("<15I", block_area)
        if any(value >= superblock.blocks_count for value in values if value):
            return None
        direct = tuple(values[:12])
    uid = uid_lo | ((_u16(inode, 120) or 0) << 16 if len(inode) >= 128 else 0)
    gid = gid_lo | ((_u16(inode, 122) or 0) << 16 if len(inode) >= 128 else 0)
    return ExtInode(mode, uid, gid, size, links, deletion, flags, generation,
                    bool(deletion or links == 0), tuple(extents), direct,
                    extent_index, inline_data)


def _valid_ext_inode(inode: object, superblock: ExtSuperblock) -> bool:
    if (not isinstance(inode, ExtInode) or not _integer(inode.mode, 1, MAX_U16)
            or inode.mode & 0xF000 not in {0x1000, 0x2000, 0x4000, 0x6000,
                                         0x8000, 0xA000, 0xC000}
            or not _integer(inode.uid, maximum=MAX_U32)
            or not _integer(inode.gid, maximum=MAX_U32)
            or not _integer(inode.size, maximum=MAX_FILE)
            or not _integer(inode.links, maximum=MAX_U16)
            or not _integer(inode.deletion_time, maximum=MAX_U32)
            or not _integer(inode.flags, maximum=MAX_U32)
            or not _integer(inode.generation, maximum=MAX_U32)
            or type(inode.deleted) is not bool
            or inode.deleted != bool(inode.deletion_time or inode.links == 0)
            or not isinstance(inode.extents, tuple)
            or not isinstance(inode.direct_blocks, tuple)
            or not isinstance(inode.extent_index_blocks, tuple)
            or inode.inline_data is not None and type(inode.inline_data) is not bytes):
        return False
    expected_logical = -1
    for extent in inode.extents:
        if (not isinstance(extent, ExtExtent)
                or not _integer(extent.logical_block, maximum=MAX_U32)
                or not _integer(extent.physical_block, 1, superblock.blocks_count - 1)
                or not _integer(extent.length, 1, 0x7FFF)
                or type(extent.unwritten) is not bool
                or extent.logical_block <= expected_logical
                or extent.physical_block + extent.length > superblock.blocks_count):
            return False
        expected_logical = extent.logical_block + extent.length - 1
    if any(not _integer(block, maximum=superblock.blocks_count - 1)
           for block in inode.direct_blocks):
        return False
    if any(not _integer(block, 1, superblock.blocks_count - 1)
           for block in inode.extent_index_blocks):
        return False
    uses_extents = bool(inode.flags & 0x00080000)
    if uses_extents:
        if inode.direct_blocks or inode.inline_data is not None:
            return False
    elif inode.mode & 0xF000 == 0xA000 and inode.inline_data is not None:
        if inode.extents or inode.extent_index_blocks or inode.direct_blocks:
            return False
        if len(inode.inline_data) != inode.size or b"\x00" in inode.inline_data:
            return False
    elif (inode.extents or inode.extent_index_blocks or len(inode.direct_blocks) != 12
          or inode.inline_data is not None):
        return False
    return not (inode.extents and inode.extent_index_blocks)


def recover_ext_file(image: object, superblock: ExtSuperblock,
                     inode: ExtInode) -> bytes | None:
    """Recover a bounded regular file represented by direct blocks or leaf extents.

    Indirect block maps and non-leaf extent trees decline because following them without the
    separately checked index blocks would turn missing metadata into guessed bytes.
    """
    if (not isinstance(image, (bytes, bytearray, memoryview))
            or not _valid_ext_superblock(superblock)
            or not _valid_ext_inode(inode, superblock)
            or inode.mode & 0xF000 != 0x8000
            or inode.extent_index_blocks):
        return None
    if inode.size == 0:
        return b""
    try:
        raw = memoryview(image).cast("B")
    except (TypeError, ValueError):
        return None
    block_size = superblock.block_size
    blocks_needed = (inode.size + block_size - 1) // block_size
    output = bytearray(blocks_needed * block_size)
    if inode.flags & 0x00080000:
        for extent in inode.extents:
            if (extent.logical_block + extent.length > blocks_needed and
                    extent.logical_block >= blocks_needed):
                continue
            count = min(extent.length, blocks_needed - extent.logical_block)
            if count <= 0:
                continue
            destination = extent.logical_block * block_size
            length = count * block_size
            if extent.unwritten:
                continue
            source = extent.physical_block * block_size
            if source < 0 or source + length > len(raw):
                return None
            output[destination:destination + length] = raw[source:source + length]
    else:
        if blocks_needed > 12 or len(inode.direct_blocks) != 12:
            return None
        for logical, physical in enumerate(inode.direct_blocks[:blocks_needed]):
            if not physical:  # sparse hole
                continue
            source = physical * block_size
            if source + block_size > len(raw):
                return None
            destination = logical * block_size
            output[destination:destination + block_size] = raw[source:source + block_size]
    return bytes(output[:inode.size])


_JBD_TYPES = {1: "descriptor", 2: "commit", 3: "superblock-v1",
              4: "superblock-v2", 5: "revoke"}


def parse_jbd2_block(data: object) -> JournalBlock | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 1024 or len(raw) > 65536 or not _pow2(len(raw)):
        return None
    magic, kind, sequence = struct.unpack_from(">III", raw)
    if magic != 0xC03B3998 or kind not in _JBD_TYPES or sequence == 0:
        return None
    referenced: list[int] = []
    revoke_count = 0
    if kind == 1:
        # Basic descriptor tags (blocknr, flags).  Stop at SAME_UUID/LAST_TAG semantics;
        # UUID-bearing variants are intentionally left for a supplied feature profile.
        position = 12
        while position + 8 <= len(raw) and len(referenced) < 1_000_000:
            block, flags = struct.unpack_from(">II", raw, position)
            if block == 0 or flags & ~0xF:
                return None
            referenced.append(block)
            position += 8
            if not flags & 0x2:  # JBD2_FLAG_SAME_UUID absent => a 16-byte UUID follows
                if position + 16 > len(raw):
                    return None
                if not any(raw[position:position + 16]):
                    return None
                position += 16
            if flags & 0x8:  # JBD2_FLAG_LAST_TAG
                break
        if not referenced or not flags & 0x8:
            return None
    elif kind == 5:
        count = _u32(raw, 12, ">")
        if count is None or count < 16 or count > len(raw) or (count - 16) % 4:
            return None
        revoke_count = (count - 16) // 4
        referenced = list(struct.unpack_from(f">{revoke_count}I", raw, 16)) if revoke_count else []
        if any(block == 0 for block in referenced):
            return None
    return JournalBlock(_JBD_TYPES[kind], sequence, tuple(referenced), revoke_count)


# ---------------------------------------------------------------------------
# APFS, Btrfs, and VSS


@dataclass(frozen=True)
class ApfsSuperblock:
    object_id: int
    transaction_id: int
    block_size: int
    block_count: int
    features: int
    readonly_features: int
    incompatible_features: int
    uuid: str
    next_object_id: int
    next_transaction_id: int


@dataclass(frozen=True)
class ApfsCheckpointMapping:
    object_type: int
    object_subtype: int
    size: int
    filesystem_object_id: int
    object_id: int
    physical_address: int


@dataclass(frozen=True)
class ApfsCheckpointMap:
    object_id: int
    transaction_id: int
    last: bool
    mappings: tuple[ApfsCheckpointMapping, ...]


@dataclass(frozen=True)
class ApfsSnapshotMetadata:
    extentref_tree_object_id: int
    superblock_object_id: int
    create_time_ns: int
    change_time_ns: int
    inode_number: int
    extentref_tree_type: int
    flags: int
    name: str


@dataclass(frozen=True)
class BtrfsSuperblock:
    fsid: str
    bytenr: int
    generation: int
    root: int
    chunk_root: int
    total_bytes: int
    bytes_used: int
    num_devices: int
    sector_size: int
    node_size: int
    checksum_type: int
    root_level: int


@dataclass(frozen=True, order=True)
class BtrfsKey:
    object_id: int
    item_type: int
    offset: int


@dataclass(frozen=True)
class BtrfsLeafItem:
    key: BtrfsKey
    data_offset: int
    data: bytes


@dataclass(frozen=True)
class BtrfsNodePointer:
    key: BtrfsKey
    block_pointer: int
    generation: int


@dataclass(frozen=True)
class BtrfsTreeBlock:
    fsid: str
    bytenr: int
    generation: int
    owner: int
    level: int
    leaf_items: tuple[BtrfsLeafItem, ...]
    node_pointers: tuple[BtrfsNodePointer, ...]


@dataclass(frozen=True)
class BtrfsRootItem:
    root_id: int
    key_offset: int
    generation: int
    root_directory_id: int
    bytenr: int
    byte_limit: int
    bytes_used: int
    last_snapshot_generation: int
    flags: int
    references: int
    level: int
    readonly: bool
    root_uuid: str | None
    parent_uuid: str | None


@dataclass(frozen=True)
class VssHeader:
    offset: int
    version: int
    record_type: int
    relative_offset: int
    next_header_offset: int
    catalog_offset: int
    maximum_size: int
    volume_id: str
    storage_volume_id: str


@dataclass(frozen=True)
class SnapshotStep:
    stage: str
    purpose: str
    inputs: tuple[str, ...]
    output: str


@dataclass(frozen=True)
class SnapshotPlan:
    kind: str
    identifier: str
    steps: tuple[SnapshotStep, ...]
    notes: tuple[str, ...]


def apfs_fletcher64(data: object) -> int | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if not raw or len(raw) % 4:
        return None
    modulus = 0xFFFFFFFF
    sum1 = sum2 = 0
    for (word,) in struct.iter_unpack("<I", raw):
        sum1 = (sum1 + word) % modulus
        sum2 = (sum2 + sum1) % modulus
    low = (modulus - ((sum1 + sum2) % modulus)) % modulus
    high = (modulus - ((sum1 + low) % modulus)) % modulus
    return (high << 32) | low


def parse_apfs_superblock(data: object) -> ApfsSuperblock | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 4096 or len(raw) > 65536 or not _pow2(len(raw)) or raw[32:36] != b"NXSB":
        return None
    stored = _u64(raw, 0)
    calculated = apfs_fletcher64(raw[8:])
    oid = _u64(raw, 8)
    xid = _u64(raw, 16)
    object_type = _u32(raw, 24)
    block_size = _u32(raw, 36)
    block_count = _u64(raw, 40)
    features = _u64(raw, 48)
    ro = _u64(raw, 56)
    incompat = _u64(raw, 64)
    next_oid = _u64(raw, 88)
    next_xid = _u64(raw, 96)
    if (stored is None or calculated != stored or None in (oid, xid, object_type, block_size,
            block_count, features, ro, incompat, next_oid, next_xid)
            or object_type & 0xFFFF != 1 or block_size != len(raw)
            or block_size < 4096 or block_size > 65536 or not block_count
            or not oid or not xid or next_oid <= oid or next_xid <= xid):
        return None
    try:
        identifier = str(uuid.UUID(bytes=raw[72:88]))
    except ValueError:
        return None
    return ApfsSuperblock(oid, xid, block_size, block_count, features, ro,
                          incompat, identifier, next_oid, next_xid)


def parse_apfs_checkpoint_map(data: object) -> ApfsCheckpointMap | None:
    """Parse a checksum-verified APFS ``checkpoint_map_phys_t`` block."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 4096 or len(raw) > 65536 or not _pow2(len(raw)):
        return None
    stored = _u64(raw, 0)
    oid = _u64(raw, 8)
    xid = _u64(raw, 16)
    object_type = _u32(raw, 24)
    flags = _u32(raw, 32)
    count = _u32(raw, 36)
    if (stored is None or stored != apfs_fletcher64(raw[8:]) or oid is None or not oid
            or xid is None or not xid or object_type is None or object_type & 0xFFFF != 0x0C
            or flags is None or flags & ~1 or count is None or not count
            or count > (len(raw) - 40) // 40):
        return None
    mappings: list[ApfsCheckpointMapping] = []
    seen: set[int] = set()
    for index in range(count):
        values = struct.unpack_from("<IIIIQQQ", raw, 40 + index * 40)
        mapped_type, subtype, size, padding, fs_oid, mapped_oid, paddr = values
        if (not mapped_type & 0xFFFF or not size or size > MAX_RECORD or size % 8
                or padding or not mapped_oid or mapped_oid in seen or not paddr):
            return None
        seen.add(mapped_oid)
        mappings.append(ApfsCheckpointMapping(mapped_type, subtype, size, fs_oid,
                                               mapped_oid, paddr))
    return ApfsCheckpointMap(oid, xid, bool(flags & 1), tuple(mappings))


def parse_apfs_snapshot_metadata(data: object) -> ApfsSnapshotMetadata | None:
    """Parse one APFS snapshot-metadata-tree value supplied by a checked tree walker."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if len(raw) < 51 or len(raw) > 512:
        return None
    extentref, sblock, created, changed, inode = struct.unpack_from("<QQQQQ", raw)
    tree_type, flags, name_length = struct.unpack_from("<IIH", raw, 40)
    if (not extentref or not sblock or not created or changed < created or inode < 2
            or not tree_type & 0xFFFF or not name_length or name_length > 256
            or 50 + name_length != len(raw)):
        return None
    name_raw = raw[50:]
    if name_raw.endswith(b"\x00"):
        name_raw = name_raw[:-1]
    try:
        name = name_raw.decode("utf-8", "strict")
        dt.datetime.fromtimestamp(created // 1_000_000_000, UTC)
        dt.datetime.fromtimestamp(changed // 1_000_000_000, UTC)
    except (UnicodeDecodeError, OverflowError, OSError, ValueError):
        return None
    if (not name or "/" in name or "\x00" in name
            or any(ord(character) < 0x20 for character in name)):
        return None
    return ApfsSnapshotMetadata(extentref, sblock, created, changed, inode,
                                tree_type, flags, name)


_CRC32C_TABLE: tuple[int, ...] | None = None


def crc32c(data: object) -> int | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        polynomial = 0x82F63B78
        table = []
        for value in range(256):
            crc = value
            for _ in range(8):
                crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
            table.append(crc)
        _CRC32C_TABLE = tuple(table)
    crc = 0xFFFFFFFF
    for byte in bytes(data):
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def parse_btrfs_superblock(data: object, *, offset: int | None = None) -> BtrfsSuperblock | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if offset is not None and not _integer(offset, maximum=MAX_I64):
        return None
    at = (0x10000 if len(raw) >= 0x11000 else 0) if offset is None else offset
    if at < 0 or at + 4096 > len(raw):
        return None
    sb = raw[at:at + 4096]
    if sb[64:72] != b"_BHRfS_M":
        return None
    checksum_type = _u16(sb, 196)
    expected = crc32c(sb[32:])
    if checksum_type != 0 or expected is None or _u32(sb, 0) != expected or any(sb[4:32]):
        return None
    bytenr = _u64(sb, 48)
    generation = _u64(sb, 72)
    root = _u64(sb, 80)
    chunk_root = _u64(sb, 88)
    total = _u64(sb, 112)
    used = _u64(sb, 120)
    devices = _u64(sb, 136)
    sector = _u32(sb, 144)
    node = _u32(sb, 148)
    root_level = sb[198]
    chunk_root_level = sb[199]
    system_chunk_size = _u32(sb, 160)
    if (None in (bytenr, generation, root, chunk_root, total, used, devices, sector, node)
            or bytenr != at or not generation or not root or not chunk_root or not total
            or used > total or not devices or sector < 4096 or not _pow2(sector)
            or node < sector or node > 65536 or not _pow2(node) or root_level > 8
            or chunk_root_level > 8 or system_chunk_size is None
            or system_chunk_size > 2048):
        return None
    try:
        fsid = str(uuid.UUID(bytes=sb[32:48]))
    except ValueError:
        return None
    if not any(sb[32:48]):
        return None
    return BtrfsSuperblock(fsid, bytenr, generation, root, chunk_root, total,
                           used, devices, sector, node, checksum_type, root_level)


def _btrfs_key(raw: bytes, offset: int) -> BtrfsKey | None:
    if offset < 0 or offset + 17 > len(raw):
        return None
    object_id = _u64(raw, offset)
    item_type = raw[offset + 8]
    key_offset = _u64(raw, offset + 9)
    if object_id is None or key_offset is None:
        return None
    return BtrfsKey(object_id, item_type, key_offset)


def _valid_btrfs_key(key: object) -> bool:
    return (isinstance(key, BtrfsKey)
            and _integer(key.object_id, maximum=MAX_U64)
            and _integer(key.item_type, maximum=0xFF)
            and _integer(key.offset, maximum=MAX_U64))


def _valid_btrfs_leaf_item(item: object) -> bool:
    return (isinstance(item, BtrfsLeafItem) and _valid_btrfs_key(item.key)
            and _integer(item.data_offset, 101, 65535)
            and type(item.data) is bytes and 0 < len(item.data) <= 65536
            and item.data_offset + len(item.data) <= 65536)


def parse_btrfs_tree_block(data: object, *, physical_bytenr: int | None = None,
                            expected_fsid: str | None = None) -> BtrfsTreeBlock | None:
    """Parse a CRC32C-verified Btrfs leaf or internal tree block."""
    if (not isinstance(data, (bytes, bytearray, memoryview))
            or physical_bytenr is not None
            and not _integer(physical_bytenr, maximum=MAX_U64)
            or expected_fsid is not None
            and (not isinstance(expected_fsid, str) or len(expected_fsid) > 64)):
        return None
    raw = bytes(data)
    if len(raw) < 4096 or len(raw) > 65536 or not _pow2(len(raw)):
        return None
    expected_checksum = crc32c(raw[32:])
    if expected_checksum is None or _u32(raw, 0) != expected_checksum or any(raw[4:32]):
        return None
    bytenr = _u64(raw, 48)
    generation = _u64(raw, 80)
    owner = _u64(raw, 88)
    item_count = _u32(raw, 96)
    level = raw[100]
    if (None in (bytenr, generation, owner, item_count) or not bytenr
            or physical_bytenr is not None and bytenr != physical_bytenr
            or not generation or not owner or level > 8 or not any(raw[32:48])
            or not any(raw[64:80])):
        return None
    try:
        fsid = str(uuid.UUID(bytes=raw[32:48]))
        uuid.UUID(bytes=raw[64:80])
        if expected_fsid is not None and str(uuid.UUID(expected_fsid)) != fsid:
            return None
    except (ValueError, AttributeError):
        return None
    leaf_items: list[BtrfsLeafItem] = []
    node_pointers: list[BtrfsNodePointer] = []
    keys: list[BtrfsKey] = []
    if level == 0:
        item_table_end = 101 + item_count * 25
        if item_table_end > len(raw):
            return None
        ranges: list[tuple[int, int]] = []
        for index in range(item_count):
            position = 101 + index * 25
            key = _btrfs_key(raw, position)
            stored_offset = _u32(raw, position + 17)
            data_size = _u32(raw, position + 21)
            if (key is None or stored_offset is None or data_size is None or not data_size):
                return None
            # btrfs_item.offset is relative to the END of the 101-byte btrfs_header, not the
            # block start; the absolute position is 101 + the stored value.
            data_offset = 101 + stored_offset
            if data_offset < item_table_end or data_offset + data_size > len(raw):
                return None
            keys.append(key)
            ranges.append((data_offset, data_offset + data_size))
            leaf_items.append(BtrfsLeafItem(key, data_offset,
                                             raw[data_offset:data_offset + data_size]))
        ordered_ranges = sorted(ranges)
        if any(left[1] > right[0] for left, right in zip(ordered_ranges, ordered_ranges[1:])):
            return None
    else:
        table_end = 101 + item_count * 33
        if not item_count or table_end > len(raw):
            return None
        for index in range(item_count):
            position = 101 + index * 33
            key = _btrfs_key(raw, position)
            pointer = _u64(raw, position + 17)
            pointer_generation = _u64(raw, position + 25)
            if (key is None or pointer is None or not pointer
                    or pointer_generation is None or not pointer_generation):
                return None
            keys.append(key)
            node_pointers.append(BtrfsNodePointer(key, pointer, pointer_generation))
    if any(left >= right for left, right in zip(keys, keys[1:])):
        return None
    return BtrfsTreeBlock(fsid, bytenr, generation, owner, level,
                          tuple(leaf_items), tuple(node_pointers))


def parse_btrfs_root_item(item: BtrfsLeafItem) -> BtrfsRootItem | None:
    """Decode one checked ``BTRFS_ROOT_ITEM_KEY`` leaf value (snapshot/subvolume root)."""
    if not _valid_btrfs_leaf_item(item) or item.key.item_type != 132:
        return None
    raw = item.data
    if len(raw) < 239:
        return None
    generation, root_dir, bytenr, byte_limit, used, last_snapshot, flags = struct.unpack_from(
        "<QQQQQQQ", raw, 160)
    references = _u32(raw, 216)
    drop_level = raw[237]
    level = raw[238]
    if (not generation or not bytenr or bytenr % 4096 or references is None
            or item.key.object_id >= 256 and not root_dir or drop_level > 8 or level > 8
            or byte_limit and used > byte_limit):
        return None
    if len(raw) >= 247:
        generation_v2 = _u64(raw, 239)
        if generation_v2 not in (0, generation):
            return None

    def optional_uuid(offset: int) -> str | None:
        if offset + 16 > len(raw) or not any(raw[offset:offset + 16]):
            return None
        return str(uuid.UUID(bytes=raw[offset:offset + 16]))

    try:
        root_uuid = optional_uuid(247)
        parent_uuid = optional_uuid(263)
    except ValueError:
        return None
    return BtrfsRootItem(item.key.object_id, item.key.offset, generation, root_dir,
                          bytenr, byte_limit, used, last_snapshot, flags,
                          references, level, bool(flags & 1), root_uuid, parent_uuid)


def parse_btrfs_snapshot_roots(tree: BtrfsTreeBlock) -> tuple[BtrfsRootItem, ...]:
    if (not isinstance(tree, BtrfsTreeBlock) or not isinstance(tree.fsid, str)
            or len(tree.fsid) > 64
            or not _integer(tree.bytenr, 1, MAX_U64)
            or not _integer(tree.generation, 1, MAX_U64)
            or not _integer(tree.owner, 1, MAX_U64)
            or not _integer(tree.level, maximum=8) or tree.level != 0 or tree.owner != 1
            or not isinstance(tree.leaf_items, tuple)
            or not isinstance(tree.node_pointers, tuple) or tree.node_pointers
            or any(not _valid_btrfs_leaf_item(item) for item in tree.leaf_items)):
        return ()
    try:
        if str(uuid.UUID(tree.fsid)) != tree.fsid.lower():
            return ()
    except (ValueError, AttributeError):
        return ()
    roots: list[BtrfsRootItem] = []
    for leaf in tree.leaf_items:
        if leaf.key.item_type != 132 or leaf.key.object_id < 256:
            continue
        root = parse_btrfs_root_item(leaf)
        if root is None:
            return ()
        roots.append(root)
    return tuple(roots)


_VSS_SIGNATURE = bytes.fromhex("3808876bc176e448b7ae04046e6cc752")


def parse_vss_header(data: object, *, offset: int | None = None) -> VssHeader | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    if offset is not None and not _integer(offset, maximum=MAX_I64):
        return None
    at = (0x1E00 if len(raw) >= 0x1E80 else 0) if offset is None else offset
    if at < 0 or at + 128 > len(raw) or raw[at:at + 16] != _VSS_SIGNATURE:
        return None
    version = _u32(raw, at + 16)
    record_type = _u32(raw, at + 20)
    current = _u64(raw, at + 24)
    relative = _u64(raw, at + 32)
    next_header = _u64(raw, at + 40)
    # The catalog offset, maximum size, and volume/store identifiers follow next_header
    # directly; there is no intervening 8-byte field.
    catalog = _u64(raw, at + 48)
    maximum = _u64(raw, at + 56)
    if (version not in (1, 2) or record_type != 1 or current != at
            or relative is None or relative > current or next_header is None
            or next_header and next_header % 0x200
            or catalog is None or maximum is None or not catalog
            or catalog % 0x4000 or maximum < 0x4000):
        return None
    try:
        volume_bytes = raw[at + 64:at + 80]
        storage_bytes = raw[at + 80:at + 96]
        if not any(volume_bytes) or not any(storage_bytes):
            return None
        volume = str(uuid.UUID(bytes_le=volume_bytes))
        storage = str(uuid.UUID(bytes_le=storage_bytes))
    except ValueError:
        return None
    return VssHeader(at, version, record_type, relative, next_header, catalog,
                     maximum, volume, storage)


def build_snapshot_plan(kind: str, identifier: str) -> SnapshotPlan | None:
    if not isinstance(kind, str) or not isinstance(identifier, str):
        return None
    normalized = kind.strip().lower()
    ident = identifier.strip()
    if (normalized not in {"ntfs-vss", "apfs", "btrfs"} or not ident or len(ident) > 256
            or any(ord(character) < 0x20 for character in ident)):
        return None
    common_note = "declarative only: perform reconstruction in the offline Docker sandbox"
    definitions = {
        "ntfs-vss": (
            SnapshotStep("validate", "verify VSS header and catalog chain", ("volume image",), "validated catalog"),
            SnapshotStep("map", "resolve store block descriptors and forwarders", ("validated catalog",), "overlay map"),
            SnapshotStep("overlay", "overlay snapshot blocks on the base volume", ("volume image", "overlay map"), "snapshot image"),
            SnapshotStep("recover", "parse NTFS MFT, USN, and deleted metadata", ("snapshot image",), "snapshot artifacts"),
        ),
        "apfs": (
            SnapshotStep("validate", "verify NXSB and checkpoint descriptors", ("container image",), "checkpoint set"),
            SnapshotStep("omap", "resolve checkpoint object maps", ("checkpoint set",), "transaction object map"),
            SnapshotStep("snapshot", "resolve snapshot metadata tree and filesystem root", ("transaction object map",), "snapshot root"),
            SnapshotStep("recover", "walk snapshot filesystem and extents", ("snapshot root",), "snapshot artifacts"),
        ),
        "btrfs": (
            SnapshotStep("validate", "verify all superblock mirrors and generations", ("filesystem image",), "selected superblock"),
            SnapshotStep("roots", "walk root tree and root refs/backrefs", ("selected superblock",), "subvolume roots"),
            SnapshotStep("snapshot", "select the supplied subvolume/snapshot generation", ("subvolume roots",), "snapshot root"),
            SnapshotStep("recover", "walk extent and checksum trees", ("snapshot root",), "snapshot artifacts"),
        ),
    }
    return SnapshotPlan(normalized, ident, definitions[normalized],
                        (common_note, "never mount or mutate the supplied image"))


__all__ = [
    "ApfsCheckpointMap", "ApfsCheckpointMapping", "ApfsSnapshotMetadata",
    "ApfsSuperblock", "BtrfsKey", "BtrfsLeafItem", "BtrfsNodePointer",
    "BtrfsRootItem", "BtrfsSuperblock", "BtrfsTreeBlock", "DataRun", "ExtExtent",
    "ExtInode", "ExtSuperblock", "FatBoot", "FatDirEntry", "JournalBlock",
    "NtfsAttribute", "NtfsBoot", "NtfsRecord", "SnapshotPlan", "SnapshotStep",
    "UsnRecord", "VssHeader", "apfs_fletcher64", "apply_ntfs_fixup",
    "build_snapshot_plan", "crc32c", "decode_ntfs_runlist", "follow_fat_chain",
    "parse_apfs_checkpoint_map", "parse_apfs_snapshot_metadata",
    "parse_apfs_superblock", "parse_btrfs_root_item", "parse_btrfs_snapshot_roots",
    "parse_btrfs_superblock", "parse_btrfs_tree_block", "parse_ext_inode",
    "parse_ext_superblock", "parse_fat_boot", "parse_fat_directory",
    "parse_jbd2_block", "parse_ntfs_boot", "parse_ntfs_record", "parse_usn_records",
    "parse_vss_header", "recover_ext_file", "recover_fat_file",
    "recover_ntfs_attribute",
]
