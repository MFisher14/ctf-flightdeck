from __future__ import annotations

import struct
import uuid
from dataclasses import fields, replace

import filesystem_depth as F


def _ntfs_boot() -> bytes:
    boot = bytearray(512)
    boot[:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 11, 512)
    boot[13] = 8
    struct.pack_into("<Q", boot, 40, 100_000)
    struct.pack_into("<Q", boot, 48, 4)
    struct.pack_into("<Q", boot, 56, 8)
    boot[64] = 0xF6  # -10 => 1024-byte records
    boot[68] = 1
    struct.pack_into("<Q", boot, 72, 0x123456789ABCDEF0)
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def _resident_attribute(kind: int, attribute_id: int, value: bytes) -> bytes:
    length = (24 + len(value) + 7) & ~7
    attr = bytearray(length)
    struct.pack_into("<II", attr, 0, kind, length)
    attr[8] = 0
    struct.pack_into("<H", attr, 14, attribute_id)
    struct.pack_into("<I", attr, 16, len(value))
    struct.pack_into("<H", attr, 20, 24)
    attr[24:24 + len(value)] = value
    return bytes(attr)


def _ntfs_record(*, in_use: bool = False) -> bytes:
    fixed = bytearray(1024)
    fixed[:4] = b"FILE"
    struct.pack_into("<HH", fixed, 4, 0x30, 3)
    struct.pack_into("<HHHH", fixed, 16, 7, 1, 0x38, 1 if in_use else 0)
    struct.pack_into("<I", fixed, 28, 1024)
    struct.pack_into("<I", fixed, 44, 42)
    fixed[0x30:0x36] = b"\xaa\xbb\x11\x22\x33\x44"

    name = "gone.txt".encode("utf-16-le")
    name_value = bytearray(66 + len(name))
    struct.pack_into("<Q", name_value, 0, 5)
    name_value[64] = len(name) // 2
    name_value[65] = 1
    name_value[66:] = name
    attributes = _resident_attribute(0x30, 1, bytes(name_value))
    attributes += _resident_attribute(0x80, 2, b"FLAG")
    first = 0x38
    fixed[first:first + len(attributes)] = attributes
    end = first + len(attributes)
    fixed[end:end + 4] = b"\xff\xff\xff\xff"
    struct.pack_into("<I", fixed, 24, end + 4)

    # Turn the fixed record into its on-disk update-sequence form.
    fixed[510:512] = b"\xaa\xbb"
    fixed[1022:1024] = b"\xaa\xbb"
    return bytes(fixed)


def test_ntfs_boot_fixups_record_and_corrupt_decline():
    boot = F.parse_ntfs_boot(_ntfs_boot())
    assert boot is not None
    assert boot.cluster_size == 4096 and boot.record_size == 1024
    assert F.parse_ntfs_boot(_ntfs_boot()[:-1]) is None
    damaged_boot = bytearray(_ntfs_boot())
    damaged_boot[13] = 3
    assert F.parse_ntfs_boot(damaged_boot) is None

    raw = _ntfs_record()
    fixed = F.apply_ntfs_fixup(raw, 512)
    assert fixed is not None and fixed[510:512] == b"\x11\x22"
    record = F.parse_ntfs_record(raw)
    assert record is not None and record.record_number == 42 and not record.in_use
    assert record.names == ("gone.txt",)
    assert next(attr.value for attr in record.attributes if attr.type_code == 0x80) == b"FLAG"
    corrupt = bytearray(raw)
    corrupt[510] ^= 1
    assert F.apply_ntfs_fixup(corrupt, 512) is None
    assert F.parse_ntfs_record(corrupt) is None


def test_ntfs_runlists_sparse_negative_and_corrupt_decline():
    encoded = bytes((0x11, 3, 5, 0x11, 2, 0xFE, 0x01, 4, 0))
    runs = F.decode_ntfs_runlist(encoded)
    assert [(run.vcn, run.length, run.lcn) for run in runs] == [
        (0, 3, 5), (3, 2, 3), (5, 4, None),
    ]
    assert F.decode_ntfs_runlist(encoded[:-1]) == ()
    assert F.decode_ntfs_runlist(b"\x19\x01") == ()
    assert F.decode_ntfs_runlist(bytes((0x11, 1, 0xFF, 0))) == ()


def _ntfs_nonresident_record(*, initialized_size: int = 600) -> bytes:
    record = bytearray(1024)
    record[:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 0x30, 3)
    struct.pack_into("<HHHH", record, 16, 2, 1, 0x38, 1)
    struct.pack_into("<I", record, 28, 1024)
    struct.pack_into("<I", record, 44, 17)
    record[0x30:0x36] = b"\xcc\xdd\x11\x22\x33\x44"
    attribute = bytearray(72)
    struct.pack_into("<II", attribute, 0, 0x80, len(attribute))
    attribute[8] = 1
    struct.pack_into("<H", attribute, 14, 3)
    struct.pack_into("<QQ", attribute, 16, 0, 1)
    struct.pack_into("<H", attribute, 32, 64)
    struct.pack_into("<QQQ", attribute, 40, 1024, 600, initialized_size)
    attribute[64:68] = bytes((0x11, 2, 2, 0))
    record[0x38:0x38 + len(attribute)] = attribute
    end = 0x38 + len(attribute)
    record[end:end + 4] = b"\xff" * 4
    struct.pack_into("<I", record, 24, end + 4)
    record[510:512] = b"\xcc\xdd"
    record[1022:1024] = b"\xcc\xdd"
    return bytes(record)


def test_ntfs_nonresident_attribute_recovery_is_checked_and_bounded():
    record = F.parse_ntfs_record(_ntfs_nonresident_record())
    assert record is not None
    attribute = record.attributes[0]
    assert not attribute.resident and attribute.runs[0].lcn == 2
    image = bytearray(2048)
    expected = bytes((index * 29 + 5) & 0xFF for index in range(600))
    image[1024:1624] = expected
    assert F.recover_ntfs_attribute(image, attribute, 512) == expected
    assert F.recover_ntfs_attribute(image[:1200], attribute, 512) is None
    assert F.recover_ntfs_attribute(image, replace(attribute, flags=1), 512) is None
    partial_record = F.parse_ntfs_record(_ntfs_nonresident_record(initialized_size=257))
    assert partial_record is not None
    partial = F.recover_ntfs_attribute(image, partial_record.attributes[0], 512)
    assert any(expected[257:])
    assert partial == expected[:257] + b"\x00" * (600 - 257)
    assert set(partial[257:]) == {0}  # backing bytes are nonzero but logically uninitialized
    parsed_resident = F.parse_ntfs_record(_ntfs_record())
    assert parsed_resident is not None
    resident = next(attr for attr in parsed_resident.attributes if attr.type_code == 0x80)
    assert F.recover_ntfs_attribute(b"", resident, 512) == b"FLAG"
    assert F.recover_ntfs_attribute(b"", replace(resident, data_size=5), 512) is None
    assert F.recover_ntfs_attribute(b"", replace(resident, initialized_size=3), 512) is None


def _usn_v2(name: str = "gone.txt") -> bytes:
    encoded = name.encode("utf-16-le")
    length = (60 + len(encoded) + 7) & ~7
    record = bytearray(length)
    struct.pack_into("<IHH", record, 0, length, 2, 0)
    struct.pack_into("<QQQQ", record, 8, 42, 5, 1234, 133_750_000_000_000_000)
    struct.pack_into("<IIII", record, 40, 0x200, 0, 7, 0x20)
    struct.pack_into("<HH", record, 56, len(encoded), 60)
    record[60:60 + len(encoded)] = encoded
    return bytes(record)


def test_usn_v2_checked_and_corrupt_decline():
    records = F.parse_usn_records(_usn_v2())
    assert len(records) == 1 and records[0].name == "gone.txt"
    assert records[0].file_reference == 42 and records[0].reason == 0x200
    bad = bytearray(_usn_v2())
    struct.pack_into("<H", bad, 56, 3)
    assert F.parse_usn_records(bad) == ()
    assert F.parse_usn_records(_usn_v2()[:-1]) == ()

    name = "v3.bin".encode("utf-16-le")
    v3 = bytearray((76 + len(name) + 7) & ~7)
    struct.pack_into("<IHH", v3, 0, len(v3), 3, 0)
    v3[8:24] = bytes(range(16))
    v3[24:40] = bytes(range(16, 32))
    struct.pack_into("<QQ", v3, 40, 99, 133_750_000_000_000_000)
    struct.pack_into("<IIII", v3, 56, 0x100, 0, 4, 0x20)
    struct.pack_into("<HH", v3, 72, len(name), 76)
    v3[76:76 + len(name)] = name
    parsed_v3 = F.parse_usn_records(v3)
    assert len(parsed_v3) == 1 and parsed_v3[0].major == 3
    struct.pack_into("<Q", v3, 48, 0)
    assert F.parse_usn_records(v3) == ()


def _fat16_boot() -> bytes:
    boot = bytearray(512)
    boot[:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, 512)
    boot[13] = 1
    struct.pack_into("<H", boot, 14, 1)
    boot[16] = 2
    struct.pack_into("<H", boot, 17, 512)
    struct.pack_into("<H", boot, 19, 10_000)
    boot[21] = 0xF8
    struct.pack_into("<H", boot, 22, 40)
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def _lfn_entry(long_name: str, short: bytes) -> bytes:
    assert len(long_name) <= 13 and len(short) == 11
    values = list(long_name.encode("utf-16-le"))
    values += [0, 0]
    values += [0xFF, 0xFF] * (13 - len(long_name) - 1)
    raw_name = bytes(values[:26])
    entry = bytearray(32)
    entry[0] = 0x41
    entry[1:11] = raw_name[:10]
    entry[11] = 0x0F
    entry[12] = 0
    entry[13] = F._fat_lfn_checksum(short)
    entry[14:26] = raw_name[10:22]
    entry[26:28] = b"\x00\x00"
    entry[28:32] = raw_name[22:26]
    return bytes(entry)


def _fat_directory() -> bytes:
    directory = bytearray(32 * 4)
    short = b"LONGNA~1TXT"
    directory[:32] = _lfn_entry("Long Name.txt", short)
    directory[32:43] = short
    directory[43] = 0x20
    struct.pack_into("<H", directory, 32 + 26, 2)
    struct.pack_into("<I", directory, 32 + 28, 600)
    directory[64:75] = b"\xe5LAG    TXT"
    directory[75] = 0x20
    struct.pack_into("<H", directory, 64 + 26, 4)
    struct.pack_into("<I", directory, 64 + 28, 10)
    return bytes(directory)


def test_fat_bpb_directory_chain_recovery_and_declines():
    boot = F.parse_fat_boot(_fat16_boot())
    assert boot is not None and boot.fat_type == "FAT16"
    assert F.parse_fat_boot(_fat16_boot()[:-2]) is None
    directory = F.parse_fat_directory(_fat_directory())
    assert [entry.name for entry in directory] == ["Long Name.txt", "?LAG.TXT"]
    assert not directory[0].deleted and directory[1].deleted
    corrupt_directory = bytearray(_fat_directory())
    corrupt_directory[13] ^= 1
    assert F.parse_fat_directory(corrupt_directory) == ()

    table = bytearray(boot.sectors_per_fat * boot.bytes_per_sector)
    struct.pack_into("<H", table, 4, 3)       # cluster 2 -> 3
    struct.pack_into("<H", table, 6, 0xFFFF)  # cluster 3 -> EOC
    assert F.follow_fat_chain(table, 2, "FAT16") == (2, 3)
    image = bytearray(boot.total_sectors * boot.bytes_per_sector)
    start = boot.first_data_sector * boot.bytes_per_sector
    expected = bytes((index * 17 + 3) & 255 for index in range(600))
    image[start:start + 512] = expected[:512]
    image[start + 512:start + 1024] = expected[512:] + b"\x00" * (1024 - 600)
    assert F.recover_fat_file(image, boot, table, directory[0]) == expected
    struct.pack_into("<H", table, 6, 2)
    assert F.follow_fat_chain(table, 2, "FAT16") == ()
    assert F.recover_fat_file(image, boot, table, directory[0]) is None


def test_fat12_and_fat32_geometry_and_chain_decoding():
    fat12_boot = bytearray(_fat16_boot())
    struct.pack_into("<H", fat12_boot, 17, 224)
    struct.pack_into("<H", fat12_boot, 19, 1000)
    struct.pack_into("<H", fat12_boot, 22, 3)
    parsed12 = F.parse_fat_boot(fat12_boot)
    assert parsed12 is not None and parsed12.fat_type == "FAT12"
    table12 = bytearray(16)
    table12[3:5] = (3).to_bytes(2, "little")
    pair = int.from_bytes(table12[4:6], "little") | (0xFFF << 4)
    table12[4:6] = pair.to_bytes(2, "little")
    assert F.follow_fat_chain(table12, 2, "FAT12") == (2, 3)

    fat32_boot = bytearray(_fat16_boot())
    struct.pack_into("<H", fat32_boot, 17, 0)
    struct.pack_into("<H", fat32_boot, 19, 0)
    struct.pack_into("<H", fat32_boot, 22, 0)
    struct.pack_into("<I", fat32_boot, 32, 70_000)
    struct.pack_into("<I", fat32_boot, 36, 600)
    struct.pack_into("<I", fat32_boot, 44, 2)
    struct.pack_into("<H", fat32_boot, 14, 32)
    parsed32 = F.parse_fat_boot(fat32_boot)
    assert parsed32 is not None and parsed32.fat_type == "FAT32"
    table32 = bytearray(32)
    struct.pack_into("<I", table32, 8, 3)
    struct.pack_into("<I", table32, 12, 0x0FFFFFFF)
    assert F.follow_fat_chain(table32, 2, "FAT32") == (2, 3)
    struct.pack_into("<I", table32, 12, 0x0FFFFFF2)
    assert F.follow_fat_chain(table32, 2, "FAT32") == ()


def _ext_superblock() -> tuple[bytes, F.ExtSuperblock]:
    image = bytearray(2048)
    sb = memoryview(image)[1024:2048]
    struct.pack_into("<I", sb, 0, 1024)
    struct.pack_into("<I", sb, 4, 50_000)
    struct.pack_into("<I", sb, 24, 2)  # 4096-byte blocks
    struct.pack_into("<I", sb, 32, 8192)
    struct.pack_into("<I", sb, 40, 1024)
    struct.pack_into("<H", sb, 56, 0xEF53)
    struct.pack_into("<I", sb, 76, 1)
    struct.pack_into("<H", sb, 88, 256)
    struct.pack_into("<III", sb, 92, 0x4, 0x40, 0x1)
    sb[104:120] = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes
    sb[120:128] = b"evidence"
    struct.pack_into("<I", sb, 224, 8)
    parsed = F.parse_ext_superblock(image)
    assert parsed is not None
    return bytes(image), parsed


def _ext_inode(*, corrupt: bool = False) -> bytes:
    inode = bytearray(256)
    struct.pack_into("<HHI", inode, 0, 0x81A4, 1000, 12_288)
    struct.pack_into("<HH", inode, 24, 1000, 1)
    struct.pack_into("<I", inode, 32, 0x00080000)
    struct.pack_into("<I", inode, 100, 9)
    struct.pack_into("<HHHHI", inode, 40, 0xF30A, 2, 4, 0, 1)
    struct.pack_into("<IHHI", inode, 52, 0, 2, 0, 100)
    struct.pack_into("<IHHI", inode, 64, 1 if corrupt else 2, 1, 0, 200)
    return bytes(inode)


def test_ext_superblock_inode_extents_journal_and_corrupt_decline():
    image, superblock = _ext_superblock()
    assert superblock.block_size == 4096 and superblock.volume_name == "evidence"
    bad_sb = bytearray(image)
    bad_sb[1024 + 56] = 0
    assert F.parse_ext_superblock(bad_sb) is None
    inode = F.parse_ext_inode(_ext_inode(), superblock)
    assert inode is not None and [extent.physical_block for extent in inode.extents] == [100, 200]
    assert F.parse_ext_inode(_ext_inode(corrupt=True), superblock) is None
    filesystem = bytearray(201 * superblock.block_size)
    expected = bytes((index * 7 + 11) & 0xFF for index in range(12_288))
    filesystem[100 * 4096:102 * 4096] = expected[:8192]
    filesystem[200 * 4096:201 * 4096] = expected[8192:]
    assert F.recover_ext_file(filesystem, superblock, inode) == expected
    assert F.recover_ext_file(filesystem[:200 * 4096], superblock, inode) is None

    descriptor = bytearray(1024)
    struct.pack_into(">III", descriptor, 0, 0xC03B3998, 1, 77)
    struct.pack_into(">II", descriptor, 12, 123, 0x8)
    descriptor[20:36] = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes
    block = F.parse_jbd2_block(descriptor)
    assert block is not None and block.block_type == "descriptor" and block.referenced_blocks == (123,)
    descriptor[15] = 0
    assert F.parse_jbd2_block(descriptor) is None


def _apfs_superblock() -> bytes:
    block = bytearray(4096)
    struct.pack_into("<QQII", block, 8, 1, 2, 0x80000001, 0)
    block[32:36] = b"NXSB"
    struct.pack_into("<I", block, 36, 4096)
    struct.pack_into("<Q", block, 40, 1000)
    struct.pack_into("<QQQ", block, 48, 1, 2, 4)
    block[72:88] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes
    struct.pack_into("<QQ", block, 88, 10, 3)
    checksum = F.apfs_fletcher64(block[8:])
    assert checksum is not None
    struct.pack_into("<Q", block, 0, checksum)
    return bytes(block)


def _btrfs_image() -> bytes:
    image = bytearray(0x11000)
    sb = memoryview(image)[0x10000:0x11000]
    sb[32:48] = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes
    struct.pack_into("<Q", sb, 48, 0x10000)
    sb[64:72] = b"_BHRfS_M"
    struct.pack_into("<QQQ", sb, 72, 7, 0x20000, 0x30000)
    struct.pack_into("<QQ", sb, 112, 1 << 30, 1 << 20)
    struct.pack_into("<Q", sb, 136, 1)
    struct.pack_into("<II", sb, 144, 4096, 16384)
    struct.pack_into("<H", sb, 196, 0)
    sb[198] = 1
    checksum = F.crc32c(sb[32:])
    assert checksum is not None
    struct.pack_into("<I", sb, 0, checksum)
    return bytes(image)


def test_apfs_btrfs_checksums_and_corrupt_decline():
    apfs = F.parse_apfs_superblock(_apfs_superblock())
    assert apfs is not None and apfs.block_size == 4096 and apfs.transaction_id == 2
    broken_apfs = bytearray(_apfs_superblock())
    broken_apfs[1000] ^= 1
    assert F.parse_apfs_superblock(broken_apfs) is None

    assert F.crc32c(b"123456789") == 0xE3069283
    btrfs = F.parse_btrfs_superblock(_btrfs_image())
    assert btrfs is not None and btrfs.generation == 7 and btrfs.bytenr == 0x10000
    broken_btrfs = bytearray(_btrfs_image())
    broken_btrfs[-1] ^= 1
    assert F.parse_btrfs_superblock(broken_btrfs) is None


def _apfs_checkpoint_map(*, bad_padding: bool = False) -> bytes:
    block = bytearray(4096)
    struct.pack_into("<QQII", block, 8, 9, 12, 0x8000000C, 0)
    struct.pack_into("<II", block, 32, 1, 1)
    struct.pack_into("<IIIIQQQ", block, 40, 0x80000004, 0, 4096,
                     int(bad_padding), 0, 77, 33)
    checksum = F.apfs_fletcher64(block[8:])
    assert checksum is not None
    struct.pack_into("<Q", block, 0, checksum)
    return bytes(block)


def _apfs_snapshot_value(name: str = "snap-1") -> bytes:
    encoded = name.encode() + b"\x00"
    value = bytearray(50 + len(encoded))
    struct.pack_into("<QQQQQ", value, 0, 90, 91,
                     1_700_000_000_000_000_000, 1_700_000_001_000_000_000, 256)
    struct.pack_into("<IIH", value, 40, 15, 0, len(encoded))
    value[50:] = encoded
    return bytes(value)


def _btrfs_root_tree(*, corrupt_root: bool = False) -> bytes:
    block = bytearray(4096)
    block[32:48] = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes
    struct.pack_into("<Q", block, 48, 0x40000)
    block[64:80] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes
    struct.pack_into("<QQI", block, 80, 8, 1, 1)
    block[100] = 0
    root = bytearray(279)
    struct.pack_into("<QQQQQQQ", root, 160, 8, 256,
                     0x12345 if corrupt_root else 0x50000, 0, 4096, 7, 1)
    struct.pack_into("<I", root, 216, 1)
    root[237:239] = b"\x00\x00"
    struct.pack_into("<Q", root, 239, 8)
    root[247:263] = uuid.UUID("10000000-0000-0000-0000-000000000001").bytes
    root[263:279] = uuid.UUID("20000000-0000-0000-0000-000000000002").bytes
    data_offset = len(block) - len(root)
    # btrfs_item.offset is stored relative to the END of the 101-byte btrfs_header.
    struct.pack_into("<QBQII", block, 101, 256, 132, 8, data_offset - 101, len(root))
    block[data_offset:] = root
    checksum = F.crc32c(block[32:])
    assert checksum is not None
    struct.pack_into("<I", block, 0, checksum)
    return bytes(block)


def test_apfs_and_btrfs_snapshot_metadata_structures_decline_corrupt():
    checkpoint = F.parse_apfs_checkpoint_map(_apfs_checkpoint_map())
    assert checkpoint is not None and checkpoint.last
    assert checkpoint.mappings[0].object_id == 77
    assert F.parse_apfs_checkpoint_map(_apfs_checkpoint_map(bad_padding=True)) is None
    snapshot = F.parse_apfs_snapshot_metadata(_apfs_snapshot_value())
    assert snapshot is not None and snapshot.name == "snap-1"
    malformed_snapshot = bytearray(_apfs_snapshot_value())
    malformed_snapshot[-2] = ord("/")
    assert F.parse_apfs_snapshot_metadata(malformed_snapshot) is None

    tree = F.parse_btrfs_tree_block(_btrfs_root_tree(), physical_bytenr=0x40000,
                                     expected_fsid="01234567-89ab-cdef-0123-456789abcdef")
    assert tree is not None and len(tree.leaf_items) == 1
    roots = F.parse_btrfs_snapshot_roots(tree)
    assert len(roots) == 1 and roots[0].readonly and roots[0].root_id == 256
    corrupt_checksum = bytearray(_btrfs_root_tree())
    corrupt_checksum[-1] ^= 1
    assert F.parse_btrfs_tree_block(corrupt_checksum) is None
    structurally_bad = F.parse_btrfs_tree_block(_btrfs_root_tree(corrupt_root=True))
    assert structurally_bad is not None
    assert F.parse_btrfs_snapshot_roots(structurally_bad) == ()


def _vss_image() -> bytes:
    image = bytearray(0x1E80)
    at = 0x1E00
    image[at:at + 16] = F._VSS_SIGNATURE
    struct.pack_into("<IIQQQ", image, at + 16, 1, 1, at, 0, 0)
    # catalog offset, maximum size and the volume/store UUIDs follow next_header directly.
    struct.pack_into("<QQ", image, at + 48, 0x4000, 0x100000)
    image[at + 64:at + 80] = uuid.UUID("11111111-1111-1111-1111-111111111111").bytes_le
    image[at + 80:at + 96] = uuid.UUID("22222222-2222-2222-2222-222222222222").bytes_le
    return bytes(image)


def test_vss_and_snapshot_plans_are_checked_and_nonexecuting():
    header = F.parse_vss_header(_vss_image())
    assert header is not None and header.catalog_offset == 0x4000
    damaged = bytearray(_vss_image())
    struct.pack_into("<Q", damaged, 0x1E00 + 24, 0)
    assert F.parse_vss_header(damaged) is None
    for kind in ("ntfs-vss", "apfs", "btrfs"):
        plan = F.build_snapshot_plan(kind, "snapshot-7")
        assert plan is not None and len(plan.steps) == 4
        assert all(step.inputs and step.output for step in plan.steps)
        assert "declarative only" in plan.notes[0]
    assert F.build_snapshot_plan("zfs", "snapshot") is None
    assert F.build_snapshot_plan("apfs", "") is None


def test_public_auxiliary_boundaries_decline_wrong_types_and_forged_dataclasses():
    huge = 1 << 4096
    record_bytes = _ntfs_nonresident_record()
    ntfs_record = F.parse_ntfs_record(record_bytes)
    assert ntfs_record is not None
    attribute = ntfs_record.attributes[0]
    run = attribute.runs[0]

    fat_boot = F.parse_fat_boot(_fat16_boot())
    fat_entries = F.parse_fat_directory(_fat_directory())
    assert fat_boot is not None and fat_entries
    fat_entry = fat_entries[0]

    _, ext_superblock = _ext_superblock()
    ext_inode = F.parse_ext_inode(_ext_inode(), ext_superblock)
    assert ext_inode is not None

    btrfs_tree = F.parse_btrfs_tree_block(_btrfs_root_tree())
    assert btrfs_tree is not None
    leaf = btrfs_tree.leaf_items[0]

    none_calls = [
        lambda: F.apply_ntfs_fixup(record_bytes, "512"),
        lambda: F.apply_ntfs_fixup(record_bytes, 512.0),
        lambda: F.apply_ntfs_fixup(record_bytes, True),
        lambda: F.parse_ntfs_record(record_bytes, sector_size=huge),
        lambda: F.recover_ntfs_attribute(b"", attribute, "512"),
        lambda: F.recover_ntfs_attribute(b"", attribute, True),
        lambda: F.recover_ntfs_attribute(b"", replace(attribute, data_size="600"), 512),
        lambda: F.recover_ntfs_attribute(b"", replace(attribute, allocated_size=True), 512),
        lambda: F.recover_ntfs_attribute(
            b"", replace(attribute, runs=(replace(run, vcn="0"),)), 512),
        lambda: F.recover_fat_file(
            b"", replace(fat_boot, bytes_per_sector="512"), b"", fat_entry),
        lambda: F.recover_fat_file(
            b"", fat_boot, b"", replace(fat_entry, deleted=1)),
        lambda: F.parse_ext_superblock(b"", offset="0"),
        lambda: F.parse_ext_superblock(b"", offset=True),
        lambda: F.parse_ext_superblock(b"", offset=huge),
        lambda: F.parse_ext_inode(b"", replace(ext_superblock, inode_size="256")),
        lambda: F.recover_ext_file(
            b"", ext_superblock, replace(ext_inode, size="12288")),
        lambda: F.recover_ext_file(
            b"", ext_superblock, replace(ext_inode, deleted=1)),
        lambda: F.parse_btrfs_superblock(b"", offset="0"),
        lambda: F.parse_btrfs_superblock(b"", offset=True),
        lambda: F.parse_btrfs_superblock(b"", offset=huge),
        lambda: F.parse_btrfs_tree_block(_btrfs_root_tree(), physical_bytenr="x"),
        lambda: F.parse_btrfs_tree_block(_btrfs_root_tree(), physical_bytenr=True),
        lambda: F.parse_btrfs_tree_block(_btrfs_root_tree(), expected_fsid=[]),
        lambda: F.parse_btrfs_root_item(replace(leaf, key="bad")),
        lambda: F.parse_btrfs_root_item(replace(leaf, data=memoryview(leaf.data))),
        lambda: F.parse_vss_header(b"", offset="0"),
        lambda: F.parse_vss_header(b"", offset=True),
        lambda: F.parse_vss_header(b"", offset=huge),
        lambda: F.build_snapshot_plan([], "id"),
        lambda: F.build_snapshot_plan("apfs", 7),
    ]
    for call in none_calls:
        assert call() is None

    empty_calls = [
        lambda: F.decode_ntfs_runlist(b"\x00", start_vcn="x"),
        lambda: F.decode_ntfs_runlist(b"\x00", start_lcn=True),
        lambda: F.decode_ntfs_runlist(b"\x00", start_vcn=huge),
        lambda: F.follow_fat_chain(b"", "2", "FAT16"),
        lambda: F.follow_fat_chain(b"", True, "FAT16"),
        lambda: F.follow_fat_chain(b"", 2, []),
        lambda: F.follow_fat_chain(b"", 2, "FAT16", max_clusters="3"),
        lambda: F.follow_fat_chain(b"", 2, "FAT16", max_clusters=True),
        lambda: F.parse_btrfs_snapshot_roots(replace(btrfs_tree, level="0")),
        lambda: F.parse_btrfs_snapshot_roots(replace(btrfs_tree, leaf_items=[])),
    ]
    for call in empty_calls:
        assert call() == ()

    # Every field of every public recovery input is hostile at the API boundary: dataclass
    # annotations do not enforce runtime types, so a forged instance must never leak bytes/raise.
    for field in fields(attribute):
        forged = replace(attribute, **{field.name: object()})
        assert F.recover_ntfs_attribute(b"", forged, 512) is None
    for field in fields(run):
        forged_run = replace(run, **{field.name: object()})
        assert F.recover_ntfs_attribute(
            b"", replace(attribute, runs=(forged_run,)), 512) is None
    for field in fields(fat_boot):
        forged_boot = replace(fat_boot, **{field.name: object()})
        assert F.recover_fat_file(b"", forged_boot, b"", fat_entry) is None
    for field in fields(fat_entry):
        forged_entry = replace(fat_entry, **{field.name: object()})
        assert F.recover_fat_file(b"", fat_boot, b"", forged_entry) is None
    for field in fields(ext_superblock):
        forged_superblock = replace(ext_superblock, **{field.name: object()})
        assert F.parse_ext_inode(b"", forged_superblock) is None
        assert F.recover_ext_file(b"", forged_superblock, ext_inode) is None
    for field in fields(ext_inode):
        forged_inode = replace(ext_inode, **{field.name: object()})
        assert F.recover_ext_file(b"", ext_superblock, forged_inode) is None
    for extent_field in fields(ext_inode.extents[0]):
        forged_extent = replace(ext_inode.extents[0], **{extent_field.name: object()})
        forged_inode = replace(ext_inode, extents=(forged_extent,) + ext_inode.extents[1:])
        assert F.recover_ext_file(b"", ext_superblock, forged_inode) is None
    for field in fields(leaf):
        forged_leaf = replace(leaf, **{field.name: object()})
        assert F.parse_btrfs_root_item(forged_leaf) is None
    for key_field in fields(leaf.key):
        forged_key = replace(leaf.key, **{key_field.name: object()})
        assert F.parse_btrfs_root_item(replace(leaf, key=forged_key)) is None
    for field in fields(btrfs_tree):
        forged_tree = replace(btrfs_tree, **{field.name: object()})
        assert F.parse_btrfs_snapshot_roots(forged_tree) == ()

    # ``bool`` is an ``int`` subclass; all numeric fields must nevertheless reject it.
    for name in ("type_code", "attribute_id", "flags", "data_size",
                 "allocated_size", "initialized_size"):
        assert F.recover_ntfs_attribute(
            b"", replace(attribute, **{name: True}), 512) is None
    for name in ("bytes_per_sector", "sectors_per_cluster", "reserved_sectors",
                 "fat_count", "sectors_per_fat", "root_entries", "total_sectors",
                 "first_data_sector", "cluster_count"):
        assert F.recover_fat_file(
            b"", replace(fat_boot, **{name: True}), b"", fat_entry) is None
