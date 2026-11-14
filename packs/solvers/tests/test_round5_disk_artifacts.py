from __future__ import annotations

import ctypes
import random
import struct
import sys
import uuid
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import artifact_depth as artifacts  # noqa: E402
import disk_images as disks  # noqa: E402


def _qcow(*, backing: bytes = b"", features: int = 0, compression: int = 0) -> bytearray:
    cluster = 512
    image = bytearray(4 * cluster)
    backing_offset = 112 if backing else 0
    struct.pack_into(">4sI", image, 0, disks.QCOW_MAGIC, 3)
    struct.pack_into(">QIIQIIQ", image, 8, backing_offset, len(backing), 9, cluster, 0, 1, cluster)
    struct.pack_into(">Q", image, 72, features)
    struct.pack_into(">I", image, 100, 112)
    image[104] = compression
    image[backing_offset:backing_offset + len(backing)] = backing
    return image


def test_qcow2_zstd_extended_l2_and_recursive_backings():
    import zstandard

    raw = b"CSCTF{qcow_zstd}".ljust(512, b"Z")
    image = _qcow(features=1 << 3, compression=1)
    struct.pack_into(">Q", image, 512, 1024)
    struct.pack_into(">Q", image, 1024, (1 << 62) | 1536)
    packed = zstandard.ZstdCompressor().compress(raw)
    image[1536:1536 + len(packed)] = packed
    assert disks.unwrap_qcow2(bytes(image)) == raw

    base = b"B" * 512
    partial = _qcow(backing=b"base.raw", features=1 << 4)
    struct.pack_into(">Q", partial, 512, 1024)
    struct.pack_into(">QQ", partial, 1024, (1 << 63) | 1536, 1 | (2 << 32))
    partial[1536:1552] = b"CSCTF{ext_l2}!".ljust(16, b"E")
    decoded = disks.unwrap_qcow2(bytes(partial), backing=base)
    assert decoded[:16] == partial[1536:1552]
    assert decoded[16:32] == b"\0" * 16
    assert decoded[32:] == base[32:]
    corrupt = bytearray(partial)
    struct.pack_into(">Q", corrupt, 1032, 1 | (1 << 32))
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_qcow2(bytes(corrupt), backing=base)

    parent = bytes(_qcow(backing=b"base.raw"))
    child = bytes(_qcow(backing=b"parent.qcow2"))
    assert disks.unwrap_qcow2_chain(child, [parent, base]) == base
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_qcow2_chain(child, [parent, base, b"extra"])


def test_compressed_vmdk_grain_roundtrip():
    raw = b"CSCTF{vmdk_deflate}".ljust(512, b"V")
    packed = zlib.compress(raw)
    image = bytearray(4 * 512)
    image[:4] = b"KDMV"
    struct.pack_into("<II", image, 4, 1, 0x10000)
    struct.pack_into("<QQ", image, 12, 1, 1)
    struct.pack_into("<QQ", image, 28, 0, 0)
    struct.pack_into("<I", image, 44, 1)
    struct.pack_into("<Q", image, 56, 1)
    struct.pack_into("<H", image, 77, 1)
    struct.pack_into("<I", image, 512, 2)
    struct.pack_into("<I", image, 1024, 3)
    struct.pack_into("<QI", image, 1536, 0, len(packed))
    image[1548:1548 + len(packed)] = packed
    assert disks.unwrap_vmdk_sparse(bytes(image)) == raw
    struct.pack_into("<Q", image, 1536, 1)
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_vmdk_sparse(bytes(image))


def _checked(signature: bytes, size: int, fill) -> bytes:
    block = bytearray(size)
    block[:4] = signature
    fill(block)
    struct.pack_into("<I", block, 4, 0)
    struct.pack_into("<I", block, 4, disks._crc32c(block))
    return bytes(block)


def _differencing_vhdx(child_sector: bytes) -> bytes:
    mib = 1 << 20
    image = bytearray(5 * mib)
    image[:8] = disks.VHDX_MAGIC

    def header(block, sequence):
        struct.pack_into("<Q", block, 8, sequence)
        struct.pack_into("<H", block, 66, 1)

    image[64 << 10:(64 << 10) + 4096] = _checked(b"head", 4096, lambda b: header(b, 1))
    image[128 << 10:(128 << 10) + 4096] = _checked(b"head", 4096, lambda b: header(b, 2))

    def region(block):
        struct.pack_into("<I", block, 8, 2)
        for index, (ident, offset) in enumerate(((disks.VHDX_BAT_GUID, mib),
                                                 (disks.VHDX_METADATA_GUID, 2 * mib))):
            at = 16 + index * 32
            block[at:at + 16] = ident.bytes_le
            struct.pack_into("<QII", block, at + 16, offset, mib, 1)

    table = _checked(b"regi", 64 << 10, region)
    image[192 << 10:256 << 10] = table
    image[256 << 10:320 << 10] = table

    key = "relative_path".encode("utf-16le")
    value = "parent.vhdx".encode("utf-16le")
    locator = bytearray(32 + len(key) + len(value))
    locator[:16] = uuid.UUID(int=1).bytes_le
    struct.pack_into("<HH", locator, 16, 0, 1)
    struct.pack_into("<IIHH", locator, 20, 32, 32 + len(key), len(key), len(value))
    locator[32:32 + len(key)] = key
    locator[32 + len(key):] = value
    metadata = bytearray(mib)
    metadata[:8] = b"metadata"
    items = ((disks.VHDX_FILE_PARAMETERS_GUID, 0x10000, struct.pack("<II", mib, 2)),
             (disks.VHDX_VIRTUAL_SIZE_GUID, 0x10010, struct.pack("<Q", mib)),
             (disks.VHDX_LOGICAL_SECTOR_GUID, 0x10020, struct.pack("<I", 512)),
             (disks.VHDX_PARENT_LOCATOR_GUID, 0x10030, bytes(locator)))
    struct.pack_into("<H", metadata, 10, len(items))
    for index, (ident, offset, payload) in enumerate(items):
        at = 32 + index * 32
        metadata[at:at + 16] = ident.bytes_le
        struct.pack_into("<IIII", metadata, at + 16, offset, len(payload), 6, 0)
        metadata[offset:offset + len(payload)] = payload
    image[2 * mib:3 * mib] = metadata
    struct.pack_into("<Q", image, mib, (3 * mib) | 7)
    bitmap_index = ((1 << 23) * 512 // mib)
    struct.pack_into("<Q", image, mib + bitmap_index * 8, (4 * mib) | 6)
    image[3 * mib:3 * mib + 512] = child_sector
    image[4 * mib] = 1
    return bytes(image)


def test_vhdx_parent_partial_sector_bitmap():
    parent = b"P" * (1 << 20)
    child = b"CSCTF{vhdx_partial}".ljust(512, b"C")
    image = _differencing_vhdx(child)
    decoded = disks.unwrap_vhdx(image, parent=parent)
    assert decoded[:512] == child and decoded[512:] == parent[512:]
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_vhdx(image)


def _pst_page(entry: bytes, ptype: int, bid: int) -> bytes:
    page = bytearray(512)
    page[:len(entry)] = entry
    struct.pack_into("BBBB", page, 488, 1, 8, len(entry), 0)
    struct.pack_into("BBH", page, 496, ptype, ptype, 0)
    struct.pack_into("Q", page, 504, bid)
    struct.pack_into("<I", page, 500, zlib.crc32(page[:496]) & 0xFFFFFFFF)
    return bytes(page)


def test_pst_unicode_nbt_bbt_walk_and_crc_decline():
    image = bytearray(2048)
    image[:4] = artifacts.PST_MAGIC
    image[8:10] = b"SM"
    struct.pack_into("<HH", image, 10, 23, 19)
    struct.pack_into("<QQ", image, 0xD8, 0x100, 512)
    struct.pack_into("<QQ", image, 0xE8, 0x200, 1024)
    nbt = bytearray(32)
    struct.pack_into("<I", nbt, 0, 0x21)
    struct.pack_into("<Q", nbt, 8, 0x200)
    bbt = struct.pack("<QQHHI", 0x200, 1536, 24, 1, 0)
    image[512:1024] = _pst_page(bytes(nbt), 0x81, 0x100)
    image[1024:1536] = _pst_page(bbt, 0x80, 0x200)
    image[1536:1560] = b"CSCTF{pst_tree}".ljust(24, b"!")
    report = artifacts.inspect_pst_ost(bytes(image), "mail.pst")
    assert report["ndb_trees"]["nbt"]["entries"][0]["bid_data"] == 0x200
    assert report["ndb_trees"]["bbt"]["entries"][0]["file_offset"] == 1536
    damaged = bytearray(image)
    damaged[700] ^= 1
    with pytest.raises(artifacts.ArtifactError):
        artifacts.inspect_pst_ost(bytes(damaged), "mail.pst")

    encoded = bytearray(image)
    encoded[0x201] = 1
    # This compact synthetic places the first page immediately after byte 511, overlapping the
    # real Unicode header's high-encoding byte; refresh that page CRC after setting the header bit.
    struct.pack_into("<I", encoded, 512 + 500,
                     zlib.crc32(encoded[512:512 + 496]) & 0xFFFFFFFF)
    encoded_report = artifacts.inspect_pst_ost(bytes(encoded), "mail.pst")
    assert encoded_report["high_encoding"] == "permute"


def test_ewf2_families_are_structured_declines_not_ewf1_misparses():
    for magic, family in ((disks.EWF2_MAGICS[0], "EVF2"), (disks.EWF2_MAGICS[1], "LEF2")):
        value = magic + b"\0" * 128
        assert disks.detect_container(value) == "ewf2"
        result = disks.unwrap(value)
        assert result.raw is None and family in result.diagnostics[0]
        assert result.command_plan == ("ewfverify {in}", "ewfexport -t /out/image -f raw {in}")


def test_journal_lz4_zstd_crosscheck_and_conflicting_flags():
    import lz4.block
    import zstandard

    field = b"MESSAGE=CSCTF{journal_codecs}"
    for flag, packed in ((2, lz4.block.compress(field, store_size=False)),
                         (4, zstandard.ZstdCompressor().compress(field))):
        obj = bytearray(64 + 8 + len(packed))
        struct.pack_into("<Q", obj, 64, len(field))
        obj[72:] = packed
        assert artifacts._journal_field_payload(bytes(obj), flag) == field
    with pytest.raises(artifacts.ArtifactError):
        artifacts._journal_field_payload(bytes(obj), 3)


def _apfs_checked(block: bytearray) -> bytes:
    struct.pack_into("<Q", block, 0, 0)
    struct.pack_into("<Q", block, 0, disks._apfs_fletcher64(block))
    return bytes(block)


def _apfs_fixture() -> tuple[bytes, bytes]:
    block_size = 4096
    marker = b"CSCTF{apfs_catalog_decmpfs}"
    image = bytearray(6 * block_size)
    nx = bytearray(block_size)
    nx[32:36] = disks.APFS_NX_MAGIC
    struct.pack_into("<IQ", nx, 36, block_size, 6)
    nx[72:88] = bytes(range(16))
    image[:block_size] = _apfs_checked(nx)

    omap = bytearray(block_size)
    struct.pack_into("<Q", omap, 16, 7)
    struct.pack_into("<II", omap, 24, 3, 11)
    struct.pack_into("<HHI", omap, 32, 0x0006, 0, 1)
    struct.pack_into("<HH", omap, 40, 0, 4)
    struct.pack_into("<HH", omap, 56, 0, 16)
    struct.pack_into("<QQ", omap, 60, 55, 7)
    struct.pack_into("<IIQ", omap, block_size - 16, 0, block_size, 5)
    image[block_size:2 * block_size] = _apfs_checked(omap)

    name = b"flag.txt\0"
    xname = b"com.apple.decmpfs\0"
    payload = b"fpmc" + struct.pack("<IQ", 3, len(marker)) + zlib.compress(marker)
    inode_key = struct.pack("<Q", (3 << 60) | 42)
    inode_value = bytearray(92)
    struct.pack_into("<Q", inode_value, 0, 2)
    struct.pack_into("<Q", inode_value, 8, 99)
    struct.pack_into("<Q", inode_value, 84, len(marker))
    drec_key = struct.pack("<QI", (9 << 60) | 2, len(name)) + name
    drec_value = struct.pack("<QQH", 42, 123, 0)
    xattr_key = struct.pack("<QH", (4 << 60) | 42, len(xname)) + xname
    xattr_value = struct.pack("<HH", 2, len(payload)) + payload
    pairs = ((inode_key, bytes(inode_value)), (drec_key, drec_value), (xattr_key, xattr_value))
    catalog = bytearray(block_size)
    struct.pack_into("<Q", catalog, 16, 9)
    struct.pack_into("<II", catalog, 24, 3, 14)
    struct.pack_into("<HHI", catalog, 32, 0x0002, 0, len(pairs))
    struct.pack_into("<HH", catalog, 40, 0, len(pairs) * 8)
    key_cursor = 56 + len(pairs) * 8
    value_cursor = block_size
    for index, (key, value) in enumerate(pairs):
        key_offset = key_cursor - (56 + len(pairs) * 8)
        catalog[key_cursor:key_cursor + len(key)] = key
        key_cursor += len(key)
        value_cursor -= len(value)
        catalog[value_cursor:value_cursor + len(value)] = value
        struct.pack_into("<HHHH", catalog, 56 + index * 8, key_offset, len(key),
                         block_size - value_cursor, len(value))
    image[2 * block_size:3 * block_size] = _apfs_checked(catalog)

    extent = bytearray(block_size)
    struct.pack_into("<HHI", extent, 32, 0x0002, 0, 1)
    struct.pack_into("<HH", extent, 40, 0, 8)
    struct.pack_into("<HHHH", extent, 56, 0, 16, 96, 24)
    struct.pack_into("<QQ", extent, 64, (8 << 60) | 99, 0)
    struct.pack_into("<QQQ", extent, block_size - 96, len(marker), 5, 7)
    image[3 * block_size:4 * block_size] = _apfs_checked(extent)
    image[5 * block_size:5 * block_size + len(marker)] = marker
    return bytes(image), marker


def test_apfs_omap_catalog_decmpfs_and_crypto_decline():
    image, marker = _apfs_fixture()
    assert disks.apfs_resolve_omap(image, 55)["physical_block"] == 5
    records = disks.apfs_catalog_records(image)
    assert any(row.get("name") == "flag.txt" for row in records)
    assert disks.recover_apfs_catalog_file(image, 42)["data"] == marker
    with pytest.raises(disks.DiskImageError):
        disks.recover_apfs_file(image, 99, len(marker))


def _btrfs_inline(compression: int, packed: bytes, expected: int) -> bytes:
    block = 4096
    image = bytearray(20 * block)
    fsid = bytes(range(16, 32))
    sb = memoryview(image)[0x10000:0x10000 + block]
    sb[0x20:0x30] = fsid
    sb[0x40:0x48] = disks.BTRFS_MAGIC
    struct.pack_into("<Q", sb, 0x70, len(image))
    struct.pack_into("<III", sb, 0x90, block, block, block)
    node = memoryview(image)[:block]
    node[32:48] = fsid
    struct.pack_into("<I", node, 96, 1)
    data_offset = 256
    struct.pack_into("<QBQII", node, 101, 77, 108, 0, data_offset, 21 + len(packed))
    struct.pack_into("<QQBBHB", node, data_offset, 1, expected, compression, 0, 0, 0)
    node[data_offset + 21:data_offset + 21 + len(packed)] = packed
    return bytes(image)


def test_btrfs_zstd_and_lzo_real_codec_crosschecks():
    import zstandard

    raw = b"CSCTF{btrfs_zstd}".ljust(1000, b"Z")
    image = _btrfs_inline(3, zstandard.ZstdCompressor().compress(raw), len(raw))
    assert disks.recover_btrfs_file(image, 77, len(raw))["data"] == raw

    library_path = Path("/opt/homebrew/opt/lzo/lib/liblzo2.dylib")
    if not library_path.exists():
        pytest.skip("local liblzo2 unavailable")
    library = ctypes.CDLL(str(library_path))
    compress = library.lzo1x_1_compress
    compress.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p)
    compress.restype = ctypes.c_int
    source = ctypes.create_string_buffer(raw)
    target = ctypes.create_string_buffer(len(raw) + len(raw) // 16 + 67)
    target_size = ctypes.c_size_t(len(target))
    workspace = ctypes.create_string_buffer(1 << 20)
    assert compress(source, len(raw), target, ctypes.byref(target_size), workspace) == 0
    compressed = target.raw[:target_size.value]
    framed = struct.pack("<II", 8 + len(compressed), len(compressed)) + compressed
    image = _btrfs_inline(2, framed, len(raw))
    assert disks.recover_btrfs_file(image, 77, len(raw))["data"] == raw


def test_round5_disk_artifact_seeded_5000_case_boundaries():
    rng = random.Random(0xC5C7D15C)
    parsers = (
        lambda value: disks.unwrap_qcow2(value),
        lambda value: disks.unwrap_vmdk_sparse(value),
        lambda value: disks.unwrap_vhdx(value),
        lambda value: disks.apfs_omap_records(value),
        lambda value: disks.apfs_catalog_records(value),
        lambda value: disks.recover_btrfs_file(value, 1, 1),
        lambda value: artifacts.parse_systemd_journal(value),
        lambda value: artifacts.inspect_pst_ost(value),
    )
    for parser in parsers:
        for _ in range(5000):
            candidate = rng.randbytes(rng.randrange(0, 96))
            try:
                parser(candidate)
            except (ValueError, TypeError, OverflowError, UnicodeError, struct.error,
                    zlib.error, MemoryError, RecursionError):
                pass
