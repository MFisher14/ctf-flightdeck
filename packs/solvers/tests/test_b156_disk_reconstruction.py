"""B-156: advanced disk-image reconstruction oracles.

Covers the formats the Round-5 engines declared as limits and now reconstruct:
  * QCOW2 LUKS (crypt_method 2) AES-XTS clusters given the master key; decline without one.
  * VHDX dirty-log replay into a private copy before BAT reconstruction.
  * EWF2/Ex01 section + sector-table chunk reconstruction (structural model).
  * VMware SEsparse grain-directory expansion, standalone and through a descriptor.
  * APFS inline decmpfs type-1 (uncompressed) recovery.

Oracles are independent: AES-XTS is pinned to the published IEEE Std 1619-2007 test vector, CRC32C to
the x^32... reflected polynomial, Adler32 to zlib.  Fixtures are built in-test; no shell tool, mount,
engine encoder, or challenge binary is used.  Byte-fidelity against real tool-produced Ex01/SEsparse
images is deferred to ``test_ewf2_byte_fidelity_against_real_tool_image`` below, a ``needs_realdata``
test reported as NOT RUN until such a corpus exists (see docs/build-log/B-156.md).
"""
import struct
import sys
import uuid
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import disk_images as D  # noqa: E402

from Crypto.Cipher import AES  # noqa: E402


# --------------------------------------------------------------------------- AES-XTS

IEEE_1619_XTS128_KEY = bytes(32)  # data-unit key || tweak key, both all-zero (Vector 1)
IEEE_1619_XTS128_CT = bytes.fromhex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e")


def _xts_encrypt(key: bytes, data: bytes, first_sector: int, sector_size: int = 512) -> bytes:
    """Test-owned XTS encryptor (the inverse of the code under test), for building fixtures."""
    half = len(key) // 2
    cipher = AES.new(key[:half], AES.MODE_ECB)
    tweaker = AES.new(key[half:], AES.MODE_ECB)
    out = bytearray(len(data))
    for sector in range(len(data) // sector_size):
        tweak = tweaker.encrypt((first_sector + sector).to_bytes(16, "little"))
        base = sector * sector_size
        for block in range(0, sector_size, 16):
            at = base + block
            masked = bytes(a ^ b for a, b in zip(data[at:at + 16], tweak))
            out[at:at + 16] = bytes(a ^ b for a, b in zip(cipher.encrypt(masked), tweak))
            tweak = D._gf128_mul_alpha(tweak)
    return bytes(out)


def test_aes_xts_matches_ieee_1619_vector_and_round_trips():
    # Independent truth: IEEE Std 1619-2007 XTS-AES-128 Vector 1 decrypts to all zeros.
    assert D._aes_xts_decrypt(IEEE_1619_XTS128_KEY, IEEE_1619_XTS128_CT, 0, sector_size=32) == bytes(32)
    key = bytes(range(64))  # AES-256 XTS (two 32-byte keys)
    plain = bytes((i * 7) & 0xFF for i in range(1024))
    cipher = _xts_encrypt(key, plain, first_sector=5)
    assert cipher != plain
    assert D._aes_xts_decrypt(key, cipher, 5) == plain
    # Wrong starting sector (wrong tweak) must not recover the plaintext.
    assert D._aes_xts_decrypt(key, cipher, 6) != plain


def test_gf128_mul_alpha_carry_reduction():
    # Top bit set -> shift carries out and the reduction polynomial 0x87 is XORed into byte 0.
    assert D._gf128_mul_alpha(b"\x00" * 15 + b"\x80") == b"\x87" + b"\x00" * 15
    assert D._gf128_mul_alpha(b"\x01" + b"\x00" * 15) == b"\x02" + b"\x00" * 15


# --------------------------------------------------------------------------- QCOW2 LUKS

def _qcow2_luks(plaintext: bytes, key: bytes) -> bytes:
    cluster = 512
    image = bytearray(4 * cluster)
    struct.pack_into(">4sI", image, 0, D.QCOW_MAGIC, 3)
    struct.pack_into(">I", image, 20, 9)            # cluster_bits = 9 (512-byte clusters)
    struct.pack_into(">Q", image, 24, cluster)      # virtual size = 512
    struct.pack_into(">II", image, 32, 2, 1)        # crypt_method = 2 (LUKS), l1_size = 1
    struct.pack_into(">Q", image, 40, cluster)      # l1_offset = 512
    struct.pack_into(">I", image, 100, 112)         # header length
    struct.pack_into(">Q", image, cluster, (1 << 63) | (2 * cluster))     # L1[0] -> L2 at 1024
    struct.pack_into(">Q", image, 2 * cluster, 3 * cluster)               # L2[0] -> host 1536
    image[3 * cluster:4 * cluster] = _xts_encrypt(key, plaintext, first_sector=0)
    return bytes(image)


def _qcow2_luks_multicluster(cluster_plaintexts: list[bytes], key: bytes) -> bytes:
    """A LUKS qcow2 whose guest spans N>=2 512-byte clusters, each at its own guest offset.

    Cluster *i* sits at guest offset ``i*512`` and is XTS-encrypted with plain64 first_sector ``i``
    (``guest // 512``).  This is the fixture the single-cluster image cannot be: it exercises the
    per-cluster XTS sector numbering past sector 0, so a mis-wired tweak (e.g. a constant 0) that
    decrypts the first cluster correctly still garbles every later cluster.
    """
    cluster = 512
    n = len(cluster_plaintexts)
    assert n >= 2
    # Layout (512-byte clusters): [0]=header, [1]=L1, [2]=L2, [3..3+n)=data clusters.
    total = 3 + n
    image = bytearray(total * cluster)
    struct.pack_into(">4sI", image, 0, D.QCOW_MAGIC, 3)
    struct.pack_into(">I", image, 20, 9)            # cluster_bits = 9 (512-byte clusters)
    struct.pack_into(">Q", image, 24, n * cluster)  # virtual size = n clusters
    struct.pack_into(">II", image, 32, 2, 1)        # crypt_method = 2 (LUKS), l1_size = 1
    struct.pack_into(">Q", image, 40, cluster)      # l1_offset = 512
    struct.pack_into(">I", image, 100, 112)         # header length
    struct.pack_into(">Q", image, cluster, (1 << 63) | (2 * cluster))     # L1[0] -> L2 at 1024
    for i, plain in enumerate(cluster_plaintexts):
        assert len(plain) == cluster
        host = (3 + i) * cluster
        struct.pack_into(">Q", image, 2 * cluster + i * 8, host)          # L2[i] -> data host
        image[host:host + cluster] = _xts_encrypt(key, plain, first_sector=i)
    return bytes(image)


def test_qcow2_luks_master_key_decrypts_and_declines_without_key():
    key = bytes(range(1, 33))  # AES-128 XTS
    plain = b"CSCTF{qcow2_luks_xts}".ljust(512, b".")
    image = _qcow2_luks(plain, key)
    assert D.detect_container(image) == "qcow2"
    assert D.unwrap_qcow2(image, luks_key=key) == plain
    assert D.unwrap(image, luks_key=key).raw == plain
    # No key: decline loudly, never guess.
    with pytest.raises(D.DiskImageError):
        D.unwrap_qcow2(image)
    with pytest.raises(D.DiskImageError):
        D.unwrap_qcow2(image, aes_key=bytes(16))  # legacy key offered for a LUKS image
    # A wrong master key produces different bytes (no silent plausible image).
    assert D.unwrap_qcow2(image, luks_key=bytes(range(2, 34))) != plain


def test_qcow2_luks_multicluster_uses_per_cluster_plain64_sector_numbering():
    # A single-cluster image fixes guest//512 == 0, so a constant-0 XTS sector wiring survives.
    # This two-cluster image puts the second cluster at guest offset 512 (plain64 first_sector = 1):
    # decrypting it with sector 0 yields garbage, so the per-cluster numbering is verified past 0.
    key = bytes(range(1, 65))  # AES-256 XTS (two 32-byte keys)
    plain0 = b"CSCTF{qcow2_luks_cluster0}".ljust(512, b"0")
    plain1 = b"CSCTF{qcow2_luks_cluster1}".ljust(512, b"1")
    assert plain0 != plain1
    image = _qcow2_luks_multicluster([plain0, plain1], key)
    recovered = D.unwrap_qcow2(image, luks_key=key)
    assert len(recovered) == 1024
    assert recovered[:512] == plain0
    # The load-bearing assertion for the mutation: the SECOND cluster, at guest offset 512, must
    # decrypt with XTS first_sector = 1, not 0.
    assert recovered[512:] == plain1
    # Cross-check that sector 1 genuinely differs from sector 0 for this plaintext: decrypting the
    # second ciphertext with first_sector 0 would NOT recover plain1 (so a constant-0 tweak fails).
    second_ct = image[4 * 512:5 * 512]
    assert D._aes_xts_decrypt(key, second_ct, 0) != plain1
    assert D._aes_xts_decrypt(key, second_ct, 1) == plain1


# --------------------------------------------------------------------------- VHDX dirty log

def _crc32c(buf: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in buf:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _vhdx_header_and_tables(log_guid: bytes, dirty: bool) -> bytearray:
    """Build a 5-MiB VHDX with headers/region/metadata/BAT but no log entries (log region left zero)."""
    mib = 1 << 20
    image = bytearray(5 * mib)
    image[:8] = D.VHDX_MAGIC
    old = (b"OLD-VHDX-BYTES!!" * 256)[:4096]
    image[3 * mib:3 * mib + 4096] = old  # payload host (overwritten by the log when dirty)

    def header(sequence: int) -> bytes:
        block = bytearray(4096)
        block[:4] = b"head"
        struct.pack_into("<Q", block, 8, sequence)
        struct.pack_into("<H", block, 66, 1)
        if dirty:
            block[48:64] = log_guid
            struct.pack_into("<I", block, 68, mib)       # LogLength
            struct.pack_into("<Q", block, 72, 4 * mib)   # LogOffset
        struct.pack_into("<I", block, 4, _crc32c(block))
        return bytes(block)

    image[64 << 10:(64 << 10) + 4096] = header(1)
    image[128 << 10:(128 << 10) + 4096] = header(2)

    region = bytearray(64 << 10)
    region[:4] = b"regi"
    struct.pack_into("<I", region, 8, 2)
    for index, (ident, offset) in enumerate(((D.VHDX_METADATA_GUID, mib),
                                             (D.VHDX_BAT_GUID, 2 * mib))):
        at = 16 + index * 32
        region[at:at + 16] = ident.bytes_le
        struct.pack_into("<QII", region, at + 16, offset, mib, 1)
    struct.pack_into("<I", region, 4, _crc32c(region))
    image[192 << 10:(192 << 10) + (64 << 10)] = region
    image[256 << 10:(256 << 10) + (64 << 10)] = region

    metadata = bytearray(mib)
    metadata[:8] = b"metadata"
    items = ((D.VHDX_FILE_PARAMETERS_GUID, 0x10000, struct.pack("<II", mib, 0)),
             (D.VHDX_VIRTUAL_SIZE_GUID, 0x10010, struct.pack("<Q", 4096)),
             (D.VHDX_LOGICAL_SECTOR_GUID, 0x10020, struct.pack("<I", 512)))
    struct.pack_into("<H", metadata, 10, len(items))
    for index, (ident, offset, payload) in enumerate(items):
        at = 32 + index * 32
        metadata[at:at + 16] = ident.bytes_le
        struct.pack_into("<IIII", metadata, at + 16, offset, len(payload), 6, 0)
        metadata[offset:offset + len(payload)] = payload
    image[mib:2 * mib] = metadata

    struct.pack_into("<Q", image, 2 * mib, (3 * mib) | 6)  # BAT[0] -> payload host, fully present
    return image


def _vhdx_log_entry(sequence: int, sector: bytes, file_offset: int, log_guid: bytes,
                    *, corrupt: bool = False) -> bytes:
    """One 8 KiB VHDX log entry (4 KiB header sector + 4 KiB data sector) writing ``sector``."""
    entry = bytearray(8192)
    entry[:4] = b"loge"
    struct.pack_into("<I", entry, 8, 8192)         # EntryLength
    struct.pack_into("<Q", entry, 16, sequence)    # SequenceNumber
    struct.pack_into("<I", entry, 24, 1)           # DescriptorCount
    entry[32:48] = log_guid
    # data descriptor at offset 64
    entry[64:68] = b"desc"
    entry[68:72] = sector[-4:]                      # TrailingBytes
    entry[72:80] = sector[:8]                       # LeadingBytes
    struct.pack_into("<Q", entry, 80, file_offset)  # FileOffset
    struct.pack_into("<Q", entry, 88, sequence)     # SequenceNumber (per-descriptor)
    # data sector at offset 4096
    entry[4096:4100] = b"data"
    entry[4104:4104 + 4084] = sector[8:4092]
    struct.pack_into("<I", entry, 4, _crc32c(entry))
    if corrupt:
        entry[5000] ^= 0xFF  # break the data sector after the checksum was written
    return bytes(entry)


def _vhdx_with_log(new_sector: bytes, *, log_guid: bytes, corrupt: bool = False,
                   dirty: bool = True) -> bytes:
    mib = 1 << 20
    image = _vhdx_header_and_tables(log_guid, dirty)
    if dirty:
        entry = _vhdx_log_entry(3, new_sector, 3 * mib, log_guid, corrupt=corrupt)
        image[4 * mib:4 * mib + len(entry)] = entry
    return bytes(image)


def test_vhdx_dirty_log_replays_newest_sector():
    new = (b"CSCTF{vhdx_dirty_log}" * 256)[:4096]
    image = _vhdx_with_log(new, log_guid=uuid.UUID(int=0x5151).bytes_le)
    out = D.unwrap_vhdx(image)
    assert out == new                       # the log write reached the payload host
    assert out != (b"OLD-VHDX-BYTES!!" * 256)[:4096]
    assert D.unwrap(image).raw == new


def test_vhdx_dirty_log_replays_active_run_and_ignores_stale_ring_entries():
    # Three log entries over the SAME payload host, all CRC32C-valid and LogGuid-matched:
    #   seq 2 -> stale (a non-contiguous ring-buffer remnant; the gap at seq 3 detaches it)
    #   seq 4 -> the lower end of the active contiguous run (applied first)
    #   seq 5 -> the newest entry of the active run (applied LAST, so its bytes win)
    # Correct replay = newest selection (seq 5) + ascending application over the active run [4, 5],
    # ignoring the stale seq-2 write entirely.  This pins both ring-buffer behaviours that a single
    # seq-3-only fixture leaves unexercised:
    #   * newest=max(...)  -> min(...)   would select seq 2 and yield the stale bytes
    #   * dropping active.reverse()      would apply [5, 4] and leave the seq-4 bytes on top
    mib = 1 << 20
    guid = uuid.UUID(int=0x5151).bytes_le
    host = 3 * mib
    stale = (b"STALE-SEQ2-WRITE." * 256)[:4096]   # must NOT appear in the reconstruction
    lower = (b"ACTIVE-SEQ4-RUN.." * 256)[:4096]   # applied, then overwritten by the newest
    newest = (b"CSCTF{vhdx_active}" * 256)[:4096]  # the only bytes that may survive at the host
    image = _vhdx_header_and_tables(guid, dirty=True)
    for position, (sequence, sector) in enumerate(((2, stale), (4, lower), (5, newest))):
        entry = _vhdx_log_entry(sequence, sector, host, guid)
        at = 4 * mib + position * len(entry)
        image[at:at + len(entry)] = entry

    out = D.unwrap_vhdx(bytes(image))
    assert out == newest               # newest-sequence selection + ascending replay over [4, 5]
    assert out != lower                # kills the dropped active.reverse() mutant (would be seq 4)
    assert out != stale                # kills the newest=max->min mutant (would be the stale seq 2)
    assert D.unwrap(bytes(image)).raw == newest


def test_vhdx_clean_image_reads_pre_log_bytes():
    new = (b"CSCTF{vhdx_dirty_log}" * 256)[:4096]
    clean = _vhdx_with_log(new, log_guid=uuid.UUID(int=0x5151).bytes_le, dirty=False)
    assert D.unwrap_vhdx(clean) == (b"OLD-VHDX-BYTES!!" * 256)[:4096]


def test_vhdx_dirty_log_with_no_valid_entry_declines():
    new = (b"N" * 4096)
    corrupt = _vhdx_with_log(new, log_guid=uuid.UUID(int=0x5151).bytes_le, corrupt=True)
    with pytest.raises(D.DiskImageError):
        D.unwrap_vhdx(corrupt)


# --------------------------------------------------------------------------- EWF2 / Ex01

def _ewf2(payloads, *, compression_method=1, bad_descriptor=False, bad_chunk=False,
          segment_number=1, global_base=0, include_device=True,
          total_chunks=None, total_sectors=None):
    """Build one EWF2/Ex01 segment.

    ``segment_number``/``global_base`` place a segment within a multi-segment set: the
    device-information geometry (total chunk/sector counts across the whole set) lives only in segment
    1; the sector-table ``first_chunk`` field is per-segment-local (0 for a single table), and a chunk
    is deflate-compressed iff its GLOBAL index (``global_base + i``) is 0, else stored+Adler32 —
    matching the single-segment default (segment 1, global_base 0) exactly.
    """
    sectors_per_chunk, bytes_per_sector = 1, 512
    chunk_size = sectors_per_chunk * bytes_per_sector
    image = bytearray()
    image += b"EVF2\r\n\x81\0"
    image += struct.pack("<BBHH", 2, 0, compression_method, segment_number)  # major, minor, compr, seg#
    image += bytes(16)  # set identifier
    assert len(image) == 30
    previous = [0]

    def section(section_type, body):
        offset = len(image)
        descriptor = bytearray(76)
        struct.pack_into("<II", descriptor, 0, section_type, 0)
        struct.pack_into("<QQ", descriptor, 8, previous[0], len(body))
        struct.pack_into("<I", descriptor, 24, 76)
        struct.pack_into("<I", descriptor, 72, zlib.adler32(descriptor[:72]) & 0xFFFFFFFF)
        image.extend(descriptor)
        image.extend(body)
        previous[0] = offset

    device_len = 0
    if include_device:
        chunks = len(payloads) if total_chunks is None else total_chunks
        sectors = len(payloads) if total_sectors is None else total_sectors
        device = struct.pack("<QIIQ", chunks, sectors_per_chunk, bytes_per_sector, sectors)
        section(D.EWF2_SECTION_DEVICE_INFORMATION, device)
        device_len = len(device)

    blob = bytearray()
    entries = []
    for index, payload in enumerate(payloads):
        if global_base + index == 0:
            packed, flags = zlib.compress(payload), 0x1
        else:
            packed, flags = payload + struct.pack("<I", zlib.adler32(payload) & 0xFFFFFFFF), 0x2
        entries.append((len(blob), len(packed), flags))
        blob.extend(packed)
    section(D.EWF2_SECTION_SECTOR_DATA, bytes(blob))

    table = bytearray()
    table += struct.pack("<QIQI", 0, len(payloads), 0, 0)  # first_chunk (segment-local), count, base, pad
    table += struct.pack("<I", zlib.adler32(bytes(table[:24])) & 0xFFFFFFFF)
    for offset, size, flags in entries:
        table += struct.pack("<QII", offset, size, flags)
    section(D.EWF2_SECTION_SECTOR_TABLE, bytes(table))
    section(D.EWF2_SECTION_DONE, b"")

    if bad_descriptor:
        image[35] ^= 0xFF  # flip inside the first descriptor, below its stored checksum
    if bad_chunk:
        # corrupt the checksum-protected second chunk's payload inside the sector-data blob
        data_body_start = 30 + 76 + device_len + 76
        image[data_body_start + len(blob) - len(payloads[-1]) - 4] ^= 0xFF
    assert chunk_size == 512
    return bytes(image)


def test_ewf2_reconstructs_compressed_and_checksummed_chunks():
    payloads = [b"CSCTF{ewf2_c0}".ljust(512, b"\xaa"), b"CSCTF{ewf2_c1}".ljust(512, b"\xbb")]
    image = _ewf2(payloads)
    assert D.detect_container(image) == "ewf2"
    assert D.unwrap_ewf2(image) == b"".join(payloads)
    result = D.unwrap(image)
    assert result.raw == b"".join(payloads) and result.format == "ewf2"


def test_ewf2_rejects_descriptor_and_chunk_corruption():
    payloads = [b"A" * 512, b"B" * 512]
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf2(_ewf2(payloads, bad_descriptor=True))
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf2(_ewf2(payloads, bad_chunk=True))


def test_ewf2_two_segments_concatenate_and_reject_misordered_or_duplicate():
    # The .Ex01/.Ex02 split path: segment 1 carries the whole-set geometry (2 chunks total) and the
    # first chunk (deflate), segment 2 carries the second chunk (stored+Adler32) at first_chunk=1.
    seg1_payloads = [b"CSCTF{ewf2_seg1}".ljust(512, b"\x11")]
    seg2_payloads = [b"CSCTF{ewf2_seg2}".ljust(512, b"\x22")]
    total = len(seg1_payloads) + len(seg2_payloads)
    seg1 = _ewf2(seg1_payloads, segment_number=1, global_base=0,
                 total_chunks=total, total_sectors=total)
    seg2 = _ewf2(seg2_payloads, segment_number=2, global_base=len(seg1_payloads),
                 include_device=False)
    # Cross-segment concatenation in segment-number order.
    assert D.unwrap_ewf2_segments([seg1, seg2]) == b"".join(seg1_payloads + seg2_payloads)
    # Out-of-order segment numbers must decline, never silently reorder/concatenate.
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf2_segments([seg2, seg1])
    # A duplicated segment number (two "segment 1"s) must decline too.
    duplicate = _ewf2(seg2_payloads, segment_number=1, global_base=len(seg1_payloads),
                      include_device=False)
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf2_segments([seg1, duplicate])
    # Segments disagreeing on the compression method must decline.
    seg2_other = _ewf2(seg2_payloads, segment_number=2, global_base=len(seg1_payloads),
                       include_device=False, compression_method=0)
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf2_segments([seg1, seg2_other])


def test_ewf2_invalid_body_is_a_structured_decline_with_command_plan():
    for magic, family in ((D.EWF2_MAGICS[0], "EVF2"), (D.EWF2_MAGICS[1], "LEF2")):
        value = magic + b"\0" * 128
        result = D.unwrap(value)
        assert result.raw is None and family in result.diagnostics[0]
        assert result.command_plan == ("ewfverify {in}", "ewfexport -t /out/image -f raw {in}")


# --------------------------------------------------------------------------- SEsparse VMDK

def _sesparse(grain0: bytes, grain3: bytes) -> bytes:
    # grain_size = 1 sector (512 B); 4 grains; 2 entries per grain table.
    image = bytearray(8192)
    image[:8] = D.SESPARSE_MAGIC
    struct.pack_into("<Q", image, 8, (2 << 32) | 1)   # version 2.1
    struct.pack_into("<QQQ", image, 16, 4, 1, 2)      # capacity, grain_size, grain_table_size
    struct.pack_into("<QQ", image, 40, 1, 2)          # grain_dir_offset(sector), grain_dir_size
    struct.pack_into("<Q", image, 56, 2)              # grain_tables_offset (sector)
    struct.pack_into("<Q", image, 72, 8)              # grain_offset (sector 8 -> 4096)
    struct.pack_into("<QQ", image, 512, 2, 3)         # grain directory: table0@sec2, table1@sec3
    # grain table 0 (grains 0,1): allocated grain index 0, then an explicit zero grain
    struct.pack_into("<QQ", image, 1024, (0x3 << 60) | 0, (0x2 << 60))
    # grain table 1 (grains 2,3): unallocated (parent/zero), then allocated grain index 1
    struct.pack_into("<QQ", image, 1536, 0, (0x3 << 60) | 1)
    image[4096:4608] = grain0
    image[4608:5120] = grain3
    return bytes(image)


def test_sesparse_grain_directory_expansion_standalone_and_parent():
    g0 = b"CSCTF{sesparse_g0}".ljust(512, b"0")
    g3 = b"CSCTF{sesparse_g3}".ljust(512, b"3")
    image = _sesparse(g0, g3)
    assert D.unwrap_vmdk_sesparse(image) == g0 + bytes(512) + bytes(512) + g3
    parent = bytes(((i * 13) & 0xFF) for i in range(2048))
    # Only the unallocated grain 2 falls through to the parent; the zero grain overrides it.
    assert D.unwrap_vmdk_sesparse(image, parent=parent) == g0 + bytes(512) + parent[1024:1536] + g3


def test_sesparse_via_descriptor_and_unknown_grain_declines():
    g0 = b"P" * 512
    g3 = b"Q" * 512
    image = _sesparse(g0, g3)
    descriptor = b'# Disk DescriptorFile\nversion=1\ncreateType="seSparse"\nRW 4 SESPARSE "disk.vmdk"\n'
    assert D.detect_container(descriptor) == "vmdk-descriptor"
    assert D.unwrap_vmdk_descriptor(descriptor, {"disk.vmdk": image}) == g0 + bytes(1024) + g3
    broken = bytearray(image)
    struct.pack_into("<Q", broken, 1024, (0x4 << 60))  # unknown grain-table entry type
    with pytest.raises(D.DiskImageError):
        D.unwrap_vmdk_sesparse(bytes(broken))


# --------------------------------------------------------------------------- APFS decmpfs type 1

def test_apfs_decmpfs_inline_type1_uncompressed_and_codec_decline():
    data = b"CSCTF{apfs_decmpfs_type1}" * 3
    value = b"fpmc" + struct.pack("<IQ", 1, len(data)) + data
    assert D._apfs_decmpfs_inline(value) == data
    # A wrong declared size is caught, not silently truncated.
    with pytest.raises(D.DiskImageError):
        D._apfs_decmpfs_inline(b"fpmc" + struct.pack("<IQ", 1, len(data) + 1) + data)
    # LZVN (type 7) needs an external codec: decline loudly, naming the type.
    with pytest.raises(D.DiskImageError):
        D._apfs_decmpfs_inline(b"fpmc" + struct.pack("<IQ", 7, 4) + b"\x00\x00\x00\x00")


def _apfs_checked(block: bytes) -> bytes:
    """Stamp an APFS object's Fletcher-64 checksum (computed over everything after the 8-byte field)."""
    block = bytearray(block)
    struct.pack_into("<Q", block, 0, 0)
    struct.pack_into("<Q", block, 0, D._apfs_fletcher64(bytes(block)))
    return bytes(block)


def _apfs_volume_with_decmpfs(payload: bytes, uncompressed_size: int, *, file_id: int = 42) -> bytes:
    """A minimal APFS container (NX superblock + one catalog leaf) holding an inline decmpfs xattr."""
    block_size = 4096
    image = bytearray(3 * block_size)
    nx = bytearray(block_size)
    nx[32:36] = D.APFS_NX_MAGIC
    struct.pack_into("<IQ", nx, 36, block_size, 3)   # block_size, block_count
    nx[72:88] = bytes(range(16))
    image[:block_size] = _apfs_checked(nx)

    name = b"flag.txt\0"
    xname = b"com.apple.decmpfs\0"
    inode_key = struct.pack("<Q", (3 << 60) | file_id)
    inode_value = bytearray(92)
    struct.pack_into("<Q", inode_value, 0, 2)                    # parent id
    struct.pack_into("<Q", inode_value, 8, 99)                   # private id
    struct.pack_into("<Q", inode_value, 84, uncompressed_size)   # uncompressed size
    drec_key = struct.pack("<QI", (9 << 60) | 2, len(name)) + name
    drec_value = struct.pack("<QQH", file_id, 123, 0)
    xattr_key = struct.pack("<QH", (4 << 60) | file_id, len(xname)) + xname
    xattr_value = struct.pack("<HH", 2, len(payload)) + payload  # XATTR_DATA_EMBEDDED (flag 2)
    pairs = ((inode_key, bytes(inode_value)), (drec_key, drec_value), (xattr_key, xattr_value))

    catalog = bytearray(block_size)
    struct.pack_into("<Q", catalog, 16, 9)                       # xid
    struct.pack_into("<II", catalog, 24, 3, 14)                  # object subtype (FS tree leaf)
    struct.pack_into("<HHI", catalog, 32, 0x0002, 0, len(pairs))  # flags=leaf, level=0, count
    struct.pack_into("<HH", catalog, 40, 0, len(pairs) * 8)      # table off/len
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
    return bytes(image)


def test_apfs_decmpfs_type1_recovers_through_catalog_entrypoint():
    # Exercise the NEW inline-type-1 branch end to end through the production caller
    # (recover_apfs_catalog_file -> _apfs_decmpfs_inline), not just by a direct private call, so the
    # catalog-inode/xattr wiring of the uncompressed path is asserted (the existing round-5 apfs test
    # covers the same caller for the zlib type-3 path).
    data = b"CSCTF{apfs_type1_e2e}" * 2
    payload = b"fpmc" + struct.pack("<IQ", 1, len(data)) + data    # type 1, uncompressed inline
    image = _apfs_volume_with_decmpfs(payload, len(data))
    result = D.recover_apfs_catalog_file(image, 42)
    assert result["data"] == data
    assert result["compressed"] is True and result["size"] == len(data)
    # A type-1 payload whose inode size disagrees with the decmpfs header is rejected, not returned.
    mismatch = _apfs_volume_with_decmpfs(payload, len(data) + 1)
    with pytest.raises(D.DiskImageError):
        D.recover_apfs_catalog_file(mismatch, 42)


# --------------------------------------------------------------------------- real-tool byte fidelity

@pytest.mark.needs_realdata("disk-images")
def test_ewf2_byte_fidelity_against_real_tool_image():
    """Byte-for-byte fidelity of EWF2 reconstruction against a real tool-produced Ex01 + raw sidecar.

    Reported as NOT RUN until a real-data corpus exists: tool-produced ``*.Ex01`` images cannot be
    generated offline, and a challenge binary may never be executed (see docs/build-log/B-156.md).
    When the ``disk-images`` realdata subfolder is present, every ``<name>.Ex01`` (with any
    ``<name>.Ex02`` ... continuation segments) must reconstruct exactly to its sibling ``<name>.raw``.
    """
    from ctf import paths
    corpus = paths.realdata_root() / "disk-images"
    firsts = sorted(corpus.glob("*.Ex01"))
    if not firsts:
        pytest.skip("realdata disk-images corpus holds no *.Ex01 sample")
    for first in firsts:
        expected = (first.parent / (first.stem + ".raw")).read_bytes()
        segments = []
        index = 1
        while True:
            part = first.parent / f"{first.stem}.Ex{index:02d}"
            if not part.exists():
                break
            segments.append(part.read_bytes())
            index += 1
        assert D.unwrap_ewf2_segments(segments) == expected
