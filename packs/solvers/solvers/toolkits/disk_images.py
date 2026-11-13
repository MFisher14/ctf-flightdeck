#!/usr/bin/env python3
"""Bounded offline disk-container unwrap and filesystem recovery primitives.

The module reconstructs QCOW2, VMDK (flat/sparse/SEsparse), VHD, VHDX (clean and dirty-log replay),
and classic EWF1/E01 and EWF2/Ex01 images entirely from their allocation tables.  QCOW2 supports
deflate clusters, caller-supplied backing bytes, the legacy per-sector AES-CBC scheme when the exact
16-byte key is supplied, and LUKS (``crypt_method`` 2) AES-XTS clusters when the master key is
supplied (no key or passphrase: it declines loudly rather than guess).  A dirty VHDX log is replayed
into a private copy before reconstruction.  Split VMDK descriptors are assembled only from explicitly
supplied extent bytes; SEsparse extent bytes are expanded through their grain directory.  QCOW2 LUKS
passphrase-to-keyslot derivation, VMFSSPARSE, and grain-compressed VMDK layouts still decline rather
than silently return bad data.

Filesystem helpers decode NTFS non-resident data runs and named ``$DATA`` streams (ADS), preserve
allocated slack, follow ext3/4 extent trees for deleted-inode recovery, and recover APFS/btrfs
catalog files (including inline decmpfs types 1 and 3).  Every allocation, table, run count, extent
depth, and output size is bounded.  No image is mounted and no artifact is executed.

EWF2 and SEsparse reconstruction here is validated against synthetic samples built to the published
format model; byte-fidelity against real tool-produced Ex01/SEsparse images is deferred to a
``needs_realdata`` corpus test (reported as not-run until such samples exist), never attempted by the
offline synthetic suite.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import dataclasses
import hashlib
import itertools
import json
import math
import re
import struct
import sys
import uuid
import zlib
from pathlib import Path


MAX_INPUT = 512 << 20
MAX_RAW = 128 << 20
MAX_TABLE = 1 << 20
MAX_RUNS = 1 << 18
MAX_RECORD = 1 << 20
MAX_EXTENTS = 1 << 18
MAX_EXT_DEPTH = 5

QCOW_MAGIC = b"QFI\xfb"
VHDX_MAGIC = b"vhdxfile"
EWF_MAGICS = (b"EVF\t\r\n\xff\x00", b"LVF\t\r\n\xff\x00")
EWF2_MAGIC = b"EVF2\r\n\x81\x00"
EWF2_MAGICS = (EWF2_MAGIC, b"LEF2\r\n\x81\x00")

VHDX_BAT_GUID = uuid.UUID("2dc27766-f623-4200-9d64-115e9bfd4a08")
VHDX_METADATA_GUID = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e")
VHDX_FILE_PARAMETERS_GUID = uuid.UUID("caa16737-fa36-4d43-b3b6-33f0aa44e76b")
VHDX_VIRTUAL_SIZE_GUID = uuid.UUID("2fa54224-cd1b-4876-b211-5dbed83bf4b8")
VHDX_LOGICAL_SECTOR_GUID = uuid.UUID("8141bf1d-a96f-4709-ba47-f233a8faab5f")
VHDX_PARENT_LOCATOR_GUID = uuid.UUID("a8d35f2d-b30b-454d-abf7-d3d84834ab0c")

APFS_NX_MAGIC = b"NXSB"
BTRFS_MAGIC = b"_BHRfS_M"
# VMware SEsparse (space-efficient sparse) const-header magic, 0xCAFEBABE as a 64-bit LE word.
SESPARSE_MAGIC = (0xCAFEBABE).to_bytes(8, "little")


class DiskImageError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class UnwrapResult:
    format: str
    raw: bytes | None
    diagnostics: tuple[str, ...]
    command_plan: tuple[str, ...] = ()

    def report(self) -> dict:
        return {"format": self.format, "raw_size": len(self.raw) if self.raw is not None else None,
                "raw_sha256": hashlib.sha256(self.raw).hexdigest() if self.raw is not None else None,
                "diagnostics": list(self.diagnostics), "command_plan": list(self.command_plan)}


def detect_container(data: bytes) -> str:
    if data.startswith(QCOW_MAGIC):
        return "qcow2"
    if data.startswith(VHDX_MAGIC):
        return "vhdx"
    if data.startswith(EWF_MAGICS):
        return "ewf"
    if data.startswith(EWF2_MAGICS):
        return "ewf2"
    if data.startswith(b"KDMV"):
        return "vmdk-sparse"
    if data[:4096].lstrip().startswith(b"# Disk DescriptorFile") or re.search(rb"(?im)^\s*createType\s*=", data[:65536]):
        return "vmdk-descriptor"
    if len(data) >= 512 and data[-512:-504] == b"conectix":
        return "vhd"
    if data[:4] == b"\x7fELF":
        return "not-disk-elf"
    return "raw-or-unknown"


def _bounded_virtual_size(size: int) -> None:
    if not isinstance(size, int) or size < 0 or size > MAX_RAW:
        raise DiskImageError("virtual disk exceeds the 128 MiB reconstruction cap")


def _gf128_mul_alpha(tweak: bytes) -> bytes:
    """Multiply a 128-bit XTS tweak by the primitive element alpha (IEEE Std 1619-2007)."""
    out = bytearray(16)
    carry = 0
    for index in range(16):
        byte = tweak[index]
        out[index] = ((byte << 1) | carry) & 0xFF
        carry = byte >> 7
    if carry:
        out[0] ^= 0x87
    return bytes(out)


def _aes_xts_decrypt(key: bytes, data: bytes, first_sector: int, sector_size: int = 512) -> bytes:
    """Decrypt AES-XTS sectors with plain64 tweaks (the LUKS/qcow2 and APFS FileVault convention).

    ``key`` is the concatenated data-unit and tweak keys (32 bytes for AES-128, 64 for AES-256).  The
    tweak of sector *s* is ``s`` encoded as a 128-bit little-endian integer, matching ``plain64`` IV
    numbering relative to the start of the encrypted region.  Only whole 16-byte blocks are handled
    (every disk sector is a multiple of 16), so no ciphertext stealing is attempted.
    """
    if len(key) not in (32, 64):
        raise DiskImageError("AES-XTS key must be 32 bytes (AES-128) or 64 bytes (AES-256)")
    if sector_size < 16 or sector_size % 16 or len(data) % sector_size:
        raise DiskImageError("AES-XTS payload is not a whole number of 16-byte-aligned sectors")
    if first_sector < 0 or (first_sector + len(data) // sector_size) >= (1 << 64):
        raise DiskImageError("AES-XTS sector index is outside bounds")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover - dependency is in the locked environment
        raise DiskImageError("pycryptodome is required for AES-XTS decryption") from exc
    half = len(key) // 2
    cipher = AES.new(key[:half], AES.MODE_ECB)
    tweaker = AES.new(key[half:], AES.MODE_ECB)
    out = bytearray(len(data))
    sectors = len(data) // sector_size
    for sector in range(sectors):
        tweak = tweaker.encrypt((first_sector + sector).to_bytes(16, "little"))
        base = sector * sector_size
        for block in range(0, sector_size, 16):
            at = base + block
            masked = bytes(a ^ b for a, b in zip(data[at:at + 16], tweak))
            plain = cipher.decrypt(masked)
            out[at:at + 16] = bytes(a ^ b for a, b in zip(plain, tweak))
            tweak = _gf128_mul_alpha(tweak)
    return bytes(out)


def _qcow2_legacy_decrypt(payload: bytes, first_sector: int, key: bytes) -> bytes:
    """Decrypt QCOW/QCOW2's legacy AES-CBC sectors.

    This is deliberately a key API, not a password API: old qemu padded/truncated passwords in
    caller-dependent ways.  Requiring the exact 16 bytes prevents a plausible-looking wrong image.
    """
    if len(key) != 16 or len(payload) % 512:
        raise DiskImageError("legacy QCOW2 AES needs an exact 16-byte key and full sectors")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover - dependency is in the locked environment
        raise DiskImageError("pycryptodome is required for legacy QCOW2 AES") from exc
    out = bytearray()
    for index in range(0, len(payload), 512):
        iv = (first_sector + index // 512).to_bytes(8, "little") + b"\0" * 8
        out.extend(AES.new(key, AES.MODE_CBC, iv).decrypt(payload[index:index + 512]))
    return bytes(out)


def _qcow2_inflate_cluster(data: bytes, entry: int, cluster_bits: int, cluster: int,
                           compression_type: int = 0) -> bytes:
    """Inflate one compressed-cluster descriptor as specified by QCOW2.

    The compressed byte stream can start between sector boundaries; the descriptor stores both the
    sector count and that intra-sector offset.  Raw deflate is canonical, while a zlib wrapper is
    accepted for older producers after the raw stream has declined.
    """
    size_bits = cluster_bits - 8
    csize_shift = 62 - size_bits
    csize_mask = (1 << size_bits) - 1
    offset_mask = (1 << csize_shift) - 1
    encoded_offset = entry & offset_mask
    sectors = ((entry >> csize_shift) & csize_mask) + 1
    sector_base = encoded_offset & ~511
    skip = encoded_offset & 511
    packed_size = sectors * 512 - skip
    if packed_size <= 0 or packed_size > cluster * 2 or sector_base + skip + packed_size > len(data):
        raise DiskImageError("QCOW2 compressed cluster is outside the input")
    packed = data[sector_base + skip:sector_base + skip + packed_size]
    decoded = None
    if compression_type == 0:
        for wbits in (-15, 15):
            try:
                obj = zlib.decompressobj(wbits)
                candidate = obj.decompress(packed, cluster + 1) + obj.flush()
            except zlib.error:
                continue
            if obj.eof and len(candidate) == cluster:
                decoded = candidate
                break
    elif compression_type == 1:
        try:
            import zstandard
            obj = zstandard.ZstdDecompressor().decompressobj()
            candidate = obj.decompress(packed)
            if obj.eof and len(candidate) == cluster:
                decoded = candidate
        except ImportError as exc:
            raise DiskImageError("QCOW2 Zstd compression needs the offline zstandard codec") from exc
        except zstandard.ZstdError:
            pass
    else:
        raise DiskImageError("unknown QCOW2 compression type")
    if decoded is None:
        raise DiskImageError("QCOW2 compressed cluster did not inflate to one full cluster")
    return decoded


def unwrap_qcow2(data: bytes, *, backing: bytes | None = None, aes_key: bytes | None = None,
                 luks_key: bytes | None = None) -> bytes:
    if len(data) < 72 or not data.startswith(QCOW_MAGIC):
        raise DiskImageError("invalid QCOW2 header")
    try:
        version = struct.unpack_from(">I", data, 4)[0]
        backing_offset = struct.unpack_from(">Q", data, 8)[0]
        backing_size, cluster_bits = struct.unpack_from(">II", data, 16)
        virtual_size = struct.unpack_from(">Q", data, 24)[0]
        crypt_method, l1_size = struct.unpack_from(">II", data, 32)
        l1_offset = struct.unpack_from(">Q", data, 40)[0]
        incompatible = struct.unpack_from(">Q", data, 72)[0] if version >= 3 and len(data) >= 104 else 0
        header_length = struct.unpack_from(">I", data, 100)[0] if version >= 3 and len(data) >= 104 else 72
    except struct.error as exc:
        raise DiskImageError("truncated QCOW2 header") from exc
    if version not in (2, 3) or not 9 <= cluster_bits <= 21:
        raise DiskImageError("unsupported QCOW2 version/cluster size")
    cluster = 1 << cluster_bits
    _bounded_virtual_size(virtual_size)
    if bool(backing_offset) != bool(backing_size) or (backing_offset and backing_offset + backing_size > len(data)):
        raise DiskImageError("QCOW2 backing filename is outside the input")
    if backing_offset and backing is None:
        name = data[backing_offset:backing_offset + backing_size].decode("utf-8", "replace")
        raise DiskImageError(f"QCOW2 needs explicitly supplied backing bytes ({name!r})")
    if backing is not None and not backing_offset:
        raise DiskImageError("QCOW2 backing bytes were supplied but the image declares no backing file")
    if backing is not None and len(backing) < virtual_size:
        raise DiskImageError("QCOW2 backing image is shorter than the virtual disk")
    if crypt_method not in (0, 1, 2):
        raise DiskImageError("unknown QCOW2 encryption method")
    if crypt_method == 1 and aes_key is None:
        raise DiskImageError("legacy AES-encrypted QCOW2 needs --aes-key-hex")
    if crypt_method == 2 and luks_key is None:
        raise DiskImageError(
            "LUKS-encrypted QCOW2 needs the AES-XTS master key (--luks-key-hex); "
            "no key or passphrase was supplied, so it declines rather than guess")
    if crypt_method != 1 and aes_key is not None:
        raise DiskImageError("a legacy AES key was supplied for a non-legacy-AES QCOW2")
    if crypt_method != 2 and luks_key is not None:
        raise DiskImageError("a LUKS master key was supplied for a non-LUKS QCOW2")
    # Dirty/corrupt and external-data-file features make a standalone exact reconstruction unsafe.
    # Compression-type and extended-L2 are the only incompatible features reconstructed here.
    if incompatible & ~((1 << 3) | (1 << 4)):
        raise DiskImageError("QCOW2 has dirty/corrupt/external-data or unknown incompatible features")
    if incompatible & (1 << 3):
        if header_length < 105 or len(data) < 105:
            raise DiskImageError("QCOW2 compression-type header is truncated")
        compression_type = data[104]
        if compression_type not in (0, 1):
            raise DiskImageError("unknown QCOW2 compression type")
    else:
        compression_type = 0
    extended_l2 = bool(incompatible & (1 << 4))
    if l1_size > MAX_TABLE or l1_offset + l1_size * 8 > len(data):
        raise DiskImageError("QCOW2 L1 table is outside the input")
    l2_entry_size = 16 if extended_l2 else 8
    l2_entries = cluster // l2_entry_size
    out = bytearray(backing[:virtual_size] if backing is not None else b"\0" * virtual_size)
    guest_clusters = (virtual_size + cluster - 1) // cluster
    if guest_clusters > MAX_TABLE * l2_entries:
        raise DiskImageError("QCOW2 guest cluster count exceeds cap")
    l2_cache: dict[int, bytes] = {}
    for guest_cluster in range(guest_clusters):
        l1_index, l2_index = divmod(guest_cluster, l2_entries)
        if l1_index >= l1_size:
            break
        l1 = struct.unpack_from(">Q", data, l1_offset + l1_index * 8)[0]
        if not l1:
            continue
        if l1 & (1 << 62):
            raise DiskImageError("compressed flag is invalid on a QCOW2 L1 entry")
        l2_offset = (l1 & ((1 << 63) - 1)) & ~(cluster - 1)
        if l2_offset + cluster > len(data):
            raise DiskImageError("QCOW2 L2 table is outside the input")
        table = l2_cache.get(l2_offset)
        if table is None:
            if len(l2_cache) >= MAX_TABLE:
                raise DiskImageError("QCOW2 L2 table count exceeds cap")
            table = data[l2_offset:l2_offset + cluster]
            l2_cache[l2_offset] = table
        entry_at = l2_index * l2_entry_size
        entry = struct.unpack_from(">Q", table, entry_at)[0]
        bitmap = struct.unpack_from(">Q", table, entry_at + 8)[0] if extended_l2 else None
        if not entry and not bitmap:
            continue
        length = min(cluster, virtual_size - guest_cluster * cluster)
        guest = guest_cluster * cluster
        # Evaluate the COMPRESSED flag (bit 62) BEFORE the zero flag (bit 0), exactly as QEMU's
        # qcow2_get_cluster_type does. For a compressed cluster bits 0..61 are the compressed
        # descriptor (a byte-granular host offset), so bit 0 is set whenever the compressed stream
        # starts at an odd file offset — testing zero first would silently zero-fill ~half of all
        # qemu-img-packed compressed clusters, corrupting the reconstruction.
        if entry & (1 << 62):
            if crypt_method:
                raise DiskImageError("compressed encrypted QCOW2 clusters are unsupported")
            if extended_l2 and bitmap != 0x00000000FFFFFFFF:
                raise DiskImageError("QCOW2 compressed extended-L2 entry is not fully allocated")
            payload = _qcow2_inflate_cluster(data, entry, cluster_bits, cluster, compression_type)
        elif entry & 1:  # zero cluster (v3); it overrides any backing data
            out[guest:guest + length] = b"\0" * length
            continue
        else:
            host = (entry & ((1 << 62) - 1)) & ~(cluster - 1)
            if not extended_l2:
                if host + cluster > len(data):
                    raise DiskImageError("QCOW2 data cluster is outside the input")
                payload = data[host:host + cluster]
                if crypt_method == 1:
                    payload = _qcow2_legacy_decrypt(payload, guest // 512, aes_key or b"")
                elif crypt_method == 2:
                    payload = _aes_xts_decrypt(luks_key or b"", payload, guest // 512)
            else:
                allocation = (bitmap or 0) & 0xFFFFFFFF
                zeroes = (bitmap or 0) >> 32
                if allocation & zeroes:
                    raise DiskImageError("QCOW2 extended-L2 subcluster is both allocated and zero")
                if allocation and (not host or host + cluster > len(data)):
                    raise DiskImageError("QCOW2 extended-L2 data cluster is outside the input")
                if host and not allocation:
                    raise DiskImageError("QCOW2 extended-L2 host cluster has no allocated subclusters")
                payload = data[host:host + cluster] if allocation else b""
                if crypt_method == 1 and payload:
                    payload = _qcow2_legacy_decrypt(payload, guest // 512, aes_key or b"")
                elif crypt_method == 2 and payload:
                    payload = _aes_xts_decrypt(luks_key or b"", payload, guest // 512)
                subcluster = cluster // 32
                for subindex in range(32):
                    sub_guest = guest + subindex * subcluster
                    if sub_guest >= guest + length:
                        break
                    take = min(subcluster, guest + length - sub_guest)
                    bit = 1 << subindex
                    if allocation & bit:
                        start = subindex * subcluster
                        out[sub_guest:sub_guest + take] = payload[start:start + take]
                    elif zeroes & bit:
                        out[sub_guest:sub_guest + take] = b"\0" * take
                continue
        out[guest:guest + length] = payload[:length]
    return bytes(out)


def unwrap_qcow2_chain(data: bytes, backings: list[bytes] | tuple[bytes, ...], *,
                       aes_keys: list[bytes | None] | tuple[bytes | None, ...] | None = None) -> bytes:
    """Resolve an explicit recursive QCOW2 backing chain without opening embedded paths.

    ``backings`` is nearest-parent first.  The farthest element may be raw bytes; every element
    closer to the child must be QCOW2.  Key entries, when supplied, correspond to the child followed
    by each nearest-to-farthest parent.  Extra layers and unrelated raw layers are rejected.
    """
    if not isinstance(data, bytes) or not isinstance(backings, (list, tuple)):
        raise DiskImageError("QCOW2 chain needs explicit byte layers")
    layers = [data, *backings]
    if not layers or len(layers) > 64 or sum(len(layer) for layer in layers) > MAX_INPUT:
        raise DiskImageError("QCOW2 backing chain exceeds aggregate bounds")
    if any(not isinstance(layer, bytes) or not layer for layer in layers):
        raise DiskImageError("QCOW2 backing chain contains a non-byte/empty layer")
    keys = list(aes_keys) if aes_keys is not None else [None] * len(layers)
    if len(keys) != len(layers):
        raise DiskImageError("QCOW2 key list must match child plus backing layers")
    parent = None
    for index in range(len(layers) - 1, -1, -1):
        layer = layers[index]
        if layer.startswith(QCOW_MAGIC):
            parent = unwrap_qcow2(layer, backing=parent, aes_key=keys[index])
        else:
            if index != len(layers) - 1 or parent is not None or keys[index] is not None:
                raise DiskImageError("only the farthest QCOW2 backing layer may be raw")
            if len(layer) > MAX_RAW:
                raise DiskImageError("raw QCOW2 backing exceeds reconstruction cap")
            parent = layer
    if not data.startswith(QCOW_MAGIC):
        raise DiskImageError("QCOW2 chain child is not QCOW2")
    return parent or b""


def unwrap_vmdk_sparse(data: bytes) -> bytes:
    if len(data) < 512 or data[:4] != b"KDMV":
        raise DiskImageError("invalid sparse VMDK header")
    try:
        version, flags = struct.unpack_from("<II", data, 4)
        capacity, grain_sectors = struct.unpack_from("<QQ", data, 12)
        descriptor_sector, descriptor_sectors = struct.unpack_from("<QQ", data, 28)
        entries_per_gt = struct.unpack_from("<I", data, 44)[0]
        gd_sector = struct.unpack_from("<Q", data, 56)[0]
    except struct.error as exc:
        raise DiskImageError("truncated sparse VMDK header") from exc
    if version not in (1, 2, 3) or not grain_sectors or grain_sectors > (1 << 20):
        raise DiskImageError("unsupported sparse VMDK geometry")
    if not entries_per_gt or entries_per_gt > MAX_TABLE:
        raise DiskImageError("VMDK grain-table size exceeds cap")
    virtual_size = capacity * 512
    grain_size = grain_sectors * 512
    _bounded_virtual_size(virtual_size)
    grains = (capacity + grain_sectors - 1) // grain_sectors
    gd_entries = (grains + entries_per_gt - 1) // entries_per_gt
    gd_offset = gd_sector * 512
    if gd_entries > MAX_TABLE or gd_offset + gd_entries * 4 > len(data):
        raise DiskImageError("VMDK grain directory is outside the input")
    compressed = bool(flags & 0x10000)
    compression_algorithm = struct.unpack_from("<H", data, 77)[0]
    if compressed and compression_algorithm != 1:
        raise DiskImageError("compressed VMDK uses an unsupported compression algorithm")
    if not compressed and compression_algorithm:
        raise DiskImageError("VMDK declares a compression algorithm without compressed grains")
    if descriptor_sectors:
        descriptor_offset, descriptor_size = descriptor_sector * 512, descriptor_sectors * 512
        if descriptor_size > MAX_TABLE or descriptor_offset + descriptor_size > len(data):
            raise DiskImageError("VMDK embedded descriptor is outside the input or exceeds cap")
        descriptor = data[descriptor_offset:descriptor_offset + descriptor_size]
        if re.search(rb"(?im)^\s*parentFileNameHint\s*=", descriptor):
            raise DiskImageError("differencing VMDK parent files are intentionally not followed")
    out = bytearray(virtual_size)
    for gd_index in range(gd_entries):
        gt_sector = struct.unpack_from("<I", data, gd_offset + gd_index * 4)[0]
        if not gt_sector:
            continue
        gt_offset = gt_sector * 512
        if gt_offset + entries_per_gt * 4 > len(data):
            raise DiskImageError("VMDK grain table is outside the input")
        for gt_index in range(entries_per_gt):
            grain_index = gd_index * entries_per_gt + gt_index
            if grain_index >= grains:
                break
            sector = struct.unpack_from("<I", data, gt_offset + gt_index * 4)[0]
            if not sector:
                continue
            host, guest = sector * 512, grain_index * grain_size
            length = min(grain_size, virtual_size - guest)
            if not compressed:
                if host + length > len(data):
                    raise DiskImageError("VMDK grain is outside the input")
                out[guest:guest + length] = data[host:host + length]
                continue
            if host + 12 > len(data):
                raise DiskImageError("compressed VMDK grain marker is outside the input")
            marker_lba, packed_size = struct.unpack_from("<QI", data, host)
            if marker_lba != grain_index * grain_sectors or not packed_size or packed_size > grain_size * 2:
                raise DiskImageError("compressed VMDK grain marker has invalid LBA/size")
            if host + 12 + packed_size > len(data):
                raise DiskImageError("compressed VMDK grain bytes are outside the input")
            packed = data[host + 12:host + 12 + packed_size]
            decoded = None
            for wbits in (15, -15):
                try:
                    decoder = zlib.decompressobj(wbits)
                    candidate = decoder.decompress(packed, grain_size + 1) + decoder.flush()
                except zlib.error:
                    continue
                if decoder.eof and not decoder.unused_data and len(candidate) == grain_size:
                    decoded = candidate
                    break
            if decoded is None:
                raise DiskImageError("compressed VMDK grain did not inflate to one full grain")
            out[guest:guest + length] = decoded[:length]
    return bytes(out)


def unwrap_vmdk_sesparse(data: bytes, *, parent: bytes | None = None) -> bytes:
    """Expand a VMware SEsparse extent through its grain directory and grain tables.

    The 4 KiB const header declares the capacity, grain size, grain-directory and grain-table layout,
    and the start of the grain-data region (all in 512-byte sectors).  Each 64-bit grain-table entry
    is typed by its top nibble: unallocated/unmapped grains fall through to ``parent`` (or read as
    zero), an explicit zero grain overrides the parent with zeros, and an allocated grain points at a
    grain-data index.  Multi-level or non-const-header SEsparse variants decline rather than guess.
    """
    if len(data) < 4096 or data[:8] != SESPARSE_MAGIC:
        raise DiskImageError("invalid SEsparse const header")
    try:
        version = struct.unpack_from("<Q", data, 8)[0]
        capacity, grain_size, grain_table_size = struct.unpack_from("<QQQ", data, 16)
        grain_dir_offset, grain_dir_size = struct.unpack_from("<QQ", data, 40)
        grain_tables_offset = struct.unpack_from("<Q", data, 56)[0]
        grain_offset = struct.unpack_from("<Q", data, 72)[0]
    except struct.error as exc:
        raise DiskImageError("truncated SEsparse const header") from exc
    if not version or version > (1 << 40):
        raise DiskImageError("unsupported SEsparse version")
    if not grain_size or grain_size > (1 << 20) or not grain_table_size or grain_table_size > MAX_TABLE:
        raise DiskImageError("unsupported SEsparse grain geometry")
    virtual_size = capacity * 512
    grain_bytes = grain_size * 512
    _bounded_virtual_size(virtual_size)
    if parent is not None and len(parent) < virtual_size:
        raise DiskImageError("SEsparse parent image is shorter than the virtual disk")
    grains = (capacity + grain_size - 1) // grain_size
    needed_tables = (grains + grain_table_size - 1) // grain_table_size
    if grain_dir_size < needed_tables or grain_dir_size > MAX_TABLE:
        raise DiskImageError("SEsparse grain directory is too small for the capacity")
    gd_at = grain_dir_offset * 512
    if gd_at + grain_dir_size * 8 > len(data):
        raise DiskImageError("SEsparse grain directory is outside the extent")
    out = bytearray(parent[:virtual_size] if parent is not None else b"\0" * virtual_size)
    for grain in range(grains):
        gd_index, gt_index = divmod(grain, grain_table_size)
        gt_sector = struct.unpack_from("<Q", data, gd_at + gd_index * 8)[0]
        if not gt_sector:
            continue  # no grain table -> unallocated region (parent/zero)
        gt_at = gt_sector * 512
        if gt_at < grain_tables_offset * 512 or gt_at + grain_table_size * 8 > len(data):
            raise DiskImageError("SEsparse grain table is outside the extent")
        entry = struct.unpack_from("<Q", data, gt_at + gt_index * 8)[0]
        guest = grain * grain_bytes
        length = min(grain_bytes, virtual_size - guest)
        kind = entry >> 60
        if entry == 0 or kind == 0x1:
            continue  # unallocated / unmapped -> inherit parent or zero
        if kind == 0x2:
            out[guest:guest + length] = b"\0" * length
            continue
        if kind != 0x3:
            raise DiskImageError("SEsparse grain-table entry has an unknown type")
        grain_index = entry & 0x0FFFFFFFFFFFFFFF
        host = (grain_offset + grain_index * grain_size) * 512
        if host < grain_offset * 512 or host + length > len(data):
            raise DiskImageError("SEsparse grain points outside the extent")
        out[guest:guest + length] = data[host:host + length]
    return bytes(out)


_VMDK_EXTENT_RE = re.compile(
    r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(FLAT|SPARSE|SESPARSE|ZERO|VMFS)'
    r'(?:\s+"((?:[^"\\]|\\.)*)"(?:\s+(\d+))?)?\s*$', re.I)


def unwrap_vmdk_descriptor(descriptor: bytes | str, extents: dict[str, bytes], *,
                           parent: bytes | None = None) -> bytes:
    """Assemble split FLAT/SPARSE/SESPARSE/ZERO VMDK extents supplied by the caller.

    Embedded filenames are dictionary keys only; they are never opened.  SESPARSE extents are expanded
    through their grain directory (see ``unwrap_vmdk_sesparse``).  Stream-optimized, VMFSSPARSE, and
    grain-compressed layouts still decline because treating them as flat bytes would be silent
    evidence corruption.
    """
    if isinstance(descriptor, bytes):
        if len(descriptor) > MAX_RECORD:
            raise DiskImageError("VMDK descriptor exceeds cap")
        try:
            text = descriptor.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise DiskImageError("VMDK descriptor is not valid UTF-8") from exc
    elif isinstance(descriptor, str):
        text = descriptor
    else:
        raise DiskImageError("VMDK descriptor must be bytes or text")
    if (not isinstance(extents, dict) or
            any(not isinstance(key, str) or not isinstance(value, bytes) for key, value in extents.items()) or
            sum(len(value) for value in extents.values()) > MAX_INPUT):
        raise DiskImageError("VMDK supplied extents exceed aggregate bounds")
    rows = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Za-z][A-Za-z0-9_.-]*\s*=", line):
            continue
        match = _VMDK_EXTENT_RE.fullmatch(line)
        if match is None:
            if re.match(r"^(?:RW|RDONLY|NOACCESS)\b", line, re.I):
                raise DiskImageError(f"unsupported VMDK extent line: {line[:120]}")
            continue
        access, sectors_s, kind, encoded_name, offset_s = match.groups()
        if access.upper() == "NOACCESS":
            raise DiskImageError("NOACCESS VMDK extents cannot be reconstructed")
        sectors = int(sectors_s)
        if not sectors:
            raise DiskImageError("zero-length VMDK extent")
        name = None
        if encoded_name is not None:
            name = re.sub(r"\\([\\\"])", r"\1", encoded_name)
        rows.append((sectors, kind.upper(), name, int(offset_s or 0)))
        if len(rows) > 65536:
            raise DiskImageError("VMDK extent count exceeds cap")
    if not rows:
        raise DiskImageError("VMDK descriptor has no extents")
    virtual_size = sum(sectors for sectors, *_ in rows) * 512
    _bounded_virtual_size(virtual_size)
    if re.search(r"(?im)^\s*parentFileNameHint\s*=", text) and parent is None:
        raise DiskImageError("differencing VMDK needs explicitly supplied parent bytes")
    if parent is not None and len(parent) < virtual_size:
        raise DiskImageError("VMDK parent image is shorter than the virtual disk")
    output = bytearray(parent[:virtual_size] if parent is not None else b"\0" * virtual_size)
    guest = 0
    basenames: dict[str, list[bytes]] = {}
    for key, value in extents.items():
        basenames.setdefault(Path(key).name, []).append(value)
    for sectors, kind, name, sector_offset in rows:
        size = sectors * 512
        if kind == "ZERO":
            output[guest:guest + size] = b"\0" * size
        else:
            if not name:
                raise DiskImageError(f"{kind} VMDK extent is missing its filename")
            source = extents.get(name)
            if source is None:
                matches = basenames.get(Path(name).name, [])
                if len(matches) == 1:
                    source = matches[0]
            if source is None:
                raise DiskImageError(f"VMDK extent bytes were not supplied for {name!r}")
            if kind == "SPARSE":
                payload = unwrap_vmdk_sparse(source)
                if sector_offset:
                    raise DiskImageError("SPARSE VMDK extent cannot have a flat sector offset")
            elif kind == "SESPARSE":
                if sector_offset:
                    raise DiskImageError("SESPARSE VMDK extent cannot have a flat sector offset")
                # A SEsparse extent inherits unallocated grains from the parent slice it covers.
                slice_parent = bytes(output[guest:guest + size]) if parent is not None else None
                payload = unwrap_vmdk_sesparse(source, parent=slice_parent)
            elif kind in ("FLAT", "VMFS"):
                start = sector_offset * 512
                if start + size > len(source):
                    raise DiskImageError(f"VMDK flat extent {name!r} is truncated")
                payload = source[start:start + size]
            else:  # guarded by the regex, kept fail-closed for future edits
                raise DiskImageError(f"unsupported VMDK extent type {kind}")
            if len(payload) < size:
                raise DiskImageError(f"VMDK extent {name!r} is smaller than declared")
            output[guest:guest + size] = payload[:size]
        guest += size
    return bytes(output)


def _vhd_footer(data: bytes) -> dict:
    if len(data) < 512 or data[-512:-504] != b"conectix":
        raise DiskImageError("VHD footer is missing")
    footer = data[-512:]
    stored = struct.unpack_from(">I", footer, 64)[0]
    check = bytearray(footer)
    check[64:68] = b"\0" * 4
    checksum = (~sum(check)) & 0xFFFFFFFF
    if stored != checksum:
        raise DiskImageError("VHD footer checksum mismatch")
    return {"data_offset": struct.unpack_from(">Q", footer, 16)[0],
            "current_size": struct.unpack_from(">Q", footer, 48)[0],
            "disk_type": struct.unpack_from(">I", footer, 60)[0]}


def unwrap_vhd(data: bytes) -> bytes:
    footer = _vhd_footer(data)
    size, disk_type = footer["current_size"], footer["disk_type"]
    _bounded_virtual_size(size)
    if disk_type == 2:  # fixed
        if size > len(data) - 512:
            raise DiskImageError("fixed VHD payload is truncated")
        return data[:size]
    if disk_type == 4:
        raise DiskImageError("differencing VHD parent images are intentionally not followed")
    if disk_type != 3:
        raise DiskImageError("unsupported VHD disk type")
    header_offset = footer["data_offset"]
    if header_offset == 0xFFFFFFFFFFFFFFFF:
        header_offset = 512
    if header_offset + 1024 > len(data) or data[header_offset:header_offset + 8] != b"cxsparse":
        raise DiskImageError("dynamic VHD header is missing")
    header = bytearray(data[header_offset:header_offset + 1024])
    stored = struct.unpack_from(">I", header, 36)[0]
    header[36:40] = b"\0" * 4
    if ((~sum(header)) & 0xFFFFFFFF) != stored:
        raise DiskImageError("dynamic VHD header checksum mismatch")
    table_offset = struct.unpack_from(">Q", header, 16)[0]
    max_entries, block_size = struct.unpack_from(">II", header, 28)
    if not block_size or block_size > MAX_RAW or max_entries > MAX_TABLE:
        raise DiskImageError("dynamic VHD allocation geometry exceeds cap")
    if table_offset + max_entries * 4 > len(data):
        raise DiskImageError("VHD BAT is outside the input")
    sectors_per_block = block_size // 512
    bitmap_bytes = ((sectors_per_block + 7) // 8 + 511) & ~511
    out = bytearray(size)
    for index in range(min(max_entries, (size + block_size - 1) // block_size)):
        sector = struct.unpack_from(">I", data, table_offset + index * 4)[0]
        if sector == 0xFFFFFFFF:
            continue
        block = sector * 512
        payload = block + bitmap_bytes
        length = min(block_size, size - index * block_size)
        if payload + length > len(data):
            raise DiskImageError("VHD block is outside the input")
        # Honor the per-sector bitmap instead of exposing stale unallocated block bytes.
        bitmap = data[block:block + bitmap_bytes]
        for sector_index in range((length + 511) // 512):
            byte_index, bit_index = divmod(sector_index, 8)
            if byte_index < len(bitmap) and bitmap[byte_index] & (0x80 >> bit_index):
                start = sector_index * 512
                take = min(512, length - start)
                guest = index * block_size + start
                out[guest:guest + take] = data[payload + start:payload + start + take]
    return bytes(out)


def _ewf_sections(data: bytes) -> list[dict]:
    if len(data) < 13 or not data.startswith(EWF_MAGICS) or data[8] != 1:
        raise DiskImageError("unsupported or invalid EWF1 file header")
    sections, seen, offset = [], set(), 13
    while offset not in seen:
        seen.add(offset)
        if len(sections) >= MAX_TABLE or offset + 76 > len(data):
            raise DiskImageError("EWF section chain is truncated or exceeds cap")
        header = data[offset:offset + 76]
        if zlib.adler32(header[:72]) & 0xFFFFFFFF != struct.unpack_from("<I", header, 72)[0]:
            raise DiskImageError("EWF section-header checksum mismatch")
        kind_raw = header[:16].split(b"\0", 1)[0]
        if not kind_raw or not re.fullmatch(rb"[A-Za-z0-9_]{1,15}", kind_raw):
            raise DiskImageError("invalid EWF section type")
        kind = kind_raw.decode("ascii")
        next_offset, size = struct.unpack_from("<QQ", header, 16)
        if kind in ("done", "next"):
            sections.append({"type": kind, "offset": offset, "next": next_offset,
                             "size": size, "body": b""})
            break
        if size < 76 or offset + size > len(data) or next_offset != offset + size:
            raise DiskImageError("invalid EWF section bounds/link")
        sections.append({"type": kind, "offset": offset, "next": next_offset,
                         "size": size, "body": data[offset + 76:offset + size]})
        offset = next_offset
    else:  # pragma: no cover - while exits via explicit cycle check below
        raise DiskImageError("cyclic EWF section chain")
    if len(sections) > 1 and sections[-1]["offset"] in {row["offset"] for row in sections[:-1]}:
        raise DiskImageError("cyclic EWF section chain")
    return sections


def _ewf_geometry(sections: list[dict]) -> dict:
    rows = [row for row in sections if row["type"] in ("volume", "disk", "data") and len(row["body"]) >= 24]
    if not rows:
        raise DiskImageError("EWF media geometry section is missing")
    body = rows[0]["body"]
    chunks, sectors_per_chunk, bytes_per_sector = struct.unpack_from("<III", body, 4)
    sectors = struct.unpack_from("<Q", body, 16)[0]
    if not chunks or chunks > MAX_TABLE or not sectors_per_chunk or sectors_per_chunk > 32768:
        raise DiskImageError("EWF chunk geometry exceeds cap")
    if bytes_per_sector not in (256, 512, 1024, 2048, 4096, 8192):
        raise DiskImageError("unsupported EWF sector size")
    total = sectors * bytes_per_sector
    _bounded_virtual_size(total + bytes_per_sector - 1)
    return {"chunks": chunks, "sectors_per_chunk": sectors_per_chunk,
            "bytes_per_sector": bytes_per_sector, "sectors": sectors,
            "chunk_size": sectors_per_chunk * bytes_per_sector, "size": total}


def _ewf_segment_chunks(data: bytes, sections: list[dict]) -> list[bytes]:
    by_offset = {row["offset"]: row for row in sections}
    output: list[bytes] = []
    for table in (row for row in sections if row["type"] == "table"):
        body = table["body"]
        if len(body) < 28:
            raise DiskImageError("truncated EWF table section")
        count = struct.unpack_from("<I", body, 0)[0]
        base = struct.unpack_from("<Q", body, 8)[0]
        if not count or count > MAX_TABLE or 28 + count * 4 > len(body):
            raise DiskImageError("EWF table count exceeds its section")
        if zlib.adler32(body[:20]) & 0xFFFFFFFF != struct.unpack_from("<I", body, 20)[0]:
            raise DiskImageError("EWF table-header checksum mismatch")
        entries = list(struct.unpack_from(f"<{count}I", body, 24))
        if zlib.adler32(body[24:24 + count * 4]) & 0xFFFFFFFF != struct.unpack_from("<I", body, 24 + count * 4)[0]:
            raise DiskImageError("EWF table-entry checksum mismatch")
        sector_section = by_offset.get(base)
        if sector_section is None or sector_section["type"] not in ("sectors", "sectors2"):
            raise DiskImageError("EWF table does not reference a sectors section")
        section_end = sector_section["offset"] + sector_section["size"]
        starts = [base + (entry & 0x7FFFFFFF) for entry in entries]
        if any(start < base + 76 or start >= section_end for start in starts) or starts != sorted(starts):
            raise DiskImageError("EWF chunk offsets are invalid")
        for index, (entry, start) in enumerate(zip(entries, starts)):
            end = starts[index + 1] if index + 1 < len(starts) else section_end
            if end <= start:
                raise DiskImageError("EWF chunk has an invalid stored length")
            packed = data[start:end]
            if entry & 0x80000000:
                try:
                    chunk = zlib.decompress(packed)
                except zlib.error as exc:
                    raise DiskImageError("EWF compressed chunk failed checksum/decompression") from exc
            else:
                if len(packed) < 4:
                    raise DiskImageError("truncated EWF uncompressed chunk")
                chunk, stored = packed[:-4], struct.unpack_from("<I", packed, len(packed) - 4)[0]
                if zlib.adler32(chunk) & 0xFFFFFFFF != stored:
                    raise DiskImageError("EWF uncompressed chunk checksum mismatch")
            output.append(chunk)
            if len(output) > MAX_TABLE:
                raise DiskImageError("EWF chunk count exceeds cap")
    if not output:
        raise DiskImageError("EWF has no readable chunk table")
    return output


def unwrap_ewf_segments(segments: list[bytes] | tuple[bytes, ...]) -> bytes:
    """Reconstruct ordered classic EWF1 segments (E01/E02/...).

    EWF2/Ex01 is a different format and intentionally declines.  Segment bytes must be supplied in
    order; this function never discovers or opens a filename embedded in evidence.
    """
    if not segments or len(segments) > 65535:
        raise DiskImageError("EWF segment count is outside bounds")
    if sum(len(segment) for segment in segments if isinstance(segment, bytes)) > MAX_INPUT:
        raise DiskImageError("EWF segments exceed aggregate input cap")
    parsed, numbers = [], []
    for segment in segments:
        if not isinstance(segment, bytes) or not segment.startswith(EWF_MAGICS):
            raise DiskImageError("all supplied EWF segments must be classic EVF/LVF bytes")
        if len(segment) > MAX_INPUT:
            raise DiskImageError("EWF segment exceeds input cap")
        if len(segment) < 11:
            raise DiskImageError("EWF segment header is truncated before the segment number")
        numbers.append(struct.unpack_from("<H", segment, 9)[0])
        parsed.append(_ewf_sections(segment))
    if numbers != list(range(numbers[0], numbers[0] + len(numbers))) or numbers[0] != 1:
        raise DiskImageError("EWF segments are missing, duplicated, or out of order")
    geometry = _ewf_geometry(parsed[0])
    chunks: list[bytes] = []
    for segment, sections in zip(segments, parsed):
        chunks.extend(_ewf_segment_chunks(segment, sections))
    if len(chunks) != geometry["chunks"]:
        raise DiskImageError("EWF table chunk count disagrees with media geometry")
    expected_chunk = geometry["chunk_size"]
    raw = bytearray()
    for index, chunk in enumerate(chunks):
        # Stream acquisitions may end mid-sector: EWF's sector count is then the floor while the
        # final stored chunk retains the tail bytes.  All preceding chunks remain exactly sized.
        if (index + 1 < len(chunks) and len(chunk) != expected_chunk) or not 0 < len(chunk) <= expected_chunk:
            raise DiskImageError(f"EWF chunk {index} has an invalid logical length")
        raw.extend(chunk)
    if not geometry["size"] <= len(raw) < geometry["size"] + geometry["bytes_per_sector"]:
        raise DiskImageError("EWF reconstructed size disagrees with media geometry")
    hash_rows = [row for sections in parsed for row in sections if row["type"] in ("hash", "digest")]
    if hash_rows and len(hash_rows[0]["body"]) >= 16:
        stored = hash_rows[0]["body"][:16]
        if stored != b"\0" * 16 and hashlib.md5(raw).digest() != stored:
            raise DiskImageError("EWF media MD5 mismatch")
    return bytes(raw)


def unwrap_ewf(data: bytes) -> bytes:
    return unwrap_ewf_segments([data])


# EWF2/Ex01 (EWF format version 2) section-type constants (libewf numbering).
EWF2_SECTION_DEVICE_INFORMATION = 1
EWF2_SECTION_SECTOR_DATA = 3
EWF2_SECTION_SECTOR_TABLE = 4
EWF2_SECTION_DONE = 15
_EWF2_DESCRIPTOR_SIZE = 76


def _ewf2_file_header(data: bytes) -> dict:
    if len(data) < 30 or not data.startswith(EWF2_MAGICS):
        raise DiskImageError("unsupported or invalid EWF2/Ex01 file header")
    major, minor = data[8], data[9]
    if major != 2:
        raise DiskImageError("EWF2 file header does not declare format version 2")
    compression_method, segment_number = struct.unpack_from("<HH", data, 10)
    if compression_method not in (0, 1):
        raise DiskImageError("unsupported EWF2 compression method")
    return {"minor": minor, "compression_method": compression_method,
            "segment_number": segment_number, "set_identifier": data[14:30]}


def _ewf2_sections(data: bytes) -> list[dict]:
    """Walk the forward-linked EWF2 section descriptors (76-byte leading descriptor model).

    Each descriptor carries the numeric section type, data flags, the previous-descriptor offset, the
    section data size, the descriptor size, and an Adler32 over the descriptor.  Section data follows
    its descriptor; the next descriptor begins immediately after that data.
    """
    sections, offset, previous = [], 30, 0
    while True:
        if len(sections) >= MAX_TABLE or offset + _EWF2_DESCRIPTOR_SIZE > len(data):
            raise DiskImageError("EWF2 section chain is truncated or exceeds cap")
        descriptor = data[offset:offset + _EWF2_DESCRIPTOR_SIZE]
        if zlib.adler32(descriptor[:72]) & 0xFFFFFFFF != struct.unpack_from("<I", descriptor, 72)[0]:
            raise DiskImageError("EWF2 section-descriptor checksum mismatch")
        section_type, data_flags = struct.unpack_from("<II", descriptor, 0)
        previous_offset, data_size = struct.unpack_from("<QQ", descriptor, 8)
        descriptor_size = struct.unpack_from("<I", descriptor, 24)[0]
        if descriptor_size != _EWF2_DESCRIPTOR_SIZE or previous_offset != previous:
            raise DiskImageError("EWF2 section descriptor has an invalid size/back-link")
        body_at = offset + _EWF2_DESCRIPTOR_SIZE
        if data_size > MAX_INPUT or body_at + data_size > len(data):
            raise DiskImageError("EWF2 section data is outside the input")
        sections.append({"type": section_type, "flags": data_flags, "offset": offset,
                         "body": data[body_at:body_at + data_size]})
        if section_type == EWF2_SECTION_DONE:
            break
        previous, offset = offset, body_at + data_size
    return sections


def _ewf2_geometry(sections: list[dict]) -> dict:
    rows = [row for row in sections
            if row["type"] == EWF2_SECTION_DEVICE_INFORMATION and len(row["body"]) >= 24]
    if not rows:
        raise DiskImageError("EWF2 device-information geometry section is missing")
    chunks, sectors_per_chunk, bytes_per_sector = struct.unpack_from("<QII", rows[0]["body"], 0)
    sectors = struct.unpack_from("<Q", rows[0]["body"], 16)[0]
    if not chunks or chunks > MAX_TABLE or not sectors_per_chunk or sectors_per_chunk > 32768:
        raise DiskImageError("EWF2 chunk geometry exceeds cap")
    if bytes_per_sector not in (256, 512, 1024, 2048, 4096, 8192):
        raise DiskImageError("unsupported EWF2 sector size")
    total = sectors * bytes_per_sector
    _bounded_virtual_size(total + bytes_per_sector - 1)
    return {"chunks": chunks, "sectors_per_chunk": sectors_per_chunk,
            "bytes_per_sector": bytes_per_sector, "sectors": sectors,
            "chunk_size": sectors_per_chunk * bytes_per_sector, "size": total}


def _ewf2_segment_chunks(sections: list[dict], expected_chunk: int, compression_method: int) -> list[bytes]:
    output: list[bytes] = []
    for table in (row for row in sections if row["type"] == EWF2_SECTION_SECTOR_TABLE):
        body = table["body"]
        if len(body) < 28:
            raise DiskImageError("truncated EWF2 sector-table section")
        first_chunk, count = struct.unpack_from("<QI", body, 0)
        base_offset = struct.unpack_from("<Q", body, 12)[0]
        if zlib.adler32(body[:24]) & 0xFFFFFFFF != struct.unpack_from("<I", body, 24)[0]:
            raise DiskImageError("EWF2 table-header checksum mismatch")
        if not count or count > MAX_TABLE or 28 + count * 16 > len(body):
            raise DiskImageError("EWF2 table entry count exceeds its section")
        if first_chunk != len(output):
            raise DiskImageError("EWF2 sector tables are out of order")
        data_rows = [row for row in sections if row["type"] == EWF2_SECTION_SECTOR_DATA]
        if len(data_rows) != 1:
            raise DiskImageError("EWF2 segment needs exactly one sector-data section")
        blob = data_rows[0]["body"]
        for index in range(count):
            chunk_offset, chunk_size, chunk_flags = struct.unpack_from("<QII", body, 28 + index * 16)
            start = base_offset + chunk_offset
            if chunk_flags & ~0x3 or not chunk_size or start + chunk_size > len(blob):
                raise DiskImageError("EWF2 chunk descriptor is invalid or outside the sector data")
            packed = blob[start:start + chunk_size]
            if chunk_flags & 0x1:
                if compression_method != 1:
                    raise DiskImageError("EWF2 compressed chunk without a deflate compression method")
                try:
                    chunk = zlib.decompress(packed)
                except zlib.error as exc:
                    raise DiskImageError("EWF2 compressed chunk failed to inflate") from exc
            elif chunk_flags & 0x2:
                if len(packed) < 4:
                    raise DiskImageError("truncated EWF2 uncompressed chunk")
                chunk, stored = packed[:-4], struct.unpack_from("<I", packed, len(packed) - 4)[0]
                if zlib.adler32(chunk) & 0xFFFFFFFF != stored:
                    raise DiskImageError("EWF2 uncompressed chunk checksum mismatch")
            else:
                chunk = packed
            if not 0 < len(chunk) <= expected_chunk:
                raise DiskImageError("EWF2 chunk has an invalid logical length")
            output.append(chunk)
            if len(output) > MAX_TABLE:
                raise DiskImageError("EWF2 chunk count exceeds cap")
    if not output:
        raise DiskImageError("EWF2 has no readable chunk table")
    return output


def unwrap_ewf2_segments(segments: list[bytes] | tuple[bytes, ...]) -> bytes:
    """Reconstruct ordered EWF2/Ex01 segments (.Ex01/.Ex02/...) from their sector tables.

    This follows the published EWF version-2 model: a 30-byte file header, forward-linked section
    descriptors, a device-information geometry section, and 16-byte sector-table entries that carry an
    explicit offset, stored size and per-chunk flags into a single sector-data section.
    """
    if not segments or len(segments) > 65535:
        raise DiskImageError("EWF2 segment count is outside bounds")
    if sum(len(segment) for segment in segments if isinstance(segment, bytes)) > MAX_INPUT:
        raise DiskImageError("EWF2 segments exceed aggregate input cap")
    parsed, headers = [], []
    for segment in segments:
        if not isinstance(segment, bytes) or not segment.startswith(EWF2_MAGICS):
            raise DiskImageError("all supplied EWF2 segments must be EVF2/LEF2 bytes")
        if len(segment) > MAX_INPUT:
            raise DiskImageError("EWF2 segment exceeds input cap")
        headers.append(_ewf2_file_header(segment))
        parsed.append(_ewf2_sections(segment))
    numbers = [header["segment_number"] for header in headers]
    if numbers != list(range(1, len(numbers) + 1)):
        raise DiskImageError("EWF2 segments are missing, duplicated, or out of order")
    if len({header["compression_method"] for header in headers}) != 1:
        raise DiskImageError("EWF2 segments disagree on the compression method")
    geometry = _ewf2_geometry(parsed[0])
    chunks: list[bytes] = []
    for sections in parsed:
        chunks.extend(_ewf2_segment_chunks(sections, geometry["chunk_size"],
                                           headers[0]["compression_method"]))
    if len(chunks) != geometry["chunks"]:
        raise DiskImageError("EWF2 table chunk count disagrees with media geometry")
    raw = bytearray()
    for index, chunk in enumerate(chunks):
        if index + 1 < len(chunks) and len(chunk) != geometry["chunk_size"]:
            raise DiskImageError(f"EWF2 chunk {index} has an invalid logical length")
        raw.extend(chunk)
    if not geometry["size"] <= len(raw) < geometry["size"] + geometry["bytes_per_sector"]:
        raise DiskImageError("EWF2 reconstructed size disagrees with media geometry")
    return bytes(raw[:geometry["size"]]) if len(raw) >= geometry["size"] else bytes(raw)


def unwrap_ewf2(data: bytes) -> bytes:
    return unwrap_ewf2_segments([data])


_CRC32C_TABLE = None


def _crc32c(data: bytes) -> int:
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        table = []
        for value in range(256):
            crc = value
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            table.append(crc)
        _CRC32C_TABLE = tuple(table)
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _vhdx_checked_block(data: bytes, offset: int, length: int, signature: bytes) -> bytes | None:
    if offset < 0 or offset + length > len(data):
        return None
    block = bytearray(data[offset:offset + length])
    if block[:4] != signature:
        return None
    stored = struct.unpack_from("<I", block, 4)[0]
    block[4:8] = b"\0" * 4
    return bytes(block) if _crc32c(block) == stored else None


def _vhdx_guid(raw: bytes) -> uuid.UUID:
    if len(raw) != 16:
        raise DiskImageError("truncated VHDX GUID")
    return uuid.UUID(bytes_le=raw)


def _vhdx_parent_locator(payload: bytes) -> dict[str, str]:
    """Validate a VHDX parent-locator metadata item without following any embedded path."""
    if len(payload) < 20:
        raise DiskImageError("VHDX parent locator is truncated")
    locator_type = _vhdx_guid(payload[:16])
    reserved, count = struct.unpack_from("<HH", payload, 16)
    if reserved or not count or count > 64 or 20 + count * 12 > len(payload):
        raise DiskImageError("VHDX parent locator table is invalid")
    values: dict[str, str] = {}
    for index in range(count):
        key_offset, value_offset, key_length, value_length = struct.unpack_from(
            "<IIHH", payload, 20 + index * 12)
        if (not key_length or key_length & 1 or value_length & 1 or
                key_offset + key_length > len(payload) or value_offset + value_length > len(payload)):
            raise DiskImageError("VHDX parent locator string is outside the metadata item")
        try:
            key = payload[key_offset:key_offset + key_length].decode("utf-16le")
            value = payload[value_offset:value_offset + value_length].decode("utf-16le")
        except UnicodeDecodeError as exc:
            raise DiskImageError("VHDX parent locator is not valid UTF-16LE") from exc
        if not key or key in values:
            raise DiskImageError("VHDX parent locator keys are empty or duplicated")
        values[key] = value
    return {"locator_type": str(locator_type), **values}


def _vhdx_replay_log(data: bytes, log_offset: int, log_length: int, log_guid: bytes) -> bytes:
    """Replay a dirty VHDX log into a private copy of the image (MS-VHDX 2.4).

    Only CRC32C-valid ``loge`` entries whose LogGuid matches the active header are considered.  The
    active sequence is the contiguous run of sequence numbers ending at the highest valid one; stale
    ring-buffer entries with lower, non-contiguous sequence numbers are ignored so their writes never
    corrupt the reconstruction.  ``zero`` and ``desc`` (data) descriptors are applied in order; each
    data descriptor's 4 KiB sector is reassembled from its leading/trailing bytes.
    """
    if not log_length or log_length % 4096 or log_length > (256 << 20):
        raise DiskImageError("VHDX log region length is invalid")
    if log_offset % 4096 or log_offset < 0 or log_offset + log_length > len(data):
        raise DiskImageError("VHDX log region is outside the input")
    entries: dict[int, tuple[int, int, int]] = {}
    position = 0
    while position < log_length:
        entry_offset = log_offset + position
        if data[entry_offset:entry_offset + 4] != b"loge":
            position += 4096
            continue
        entry_length = struct.unpack_from("<I", data, entry_offset + 8)[0]
        if not entry_length or entry_length % 4096 or position + entry_length > log_length:
            position += 4096
            continue
        block = bytearray(data[entry_offset:entry_offset + entry_length])
        stored = struct.unpack_from("<I", block, 4)[0]
        block[4:8] = b"\0\0\0\0"
        if _crc32c(bytes(block)) != stored or bytes(block[32:48]) != log_guid:
            position += 4096
            continue
        sequence = struct.unpack_from("<Q", block, 16)[0]
        descriptor_count = struct.unpack_from("<I", block, 24)[0]
        if not sequence:
            raise DiskImageError("VHDX log entry has a zero sequence number")
        entries[sequence] = (entry_offset, descriptor_count, entry_length)
        position += entry_length
    if not entries:
        raise DiskImageError("VHDX log is dirty but holds no valid replayable entry")
    newest = max(entries)
    active, sequence = [], newest
    while sequence in entries:
        active.append(sequence)
        sequence -= 1
    active.reverse()
    out = bytearray(data)
    writes = 0
    for sequence in active:
        entry_offset, descriptor_count, entry_length = entries[sequence]
        if descriptor_count > (entry_length - 64) // 32:
            raise DiskImageError("VHDX log entry descriptor count exceeds its entry")
        data_cursor = entry_offset + 4096  # data sectors follow the header sector in order
        for index in range(descriptor_count):
            at = entry_offset + 64 + index * 32
            signature = data[at:at + 4]
            file_offset = struct.unpack_from("<Q", data, at + 16)[0]
            if signature == b"zero":
                zero_length = struct.unpack_from("<Q", data, at + 8)[0]
                if zero_length > MAX_RAW or file_offset + zero_length > len(out):
                    raise DiskImageError("VHDX log zero descriptor is out of bounds")
                out[file_offset:file_offset + zero_length] = b"\0" * zero_length
            elif signature == b"desc":
                trailing = data[at + 4:at + 8]
                leading = data[at + 8:at + 16]
                sector = data[data_cursor:data_cursor + 4096]
                data_cursor += 4096
                if len(sector) < 4096 or sector[:4] != b"data":
                    raise DiskImageError("VHDX log data sector is missing or mis-signatured")
                if file_offset + 4096 > len(out):
                    raise DiskImageError("VHDX log data descriptor is out of bounds")
                out[file_offset:file_offset + 4096] = leading + sector[8:4092] + trailing
                writes += 1
                if writes > MAX_TABLE:
                    raise DiskImageError("VHDX log write count exceeds cap")
            else:
                raise DiskImageError("VHDX log descriptor has an unknown signature")
    return bytes(out)


def unwrap_vhdx(data: bytes, *, parent: bytes | None = None) -> bytes:
    """Reconstruct a VHDX, replaying a dirty log first, with explicit parents and partial bitmaps."""
    if len(data) < 1 << 20 or data[:8] != VHDX_MAGIC:
        raise DiskImageError("invalid or truncated VHDX")
    headers = []
    for offset in (64 << 10, 128 << 10):
        block = _vhdx_checked_block(data, offset, 4096, b"head")
        if block is None:
            continue
        sequence = struct.unpack_from("<Q", block, 8)[0]
        version = struct.unpack_from("<H", block, 66)[0]
        if version != 1:
            continue
        headers.append((sequence, block))
    if not headers:
        raise DiskImageError("VHDX has no valid current header")
    header = max(headers, key=lambda row: row[0])[1]
    log_guid = bytes(header[48:64])
    if log_guid != b"\0" * 16:
        # A non-zero LogGuid marks the log as dirty: replay it into a private copy, then reconstruct
        # from the replayed bytes (the log may rewrite metadata, BAT and payload file offsets alike).
        log_length = struct.unpack_from("<I", header, 68)[0]
        log_offset = struct.unpack_from("<Q", header, 72)[0]
        data = _vhdx_replay_log(data, log_offset, log_length, log_guid)

    region = None
    for offset in (192 << 10, 256 << 10):
        candidate = _vhdx_checked_block(data, offset, 64 << 10, b"regi")
        if candidate is not None:
            region = candidate
            break
    if region is None:
        raise DiskImageError("VHDX has no valid region table")
    count = struct.unpack_from("<I", region, 8)[0]
    if count > 2047 or 16 + count * 32 > len(region):
        raise DiskImageError("VHDX region-entry count exceeds cap")
    regions: dict[uuid.UUID, tuple[int, int, int]] = {}
    for index in range(count):
        at = 16 + index * 32
        ident = _vhdx_guid(region[at:at + 16])
        file_offset, length, required = struct.unpack_from("<QII", region, at + 16)
        if file_offset + length > len(data):
            raise DiskImageError("VHDX region points outside the input")
        regions[ident] = (file_offset, length, required)
    if VHDX_BAT_GUID not in regions or VHDX_METADATA_GUID not in regions:
        raise DiskImageError("VHDX BAT or metadata region is missing")

    metadata_offset, metadata_length, _ = regions[VHDX_METADATA_GUID]
    metadata = data[metadata_offset:metadata_offset + metadata_length]
    if len(metadata) < 64 << 10 or metadata[:8] != b"metadata":
        raise DiskImageError("invalid VHDX metadata region")
    item_count = struct.unpack_from("<H", metadata, 10)[0]
    if item_count > 2047 or 32 + item_count * 32 > min(len(metadata), 64 << 10):
        raise DiskImageError("VHDX metadata-item count exceeds cap")
    items: dict[uuid.UUID, bytes] = {}
    for index in range(item_count):
        at = 32 + index * 32
        ident = _vhdx_guid(metadata[at:at + 16])
        rel, length, flags, _reserved = struct.unpack_from("<IIII", metadata, at + 16)
        if rel < 64 << 10 or rel + length > len(metadata):
            raise DiskImageError("VHDX metadata item points outside its region")
        items[ident] = metadata[rel:rel + length]
    try:
        params = items[VHDX_FILE_PARAMETERS_GUID]
        virtual_item = items[VHDX_VIRTUAL_SIZE_GUID]
        sector_item = items[VHDX_LOGICAL_SECTOR_GUID]
        block_size, file_flags = struct.unpack_from("<II", params)
        virtual_size = struct.unpack_from("<Q", virtual_item)[0]
        logical_sector = struct.unpack_from("<I", sector_item)[0]
    except (KeyError, struct.error) as exc:
        raise DiskImageError("VHDX required metadata is absent/truncated") from exc
    _bounded_virtual_size(virtual_size)
    if file_flags & ~3:
        raise DiskImageError("VHDX file-parameter flags are unknown")
    has_parent = bool(file_flags & 2)
    if has_parent:
        locator = items.get(VHDX_PARENT_LOCATOR_GUID)
        if locator is None:
            raise DiskImageError("differencing VHDX has no parent locator metadata")
        _vhdx_parent_locator(locator)
        if parent is None:
            raise DiskImageError("differencing VHDX needs explicitly supplied parent bytes")
    elif parent is not None:
        raise DiskImageError("VHDX parent bytes were supplied for a non-differencing image")
    if parent is not None and len(parent) < virtual_size:
        raise DiskImageError("VHDX parent image is shorter than the virtual disk")
    if block_size < 1 << 20 or block_size > 256 << 20 or block_size & (block_size - 1):
        raise DiskImageError("invalid VHDX payload-block size")
    if logical_sector not in (512, 4096):
        raise DiskImageError("invalid VHDX logical-sector size")
    chunk_ratio = ((1 << 23) * logical_sector) // block_size
    if not chunk_ratio:
        raise DiskImageError("invalid VHDX chunk ratio")
    payload_blocks = (virtual_size + block_size - 1) // block_size
    bat_offset, bat_length, _ = regions[VHDX_BAT_GUID]
    bat = data[bat_offset:bat_offset + bat_length]
    out = bytearray(parent[:virtual_size] if parent is not None else b"\0" * virtual_size)
    for block_index in range(payload_blocks):
        bat_index = block_index + block_index // chunk_ratio
        if bat_index * 8 + 8 > len(bat):
            raise DiskImageError("VHDX BAT is shorter than the virtual disk")
        entry = struct.unpack_from("<Q", bat, bat_index * 8)[0]
        state = entry & 7
        guest = block_index * block_size
        take = min(block_size, virtual_size - guest)
        if state == 0:  # NOT_PRESENT: inherit parent, or read as zero in a base image.
            continue
        if state == 1:  # UNDEFINED is not evidence of bytes in a differencing image.
            if parent is not None:
                raise DiskImageError("differencing VHDX contains an undefined payload block")
            continue
        if state in (2, 3):  # ZERO / UNMAPPED override a parent.
            out[guest:guest + take] = b"\0" * take
            continue
        if state == 7:
            if parent is None:
                raise DiskImageError("partially-present VHDX block has no explicit parent")
            host = entry & 0xFFFFFFFFFFF00000
            if host + block_size > len(data):
                raise DiskImageError("partial VHDX payload block is outside the input")
            chunk = block_index // chunk_ratio
            bitmap_index = chunk * (chunk_ratio + 1) + chunk_ratio
            if bitmap_index * 8 + 8 > len(bat):
                raise DiskImageError("VHDX sector-bitmap BAT entry is missing")
            bitmap_entry = struct.unpack_from("<Q", bat, bitmap_index * 8)[0]
            if (bitmap_entry & 7) != 6:
                raise DiskImageError("VHDX sector bitmap is not fully present")
            bitmap_host = bitmap_entry & 0xFFFFFFFFFFF00000
            bitmap_size = 1 << 20
            if bitmap_host + bitmap_size > len(data):
                raise DiskImageError("VHDX sector bitmap block is outside the input")
            bitmap = data[bitmap_host:bitmap_host + bitmap_size]
            sectors_per_block = block_size // logical_sector
            within_chunk = block_index % chunk_ratio
            for sector_index in range((take + logical_sector - 1) // logical_sector):
                bit_index = within_chunk * sectors_per_block + sector_index
                if bitmap[bit_index >> 3] & (1 << (bit_index & 7)):
                    source = host + sector_index * logical_sector
                    target = guest + sector_index * logical_sector
                    sector_take = min(logical_sector, guest + take - target)
                    out[target:target + sector_take] = data[source:source + sector_take]
            continue
        if state != 6:
            raise DiskImageError("unknown VHDX BAT payload state")
        host = entry & 0xFFFFFFFFFFF00000
        if host + block_size > len(data):
            raise DiskImageError("VHDX payload block is outside the input")
        out[guest:guest + take] = data[host:host + take]
    return bytes(out)


def unwrap(data: bytes, *, backing: bytes | None = None, aes_key: bytes | None = None,
           luks_key: bytes | None = None, vmdk_extents: dict[str, bytes] | None = None) -> UnwrapResult:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT:
        raise DiskImageError("container input outside the 512 MiB cap")
    kind = detect_container(data)
    if kind == "qcow2":
        raw = unwrap_qcow2(data, backing=backing, aes_key=aes_key, luks_key=luks_key)
    elif kind == "vmdk-sparse":
        raw = unwrap_vmdk_sparse(data)
    elif kind == "vmdk-descriptor":
        raw = unwrap_vmdk_descriptor(data, vmdk_extents or {}, parent=backing)
    elif kind == "vhd":
        raw = unwrap_vhd(data)
    elif kind == "ewf":
        try:
            raw = unwrap_ewf(data)
        except DiskImageError as exc:
            return UnwrapResult(kind, None, (f"pure-Python EWF1 decline: {exc}",),
                                ("ewfverify {in}", "ewfexport -t /out/image -f raw {in}"))
    elif kind == "ewf2":
        family = "LEF2" if data.startswith(EWF2_MAGICS[1]) else "EVF2"
        try:
            raw = unwrap_ewf2(data)
        except DiskImageError as exc:
            return UnwrapResult(kind, None, (f"{family}/Ex01 EWF2 decline: {exc}",),
                                ("ewfverify {in}", "ewfexport -t /out/image -f raw {in}"))
    elif kind == "vhdx":
        try:
            raw = unwrap_vhdx(data, parent=backing)
        except DiskImageError as exc:
            return UnwrapResult(kind, None, (f"pure-Python VHDX decline: {exc}",),
                                ("qemu-img check {in}", "qemu-img convert -O raw {in} /out/image.raw"))
    else:
        raise DiskImageError(f"unsupported container: {kind}")
    return UnwrapResult(kind, raw, ("checksums/allocation tables validated; absent clusters zero-filled",))


def parse_ntfs_data_runs(runlist: bytes) -> list[dict]:
    """Decode a non-resident NTFS runlist, including sparse runs and signed LCN deltas."""
    if not isinstance(runlist, bytes) or len(runlist) > MAX_RECORD:
        raise DiskImageError("NTFS runlist exceeds cap")
    runs, pos, lcn, vcn = [], 0, 0, 0
    while pos < len(runlist):
        header = runlist[pos]
        pos += 1
        if header == 0:
            return runs
        length_bytes, offset_bytes = header & 0xF, header >> 4
        if not 1 <= length_bytes <= 8 or offset_bytes > 8 or pos + length_bytes + offset_bytes > len(runlist):
            raise DiskImageError("invalid NTFS data-run field widths")
        count = int.from_bytes(runlist[pos:pos + length_bytes], "little")
        pos += length_bytes
        if not count:
            raise DiskImageError("zero-length NTFS data run")
        sparse = offset_bytes == 0
        if not sparse:
            delta = int.from_bytes(runlist[pos:pos + offset_bytes], "little", signed=True)
            lcn += delta
            if lcn < 0:
                raise DiskImageError("NTFS data run resolves before cluster zero")
        pos += offset_bytes
        runs.append({"vcn": vcn, "lcn": None if sparse else lcn, "clusters": count, "sparse": sparse})
        vcn += count
        if len(runs) > MAX_RUNS or vcn > MAX_RAW:
            raise DiskImageError("NTFS run count/span exceeds cap")
    raise DiskImageError("unterminated NTFS data runlist")


def extract_ntfs_runs(volume: bytes, runs, cluster_size: int, data_size: int,
                      allocated_size: int | None = None) -> dict:
    if not 512 <= cluster_size <= (2 << 20) or cluster_size & (cluster_size - 1):
        raise DiskImageError("invalid NTFS cluster size")
    if not 0 <= data_size <= MAX_RAW:
        raise DiskImageError("NTFS data size exceeds cap")
    allocation = data_size if allocated_size is None else allocated_size
    if not data_size <= allocation <= MAX_RAW:
        raise DiskImageError("NTFS allocated size exceeds cap")
    try:
        run_rows = list(itertools.islice(iter(runs), MAX_RUNS + 1))
    except (TypeError, MemoryError) as exc:
        raise DiskImageError("NTFS runs must be a bounded iterable") from exc
    if len(run_rows) > MAX_RUNS:
        raise DiskImageError("NTFS run count exceeds cap")
    out = bytearray()
    for run in run_rows:
        if not isinstance(run, dict) or "clusters" not in run:
            raise DiskImageError("NTFS run entry lacks a cluster count")
        length = int(run["clusters"]) * cluster_size
        if len(out) + length > allocation + cluster_size:
            length = max(0, allocation - len(out))
        if run.get("lcn") is None:
            out.extend(b"\0" * length)
        else:
            start = int(run["lcn"]) * cluster_size
            if start < 0 or start + length > len(volume):
                raise DiskImageError("NTFS run points outside the supplied volume")
            out.extend(volume[start:start + length])
        if len(out) >= allocation:
            break
    if len(out) < data_size:
        raise DiskImageError("NTFS runs do not cover the logical data size")
    return {"data": bytes(out[:data_size]), "slack": bytes(out[data_size:allocation]),
            "allocated": min(len(out), allocation)}


def _fix_ntfs_record(record: bytes, sector_size: int = 512) -> bytes:
    if len(record) < 48 or record[:4] != b"FILE":
        raise DiskImageError("not an NTFS FILE record")
    data = bytearray(record)
    usa_offset, usa_count = struct.unpack_from("<HH", data, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(data):
        raise DiskImageError("invalid NTFS update-sequence array")
    sequence = data[usa_offset:usa_offset + 2]
    for index in range(1, usa_count):
        end = index * sector_size - 2
        if end < 0 or end + 2 > len(data) or data[end:end + 2] != sequence:
            raise DiskImageError("NTFS update-sequence check failed")
        data[end:end + 2] = data[usa_offset + index * 2:usa_offset + index * 2 + 2]
    return bytes(data)


def ntfs_data_streams(record: bytes, volume: bytes | None = None, *, cluster_size: int = 4096,
                      sector_size: int = 512) -> list[dict]:
    fixed = _fix_ntfs_record(record, sector_size)
    attr_offset = struct.unpack_from("<H", fixed, 20)[0]
    used = struct.unpack_from("<I", fixed, 24)[0]
    if not 24 <= attr_offset < used <= len(fixed):
        raise DiskImageError("invalid NTFS attribute bounds")
    streams, pos = [], attr_offset
    while pos + 16 <= used and len(streams) < 1024:
        attr_type, length = struct.unpack_from("<II", fixed, pos)
        if attr_type == 0xFFFFFFFF:
            break
        if length < 24 or pos + length > used:
            raise DiskImageError("invalid NTFS attribute length")
        nonresident, name_len, name_offset = struct.unpack_from("<BBH", fixed, pos + 8)
        if name_len and (name_offset < 16 or name_offset + name_len * 2 > length):
            raise DiskImageError("invalid NTFS attribute name")
        if name_len:
            try:
                name = fixed[pos + name_offset:pos + name_offset + name_len * 2].decode("utf-16le")
            except UnicodeDecodeError as exc:
                raise DiskImageError("NTFS attribute name is not valid UTF-16") from exc
        else:
            name = ""
        if attr_type == 0x80:
            if not nonresident:
                value_len, value_off = struct.unpack_from("<IH", fixed, pos + 16)
                if value_off < 24 or value_off + value_len > length:
                    raise DiskImageError("resident NTFS data is outside its attribute")
                payload = fixed[pos + value_off:pos + value_off + value_len]
                slack = fixed[pos + value_off + value_len:pos + length]
                streams.append({"name": name, "resident": True, "data": payload, "slack": slack,
                                "size": value_len})
            else:
                if length < 64:
                    raise DiskImageError("non-resident NTFS attribute is truncated")
                run_off = struct.unpack_from("<H", fixed, pos + 32)[0]
                allocated, real = struct.unpack_from("<QQ", fixed, pos + 40)
                if run_off < 64 or run_off >= length:
                    raise DiskImageError("NTFS runlist offset is invalid")
                runs = parse_ntfs_data_runs(fixed[pos + run_off:pos + length])
                stream = {"name": name, "resident": False, "runs": runs, "size": real,
                          "allocated_size": allocated, "data": None, "slack": None}
                if volume is not None:
                    stream.update(extract_ntfs_runs(volume, runs, cluster_size, real, allocated))
                streams.append(stream)
        pos += length
    return streams


def ext_extent_tree(inode: bytes, filesystem: bytes | None = None, *, block_size: int = 4096) -> list[dict]:
    if not isinstance(inode, bytes) or len(inode) < 100:
        raise DiskImageError("ext inode is too short")
    if not 1024 <= block_size <= 65536 or block_size & (block_size - 1):
        raise DiskImageError("invalid ext block size")

    def node(buf: bytes, depth_left=0):
        if len(buf) < 12:
            raise DiskImageError("truncated ext extent node")
        magic, entries, maximum, depth = struct.unpack_from("<HHHH", buf, 0)
        if magic != 0xF30A or entries > maximum or entries > 340 or depth > MAX_EXT_DEPTH:
            raise DiskImageError("invalid ext extent header")
        if depth_left and depth >= depth_left:
            raise DiskImageError("ext extent depth does not decrease")
        result = []
        if depth == 0:
            if 12 + entries * 12 > len(buf):
                raise DiskImageError("truncated ext extent leaf")
            for index in range(entries):
                logical, raw_len, hi, lo = struct.unpack_from("<IHHI", buf, 12 + index * 12)
                # ext4 ee_len: values up to and including 0x8000 are initialized with that exact
                # length; only values strictly above 0x8000 are unwritten (length = ee_len - 0x8000).
                if raw_len <= 0x8000:
                    unwritten, count = False, raw_len
                else:
                    unwritten, count = True, raw_len - 0x8000
                if not count:
                    raise DiskImageError("zero-length ext extent")
                result.append({"logical": logical, "physical": (hi << 32) | lo,
                               "blocks": count, "unwritten": unwritten})
        else:
            if filesystem is None:
                raise DiskImageError("ext index node needs filesystem bytes")
            if 12 + entries * 12 > len(buf):
                raise DiskImageError("truncated ext extent index")
            for index in range(entries):
                _logical, lo, hi, _unused = struct.unpack_from("<IIHH", buf, 12 + index * 12)
                block = (hi << 32) | lo
                start = block * block_size
                if start + block_size > len(filesystem):
                    raise DiskImageError("ext extent node points outside filesystem")
                child = node(filesystem[start:start + block_size], depth)
                if len(result) + len(child) > MAX_EXTENTS:
                    raise DiskImageError("ext extent count exceeds cap")
                result.extend(child)
        return result

    extents = node(inode[40:100])
    if len(extents) > MAX_EXTENTS:
        raise DiskImageError("ext extent count exceeds cap")
    if any(a["logical"] + a["blocks"] > b["logical"] for a, b in zip(extents, extents[1:])):
        raise DiskImageError("overlapping/out-of-order ext extents")
    return extents


def ext_legacy_blocks(inode: bytes, filesystem: bytes, *, block_size: int = 4096,
                      wanted_blocks: int | None = None) -> list[int | None]:
    """Resolve ext2/3's 12 direct + single/double/triple-indirect block map."""
    if len(inode) < 100 or not 1024 <= block_size <= 65536 or block_size & (block_size - 1):
        raise DiskImageError("invalid ext legacy inode/block size")
    pointers = list(struct.unpack_from("<15I", inode, 40))
    per_block = block_size // 4
    limit = MAX_EXTENTS if wanted_blocks is None else min(MAX_EXTENTS, max(0, wanted_blocks))
    output: list[int | None] = []

    def add(value: int | None):
        if len(output) < limit:
            output.append(value)

    for pointer in pointers[:12]:
        add(pointer or None)

    def indirect(pointer: int, level: int):
        if len(output) >= limit:
            return
        if not pointer:
            # A missing indirect tree represents a sparse range.  Append only as much as requested.
            span = min(limit - len(output), per_block ** level)
            output.extend([None] * span)
            return
        start = pointer * block_size
        if start + block_size > len(filesystem):
            raise DiskImageError("ext indirect block points outside filesystem")
        values = struct.unpack_from(f"<{per_block}I", filesystem, start)
        if level == 1:
            for value in values:
                add(value or None)
                if len(output) >= limit:
                    break
        else:
            for value in values:
                indirect(value, level - 1)
                if len(output) >= limit:
                    break

    for level, pointer in enumerate(pointers[12:15], 1):
        indirect(pointer, level)
        if len(output) >= limit:
            break
    return output[:limit]


def recover_ext_inode(inode: bytes, filesystem: bytes, *, block_size: int = 4096) -> dict:
    if len(inode) < 128:
        raise DiskImageError("ext inode is too short")
    mode, size_lo, dtime, links, flags = (struct.unpack_from("<H", inode, 0)[0],
                                          struct.unpack_from("<I", inode, 4)[0],
                                          struct.unpack_from("<I", inode, 20)[0],
                                          struct.unpack_from("<H", inode, 26)[0],
                                          struct.unpack_from("<I", inode, 32)[0])
    size_hi = struct.unpack_from("<I", inode, 108)[0] if len(inode) >= 112 and mode & 0xF000 == 0x8000 else 0
    size = size_lo | (size_hi << 32)
    if size > MAX_RAW:
        raise DiskImageError("ext inode size exceeds recovery cap")
    blocks = (size + block_size - 1) // block_size
    out = bytearray(blocks * block_size)
    if flags & 0x80000:
        extents = ext_extent_tree(inode, filesystem, block_size=block_size)
        for extent in extents:
            guest = extent["logical"] * block_size
            length = extent["blocks"] * block_size
            if guest >= len(out):
                continue
            length = min(length, len(out) - guest)
            if extent["unwritten"]:
                continue
            host = extent["physical"] * block_size
            if host + length > len(filesystem):
                raise DiskImageError("ext data extent points outside filesystem")
            out[guest:guest + length] = filesystem[host:host + length]
        mapping = {"mapping": "extents", "extents": extents}
    else:
        block_map = ext_legacy_blocks(inode, filesystem, block_size=block_size, wanted_blocks=blocks)
        if len(block_map) < blocks:
            raise DiskImageError("ext legacy block map does not cover the file")
        for logical, physical in enumerate(block_map):
            if physical is None:
                continue
            host = physical * block_size
            if host + block_size > len(filesystem):
                raise DiskImageError("ext data block points outside filesystem")
            out[logical * block_size:(logical + 1) * block_size] = filesystem[host:host + block_size]
        mapping = {"mapping": "legacy", "blocks": block_map}
    allocation_end = min(len(out), blocks * block_size)
    return {"deleted": bool(dtime or links == 0), "deletion_time": dtime, "links": links,
            "size": size, "data": bytes(out[:size]), "slack": bytes(out[size:allocation_end]),
            **mapping}


def _apfs_fletcher64(block: bytes) -> int:
    if len(block) < 8 or len(block) & 3:
        raise DiskImageError("APFS object size is not a whole number of words")
    modulus = 0xFFFFFFFF
    low = high = 0
    for (word,) in struct.iter_unpack("<I", block[8:]):
        low = (low + word) % modulus
        high = (high + low) % modulus
    check_low = (modulus - ((low + high) % modulus)) % modulus
    check_high = (modulus - ((low + check_low) % modulus)) % modulus
    return check_low | (check_high << 32)


def apfs_container_info(volume: bytes) -> dict:
    """Validate and describe an APFS NX superblock at the start of a supplied container."""
    if not isinstance(volume, bytes) or len(volume) < 4096 or len(volume) > MAX_INPUT or volume[32:36] != APFS_NX_MAGIC:
        raise DiskImageError("APFS NX superblock is missing")
    block_size = struct.unpack_from("<I", volume, 36)[0]
    block_count = struct.unpack_from("<Q", volume, 40)[0]
    if block_size < 4096 or block_size > 65536 or block_size & (block_size - 1):
        raise DiskImageError("invalid APFS block size")
    if block_count == 0 or block_count > (1 << 48):
        raise DiskImageError("invalid APFS block count")
    first = volume[:block_size]
    stored = struct.unpack_from("<Q", first, 0)[0]
    if stored != _apfs_fletcher64(first):
        raise DiskImageError("APFS NX superblock checksum mismatch")
    return {"block_size": block_size, "block_count": block_count,
            "uuid": str(uuid.UUID(bytes=volume[72:88])),
            "features": struct.unpack_from("<Q", volume, 48)[0],
            "readonly_compatible_features": struct.unpack_from("<Q", volume, 56)[0],
            "incompatible_features": struct.unpack_from("<Q", volume, 64)[0]}


def _apfs_leaf_records(node: bytes, *, fixed_key_size: int | None = None,
                       fixed_value_size: int | None = None) -> list[tuple[bytes, bytes]]:
    """Return bounded key/value pairs from one checksummed APFS leaf node."""
    size = len(node)
    if size < 4096 or size > 65536 or size & (size - 1):
        raise DiskImageError("invalid APFS B-tree node size")
    if struct.unpack_from("<Q", node, 0)[0] != _apfs_fletcher64(node):
        raise DiskImageError("APFS B-tree node checksum mismatch")
    flags, level, count = struct.unpack_from("<HHI", node, 32)
    if level or not (flags & 0x0002):
        return []
    fixed = bool(flags & 0x0004)
    if fixed != (fixed_key_size is not None and fixed_value_size is not None):
        return []
    table_off, table_len = struct.unpack_from("<HH", node, 40)
    table_start = 56 + table_off
    stride = 4 if fixed else 8
    if count > 8192 or table_len < count * stride or table_start + table_len > size:
        raise DiskImageError("invalid APFS B-tree table of contents")
    key_base = table_start + table_len
    value_end = size - (40 if flags & 0x0001 else 0)
    records = []
    for index in range(count):
        at = table_start + index * stride
        if fixed:
            key_off, value_off = struct.unpack_from("<HH", node, at)
            key_len, value_len = fixed_key_size or 0, fixed_value_size or 0
        else:
            key_off, key_len, value_off, value_len = struct.unpack_from("<HHHH", node, at)
        key_at = key_base + key_off
        value_at = value_end - value_off
        if (not key_len or not value_len or key_at < key_base or key_at + key_len > value_end or
                value_at < key_base or value_at + value_len > value_end):
            raise DiskImageError("APFS B-tree key/value points outside its data area")
        records.append((node[key_at:key_at + key_len], node[value_at:value_at + value_len]))
    return records


def apfs_omap_records(volume: bytes) -> list[dict]:
    """Scan checked OMAP leaves and return object-version to physical-address mappings."""
    info = apfs_container_info(volume)
    block_size = info["block_size"]
    records = []
    for offset in range(0, len(volume) - block_size + 1, block_size):
        node = volume[offset:offset + block_size]
        # OMAP tree nodes are generic B-tree objects (type 3) with OMAP subtype (11).
        if (struct.unpack_from("<I", node, 24)[0] & 0xFFFF) != 3 or (struct.unpack_from("<I", node, 28)[0] & 0xFFFF) != 11:
            continue
        try:
            pairs = _apfs_leaf_records(node, fixed_key_size=16, fixed_value_size=16)
        except DiskImageError:
            continue
        for key, value in pairs:
            oid, xid = struct.unpack("<QQ", key)
            flags, size, physical = struct.unpack("<IIQ", value)
            if not oid or not xid or not size or size > block_size:
                continue
            if not (flags & 1) and (physical >= info["block_count"] or physical * block_size + size > len(volume)):
                continue
            records.append({"oid": oid, "xid": xid, "flags": flags, "size": size,
                            "physical_block": physical, "node_offset": offset})
            if len(records) > MAX_EXTENTS:
                raise DiskImageError("APFS OMAP record count exceeds cap")
    return records


def apfs_resolve_omap(volume: bytes, oid: int, *, xid: int | None = None) -> dict:
    """Resolve an OID at a checkpoint, declining deleted or ambiguous newest mappings."""
    if not 0 < oid < 1 << 64 or xid is not None and not 0 < xid < 1 << 64:
        raise DiskImageError("APFS OMAP lookup key is outside bounds")
    candidates = [row for row in apfs_omap_records(volume)
                  if row["oid"] == oid and (xid is None or row["xid"] <= xid)]
    if not candidates:
        raise DiskImageError("APFS OMAP object has no mapping at the requested checkpoint")
    newest = max(row["xid"] for row in candidates)
    rows = [row for row in candidates if row["xid"] == newest]
    signatures = {(row["flags"], row["size"], row["physical_block"]) for row in rows}
    if len(signatures) != 1:
        raise DiskImageError("APFS OMAP newest mapping is ambiguous")
    row = rows[0]
    if row["flags"] & 1:
        raise DiskImageError("APFS OMAP object is deleted at the requested checkpoint")
    return row


def apfs_catalog_records(volume: bytes) -> list[dict]:
    """Decode checked filesystem-tree inode, directory, and embedded-xattr catalog records."""
    info = apfs_container_info(volume)
    block_size = info["block_size"]
    records = []
    for offset in range(0, len(volume) - block_size + 1, block_size):
        node = volume[offset:offset + block_size]
        if (struct.unpack_from("<I", node, 24)[0] & 0xFFFF) != 3 or (struct.unpack_from("<I", node, 28)[0] & 0xFFFF) != 14:
            continue
        try:
            pairs = _apfs_leaf_records(node)
        except DiskImageError:
            continue
        xid = struct.unpack_from("<Q", node, 16)[0]
        for item, (key, value) in enumerate(pairs):
            if len(key) < 8:
                continue
            raw_id = struct.unpack_from("<Q", key)[0]
            record_type, object_id = raw_id >> 60, raw_id & 0x0FFFFFFFFFFFFFFF
            row = {"record_type": record_type, "object_id": object_id, "xid": xid,
                   "node_offset": offset, "item": item}
            if record_type == 3 and len(value) >= 92:  # INODE
                row.update({
                    "kind": "inode", "parent_id": struct.unpack_from("<Q", value, 0)[0],
                    "private_id": struct.unpack_from("<Q", value, 8)[0],
                    "internal_flags": struct.unpack_from("<Q", value, 48)[0],
                    "default_protection_class": struct.unpack_from("<I", value, 60)[0],
                    "bsd_flags": struct.unpack_from("<I", value, 68)[0],
                    "owner": struct.unpack_from("<I", value, 72)[0],
                    "group": struct.unpack_from("<I", value, 76)[0],
                    "mode": struct.unpack_from("<H", value, 80)[0],
                    "uncompressed_size": struct.unpack_from("<Q", value, 84)[0],
                })
            elif record_type == 9 and len(key) >= 12 and len(value) >= 18:  # DREC
                name_length = struct.unpack_from("<I", key, 8)[0] & 0x3FF
                if not name_length or 12 + name_length > len(key):
                    continue
                name_bytes = key[12:12 + name_length].rstrip(b"\0")
                row.update({"kind": "directory-record", "name": name_bytes.decode("utf-8", "replace"),
                            "file_id": struct.unpack_from("<Q", value, 0)[0],
                            "date_added": struct.unpack_from("<Q", value, 8)[0],
                            "flags": struct.unpack_from("<H", value, 16)[0]})
            elif record_type == 4 and len(key) >= 10 and len(value) >= 4:  # XATTR
                name_length = struct.unpack_from("<H", key, 8)[0]
                if not name_length or 10 + name_length > len(key):
                    continue
                flags, data_length = struct.unpack_from("<HH", value, 0)
                if data_length > len(value) - 4:
                    continue
                row.update({"kind": "xattr", "name": key[10:10 + name_length].rstrip(b"\0").decode("utf-8", "replace"),
                            "flags": flags, "data_length": data_length})
                if flags & 2:  # XATTR_DATA_EMBEDDED
                    row["embedded_hex"] = value[4:4 + data_length].hex()
            else:
                continue
            records.append(row)
            if len(records) > MAX_EXTENTS:
                raise DiskImageError("APFS catalog record count exceeds cap")
    return records


def _apfs_decmpfs_inline(payload: bytes) -> bytes:
    """Decode a bounded inline ``com.apple.decmpfs`` value (type 1 uncompressed, type 3 zlib).

    Resource-fork (types 4/8) and LZVN/LZFSE (types 7/8/10/11) layouts need a separate fork extent or
    an external codec; they decline loudly with their type rather than return partial bytes.
    """
    if len(payload) < 16 or payload[:4] != b"fpmc":
        raise DiskImageError("APFS decmpfs xattr header is invalid")
    compression_type = struct.unpack_from("<I", payload, 4)[0]
    expected = struct.unpack_from("<Q", payload, 8)[0]
    _bounded_virtual_size(expected)
    if compression_type == 1:  # uncompressed, stored inline in the xattr
        decoded = payload[16:]
        if len(decoded) != expected:
            raise DiskImageError("APFS uncompressed decmpfs size disagrees with its header")
        return decoded
    if compression_type != 3:
        raise DiskImageError(
            f"APFS decmpfs type {compression_type} needs a resource-fork/LZVN/LZFSE decoder")
    packed = payload[16:]
    if packed[:1] == b"\x0f":
        decoded = packed[1:]
    else:
        try:
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(packed, expected + 1) + decoder.flush()
        except zlib.error as exc:
            raise DiskImageError("APFS inline decmpfs zlib stream did not decompress") from exc
        if not decoder.eof or decoder.unused_data:
            raise DiskImageError("APFS inline decmpfs stream is truncated or has trailing bytes")
    if len(decoded) != expected:
        raise DiskImageError("APFS inline decmpfs size disagrees with its header")
    return decoded


def recover_apfs_catalog_file(volume: bytes, file_id: int) -> dict:
    """Resolve a catalog inode (including shared clone extents) and recover verified bytes."""
    catalog = apfs_catalog_records(volume)
    inodes = [row for row in catalog if row.get("kind") == "inode" and row["object_id"] == file_id]
    if not inodes:
        raise DiskImageError("APFS catalog inode was not found")
    newest = max(row["xid"] for row in inodes)
    rows = [row for row in inodes if row["xid"] == newest]
    signatures = {(row["private_id"], row["uncompressed_size"], row["internal_flags"]) for row in rows}
    if len(signatures) != 1:
        raise DiskImageError("APFS newest catalog inode is ambiguous")
    inode = rows[0]
    compressed = [row for row in catalog if row.get("kind") == "xattr" and
                  row["object_id"] == file_id and row["name"] == "com.apple.decmpfs" and
                  "embedded_hex" in row]
    if compressed:
        newest_xid = max(row["xid"] for row in compressed)
        payloads = {row["embedded_hex"] for row in compressed if row["xid"] == newest_xid}
        if len(payloads) != 1:
            raise DiskImageError("APFS newest decmpfs xattr is ambiguous")
        data = _apfs_decmpfs_inline(bytes.fromhex(payloads.pop()))
        if len(data) != inode["uncompressed_size"]:
            raise DiskImageError("APFS inode and decmpfs sizes disagree")
        return {"file_id": file_id, "private_id": inode["private_id"], "size": len(data),
                "data": data, "compressed": True, "inode": inode}
    recovered = recover_apfs_file(volume, inode["private_id"], inode["uncompressed_size"])
    return {**recovered, "file_id": file_id, "private_id": inode["private_id"],
            "compressed": False, "inode": inode}


def apfs_file_extent_records(node: bytes, *, block_size: int | None = None) -> list[dict]:
    """Decode variable-key APFS file-extent records from one checksummed B-tree leaf.

    Fixed-key nodes are deliberately excluded: catalog/file-extent trees use variable keys and a
    guessed fixed layout is more dangerous than a decline during evidence recovery.
    """
    size = block_size or len(node)
    if size != len(node) or size < 4096 or size > 65536 or size & (size - 1):
        raise DiskImageError("invalid APFS B-tree node size")
    if struct.unpack_from("<Q", node, 0)[0] != _apfs_fletcher64(node):
        raise DiskImageError("APFS B-tree node checksum mismatch")
    flags, level, count = struct.unpack_from("<HHI", node, 32)
    if level != 0 or not (flags & 0x0002) or flags & 0x0004:
        return []
    table_off, table_len = struct.unpack_from("<HH", node, 40)
    table_start = 56 + table_off
    if count > 8192 or table_len < count * 8 or table_start + table_len > size:
        raise DiskImageError("invalid APFS B-tree table of contents")
    key_base = table_start + table_len
    records = []
    for index in range(count):
        key_off, key_len, value_off, value_len = struct.unpack_from("<HHHH", node, table_start + index * 8)
        if key_len < 16 or value_len < 24 or key_base + key_off + key_len > size:
            continue
        key = node[key_base + key_off:key_base + key_off + key_len]
        raw_id, logical = struct.unpack_from("<QQ", key)
        if raw_id >> 60 != 8:  # APFS_TYPE_FILE_EXTENT
            continue
        # APFS B-tree values are stored backward from the end of the node's data area. A ROOT node
        # (flag 0x0001) carries a 40-byte btree_info_fixed trailer at the very end, so the value area
        # ends 40 bytes earlier. Compute the single correct offset rather than guessing two (a guess
        # could mis-attribute another record's bytes); decline the record if it is implausible.
        value_end = size - (40 if flags & 0x0001 else 0)
        start = value_end - value_off
        value = None
        if 0 <= start <= size - value_len:
            candidate = node[start:start + value_len]
            length_flags, physical, crypto_id = struct.unpack_from("<QQQ", candidate)
            length = length_flags & 0x00FFFFFFFFFFFFFF
            if length and physical and logical + length <= MAX_RAW:
                value = (length_flags, physical, crypto_id, length)
        if value is None:
            continue
        length_flags, physical, crypto_id, length = value
        records.append({"object_id": raw_id & 0x0FFFFFFFFFFFFFFF, "logical": logical,
                        "length": length, "flags": length_flags >> 56,
                        "physical_block": physical, "crypto_id": crypto_id,
                        "node_oid": struct.unpack_from("<Q", node, 8)[0], "item": index})
    return records


def recover_apfs_file(volume: bytes, object_id: int, size: int) -> dict:
    """Recover an unencrypted APFS file whose stale leaf extent records remain checksummed."""
    info = apfs_container_info(volume)
    block_size = info["block_size"]
    if not 0 <= size <= MAX_RAW or not 0 < object_id < 1 << 60:
        raise DiskImageError("APFS file id/size is outside bounds")
    records = []
    for offset in range(0, len(volume) - block_size + 1, block_size):
        node = volume[offset:offset + block_size]
        if len(records) > MAX_EXTENTS:
            raise DiskImageError("APFS extent count exceeds cap")
        try:
            records.extend(row for row in apfs_file_extent_records(node, block_size=block_size)
                           if row["object_id"] == object_id)
        except DiskImageError:
            continue
    # Checkpoint remnants can duplicate the same logical record.  Prefer the highest object/xid
    # tuple, but require duplicate locations to agree on bytes before accepting the reconstruction.
    grouped: dict[int, list[dict]] = {}
    for row in records:
        grouped.setdefault(row["logical"], []).append(row)
    chosen = []
    for logical, rows in grouped.items():
        signatures = {(row["length"], row["physical_block"], row["flags"]) for row in rows}
        if len(signatures) != 1:
            raise DiskImageError(f"ambiguous APFS checkpoint extents at logical offset {logical}")
        chosen.append(rows[0])
    chosen.sort(key=lambda row: row["logical"])
    out = bytearray(size)
    cursor = 0
    for row in chosen:
        if row["logical"] != cursor or row["flags"] or row["crypto_id"]:
            raise DiskImageError("APFS extents are gapped, overlapping, encoded, or encrypted")
        take = min(row["length"], size - cursor)
        host = row["physical_block"] * block_size
        if host + take > len(volume):
            raise DiskImageError("APFS extent points outside the supplied container")
        out[cursor:cursor + take] = volume[host:host + take]
        cursor += take
        if cursor == size:
            break
    if cursor != size:
        raise DiskImageError("APFS stale extents do not cover the requested file size")
    return {"object_id": object_id, "size": size, "data": bytes(out), "extents": chosen,
            "container": info}


def btrfs_superblock_info(volume: bytes) -> dict:
    if not isinstance(volume, bytes) or len(volume) < 0x10000 + 4096 or len(volume) > MAX_INPUT:
        raise DiskImageError("btrfs image is too short for its primary superblock")
    sb = volume[0x10000:0x10000 + 4096]
    if sb[0x40:0x48] != BTRFS_MAGIC:
        raise DiskImageError("btrfs superblock magic is missing")
    total_bytes = struct.unpack_from("<Q", sb, 0x70)[0]
    sector_size, node_size, leaf_size = struct.unpack_from("<III", sb, 0x90)
    if sector_size < 4096 or sector_size > 65536 or sector_size & (sector_size - 1):
        raise DiskImageError("invalid btrfs sector size")
    if node_size < sector_size or node_size > 65536 or node_size & (node_size - 1) or leaf_size != node_size:
        raise DiskImageError("unsupported btrfs node/leaf size")
    return {"fsid": sb[0x20:0x30], "total_bytes": total_bytes, "sector_size": sector_size,
            "node_size": node_size, "leaf_size": leaf_size,
            "generation": struct.unpack_from("<Q", sb, 0x48)[0]}


def _btrfs_item_base(node: bytes, count: int, node_size: int) -> int:
    """Resolve the byte that a leaf item's ``offset`` field is measured from.

    On-disk Btrfs stores ``btrfs_item.offset`` relative to the end of the 101-byte leaf
    header, and item data is packed backward from the leaf end, so the top item satisfies
    ``offset + size == node_size - 101``. When that backward-packing invariant holds the
    offsets are relative (base 101); otherwise they are already absolute node offsets.
    """
    ends = []
    for index in range(count):
        at = 101 + index * 25
        data_offset, data_size = struct.unpack_from("<II", node, at + 17)
        ends.append(data_offset + data_size)
    if ends and max(ends) == node_size - 101:
        return 101
    return 0


def btrfs_extent_records(volume: bytes) -> list[dict]:
    """Scan validated-fsid btrfs leaves for EXTENT_DATA_KEY records (type 108)."""
    info = btrfs_superblock_info(volume)
    node_size, fsid = info["node_size"], info["fsid"]
    records = []
    for base in range(0, len(volume) - node_size + 1, node_size):
        node = volume[base:base + node_size]
        if node[32:48] != fsid or node[100] != 0:
            continue
        count = struct.unpack_from("<I", node, 96)[0]
        if count > (node_size - 101) // 25:
            continue
        item_base = _btrfs_item_base(node, count, node_size)
        for index in range(count):
            at = 101 + index * 25
            object_id = struct.unpack_from("<Q", node, at)[0]
            key_type = node[at + 8]
            file_offset = struct.unpack_from("<Q", node, at + 9)[0]
            data_offset, data_size = struct.unpack_from("<II", node, at + 17)
            item_pos = item_base + data_offset
            if key_type != 108 or data_size < 21 or item_pos < 101 or item_pos + data_size > node_size:
                continue
            item = node[item_pos:item_pos + data_size]
            generation, ram_bytes = struct.unpack_from("<QQ", item, 0)
            compression, encryption, other, extent_type = struct.unpack_from("<BBHB", item, 16)
            row = {"object_id": object_id, "file_offset": file_offset, "generation": generation,
                   "ram_bytes": ram_bytes, "compression": compression, "encryption": encryption,
                   "other_encoding": other, "extent_type": extent_type, "leaf": base, "item": index}
            if extent_type == 0:
                row["inline"] = item[21:]
            elif extent_type in (1, 2) and len(item) >= 53:
                (row["disk_bytenr"], row["disk_num_bytes"], row["extent_offset"],
                 row["num_bytes"]) = struct.unpack_from("<QQQQ", item, 21)
            else:
                continue
            records.append(row)
            if len(records) > MAX_EXTENTS:
                raise DiskImageError("btrfs extent count exceeds cap")
    return records


def btrfs_chunk_map(volume: bytes) -> list[tuple[int, int, int]]:
    """Scan btrfs leaves for CHUNK_ITEM records (key type 228) and return single-device
    ``(logical_start, length, physical_offset)`` mappings. Multi-stripe (RAID/multi-device) chunks
    are skipped: a single raw image cannot prove their physical bytes.
    """
    info = btrfs_superblock_info(volume)
    node_size, fsid = info["node_size"], info["fsid"]
    chunks: list[tuple[int, int, int]] = []
    for base in range(0, len(volume) - node_size + 1, node_size):
        node = volume[base:base + node_size]
        if node[32:48] != fsid or node[100] != 0:
            continue
        count = struct.unpack_from("<I", node, 96)[0]
        if count > (node_size - 101) // 25:
            continue
        item_base = _btrfs_item_base(node, count, node_size)
        for index in range(count):
            at = 101 + index * 25
            key_type = node[at + 8]
            logical = struct.unpack_from("<Q", node, at + 9)[0]
            data_offset, data_size = struct.unpack_from("<II", node, at + 17)
            item_pos = item_base + data_offset
            if key_type != 228 or data_size < 48 or item_pos < 101 or item_pos + data_size > node_size:
                continue
            item = node[item_pos:item_pos + data_size]
            length = struct.unpack_from("<Q", item, 0)[0]
            num_stripes = struct.unpack_from("<H", item, 44)[0]
            if num_stripes != 1 or 48 + 32 > data_size:
                continue  # multi-device/RAID chunk — not reconstructable from one image; skip
            physical = struct.unpack_from("<Q", item, 48 + 8)[0]  # stripe[0].offset
            if length and 0 < length <= MAX_RAW:
                chunks.append((logical, length, physical))
    return chunks


def _btrfs_logical_to_physical(chunks: list[tuple[int, int, int]], logical: int, length: int) -> int:
    """Translate a btrfs logical byte range to a physical offset, or raise if unmapped/split."""
    for chunk_logical, chunk_length, physical in chunks:
        if chunk_logical <= logical and logical + length <= chunk_logical + chunk_length:
            return physical + (logical - chunk_logical)
    raise DiskImageError("btrfs extent logical address is not covered by a single-device chunk map")


def _lzo1x_decompress(packed: bytes, expected: int) -> bytes:
    """Call a local liblzo2 decoder with fixed output bounds; no subprocess or path lookup occurs."""
    if not 0 <= expected <= MAX_RAW:
        raise DiskImageError("LZO output size exceeds reconstruction cap")
    names = [ctypes.util.find_library("lzo2"), "liblzo2.so.2", "liblzo2.so",
             "/opt/homebrew/opt/lzo/lib/liblzo2.dylib",
             "/usr/local/opt/lzo/lib/liblzo2.dylib"]
    library = None
    for name in names:
        if not name:
            continue
        try:
            library = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if library is None:
        raise DiskImageError("btrfs LZO extent needs a local liblzo2 codec")
    function = library.lzo1x_decompress_safe
    function.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p)
    function.restype = ctypes.c_int
    source = ctypes.create_string_buffer(packed, len(packed))
    destination = ctypes.create_string_buffer(max(1, expected))
    destination_size = ctypes.c_size_t(expected)
    result = function(source, len(packed), destination, ctypes.byref(destination_size), None)
    if result != 0 or destination_size.value != expected:
        raise DiskImageError("btrfs LZO chunk did not decompress to its declared size")
    return destination.raw[:expected]


def _btrfs_lzo_decompress(packed: bytes, expected: int, sector_size: int = 4096) -> bytes:
    """Decode btrfs's length-prefixed sequence of independently compressed LZO1X pages."""
    if len(packed) < 8 or expected < 0 or expected > MAX_RAW:
        raise DiskImageError("btrfs LZO extent header is truncated or oversized")
    total = struct.unpack_from("<I", packed, 0)[0]
    if total < 8 or total > len(packed):
        raise DiskImageError("btrfs LZO total compressed length is invalid")
    position = 4
    output = bytearray()
    while position < total and len(output) < expected:
        page_end = ((position // sector_size) + 1) * sector_size
        if position + 4 > page_end:
            position = page_end
        if position + 4 > total:
            raise DiskImageError("btrfs LZO chunk header is truncated")
        compressed_size = struct.unpack_from("<I", packed, position)[0]
        position += 4
        wanted = min(4096, expected - len(output))
        if not compressed_size or compressed_size > (4096 + 4096 // 16 + 64 + 3):
            raise DiskImageError("btrfs LZO chunk length is invalid")
        if position + compressed_size > total:
            raise DiskImageError("btrfs LZO chunk exceeds its extent")
        output.extend(_lzo1x_decompress(packed[position:position + compressed_size], wanted))
        position += compressed_size
    if len(output) != expected or position != total:
        raise DiskImageError("btrfs LZO extent size/count disagrees with its header")
    return bytes(output)


def _zstd_decompress_exact(packed: bytes, expected: int, label: str) -> bytes:
    if not 0 <= expected <= MAX_RAW:
        raise DiskImageError(f"{label} output exceeds reconstruction cap")
    try:
        import zstandard
        decoder = zstandard.ZstdDecompressor().decompressobj()
        decoded = decoder.decompress(packed)
        if not decoder.eof or any(decoder.unused_data):
            raise DiskImageError(f"{label} has a truncated frame or nonzero trailing bytes")
    except ImportError as exc:
        raise DiskImageError(f"{label} needs the offline zstandard codec") from exc
    except zstandard.ZstdError as exc:
        raise DiskImageError(f"{label} did not decompress") from exc
    if len(decoded) != expected:
        raise DiskImageError(f"{label} size disagrees with its metadata")
    return decoded


def recover_btrfs_file(volume: bytes, object_id: int, size: int) -> dict:
    if not 0 < object_id < 1 << 64 or not 0 <= size <= MAX_RAW:
        raise DiskImageError("btrfs file id/size is outside bounds")
    chunk_map = btrfs_chunk_map(volume)
    rows = [row for row in btrfs_extent_records(volume) if row["object_id"] == object_id]
    grouped: dict[int, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["file_offset"], []).append(row)
    chosen = []
    for file_offset, versions in grouped.items():
        newest_generation = max(row["generation"] for row in versions)
        newest = [row for row in versions if row["generation"] == newest_generation]
        signatures = {(row.get("disk_bytenr"), row.get("disk_num_bytes"), row.get("extent_offset"),
                       row.get("num_bytes"), row.get("inline"), row["compression"], row["encryption"])
                      for row in newest}
        if len(signatures) != 1:
            raise DiskImageError(f"ambiguous btrfs extents at file offset {file_offset}")
        chosen.append(newest[0])
    chosen.sort(key=lambda row: row["file_offset"])
    output = bytearray(size)
    cursor = 0
    for row in chosen:
        if row["file_offset"] != cursor or row["encryption"] or row["other_encoding"]:
            raise DiskImageError("btrfs extents are gapped/overlapping or use unsupported encoding")
        if row["extent_type"] == 2:
            raise DiskImageError("btrfs preallocation does not prove recovered file bytes")
        if row["extent_type"] == 0:
            packed = row["inline"]
            wanted = min(row["ram_bytes"], size - cursor)
        else:
            logical, length = row["disk_bytenr"], row["disk_num_bytes"]
            if not logical:
                raise DiskImageError("btrfs extent has a null disk_bytenr")
            # disk_bytenr is a LOGICAL address: translate it through the chunk tree to a physical
            # offset. Treating it as a raw offset (the former bug) returns another region's bytes as a
            # confident reconstruction. Unmapped/RAID extents raise rather than emit wrong bytes.
            start = _btrfs_logical_to_physical(chunk_map, logical, length)
            if start + length > len(volume):
                raise DiskImageError("btrfs extent points outside the supplied image")
            packed = volume[start:start + length]
            wanted = min(row["num_bytes"], size - cursor)
        if row["compression"] == 0:
            decoded = packed
        elif row["compression"] == 1:
            try:
                decoder = zlib.decompressobj()
                decoded = decoder.decompress(packed, row["ram_bytes"] + 1) + decoder.flush()
            except zlib.error as exc:
                raise DiskImageError("btrfs zlib extent did not decompress") from exc
            if (not decoder.eof or any(decoder.unused_data) or
                    len(decoded) != row["ram_bytes"]):
                raise DiskImageError("btrfs zlib extent size/trailer disagrees with metadata")
        elif row["compression"] == 2:
            decoded = _btrfs_lzo_decompress(packed, row["ram_bytes"],
                                             btrfs_superblock_info(volume)["sector_size"])
        elif row["compression"] == 3:
            decoded = _zstd_decompress_exact(packed, row["ram_bytes"], "btrfs Zstd extent")
        else:
            raise DiskImageError("btrfs extent uses an unknown compression type")
        offset = row.get("extent_offset", 0)
        if offset + wanted > len(decoded):
            raise DiskImageError("btrfs decoded extent is shorter than declared")
        output[cursor:cursor + wanted] = decoded[offset:offset + wanted]
        cursor += wanted
        if cursor == size:
            break
    if cursor != size:
        raise DiskImageError("btrfs stale extents do not cover the requested file size")
    return {"object_id": object_id, "size": size, "data": bytes(output), "extents": chosen}


def _read(path: str, cap: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise DiskImageError("input exceeds size cap")
    return data


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="disk_images.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("input")
    extract = sub.add_parser("unwrap")
    extract.add_argument("input")
    extract.add_argument("--output")
    extract.add_argument("--backing", help="explicit raw backing/parent image")
    extract.add_argument("--backing-layer", action="append", default=[],
                         help="QCOW2 nearest-parent layer (repeat toward the farthest/raw base)")
    extract.add_argument("--aes-key-hex", help="exact 16-byte legacy QCOW2 AES key")
    extract.add_argument("--luks-key-hex",
                         help="QCOW2 LUKS AES-XTS master key (32 or 64 bytes, hex)")
    extract.add_argument("--extent", action="append", default=[], metavar="NAME=PATH",
                         help="explicit VMDK descriptor extent (repeatable)")
    extract.add_argument("--segment", action="append", default=[],
                         help="additional ordered EWF1/EWF2 segment (E02/Ex02, ...)")
    runs = sub.add_parser("ntfs-runs")
    runs.add_argument("runlist", help="hex runlist")
    ntfs = sub.add_parser("ntfs-record")
    ntfs.add_argument("record")
    ntfs.add_argument("--volume")
    ntfs.add_argument("--cluster-size", type=int, default=4096)
    ext = sub.add_parser("ext-inode")
    ext.add_argument("inode")
    ext.add_argument("filesystem")
    ext.add_argument("--block-size", type=int, default=4096)
    apfs_info = sub.add_parser("apfs-info")
    apfs_info.add_argument("filesystem")
    apfs_omap = sub.add_parser("apfs-omap")
    apfs_omap.add_argument("filesystem")
    apfs_omap.add_argument("--oid", type=lambda value: int(value, 0))
    apfs_omap.add_argument("--xid", type=lambda value: int(value, 0))
    apfs_catalog = sub.add_parser("apfs-catalog")
    apfs_catalog.add_argument("filesystem")
    apfs_catalog.add_argument("--file-id", type=lambda value: int(value, 0))
    apfs_catalog.add_argument("--output")
    apfs_recover = sub.add_parser("apfs-recover")
    apfs_recover.add_argument("filesystem")
    apfs_recover.add_argument("object_id", type=lambda value: int(value, 0))
    apfs_recover.add_argument("size", type=lambda value: int(value, 0))
    apfs_recover.add_argument("--output")
    btrfs_info = sub.add_parser("btrfs-info")
    btrfs_info.add_argument("filesystem")
    btrfs_recover = sub.add_parser("btrfs-recover")
    btrfs_recover.add_argument("filesystem")
    btrfs_recover.add_argument("object_id", type=lambda value: int(value, 0))
    btrfs_recover.add_argument("size", type=lambda value: int(value, 0))
    btrfs_recover.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    for command in (inspect, extract, runs, ntfs, ext, apfs_info, apfs_omap, apfs_catalog,
                    apfs_recover, btrfs_info, btrfs_recover):
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if args.operation == "inspect":
            data = _read(args.input)
            result = {"format": detect_container(data), "size": len(data)}
        elif args.operation == "unwrap":
            data = _read(args.input)
            if args.segment:
                container = detect_container(data)
                segments = [data] + [_read(path) for path in args.segment]
                if container == "ewf":
                    raw = unwrap_ewf_segments(segments)
                    unwrapped = UnwrapResult("ewf", raw, ("all EWF1 segment checksums validated",))
                elif container == "ewf2":
                    raw = unwrap_ewf2_segments(segments)
                    unwrapped = UnwrapResult("ewf2", raw, ("all EWF2 segment checksums validated",))
                else:
                    raise DiskImageError("--segment is only valid for classic EWF1 or EWF2")
            else:
                extent_bytes = {}
                for spec in args.extent:
                    if "=" not in spec:
                        raise DiskImageError("--extent must be NAME=PATH")
                    name, path = spec.split("=", 1)
                    if not name or name in extent_bytes:
                        raise DiskImageError("VMDK extent names must be nonempty and unique")
                    extent_bytes[name] = _read(path)
                key = bytes.fromhex(args.aes_key_hex) if args.aes_key_hex else None
                luks = bytes.fromhex(args.luks_key_hex) if args.luks_key_hex else None
                if args.backing_layer:
                    if args.backing or extent_bytes or detect_container(data) != "qcow2":
                        raise DiskImageError("--backing-layer is exclusive to QCOW2 and --backing/--extent")
                    raw = unwrap_qcow2_chain(data, [_read(path) for path in args.backing_layer],
                                             aes_keys=[key] + [None] * len(args.backing_layer))
                    unwrapped = UnwrapResult("qcow2", raw,
                                             ("explicit recursive backing chain reconstructed",))
                else:
                    unwrapped = unwrap(data, backing=_read(args.backing) if args.backing else None,
                                       aes_key=key, luks_key=luks, vmdk_extents=extent_bytes)
            result = unwrapped.report()
            if args.output:
                if unwrapped.raw is None:
                    raise DiskImageError("format needs the reported sandbox command plan")
                output = Path(args.output)
                if output.exists():
                    raise DiskImageError("output already exists")
                output.write_bytes(unwrapped.raw)
                result["output"] = str(output)
        elif args.operation == "ntfs-runs":
            result = {"runs": parse_ntfs_data_runs(bytes.fromhex(args.runlist))}
        elif args.operation == "ntfs-record":
            volume = _read(args.volume) if args.volume else None
            result = {"streams": ntfs_data_streams(_read(args.record, MAX_RECORD), volume,
                                                     cluster_size=args.cluster_size)}
        elif args.operation == "ext-inode":
            result = recover_ext_inode(_read(args.inode, MAX_RECORD), _read(args.filesystem),
                                       block_size=args.block_size)
        elif args.operation == "apfs-info":
            result = apfs_container_info(_read(args.filesystem))
        elif args.operation == "apfs-omap":
            filesystem = _read(args.filesystem)
            result = (apfs_resolve_omap(filesystem, args.oid, xid=args.xid) if args.oid is not None
                      else {"records": apfs_omap_records(filesystem)})
        elif args.operation == "apfs-catalog":
            filesystem = _read(args.filesystem)
            if args.file_id is None:
                result = {"records": apfs_catalog_records(filesystem)}
            else:
                result = recover_apfs_catalog_file(filesystem, args.file_id)
                if args.output:
                    output = Path(args.output)
                    if output.exists():
                        raise DiskImageError("output already exists")
                    output.write_bytes(result["data"])
                    result = {key: value for key, value in result.items() if key != "data"}
                    result["output"] = str(output)
        elif args.operation == "apfs-recover":
            result = recover_apfs_file(_read(args.filesystem), args.object_id, args.size)
            if args.output:
                output = Path(args.output)
                if output.exists():
                    raise DiskImageError("output already exists")
                output.write_bytes(result.pop("data"))
                result["output"] = str(output)
        elif args.operation == "btrfs-info":
            info = btrfs_superblock_info(_read(args.filesystem))
            result = {**info, "fsid": info["fsid"].hex()}
        else:
            result = recover_btrfs_file(_read(args.filesystem), args.object_id, args.size)
            if args.output:
                output = Path(args.output)
                if output.exists():
                    raise DiskImageError("output already exists")
                output.write_bytes(result.pop("data"))
                result["output"] = str(output)
        print(json.dumps(result, sort_keys=True, default=lambda value: value.hex() if isinstance(value, bytes) else str(value)))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, struct.error,
            RecursionError, MemoryError) as exc:
        print(f"disk_images: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
