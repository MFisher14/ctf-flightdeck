from __future__ import annotations

import hashlib
import importlib.util
import lzma
import marshal
import random
import re
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import flagfmt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
sys.path.insert(0, str(ROOT / "solvers" / "binary"))
import artifact_depth as artifacts  # noqa: E402
import disk_images as disks  # noqa: E402
import pyinstaller_extract as pyi  # noqa: E402
from ctf.triage import suggest  # noqa: E402


def _ewf_section(kind: str, offset: int, body: bytes, next_offset: int | None = None) -> bytes:
    size = 0 if kind == "done" else 76 + len(body)
    next_at = offset if kind == "done" else (next_offset if next_offset is not None else offset + size)
    header = bytearray(76)
    header[:len(kind)] = kind.encode()
    struct.pack_into("<QQ", header, 16, next_at, size)
    struct.pack_into("<I", header, 72, zlib.adler32(header[:72]) & 0xFFFFFFFF)
    return bytes(header) + body


def _ewf_fixture(raw: bytes, compressed: bool = True) -> bytes:
    assert len(raw) == 512
    prefix = disks.EWF_MAGICS[0] + b"\x01" + struct.pack("<H", 1) + b"\0\0"
    volume_body = bytearray(24)
    struct.pack_into("<IIIQ", volume_body, 4, 1, 1, 512, 1)
    volume_at = len(prefix)
    sectors_at = volume_at + 76 + len(volume_body)
    stored = zlib.compress(raw) if compressed else raw + struct.pack("<I", zlib.adler32(raw) & 0xFFFFFFFF)
    sectors_size = 76 + len(stored)
    table_at = sectors_at + sectors_size
    entry = 76 | (0x80000000 if compressed else 0)
    table_head = struct.pack("<IIQI", 1, 0, sectors_at, 0)
    table_head += struct.pack("<I", zlib.adler32(table_head) & 0xFFFFFFFF)
    entry_bytes = struct.pack("<I", entry)
    table_body = table_head + entry_bytes + struct.pack("<I", zlib.adler32(entry_bytes) & 0xFFFFFFFF)
    hash_at = table_at + 76 + len(table_body)
    hash_body = hashlib.md5(raw).digest()
    done_at = hash_at + 76 + len(hash_body)
    return (prefix + _ewf_section("volume", volume_at, bytes(volume_body))
            + _ewf_section("sectors", sectors_at, stored)
            + _ewf_section("table", table_at, table_body)
            + _ewf_section("hash", hash_at, hash_body)
            + _ewf_section("done", done_at, b""))


def _checked_vhdx_block(signature: bytes, size: int, fill) -> bytes:
    block = bytearray(size)
    block[:4] = signature
    fill(block)
    struct.pack_into("<I", block, 4, 0)
    struct.pack_into("<I", block, 4, disks._crc32c(block))
    return bytes(block)


def _vhdx_fixture(payload: bytes) -> bytes:
    block_size = 1 << 20
    image = bytearray(4 << 20)
    image[:8] = disks.VHDX_MAGIC

    def header(block, sequence):
        struct.pack_into("<Q", block, 8, sequence)
        struct.pack_into("<H", block, 66, 1)
    image[64 << 10:(64 << 10) + 4096] = _checked_vhdx_block(b"head", 4096, lambda b: header(b, 1))
    image[128 << 10:(128 << 10) + 4096] = _checked_vhdx_block(b"head", 4096, lambda b: header(b, 2))

    def region(block):
        struct.pack_into("<I", block, 8, 2)
        for index, (ident, offset, length) in enumerate((
                (disks.VHDX_BAT_GUID, 1 << 20, 1 << 20),
                (disks.VHDX_METADATA_GUID, 2 << 20, 1 << 20))):
            at = 16 + index * 32
            block[at:at + 16] = ident.bytes_le
            struct.pack_into("<QII", block, at + 16, offset, length, 1)
    table = _checked_vhdx_block(b"regi", 64 << 10, region)
    image[192 << 10:256 << 10] = table
    image[256 << 10:320 << 10] = table

    metadata = bytearray(1 << 20)
    metadata[:8] = b"metadata"
    items = ((disks.VHDX_FILE_PARAMETERS_GUID, 0x10000, struct.pack("<II", block_size, 0)),
             (disks.VHDX_VIRTUAL_SIZE_GUID, 0x10010, struct.pack("<Q", block_size)),
             (disks.VHDX_LOGICAL_SECTOR_GUID, 0x10020, struct.pack("<I", 512)))
    struct.pack_into("<H", metadata, 10, len(items))
    for index, (ident, offset, value) in enumerate(items):
        at = 32 + index * 32
        metadata[at:at + 16] = ident.bytes_le
        struct.pack_into("<IIII", metadata, at + 16, offset, len(value), 6, 0)
        metadata[offset:offset + len(value)] = value
    image[2 << 20:3 << 20] = metadata
    struct.pack_into("<Q", image, 1 << 20, (3 << 20) | 6)
    image[3 << 20:(3 << 20) + len(payload)] = payload
    return bytes(image)


def _qcow_header(*, crypt=0, backing_name=b"") -> bytearray:
    cluster = 512
    data = bytearray(4 * cluster)
    backing_offset = 104 if backing_name else 0
    struct.pack_into(">4sI", data, 0, disks.QCOW_MAGIC, 3)
    struct.pack_into(">QIIQIIQ", data, 8, backing_offset, len(backing_name), 9, cluster, crypt, 1, cluster)
    struct.pack_into(">Q", data, 72, 0)
    if backing_name:
        data[backing_offset:backing_offset + len(backing_name)] = backing_name
    return data


def test_ewf_vhdx_qcow_and_split_vmdk_roundtrips():
    prefix = b"CSCTF{round4_disk}"
    marker = prefix + b"D" * (512 - len(prefix))
    for compressed in (False, True):
        wrapped = _ewf_fixture(marker, compressed)
        assert disks.unwrap_ewf(wrapped) == marker
        damaged = bytearray(wrapped); damaged[30] ^= 1
        with pytest.raises(disks.DiskImageError):
            disks.unwrap_ewf(bytes(damaged))

    vhdx = _vhdx_fixture(marker)
    assert disks.unwrap_vhdx(vhdx)[:len(marker)] == marker
    broken = bytearray(vhdx); broken[(64 << 10) + 100] ^= 1; broken[(128 << 10) + 100] ^= 1
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_vhdx(bytes(broken))

    cluster = 512
    raw_prefix = b"CSCTF{compressed_qcow}"
    raw = raw_prefix + b"Q" * (cluster - len(raw_prefix))
    compressor = zlib.compressobj(level=9, wbits=-15)
    packed = compressor.compress(raw) + compressor.flush()
    qcow = _qcow_header()
    struct.pack_into(">Q", qcow, cluster, 2 * cluster)
    entry = (1 << 62) | (3 * cluster)
    struct.pack_into(">Q", qcow, 2 * cluster, entry)
    qcow[3 * cluster:3 * cluster + len(packed)] = packed
    assert disks.unwrap_qcow2(bytes(qcow)) == raw

    backing_prefix = b"CSCTF{backing_qcow}"
    backing = backing_prefix + b"B" * (cluster - len(backing_prefix))
    backed = _qcow_header(backing_name=b"base.raw")
    assert disks.unwrap_qcow2(bytes(backed), backing=backing) == backing
    with pytest.raises(disks.DiskImageError):
        disks.unwrap_qcow2(bytes(backed))

    from Crypto.Cipher import AES
    key = b"0123456789abcdef"
    clear_prefix = b"CSCTF{aes_qcow}"
    clear = clear_prefix + b"A" * (cluster - len(clear_prefix))
    encrypted = AES.new(key, AES.MODE_CBC, b"\0" * 16).encrypt(clear)
    crypt = _qcow_header(crypt=1)
    struct.pack_into(">Q", crypt, cluster, 2 * cluster)
    struct.pack_into(">Q", crypt, 2 * cluster, (1 << 63) | (3 * cluster))
    crypt[3 * cluster:4 * cluster] = encrypted
    assert disks.unwrap_qcow2(bytes(crypt), aes_key=key) == clear

    descriptor = b'# Disk DescriptorFile\nRW 1 FLAT "one-flat.vmdk" 1\nRW 1 ZERO\nRW 1 FLAT "two-flat.vmdk" 0\n'
    one = b"skip".ljust(512, b"X") + b"ONE".ljust(512, b"1")
    two = b"TWO".ljust(512, b"2")
    assembled = disks.unwrap_vmdk_descriptor(descriptor, {"one-flat.vmdk": one, "two-flat.vmdk": two})
    assert assembled[:3] == b"ONE" and assembled[512:1024] == b"\0" * 512 and assembled[1024:1027] == b"TWO"


def _apfs_block(body: bytearray) -> bytes:
    struct.pack_into("<Q", body, 0, 0)
    struct.pack_into("<Q", body, 0, disks._apfs_fletcher64(body))
    return bytes(body)


def test_apfs_and_btrfs_stale_extent_recovery():
    marker = b"CSCTF{filesystem_recovery}"
    block = 4096
    apfs = bytearray(block * 3)
    nx = bytearray(block)
    nx[32:36] = disks.APFS_NX_MAGIC
    struct.pack_into("<IQ", nx, 36, block, 3)
    nx[72:88] = bytes(range(16))
    apfs[:block] = _apfs_block(nx)
    leaf = bytearray(block)
    struct.pack_into("<Q", leaf, 8, 9)
    struct.pack_into("<HHI", leaf, 32, 0x0002, 0, 1)
    struct.pack_into("<HH", leaf, 40, 0, 8)
    struct.pack_into("<HHHH", leaf, 56, 0, 16, 96, 24)
    struct.pack_into("<QQ", leaf, 64, (8 << 60) | 42, 0)
    struct.pack_into("<QQQ", leaf, block - 96, len(marker), 2, 0)
    apfs[block:2 * block] = _apfs_block(leaf)
    apfs[2 * block:2 * block + len(marker)] = marker
    recovered = disks.recover_apfs_file(bytes(apfs), 42, len(marker))
    assert recovered["data"] == marker

    btrfs = bytearray(20 * block)
    fsid = bytes(range(16, 32))
    sb = memoryview(btrfs)[0x10000:0x10000 + block]
    sb[0x20:0x30] = fsid; sb[0x40:0x48] = disks.BTRFS_MAGIC
    struct.pack_into("<Q", sb, 0x70, len(btrfs))
    struct.pack_into("<III", sb, 0x90, block, block, block)
    node = memoryview(btrfs)[:block]
    node[32:48] = fsid; node[100] = 0; struct.pack_into("<I", node, 96, 1)
    data_offset = 256
    struct.pack_into("<QBQII", node, 101, 77, 108, 0, data_offset, 21 + len(marker))
    struct.pack_into("<QQBBHB", node, data_offset, 5, len(marker), 0, 0, 0, 0)
    node[data_offset + 21:data_offset + 21 + len(marker)] = marker
    assert disks.recover_btrfs_file(bytes(btrfs), 77, len(marker))["data"] == marker


def test_btrfs_regular_extent_translates_logical_through_chunk_map():
    # A non-inline (regular) extent stores disk_bytenr as a LOGICAL address that MUST be translated
    # through the chunk tree. The physical bytes live at a different offset; treating the logical
    # address as physical (the former bug) would return the wrong region. A CHUNK_ITEM maps them.
    import struct
    block = 4096
    marker = b"CSCTF{btrfs_chunk_mapped!}"
    logical = 0x100000
    physical = 9 * block
    btrfs = bytearray(20 * block)
    btrfs[physical:physical + len(marker)] = marker  # real bytes live here, NOT at `logical`
    fsid = bytes(range(16, 32))
    sb = memoryview(btrfs)[0x10000:0x10000 + block]
    sb[0x20:0x30] = fsid
    sb[0x40:0x48] = disks.BTRFS_MAGIC
    struct.pack_into("<Q", sb, 0x70, len(btrfs))
    struct.pack_into("<III", sb, 0x90, block, block, block)
    node = memoryview(btrfs)[:block]
    node[32:48] = fsid
    node[100] = 0
    struct.pack_into("<I", node, 96, 2)  # two items: EXTENT_DATA + CHUNK_ITEM
    # item 0: EXTENT_DATA (type 108), regular extent (extent_type=1), disk_bytenr=logical
    ed_off = 1024
    struct.pack_into("<QBQII", node, 101, 77, 108, 0, ed_off, 53)
    struct.pack_into("<QQBBHB", node, ed_off, 5, len(marker), 0, 0, 0, 1)
    struct.pack_into("<QQQQ", node, ed_off + 21, logical, len(marker), 0, len(marker))
    # item 1: CHUNK_ITEM (type 228), key.offset=logical, single stripe at `physical`
    ch_off = 2048
    struct.pack_into("<QBQII", node, 101 + 25, 256, 228, logical, ch_off, 80)
    struct.pack_into("<QQQQIIIHH", node, ch_off, 0x100000, 0, block, 1, block, block, block, 1, 1)
    struct.pack_into("<QQ", node, ch_off + 48, 1, physical)  # stripe[0]: devid, physical offset
    assert disks.recover_btrfs_file(bytes(btrfs), 77, len(marker))["data"] == marker

    # Without a covering chunk (unmapped logical address) it must DECLINE, never return wrong bytes.
    no_chunk = bytearray(btrfs)
    nn = memoryview(no_chunk)[:block]
    struct.pack_into("<I", nn, 96, 1)  # drop the CHUNK_ITEM, keep only the extent
    with pytest.raises(disks.DiskImageError):
        disks.recover_btrfs_file(bytes(no_chunk), 77, len(marker))


def _journal_object(obj_type: int, payload: bytes, flags: int = 0) -> bytes:
    obj = bytearray(16 + len(payload))
    struct.pack_into("<BBQ", obj, 0, obj_type, flags, len(obj))
    return bytes(obj[:2] + b"\0" * 6 + obj[8:]) if False else bytes(obj)


def test_binary_journal_pst_and_safe_yara():
    header_size = 256
    field = b"MESSAGE=CSCTF{binary_journal}"
    data_payload = b"\0" * 48 + field
    data_obj = bytearray(16 + len(data_payload)); data_obj[0] = 1
    struct.pack_into("<Q", data_obj, 8, len(data_obj)); data_obj[16:] = data_payload
    data_at = header_size
    entry_at = (data_at + len(data_obj) + 7) & ~7
    entry = bytearray(80); entry[0] = 3; struct.pack_into("<Q", entry, 8, len(entry))
    struct.pack_into("<QQQ", entry, 16, 1, 1_700_000_000_000_000, 99)
    struct.pack_into("<Q", entry, 64, data_at)
    arena_end = entry_at + len(entry)
    journal = bytearray(arena_end)
    journal[:8] = artifacts.JOURNAL_MAGIC
    journal[24:72] = bytes(range(48))
    struct.pack_into("<QQ", journal, 88, header_size, arena_end - header_size)
    journal[data_at:data_at + len(data_obj)] = data_obj
    journal[entry_at:arena_end] = entry
    parsed = artifacts.parse_systemd_journal(bytes(journal))
    assert parsed["entries"][0]["fields"]["MESSAGE"] == "CSCTF{binary_journal}"
    route = suggest("forensics", "recover flag from a binary systemd journal")
    assert route["engines"][0] == "solvers/toolkits/artifact_depth.py"
    assert flagfmt.is_flag(parsed["entries"][0]["fields"]["MESSAGE"])

    # Same journal field through the standard-library XZ path.
    packed = struct.pack("<Q", len(field)) + lzma.compress(field)
    compressed_obj = bytearray(64 + len(packed)); compressed_obj[0] = 1; compressed_obj[1] = 1
    struct.pack_into("<Q", compressed_obj, 8, len(compressed_obj)); compressed_obj[64:] = packed
    assert artifacts._journal_field_payload(bytes(compressed_obj), 1) == field

    pst = bytearray(2048); pst[:4] = artifacts.PST_MAGIC; pst[8:10] = b"SM"
    struct.pack_into("<HH", pst, 10, 23, 19)
    pst[512:512 + len("CSCTF{pst_carve}".encode("utf-16le"))] = "CSCTF{pst_carve}".encode("utf-16le")
    pst[1024:1028] = b"PK\x03\x04"
    report = artifacts.inspect_pst_ost(bytes(pst), "mail.ost")
    assert report["format"] == "ost" and any("CSCTF{pst_carve}" in row["value"] for row in report["strings"])
    assert report["embedded"][0]["type"] == "zip"

    sample = b"MZ....VirtualAlloc..WriteProcessMemory..CSCTF{yara_lane}"
    matches = artifacts.builtin_malware_triage(sample)
    assert {row["rule"] for row in matches} == {"suspicious_loader_apis"}
    custom = artifacts.parse_yara_rules('rule x { strings: $a = { 43 53 ?? 54 46 } condition: $a }')
    assert artifacts.scan_yara(b"CSXTF", custom)[0]["matches"]["a"] == [0]


def _pyinstaller_fixture(payload: bytes) -> bytes:
    packed = zlib.compress(payload)
    name = b"main\0"
    entry_size = 18 + len(name)
    toc = struct.pack(">IIIIBB", entry_size, 0, len(packed), len(payload), 1, ord("s")) + name
    cookie_size = 24
    package_length = len(packed) + len(toc) + cookie_size
    cookie = pyi.MAGIC + struct.pack(">IIII", package_length, len(packed), len(toc), 312)
    return b"MZ-synthetic-bootloader" + packed + toc + cookie


def test_pyinstaller_extract_to_pyc_static_integration(tmp_path):
    code = compile("marker = 'CSCTF{pyinstaller_chain}'", "fixture.py", "exec")
    archive = _pyinstaller_fixture(marshal.dumps(code))
    cookie, entries = pyi.extract_carchive(archive)
    assert cookie.python_version == 312 and len(entries) == 1
    assert "CSCTF{pyinstaller_chain}" in pyi.printable_leads(entries[0].data)
    pyc = pyi.make_pyc(entries[0], importlib.util.MAGIC_NUMBER)
    assert pyc[:4] == importlib.util.MAGIC_NUMBER and pyc[16:] == entries[0].data
    plan = pyi.docker_disassembly_plan("fixture.pyc")
    assert "--pull=never" in plan and "none" in plan and "marshal.loads" in plan[-1]
    assert suggest("reverse", "extract a PyInstaller CArchive")["engines"][0] == "solvers/binary/pyinstaller_extract.py"


def test_pyinstaller_extracted_pyc_disassembles_in_networkless_container(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("docker unavailable")
    image = "csctf-sandbox:2"
    inspected = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=10)
    if inspected.returncode:
        pytest.skip("already-local sandbox image unavailable")
    code = compile("marker = 'CSCTF{pyinstaller_docker_fixture}'", "fixture.py", "exec")
    _cookie, entries = pyi.extract_carchive(_pyinstaller_fixture(marshal.dumps(code)))
    path = tmp_path / "fixture.pyc"
    path.write_bytes(pyi.make_pyc(entries[0], importlib.util.MAGIC_NUMBER))
    script = ("import dis,marshal,pathlib; d=pathlib.Path('/work/fixture.pyc').read_bytes(); "
              "dis.dis(marshal.loads(d[16:]))")
    result = subprocess.run([
        "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--pids-limit", "64", "--memory", "256m",
        "-v", f"{tmp_path}:/work:ro", image, "python3", "-I", "-c", script,
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "CSCTF{pyinstaller_docker_fixture}" in result.stdout


def test_round4_forensics_seeded_mutation_boundaries(tmp_path, capsys):
    rng = random.Random(0xC5C7F4)
    ewf = _ewf_fixture(b"A" * 512)
    vhdx = _vhdx_fixture(b"B" * 512)
    for seed in (ewf, vhdx, b"LPKSHHRH" + b"\0" * 200, b"!BDN" + b"\0" * 600):
        for _ in range(40):
            candidate = bytearray(seed)
            for _ in range(1 + rng.randrange(4)):
                if candidate:
                    candidate[rng.randrange(len(candidate))] ^= 1 << rng.randrange(8)
            for parser in (disks.detect_container,):
                parser(bytes(candidate))
            for parser in (disks.unwrap_ewf, disks.unwrap_vhdx,
                           artifacts.parse_systemd_journal, artifacts.inspect_pst_ost):
                try:
                    parser(bytes(candidate))
                except (ValueError, TypeError, OverflowError, UnicodeError, struct.error,
                        lzma.LZMAError, zlib.error, MemoryError, RecursionError):
                    pass

    qcow = bytes(_qcow_header())
    descriptor = b'# Disk DescriptorFile\nRW 1 FLAT "part.vmdk" 0\n'
    nx = bytearray(4096); nx[32:36] = disks.APFS_NX_MAGIC
    struct.pack_into("<IQ", nx, 36, 4096, 1); nx[72:88] = bytes(range(16)); nx = bytearray(_apfs_block(nx))
    btrfs = bytearray(0x10000 + 4096); sb = memoryview(btrfs)[0x10000:]
    sb[0x20:0x30] = bytes(range(16)); sb[0x40:0x48] = disks.BTRFS_MAGIC
    struct.pack_into("<Q", sb, 0x70, len(btrfs)); struct.pack_into("<III", sb, 0x90, 4096, 4096, 4096)
    archive = _pyinstaller_fixture(b"CSCTF{fuzz_fixture}")
    for _ in range(80):
        index = rng.randrange(len(qcow)); mutated = bytearray(qcow); mutated[index] ^= 1 << rng.randrange(8)
        try:
            disks.unwrap_qcow2(bytes(mutated))
        except (ValueError, TypeError, OverflowError, UnicodeError, struct.error,
                zlib.error, MemoryError, RecursionError):
            pass
        mutated = bytearray(descriptor); mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
        try:
            disks.unwrap_vmdk_descriptor(bytes(mutated), {"part.vmdk": b"P" * 512})
        except (ValueError, TypeError, OverflowError, UnicodeError, struct.error,
                MemoryError, RecursionError):
            pass
        for seed, parser in ((bytes(nx), disks.apfs_container_info),
                             (bytes(btrfs), disks.btrfs_superblock_info),
                             (archive, pyi.extract_carchive)):
            mutated = bytearray(seed); mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
            try:
                parser(bytes(mutated))
            except (ValueError, TypeError, OverflowError, UnicodeError, struct.error,
                    zlib.error, MemoryError, RecursionError):
                pass
        rule = bytearray(b'rule f { strings: $a = "needle" condition: $a }')
        rule[rng.randrange(len(rule))] ^= 1 << rng.randrange(7)
        try:
            parsed_rules = artifacts.parse_yara_rules(rule.decode("ascii"))
            artifacts.scan_yara(b"prefix needle suffix", parsed_rules)
        except (ValueError, TypeError, OverflowError, UnicodeError, re.error,
                MemoryError, RecursionError):
            pass

    bad = tmp_path / "bad.bin"; bad.write_bytes(b"bad")
    assert artifacts.main(["journal", str(bad)]) == 2
    assert "Traceback" not in capsys.readouterr().err
    assert pyi.main([str(bad)]) == 2
    assert "Traceback" not in capsys.readouterr().err
