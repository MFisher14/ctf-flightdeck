#!/usr/bin/env python3
"""B-221: the disk.* family beyond the judged start-LBA sequence (readers_disk.py), the `disk` catalog format
and its detector.

Every image is built here (ctf/formats/corpus.py gpt_image / mbr_image, or patched bytes with CRCs recomputed
by this file's own code): no real disk image is read.
"""
import atexit
import json
import os
import shutil
import struct
import sys
import tempfile
import uuid
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_disk_family_"))
atexit.register(shutil.rmtree, SCRATCH, True)
os.environ.setdefault("CTF_WORKDIR", str(SCRATCH / "challenges"))
os.environ.setdefault("CTF_STATE_DIR", str(SCRATCH / "state"))
for path in (REPO / "solvers/common", REPO / "solvers/metadata-forensics"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import labels  # noqa: E402
import properties_strict as M  # noqa: E402

from ctf import formats  # noqa: E402
from ctf.formats import corpus as C  # noqa: E402

D = M.MORE_MODULES["readers_disk.py"]
R = M.MORE_MODULES["readers_more.py"]

EFI, LINUX, BASIC = C.GPT_EFI_SYSTEM, C.GPT_LINUX_FS, C.GPT_MS_BASIC_DATA
U1, U2 = "aaaaaaaa-bbbb-4ccc-8ddd-000000000001", "aaaaaaaa-bbbb-4ccc-8ddd-000000000002"
DISK = "01234567-89ab-4def-8123-456789abcdef"

NEW_NAMES = [
    "disk.partition_table_type", "disk.partition_count", "disk.has_protective_mbr", "disk.disk_guid",
    "disk.sector_size_bytes", "disk.total_sectors", "disk.first_usable_lba", "disk.last_usable_lba",
    "disk.backup_header_lba", "disk.partition_entry_lba", "disk.partition_entry_count",
    "disk.partition_entry_size_bytes", "disk.mbr_disk_signature", "disk.partition_type_guid_sequence",
    "disk.partition_guid_sequence", "disk.partition_name_sequence", "disk.partition_type_code_sequence",
    "disk.partition_end_lba_sequence", "disk.partition_sector_count_sequence", "disk.partition_size_bytes_sequence",
]


def opts(name, data, file="disk-001.img"):
    """(options, absent) of the registered reader `name` on `data`."""
    p = M.lookup(name)
    assert p is not None, name
    return M.options_for(p, file, data)


def first(name, data):
    options, absent = opts(name, data)
    assert not absent and options, (name, options, absent)
    return options[0][1]


def unknown(name, data) -> str:
    with pytest.raises(M.Unknown) as e:
        opts(name, data)
    return str(e.value)


def gpt_two(sector=512):
    """Two partitions, the later LBA first in the table; a non-ASCII name and a full 36-unit name."""
    if sector == 512:
        parts = [(LINUX, U2, 200, 299, "Données"), (EFI, U1, 40, 99, "N" * 36)]
        return C.gpt_image(parts, sector=512, sectors=512, disk_guid=DISK), parts
    parts = [(LINUX, U2, 20, 29, "Données"), (EFI, U1, 7, 9, "N" * 36)]
    return C.gpt_image(parts, sector=4096, sectors=64, disk_guid=DISK), parts


def refresh(img: bytearray, sector: int):
    """Recompute the primary GPT's array and header CRCs after a patch (this test's own arithmetic)."""
    h = sector
    table_lba, count, esize = struct.unpack_from("<QII", img, h + 72)
    table = bytes(img[table_lba * sector:table_lba * sector + count * esize])
    struct.pack_into("<I", img, h + 88, zlib.crc32(table) & 0xFFFFFFFF)
    struct.pack_into("<I", img, h + 16, 0)
    struct.pack_into("<I", img, h + 16, zlib.crc32(bytes(img[h:h + 92])) & 0xFFFFFFFF)


# ------------------------------------------------------------------ registration

def test_pack_loads_after_readers_more_and_replaces_nothing():
    assert "readers_disk.py" in M.MORE_LOADED and M.MORE_FILES.index("readers_disk.py") > M.MORE_FILES.index("readers_more.py")
    assert not [c for c in M.MORE_CLASHES if c.startswith("disk.")]
    for name in NEW_NAMES:
        p = M.lookup(name)
        assert p is not None and not p.confirmed, name
        assert M.canon(name) not in M.JUDGED_LEDGER, name
    judged = M.lookup("disk.partition_start_lba_sequence")
    assert judged.fn is R._partition_start_forms
    assert M.JUDGED_LEDGER[M.canon("disk.partition_start_lba_sequence")] == \
        "metadata.format/disk.partition_start_lba_sequence+gpt"


def test_corpus_image_is_a_valid_gpt_by_independent_arithmetic():
    img, parts = gpt_two()
    head = img[512:512 + 92]
    assert head[:8] == b"EFI PART"
    crc = struct.unpack_from("<I", head, 16)[0]
    assert crc == zlib.crc32(head[:16] + b"\x00" * 4 + head[20:]) & 0xFFFFFFFF
    table_lba, count, esize, table_crc = struct.unpack_from("<QIII", head, 72)
    table = img[table_lba * 512:table_lba * 512 + count * esize]
    assert table_crc == zlib.crc32(table) & 0xFFFFFFFF
    assert uuid.UUID(bytes_le=table[:16]) == uuid.UUID(LINUX)
    backup = img[-512:-512 + 92]
    assert backup[:8] == b"EFI PART" and struct.unpack_from("<QQ", backup, 24) == (511, 1)


# ------------------------------------------------------------------ GPT

@pytest.mark.parametrize("sector", [512, 4096])
def test_gpt_family_reads_the_table_in_table_order(sector):
    img, parts = gpt_two(sector)
    sectors = len(img) // sector
    array = (128 * 128 + sector - 1) // sector
    assert opts("disk.partition_table_type", img) == ([("lower", "gpt"), ("upper", "GPT")], False)
    assert opts("disk.partition_count", img) == ([("integer", "2")], False)
    assert first("disk.disk_guid", img) == DISK
    assert opts("disk.partition_type_guid_sequence", img)[0] == [
        ("hyphen_lower", json.dumps([LINUX, EFI], separators=(",", ":"))),
        ("hyphen_upper", json.dumps([LINUX.upper(), EFI.upper()], separators=(",", ":"))),
        ("comma", f"{LINUX},{EFI}")]
    assert first("disk.partition_guid_sequence", img) == json.dumps([U2, U1], separators=(",", ":"))
    assert opts("disk.partition_name_sequence", img)[0] == [
        ("json_compact", json.dumps(["Données", "N" * 36], ensure_ascii=False, separators=(",", ":"))),
        ("comma", "Données," + "N" * 36)]
    starts, ends = [p[2] for p in parts], [p[3] for p in parts]
    sizes = [b - a + 1 for a, b in zip(starts, ends)]
    assert opts("disk.partition_end_lba_sequence", img)[0] == [
        ("json_numbers_table_order", json.dumps(ends, separators=(",", ":"))),
        ("comma", ",".join(map(str, ends))), ("comma_space", ", ".join(map(str, ends)))]
    assert first("disk.partition_sector_count_sequence", img) == json.dumps(sizes, separators=(",", ":"))
    assert first("disk.partition_size_bytes_sequence", img) == json.dumps([n * sector for n in sizes], separators=(",", ":"))
    assert first("disk.sector_size_bytes", img) == str(sector)
    assert first("disk.total_sectors", img) == str(sectors)
    assert first("disk.first_usable_lba", img) == str(2 + array)
    assert first("disk.last_usable_lba", img) == str(sectors - 2 - array)
    assert first("disk.backup_header_lba", img) == str(sectors - 1)
    assert first("disk.partition_entry_lba", img) == "2"
    assert first("disk.partition_entry_count", img) == "128"
    assert first("disk.partition_entry_size_bytes", img) == "128"
    assert first("disk.has_protective_mbr", img) == "true"
    # the judged reader reads the same table
    assert R._partition_start_lbas(img) == ("gpt", starts)


def test_gpt_without_a_protective_mbr_says_so():
    img = bytearray(gpt_two()[0])
    img[446:462] = b"\x00" * 16
    img[510:512] = b"\x00\x00"
    assert first("disk.has_protective_mbr", bytes(img)) == "false"
    assert first("disk.partition_count", bytes(img)) == "2"
    hybrid = bytearray(gpt_two()[0])                      # boot signature kept, the 0xEE entry now a Linux one
    hybrid[446 + 4] = 0x83
    assert first("disk.has_protective_mbr", bytes(hybrid)) == "false"
    unsigned = bytearray(gpt_two()[0])                    # the 0xEE entry kept, no boot signature
    unsigned[510:512] = b"\x00\x00"
    assert first("disk.has_protective_mbr", bytes(unsigned)) == "false"
    later_slot = bytearray(gpt_two()[0])                  # a protective entry in slot 3 still counts
    later_slot[446 + 48:462 + 48] = later_slot[446:462]
    later_slot[446:462] = b"\x00" * 16
    assert first("disk.has_protective_mbr", bytes(later_slot)) == "true"


def test_gpt_unnamed_entries_and_an_empty_table():
    img = C.gpt_image([(EFI, U1, 34, 40, ""), (LINUX, U2, 41, 50, "root")])
    assert opts("disk.partition_name_sequence", img)[0] == [("json_compact", '["","root"]')]   # no comma form with an empty name
    comma = C.gpt_image([(EFI, U1, 34, 40, "data, backup"), (LINUX, U2, 41, 50, "root")])
    assert opts("disk.partition_name_sequence", comma)[0] == [            # a comma list would read as 3 names
        ("json_compact", '["data, backup","root"]')]
    empty = C.gpt_image([])
    assert opts("disk.partition_count", empty) == ([("integer", "0")], False)
    assert opts("disk.partition_start_lba_sequence", empty)[0] == [("json_numbers_table_order", "[]")]
    assert opts("disk.partition_type_guid_sequence", empty)[0] == [("hyphen_lower", "[]")]   # one value, one option
    assert opts("disk.partition_end_lba_sequence", empty)[0] == [("json_numbers_table_order", "[]")]


def test_gpt_name_stops_at_the_first_nul_unit():
    img = bytearray(C.gpt_image([(EFI, U1, 34, 40, "boot")]))
    at = 2 * 512 + 56 + len("boot".encode("utf-16-le")) + 2     # after the NUL unit that ends the name
    img[at:at + 4] = "zz".encode("utf-16-le")
    refresh(img, 512)
    assert opts("disk.partition_name_sequence", bytes(img))[0][0] == ("json_compact", '["boot"]')


def test_a_name_that_is_not_utf16_is_unknown_and_costs_only_the_names():
    img = bytearray(C.gpt_image([(EFI, U1, 34, 40, "ok")]))
    img[2 * 512 + 56:2 * 512 + 60] = b"\x00\xd8a\x00"          # a lone high surrogate
    refresh(img, 512)
    assert "UTF-16" in unknown("disk.partition_name_sequence", bytes(img))
    assert first("disk.partition_count", bytes(img)) == "1"


def test_gpt_facts_are_absent_on_an_mbr_disk_and_mbr_facts_absent_on_a_gpt():
    mbr = C.mbr_image([(0x80, 0x83, 63, 100)])
    gpt = gpt_two()[0]
    for name in ("disk.disk_guid", "disk.partition_type_guid_sequence", "disk.partition_guid_sequence",
                 "disk.partition_name_sequence", "disk.first_usable_lba", "disk.last_usable_lba",
                 "disk.backup_header_lba", "disk.partition_entry_lba", "disk.partition_entry_count",
                 "disk.partition_entry_size_bytes"):
        assert opts(name, mbr) == ([], True), name
    for name in ("disk.mbr_disk_signature", "disk.partition_type_code_sequence"):
        assert opts(name, gpt) == ([], True), name


# ------------------------------------------------------------------ MBR

def test_mbr_family():
    img = C.mbr_image([(0x00, 0x83, 2048, 1000), (0x80, 0x07, 63, 1985)], sectors=4096, signature=0xDEADBEEF)
    assert opts("disk.partition_table_type", img) == ([("lower", "mbr"), ("upper", "MBR"), ("name", "dos")], False)
    assert first("disk.partition_count", img) == "2"
    assert opts("disk.partition_type_code_sequence", img)[0] == [
        ("hex_lower", '["83","07"]'), ("0x_hex_lower", '["0x83","0x07"]'), ("json_numbers_table_order", "[131,7]")]
    assert first("disk.partition_end_lba_sequence", img) == "[3047,2047]"
    assert first("disk.partition_sector_count_sequence", img) == "[1000,1985]"
    assert first("disk.mbr_disk_signature", img) == "0xdeadbeef"
    assert first("disk.has_protective_mbr", img) == "false"
    assert R._partition_start_lbas(img) == ("mbr", [2048, 63])


def test_mbr_skips_empty_slots_but_keeps_table_order():
    img = bytearray(C.mbr_image([]))
    struct.pack_into("<B3xB3xII", img, 446 + 16 * 2, 0, 0x83, 500, 10)    # slot 2 only
    struct.pack_into("<B3xB3xII", img, 446 + 16 * 0, 0, 0x0C, 900, 20)    # slot 0, later LBA
    assert first("disk.partition_end_lba_sequence", bytes(img)) == "[919,509]"
    assert first("disk.partition_count", bytes(img)) == "2"


@pytest.mark.parametrize("name", ["disk.sector_size_bytes", "disk.total_sectors", "disk.partition_size_bytes_sequence"])
def test_an_mbr_never_states_its_sector_size(name):
    assert "sector size" in unknown(name, C.mbr_image([(0x80, 0x83, 63, 100)]))


@pytest.mark.parametrize("ext", [0x05, 0x0F, 0x85])
def test_an_extended_partition_makes_counts_and_sequences_unknown(ext):
    img = C.mbr_image([(0x80, 0x83, 63, 100), (0x00, ext, 200, 50)])
    for name in ("disk.partition_count", "disk.partition_end_lba_sequence", "disk.partition_type_code_sequence",
                 "disk.partition_sector_count_sequence"):
        assert "extended" in unknown(name, img), name
    assert first("disk.partition_table_type", img) == "mbr"              # the scheme is still settled
    assert first("disk.mbr_disk_signature", img) == "0x00000000"


def test_zero_start_or_length_and_a_bare_protective_mbr_are_unknown():
    zero = C.mbr_image([(0x80, 0x83, 0, 100)])
    assert "zero start" in unknown("disk.partition_count", zero)
    short = C.mbr_image([(0x80, 0x83, 63, 0)])
    assert "zero start" in unknown("disk.partition_count", short)
    protective = C.mbr_image([(0x00, 0xEE, 1, 255)])
    assert "protective MBR" in unknown("disk.partition_table_type", protective)


# ------------------------------------------------------------------ damaged or ambiguous GPT

def test_a_damaged_gpt_is_unknown_never_an_mbr_answer():
    bad_header = bytearray(gpt_two()[0])
    bad_header[512 + 16] ^= 1
    assert "CRC" in unknown("disk.partition_count", bytes(bad_header))
    assert "CRC" in unknown("disk.partition_table_type", bytes(bad_header))
    bad_array = bytearray(gpt_two()[0])
    bad_array[2 * 512 + 60] ^= 1
    assert "CRC" in unknown("disk.partition_name_sequence", bytes(bad_array))


def _dual(parts512, parts4096):
    """An image with a primary GPT at both 512 and 4096 bytes (4-entry arrays, no overlap). The 512-byte
    header's last usable LBA is set to the 4096-byte one's (29), so equal entries give equal tables."""
    a = bytearray(C.gpt_image(parts512, sector=512, sectors=256, entries=4, disk_guid=DISK))
    struct.pack_into("<Q", a, 512 + 48, 29)
    refresh(a, 512)
    b = C.gpt_image(parts4096, sector=4096, sectors=32, entries=4, disk_guid=DISK)
    assert struct.unpack_from("<Q", b, 4096 + 48)[0] == 29
    a[4096:4096 + 92] = b[4096:4096 + 92]
    a[8192:8192 + 512] = b[8192:8192 + 512]
    return bytes(a)


def test_two_valid_headers_that_agree_leave_only_the_sector_size_open():
    same = [(LINUX, U1, 10, 20, "x")]
    img = _dual(same, same)
    assert first("disk.partition_count", img) == "1"
    assert first("disk.partition_end_lba_sequence", img) == "[20]"
    for name in ("disk.sector_size_bytes", "disk.total_sectors", "disk.partition_size_bytes_sequence"):
        assert "both 512 and 4096" in unknown(name, img), name


def test_two_valid_headers_that_disagree_are_unknown():
    img = _dual([(LINUX, U1, 10, 20, "x")], [(LINUX, U1, 11, 20, "x")])
    assert "different valid GPT headers" in unknown("disk.partition_count", img)


def test_two_valid_headers_that_differ_only_in_a_partition_name_are_unknown():
    img = _dual([(LINUX, U1, 10, 20, "x")], [(LINUX, U1, 10, 20, "y")])
    assert "different valid GPT headers" in unknown("disk.partition_name_sequence", img)
    assert "different valid GPT headers" in unknown("disk.partition_count", img)


def test_two_valid_headers_that_differ_only_in_the_entry_slot_are_unknown():
    """The same one entry in slot 0 of the 512-byte array and slot 1 of the 4096-byte one: every value a
    reader reports agrees, but they are two different tables, so neither reading is trusted."""
    a = bytearray(_dual([(LINUX, U1, 10, 20, "x")], [(LINUX, U1, 10, 20, "x")]))
    base = 2 * 4096                                       # the 4096-byte header's array (LBA 2, 4 x 128 bytes)
    a[base + 128:base + 256] = a[base:base + 128]
    a[base:base + 128] = b"\x00" * 128
    refresh(a, 4096)
    img = bytes(a)
    assert [e["index"] for e in R._gpt_table_at(img, 4096)["entries"]] == [1]      # the patch is a valid GPT
    assert [e["index"] for e in R._gpt_table_at(img, 512)["entries"]] == [0]
    assert "different valid GPT headers" in unknown("disk.partition_count", img)


@pytest.mark.parametrize("data", [b"", b"\x00" * 4096, b"not a disk" * 100])
def test_bytes_that_are_no_disk_are_absent(data):
    for name in NEW_NAMES:
        assert opts(name, data) == ([], True), name


def test_a_filesystem_boot_sector_is_no_partitioned_disk():
    fat = bytearray(512)
    fat[0:3] = b"\xeb\x58\x90"
    fat[3:11] = b"MSDOS5.0"
    fat[82:90] = b"FAT32   "
    fat[510:512] = b"\x55\xaa"
    struct.pack_into("<B3xB3xII", fat, 446, 0, 0x0C, 1, 100)     # boot code bytes that look like an entry
    assert opts("disk.partition_count", bytes(fat)) == ([], True)
    assert not formats.DETECTORS["disk"](bytes(fat))


# ------------------------------------------------------------------ through the lane

@pytest.mark.parametrize("name", NEW_NAMES)
def test_every_new_reader_answers_unsure_under_its_own_key(name):
    img = gpt_two()[0] if name not in ("disk.mbr_disk_signature", "disk.partition_type_code_sequence") \
        else C.mbr_image([(0x80, 0x83, 63, 100)], signature=7)
    qid = "d28-disk-001-" + name.replace(".", "-").replace("_", "-")
    q = {"qid": qid, "answer_id": qid, "question": f"Inspect disk-001.img. Determine {name} for disk-001.img.",
         "artifact": "evidence.zip -> disk-001.img", "member": "disk-001.img"}
    answer = M.solve_set([q], {"disk-001.img": img, "evidence.zip -> disk-001.img": img}, {"set": 1})[qid]
    parsed = labels.parse(answer) if isinstance(answer, str) else None
    assert parsed is not None, (name, answer)
    assert parsed.key == "metadata.format/" + name
    want = opts(name, img)[0]
    assert [tuple(o) for o in parsed.options][:len(want)] == [tuple(o) for o in want]


# ------------------------------------------------------------------ the catalog format and detector

def test_disk_is_a_catalog_format_with_its_samples():
    cat = formats.load()
    disk = next(f for f in cat if f.id == "disk")
    assert set(disk.namespaces) == {"disk", "gpt", "mbr"} and disk.samples == ("disk_gpt", "disk_mbr")
    for sid in disk.samples:
        s = C.build(sid)
        got = formats.identify(s.name, s.data, cat)
        assert got[0].format == "disk" and got[0].sure, (sid, got)
    assert [(m.format, m.sure) for m in formats.identify("blank.img", b"\x00" * 1024, cat)] == [("disk", False)]


def test_detector_edges():
    det = formats.DETECTORS["disk"]
    assert det(C.gpt_image([], sector=4096, sectors=16))                  # a 4096-byte-sector GPT
    assert det(C.mbr_image([(0x80, 0x83, 63, 100)]))
    assert not det(C.mbr_image([]))                                       # boot signature, no used entry
    assert not det(C.mbr_image([(0x80, 0x83, 0, 100)]))                   # an entry with no start
    assert not det(C.mbr_image([(0x80, 0x83, 63, 0)]))                    # an entry with no length
    bad_status = bytearray(C.mbr_image([(0x80, 0x83, 63, 100)]))
    bad_status[446] = 0x7F
    assert not det(bytes(bad_status))
    no_sig = bytearray(C.mbr_image([(0x80, 0x83, 63, 100)]))
    no_sig[511] = 0
    assert not det(bytes(no_sig))
    ntfs = bytearray(C.mbr_image([(0x80, 0x83, 63, 100)]))
    ntfs[3:11] = b"NTFS    "
    assert not det(bytes(ntfs))
    fat16 = bytearray(C.mbr_image([(0x80, 0x83, 63, 100)]))
    fat16[54:59] = b"FAT16"
    assert not det(bytes(fat16))
    assert not det(b"\x55\xaa" * 100)
    assert not det(b"")


def test_corpus_builders_refuse_what_the_format_cannot_hold():
    with pytest.raises(C.CorpusError, match="36 UTF-16"):
        C.gpt_image([(EFI, U1, 34, 40, "N" * 37)])
    with pytest.raises(C.CorpusError, match="usable LBA"):
        C.gpt_image([(EFI, U1, 30, 40, "x")])
    with pytest.raises(C.CorpusError, match="usable LBA"):
        C.gpt_image([(EFI, U1, 40, 39, "x")])
    with pytest.raises(C.CorpusError, match="four primary"):
        C.mbr_image([(0, 0x83, 1, 1)] * 5)
