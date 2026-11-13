#!/usr/bin/env python3
"""Focused tests for disk.partition_start_lba_sequence (GPT and MBR).

    PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_day28_metadata_disk.py

All generated GPT fixtures carry valid header and partition-array CRCs. The exact saved Day 28 base and Mastery
delivery are checked when $CTF_REAL_CHALLENGES names the saved Huntress attempts (read only); otherwise those two
tests are reported not run.
"""
import atexit
import json
import io
import os
import shutil
import struct
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

import pytest

from ctf import paths

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_day28_metadata_disk_"))
# CTF_WORKDIR is set at import and may outlive this module in a pytest worker: remove the folder at exit only.
atexit.register(shutil.rmtree, SCRATCH, True)
os.environ["CTF_WORKDIR"] = str(SCRATCH / "challenges")
os.environ["CTF_STATE_DIR"] = str(SCRATCH / "state")
for path in (REPO / "solvers/common", REPO / "solvers/metadata-forensics"):
    sys.path.insert(0, str(path))

import labels  # noqa: E402
import properties_strict as M  # noqa: E402

M._day_patch = lambda: None
R = M.MORE_MODULES["readers_more.py"]
DAY28 = "day-28/metadata-forensics-day-28-where-it-all-began"


def saved_file(rel):
    # The saved Huntress attempts (read only), only through ctf.paths: None when $CTF_REAL_CHALLENGES is unset
    # (those tests do not run); set to a missing folder, FileNotFoundError fails the test.
    saved = paths.saved_challenges_root()
    if saved is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    f = saved / rel
    if not f.is_file():
        pytest.skip(f"saved Day 28 file not present: {f}")
    return f


def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


def gpt(starts, sector=512):
    """A small primary GPT with four 128-byte entries and table-order `starts`."""
    sectors = 256
    data = bytearray(sector * sectors)
    data[446:462] = struct.pack("<B3xB3xII", 0, 0xEE, 1, sectors - 1)
    data[510:512] = b"\x55\xaa"
    count, esize, table_lba = 4, 128, 2
    table = bytearray(count * esize)
    for index, start in enumerate(starts):
        off = index * esize
        table[off:off + 16] = bytes(range(1, 17))
        table[off + 16:off + 32] = bytes([index + 17]) * 16
        struct.pack_into("<QQQ", table, off + 32, start, start + 4, 0)
    table_crc = zlib.crc32(table) & 0xFFFFFFFF
    data[table_lba * sector:table_lba * sector + len(table)] = table
    header = bytearray(sector)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x00010000, 92, 0, 0, 1, sectors - 1, 34, sectors - 34)
    header[56:72] = bytes.fromhex("00112233445566778899aabbccddeeff")
    struct.pack_into("<QIII", header, 72, table_lba, count, esize, table_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xFFFFFFFF)
    data[sector:2 * sector] = header
    return bytes(data)


def mbr(starts):
    data = bytearray(512)
    for index, start in enumerate(starts):
        data[446 + 16 * index:462 + 16 * index] = struct.pack("<B3xB3xII", 0x80 if index == 0 else 0,
                                                              0x07 if index == 0 else 0x83, start, 100)
    data[510:512] = b"\x55\xaa"
    return bytes(data)


prop = M.lookup("disk.partition_start_lba_sequence")


def test_registry_ships_the_judged_gpt_reader():
    check(prop is not None and prop.fmt == "forms", "registry: disk sequence reader is shipped")
    check(M.JUDGED_LEDGER.get(M.canon(prop.name)) == "metadata.format/disk.partition_start_lba_sequence+gpt",
          "registry: folded reader preserves Day 28's judged GPT ledger key")


@pytest.mark.parametrize("sector", [512, 4096])
def test_gpt_table_order_and_compact_json(sector):
    image = gpt([70, 34], sector)
    check(R._partition_start_lbas(image) == ("gpt", [70, 34]),
          f"GPT: {sector}-byte sectors preserve partition-table order")
    options, absent = M.options_for(prop, "disk-001.img", image)
    check(not absent and options == [("json_numbers_table_order", "[70,34]")],
          f"GPT: {sector}-byte sectors offer compact numeric JSON", options)


def test_mbr_table_order_and_unsure_integration():
    image = mbr([2048, 4096])
    check(R._partition_start_lbas(image) == ("mbr", [2048, 4096]), "MBR: occupied primary entries stay in table order")

    question = {
        "qid": "d28-disk-001-disk-partition-start-lba-sequence",
        "answer_id": "d28-disk-001-disk-partition-start-lba-sequence",
        "question": "Inspect disk-001.img. Determine disk.partition_start_lba_sequence for disk-001.img.",
        "artifact": "evidence.zip -> disk-001.img",
        "member": "disk-001.img",
        "answer_format": {"kind": "json", "syntax": "compact valid JSON array with exact values and order"},
    }
    answer = M.solve_set([question], {"disk-001.img": image, "evidence.zip -> disk-001.img": image}, {"set": 1})[question["qid"]]
    parsed = labels.parse(answer) if isinstance(answer, str) else None
    check(parsed is not None and ("json_numbers_table_order", "[2048,4096]") in parsed.options,
          "integration: an unjudged MBR shape is unsure with the byte-derived JSON option", answer)


def test_guards_refuse_bad_crc_out_of_image_and_protective_mbr():
    bad_header = bytearray(gpt([34]))
    bad_header[512 + 16] ^= 1
    try:
        R._partition_start_lbas(bytes(bad_header))
        header_refused = False
    except M.Unknown:
        header_refused = True
    check(header_refused, "guard: a bad GPT header CRC is Unknown")

    bad_table = bytearray(gpt([34]))
    bad_table[2 * 512 + 60] ^= 1
    try:
        R._partition_start_lbas(bytes(bad_table))
        table_refused = False
    except M.Unknown:
        table_refused = True
    check(table_refused, "guard: a bad GPT entry-array CRC is Unknown")

    out_of_image = bytearray(gpt([34]))
    struct.pack_into("<Q", out_of_image, 512 + 48, 9000)  # last usable LBA beyond the 256-sector image
    struct.pack_into("<I", out_of_image, 512 + 16, 0)
    struct.pack_into("<I", out_of_image, 512 + 16,
                     zlib.crc32(out_of_image[512:512 + 92]) & 0xFFFFFFFF)
    try:
        R._partition_start_lbas(bytes(out_of_image))
        bounds_refused = False
    except M.Unknown:
        bounds_refused = True
    check(bounds_refused, "guard: CRC-valid GPT header LBAs cannot exceed the delivered image")

    protective = bytearray(512)
    protective[446:462] = struct.pack("<B3xB3xII", 0, 0xEE, 1, 100)
    protective[510:512] = b"\x55\xaa"
    try:
        R._partition_start_lbas(bytes(protective))
        protective_refused = False
    except M.Unknown:
        protective_refused = True
    check(protective_refused, "guard: a protective MBR never becomes the answer when GPT is missing")
    check(R._partition_start_lbas(b"not a disk") is None, "guard: unrelated bytes are not a disk answer")


def test_exact_saved_day28_disk():
    saved = saved_file(f"{DAY28}/artifact/metadata-day-28-evidence.zip")
    with zipfile.ZipFile(saved) as archive:
        exact = archive.read("disk-001.img")
    started = time.perf_counter()
    got = R._partition_start_lbas(exact)
    elapsed = time.perf_counter() - started
    check(got == ("gpt", [34]), "exact: Day 28 disk reads [34]", got)
    check(elapsed < 1.0, "exact: CRC-validated sequence reader stays under one second", round(elapsed, 3))
    exact_options, exact_absent = M.options_for(prop, "disk-001.img", exact)
    check(not exact_absent and exact_options == [("json_numbers_table_order", "[34]")],
          "exact: Day 28 reader offers the judge-accepted form", exact_options)
    print(f"INFO exact Day 28 disk: bytes={len(exact)} parse={elapsed:.4f}s")


def test_exact_saved_day28_mastery():
    mastery = saved_file(f"{DAY28}/mastery/artifact/metadata-forensics-day-28-where-it-all-began-mastery.zip")
    mastery_key = saved_file(f"{DAY28}/mastery/key.json")
    truth = json.loads(mastery_key.read_text())["answers"]
    wrong = {}
    started = time.perf_counter()
    with zipfile.ZipFile(mastery) as outer:
        for number in range(1, 13):
            with zipfile.ZipFile(io.BytesIO(outer.read(f"evidence-{number:02}.zip"))) as delivery:
                disk = delivery.read("disk-001.img")
            table = R._partition_start_lbas(disk)
            value = json.dumps(table[1], separators=(",", ":")) if table is not None else None
            qid = f"set{number}.d28-disk-001-disk-partition-start-lba-sequence"
            if value != truth[qid]:
                wrong[qid] = (value, truth[qid])
    mastery_elapsed = time.perf_counter() - started
    check(not wrong, "exact: shipped reader reproduces all 12/12 Mastery partition sequences",
          list(wrong.items())[:3])
    check(mastery_elapsed < 2.0, "exact: all 12 nested delivery reads stay under two seconds",
          round(mastery_elapsed, 3))
    print(f"INFO exact Day 28 Metadata Mastery: answers=12 parse={mastery_elapsed:.4f}s")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
