"""Synthetic offline fixtures for the round-3 memory/disk/video/repair depth lane."""
from __future__ import annotations

import binascii
import importlib.util
import io
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
TOOLKITS = REPO / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import disk_images as disks  # noqa: E402
import file_repair as repair  # noqa: E402
import memory  # noqa: E402
import video_stego as video  # noqa: E402


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body) & 0xFFFFFFFF)


def _png(width: int, height: int, pixels: bytes, *, color=2, interlace=0) -> bytes:
    channels = {0: 1, 2: 3}[color]
    assert len(pixels) == width * height * channels
    raw = b"".join(b"\0" + pixels[row * width * channels:(row + 1) * width * channels]
                   for row in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, interlace)
    return repair.PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")


def test_memory_plugin_plan_credentials_and_carve_chain(tmp_path, capsys):
    plan = memory.volatility_plan(("credentials", "console", "files", "injection"),
                                  pids=[444], file_offsets=[0x1234])
    plugins = [step["plugin"] for step in plan]
    assert "windows.registry.hivelist" in plugins
    assert "windows.hashdump" in plugins
    assert any(step["plugin"] == "windows.dumpfiles" and step["args"][-1] == "--dump" for step in plan)
    assert any(step["plugin"] == "windows.malfind" and step["args"] == ["--pid", "444", "--dump"] for step in plan)

    rows = memory.parse_credential_rows("alice:01f4:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::\n")
    assert rows == [{"user": "alice", "rid": "01f4", "lm": "aad3b435b51404eeaad3b435b51404ee",
                     "nt": "0123456789abcdef0123456789abcdef"}]
    chained = memory.chain_carved_blobs({"pid.444.dmp": b"xxCSCTF{memory_fixture}yy" + repair.PNG_SIG})
    assert chained[0]["value"] == "CSCTF{memory_fixture}"
    assert any(row["kind"] == "png" for row in chained)

    assert memory.main(["--plan", "bogus"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("memory: ") and "Traceback" not in captured.err


def _qcow_fixture(payload: bytes) -> bytes:
    cluster = 512
    data = bytearray(cluster * 4)
    struct.pack_into(">IIQIIQIIQ", data, 0, 0x514649FB, 2, 0, 0, 9, cluster * 2, 0, 1, cluster)
    struct.pack_into(">Q", data, cluster, cluster * 2)
    struct.pack_into(">Q", data, cluster * 2, cluster * 3)
    data[cluster * 3:cluster * 3 + len(payload)] = payload
    return bytes(data)


def _fixed_vhd(payload: bytes) -> bytes:
    footer = bytearray(512)
    footer[:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", footer, 40, len(payload))
    struct.pack_into(">Q", footer, 48, len(payload))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, 0)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return payload + footer


def _sparse_vmdk(payload: bytes) -> bytes:
    data = bytearray(4 * 512)
    data[:4] = b"KDMV"
    struct.pack_into("<II", data, 4, 1, 0)
    struct.pack_into("<QQ", data, 12, 2, 1)  # two sectors, one sector/grain
    struct.pack_into("<I", data, 44, 2)
    struct.pack_into("<Q", data, 56, 1)      # grain directory at sector 1
    struct.pack_into("<I", data, 512, 2)     # grain table at sector 2
    struct.pack_into("<I", data, 1024, 3)    # first grain at sector 3
    data[1536:1536 + len(payload)] = payload
    return bytes(data)


def test_disk_container_unwrap_qcow_and_fixed_vhd():
    payload = b"QCOW fixture" + b"\0" * 500
    qcow = disks.unwrap(_qcow_fixture(payload))
    assert qcow.format == "qcow2"
    assert qcow.raw[:12] == b"QCOW fixture"
    assert len(qcow.raw) == 1024

    raw = b"V" * 1024
    vhd = disks.unwrap(_fixed_vhd(raw))
    assert vhd.format == "vhd" and vhd.raw == raw

    vmdk = disks.unwrap(_sparse_vmdk(b"VMDK" + b"\0" * 508))
    assert vmdk.format == "vmdk-sparse" and vmdk.raw[:4] == b"VMDK"

    ewf = disks.unwrap(b"EVF\t\r\n\xff\x00" + b"\0" * 100)
    assert ewf.raw is None and any("ewfexport" in command for command in ewf.command_plan)


def test_ntfs_runs_ads_slack_and_ext_deleted_extent():
    runlist = bytes([0x11, 0x02, 0x05, 0x01, 0x01, 0x11, 0x01, 0xFE, 0x00])
    runs = disks.parse_ntfs_data_runs(runlist)
    assert [(row["lcn"], row["clusters"]) for row in runs] == [(5, 2), (None, 1), (3, 1)]
    volume = b"".join(bytes([index]) * 512 for index in range(8))
    extracted = disks.extract_ntfs_runs(volume, runs, 512, 1600, 2048)
    assert extracted["data"][:2] == b"\x05\x05"
    assert extracted["data"][1024:1536] == b"\0" * 512
    assert len(extracted["slack"]) == 448

    record = bytearray(1024)
    record[:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 0x30, 3)
    sequence = b"\xaa\xbb"
    record[0x30:0x36] = sequence + b"\x11\x22\x33\x44"
    record[510:512] = sequence
    record[1022:1024] = sequence
    attr = 0x38
    name = "note".encode("utf-16le")
    payload = b"secret"
    length, value_off = 48, 32
    struct.pack_into("<II", record, attr, 0x80, length)
    struct.pack_into("<BBH", record, attr + 8, 0, 4, 24)
    struct.pack_into("<IH", record, attr + 16, len(payload), value_off)
    record[attr + 24:attr + 24 + len(name)] = name
    record[attr + value_off:attr + value_off + len(payload)] = payload
    struct.pack_into("<I", record, attr + length, 0xFFFFFFFF)
    struct.pack_into("<H", record, 20, attr)
    struct.pack_into("<I", record, 24, attr + length + 4)
    streams = disks.ntfs_data_streams(bytes(record))
    assert streams[0]["name"] == "note" and streams[0]["data"] == payload

    inode = bytearray(128)
    struct.pack_into("<H", inode, 0, 0x8000)
    struct.pack_into("<I", inode, 4, 5)
    struct.pack_into("<I", inode, 20, 123)
    struct.pack_into("<H", inode, 26, 0)
    struct.pack_into("<I", inode, 32, 0x80000)
    struct.pack_into("<HHHHI", inode, 40, 0xF30A, 1, 4, 0, 0)
    struct.pack_into("<IHHI", inode, 52, 0, 1, 0, 2)
    filesystem = bytearray(4 * 1024)
    filesystem[2 * 1024:3 * 1024] = b"hello" + b"S" * (1024 - 5)
    recovered = disks.recover_ext_inode(bytes(inode), bytes(filesystem), block_size=1024)
    assert recovered["deleted"] is True and recovered["data"] == b"hello"
    assert recovered["slack"].startswith(b"S")

    legacy = bytearray(128)
    struct.pack_into("<H", legacy, 0, 0x8000)
    struct.pack_into("<I", legacy, 4, 5)
    struct.pack_into("<I", legacy, 20, 456)
    struct.pack_into("<H", legacy, 26, 0)
    struct.pack_into("<I", legacy, 40, 3)  # first direct block, ext2/3 layout
    filesystem[3 * 1024:4 * 1024] = b"ext3!" + b"L" * (1024 - 5)
    legacy_result = disks.recover_ext_inode(bytes(legacy), bytes(filesystem), block_size=1024)
    assert legacy_result["mapping"] == "legacy" and legacy_result["data"] == b"ext3!"


def _lsb_pixels(message: bytes) -> bytes:
    bits = [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]
    pixels = bytearray()
    for bit in bits:
        pixels += bytes([0x40 | bit, 0x80, 0xC0])
    return bytes(pixels)


def test_video_frame_lsb_difference_tracks_and_plan(tmp_path, capsys):
    message = b"CSCTF{video_fixture}"
    pixels = _lsb_pixels(message)
    frame = video.read_png_frame(_png(len(message) * 8, 1, pixels), "embedded.png")
    candidates = video.frame_lsb_candidates([frame], channels=[0])
    assert candidates[0]["value"] == message.decode()

    bit_count = len(message) * 8
    left = video.Frame(bit_count, 1, 1, b"\0" * bit_count, "left")
    bits = [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]
    right = video.Frame(bit_count, 1, 1, bytes(bits), "right")
    diff = video.interframe_candidates([left, right])
    assert any(row.get("value") == message.decode() for row in diff)

    def box(kind, body):
        return struct.pack(">I4s", len(body) + 8, kind) + body
    hdlr = box(b"hdlr", b"\0" * 8 + b"subt" + b"\0" * 12)
    mp4 = box(b"ftyp", b"isom\0\0\0\0") + box(b"moov", box(b"trak", box(b"mdia", hdlr)))
    tracks = video.hidden_tracks(mp4)
    assert any(row.get("handler") == "subt" for row in tracks)
    assert all("sandbox.py" in row["command"] for row in video.sandbox_plan("movie.mp4"))

    garbage = tmp_path / "bad.png"
    garbage.write_bytes(b"garbage")
    assert video.main(["frames", str(garbage)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("video_stego: ") and "Traceback" not in captured.err


def test_interlaced_png_descriptor_zip_and_indirect_pdf_length():
    # A 1x1 Adam7 image has one scanline in pass 1; its byte layout matches the helper's raw row.
    adam7 = _png(1, 1, b"\x7f", color=0, interlace=1)
    assert repair.repair_png(adam7).status == "valid"

    payload = b"descriptor member payload"
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(payload) + compressor.flush()
    name = b"member.txt"
    local = struct.pack("<I5H3I2H", 0x04034B50, 20, 8, 8, 0, 0, 0, 0, 0, len(name), 0) + name
    descriptor = struct.pack("<IIII", 0x08074B50, binascii.crc32(payload) & 0xFFFFFFFF,
                             len(compressed), len(payload))
    result = repair.repair_zip(local + compressed + descriptor)
    assert result.status == "repaired"
    with zipfile.ZipFile(io.BytesIO(result.candidate)) as archive:
        assert archive.read("member.txt") == payload

    stream = zlib.compress(b"hello indirect length")
    pdf = (b"%PDF-1.4\n"
           b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
           b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
           + f"3 0 obj\n{len(stream)}\nendobj\n".encode()
           + b"4 0 obj\n<< /Length 3 0 R /Filter /FlateDecode >>\nstream\n" + stream
           + b"\nendstream\nendobj\n")
    repaired = repair.repair_pdf(pdf)
    assert repaired.status == "repaired"
    assert repair._validate_pdf_xref(repaired.candidate) == 4


def test_disk_guarded_cli_bad_input(tmp_path, capsys):
    bad = tmp_path / "garbage.img"
    bad.write_bytes(b"garbage")
    assert disks.main(["unwrap", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("disk_images: ") and "Traceback" not in captured.err


def test_round3_forensics_json_switch_after_subcommand(tmp_path, capsys):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"not-a-container")
    assert disks.main(["inspect", str(raw), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "raw-or-unknown"
    assert video.main(["plan", "fixture.mp4", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidates"]

