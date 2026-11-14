"""Independent encoders implement published systemd layouts, never engine output.

Reference: https://systemd.io/JOURNAL_FILE_FORMAT/ and JOURNAL_EXPORT_FORMATS/.
Compression bytes come from lzma/lz4/zstandard library producers. Layout offsets
are deliberately literal here rather than imported from the parser under test.
"""
import json
import lzma
import random
import struct

import lz4.block
import pytest
import zstandard

import foridepth_journal as journal


def fixture(compact=False, codec=0, orphan=False, chain=False, unknown_object=False,
            compressed_suffix=b"", zstd_unknown_size=False):
    image = bytearray(264)
    offsets = {}
    number = 0
    tail = 0

    def append(kind, payload, flags=0):
        nonlocal number, tail
        image.extend(b"\0" * (-len(image) % 8))
        tail = len(image)
        image.extend(struct.pack("<BB6xQ", kind, flags, len(payload) + 16) + payload)
        number += 1
        return tail

    for label, value in [("one", b"MESSAGE=CSCTF{journal_field}"),
                         ("two", b"MESSAGE=second\nline\xff"),
                         ("unit", b"_SYSTEMD_UNIT=sshd.service")]:
        if codec == 1:
            value = lzma.compress(value, format=lzma.FORMAT_XZ)
        elif codec == 2:
            value = struct.pack("<Q", len(value)) + lz4.block.compress(value, store_size=False)
        elif codec == 4:
            value = zstandard.ZstdCompressor(write_content_size=not zstd_unknown_size).compress(value)
        if codec:
            value += compressed_suffix
        offsets[label] = append(1, bytes(56 if compact else 48) + value, codec)

    def entry(seq):
        body = struct.pack("<QQQ16sQ", seq, 1_700_000_000_123_456, 12_345, bytes(range(16)), 0)
        for name in ("one", "two", "unit"):
            body += struct.pack("<I" if compact else "<QQ", *([offsets[name]] if compact else [offsets[name], 0]))
        return append(3, body)

    offsets["entry"] = entry(7)
    if orphan:
        offsets["orphan"] = entry(999)
    if chain:
        offsets["entry2"] = entry(8)
    if unknown_object:
        append(99, b"future-compatible-object")
    fmt = "<I" if compact else "<Q"
    offsets["array"] = append(6, bytes(8) + struct.pack(fmt, offsets["entry"]))
    if chain:
        offsets["array2"] = append(6, bytes(8) + struct.pack(fmt, offsets["entry2"]) + struct.pack(fmt, 0))
        struct.pack_into("<Q", image, offsets["array"] + 16, offsets["array2"])
    image.extend(b"slack is not an object" * 8)
    image[:8] = b"LPKSHHRH"
    struct.pack_into("<II", image, 8, 2, (16 if compact else 0) | {0: 0, 1: 1, 2: 2, 4: 8}[codec])
    image[16] = 2
    image[24:40] = bytes(range(16))
    image[40:56] = bytes(range(16, 32))
    struct.pack_into("<QQ", image, 88, 264, len(image) - 264)
    struct.pack_into("<QQQ", image, 136, tail, number, 2 if chain else 1)
    struct.pack_into("<Q", image, 176, offsets["array"])
    return bytes(image), offsets


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("codec", [0, 1, 2, 4])
def test_published_layout_and_independent_codec_producers(compact, codec):
    data, _ = fixture(compact, codec)
    result = journal.parse_journal(data)
    assert result["compact"] is compact
    assert result["hashes_verified"] is False
    assert result["machine_id"] == "101112131415161718191a1b1c1d1e1f"
    [entry] = result["entries"]
    assert entry["seqnum"] == 7
    assert entry["realtime_us"] == 1_700_000_000_123_456
    assert entry["monotonic_us"] == 12_345
    assert entry["boot_id"] == "000102030405060708090a0b0c0d0e0f"
    assert entry["fields"] == {"MESSAGE": [b"CSCTF{journal_field}", b"second\nline\xff"],
                                "_SYSTEMD_UNIT": [b"sshd.service"]}


@pytest.mark.parametrize("compact", [False, True])
def test_committed_index_excludes_orphan_and_follows_chain(compact):
    data, _ = fixture(compact, orphan=True, chain=True, unknown_object=True)
    assert [row["seqnum"] for row in journal.parse_journal(data)["entries"]] == [7, 8]


def overwrite(data, at, fmt, value):
    result = bytearray(data)
    struct.pack_into(fmt, result, at, value)
    return bytes(result)


@pytest.mark.parametrize("kind", ["cycle", "wrong_type", "interior", "count", "tail", "flags", "short_object", "header", "mixed_codec", "undeclared_codec"])
def test_bad_structures_fail_closed(kind):
    data, off = fixture()
    changes = {
        "cycle": (off["array"] + 16, "<Q", off["array"]),
        "wrong_type": (off["array"] + 24, "<Q", off["one"]),
        "interior": (off["entry"] + 64, "<Q", off["one"] + 8),
        "count": (152, "<Q", 2),
        "tail": (136, "<Q", off["array"] + 8),
        "flags": (12, "<I", 32),
        "short_object": (off["one"] + 8, "<Q", 32),
        "header": (88, "<Q", 200),
        "mixed_codec": (off["one"] + 1, "B", 3),
        "undeclared_codec": (off["one"] + 1, "B", 1),
    }
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_journal(overwrite(data, *changes[kind]))


@pytest.mark.parametrize("codec", [1, 2, 4])
def test_compression_rejects_truncated_and_oversized(codec, monkeypatch):
    data, off = fixture(codec=codec)
    size = struct.unpack_from("<Q", data, off["one"] + 8)[0]
    # A shorter first object still gets rejected (codec or subsequent framing).
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_journal(overwrite(data, off["one"] + 8, "<Q", size - 1))
    monkeypatch.setattr(journal, "MAX_FIELD", 12)
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_journal(data)


def test_xz_and_zstd_reject_trailing_frame_bytes():
    for codec in (1, 4):
        with pytest.raises(journal.ForidepthJournalError):
            journal.parse_journal(fixture(codec=codec, compressed_suffix=b"garbage")[0])


def test_zstd_frame_without_declared_content_size():
    data, _ = fixture(compact=True, codec=4, zstd_unknown_size=True)
    assert journal.parse_journal(data)["entries"][0]["fields"]["_SYSTEMD_UNIT"] == [b"sshd.service"]


def test_resource_limits_are_atomic(monkeypatch):
    data, _ = fixture()
    monkeypatch.setattr(journal, "MAX_TOTAL", 10)
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_journal(data)
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_export(b"MESSAGE=12345678901\n\n")


def test_binary_export_manual_reference_encoding():
    # Published wire grammar, literal little-endian 64-bit length, no engine encoder.
    blob = (b"__CURSOR=s=abc;i=1\n__REALTIME_TIMESTAMP=1700000000000000\n"
            b"MESSAGE=first\nMESSAGE\n\x09\0\0\0\0\0\0\0a\nb\x00\xff\nxyz\n\n"
            b"_SYSTEMD_UNIT=cron.service\nEMPTY\n\0\0\0\0\0\0\0\0\n\n")
    result = journal.parse_export(blob)
    assert len(result["entries"]) == 2
    assert result["entries"][0]["fields"]["MESSAGE"] == [b"first", b"a\nb\0\xff\nxyz"]
    assert result["entries"][1]["fields"]["EMPTY"] == [b""]


@pytest.mark.parametrize("data", [b"MESSAGE=a\n", b"MESSAGE=a", b"MESSAGE\n", b"MESSAGE\n\xff" * 8,
                                  b"MESSAGE\n\x01\0\0\0\0\0\0\0x!\n", b"bad=field\n\n",
                                  b"MESSAGE=bad\xff\n\n", b"MESSAGE=bad\x00\n\n", b"\n"])
def test_malformed_export(data):
    with pytest.raises(journal.ForidepthJournalError):
        journal.parse_export(data)


def test_malformed_inputs_never_leak_builtin_exceptions():
    rng = random.Random(8237)
    for data in [None, "text", [], 1, {}, *[rng.randbytes(n) for n in range(400)]]:
        for parser in (journal.parse_journal, journal.parse_export):
            try:
                parser(data)
            except journal.ForidepthJournalError:
                pass


def test_cli_guards_and_json_binary(tmp_path, capsys):
    assert journal.main(["--help"]) == 0
    assert journal.main([]) == 2
    assert journal.main([str(tmp_path / "missing")]) == 2
    assert journal.main(["bad\x00path"]) == 2
    path = tmp_path / "system.journal"
    path.write_bytes(fixture(compact=True)[0])
    capsys.readouterr()
    assert journal.main([str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["entries"][0]["fields"]["MESSAGE"] == ["CSCTF{journal_field}", {"base64": "c2Vjb25kCmxpbmX/"}]
