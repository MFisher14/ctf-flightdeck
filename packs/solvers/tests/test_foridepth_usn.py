"""Independent Microsoft-layout fixtures plus dissect.ntfs 3.16 oracle.

Fixtures use field-order concatenation, not the parser or a parser encoder:
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v4
"""
import io
import random

import pytest
from dissect.ntfs.usnjrnl import UsnJrnl, UsnRecord

import foridepth_usn as engine


EPOCH = 116444736000000000


def le(value, width):
    return value.to_bytes(width, "little", signed=value < 0)


def named_record(version=2, name="CSCTF{journal_λ}.txt", ticks=EPOCH + 1234567,
                 reason=0x80002100, minor=0, extra_header=b""):
    width = 8 if version == 2 else 16
    file_id = (0xabcd << 48) | 0x123456789abc if version == 2 else 0xfedcba98765432100123456789abcdef
    parent_id = (0x8765 << 48) | 5 if version == 2 else 0x112233445566778899aabbccddeeff00
    encoded_name = name.encode("utf-16-le")
    # FileNameOffset is read from the format, never assumed to equal sizeof.
    prefix = b"".join((le(version, 2), le(minor, 2), le(file_id, width),
                       le(parent_id, width), le(8192, 8), le(ticks, 8),
                       le(reason, 4), le(8, 4), le(42, 4), le(0x20, 4)))
    name_offset = 4 + len(prefix) + 4 + len(extra_header)
    body = prefix + le(len(encoded_name), 2) + le(name_offset, 2) + extra_header + encoded_name
    total = (4 + len(body) + 7) // 8 * 8
    return le(total, 4) + body + bytes(total - 4 - len(body))


def extent_record(extents=((4096, 512), (8192, 128)), remaining=1, size=16):
    payload = b"".join(le(off, 8) + le(length, 8) + b"X" * (size - 16)
                       for off, length in extents)
    return b"".join((le(64 + len(payload), 4), le(4, 2), le(0, 2),
                     le(0xfedcba98765432100123456789abcdef, 16),
                     le(0x112233445566778899aabbccddeeff00, 16), le(9000, 8),
                     le(1, 4), le(2, 4), le(remaining, 4), le(len(extents), 2),
                     le(size, 2), payload))


@pytest.mark.parametrize("version", [2, 3])
def test_published_layout_and_non_circular_oracle(version):
    data = named_record(version)
    actual = engine.parse_record(data)
    oracle = UsnRecord(UsnJrnl(io.BytesIO(data)), io.BytesIO(data), 0)
    assert actual["filename"] == oracle.filename == "CSCTF{journal_λ}.txt"
    assert actual["timestamp_raw"] == oracle.TimeStamp == EPOCH + 1234567
    assert actual["timestamp_utc"] == "1970-01-01T00:00:00.1234567Z"
    assert oracle.timestamp_ns == 123456700
    assert actual["usn"] == oracle.Usn == 8192
    assert actual["reason"] == int(oracle.Reason) == 0x80002100
    assert actual["security_id"] == oracle.SecurityId == 42
    assert actual["file_attributes"] == int(oracle.FileAttributes) == 0x20
    assert actual["sources"] == ["CLIENT_REPLICATION_MANAGEMENT"]
    assert actual["reasons"] == ["FILE_CREATE", "RENAME_NEW_NAME", "CLOSE"]
    assert actual["file_reference"]["bits"] == (64 if version == 2 else 128)
    if version == 2:
        assert actual["file_reference"]["value"] == 0xabcd123456789abc
        assert actual["file_reference"]["mft_entry"] == 0x123456789abc
        assert actual["file_reference"]["sequence"] == 0xabcd
        assert actual["parent_reference"]["sequence"] == 0x8765
    else:
        assert actual["file_reference"]["hex"] == "fedcba98765432100123456789abcdef"
        assert actual["file_reference"]["raw_hex"] == "efcdab89674523011032547698badcfe"
        assert "sequence" not in actual["file_reference"]


def test_v4_matches_dissect_without_inventing_filename_or_time():
    data = extent_record()
    actual = engine.parse_record(data)
    oracle = UsnRecord(UsnJrnl(io.BytesIO(data)), io.BytesIO(data), 0)
    assert actual["filename"] is oracle.filename is None
    assert actual["timestamp_raw"] is actual["timestamp_utc"] is None
    assert actual["file_attributes"] is actual["security_id"] is None
    assert actual["remaining_extents"] == oracle.RemainingExtents == 1
    assert actual["extent_size"] == oracle.ExtentSize == 16
    assert [(x["offset"], x["length"]) for x in actual["extents"]] == [
        (x.Offset, x.Length) for x in oracle.extents] == [(4096, 512), (8192, 128)]


def test_extended_filename_offset_not_compile_time_assumption():
    assert engine.parse_record(named_record(3, extra_header=b"\xff" * 8))["filename"] == "CSCTF{journal_λ}.txt"


def test_extent_stride_and_preserved_extension():
    row = engine.parse_record(extent_record(size=24))
    assert [x["offset"] for x in row["extents"]] == [4096, 8192]
    assert row["extents"][0]["extension_hex"] == (b"X" * 8).hex()


def test_mixed_stream_sparse_padding_and_full_identifiers():
    two, three, four = named_record(2), named_record(3), extent_record(remaining=0)
    result = engine.parse_usn(bytes(8192) + two + bytes(32) + four + three + bytes(3))
    assert [x["major_version"] for x in result] == [2, 4, 3]
    assert [x["offset"] for x in result] == [8192, 8192 + len(two) + 32,
                                             8192 + len(two) + 32 + len(four)]
    assert engine.parse_usn(b"") == []
    assert engine.parse_usn(bytes(8193)) == []
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_usn(bytes(8) + two, allow_zero_padding=False)


def test_reused_mft_slot_remains_distinct():
    first = bytearray(named_record())
    second = bytearray(first)
    second[14:16] = le(0xabce, 2)
    rows = engine.parse_usn(first + second)
    assert rows[0]["file_reference"]["mft_entry"] == rows[1]["file_reference"]["mft_entry"]
    assert rows[0]["file_reference"]["value"] != rows[1]["file_reference"]["value"]


def test_unknown_reason_bits_and_absent_time_preserved():
    row = engine.parse_record(named_record(ticks=0, reason=0x10800008))
    assert row["timestamp_raw"] == 0 and row["timestamp_utc"] is None
    assert row["reasons"] == ["INTEGRITY_CHANGE"]
    assert row["unknown_reason_bits"] == 0x10000008


@pytest.mark.parametrize("maker", [named_record, lambda: named_record(3), extent_record])
def test_every_truncation_is_declared_error(maker):
    data = maker()
    for length in range(len(data)):
        with pytest.raises(engine.ForidepthUsnError):
            engine.parse_record(data[:length])


@pytest.mark.parametrize("offset,replacement", [
    (0, le(0, 4)), (0, le(63, 4)), (0, le(0xfffffff8, 4)),
    (4, le(5, 2)), (6, le(1, 2)), (24, le(-1, 8)),
    (32, le(-1, 8)), (32, le(0x7fffffffffffffff, 8)),
    (56, le(3, 2)), (56, le(0xffff, 2)), (58, le(2, 2)),
    (58, le(61, 2)), (58, le(0xfffe, 2)),
    (60, b"\x00\xd8"),  # isolated UTF-16 high surrogate
])
def test_corrupt_named_records(offset, replacement):
    data = bytearray(named_record())
    data[offset:offset + len(replacement)] = replacement
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_usn(named_record() + data)


@pytest.mark.parametrize("offset,replacement", [
    (60, le(0xffff, 2)), (62, le(8, 2)), (62, le(17, 2)),
    (64, le(-1, 8)), (72, le(-1, 8)),
    (64, le(0x7fffffffffffffff, 8)),
])
def test_corrupt_extents(offset, replacement):
    data = bytearray(extent_record())
    data[offset:offset + len(replacement)] = replacement
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_record(data)


def test_limits_and_bad_argument_contract():
    data = named_record()
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_usn(data * 2, max_records=1)
    for value in (None, "bad", 1, {}, [1, 2]):
        with pytest.raises(engine.ForidepthUsnError):
            engine.parse_usn(value)
    for value in (True, 0, -1, 500001, "1", None):
        with pytest.raises(engine.ForidepthUsnError):
            engine.parse_usn(data, max_records=value)
    for value in (-1, 1, "0", True, None, len(data) + 8):
        with pytest.raises(engine.ForidepthUsnError):
            engine.parse_record(data, value)
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_usn(data, allow_zero_padding=1)
    released = memoryview(data)
    released.release()
    with pytest.raises(engine.ForidepthUsnError):
        engine.parse_usn(released)


def test_deterministic_mutations_never_leak_stdlib_exception():
    rng = random.Random(20261105)
    for _ in range(200):
        data = bytearray(named_record(rng.choice((2, 3))) if rng.randrange(2) else extent_record())
        for _ in range(rng.randrange(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            engine.parse_usn(data)
        except engine.ForidepthUsnError:
            pass


def test_file_cli_and_guarded_argparse(tmp_path, capsys, monkeypatch):
    path = tmp_path / "$J"
    path.write_bytes(named_record())
    assert engine.parse_file(path)[0]["usn"] == 8192
    assert engine.main([str(path)]) == 0
    assert '"major_version": 2' in capsys.readouterr().out
    assert engine.main([str(path), "--max-records", "0"]) == 2
    assert engine.main([str(path) + "-missing"]) == 2
    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0
    def raise_string(*args, **kwargs):
        raise SystemExit("bad")
    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", raise_string)
    assert engine.main([]) == 2
