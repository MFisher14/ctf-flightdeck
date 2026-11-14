"""Independent LRZI layout vectors and deterministic fail-closed mutations.

Oracles (no lrzip execution or engine-generated fixture):
* https://github.com/ckolivas/lrzip/blob/v0.631/lrzip.c#L129-L245
* https://github.com/ckolivas/lrzip/blob/v0.631/doc/magic.header.txt
* https://github.com/ckolivas/lrzip/blob/3a849ef9529593b5993331fcc43fbe1167338c43/doc/magic.header.txt
* Python/liblzma's properties parser for LZMA lc/lp/pb/dictionary fields.

The legacy document's 6..14 size range is an off-by-one typo; the C writer
and reader use memcpy(..., 8) at offset 6. The vectors lock that behavior.
"""
import argparse
import hashlib
import json
import lzma
import random
import struct

import pytest

import ff_lrzip_header as engine


def _header(*, minor=6, size=0x0102030405060708, props=b"\x5d\x00\x00\x80\x00",
            checksum=1, encryption=0, salt=b"\x12\x04ABCDEF",
            streaming=0, last=1):
    """Hand-written source-layout builder, independent of the engine."""
    result = bytearray(24)
    result[0:6] = bytes((76, 82, 90, 73, 0, minor))
    if encryption:
        result[6:14] = salt
    elif minor < 4:
        result[6:14] = struct.pack(">II", size & 0xffffffff, size >> 32)
    else:
        result[6:14] = struct.pack("<Q", size)
    result[16:21] = props
    result[21:23] = bytes((checksum, encryption))
    if minor == 7:
        result[14] = streaming
        result[23] = last
    return bytes(result)


def _aead_header(iterations=600_000):
    salt = b"0123456789abcdef"
    descriptor = (bytes((1, 16)) + struct.pack("<I", iterations) + b"\0\0"
                  + salt + b"\0" * 8)
    return _header(minor=7, encryption=3, salt=salt[:8]) + descriptor


def _replace(data, offset, value):
    return data[:offset] + bytes((value,)) + data[offset + 1:]


def test_literal_v06_source_layout():
    # Literal fixed vector: this is not produced by a parser/encoder round trip.
    wire = bytes.fromhex("4c525a490006080706050403020100005d00008000010000")
    result = engine.parse_header(wire)
    assert result["version"] == "0.6"
    assert result["header_size"] == result["data_offset"] == 24
    assert result["declared_uncompressed_size"] == 0x0102030405060708
    assert result["raw_uncompressed_size"] == 0x0102030405060708
    assert result["size_encoding"] == "little-endian-u64"
    assert result["appended_md5_declared"] is True
    assert result["checksum_verified"] is False
    assert result["encrypted"] is False
    assert result["compression_backend"] is None
    assert result["compressed_size"] is None
    assert result["header_sha256"] == hashlib.sha256(wire).hexdigest()


@pytest.mark.parametrize("minor", [2, 3, 4, 5, 6, 7])
def test_size_endianness_per_source_version(minor):
    wire = _header(minor=minor, checksum=int(minor >= 5))
    result = engine.parse_header(wire)
    assert result["version"] == f"0.{minor}"
    assert result["declared_uncompressed_size"] == 0x0102030405060708
    assert result["size_status"] == "declared"


@pytest.mark.parametrize("size", [1, 0xffffffff, 0x100000000, (1 << 63) - 1])
def test_size_boundaries(size):
    assert engine.parse_header(_header(size=size))["declared_uncompressed_size"] == size


@pytest.mark.parametrize("properties", [b"\x5d\x00\x00\x80\x00", b"\x04\x00\x00\x10\x00",
                                        b"\x51\x00\x10\x00\x00", b"\x5d\x00\x00\x00\x00"])
def test_properties_against_real_liblzma(properties):
    oracle = lzma._decode_filter_properties(lzma.FILTER_LZMA1, properties)
    result = engine.parse_header(_header(props=properties))
    fields = result["lzma_properties"]
    for name in ("lc", "lp", "pb"):
        assert fields[name] == oracle[name]
    assert fields["dictionary_size"] == oracle["dict_size"]
    assert result["lzma_properties_hex"] == properties.hex()
    assert result["compression_backend"] is None  # Properties do not establish every block's type.


def test_lzma_sdk_minimum_dictionary_metadata():
    # LzmaDec.c:LzmaProps_Decode normalizes dictionaries below LZMA_DIC_MIN.
    # This differs from liblzma's raw property extractor; neither allocates here.
    fields = engine.parse_header(_header(props=b"\x5d\0\0\0\0"))["lzma_properties"]
    assert fields["dictionary_size"] == 0
    assert fields["decoder_dictionary_size"] == 4096


def test_absent_and_ignored_properties_are_not_backend_ids():
    for props in (b"\0" * 5, b"\0\x12\x34\x56\x78"):
        result = engine.parse_header(_header(props=props, checksum=0))
        assert result["lzma_properties"] is None
        assert result["lzma_properties_used_by_reference"] is False
        assert result["compression_backend"] is None
        assert result["appended_md5_declared"] is False


def test_zero_size_is_unspecified_not_proven_empty():
    result = engine.parse_header(_header(size=0))
    assert result["raw_uncompressed_size"] == 0
    assert result["declared_uncompressed_size"] is None
    assert result["size_status"] == "unspecified"


def test_legacy_encryption_replaces_size_with_salt():
    result = engine.parse_header(_header(encryption=1))
    assert result["encrypted"] is True
    assert result["encryption_mode"] == 1
    assert result["encryption"] == "AES-128-CBC / SHA-512 KDF"
    assert result["size_encoding"] == "salt"
    assert result["size_status"] == "encrypted"
    assert result["raw_uncompressed_size"] is None
    assert result["declared_uncompressed_size"] is None
    assert result["salt_prefix_hex"] == "1204414243444546"
    assert result["legacy_kdf_loops"] == 1_048_576
    assert result["crypto_descriptor"] is None


@pytest.mark.parametrize("streaming,last", [(0, 1), (1, 0), (1, 1)])
def test_v07_streaming_flag_combinations(streaming, last):
    result = engine.parse_header(_header(minor=7, streaming=streaming, last=last))
    assert result["streaming"] is bool(streaming)
    assert result["first_block_is_last"] is bool(last)


def test_v07_aead_crypto_descriptor_layout():
    wire = _aead_header()
    result = engine.parse_header(b"prefix" + wire + b"UNEXAMINED", offset=6)
    assert result["header_offset"] == 6
    assert result["header_size"] == 56
    assert result["data_offset"] == 62
    assert result["encryption_mode"] == 3
    assert result["declared_uncompressed_size"] is None
    assert result["header_sha256"] == hashlib.sha256(wire).hexdigest()
    assert result["crypto_descriptor"] == {
        "offset": 30, "size": 32, "suite_id": 1, "kdf": "PBKDF2-HMAC-SHA512",
        "iterations": 600_000, "salt_hex": "30313233343536373839616263646566",
    }
    assert result["payload_examined"] is False
    assert result["validation_scope"] == "header_only"


@pytest.mark.parametrize("iterations", [1, 5_000_000])
def test_aead_iteration_bounds(iterations):
    assert engine.parse_header(_aead_header(iterations))["crypto_descriptor"]["iterations"] == iterations


def test_non_metadata_payload_is_ignored():
    header = _header()
    assert engine.parse_header(header) == engine.parse_header(header + b"\xff" * 100_000)


@pytest.mark.parametrize("value", [None, "LRZI", bytearray(24), memoryview(b"\0" * 24), 42, []])
def test_wrong_data_types_fail_closed(value):
    with pytest.raises(engine.LRZIPError):
        engine.parse_header(value)


@pytest.mark.parametrize("offset", [None, True, 0.0, -1, 25, 1 << 100, "0"])
def test_invalid_offsets_fail_closed(offset):
    with pytest.raises(engine.LRZIPError):
        engine.parse_header(_header(), offset)


def test_every_header_truncation_fails_closed():
    for wire in (_header(), _aead_header()):
        for length in range(len(wire)):
            with pytest.raises(engine.LRZIPError):
                engine.parse_header(wire[:length])


def test_invalid_field_combinations_fail_closed():
    invalid = [
        _replace(_header(), 0, 0), _replace(_header(), 4, 1),
        _replace(_header(), 5, 8), _replace(_header(), 5, 0),
        _replace(_header(), 21, 2), _replace(_header(), 22, 2),
        _replace(_header(), 16, 225), _header(minor=4, checksum=1),
        _header(minor=5, encryption=1), _header(encryption=3),
        _header(size=1 << 63), _header(minor=3, size=1 << 63, checksum=0),
        _header(encryption=1, salt=b"\x29\x04ABCDEF"),
        _header(encryption=1, salt=b"\x00\x00ABCDEF"),
        _header(minor=7, streaming=0, last=0), _header(minor=7, streaming=2),
        _replace(_header(minor=7), 15, 1), _header(minor=7, last=2),
        _replace(_aead_header(), 24, 2), _replace(_aead_header(), 25, 8),
        _replace(_aead_header(), 30, 1), _replace(_aead_header(), 55, 1),
        _replace(_aead_header(), 32, 1), _aead_header(0), _aead_header(5_000_001),
    ]
    for wire in invalid:
        with pytest.raises(engine.LRZIPError):
            engine.parse_header(wire)


def test_deterministic_fail_closed_fuzz():
    rng = random.Random(0x4c525a49)
    corpus = [b"", b"\xff" * 100, b"LRZI" + b"\xff" * 100]
    for length in range(101):
        corpus.append(rng.randbytes(length))
        corpus.append(b"LRZI" + rng.randbytes(length))
    for wire in (_header(), _aead_header()):
        for index in range(len(wire)):
            for bit in range(8):
                corpus.append(_replace(wire, index, wire[index] ^ (1 << bit)))
    for wire in corpus:
        try:
            result = engine.parse_header(wire)
        except engine.LRZIPError:
            pass
        else:
            assert result["validation_scope"] == "header_only"
            assert result["payload_examined"] is False


def test_cli_json_and_embedded_aead(tmp_path, capsys):
    archive = tmp_path / "header.lrz"
    archive.write_bytes(b"pre" + _aead_header() + b"\xff" * 100_000)
    assert engine.main([str(archive), "--offset", "3"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["header_offset"] == 3
    assert result["data_offset"] == 59
    assert result["crypto_descriptor"]["offset"] == 27
    assert result["source_file_size"] == 100_059


def test_cli_reads_at_most_56_bytes(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "huge.lrz"
    archive.write_bytes(_header() + b"X" * 1_000_000)
    original_open = engine.Path.open
    reads = []

    class Spy:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.file.close()

        def fileno(self):
            return self.file.fileno()

        def seek(self, offset):
            return self.file.seek(offset)

        def read(self, count):
            reads.append(count)
            return self.file.read(count)

    monkeypatch.setattr(engine.Path, "open", lambda self, *args: Spy(original_open(self, *args)))
    assert engine.main([str(archive)]) == 0
    assert reads == [56]
    capsys.readouterr()


def test_cli_errors_return_codes(tmp_path, capsys):
    archive = tmp_path / "bad.lrz"
    archive.write_bytes(b"LRZI")
    for args in ([], [str(archive)], [str(archive), "--offset", "-1"],
                 [str(archive), "--offset", str(1 << 100)], [str(tmp_path)],
                 [str(tmp_path / "missing")], ["\0"], ["--unknown"]):
        assert engine.main(args) == 2
    assert engine.main(["--help"]) == 0
    capsys.readouterr()


def test_cli_noninteger_systemexit_guard(monkeypatch):
    def stop(*args, **kwargs):
        raise SystemExit("noninteger")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", stop)
    assert engine.main([]) == 2
