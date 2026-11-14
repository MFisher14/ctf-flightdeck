from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

import brotli
import lz4.frame
import pytest
import snappy
import zstandard

import compression_codecs as C


PAYLOAD = (b"CSCTF compression breadth 2026 | " * 80) + bytes(range(256))


def _streams():
    stream_compressor = snappy.StreamCompressor()
    framed_snappy = stream_compressor.compress(PAYLOAD) + stream_compressor.flush()
    return {
        "gzip": gzip.compress(PAYLOAD, mtime=0),
        "zlib": zlib.compress(PAYLOAD, level=9),
        "bzip2": bz2.compress(PAYLOAD),
        "lzma-xz": lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64),
        "lzma-alone": lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE),
        "brotli": brotli.compress(PAYLOAD, quality=6),
        "lz4": lz4.frame.compress(PAYLOAD, block_checksum=True, content_checksum=True),
        "zstd": zstandard.ZstdCompressor(write_checksum=True, write_content_size=True).compress(PAYLOAD),
        "snappy": snappy.compress(PAYLOAD),
        "snappy-framed": framed_snappy,
        "lzo": C.encode_lzo_literal_frame(b"LZO literal frame"),
        "arithmetic": C.encode_arithmetic_frame(PAYLOAD),
        "range": C.encode_range_frame(PAYLOAD),
    }


@pytest.mark.parametrize(
    ("stream_name", "decoder_name", "expected"),
    [
        ("gzip", "gzip", PAYLOAD),
        ("zlib", "zlib", PAYLOAD),
        ("bzip2", "bzip2", PAYLOAD),
        ("lzma-xz", "lzma", PAYLOAD),
        ("lzma-alone", "lzma", PAYLOAD),
        ("brotli", "brotli", PAYLOAD),
        ("lz4", "lz4", PAYLOAD),
        ("zstd", "zstd", PAYLOAD),
        ("snappy", "snappy", PAYLOAD),
        ("snappy-framed", "snappy-framed", PAYLOAD),
        ("lzo", "lzo", b"LZO literal frame"),
        ("arithmetic", "arithmetic", PAYLOAD),
        ("range", "range", PAYLOAD),
    ],
)
def test_reference_streams_and_corrupt_decline(stream_name, decoder_name, expected):
    stream = _streams()[stream_name]
    got = C.decode_one(stream, decoder_name)
    assert got is not None and got.payload == expected
    # Every format must decline a truncated stream, including the signatureless explicit readers.
    assert C.decode_one(stream[:-1], decoder_name) is None


def test_lzo1x_match_path_and_bounds_decline():
    # Four literals followed by an M2 offset-1, length-3 match, then the canonical end marker.
    stream = bytes((21,)) + b"ABCD" + bytes((0x40, 0x00, 0x11, 0x00, 0x00))
    assert C.decode_lzo1x(stream, expected_size=7) == b"ABCDDDD"
    assert C.decode_lzo1x(stream, expected_size=8) is None
    assert C.decode_lzo1x(stream[:-1], expected_size=7) is None
    assert C.decode_lzo1x(b"\x12A\x40\xff\x11\x00\x00") is None

    # M3: offset four, length three.
    m3 = bytes((21,)) + b"ABCD" + bytes((0x21, 0x0C, 0x00, 0x11, 0x00, 0x00))
    assert C.decode_lzo1x(m3, expected_size=7) == b"ABCDABC"

    # Extended literal run followed by M4's >=0x4000 offset class.
    literals = bytes((index * 29 + 7) & 255 for index in range(16_385))
    m4 = b"\x00" + b"\x00" * 64 + b"\x2f" + literals
    m4 += bytes((0x11, 0x04, 0x00, 0x11, 0x00, 0x00))
    assert C.decode_lzo1x(m4, expected_size=len(literals) + 3) == literals + literals[:3]


def test_entropy_frames_correct_noise_and_crc_decline():
    data = bytes((index * 73 + 19) & 255 for index in range(5000))
    for encode, decode in (
        (C.encode_arithmetic_frame, C.decode_arithmetic),
        (C.encode_range_frame, C.decode_range),
    ):
        frame = encode(data)
        assert decode(frame) == data
        damaged = bytearray(frame)
        damaged[-3] ^= 0x20
        assert decode(damaged) is None
        assert decode(frame, max_output=len(data) - 1) is None


def test_entropy_model_rescale_roundtrip():
    data = bytes(range(256)) * 130  # crosses the adaptive model's 32768-total rescale
    assert C.decode_arithmetic(C.encode_arithmetic_frame(data)) == data
    assert C.decode_range(C.encode_range_frame(data)) == data


def test_auto_detection_uses_only_strong_or_checkable_headers():
    streams = _streams()
    for name in ("gzip", "zlib", "bzip2", "lzma-xz", "lz4", "zstd", "snappy-framed", "lzo", "arithmetic", "range"):
        expected_name = "lzma" if name == "lzma-xz" else name
        got = C.decode_compression(streams[name])
        assert any(item.codec == expected_name for item in got)
    assert C.decode_compression(streams["brotli"]) == []
    assert C.decode_compression(streams["snappy"]) == []
    assert C.decode_compression(streams["brotli"], ["brotli"])[0].payload == PAYLOAD
    assert C.decode_compression(streams["snappy"], ["snappy"])[0].payload == PAYLOAD
    assert C.decode_compression(b"ordinary uncompressed text") == []


def test_output_limits_unknown_names_and_registry_adapter():
    streams = _streams()
    for stream_name, decoder_name in (
        ("gzip", "gzip"), ("zlib", "zlib"), ("bzip2", "bzip2"),
        ("lzma-xz", "lzma"), ("brotli", "brotli"), ("lz4", "lz4"),
        ("zstd", "zstd"), ("snappy", "snappy"), ("snappy-framed", "snappy-framed"),
    ):
        assert C.decode_one(streams[stream_name], decoder_name, max_output=32) is None
    assert C.decode_one(streams["gzip"], "not-a-codec") is None
    assert C.step_fn("not-a-codec") is None
    assert C.step_fn("gzip")(streams["gzip"]) == PAYLOAD
    assert ("gzip", PAYLOAD) in C.steps(streams["gzip"])
