"""Independent compressor vectors and bounded malformed-stream probes.

Oracles: stdlib gzip/zlib/bz2/lzma; installed brotli/lz4/zstandard/snappy.
LZO literal stream follows the LZO1X literal count + 11 00 00 EOF grammar.
R5 arithmetic/range fixtures use a manually derived uniform first-symbol
interval (A -> bits 01000001, followed by finalization bits 01).
No engine encoder supplies expected decoder output.
"""
import bz2
import gzip
import lzma
import random
import struct
import zlib

import brotli
import lz4.frame
import pytest
import snappy
import zstandard

import compression_codecs as codec


PAYLOAD = b'CSCTF{reference_compressors}\0' + bytes(range(256)) * 4
COMPRESSORS = {
    'gzip': lambda value: gzip.compress(value, mtime=0),
    'zlib': zlib.compress,
    'bzip2': bz2.compress,
    'lzma': lzma.compress,
    'brotli': brotli.compress,
    'lz4': lambda value: lz4.frame.compress(value, content_checksum=True),
    'zstd': lambda value: zstandard.ZstdCompressor(write_checksum=True).compress(value),
    'snappy': snappy.compress,
    'snappy-framed': lambda value: snappy.StreamCompressor().add_chunk(value),
}


def literal_lzo(value):
    return bytes([17 + len(value)]) + value + b'\x11\0\0'


def literal_lzo_frame(value):
    return struct.pack('>6sII', b'R5LZO1', len(value), zlib.crc32(value)) + literal_lzo(value)


def entropy_frame(magic):
    return struct.pack('>5sIII', magic, 1, zlib.crc32(b'A'), 10) + bytes.fromhex('41 40')


VECTORS = {name: (compress(PAYLOAD), PAYLOAD) for name, compress in COMPRESSORS.items()}
VECTORS.update({'lzo': (literal_lzo_frame(b'CSCTF{LZO}'), b'CSCTF{LZO}'),
                'arithmetic': (entropy_frame(b'R5AC1'), b'A'),
                'range': (entropy_frame(b'R5RC1'), b'A')})


@pytest.mark.parametrize('name', list(VECTORS))
def test_exact_payload_real_compressor_or_independent_frame(name):
    compressed, expected = VECTORS[name]
    decoder = codec.DECODERS[name]
    for value in [compressed, bytearray(compressed), memoryview(compressed)]:
        assert decoder(value, max_output=len(expected)) == expected
    result = codec.decode_one(compressed, name, max_output=len(expected))
    assert result.codec == name and result.payload == expected
    assert result.checked_by
    assert codec.step_fn(name)(compressed) == expected
    candidates = codec.decode_compression(compressed, names=[name])
    assert [(candidate.codec, candidate.payload) for candidate in candidates] == [(name, expected)]


@pytest.mark.parametrize('name', list(COMPRESSORS))
def test_small_explicit_output_cap_stops_compressible_payload(name):
    compressed = COMPRESSORS[name](b'A' * 8192)
    assert codec.DECODERS[name](compressed, max_output=16) is None
    assert codec.decode_one(compressed, name, max_output=16) is None
    assert codec.decode_compression(compressed, names=[name], max_output=16) == []


@pytest.mark.parametrize('name', list(VECTORS))
def test_zero_and_just_too_small_output_caps(name):
    compressed, expected = VECTORS[name]
    assert codec.DECODERS[name](compressed, max_output=0) is None
    assert codec.DECODERS[name](compressed, max_output=len(expected) - 1) is None


def test_lzo_raw_and_encoder_against_handbuilt_literal_bytes():
    value = b'CSCTF{literal}'
    stream = literal_lzo(value)
    assert codec.decode_lzo1x(stream, expected_size=len(value)) == value
    assert codec.decode_lzo1x(stream, expected_size=len(value) + 1) is None
    assert codec.decode_lzo1x(stream, max_output=4) is None
    assert codec.encode_lzo_literal_frame(value) == literal_lzo_frame(value)


def test_manual_first_symbol_arithmetic_and_range_encoding():
    assert codec.encode_arithmetic_frame(b'A') == entropy_frame(b'R5AC1')
    assert codec.encode_range_frame(b'A') == entropy_frame(b'R5RC1')


def test_lzma_alone_and_multichunk_incompressible_stream():
    alone = lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE)
    assert codec.decode_lzma(alone) == PAYLOAD
    data = random.Random(815).randbytes(140000)
    for compress, decoder in [(bz2.compress, codec.decode_bzip2), (lzma.compress, codec.decode_lzma)]:
        stream = compress(data)
        assert len(stream) > 65536
        assert decoder(stream, max_output=len(data)) == data
        assert decoder(stream, max_output=1024) is None


@pytest.mark.parametrize('name', list(COMPRESSORS))
def test_concatenated_stream_policy_and_trailer_rejection(name):
    stream, expected = VECTORS[name]
    result = codec.DECODERS[name](stream + stream)
    # Snappy permits repeated identifier chunks within a framed stream.
    assert result == (expected * 2 if name == 'snappy-framed' else None)
    assert codec.DECODERS[name](stream + b'INVALID_TRAILER') is None


def test_auto_detection_strong_signatures_and_unknown_codec():
    for name in ['gzip', 'zlib', 'bzip2', 'lzma', 'lz4', 'zstd', 'snappy-framed', 'lzo', 'arithmetic', 'range']:
        stream, expected = VECTORS[name]
        assert (name, expected) in codec.steps(stream)
    assert codec.decode_one(b'anything', 'unknown') is None
    assert codec.step_fn('unknown') is None
    assert codec.decode_compression(b'') == []


@pytest.mark.parametrize('name', list(VECTORS))
def test_deterministic_empty_random_ff_truncated_and_bitflipped(name):
    stream, _ = VECTORS[name]
    rng = random.Random(0x434f4445)
    samples = [b'', b'\xff' * 1024, None, '', 13, [], {}]
    samples += [rng.randbytes(n) for n in range(0, 80, 3)]
    samples += [stream[:n] for n in range(0, len(stream), max(1, len(stream) // 12))]
    for index in range(min(24, len(stream))):
        changed = bytearray(stream)
        changed[index] ^= 1 << (index % 8)
        samples.append(bytes(changed))
    for sample in samples:
        result = codec.DECODERS[name](sample, max_output=4096)
        assert result is None or isinstance(result, bytes) and 0 < len(result) <= 4096


def test_raw_lzo_fuzz_and_all_decoder_input_cap(monkeypatch):
    stream = literal_lzo(b'CSCTF{LZO}')
    for index in range(len(stream)):
        result = codec.decode_lzo1x(stream[:index], max_output=64)
        assert result is None
    monkeypatch.setattr(codec, 'MAX_INPUT', 8)
    for decoder in list(codec.DECODERS.values()) + [codec.decode_lzo1x]:
        assert decoder(b'\xff' * 9) is None
    assert codec.decode_compression(b'\xff' * 9) == []


@pytest.mark.parametrize('name', ['gzip', 'zlib', 'bzip2', 'lzma', 'lz4', 'zstd', 'snappy-framed'])
def test_corrupted_checksums_are_rejected(name):
    stream, _ = VECTORS[name]
    bad = bytearray(stream)
    # Framed Snappy CRC32C follows its ten-byte identifier and chunk header;
    # bzip2's block CRC follows BZhN + six-byte block magic.
    index = 14 if name == 'snappy-framed' else 10 if name == 'bzip2' else len(stream) - 1
    bad[index] ^= 1
    assert codec.DECODERS[name](bad) is None


def test_released_memoryview_is_fail_closed():
    view = memoryview(b'abc')
    view.release()
    assert codec.decode_gzip(view) is None


def test_noninteger_output_limit_is_fail_closed():
    assert codec.decode_gzip(VECTORS['gzip'][0], max_output='bad') is None


def test_lzma_overflowing_output_limit_is_fail_closed():
    assert codec.decode_lzma(VECTORS['lzma'][0], max_output=1 << 80) is None


def test_nonstring_codec_name_is_fail_closed():
    assert codec.decode_one(VECTORS['gzip'][0], []) is None
