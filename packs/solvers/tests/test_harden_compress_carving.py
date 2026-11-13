"""File carving vectors produced independently with standard compressors."""
import bz2
import gzip
import io
import lzma
import random
import zipfile
import zlib

import pytest

import carving


PAYLOAD = b'CSCTF{independent_stream}\n' * 8
CODECS = [('gzip', lambda b: gzip.compress(b, mtime=0), gzip.decompress),
          ('zlib', zlib.compress, zlib.decompress),
          ('bzip2', bz2.compress, bz2.decompress),
          ('xz', lzma.compress, lzma.decompress)]


def zipped(payload=PAYLOAD):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        if payload is not None:
            info = zipfile.ZipInfo('payload.txt', (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return stream.getvalue()


@pytest.mark.parametrize(('kind', 'encode', 'decode'), CODECS)
def test_real_compressor_exact_stream_extent(kind, encode, decode):
    encoded = encode(PAYLOAD)
    prefix, suffix = b'prefix\0', b'\0trailing'
    found = carving.carve_all(prefix + encoded + suffix, kinds=[kind])
    assert len(found) == 1
    assert (found[0].kind, found[0].offset, found[0].end) == (kind, len(prefix), len(prefix)+len(encoded))
    assert found[0].data == encoded
    assert decode(found[0].data) == PAYLOAD


def test_zlib_preset_dictionary_and_zip_crc_validation():
    dictionary = b'CSCTF{independent_stream}\n'
    compressor = zlib.compressobj(zdict=dictionary)
    encoded = compressor.compress(PAYLOAD) + compressor.flush()
    assert carving.carve_all(encoded, kinds=['zlib']) == ()
    found = carving.carve_all(encoded, kinds=['zlib'], zlib_dictionaries=[dictionary])
    assert len(found) == 1 and found[0].data == encoded
    decoder = zlib.decompressobj(zdict=dictionary)
    assert decoder.decompress(found[0].data) == PAYLOAD
    archive = zipped()
    found = carving.carve_all(b'pad' + archive + b'end', kinds=['zip'])
    assert len(found) == 1
    assert found[0].offset == 3 and found[0].end == 3+len(archive)
    with zipfile.ZipFile(io.BytesIO(found[0].data)) as decoded:
        assert decoded.read('payload.txt') == PAYLOAD


def test_valid_empty_zip_is_carved():
    archive = zipped(None)
    found = carving.carve_all(archive, kinds=['zip'])
    assert len(found) == 1 and found[0].data == archive


@pytest.mark.parametrize(('kind', 'encode', 'decode'), CODECS)
def test_compressed_bomb_small_output_cap(kind, encode, decode, monkeypatch):
    compressed = encode(b'A' * 4096)
    monkeypatch.setattr(carving, 'MAX_OUTPUT', 32)
    assert carving.carve_all(compressed, kinds=[kind]) == ()


def test_zip_and_scan_caps(monkeypatch):
    archive = zipped(b'A' * 4096)
    monkeypatch.setattr(carving, 'MAX_OUTPUT', 32)
    assert carving.carve_all(archive, kinds=['zip']) == ()
    monkeypatch.setattr(carving, 'MAX_SCAN', 8)
    assert carving.carve_all(gzip.compress(PAYLOAD, mtime=0)) == ()


def test_slack_unallocated_and_polyglot_offsets():
    encoded = gzip.compress(PAYLOAD, mtime=0)
    image = b'A' * 64 + encoded + bytes(128-len(encoded))
    extent = carving.FileExtent(0, 64, len(image), 'example')
    slack = carving.carve_file_slack(image, [extent])
    assert len(slack) == 1 and slack[0].slack_offset == 64
    assert slack[0].carvings[0].data == encoded
    assert slack[0].carvings[0].offset == 64
    unallocated = carving.carve_unallocated(image, [True, False, False], block_size=64)
    assert len(unallocated) == 1
    assert (unallocated[0].start, unallocated[0].end) == (64, 192)
    assert unallocated[0].carvings[0].data == encoded
    appended = bz2.compress(PAYLOAD)
    polyglot = carving.detect_polyglot(encoded + appended)
    assert polyglot.formats == ('gzip', 'bzip2')
    assert polyglot.carvings[1].offset == len(encoded)


@pytest.mark.parametrize('entry', [carving.carve_all, carving.detect_polyglot,
                                 lambda b: carving.carve_file_slack(b, [carving.FileExtent(0, 0, len(b))]),
                                 lambda b: carving.carve_unallocated(b, [False]*len(b), block_size=1)])
def test_malformed_byte_corpus_returns_cleanly(entry):
    rng = random.Random(0x43415256)
    samples = [b'', b'\0'*512, b'\xff'*512]
    samples += [rng.randbytes(n) for n in (1, 4, 16, 256, 4096)]
    archive = zipped()
    samples.extend(archive[:n] for n in range(len(archive)))
    for encoded in [codec[1](PAYLOAD) for codec in CODECS]:
        samples.extend(encoded[:n] for n in range(len(encoded)))
        for _ in range(12):
            changed = bytearray(encoded)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            samples.append(bytes(changed))
    for raw in samples:
        entry(raw)  # This module declares no exception type: clean decline is its contract.


@pytest.mark.parametrize('entry', [carving.carve_all, carving.detect_polyglot,
                                 lambda b: carving.carve_file_slack(b, [carving.FileExtent(0, 0, len(b))]),
                                 lambda b: carving.carve_unallocated(b, [False]*len(b), block_size=1)])
def test_zip_reserved_deflate_block_fails_closed(entry):
    archive = bytearray(zipped())
    archive[30+len('payload.txt')] = 7  # BFINAL=1, reserved BTYPE=3.
    entry(bytes(archive))


@pytest.mark.parametrize(('entry', 'args', 'kwargs'), [
    (carving.carve_all, (b'bad',), {'max_carves': None}),
    (carving.carve_all, (b'bad',), {'kinds': 7}),
    (carving.carve_file_slack, (b'bad', None), {}),
    (carving.carve_unallocated, (b'bad', None), {'block_size': 1}),
    (carving.carve_unallocated, (b'bad', [False]), {'block_size': None})])
def test_bad_public_options_fail_closed(entry, args, kwargs):
    entry(*args, **kwargs)
