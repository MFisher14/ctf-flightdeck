"""Hand-authored MS-CFB mini-stream fixtures validated by independent olefile."""
import io
import random
import struct

import olefile
import pytest

import jumplist as jl
from test_harden_winart_windows import TICKS, closed, lnk_fixture, offline_only


def destlist_fixture(version=1):
    # libyal Jump Lists format section 2.1.2: hostname at 72, entry at 88,
    # FILETIME at 100; path count at 112 (v1) or 128 (v2+).
    path = r'C:\work\fixture.exe'.encode('utf-16-le')
    prefix = bytearray(32)
    struct.pack_into('<II', prefix, 0, version, 1)
    entry = bytearray(114 if version == 1 else 130)
    entry[72:79] = b'LABHOST'
    struct.pack_into('<I', entry, 88, 1)
    struct.pack_into('<Q', entry, 100, TICKS)
    struct.pack_into('<I', entry, 108, 0xFFFFFFFF)
    struct.pack_into('<H', entry, 112 if version == 1 else 128, len(path)//2)
    return bytes(prefix + entry + path + (b'' if version == 1 else b'\0' * 4))


def compound_fixture(streams, version=3):
    """Small valid CFB file, all streams stored in the root mini stream."""
    sector_size = 512 if version == 3 else 4096
    end, free = 0xFFFFFFFE, 0xFFFFFFFF
    header = bytearray(sector_size)
    header[:8] = bytes.fromhex('d0cf11e0a1b11ae1')
    struct.pack_into('<HHHHH', header, 24, 0x3E, version, 0xFFFE, 9 if version == 3 else 12, 6)
    struct.pack_into('<IIIIIIIII', header, 40, 0 if version == 3 else 1, 1, 1, 0, 4096, 2, 1, end, 0)
    struct.pack_into('<109I', header, 76, 0, *([free] * 108))
    fat = [free] * (sector_size//4)
    fat[:4] = [0xFFFFFFFD, end, end, end]
    mini_fat = [free] * (sector_size//4)
    mini_stream = bytearray()
    locations = []
    for name, content in streams.items():
        start = len(mini_stream)//64
        count = (len(content)+63)//64
        for index in range(count):
            mini_fat[start+index] = start+index+1 if index+1 < count else end
        mini_stream.extend(content.ljust(count*64, b'\0'))
        locations.append((name, start, len(content)))
    assert len(mini_stream) <= sector_size
    directory = bytearray(sector_size)
    for index, (name, start, size) in enumerate([('Root Entry', 3, len(mini_stream))] + locations):
        offset = index*128
        encoded = (name+'\0').encode('utf-16-le')
        directory[offset:offset+len(encoded)] = encoded
        struct.pack_into('<HBBIII', directory, offset+64, len(encoded), 5 if index == 0 else 2,
                         1, free, index+1 if 0 < index < len(locations) else free, 1 if index == 0 else free)
        struct.pack_into('<IQ', directory, offset+116, start, size)
    return bytes(header + struct.pack('<%dI' % len(fat), *fat) + directory +
                 struct.pack('<%dI' % len(mini_fat), *mini_fat) + mini_stream.ljust(sector_size, b'\0'))


def test_custom_shortcuts_preserve_order_offsets_and_strings():
    first, second = lnk_fixture('first', tracker=False), lnk_fixture('second', tracker=False)
    data = b'CUSTOM\0\0' + first + second
    report = jl.parse(data, '0123456789abcdef.customDestinations-ms')
    assert report['kind'] == 'custom'
    assert report['app_id'] == '0123456789abcdef'
    assert report['stream_count'] == 2
    assert [entry['offset'] for entry in report['entries']] == [8, 8+len(first)]
    assert [entry['lnk']['description'] for entry in report['entries']] == ['first', 'second']
    assert report['destlist_ok'] is False and report['mru'] is None
    assert jl.classify(first) is None


def test_automatic_cfb_mini_streams_match_olefile():
    streams = {'1': lnk_fixture('automatic', tracker=False), 'DestList': destlist_fixture()}
    data = compound_fixture(streams)
    with olefile.OleFileIO(io.BytesIO(data)) as oracle:
        assert {name: oracle.openstream(name).read() for name in streams} == streams
    report = jl.parse(data, '0123456789abcdef.automaticDestinations-ms')
    assert report['kind'] == 'automatic' and report['stream_count'] == 1
    assert report['entries'][0]['lnk']['description'] == 'automatic'


@pytest.mark.parametrize('version', [1, 3, 4])
def test_published_destlist_metadata_offsets(version):
    data = compound_fixture({'1': lnk_fixture('automatic', tracker=False), 'DestList': destlist_fixture(version)})
    report = jl.parse(data, '0123456789abcdef.automaticDestinations-ms')
    assert report['destlist_ok'] is True and report['mru'] == [1]
    entry = report['entries'][0]
    assert entry['destlist']['path'] == r'C:\work\fixture.exe'
    assert entry['destlist']['hostname'] == 'LABHOST'
    assert entry['destlist']['pinned'] is False
    assert int(entry['destlist']['access_time']) == TICKS


def test_cfb_version4_sector_alignment_matches_olefile():
    streams = {'1': lnk_fixture('v4', tracker=False), 'DestList': destlist_fixture()}
    data = compound_fixture(streams, version=4)
    with olefile.OleFileIO(io.BytesIO(data)) as oracle:
        assert oracle.openstream('1').read() == streams['1']
    report = jl.parse(data, '0123456789abcdef.automaticDestinations-ms')
    assert report is not None and report['entries'][0]['lnk']['description'] == 'v4'


@pytest.mark.parametrize('fn', [jl.classify, jl.parse])
def test_classifier_parser_fuzz_and_input_caps(fn, monkeypatch):
    rng = random.Random(707)
    data = compound_fixture({'1': lnk_fixture('fuzz', tracker=False), 'DestList': destlist_fixture()})
    corpus = [None, {}, '', b'', b'\xff'*1024, b'\0'*1024, b'x'*8193]
    corpus += [rng.randbytes(n) for n in [1, 8, 76, 512, 4096]]
    corpus += [data[:n] for n in [4, 76, 511, 512, 1023, len(data)-1]]
    for offset in [30, 48, 76, 512, 1024, 2048]:
        changed = bytearray(data); changed[offset] ^= 0x80; corpus.append(bytes(changed))
    monkeypatch.setattr(jl, 'MAX_BYTES', 8192)
    for value in corpus:
        closed(fn, value)


def test_cyclic_fat_is_rejected_without_hanging():
    data = bytearray(compound_fixture({'1': lnk_fixture('fuzz', tracker=False)}))
    struct.pack_into('<I', data, 512+4, 1)  # directory FAT chain loops to itself
    assert jl.parse(bytes(data)) is None


def test_cli_missing_arguments_returns_status(capsys):
    assert jl.main([]) == 2
