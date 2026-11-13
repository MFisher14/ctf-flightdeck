"""Independent fontTools/spec vectors for the new structural font inspector."""
import gzip
import io
import random
import struct
import sys
import zlib
from dataclasses import replace

import brotli
import pytest
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont, TTCollection, newTable
from fontTools.ttLib.sfnt import calcChecksum, WOFFFlavorData
from fontTools.ttLib.woff2 import WOFF2FlavorData

import ff_woff_inspect as engine


def font(extra=None):
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder(['.notdef', 'A'])
    empty = TTGlyphPen(None).glyph()
    pen = TTGlyphPen(None)
    pen.moveTo((100, 0)); pen.lineTo((500, 700)); pen.lineTo((900, 0)); pen.closePath()
    fb.setupGlyf({'.notdef': empty, 'A': pen.glyph()})
    fb.setupHorizontalMetrics({'.notdef': (1000, 0), 'A': (1000, 100)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupCharacterMap({65: 'A'})
    fb.setupNameTable({'familyName': 'Reference', 'styleName': 'Regular',
                       'uniqueFontIdentifier': 'Reference Regular', 'fullName': 'Reference Regular',
                       'psName': 'Reference-Regular', 'version': 'Version 1.0'})
    fb.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
    fb.setupPost()
    fb.setupMaxp()
    fb.font['head'].created = fb.font['head'].modified = 3800000000
    for tag, data in (extra or {}).items():
        table = newTable(tag)
        # Unknown-tag DefaultTable is deliberately used for uninterpreted data.
        if hasattr(table, 'data') or tag == 'zzZZ':
            table.data = data
        else:
            from fontTools.ttLib.tables.DefaultTable import DefaultTable
            table = DefaultTable(tag); table.data = data
        fb.font[tag] = table
    return fb.font


def saved(f, flavor=None, metadata=None, private=None):
    f.flavor = flavor
    if flavor:
        cls = WOFF2FlavorData if flavor == 'woff2' else WOFFFlavorData
        f.flavorData = cls()
        f.flavorData.metaData = metadata
        f.flavorData.privData = private
    out = io.BytesIO(); f.save(out)
    return out.getvalue()


def checksum_reference(data, tag):
    if tag == 'head':
        data = data[:8] + b'\0' * 4 + data[12:]
    return calcChecksum(data)


def woff_private():
    # WOFF1 section3/4: independently hand-written one-table file, gap, private block.
    payload = b'CSCTF{private_table}'
    private = b'CSCTF{private_block}'
    offset = 64
    gap = b'GAP!'
    priv_offset = (offset + len(payload) + 3) & ~3
    priv_offset += len(gap)
    sfnt_size = 12 + 16 + ((len(payload) + 3) & ~3)
    header = struct.pack('>4s4sIHHIHHIIIII', b'wOFF', b'\0\1\0\0',
                         priv_offset + len(private), 1, 0, sfnt_size, 1, 0, 0, 0, 0,
                         priv_offset, len(private))
    directory = struct.pack('>4sIIII', b'zzZZ', offset, len(payload), len(payload), calcChecksum(payload))
    return header + directory + payload + b'\0' * (-len(payload) % 4) + gap + private


def sfnt_raw(tables, offsets=None):
    # OpenType table directory constructed by hand, no engine encoder used.
    count = len(tables)
    header = b'\0\1\0\0' + struct.pack('>HHHH', count, 0, 0, 0)
    cursor = 12 + count * 16
    output = bytearray(cursor)
    output[:12] = header
    for i, (tag, raw) in enumerate(tables.items()):
        off = offsets[i] if offsets else cursor
        output[12 + i * 16:28 + i * 16] = struct.pack('>4sIII', tag.encode('ascii'),
                            checksum_reference(raw, tag), off, len(raw))
        if len(output) < off + len(raw):
            output.extend(b'\0' * (off + len(raw) - len(output)))
        output[off:off + len(raw)] = raw
        cursor = (off + len(raw) + 3) & ~3
        if len(output) < cursor:
            output.extend(b'\0' * (cursor - len(output)))
    return bytes(output)


@pytest.mark.parametrize('flavor', [None, 'woff', 'woff2'])
def test_fonttools_roundtrip_tables_and_checksums(flavor):
    raw = saved(font({'zzZZ': b'CSCTF{font_private}'}), flavor)
    oracle = TTFont(io.BytesIO(raw), recalcBBoxes=False, recalcTimestamp=False)
    report = engine.inspect_font(raw)
    assert report['format'] == {None: 'SFNT', 'woff': 'WOFF', 'woff2': 'WOFF2'}[flavor]
    entries = {t['tag']: t for t in report['fonts'][0]['tables']}
    assert set(entries) == set(oracle.reader.keys())
    assert entries['zzZZ']['private_candidate'] is True
    assert entries['zzZZ']['flags'] == ['CSCTF{font_private}']
    for tag, table in entries.items():
        if table.get('transformed'):
            assert table['checksum']['actual'] is None
        else:
            assert table['checksum']['actual'] == checksum_reference(oracle.reader[tag], tag)
            assert table['checksum']['valid'] is (None if flavor == 'woff2' else True)
    if flavor == 'woff2':
        assert entries['glyf']['transformed'] is True
        assert entries['loca']['stored_length'] == 0
        assert report['transform_reconstruction'] is False


@pytest.mark.parametrize('flavor', ['woff', 'woff2'])
def test_fonttools_metadata_and_private(flavor):
    metadata = b'<?xml version="1.0"?><metadata version="1.0"><description>CSCTF{metadata}</description></metadata>'
    private = b'CSCTF{private}'
    raw = saved(font(), flavor, metadata, private)
    report = engine.inspect_font(raw)
    assert report['metadata']['length'] == len(metadata)
    assert report['metadata']['flags'] == ['CSCTF{metadata}']
    assert report['private']['length'] == len(private)
    assert report['private']['flags'] == ['CSCTF{private}']


def test_handwritten_woff_private_and_nonzero_gap():
    report = engine.inspect_font(woff_private())
    assert report['private']['flags'] == ['CSCTF{private_block}']
    assert report['fonts'][0]['tables'][0]['flags'] == ['CSCTF{private_table}']
    assert report['fonts'][0]['tables'][0]['checksum']['valid'] is True
    assert any(not gap['zero_padding'] for gap in report['gaps'])


def test_ttc_all_fonts_and_shared_tables():
    collection = TTCollection()
    collection.fonts = [font({'zzZZ': b'CSCTF{first}'}), font({'zzZZ': b'CSCTF{second}'})]
    out = io.BytesIO(); collection.save(out, shareTables=True)
    report = engine.inspect_font(out.getvalue())
    assert len(report['fonts']) == 2
    assert [next(t['flags'] for t in f['tables'] if t['tag'] == 'zzZZ')
            for f in report['fonts']] == [['CSCTF{first}'], ['CSCTF{second}']]
    assert any(r['shared_exact_range'] for r in report['overlaps'])
    assert all(t['checksum']['valid'] for f in report['fonts'] for t in f['tables'])


def test_checksum_mismatch_and_partial_overlap_reported():
    data = bytearray(sfnt_raw({'aaaa': b'ABCDEFGH', 'bbbb': b'12345678'}, [44, 48]))
    data[-1] ^= 1
    report = engine.inspect_font(data)
    assert any(not t['checksum']['valid'] for t in report['fonts'][0]['tables'])
    assert report['overlaps'][0]['length'] == 4
    assert report['overlaps'][0]['shared_exact_range'] is False


@pytest.mark.parametrize('compress', [False, True])
def test_svg_glyph_range_inventory_without_xml_execution(compress):
    text = b'<svg xmlns="http://www.w3.org/2000/svg"><script>CSCTF{svg}</script></svg>'
    raw = gzip.compress(text, mtime=0) if compress else text
    svg = struct.pack('>HIIH', 0, 10, 0, 1) + struct.pack('>HHII', 1, 2, 14, len(raw)) + raw
    report = engine.inspect_font(sfnt_raw({'SVG ': svg}))
    doc = report['fonts'][0]['svg_documents'][0]
    assert (doc['first_glyph'], doc['last_glyph'], doc['gzip']) == (1, 2, compress)
    assert doc['length'] == len(text) and doc['flags'] == ['CSCTF{svg}']
    assert doc['script_markup'] is True


def test_sbix_bitmap_headers_and_dupe_inventory():
    # Two maxp glyphs: PNG and a dupe record. No image decoder is invoked.
    png = b'\x89PNG\r\n\x1a\n' + struct.pack('>I4sII', 13, b'IHDR', 37, 19)
    first = struct.pack('>hh4s', 3, -4, b'png ') + png
    second = struct.pack('>hh4sH', 0, 0, b'dupe', 0)
    strike = struct.pack('>HHIII', 16, 96, 16, 16 + len(first), 16 + len(first) + len(second)) + first + second
    sbix = struct.pack('>HHII', 1, 1, 1, 12) + strike
    maxp = struct.pack('>IH', 0x5000, 2)
    rows = engine.inspect_font(sfnt_raw({'maxp': maxp, 'sbix': sbix}))['fonts'][0]['bitmap_glyphs']
    assert rows[0]['glyph'] == 0 and rows[0]['width'] == 37 and rows[0]['height'] == 19
    assert rows[0]['origin'] == [3, -4]
    assert rows[1]['glyph'] == 1 and rows[1]['duplicate_glyph'] == 0


def test_cblc_bitmap_strike_and_glyph_range_inventory():
    # OpenType BitmapSize is48 bytes; index format1 has array(header8)+subtable8+offsets.
    index = struct.pack('>HHI', 3, 5, 8) + struct.pack('>HHI', 1, 17, 4) + struct.pack('>IIII', 0, 1, 2, 3)
    size = struct.pack('>IIII', 56, len(index), 1, 0) + b'\0' * 24 + struct.pack('>HHBBBb', 3, 5, 12, 13, 32, 1)
    cblc = struct.pack('>HHI', 3, 0, 1) + size + index
    row = engine.inspect_font(sfnt_raw({'CBLC': cblc}))['fonts'][0]['bitmap_glyphs'][0]
    assert (row['first_glyph'], row['last_glyph'], row['ppem_x'], row['bit_depth']) == (3, 5, 12, 32)
    assert row['subtables'] == [{'first_glyph': 3, 'last_glyph': 5, 'index_format': 1,
                                'image_format': 17, 'image_data_offset': 4}]


def test_woff2_reserved_and_reference_size_do_not_reject():
    raw = bytearray(saved(font(), 'woff2'))
    struct.pack_into('>H', raw, 14, 1)
    struct.pack_into('>I', raw, 16, 1)
    report = engine.inspect_font(raw)
    assert report['reserved_nonzero'] is True
    assert report['total_sfnt_size_reference'] == 1


@pytest.mark.parametrize('field_offset,value', [(8, 1), (24, 999999), (28, 999999), (36, 999999), (40, 999999)])
def test_woff_malformed_bounds(field_offset, value):
    raw = bytearray(woff_private())
    struct.pack_into('>I', raw, field_offset, value)
    with pytest.raises(engine.FFWOFFError):
        engine.inspect_font(raw)


@pytest.mark.parametrize('flavor', ['woff', 'woff2'])
def test_compressed_output_budget_and_ratio(flavor):
    raw = saved(font({'zzZZ': b'A' * 100000}), flavor)
    with pytest.raises(engine.FFWOFFError):
        engine.inspect_font(raw, limits=replace(engine.Limits(), max_decoded=100))
    with pytest.raises(engine.FFWOFFError):
        engine.inspect_font(raw, limits=replace(engine.Limits(), max_ratio=1))


def test_brotli_overproducing_false_directory_length():
    # Custom-tag WOFF2 promises one byte but compressed stream expands to one million.
    packed = brotli.compress(b'A' * 1000000)
    directory = b'\x3fzzZZ\x01'
    header = struct.pack('>4s4sIHHIIHHIIIII', b'wOF2', b'\0\1\0\0', 48 + len(directory) + len(packed),
                         1, 0, 32, len(packed), 1, 0, 0, 0, 0, 0, 0)
    with pytest.raises(engine.FFWOFFError, match='exceeds declared'):
        engine.inspect_font(header + directory + packed)


@pytest.mark.parametrize('bad', [None, 'font', 2, {}, b'', b'bad', b'\xff' * 100])
def test_declared_exception_contract(bad):
    with pytest.raises(engine.FFWOFFError):
        engine.inspect_font(bad)


def test_seeded_fuzz_valid_magic_truncation_and_bitflips():
    rng = random.Random(0xff770ff)
    seeds = [saved(font(), flavor) for flavor in (None, 'woff', 'woff2')] + [woff_private()]
    corpus = [rng.randbytes(rng.randrange(512)) for _ in range(80)]
    corpus += [b'\xff' * n for n in (1, 4, 44, 48, 255)]
    for seed in seeds:
        corpus += [seed[:n] for n in range(len(seed))]
        for _ in range(80):
            raw = bytearray(seed); raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            corpus.append(bytes(raw))
    for raw in corpus:
        try:
            assert isinstance(engine.inspect_font(raw), dict)
        except engine.FFWOFFError:
            pass


def test_cli_and_import_contract(tmp_path, capsys):
    path = tmp_path / 'private.woff'; path.write_bytes(woff_private())
    assert engine.main([str(path)]) == 0
    assert 'CSCTF{private_block}' in capsys.readouterr().out
    assert engine.main(['--help']) == 0
    assert engine.main([]) == 2
    assert engine.main([str(path), '--max-input', '-1']) == 1
    assert engine.main([str(path) + '.missing']) == 1
    assert engine.__name__ not in sys.stdlib_module_names


def test_large_woff2_output_drains_brotli_buffers():
    raw = saved(font({'zzZZ': bytes(range(256)) * 4096}), 'woff2')
    report = engine.inspect_font(raw, limits=replace(engine.Limits(), max_ratio=10000))
    entry = next(t for t in report['fonts'][0]['tables'] if t['tag'] == 'zzZZ')
    assert entry['length'] == 1048576
    assert entry['original_length'] == 1048576


def test_sfnt_cumulative_table_work_is_bounded():
    raw = sfnt_raw({'aaaa': b'A' * 1000, 'bbbb': b'B' * 1000})
    with pytest.raises(engine.FFWOFFError, match='budget'):
        engine.inspect_font(raw, limits=replace(engine.Limits(), max_decoded=1500))


def test_multidimensional_memoryview_input_limit():
    data = memoryview(bytearray(100)).cast('B', shape=[2, 50])
    with pytest.raises(engine.FFWOFFError, match='input byte limit'):
        engine.inspect_font(data, limits=replace(engine.Limits(), max_input=50))


def test_empty_woff_table_from_fonttools():
    raw = saved(font({'zzZZ': b''}), 'woff')
    report = engine.inspect_font(raw)
    entry = next(t for t in report['fonts'][0]['tables'] if t['tag'] == 'zzZZ')
    assert entry['length'] == 0 and entry['checksum']['valid'] is True


def woff2_collection():
    # W3C WOFF2 section4.2: two unique private tables, one for each font.
    first, second = b'CSCTF{collection_first}', b'CSCTF{collection_second}'
    directory = b'\x3fzzZZ' + bytes([len(first)]) + b'\x3fzzZZ' + bytes([len(second)])
    collection = struct.pack('>I', 0x10000) + b'\x02'
    collection += b'\x01\x00\x01\x00\x00\x00' + b'\x01\x00\x01\x00\x00\x01'
    packed = brotli.compress(first + second)
    header = struct.pack('>4s4sIHHIIHHIIIII', b'wOF2', b'ttcf',
                         48 + len(directory) + len(collection) + len(packed),
                         2, 0, 0, len(packed), 1, 0, 0, 0, 0, 0, 0)
    return header + directory + collection + packed


def test_woff2_collection_directory_visits_each_font():
    report = engine.inspect_font(woff2_collection())
    assert [f['table_indices'] for f in report['fonts']] == [[0], [1]]
    assert [f['tables'][0]['flags'] for f in report['fonts']] == [
        ['CSCTF{collection_first}'], ['CSCTF{collection_second}']]


def test_woff2_base128_noncanonical_rejected():
    raw = woff2_collection()
    raw = raw[:53] + b'\x80' + raw[53:]
    raw = raw[:8] + struct.pack('>I', len(raw)) + raw[12:]
    with pytest.raises(engine.FFWOFFError, match='noncanonical'):
        engine.inspect_font(raw)


def test_huge_byte_limits_rejected_before_cli_read(tmp_path, capsys):
    path = tmp_path / 'font.woff'; path.write_bytes(woff_private())
    assert engine.main([str(path), '--max-input', str(1 << 100)]) == 1
    with pytest.raises(engine.FFWOFFError, match='ceiling'):
        engine.inspect_font(path.read_bytes(), limits=replace(engine.Limits(), max_decoded=1 << 100))


def test_woff2_collection_shared_table_with_long_255uint16_encodings():
    # 255UInt16 word-code 0xfd is legal even for tiny values, unlike UIntBase128.
    payload = b'CSCTF{shared_collection}'
    directory = b'\x3fzzZZ' + bytes([len(payload)])
    collection = struct.pack('>I', 0x10000) + b'\xfd\x00\x02'
    entry = b'\xfd\x00\x01' + b'\x00\x01\x00\x00' + b'\xfd\x00\x00'
    collection += entry + entry
    packed = brotli.compress(payload)
    header = struct.pack('>4s4sIHHIIHHIIIII', b'wOF2', b'ttcf',
                         48 + len(directory) + len(collection) + len(packed),
                         1, 0, 0, len(packed), 1, 0, 0, 0, 0, 0, 0)
    report = engine.inspect_font(header + directory + collection + packed)
    assert [f['table_indices'] for f in report['fonts']] == [[0], [0]]
    assert all(f['tables'][0]['flags'] == ['CSCTF{shared_collection}'] for f in report['fonts'])


@pytest.mark.parametrize('length', [b'\x90\x80\x80\x80\x00', b'\x81' * 6])
def test_woff2_base128_overflow_and_unterminated_rejected(length):
    raw = woff2_collection()
    raw = raw[:53] + length + raw[54:]
    raw = raw[:8] + struct.pack('>I', len(raw)) + raw[12:]
    with pytest.raises(engine.FFWOFFError, match='UIntBase128'):
        engine.inspect_font(raw)
