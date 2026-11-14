"""Independent iWork/Snappy/protobuf locks; no engine-generated fixtures.

The raw Snappy tag fixtures follow google/snappy/format_description.txt;
python-snappy independently validates them. Protobuf objects are serialized and
parsed by Google's real protobuf implementation. ZIP/plist use stdlib writers.
"""
from dataclasses import replace
import io
import json
import plistlib
import random
import stat
import struct
import zipfile

from crccheck.crc import Crc32Iscsi
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
import pytest
import snappy

import ff_iwork_inspect as engine


def varint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def chunk(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, 'little') + body


def literal(body):
    # Independent encoder of Google's literal-only raw Snappy representation.
    if not body:
        return b'\x00'
    n = len(body) - 1
    if n < 60:
        header = bytes([n << 2])
    else:
        size = (n.bit_length() + 7) // 8
        header = bytes([(59 + size) << 2]) + n.to_bytes(size, 'little')
    return varint(len(body)) + header + body


def masked_crc(body):
    n = Crc32Iscsi.calc(body)
    return (((n >> 15) | (n << 17)) + 0xa282ead8) & 0xffffffff


def standard_frame(body, compressed=True):
    encoded = literal(body) if compressed else body
    return b'\xff\x06\x00\x00sNaPpY' + chunk(0 if compressed else 1,
                masked_crc(body).to_bytes(4, 'little') + encoded)


def message_class():
    file = descriptor_pb2.FileDescriptorProto(name='oracle.proto', package='oracle', syntax='proto2')
    msg = file.message_type.add(name='Known')
    for name, number, kind in [('counter', 1, 4), ('wide', 2, 6), ('opaque', 3, 12), ('fixed', 4, 7)]:
        msg.field.add(name=name, number=number, type=kind, label=1)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName('oracle.Known'))


def payload():
    return message_class()(counter=150, wide=0x123456789abcdef0,
                           opaque=b'CSCTF{iwa}', fixed=0x12345678).SerializeToString()


def archive_record(bodies):
    # The documented container schema only: ArchiveInfo field 1 identifier,
    # repeated field 2 MessageInfo with field 1 type and field 3 payload length.
    header = b'\x08\x07'
    for body in bodies:
        info = b'\x08\x01\x18' + varint(len(body))
        header += b'\x12' + varint(len(info)) + info
    return varint(len(header)) + header + b''.join(bodies)


def iwa_wire(plain=None):
    if plain is None:
        plain = archive_record([payload()])
    return chunk(0, literal(plain))


def zip_bytes(entries, compression=zipfile.ZIP_STORED):
    sink = io.BytesIO()
    with zipfile.ZipFile(sink, 'w', compression=compression) as archive:
        for name, body in entries:
            # a fixed member time: these bytes are parametrize ids, and the wall-clock default made xdist
            # workers that collected in different seconds disagree on them (R-01)
            if isinstance(name, zipfile.ZipInfo):
                archive.writestr(name, body)
                continue
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o600 << 16
            archive.writestr(info, body, compress_type=compression)
    return sink.getvalue()


def test_known_protobuf_blob_against_google_library():
    wire = bytes.fromhex('08960111f0debc9a785634121a0a43534354467b6977617d2578563412')
    oracle = message_class().FromString(wire)
    assert (oracle.counter, oracle.wide, oracle.opaque, oracle.fixed) == (
        150, 0x123456789abcdef0, b'CSCTF{iwa}', 0x12345678)
    rows = engine.protobuf_fields(wire)
    assert [(r['field_number'], r['wire_type']) for r in rows] == [(1, 0), (2, 1), (3, 2), (4, 5)]
    assert [r['value_length'] for r in rows] == [2, 8, 10, 4]
    assert all('value' not in r and 'string' not in r and 'message' not in r for r in rows)
    assert wire == oracle.SerializeToString()


def test_length_delimited_values_are_not_guessed_as_submessages():
    wire = message_class()(opaque=b'\x08\x01').SerializeToString()
    assert len(engine.protobuf_fields(wire)) == 1


def test_protobuf_groups_are_structural_and_matched():
    # Legacy group field 1 containing varint field 2, then end-group 1.
    wire = b'\x0b\x10\x01\x0c'
    # The real parser accepts an unknown group and round-trips it unchanged.
    assert message_class().FromString(wire).SerializeToString() == wire
    rows = engine.protobuf_fields(wire)
    assert [(r['field_number'], r['wire_type'], r['depth']) for r in rows] == [
        (1, 3, 0), (2, 0, 1), (1, 4, 0)]


@pytest.mark.parametrize('copy', [b'\x01\x02', b'\x0e\x02\x00', b'\x0f\x02\x00\x00\x00'])
def test_raw_copy_tags_against_snappy(copy):
    raw = b'\x07\x08xab' + copy
    assert snappy.decompress(raw) == b'xababab'
    decoded, report = engine.decode_snappy_stream(chunk(0, raw), framing='iwa')
    assert decoded == b'xababab'
    assert report['chunks'][0]['checksum'] == 'absent'


@pytest.mark.parametrize('size', [0, 1, 60, 61, 256, 65536])
def test_manual_snappy_literal_boundaries(size):
    body = b'A' * size
    raw = literal(body)
    assert snappy.decompress(raw) == body
    assert engine.decode_snappy_stream(chunk(0, raw), framing='iwa')[0] == body


@pytest.mark.parametrize('compressed', [False, True])
def test_standard_snappy_manual_frame_and_crc(compressed):
    body = b'123456789'
    assert Crc32Iscsi.calc(body) == 0xe3069283  # published CRC32C check value
    wire = standard_frame(body, compressed)
    assert snappy.StreamDecompressor().decompress(wire) == body
    decoded, report = engine.decode_snappy_stream(wire)
    assert decoded == body
    assert report['framing'] == 'snappy'
    assert report['chunks'][1]['checksum'] == 'valid'


def test_reference_library_compressor_and_skippable_chunks():
    body = payload() * 1000
    wire = snappy.StreamCompressor().add_chunk(body)
    wire += chunk(128, b'ignored') + chunk(254, b'padding need not be zero')
    wire += standard_frame(b'last', False)
    decoded, report = engine.decode_snappy_stream(wire, framing='snappy')
    assert decoded == body + b'last'
    assert len([r for r in report['chunks'] if r['kind'] == 'stream_identifier']) == 2


def test_iwa_records_cross_chunk_boundaries():
    body = payload()
    plain = archive_record([body, b'\x08\x01']) + archive_record([body])
    wire = b''.join(chunk(0, literal(part)) for part in (plain[:1], plain[1:13], plain[13:]))
    report = engine.inspect_iwa(wire)
    assert report['uncompressed_size'] == len(plain)
    assert len(report['records']) == 2
    assert [len(r['payloads']) for r in report['records']] == [2, 1]
    assert [(r['field_number'], r['wire_type']) for r in report['records'][0]['payloads'][0]['fields']] == [
        (1, 0), (2, 1), (3, 2), (4, 5)]
    json.dumps(report)


@pytest.mark.parametrize('fmt', [plistlib.FMT_BINARY, plistlib.FMT_XML])
def test_modern_bundle_assets_plists_previews(fmt):
    wire = zip_bytes([
        ('Index/Document.iwa', iwa_wire()),
        ('Data/image.png', b'\x89PNG\r\n\x1a\nopaque'),
        ('Metadata/Properties.plist', plistlib.dumps({'Title': 'CSCTF{title}', 'Count': 3}, fmt=fmt)),
        ('preview.jpg', b'\xff\xd8\xffopaque'),
    ], compression=zipfile.ZIP_DEFLATED)
    report = engine.inspect_bundle(wire)
    rows = {r['path']: r for r in report['members']}
    assert report['member_count'] == 4
    assert rows['Data/image.png']['kind'] == 'asset'
    assert rows['preview.jpg']['kind'] == 'preview'
    assert rows['Metadata/Properties.plist']['plist']['top_level_keys'] == ['Count', 'Title']
    assert rows['Index/Document.iwa']['iwa']['records'][0]['payloads'][0]['length'] == len(payload())


def test_nested_index_zip_and_shared_expansion_budget():
    nested = zip_bytes([('Index/Document.iwa', iwa_wire())])
    outer = zip_bytes([('Essay.key/Index.zip', nested), ('Essay.key/preview.jpg', b'preview')])
    report = engine.inspect_bundle(outer)
    assert report['members'][0]['members'][0]['path'] == 'Essay.key/Index.zip!/Index/Document.iwa'
    assert report['records'] == 1 and report['member_count'] == 3
    # All layers count: nested ZIP bytes, contained compressed IWA, and decoded IWA.
    expected = len(nested) + len(iwa_wire()) + len(archive_record([payload()])) + len(b'preview')
    assert report['expanded_bytes'] == expected
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(outer, limits=replace(engine.Limits(), max_expanded=expected - 1))


@pytest.mark.parametrize('name', ['../x.iwa', '/x.iwa', 'C:/x.iwa', 'a\\x.iwa', 'a//x.iwa', './x.iwa'])
def test_zip_unsafe_paths(name):
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(zip_bytes([(name, iwa_wire())]))


def test_zip_duplicate_symlink_and_bomb_guards():
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(zip_bytes([('Index/A.iwa', iwa_wire()), ('Index/a.iwa', iwa_wire())]))
    info = zipfile.ZipInfo('Index/Document.iwa')
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(zip_bytes([(info, iwa_wire())]))
    bomb = zip_bytes([('Data/bomb', b'0' * 1000000), ('Index/Document.iwa', iwa_wire())],
                     compression=zipfile.ZIP_DEFLATED)
    with pytest.raises(engine.IWorkError, match='ratio'):
        engine.inspect_bundle(bomb)


@pytest.mark.parametrize('raw', [b'', b'\x80', b'\x80' * 6, b'\xff\xff\xff\xff\x10',
                                  varint(65537), b'\x01\x01\x00', b'\x01\x00'])
def test_bad_raw_snappy_refused(raw):
    with pytest.raises(engine.IWorkError):
        engine.decode_snappy_stream(chunk(0, raw), framing='iwa')


@pytest.mark.parametrize('wire', [b'', b'\x00\x01', b'\x00\xff\xff\xffx', chunk(1, b'x'),
                                  chunk(128, b'ignored')])
def test_bad_iwa_framing_refused(wire):
    with pytest.raises(engine.IWorkError):
        engine.inspect_iwa(wire, framing='iwa')


def test_standard_snappy_crc_and_identifier_refusal():
    wire = bytearray(standard_frame(b'123456789'))
    wire[14] ^= 1
    for invalid in [bytes(wire), standard_frame(b'x')[:-1], chunk(0, literal(b'x')),
                    b'\xff\x06\x00\x00sNaPpZ', standard_frame(b'x') + chunk(2, b'')]:
        with pytest.raises(engine.IWorkError):
            engine.decode_snappy_stream(invalid, framing='snappy')


@pytest.mark.parametrize('wire', [b'\x00', b'\x0e', b'\x0f', b'\x08\x80', b'\x09x', b'\x0dx',
                                  b'\x0a\x04x', b'\x0b', b'\x0c', b'\x0b\x14',
                                  b'\x08' + b'\xff' * 9 + b'\x02'])
def test_malformed_protobuf_refused(wire):
    with pytest.raises(engine.IWorkError):
        engine.protobuf_fields(wire)


@pytest.mark.parametrize('plain', [b'\xff\xff\xff\xff\x0f', b'\x03\x08',
    b'\x02\x12\x00',  # MessageInfo lacks required length.
    b'\x04\x12\x02\x18\x64',  # Payload length exceeds bytes.
    b'\x02\x10\x01',  # Envelope field 2 uses wrong wire type.
    b'\x06\x12\x04\x18\x00\x18\x00',  # Ambiguous duplicate length.
])
def test_bad_iwa_record_envelopes(plain):
    with pytest.raises(engine.IWorkError):
        engine.inspect_iwa(iwa_wire(plain))


@pytest.mark.parametrize('limit,wire,call', [
    ('max_fields', b'\x08\x01\x08\x02', engine.protobuf_fields),
    ('max_chunks', chunk(0, literal(b'x')) * 2, engine.decode_snappy_stream),
    ('max_records', iwa_wire(archive_record([]) * 2), engine.inspect_iwa),
    ('max_depth', b'\x0b\x13\x14\x0c', engine.protobuf_fields),
    ('max_members', zip_bytes([('Index/A.iwa', iwa_wire()), ('Index/B.iwa', iwa_wire())]), engine.inspect_bundle),
])
def test_count_limits(limit, wire, call):
    with pytest.raises(engine.IWorkError):
        call(wire, limits=replace(engine.Limits(), **{limit: 1}))


def test_entrypoints_fail_closed_seeded_corpus():
    rng = random.Random(0x1a4a)
    seeds = [payload(), iwa_wire(), standard_frame(payload()),
             zip_bytes([('Index/Document.iwa', iwa_wire())])]
    cases = [b'', b'\xff' * 256, b'\0' * 256]
    cases += [rng.randbytes(rng.randrange(300)) for _ in range(80)]
    for seed in seeds:
        cases += [seed[:n] for n in range(len(seed))]
        for _ in range(40):
            changed = bytearray(seed)
            changed[rng.randrange(len(seed))] ^= 1 << rng.randrange(8)
            cases.append(bytes(changed))
    for call in [engine.protobuf_fields, engine.decode_snappy_stream,
                 engine.inspect_iwa, engine.inspect_bundle, engine.inspect]:
        for data in cases + [None, 'text', 4, [], object()]:
            try:
                call(data)
            except engine.IWorkError:
                pass


def test_cli_guard_and_json_output(tmp_path, capsys, monkeypatch):
    assert engine.main(['--help']) == 0
    assert engine.main([]) == 2
    path = tmp_path / 'sample.iwa'
    path.write_bytes(iwa_wire())
    assert engine.main([str(path)]) == 0
    output = capsys.readouterr().out
    assert '"format": "iwa"' in output
    assert engine.main([str(path) + '.missing']) == 2
    def string_exit(*args, **kwargs):
        raise SystemExit('text')
    monkeypatch.setattr(engine.argparse.ArgumentParser, 'parse_args', string_exit)
    assert engine.main([]) == 2


def test_memoryview_nbytes_not_element_count():
    view = memoryview(b'\x08\x01' * 4).cast('I')
    assert len(view) == 2 and view.nbytes == 8
    with pytest.raises(engine.IWorkError, match='size'):
        engine.inspect(view, format='protobuf', limits=replace(engine.Limits(), max_input=4))
    with pytest.raises(engine.IWorkError, match='size'):
        engine.protobuf_fields(view, limits=replace(engine.Limits(), max_stream=4))


@pytest.mark.parametrize('case', ['count', 'cycle', 'xml_depth'])
def test_plist_preflight_before_library_allocation(case, monkeypatch):
    if case == 'count':
        plist = bytearray(plistlib.dumps({'A': 1}, fmt=plistlib.FMT_BINARY))
        plist[-24:-16] = (100001).to_bytes(8, 'big')
        plist = bytes(plist)
    elif case == 'cycle':
        # One array object at offset 8 refers to itself; table starts at 10.
        plist = b'bplist00\xa1\x00\x08' + struct.pack('>6xBBQQQ', 1, 1, 1, 0, 10)
    else:
        plist = b'<plist>' + b'<array>' * 34 + b'<string>x</string>' + b'</array>' * 34 + b'</plist>'
    calls = []
    def forbidden(data):
        calls.append(True)
        raise AssertionError('must reject before full object allocation')
    monkeypatch.setattr(engine.plistlib, 'loads', forbidden)
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(zip_bytes([('Metadata/Properties.plist', plist)]))
    assert calls == []


def test_oversized_snappy_prefix_rejected_before_native_decoder(monkeypatch):
    calls = []
    def forbidden(data):
        calls.append(True)
        raise AssertionError('no oversized allocation')
    monkeypatch.setattr(snappy, 'decompress', forbidden)
    with pytest.raises(engine.IWorkError):
        engine.decode_snappy_stream(chunk(0, varint(65537)))
    assert calls == []


def test_nested_zip_member_budget_and_zip_crc():
    nested = zip_bytes([('Index/Document.iwa', iwa_wire())])
    outer = zip_bytes([('Index.zip', nested)])
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(outer, limits=replace(engine.Limits(), max_members=1))
    nested_twice = zip_bytes([('Index.zip', outer)])
    with pytest.raises(engine.IWorkError, match='depth'):
        engine.inspect_bundle(nested_twice)
    wire = bytearray(zip_bytes([('Index/Document.iwa', iwa_wire())]))
    pos = wire.find(iwa_wire())
    assert pos > 0
    wire[pos + len(iwa_wire()) - 1] ^= 1
    with pytest.raises(engine.IWorkError):
        engine.inspect_bundle(wire)
