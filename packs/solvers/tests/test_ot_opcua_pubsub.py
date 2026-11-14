"""Independent UA Part 14/Part 6 fixtures; no solver encoder is used.

UADP: Part 14 7.2.4.4/7.2.4.5 field tables. Numeric/Variant bytes use
Part 6 UA Binary little-endian rules. NodeSet2: Part 6 Annex F hand-built model.
"""
import json
from array import array
import random
import struct
import uuid

import pytest

import ot_opcua_pubsub as engine


# Fully literal layout: publisher(Byte)=42, writer group=7, writer=9,
# one key-frame with Int32(42), String("ok").
BASIC = bytes.fromhex("71 2a 01 0700 01 0900 01 0200 06 2a000000 0c 02000000 6f6b")
NODESET = b'''<?xml version="1.0"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
 xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
 <NamespaceUris><Uri>urn:ctf:plant</Uri></NamespaceUris>
 <Aliases><Alias Alias="HasComponent">i=47</Alias><Alias Alias="Double">i=11</Alias></Aliases>
 <UAObject NodeId="ns=1;i=100" BrowseName="1:Pump">
  <DisplayName Locale="en">Pump</DisplayName>
  <References><Reference ReferenceType="HasComponent">ns=1;s=Speed</Reference></References>
 </UAObject>
 <UAVariable NodeId="ns=1;s=Speed" BrowseName="1:Speed" DataType="Double" ValueRank="-1" ParentNodeId="ns=1;i=100">
  <DisplayName>Speed</DisplayName><Description>CSCTF{model_evidence}</Description>
  <References><Reference ReferenceType="HasComponent" IsForward="false">ns=1;i=100</Reference>
  <Reference ReferenceType="i=40">i=63</Reference></References>
  <Value><uax:Double>12.5</uax:Double></Value>
 </UAVariable>
</UANodeSet>'''


def test_literal_uadp_network_and_dataset_vector():
    report = engine.parse_uadp(BASIC)
    assert report['publisher_id'] == {'type': 'Byte', 'value': 42}
    assert report['group'] == {'flags': 1, 'writer_group_id': 7}
    assert report['writer_ids'] == [9]
    dataset = report['dataset_messages'][0]
    assert dataset['message_type'] == 'key-frame'
    assert dataset['writer_id'] == 9
    assert [(f['value']['type'], f['value']['value']) for f in dataset['fields']] == [('Int32', 42), ('String', 'ok')]


def test_all_optional_network_and_dataset_fields():
    ident = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
    promoted = b'\x05' + struct.pack('<H', 500)
    # Header ordering is independently transcribed from Tables 154 and 162.
    dataset = b'\xf9\x30' + struct.pack('<HqHHII', 7, 0, 10002, 0x8001, 20, 21) + b'\x01\x00\x01\x01'
    raw = (b'\xf1\xe9\x02' + struct.pack('<H', 1234) + ident.bytes_le + b'\x0f' +
           struct.pack('<HIHH', 42, 43, 1, 2) + b'\x01' + struct.pack('<HqH', 999, 0, 10001) +
           struct.pack('<H', len(promoted)) + promoted + dataset)
    out = engine.parse_uadp(raw)
    assert out['publisher_id'] == {'type': 'UInt16', 'value': 1234}
    assert out['dataset_class_id'] == str(ident)
    assert out['group'] == {'flags': 15, 'writer_group_id': 42, 'group_version': 43, 'network_message_number': 1, 'sequence_number': 2}
    assert out['timestamp']['filetime_100ns'] == 0
    assert out['picoseconds_raw'] == 10001 and out['picoseconds'] == 9999
    assert out['promoted_fields'][0]['value'] == 500
    ds = out['dataset_messages'][0]
    assert ds['sequence_number'] == 7
    assert ds['timestamp']['filetime_100ns'] == 0
    assert ds['picoseconds'] == 9999
    assert (ds['status'], ds['status_code'], ds['configuration_major'], ds['configuration_minor']) == (0x8001, 0x80010000, 20, 21)
    assert ds['fields'][0]['value']['value'] is True


@pytest.mark.parametrize('kind,encoded,wanted', [
    (0, b'\xff', 255), (1, b'\x34\x12', 0x1234),
    (2, b'\x78\x56\x34\x12', 0x12345678),
    (3, bytes.fromhex('8877665544332211'), 0x1122334455667788),
    (4, b'\x03\x00\x00\x00abc', 'abc'),
])
def test_publisher_id_types(kind, encoded, wanted):
    out = engine.parse_uadp(bytes([0xd1, kind]) + encoded + b'\x01\x01\x00\x81\x03')
    assert out['publisher_id']['value'] == wanted


def test_multiple_dataset_boundaries_and_keepalive():
    first = bytes.fromhex('01 0100 06 7b000000')
    second = bytes.fromhex('81 03')
    raw = b'\x41\x02' + struct.pack('<4H', 30, 40, len(first), len(second)) + first + second
    out = engine.parse_uadp(raw)
    assert [ds['writer_id'] for ds in out['dataset_messages']] == [30, 40]
    assert out['dataset_messages'][0]['fields'][0]['value']['value'] == 123
    assert out['dataset_messages'][1]['message_type'] == 'keep-alive'


def test_delta_event_datavalue_and_nodeid_primitives():
    delta = bytes.fromhex('81 01 0200 0500 03 64 0200 01 00')
    out = engine.parse_dataset_message(delta)
    assert [f['index'] for f in out['fields']] == [5, 2]
    assert [f['value']['value'] for f in out['fields']] == [100, False]
    event = bytes.fromhex('81 02 0100 11 01 02 3412')
    assert engine.parse_dataset_message(event)['fields'][0]['value']['value'] == {'namespace': 2, 'type': 'numeric', 'identifier': 0x1234}
    dv = bytes.fromhex('05 0100 03 06 feffffff 00000080')
    value = engine.parse_dataset_message(dv)['fields'][0]['value']
    assert value['value']['value'] == -2
    assert value['status_code'] == 0x80000000


def test_raw_invalid_and_heartbeat_are_explicit():
    assert engine.parse_dataset_message(b'\x01')['payload_status'] == 'heartbeat'
    assert engine.parse_dataset_message(b'\x03')['payload_status'] == 'heartbeat'
    assert engine.parse_dataset_message(b'\x00anything')['payload_status'] == 'invalid-message'
    raw = engine.parse_dataset_message(b'\x03\x2a\x00\x00\x00')
    assert raw['payload_status'] == 'metadata-required'
    assert raw['opaque_hex'] == '2a000000'


def test_without_payload_header_requires_reader_configuration():
    ds = bytes.fromhex('01 0100 06 2a000000')
    assert engine.parse_uadp(b'\x01' + ds)['payload_status'] == 'reader-configuration-required'
    out = engine.parse_uadp(b'\x01' + ds, dataset_sizes=[len(ds)])
    assert out['dataset_messages'][0]['fields'][0]['value']['value'] == 42


def test_security_headers_are_never_claimed_verified():
    ds = bytes.fromhex('01 0100 06 2a000000')
    # Security flags: signed + footer + key-reset. Token=500, 8-byte nonce,
    # two-byte footer, and four signature bytes (caller supplies policy length).
    header = b'\xc1\x10\x01\x09\x00\x0d' + struct.pack('<IB', 500, 8) + b'12345678' + struct.pack('<H', 2)
    raw = header + ds + b'\xaa\xbbSIGN'
    unknown = engine.parse_uadp(raw)
    assert unknown['payload_status'] == 'signature-size-required'
    out = engine.parse_uadp(raw, signature_size=4)
    assert out['security'] == {'flags': 13, 'signed': True, 'encrypted': False, 'force_key_reset': True,
        'token_id': 500, 'authentication': 'not-verified', 'nonce_hex': b'12345678'.hex(), 'footer_size': 2,
        'footer_hex': 'aabb', 'signature_hex': b'SIGN'.hex()}
    assert out['dataset_messages'][0]['fields'][0]['value']['value'] == 42
    encrypted = bytearray(raw)
    encrypted[5] |= 2
    out = engine.parse_uadp(encrypted, signature_size=4)
    assert out['payload_status'] == 'encrypted' and out['dataset_messages'] == []


def test_chunk_header_has_no_count_byte():
    raw = b'\xc1\x80\x01' + struct.pack('<HHIIi', 4321, 7, 4, 10, 3) + b'abc'
    out = engine.parse_uadp(raw)
    assert out['writer_ids'] == [4321]
    assert out['chunk'] == {'sequence_number': 7, 'offset': 4, 'total_size': 10, 'data_hex': '616263'}


def test_zero_padding_is_accepted_but_nonzero_tail_rejected():
    ds = bytes.fromhex('01 0100 06 2a000000')
    assert engine.parse_dataset_message(ds + b'\0' * 4)['padding_size'] == 4
    with pytest.raises(engine.ParseError):
        engine.parse_dataset_message(ds + b'X')


@pytest.mark.parametrize('raw', [b'', b'\x00', b'\x81\x40', b'\x41\x00',
    b'\xc1\x80\x04', b'\x21\x10', b'\xd1\x05', b'\x91\x07',
    b'\xc1\x10\x01\x01\x00\x02' + b'\0' * 6])
def test_bad_network_headers_fail_closed(raw):
    with pytest.raises(engine.ParseError):
        engine.parse_uadp(raw)


def test_bad_delta_indexes_and_reserved_flags():
    for raw in [bytes.fromhex('81 01 0200 0500 00 0500 00'), b'\x07', b'\x81\x40', b'\x81\x20',
                b'\x83\x01\0\0', b'\x83\x03']:
        with pytest.raises(engine.ParseError):
            engine.parse_dataset_message(raw)


def test_nodeset_handbuilt_model_and_reference_direction():
    out = engine.parse_nodeset(NODESET)
    assert out['namespace_uris'] == ['http://opcfoundation.org/UA/', 'urn:ctf:plant']
    assert out['aliases'] == {'Double': 'i=11', 'HasComponent': 'i=47'}
    pump, speed = out['nodes']
    assert pump['node_class'] == 'UAObject' and speed['node_class'] == 'UAVariable'
    assert speed['DataType']['identifier'] == 11
    assert speed['browse_name'] == {'namespace': 1, 'name': 'Speed', 'namespace_uri': 'urn:ctf:plant'}
    assert speed['value_xml']['children'][0]['text'] == '12.5'
    assert pump['references'][0]['target_scope'] == 'internal'
    assert speed['references'][0]['is_forward'] is False
    assert speed['references'][0]['source_id'] == 'ns=1;i=100'
    assert speed['references'][0]['target_id'] == 'ns=1;s=Speed'
    assert speed['references'][1]['target_scope'] == 'external'
    assert out['findings'] == []


def test_nodeset_duplicates_and_external_references():
    raw = NODESET.replace(b'ns=1;s=Speed" BrowseName', b'ns=1;i=100" BrowseName')
    assert engine.parse_nodeset(raw)['findings'] == [{'kind': 'duplicate-node-id', 'node_id': 'ns=1;i=100'}]


def test_nodeset_namespace_uri_reference_resolves_locally():
    raw = NODESET.replace(b'>ns=1;s=Speed</Reference>', b'>nsu=urn:ctf:plant;s=Speed</Reference>')
    ref = engine.parse_nodeset(raw)['nodes'][0]['references'][0]
    assert ref['target']['text'] == 'ns=1;s=Speed'
    assert ref['target_scope'] == 'internal'


def test_nodeset_percent_encoded_namespace_uri():
    raw = NODESET.replace(b'<Uri>urn:ctf:plant</Uri>', b'<Uri>urn:ctf:plant;area</Uri>')
    raw = raw.replace(b'>ns=1;s=Speed</Reference>', b'>nsu=urn:ctf:plant%3Barea;s=Speed</Reference>')
    ref = engine.parse_nodeset(raw)['nodes'][0]['references'][0]
    assert ref['target']['text'] == 'ns=1;s=Speed'
    assert ref['target']['namespace_uri'] == 'urn:ctf:plant;area'
    assert ref['target_scope'] == 'internal'


def test_nodeset_string_nodeid_whitespace_is_significant():
    raw = NODESET.replace(b'ns=1;s=Speed', b'ns=1;s=Speed ')
    out = engine.parse_nodeset(raw)
    assert out['nodes'][1]['node_id']['text'] == 'ns=1;s=Speed '
    ref = out['nodes'][0]['references'][0]
    assert ref['target']['identifier'] == 'Speed ' and ref['target_scope'] == 'internal'
    raw = raw.replace(b'</Aliases>', b'<Alias Alias="SpeedAlias">ns=1;s=Speed </Alias></Aliases>')
    raw = raw.replace(b'>ns=1;s=Speed </Reference>', b'>SpeedAlias</Reference>')
    out = engine.parse_nodeset(raw)
    assert out['aliases']['SpeedAlias'] == 'ns=1;s=Speed '
    assert out['nodes'][0]['references'][0]['target_scope'] == 'internal'


def test_variant_array_and_string_containing_flag():
    # Variant mask=Int32|array, length=3, signed values in little-endian.
    ds = b'\x01\x02\x00\x86' + struct.pack('<4i', 3, -1, 0, 42)
    text = b'CSCTF{offline_uadp}'
    ds += b'\x0c' + struct.pack('<i', len(text)) + text
    fields = engine.parse_dataset_message(ds)['fields']
    assert fields[0]['value']['value'] == [-1, 0, 42]
    assert fields[1]['value']['value'] == text.decode()


def test_explicit_signature_length_is_checked_for_encrypted_messages():
    raw = b'\xc1\x10\x01\x01\x00\x03' + struct.pack('<IB', 1, 8) + b'12345678' + b'x'
    with pytest.raises(engine.ParseError):
        engine.parse_uadp(raw, signature_size=32)


def test_nodeset_nodeid_forms_use_binary_baseline():
    raw = '''<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
    <UAObject NodeId="g=00112233-4455-6677-8899-aabbccddeeff" BrowseName="G"/>
    <UAObject NodeId="b=YWJj" BrowseName="B"/>
    </UANodeSet>'''
    out = engine.parse_nodeset(raw)
    assert out['nodes'][0]['node_id']['identifier'] == '00112233-4455-6677-8899-aabbccddeeff'
    assert out['nodes'][1]['node_id']['identifier'] == '616263'


@pytest.mark.parametrize('raw', [
    b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>',
    NODESET.replace(b'<UANodeSet ', b'<!DOCTYPE UANodeSet [<!ENTITY a "abc">]><UANodeSet ', 1),
    b'<?xml version="1.0" encoding="UNKNOWN"?><UANodeSet/>',
    NODESET.replace(b'IsForward="false"', b'IsForward="yes"'),
    NODESET.replace(b'ns=1;s=Speed', b'ns=5;s=Speed'),
    NODESET.replace(b'DataType="Double"', b'DataType="NotAnAlias"'),
    '\ud800', None, b'<UANodeSet/>',
])
def test_nodeset_rejects_malformed_without_external_fetch(raw):
    with pytest.raises(engine.ParseError):
        engine.parse_nodeset(raw)


@pytest.mark.parametrize('parser,seed', [(engine.parse_uadp, BASIC),
    (engine.parse_dataset_message, BASIC[9:]), (engine.parse_nodeset, NODESET)])
def test_seeded_truncation_and_bitflip_fuzz(parser, seed):
    rng = random.Random(0x0FC0A)
    cases = [b'', b'\xff' * 100] + [seed[:i] for i in range(len(seed))]
    cases += [rng.randbytes(n) for n in range(128)]
    for _ in range(128):
        raw = bytearray(seed)
        i = rng.randrange(len(raw))
        raw[i] ^= 1 << rng.randrange(8)
        cases.append(bytes(raw))
    for raw in cases:
        try:
            assert isinstance(parser(raw), dict)
        except engine.ParseError:
            pass


def test_cli_guard_and_json(tmp_path, capsys):
    assert engine.main([]) == 2
    assert engine.main(['--help']) == 0
    path = tmp_path / 'message.bin'
    path.write_bytes(BASIC)
    capsys.readouterr()
    assert engine.main(['uadp', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['writer_ids'] == [9]
    path.write_bytes(b'\xff')
    assert engine.main(['uadp', str(path)]) == 2
    assert engine.main(['nodeset', str(tmp_path / 'missing')]) == 2


@pytest.mark.parametrize('kwargs', [{'signature_size': -1}, {'signature_size': True},
    {'dataset_sizes': '3'}, {'dataset_sizes': [-1]}, {'dataset_sizes': [True]}])
def test_invalid_parser_options_are_declared(kwargs):
    with pytest.raises(engine.ParseError):
        engine.parse_uadp(BASIC, **kwargs)


def test_memoryview_byte_extent_is_bounded(monkeypatch):
    data = memoryview(array('I', [0] * 10))
    assert len(data) == 10 and data.nbytes == 40
    monkeypatch.setattr(engine, 'MAX_INPUT', 16)
    with pytest.raises(engine.ParseError, match='size limit'):
        engine.parse_uadp(data)


def test_aggregate_network_output_is_bounded(monkeypatch):
    ds = b'\x01\x01\x00\x0c' + struct.pack('<i', 300) + b'x' * 300
    monkeypatch.setattr(engine.devices, 'MAX_OUTPUT_CHARS', 1000)
    assert engine.parse_dataset_message(ds)['field_count'] == 1
    raw = b'\x41\x03' + struct.pack('<6H', 1, 2, 3, len(ds), len(ds), len(ds)) + ds * 3
    with pytest.raises(engine.ParseError, match='UADP dataset output'):
        engine.parse_uadp(raw)


@pytest.mark.parametrize('prefix', [b'', b'\x18', b'\x17\x01', b'\x18\x17\x01'])
def test_array_bound_checked_through_scalar_variant_and_datavalue(prefix):
    oversized = b'\x86' + struct.pack('<i', 4097)
    ds = b'\x01\x01\x00' + prefix + oversized
    with pytest.raises(engine.ParseError, match='4096-element limit'):
        engine.parse_dataset_message(ds)


@pytest.mark.parametrize('kind', [0, 23, 24, 25])
def test_reserved_or_recursive_variant_arrays_are_rejected(kind):
    ds = b'\x01\x01\x00' + bytes([128 | kind]) + struct.pack('<i', 0)
    with pytest.raises(engine.ParseError):
        engine.parse_dataset_message(ds)


def test_flat_array_at_limit_and_scalar_nesting_remain_supported():
    ds = b'\x01\x01\x00\x18\x86' + struct.pack('<i', 4096) + bytes(4096 * 4)
    value = engine.parse_dataset_message(ds)['fields'][0]['value']
    assert value['type'] == 'Variant'
    assert value['value']['value'] == [0] * 4096
