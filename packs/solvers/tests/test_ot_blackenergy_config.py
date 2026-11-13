"""Synthetic BlackEnergy layouts; no sample, network, or executable oracle.

F-Secure BlackEnergy & Quedagh image 13/14 and table 4 supply XML names,
DWORD lengths and ASN.1 field IDs. pyasn1 independently reads the handwritten
DER records. Published ESET 2016 IOCs are inert strings in test artifacts.
"""
import json
import random
import struct

import pytest
from pyasn1.codec.der.decoder import decode as der_decode

import ot_blackenergy_config as engine


XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<bkernel>
 <servers><server><type>https</type><addr>https://5.149.254.114/synthetic?proxy=https=192.0.2.4:8080</addr></server></servers>
 <plugins><plugin><name>si</name></plugin></plugins>
 <cmds></cmds><sleepfreq>600</sleepfreq><build_id>2015en</build_id>
</bkernel>'''


def der(tag, content):
    """Independent X.690 definite-length serializer, not engine code."""
    size = len(content)
    if size < 128:
        encoded_length = bytes([size])
    else:
        encoded_length = size.to_bytes((size.bit_length() + 7) // 8, "big")
        encoded_length = bytes([128 + len(encoded_length)]) + encoded_length
    return bytes([tag]) + encoded_length + content


def record(number, value):
    # OID 1.N combines the first two arcs as 40 + N (X.690 section 8.19).
    attribute = der(0x30, der(0x06, bytes([40 + number])) + der(0x13, value.encode('ascii')))
    name = der(0x30, der(0x31, attribute))
    return struct.pack('<I', len(name)) + name


def asn1_config(*, server='http://198.51.100.22/synthetic', build='2015en', sleep='600'):
    return b''.join(record(number, value) for number, value in [
        (1, server), (2, ''), (3, ''), (4, build), (5, sleep)])


def test_xml_documented_fields_and_proxy_address_preserved():
    result = engine.decode_be2_xml(XML)
    assert result['format'] == 'be2-xml'
    assert result['build_id'] == '2015en'
    assert result['sleepfreq'] == 600
    assert result['servers'] == [{'type': 'https', 'addr': 'https://5.149.254.114/synthetic?proxy=https=192.0.2.4:8080'}]
    assert '<name>si</name>' in result['plugins_xml']
    assert result['cmds_xml'] == '<cmds />'


def test_xml_http_key_and_utf8_values_are_inert():
    raw = XML.replace(b'<build_id>2015en</build_id>', '<build_id>CSCTF{café}</build_id><http_key>test-secret</http_key>'.encode())
    result = engine.decode_be2_xml(raw)
    assert result['build_id'] == 'CSCTF{café}'
    assert result['http_key'] == 'test-secret'


def test_published_empty_plugin_name_record_matches_independent_encoder():
    # Exact 15 bytes from image14, starting at its byte offset 0x4B.
    expected = bytes.fromhex('0b00000030093107300506012a1300')
    assert record(2, '') == expected
    node, trailing = der_decode(expected[4:])
    assert trailing == b''
    assert str(node[0][0][0]) == '1.2'
    assert str(node[0][0][1]) == ''


@pytest.mark.parametrize('server', ['http://198.51.100.22/synthetic', 'https://example.invalid/' + 'a' * 140])
def test_be3_published_name_layout_matches_pyasn1(server):
    raw = asn1_config(server=server)
    position, values = 0, {}
    while position < len(raw):
        size, = struct.unpack_from('<I', raw, position)
        position += 4
        name, tail = der_decode(raw[position:position + size])
        assert tail == b''
        values[str(name[0][0][0])] = str(name[0][0][1])
        position += size
    assert values == {'1.1': server, '1.2': '', '1.3': '', '1.4': '2015en', '1.5': '600'}
    result = engine.decode_be3_asn1(raw)
    assert result['format'] == 'be3-asn1'
    assert result['servers'][0]['addr'] == values['1.1']
    assert result['plugins'] == result['cmds'] == ''
    assert result['build_id'] == values['1.4']
    assert result['sleepfreq'] == int(values['1.5'])
    assert result['raw_fields']['servers'] == server
    assert result['field_oids'] == {'servers': '1.1', 'plugins': '1.2', 'cmds': '1.3', 'build_id': '1.4', 'sleepfreq': '1.5'}


def test_carves_both_complete_configs_with_offsets():
    xml_body = XML[XML.index(b'<bkernel>'):]
    binary = asn1_config()
    raw = b'harmless-prefix' + xml_body + b'\x00separator\x00' + binary + b'suffix'
    results = engine.extract_configs(raw)
    assert len(results) == 2
    assert [(x['format'], x['offset'], x['length']) for x in results] == [
        ('be2-xml', len(b'harmless-prefix'), len(xml_body)),
        ('be3-asn1', raw.index(binary), len(binary))]


@pytest.mark.parametrize('sleep', ['0', '1', '600', '4294967295'])
def test_nonnegative_interval_no_invented_minimum(sleep):
    assert engine.decode_be3_asn1(asn1_config(sleep=sleep))['sleepfreq'] == int(sleep)


@pytest.mark.parametrize('bad', [
    b'<bkernel>', XML.replace(b'600', b'-1'), XML.replace(b'600', b'4294967296'),
    XML.replace(b'<build_id>2015en</build_id>', b'<build_id>x</build_id><build_id>y</build_id>'),
    b'<!DOCTYPE bkernel [<!ENTITY secret SYSTEM "file:///etc/passwd">]>' + XML,
    XML.replace(b'<type>https</type>', b'<type>http</type>'),
    XML.replace(b'2015en', b'&undefined;'),
    XML.replace(b'<cmds></cmds>', b'<cmds>' + b'<nested>' * 13 + b'</nested>' * 13 + b'</cmds>'),
])
def test_xml_rejects_malformed_or_ambiguous_input(bad):
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be2_xml(bad)


def test_wrong_xml_root_and_arbitrary_der_are_not_family_configs():
    assert engine.decode_be2_xml(b'<config><build_id>2015en</build_id></config>') is None
    assert engine.decode_be3_asn1(der(0x30, der(0x02, b'\x01'))) is None
    assert engine.extract_configs(b'BlackEnergy KillDisk snake certificate') == []


def test_every_be3_truncation_and_trailing_byte_fails_closed():
    raw = asn1_config()
    for length in range(len(raw)):
        try:
            assert engine.decode_be3_asn1(raw[:length]) is None
        except engine.BlackEnergyError:
            pass
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be3_asn1(raw + b'\0')


@pytest.mark.parametrize('mutation', [
    lambda raw: b'\xff\xff\xff\xff' + raw[4:],
    lambda raw: raw.replace(b'\x06\x01\x2c', b'\x06\x01\x2b'),
    lambda raw: raw.replace(b'\x06\x01\x2c', b'\x06\x01\x39'),
    lambda raw: raw.replace(b'\x06\x01\x2c', b'\x02\x01\x04'),
    lambda raw: raw.replace(b'\x13\x062015en', b'\x04\x062015en'),
    lambda raw: raw.replace(b'2015en', b'\xff015en'),
])
def test_asn1_wrong_tags_lengths_ids_and_strings_decline(mutation):
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be3_asn1(mutation(asn1_config()))


def test_profile_corroboration_and_source_timeline():
    result = engine.match_profile({'config.xml': XML, 'inventory.txt': b'komut.exe\nsec_service.exe'})
    assert result['matched'] is True
    assert result['score'] == 100
    assert result['category_scores'] == {'configuration': 25, 'campaign_build': 25, 'historical_c2': 25, 'killdisk_processes': 30}
    assert [item['phase'] for item in result['timeline']] == ['configuration', '2015 campaign', 'destruction']
    assert result['timeline_kind'] == 'source chronology, not artifact timestamps'
    assert all(item['source'].startswith('https://') for item in result['evidence'])


@pytest.mark.parametrize('data', [b'BlackEnergy', b'KillDisk', b'komut.exe\nsec_service.exe', b'5.149.254.114', b'2015en'])
def test_names_and_single_indicator_categories_do_not_verdict(data):
    result = engine.match_profile({'test': data})
    assert result['matched'] is False
    assert result['score'] < 50


def test_repeated_indicators_do_not_inflate_score_or_cross_token_boundaries():
    assert engine.match_profile({'a': b'2015en\n' * 100})['score'] == 25
    assert engine.match_profile({'a': b'12015en 2015enx xkomut.exe 5.149.254.1145'})['score'] == 0
    assert engine.match_profile({'a': 'komut.exe\0sec_service.exe\0'.encode('utf-16-le')})['score'] == 30


def test_wide_token_suffixes_decline_and_later_valid_match_survives():
    wrong = 'kiev_o_suffix\0sec_service.exe.bak\0'.encode('utf-16-le')
    assert engine.match_profile({'a': wrong})['score'] == 0
    right = wrong + 'kiev_o\0sec_service.exe\0'.encode('utf-16-le')
    result = engine.match_profile({'a': right})
    assert result['category_scores'] == {'campaign_build': 25, 'killdisk_processes': 10}
    assert all(item['offset'] >= len(wrong) for item in result['evidence'])


def test_asn1_printable_string_alphabet_is_validated():
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be3_asn1(asn1_config(build='invalid{}'))


@pytest.mark.parametrize('server', ['http://bad host/', 'http://example.invalid:99999/', 'http://example.invalid:bad/'])
def test_server_address_whitespace_and_invalid_ports_rejected(server):
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be3_asn1(asn1_config(server=server))


def test_hash_manifest_is_reported_not_verified_digest():
    result = engine.match_profile({'manifest': b'16f44fac7e8bc94eccd7ad9692e6665ef540eec4\nkomut.exe\nsec_service.exe'})
    assert result['matched'] is True
    assert result['score'] == 55
    assert 'reported_killdisk_sha1' in result['category_scores']
    assert 'verified_killdisk_sha1' not in result['category_scores']


def test_profile_delivery_and_ssh_markers_are_static_only():
    data = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\0Workbook_Open\0'
    result = engine.match_profile({'delivery.xls': data, 'ssh.txt': b'dropbear.exe passDs5Bu9Te7'})
    assert result['score'] == 40 and result['matched'] is False
    assert set(result['category_scores']) == {'office_macro_context', 'sshbeardoor'}


def test_deterministic_random_magic_and_bitflip_fuzz_only_declared_error():
    rng = random.Random(0xBE2026)
    samples = [b'', b'\xff' * 512, b'<bkernel', bytes.fromhex('0b0000003009'), b'PK\x03\x04', b'MZ']
    samples += [rng.randbytes(n) for n in range(0, 256, 3)]
    for valid in (XML, asn1_config()):
        for offset in rng.sample(range(len(valid)), 20):
            damaged = bytearray(valid)
            damaged[offset] ^= 1 << (offset % 8)
            samples.append(bytes(damaged))
    for data in samples:
        for reader in (engine.decode_be2_xml, engine.decode_be3_asn1, engine.extract_configs):
            try:
                reader(data)
            except engine.BlackEnergyError:
                pass
        try:
            engine.match_profile({'sample': data})
        except engine.BlackEnergyError:
            pass


@pytest.mark.parametrize('bad', [None, 3, 'str', [], {}, True])
def test_public_byte_reader_type_contract(bad):
    for reader in (engine.decode_be2_xml, engine.decode_be3_asn1, engine.extract_configs):
        with pytest.raises(engine.BlackEnergyError):
            reader(bad)


def test_resource_limits_and_released_memoryview(monkeypatch):
    with pytest.raises(engine.BlackEnergyError):
        engine.decode_be2_xml(b' ' * (engine.MAX_CONFIG + 1))
    with pytest.raises(engine.BlackEnergyError):
        engine.match_profile({str(i): b'' for i in range(engine.MAX_ARTIFACTS + 1)})
    with pytest.raises(engine.BlackEnergyError):
        engine.extract_configs(b'<bkernel>' * (engine.MAX_CANDIDATES + 1))
    with pytest.raises(engine.BlackEnergyError):
        engine.extract_configs(b'<bkernel ' * (engine.MAX_CANDIDATES + 1))
    view = memoryview(b'bytes')
    view.release()
    with pytest.raises(engine.BlackEnergyError):
        engine.extract_configs(view)
    monkeypatch.setattr(engine, 'MAX_TOTAL', 3)
    with pytest.raises(engine.BlackEnergyError):
        engine.match_profile({'a': b'1234'})


def test_cli_both_modes_errors_and_systemexit_guard(tmp_path, capsys, monkeypatch):
    path = tmp_path / 'synthetic.xml'
    path.write_bytes(XML)
    assert engine.main(['config', str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result[str(path)][0]['build_id'] == '2015en'
    assert engine.main(['profile', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['matched'] is True
    assert engine.main(['config', str(tmp_path / 'absent')]) == 2
    assert engine.main([]) == 2
    assert engine.main(['--help']) == 0
    assert engine.main([object()]) == 2
    def string_exit(*args, **kwargs):
        raise SystemExit('not an integer')
    monkeypatch.setattr(engine.argparse.ArgumentParser, 'parse_args', string_exit)
    assert engine.main([]) == 2


def test_cli_rejects_nonregular_fifo_without_reading(tmp_path):
    import os
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    assert engine.main(['config', str(fifo)]) == 2


@pytest.mark.parametrize('mode', ['config', 'profile'])
def test_cli_total_limit_is_enforced_while_loading(mode, monkeypatch):
    requested = []
    def bounded_read(name, maximum):
        requested.append((name, maximum))
        if maximum < 8:
            raise engine.BlackEnergyError('fixture does not fit remaining budget')
        return b'ordinary'
    monkeypatch.setattr(engine, '_read', bounded_read)
    monkeypatch.setattr(engine, 'MAX_TOTAL', 10)
    assert engine.main([mode, 'first', 'second', 'third']) == 2
    assert requested == [('first', 10), ('second', 2)]
