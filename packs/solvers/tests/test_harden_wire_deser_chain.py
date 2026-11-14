"""Independent Java/PHP/PHAR/MS-NRBF structural vectors; nothing deserializes.

Oracle sources: Oracle Serialization Protocol ch6; PHP Phar manifest docs;
Microsoft MS-NRBF ClassWithId and binary record grammar.
"""
import base64
import pickle
import random
import struct
import zlib

import pytest

import deser_chain as deser


PHP = b'O:4:"Item":2:{s:4:"name";s:3:"bob";s:5:"count";i:42;}'


def java_class(name=b'Example', parent=b'\x70'):
    return b'\x72' + struct.pack('>H', len(name)) + name + struct.pack('>q', 123) + b'\x02\0\0\x78' + parent


JAVA = bytes.fromhex('aced000573') + java_class()


def lp(value):
    assert len(value) < 128
    return bytes([len(value)]) + value


def net_header(root=42):
    return b'\0' + struct.pack('<iiii', root, -1, 1, 0)


def net_class(object_id=42):
    return b'\x04' + struct.pack('<i', object_id) + lp(b'Example') + struct.pack('<i', 0)


DOTNET = net_header(1) + net_class(1) + b'\x0b'


def phar(meta=PHP, manifest_override=None):
    filename, payload = b'a.txt', b'hello'
    manifest = (struct.pack('<I', 1) + b'\x11\x10' + struct.pack('<II', 0, 0)
                + struct.pack('<I', len(meta)) + meta
                + struct.pack('<I', len(filename)) + filename
                + struct.pack('<6I', len(payload), 0, len(payload), zlib.crc32(payload), 0o644, 0))
    stub = b'<?php __HALT_COMPILER(); ?>\r\n'
    return stub + struct.pack('<I', len(manifest) if manifest_override is None else manifest_override) + manifest + payload


def test_java_class_and_serial_uid_from_protocol():
    out = deser.parse_java(JAVA)
    assert out['complete'] is True
    assert out['classes'] == ['Example']
    assert out['serial_uids'] == {'Example': 123}
    assert out['root_class'] == 'Example'
    assert (out['object_count'], out['class_count']) == (1, 1)
    raw = bytes.fromhex('aced0005740003') + b'bob'
    assert deser.parse_java(raw)['strings'] == ['bob']


def test_php_property_inventory_and_phar_metadata():
    out = deser.parse_php(PHP)
    assert out['complete'] is True
    assert out['classes'] == ['Item']
    assert out['root'] == ('Item', ['name', 'count'], 2)
    assert (out['object_count'], out['class_count']) == (1, 1)
    archive = deser.parse_phar(phar())
    assert archive['has_phar'] is True and archive['phar_files'] == 1
    assert archive['classes'] == ['Item']


def test_dotnet_documented_records_and_library_strings():
    out = deser.parse_dotnet(DOTNET)
    assert out['complete'] is True
    assert out['types'] == ['Example'] and out['root_type'] == 'Example'
    assert out['record_count'] == 3
    raw = (net_header(1) + b'\x0c' + struct.pack('<i', 2) + lp(b'Example.Assembly')
           + b'\x06' + struct.pack('<i', 1) + lp(b'CSCTF{metadata}') + b'\x0b')
    out = deser.parse_dotnet(raw)
    assert out['complete'] is True
    assert out['libraries'] == ['Example.Assembly']
    assert out['strings'] == ['CSCTF{metadata}']


def test_dispatch_base64_and_finding_semantics():
    out = deser.classify(base64.b64encode(JAVA))
    assert out['format'] == 'java' and out['classes'] == ['Example']
    assert out['outer_encoding'] == ['base64']
    assert deser.classify(PHP)['root'] == ('Item', ['name', 'count'], 2)
    assert deser.classify(DOTNET)['types'] == ['Example']
    assert deser.classify(phar())['has_phar'] is True
    assert deser.gadget_families({'format': 'java', 'classes': ['java.net.URL']}) == [('urldns', 'urldns')]
    assert deser.gadget_families({'format': 'dotnet', 'types': ['System.Windows.Data.ObjectDataProvider']}) == [
        ('object_data_provider', 'object_data_provider')]
    assert deser.leads_from({'strings': ['https://example.invalid/artifact']}) == [
        {'kind': 'url', 'value': 'https://example.invalid/artifact'}]


def test_csctf_flag_is_reported_as_literal_finding():
    assert deser.leads_from({'strings': ['CSCTF{literal}']}) == [
        {'kind': 'flag_shaped', 'value': 'CSCTF{literal}'}]


def test_java_null_stream_is_complete():
    out = deser.parse_java(bytes.fromhex('aced000570'))
    assert out is not None and out['complete'] is True and out['object_count'] == 0


@pytest.mark.parametrize(('encoded', 'expected'), [(b'A\xc0\x80B', 'A\0B'),
                                                  (bytes.fromhex('eda0bdedb880'), '\U0001f600')])
def test_java_modified_utf8_exact_values(encoded, expected):
    raw = bytes.fromhex('aced000574') + struct.pack('>H', len(encoded)) + encoded
    assert deser.parse_java(raw)['strings'] == [expected]


def test_php_root_is_outermost_object():
    out = deser.parse_php(b'O:5:"Outer":1:{s:5:"child";O:5:"Inner":0:{}}')
    assert out['root'] == ('Outer', ['child'], 1)


def test_phar_metadata_cannot_escape_manifest():
    out = deser.parse_phar(phar(manifest_override=18))
    assert out is None or out['complete'] is False


def test_nrbf_metadata_id_is_object_id():
    raw = net_header() + net_class() + b'\x01' + struct.pack('<ii', 43, 42) + b'\x0b'
    assert deser.parse_dotnet(raw)['complete'] is True


def test_nrbf_requires_message_end():
    assert deser.parse_dotnet(net_header() + net_class())['complete'] is False


def test_nrbf_classifier_accepts_non_one_root_id():
    out = deser.classify(net_header(42) + net_class(42) + b'\x0b')
    assert out is not None and out['types'] == ['Example']


def test_java_descriptor_depth_cap(monkeypatch):
    monkeypatch.setattr(deser, 'MAX_DEPTH', 2)
    parent = b'\x70'
    for _ in range(5):
        parent = java_class(parent=parent)
    assert deser.parse_java(bytes.fromhex('aced000573') + parent)['complete'] is False


@pytest.mark.parametrize('entry', [deser.parse_java, deser.parse_php, deser.parse_phar, deser.parse_dotnet,
                                 deser.classify, deser.looks_like_pickle])
def test_deterministic_malformed_bytes(entry):
    rng = random.Random(0x44455345)
    samples = [b'', b'\xff'*4096, b'\0'*4096]
    samples += [rng.randbytes(n) for n in (1, 2, 5, 16, 128, 4096)]
    for raw in (PHP, JAVA, DOTNET, phar()):
        samples.extend(raw[:n] for n in range(len(raw)))
        for _ in range(32):
            changed = bytearray(raw)
            changed[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            samples.append(bytes(changed))
    for raw in samples:
        try:
            entry(raw)
        except deser._DeserError:
            pass


def test_phar_wrong_input_type_declines():
    try:
        deser.parse_phar(None)
    except deser._DeserError:
        pass


def test_explicit_small_caps(monkeypatch):
    monkeypatch.setattr(deser, 'MAX_FILE', 16)
    assert deser.classify(PHP) is None
    assert deser.parse_phar(phar()) is None
    monkeypatch.setattr(deser, 'MAX_DEPTH', 2)
    assert deser.parse_php(b'a:1:{i:0;a:1:{i:0;a:1:{i:0;i:1;}}}') is None
    monkeypatch.setattr(deser, 'MAX_NODES', 2)
    assert deser.parse_dotnet(net_header() + b'\x0a'*8 + b'\x0b')['complete'] is False


def test_no_deserialization_process_or_network(monkeypatch):
    import socket
    import subprocess
    serialized = pickle.dumps({'value': 42}, protocol=4)
    def forbidden(*args, **kwargs):
        pytest.fail('Passive parser attempted execution or network')
    monkeypatch.setattr(pickle, 'loads', forbidden)
    monkeypatch.setattr(pickle, 'load', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    for raw in (PHP, JAVA, DOTNET, phar()):
        assert deser.classify(raw) is not None
    assert deser.looks_like_pickle(serialized)
    assert deser.classify(serialized) is None


def test_reports_and_offline_cli(tmp_path, capsys):
    assert deser.reports({'fixture': JAVA})[0][1]['serial_uids'] == {'Example': 123}
    path = tmp_path/'fixture.ser'
    path.write_bytes(JAVA)
    assert deser.main([str(path), '--json']) == 0
    assert 'Example' in capsys.readouterr().out
    assert deser.main([]) == 2
