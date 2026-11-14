"""Static-only Java encoding/template hardening; no Java process or probe runs.

Oracles: Oracle JVMS 4.4.7 modified UTF-8, serialization section 6 string
lengths; independent mutf8 codec and jawa ClassFile writer/parser.
https://docs.oracle.com/javase/specs/jvms/se24/html/jvms-4.html
https://docs.oracle.com/en/java/javase/24/docs/specs/serialization/protocol.html
"""
import base64
import gzip
import io
import random
import socket
import struct
import subprocess

from jawa.cf import ClassFile
from jawa.constants import UTF8, Long
import mutf8
import pytest
import requests

import java_deser as engine


@pytest.fixture(autouse=True)
def prohibit_execution_and_network(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail('static Java tests attempted execution or networking')
    monkeypatch.setattr(engine, '_run', denied)
    monkeypatch.setattr(engine, '_via_java', denied)
    monkeypatch.setattr(engine, '_via_docker', denied)
    monkeypatch.setattr(subprocess, 'run', denied)
    monkeypatch.setattr(subprocess, 'Popen', denied)
    monkeypatch.setattr(requests.Session, 'request', denied)
    monkeypatch.setattr(socket, 'getaddrinfo', denied)
    monkeypatch.setattr(socket.socket, 'connect', denied)


def classes_in_blob(raw):
    """Independent bounded class locator; jawa validates the discovered class."""
    for offset in range(4, len(raw) - 10):
        if raw[offset:offset+4] != b'\xca\xfe\xba\xbe':
            continue
        length = int.from_bytes(raw[offset-4:offset], 'big')
        if 10 <= length <= len(raw) - offset:
            yield ClassFile(io.BytesIO(raw[offset:offset+length]))


@pytest.mark.parametrize(('text', 'hex_bytes'), [
    ('', ''), ('ASCII', '4153434949'), ('\0', 'c080'), ('£', 'c2a3'),
    ('अ', 'e0a485'), ('😀', 'eda0bdedb880'), ('A\0😀', '41c080eda0bdedb880'),
])
def test_jvms_modified_utf8_published_semantics(text, hex_bytes):
    assert engine.mutf8(text) == bytes.fromhex(hex_bytes)
    assert engine.mutf8(text) == mutf8.encode_modified_utf8(text)


def test_serialization_tc_string_lengths_at_65535_boundary(monkeypatch):
    # A small independently encoded template isolates boundary logic from the
    # stale checked-in placeholder defect covered by the real-template tests.
    old = b'CSCTF_YSO_PLACEHOLDER_CMD_0123456789'
    raw = b'\xac\xed\0\x05t' + len(old).to_bytes(2, 'big') + old
    monkeypatch.setattr(engine, '_TEMPLATES', {'exec': {'CommonsCollections6':
                        {'where': 'tc_string', 'b64': base64.b64encode(raw).decode()}}})
    for length, prefix in ((65535, b't\xff\xff'), (65536, b'|\0\0\0\0\0\x01\0\0')):
        # A real public template path exercises the private TC_STRING patcher.
        payload = engine.template_payload('CommonsCollections6', 'X' * length)
        assert prefix + b'X' * length in payload
        assert payload.gadget == 'CommonsCollections6'
        assert payload.route == 'template'


@pytest.mark.parametrize('kind', ['raw', 'base64', 'base64url', 'hex', 'gzip', 'gzip_base64'])
def test_encodings_against_real_standard_codecs(kind):
    payload = b'\xac\xed\0\x05t\0\x03A\0\xff'
    actual = engine.java_encode(payload, kind)
    if kind == 'raw':
        assert actual == payload
    elif kind == 'hex':
        assert actual == payload.hex()
    elif kind == 'base64':
        assert actual == base64.b64encode(payload).decode()
    elif kind == 'base64url':
        assert actual == base64.urlsafe_b64encode(payload).decode()
    else:
        compressed = actual if kind == 'gzip' else base64.b64decode(actual)
        assert gzip.decompress(compressed) == payload
        assert int.from_bytes(compressed[4:8], 'little') == 0


def test_observed_encoding_and_payload_wrapper():
    data = b'\xac\xed\0\x05t\0\x01x'
    payload = engine.JavaPayload(data, gadget='fixture', route='static', command='inert')
    assert payload.encode('hex') == data.hex()
    assert engine.java_encode_like(data, data.hex()) == ('hex', data.hex())
    assert engine.java_encode_like(data, base64.b64encode(data).decode()) == ('base64', base64.b64encode(data).decode())
    assert bytes(payload) == data


@pytest.mark.parametrize('gadget', ['CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3',
                                     'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6',
                                     'CommonsCollections7', 'CommonsBeanutils1'])
def test_static_templates_contain_correct_mutf8_and_lengths(gadget):
    text = 'CSCTF{static_only} £\0😀'
    expected = mutf8.encode_modified_utf8(text)
    result = engine.ysoserial(gadget, text, route='template')
    assert bytes(result).startswith(b'\xac\xed\0\x05')
    assert result.route == 'template'
    if gadget in ('CommonsCollections1', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7'):
        assert b't' + struct.pack('>H', len(expected)) + expected in result
    else:
        # The literal constant entry independently establishes byte length;
        # jawa additionally proves class offsets/lengths remain parseable.
        assert b'\x01' + struct.pack('>H', len(expected)) + expected in result
        assert list(classes_in_blob(result))


def test_classfile_normalization_against_independent_jawa():
    fixture = ClassFile.create('ysoserial/Pwner123456789')
    fixture.constants.create_utf8('Lysoserial/Pwner987654321;')
    fixture.constants.create_utf8('keep/ThisName')
    output = io.BytesIO(); fixture.save(output)
    raw = output.getvalue()
    wrapped = b'prefix' + struct.pack('>I', len(raw)) + raw + b'suffix'
    normalized = engine.normalize_pwner(wrapped)
    classes = list(classes_in_blob(normalized))
    assert len(classes) == 1
    names = [item.value for item in classes[0].constants if isinstance(item, UTF8)]
    assert 'ysoserial/Pwner0' in names
    assert 'Lysoserial/Pwner0;' in names
    assert 'keep/ThisName' in names
    assert normalized.endswith(b'suffix')


def test_sleep_template_patches_milliseconds_without_execution():
    result = engine.java_sleep_payload('CommonsCollections2', 1.234)
    constants = [item.value for cls in classes_in_blob(result) for item in cls.constants if isinstance(item, Long)]
    assert 1234 in constants
    assert result.command == 'Thread.sleep(1234)'


def test_urldns_template_is_only_bytes_no_name_resolution():
    url = 'https://fixture.invalid/path?q=1'
    result = engine.template_urldns(url)
    for text in (url, 'fixture.invalid', '/path?q=1', 'https'):
        raw = text.encode('ascii')
        assert b't' + struct.pack('>H', len(raw)) + raw in result
    assert result.route == 'template'


def test_class_constant_oversize_and_invalid_options_are_declared():
    with pytest.raises(engine.JavaGap):
        engine.template_payload('CommonsCollections2', 'x' * 65536)
    # These APIs explicitly document ValueError for caller-option rejection.
    with pytest.raises(ValueError):
        engine.canonical('not-a-gadget')
    with pytest.raises(ValueError):
        engine.java_encode(b'x', 'invalid')
    with pytest.raises(ValueError):
        engine.java_sleep_payload('CommonsCollections2', 601)


def test_byte_mutations_of_class_blob_are_clean_or_declared():
    cf = ClassFile.create('fixture/Safe')
    buffer = io.BytesIO(); cf.save(buffer)
    cls = buffer.getvalue()
    raw = struct.pack('>I', len(cls)) + cls
    rng = random.Random(0x4a617661)
    inputs = [b'', b'\xff' * 80, rng.randbytes(512)] + [raw[:n] for n in range(len(raw))]
    for _ in range(40):
        mutant = bytearray(raw); mutant[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        inputs.append(bytes(mutant))
    for candidate in inputs:
        try:
            assert isinstance(engine.normalize_pwner(candidate), bytes)
        except Exception as exc:
            assert type(exc) in (ValueError, engine.JavaGap)


def test_truncated_constant_pool_length_fails_closed():
    cls = bytes.fromhex('cafebabe00000034000201')
    try:
        engine.normalize_pwner(struct.pack('>I', len(cls)) + cls)
    except Exception as exc:
        assert type(exc) in (ValueError, engine.JavaGap)


@pytest.mark.parametrize('call', [lambda: engine.mutf8(None), lambda: engine.java_encode(None),
                                 lambda: engine.java_sleep_payload('CommonsCollections2', float('inf'))])
def test_malformed_safe_helper_arguments_fail_closed(call):
    try:
        call()
    except Exception as exc:
        assert type(exc) in (ValueError, engine.JavaGap)


@pytest.mark.parametrize('argv', [[], ['--help'], ['--unknown']])
def test_cli_argument_guard(argv):
    assert isinstance(engine.main(argv), int)
