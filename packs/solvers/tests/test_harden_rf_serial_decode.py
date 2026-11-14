"""Static language-serialization vectors, deliberately never deserializing objects.

Independent references: Oracle serialization protocol chapter 6;
https://docs.ruby-lang.org/en/3.4/marshal_rdoc.html ; PHP serialize grammar.
All bytes below are hand-written from the grammar, not engine output.
"""
import random
import struct

import pytest

import serial_decode as serial


PHP = b'a:2:{s:5:"count";i:42;s:4:"name";s:3:"bob";}'
RUBY = b'\x04\x08[\x07:\x0ahello;\x00'
JAVA = bytes.fromhex('aced0005740003') + b'bob'


def java_class(name=b'Item', parent=b'\x70'):
    return b'\x72' + struct.pack('>H', len(name)) + name + bytes(8) + b'\x02\0\0\x78' + parent


def test_php_map_binary_string_and_object_visibility():
    assert serial.decode_php(PHP) == {'k': 'map', 'pairs': [
        ({'k': 'str', 'v': 'count'}, {'k': 'int', 'v': 42}),
        ({'k': 'str', 'v': 'name'}, {'k': 'str', 'v': 'bob'})]}
    assert serial.decode_php(b's:3:"\x00\xffA";') == {'k': 'bytes', 'hex': '00ff41'}
    # PHP prefixes protected property names with NUL, *, NUL.
    raw = b'O:4:"Item":1:{s:6:"\x00*\x00pin";s:4:"1234";}'
    assert serial.decode_php(raw) == {'k': 'object', 'class': 'Item',
                                      'fields': [('\x00*\x00pin', {'k': 'str', 'v': '1234'})]}


@pytest.mark.parametrize(('raw', 'expected'), [
    (b'N;', {'k': 'null'}), (b'b:1;', {'k': 'bool', 'v': True}),
    (b'i:-123;', {'k': 'int', 'v': -123}), (b'd:1.5;', {'k': 'float', 'v': 1.5}),
    (b'R:1;', {'k': 'ref', 'handle': 1})])
def test_php_scalar_grammar(raw, expected):
    assert serial.decode_php(raw) == expected


def test_ruby_documented_symbol_link_example():
    # This exact [:hello,:hello] vector is published in Ruby's Marshal format doc.
    assert serial.decode_ruby(RUBY) == {'k': 'array', 'items': [
        {'k': 'sym', 'v': 'hello'}, {'k': 'sym', 'v': 'hello'}]}
    assert serial.decode_ruby(b'\x04\x08[\x07"\x0ahello@\x06') == {
        'k': 'array', 'items': [{'k': 'str', 'v': 'hello'}, {'k': 'str', 'v': 'hello'}]}


@pytest.mark.parametrize(('encoded', 'value'), [(b'\0', 0), (b'\x06', 1), (b'\xfa', -1),
                                               (b'\x01\xff', 255), (b'\xff\0', -256),
                                               (b'\x02\x34\x12', 0x1234)])
def test_ruby_packed_signed_integer(encoded, value):
    assert serial.decode_ruby(b'\x04\x08i' + encoded) == {'k': 'int', 'v': value}


def test_java_string_handle_and_typed_primitive_array():
    assert serial.decode_java(JAVA) == {'k': 'str', 'v': 'bob'}
    assert serial.decode_java(JAVA + bytes.fromhex('71007e0000')) == {
        'k': 'array', 'items': [{'k': 'str', 'v': 'bob'}, {'k': 'str', 'v': 'bob'}]}
    raw = bytes.fromhex('aced000575') + java_class(b'[I') + struct.pack('>Iiii', 3, -1, 0, 12345)
    assert serial.decode_java(raw) == {'k': 'array', 'items': [
        {'k': 'int', 'v': -1, 'bits': 32}, {'k': 'int', 'v': 0, 'bits': 32},
        {'k': 'int', 'v': 12345, 'bits': 32}]}


@pytest.mark.parametrize(('raw', 'format_name', 'expected'), [
    (b'i:42;', 'php', {'k': 'int', 'v': 42}),
    (b'\x04\x08i\x2f', 'ruby', {'k': 'int', 'v': 42}),
    (JAVA, 'java', {'k': 'str', 'v': 'bob'})])
def test_classify_independent_values(raw, format_name, expected):
    assert serial.classify(raw) == {'format': format_name, 'root': expected}


@pytest.mark.parametrize(('encoded', 'expected'), [(b'A\xc0\x80B', 'A\0B'),
                                                  (bytes.fromhex('eda0bdedb880'), '\U0001f600')])
def test_java_modified_utf8_string_semantics(encoded, expected):
    raw = bytes.fromhex('aced000574') + struct.pack('>H', len(encoded)) + encoded
    assert serial.decode_java(raw) == {'k': 'str', 'v': expected}


def samples():
    rng = random.Random(260611)
    items = [b'', b'\xff' * 64, b'\0' * 64]
    items += [rng.randbytes(n) for n in (1, 2, 3, 4, 8, 16, 64, 256, 1024)]
    seeds = [b'i:12;', b's:3:"abc";', b'd:1.5;', bytes.fromhex('04086608312e35'),
             bytes.fromhex('aced0005740003616263')]
    for seed in seeds:
        items.extend(seed[:n] for n in range(len(seed)))
        for index in range(min(12, len(seed))):
            raw = bytearray(seed)
            raw[index] ^= 128
            items.append(bytes(raw))
    return items


PHP_UNICODE = {'693ab1323b', '693a31b23b', '733ab33a22616263223b',
               '643ab12e353b', '643a31ae353b', '643a312eb53b'}
RUBY_UNICODE = {'04086608b12e35', '0408660831ae35', '04086608312eb5'}


def fuzz_cases():
    for entry in (serial.decode_php, serial.decode_ruby, serial.decode_java, serial.classify):
        for index, raw in enumerate(samples()):
            yield pytest.param(entry, raw, id=f'{entry.__name__}-{index}')


@pytest.mark.parametrize(('entry', 'raw'), list(fuzz_cases()))
def test_deterministic_malformed_bytes_only_declared_errors(entry, raw):
    try:
        entry(raw)
    except serial._SerialError:
        pass


@pytest.mark.parametrize(('entry', 'raw'), [
    (serial.decode_php, b's:x:"";'), (serial.decode_php, b'a:x:{}'),
    (serial.decode_php, b'd:bad;'), (serial.decode_ruby, b'\x04\x08f\x08bad'),
    (serial.decode_php, b'i:' + b'9' * 5000 + b';')])
def test_invalid_numeric_tokens_declared_error(entry, raw):
    with pytest.raises(serial._SerialError):
        entry(raw)


@pytest.mark.parametrize('entry', [serial.decode_ruby, serial.decode_java])
def test_none_decoders_only_declared_error(entry):
    with pytest.raises(serial._SerialError):
        entry(None)


def test_caps_and_oversized_declared_lengths(monkeypatch):
    for entry, raw in [(serial.decode_php, b's:999999999999999999:"a";'),
                       (serial.decode_ruby, b'\x04\x08"\x04\xff\xff\xff\x7f'),
                       (serial.decode_java, bytes.fromhex('aced00057c7fffffffffffffff'))]:
        with pytest.raises(serial._SerialError):
            entry(raw)
    monkeypatch.setattr(serial, 'MAX_FILE', 16)
    assert serial.classify(PHP) is None
    monkeypatch.setattr(serial, 'MAX_DEPTH', 2)
    with pytest.raises(serial._SerialError):
        serial.decode_php(b'a:1:{i:0;a:1:{i:0;a:1:{i:0;i:1;}}}')
    with pytest.raises(serial._SerialError):
        serial.decode_ruby(b'\x04\x08[\x06[\x06[\x06[\x060')


def test_java_descriptor_depth_cap(monkeypatch):
    monkeypatch.setattr(serial, 'MAX_DEPTH', 2)
    descriptor = b'\x70'
    for _ in range(5):
        descriptor = java_class(parent=descriptor)
    with pytest.raises(serial._SerialError):
        serial.decode_java(bytes.fromhex('aced000573') + descriptor)


def test_no_object_execution(monkeypatch):
    import pickle
    import subprocess
    def forbidden(*args, **kwargs):
        pytest.fail('Static serialization inspection attempted execution')
    monkeypatch.setattr(pickle, 'loads', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    assert serial.decode_php(b'O:4:"Item":0:{}')['class'] == 'Item'
    assert serial.decode_ruby(b'\x04\x08o:\x09Item\0')['class'] == 'Item'
    assert serial.decode_java(bytes.fromhex('aced000573') + java_class())['class'] == 'Item'
