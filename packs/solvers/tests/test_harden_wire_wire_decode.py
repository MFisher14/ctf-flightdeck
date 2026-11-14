"""Independent protobuf/cbor2/msgpack/bson locks and bounded malformed inputs.

References: protobuf encoding guide, RFC8949, MessagePack specification,
https://bsonspec.org/spec.html and gRPC PROTOCOL-HTTP2/PROTOCOL-WEB.
No serialization constructor from wire_decode is used.
"""
import base64
import datetime
import gzip
import math
import random
import struct
import zlib

import bson
import cbor2
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError
import msgpack
import pytest

import wire_decode as wire


def proto_class():
    file = descriptor_pb2.FileDescriptorProto(name='harden_wire_fixture.proto', package='harden_wire', syntax='proto3')
    child = file.message_type.add(name='Child')
    child.field.add(name='value', number=1, type=4, label=1)
    root = file.message_type.add(name='Root')
    for name, number, kind in [('negative', 1, 3), ('zigzag', 2, 17), ('single', 3, 2),
                                ('double', 4, 1), ('text', 5, 9), ('raw', 6, 12)]:
        root.field.add(name=name, number=number, type=kind, label=1)
    root.field.add(name='child', number=7, type=11, type_name='.harden_wire.Child', label=1)
    packed = root.field.add(name='packed', number=8, type=13, label=3)
    packed.options.packed = True
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName('harden_wire.Root'))


def protobuf_fixture():
    message = proto_class()(negative=-1, zigzag=-123, single=1.5, double=-2.25,
                            text='CSCTF{wire}', raw=b'\xff\0', packed=[1, 128, 300])
    message.child.value = 150
    return message.SerializeToString(deterministic=True)


TREE = {'text': 'CSCTF{unicode_é}', 'integer': -123456, 'large': 2**63 + 5,
        'float': 1.5, 'bytes': b'\0\xff', 'array': [True, None, {'x': 7}]}
BSON_TREE = {'text': 'CSCTF{bson_é}', 'integer': -123456, 'large': -(2**40),
             'float': 1.5, 'bytes': b'\0\xff', 'array': [True, None, {'x': 7}]}


def frame(body, flag=0):
    return bytes([flag]) + struct.pack('>I', len(body)) + body


def test_protobuf_real_schema_wire_values_and_ambiguity():
    data = protobuf_fixture()
    fields = {field['field']: field for field in wire.decode_protobuf(data)}
    assert fields[1]['value'] == 2**64 - 1  # signed meaning requires the schema
    assert fields[2]['value'] == 245  # ZigZag(-123)
    assert fields[3]['wire_type'] == 5 and fields[3]['value'] == 0x3fc00000
    assert fields[4]['wire_type'] == 1 and fields[4]['value'] == 0xc002000000000000
    assert fields[5]['value']['string'] == 'CSCTF{wire}'
    assert fields[6]['value']['hex'] == 'ff00'
    assert fields[7]['value']['message'] == [{'field': 1, 'wire_type': 0, 'wire_name': 'varint', 'value': 150}]
    assert fields[8]['value']['hex'] == '018001ac02'


@pytest.mark.parametrize(('encode', 'decode'), [(cbor2.dumps, wire.decode_cbor),
                                              (lambda obj: msgpack.packb(obj, use_bin_type=True), wire.decode_msgpack)])
def test_real_cbor_msgpack_nested_values(encode, decode):
    assert decode(encode(TREE)) == TREE


def test_cbor_published_float_and_indefinite_vectors():
    # RFC8949 Appendix A: half float1.5, infinities, subnormal and indefinite arrays.
    for encoded, expected in [('f93e00', 1.5), ('f90001', 2**-24), ('f97c00', math.inf), ('f9fc00', -math.inf),
                               ('9f018202039f0405ffff', [1, [2, 3], [4, 5]]),
                               ('7f657374726561646d696e67ff', 'streaming'), ('5f42010243030405ff', b'\1\2\3\4\5')]:
        raw = bytes.fromhex(encoded)
        assert cbor2.loads(raw) == expected
        assert wire.decode_cbor(raw) == expected
    assert math.isnan(wire.decode_cbor(bytes.fromhex('f97e00')))


def test_msgpack_float32_and_extension_payload():
    assert wire.decode_msgpack(msgpack.packb(1.5, use_single_float=True)) == 1.5
    assert wire.decode_msgpack(msgpack.packb(msgpack.ExtType(7, b'ABCD'))) == {'ext': 7, 'data': '41424344'}


def test_bson_real_library_and_datetime_layout():
    data = bson.dumps(BSON_TREE)
    expected = dict(BSON_TREE, bytes={'binary_subtype': 0, 'hex': '00ff'})
    assert bson.loads(data) == BSON_TREE
    assert wire.decode_bson(data) == expected
    assert wire.classify(data) == {'format': 'bson', 'value': expected}
    date = datetime.datetime(2020, 1, 2, tzinfo=datetime.timezone.utc)
    assert wire.decode_bson(bson.dumps({'when': date})) == {'when': {'datetime_ms': 1577923200000}}


@pytest.mark.parametrize(('compression', 'compress'), [('gzip', lambda data: gzip.compress(data, mtime=0)), ('deflate', zlib.compress)])
def test_grpc_real_compression_and_web_trailers(compression, compress):
    message = proto_class()(negative=300, text='CSCTF{grpc}').SerializeToString(deterministic=True)
    data = frame(message) + frame(compress(message), 1)
    rows = wire.decode_grpc_frames(data, compression=compression)
    assert [row['message'] for row in rows] == [message, message]
    assert [row['compressed'] for row in rows] == [False, True]
    assert rows[1]['protobuf'][0]['value'] == 300
    trailers = frame(b'grpc-status: 0\r\nx-flag: CSCTF{grpc}\r\nx-flag: second\r\n', 0x80)
    rows = wire.decode_grpc_frames(base64.b64encode(frame(message) + trailers), grpc_web=True, base64_encoded=True)
    assert rows[-1]['headers'] == {'grpc-status': ['0'], 'x-flag': ['CSCTF{grpc}', 'second']}


def test_grpc_decompression_bomb_and_frame_count_caps(monkeypatch):
    monkeypatch.setattr(wire, 'MAX_FILE', 64)
    data = frame(gzip.compress(b'A' * 1024, mtime=0), 1)
    assert len(data) < 64
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(data, compression='gzip')
    monkeypatch.setattr(wire, 'MAX_GRPC_FRAMES', 1)
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(frame(b'') + frame(b''))


@pytest.mark.parametrize(('decode', 'data'), [
    (wire.decode_cbor, b'\x81' * 40 + b'\x00'),
    (wire.decode_msgpack, b'\x91' * 40 + b'\x00'),
])
def test_container_recursion_cap(decode, data):
    with pytest.raises(wire._WireError):
        decode(data)


def test_item_caps(monkeypatch):
    monkeypatch.setattr(wire, 'MAX_ITEMS', 2)
    for decode, data in [(wire.decode_cbor, cbor2.dumps([1, 2, 3])),
                         (wire.decode_msgpack, msgpack.packb([1, 2, 3])),
                         (wire.decode_bson, bson.dumps({'a': 1, 'b': 2, 'c': 3})),
                         (wire.decode_protobuf, b'\x08\x01' * 3)]:
        with pytest.raises(wire._WireError):
            decode(data)


def test_file_input_cap_on_classifier_and_grpc(monkeypatch):
    monkeypatch.setattr(wire, 'MAX_FILE', 8)
    assert wire.classify(b'\0' * 9) is None
    with pytest.raises(wire._WireError):
        wire.decode_grpc_frames(b'\0' * 9)


def corpus():
    rng = random.Random(0x57495245)
    values = [('empty', b''), ('ff', b'\xff' * 64), ('huge-length', b'\x5a\xff\xff\xff\xff\x0f')]
    values += [(f'random-{n}', rng.randbytes(n)) for n in range(1, 20)]
    sources = [('pb', protobuf_fixture()), ('cbor', cbor2.dumps(TREE)),
               ('msgpack', msgpack.packb(TREE, use_bin_type=True)), ('bson', bson.dumps(BSON_TREE))]
    for label, data in sources:
        values += [(f'{label}-trunc-{n}', data[:n]) for n in [1, 2, 3, 4, 5, len(data) - 1]]
        for n in range(4):
            changed = bytearray(data)
            changed[n] ^= 128
            values.append((f'{label}-flip-{n}', bytes(changed)))
    return values


# The previously discovered stdlib-exception leaks are now all fail-closed to _WireError.
KNOWN_LEAKS = {}


def malformed_cases():
    functions = {'protobuf': wire.decode_protobuf, 'cbor': wire.decode_cbor,
                 'msgpack': wire.decode_msgpack, 'bson': wire.decode_bson,
                 'grpc': wire.decode_grpc_frames, 'classify': wire.classify}
    cases = []
    for name, function in functions.items():
        for label, data in corpus():
            marks = ()
            if label in KNOWN_LEAKS.get(name, set()):
                marks = pytest.mark.xfail(reason=f'BUG: {name} leaks a stdlib exception on malformed {label}', strict=True)
            cases.append(pytest.param(function, data, marks=marks, id=f'{name}-{label}'))
    return cases


@pytest.mark.parametrize(('decode', 'data'), malformed_cases())
def test_malformed_corpus_only_declared_error(decode, data):
    try:
        decode(data)
    except wire._WireError:
        pass


def test_protobuf_integer_overflow_rejected_by_real_library():
    data = b'\x08' + b'\x80' * 10 + b'\x01'
    with pytest.raises(DecodeError):
        proto_class().FromString(data)
    with pytest.raises(wire._WireError):
        wire.decode_protobuf(data)


def test_cbor_wrong_chunk_type_rejected_by_real_library():
    data = bytes.fromhex('7f4141ff')
    with pytest.raises(cbor2.CBORDecodeError):
        cbor2.loads(data)
    with pytest.raises(wire._WireError):
        wire.decode_cbor(data)


def test_bson_string_length_past_document_is_rejected():
    data = bytearray(bson.dumps({'x': 'A'}))
    data[7:11] = struct.pack('<i', 1000)
    with pytest.raises(wire._WireError):
        wire.decode_bson(data)


@pytest.mark.parametrize(('decode', 'data'), [
    (wire.decode_cbor, b'\x18'), (wire.decode_cbor, b'\x19'),
    (wire.decode_cbor, b'\x1f'), (wire.decode_cbor, b'\x3f'),
    (wire.decode_msgpack, b'\xca'), (wire.decode_msgpack, b'\xcb'),
    (wire.decode_msgpack, b'\xd4'),
])
def test_scalar_header_validation(decode, data):
    with pytest.raises(wire._WireError):
        decode(data)


def test_classify_reserved_cbor_head_fail_closed():
    assert wire.classify(b'\x3f') is None
