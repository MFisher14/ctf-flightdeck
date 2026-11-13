"""Independent vector locks and bounded deterministic malformed-input corpus.

Oracles (no encoder from ics_protocols is used):
* pymodbus 3.16 PDUs and crccheck; published CRC checks in Infineon PDL CRC table.
* Modbus Application Protocol V1.1b3 sections 6.1, 6.3, 6.12.
* DNP3 object layouts: Emerson D301806X012 and opendnp3 Group43.scala.
* S7/COTP, CIP/ENIP, IEC104 and BACnet fixtures are hand-built wire fields.
* BACnet routed NPDU order: bacnet-stack/src/bacnet/npdu.c npdu_encode_pdu.

Former defect vectors are normal regression assertions after targeted fixes.
"""
import inspect
import json
import random
import struct

import pytest
from crccheck.crc import Crc16Dnp, Crc16Modbus
from pymodbus.framer.rtu import FramerRTU
from pymodbus.pdu.register_message import (
    ReadHoldingRegistersRequest,
    ReadHoldingRegistersResponse,
    WriteMultipleRegistersRequest,
)

import ics_protocols as ics


def _mbap(pdu, transaction=0x1234, unit=17):
    return struct.pack('>HHHB', transaction, 0, len(pdu) + 1, unit) + pdu


def _dnp_frame(application):
    # CRC oracle is an independent package, not the engine's own CRC.
    user = b'\xc7' + application
    header = b'\x05\x64' + bytes([5 + len(user), 0x44]) + struct.pack('<HH', 1024, 23)
    frame = header + Crc16Dnp.calc(header).to_bytes(2, 'little')
    for offset in range(0, len(user), 16):
        block = user[offset:offset + 16]
        frame += block + Crc16Dnp.calc(block).to_bytes(2, 'little')
    return frame


def _s7(parameter, payload=b'', rosctr=1):
    header = bytes([0x32, rosctr]) + b'\0\0' + struct.pack('>HHH', 0x1234, len(parameter), len(payload))
    if rosctr in (2, 3):
        header += b'\0\0'
    body = b'\x02\xf0\x80' + header + parameter + payload
    return b'\x03\x00' + struct.pack('>H', len(body) + 4) + body


def _bvlc(body):
    return b'\x81\x0a' + struct.pack('>H', 4 + len(body)) + body


def _enip(body, command=0x6f):
    return struct.pack('<HHII8sI', command, len(body), 0x11223344, 0, b'CTXBYTES', 0) + body


def _iec(asdu, send=7, receive=13):
    return b'\x68' + bytes([4 + len(asdu)]) + struct.pack('<HH', send << 1, receive << 1) + asdu


MODBUS = _mbap(bytes.fromhex('03006b0003'))
DNP_APP = bytes.fromhex('c08100001e050701010000c03f')
DNP = _dnp_frame(DNP_APP)
S7 = _s7(bytes.fromhex('f0000001000101e0'))
BACNET = _bvlc(bytes.fromhex('01001008'))
CIP = bytes.fromhex('0e03200124013007')
ENIP = _enip(bytes.fromhex('01000000'), 0x65)
ENIP_IO = bytes.fromhex('0200028008007856341205000000b100040006004142')
IEC = _iec(bytes.fromhex('0d01030123014523010000c03f00'))


@pytest.mark.parametrize(('function', 'oracle', 'check'), [
    (ics.crc16_modbus, Crc16Modbus, 0x4b37),
    (ics.crc16_dnp3, Crc16Dnp, 0xea82),
])
def test_published_crc_check_and_independent_library(function, oracle, check):
    # https://infineon.github.io/mtb-pdl-cat2/pdl_api_reference_manual/html/group__group__crypto__lld__crc__functions.html
    assert function(b'123456789') == check
    rng = random.Random(0x435243)
    for raw in [b'', bytes(range(256)), b'\xff' * 47] + [rng.randbytes(n) for n in range(40)]:
        assert function(raw) == oracle.calc(raw)


def test_modbus_pymodbus_oracle_and_rtu_wire_endianness():
    message = ReadHoldingRegistersRequest(address=107, count=3)
    pdu = bytes([message.function_code]) + message.x_encode()
    out = ics.parse_modbus(_mbap(pdu), direction='request')
    assert (out['transaction_id'], out['unit_id']) == (0x1234, 17)
    assert (out['pdu']['function'], out['pdu']['address'], out['pdu']['quantity']) == (3, 107, 3)
    payload = b'\x11' + pdu
    # pymodbus compute_CRC swaps its returned int for big-endian wire emission.
    rtu = payload + FramerRTU.compute_CRC(payload).to_bytes(2, 'big')
    decoded = ics.parse_modbus(rtu, transport='rtu', direction='request')
    assert (decoded['unit_id'], decoded['crc_valid'], decoded['pdu']['address']) == (17, True, 107)


def test_modbus_pymodbus_response_and_write():
    response = ReadHoldingRegistersResponse(registers=[555, 0, 100])
    pdu = bytes([response.function_code]) + response.x_encode()
    assert ics.parse_modbus(pdu, transport='pdu', direction='response')['pdu']['registers'] == [555, 0, 100]
    message = WriteMultipleRegistersRequest(address=1, registers=[10, 258])
    pdu = bytes([message.function_code]) + message.x_encode()
    out = ics.parse_modbus(_mbap(pdu), direction='request')['pdu']
    assert (out['function'], out['address'], out['quantity'], out['registers']) == (16, 1, 2, [10, 258])


def test_modbus_published_coil_and_exception_examples():
    # Fixed CD 6B 05 bytes are independently expanded LSB-first, following
    # Modbus V1.1b3 section 6.1 (unused high bits in the final octet are zero).
    out = ics.parse_modbus(bytes.fromhex('0103cd6b05'), transport='pdu', direction='response')['pdu']
    assert out['bits'] == [True, False, True, True, False, False, True, True,
                           True, True, False, True, False, True, True, False,
                           True, False, True, False, False, False, False, False]
    out = ics.parse_modbus(bytes.fromhex('8302'), transport='pdu', direction='response')['pdu']
    assert (out['function'], out['is_exception'], out['exception_code']) == (3, True, 2)


@pytest.mark.parametrize(('group', 'variation', 'encoding', 'number', 'timed'), [
    (30, 1, '<i', -1234567, False), (30, 2, '<h', -1234, False),
    (30, 5, '<f', 1.5, False), (30, 6, '<d', -2.25, False),
    (32, 1, '<i', -1234567, False), (32, 2, '<h', -1234, False),
    (32, 3, '<i', -1234567, True), (32, 4, '<h', -1234, True),
    (32, 5, '<f', 1.5, False), (32, 6, '<d', -2.25, False),
    (32, 7, '<f', 1.5, True), (32, 8, '<d', -2.25, True),
    (40, 1, '<i', -1234567, False), (40, 2, '<h', -1234, False),
    (40, 3, '<f', 1.5, False), (40, 4, '<d', -2.25, False),
])
def test_dnp3_analog_layouts(group, variation, encoding, number, timed):
    raw = b'\x01' + struct.pack(encoding, number)
    if timed:
        raw += (1700000000123).to_bytes(6, 'little')
    application = b'\xc3\x81\x00\x00' + bytes([group, variation, 0x17, 1, 9]) + raw
    direct = ics.parse_dnp3_application(application)['application']
    framed = ics.parse_dnp3(_dnp_frame(application))
    for app in [direct, framed['application']]:
        point = app['objects'][0]['points'][0]
        assert (point['index'], point['flags'], point['value']) == (9, 1, number)
        if timed:
            assert point['time']['unix_ms'] == 1700000000123
    assert (framed['source'], framed['destination'], framed['transport']['sequence']) == (23, 1024, 7)
    assert framed['header_crc_valid'] is True
    assert framed['block_crcs_valid'] is True


@pytest.mark.parametrize(('variation', 'encoding', 'number'), [(1, '<i', -2), (2, '<h', -2), (3, '<f', 1.5), (4, '<d', -2.25)])
def test_dnp3_analog_command_group41(variation, encoding, number):
    # Group41 differs from group43: command status is after the value.
    application = b'\xc0\x04' + bytes([41, variation, 7, 1]) + struct.pack(encoding, number) + b'\x02'
    point = ics.parse_dnp3_application(application)['application']['objects'][0]['points'][0]
    assert (point['value'], point['status']) == (number, 2)


@pytest.mark.parametrize(('variation', 'encoding', 'number', 'timed'), [
    (1, '<i', -2, False), (2, '<h', -2, False), (3, '<i', -2, True), (4, '<h', -2, True),
    (5, '<f', 1.5, False), (6, '<d', 1.5, False), (7, '<f', 1.5, True), (8, '<d', 1.5, True),
])
def test_bug_dnp3_group43(variation, encoding, number, timed):
    # Primary implementation's published object definition:
    # https://raw.githubusercontent.com/dnp3/opendnp3/release/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group43.scala
    raw = b'\x02' + struct.pack(encoding, number) + ((1).to_bytes(6, 'little') if timed else b'')
    app = ics.parse_dnp3_application(b'\xc0\x81\0\0' + bytes([43, variation, 7, 1]) + raw)['application']
    point = app['objects'][0]['points'][0]
    assert (len(app['objects']), point.get('value'), point.get('status'), point.get('time', {}).get('unix_ms')) == (1, number, 2, 1 if timed else None)


def test_s7_setup_and_read_variable_address():
    out = ics.parse_s7comm(S7)['s7']
    assert (out['pdu_reference'], out['setup']['max_amq_calling'], out['setup']['pdu_length']) == (0x1234, 1, 480)
    request = _s7(bytes.fromhex('0401120a10020003000784000123'))
    address = ics.parse_s7comm(request)['s7']['variables'][0]
    assert (address['db_number'], address['byte_address'], address['bit_offset']) == (7, 36, 3)
    response = _s7(bytes.fromhex('0401'), bytes.fromhex('ff0400101234'), rosctr=3)
    item = ics.parse_s7comm(response)['s7']['data_items'][0]
    assert (item['return_code'], item['transport_size'], item['length'], item['value']) == (255, 4, 16, '1234')


def test_bug_s7_write_acknowledgement():
    # Wireshark packet-s7comm.c WriteVar response branch uses one return code.
    frame = _s7(bytes.fromhex('0501'), b'\xff', rosctr=3)
    assert ics.parse_s7comm(frame)['s7']['data_items'][0]['return_code'] == 255


def test_s7_write_acknowledgement_multiple_return_codes():
    frame = _s7(bytes.fromhex('0502'), bytes.fromhex('ff05'), rosctr=3)
    assert ics.parse_s7comm(frame)['s7']['data_items'] == [
        {'return_code': 255}, {'return_code': 5}]


@pytest.mark.parametrize('data', [b'', b'\xff', b'\xff\x05\xff'])
def test_s7_write_acknowledgement_rejects_count_mismatch(data):
    frame = _s7(bytes.fromhex('0502'), data, rosctr=3)
    with pytest.raises(ics.ParseError, match='return-code count mismatch'):
        ics.parse_s7comm(frame)


def test_bacnet_whois_and_primitive_tags():
    assert ics.parse_bacnet(BACNET)['apdu']['service_name'] == 'who-Is'
    # I-Am application tags: object identifier device/123, unsigned max APDU480,
    # enumerated segmentation3, unsigned vendor42.
    tags = bytes.fromhex('c40200007b2201e09103212a')
    out = ics.parse_bacnet(_bvlc(b'\x01\x00\x10\x00' + tags))['apdu']['tags']
    assert (out[0]['object_type'], out[0]['instance']) == (8, 123)
    assert [tag['value'] for tag in out[1:]] == [480, 3, 42]


def test_bug_bacnet_routed_npdu_order():
    # bacnet-stack npdu_encode_pdu emits DNET/DLEN/DADR, SNET/SLEN/SADR, Hop.
    frame = _bvlc(bytes.fromhex('01280001010300020104ff1008'))
    npdu = ics.parse_bacnet(frame)['npdu']
    assert (npdu['dnet'], npdu['dadr'], npdu['snet'], npdu['sadr'], npdu['hop_count']) == (1, '03', 2, '04', 255)


@pytest.mark.parametrize('wire,expected', [
    ('012000010103ff1008', {'dnet': 1, 'dadr': '03', 'hop_count': 255}),
    ('0108000201041008', {'snet': 2, 'sadr': '04'}),
])
def test_bacnet_single_routing_address(wire, expected):
    report = ics.parse_bacnet(_bvlc(bytes.fromhex(wire)))
    assert {key: report['npdu'][key] for key in expected} == expected
    assert report['apdu']['service_name'] == 'who-Is'


def test_cip_enip_and_implicit_io():
    path = ics.parse_cip(CIP)['path']
    assert [(item['type'], item['value']) for item in path] == [('class', 1), ('instance', 1), ('attribute', 7)]
    response = ics.parse_cip(bytes.fromhex('8e0005013412'))
    assert (response['general_status'], response['additional_status']) == (5, [0x1234])
    registered = ics.parse_enip(ENIP)
    assert (registered['session'], registered['protocol_version'], registered['sender_context']) == (0x11223344, 1, '4354584259544553')
    cpf = struct.pack('<IHHHHHH', 0, 10, 2, 0, 0, 0xb2, len(CIP)) + CIP
    nested = ics.parse_enip(_enip(cpf))['items'][1]['cip']
    assert (nested['service'], nested['path'][2]['value']) == (14, 7)
    io = ics.parse_enip_io(ENIP_IO)
    assert (io['items'][0]['connection_id'], io['items'][0]['sequence'], io['items'][1]['sequence']) == (0x12345678, 5, 6)


@pytest.mark.parametrize(('type_id', 'wire', 'expected'), [
    (1, b'\x81', True), (3, b'\x02', 2), (9, bytes.fromhex('004000'), 0.5),
    (11, bytes.fromhex('feff00'), -2), (13, bytes.fromhex('0000c03f00'), 1.5),
    (15, bytes.fromhex('feffffff03'), -2),
])
def test_iec104_measured_fields(type_id, wire, expected):
    asdu = bytes([type_id, 1, 0xc3, 7, 0x34, 0x12, 0x56, 0x34, 0x12]) + wire
    out = ics.parse_iec104(_iec(asdu))
    assert (out['send_sequence'], out['receive_sequence']) == (7, 13)
    assert (out['asdu']['cause'], out['asdu']['originator'], out['asdu']['common_address'], out['asdu']['negative_confirm'], out['asdu']['test']) == (3, 7, 0x1234, True, True)
    assert (out['asdu']['objects'][0]['ioa'], out['asdu']['objects'][0]['value']) == (0x123456, expected)


def test_iec104_sequential_addresses_commands_and_u_frames():
    out = ics.parse_iec104(_iec(bytes.fromhex('018203000100feff000100')))
    assert [(o['ioa'], o['value']) for o in out['asdu']['objects']] == [(65534, True), (65535, False)]
    out = ics.parse_iec104(_iec(bytes.fromhex('2d01060001000300008d')))
    assert (out['asdu']['objects'][0]['command'], out['asdu']['objects'][0]['select'], out['asdu']['objects'][0]['qualifier']) == (True, True, 3)
    assert ics.parse_iec104(bytes.fromhex('680407000000'))['u_function'] == 'STARTDT act'


@pytest.mark.parametrize(('frame', 'protocol'), [(MODBUS, 'modbus'), (DNP, 'dnp3'), (S7, 's7comm'), (BACNET, 'bacnet'), (ENIP, 'enip'), (IEC, 'iec104')])
def test_public_detection_dispatch(frame, protocol):
    assert ics.detect_protocol(frame) == protocol
    assert ics.dissect(frame)['protocol'] == protocol


def test_public_cli_on_known_modbus_frame(tmp_path, capsys):
    path = tmp_path / 'modbus.bin'
    path.write_bytes(MODBUS)
    assert ics.main([str(path), '--direction', 'request']) == 0
    out = json.loads(capsys.readouterr().out)[0]['analysis']
    assert (out['protocol'], out['pdu']['address'], out['pdu']['quantity']) == ('modbus', 107, 3)


PARSER_SEEDS = {
    'parse_modbus': MODBUS, 'parse_dnp3': DNP, 'parse_dnp3_application': DNP_APP,
    'parse_s7comm': S7, 'parse_bacnet': BACNET, 'parse_cip': CIP,
    'parse_enip': ENIP, 'parse_enip_io': ENIP_IO, 'parse_iec104': IEC,
}


def test_all_public_parsers_have_fuzz_seeds():
    assert {n for n, f in inspect.getmembers(ics, inspect.isfunction) if n.startswith('parse_')} == set(PARSER_SEEDS)


def _fuzz_cases():
    rng = random.Random(0x1c52026)
    for name, seed in PARSER_SEEDS.items():
        samples = [('empty', b'')]
        samples += [(f'ff-{n}', b'\xff' * n) for n in [1, 2, 3, 4, 8, 16, 31, 64]]
        samples += [(f'random-{n}', rng.randbytes(n)) for n in range(1, 65)]
        samples += [(f'truncated-{n}', seed[:n]) for n in range(1, len(seed))]
        for index in range(len(seed)):
            for bit in (0, 7):
                modified = seed[:index] + bytes([seed[index] ^ (1 << bit)]) + seed[index + 1:]
                samples.append((f'bit-{index}-{bit}', modified))
        for label, blob in samples:
            yield pytest.param(name, blob, id=f'{name}-{label}')


@pytest.mark.parametrize(('name', 'blob'), list(_fuzz_cases()))
def test_public_parser_malformed_corpus(name, blob):
    try:
        getattr(ics, name)(blob)
    except ics.ParseError:
        pass


def test_bug_segmented_bacnet_truncated_service():
    with pytest.raises(ics.ParseError, match='confirmed request service'):
        ics.parse_bacnet(bytes.fromhex('810a000b01000805010001'))


def test_bacnet_segmented_request_with_service():
    report = ics.parse_bacnet(_bvlc(bytes.fromhex('010008050100010c')))
    apdu = report['apdu']
    assert (apdu['invoke_id'], apdu['sequence_number'], apdu['proposed_window'],
            apdu['service']) == (1, 0, 1, 12)


