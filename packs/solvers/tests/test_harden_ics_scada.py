"""Independent wire vectors and deterministic malformed-input checks for ICS SCADA.

CRC oracle: CRC RevEng catalogue / Infineon published DNP check EA82, plus
crccheck.Crc16Dnp (never the engine checksum) to frame independent fixtures.
S7 framing: RFC1006 and Wireshark packet-s7comm.c; DNP types: Siemens RTU3030C
DNP3 device profile; IEC104 fields: lib60870 CS101 information object codecs.
All packets are constructed locally and only parsed; no network operations.
"""
import inspect
import json
import random
import struct

from crccheck.crc import Crc16Dnp
import pytest
from scapy.all import IP, TCP, UDP, Raw, wrpcap

import ics_scada as s


def _dnp(app, *, transport=0xC0):
    user = bytes([transport]) + app
    header = b'\x05\x64' + bytes([len(user) + 5, 0x44]) + b'\x01\x00\x0a\x00'
    chunks = [user[i:i + 16] for i in range(0, len(user), 16)]
    return header + Crc16Dnp.calc(header).to_bytes(2, 'little') + b''.join(
        part + Crc16Dnp.calc(part).to_bytes(2, 'little') for part in chunks)


def _s7(parameter, data=b'', *, response=False):
    # Protocol 32, Job/Ack_Data, PDU ref 1234, network-order lengths.
    return (struct.pack('>BBHHHH', 0x32, 3 if response else 1, 0, 0x1234,
                        len(parameter), len(data))
            + (b'\x00\x00' if response else b'') + parameter + data)


def _tpkt(s7):
    return b'\x03\x00' + struct.pack('>H', len(s7) + 7) + b'\x02\xf0\x80' + s7


def _iec(type_id, payload, *, address=0x030201, cause=3, count=1, sq=False):
    asdu = bytes([type_id, count | (0x80 if sq else 0), cause, 7]) + b'\x34\x12'
    asdu += address.to_bytes(3, 'little') + payload
    control = struct.pack('<HH', 1000 << 1, 2000 << 1)
    return b'\x68' + bytes([len(asdu) + 4]) + control + asdu


S7_SETUP = _s7(bytes.fromhex('f0000003000403c0'))
TPKT_SETUP = _tpkt(S7_SETUP)
DNP_RESPONSE = _dnp(bytes.fromhex('c08100001e0507010100004841'))
IEC_START = bytes.fromhex('680407000000')


def test_crc_published_check_and_independent_library():
    # https://reveng.sourceforge.io/crc-catalogue/16.htm#crc.cat.crc-16-dnp
    assert s.dnp3_crc(b'123456789') == 0xEA82
    assert s.dnp3_crc(b'') == 0xFFFF
    rng = random.Random(913)
    for length in (1, 2, 8, 16, 17, 64, 255):
        data = rng.randbytes(length)
        assert s.dnp3_crc(data) == Crc16Dnp.calc(data)


def test_s7_setup_and_tpkt_cotp():
    record = s.parse_s7_pdu(S7_SETUP)
    assert record['pdu_reference'] == 0x1234
    assert record['setup'] == {'max_amq_calling': 3, 'max_amq_called': 4, 'pdu_length': 960}
    wrapped, end = s.parse_tpkt_cotp(b'PAD' + TPKT_SETUP, off=3)
    assert end == len(TPKT_SETUP) + 3
    assert wrapped['eot'] is True
    assert wrapped['s7']['setup']['pdu_length'] == 960


def test_s7_address_bit_offset():
    # S7ANY WORD x2, DB7, area84, byte12.bit3 => 99-bit address.
    parameter = bytes.fromhex('0401120a10040002000784000063')
    item = s.parse_s7_pdu(_s7(parameter))['items'][0]
    assert (item['count'], item['db_number'], item['area']) == (2, 7, 0x84)
    assert (item['bit_address'], item['byte_address'], item['bit_offset']) == (99, 12, 3)


@pytest.mark.parametrize('transport,length,raw,key,expected', [
    (3, 1, b'\x01', 'bit', 1),
    (4, 16, bytes.fromhex('fedc'), 'uint16', 65244),
    (4, 32, bytes.fromhex('deadbeef'), 'uint32', 3735928559),
    (5, 16, bytes.fromhex('ff85'), 'int16', -123),
    (6, 4, bytes.fromhex('fffffffe'), 'int32', -2),
    (7, 4, bytes.fromhex('41480000'), 'real', 12.5),
])
def test_s7_data_types(transport, length, raw, key, expected):
    data = bytes([0xFF, transport]) + struct.pack('>H', length) + raw
    item = s.parse_s7_pdu(_s7(b'\x04\x01', data, response=True))['data_items'][0]
    assert item['value'][key] == expected
    assert item['length_bytes'] == len(raw)


@pytest.mark.parametrize('group,variation,raw,expected', [
    (30, 1, bytes.fromhex('0100000080'), -2147483648),
    (30, 2, bytes.fromhex('010080'), -32768),
    (30, 3, bytes.fromhex('c01dfeff'), -123456),
    (30, 4, bytes.fromhex('2efb'), -1234),
    (30, 5, bytes.fromhex('0100004841'), 12.5),
    (40, 1, bytes.fromhex('01feffffff'), -2),
    (40, 2, bytes.fromhex('01ffff'), -1),
    (41, 1, bytes.fromhex('feffffff00'), -2),
    (41, 2, bytes.fromhex('ffff00'), -1),
    (41, 3, bytes.fromhex('0000484100'), 12.5),
    (20, 1, bytes.fromhex('01ffffffff'), 4294967295),
    (20, 2, bytes.fromhex('01ffff'), 65535),
    (20, 5, bytes.fromhex('ffffffff'), 4294967295),
    (20, 6, bytes.fromhex('ffff'), 65535),
])
def test_dnp_known_group_variation_numeric_types(group, variation, raw, expected):
    # qualifier17 = 1-byte count + 1-byte point index; one point #7.
    frame = _dnp(b'\xc5\x81\x00\x00' + bytes([group, variation, 0x17, 1, 7]) + raw)
    record, end = s.parse_dnp3_frame(frame)
    assert end == len(frame)
    assert record['header_crc_ok'] and record['block_crc_ok']
    assert (record['destination'], record['source']) == (1, 10)
    point = record['application']['objects'][0]['points'][0]
    assert point['index'] == 7
    assert point['value'] == expected
    assert type(point['value']) is type(expected)


def test_dnp_binary_crob_and_timestamp():
    binary = bytes.fromhex('010217010581')
    # CROB: trip/pulse on, count2, on100ms, off200ms, success status.
    crob = bytes.fromhex('0c01170109810264000000c800000000')
    time = bytes.fromhex('32010701010203040506')
    frame = _dnp(b'\xc0\x81\x00\x00' + binary + crob + time)
    record = s.parse_dnp3_frame(frame)[0]
    assert record['data_blocks'] == 3
    points = [o['points'][0] for o in record['application']['objects']]
    assert (points[0]['index'], points[0]['state'], points[0]['online']) == (5, 1, 1)
    assert (points[1]['index'], points[1]['count'], points[1]['on_time_ms'], points[1]['off_time_ms']) == (9, 2, 100, 200)
    assert points[2]['ms_since_epoch'] == 0x060504030201


@pytest.mark.parametrize('type_id,raw,field,expected', [
    (1, bytes.fromhex('81'), 'spi', 1),
    (3, bytes.fromhex('82'), 'dpi', 2),
    (5, bytes.fromhex('ff00'), 'value', -1),
    (9, bytes.fromhex('00c000'), 'normalized', -0.5),
    (11, bytes.fromhex('2efb00'), 'scaled', -1234),
    (13, bytes.fromhex('0000484100'), 'float', 12.5),
    (15, bytes.fromhex('feffffff07'), 'counter', -2),
    (21, bytes.fromhex('0080'), 'normalized', -1.0),
    (45, bytes.fromhex('85'), 'select', 1),
    (46, bytes.fromhex('82'), 'dcs', 2),
    (47, bytes.fromhex('81'), 'rcs', 1),
    (48, bytes.fromhex('004000'), 'normalized', 0.5),
    (49, bytes.fromhex('feff00'), 'scaled', -2),
    (50, bytes.fromhex('0000484100'), 'float', 12.5),
    (100, bytes.fromhex('14'), 'qoi', 20),
])
def test_iec104_asdu_values(type_id, raw, field, expected):
    record, end = s.parse_iec104_apdu(_iec(type_id, raw, cause=0xC3))
    assert end == 15 + len(raw)
    assert (record['tx_sequence'], record['rx_sequence']) == (1000, 2000)
    asdu = record['asdu']
    assert (asdu['test'], asdu['negative'], asdu['cause']) == (True, True, 3)
    assert (asdu['originator_address'], asdu['common_address']) == (7, 0x1234)
    point = asdu['information_objects'][0]
    assert point['ioa'] == 0x030201
    assert point[field] == expected


def test_iec104_sequence_and_cp56time():
    values = bytes.fromhex('feff00ff7f00')
    points = s.parse_iec104_apdu(_iec(11, values, address=100, sq=True, count=2))[0]['asdu']['information_objects']
    assert [p['ioa'] for p in points] == [100, 101]
    assert [p['scaled'] for p in points] == [-2, 32767]
    # 2026-11-05 13:14:15.250, weekday4. CP56 milliseconds=15250=3B92.
    time = bytes.fromhex('923b0e0d850b1a')
    point = s.parse_iec104_apdu(_iec(103, time))[0]['asdu']['information_objects'][0]
    assert (point['year'], point['month'], point['day'], point['day_of_week']) == (2026, 11, 5, 4)
    assert (point['hour'], point['minute'], point['second'], point['millisecond']) == (13, 14, 15, 250)


@pytest.mark.parametrize('wire,command', [
    ('680407000000', 'STARTDT act'), ('68040b000000', 'STARTDT con'),
    ('680413000000', 'STOPDT act'), ('680423000000', 'STOPDT con'),
    ('680443000000', 'TESTFR act'), ('680483000000', 'TESTFR con'),
])
def test_iec104_unnumbered_commands(wire, command):
    assert s.parse_iec104_apdu(bytes.fromhex(wire))[0]['u_command'] == command


def test_public_dispatch_iterators_reports_and_cli(tmp_path, capsys):
    frames = [('s7comm', TPKT_SETUP, s.iter_s7), ('dnp3', DNP_RESPONSE, s.iter_dnp3),
              ('iec104', IEC_START, s.iter_iec104)]
    for protocol, frame, iterator in frames:
        assert len(iterator(frame * 2)) == 2
        name, records = s.dissect_payload(frame)
        assert name == protocol and len(records) == 1
        report = s.analyze_bytes(frame, source='vector')
        assert report['protocol'] == protocol and report['frame_count'] == 1
        path = tmp_path / (protocol + '.bin')
        path.write_bytes(frame)
        assert s.analyze_file(path)['protocol'] == protocol
        assert json.loads(s.report([path], as_json=True))[0]['protocol'] == protocol
        assert str(path) in s.format_report(s.analyze_file(path), color=False)
        assert s.main([str(path), '--json']) == 0
        assert json.loads(capsys.readouterr().out)[0]['protocol'] == protocol


def test_scapy_capture_oracle(tmp_path):
    # Packet layout/file writer oracle is Scapy. Expected reassembled bytes are
    # the independently built TPKT fixture, never a second engine decode.
    packets = [
        IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=40000, dport=102, seq=106)/Raw(TPKT_SETUP[6:]),
        IP(src='192.0.2.1', dst='192.0.2.2')/TCP(sport=40000, dport=102, seq=100)/Raw(TPKT_SETUP[:6]),
        IP(src='192.0.2.1', dst='192.0.2.2')/UDP(sport=40001, dport=20000)/Raw(DNP_RESPONSE),
    ]
    path = tmp_path/'independent.pcap'
    wrpcap(str(path), packets)
    flows = s.read_pcap(str(path))
    assert {f['proto']: f['payload'] for f in flows} == {'tcp': TPKT_SETUP, 'udp': DNP_RESPONSE}
    report = s.analyze_file(path)
    assert {f['protocol'] for f in report['flows']} == {'s7comm', 'dnp3'}


def test_dnp_multiblock_octet_string():
    flag = b'CSCTF{offline_vector}'
    flagged = _dnp(b'\xc0\x81\x00\x00' + bytes([110, len(flag), 7, 1]) + flag)
    record = s.parse_dnp3_frame(flagged)[0]
    assert record['application']['objects'][0]['points'][0]['ascii'] == flag.decode('ascii')


def _corpus(seed, magic):
    rng = random.Random(0xC5C7)
    values = [b'', *(b'\xff' * n for n in (1, 2, 4, 8, 16, 32, 64, 128)),
              *(b'\0' * n for n in (1, 2, 4, 16, 64)),
              *(rng.randbytes(rng.randrange(1, 129)) for _ in range(80)),
              *(magic[:n] for n in range(len(magic))),
              *(seed[:n] for n in range(len(seed)))]
    for i in range(len(seed)):
        for bit in (0, 3, 7):
            changed = bytearray(seed)
            changed[i] ^= 1 << bit
            values.append(bytes(changed))
    return list(dict.fromkeys(values))


_SEEDS = {'parse_s7_pdu': (S7_SETUP, b'\x32'),
          'parse_tpkt_cotp': (TPKT_SETUP, b'\x03\x00'),
          'parse_dnp3_frame': (DNP_RESPONSE, b'\x05\x64'),
          'parse_iec104_apdu': (_iec(13, bytes.fromhex('0000484100')), b'\x68')}


def test_fuzz_inventory_covers_every_public_parser():
    assert {name for name, fn in inspect.getmembers(s, inspect.isfunction) if name.startswith('parse_')} == set(_SEEDS)


@pytest.mark.parametrize('name', sorted(_SEEDS))
def test_fail_closed_deterministic_corpus(name):
    seed, magic = _SEEDS[name]
    parser = getattr(s, name)
    for data in _corpus(seed, magic):
        try:
            parser(data)
        except s.ParseError:
            pass
        except Exception as exc:
            pytest.fail(f'{name}({data.hex()}) leaked {type(exc).__name__}: {exc}')


def test_bug_cotp_connect_truncated_source_reference():
    with pytest.raises(s.ParseError):
        s.parse_tpkt_cotp(bytes.fromhex('0300000906e0000000'))


def test_bug_dnp_missing_one_byte_count():
    # Valid independent CRCs, but object header lacks the required count byte.
    with pytest.raises(s.ParseError):
        s.parse_dnp3_frame(bytes.fromhex('05640d4401000a0050fbc0c08100001e0107e787'))


@pytest.mark.parametrize('pdu_type', [0xE0, 0xD0])
def test_cotp_connection_reference_boundaries(pdu_type):
    frame = bytes.fromhex('0300000b06') + bytes([pdu_type]) + bytes.fromhex('1234567800')
    record, end = s.parse_tpkt_cotp(b'PAD' + frame, off=3)
    assert (record['dst_ref'], record['src_ref'], end) == (0x1234, 0x5678, 14)
    # Bytes after this TPKT do not complete its declared header.
    truncated = bytes.fromhex('0300000906') + bytes([pdu_type]) + bytes.fromhex('123456')
    with pytest.raises(s.ParseError):
        s.parse_tpkt_cotp(truncated + frame)
    # A too-short LI must not borrow reference bytes from the payload.
    short_li = frame[:4] + b'\x03' + frame[5:]
    with pytest.raises(s.ParseError):
        s.parse_tpkt_cotp(short_li)


@pytest.mark.parametrize('qualifier', [0x07, 0x17, 0x27])
def test_dnp_count_byte_bounds_with_independent_crcs(qualifier):
    missing_count = _dnp(b'\xc0\x81\x00\x00' + bytes([30, 1, qualifier]))
    with pytest.raises(s.ParseError):
        s.parse_dnp3_frame(missing_count)
    zero_count = _dnp(b'\xc0\x81\x00\x00' + bytes([30, 1, qualifier, 0]))
    obj = s.parse_dnp3_frame(zero_count)[0]['application']['objects'][0]
    assert obj['count'] == 0


def test_dnp_multiblock_recovered_flag_in_report():
    flag = b'CSCTF{offline_vector}'
    flagged = _dnp(b'\xc0\x81\x00\x00' + bytes([110, len(flag), 7, 1]) + flag)
    # The API explicitly reports both raw-wire and decoded candidates; only
    # membership of the known semantic flag is part of the documented contract.
    assert flag.decode('ascii') in s.analyze_bytes(flagged)['flags']
