"""Independent hand-packed frames following the published Wireshark layouts.

No engine encoder is used. Struct's endian encoder is independent of the
reader; quarter-circle coordinate vectors catch SA32 versus BA32 confusion.
"""
import json
import random
import struct

import pytest
import defense_stanag as d


def segment(kind, payload):
    return struct.pack('>BI', kind, len(payload) + 5) + payload


def packet(payload, version=b'30'):
    # 32-byte header per STANAG4607 and packet-stanag4607.c.
    return struct.pack('>2sI2sB2sHB10sII', version, 32 + len(payload),
                       b'US', 5, b'  ', 0, 128, b'EAGLE     ', 42, 9) + payload


def mission():
    return struct.pack('>12s12sB10sHBB', b'MISSION A', b'FLIGHT 7', 1,
                       b'CONFIG', 2026, 11, 6)


def location(lat=0x40000000, lon=0xc0000000):
    return struct.pack('>IiIiHIb', 43200000, lat, lon, -1200, 16384, 123000, -7)


def test_gmti_mission_and_location_units():
    raw = packet(segment(1, mission()) + segment(13, location()))
    out = d.parse_4607(raw)['packets'][0]
    assert out['length'] == len(raw)
    assert (out['nationality'], out['platform_id'], out['mission_id'], out['job_id']) == ('US', 'EAGLE', 42, 9)
    assert out['segments'][0]['offset'] == 32
    assert out['segments'][0]['mission'] == {
        'mission_plan': 'MISSION A', 'flight_plan': 'FLIGHT 7',
        'platform_type': 1, 'platform_configuration': 'CONFIG', 'date': '2026-11-06'}
    pos = out['segments'][1]['platform_location']
    assert pos == {'time_ms': 43200000, 'latitude_deg': 45.0,
                   'longitude_deg': 270.0, 'longitude_signed_deg': -90.0,
                   'altitude_cm': -1200, 'track_deg': 90.0,
                   'speed_mm_s': 123000, 'vertical_velocity_dm_s': -7}
    assert d.parse_4607(packet(segment(13, location(-2**31, 0))))['packets'][0]['segments'][0]['platform_location']['latitude_deg'] == -90.0


def test_opaque_and_concatenation():
    raw = packet(segment(255, b'CSCTF{opaque}'), b'21')
    out = d.parse_4607(raw + raw)
    assert out['packets'][1]['offset'] == len(raw)
    assert out['packets'][0]['segments'][0]['body_hex'] == b'CSCTF{opaque}'.hex()
    assert out['flags'] == ['CSCTF{opaque}']


def test_gmti_every_truncation():
    raw = packet(segment(1, mission()) + segment(13, location()))
    for n in range(len(raw)):
        with pytest.raises(d.DefenseStanagError):
            d.parse_4607(raw[:n])


@pytest.mark.parametrize('size', [0, 1, 4, 31, 32, 0xffffffff])
def test_bad_packet_lengths(size):
    raw = bytearray(packet(segment(1, mission())))
    raw[2:6] = size.to_bytes(4, 'big')
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(raw)


@pytest.mark.parametrize('size', [0, 1, 4, 43, 45, 0xffffffff])
def test_bad_segment_lengths(size):
    raw = bytearray(packet(segment(1, mission())))
    raw[33:37] = size.to_bytes(4, 'big')
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(raw)


def test_bad_date_version_and_ascii():
    body = bytearray(mission())
    body[-1] = 32
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(packet(segment(1, body)))
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(packet(segment(1, mission()), b'ZZ'))
    raw = bytearray(packet(segment(1, mission())))
    raw[14] = 255
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(raw)


def test_sis_published_header_semantics():
    # 90EB sync, version00, length0001 (type included), KEEP_ALIVE=17.
    keepalive = bytes.fromhex('90eb00000111')
    out = d.parse_5066(keepalive * 2)
    assert out['records'] == [
        {'offset': n, 'length': 6, 'pdu_type': 17, 'name': 'S_KEEP_ALIVE',
         'body_hex': '', 'body_validation': 'opaque'} for n in (0, 6)]
    old = bytes.fromhex('90eb000111')
    assert d.parse_5066(old, edition_one=True)['records'][0]['pdu_type'] == 17
    with pytest.raises(d.DefenseStanagError):
        d.parse_5066(old)
    raw = b'\x90\xeb\0' + struct.pack('>H', 1 + len(b'CSCTF{sis}')) + b'\xffCSCTF{sis}'
    assert d.parse_5066(raw)['flags'] == ['CSCTF{sis}']
    assert d.parse_5066(raw)['records'][0]['name'] == 'UNKNOWN'


def test_sis_truncation_and_bad_headers():
    raw = bytes.fromhex('90eb00000414010203')
    for n in range(len(raw)):
        with pytest.raises(d.DefenseStanagError):
            d.parse_5066(raw[:n])
    for bad in ('90eb00000011', '90eb01000111', '90ec00000111', '90eb00ffff11'):
        with pytest.raises(d.DefenseStanagError):
            d.parse_5066(bytes.fromhex(bad))
    with pytest.raises(d.DefenseStanagError):
        d.parse_5066(raw, edition_one=1)


def test_limits_types_and_deterministic_noise(monkeypatch):
    for parser in (d.parse_4607, d.parse_5066):
        for invalid in (None, 1, True, '30', [], {}, memoryview(b'30')):
            with pytest.raises(d.DefenseStanagError):
                parser(invalid)
        rng = random.Random(4607)
        for _ in range(300):
            try:
                parser(rng.randbytes(rng.randrange(160)))
            except d.DefenseStanagError:
                pass
    monkeypatch.setattr(d, 'MAX_RECORDS', 1)
    with pytest.raises(d.DefenseStanagError):
        d.parse_5066(bytes.fromhex('90eb00000111') * 2)
    with pytest.raises(d.DefenseStanagError):
        d.parse_4607(packet(segment(1, mission()) * 2))
    monkeypatch.setattr(d, 'MAX_BYTES', 4)
    with pytest.raises(d.DefenseStanagError):
        d.parse_5066(b'x' * 5)


def test_cli(tmp_path, capsys):
    assert d.main(['--help']) == 0
    assert d.main([]) == 2
    assert d.main(['4607', str(tmp_path / 'absent')]) == 2
    path = tmp_path / 'packet.bin'
    path.write_bytes(packet(segment(1, mission())))
    capsys.readouterr()
    assert d.main(['4607', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['packets'][0]['mission_id'] == 42
    assert d.main(['4607', str(path), '--edition-one']) == 2
