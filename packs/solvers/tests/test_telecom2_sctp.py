"""Noncircular SCTP tests: Scapy writer + RFC field fixtures, no engine encoder."""
import random
import struct

import pytest
from scapy.layers.sctp import SCTP, SCTPChunkData, SCTPChunkInit, SCTPChunkSACK
import telecom2_sctp as s


def data_packet(tsn=1, data=b'CSCTF{carrier}', begin=1, end=1, stream=2, seq=3, ppid=60, unordered=0):
    return bytes(SCTP(sport=2905, dport=2906, tag=123) /
                 SCTPChunkData(tsn=tsn, stream_id=stream, stream_seq=seq, proto_id=ppid,
                               beginning=begin, ending=end, unordered=unordered, data=data))


def test_crc32c_standard_check_and_scapy_wire():
    # CRC-32C canonical check string; separately compare the SCTP wire to Scapy.
    assert s.crc32c(b'123456789') == 0xe3069283
    raw = data_packet()
    rec = s.parse_packet(raw, require_checksum=True)
    assert rec['checksum'] == int.from_bytes(raw[8:12], 'little')
    assert rec['checksum_valid']
    ch = rec['chunks'][0]
    assert (ch['tsn'], ch['stream_id'], ch['stream_sequence'], ch['ppid']) == (1, 2, 3, 60)
    assert ch['protocol_hint'] == 'NGAP'
    assert bytes.fromhex(ch['payload_hex']) == b'CSCTF{carrier}'


def test_checksum_corruption_is_explicit():
    raw = bytearray(data_packet())
    raw[-4] ^= 1
    assert not s.parse_packet(raw)['checksum_valid']
    with pytest.raises(s.SCTPError, match='CRC32c'):
        s.parse_packet(raw, require_checksum=True)


def test_multiple_chunks_and_padding():
    raw = bytes(SCTP(sport=1, dport=2, tag=123) /
                SCTPChunkData(tsn=5, beginning=1, ending=1, data=b'a') /
                SCTPChunkData(tsn=6, beginning=1, ending=1, data=b'b'))
    rec = s.parse_packet(raw, require_checksum=True)
    assert [c['payload_hex'] for c in rec['chunks']] == ['61', '62']
    # RFC9260 receiver ignores padding contents.
    raw = bytearray(raw)
    raw[29:32] = b'XYZ'
    assert len(s.parse_packet(raw)['chunks']) == 2


def test_init_parameters_and_sack():
    # Hand-packed RFC9260 INIT with IPv4 address parameter, not engine output.
    body = struct.pack('!IIHHI', 5, 65535, 3, 4, 100) + struct.pack('!HH4B', 5, 8, 192, 0, 2, 1)
    raw = struct.pack('!HHII', 1, 2, 0, 0) + struct.pack('!BBH', 1, 0, 4 + len(body)) + body
    init = s.parse_packet(raw)['chunks'][0]
    assert init['parameters'][0]['address'] == '192.0.2.1'
    assert init['initial_tsn'] == 100
    oracle = bytes(SCTP(sport=1, dport=2) / SCTPChunkInit(init_tag=5, n_out_streams=3, n_in_streams=4, init_tsn=100))
    assert s.parse_packet(oracle, require_checksum=True)['chunks'][0]['inbound_streams'] == 4
    sack = bytes(SCTP(sport=1, dport=2) / SCTPChunkSACK(cumul_tsn_ack=20, a_rwnd=99, gap_ack_list=['1:3'], dup_tsn_list=[18]))
    result = s.parse_packet(sack, require_checksum=True)['chunks'][0]
    assert result['gaps'] == [[1, 3]]
    assert result['duplicate_tsns'] == [18]


def test_reassembly_reordering_wrap_and_retransmission():
    a = data_packet(0xffffffff, b'CSCTF{', 1, 0)
    b = data_packet(0, b'carrier', 0, 0)
    c = data_packet(1, b'}', 0, 1)
    rec = s.reassemble([c, b, a, b], require_checksum=True)
    assert bytes.fromhex(rec[0]['payload_hex']) == b'CSCTF{carrier}'
    assert rec[0]['first_tsn'] == 0xffffffff


def test_unordered_fragments_ignore_ssn():
    a = data_packet(4, b'a', 1, 0, seq=100, unordered=1)
    b = data_packet(5, b'b', 0, 1, seq=200, unordered=1)
    assert s.reassemble([a, b])[0]['payload_hex'] == '6162'


@pytest.mark.parametrize('packets', [
    [data_packet(1, b'a', 0, 1)],
    [data_packet(1, b'a', 1, 0)],
    [data_packet(1, b'a', 1, 0), data_packet(3, b'b', 0, 1)],
    [data_packet(1, b'a'), data_packet(1, b'b')],
    [data_packet(1, b'a', 1, 0), data_packet(2, b'b', 0, 1, stream=9)],
    [data_packet(1, b'a', 1, 0), data_packet(2, b'b', 0, 1, ppid=3)],
    [data_packet(1, b'a', 1, 0), data_packet(2, b'b', 0, 1, seq=9)],
])
def test_reassembly_fails_closed(packets):
    with pytest.raises(s.SCTPError):
        s.reassemble(packets)


def test_mixed_association_and_unsupported_interleave():
    other = bytearray(data_packet())
    other[7] = 222
    with pytest.raises(s.SCTPError, match='mixed'):
        s.reassemble([data_packet(), other])
    raw = struct.pack('!HHII', 1, 2, 3, 0) + b'\x40\0\0\x04'
    assert s.parse_packet(raw)['chunks'][0]['name'] == 'I_DATA'
    with pytest.raises(s.SCTPError, match='interleaving'):
        s.reassemble([raw])


def test_truncation_and_type_contract():
    raw = data_packet()
    for n in range(len(raw)):
        with pytest.raises(s.SCTPError):
            s.parse_packet(raw[:n])
    for value in (None, 'string', 42, {}, []):
        with pytest.raises(s.SCTPError):
            s.parse_packet(value)
    rng = random.Random(2026)
    for _ in range(200):
        try:
            s.parse_packet(rng.randbytes(rng.randrange(100)))
        except s.SCTPError:
            pass  # Any other exception fails the test.


def test_nested_bounds_unknown_and_cli(tmp_path, capsys):
    header = struct.pack('!HHII', 1, 2, 3, 0)
    assert s.parse_packet(header + b'\xfe\0\0\x04')['chunks'][0]['name'] == 'UNKNOWN'
    with pytest.raises(s.SCTPError):
        s.parse_packet(header + b'\x04\0\0\x08\0\x01\0\x02')
    path = tmp_path / 'packet.bin'
    path.write_bytes(data_packet())
    assert s.main([str(path), '--require-checksum']) == 0
    assert s.main(['--help']) == 0
    assert s.main([]) == 2
    assert s.main([str(path) + '.missing']) == 2


def test_resource_limits_and_invalid_buffer():
    released = memoryview(b'ab')
    released.release()
    for data in (released, b'x' * (s.MAX_BYTES + 1)):
        with pytest.raises(s.SCTPError):
            s.parse_packet(data)
    with pytest.raises(s.SCTPError):
        s.reassemble([data_packet()] * (s.MAX_ITEMS + 1))


def test_init_verification_and_forbidden_bundling():
    raw = bytes(SCTP(sport=1, dport=2, tag=99) /
                SCTPChunkInit(init_tag=5, n_out_streams=1, n_in_streams=1))
    with pytest.raises(s.SCTPError, match='verification tag'):
        s.parse_packet(raw)
    raw = bytes(SCTP(sport=1, dport=2, tag=0) /
                SCTPChunkInit(init_tag=5, n_out_streams=1, n_in_streams=1) /
                SCTPChunkData(beginning=1, ending=1, data=b'a'))
    with pytest.raises(s.SCTPError, match='bundled'):
        s.parse_packet(raw)
