"""Independent vector locks and deterministic malformed input for net_voip.

SIP/Digest vectors: RFC 3261 §4 and RFC 7616 §3.9.1. RTP wire data is
serialized by Scapy, never by the engine under test; expected durations follow
RFC 3551's 8-kHz RTP clock for PCMU/PCMA/G722. The capture adapters only carry
bytes/addresses and deliberately do not implement any protocol parsing.

net_voip declares no exception class. Every tested parser must return cleanly.
"""
import inspect
import random
from types import SimpleNamespace
from urllib.request import parse_http_list, parse_keqv_list

import pytest
from scapy.layers.rtp import RTP, RTPExtension
from scapy.packet import Raw
import net_voip as engine


# Selected header fields from the published RFC3261 §4 INVITE example.
RFC_INVITE = (
    b'INVITE sip:bob@biloxi.com SIP/2.0\r\n'
    b'To: Bob <sip:bob@biloxi.com>\r\n'
    b'From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n'
    b'Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n'
    b'CSeq: 314159 INVITE\r\n'
    b'Contact: <sip:alice@pc33.atlanta.com>\r\n'
    b'Content-Length: 0\r\n\r\n'
)
# The RFC7616 §3.9.1 MD5 Authorization example, unfolded without altering values.
RFC_DIGEST = (
    'Digest username="Mufasa", realm="http-auth@example.org", '
    'uri="/dir/index.html", algorithm=MD5, '
    'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", nc=00000001, '
    'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", qop=auth, '
    'response="8ca523f5e9506fed4657c9700eebdbec", '
    'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
)


def _udp(data, source='192.0.2.1', destination='192.0.2.2', sport=5000, dport=5002):
    return SimpleNamespace(proto=17, payload=data, frag=0, src=source, dst=destination,
                           sport=sport, dport=dport)


def _capture(payloads=(), tcp_streams=()):
    streams = {i: value for i, value in enumerate(tcp_streams)}
    return SimpleNamespace(packets=[_udp(p) for p in payloads], streams=lambda: streams)


def _tcp(data):
    return SimpleNamespace(data=data, src='192.0.2.1', dst='192.0.2.2', sport=5060, dport=5060)


def _rtp(sequence, timestamp, payload=b'\xff' * 160, pt=0, ssrc=0x12345678,
         padding=0, extension=False):
    header = RTP(version=2, payload_type=pt, sequence=sequence, timestamp=timestamp,
                 sourcesync=ssrc, marker=0, padding=bool(padding),
                 extension=extension, sync=[0x11223344, 0xaabbccdd] if extension else [])
    if extension:
        header /= RTPExtension(header_id=0xbede, header=[0x43534354])
    if padding:
        payload += b'\0' * (padding - 1) + bytes([padding])
    return bytes(header / Raw(payload))


def _sip_message(body=b'', call_id='CSCTF{message}', method='MESSAGE'):
    # Independent RFC3261 text framing; Content-Length counts body octets.
    header = (f'{method} sip:bob@example.org SIP/2.0\r\n'
              f'From: <sip:alice@example.org>;tag=1\r\n'
              f'To: <sip:bob@example.org>\r\n'
              f'Call-ID: {call_id}\r\n'
              f'CSeq: 7 {method}\r\n'
              f'Content-Length: {len(body)}\r\n\r\n')
    return header.encode('ascii') + body


def _mutations(seed, valid):
    """Deterministic bounded corpus: magic truncation, FF/zero, random, flips."""
    rng = random.Random(seed)
    corpus = [b'', b'\xff', b'\xff' * 256, b'\0' * 256]
    corpus.extend(valid[:n] for n in range(len(valid)))
    for _ in range(192):
        corpus.append(rng.randbytes(rng.randrange(257)))
    for position in range(len(valid)):
        for bit in (1, 0x80):
            blob = bytearray(valid)
            blob[position] ^= bit
            corpus.append(bytes(blob))
    return corpus


def test_public_parse_is_inventory():
    actual = {name for name, obj in vars(engine).items()
              if name.startswith(('parse_', 'is_')) and inspect.isfunction(obj)}
    assert actual == {'parse_digest', 'parse_sip'}


def test_digest_rfc7616_published_values():
    result = engine.parse_digest(RFC_DIGEST)
    assert result == {
        'username': 'Mufasa', 'realm': 'http-auth@example.org', 'uri': '/dir/index.html',
        'algorithm': 'MD5', 'nonce': '7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v',
        'nc': '00000001', 'cnonce': 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
        'qop': 'auth', 'response': '8ca523f5e9506fed4657c9700eebdbec',
        'opaque': 'FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS',
    }


def test_digest_challenge_quoted_list_and_case_against_stdlib():
    fields = 'Realm="CSCTF{realm}", QOP="auth,auth-int", algorithm=SHA-256, nonce="abc"'
    oracle = {key.lower(): value for key, value in parse_keqv_list(parse_http_list(fields)).items()}
    assert engine.parse_digest('dIgEsT ' + fields) == oracle


def test_sip_rfc3261_invite_selected_fields():
    result = engine.parse_sip(RFC_INVITE)
    assert (result['kind'], result['method'], result['status']) == ('request', 'INVITE', None)
    assert result['from'] == 'Alice <sip:alice@atlanta.com>;tag=1928301774'
    assert result['to'] == 'Bob <sip:bob@biloxi.com>'
    assert result['call_id'] == 'a84b4c76e66710@pc33.atlanta.com'
    assert result['cseq'] == '314159 INVITE'
    assert result['contact'] == '<sip:alice@pc33.atlanta.com>'


def test_sip_response_compact_headers_folding_and_digest():
    wire = (b'SIP/2.0 407 Proxy Authentication Required\r\n'
            b'f: <sip:alice@example.org>;tag=1\r\n'
            b't: <sip:bob@example.org>\r\n'
            b'i: CSCTF{compact}\r\n'
            b'm: <sip:bob@192.0.2.2>\r\n'
            b'User-Agent: Carrier\r\n\tLab/1.0\r\n'
            b'Proxy-Authenticate: Digest realm="CSCTF{realm}", nonce="abc",\r\n'
            b' qop="auth,auth-int"\r\n'
            b'l: 0\r\n\r\n')
    result = engine.parse_sip(wire)
    assert (result['kind'], result['status'], result['method']) == ('response', 407, None)
    assert result['call_id'] == 'CSCTF{compact}'
    assert result['contact'] == '<sip:bob@192.0.2.2>'
    assert result['user_agent'] == 'Carrier Lab/1.0'
    assert result['www_authenticate'] == {'realm': 'CSCTF{realm}', 'nonce': 'abc', 'qop': 'auth,auth-int'}


def test_sip_authorization_independent_digest_vector():
    wire = RFC_INVITE.replace(b'Content-Length: 0', b'Authorization: ' + RFC_DIGEST.encode() + b'\r\nContent-Length: 0')
    assert engine.parse_sip(wire)['authorization']['response'] == '8ca523f5e9506fed4657c9700eebdbec'


def test_sip_messages_udp_and_concatenated_tcp():
    second = _sip_message(call_id='CSCTF{second}')
    cap = _capture([RFC_INVITE], [_tcp(second + _sip_message(call_id='CSCTF{third}', method='OPTIONS'))])
    results = engine.sip_messages(cap)
    assert [r['call_id'] for r in results] == ['a84b4c76e66710@pc33.atlanta.com', 'CSCTF{second}', 'CSCTF{third}']
    assert all(r['src'] == '192.0.2.1' for r in results)


@pytest.mark.parametrize('pt', [0, 8, 9])
def test_rtp_scapy_wire_fields_and_clock_duration(pt):
    # RFC3551 §4.5.2 and table 4: PCMU, PCMA and G722 use 8000 RTP ticks/s.
    wires = [_rtp(100 + i, 5000 + 160 * i, pt=pt) for i in range(4)]
    reference = [RTP(w) for w in wires]
    result = engine.rtp_streams(_capture(wires))
    assert len(result) == 1
    stream = result[0]
    assert stream['ssrc'] == 0x12345678
    assert stream['pt'] == pt
    assert stream['seqs'] == [int(r.sequence) for r in reference]
    assert stream['timestamps'] == [int(r.timestamp) for r in reference]
    assert stream['media_lens'] == [len(bytes(r.payload)) for r in reference]
    assert engine.rtp_duration(stream) == pytest.approx(4 * 160 / 8000)


def test_rtp_scapy_csrc_extension_and_padding():
    wires = [_rtp(i, i * 160, extension=True, padding=4) for i in (7, 8)]
    reference = RTP(wires[0])
    assert reference.numsync == 2 and reference.extension == 1
    assert reference[RTPExtension].header_len == 1
    result = engine.rtp_streams(_capture(wires))[0]
    assert result['media_lens'] == [160, 160]
    assert engine.rtp_duration(result) == pytest.approx(0.04)


def test_rtp_timestamp_wrap_and_reordering():
    wires = [_rtp(21, 0x00000060), _rtp(20, 0xffffffc0)]
    result = engine.rtp_streams(_capture(wires))[0]
    assert engine.rtp_duration(result) == pytest.approx(0.04)


@pytest.mark.parametrize('wires', [
    [_rtp(1, 160)],
    [_rtp(1, 160, ssrc=1), _rtp(2, 320, ssrc=2)],
    [_rtp(1, 160, pt=0), _rtp(2, 320, pt=8)],
])
def test_rtp_unambiguous_stream_requirement(wires):
    assert engine.rtp_streams(_capture(wires)) == []


@pytest.mark.parametrize('wires', [
    [_rtp(1, 160), _rtp(3, 480)],
    [_rtp(1, 160), _rtp(2, 400)],
    [_rtp(1, 160, pt=101), _rtp(2, 320, pt=101)],
])
def test_rtp_duration_rejects_gaps_mismatch_or_unknown_codec(wires):
    stream = engine.rtp_streams(_capture(wires))[0]
    assert engine.rtp_duration(stream) is None


def test_digest_fail_closed_deterministic_text_corpus():
    for raw in _mutations(32617616, RFC_DIGEST.encode()):
        result = engine.parse_digest(raw.decode('latin1'))
        assert result is None or isinstance(result, dict)


def test_sip_fail_closed_deterministic_byte_corpus():
    for wire in _mutations(3261, RFC_INVITE):
        result = engine.parse_sip(wire)
        assert result is None or isinstance(result, dict)


def test_rtp_and_sip_aggregation_fail_closed_deterministic_corpus():
    for wire in _mutations(3550, _rtp(1, 160, extension=True, padding=4)):
        cap = _capture([wire, wire])
        assert isinstance(engine.sip_messages(cap), list)
        for stream in engine.rtp_streams(cap):
            result = engine.rtp_duration(stream)
            assert result is None or isinstance(result, (int, float))


@pytest.mark.parametrize('username', [r'a\"b', r'a\\b', r'a\,b'])
def test_bug_digest_escaped_quote_against_stdlib(username):
    fields = 'username="' + username + '", realm="example.org", nonce="CSCTF{nonce}"'
    expected = parse_keqv_list(parse_http_list(fields))['username']
    assert engine.parse_digest('Digest ' + fields)['username'] == expected


@pytest.mark.parametrize('order', [(0, 1), (1, 0)])
def test_bug_rtp_sequence_wrap_duration(order):
    packets = [_rtp(65535, 160), _rtp(0, 320)]
    wires = [packets[i] for i in order]
    stream = engine.rtp_streams(_capture(wires))[0]
    assert engine.rtp_duration(stream) == pytest.approx(2 * 160 / 8000)


def test_bug_rtp_zero_padding_count():
    # RFC3550 §5.1: the final octet counts padding including itself, hence >=1.
    wires = [bytes(RTP(version=2, padding=1, payload_type=0, sequence=i,
                       timestamp=i * 160, sourcesync=7) / Raw(b'\xff' * 159 + b'\0'))
             for i in (1, 2)]
    assert engine.rtp_streams(_capture(wires)) == []


def test_bug_sip_body_is_not_a_second_message():
    body = b'SIP/2.0 200 text inside body\r\nCall-ID: CSCTF{body}\r\n\r\n'
    wire = _sip_message(body, 'CSCTF{outer}') + _sip_message(call_id='CSCTF{next}')
    assert [r['call_id'] for r in engine.sip_messages(_capture(tcp_streams=[_tcp(wire)]))] == [
        'CSCTF{outer}', 'CSCTF{next}']


@pytest.mark.parametrize('header', [b'Content-Length: ', b'l: ', b'cOnTeNt-LeNgTh:\r\n\t'])
def test_sip_binary_body_octets_and_compact_or_folded_length(header):
    # The UTF-8 prefix counts as two octets; the last octet is not a newline.
    body = b'\xc3\xa9\nSIP/2.0 200 body text\r\nCall-ID: body\r\n\r\n\xff'
    wire = _sip_message(body, 'outer')
    wire = wire.replace(b'Content-Length: ', header, 1) + _sip_message(call_id='next')
    assert [r['call_id'] for r in engine.sip_messages(_capture(tcp_streams=[_tcp(wire)]))] == [
        'outer', 'next']


@pytest.mark.parametrize('length', [b'-1', b'+1', b'abc', b'999999999', b'9' * 5000])
def test_sip_invalid_length_does_not_scan_body(length):
    wire = _sip_message(call_id='outer').replace(b'Content-Length: 0', b'Content-Length: ' + length)
    wire += _sip_message(call_id='body')
    assert engine.sip_messages(_capture(tcp_streams=[_tcp(wire)])) == []


def test_sip_truncated_body_does_not_scan_embedded_message():
    body = _sip_message(call_id='body') + b'last octet'
    wire = _sip_message(body, 'outer')[:-1]
    assert engine.sip_messages(_capture(tcp_streams=[_tcp(wire)])) == []


@pytest.mark.parametrize('seqs', [(65534, 0), (65535, 0, 0)])
def test_rtp_wrap_rejects_missing_or_duplicate_packets(seqs):
    wires = [_rtp(seq, i * 160) for i, seq in enumerate(seqs)]
    stream = engine.rtp_streams(_capture(wires))[0]
    assert engine.rtp_duration(stream) is None
