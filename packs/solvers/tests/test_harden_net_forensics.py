"""Independent vectors and deterministic malformed-input tests for forensics APIs.

Oracles: dnspython, dpkt, Scapy, hyperframe, cryptography; RFC6455 section5.7.
TLS/QUIC ciphertext is built here from RFC8446/RFC9001 using cryptography, not
with any repository crypto helper. All data is local, generated and inert.
"""
import base64
import hashlib
import io
import random
import struct

import dns.message
import dns.name
import dns.rrset
import dpkt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from hyperframe.frame import DataFrame, SettingsFrame
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.tls.session import parse_nss_keys

import network_forensics as nf

PAYLOAD = b'CSCTF{independent_network_vector}'
RANDOM = bytes(range(32))
SECRET = bytes(range(32, 64))
LABEL = 'CLIENT_TRAFFIC_SECRET_0'
KEYLOG = f'{LABEL} {RANDOM.hex()} {SECRET.hex()}\n'.encode()


def pcap(frames):
    f = io.BytesIO()
    w = dpkt.pcap.Writer(f)
    for i, frame in enumerate(frames):
        w.writepkt(bytes(frame), ts=1 + i / 8)
    return f.getvalue()


def tcp_capture(content=PAYLOAD):
    base = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') / IP(src='192.0.2.1', dst='192.0.2.2')
    split = len(content) // 2
    rows = [base / TCP(sport=12000, dport=80, seq=100, flags='S'),
            base / TCP(sport=12000, dport=80, seq=101, flags='PA') / content[:split],
            base / TCP(sport=12000, dport=80, seq=101 + split, flags='PA') / content[split:],
            base / TCP(sport=12000, dport=80, seq=101 + len(content), flags='FA')]
    return pcap(rows)


def dns_pair():
    q = dns.message.make_query('carrier.test.', 'TXT')
    q.id = 0x4353
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text('carrier.test.', 60, 'IN', 'TXT', '"CSCTF{" "dns}"'))
    r.answer.append(dns.rrset.from_text('carrier.test.', 120, 'IN', 'MX', '10 mail.carrier.test.'))
    r.authority.append(dns.rrset.from_text('carrier.test.', 300, 'IN', 'SOA', 'ns.carrier.test. hostmaster.carrier.test. 1 2 3 4 5'))
    return q.to_wire(), r.to_wire()


def http_pair():
    request = dpkt.http.Request(method='POST', uri='/flag.bin', headers={'host': 'carrier.test', 'content-length': str(len(PAYLOAD))}, body=PAYLOAD)
    response = dpkt.http.Response(status='200', reason='OK', headers={'content-length': str(len(PAYLOAD)), 'content-type': 'application/octet-stream'}, body=PAYLOAD)
    return bytes(request), bytes(response)


def hkdf_label(label, length):
    full = b'tls13 ' + label
    info = struct.pack('!H', length) + bytes([len(full)]) + full + b'\x00'
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(SECRET)


def tls_records():
    key, iv = hkdf_label(b'key', 16), hkdf_label(b'iv', 12)
    result = []
    for seq, content in enumerate((PAYLOAD, b'next')):
        inner = content + b'\x17'
        header = b'\x17\x03\x03' + struct.pack('!H', len(inner) + 16)
        nonce = (int.from_bytes(iv, 'big') ^ seq).to_bytes(12, 'big')
        result.append(header + AESGCM(key).encrypt(nonce, inner, header))
    return result


def quic_short():
    key, iv, hp = (hkdf_label(b'quic key', 16), hkdf_label(b'quic iv', 12), hkdf_label(b'quic hp', 16))
    # RFC9000 STREAM LEN frame, stream=0, no offset, length in one-byte varint.
    plain = b'\x0a\x00' + bytes([len(PAYLOAD)]) + PAYLOAD
    pn, dcid = 7, b'CID12345'
    header = b'\x40' + dcid + bytes([pn])
    nonce = (int.from_bytes(iv, 'big') ^ pn).to_bytes(12, 'big')
    ciphertext = AESGCM(key).encrypt(nonce, plain, header)
    raw = bytearray(header + ciphertext)
    offset = 1 + len(dcid)
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(raw[offset + 4:offset + 20])) + encryptor.finalize()
    raw[0] ^= mask[0] & 0x1f
    raw[offset] ^= mask[1]
    return bytes(raw), plain


def test_capture_and_reassembly_against_dpkt_scapy():
    wire = tcp_capture()
    artifact = nf.admit_capture(wire)
    assert artifact is not None
    assert artifact.packets == len(list(dpkt.pcap.Reader(io.BytesIO(wire)))) == 4
    assert artifact.sha256 == hashlib.sha256(wire).hexdigest()
    assert artifact.dpkt_crosschecked
    streams = nf.reassemble_tcp(wire)
    assert len(streams) == 1
    assert streams[0].data == PAYLOAD
    assert streams[0].src == '192.0.2.1'
    assert streams[0].syn and streams[0].fin and streams[0].complete


def test_http_and_object_reconstruction_against_dpkt():
    request, response = http_pair()
    for wire, oracle in [(request, dpkt.http.Request), (response, dpkt.http.Response)]:
        result = nf.decode_http_stream(wire)
        assert len(result) == 1
        assert result[0].body == oracle(wire).body == PAYLOAD
        assert result[0].header('Content-Length') == str(len(PAYLOAD))
    objects = nf.reconstruct_http_objects(request, response)
    assert {o.direction for o in objects} == {'upload', 'download'}
    assert all(o.data == PAYLOAD and o.sha256 == hashlib.sha256(PAYLOAD).hexdigest() for o in objects)


def test_dns_compression_records_tcp_transactions_and_txt():
    query, response = dns_pair()
    oracle = dns.message.from_wire(response)
    result = nf.decode_dns_message(response)
    assert result.ident == oracle.id == 0x4353
    assert result.questions[0].name == 'carrier.test'
    assert result.answers[0].value == (b'CSCTF{', b'dns}')
    assert result.answers[1].value == (10, 'mail.carrier.test')
    assert result.authority[0].value == ('ns.carrier.test', 'hostmaster.carrier.test', 1, 2, 3, 4, 5)
    wire = struct.pack('!H', len(response)) + response
    assert nf.decode_dns_message(wire, tcp=True) == result
    stream = struct.pack('!H', len(query)) + query + wire
    assert [m.ident for m in nf.decode_dns_tcp_stream(stream)] == [0x4353, 0x4353]
    rows = [nf.DNSDatagram('192.0.2.1', 12000, '192.0.2.2', 53, query, timestamp_ns=100),
            nf.DNSDatagram('192.0.2.2', 53, '192.0.2.1', 12000, response, timestamp_ns=150)]
    transactions = nf.reconstruct_dns_transactions(rows)
    assert len(transactions) == 1 and transactions[0].latency_ns == 50
    obj = nf.extract_dns_txt_objects([result])[0]
    assert obj.data == b'CSCTF{dns}'
    assert obj.sha256 == hashlib.sha256(b'CSCTF{dns}').hexdigest()


def test_dns_label_boundaries_and_encoded_object():
    special = dns.name.Name((b'a.b', b'back\\slash', b'\x00\xff', b''))
    query = dns.message.make_query(special, 'A')
    query.id = 0x4353
    result = nf.decode_dns_message(query.to_wire())
    assert dns.name.from_text(result.questions[0].name + '.') == special
    pieces = (PAYLOAD[:12], PAYLOAD[12:])
    messages = []
    for i, chunk in enumerate(pieces, 1):
        label = base64.b32encode(chunk).decode().rstrip('=')
        query = dns.message.make_query(f'{i}-2-{label}.tunnel.test.', 'A')
        query.id = i
        wire = query.to_wire()
        messages.append(nf.decode_dns_message(wire))
    obj = nf.reconstruct_dns_label_object(messages[::-1], 'tunnel.test', expected_sha256=hashlib.sha256(PAYLOAD).hexdigest())
    assert obj.data == PAYLOAD
    assert nf.reconstruct_dns_label_object(messages[:1], 'tunnel.test') is None


@pytest.mark.parametrize('wire,client', [
    ('810548656c6c6f', False), ('818537fa213d7f9f4d5158', True),
    ('010348656c80026c6f', False),
])
def test_websocket_rfc6455_section_5_7(wire, client):
    result = nf.decode_websocket_stream(bytes.fromhex(wire), from_client=client)
    assert len(result.messages) == 1
    assert result.messages[0].data == b'Hello' and result.messages[0].text == 'Hello'


def test_http2_hyperframe_vector():
    settings = SettingsFrame(0)
    settings.settings[4] = 65535
    frame = DataFrame(1)
    frame.flags.add('END_STREAM')
    frame.data = PAYLOAD
    wire = settings.serialize() + frame.serialize()
    result = nf.decode_http2_frames(wire)
    assert [(x.frame_type, x.stream_id, x.payload) for x in result] == [(4, 0, settings.serialize_body()), (0, 1, PAYLOAD)]
    assert nf.decode_http2_frames(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + wire, expect_preface=True) == result


def test_keylog_against_independent_scapy_parser():
    source = b'# locally generated deterministic keys\n' + KEYLOG
    oracle = parse_nss_keys(source.decode())
    parsed = nf.parse_keylog(source)
    assert parsed is not None
    assert parsed.secret(RANDOM, LABEL) == oracle[LABEL][RANDOM] == SECRET
    assert parsed.secret(RANDOM.hex(), LABEL) == SECRET
    assert parsed.secret(bytes(32), LABEL) is None


def test_tls13_ciphertext_from_cryptography():
    records = tls_records()
    result = nf.decrypt_tls13(records, KEYLOG, RANDOM, LABEL, 0x1301)
    assert result.records == (PAYLOAD, b'next')
    assert result.content_types == (23, 23) and result.final_epoch == 0
    corrupted = records[0][:-1] + bytes([records[0][-1] ^ 1])
    assert nf.decrypt_tls13([corrupted], KEYLOG, RANDOM, LABEL, 0x1301) is None


def test_quic_ciphertext_from_cryptography_and_inert_plan():
    packet, plain = quic_short()
    result = nf.decrypt_quic_packet(packet, KEYLOG, RANDOM, LABEL, 0x1301, dcid_length=8)
    assert result is not None
    assert result.plaintext == plain and result.packet_number == 7
    wire = pcap([Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') / IP(src='192.0.2.1', dst='192.0.2.2') / UDP(sport=12345, dport=443) / packet])
    plan = nf.plan_quic_decryption(wire, KEYLOG)
    assert plan.client_random == RANDOM.hex()
    assert plan.packet_count == 1 and plan.labels == (LABEL,)
    corrupted = packet[:-1] + bytes([packet[-1] ^ 1])
    assert nf.decrypt_quic_packet(corrupted, KEYLOG, RANDOM, LABEL, 0x1301, dcid_length=8) is None


def fuzz_corpus():
    rng = random.Random(0x4e465a)
    rows = [b''] + [b'\xff' * n for n in (1, 4, 12, 32, 64, 256)]
    rows += [rng.randbytes(rng.randrange(160)) for _ in range(80)]
    seeds = [dns_pair()[1], http_pair()[1], KEYLOG, tcp_capture(), bytes.fromhex('810548656c6c6f'), tls_records()[0], quic_short()[0]]
    for seed in seeds:
        # Every prefix of small frames, bounded even sampling for captures.
        offsets = range(len(seed)) if len(seed) < 256 else range(0, len(seed), 9)
        rows += [seed[:n] for n in offsets]
        for _ in range(20):
            data = bytearray(seed)
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
            rows.append(bytes(data))
    return list(dict.fromkeys(rows))


def test_public_byte_decoders_never_leak_exceptions():
    # No public declared exception class: do not catch any stdlib exception.
    functions = [nf.admit_capture, nf.reassemble_tcp, nf.decode_dns_message,
                 nf.decode_dns_tcp_stream, nf.decode_http_stream, nf.decode_http2_frames,
                 nf.parse_keylog, nf.reconstruct_smb2_files,
                 lambda b: nf.decode_websocket_stream(b, from_client=False),
                 lambda b: nf.decode_websocket_stream(b, from_client=True),
                 lambda b: nf.decrypt_tls13(b, KEYLOG, RANDOM, LABEL, 0x1301),
                 lambda b: nf.decrypt_quic_packet(b, KEYLOG, RANDOM, LABEL, 0x1301, dcid_length=8)]
    for wire in fuzz_corpus():
        for fn in functions:
            fn(wire)


def test_invalid_input_types_fail_closed():
    for value in (None, 3, 'text', [], {}, bytearray(b'x')):
        for fn in (nf.parse_keylog, nf.decode_dns_message, nf.decode_dns_tcp_stream,
                   nf.decode_http_stream, nf.decode_http2_frames, nf.admit_capture):
            assert fn(value) is None


def test_tls_plan_from_scapy_client_hello():
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello
    hello = TLSClientHello(gmt_unix_time=int.from_bytes(RANDOM[:4], 'big'),
                           random_bytes=RANDOM[4:], sid=b'', ciphers=[0x1301], comp=[0])
    wire = tcp_capture(bytes(TLS(msg=[hello])))
    plan = nf.plan_tls_decryption(wire, KEYLOG)
    assert len(plan) == 1
    assert plan[0].client_random == RANDOM.hex()
    assert plan[0].labels == (LABEL,)
    assert plan[0].packet_count == 4 and plan[0].protocol == 'tls'
