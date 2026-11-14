"""Independent wire-vector locks and deterministic malformed-input checks.

Scapy serializes SNMP/Kerberos/SMB2/NTLM objects; dpkt serializes captures and
Ethernet/IP/TCP/UDP. None of the production fixture builders are used. Parsers
here declare no custom exception class, so byte-input fuzz must not raise.
"""
import base64
import io
import hashlib
import random
import sys
from types import SimpleNamespace as NS

import dpkt
import pytest
from pyasn1.codec.der import decoder as der_decoder
from scapy.layers.kerberos import (
    EncryptedData, KRB_AS_REP, KRB_AS_REQ, KRB_KDC_REQ_BODY, KRB_Ticket, PrincipalName,
)
from scapy.layers.ntlm import NTLM_AUTHENTICATE, NTLM_CHALLENGE
from scapy.layers.smb2 import (
    SMB2_Create_Request, SMB2_Create_Response, SMB2_Write_Request, SMB2_FILEID,
    SMB2_Close_Request, SMB2_Close_Response, SMB2_Header, SMB2_Negotiate_Protocol_Response,
    SMB2_Tree_Connect_Request,
)
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

import net_auth
import network_forensics
import pcap_creds


def snmp_wire(oid='1.3.6.1.2.1.1.1.0'):
    return bytes(SNMP(version=1, community='CSCTF{snmp}',
                      PDU=SNMPget(id=17, varbindlist=[SNMPvarbind(oid=oid)])))


def kerberos_reply():
    return bytes(KRB_AS_REP(
        crealm='EXAMPLE.TEST', cname=PrincipalName(nameType=1, nameString=['alice']),
        ticket=KRB_Ticket(
            realm='EXAMPLE.TEST',
            sname=PrincipalName(nameType=2, nameString=['krbtgt', 'EXAMPLE.TEST']),
            encPart=EncryptedData(etype=23, cipher=b'T' * 32)),
        encPart=EncryptedData(etype=23, cipher=bytes(range(48)))))


def kerberos_request():
    return bytes(KRB_AS_REQ(reqBody=KRB_KDC_REQ_BODY(
        cname=PrincipalName(nameType=1, nameString=['alice']), realm='EXAMPLE.TEST',
        sname=PrincipalName(nameType=2, nameString=['krbtgt', 'EXAMPLE.TEST']),
        till='20261106000000Z', rtime='20261106000000Z', nonce=12345, etype=[18, 23])))


def ntlm_messages():
    challenge = bytes(NTLM_CHALLENGE(NegotiateFlags=1, ServerChallenge=b'12345678',
                                     TargetName='DOMAIN'))
    response = bytes(NTLM_AUTHENTICATE(
        NegotiateFlags=1, DomainName='DOMAIN', UserName='alice', Workstation='client',
        LmChallengeResponse=b'L' * 24, NtChallengeResponse=b'N' * 16 + b'B' * 32))
    return challenge, response


def frame(payload, *, reverse=False, udp=False, port=445):
    a, b = (b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02')
    src, dst = (b, a) if reverse else (a, b)
    sport, dport = (port, 49152) if reverse else (49152, port)
    if udp:
        transport = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        transport.ulen = len(transport)
    else:
        transport = dpkt.tcp.TCP(sport=sport, dport=dport, seq=100, ack=1,
                                 flags=dpkt.tcp.TH_ACK, data=payload)
        transport.off = 5
    ip = dpkt.ip.IP(src=src, dst=dst, p=17 if udp else 6, ttl=64, data=transport)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x02\0\0\0\0\x01',
                                      dst=b'\x02\0\0\0\0\x02', type=0x0800, data=ip))


def capture(frames, *, ng=False):
    sink = io.BytesIO()
    writer = (dpkt.pcapng.Writer if ng else dpkt.pcap.Writer)(sink, snaplen=65535, linktype=1)
    for i, packet in enumerate(frames):
        writer.writepkt(packet, ts=1700000000 + i)
    return sink.getvalue()


def as_datagrams(*payloads, port):
    return NS(packets=[NS(proto=17, sport=49152, dport=port, src='192.0.2.1',
                           dst='192.0.2.2', payload=p) for p in payloads], conns=lambda: [])


def test_parse_snmp_scapy_vector():
    assert net_auth.parse_snmp(snmp_wire()) == {
        'version': 'v2c', 'community': 'CSCTF{snmp}', 'pdu': 'get_request',
        'oids': ['1.3.6.1.2.1.1.1.0']}


def test_snmp_messages_scapy_vector():
    rows = net_auth.snmp_messages(as_datagrams(snmp_wire(), port=161))
    assert rows == [{'version': 'v2c', 'community': 'CSCTF{snmp}', 'pdu': 'get_request',
                     'oids': ['1.3.6.1.2.1.1.1.0'], 'src': '192.0.2.1', 'dst': '192.0.2.2'}]


def test_snmp_multioctet_first_subidentifier_vector():
    # Scapy produces 06 03 88 37 03. pyasn1 DER decoding independently establishes
    # its value as 2.999.3; no expected value is read from the production parser.
    wire = snmp_wire('2.999.3')
    oid, tail = der_decoder.decode(bytes.fromhex('0603883703'))
    assert net_auth.parse_snmp(wire)['oids'] == [str(oid)]


@pytest.mark.parametrize('oid', ['0.39.3', '1.0.3', '1.39.3', '2.0.3', '2.47.3',
                                  '2.48.3', '2.4294967295.3'])
def test_snmp_first_subidentifier_boundaries(oid):
    wire = snmp_wire(oid)
    assert net_auth.parse_snmp(wire)['oids'] == [oid]


def test_snmp_unterminated_oid_subidentifier_rejected():
    wire = snmp_wire('2.999.3').replace(bytes.fromhex('0603883703'),
                                      bytes.fromhex('0603883783'))
    assert net_auth.parse_snmp(wire) is None


@pytest.mark.parametrize('first_subidentifier', [True, False], ids=['first-arc', 'later-arc'])
def test_snmp_oversized_oid_subidentifier_rejected(first_subidentifier):
    # Hand-built definite-length BER avoids decimal conversion in an encoder.
    def tlv(tag, body):
        size = len(body)
        encoded_size = size.to_bytes(max(1, (size.bit_length() + 7) // 8), 'big')
        length = (bytes([size]) if size < 128 else
                  bytes([0x80 | len(encoded_size)]) + encoded_size)
        return bytes([tag]) + length + body

    subidentifier = b'\x81' * 2200 + b'\x01'
    oid = subidentifier + b'\x03' if first_subidentifier else b'\x2b' + subidentifier
    varbind = tlv(0x30, tlv(0x06, oid) + b'\x05\x00')
    pdu = tlv(0xa0, b'\x02\x01\x01\x02\x01\x00\x02\x01\x00' + tlv(0x30, varbind))
    wire = tlv(0x30, b'\x02\x01\x01' + tlv(0x04, b'public') + pdu)
    previous_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        assert net_auth.parse_snmp(wire) is None
    finally:
        sys.set_int_max_str_digits(previous_limit)


@pytest.mark.parametrize('factory,expected', [
    (kerberos_request, {'msg_type': 'as_req', 'realm': 'EXAMPLE.TEST', 'cname': 'alice',
                        'sname': 'krbtgt/EXAMPLE.TEST', 'etype': None}),
    (kerberos_reply, {'msg_type': 'as_rep', 'realm': 'EXAMPLE.TEST', 'cname': 'alice',
                      'sname': None, 'etype': 23}),
])
def test_parse_kerberos_scapy_vectors(factory, expected):
    assert net_auth.parse_kerberos(factory()) == expected


def test_kerberos_udp_and_tcp_entrypoint_vectors():
    wire = kerberos_reply()
    udp = net_auth.kerberos_messages(as_datagrams(wire, port=88))
    tcp = NS(conns=lambda: [NS(cport=49152, sport=88, c=None,
                              s=NS(data=len(wire).to_bytes(4, 'big') + wire,
                                   src='192.0.2.1', dst='192.0.2.2'))], packets=[])
    assert net_auth.kerberos_messages(tcp) == udp
    assert udp[0]['etype'] == 23 and udp[0]['realm'] == 'EXAMPLE.TEST'


def test_smb2_facts_scapy_vectors():
    tree = bytes(SMB2_Header(Command=3) /
                 SMB2_Tree_Connect_Request(Path='\\\\server\\share'))
    create = bytes(SMB2_Header(Command=5) / SMB2_Create_Request(Name='CSCTF{file}.txt'))
    negotiate = bytes(SMB2_Header(Command=0, Flags=1) /
                      SMB2_Negotiate_Protocol_Response(DialectRevision=0x311,
                                                       ServerTime=0, ServerStartTime=0))
    # RFC1002 session-service prefix is independent of the SMB2 packet encoder.
    wrap = lambda p: len(p).to_bytes(4, 'big') + p
    conn = NS(cport=49152, sport=445, c=NS(data=wrap(tree) + wrap(create)),
              s=NS(data=wrap(negotiate)))
    assert net_auth.smb2_facts(NS(conns=lambda: [conn])) == {
        'dialect': '3.1.1', 'dialect_hex': '0x0311',
        'shares': ['\\\\server\\share'], 'files': ['CSCTF{file}.txt']}


@pytest.mark.parametrize('ng', [False, True], ids=['pcap', 'pcapng'])
def test_capture_public_entrypoints_dpkt_vectors(ng):
    frames = [frame(b'CSCTF{wire}', udp=True, port=12345), frame(snmp_wire(), udp=True, port=161)]
    raw = capture(frames, ng=ng)
    assert pcap_creds.is_capture(raw) is True
    assert list(pcap_creds.read_packets(raw)) == [(1, f) for f in frames]
    assert pcap_creds.find_captures({'capture': raw, 'text': b'ordinary bytes'}) == [('capture', raw)]


@pytest.mark.parametrize('http', [False, True], ids=['raw-ntlm', 'http-base64-ntlm'])
def test_extract_ntlm_scapy_dpkt_vector(http):
    challenge, response = ntlm_messages()
    if http:
        challenge = b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM ' + base64.b64encode(challenge) + b'\r\n\r\n'
        response = b'GET / HTTP/1.1\r\nAuthorization: NTLM ' + base64.b64encode(response) + b'\r\n\r\n'
    raw = capture([frame(challenge, reverse=True), frame(response)])
    expected = {'field': 'netntlmv2_hashcat', 'shape': 'mode5600', 'mode': 5600,
                'user': 'alice', 'domain': 'DOMAIN', 'challenge': b'12345678'.hex(),
                'ntproof': (b'N' * 16).hex(), 'blob': (b'B' * 32).hex()}
    assert pcap_creds.extract(raw) == [expected]
    # Documented NetNTLMv2 interchange line: name::domain:challenge:proof:blob.
    assert pcap_creds.renderings(expected) == [
        ('hashcat_lower', 'alice::DOMAIN:3132333435363738:' + '4e' * 16 + ':' + '42' * 32),
        ('hashcat_upper', 'alice::DOMAIN:3132333435363738:' + '4E' * 16 + ':' + '42' * 32)]


@pytest.mark.parametrize('tcp', [False, True], ids=['udp', 'tcp'])
def test_extract_kerberos_scapy_dpkt_vector(tcp):
    wire = kerberos_reply()
    if tcp:
        wire = len(wire).to_bytes(4, 'big') + wire
    raw = capture([frame(wire, reverse=True, udp=not tcp, port=88)])
    expected = {'field': 'krb5asrep_hashcat', 'shape': 'mode18200', 'mode': 18200,
                'user': 'alice', 'realm': 'EXAMPLE.TEST',
                'checksum': bytes(range(16)).hex(), 'edata': bytes(range(16, 48)).hex()}
    assert pcap_creds.extract(raw) == [expected]
    assert pcap_creds.renderings(expected)[0] == (
        'hashcat_lower', '$krb5asrep$23$alice@EXAMPLE.TEST:' + bytes(range(16)).hex() + '$' + bytes(range(16, 48)).hex())


@pytest.mark.parametrize('little_endian', [False, True], ids=['big-endian', 'little-endian'])
def test_pcapng_legacy_packet_block_dpkt_vector(little_endian):
    p = dpkt.pcapng
    section = p.SectionHeaderBlockLE if little_endian else p.SectionHeaderBlock
    interface = p.InterfaceDescriptionBlockLE if little_endian else p.InterfaceDescriptionBlock
    packet = p.PacketBlockLE if little_endian else p.PacketBlock
    raw = (bytes(section()) + bytes(interface()) +
           bytes(packet(iface_id=0, ts_high=0, ts_low=10, pkt_data=b'ABCDEFG')))
    oracle = [data for _, data in p.Reader(io.BytesIO(raw))]
    assert list(pcap_creds.read_packets(raw)) == [(1, data) for data in oracle]


def mutated_cases(seed_wire, seed):
    rng = random.Random(seed)
    yield b''
    for n in (1, 2, 3, 4, 8, 12, 16, 24, 32, 64, 128, 255):
        yield b'\xff' * n
        yield b'\0' * n
        yield rng.randbytes(n)
    # Prefixes retain actual protocol magic, including every structural boundary.
    yield from (seed_wire[:n] for n in range(len(seed_wire)))
    for _ in range(128):
        mutated = bytearray(seed_wire)
        if mutated:
            i = rng.randrange(len(mutated))
            mutated[i] ^= 1 << rng.randrange(8)
        yield bytes(mutated)


@pytest.mark.parametrize('parser,factory,seed', [
    (net_auth.parse_snmp, snmp_wire, 1101),
    (net_auth.parse_kerberos, kerberos_reply, 1102),
    (net_auth.parse_kerberos, kerberos_request, 1103),
])
def test_auth_public_parsers_fail_closed_bytes(parser, factory, seed):
    for data in mutated_cases(factory(), seed):
        parser(data)  # No declared parser error exists: any exception fails.


@pytest.mark.parametrize('ng', [False, True], ids=['pcap', 'pcapng'])
def test_creds_public_byte_entrypoints_fail_closed(ng):
    challenge, response = ntlm_messages()
    wire = capture([frame(challenge, reverse=True), frame(response)], ng=ng)
    for data in mutated_cases(wire, 2200 + ng):
        assert isinstance(pcap_creds.is_capture(data), bool)
        list(pcap_creds.read_packets(data))
        pcap_creds.extract(data)


def test_public_parse_and_is_inventory_is_locked():
    # A newly exported parser must not silently escape this fuzz inventory.
    expected = {net_auth: {'parse_snmp', 'parse_kerberos'}, pcap_creds: {'is_capture'}}
    for module, names in expected.items():
        actual = {name for name, value in vars(module).items()
                  if callable(value) and name.startswith(('parse_', 'is_'))}
        assert actual == names


def test_smb2_complete_write_scapy_vector():
    body = b'CSCTF{independent_smb2}'
    fid = SMB2_FILEID(Persistent=0x12345678, Volatile=0x9abcdef0)
    reqs = [
        SMB2_Header(Command=5, MID=1) / SMB2_Create_Request(Name='proof.txt'),
        SMB2_Header(Command=9, MID=2) / SMB2_Write_Request(FileId=fid, Data=body),
        SMB2_Header(Command=6, MID=3) / SMB2_Close_Request(FileId=fid),
    ]
    resps = [
        SMB2_Header(Command=5, MID=1, Flags=1) / SMB2_Create_Response(
            FileId=fid, EndOfFile=0, CreationTime=0, LastAccessTime=0,
            LastWriteTime=0, ChangeTime=0),
        SMB2_Header(Command=6, MID=3, Flags=1) / SMB2_Close_Response(Flags=1, EndOfFile=len(body)),
    ]
    def stream(packets):
        raw = [bytes(p) for p in packets]
        return NS(data=b''.join(len(p).to_bytes(4, 'big') + p for p in raw), sound=True)
    cap = NS(conns=lambda: [NS(cport=49152, sport=445, c=stream(reqs), s=stream(resps))])
    rows = net_auth.smb_transfers(cap)
    assert len(rows) == 1
    assert rows[0]['complete'] is True
    assert rows[0]['data'] == body
    assert rows[0]['path'] == 'proof.txt'
    assert rows[0]['size'] == len(body)
    assert rows[0]['sha256'] == hashlib.sha256(body).hexdigest()
    raw = capture([frame(stream(reqs).data), frame(stream(resps).data, reverse=True)])
    objects = network_forensics.reconstruct_smb2_files(raw)
    assert objects is not None and len(objects) == 1
    assert objects[0].data == body
    assert objects[0].name == 'proof.txt'
    assert objects[0].sha256 == hashlib.sha256(body).hexdigest()


def test_renderings_published_hashcat_vectors():
    # Authoritative format/examples: https://hashcat.net/wiki/doku.php?id=example_hashes
    # Modes5600 and18200. The below NetNTLMv2 fixture is the published example,
    # split only into the fields accepted by the public formatting entrypoint.
    published = ('admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:'
                 '5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e00000000'
                 '52920b85f78d013c31cdb3b92f5d765c783030')
    user, empty, domain, challenge, proof, blob = published.split(':')
    fields = dict(field='netntlmv2_hashcat', user=user, domain=domain,
                  challenge=challenge, ntproof=proof, blob=blob)
    assert pcap_creds.renderings(fields)[0] == ('hashcat_lower', published)
