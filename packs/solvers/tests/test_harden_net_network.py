"""Independent network.py locks: dnspython DNS, Scapy NTLM, dpkt PCAP.

Sources: RFC1035 section 4.1.4; Microsoft MS-NLMP section 2.2.1.
No network.py builder, decoder output, or private helper supplies expectations.
Previously documented defects are locked by ordinary regression assertions.
"""
import io
import random
import struct

import dns.message
import dns.name
import dns.rrset
import dpkt
import pytest
from scapy.layers.ntlm import NTLM_NEGOTIATE, NTLM_CHALLENGE, NTLM_AUTHENTICATE, AV_PAIR

import network


def dns_wire():
    q = dns.message.make_query('sms.carrier.test.', 'A')
    q.id = 0x4353
    r = dns.message.make_response(q)
    for owner, kind, value in [
        ('sms.carrier.test.', 'CNAME', 'gateway.carrier.test.'),
        ('gateway.carrier.test.', 'A', '192.0.2.45'),
        ('gateway.carrier.test.', 'AAAA', '2001:db8::45'),
        ('carrier.test.', 'MX', '10 mail.carrier.test.'),
        ('_sip._tcp.carrier.test.', 'SRV', '1 2 5060 sip.carrier.test.'),
        ('carrier.test.', 'TXT', '"CSCTF{" "dns_vector}"'),
    ]:
        r.answer.append(dns.rrset.from_text(owner, 60, 'IN', kind, value))
    return r.to_wire()


def ntlm_vectors():
    return [
        bytes(NTLM_NEGOTIATE(NegotiateFlags=0x02003001, DomainName=b'LAB', WorkstationName=b'WS01')),
        bytes(NTLM_CHALLENGE(NegotiateFlags=0x02800005, TargetName='LAB', ServerChallenge=b'12345678',
                            TargetInfo=[AV_PAIR(AvId=2, Value='LAB'),
                                        AV_PAIR(AvId=3, Value='server.lab'),
                                        AV_PAIR(AvId=7, Value=132000000000000000), AV_PAIR(AvId=0)])),
        bytes(NTLM_AUTHENTICATE(NegotiateFlags=0x02000001, DomainName='LAB', UserName='alice',
                               Workstation='WS01', LmChallengeResponse=b'L' * 24,
                               NtChallengeResponse=b'N' * 24)),
    ]


def capture_wire():
    udp = dpkt.udp.UDP(sport=4242, dport=53, data=dns_wire())
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=b'\xc0\x00\x02\x01', dst=b'\xc0\x00\x02\x35', p=17, data=udp)
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(src=b'\x01' * 6, dst=b'\x02' * 6, type=0x800, data=ip)
    handle = io.BytesIO()
    writer = dpkt.pcap.Writer(handle)
    writer.writepkt(bytes(ethernet), ts=1.25)
    return handle.getvalue()


def test_dns_compression_reference_roundtrip():
    wire = dns_wire()
    oracle = dns.message.from_wire(wire)
    answer_offset = 12 + len(oracle.question[0].name.to_wire()) + 4
    assert wire[answer_offset:answer_offset + 2] == b'\xc0\x0c'
    parsed = network.parse_dns(wire)
    assert parsed is not None
    assert parsed.id == oracle.id == 0x4353
    assert parsed.qname == oracle.question[0].name.to_text(omit_final_dot=True)
    assert parsed.answers == [
        ('sms.carrier.test', 'CNAME', 'gateway.carrier.test'),
        ('gateway.carrier.test', 'A', '192.0.2.45'),
        ('gateway.carrier.test', 'AAAA', '2001:db8::45'),
        ('carrier.test', 'MX', 'mail.carrier.test'),
        ('_sip._tcp.carrier.test', 'SRV', 'sip.carrier.test:5060'),
        ('carrier.test', 'TXT', 'CSCTF{dns_vector}'),
    ]


def test_ntlm_scapy_negotiate_challenge_authenticate():
    negotiate, challenge, authenticate = map(network.parse_ntlmssp, ntlm_vectors())
    assert (negotiate.type, negotiate.domain, negotiate.workstation) == (1, 'LAB', 'WS01')
    assert (challenge.type, challenge.target_name, challenge.challenge) == (2, 'LAB', b'12345678')
    assert dict(challenge.av) == {'netbios_domain': 'LAB', 'dns_computer': 'server.lab',
                                  'timestamp': 132000000000000000}
    assert (authenticate.type, authenticate.domain, authenticate.user, authenticate.workstation) == (3, 'LAB', 'alice', 'WS01')
    assert authenticate.lm_response == b'L' * 24
    assert authenticate.nt_response == b'N' * 24


def test_capture_sniffer_and_reader_against_dpkt():
    wire = capture_wire()
    oracle = list(dpkt.pcap.Reader(io.BytesIO(wire)))
    assert network.is_capture(wire) is True
    assert network.is_capture(b'CSCTF{not_pcap}') is False
    cap = network.read(wire)
    assert len(cap.packets) == len(oracle) == 1
    p = cap.packets[0]
    assert (p.src, p.dst, p.sport, p.dport, p.ts) == ('192.0.2.1', '192.0.2.53', 4242, 53, 1250000000)
    assert p.payload == dns_wire()


@pytest.mark.parametrize('kind,size', [(1, n) for n in range(12, 16)] + [(2, n) for n in range(12, 24)])
def test_ntlm_truncated_flags_fail_closed(kind, size):
    wire = b'NTLMSSP\0' + struct.pack('<I', kind) + b'\0' * (size - 12)
    assert network.parse_ntlmssp(wire) is None


@pytest.mark.parametrize('label', [b'a.b', b'a\\b', b'a b', b'a\x00b', b'a\xffb'])
def test_dns_embedded_dot_label_is_preserved(label):
    # A single label containing '.' is NOT equivalent to two separate labels.
    oracle_name = dns.name.Name((label, b'test', b''))
    query = dns.message.make_query(oracle_name, 'A')
    query.id = 0x4353
    wire = query.to_wire()
    parsed = network.parse_dns(wire)
    assert dns.name.from_text(parsed.qname + '.') == oracle_name


def test_dns_truncated_rdata_rejected():
    wire = dns_wire()[:-1]
    with pytest.raises(dns.exception.DNSException):
        dns.message.from_wire(wire)
    assert network.parse_dns(wire) is None


def byte_corpus(seeds):
    rng = random.Random(0x43534354)
    rows = [b''] + [b'\xff' * n for n in (1, 4, 8, 12, 16, 32, 64, 256)]
    rows += [rng.randbytes(rng.randrange(257)) for _ in range(120)]
    for seed in seeds:
        rows += [seed[:n] for n in range(len(seed) + 1)]
        for _ in range(40):
            data = bytearray(seed)
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
            rows.append(bytes(data))
    return list(dict.fromkeys(rows))


def test_parse_dns_and_capture_sniffer_seeded_fuzz():
    # Parser has no declared public error class: any exception fails this test.
    for wire in byte_corpus([dns_wire(), capture_wire()]):
        parsed = network.parse_dns(wire)
        assert parsed is None or isinstance(parsed, network.Rec)
        assert type(network.is_capture(wire)) is bool


def test_ntlm_seeded_fuzz():
    for wire in byte_corpus(ntlm_vectors()):
        parsed = network.parse_ntlmssp(wire)
        assert parsed is None or isinstance(parsed, network.Rec)


def test_public_parse_is_inventory_is_explicit():
    # New entrypoints cannot silently miss fuzz coverage when engines evolve.
    import inspect
    import net_auth
    import net_dbproto
    import net_voip
    import network_forensics
    import pcap_creds
    expected = {
        network: {'parse_dns', 'parse_ntlmssp', 'is_capture'},
        network_forensics: {'parse_keylog'},
        net_auth: {'parse_snmp', 'parse_kerberos'},
        net_dbproto: set(),
        net_voip: {'parse_digest', 'parse_sip'},
        pcap_creds: {'is_capture'},
    }
    for module, names in expected.items():
        actual = {name for name, value in vars(module).items()
                  if inspect.isfunction(value) and value.__module__ == module.__name__
                  and name.startswith(('parse_', 'is_'))}
        assert actual == names
