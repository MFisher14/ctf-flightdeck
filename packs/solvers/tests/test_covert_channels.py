#!/usr/bin/env python3
"""Synthetic regression for solvers/toolkits/covert_channels.py (general covert-channel decoder).

Every fixture is BUILT IN-TEST: plain packet dicts (and one hand-assembled classic pcap to exercise
the network.py reader path) with a KNOWN planted flag. The decoder must recover it, rank a
flag-bearing reading first, and return it only as a labels CANDIDATE value (an unsure "??" string,
never a bare auto-submit) -- the never-guess contract. Standalone:

    CTF_WORKDIR=/tmp/ctfdur .venv/bin/python tests/test_covert_channels.py   -> prints 'ok', exit 0

No real capture file and no network are needed.
"""
import base64
import json
import os
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
os.environ.setdefault("CTF_WORKDIR", "/tmp/ctfdur")

import covert_channels as cc   # noqa: E402

SENTINEL = "??"
FLAG = "CSCTF{c0v3rt_ch4nn3l}"


# ---------------------------------------------------------------------------- helpers

def _unsure(ans):
    """(key, [(name, value), ...]) for a labels candidate/unsure value; None for anything else."""
    if not isinstance(ans, str) or not ans.startswith(SENTINEL):
        return None
    body = json.loads(ans[len(SENTINEL):])
    return body["k"], [tuple(o) for o in body["o"]]


def _values(result):
    """The candidate values offered for one channel result, from its labels unsure string."""
    u = _unsure(result["candidates"])
    assert u is not None, f"candidates must be an unsure value, got {result['candidates']!r}"
    key, opts = u
    assert key.endswith("#candidates"), key          # a candidate key, probed one option at a time
    return [v for _n, v in opts]


def _assert_recovers(result, flag=FLAG):
    """A channel result offers the flag, ranked first, as a candidate (never a bare plain answer)."""
    assert result is not None, "channel recovered nothing"
    assert result["ranked"] and result["ranked"][0] == flag, result["ranked"][:3]
    assert flag in _values(result), result["candidates"]
    assert flag in result["shown"], result["shown"]


def _first(results):
    """The result whose top reading is the flag (channels may return a list of arrangements)."""
    for r in results if isinstance(results, list) else [results]:
        if r["ranked"] and r["ranked"][0] == FLAG:
            return r
    return (results[0] if isinstance(results, list) else results)


# ---------------------------------------------------------------------------- (a) NTP RefID

def test_ntp_refid_ascii():
    msg = FLAG.encode().ljust((len(FLAG) + 3) // 4 * 4, b"\x00")
    pkts = [{"proto": "ntp", "dport": 123, "payload": bytes(12) + msg[i:i + 4]}
            for i in range(0, len(msg), 4)]
    _assert_recovers(_first(cc.ntp_refid(pkts)))


def test_ntp_refid_from_explicit_field_and_server_port():
    # refid can be given directly, and NTP is detected by either sport or dport 123
    pkts = [{"proto": "udp", "sport": 123, "refid": FLAG.encode()[i:i + 4]}
            for i in range(0, len(FLAG), 4)]
    _assert_recovers(_first(cc.ntp_refid(pkts)))


# ---------------------------------------------------------------------------- (b) DNS exfil

def test_dns_qname_base32_labels():
    enc = base64.b32encode(FLAG.encode()).decode().rstrip("=").lower()
    chunks = [enc[i:i + 12] for i in range(0, len(enc), 12)]
    pkts = [{"qname": f"{c}.tunnel.evil.com", "qr": 0} for c in chunks]
    res = cc.dns_exfil(pkts)
    # the qname arrangement strips the 'evil.com' parent, joins the leading labels, base32-decodes
    assert any(FLAG in r["ranked"][:2] for r in res), [r["ranked"][:2] for r in res]
    _assert_recovers(_first(res))


def test_dns_txt_answers():
    enc = base64.b64encode(FLAG.encode()).decode()
    chunks = [enc[i:i + 6] for i in range(0, len(enc), 6)]
    pkts = [{"qname": "beacon.evil.com", "qr": 1, "txt": c} for c in chunks]
    res = cc.dns_exfil(pkts)
    txt = [r for r in res if r["arrangement"] == "txt"]
    assert txt, res
    _assert_recovers(txt[0])


def test_dns_from_raw_query_payload():
    # a real DNS query packet, parsed by network.parse_dns through the decoder
    def query(name):
        msg = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        for label in name.split("."):
            msg += bytes([len(label)]) + label.encode()
        return msg + b"\x00" + struct.pack("!HH", 16, 1)   # TXT, IN
    enc = FLAG.encode().hex()
    chunks = [enc[i:i + 8] for i in range(0, len(enc), 8)]
    pkts = [{"proto": "udp", "dport": 53, "payload": query(f"{c}.x.io")} for c in chunks]
    res = cc.dns_exfil(pkts)
    assert any(FLAG in (r["ranked"][:2]) for r in res), [r["ranked"][:2] for r in res]


# ---------------------------------------------------------------------------- (c) ICMP echo

def test_icmp_echo_request_payload():
    data = FLAG.encode()
    pkts = [{"proto": "icmp", "itype": 8, "iid": 7, "iseq": i, "src": "10.0.0.1", "dst": "10.0.0.2",
             "payload": data[i:i + 3]} for i in range(0, len(data), 3)]
    _assert_recovers(_first(cc.icmp_echo(pkts)))


def test_icmp_first_byte_arrangement():
    # one covert byte per echo, hidden behind a plausible leading byte
    pkts = [{"proto": "icmp", "itype": 8, "iid": 1, "iseq": i, "src": "a", "dst": "b",
             "payload": bytes([b]) + b"\x00\x00"} for i, b in enumerate(FLAG.encode())]
    res = cc.icmp_echo(pkts)
    fb = [r for r in res if r["arrangement"].endswith("first_byte")]
    assert fb, res
    _assert_recovers(fb[0])


def test_icmp_ignores_standard_ping():
    # standard ping payloads must not drown the covert ones
    std = b"abcdefghijklmnopqrstuvwabcdefghi"
    data = FLAG.encode()
    pkts = [{"proto": "icmp", "itype": 8, "iid": 9, "iseq": 100 + i, "src": "a", "dst": "b", "payload": std}
            for i in range(3)]
    pkts += [{"proto": "icmp", "itype": 8, "iid": 9, "iseq": i, "src": "a", "dst": "b",
              "payload": data[i:i + 3]} for i in range(0, len(data), 3)]
    _assert_recovers(_first(cc.icmp_echo(pkts)))


# ---------------------------------------------------------------------------- (d) timing channel

def _timing_pkts(flag, long_is_one=True, t0=1000.0, short=0.04, long=0.22):
    bits = "".join(format(b, "08b") for b in flag.encode())
    ts = [t0]
    for bit in bits:
        one = bit == "1"
        ts.append(ts[-1] + (long if one == long_is_one else short))
    return [{"proto": "tcp", "seq": 0, "ts": t, "payload": b""} for t in ts]


def test_timing_bits_long_is_one():
    _assert_recovers(_first(cc.timing_bits(_timing_pkts(FLAG, long_is_one=True))))


def test_timing_bits_inverted_polarity():
    # the decoder offers both polarities, so an inverted channel is still recovered
    _assert_recovers(_first(cc.timing_bits(_timing_pkts(FLAG, long_is_one=False))))


def test_timing_too_few_packets_is_none():
    pkts = [{"proto": "tcp", "seq": 0, "ts": float(i)} for i in range(5)]
    assert cc.timing_bits(pkts) is None


# ---------------------------------------------------------------------------- (e) header fields

def test_header_ip_id_low_byte():
    pkts = [{"proto": "udp", "ip_id": 0x4000 | b, "payload": b""} for b in FLAG.encode()]
    res = cc.header_field(pkts)
    low = [r for r in res if r["arrangement"] == "ip_id_low_byte"]
    assert low, res
    _assert_recovers(low[0])


def test_header_tcp_seq_low_byte():
    pkts = [{"proto": "tcp", "seq": (0x11223300 | b), "payload": b""} for b in FLAG.encode()]
    res = cc.header_field(pkts)
    low = [r for r in res if r["arrangement"] == "tcp_seq_low_byte"]
    assert low, res
    _assert_recovers(low[0])


def test_header_ttl_raw():
    pkts = [{"proto": "udp", "ttl": b, "payload": b""} for b in FLAG.encode()]
    res = cc.header_field(pkts)
    ttl = [r for r in res if r["arrangement"] == "ttl_raw"]
    assert ttl, res
    _assert_recovers(ttl[0])


# ---------------------------------------------------------------------------- pcap reader path

def _classic_pcap(frames):
    """A little-endian classic pcap (linktype Ethernet) from raw ethernet frames."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", i, 0, len(f), len(f)) + f
    return out


def _icmp_frame(data, seq):
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1337, seq) + data
    total = 20 + len(icmp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, seq, 0, 64, 1, 0) + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
    eth = bytes(6) + bytes(6) + b"\x08\x00"
    return eth + ip + icmp


def test_scan_reads_a_real_pcap():
    data = FLAG.encode()
    frames = [_icmp_frame(data[i:i + 4], seq=i) for i in range(0, len(data), 4)]
    pcap = _classic_pcap(frames)
    scanned = cc.scan(pcap)          # bytes of a pcap: goes through network.read
    assert "icmp" in scanned, scanned
    _assert_recovers(_first(scanned["icmp"]))


# ---------------------------------------------------------------------------- aggregate + guards

def test_scan_aggregates_multiple_channels():
    pkts = [{"proto": "ntp", "dport": 123, "payload": bytes(12) + FLAG.encode()[i:i + 4].ljust(4, b"\x00")}
            for i in range(0, len(FLAG), 4)]
    pkts += [{"proto": "udp", "ip_id": 0x4000 | b, "payload": b""} for b in FLAG.encode()]
    scanned = cc.scan(pkts)
    assert "ntp" in scanned and "header" in scanned, list(scanned)


def test_empty_and_irrelevant_input_recovers_nothing():
    assert cc.scan([]) == {}
    # plain HTTP-ish packets with no covert arrangement: no flag invented
    noise = [{"proto": "tcp", "sport": 1000 + i, "dport": 80, "payload": b"GET / HTTP/1.1\r\n"} for i in range(4)]
    scanned = cc.scan(noise)
    for name, res in scanned.items():
        if name == "_errors":
            continue
        for r in (res if isinstance(res, list) else [res]):
            assert not (r["ranked"] and r["ranked"][0].startswith("CSCTF{")), r


def test_candidates_never_plain():
    # the never-guess contract: a recovered reading is ALWAYS an unsure candidate, never plain
    r = _first(cc.ntp_refid([{"proto": "ntp", "dport": 123,
                              "payload": bytes(12) + FLAG.encode()[i:i + 4].ljust(4, b"\x00")}
                             for i in range(0, len(FLAG), 4)]))
    assert isinstance(r["candidates"], str) and r["candidates"].startswith(SENTINEL)


# ---------------------------------------------------------------------------- standalone runner

def _run():
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
    print(f"ok ({len(fns)} checks)")


if __name__ == "__main__":
    _run()
    sys.exit(0)
