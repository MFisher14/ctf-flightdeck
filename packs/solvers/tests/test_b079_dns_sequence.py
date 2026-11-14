"""B-079: sequence-aware DNS-exfil reassembly (Layer-1).

An exfil client writes <data>.<NN>.<zone> (or <NN>.<data>.<zone>) and sends the chunks out of order,
once more on a retry, beside cover traffic and another host's stream into the same zone. The shared
reassembly (network.dns_sequences) groups by source and zone, sorts by NN, drops repeats and strips
the NN labels; covert_channels.dns_exfil and network.Capture.dns_tunnel both read through it, and
intake runs covert_channels --auto on every packet capture, which reports only a DNS-dominated one.

Every capture is built here, byte by byte (classic pcap, Ethernet/IPv4/UDP/DNS). No challenge file,
no network: the intake run uses a fake platform adapter and intake's own network guard.
"""
from __future__ import annotations

import base64
import random
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import event, paths
from ctf import intake as I
from ctf.engines import manifest as M
from ctf.engines import router as R
from ctf.platform.base import Challenge

REPO = paths.repo_root()
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import covert_channels as cc   # noqa: E402
import network                 # noqa: E402

CSCTF = event.load("csctf")
FLAG = "CSCTF{dns_s3qu3nc3_r3ass3mbl3d}"
ZONE = "sync.telemetry-svc.example"
EXFIL_SRC, OTHER_SRC, RESOLVER = "198.51.100.7", "198.51.100.20", "198.51.100.1"
ORDER = [3, 0, 4, 1, 2]          # the order the five numbered chunks are asked in


def _b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


def _chunks(text: str, n: int) -> list[str]:
    size = -(-len(text) // n)
    return [text[i:i + size] for i in range(0, len(text), size)]


# ---------------------------------------------------------------------------- capture builder

def _dns_query(name: str, qid: int, qtype: int = 1) -> bytes:
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        msg += bytes([len(label)]) + label.encode()
    return msg + b"\x00" + struct.pack("!HH", qtype, 1)


def _dns_txt_answer(name: str, qid: int, txt: str) -> bytes:
    q = _dns_query(name, qid, 16)
    msg = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q[12:]
    rdata = bytes([len(txt)]) + txt.encode()
    return msg + b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata


def _dns_a_answer(name: str, qid: int) -> bytes:
    """The resolver's answer to an A query: the question echoed, one A record."""
    q = _dns_query(name, qid)
    msg = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q[12:]
    return msg + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 1])


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _frame(src: str, dst: str, proto: int, l4: bytes, ident: int) -> bytes:
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0) + _ip(src) + _ip(dst)
    return bytes(6) + bytes(6) + b"\x08\x00" + ip + l4


def _udp(src, dst, sport, dport, payload, ident):
    return _frame(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, ident)


def _icmp(src, dst, seq, data):
    return _frame(src, dst, 1, struct.pack("!BBHHH", 8, 0, 0, 0x4242, seq) + data, seq)


def _pcap(frames) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(f), len(f)) + f
    return out


def _exfil_names(payload: bytes, *, n=5, order=ORDER, layout="data.seq", zone=ZONE):
    parts = _chunks(_b32(payload), n)
    if layout == "data.seq":
        return [f"{parts[i]}.{i:02d}.{zone}" for i in order], parts
    return [f"{i:02d}.{parts[i]}.{zone}" for i in order], parts


def _radar_capture(payload: bytes = FLAG.encode(), *, extra_frames=(), layout="data.seq") -> bytes:
    """A DNS-only capture: the numbered stream from EXFIL_SRC asked out of order with one retry,
    another host's numbered stream into the same zone, cover lookups and TXT decoys."""
    names, parts = _exfil_names(payload, layout=layout)
    decoy, _ = _exfil_names(b"not the payload, a decoy!", n=3, order=[0, 1, 2])
    frames, qid = [], 0x100

    def q(src, name):
        nonlocal qid
        qid += 1
        frames.append(_udp(src, RESOLVER, 40000 + qid % 1000, 53, _dns_query(name, qid), qid))

    q(EXFIL_SRC, "www.airnet.example")
    for i, name in enumerate(names):
        q(EXFIL_SRC, name)
        if i == 1:
            q(OTHER_SRC, decoy[0])
            q(EXFIL_SRC, "cdn.airnet.example")
        if i == 2:
            q(EXFIL_SRC, names[0])                       # the client retries a chunk
            q(OTHER_SRC, decoy[1])
    q(OTHER_SRC, decoy[2])
    q(EXFIL_SRC, "mail.airnet.example")
    frames.append(_udp(RESOLVER, EXFIL_SRC, 53, 40999, _dns_txt_answer("cfg." + ZONE, 0x77, "v=telemetry;n=3"), 900))
    frames.extend(extra_frames)
    return _pcap(frames)


def _top(result) -> str:
    return result["ranked"][0] if result["ranked"] else ""


# ---------------------------------------------------------------------------- the naming

@pytest.mark.parametrize("qname, want", [
    (f"mzxw6ytb.07.{ZONE}", ("data.seq", 7, "mzxw6ytb", ZONE)),
    ("mzxw6ytb.03.evil.com.", ("data.seq", 3, "mzxw6ytb", "evil.com")),
    ("aa.bb.12.x.example", ("data.seq", 12, "aabb", "x.example")),
    ("12345678.02.t.example", ("data.seq", 2, "12345678", "t.example")),
    (f"05.mzxw6ytb.{ZONE}", ("seq.data", 5, "mzxw6ytb", ZONE)),
    ("Data.01.Tunnel.Example", ("data.seq", 1, "Data", "tunnel.example")),
])
def test_seq_parse_reads_the_number_the_data_and_the_zone(qname, want):
    assert network.dns_seq_parse(qname) == want


@pytest.mark.parametrize("qname", [
    "mzxw6ytb.07.example",                 # a zone of one label is no zone: 07 is the parent's label
    "www.airnet.example",                  # no number
    "4.3.2.1.in-addr.arpa",                # reverse lookup
    "printer.01.lan.local",                # .local
    "_ldap._tcp.01.dc.example",            # a service name
    "a..01.x.example",                     # an empty label
    "chunk.1234567.x.example",             # seven digits is not a sequence label
    "aa.bb.01.com",                        # four labels, but the zone after 01 is one label
    "aa.bb.cc.01.com",
    "",
    None,
])
def test_seq_parse_rejects_what_is_not_a_numbered_chunk(qname):
    assert network.dns_seq_parse(qname) is None


# ---------------------------------------------------------------------------- the shared reassembly

def test_sequences_sort_by_number_strip_it_and_drop_a_repeat():
    names, parts = _exfil_names(FLAG.encode())
    queries = [(EXFIL_SRC, n) for n in names] + [(EXFIL_SRC, names[2])]
    [s] = network.dns_sequences(queries)
    assert (s.src, s.zone, s.layout) == (EXFIL_SRC, ZONE, "data.seq")
    assert s.seq == [0, 1, 2, 3, 4] and s.labels == parts and s.repeats == 1 and s.conflicts == []
    assert s.joined == "".join(parts) and not any(".0" in x for x in s.labels)
    assert s.decoded["base32"] == FLAG.encode()
    assert s.missing == [] and s.qnames == [f"{p}.{i:02d}.{ZONE}" for i, p in enumerate(parts)]
    assert sorted(s.members) == sorted(names + [names[2]])


def test_sequences_are_kept_apart_by_source_and_by_zone():
    a, _ = _exfil_names(b"first source, first zone", n=3, order=[2, 0, 1])
    b, _ = _exfil_names(b"second source data", n=3, order=[1, 2, 0])
    c, _ = _exfil_names(b"first source, other zone", n=3, order=[0, 2, 1], zone="other.example")
    queries = ([("10.0.0.1", n) for n in a] + [("10.0.0.2", n) for n in b] + [("10.0.0.1", n) for n in c])
    random.Random(7).shuffle(queries)
    got = {(s.src, s.zone): s.decoded.get("base32") for s in network.dns_sequences(queries)}
    assert got == {("10.0.0.1", ZONE): b"first source, first zone", ("10.0.0.2", ZONE): b"second source data",
                   ("10.0.0.1", "other.example"): b"first source, other zone"}


def test_sequences_keep_the_first_data_under_a_number_and_name_the_rest():
    queries = [(None, f"aaaa.01.{ZONE}"), (None, f"bbbb.00.{ZONE}"), (None, f"zzzz.01.{ZONE}"),
               (None, f"cccc.03.{ZONE}")]
    [s] = network.dns_sequences(queries)
    assert s.labels == ["bbbb", "aaaa", "cccc"] and s.conflicts == [f"zzzz.01.{ZONE}"]
    assert s.missing == [2] and s.repeats == 0


def test_a_counter_in_a_constant_name_and_a_mostly_gaps_series_are_not_streams():
    pool = [(None, f"{i}.pool.ntp.org.example") for i in range(4)]           # data label never changes
    assert network.dns_sequences(pool) == []
    sparse = [(None, f"abcd{i}.{n:02d}.{ZONE}") for i, n in enumerate((1, 40))]
    assert network.dns_sequences(sparse) == []
    one = [(None, f"abcd.01.{ZONE}"), (None, f"abcd.01.{ZONE}")]            # one number, asked twice
    assert network.dns_sequences(one) == []


# ---------------------------------------------------------------------------- round 1 fixes

@pytest.mark.parametrize("qname, want", [
    ("05.313233.evil.com", ("seq.data", 5, "313233", "evil.com")),     # a hex chunk of ASCII digits
    ("313233.05.evil.com", ("data.seq", 5, "313233", "evil.com")),
    ("12.03.evil.com", ("data.seq", 3, "12", "evil.com")),             # same length: data.seq first
])
def test_seq_parse_prefers_the_shorter_counter_when_both_labels_are_digits(qname, want):
    assert network.dns_seq_parse(qname) == want


def test_seq_readings_list_both_layouts_of_an_ambiguous_name():
    assert network.dns_seq_readings("12.03.evil.com") == [("data.seq", 3, "12", "evil.com"),
                                                          ("seq.data", 12, "03", "evil.com")]
    assert network.dns_seq_readings(f"mzxw6ytb.07.{ZONE}") == [("data.seq", 7, "mzxw6ytb", ZONE)]
    assert network.dns_seq_readings("www.airnet.example") == []


@pytest.mark.parametrize("qname", [
    "a*b.07.x.example",           # the data label before the number is not a data label
    "ab.c*d.07.x.y.example",
    "a*b.cd.07.x.example",
])
def test_seq_parse_rejects_a_number_after_a_label_that_is_not_data(qname):
    assert network.dns_seq_parse(qname) is None and network.dns_seq_readings(qname) == []


def test_a_chunk_of_digits_stays_in_its_number_first_stream():
    chunks = [b"key", b"123", b"end"]
    names = [f"{i:02d}.{c.hex()}.{ZONE}" for i, c in enumerate(chunks)]
    assert names[1] == f"01.313233.{ZONE}"
    queries = [(EXFIL_SRC, names[i]) for i in (2, 0, 1)]
    [s] = network.dns_sequences(queries)
    assert s.layout == "seq.data" and s.seq == [0, 1, 2] and s.decoded["hex"] == b"key123end"


def test_an_ambiguous_name_takes_the_layout_of_its_stream():
    # number first, two-character hex chunks: 01.31 reads either way, its stream says number first
    a = [f"{i:02d}.{c}.{ZONE}" for i, c in enumerate(["6b", "31", "65"])]
    # data first, four-digit counters: 37.0001 alone would read as number first (37 is the shorter)
    b = [f"{c}.{i:04d}.other.example" for i, c in enumerate(["6b", "37", "65"])]
    assert network.dns_seq_parse(b[1])[0] == "seq.data" and network.dns_seq_parse(a[1])[0] == "data.seq"
    # another host asks only data-first names into the first zone: it must not sway the first host
    c = [f"{w}.{i:02d}.{ZONE}" for i, w in enumerate(["mzxw", "6ytb", "ozxa", "nbqx"])]
    queries = ([("10.0.0.1", n) for n in reversed(a)] + [("10.0.0.1", n) for n in b]
               + [("10.0.0.9", n) for n in c])
    got = {(s.src, s.zone): s for s in network.dns_sequences(queries)}
    assert set(got) == {("10.0.0.1", ZONE), ("10.0.0.1", "other.example"), ("10.0.0.9", ZONE)}
    assert got[("10.0.0.1", ZONE)].layout == "seq.data" and got[("10.0.0.1", ZONE)].decoded["hex"] == b"k1e"
    assert got[("10.0.0.1", "other.example")].layout == "data.seq"
    assert got[("10.0.0.1", "other.example")].decoded["hex"] == b"k7e"


def test_a_stream_of_ambiguous_names_only_takes_their_preferred_reading():
    queries = [(None, "01.343536.z.example"), (None, "00.313233.z.example")]
    [s] = network.dns_sequences(queries)
    assert s.layout == "seq.data" and s.seq == [0, 1] and s.decoded["hex"] == b"123456"


def test_as_many_gaps_as_numbers_is_still_a_stream_one_more_is_not():
    even = [(None, f"abcd.00.{ZONE}"), (None, f"efgh.03.{ZONE}")]             # 2 present, 2 missing
    [s] = network.dns_sequences(even)
    assert s.missing == [1, 2] and s.labels == ["abcd", "efgh"]
    assert network.dns_sequences([(None, f"abcd.00.{ZONE}"), (None, f"efgh.04.{ZONE}")]) == []


def test_the_longest_stream_comes_first():
    short, _ = _exfil_names(b"short", n=2, order=[0, 1])
    long_, _ = _exfil_names(b"the longer of the two streams", n=4, order=[2, 0, 3, 1])
    queries = [("10.0.0.1", n) for n in short] + [("10.0.0.2", n) for n in long_]
    got = network.dns_sequences(queries)
    assert [(s.src, s.names) for s in got] == [("10.0.0.2", 4), ("10.0.0.1", 2)]


def test_min_parts_drops_a_shorter_stream():
    names, _ = _exfil_names(b"three part stream", n=3, order=[1, 0, 2])
    queries = [(EXFIL_SRC, n) for n in names]
    assert network.dns_sequences(queries, min_parts=4) == []
    [s] = network.dns_sequences(queries, min_parts=3)
    assert s.decoded["base32"] == b"three part stream"


# ---------------------------------------------------------------------------- round 2 fixes

def test_seq_readings_offer_every_digit_label_as_the_number():
    # hex of ASCII digits split over two labels: 3334 could be the number, but so could 01 (or 3132)
    assert network.dns_seq_readings("3132.3334.01.evil.com") == [
        ("data.seq", 3334, "3132", "01.evil.com"), ("data.seq", 1, "31323334", "evil.com"),
        ("seq.data", 3132, "3334", "01.evil.com")]
    assert network.dns_seq_readings("ab.12.cd.34.x.example") == [
        ("data.seq", 12, "ab", "cd.34.x.example"), ("data.seq", 34, "ab12cd", "x.example")]


def test_a_chunk_of_digits_over_two_labels_stays_in_its_data_first_stream():
    words = [b"key:", b"1234", b"end!"]                         # hex 6b65793a, 31323334, 656e6421
    names = [f"{w.hex()[:4]}.{w.hex()[4:]}.{i:02d}.{ZONE}" for i, w in enumerate(words)]
    assert names[1] == f"3132.3334.01.{ZONE}"
    [s] = network.dns_sequences([(EXFIL_SRC, names[i]) for i in (1, 2, 0)])
    assert (s.zone, s.layout, s.seq, s.missing) == (ZONE, "data.seq", [0, 1, 2], [])
    assert s.decoded["hex"] == b"key:1234end!"


def test_a_stream_of_all_digit_names_finds_its_shared_zone():
    # no name reads one way only: the zone every name can be read in wins over 00.z.example, 01.z...
    words = [b"1234", b"5678", b"9012"]
    names = [f"{w.hex()[:4]}.{w.hex()[4:]}.{i:02d}.z.example" for i, w in enumerate(words)]
    [s] = network.dns_sequences([(None, names[i]) for i in (2, 0, 1)])
    assert (s.zone, s.seq) == ("z.example", [0, 1, 2]) and s.decoded["hex"] == b"123456789012"


def test_an_unambiguous_name_outweighs_readings_of_ambiguous_ones():
    # 00.6b reads number-first only; 01.31 reads either way. Two digit-only data-first names offer
    # data.seq in z.example among their readings, more often than seq.data is offered, but only the
    # unambiguous name is evidence: 01.31 joins 00.6b, and the data-first names keep their own stream.
    queries = [(None, "00.6b.z.example"), (None, "01.31.z.example"),
               (None, "3132.3334.07.z.example"), (None, "3536.3738.08.z.example")]
    got = {s.layout: s for s in network.dns_sequences(queries)}
    assert set(got) == {"seq.data", "data.seq"}
    assert got["seq.data"].seq == [0, 1] and got["seq.data"].decoded["hex"] == b"k1"
    assert got["data.seq"].seq == [7, 8] and got["data.seq"].decoded["hex"] == b"12345678"


def _echoed_capture() -> bytes:
    """The radar capture plus the resolver's answer to every numbered query, each echoing its name."""
    names, _ = _exfil_names(FLAG.encode())
    echoes = [_udp(RESOLVER, EXFIL_SRC, 53, 41000 + k, _dns_a_answer(n, 0x500 + k), 0x500 + k)
              for k, n in enumerate(names)]
    return _radar_capture(extra_frames=echoes)


def test_dns_exfil_reads_queries_not_the_answers_that_echo_them():
    res = cc.dns_exfil(cc._normalize(_echoed_capture()))
    seq = [r for r in res if r["arrangement"] == "qname_sequence"]
    assert [r["src"] for r in seq].count(EXFIL_SRC) == 1
    assert not any(r["src"] == RESOLVER for r in seq), [r["src"] for r in seq]
    mine = [r for r in seq if r["src"] == EXFIL_SRC][0]
    assert _top(mine) == FLAG and mine["repeats"] == 1


def test_dns_tunnel_reads_queries_not_the_answers_that_echo_them():
    seqs = [t for t in network.read(_echoed_capture()).dns_tunnel() if t.kind == "sequence"]
    assert sorted(t.src for t in seqs) == sorted([EXFIL_SRC, OTHER_SRC])
    assert [t for t in seqs if t.src == EXFIL_SRC][0].decoded["base32"] == FLAG.encode()


# ---------------------------------------------------------------------------- covert_channels.dns_exfil

def test_dns_exfil_reassembles_a_shuffled_stream_from_a_real_capture():
    pkts = cc._normalize(_radar_capture())
    res = cc.dns_exfil(pkts)
    seq = [r for r in res if r["arrangement"] == "qname_sequence"]
    assert res[0]["arrangement"] == "qname_sequence"           # the numbered reading comes first
    by_src = {r["src"]: r for r in seq}
    assert set(by_src) == {EXFIL_SRC, OTHER_SRC}
    mine = by_src[EXFIL_SRC]
    assert _top(mine) == FLAG and mine["zone"] == ZONE and mine["sequence"] == [0, 1, 2, 3, 4]
    assert mine["repeats"] == 1 and FLAG in mine["shown"]
    assert by_src[OTHER_SRC]["ranked"][0] == "not the payload, a decoy!"
    # the names a stream took are not read again in the order asked: no other arrangement holds them
    for r in res:
        if r["arrangement"] == "qname":
            assert not any(".0" in p or p[:2].isdigit() for p in r["pieces"]), r["pieces"]
            assert all("airnet" not in p for p in r["pieces"])


def test_the_join_in_the_order_asked_does_not_recover_the_flag():
    """The fixture is a real test: the order the chunks were asked in does not decode to the flag,
    so only a reassembly that sorts by the number passes the test above."""
    names, _ = _exfil_names(FLAG.encode())
    asked = "".join(n.split(".")[0] for n in names)
    assert network.decodings(asked.encode()).get("base32") != FLAG.encode()
    assert FLAG.encode() not in b"".join(network.decodings(asked.encode()).values())


def test_dns_exfil_reads_the_number_first_layout_too():
    res = cc.dns_exfil(cc._normalize(_radar_capture(layout="seq.data")))
    mine = [r for r in res if r["arrangement"] == "qname_sequence" and r["src"] == EXFIL_SRC]
    assert mine and _top(mine[0]) == FLAG and mine[0]["layout"] == "seq.data"


def test_a_decoded_stream_outranks_the_text_as_sent_even_without_a_flag():
    token = bytes.fromhex("00112233445566778899aabbccddeeff").hex().encode()   # 32 hex characters
    res = cc.dns_exfil(cc._normalize(_radar_capture(token)))
    mine = [r for r in res if r["arrangement"] == "qname_sequence" and r["src"] == EXFIL_SRC][0]
    assert _top(mine) == token.decode()
    assert mine["ranked"].index(token.decode()) < mine["ranked"].index(_b32(token))
    lines = "\n".join(cc._sequence_lines(mine))
    assert f"source {EXFIL_SRC} -> zone {ZONE}" in lines and "5 parts numbered 0-4" in lines
    assert "repeats dropped: 1" in lines
    assert "assembly: no reading is in the event flag format" in lines


def test_a_gap_in_the_numbers_is_reported():
    names, parts = _exfil_names(FLAG.encode())
    pkts = [{"qname": n, "qr": 0, "src": EXFIL_SRC} for n in names if ".02." not in n]
    [mine] = [r for r in cc.dns_exfil(pkts) if r["arrangement"] == "qname_sequence"]
    assert mine["missing"] == [2] and mine["pieces"] == [p for i, p in enumerate(parts) if i != 2]
    assert "missing numbers: [2]" in "\n".join(cc._sequence_lines(mine))


# ---------------------------------------------------------------------------- network.Capture.dns_tunnel

def test_dns_tunnel_reads_the_same_reassembly():
    cap = network.read(_radar_capture())
    tun = cap.dns_tunnel()
    seqs = [t for t in tun if t.kind == "sequence"]
    assert tun[:len(seqs)] == seqs                                   # numbered streams come first
    mine = [t for t in seqs if t.src == EXFIL_SRC][0]
    assert mine.parent == ZONE and mine.seq == [0, 1, 2, 3, 4]
    assert mine.decoded["base32"] == FLAG.encode()
    # the numbered names are not also read as the zone's labels in the order asked
    for t in tun:
        if t.kind == "labels":
            assert not any(x[-2:].isdigit() or ".0" in x for x in t.labels), t.labels
    hidden = cap.hidden("dns")
    assert hidden[f"sequence@{ZONE}<-{EXFIL_SRC}:joined_base32"] == FLAG


# ---------------------------------------------------------------------------- --auto (intake's read)

def test_auto_reads_a_dns_dominated_capture():
    got = cc.auto(_radar_capture())
    assert got["dns_dominated"] and got["dns_messages"] == got["packets"] and not got["truncated"]
    assert any(_top(r) == FLAG for r in got["scanned"]["dns"])


def test_auto_reports_nothing_for_a_capture_that_is_not_dns_dominated():
    pings = [_icmp("10.9.9.9", "10.9.9.10", i, b"abcdefghijklmnop") for i in range(40)]
    got = cc.auto(_radar_capture(extra_frames=pings))
    assert got["dns_messages"] == 13 and got["packets"] == 53
    assert not got["dns_dominated"] and got["scanned"] == {}


def test_dns_dominated_is_more_than_half():
    dns = [{"qname": f"a{i}.example.com", "qr": 0} for i in range(3)]
    other = [{"proto": "tcp", "sport": 1, "dport": 80, "payload": b"x"} for _ in range(3)]
    dns, other = cc._normalize(dns), cc._normalize(other)
    assert not cc.dns_dominated(dns + other)
    assert cc.dns_dominated(dns + other[:2])
    assert not cc.dns_dominated(dns[:1])                             # one message is not a channel


def _cli(*args):
    return subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "covert_channels.py"), *args],
                          capture_output=True, text=True, timeout=300)


def test_cli_auto_prints_the_payload_its_source_and_its_order(tmp_path):
    cap = tmp_path / "radar.pcap"
    cap.write_bytes(_radar_capture())
    r = _cli("--auto", str(cap))
    assert r.returncode == 0, r.stderr
    assert "DNS-dominated: 13 of 13 packets are DNS" in r.stdout
    assert f"[flag] {FLAG}" in r.stdout
    assert f"source {EXFIL_SRC} -> zone {ZONE}" in r.stdout
    assert "pieces in number order: " + " ".join(_exfil_names(FLAG.encode())[1]) in r.stdout


def test_cli_auto_is_silent_on_other_captures_and_loud_on_a_bad_file(tmp_path):
    pings = [_icmp("10.9.9.9", "10.9.9.10", i, b"abcdefghijklmnop") for i in range(40)]
    cap = tmp_path / "web.pcap"
    cap.write_bytes(_radar_capture(extra_frames=pings))
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture at all")
    r = _cli("--auto", str(cap))
    assert r.returncode == 0 and "not DNS-dominated: 13 of 53 packets are DNS" in r.stdout
    assert FLAG not in r.stdout and "qname_sequence" not in r.stdout
    r = _cli("--auto", str(bad))
    assert r.returncode == 1 and "bad.pcap" in r.stderr and r.stdout == ""
    r = _cli("--auto", str(bad), str(cap))                          # one bad file does not hide the rest
    assert r.returncode == 1 and "not DNS-dominated" in r.stdout


# ---------------------------------------------------------------------------- intake wiring

def test_manifest_intake_takes_captures_by_magic_and_name_only():
    m = M.load(REPO / "solvers" / "toolkits" / "covert_channels.manifest.toml")
    assert m.intake is not None and m.intake.select == "files" and m.intake.run == "per-file"
    assert m.intake.args == ("--auto", "{file}")

    def takes(name, head):
        return any(R._file_match(spec, [(Path(name), head)]) for spec in m.intake.match)

    for head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                 b"\x0a\x0d\x0d\x0a"):
        assert takes("blob.bin", head + bytes(20)), head
    assert takes("x.pcap", b"junk") and takes("x.pcapng", b"junk")
    assert not takes("bios.cap", b"junk") and not takes("notes.txt", b"hello")


class _Adapter:
    kind = "fake"

    def __init__(self, cid, ch, files):
        self.cid, self.ch, self.files = cid, ch, files

    def list_challenges(self):
        return [self.ch]

    def get_challenge(self, cid):
        return self.ch

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake must never submit")


def test_intake_runs_it_on_a_dns_capture_and_reads_the_flag(tmp_path):
    ch = Challenge(id="79", name="Radar", category="misc", points=100, description="", files=(),
                   solved_by_team=False)
    ad = _Adapter("79", ch, {"radar.pcap": _radar_capture()})
    rep = I.intake_one("79", CSCTF, adapter=ad, workdir=tmp_path / "wd", options=I.Options(net_guard="hook"))
    runs = [r for r in rep.runs if r.engine == "toolkits.covert_channels"]
    assert len(runs) == 1 and runs[0].status == "ok", [(r.engine, r.status) for r in rep.runs]
    out = (rep.dir / runs[0].output).read_text()
    assert f"[flag] {FLAG}" in out and f"source {EXFIL_SRC}" in out
    assert FLAG in rep.flags
