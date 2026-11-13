"""B-080: the opt-in tolerant TCP reassembly in network_forensics (strict stays the default).

    .venv/bin/python -m pytest tests/test_network_forensics_tolerant.py

Every capture is built in tests/b080_fixtures.py with real checksums or deliberately broken ones.
What is checked: a bad-checksum copy is dropped (before or after the original) and reported; the first
valid copy of a byte wins and a later disagreeing copy is reported as a conflict; identical
retransmissions are counted, not reported; a bad IPv4 header checksum, an unparseable TCP header and
a segment before the stream start are dropped by name; a hole ends the stream data and is reported;
partial overlaps keep the accepted bytes and append the new ones; a second SYN with another seq is
set aside and reported; a bad-checksum non-TCP packet or fragment is reported; the strict reader still
declines all of these and is unchanged on a clean capture.
"""
from __future__ import annotations

import b080_fixtures as fx
from solvers.toolkits import network_forensics as nf

C, S, CP, SP = fx.CLIENT, fx.SERVER, fx.CPORT, fx.SPORT


def _server(tr):
    got = [s for s in tr.streams if s.sport == SP]
    assert len(got) == 1, tr.report()
    return got[0]


def _handshake(cseq=1000, sseq=50000):
    return [fx.tcp_frame(C, S, CP, SP, cseq, 0x02), fx.tcp_frame(S, C, SP, CP, sseq, 0x12)]


# ------------------------------------------------------------------------------ the relay fixture

def test_strict_reader_declines_the_forged_capture_but_tolerant_keeps_the_original():
    data, facts = fx.relay_capture()
    assert nf.reassemble_tcp(data) is None                 # strict: one bad checksum declines it all
    tr = nf.reassemble_tcp_tolerant(data)
    assert tr is not None
    assert _server(tr).data == facts["server_stream"]      # the original DATA frame, not a forgery
    client = [s for s in tr.streams if s.sport == CP][0]
    assert client.data == facts["client_stream"]
    assert _server(tr).complete and client.complete


def test_bad_checksum_copies_are_dropped_and_reported_with_their_bytes():
    data, facts = fx.relay_capture()
    tr = nf.reassemble_tcp_tolerant(data)
    drops = {d.packet_index: d for d in tr.dropped}
    assert set(drops) == {facts["forged_before"], facts["forged_bad_after"]}
    for d in drops.values():
        assert d.reason == nf.CHECKSUM_TCP
        assert (d.src, d.sport, d.dst, d.dport) == (S, SP, C, CP)
        assert d.payload == facts["forged_frame"]


def test_a_later_valid_copy_that_disagrees_is_a_reported_conflict_and_loses():
    data, facts = fx.relay_capture()
    tr = nf.reassemble_tcp_tolerant(data)
    assert [c.packet_index for c in tr.conflicts] == [facts["forged_valid_after"]]
    c = tr.conflicts[0]
    assert c.offset == facts["data_offset"]
    assert c.payload == facts["forged_frame"] and c.accepted == facts["data_frame"]
    assert c.differing_bytes == sum(1 for a, b in zip(facts["data_frame"], facts["forged_frame"]) if a != b)
    assert c.differing_bytes > 0
    # the overlap of the valid forged copy is a retransmission of accepted bytes
    assert _server(tr).retransmitted_bytes == len(facts["data_frame"])


def test_report_names_every_drop_and_conflict():
    data, facts = fx.relay_capture()
    lines = nf.reassemble_tcp_tolerant(data).report()
    assert sum(ln.startswith("dropped packet") for ln in lines) == 2
    assert any(ln.startswith(f"conflicting copy in packet {facts['forged_valid_after']}") for ln in lines)
    assert sum(ln.startswith("stream ") for ln in lines) == 2


def test_clean_capture_gives_the_same_streams_in_both_modes():
    data, facts = fx.relay_capture(forged=False)
    strict = nf.reassemble_tcp(data)
    tr = nf.reassemble_tcp_tolerant(data)
    assert strict is not None
    assert tr.streams == strict
    assert tr.dropped == () and tr.conflicts == () and tr.gaps == () and tr.declined == ()


# ------------------------------------------------------------------------------ individual rules

def test_first_valid_copy_wins_even_when_it_is_the_forgery():
    # first-copy-wins is about capture order: a valid copy arriving first is accepted, and the later
    # original is the one reported as conflicting. (The report is what lets a reader see the swap.)
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"EVIL"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"GOOD"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"EVIL"
    assert [(c.packet_index, c.payload, c.accepted, c.differing_bytes) for c in tr.conflicts] == \
        [(3, b"GOOD", b"EVIL", 4)]


def test_identical_retransmission_is_counted_not_reported():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"hello world"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"hello world"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"hello world"
    assert _server(tr).retransmitted_bytes == 11 and tr.conflicts == () and tr.dropped == ()


def test_bad_ipv4_header_checksum_is_dropped_by_name():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"XXXX", bad_ip=True),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
    ]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is None
    tr = nf.reassemble_tcp_tolerant(data)
    assert _server(tr).data == b"abcd"
    assert [(d.packet_index, d.reason, d.payload) for d in tr.dropped] == [(2, nf.CHECKSUM_IPV4, b"XXXX")]


def test_unparseable_tcp_header_is_dropped_as_malformed():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"efgh", data_offset_words=3, zero_tcp=True),   # offset 12 < 20
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"efgh"),
    ]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is None
    tr = nf.reassemble_tcp_tolerant(data)
    assert _server(tr).data == b"abcdefgh"
    assert [(d.packet_index, d.reason, d.src) for d in tr.dropped] == [(3, nf.MALFORMED, None)]


def test_zero_tcp_checksum_means_not_computed_and_is_kept():
    frames = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"offload", zero_tcp=True)]
    data = fx.pcap(frames)
    tr = nf.reassemble_tcp_tolerant(data)
    assert _server(tr).data == b"offload" and tr.dropped == ()
    assert nf.reassemble_tcp(data) is not None


def test_a_hole_ends_the_stream_and_is_reported():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 50009, 0x18, b"ijkl"),           # efgh (offset 4..8) never arrives
        fx.tcp_frame(S, C, SP, CP, 50013, 0x11),
    ]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is None
    tr = nf.reassemble_tcp_tolerant(data)
    srv = _server(tr)
    assert srv.data == b"abcd" and not srv.complete
    assert [(g.offset, g.length) for g in tr.gaps] == [(4, 4)]
    assert any("gap in" in ln and "offset 4" in ln for ln in tr.report())


def test_partial_overlap_keeps_accepted_bytes_and_appends_new_ones():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcdef"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"XYghij"),          # offset 4: "ef" disagrees, "ghij" new
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"abcdefghij"
    (c,) = tr.conflicts
    assert (c.offset, c.payload, c.accepted, c.differing_bytes) == (4, b"XYghij", b"efghij", 2)
    assert _server(tr).retransmitted_bytes == 2


def test_segment_before_the_stream_start_is_dropped():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 49990, 0x18, b"early"),            # before SYN+1
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"data"
    assert [(d.packet_index, d.reason, d.payload) for d in tr.dropped] == [(2, nf.DROP_BEFORE_START, b"early")]


def test_direction_with_only_early_bytes_is_declined_by_name():
    frames = _handshake() + [fx.tcp_frame(S, C, SP, CP, 49990, 0x18, b"early")]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert tr.streams == ()
    assert len(tr.declined) == 1 and "no payload byte" in tr.declined[0]


def test_direction_without_syn_is_anchored_at_its_lowest_sequence():
    # no handshake in the capture (it started mid-conversation): the lowest seq is the stream start,
    # whatever order the segments arrive in.
    frames = [
        fx.tcp_frame(S, C, SP, CP, 7004, 0x18, b"efgh"),
        fx.tcp_frame(S, C, SP, CP, 7000, 0x18, b"abcd"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    srv = _server(tr)
    assert srv.data == b"abcdefgh" and srv.first_sequence == 7000
    assert not srv.syn and not srv.complete and tr.gaps == ()


def test_direction_without_syn_spanning_too_far_is_declined_by_name(monkeypatch):
    monkeypatch.setattr(nf, "MAX_STREAM", 16)
    frames = [
        fx.tcp_frame(S, C, SP, CP, 7000, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 7100, 0x18, b"efgh"),          # 100 bytes on: over the 16-byte limit
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert tr.streams == ()
    assert len(tr.declined) == 1 and "no SYN" in tr.declined[0]


def test_segment_beyond_the_stream_limit_is_dropped_by_name(monkeypatch):
    monkeypatch.setattr(nf, "MAX_STREAM", 8)
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"efghij"),        # ends at offset 10 > 8
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"abcd"
    assert [(d.packet_index, d.reason, d.payload) for d in tr.dropped] == [(3, nf.DROP_TOO_LARGE, b"efghij")]


def test_fin_at_the_end_of_the_accepted_bytes_makes_the_stream_complete():
    base = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd")]
    good = nf.reassemble_tcp_tolerant(fx.pcap(base + [fx.tcp_frame(S, C, SP, CP, 50005, 0x11)]))
    assert _server(good).complete and _server(good).fin
    off = nf.reassemble_tcp_tolerant(fx.pcap(base + [fx.tcp_frame(S, C, SP, CP, 50009, 0x11)]))
    assert _server(off).fin and not _server(off).complete      # FIN past the data: bytes are missing


def test_container_that_is_not_a_capture_is_none():
    assert nf.reassemble_tcp_tolerant(b"not a capture at all, just some text bytes") is None


# ------------------------------------------------------------------------------ verification round 1

def test_strict_reader_declines_a_lone_bad_ipv4_header_checksum():
    # no duplicate and no conflict: the bad IPv4 header checksum alone must decline the strict result
    clean = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd")]
    assert [s.data for s in nf.reassemble_tcp(fx.pcap(clean))] == [b"abcd"]
    bad = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd", bad_ip=True)]
    assert nf.reassemble_tcp(fx.pcap(bad)) is None


def test_strict_reader_declines_a_lone_bad_tcp_checksum():
    bad = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd", bad_tcp=True)]
    assert nf.reassemble_tcp(fx.pcap(bad)) is None


def test_segment_straddling_the_stream_start_is_trimmed_and_the_trim_reported():
    # seq = ISN: one byte before SYN+1. The receiver keeps "data" and the leading "X" is reported.
    frames = _handshake() + [fx.tcp_frame(S, C, SP, CP, 50000, 0x18, b"Xdata")]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"data" and tr.gaps == () and tr.conflicts == ()
    assert [(d.packet_index, d.reason, d.seq, d.payload) for d in tr.dropped] == \
        [(2, nf.DROP_TRIMMED, 50000, b"X")]


def test_trimmed_bytes_still_obey_first_copy_wins():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"good"),
        fx.tcp_frame(S, C, SP, CP, 49998, 0x18, b"XYZevil"),        # trims "XYZ", then "evil" conflicts
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"good"
    assert [(c.packet_index, c.offset, c.payload, c.accepted) for c in tr.conflicts] == \
        [(3, 0, b"evil", b"good")]
    assert [(d.reason, d.payload) for d in tr.dropped] == [(nf.DROP_TRIMMED, b"XYZ")]


def test_segment_ending_exactly_at_the_stream_start_is_dropped_whole():
    # 5 bytes at seq 49996 end at SYN+1 = 50001: nothing is in the stream, so the whole copy is dropped
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 49996, 0x18, b"early"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"data"
    assert [(d.packet_index, d.reason, d.payload) for d in tr.dropped] == [(2, nf.DROP_BEFORE_START, b"early")]


def test_data_carried_in_a_syn_starts_the_stream():
    frames = [
        fx.tcp_frame(C, S, CP, SP, 1000, 0x02, b"hello"),            # SYN with data (TCP Fast Open)
        fx.tcp_frame(S, C, SP, CP, 50000, 0x12),
        fx.tcp_frame(C, S, CP, SP, 1006, 0x18, b" world"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    (client,) = [s for s in tr.streams if s.sport == CP]
    assert client.data == b"hello world" and client.first_sequence == 1001
    assert tr.dropped == () and tr.gaps == ()


def test_segment_ending_exactly_at_the_stream_limit_is_kept_and_one_past_it_dropped(monkeypatch):
    monkeypatch.setattr(nf, "MAX_STREAM", 8)
    at = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"efgh"),           # ends at offset 8 == MAX_STREAM
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(at))
    assert _server(tr).data == b"abcdefgh" and tr.dropped == ()
    past = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"abcd"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x18, b"efghi"),          # ends at offset 9 == MAX_STREAM + 1
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(past))
    assert _server(tr).data == b"abcd"
    assert [(d.packet_index, d.reason) for d in tr.dropped] == [(3, nf.DROP_TOO_LARGE)]


def test_drops_are_reported_in_capture_order_across_kinds():
    # the before-start drop (packet 2) is found per direction, after the checksum drop (packet 3) is
    # found in the packet scan; the report still lists them in capture order.
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 49990, 0x18, b"early"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"XXXX", bad_tcp=True),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert [(d.packet_index, d.reason) for d in tr.dropped] == \
        [(2, nf.DROP_BEFORE_START), (3, nf.CHECKSUM_TCP)]


def test_conflicts_are_reported_in_capture_order_across_directions():
    # the client direction sorts first by key, but its conflict (packet 5) comes after the server's (4)
    assert (C, CP) < (S, SP)
    frames = _handshake() + [
        fx.tcp_frame(C, S, CP, SP, 1001, 0x18, b"ping"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"pong"),
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"PONG"),
        fx.tcp_frame(C, S, CP, SP, 1001, 0x18, b"PING"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert [(c.packet_index, c.sport) for c in tr.conflicts] == [(4, SP), (5, CP)]


def test_a_second_syn_ack_with_another_isn_is_set_aside_and_the_first_anchors():
    # A SYN-ACK does not open a new generation, so a second one with another ISN lands in the same
    # direction. The first SYN anchors the stream; the disagreeing one is dropped by name, payload and all.
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 70000, 0x12, b"spoof"),          # packet 2: forged SYN-ACK, other ISN
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
    ]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is None                          # strict declines the disagreeing SYN
    tr = nf.reassemble_tcp_tolerant(data)
    server = _server(tr)
    assert server.data == b"data" and server.first_sequence == 50001
    assert [(d.packet_index, d.reason, d.seq, d.payload, d.sport) for d in tr.dropped] == \
        [(2, nf.DROP_SYN_DISAGREES, 70000, b"spoof", SP)]
    assert tr.conflicts == () and tr.gaps == () and tr.declined == ()
    assert any(ln.startswith(f"dropped packet 2 ({nf.DROP_SYN_DISAGREES}) {S}:{SP} -> {C}:{CP} seq 70000")
               for ln in tr.report())


def test_a_repeated_syn_ack_with_the_same_isn_is_not_a_drop():
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 50000, 0x12),                    # retransmitted SYN-ACK, same ISN
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert _server(tr).data == b"data" and tr.dropped == ()


def _as_ipv4_proto(frame: bytes, proto: int, *, frag: bool = False, fix_checksum: bool) -> bytes:
    """The same Ethernet/IPv4 frame with another IP protocol (and optionally the MF flag set)."""
    b = bytearray(frame)
    ip = 14
    b[ip + 9] = proto
    if frag:
        b[ip + 6:ip + 8] = (0x2000).to_bytes(2, "big")             # MF set, offset 0
    if fix_checksum:
        b[ip + 10:ip + 12] = b"\x00\x00"
        b[ip + 10:ip + 12] = fx.checksum(bytes(b[ip:ip + 20])).to_bytes(2, "big")
    return bytes(b)


def test_a_bad_checksum_non_tcp_packet_is_reported_not_silently_skipped():
    udp_bad = _as_ipv4_proto(fx.tcp_frame(C, S, 5353, 53, 0, 0, b"q"), 17, fix_checksum=False)
    frames = _handshake() + [udp_bad, fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data")]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is None                          # strict declines the whole capture
    tr = nf.reassemble_tcp_tolerant(data)
    assert _server(tr).data == b"data"
    assert [(d.packet_index, d.reason, d.src) for d in tr.dropped] == [(2, nf.DROP_NOT_TCP_BAD_IPV4, None)]
    assert f"dropped packet 2 ({nf.DROP_NOT_TCP_BAD_IPV4}), 0 payload bytes" in tr.report()


def test_a_bad_checksum_ip_fragment_is_reported():
    frag_bad = _as_ipv4_proto(fx.tcp_frame(C, S, CP, SP, 1001, 0x18, b"frag"), 6, frag=True,
                              fix_checksum=False)
    frames = _handshake() + [frag_bad, fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data")]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    assert [(d.packet_index, d.reason) for d in tr.dropped] == [(2, nf.DROP_NOT_TCP_BAD_IPV4)]


def test_a_good_checksum_non_tcp_packet_is_ignored_without_a_report():
    udp_ok = _as_ipv4_proto(fx.tcp_frame(C, S, 5353, 53, 0, 0, b"q"), 17, fix_checksum=True)
    frames = _handshake() + [udp_ok, fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data")]
    data = fx.pcap(frames)
    assert nf.reassemble_tcp(data) is not None
    tr = nf.reassemble_tcp_tolerant(data)
    assert _server(tr).data == b"data" and tr.dropped == ()


def test_a_set_aside_syn_carrying_fin_does_not_spoil_the_stream_end():
    # the disagreeing SYN-ACK also carries FIN; it is set aside whole, so the real FIN still closes
    # the stream at the end of the accepted bytes and the stream is complete.
    frames = _handshake() + [
        fx.tcp_frame(S, C, SP, CP, 70000, 0x13),                    # packet 2: SYN|ACK|FIN, other ISN
        fx.tcp_frame(S, C, SP, CP, 50001, 0x18, b"data"),
        fx.tcp_frame(S, C, SP, CP, 50005, 0x11),                    # FIN at the end of "data"
    ]
    tr = nf.reassemble_tcp_tolerant(fx.pcap(frames))
    server = _server(tr)
    assert server.data == b"data" and server.complete
    assert [(d.packet_index, d.reason) for d in tr.dropped] == [(2, nf.DROP_SYN_DISAGREES)]
