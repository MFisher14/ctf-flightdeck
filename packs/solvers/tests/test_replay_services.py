"""B-155: the replayable live-service servers (ctf.livereplay). Each binds 127.0.0.1 only and answers
exactly what its declarative spec says; no challenge binary runs. Tests drive each over loopback."""
from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from ctf import livereplay


def test_dns_replay_answers_txt_and_is_loopback():
    spec = {"kind": "dns", "records": {"flag.chal": ["DEMO{dns_1}", "part2"]},
            "probe": {"name": "flag.chal", "qtype": "TXT"}}
    with livereplay.start(spec) as svc:
        host, port = svc.address
        assert host == "127.0.0.1"
        txts = livereplay.probe_dns(svc.address, "flag.chal")
        assert txts == ["DEMO{dns_1}", "part2"]
        # unknown name -> NXDOMAIN -> no strings (not a crash, not the flag)
        assert livereplay.probe_dns(svc.address, "nope.chal") == []
    # the probe/run_probe flattens TXT strings for scanning
    with livereplay.start(spec) as svc:
        assert livereplay.run_probe(svc, spec) == b"DEMO{dns_1}\npart2"


def test_dns_replay_only_answers_its_records():
    # a record configured but queried with the wrong name must not leak another record's value
    spec = {"kind": "dns", "records": {"a.chal": ["AAA"], "b.chal": ["BBB"]}}
    with livereplay.start(spec) as svc:
        assert livereplay.probe_dns(svc.address, "a.chal") == ["AAA"]
        assert livereplay.probe_dns(svc.address, "b.chal") == ["BBB"]
        assert livereplay.probe_dns(svc.address, "c.chal") == []


def _raw_query(address, name: str, qtype: int) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(query, address)
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return data


def test_dns_replay_answers_only_txt_queries():
    spec = {"kind": "dns", "records": {"flag.chal": ["DEMO{only_txt}"]}}
    with livereplay.start(spec) as svc:
        a = _raw_query(svc.address, "flag.chal", 1)          # type A for a name that has a TXT record
        txt = _raw_query(svc.address, "flag.chal", livereplay.DNS_TYPE_TXT)
    txid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", a[:12])
    assert txid == 0x4242 and flags & 0x000F == 3 and an == 0      # NXDOMAIN, no answer
    assert b"DEMO{only_txt}" not in a
    _, tflags, _, tan, _, _ = struct.unpack(">HHHHHH", txt[:12])
    assert tflags & 0x000F == 0 and tan == 1 and b"DEMO{only_txt}" in txt


def _slow_line_server(delay: float, reply: bytes):
    """A loopback TCP server that answers one line `delay` seconds after receiving it."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            time.sleep(delay)
            conn.sendall(reply)
            time.sleep(0.5)
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, t


def test_socat_probe_reads_a_delayed_reply():
    # a reply 0.4 s after the send (a loaded machine) is still read; a fixed short sleep missed it
    srv, t = _slow_line_server(0.4, b"DEMO{slow_reply}\n")
    try:
        got = livereplay.probe_socat(srv.getsockname(), ["hello\n"], reply_wait=1.0)
    finally:
        t.join(timeout=3)
        srv.close()
    assert b"DEMO{slow_reply}" in got


def test_socat_probe_until_waits_for_the_text_or_fails_loudly():
    srv, t = _slow_line_server(0.3, b"DEMO{until}\n")
    try:
        got = livereplay.probe_socat(srv.getsockname(), ["go\n"], reply_wait=0.05, until="DEMO{until}")
    finally:
        t.join(timeout=3)
        srv.close()
    assert b"DEMO{until}" in got
    spec = {"kind": "socat", "banner": "hi\n", "turns": []}
    with livereplay.start(spec) as svc:
        with pytest.raises(livereplay.ReplayError, match="never-sent"):
            livereplay.probe_socat(svc.address, [], timeout=1.0, reply_wait=0.2, until="never-sent")


def test_socat_replay_scripted_conversation():
    spec = {"kind": "socat", "banner": "welcome\n",
            "turns": [{"recv_contains": "flag", "send": "DEMO{socat_1}\n"},
                      {"recv_contains": None, "send": "bye\n"}],
            "probe": {"inputs": ["give me the flag\n", "anything\n"]}}
    with livereplay.start(spec) as svc:
        host, _ = svc.address
        assert host == "127.0.0.1"
        data = livereplay.run_probe(svc, spec)
    assert b"welcome\n" in data
    assert b"DEMO{socat_1}\n" in data
    assert b"bye\n" in data


def test_socat_turn_only_fires_on_match():
    # the flag turn requires the substring; an input that never contains it must not reveal the flag
    spec = {"kind": "socat", "banner": "",
            "turns": [{"recv_contains": "password", "send": "DEMO{secret}\n"}]}
    with livereplay.start(spec) as svc:
        got = livereplay.probe_socat(svc.address, ["hello\n"], reply_wait=0.3)
    assert b"DEMO{secret}" not in got


def test_web_replay_serves_routes_and_404():
    spec = {"kind": "web",
            "routes": {"/": {"status": 200, "body": "home"},
                       "/flag": {"status": 200, "body": "DEMO{web_1}", "headers": {"X-Chal": "1"}}},
            "probe": {"path": "/flag"}}
    with livereplay.start(spec) as svc:
        assert svc.address[0] == "127.0.0.1"
        assert livereplay.probe_web(svc.service.base_url, "/") == b"home"
        assert livereplay.run_probe(svc, spec) == b"DEMO{web_1}"
        assert livereplay.probe_web(svc.service.base_url, "/missing") == b"not found"


def test_unknown_kind_and_missing_fields_fail_loudly():
    with pytest.raises(livereplay.ReplayError):
        with livereplay.start({"kind": "smtp"}):
            pass
    with pytest.raises(livereplay.ReplayError):
        with livereplay.start({"kind": "dns"}):      # no records
            pass


def test_run_probe_requires_a_probe_section():
    spec = {"kind": "dns", "records": {"a": ["x"]}}
    with livereplay.start(spec) as svc:
        with pytest.raises(livereplay.ReplayError):
            livereplay.run_probe(svc, spec)


def test_servers_stop_on_exit():
    spec = {"kind": "web", "routes": {"/": {"body": "hi"}}}
    with livereplay.start(spec) as svc:
        addr = svc.address
    # after exit the port is no longer served
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        with pytest.raises(OSError):
            s.connect(addr)
    finally:
        s.close()
