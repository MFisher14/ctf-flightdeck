"""B-205: the live-service probe and exploit harness (solvers/toolkits/live_harness.py).

Every test runs against a fake service the test itself starts on 127.0.0.1 (loopback, no external
network) and pins a scope profile that allows 127.0.0.1. No challenge binary is executed; the servers
are synthetic Python handlers built here.

What is covered, each with a test that fails when the behaviour is wrong:
  - the framing map (line/raw/prompt/length): frame() and complete().
  - Session: scope refusal before any socket, banner read, framed request/response, raw send, replay,
    the PASS/FAIL loop, and length framing round-trip.
  - Chain: the fast prefix, run with oracles, and replay_prefix.
  - InstanceLifecycle: it detects a mid-chain rotation to a new host:port, re-establishes (re-checking
    scope), replays only the fast prefix on the new instance, and resumes the tail -- proven by the
    per-server request logs.
  - the mechanical primitives: p64/u64/flat and the cyclic pattern + offset find.
"""
import datetime as dt
import socket
import socketserver
import threading

import pytest

import live_harness as lh
import pwn_target as pt
from ctf import event, scope


# --------------------------------------------------------------------------- scope fixture

def _profile(scope_list, slug="harness-test"):
    return event.parse({
        "slug": slug, "name": "harness test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": ["FLAG"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_list)},
    }, src="<test>")


@pytest.fixture
def loopback_scope():
    before = scope.pinned()
    scope.pin(_profile(["127.0.0.1"]))
    yield
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


# --------------------------------------------------------------------------- fake services

class _LineServer(socketserver.ThreadingTCPServer):
    """A line-oriented stateful service: AUTH, then SET, then WIN yields the flag. State is per
    connection, so a fresh instance (after rotation) has none until AUTH/SET are replayed on it."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.log = []                       # every command line this instance received (any connection)
        super().__init__(("127.0.0.1", 0), _LineHandler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()


class _LineHandler(socketserver.StreamRequestHandler):
    def handle(self):
        authed = seted = False
        for raw in self.rfile:
            cmd = raw.rstrip(b"\n")
            self.server.log.append(cmd)
            if cmd == b"AUTH":
                authed = True
                self.wfile.write(b"OK\n")
            elif cmd == b"SET":
                seted = authed
                self.wfile.write(b"OK\n" if authed else b"NO\n")
            elif cmd == b"WIN":
                self.wfile.write(b"FLAG{win}\n" if (authed and seted) else b"NO\n")
            else:
                self.wfile.write(b"?\n")
            self.wfile.flush()


class _LengthServer(socketserver.ThreadingTCPServer):
    """A 4-byte big-endian length-prefixed echo (upper-cased body)."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _LengthHandler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()


class _LengthHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        while True:
            hdr = _recvn(s, 4)
            if len(hdr) < 4:
                return
            n = int.from_bytes(hdr, "big")
            body = _recvn(s, n)
            if len(body) < n:
                return
            out = body.upper()
            s.sendall(len(out).to_bytes(4, "big") + out)


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        b = sock.recv(n - len(buf))
        if not b:
            break
        buf += b
    return buf


def _line_session(host, port):
    return lh.Session(host, port, framing=lh.Framing(mode="line"), min_interval=0, read_timeout=4)


# --------------------------------------------------------------------------- framing map

def test_framing_line_frame_and_complete():
    fr = lh.Framing(mode="line")
    assert fr.frame(b"hello") == b"hello\n"
    body, rest = fr.complete(b"abc\ndef")
    assert body == b"abc" and rest == b"def"
    assert fr.complete(b"partial") == (None, b"partial")


def test_framing_raw_is_one_read():
    fr = lh.Framing(mode="raw")
    assert fr.frame(b"xy") == b"xy"
    assert fr.complete(b"anything") == (b"anything", b"")
    assert fr.complete(b"") == (None, b"")


def test_framing_prompt_includes_delimiter():
    fr = lh.Framing(mode="prompt", prompt=b"> ")
    body, rest = fr.complete(b"menu:\n1) go\n> leftover")
    assert body.endswith(b"> ") and rest == b"leftover"


def test_framing_length_roundtrip_math():
    fr = lh.Framing(mode="length", length_bytes=4, byteorder="big")
    assert fr.frame(b"hi") == b"\x00\x00\x00\x02hi"
    assert fr.complete(b"\x00\x00\x00\x02h") == (None, b"\x00\x00\x00\x02h")  # body not all here yet
    body, rest = fr.complete(b"\x00\x00\x00\x02hiXX")
    assert body == b"hi" and rest == b"XX"


def test_framing_rejects_bad_config():
    with pytest.raises(lh.HarnessError):
        lh.Framing(mode="nope")
    with pytest.raises(lh.HarnessError):
        lh.Framing(mode="prompt", prompt=b"")
    with pytest.raises(lh.HarnessError):
        lh.Framing(mode="length", length_bytes=99)


# --------------------------------------------------------------------------- Session / scope

def test_session_refuses_out_of_scope_before_any_socket(loopback_scope, monkeypatch):
    # The scope allows only 127.0.0.1; a public host must be refused at construction, no socket opened.
    opened = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (opened.append(a), real(*a, **k))[1])
    with pytest.raises(lh.ct.OutOfScope):
        lh.Session("8.8.8.8", 80)
    assert opened == []


def test_session_banner_request_replay_and_loop(loopback_scope):
    srv = _LineServer()
    try:
        with _line_session("127.0.0.1", srv.port) as s:
            assert s.request(b"AUTH") == b"OK"            # framed request/response
            assert s.replay([b"SET", b"WIN"]) == [b"OK", b"FLAG{win}"]   # ordered replay
            # PASS/FAIL loop: only the AUTH+SET+WIN state yields the flag; a cold WIN FAILs.
        with _line_session("127.0.0.1", srv.port) as s2:
            cold = s2.check(b"WIN", lh.contains(b"FLAG{"))
            assert cold.verdict == lh.FAIL and cold.response == b"NO"
            s2.request(b"AUTH"); s2.request(b"SET")
            hot = s2.check(b"WIN", lh.contains(b"FLAG{"))
            assert hot.passed and hot.response == b"FLAG{win}"
    finally:
        srv.stop()


def test_session_run_until_fires_until_pass(loopback_scope):
    srv = _LineServer()
    try:
        with _line_session("127.0.0.1", srv.port) as s:
            s.request(b"AUTH"); s.request(b"SET")
            # Candidates: the first two FAIL the oracle, WIN PASSes; run_until returns the PASS.
            res = s.run_until([b"nope", b"still-no", b"WIN"], lh.contains(b"FLAG{"))
            assert res.passed and res.request == b"WIN"
    finally:
        srv.stop()


def test_session_raw_send_and_recv(loopback_scope):
    srv = _LineServer()
    try:
        s = lh.Session("127.0.0.1", srv.port, framing=lh.Framing("raw"), min_interval=0, read_timeout=4)
        with s:
            s.send_raw(b"AUTH\n")              # exact bytes, caller-framed
            assert b"OK" in s.recv_raw()
    finally:
        srv.stop()


def test_session_length_framing_roundtrip(loopback_scope):
    srv = _LengthServer()
    try:
        fr = lh.Framing(mode="length", length_bytes=4, byteorder="big")
        with lh.Session("127.0.0.1", srv.port, framing=fr, min_interval=0, read_timeout=4) as s:
            assert s.request(b"hello") == b"HELLO"
            assert s.request(b"abc") == b"ABC"
    finally:
        srv.stop()


# --------------------------------------------------------------------------- Chain

def test_chain_fast_prefix_and_run(loopback_scope):
    srv = _LineServer()
    chain = lh.Chain([
        lh.Step(b"AUTH", lh.contains(b"OK"), name="auth", fast=True),
        lh.Step(b"SET", lh.contains(b"OK"), name="set", fast=True),
        lh.Step(b"WIN", lh.contains(b"FLAG{"), name="win", fast=False),
    ])
    assert [st.name for st in chain.fast_prefix()] == ["auth", "set"]
    try:
        with _line_session("127.0.0.1", srv.port) as s:
            results = chain.run(s)
        assert [r.verdict for r in results] == [lh.PASS, lh.PASS, lh.PASS]
        assert chain.checkpoint == 2
    finally:
        srv.stop()


def test_chain_run_raises_when_oracle_fails(loopback_scope):
    srv = _LineServer()
    # WIN before AUTH/SET: the first step's oracle (expects OK) actually passes AUTH, but a SET-less
    # WIN FAILs. Build a chain whose first step is WIN to force an early oracle failure.
    chain = lh.Chain([lh.Step(b"WIN", lh.contains(b"FLAG{"), name="win")])
    try:
        with _line_session("127.0.0.1", srv.port) as s:
            with pytest.raises(lh.HarnessError):
                chain.run(s)
    finally:
        srv.stop()


def test_chain_replay_prefix_only(loopback_scope):
    srv = _LineServer()
    chain = lh.Chain([
        lh.Step(b"AUTH", lh.contains(b"OK"), fast=True),
        lh.Step(b"SET", lh.contains(b"OK"), fast=True),
        lh.Step(b"WIN", lh.contains(b"FLAG{"), fast=False),
    ])
    try:
        with _line_session("127.0.0.1", srv.port) as s:
            pref = chain.replay_prefix(s)
        assert [r.request for r in pref] == [b"AUTH", b"SET"]      # only the prefix, not WIN
        assert chain.checkpoint == -1                              # replay does not advance the checkpoint
    finally:
        srv.stop()


# --------------------------------------------------------------------------- InstanceLifecycle

def test_lifecycle_detects_rotation_replays_prefix_and_resumes(loopback_scope):
    a, b = _LineServer(), _LineServer()
    chain = lh.Chain([
        lh.Step(b"AUTH", lh.contains(b"OK"), name="auth", fast=True),
        lh.Step(b"SET", lh.contains(b"OK"), name="set", fast=True),
        lh.Step(b"WIN", lh.contains(b"FLAG{"), name="win", fast=False),
    ])

    # The source rotates from instance A to instance B after it has been read a few times -- standing in
    # for CSCTF's ~5-minute rotation handing out a new host:port mid-exploit.
    state = {"n": 0}

    def source():
        state["n"] += 1
        inst = a if state["n"] <= 3 else b
        return {"host": "127.0.0.1", "port": inst.port, "remaining": 300}

    def factory(host, port):
        return _line_session(host, port)

    life = lh.InstanceLifecycle(source, factory, chain=chain)
    try:
        results = life.run_chain()
        assert [r.verdict for r in results] == [lh.PASS, lh.PASS, lh.PASS]
        assert results[-1].response == b"FLAG{win}"
        # Instance A got only the fast prefix before the rotation; it never saw WIN.
        assert a.log == [b"AUTH", b"SET"]
        # Instance B got the replayed prefix AND the resumed tail -- the exploit finished on the new box.
        assert b.log == [b"AUTH", b"SET", b"WIN"]
        # The lifecycle ended pointed at the new instance.
        assert life.endpoint.port == b.port
    finally:
        a.stop()
        b.stop()


def test_lifecycle_rotation_imminent_from_remaining(loopback_scope):
    srv = _LineServer()
    rem = {"v": 300.0}

    def source():
        return {"host": "127.0.0.1", "port": srv.port, "remaining": rem["v"]}

    life = lh.InstanceLifecycle(source, lambda h, p: _line_session(h, p))
    try:
        life.session()                         # establish on the current endpoint
        assert life.rotation_imminent(30) is False
        rem["v"] = 10.0
        assert life.rotation_imminent(30) is True
    finally:
        srv.stop()


def test_lifecycle_reestablish_rechecks_scope(loopback_scope):
    # When the rotated endpoint is out of scope, the session factory (via PwnTarget -> ctf.scope) must
    # refuse it rather than connect. Prove scope is re-run on the new endpoint, not only the first.
    srv = _LineServer()
    endpoints = [{"host": "127.0.0.1", "port": srv.port},
                 {"host": "203.0.113.9", "port": 9999}]      # second read: out of scope
    calls = {"n": 0}

    def source():
        ep = endpoints[min(calls["n"], 1)]
        calls["n"] += 1
        return ep

    life = lh.InstanceLifecycle(source, lambda h, p: _line_session(h, p))
    try:
        life.session()                         # fine: 127.0.0.1 is in scope
        with pytest.raises(lh.ct.OutOfScope):
            life.establish()                   # the rotated 203.0.113.9 is refused before any socket
    finally:
        srv.stop()


# --------------------------------------------------------------------------- flag oracle

def test_flag_oracle_matches_event_format():
    prof = _profile(["127.0.0.1"])
    oracle = lh.flag_oracle(prof)
    assert oracle(b"here is FLAG{abc_123} for you") is True
    assert oracle(b"no flag here") is False


# --------------------------------------------------------------------------- primitives

def test_pack_unpack_roundtrip():
    assert lh.p64(0x4142434445464748) == b"HGFEDCBA"
    assert lh.u64(b"HGFEDCBA") == 0x4142434445464748
    assert lh.p32(1, byteorder="big") == b"\x00\x00\x00\x01"
    with pytest.raises(lh.HarnessError):
        lh.p8(256)                              # does not fit one byte
    with pytest.raises(lh.HarnessError):
        lh.u32(b"abc")                          # wrong width


def test_flat_packs_ints_and_joins_bytes():
    assert lh.flat(b"AAAA", 0x4142, b"ZZ") == b"AAAA" + lh.p64(0x4142) + b"ZZ"


def test_cyclic_is_unique_per_window_and_find_recovers_offset():
    pat = lh.cyclic(600, width=4)
    assert len(pat) == 600
    windows = [bytes(pat[i:i + 4]) for i in range(len(pat) - 3)]
    assert len(set(windows)) == len(windows)    # every 4-byte window distinct
    # A value "read from a crashed register" names its offset in the pattern.
    probe = bytes(pat[120:124])
    assert lh.cyclic_find(probe, width=4) == 120
    assert lh.cyclic_find(lh.u32(probe), width=4) == 120
    assert lh.cyclic_find(b"\xff\xff\xff\xff", width=4) == -1


def test_cyclic_rejects_over_capacity():
    with pytest.raises(lh.HarnessError):
        lh.cyclic(100, width=1, alphabet=b"ab")   # capacity 2, asked for 100
