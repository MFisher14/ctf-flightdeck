"""B-031: the MAVLink 2 parse / sign / live-link engine and provisioning re-sign (solvers/toolkits/mavlink_link.py).

Everything is synthetic: frames, tlog and pcap bytes are built in the test, and the live link is
driven against a loopback fake on 127.0.0.1. No challenge binary is executed and no real MAVLink is
read. The independent anchors (not derived from the module under test) are:
  * the real MAVLink common.xml CRC_EXTRA values,
  * the RFC 5869 HKDF-SHA256 Test Case 1 vector,
  * the signature formula sha256(key || frame || link_id || ts6)[:6] recomputed by hand.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import socket
import socketserver
import struct
import threading

import pytest

import mavlink_link as mav
from ctf import event, scope
from ctf.cli import mavlink as cli
from ctf.result import SolverResult

KEY = bytes.fromhex("8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60")


# --------------------------------------------------------------------------- CRC_EXTRA (external truth)
def test_crc_extra_matches_real_mavlink_values():
    # The real common.xml CRC_EXTRA bytes; each must be reproduced from the message definition.
    known = {0: 50, 1: 124, 11: 89, 33: 104, 75: 158, 76: 152, 77: 143, 253: 83, 256: 71}
    for msgid, want in known.items():
        name, fields = mav.MESSAGE_DEFS[msgid]
        assert mav.crc_extra_from_def(name, fields) == want, msgid
        assert mav.crc_extra(msgid) == want


def test_crc_extra_table_is_backed_by_a_definition():
    # No magic numbers: every table entry is recomputed from its definition (table can't drift).
    for msgid, want in mav.CRC_EXTRA.items():
        name, fields = mav.MESSAGE_DEFS[msgid]
        assert mav.crc_extra_from_def(name, fields) == want, msgid


def test_crc_extra_unknown_msgid_fails_loudly():
    with pytest.raises(mav.MavlinkError):
        mav.crc_extra(4242)


# --------------------------------------------------------------------------- framing round-trip
def test_build_parse_roundtrip_unsigned():
    frame = mav.build_frame(0, mav.heartbeat(), seq=7, sysid=1, compid=1)
    frames, rest = mav.parse_stream(frame)
    assert rest == b""
    assert len(frames) == 1
    f = frames[0]
    assert f.msgid == 0 and f.sysid == 1 and f.seq == 7 and not f.signed
    assert f.crc_ok()


def test_crc_detects_a_mutated_frame():
    frame = bytearray(mav.build_frame(76, mav.command_long(400), seq=0))
    frames, _ = mav.parse_stream(bytes(frame))
    assert frames[0].crc_ok()
    frame[12] ^= 0x01  # flip a payload bit
    frames, _ = mav.parse_stream(bytes(frame))
    assert not frames[0].crc_ok()


def test_signature_matches_the_documented_formula():
    ts = 123456789
    frame = mav.build_signed(76, mav.command_long(400, params=(1,)), KEY, seq=3, link_id=5, timestamp=ts)
    f, _ = mav.parse_stream(frame)
    f = f[0]
    assert f.signed and f.link_id == 5 and f.timestamp == ts
    # recompute the trailer by hand from the formula
    want = hashlib.sha256(KEY + f.body_no_sig + bytes([5]) + ts.to_bytes(6, "little")).digest()[:6]
    assert f.signature == want
    assert mav.verify_signature(f, KEY)


def test_verify_rejects_the_wrong_key():
    frame = mav.build_signed(0, mav.heartbeat(), KEY, timestamp=99)
    f, _ = mav.parse_stream(frame)
    assert not mav.verify_signature(f[0], bytes(32))


def test_which_key_picks_the_signer():
    frame = mav.build_signed(0, mav.heartbeat(), KEY, timestamp=99)
    f, _ = mav.parse_stream(frame)
    assert mav.which_key(f, [bytes(32), b"\x11" * 32, KEY]) == KEY
    assert mav.which_key(f, [bytes(32)]) is None


def test_payload_truncation_and_resync():
    # A heartbeat with a trailing zero custom_mode truncates; junk before the frame is resynced past.
    frame = mav.build_frame(0, mav.heartbeat(custom_mode=0))
    buf = b"\x00\xff\xAApre-junk" + frame
    frames, _ = mav.parse_stream(buf, require_crc=True)
    assert len(frames) == 1 and frames[0].msgid == 0
    # a partial trailing frame comes back as leftover, not a bad parse
    frames, rest = mav.parse_stream(frame + frame[:4])
    assert len(frames) == 1 and rest == frame[:4]


def test_build_frame_truncates_trailing_zero_payload():
    # MAVLink 2 drops trailing zero bytes of the payload on the wire; parsing must reflect that.
    # Kills the _trim identity mutation (rstrip -> payload): without truncation the on-wire payload
    # would keep its trailing zeros and come back at full length.
    full = mav.heartbeat(custom_mode=0, system_status=0, mavlink_version=0)
    assert full == b"\x00\x00\x00\x00\x06\x08\x00\x00\x00"  # 9 bytes, 3 trailing zeros
    frame = mav.build_frame(0, full)
    parsed, _ = mav.parse_stream(frame, require_crc=True)
    assert parsed[0].payload == b"\x00\x00\x00\x00\x06\x08"
    assert len(parsed[0].payload) < len(full)


# --------------------------------------------------------------------------- SETUP_SIGNING leak
def test_extract_setup_signing_recovers_the_key():
    leaked = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    pl = mav.setup_signing_payload(1, 1, leaked, 777)
    frame = mav.build_signed(mav.SETUP_SIGNING, pl, KEY, timestamp=5)
    f, _ = mav.parse_stream(frame)
    got = mav.extract_setup_signing(f)
    assert len(got) == 1
    assert got[0].secret_key == leaked and got[0].initial_timestamp == 777


def test_extract_handles_truncated_key_with_trailing_zeros():
    # MAVLink 2 truncates trailing zero bytes; a key ending in zeros must still decode in full.
    leaked = bytes.fromhex("aa" * 30) + b"\x00\x00"
    pl = mav.setup_signing_payload(2, 3, leaked, 0)
    frame = mav.build_signed(mav.SETUP_SIGNING, pl, KEY, timestamp=5)
    f, _ = mav.parse_stream(frame)
    s = mav.extract_setup_signing(f)[0]
    assert s.secret_key == leaked and len(s.secret_key) == 32
    assert s.target_system == 2 and s.target_component == 3


# --------------------------------------------------------------------------- tlog / pcap
def _tlog(records):
    out = b""
    for ts_us, frame in records:
        out += ts_us.to_bytes(8, "big") + frame
    return out


def test_parse_tlog():
    f1 = mav.build_signed(0, mav.heartbeat(), KEY, seq=0, timestamp=10)
    f2 = mav.build_signed(253, b"\x06CX-FALCON online", KEY, seq=1, timestamp=20, extra=83)
    data = _tlog([(1_700_000_000_000000, f1), (1_700_000_000_100000, f2)])
    got = mav.parse_tlog(data)
    assert [f.msgid for _, f in got] == [0, 253]
    assert got[0][0] == 1_700_000_000_000000
    assert mav.verify_signature(got[0][1], KEY)


def _udp_pcap(payloads, linktype=1):
    """A classic little-endian pcap of UDP packets each carrying one transport payload."""
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    out = gh
    for i, pl in enumerate(payloads):
        udp = struct.pack(">HHHH", 14550, 14555, 8 + len(pl), 0) + pl
        total = 20 + len(udp)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, i, 0, 64, 17, 0,
                         bytes([10, 42, 0, 1]), bytes([10, 42, 0, 2])) + udp
        if linktype == 1:
            frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip
        else:
            frame = ip
        rh = struct.pack("<IIII", i, 0, len(frame), len(frame))
        out += rh + frame
    return out


def test_parse_pcap_ethernet_udp():
    f1 = mav.build_signed(0, mav.heartbeat(), KEY, seq=0, timestamp=10)
    f2 = mav.build_signed(76, mav.command_long(176, params=(1, 4)), KEY, seq=1, timestamp=20)
    data = _udp_pcap([f1, f2])
    got = mav.parse_pcap(data)
    assert [f.msgid for _, f in got] == [0, 76]
    assert all(mav.verify_signature(f, KEY) for _, f in got)


def test_parse_pcap_raw_linktype():
    f1 = mav.build_signed(0, mav.heartbeat(), KEY, timestamp=10)
    data = _udp_pcap([f1], linktype=101)
    got = mav.parse_pcap(data)
    assert len(got) == 1 and got[0][1].msgid == 0


def test_parse_pcap_rejects_non_pcap():
    with pytest.raises(mav.MavlinkError):
        mav.parse_pcap(b"not a pcap at all............")


# --------------------------------------------------------------------------- HKDF / provisioning
def test_hkdf_rfc5869_test_case_1():
    okm = mav.hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                          bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_derive_prov_key_is_hkdf_of_serial_epoch_nonce():
    serial = b"CX-FALCON-9951"
    epoch = 1733965123
    nonce = bytes.fromhex("0123456789abcdef0123456789abcdef")
    want = mav.hkdf_sha256(serial + struct.pack("<Q", epoch), nonce, b"CX-PROV/v1", 32)
    assert mav.derive_prov_key(serial, epoch, nonce, info=b"CX-PROV/v1") == want


def test_resign_installs_new_key_and_is_signed_by_prov_key():
    prov = hashlib.sha256(b"prov").digest()
    newk = hashlib.sha256(b"attacker-key").digest()
    frame = mav.resign_setup_signing(prov, newk, target_sys=1, target_comp=1, timestamp=42)
    f, _ = mav.parse_stream(frame)
    f = f[0]
    assert f.msgid == mav.SETUP_SIGNING
    assert mav.verify_signature(f, prov)          # authenticated by the provisioning key
    assert not mav.verify_signature(f, newk)
    assert mav.extract_setup_signing([f])[0].secret_key == newk   # installs our key
    # a command signed with the new key then verifies under the new key
    cmd = mav.build_signed(76, mav.command_long(400, params=(1,)), newk, timestamp=43)
    cf, _ = mav.parse_stream(cmd)
    assert mav.verify_signature(cf[0], newk)


# --------------------------------------------------------------------------- scope guard
def _profile(scope_list):
    return event.parse({
        "slug": "mav-test", "name": "mav",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_list)},
    }, src="<test>")


def test_guard_loopback_always_allowed():
    assert mav.guard_target("127.0.0.1", 14560, None) == "127.0.0.1"
    assert mav.guard_target("127.0.0.1", 14560, _profile([])) == "127.0.0.1"


def test_guard_refuses_out_of_scope_host():
    prof = _profile(["drone.ctf.example"])
    with pytest.raises(scope.OutOfScope):
        mav.guard_target("evil.example", 14560, prof)
    assert mav.guard_target("drone.ctf.example", 14560, prof) == "drone.ctf.example"


# --------------------------------------------------------------------------- live link (loopback fake)
class _FakeDrone(socketserver.BaseRequestHandler):
    """A synthetic MAVLink unit: announces a nonce, re-provisions on a prov-key SETUP_SIGNING, and
    returns a flag from a signed reposition with the new key. Replays and unsigned frames refused."""

    PROV = hashlib.sha256(b"unit-prov-key").digest()
    FLAG = b"CSCTF{live_reposition_accepted}"

    def handle(self):
        sock = self.request
        sock.settimeout(3.0)
        active_key = None
        seen_ts = -1
        # banner: a signed STATUSTEXT with the session nonce
        banner = mav.build_signed(253, b"\x06PROV NONCE deadbeef", self.PROV, seq=0, timestamp=1000)
        sock.sendall(banner)
        buf = b""
        while True:
            try:
                chunk = sock.recv(65535)
            except socket.timeout:
                return
            if not chunk:
                return
            buf += chunk
            frames, buf = mav.parse_stream(buf)
            for f in frames:
                if not f.signed:
                    continue
                if f.timestamp is not None and f.timestamp <= seen_ts:
                    sock.sendall(mav.build_signed(253, b"\x03replay refused", self.PROV,
                                                  seq=9, timestamp=2000))
                    continue
                seen_ts = f.timestamp
                if f.msgid == mav.SETUP_SIGNING and mav.verify_signature(f, self.PROV):
                    active_key = mav.extract_setup_signing([f])[0].secret_key
                    sock.sendall(mav.build_signed(253, b"\x06signing re-provisioned", self.PROV,
                                                  seq=1, timestamp=max(seen_ts + 1, 1001)))
                elif f.msgid == 76 and active_key and mav.verify_signature(f, active_key):
                    sock.sendall(mav.build_signed(253, b"\x06" + self.FLAG, active_key,
                                                  seq=2, timestamp=max(seen_ts + 1, 1002)))


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def fake_drone():
    srv = _Server(("127.0.0.1", 0), _FakeDrone)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address
    srv.shutdown()
    srv.server_close()


def test_live_provisioning_resign_recovers_flag(fake_drone):
    host, port = fake_drone
    newk = hashlib.sha256(b"my-key").digest()
    with mav.LiveLink.connect(host, port) as link:
        banner = link.recv_frames(max_seconds=1.0)
        assert any(mav.statustext_text(f) and "NONCE" in mav.statustext_text(f) for f in banner)
        # the unit's RTC advanced the link timestamp; our next ts must exceed it
        ts0 = link.next_timestamp()
        assert ts0 > 1000
        link.send_raw(mav.resign_setup_signing(_FakeDrone.PROV, newk, timestamp=link.next_timestamp()))
        ack = link.recv_frames(max_seconds=1.0)
        assert any("re-provisioned" in (mav.statustext_text(f) or "") for f in ack)
        link.send(76, mav.command_long(192, params=(0, 0, 0, 0, 47.0, 23.0, 120.0)), newk)
        resp = link.recv_frames(max_seconds=1.0)
    flag = None
    for f in resp:
        if b"CSCTF{" in f.payload:
            flag = f.payload[f.payload.find(b"CSCTF{"):].split(b"}")[0] + b"}"
    assert flag == _FakeDrone.FLAG


def test_next_timestamp_strictly_advances_past_a_future_last_ts():
    # When the link has already seen a timestamp AHEAD of the wall clock (an RTC in the future, or
    # the last ts we ourselves emitted this tick), the next ts must still be strictly greater so the
    # stream is never replayable. Kills the mutation max(last_ts + 1, ...) -> max(last_ts, ...),
    # which would return last_ts unchanged and let a timestamp repeat.
    link = mav.LiveLink(None)
    future = mav.mav_timestamp() + 1_000_000  # well above the current wall-clock tick
    link.last_ts = future
    ts = link.next_timestamp()
    assert ts == future + 1
    assert ts > future
    # and it keeps strictly advancing when called again in the same tick
    ts2 = link.next_timestamp()
    assert ts2 > ts


def test_live_unsigned_command_is_refused(fake_drone):
    host, port = fake_drone
    with mav.LiveLink.connect(host, port) as link:
        link.recv_frames(max_seconds=0.5)
        link.sock.sendall(mav.build_frame(76, mav.command_long(400)))  # unsigned
        resp = link.recv_frames(max_seconds=1.0)
    assert not any(b"CSCTF{" in f.payload for f in resp)


# --------------------------------------------------------------------------- solve() intake
def test_solve_reports_leaked_key(tmp_path):
    leaked = bytes.fromhex("1234" * 16)
    pl = mav.setup_signing_payload(1, 190, leaked, 0)
    f1 = mav.build_signed(mav.SETUP_SIGNING, pl, leaked, seq=0, timestamp=10)  # signed by the leaked key
    f2 = mav.build_signed(0, mav.heartbeat(), leaked, seq=1, timestamp=20)
    (tmp_path / "mission.tlog").write_bytes(_tlog([(1, f1), (2, f2)]))
    res = mav.solve(tmp_path)
    assert isinstance(res, SolverResult) and res.status == "unsure"
    assert any(leaked.hex() in e.detail and "verified" in e.detail for e in res.evidence)


def test_solve_flags_provisioning_shape_when_no_inband_key(tmp_path):
    f1 = mav.build_signed(0, mav.heartbeat(), KEY, seq=0, timestamp=10)
    (tmp_path / "capture.tlog").write_bytes(_tlog([(1, f1)]))
    res = mav.solve(tmp_path)
    assert res.status == "unsure"
    assert "re-sign" in res.notes or "provisioning" in res.notes


def test_solve_none_without_mavlink(tmp_path):
    (tmp_path / "readme.txt").write_text("nothing here")
    res = mav.solve(tmp_path)
    assert res.status == "none" and not res.flags


def test_solve_reports_a_corrupt_capture_as_a_named_skip(tmp_path):
    # A capture-suffixed file that fails to parse must be surfaced with its reason, not dropped
    # silently (no-silent-fallbacks). Here a .pcap with a bad magic raises in parse_capture.
    (tmp_path / "broken.pcap").write_bytes(b"NOTPCAP!" + b"\x00" * 64)
    res = mav.solve(tmp_path)
    assert res.status == "none"
    assert "broken.pcap" in res.notes and "skipped" in res.notes.lower()


def test_solve_marks_verified_leak_as_a_strong_signal(tmp_path):
    leaked = bytes.fromhex("1234" * 16)
    pl = mav.setup_signing_payload(1, 190, leaked, 0)
    f1 = mav.build_signed(mav.SETUP_SIGNING, pl, leaked, seq=0, timestamp=10)
    f2 = mav.build_signed(0, mav.heartbeat(), leaked, seq=1, timestamp=20)
    (tmp_path / "mission.tlog").write_bytes(_tlog([(1, f1), (2, f2)]))
    res = mav.solve(tmp_path)
    assert res.status == "unsure"
    assert "STRONG SIGNAL" in res.notes


def test_solve_does_not_flag_an_unverified_leak_as_a_strong_signal(tmp_path):
    # The leaked key is reported, but the link is signed by a different key: the strong-signal note
    # must be gated on verification, not on the mere presence of a SETUP_SIGNING leak.
    leaked = bytes.fromhex("1234" * 16)
    pl = mav.setup_signing_payload(1, 190, leaked, 0)
    f1 = mav.build_signed(mav.SETUP_SIGNING, pl, KEY, seq=0, timestamp=10)
    f2 = mav.build_signed(0, mav.heartbeat(), KEY, seq=1, timestamp=20)
    assert leaked != KEY
    (tmp_path / "mission.tlog").write_bytes(_tlog([(1, f1), (2, f2)]))
    res = mav.solve(tmp_path)
    assert res.status == "unsure"
    assert any(leaked.hex() in e.detail and "not seen signing frames" in e.detail
               for e in res.evidence)
    assert "STRONG SIGNAL" not in res.notes


def test_solve_reports_a_corrupt_capture_alongside_parseable_frames(tmp_path):
    # When one capture parses and another is corrupt, the corrupt one must still be named in the
    # notes (the frames-present path, not only the no-frames early return).
    leaked = bytes.fromhex("1234" * 16)
    pl = mav.setup_signing_payload(1, 190, leaked, 0)
    f1 = mav.build_signed(mav.SETUP_SIGNING, pl, leaked, seq=0, timestamp=10)
    (tmp_path / "mission.tlog").write_bytes(_tlog([(1, f1)]))
    (tmp_path / "broken.pcap").write_bytes(b"NOTPCAP!" + b"\x00" * 64)
    res = mav.solve(tmp_path)
    assert res.status == "unsure"
    assert "1 MAVLink 2 frames in 1 capture(s)" in res.notes
    assert "broken.pcap" in res.notes and "skipped unparseable capture" in res.notes


# --------------------------------------------------------------------------- CLI
def _run(*argv):
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return cli.run(p.parse_args(list(argv)))


def test_cli_extract_and_verify(tmp_path, capsys):
    leaked = bytes.fromhex("abcd" * 16)
    pl = mav.setup_signing_payload(1, 1, leaked, 0)
    f1 = mav.build_signed(mav.SETUP_SIGNING, pl, leaked, seq=0, timestamp=10)
    cap = tmp_path / "m.tlog"
    cap.write_bytes(_tlog([(1, f1)]))
    assert _run("extract-key", str(cap)) == 0
    assert leaked.hex() in capsys.readouterr().out
    assert _run("verify", str(cap), "--key", leaked.hex()) == 0
    assert "1/1" in capsys.readouterr().out
    assert _run("verify", str(cap), "--key", "00" * 32) == 1


def test_cli_forge_and_resign_roundtrip(capsys):
    prov = hashlib.sha256(b"p").hexdigest()
    newk = hashlib.sha256(b"n").hexdigest()
    assert _run("resign", "--prov-key", prov, "--new-key", newk, "--timestamp", "5") == 0
    hexframe = capsys.readouterr().out.strip()
    f, _ = mav.parse_stream(bytes.fromhex(hexframe))
    assert f[0].msgid == mav.SETUP_SIGNING
    assert mav.verify_signature(f[0], bytes.fromhex(prov))
    assert mav.extract_setup_signing(f)[0].secret_key == bytes.fromhex(newk)


def test_cli_send_recovers_flag(fake_drone, capsys):
    host, port = fake_drone
    newk = hashlib.sha256(b"cli-key").digest()
    resign = mav.resign_setup_signing(_FakeDrone.PROV, newk, timestamp=mav.mav_timestamp() + 1)
    cmd = mav.build_signed(76, mav.command_long(192, params=(0, 0, 0, 0, 47.0, 23.0, 120.0)), newk,
                           timestamp=mav.mav_timestamp() + 2)
    rc = _run("send", host, str(port), "--listen", "0.5", "--frame", resign.hex(),
              "--frame", cmd.hex(), "--recv", "1.0")
    out = capsys.readouterr().out
    assert rc == 0 and "CSCTF{live_reposition_accepted}" in out


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
