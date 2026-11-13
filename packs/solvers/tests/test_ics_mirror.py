"""B-081: Live ICS instance mirror + protocol engines (solvers/toolkits/ics_mirror.py).

Every networked test runs against a fake the test itself starts on 127.0.0.1 (loopback, no external
network), under the suite's loopback scope pin (tests/conftest.py allows 127.0.0.0/8). No challenge
binary is executed: the AVR firmware, the IEC-104 burst and the HTTP bodies are synthetic bytes built
here; `avr-objdump` is a static disassembler, run only in the @needs_tool test and skipped otherwise.

Each behaviour has a test that fails when the behaviour is wrong:
  - endpoint parsing: URL / host:port / "nc host port"; a string with no host:port is a named error.
  - IEC-104 decode: a C_SC_NA_1 single command and a STARTDT U-frame are decoded; commands are singled
    out; a non-bytes input is refused.
  - raw read: recv_raw chunks are concatenated and the byte cap holds.
  - AVR: Intel-HEX is parsed to a flash image; a non-ihex blob is refused; disassembly without
    avr-objdump is a named NeedsTool, with it (needs_tool) returns a disassembly.
  - CBC-MAC: the forge candidate MACs to the expected tag under a local zero-IV CBC-MAC.
  - state-change gate: refused when web_state_changing is false, refused without approval when it is
    true, allowed with both; post_state_change sends nothing when refused.
  - HTTP mirror: a get_only WebClient mirrors documented routes end-to-end over a loopback server; a
    client whose get() raises is recorded, not dropped.
  - orchestrator: run_mirror starts through the capped scheduler, writes a pre-parsed evidence pack,
    and a start over the cap is a named CapReached.
"""
import datetime as _dt
import hashlib
import http.server
import json
import threading

import pytest

import ics_mirror as m
from ctf import event as _event
from ctf import instsched as _sched
from ctf import scope as _scope
from ctf.platform.base import InstanceInfo


# --------------------------------------------------------------------------- helpers / fixtures

def _iec104_i_apdu(asdu: bytes) -> bytes:
    """One IEC-104 I-format APDU carrying `asdu` (tx/rx sequence 0)."""
    return bytes([0x68, len(asdu) + 4, 0x00, 0x00, 0x00, 0x00]) + asdu


def _single_command_asdu(scs_on: int = 1, ioa: int = 3) -> bytes:
    # Type 45 C_SC_NA_1, VSQ=1 object, COT=6 (activation), orig 0, CA=1, IOA (3 bytes), SCO byte.
    return bytes([45, 1, 6, 0, 1, 0, ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF, scs_on & 1])


def _startdt_act() -> bytes:
    # U-format APDU: control octet 0x07 = STARTDT act.
    return bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


def _ihex(records, *, eof=True) -> str:
    lines = []
    for addr, data in records:
        rec = bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, 0x00]) + bytes(data)
        checksum = (-sum(rec)) & 0xFF
        lines.append(":" + (rec + bytes([checksum])).hex().upper())
    if eof:
        lines.append(":00000001FF")
    return "\n".join(lines)


def _toy_cbc_mac(key: bytes, block_size: int = 16):
    """A zero-IV raw CBC-MAC over any block function E (here E = sha256(key||block)[:bs])."""
    def E(block: bytes) -> bytes:
        return hashlib.sha256(key + block).digest()[:block_size]

    def mac(message: bytes) -> bytes:
        assert len(message) % block_size == 0
        state = bytes(block_size)
        for i in range(0, len(message), block_size):
            state = E(bytes(a ^ b for a, b in zip(state, message[i:i + block_size])))
        return state
    return mac


class _FakeController:
    """An InstanceCapability fake: start/status/stop over an in-memory slot map (no network)."""

    def __init__(self, connection_info="http://127.0.0.1:65000/"):
        self.connection_info = connection_info
        self.running = {}

    def start_instance(self, cid):
        info = InstanceInfo(str(cid), "running", self.connection_info)
        self.running[str(cid)] = info
        return info

    def instance_status(self, cid):
        return self.running.get(str(cid), InstanceInfo(str(cid), "stopped", ""))

    def stop_instance(self, cid):
        self.running.pop(str(cid), None)
        return InstanceInfo(str(cid), "stopped", "")


class _FakeSession:
    """A recv_raw-only session fake: hands back preloaded chunks, then empty (peer done)."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.closed = False

    def connect(self):
        return self

    def recv_raw(self):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        self.closed = True


class _LoopbackHTTP:
    """A tiny loopback HTTP server serving a fixed route->bytes map; 404 for anything else."""

    def __init__(self, routes):
        server_routes = routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_GET(self):
                body = server_routes.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------- endpoint parsing

def test_parse_endpoint_url():
    ep = m.parse_endpoint("http://10.13.37.5:8080/console")
    assert ep.host == "10.13.37.5" and ep.port == 8080 and ep.scheme == "http"
    assert ep.base_url == "http://10.13.37.5:8080/"


def test_parse_endpoint_ws_aliases_http():
    assert m.parse_endpoint("wss://h.test:9000/").base_url == "https://h.test:9000/"


def test_parse_endpoint_hostport_and_nc():
    assert m.parse_endpoint("10.13.37.5:2404").addr == ("10.13.37.5", 2404)
    assert m.parse_endpoint("nc 10.13.37.5 2404").addr == ("10.13.37.5", 2404)
    assert m.parse_endpoint("host.test 9999").addr == ("host.test", 9999)


def test_parse_endpoint_no_hostport_is_named_error():
    with pytest.raises(m.MirrorError):
        m.parse_endpoint("provisioning, please wait")
    with pytest.raises(m.MirrorError):
        m.parse_endpoint("")


# --------------------------------------------------------------------------- IEC-104 decode

def test_decode_iec104_single_command():
    raw = _iec104_i_apdu(_single_command_asdu(scs_on=1, ioa=3))
    dec = m.decode_iec104(raw)
    assert dec["apdu_count"] == 1
    assert dec["command_count"] == 1
    cmd = dec["commands"][0]
    assert cmd["type_name"].startswith("C_SC_NA_1")
    io = cmd["information_objects"][0]
    assert io["ioa"] == 3 and io["scs"] == 1 and io["scs_name"] == "ON"


def test_decode_iec104_u_frame_not_a_command():
    dec = m.decode_iec104(_startdt_act())
    assert dec["apdu_count"] == 1
    assert dec["formats"].get("U") == 1
    assert dec["command_count"] == 0


def test_decode_iec104_multiple_apdus_and_byte_count():
    raw = _startdt_act() + _iec104_i_apdu(_single_command_asdu())
    dec = m.decode_iec104(raw)
    assert dec["apdu_count"] == 2
    assert dec["bytes"] == len(raw)
    assert dec["command_count"] == 1


def test_decode_iec104_rejects_non_bytes():
    with pytest.raises(m.MirrorError):
        m.decode_iec104("68 04 07 00")


# --------------------------------------------------------------------------- raw read

def test_read_iec104_stream_concatenates_chunks():
    raw = _iec104_i_apdu(_single_command_asdu())
    session = _FakeSession([raw[:3], raw[3:], b""])
    out = m.read_iec104_stream(session)
    assert out == raw


def test_read_iec104_stream_byte_cap():
    session = _FakeSession([b"A" * 100, b"B" * 100])
    out = m.read_iec104_stream(session, max_bytes=150)
    assert len(out) == 150


# --------------------------------------------------------------------------- AVR

def test_decode_avr_hex_image():
    text = _ihex([(0x0000, [0x0C, 0x94, 0x34, 0x00])])  # a plausible AVR rjmp vector
    out = m.decode_avr_hex(text)
    assert out["format"] == "ihex"
    assert out["image_size"] == 4
    assert bytes.fromhex(out["image_hex"]) == bytes([0x0C, 0x94, 0x34, 0x00])


def test_decode_avr_hex_rejects_non_ihex():
    with pytest.raises(m.MirrorError):
        m.decode_avr_hex("this is not intel hex\nnor is this\n")


def test_disassemble_avr_missing_tool_is_named_failure(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: None)
    with pytest.raises(m.NeedsTool) as e:
        m.disassemble_avr(bytes([0x0C, 0x94, 0x34, 0x00]))
    assert m.AVR_OBJDUMP in str(e.value)


def test_disassemble_avr_empty_image_refused():
    with pytest.raises(m.MirrorError):
        m.disassemble_avr(b"")


@pytest.mark.needs_tool("avr-objdump")
def test_disassemble_avr_with_tool():
    out = m.disassemble_avr(bytes([0x0C, 0x94, 0x34, 0x00, 0x18, 0x95]))  # rjmp + reti
    assert isinstance(out, str) and out.strip()
    assert "binary" in out or "Disassembly" in out or ":" in out


# --------------------------------------------------------------------------- CBC-MAC forge

def test_cbc_mac_forge_candidate_verifies():
    bs = 16
    mac = _toy_cbc_mac(b"device-key-01", bs)
    m1 = b"OPEN-VALVE-1-NOW"              # exactly one 16-byte block
    m2 = b"OPEN-VALVE-1-NOW" b"DISABLE-ALARMS!!"  # two 16-byte blocks
    assert len(m1) == bs and len(m2) == 2 * bs
    t1, t2 = mac(m1), mac(m2)
    out = m.cbc_mac_forge(m1, t1, m2, t2, block_size=bs)
    candidate = bytes.fromhex(out["candidate_hex"])
    assert mac(candidate) == bytes.fromhex(out["expected_tag_hex"]) == t2
    assert candidate != m2  # the forge is a distinct message with the same tag
    assert out["assumptions"]


# --------------------------------------------------------------------------- state-change gate

def _profile_with(web_state_changing: bool):
    return _event.parse({
        "slug": "mirror-test", "name": "mirror test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.mirror.test"},
        "flag": {"prefixes": ["flag"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": web_state_changing,
                  "live_service_scope": ["127.0.0.0/8", "*.test"]},
    }, src="tests/test_ics_mirror.py")


def test_authorize_state_change_refused_when_disabled():
    prof = _profile_with(False)
    with pytest.raises(m.StateChangeRefused):
        m.authorize_state_change("/confirm-target", approved=True, profile=prof)


def test_authorize_state_change_needs_approval():
    prof = _profile_with(True)
    with pytest.raises(m.StateChangeRefused):
        m.authorize_state_change("/submit", approved=False, profile=prof)
    assert m.authorize_state_change("/submit", approved=True, profile=prof) is True


def test_post_state_change_sends_nothing_when_refused():
    prof = _profile_with(False)
    sent = []

    class _Client:
        def post(self, path, data=None):
            sent.append((path, data))
            return "sent"

    with pytest.raises(m.StateChangeRefused):
        m.post_state_change(_Client(), "/submit", {"flag": "x"}, action="/submit",
                            approved=True, profile=prof)
    assert sent == []


# --------------------------------------------------------------------------- HTTP mirror

def test_mirror_http_get_only_end_to_end():
    import web as _web
    bodies = {"/health": b"ok\n", "/firmware.hex": _ihex([(0, [1, 2, 3, 4])]).encode()}
    srv = _LoopbackHTTP(bodies)
    try:
        client = _web.WebClient(srv.base_url, get_only=True)
        res = m.mirror_http(client, [m.DocumentedRoute("/health"), "/firmware.hex", "/missing"])
        by_route = {r.route: r for r in res}
        assert by_route["/health"].status == 200
        assert by_route["/health"].body == b"ok\n"
        assert by_route["/health"].sha256 == hashlib.sha256(b"ok\n").hexdigest()
        assert by_route["/firmware.hex"].body == bodies["/firmware.hex"]
        assert by_route["/missing"].status == 404
    finally:
        srv.stop()


def test_mirror_http_records_client_error():
    class _BadClient:
        def get(self, path):
            raise ConnectionError("boom")

    res = m.mirror_http(_BadClient(), ["/x"])
    assert res[0].error and "ConnectionError" in res[0].error
    assert res[0].status is None


# --------------------------------------------------------------------------- orchestrator

def _ledger(tmp_path):
    return _sched.SlotLedger(tmp_path / "instances" / "slots.json")


def test_run_mirror_starts_capped_and_writes_pack(tmp_path):
    bodies = {"/console": b"<html>ws console</html>"}
    srv = _LoopbackHTTP(bodies)
    try:
        ctrl = _FakeController(connection_info=srv.base_url)
        rep = m.run_mirror(ctrl, "9118", out_dir=tmp_path / "pack", ledger=_ledger(tmp_path),
                           cap=3, routes=[m.DocumentedRoute("/console")])
        assert rep.endpoint.port == srv.port
        assert rep.http[0].status == 200
        index = json.loads((tmp_path / "pack" / "index.json").read_text())
        assert index["challenge_id"] == "9118"
        assert index["http"][0]["status"] == 200
        saved = tmp_path / "pack" / index["http"][0]["saved_as"]
        assert saved.read_bytes() == bodies["/console"]
        # the instance was recorded in the slot ledger (started through the scheduler)
        with _ledger(tmp_path) as led:
            assert "9118" in led.ids
    finally:
        srv.stop()


def test_run_mirror_over_cap_is_named_error(tmp_path):
    ctrl = _FakeController(connection_info="http://127.0.0.1:65000/")
    led = _ledger(tmp_path)
    # Fill the single slot.
    m.start_instance(ctrl, led, "A", cap=1)
    with pytest.raises(_sched.CapReached):
        m.run_mirror(ctrl, "B", out_dir=tmp_path / "pack", ledger=led, cap=1,
                     routes=[m.DocumentedRoute("/x")])


def test_run_mirror_iec104_leg(tmp_path):
    raw = _iec104_i_apdu(_single_command_asdu(scs_on=1))
    ctrl = _FakeController(connection_info="10.13.37.9:2404")

    def factory(host, port):
        assert (host, port) == ("10.13.37.9", 2404)
        return _FakeSession([raw, b""])

    rep = m.run_mirror(ctrl, "rtu-1", out_dir=tmp_path / "pack", ledger=_ledger(tmp_path),
                       cap=3, iec104=True, iec104_session_factory=factory)
    assert rep.iec104["command_count"] == 1
    cap_bin = (tmp_path / "pack" / "iec104" / "capture.bin").read_bytes()
    assert cap_bin == raw
    decoded = json.loads((tmp_path / "pack" / "iec104" / "decoded.json").read_text())
    assert decoded["commands"][0]["type_name"].startswith("C_SC_NA_1")


def test_write_pack_layout(tmp_path):
    pack = m.EvidencePack(
        challenge_id="c1",
        endpoint=m.Endpoint("127.0.0.1", 8080, "http"),
        http=[m.MirroredResource("/a", "http://127.0.0.1:8080/a", 200, "text/plain", 3,
                                 hashlib.sha256(b"abc").hexdigest(), body=b"abc")],
        avr={"image_hex": "0c94", "image_size": 2, "format": "ihex"},
    )
    out = m.write_pack(pack, tmp_path / "pk")
    assert (out / "index.json").is_file()
    assert (out / "http" / "a").read_bytes() == b"abc"
    assert (out / "avr" / "flash.bin").read_bytes() == bytes.fromhex("0c94")
