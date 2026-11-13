#!/usr/bin/env python3
"""B-084: the player-gated live validator probe (solvers/toolkits/rfid_validator_probe.py).

The live upload loop is exercised against a fake card validator started on 127.0.0.1 (the suite pins
a loopback scope profile in tests/conftest.py). No real network, no challenge binary. The fake
validator mirrors the 9131 Ultralight C logic (admin user_type + correct CRC + a fresh UID) but every
card and key here is synthetic and built in-test.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import json
import struct
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import rfid_nfc_depth as rfid          # noqa: E402
import rfid_validator_probe as probe   # noqa: E402
from web import WebClient              # noqa: E402
from ctf import scope as _scope        # noqa: E402

# reuse the synthetic card builders
from test_b084_ultralight_c import (   # noqa: E402
    ADMIN_UID, FACTORY_KEY, SAM_UID, build_plaintext, build_ulc_dump)

FLAG = "CSCTF{synthetic_admin_card_ok}"
ISSUED_UIDS = {SAM_UID.hex()}


def _profile(*, web_state_changing: bool):
    from ctf import event
    return event.parse({
        "slug": "ulc-probe-test", "name": "ulc probe test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.suite-platform.test"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.0/8", "localhost"],
                  "web_state_changing": web_state_changing},
    }, src="tests/test_b084_validator_probe.py")


@contextlib.contextmanager
def pinned(*, web_state_changing: bool):
    """Pin the active event profile (the probe reads only the active profile, never a caller's)."""
    prev = _scope.pinned()
    _scope.pin(_profile(web_state_changing=web_state_changing))
    try:
        yield
    finally:
        if prev is not None:
            _scope.pin(prev)
        else:  # pragma: no cover - the suite always has a pinned profile
            _scope.unpin()


def _extract_file(body: bytes, boundary: bytes) -> bytes:
    """Minimal multipart extraction of the `card` file part (test helper)."""
    sep = b"--" + boundary
    for part in body.split(sep):
        if b'name="card"' in part and b"\r\n\r\n" in part:
            payload = part.split(b"\r\n\r\n", 1)[1]
            return payload[:-2] if payload.endswith(b"\r\n") else payload
    raise AssertionError("no card part in upload")


def _validate(card: bytes) -> dict:
    """The fake server's decision, mirroring the 9131 validator's checks."""
    if len(card) != 192:
        return {"ok": False, "error": "bad_length"}
    try:
        pt = rfid.decrypt_ul_c_data(card, FACTORY_KEY)
    except Exception:
        return {"ok": False, "error": "decrypt_failed"}
    if bytes(card[0x0C:0x0E]) != bytes([0x43, 0x55]):  # OTP "CU" marker, page 3
        return {"ok": False, "error": "expected a Chronos Ultralight C card"}
    uid7 = bytes(card[0:3] + card[4:8])
    tag = struct.unpack(">I", pt[48:52])[0]
    if zlib.crc32(uid7 + bytes(pt[40:48]) + bytes([pt[17]])) & 0xFFFFFFFF != tag:
        return {"ok": False,
                "error": "checksum_error: CRC-32 over UID (7 bytes), timestamp (8, big-endian), user_type"}
    if pt[17] != 0x03:
        return {"ok": False, "error": "invalid_cardtype: an administrator card is required"}
    if uid7.hex() in ISSUED_UIDS:
        return {"ok": False, "error": "invalid_user: UID belongs to an issued user card"}
    return {"ok": True, "message": "Administrator card accepted. Access granted.", "flag": FLAG}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if self.path != "/api/validate" or "boundary=" not in ctype:
            self.send_response(404)
            self.end_headers()
            return
        boundary = ctype.split("boundary=", 1)[1].strip().encode()
        try:
            card = _extract_file(body, boundary)
            result = _validate(card)
        except AssertionError:
            result = {"ok": False, "error": "no_card"}
        payload = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _forge_admin(base_card: bytes) -> bytes:
    crc_spec = {"message": [("uid",), ("plain", 40, 48), ("plain", 17, 18)],
                "at": 48, "params": rfid._ecc().CRCParameters(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True),
                "endian": "big"}
    return rfid.forge_ul_c_card(base_card, FACTORY_KEY, uid=ADMIN_UID, crc=crc_spec,
                                data_edits=[(17, b"\x03"), (20, bytes(24)), (20, b"Admin")])["dump"]


@pytest.fixture
def sam_card():
    pt = build_plaintext(user_type=0x01, name=b"Sam", ts=0x63BF4D80, uid7=SAM_UID)
    return build_ulc_dump(uid7=SAM_UID, plaintext=pt)


# ---- the gates ----------------------------------------------------------------------------------

class _RecordingHandler(BaseHTTPRequestHandler):
    """Loopback stub transport: records each POST and answers with the next scripted reply."""

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.sent.append((self.path, body))
        payload = self.server.replies.pop(0) if self.server.replies else b'{"ok": false, "error": "no"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


_RECORDERS: list = []


def _RecordingClient(replies=None):
    """An unmodified (scope-locked) WebClient aimed at a loopback recording server. ``client.sent``
    is the server's record of what actually arrived on the wire."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    srv.sent, srv.replies = [], list(replies or [])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _RECORDERS.append(srv)
    host, port = srv.server_address
    client = WebClient(f"http://{host}:{port}/")
    client.sent = srv.sent
    return client


@pytest.fixture(autouse=True)
def _stop_recorders():
    yield
    while _RECORDERS:
        srv = _RECORDERS.pop()
        srv.shutdown()
        srv.server_close()


def test_refuses_when_active_profile_not_state_changing(sam_card):
    with pinned(web_state_changing=False):
        client = _RecordingClient()
        with pytest.raises(probe.ProbeRefused, match="web_state_changing=false"):
            probe.probe_validator(client, "/api/validate", [sam_card], approved=True)
        assert client.sent == []


def test_caller_cannot_supply_its_own_profile(sam_card):
    # The old `profile=` escape hatch is gone: a caller-built permissive profile is not accepted.
    with pinned(web_state_changing=False):
        with pytest.raises(TypeError):
            probe.probe_validator(_RecordingClient(), "/api/validate", [sam_card], approved=True,
                                  profile=_profile(web_state_changing=True))


def test_suite_default_profile_refuses(sam_card):
    # The suite's pinned scope profile does not set web_state_changing: refused by default.
    client = _RecordingClient()
    with pytest.raises(probe.ProbeRefused, match="web_state_changing=false"):
        probe.probe_validator(client, "/api/validate", [sam_card], approved=True)
    assert client.sent == []


def test_refuses_with_no_event_profile_loaded(sam_card, monkeypatch):
    def _no_event():
        raise probe._event.EventError("no event profile found under events/")
    monkeypatch.setattr(probe._scope, "pinned", lambda: None)
    monkeypatch.setattr(probe._event, "current", _no_event)
    with pytest.raises(probe.ProbeRefused, match="no event profile loaded"):
        probe.probe_validator(object(), "/api/validate", [sam_card], approved=True)


def test_refuses_without_player_approval(sam_card):
    with pinned(web_state_changing=True):
        client = _RecordingClient()
        with pytest.raises(probe.ProbeRefused, match="approval"):
            probe.probe_validator(client, "/api/validate", [sam_card], approved=False)
        assert client.sent == []


def test_refuses_a_client_that_is_not_a_webclient(sam_card):
    class _DuckClient:
        def __init__(self):
            self.sent = []

        def post(self, path, data=None, headers=None):
            self.sent.append(path)
            return {"status": 200, "body": b'{"ok": true}'}

    with pinned(web_state_changing=True):
        duck = _DuckClient()
        with pytest.raises(probe.ProbeRefused, match="WebClient"):
            probe.probe_validator(duck, "/api/validate", [sam_card], approved=True)
        assert duck.sent == []
        with pytest.raises(probe.ProbeRefused, match="WebClient"):
            probe.probe_validator(object(), "/api/validate", [sam_card], approved=True)


@pytest.mark.parametrize("method", ["post", "request", "_resolve_url", "_in_scope", "_check_private"])
def test_refuses_a_webclient_subclass_that_overrides_the_transport(sam_card, method):
    # A subclass passes isinstance but could send the card anywhere: it is refused before any upload.
    elsewhere = []

    def hijack(self, *a, **kw):
        elsewhere.append(method)
        return {"status": 200, "body": b'{"ok": true}'}

    rogue_cls = type("_Rogue", (WebClient,), {method: hijack})
    with pinned(web_state_changing=True):
        recorder = _RecordingClient()
        rogue = rogue_cls(recorder.base)
        with pytest.raises(probe.ProbeRefused, match=f"overrides WebClient.{method}"):
            probe.probe_validator(rogue, "/api/validate", [sam_card], approved=True, min_interval=0.0)
    assert elsewhere == [] and recorder.sent == []


def test_refuses_a_webclient_whose_post_is_replaced_on_the_instance(sam_card):
    with pinned(web_state_changing=True):
        client = _RecordingClient()
        client.post = lambda path, data=None, **kw: {"status": 200, "body": b'{"ok": true}'}
        with pytest.raises(probe.ProbeRefused, match="overrides WebClient.post"):
            probe.probe_validator(client, "/api/validate", [sam_card], approved=True, min_interval=0.0)
    assert client.sent == []


def test_accepts_a_webclient_subclass_that_keeps_the_transport(sam_card):
    # A subclass that only adds behaviour off the upload path is still the scope-locked transport.
    class _Annotated(WebClient):
        def discover(self, wordlist=None):  # not on the upload path
            return []

    with pinned(web_state_changing=True):
        recorder = _RecordingClient([b'{"ok": true, "flag": "CSCTF{x}"}'])
        client = _Annotated(recorder.base)
        results = probe.probe_validator(client, "/api/validate", [sam_card], approved=True,
                                        min_interval=0.0)
    assert results[0]["accepted"] is True
    assert [path for path, _ in recorder.sent] == ["/api/validate"]


def test_upload_cap_boundary(sam_card):
    with pinned(web_state_changing=True):
        over = _RecordingClient()
        with pytest.raises(probe.ProbeRefused, match="max_uploads"):
            probe.probe_validator(over, "/api/validate", [sam_card] * 4, approved=True,
                                  max_uploads=3, min_interval=0.0)
        assert over.sent == []
        at_cap = _RecordingClient()
        results = probe.probe_validator(at_cap, "/api/validate", [sam_card] * 3, approved=True,
                                        max_uploads=3, min_interval=0.0, stop_on_accept=False)
        assert len(results) == 3 and len(at_cap.sent) == 3


def test_stop_on_accept(sam_card):
    accept, reject = b'{"ok": true, "flag": "CSCTF{x}"}', b'{"ok": false, "error": "no"}'
    with pinned(web_state_changing=True):
        first = _RecordingClient([accept, reject])
        results = probe.probe_validator(first, "/api/validate", [sam_card, sam_card],
                                        approved=True, min_interval=0.0)
        assert len(results) == 1 and results[0]["accepted"] is True and len(first.sent) == 1
        both = _RecordingClient([accept, reject])
        results = probe.probe_validator(both, "/api/validate", [sam_card, sam_card],
                                        approved=True, min_interval=0.0, stop_on_accept=False)
        assert [r["accepted"] for r in results] == [True, False] and len(both.sent) == 2


# ---- pacing (injected clock/sleep, no real waits) -----------------------------------------------

def test_paces_uploads_without_wall_clock(sam_card):
    # clock(): first upload stamped at 0.0; before the second, 2.0 s have elapsed of a 5.0 s interval
    # => exactly the remaining 3.0 s is slept (not the whole interval).
    recorded, ticks = [], iter([0.0, 2.0, 5.0])
    with pinned(web_state_changing=True):
        probe.probe_validator(
            _RecordingClient(), "/api/validate", [sam_card, sam_card], approved=True,
            min_interval=5.0, stop_on_accept=False, clock=lambda: next(ticks), sleep=recorded.append)
    assert recorded == [3.0]


def test_no_sleep_when_interval_already_elapsed(sam_card):
    recorded, ticks = [], iter([0.0, 7.0, 7.0])
    with pinned(web_state_changing=True):
        probe.probe_validator(
            _RecordingClient(), "/api/validate", [sam_card, sam_card], approved=True,
            min_interval=5.0, stop_on_accept=False, clock=lambda: next(ticks), sleep=recorded.append)
    assert recorded == []


# ---- live loopback probe ------------------------------------------------------------------------

def test_probe_accepts_forged_admin_card(sam_card):
    srv = _server()
    try:
        host, port = srv.server_address
        with pinned(web_state_changing=True):
            client = WebClient(f"http://{host}:{port}/")
            admin = _forge_admin(sam_card)
            results = probe.probe_validator(client, "/api/validate", [admin], approved=True,
                                            min_interval=0.0)
        assert results[-1]["accepted"] is True
        assert results[-1]["flag"] == FLAG
    finally:
        srv.shutdown()


def test_probe_reports_validator_rejection(sam_card):
    srv = _server()
    try:
        host, port = srv.server_address
        with pinned(web_state_changing=True):
            client = WebClient(f"http://{host}:{port}/")
            # the untouched Sam card is a valid user card, not an admin card
            results = probe.probe_validator(client, "/api/validate", [sam_card], approved=True,
                                            min_interval=0.0)
        assert results[-1]["accepted"] is False
        assert "administrator card is required" in results[-1]["error"]
    finally:
        srv.shutdown()


def test_probe_stops_after_live_accept(sam_card):
    # Against the loopback validator: [admin, sam] stops after the accepted admin card.
    srv = _server()
    try:
        host, port = srv.server_address
        with pinned(web_state_changing=True):
            client = WebClient(f"http://{host}:{port}/")
            admin = _forge_admin(sam_card)
            stopped = probe.probe_validator(client, "/api/validate", [admin, sam_card],
                                            approved=True, min_interval=0.0)
            full = probe.probe_validator(client, "/api/validate", [admin, sam_card],
                                         approved=True, min_interval=0.0, stop_on_accept=False)
        assert [r["accepted"] for r in stopped] == [True]
        assert [r["accepted"] for r in full] == [True, False]
    finally:
        srv.shutdown()
