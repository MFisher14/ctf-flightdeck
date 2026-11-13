"""Minecraft protocol framing and the status ping (B-120), against a fake server on 127.0.0.1 only."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import socket
import socketserver
import threading
import time

import pytest

import minecraft_netplay as mn
from ctf import env, event, scope
from ctf.engines import router
from ctf.result import SolverResult

# How long a test waits for the fake server's handler thread to finish, and the deadline every ping
# in this file is given (the largest solve() accepts).  It is a wait, not a speed assertion: it only
# bounds a hang, and holds at any machine load.  The production default (10 s) is never relied on.
HANDLER_WAIT_S = 120


def _profile(scope_list, prefixes=("CSCTF",), platform="https://board.ctf.example"):
    return event.parse({
        "slug": "mc-test", "name": "mc",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": platform},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_list)},
    }, src="<test>")


class StepClock:
    """A clock that advances one second per reading: a deadline without real time."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        value, self.now = self.now, self.now + 1.0
        return value


# --------------------------------------------------------------------------- VarInt and String
# The protocol documentation's sample values.
VARINTS = [(0, "00"), (1, "01"), (2, "02"), (127, "7f"), (128, "8001"), (255, "ff01"), (25565, "ddc701"),
           (2097151, "ffff7f"), (2147483647, "ffffffff07"), (-1, "ffffffff0f"), (-2147483648, "8080808008")]


@pytest.mark.parametrize("value,encoded", VARINTS, ids=[str(v) for v, _ in VARINTS])
def test_varint_vectors(value, encoded):
    assert mn.encode_varint(value).hex() == encoded
    assert mn.decode_varint(bytes.fromhex(encoded)) == (value, len(encoded) // 2)
    assert mn.decode_varint(b"\xaa" + bytes.fromhex(encoded) + b"\xbb", 1) == (value, 1 + len(encoded) // 2)


def test_varint_rejects_what_the_protocol_does():
    for bad in (2 ** 31, -2 ** 31 - 1, True, 1.5, "1"):
        with pytest.raises(mn.MinecraftNetplayError):
            mn.encode_varint(bad)
    with pytest.raises(mn.MinecraftNetplayError, match="truncated"):
        mn.decode_varint(b"\x80\x80")
    with pytest.raises(mn.MinecraftNetplayError, match="exceeds 5 bytes"):
        mn.decode_varint(b"\x80\x80\x80\x80\x80\x01")
    with pytest.raises(mn.MinecraftNetplayError, match="32 bits"):
        mn.decode_varint(b"\xff\xff\xff\xff\x7f")            # the fifth byte carries more than four bits
    with pytest.raises(mn.MinecraftNetplayError, match="bytes-like"):
        mn.decode_varint("00")


def test_string_codec():
    encoded = mn.encode_string("héllo")
    assert encoded == b"\x06h\xc3\xa9llo"
    assert mn.decode_string(encoded) == ("héllo", 7)
    assert mn.decode_string(b"\x00\x02ok\xff", 1) == ("ok", 4)
    with pytest.raises(mn.MinecraftNetplayError, match="truncated protocol String"):
        mn.decode_string(b"\x05abc")
    with pytest.raises(mn.MinecraftNetplayError, match="negative"):
        mn.decode_string(mn.encode_varint(-1))
    with pytest.raises(mn.MinecraftNetplayError, match="UTF-8"):
        mn.decode_string(b"\x02\xff\xfe")
    with pytest.raises(mn.MinecraftNetplayError, match="exceeds the cap"):
        mn.decode_string(mn.encode_varint(mn.MAX_STRING_BYTES + 1))
    with pytest.raises(mn.MinecraftNetplayError, match="must be str"):
        mn.encode_string(b"bytes")


# --------------------------------------------------------------------------- packets
def test_handshake_bytes_and_round_trip():
    packet = mn.build_handshake("localhost", 25565)
    # length 19, id 0, protocol -1, "localhost", port 25565 big-endian, next state 1 (status)
    assert packet.hex() == "1300" + "ffffffff0f" + "09" + b"localhost".hex() + "63dd" + "01"
    (body,), rest = mn.split_frames(packet)
    assert rest == b""
    assert mn.parse_handshake(body) == {"protocol_version": -1, "server_address": "localhost",
                                        "server_port": 25565, "next_state": 1}
    login = mn.parse_handshake(mn.split_frames(mn.build_handshake("mc.example", 1, protocol_version=765,
                                                                  next_state=mn.NEXT_STATE_LOGIN))[0][0])
    assert login == {"protocol_version": 765, "server_address": "mc.example", "server_port": 1, "next_state": 2}


def test_handshake_rejects_bad_fields():
    for port in (-1, 65536, True, "25565"):
        with pytest.raises(mn.MinecraftNetplayError, match="port"):
            mn.build_handshake("h", port)
    with pytest.raises(mn.MinecraftNetplayError, match="next_state"):
        mn.build_handshake("h", 1, next_state=0)
    with pytest.raises(mn.MinecraftNetplayError, match="server address"):
        mn.build_handshake("h" * 256, 1)
    body = mn.split_frames(mn.build_handshake("h", 1))[0][0]
    with pytest.raises(mn.MinecraftNetplayError, match="trailing bytes"):
        mn.parse_handshake(body + b"\x00")
    with pytest.raises(mn.MinecraftNetplayError, match="truncated handshake port"):
        mn.parse_handshake(body[:-2])
    with pytest.raises(mn.MinecraftNetplayError, match="packet id 0x00"):
        mn.parse_handshake(b"\x01" + body[1:])


def test_frames_and_stream_splitting():
    assert mn.build_status_request() == b"\x01\x00"
    assert mn.frame_packet(0x01, b"\xaa\xbb") == b"\x03\x01\xaa\xbb"
    assert mn.parse_packet(b"\x7fpayload") == (0x7F, b"payload")
    stream = mn.frame_packet(0, b"one") + mn.frame_packet(1, b"two!") + mn.frame_packet(2, b"x" * 300)
    bodies, rest = mn.split_frames(stream)
    assert bodies == [b"\x00one", b"\x01two!", b"\x02" + b"x" * 300] and rest == b""
    bodies, rest = mn.split_frames(stream[:-10])                 # the last frame has not fully arrived
    assert bodies == [b"\x00one", b"\x01two!"] and rest == stream[11:-10]
    assert mn.split_frames(stream[:12]) == ([b"\x00one", b"\x01two!"], b"\xad")   # half a length prefix
    with pytest.raises(mn.MinecraftNetplayError, match="exceeds the cap"):
        mn.split_frames(mn.encode_varint(mn.MAX_PACKET_BYTES + 1) + b"x")
    with pytest.raises(mn.MinecraftNetplayError, match="exceeds 5 bytes"):
        mn.split_frames(b"\x80\x80\x80\x80\x80\x01")
    with pytest.raises(mn.MinecraftNetplayError, match="exceeds the length cap"):
        mn.frame_packet(0, b"x" * (mn.MAX_PACKET_BYTES + 1))


def _status_body(status) -> bytes:
    text = status if isinstance(status, str) else json.dumps(status)
    return b"\x00" + mn.encode_string(text)


def test_status_response_parsing():
    assert mn.parse_status_response(_status_body({"description": "hi"})) == {"description": "hi"}
    with pytest.raises(mn.MinecraftNetplayError, match="packet id 0x00"):
        mn.parse_status_response(b"\x01" + mn.encode_string("{}"))
    with pytest.raises(mn.MinecraftNetplayError, match="trailing bytes"):
        mn.parse_status_response(_status_body({}) + b"\x00")
    with pytest.raises(mn.MinecraftNetplayError, match="not valid JSON"):
        mn.parse_status_response(_status_body("{nope"))
    with pytest.raises(mn.MinecraftNetplayError, match="not an object"):
        mn.parse_status_response(_status_body("[1, 2]"))


# --------------------------------------------------------------------------- what a status carries
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(40))
STATUS = {
    "version": {"name": "Paper 1.20.4 §cCSCTF{in_version_name}", "protocol": 765},
    "players": {"max": 20, "online": 3, "sample": [{"name": "CSCTF{pl", "id": "1"}, {"name": "ayer_", "id": "2"},
                                                   {"name": "list}", "id": "3"}]},
    "description": {"text": "§6Welcome ", "extra": [{"text": "CSCTF{mo"}, {"text": "§ltd_split}"}]},
    "forgeData": {"mods": [{"modId": "CSCTF{mod_id}", "modmarker": "1.0"}]},
    "favicon": "data:image/png;base64," + base64.b64encode(PNG).decode(),
    "note": "CSCTF{elsewhere_in_json}",
}


def test_status_surfaces_are_read_as_the_client_shows_them():
    surfaces = mn.status_surfaces(STATUS)
    by_name = {}
    for name, text in surfaces:
        by_name.setdefault(name, []).append(text)
    assert by_name["motd"] == ["Welcome CSCTF{motd_split}"]         # component flattened, codes removed
    assert by_name["version"] == ["Paper 1.20.4 CSCTF{in_version_name}"]
    assert by_name["player"] == ["CSCTF{pl", "ayer_", "list}"]
    assert by_name["players-joined"] == ["CSCTF{player_list}"]
    assert by_name["mod"] == ["CSCTF{mod_id} 1.0"]
    # every other string value, one at a time: never the icon, never text already shown above
    assert by_name["field"] == ["Paper 1.20.4 §cCSCTF{in_version_name}", "1", "2", "3", "§6Welcome ",
                                "CSCTF{mo", "§ltd_split}", "CSCTF{mod_id}", "1.0", "CSCTF{elsewhere_in_json}"]
    assert mn.status_surfaces({"description": "plain §amotd"})[0] == ("motd", "plain motd")


def test_status_flags_name_their_surface_and_follow_the_profile():
    found = {row["flag"]: row["surface"] for row in mn.harvest_status_flags(STATUS, _profile([]))}
    assert found == {"CSCTF{motd_split}": "motd", "CSCTF{in_version_name}": "version",
                     "CSCTF{player_list}": "players-joined", "CSCTF{mod_id}": "mod",
                     "CSCTF{elsewhere_in_json}": "field"}
    pink = {"description": "PINK{pink_motd} and CSCTF{not_this_event}"}
    assert mn.harvest_status_flags(pink, _profile([], prefixes=("PINK",))) == [
        {"flag": "PINK{pink_motd}", "surface": "motd"}]


def test_two_sampled_player_names_are_joined_too():
    status = {"players": {"sample": [{"name": "CSCTF{tw"}, {"name": "o_names}"}]}}
    assert ("players-joined", "CSCTF{two_names}") in mn.status_surfaces(status)
    assert mn.harvest_status_flags(status, _profile([])) == [
        {"flag": "CSCTF{two_names}", "surface": "players-joined"}]
    one = {"players": {"sample": [{"name": "solo"}]}}
    assert [name for name, _text in mn.status_surfaces(one)] == ["player"]     # nothing to join


MANY_FLAGS = {"description": "CSCTF{one}", "version": {"name": "CSCTF{two}"}, "note": "CSCTF{three}",
              "other": "CSCTF{four}", "again": "CSCTF{four}"}


def test_flags_past_the_cap_are_counted_not_lost_silently(monkeypatch):
    assert len(mn.harvest_status_flags(MANY_FLAGS, _profile([]))) == 4
    monkeypatch.setattr(mn, "MAX_FLAGS", 2)
    assert mn.harvest_status_flags(MANY_FLAGS, _profile([])) == [
        {"flag": "CSCTF{one}", "surface": "motd"}, {"flag": "CSCTF{two}", "surface": "version"}]
    assert mn._harvest(MANY_FLAGS, _profile([]))[1] == 2          # two distinct flags, one of them twice


def test_favicon_is_decoded_or_named_broken():
    assert mn.favicon_bytes(STATUS) == PNG
    assert mn.favicon_bytes({"description": "x"}) is None and mn.favicon_bytes({"favicon": "nope"}) is None
    with pytest.raises(mn.MinecraftNetplayError, match="base64"):
        mn.favicon_bytes({"favicon": "data:image/png;base64,@@@@"})
    # line breaks (LF or CRLF, in the middle or at the end) and blanks are not base64 data
    encoded = base64.b64encode(PNG).decode()
    for wrapped in (encoded + "\r\n", encoded + "\n", encoded[:20] + "\r\n" + encoded[20:],
                    encoded[:8] + " " + encoded[8:] + "\t"):
        assert mn.favicon_bytes({"favicon": "data:image/png;base64," + wrapped}) == PNG, repr(wrapped)
        assert mn.read_favicon({"favicon": "data:image/png;base64," + wrapped}) == (PNG, None)
    # the form that never raises: the icon, or the reason there is none
    assert mn.read_favicon(STATUS) == (PNG, None)
    assert mn.read_favicon({"description": "x"}) == (None, None)
    assert mn.read_favicon({"favicon": BROKEN_ICONS["no-padding"]}) == (None, "favicon is not valid base64")


BROKEN_ICONS = {
    "no-padding": "data:image/png;base64," + base64.b64encode(PNG + b"x").decode().rstrip("="),
    "not-base64": "data:image/png;base64,@@@@",
}


@pytest.mark.parametrize("icon", sorted(BROKEN_ICONS), ids=sorted(BROKEN_ICONS))
def test_a_broken_favicon_does_not_cost_the_status(fake_server, tmp_path, capsys, icon):
    assert base64.b64encode(PNG + b"x").decode().endswith("=")        # so the stripped form is short
    status = {"description": "CSCTF{in_the_motd}", "version": {"name": "1.20.4"},
              "favicon": BROKEN_ICONS[icon]}
    host, port = fake_server(_reply(status)).server_address
    report = mn.status_ping(host, port, timeout=HANDLER_WAIT_S)
    assert report["flags"] == [{"flag": "CSCTF{in_the_motd}", "surface": "motd"}]
    assert report["favicon"] is None and report["favicon_png"] is None
    assert report["favicon_error"] == "favicon is not valid base64"
    assert report["status"] == {"description": "CSCTF{in_the_motd}", "version": {"name": "1.20.4"}}
    assert {"surface": "motd", "text": "CSCTF{in_the_motd}"} in report["surfaces"]

    out = tmp_path / "icon.png"
    result = mn.solve(tmp_path, host=host, port=fake_server(_reply(status)).server_address[1],
                      timeout=HANDLER_WAIT_S, favicon_out=str(out))
    assert result.status == "solved" and result.flags == ("CSCTF{in_the_motd}",)
    assert "the server icon was not decoded (favicon is not valid base64)" in result.notes
    assert "did not answer" not in result.notes and not out.exists()        # nothing to write

    assert mn.main([host, str(fake_server(_reply(status)).server_address[1]), "--compact",
                    "--timeout", str(HANDLER_WAIT_S)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["favicon_error"] == "favicon is not valid base64"
    assert [row["flag"] for row in printed["flags"]] == ["CSCTF{in_the_motd}"]


def test_a_good_favicon_reports_no_error_and_a_wrapped_one_is_decoded(fake_server, tmp_path):
    wrapped = dict(STATUS, favicon=STATUS["favicon"] + "\r\n")
    host, port = fake_server(_reply(wrapped)).server_address
    report = mn.status_ping(host, port, timeout=HANDLER_WAIT_S)
    assert report["favicon_png"] == PNG and report["favicon_error"] is None
    assert "favicon-text" not in {row["surface"] for row in report["surfaces"]}
    result = mn.solve(tmp_path, host=host, port=fake_server(_reply(wrapped)).server_address[1],
                      timeout=HANDLER_WAIT_S)
    assert "was not decoded" not in result.notes and f"favicon: {len(PNG)} bytes" in result.notes


def test_an_icon_field_that_is_not_an_icon_is_searched_as_text():
    # an icon is never text; a field that only claims to be one is
    assert "favicon-text" not in {name for name, _text in mn.status_surfaces(STATUS)}
    plain = {"description": "x", "favicon": "CSCTF{in_the_icon_field}"}
    assert ("favicon-text", "CSCTF{in_the_icon_field}") in mn.status_surfaces(plain)
    assert mn.harvest_status_flags(plain, _profile([])) == [
        {"flag": "CSCTF{in_the_icon_field}", "surface": "favicon-text"}]
    late = "data:image/png;base64,@" + "A" * 9000 + " CSCTF{far_into_a_broken_icon}"
    assert mn.harvest_status_flags({"favicon": late}, _profile([])) == [
        {"flag": "CSCTF{far_into_a_broken_icon}", "surface": "favicon-text"}]       # the whole text
    assert mn.status_surfaces({"favicon": ""}) == [] and mn.status_surfaces({"favicon": 7}) == []


# --------------------------------------------------------------------------- scope guard
def test_guard_allows_in_scope_hosts_only_and_returns_the_normalised_host():
    prof = _profile(["*.mc.ctf.example"])
    assert mn.guard_target("play.mc.ctf.example", 25565, prof) == "play.mc.ctf.example"
    assert mn.guard_target("PLAY.mc.ctf.example.", 25565, prof) == "play.mc.ctf.example"
    with pytest.raises(scope.OutOfScope, match="outside event"):
        mn.guard_target("hypixel.example", 25565, prof)
    with pytest.raises(scope.OutOfScope, match="event platform"):
        mn.guard_target("board.ctf.example", 443, _profile(["*.ctf.example"]))
    with pytest.raises(scope.OutOfScope, match="empty rules.live_service_scope"):
        mn.guard_target("play.mc.ctf.example", 25565, _profile([]))
    for host, port in (("", 1), ("  ", 1), ("h", -1), ("h", 70000), ("h", True)):
        with pytest.raises(mn.MinecraftNetplayError):
            mn.guard_target(host, port, prof)


def test_loopback_gets_no_exemption_from_the_scope_rules():
    # the suite's pinned profile lists loopback, which is why the fake-server tests below may connect
    assert mn.guard_target("127.0.0.1", 25565, None) == "127.0.0.1"
    assert mn.guard_target("LOCALHOST", 25565, None) == "localhost"
    for host in ("127.0.0.1", "::1", "localhost", "ip6-localhost"):
        with pytest.raises(scope.OutOfScope, match="empty rules.live_service_scope"):
            mn.guard_target(host, 25565, _profile([]))
        with pytest.raises(scope.OutOfScope, match="outside event"):
            mn.guard_target(host, 25565, _profile(["*.mc.ctf.example"]))
    # a platform on a loopback port is never a target, even when loopback is in scope
    local_platform = _profile(["127.0.0.1"], platform="http://127.0.0.1:8000")
    with pytest.raises(scope.OutOfScope, match="event platform"):
        mn.guard_target("127.0.0.1", 8000, local_platform)
    assert mn.guard_target("127.0.0.1", 25565, local_platform) == "127.0.0.1"


def test_guard_fails_closed_when_no_event_resolves(monkeypatch):
    before = scope.pinned()                 # the suite's profile (tests/conftest.py): put back below
    assert before is not None
    scope.unpin()
    try:
        monkeypatch.delenv("CTF_EVENT", raising=False)
        for legacy in env.legacy_names("CTF_EVENT"):
            monkeypatch.delenv(legacy, raising=False)
        for host in ("play.mc.ctf.example", "127.0.0.1", "localhost"):
            with pytest.raises(scope.OutOfScope, match="event profile did not load"):
                mn.guard_target(host, 25565, None)
    finally:
        scope.pin(before)
    assert scope.pinned() is before


def test_this_file_leaves_the_suite_scope_pin_in_place():
    """Runs after the test above (file order): a later test in the same process still has the pin."""
    assert scope.pinned() is not None and scope.pinned().slug == "test-suite"
    assert scope.check_host("127.0.0.1", 8080) == "127.0.0.1"


# --------------------------------------------------------------------------- the fake server
class _FakeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, reply, hang_up=False, drip_s=0.0):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.reply = reply                 # bytes to send once the status request is in
        self.hang_up = hang_up             # close right after the reply (a short reply then ends in EOF)
        self.drip_s = drip_s               # > 0: send the reply one byte at a time, this far apart
        self.packets: list[bytes] = []     # every packet body the client sent
        self.extra = b""                   # anything sent after the status request
        self.done = threading.Event()


class _Handler(socketserver.BaseRequestHandler):
    """Reads frames with its own VarInt reader (not the module's), answers the status request once."""

    def _varint(self):
        value = shift = 0
        while True:
            byte = self.request.recv(1)
            if not byte:
                return None
            value |= (byte[0] & 0x7F) << shift
            shift += 7
            if not byte[0] & 0x80:
                return value

    def _frame(self):
        length = self._varint()
        if length is None:
            return None
        body = b""
        while len(body) < length:
            chunk = self.request.recv(length - len(body))
            if not chunk:
                return None
            body += chunk
        return body

    def handle(self):
        server: _FakeServer = self.server  # type: ignore[assignment]
        try:
            self.request.settimeout(HANDLER_WAIT_S)
            for _ in range(2):             # handshake, then status request
                body = self._frame()
                if body is None:
                    return
                server.packets.append(body)
            if server.drip_s:
                for index in range(len(server.reply)):     # ends with an OSError once the client is gone
                    self.request.sendall(server.reply[index:index + 1])
                    time.sleep(server.drip_s)
            else:
                self.request.sendall(server.reply)
            if server.hang_up:
                return
            while True:                    # until the client hangs up: a login packet would land here
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                server.extra += chunk
        except OSError:
            pass
        finally:
            server.done.set()


@pytest.fixture
def fake_server():
    servers = []

    def start(reply, hang_up=False, drip_s=0.0) -> _FakeServer:
        server = _FakeServer(reply, hang_up, drip_s)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _reply(status) -> bytes:
    body = _status_body(status)
    return mn.encode_varint(len(body)) + body


def test_status_ping_sends_a_handshake_and_a_status_request_and_nothing_else(fake_server):
    server = fake_server(_reply(STATUS))
    host, port = server.server_address
    report = mn.status_ping(host, port, profile=_profile(["127.0.0.1"]), timeout=HANDLER_WAIT_S)
    assert server.done.wait(HANDLER_WAIT_S)
    handshake, request = server.packets
    # decoded by hand, not by the module: id 0, VarInt -1, the address, the port, next state 1 = status
    assert handshake == (b"\x00" + bytes.fromhex("ffffffff0f") + bytes([len(host)]) + host.encode()
                         + port.to_bytes(2, "big") + b"\x01")
    assert request == b"\x00"
    assert server.extra == b""                                  # no login start, no ping, no chat
    assert report["logged_in"] is False and report["host"] == host and report["port"] == port
    assert report["status"]["players"]["online"] == 3 and "favicon" not in report["status"]
    assert report["favicon"] == {"bytes": len(PNG), "sha256": hashlib.sha256(PNG).hexdigest()}
    assert report["favicon_png"] == PNG
    assert {row["flag"] for row in report["flags"]} == {
        "CSCTF{motd_split}", "CSCTF{in_version_name}", "CSCTF{player_list}", "CSCTF{mod_id}",
        "CSCTF{elsewhere_in_json}"}
    assert {"surface": "motd", "text": "Welcome CSCTF{motd_split}"} in report["surfaces"]
    assert report["flags_dropped"] == 0 and report["status_truncated"] is False


def test_status_ping_passes_the_protocol_version_it_is_given(fake_server):
    server = fake_server(_reply({"description": "x"}))
    host, port = server.server_address
    mn.status_ping(host, port, protocol_version=765, timeout=HANDLER_WAIT_S)
    assert server.done.wait(HANDLER_WAIT_S)
    assert server.packets[0][1:3] == bytes.fromhex("fd05")       # VarInt 765


def test_out_of_scope_target_is_refused_before_any_connection(monkeypatch):
    opened = []

    def no_connection(host, port, _deadline):
        opened.append((host, port))
        raise AssertionError("a connection was opened")

    monkeypatch.setattr(mn, "_connect", no_connection)      # the one place the module opens a socket
    prof = _profile(["*.mc.ctf.example"])
    for host in ("hypixel.example", "127.0.0.1", "localhost"):      # loopback is not in this scope either
        with pytest.raises(scope.OutOfScope):
            mn.status_ping(host, 25565, profile=prof, timeout=HANDLER_WAIT_S)
    with pytest.raises(scope.OutOfScope, match="event platform"):
        mn.status_ping("127.0.0.1", 8000, profile=_profile(["127.0.0.1"], platform="http://127.0.0.1:8000"),
                       timeout=HANDLER_WAIT_S)
    assert opened == []
    with pytest.raises(AssertionError, match="a connection was opened"):   # an in-scope host does connect
        mn.status_ping("PLAY.mc.ctf.example.", 25565, profile=prof, timeout=HANDLER_WAIT_S)
    assert opened == [("play.mc.ctf.example", 25565)]             # to the host the scope check returned


# --------------------------------------------------------------------------- one deadline for the exchange
class _DripSocket:
    """A connected socket as the frame reader sees a slow server: one byte per read, never blocking."""

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.timeouts: list[float] = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, _count):
        chunk = bytes(self.data[:1])
        del self.data[:1]
        return chunk


class _StalledSocket(_DripSocket):
    def recv(self, _count):
        raise socket.timeout("timed out")


def test_read_frame_is_bounded_by_one_deadline_not_by_each_read():
    reply = _reply({"description": "x" * 40})
    sock = _DripSocket(reply)
    # the clock reads 0 when the deadline is made, then 1, 2, ... before each read: 5 s allows four
    with pytest.raises(mn.MinecraftNetplayError, match="within the 5 s deadline"):
        mn.read_frame(sock, mn.Deadline(5, StepClock()))
    assert sock.timeouts == [4.0, 3.0, 2.0, 1.0]                  # each read gets only the time left
    assert len(sock.data) == len(reply) - 4                       # and the fifth read is never made
    assert mn.read_frame(_DripSocket(reply), mn.Deadline(len(reply) + 1, StepClock())) == reply[1:]
    assert mn.read_frame(_DripSocket(reply)) == reply[1:]         # no deadline: the caller's timeout
    with pytest.raises(mn.MinecraftNetplayError, match="within the 9 s deadline"):
        mn.read_frame(_StalledSocket(b""), mn.Deadline(9, StepClock()))   # a read that times out
    with pytest.raises(socket.timeout):
        mn.read_frame(_StalledSocket(b""))
    for bad in (0, -1, float("nan"), float("inf"), True, "5"):
        with pytest.raises(mn.MinecraftNetplayError, match="timeout must be a positive number"):
            mn.Deadline(bad)


class _FakeNet:
    """Stands in for the ``socket`` module inside minecraft_netplay: no real socket, no real time.

    ``plan`` maps an address to what connecting to it does (an exception to raise, or None to
    connect).  Every socket made is kept, with the timeouts it was given and the bytes sent on it."""

    SOCK_STREAM = socket.SOCK_STREAM
    timeout = socket.timeout

    def __init__(self, plan, reply=b"", send_fails_at=None):
        self.plan, self.reply, self.send_fails_at = dict(plan), reply, send_fails_at
        self.lookups: list[tuple] = []
        self.sockets: list["_FakeNetSocket"] = []

    def getaddrinfo(self, host, port, **kwargs):
        self.lookups.append((host, port, kwargs))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in self.plan]

    def socket(self, family, kind, proto):
        made = _FakeNetSocket(self, (family, kind, proto))
        self.sockets.append(made)
        return made


class _FakeNetSocket:
    def __init__(self, net, made_with):
        self.net, self.made_with = net, made_with
        self.timeouts: list[float] = []
        self.address = None
        self.sent: list[bytes] = []
        self.closed = False
        self.data = bytearray(net.reply)

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.address = address
        outcome = self.net.plan[address[0]]
        if outcome is not None:
            raise outcome

    def sendall(self, data):
        if self.net.send_fails_at == len(self.sent):
            raise socket.timeout("timed out")
        self.sent.append(bytes(data))

    def recv(self, count):
        chunk = bytes(self.data[:count])
        del self.data[:count]
        return chunk

    def close(self):
        self.closed = True


DEAD = ("192.0.2.1", "192.0.2.2", "192.0.2.3")           # TEST-NET-1: never contacted, the net is fake


def test_connect_resolves_once_and_gives_each_address_only_the_time_left(monkeypatch):
    # three addresses that never answer.  The clock reads 0 when the deadline is made, then 1, 2, 3
    # before each attempt: 3 s allows two attempts (2 s, then 1 s), never a full 3 s for each
    net = _FakeNet({address: socket.timeout("timed out") for address in DEAD})
    monkeypatch.setattr(mn, "socket", net)
    with pytest.raises(socket.timeout):                    # the last connection error, an OSError
        mn._connect("many.mc.ctf.example", 25565, mn.Deadline(3, StepClock()))
    assert net.lookups == [("many.mc.ctf.example", 25565, {"type": socket.SOCK_STREAM})]     # one lookup
    assert [sock.timeouts for sock in net.sockets] == [[2.0], [1.0]]
    assert [sock.address for sock in net.sockets] == [(DEAD[0], 25565), (DEAD[1], 25565)]
    assert all(sock.closed for sock in net.sockets)

    # an address that answers after one that refuses: that socket is returned, the failed one closed
    net = _FakeNet({DEAD[0]: ConnectionRefusedError(61, "Connection refused"), DEAD[1]: None, DEAD[2]: None})
    monkeypatch.setattr(mn, "socket", net)
    sock = mn._connect("two.mc.ctf.example", 25565, mn.Deadline(60, StepClock()))
    assert sock is net.sockets[1] and sock.address == (DEAD[1], 25565) and not sock.closed
    assert sock.made_with == (socket.AF_INET, socket.SOCK_STREAM, 6)
    assert net.sockets[0].closed and len(net.sockets) == 2 and sock.timeouts == [58.0]

    # every address refuses: all are tried, and the error is the connection's own
    net = _FakeNet({address: ConnectionRefusedError(61, "Connection refused") for address in DEAD})
    monkeypatch.setattr(mn, "socket", net)
    with pytest.raises(ConnectionRefusedError):
        mn._connect("none.mc.ctf.example", 25565, mn.Deadline(60, StepClock()))
    assert len(net.sockets) == 3 and all(sock.closed for sock in net.sockets)

    # a deadline that is gone before the first attempt (the lookup took it) is the deadline's error
    net = _FakeNet({DEAD[0]: None})
    monkeypatch.setattr(mn, "socket", net)
    with pytest.raises(mn.MinecraftNetplayError, match="within the 1 s deadline"):
        mn._connect("slow.mc.ctf.example", 25565, mn.Deadline(1, StepClock()))
    assert net.sockets == []


def test_the_deadline_covers_the_connection_and_each_send(monkeypatch, tmp_path):
    prof = _profile(["play.mc.ctf.example"])
    reply = _reply({"description": "CSCTF{over_a_fake_net}"})
    handshake = mn.build_handshake("play.mc.ctf.example", 25565)

    # clock: 0 when the deadline is made, 1 at the connection, 2 before the handshake, 3 before the
    # status request, then one reading per read
    net = _FakeNet({DEAD[0]: None}, reply)
    monkeypatch.setattr(mn, "socket", net)
    report = mn.status_ping("play.mc.ctf.example", profile=prof, timeout=100, clock=StepClock())
    (sock,) = net.sockets
    assert report["flags"] == [{"flag": "CSCTF{over_a_fake_net}", "surface": "motd"}]
    assert sock.sent == [handshake, mn.build_status_request()] and sock.closed
    assert sock.timeouts[:3] == [99.0, 98.0, 97.0]         # the connection, then each send: time left
    assert sock.timeouts[3:] == [96.0, 95.0]               # the length prefix, then the body

    # 3 s: gone by the time the status request is due, so it is never sent
    net = _FakeNet({DEAD[0]: None}, reply)
    monkeypatch.setattr(mn, "socket", net)
    with pytest.raises(mn.MinecraftNetplayError, match="within the 3 s deadline"):
        mn.status_ping("play.mc.ctf.example", profile=prof, timeout=3, clock=StepClock())
    (sock,) = net.sockets
    assert sock.sent == [handshake] and sock.timeouts == [2.0, 1.0] and sock.closed

    # a send that times out (a server that stops reading) is the deadline's error, at either send
    for failing, sent in ((0, []), (1, [handshake])):
        net = _FakeNet({DEAD[0]: None}, reply, send_fails_at=failing)
        monkeypatch.setattr(mn, "socket", net)
        with pytest.raises(mn.MinecraftNetplayError, match="within the 100 s deadline"):
            mn.status_ping("play.mc.ctf.example", profile=prof, timeout=100, clock=StepClock())
        assert net.sockets[0].sent == sent and net.sockets[0].closed
    net = _FakeNet({DEAD[0]: None}, reply, send_fails_at=1)
    monkeypatch.setattr(mn, "socket", net)
    blocked = mn.solve(tmp_path, prof, host="play.mc.ctf.example", timeout=100)
    assert blocked.status == "blocked" and "within the 100 s deadline" in blocked.notes

    # addresses that never answer: solve says the server could not be reached
    net = _FakeNet({address: socket.timeout("timed out") for address in DEAD})
    monkeypatch.setattr(mn, "socket", net)
    unreachable = mn.solve(tmp_path, prof, host="play.mc.ctf.example", timeout=100)
    assert unreachable.status == "blocked" and "could not reach play.mc.ctf.example:25565" in unreachable.notes
    assert len(net.sockets) == 3


def test_a_dripped_reply_does_not_outlast_the_deadline(fake_server, tmp_path):
    # This one is about wall-clock time, so the bound is a lower one that holds at any load: the server
    # needs at least 0.25 s x 60 bytes = 15 s to send its reply (sleep never returns early), and each
    # gap is far below the 1 s the client allows in total.  A client that applied its timeout to each
    # read on its own would take the whole reply; one deadline for the exchange gives up after 1 s.
    reply = _reply({"description": "slow " * 10})
    assert len(reply) >= 60
    server = fake_server(reply, drip_s=0.25)
    host, port = server.server_address
    with pytest.raises(mn.MinecraftNetplayError, match="within the 1 s deadline"):
        mn.status_ping(host, port, timeout=1.0)
    blocked = mn.solve(tmp_path, host=host, port=fake_server(reply, drip_s=0.25).server_address[1], timeout=1)
    assert blocked.status == "blocked" and "within the 1 s deadline" in blocked.notes


def test_status_flags_past_the_cap_are_reported(fake_server, tmp_path, monkeypatch):
    monkeypatch.setattr(mn, "MAX_FLAGS", 2)
    host, port = fake_server(_reply(MANY_FLAGS)).server_address
    report = mn.status_ping(host, port, timeout=HANDLER_WAIT_S)
    assert [row["flag"] for row in report["flags"]] == ["CSCTF{one}", "CSCTF{two}"]
    assert report["flags_dropped"] == 2
    result = mn.solve(tmp_path, host=host, port=fake_server(_reply(MANY_FLAGS)).server_address[1],
                      timeout=HANDLER_WAIT_S)
    assert result.status == "candidate" and "2 more distinct flag(s) past the cap of 2" in result.notes


def test_a_status_with_more_values_than_are_read_says_so(fake_server, tmp_path):
    values = mn._world.MAX_COMPONENT_NODES
    big = {"description": "CSCTF{in_the_motd}", "filler": ["x"] * values, "last": "CSCTF{past_the_values_read}"}
    host, port = fake_server(_reply(big)).server_address
    report = mn.status_ping(host, port, timeout=HANDLER_WAIT_S)
    assert [row["flag"] for row in report["flags"]] == ["CSCTF{in_the_motd}"]
    assert report["status_truncated"] is True
    result = mn.solve(tmp_path, host=host, port=fake_server(_reply(big)).server_address[1], timeout=HANDLER_WAIT_S)
    assert f"the status JSON holds more than {values} values" in result.notes


def test_favicon_size_cap(monkeypatch):
    monkeypatch.setattr(mn, "MAX_FAVICON_BYTES", 8)
    assert mn.favicon_bytes({"favicon": "data:image/png;base64," + "A" * 16}) == bytes(12)
    with pytest.raises(mn.MinecraftNetplayError, match="favicon exceeds the size cap"):
        mn.favicon_bytes({"favicon": "data:image/png;base64," + "A" * 20})


@pytest.mark.parametrize("reply,message", [
    (mn.encode_varint(mn.MAX_PACKET_BYTES + 1) + b"x", "exceeds the cap"),
    (b"\x80\x80\x80\x80\x80\x01", "exceeds 5 bytes"),
    (b"\x10\x00\x05ab", "connection closed before the full frame"),
    (b"", "connection closed before the full frame"),
    (mn.frame_packet(0x00, mn.encode_string("<html>")), "not valid JSON"),
    (mn.frame_packet(0x1B, mn.encode_string("{}")), "packet id 0x00"),
], ids=["oversize", "long-varint", "short-frame", "silent", "not-json", "wrong-packet"])
def test_a_hostile_or_broken_server_is_a_named_error(fake_server, reply, message):
    server = fake_server(reply, hang_up=True)        # it closes after its reply, so a short one is EOF
    host, port = server.server_address
    with pytest.raises(mn.MinecraftNetplayError, match=message):
        mn.status_ping(host, port, timeout=HANDLER_WAIT_S)
    assert server.done.wait(HANDLER_WAIT_S) and len(server.packets) == 2


# --------------------------------------------------------------------------- engine entry and CLI
def test_solve_statuses(fake_server, tmp_path):
    blocked = mn.solve(tmp_path)
    assert isinstance(blocked, SolverResult) and blocked.status == "blocked" and "--opt host=" in blocked.notes

    refused = mn.solve(tmp_path, _profile(["*.mc.ctf.example"]), host="hypixel.example")
    assert refused.status == "blocked" and "refused by the event scope" in refused.notes
    local = mn.solve(tmp_path, _profile(["*.mc.ctf.example"]), host="127.0.0.1")     # loopback too
    assert local.status == "blocked" and "refused by the event scope" in local.notes

    wait = {"timeout": HANDLER_WAIT_S}
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()
    unreachable = mn.solve(tmp_path, host="127.0.0.1", port=dead_port, **wait)
    assert unreachable.status == "blocked" and f"could not reach 127.0.0.1:{dead_port}" in unreachable.notes

    server = fake_server(_reply({"description": {"text": "CSCTF{only_one}"}, "favicon": STATUS["favicon"]}))
    icon = tmp_path / "icon.png"
    solved = mn.solve(tmp_path, host="127.0.0.1", port=server.server_address[1], favicon_out=str(icon), **wait)
    assert solved.status == "solved" and solved.flags == ("CSCTF{only_one}",) and solved.engine == mn.ENGINE_ID
    assert solved.evidence[0].detail == "flag format on the status motd" and "no login" in solved.notes
    assert icon.read_bytes() == PNG

    many = mn.solve(tmp_path, host="127.0.0.1", port=fake_server(_reply(STATUS)).server_address[1], **wait)
    assert many.status == "candidate" and len(many.flags) == 5 and "past the cap" not in many.notes

    quiet = mn.solve(tmp_path, host="127.0.0.1",
                     port=fake_server(_reply({"description": "A Minecraft Server",
                                              "version": {"name": "1.20.4"}})).server_address[1], **wait)
    assert quiet.status == "unsure" and quiet.flags == ()
    assert [e.detail for e in quiet.evidence] == ["motd: A Minecraft Server", "version: 1.20.4"]

    garbage = mn.solve(tmp_path, host="127.0.0.1", **wait,
                       port=fake_server(mn.frame_packet(0, mn.encode_string("nope"))).server_address[1])
    assert garbage.status == "blocked" and "did not answer a status ping" in garbage.notes


def test_solve_rejects_bad_options(tmp_path):
    with pytest.raises(mn.MinecraftNetplayError, match="unknown option"):
        mn.solve(tmp_path, host="127.0.0.1", prot=1)
    for bad in ({"port": "25565"}, {"port": 70000}, {"protocol": 2 ** 40}, {"timeout": 0}, {"timeout": 500}):
        with pytest.raises(mn.MinecraftNetplayError):
            mn.solve(tmp_path, host="127.0.0.1", **bad)


def test_cli(fake_server, tmp_path, capsys, monkeypatch):
    server = fake_server(_reply(STATUS))
    icon = tmp_path / "server-icon.png"
    wait = ["--timeout", str(HANDLER_WAIT_S)]
    assert mn.main(["127.0.0.1", str(server.server_address[1]), "--compact", "--favicon-out", str(icon),
                    *wait]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["kind"] == "minecraft-status" and "favicon_png" not in report and len(report["flags"]) == 5
    assert icon.read_bytes() == PNG

    quiet = fake_server(_reply({"description": "nothing"}))
    assert mn.main(["127.0.0.1", str(quiet.server_address[1]), *wait]) == 1
    capsys.readouterr()
    assert mn.main(["127.0.0.1", str(quiet.server_address[1]), "--timeout", "0"]) == 2
    assert "timeout must be a positive number" in capsys.readouterr().err

    monkeypatch.setattr(mn, "_connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("connected")))
    assert mn.main(["hypixel.example", "--event", "csctf"]) == mn.REFUSED_EXIT == 4
    assert "refused" in capsys.readouterr().err
    assert mn.main(["hypixel.example", "--event", "no-such-event"]) == 2
    assert "no event" in capsys.readouterr().err


def test_router_lists_the_status_ping_for_a_live_server_brief():
    ids = [hit.manifest.id for hit in router.route("misc", "join the minecraft server at mc.ctf.example:25565")]
    assert "toolkits.minecraft_netplay" in ids and "toolkits.minecraft_world" in ids
    for brief in ("the flag is in the minecraft motd", "do a server list ping", "nc mc.ctf.example 25565"):
        assert "toolkits.minecraft_netplay" in [hit.manifest.id for hit in router.route("misc", brief)], brief


@pytest.mark.parametrize("category,brief", [
    ("pwn", "ssh in as ctf; the hint is in /etc/motd on the box"),
    ("misc", "join the server on discord and read the rules channel"),
    ("web", "the login page prints the motd of the day"),
])
def test_router_does_not_offer_the_ping_for_briefs_that_are_not_minecraft(category, brief):
    assert "toolkits.minecraft_netplay" not in [hit.manifest.id for hit in router.route(category, brief)]
