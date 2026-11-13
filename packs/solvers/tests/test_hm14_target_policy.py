"""Hand-merge batch hm-14: chat_target / pwn_target keep the pass-a-URL interface (CSCTF) and get back the
_targets.json registry read and the platform-host refusal (Huntress). Since B-001c the target policy is
ctf.scope, driven by the current event profile's rules.live_service_scope (the full guard tests are in
tests/test_scope_guard.py); this file keeps the registry and pass-a-URL behaviour.

No real network: the only sockets are a toy chatbot on loopback that the test starts itself, and every
refusal is raised before any connection.
"""
import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import chat_target as ct
import pwn_target as PT
from ctf import event, scope

PLATFORM = "https://board.example-event.test"


@pytest.fixture
def policy(monkeypatch, tmp_path):
    """A pinned event profile (platform PLATFORM, scope below) and an empty registry folder."""
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    before = scope.pinned()

    def set_scope(globs=("10.0.0.0/8", "127.0.0.1", "*.internal", "*.example-event.test")):
        scope.pin(event.parse({
            "slug": "hm14", "name": "hm14",
            "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
            "platform": {"kind": "ctfd", "base_url": PLATFORM},
            "flag": {"prefixes": []},
            "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                      "live_service_scope": list(globs)}}))
    set_scope()
    set_scope.registry = tmp_path / "_targets.json"
    yield set_scope
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


# ------------------------------------------------------------------ the policy itself

def test_platform_host_from_the_profile_is_refused_for_chat_and_pwn(policy):
    with pytest.raises(ct.OutOfScope, match="platform"):
        ct.ChatTarget(PLATFORM + "/api/v1/challenges")
    with pytest.raises(ct.OutOfScope, match="platform"):
        PT.PwnTarget("board.example-event.test", 443)


def test_platform_from_env_is_refused(policy, monkeypatch):
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://gm.example-event.test/")
    with pytest.raises(ct.OutOfScope, match="platform"):
        ct.ChatTarget("https://gm.example-event.test/chat")
    with pytest.raises(ct.OutOfScope, match="platform"):
        PT.PwnTarget("gm.example-event.test", 443)


def test_host_outside_the_scope_is_refused(policy):
    with pytest.raises(ct.OutOfScope, match="live_service_scope"):
        ct.ChatTarget("http://93.184.216.34/chat")
    with pytest.raises(ct.OutOfScope, match="live_service_scope"):
        ct.ChatTarget("http://api.example-ai.test/chat")
    with pytest.raises(ct.OutOfScope, match="live_service_scope"):
        PT.PwnTarget("8.8.8.8", 9999)
    with pytest.raises(ct.OutOfScope, match="live_service_scope"):
        ct.ChatTarget("http://192.168.1.4/chat")          # private, but not in this event's scope


def test_hosts_inside_the_scope_pass(policy):
    assert ct.ChatTarget("http://10.1.2.3:8080/chat").needs_vpn is True
    assert ct.ChatTarget("http://arena-bot.internal/chat").url.endswith("/chat")
    assert PT.PwnTarget("127.0.0.1", 31337).host == "127.0.0.1"
    policy(["8.8.8.8"])                                   # an event whose instance is public
    assert PT.PwnTarget("8.8.8.8", 9999).port == 9999


def test_policy_reports_the_pinned_profile(policy):
    pol = ct.target_policy()
    assert pol["event"] == "hm14"
    assert pol["platform_hosts"] == {"board.example-event.test"}
    assert ("board.example-event.test", 443) in pol["platform"]
    assert "*.internal" in pol["scope"]


# ------------------------------------------------------------------ the registry read

def test_registry_tools_target_shape_resolves_names(policy):
    policy.registry.write_text(json.dumps({"version": 1, "targets": {
        "web-07": {"url": "http://10.1.2.3:8080/chat", "address": "10.1.2.3:8080", "label": "bot"},
        "pwn-03": {"address": "10.9.8.7:31337", "host": "10.9.8.7", "port": 31337},
        "off": {"url": "http://10.1.2.4/chat", "allowed": False},
    }}))
    t = ct.ChatTarget.from_registry("web-07", kind="text")
    assert t.url == "http://10.1.2.3:8080/chat" and t.entry["note"] == "bot"
    p = PT.PwnTarget.from_registry("pwn-03")
    assert (p.host, p.port) == ("10.9.8.7", 31337) and p.entry["name"] == "pwn-03"
    with pytest.raises(ct.OutOfScope, match="allowed=false"):
        ct.ChatTarget.from_registry("off")
    with pytest.raises(ct.OutOfScope, match="allowed=false"):
        ct.ChatTarget("http://10.1.2.4/chat")                         # the entry follows the URL
    assert ct.find_target("http://10.1.2.3:8080/chat/")["name"] == "web-07"   # trailing slash
    assert ct.main(["list"]) == 0


def test_registry_list_shape_and_unknown_name(policy):
    policy.registry.write_text(json.dumps({"targets": [
        {"name": "arena-bot", "url": "http://10.13.37.5:8080/chat", "kind": "form", "field": "q"}]}))
    assert ct.ChatTarget.from_registry("arena-bot").kind == "form"
    with pytest.raises(ct.NotRegistered):
        ct.ChatTarget.from_registry("no-such-target")
    with pytest.raises(ct.NotRegistered):
        PT.PwnTarget.from_registry("no-such-target")


def test_pwn_from_registry_accepts_tcp_url_and_host_port_unregistered(policy):
    p = PT.PwnTarget.from_registry("tcp://10.0.0.5:4444")
    assert (p.host, p.port) == ("10.0.0.5", 4444)
    q = PT.PwnTarget.from_registry("10.0.0.6:5555")
    assert (q.host, q.port) == ("10.0.0.6", 5555)
    with pytest.raises(ct.OutOfScope, match="live_service_scope"):
        PT.PwnTarget.from_registry("tcp://8.8.8.8:53")


def test_corrupt_registry_fails_loudly(policy):
    policy.registry.write_text("{not json")
    with pytest.raises(ValueError, match="_targets.json"):
        ct.read_targets()


def test_policy_cli(policy, capsys):
    policy(["api.example-ai.test"])
    assert ct.main(["policy"]) == 0
    out = capsys.readouterr().out
    assert "board.example-event.test" in out and "api.example-ai.test" in out


# ------------------------------------------------------------------ the pass-a-URL path still talks

class _ToyBot(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        msg = json.loads(body)["messages"][-1]["content"]
        out = json.dumps({"choices": [{"message": {"content": f"echo: {msg}"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def test_unregistered_loopback_url_round_trips(policy):
    srv = HTTPServer(("127.0.0.1", 0), _ToyBot)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t = ct.ChatTarget(f"http://127.0.0.1:{srv.server_address[1]}/chat", min_interval=0)
        assert t.entry == {}
        assert t.chat("hi") == "echo: hi"
        assert [e["direction"] for e in t.transcript] == ["sent", "recv"]
    finally:
        srv.shutdown()
