"""B-001c: the scope guards restored in the web, chat and pwn clients (ctf/scope.py).

Every client (web.WebClient, web.RawSocketScope, chat_target.ChatTarget, pwn_target.PwnTarget)
refuses, before opening any connection and with a named error, a target outside the current event
profile's rules.live_service_scope, and the event platform; an empty scope refuses everything.

No network: the socket boundary (socket.create_connection, socket.getaddrinfo, socket.socket.connect)
is replaced by a recorder that refuses every connection, so a refused client must leave it untouched
and an allowed client must reach it with exactly its target.
"""
import datetime as dt
import socket
import warnings

import pytest

import chat_target as ct
import pwn_target as pt
import web
from ctf import env, event, scope

PLATFORM = "https://board.ctf.example"


def _profile(live_service_scope, base_url=PLATFORM, slug="scope-test"):
    return event.parse({
        "slug": slug, "name": "scope test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": base_url},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(live_service_scope)},
    }, src="<test>")


@pytest.fixture
def use_scope():
    """Pin a profile with the given scope for one test; the suite profile comes back afterwards."""
    before = scope.pinned()

    def _use(globs, **kw):
        scope.pin(_profile(globs, **kw))
    yield _use
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


@pytest.fixture
def wire(monkeypatch):
    """The socket boundary: records every connection or name lookup and refuses it."""
    seen = []

    def create_connection(address, *a, **k):
        seen.append(("connect", address[0], address[1]))
        raise ConnectionRefusedError("test socket boundary: no network")

    def getaddrinfo(host, port, *a, **k):
        seen.append(("resolve", host, port))
        raise socket.gaierror("test socket boundary: no network")

    def sock_connect(self, address):
        seen.append(("connect", address[0], address[1]))
        raise ConnectionRefusedError("test socket boundary: no network")

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", sock_connect)
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    for legacy in env.legacy_names("CTF_PLATFORM_URL"):
        monkeypatch.delenv(legacy, raising=False)
    for proxy in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(proxy, raising=False)
    monkeypatch.setenv("no_proxy", "*")              # urllib goes straight to the target's socket
    return seen


# One builder per client: construct it, then make one call that would open its connection.

def _web(host, port=443):
    c = web.WebClient(f"https://{host}:{port}/")
    with pytest.raises(web.VPNRequired):
        c.get("/")


def _raw(host, port=443):
    c = web.RawSocketScope(host, port)
    with pytest.raises(web.VPNRequired):
        c.send_raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def _chat(host, port=443):
    c = ct.ChatTarget(f"https://{host}:{port}/chat", min_interval=0)
    with pytest.raises((OSError, ct.VPNRequired)):    # URLError (a hostname) or VPNRequired (private IP)
        c.chat("hi")


def _pwn(host, port=443):
    c = pt.PwnTarget(host, port, min_interval=0)
    with pytest.raises(ct.VPNRequired):
        c.connect()


CLIENTS = {
    "web": (_web, web.OutOfScope),
    "raw": (_raw, web.OutOfScope),
    "chat": (_chat, ct.OutOfScope),
    "pwn": (_pwn, ct.OutOfScope),
}


# ------------------------------------------------------------------------------- the acceptance tests

@pytest.mark.parametrize("client", sorted(CLIENTS))
def test_out_of_scope_host_is_refused_before_any_connection(client, use_scope, wire):
    build, err = CLIENTS[client]
    use_scope(["*.ctf.example", "10.13.37.0/24"])
    for host in ("api.openai.example.com", "8.8.8.8", "10.13.38.5", "ctf.example.evil.test"):
        with pytest.raises(err, match=r"outside event 'scope-test' rules\.live_service_scope") as ei:
            build(host)
        assert isinstance(ei.value, scope.OutOfScope)
    assert wire == []


@pytest.mark.parametrize("client", sorted(CLIENTS))
def test_in_scope_host_is_allowed_and_reaches_the_socket(client, use_scope, wire):
    build, _ = CLIENTS[client]
    use_scope(["*.ctf.example", "10.13.37.0/24"])
    build("web-1.ctf.example", 8443)
    assert wire and {(h, p) for _, h, p in wire} == {("web-1.ctf.example", 8443)}
    wire.clear()
    build("10.13.37.5", 31337)
    assert wire and {(h, p) for _, h, p in wire} == {("10.13.37.5", 31337)}


@pytest.mark.parametrize("client", sorted(CLIENTS))
def test_empty_scope_refuses_everything(client, use_scope, wire):
    build, err = CLIENTS[client]
    use_scope([])
    for host in ("127.0.0.1", "localhost", "10.0.0.5", "web-1.ctf.example", "board.ctf.example"):
        with pytest.raises(err, match="empty rules.live_service_scope"):
            build(host)
    assert wire == []


@pytest.mark.parametrize("client", sorted(CLIENTS))
def test_platform_is_refused_even_when_the_scope_matches_it(client, use_scope, wire):
    build, err = CLIENTS[client]
    use_scope(["*.ctf.example"])                      # matches board.ctf.example, the platform
    with pytest.raises(err, match="event platform"):
        build("board.ctf.example", 443)
    with pytest.raises(err, match="event platform"):
        build("BOARD.ctf.example.", 443)              # case and trailing dot are the same host
    assert wire == []


# ------------------------------------------------------------------------------- the guard's rules

def test_platform_check_is_by_host_and_port(use_scope, wire):
    use_scope(["*.ctf.example"])
    _pwn("board.ctf.example", 31337)                  # an instance on another port of the same host
    assert {(h, p) for _, h, p in wire} == {("board.ctf.example", 31337)}


def test_platform_from_ctf_platform_url_and_legacy_spelling(use_scope, wire, monkeypatch):
    use_scope(["*.ctf.example"])
    monkeypatch.setenv("CTF_PLATFORM_URL", "http://gm.ctf.example:8080/")
    with pytest.raises(web.OutOfScope, match="event platform"):
        web.WebClient("http://gm.ctf.example:8080/")
    monkeypatch.delenv("CTF_PLATFORM_URL")
    monkeypatch.setenv(env.legacy_names("CTF_PLATFORM_URL")[1], "http://gm.ctf.example:8080/")   # Huntress's old spelling, mapped by ctf.env
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(ct.OutOfScope, match="event platform"):
            ct.ChatTarget("http://gm.ctf.example:8080/chat")
        assert web.WebClient("http://gm.ctf.example:8081/").base == "http://gm.ctf.example:8081/"
    assert wire == []


def test_glob_and_cidr_matching(use_scope):
    use_scope(["web-?.ctf.example", "10.0.0.0/8", "fd00::/8", "localhost"])
    for ok in ("web-1.ctf.example", "WEB-2.CTF.EXAMPLE", "10.200.1.2", "fd00::5", "localhost"):
        assert scope.check_host(ok, 80) == ok.lower()
    for bad in ("web-10.ctf.example", "ctf.example", "11.0.0.1", "fe80::1", "localhost.evil.test", ""):
        with pytest.raises(scope.OutOfScope):
            scope.check_host(bad, 80)
    assert ct.ChatTarget("http://[fd00::5]:8080/chat").url == "http://[fd00::5]:8080/chat"


@pytest.mark.parametrize("entry", ["*", "*.*", "?.*", "10.0.0.0/33"])
def test_unusable_scope_entry_is_refused_loudly(entry, use_scope):
    use_scope(["web.ctf.example", entry])
    with pytest.raises(ct.OutOfScope, match=r"rules\.live_service_scope entry"):
        ct.ChatTarget("http://web.ctf.example/chat")


def test_reads_the_real_profiles_through_ctf_event(wire, monkeypatch):
    """Unpinned, the guard uses event.current(): CTF_EVENT picks a shipped profile under events/."""
    before = scope.pinned()
    scope.unpin()
    try:
        monkeypatch.delenv("CTF_EVENT", raising=False)
        for legacy in env.legacy_names("CTF_EVENT"):
            monkeypatch.delenv(legacy, raising=False)
        if len(event.available()) > 1:
            with pytest.raises(web.OutOfScope, match="no live-service scope.*CTF_EVENT"):
                web.WebClient("http://127.0.0.1:8080/")
        prof = event.load("csctf")
        monkeypatch.setenv("CTF_EVENT", "csctf")
        glob = prof.rules.live_service_scope[0]
        assert glob.startswith("*.")
        assert pt.PwnTarget("chal-1" + glob[1:], 1337).port == 1337
        platform_host = scope.split_url(prof.platform.base_url)[0]
        with pytest.raises(web.OutOfScope, match="event platform"):
            web.WebClient(prof.platform.base_url + "/")
        with pytest.raises(ct.OutOfScope, match="outside event 'csctf'"):
            ct.ChatTarget("http://127.0.0.1:8080/chat")
        assert platform_host and scope.policy().event == "csctf"
        monkeypatch.setenv("CTF_EVENT", "spooky")
        assert event.load("spooky").rules.live_service_scope == ()
        with pytest.raises(ct.OutOfScope, match="empty rules.live_service_scope"):
            pt.PwnTarget("127.0.0.1", 31337)
    finally:
        if before is not None:
            scope.pin(before)
    assert wire == []


def test_registry_entry_is_checked_against_the_scope(use_scope, wire, tmp_path, monkeypatch):
    import json
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    (tmp_path / "_targets.json").write_text(json.dumps({"targets": {
        "in": {"url": "http://10.13.37.5:8080/chat"},
        "out": {"url": "http://192.168.1.5:8080/chat"},
    }}))
    use_scope(["10.13.37.0/24"])
    assert ct.ChatTarget.from_registry("in").url.endswith("/chat")
    assert pt.PwnTarget.from_registry("in").port == 8080
    with pytest.raises(ct.OutOfScope, match="outside event"):
        ct.ChatTarget.from_registry("out")
    with pytest.raises(ct.OutOfScope, match="outside event"):
        pt.PwnTarget.from_registry("out")
    assert wire == []


def test_policy_cli_prints_the_profile_scope(use_scope, capsys):
    use_scope(["*.ctf.example", "10.13.37.0/24"])
    assert ct.main(["policy"]) == 0
    out = capsys.readouterr().out
    assert "scope-test" in out and "*.ctf.example, 10.13.37.0/24" in out and "board.ctf.example:443" in out
    use_scope([])
    assert ct.main(["policy"]) == 0
    assert "empty: every target is refused" in capsys.readouterr().out
