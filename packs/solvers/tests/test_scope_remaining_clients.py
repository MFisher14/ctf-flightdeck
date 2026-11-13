"""R-13: the scope guard on the network code B-001c left unguarded (ctf/scope.py).

- tools/netplay.py connect(): a live target, so ctf.scope.check_host (scope + platform refusal).
- speedrun/wire.py (fast CTFd): a platform client, so ctf.scope.check_platform_url (the event
  platform only; a challenge host or any other host is refused).
- tools/vpn.py probe / tcp / ensure / up: ctf.scope.check_host before any ping, socket or VPN change.
- tools/oob.py: selftest connects only to this Mac's own listener; the Cloudflare quick tunnel
  (up --public, the public probe) is a public third-party service: ctf.scope.check_public_fetch.
- solvers/toolkits/memory.py fetch_isf and vol(online=True, where="venv"): public symbol mirrors,
  ctf.scope.check_public_fetch against the profile's rules.public_fetch_allow.
- solvers/mobile-android/mobile_depth.py, solvers/toolkits/android_depth.py and
  solvers/web/cache_analysis.py open no connection at all (their "network" lines are string-lead
  regexes); a static check keeps it that way.

No network: the socket boundary (socket.create_connection, socket.getaddrinfo,
socket.socket.connect), urllib.request.urlopen and subprocess are replaced by recorders that refuse
every call, so a refused call must leave them untouched and an allowed one must reach them with
exactly its target.
"""
import ast
import datetime as dt
import socket
import subprocess
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ctf import env, event, scope
from ctf import eventscaffold as sc
from ctf.cli import main as ctf_main

import memory as M  # solvers/toolkits (root conftest puts it on sys.path)
import netplay as N  # tools/
import oob
import target
import vpn
from speedrun import wire

REPO = Path(__file__).resolve().parents[1]
PLATFORM = "https://board.ctf.example"
SCOPE = ["*.ctf.example", "10.13.37.0/24"]


def _profile(live=SCOPE, public=(), base_url=PLATFORM, kind="ctfd", slug="r13-test"):
    platform = {"kind": kind}
    if base_url:
        platform["base_url"] = base_url
    rules = {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
             "live_service_scope": list(live)}
    if public is not None:
        rules["public_fetch_allow"] = list(public)
    return event.parse({
        "slug": slug, "name": "r13 test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": platform, "flag": {"prefixes": []}, "rules": rules,
    }, src="<test>")


@pytest.fixture
def use_profile():
    """Pin a profile for one test; the suite profile comes back afterwards."""
    before = scope.pinned()

    def _use(**kw):
        prof = _profile(**kw)
        scope.pin(prof)
        return prof
    yield _use
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


@pytest.fixture
def net(monkeypatch):
    """The network boundary: records every connection, lookup, URL open and subprocess, refuses them."""
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

    def urlopen(req, *a, **k):
        url = req.full_url if isinstance(req, urllib.request.Request) else str(req)
        seen.append(("urlopen", url))
        raise urllib.error.URLError("test boundary: no network")

    def run(argv, *a, **k):
        seen.append(("run", tuple(str(x) for x in argv)))
        return subprocess.CompletedProcess(argv, 1, b"", b"test boundary: not run")

    def popen(argv, *a, **k):
        seen.append(("popen", tuple(str(x) for x in argv)))
        raise OSError("test boundary: no subprocess")

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", sock_connect)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", popen)
    for canon in ("CTF_PLATFORM_URL",):
        for n in (canon, *env.legacy_names(canon)):
            monkeypatch.delenv(n, raising=False)
    for proxy in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(proxy, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    return seen


# ================================================================================ ctf.scope additions

def test_public_fetch_is_refused_unless_the_profile_lists_the_host(use_profile, net):
    use_profile(public=[])
    with pytest.raises(scope.OutOfScope) as ei:
        scope.check_public_fetch("https://mirror.example.org/pack.zip", purpose="symbol pack")
    msg = str(ei.value)
    assert "symbol pack" in msg and "mirror.example.org" in msg and "rules.public_fetch_allow" in msg
    assert "(empty)" in msg and "events/r13-test/event.toml" in msg
    use_profile(public=["*.mirror.example.org", "downloads.example.net"])
    assert scope.check_public_fetch("https://cdn.mirror.example.org/x", purpose="p") == "cdn.mirror.example.org"
    assert scope.check_public_fetch("DOWNLOADS.example.net.", purpose="p") == "downloads.example.net"
    with pytest.raises(scope.OutOfScope, match="does not list it"):
        scope.check_public_fetch("https://mirror.example.org.evil.test/", purpose="p")
    with pytest.raises(scope.OutOfScope, match="does not list it"):
        scope.check_public_fetch("https://other.example.net/", purpose="p")
    assert net == []


def test_public_fetch_and_live_scope_do_not_open_each_other(use_profile):
    use_profile(live=["*.ctf.example"], public=["mirror.example.org"])
    with pytest.raises(scope.OutOfScope, match="public_fetch_allow"):
        scope.check_public_fetch("https://web-1.ctf.example/", purpose="p")
    with pytest.raises(scope.OutOfScope, match="live_service_scope"):
        scope.check_host("mirror.example.org", 443)


def test_public_fetch_never_reaches_the_platform_and_checks_its_entries(use_profile, monkeypatch):
    use_profile(public=["board.ctf.example"])
    with pytest.raises(scope.OutOfScope, match="is the event platform"):
        scope.check_public_fetch("https://board.ctf.example/files/x", purpose="p")
    # A bare host (what oob.py and a symbol-server check pass) carries no port: still the platform.
    for bare in ("board.ctf.example", "BOARD.ctf.example."):
        with pytest.raises(scope.OutOfScope, match="board.ctf.example is the event platform"):
            scope.check_public_fetch(bare, purpose="p")
    use_profile(public=["*.*"])
    with pytest.raises(scope.OutOfScope, match="public_fetch_allow entry '\\*\\.\\*' is too broad"):
        scope.check_public_fetch("https://anything.example/", purpose="p")
    use_profile(public=["10.0.0.0/33"])
    with pytest.raises(scope.OutOfScope, match="not an IP network"):
        scope.check_public_fetch("10.0.0.1", purpose="p")
    use_profile(public=["198.51.100.0/24"])
    assert scope.check_public_fetch("http://198.51.100.7/x", purpose="p") == "198.51.100.7"
    with pytest.raises(ValueError, match="needs a purpose"):
        scope.check_public_fetch("198.51.100.7", purpose="")


def test_public_fetch_without_a_profile_is_refused(monkeypatch):
    before = scope.pinned()
    scope.unpin()
    try:
        monkeypatch.setenv("CTF_EVENT", "no-such-event-r13")
        with pytest.raises(scope.OutOfScope, match="profile did not load"):
            scope.check_public_fetch("https://mirror.example.org/", purpose="p")
        with pytest.raises(scope.OutOfScope, match="profile did not load"):
            scope.check_platform_url(PLATFORM)
    finally:
        if before is not None:
            scope.pin(before)


def test_platform_url_check_admits_only_the_platform(use_profile, monkeypatch):
    for n in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(n, raising=False)
    use_profile()
    assert scope.check_platform_url("https://board.ctf.example/api/v1/") == ("board.ctf.example", 443)
    for bad in ("https://web-1.ctf.example/", "https://board.ctf.example:8443/", "http://board.ctf.example/",
                "https://evil.test/", "http://127.0.0.1:8000/"):
        with pytest.raises(scope.OutOfScope, match="is not the platform of event 'r13-test'"):
            scope.check_platform_url(bad)
    monkeypatch.setenv("CTF_PLATFORM_URL", "http://127.0.0.1:8000")
    assert scope.check_platform_url("http://127.0.0.1:8000/") == ("127.0.0.1", 8000)
    monkeypatch.delenv("CTF_PLATFORM_URL")
    use_profile(kind="manual", base_url=None)
    with pytest.raises(scope.OutOfScope, match="no platform.base_url"):
        scope.check_platform_url("https://board.ctf.example/")


# ============================================================================ the profile field

def test_profile_reads_public_fetch_allow_with_a_default_and_type_check():
    assert _profile(public=None).rules.public_fetch_allow == ()
    assert _profile(public=["msdl.microsoft.com", "*.trycloudflare.com"]).rules.public_fetch_allow == (
        "msdl.microsoft.com", "*.trycloudflare.com")
    with pytest.raises(event.EventError, match="rules.public_fetch_allow must be a list of non-empty strings"):
        _profile(public=[""])
    for shipped in ("huntress", "csctf", "pink", "spooky"):
        assert event.load(shipped).rules.public_fetch_allow == ()


def test_scaffold_and_new_event_write_public_fetch_allow(tmp_path, monkeypatch, capsys):
    data = sc.profile_data("acme", name="ACME", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2),
                           kind="ctfd", base_url="https://ctf.acme.example", submit_mode="confirm",
                           ai_on_platform="allowed", public_fetch_allow=["msdl.microsoft.com"])
    assert sc.validate(data, "acme").rules.public_fetch_allow == ("msdl.microsoft.com",)
    for canon in ("CTF_TOKEN", "CTF_PLATFORM_URL", "CTF_COOKIE"):
        for n in (canon, *env.legacy_names(canon)):
            monkeypatch.delenv(n, raising=False)
    root = tmp_path / "events"
    root.mkdir()
    rc = ctf_main(["new-event", "acme", "--start", "2027-03-01", "--end", "2027-03-02", "--base-url",
                   "https://ctf.acme.example", "--public-fetch", "*.trycloudflare.com", "--no-fetch",
                   "--events-root", str(root)])
    assert rc == 0, capsys.readouterr()
    assert event.load("acme", root).rules.public_fetch_allow == ("*.trycloudflare.com",)


# ===================================================================================== netplay

def test_netplay_refuses_an_out_of_scope_host_before_any_socket(use_profile, net, monkeypatch):
    use_profile()
    imported = []
    monkeypatch.setitem(sys.modules, "pwn", types.SimpleNamespace(
        remote=lambda *a, **k: imported.append(("remote", a)), ssh=lambda **k: imported.append(("ssh", k))))
    for host, port in (("8.8.8.8", 1337), ("quiz.evil.test", 4000), ("10.13.38.5", 9001)):
        with pytest.raises(scope.OutOfScope, match="outside event 'r13-test'"):
            N.connect(host, port)
        with pytest.raises(scope.OutOfScope, match="outside event 'r13-test'"):
            N.connect(host, None, ssh_user="ctf")
    with pytest.raises(scope.OutOfScope, match="event platform"):
        N.connect("board.ctf.example", 443, prefer_pwntools=False)
    assert net == [] and imported == []


def test_netplay_reaches_the_socket_with_exactly_an_in_scope_target(use_profile, net):
    use_profile()
    with pytest.raises(ConnectionRefusedError):
        N.connect("quiz.ctf.example", 31337, prefer_pwntools=False)
    with pytest.raises(ConnectionRefusedError):
        N.connect("10.13.37.9", 4444, prefer_pwntools=False)
    assert net == [("connect", "quiz.ctf.example", 31337), ("connect", "10.13.37.9", 4444)]


def test_netplay_ssh_defaults_port_22_for_the_scope_check(use_profile, monkeypatch):
    use_profile(live=["*.ctf.example"])
    calls = []

    class _Sess:
        def shell(self):
            return object()
    monkeypatch.setitem(sys.modules, "pwn", types.SimpleNamespace(ssh=lambda **k: calls.append(k) or _Sess()))
    N.connect("shell.ctf.example", None, ssh_user="ctf")
    assert calls[0]["host"] == "shell.ctf.example" and calls[0]["port"] == 22
    use_profile(live=["*.ctf.example"], base_url="https://shell.ctf.example:22")
    with pytest.raises(scope.OutOfScope, match="event platform"):     # port 22 is what is checked
        N.connect("shell.ctf.example", None, ssh_user="ctf")
    assert len(calls) == 1


def test_netplay_cli_exits_2_naming_the_refusal(use_profile, net, capsys):
    use_profile()
    assert N.main(["8.8.8.8", "1337"]) == 2
    assert "netplay: refused:" in capsys.readouterr().err and net == []


# ======================================================================================== wire

def test_wire_refuses_any_host_but_the_platform_before_a_socket(use_profile, net):
    use_profile()
    for url in ("https://web-1.ctf.example/", "https://evil.test/", "https://board.ctf.example:8443/"):
        with pytest.raises(scope.OutOfScope, match="not the platform"):
            wire.FastCTFd(url, "tok", conns=1)
        tgt = wire.target(url)
        with pytest.raises(scope.OutOfScope, match="not the platform"):
            wire.Conn(tgt).open()
        with pytest.raises(scope.OutOfScope, match="not the platform"):
            wire.Pool(tgt, 2).open()
    assert net == []


def test_wire_opens_connections_to_the_platform(use_profile, net):
    use_profile()
    c = wire.FastCTFd(PLATFORM + "/", "tok", conns=2, open_cap=1.0)
    c.open()                                       # the boundary refuses: no connection is ok
    assert c.pool.conns == []
    assert net and all(x == ("connect", "board.ctf.example", 443) for x in net)
    net.clear()
    conn = wire.Conn(wire.target(PLATFORM)).open()
    assert conn.sock is None and conn.error and net == [("connect", "board.ctf.example", 443)]


def test_wire_pool_checks_the_platform_once_not_once_per_connection(use_profile, net, monkeypatch):
    """The real check_platform_url runs (a counting pass-through): a pool of 5 checks once, its cold
    connections ride on that check, and an unopened pool's cold connection checks for itself."""
    use_profile()
    calls = []
    real = scope.check_platform_url
    monkeypatch.setattr(scope, "check_platform_url", lambda url, **k: calls.append(url) or real(url, **k))
    pool = wire.Pool(wire.target(PLATFORM), 5, cap=1.0).open()
    assert calls == [PLATFORM + "/"]
    assert sum(1 for x in net if x == ("connect", "board.ctf.example", 443)) == 5
    pool.take()                                    # no idle connection: a cold one, already checked
    assert len(calls) == 1 and net[-1] == ("connect", "board.ctf.example", 443)
    calls.clear()
    c = wire.FastCTFd(PLATFORM + "/", "tok", conns=4, open_cap=1.0).open()
    assert len(calls) == 2 and len(c.pool.conns) == 0   # the client's own check, then the pool's
    calls.clear()
    with pytest.raises(scope.OutOfScope, match="not the platform"):
        wire.Pool(wire.target("https://evil.test/"), 3).take()
    assert calls == ["https://evil.test/"]
    assert not wire.Conn(wire.target(PLATFORM)).checked


def test_wire_accepts_a_loopback_fixture_only_when_ctf_platform_url_names_it(use_profile, net, monkeypatch):
    use_profile()
    with pytest.raises(scope.OutOfScope):
        wire.Conn(wire.target("http://127.0.0.1:8123/")).open()
    monkeypatch.setenv("CTF_PLATFORM_URL", "http://127.0.0.1:8123")
    wire.Conn(wire.target("http://127.0.0.1:8123/")).open()
    assert net == [("connect", "127.0.0.1", 8123)]


# ========================================================================================= vpn

def _addr(host, port):
    return {"host": host, "port": port, "address": f"{host}:{port}" if port else host, "vpn": None}


def test_vpn_probe_and_tcp_refuse_before_ping_or_socket(use_profile, net):
    use_profile()
    for host, port in (("8.8.8.8", None), ("8.8.8.8", 80), ("board.ctf.example", 443), ("evil.test", 22)):
        with pytest.raises(scope.OutOfScope):
            vpn.probe(host, port)
    with pytest.raises(scope.OutOfScope):
        vpn.tcp("8.8.8.8", 443)
    assert net == []


def test_vpn_probe_reaches_exactly_an_in_scope_target(use_profile, net):
    use_profile()
    assert vpn.probe("10.13.37.4", 8080) == "refused"          # the boundary refuses the connection
    assert net == [("connect", "10.13.37.4", 8080)]
    net.clear()
    vpn.probe("web.ctf.example")                              # no port: one ping, then 80/443/22
    assert net[0][0] == "run" and net[0][1][-1] == "web.ctf.example"
    assert [x[1:] for x in net[1:]] == [("web.ctf.example", 80), ("web.ctf.example", 443), ("web.ctf.example", 22)]


def test_vpn_ensure_and_up_refuse_before_any_probe_or_vpn_change(use_profile, net):
    use_profile()
    probes, runs = [], []

    def probe_fn(h, p):
        probes.append((h, p))
        return "open"

    def runner(lines, timeout=None):
        runs.append(lines)
        return 0, "EXITING"
    for addr in (_addr("8.8.8.8", 80), _addr("board.ctf.example", 443)):
        with pytest.raises(scope.OutOfScope):
            vpn.ensure(addr, runner=runner, probe_fn=probe_fn)
        with pytest.raises(scope.OutOfScope):
            vpn.up(address=addr, runner=runner, probe_fn=probe_fn)
    assert probes == [] and runs == [] and net == []
    ok, line = vpn.ensure(_addr("10.13.37.4", 80), runner=runner, probe_fn=probe_fn)
    assert ok and probes == [("10.13.37.4", 80)]


def test_vpn_cli_ensure_exits_2_for_an_out_of_scope_address(use_profile, net, monkeypatch, capsys):
    use_profile()
    monkeypatch.setattr(target, "_event_config", lambda: (PLATFORM, {}))
    assert vpn.main(["ensure", "8.8.8.8:80"]) == 2
    err = capsys.readouterr().err
    assert "vpn.py: refused:" in err and "outside event 'r13-test'" in err and net == []


# ========================================================================================= oob

def test_oob_selftest_connects_only_to_this_macs_own_listener(use_profile, net, monkeypatch, tmp_path):
    use_profile()
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    ifaces = [("lo0", "127.0.0.1"), ("utun4", "10.200.3.9")]
    assert oob.check_own_address("127.0.0.1", ifaces) == "127.0.0.1"
    assert oob.check_own_address("10.200.3.9", ifaces) == "10.200.3.9"
    for bad in ("8.8.8.8", "10.200.3.10", "board.ctf.example", ""):
        with pytest.raises(oob.OutOfScope, match="own listener"):
            oob.check_own_address(bad, ifaces)
    monkeypatch.setattr(oob, "interfaces", lambda text=None: ifaces)
    monkeypatch.setattr(oob, "running", lambda: {"bind": "8.8.8.8", "port": 8380, "tcp_port": 8381})
    with pytest.raises(oob.OutOfScope):
        oob.cmd_selftest(None)
    assert net == []
    assert issubclass(oob.OutOfScope, scope.OutOfScope) and issubclass(oob.OutOfScope, oob.Refused)


def test_oob_selftest_on_its_own_address_reaches_the_socket(use_profile, net, monkeypatch, tmp_path):
    use_profile()
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(oob, "interfaces", lambda text=None: [("utun4", "10.200.3.9")])
    monkeypatch.setattr(oob, "running", lambda: {"bind": "10.200.3.9", "port": 8380, "tcp_port": 0})
    monkeypatch.setattr(oob.time, "sleep", lambda s: None)
    assert oob.cmd_selftest(None) == 1                        # the boundary refuses: FAIL, not refused
    assert ("connect", "10.200.3.9", 8380) in net


def test_oob_public_tunnel_needs_the_profile_allow_list(use_profile, net, monkeypatch, tmp_path, capsys):
    use_profile(public=[])
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(oob, "running", lambda: {})
    looked = []
    monkeypatch.setattr(oob, "cloudflared_path", lambda: looked.append(1) or "/nonexistent/cloudflared")
    assert oob.main(["up", "--public"]) == 2
    err = capsys.readouterr().err
    assert "api.trycloudflare.com" in err and "public_fetch_allow" in err
    with pytest.raises(oob.OutOfScope, match="public_fetch_allow"):
        oob.public_probe("https://abc-def.trycloudflare.com", "o0123456789ab", patience=0.05)
    assert net == [] and looked == []
    use_profile(public=["*.trycloudflare.com"])
    with pytest.raises(oob.Refused, match="cloudflared not found"):   # past the scope check now
        oob.cmd_up(types.SimpleNamespace(public=True, bind=None, tcp_port=0, port=8380, minutes=1))
    assert looked == [1]


def test_oob_serve_child_rechecks_the_public_allow_list(use_profile, net, monkeypatch, tmp_path, capsys):
    """The `_serve` child (what `up` spawns) re-checks --public itself: run directly with an empty
    public_fetch_allow it exits 2 before serve() is called; with the tunnel host listed it serves."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(oob, "interfaces", lambda text=None: [("lo0", "127.0.0.1")])
    monkeypatch.setattr(oob, "event_ranges", lambda: ())
    served = []
    monkeypatch.setattr(oob, "serve", lambda *a, **k: served.append((a, k)) or {})
    argv = ["_serve", "--bind", "127.0.0.1", "--port", "8380", "--tcp-port", "0",
            "--until", str(oob.time.time() + 60), "--public"]
    use_profile(public=[])
    assert oob.main(argv) == 2
    err = capsys.readouterr().err
    assert "api.trycloudflare.com" in err and "public_fetch_allow" in err
    assert served == [] and net == []
    use_profile(public=["*.trycloudflare.com"])
    assert oob.main(argv) == 0
    assert len(served) == 1 and served[0][0][0] == "127.0.0.1" and served[0][1]["public"] is True
    use_profile(public=[])
    assert oob.main(argv[:-1]) == 0                          # no --public: no public fetch, no check
    assert len(served) == 2 and served[1][1]["public"] is False and net == []


def test_oob_public_probe_with_the_allow_list_reaches_only_the_tunnel(use_profile, net, monkeypatch):
    use_profile(public=["*.trycloudflare.com"])
    monkeypatch.setattr(oob.time, "sleep", lambda s: None)
    ok, why = oob.public_probe("https://abc-def.trycloudflare.com", "o0123456789ab", patience=0.05)
    assert not ok
    hosts = {x[1] for x in net if x[0] in ("connect", "resolve")}
    assert hosts and hosts <= {"abc-def.trycloudflare.com", "api.trycloudflare.com"}


# ====================================================================================== memory

KERNEL = ("ntkrnlmp.pdb", "0123456789ABCDEF0123456789ABCDEF", 1)


def test_memory_fetch_isf_needs_the_mirror_in_the_allow_list(use_profile, net, monkeypatch, tmp_path):
    monkeypatch.setattr(M, "symbols_folder", lambda: tmp_path / "_symbols")
    use_profile(public=[])
    with pytest.raises(scope.OutOfScope, match="downloads.volatilityfoundation.org.*public_fetch_allow"):
        M.fetch_isf(*KERNEL)
    assert net == []
    use_profile(public=["downloads.volatilityfoundation.org"])
    path, note = M.fetch_isf(*KERNEL)
    assert path is None and "could not be fetched" in note
    assert net and all(x[0] == "urlopen" and x[1] == M.VOL_SYMBOLS for x in net)


def test_memory_fetch_isf_reuses_a_saved_pack_without_a_public_fetch(use_profile, net, monkeypatch, tmp_path):
    monkeypatch.setattr(M, "symbols_folder", lambda: tmp_path / "_symbols")
    pack = tmp_path / "_symbols" / f"{KERNEL[1]}-{KERNEL[2]}" / "windows.zip"
    pack.parent.mkdir(parents=True)
    pack.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    use_profile(public=[])
    assert M.fetch_isf(*KERNEL) == (pack, f"windows/{KERNEL[0]}/{KERNEL[1]}-{KERNEL[2]}.json.xz: already saved")
    assert net == []


def test_memory_vol_online_venv_needs_the_symbol_server_allowed(use_profile, net, tmp_path):
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 64)
    use_profile(public=[])
    with pytest.raises(scope.OutOfScope, match="msdl.microsoft.com"):
        M.vol(img, "windows.pslist", where="venv", online=True)
    with pytest.raises(scope.OutOfScope, match="msdl.microsoft.com"):
        M.vol_save(img, "windows", where="venv", online=True, say=lambda s: None)
    assert net == []
    rows, note = M.vol(img, "windows.pslist", where="venv", online=False)     # offline: no fetch, no check
    assert rows is None and net and "--offline" in net[-1][1]
    net.clear()
    use_profile(public=["msdl.microsoft.com"])
    M.vol(img, "windows.pslist", where="venv", online=True)
    assert net and net[-1][0] == "run" and "--offline" not in net[-1][1]


def test_memory_vol_save_refuses_before_reading_the_image_or_making_a_folder(use_profile, net, monkeypatch, tmp_path):
    """The --online venv refusal comes up front: before the image is opened and hashed, before the
    tables folder is made and before any plugin runs (vol() refusing per plugin is not enough)."""
    touched = []
    monkeypatch.setattr(M, "tables_root", lambda: touched.append("tables_root") or tmp_path / "_memory")
    monkeypatch.setattr(M, "vol", lambda *a, **k: touched.append("vol") or (None, "stub"))
    missing = tmp_path / "absent.raw"                    # opening it would raise FileNotFoundError
    use_profile(public=[])
    with pytest.raises(scope.OutOfScope, match="msdl.microsoft.com.*public_fetch_allow"):
        M.vol_save(missing, "windows", where="venv", online=True, say=lambda s: None)
    assert touched == [] and net == [] and not (tmp_path / "_memory").exists()
    img = tmp_path / "mem.raw"                           # allowed: it reads, makes the folder, runs plugins
    img.write_bytes(b"\x00" * 64)
    use_profile(public=["msdl.microsoft.com"])
    folder = M.vol_save(img, "windows", where="venv", online=True, plugins=["windows.pslist"], say=lambda s: None)
    assert folder.is_dir() and folder.name == M.fingerprint(b"\x00" * 64)
    assert touched == ["tables_root", "vol"]


def test_memory_cli_exits_2_on_a_refused_fetch(use_profile, net, tmp_path, capsys):
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\x00" * 64)
    use_profile(public=[])
    assert M.main([str(img), "--vol", "windows", "--where", "venv", "--online"]) == 2
    assert "memory.py: refused:" in capsys.readouterr().err and net == []


# ============================================== the modules that open no connection stay that way

NETWORK_MODULES = {"socket", "ssl", "http.client", "urllib.request", "requests", "httpx", "aiohttp",
                   "websocket", "websockets", "pwn", "pwnlib", "paramiko", "ftplib", "smtplib", "telnetlib",
                   "subprocess", "asyncio"}
NETWORK_CALLS = {"urlopen", "create_connection", "getaddrinfo", "open_connection"}


def network_uses(path: Path, seen=None) -> list:
    """Network imports and calls in `path` and in the sibling modules it imports (same folder)."""
    seen = set() if seen is None else seen
    if path in seen:
        return []
    seen.add(path)
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in NETWORK_CALLS:
                found.append(f"{path.name}:{node.lineno} call {name}")
        for n in names:
            if any(n == m or n.startswith(m + ".") for m in NETWORK_MODULES):
                found.append(f"{path.name}:{node.lineno} import {n}")
            sibling = path.parent / (n.split(".")[0] + ".py")
            if sibling.is_file():
                found += network_uses(sibling, seen)
    return found


def test_network_checker_catches_planted_network_code(tmp_path):
    (tmp_path / "helper.py").write_text("import urllib.request as u\n")
    (tmp_path / "a.py").write_text("import json\nfrom helper import u\n")
    (tmp_path / "b.py").write_text("x = s.create_connection(('h', 1))\n")
    (tmp_path / "c.py").write_text("from http.client import HTTPConnection\n")
    (tmp_path / "d.py").write_text("import re, zlib\nfrom urllib.parse import quote\n")
    assert network_uses(tmp_path / "a.py") == ["helper.py:1 import urllib.request"]
    assert network_uses(tmp_path / "b.py") == ["b.py:1 call create_connection"]
    assert network_uses(tmp_path / "c.py") == ["c.py:1 import http.client", "c.py:1 import http.client.HTTPConnection"]
    assert network_uses(tmp_path / "d.py") == []


@pytest.mark.parametrize("rel", ["solvers/mobile-android/mobile_depth.py", "solvers/toolkits/android_depth.py",
                                 "solvers/web/cache_analysis.py"])
def test_offline_modules_open_no_connection(rel):
    assert network_uses(REPO / rel) == []
