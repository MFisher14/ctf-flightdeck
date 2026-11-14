"""B-255: tools/oob.py's follow read, and the per-event reachability probe.

  * `hits --follow` takes what it prints and what it has seen from ONE read (HitTail): a hit logged
    while the first batch prints is printed by the follow (it used to be counted by a second read and
    lost), and a follow across midnight reads the new day's file from its first byte.
  * `oob.py reach` reports whether a target can reach the listener and never assumes it: CONFIRMED
    needs a callback carrying our token from an address that is not this Mac's since this listener
    started; the probe itself sends one request to this Mac's own listener and nothing to a target.
Every listener here is the real one, on 127.0.0.1, port 0; the "target" is this test.
"""
import json
import socket
import threading
import time
import types

import pytest

import oob

IFACES = [("lo0", "127.0.0.1"), ("en0", "192.168.1.20"), ("utun4", "10.200.3.9")]
RANGES = ("10.200.0.0/16",)


@pytest.fixture(autouse=True)
def _workdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", "huntress")
    return tmp_path


def _append(row, day=None):
    p = oob.hits_path(day)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


# ------------------------------------------------------------------------------------- the follow read

def test_hit_tail_returns_each_row_once_even_mid_write_and_across_midnight(monkeypatch):
    monkeypatch.setattr(oob, "today", lambda: "2026-11-11")
    tail = oob.HitTail()
    assert tail.read() == []                                   # no file yet: nothing, no error
    _append({"n": 1})
    assert [r["n"] for r in tail.read()] == [1]
    assert tail.read() == []                                   # nothing new: nothing twice
    p = oob.hits_path()
    with open(p, "a", encoding="utf-8") as fh:                 # a write still in progress
        fh.write('{"n": 2')
    assert tail.read() == []
    with open(p, "a", encoding="utf-8") as fh:
        fh.write('}\n{"n": 3}\n')
    assert [r["n"] for r in tail.read()] == [2, 3]
    monkeypatch.setattr(oob, "today", lambda: "2026-11-12")    # midnight: the new day's file
    _append({"n": 4})
    _append({"n": 5}, day="2026-11-11")                        # a late write to the old day still counts
    assert sorted(r["n"] for r in tail.read()) == [4, 5]
    p.write_text('{"n": 6}\n')                                 # the old file replaced (shorter): re-read
    assert [r["n"] for r in tail.read()] == [6]
    p.write_text('{"n":7}\n')                                  # replaced again, one byte shorter: re-read
    assert [r["n"] for r in tail.read()] == [7]


def test_hit_tail_every_reads_all_days_and_read_hits_filters_by_token():
    _append({"n": 1, "tokens": ["o000000000001"]}, day="2026-11-01")
    _append({"n": 2, "tokens": []}, day="2026-11-02")
    assert sorted(r["n"] for r in oob.HitTail(every=True).read()) == [1, 2]
    assert [r["n"] for r in oob.read_hits("o000000000001", every=True)] == [1]
    assert oob.read_hits("o000000000001") == []                 # today only by default


def test_hits_follow_prints_a_hit_logged_while_the_first_batch_prints(monkeypatch, capsys):
    """The race of row 380: the old cmd_hits printed read #1, then took `seen` from read #2, so a hit
    logged between them was never printed. Here the second hit is logged while the first prints."""
    tok = "o0123456789ab"
    _append({"time": "t1", "kind": "http", "peer": "10.200.7.7:1", "method": "GET", "path": f"/{tok}/a",
             "tokens": [tok], "labels": ["x"]})
    real_show, calls = oob.show, []

    def show(r):
        calls.append(r["path"])
        if len(calls) == 1:                                    # a hit lands mid-print
            _append({"time": "t2", "kind": "http", "peer": "10.200.7.7:2", "method": "GET",
                     "path": f"/{tok}/b", "tokens": [tok], "labels": ["x"]})
            _append({"time": "t3", "kind": "http", "peer": "10.200.7.7:3", "method": "GET",
                     "path": "/other", "tokens": [], "labels": []})
        return real_show(r)

    monkeypatch.setattr(oob, "show", show)
    assert oob.main(["hits", "--token", tok, "--follow", "1"]) == 0
    out = capsys.readouterr().out
    assert out.count(f"/{tok}/a") == 1 and out.count(f"/{tok}/b") == 1
    assert "/other" not in out                                 # the token filter holds in the follow


# --------------------------------------------------------------------------------- reachability (pure)

def _hit(origin, *, epoch=200.0, tokens=("o0123456789ab",), labels=("reach-probe huntress",), headers=(),
         kind="http", real_peer=None, body=None):
    r = {"kind": kind, "epoch": epoch, "time": "t", "peer": f"{origin}:5555", "tokens": list(tokens),
         "labels": list(labels), "headers": [list(h) for h in headers]}
    if real_peer:
        r["real_peer"] = real_peer
    if body is not None:
        r["body"] = body
    return r


TUNNEL = {"pid": 1, "bind": "10.200.3.9", "port": 8380, "tcp_port": 8381, "started": 100.0}


def _rep(st, rows=(), **kw):
    kw.setdefault("local", ("ok", "answers"))
    return oob.reachability(st, IFACES, RANGES, list(rows), **kw)


def test_reach_is_unusable_without_a_listener_or_on_loopback_or_when_it_does_not_answer():
    assert _rep({})["verdict"] == "unusable"
    assert _rep({}, [_hit("10.200.7.7")])["earlier_callbacks"] == 1
    lo = dict(TUNNEL, bind="127.0.0.1")
    rep = _rep(lo)
    assert rep["verdict"] == "unusable" and not rep["usable"]
    assert any(c["check"] == "route" and c["status"] == "no" for c in rep["checks"])
    assert _rep(TUNNEL, local=("no", "refused"))["verdict"] == "unusable"
    assert oob.REACH_EXIT["unusable"] == 1


def test_reach_never_assumes_a_route_it_cannot_see():
    assert _rep(TUNNEL)["verdict"] == "plausible"                          # the tunnel, no target named
    assert _rep(TUNNEL, target="10.200.9.9")["verdict"] == "plausible"     # target inside the ranges
    for target in ("10.9.9.9", "web.huntress.example"):                    # outside / a name never resolved
        rep = _rep(TUNNEL, target=target)
        assert rep["verdict"] == "unproven" and not rep["usable"], target
    assert _rep(dict(TUNNEL, bind="192.168.1.20"))["verdict"] == "unproven"   # a LAN address, not the tunnel
    # an address inside the VPN ranges, but on a non-utun interface, is not the tunnel either
    en = [("lo0", "127.0.0.1"), ("en1", "10.200.3.9")]
    rep = oob.reachability(TUNNEL, en, RANGES, [], local=("ok", ""))
    assert rep["verdict"] == "unproven"
    assert "on en1 is not the event VPN tunnel" in {c["check"]: c["why"] for c in rep["checks"]}["route"]
    assert oob.reachability(TUNNEL, IFACES, (), [], local=("ok", ""))["verdict"] == "unproven"   # no ranges
    assert _rep(TUNNEL, local=None)["verdict"] == "unproven"               # local not checked: not plausible
    rep = _rep(TUNNEL, firewall="Firewall is enabled. (State = 1)")
    assert any(c["check"] == "firewall" for c in rep["checks"])
    assert oob.REACH_EXIT["plausible"] == oob.REACH_EXIT["unproven"] == 3


def test_reach_is_confirmed_only_by_a_target_callback_carrying_our_token_since_this_listener_started():
    good = _hit("10.200.7.7")
    rep = _rep(TUNNEL, [good], target="10.200.7.7")
    assert rep["verdict"] == "confirmed" and rep["usable"] and oob.REACH_EXIT["confirmed"] == 0
    assert rep["callbacks"][0]["origin"] == "10.200.7.7" and rep["callbacks"][0]["from_target"] is True
    other = _rep(TUNNEL, [good], target="10.200.8.8")     # a callback, but not from the named target
    assert other["callbacks"][0]["from_target"] is False
    assert other["verdict"] == "plausible" and not other["usable"]
    assert "none from the target 10.200.8.8 (from 10.200.7.7)" in {c["check"]: c["why"] for c in other["checks"]}["callback"]
    both = _rep(TUNNEL, [good, _hit("10.200.8.8")], target="10.200.8.8")
    assert both["verdict"] == "confirmed" and len(both["callbacks"]) == 2
    not_proof = [
        _hit("10.200.7.7", epoch=50.0),                                    # before this listener started
        _hit("10.200.7.7", tokens=()),                                     # unattributed (a scanner)
        _hit("10.200.3.9"),                                                # this Mac's own address
        _hit("127.0.0.1"),                                                 # loopback, no real_peer
        _hit("10.200.7.7", headers=[("X-Oob-Selftest", "1")]),             # our own selftest
        _hit("10.200.7.7", labels=("selftest",)),                          # a selftest token
        _hit("10.200.7.7", kind="tcp", body="selftest o0123456789ab\n"),   # the TCP selftest line
        _hit("not-an-address"),
    ]
    for row in not_proof:
        rep = _rep(TUNNEL, [row])
        assert rep["verdict"] == "plausible", row
    assert _rep(TUNNEL, [not_proof[0]])["earlier_callbacks"] == 1
    # behind a quick tunnel the origin is the real_peer cloudflared reports
    pub = {"pid": 1, "bind": "127.0.0.1", "port": 8380, "public": True, "started": 100.0,
           "public_url": "https://abc-def.trycloudflare.com"}
    assert _rep(pub)["verdict"] == "plausible"
    assert _rep(pub, [_hit("127.0.0.1", real_peer="203.0.113.5")])["verdict"] == "confirmed"
    # this Mac's own public egress, as its selftest through the tunnel showed it, is never a target:
    # the player's own curl to a minted token (no selftest header) arrives from that address
    own_selftest = _hit("127.0.0.1", real_peer="198.51.100.77", headers=[("X-Oob-Selftest", "public")],
                        labels=("selftest",), epoch=20.0)
    players_curl = _hit("127.0.0.1", real_peer="198.51.100.77", labels=("challenge web",))
    assert oob.own_egress([own_selftest, players_curl]) == {"198.51.100.77"}
    assert _rep(pub, [own_selftest, players_curl])["verdict"] == "plausible"
    assert _rep(pub, [players_curl])["verdict"] == "confirmed"         # without the selftest, it cannot tell
    # a callback from a target outranks an unknown route
    assert _rep(dict(TUNNEL, bind="192.168.1.20"), [good])["verdict"] == "confirmed"


def test_reach_report_must_exist_and_be_readable():
    with pytest.raises(oob.Refused, match="run oob.py reach"):
        oob.reach_report()
    oob.reach_path().parent.mkdir(parents=True, exist_ok=True)
    oob.reach_path().write_text('{"verdict": "maybe"}')
    with pytest.raises(oob.Refused, match="unreadable"):
        oob.reach_report()


# ------------------------------------------------------------------------------ reachability (real listener)

@pytest.fixture
def listener(monkeypatch):
    """The real collector on 127.0.0.1:<ephemeral>, in a thread, standing in for `oob.py up --public`
    (the state claims a quick tunnel so a loopback hit with CF-Connecting-IP is a target callback)."""
    stop, ready = threading.Event(), []
    th = threading.Thread(target=oob.serve, args=("127.0.0.1", 0, None, time.time() + 300),
                          kwargs={"write_state": False, "stop": stop, "ready": ready}, daemon=True)
    th.start()
    for _ in range(200):
        if ready:
            break
        stop.wait(0.05)
    assert ready, "the listener did not start"
    port = ready[0][0]
    st = {"pid": 1, "bind": "127.0.0.1", "port": port, "tcp_port": None, "public": True,
          "public_url": "https://abc-def.trycloudflare.com", "started": time.time() - 1}
    monkeypatch.setattr(oob, "running", lambda: st)
    monkeypatch.setattr(oob, "interfaces", lambda text=None: IFACES)
    monkeypatch.setattr(oob, "event_ranges", lambda: RANGES)
    monkeypatch.setattr(oob, "firewall_state", lambda: "")
    conns = []
    real_cc = socket.create_connection

    def cc(addr, *a, **k):
        conns.append(addr[0])
        return real_cc(addr, *a, **k)

    monkeypatch.setattr(oob.socket, "create_connection", cc)
    yield types.SimpleNamespace(port=port, st=st, conns=conns)
    stop.set()
    th.join(10)


def _callback(port, path, origin):
    """The 'target': a request arriving through cloudflared (loopback hop, CF-Connecting-IP)."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: abc-def.trycloudflare.com\r\nCF-Connecting-IP: {origin}\r\n\r\n".encode())
        s.recv(64)


def test_reach_with_a_live_listener_is_plausible_then_confirmed_and_saved_per_event(listener, capsys):
    assert oob.main(["reach", "--target", "203.0.113.5", "--json"]) == 3
    rep = json.loads(capsys.readouterr().out)
    assert rep["verdict"] == "plausible" and rep["event"] == "huntress"
    assert {c["check"]: c["status"] for c in rep["checks"]}["local"] == "ok"
    tok = rep["token"]
    assert oob.TOKEN.fullmatch(tok) and rep["probe_url"] == f"https://abc-def.trycloudflare.com/{tok}/reach"
    assert oob.reach_report()["verdict"] == "plausible"
    # the probe's own local request is logged but never counts as a target
    assert any(oob._header(r, "X-Oob-Selftest") == "reach" for r in oob.read_hits(tok))
    assert listener.conns and set(listener.conns) == {"127.0.0.1"}            # nothing went to the target
    _callback(listener.port, f"/{tok}/reach", "203.0.113.5")
    for _ in range(100):
        if any(r.get("real_peer") == "203.0.113.5" for r in oob.read_hits(tok)):
            break
        time.sleep(0.05)
    assert oob.main(["reach", "--target", "203.0.113.5"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("REACH CONFIRMED event=huntress") and "from 203.0.113.5" in out
    saved = oob.reach_report()
    assert saved["verdict"] == "confirmed" and saved["usable"] and saved["token"] == tok   # the token is reused


def test_reach_wait_catches_a_callback_that_arrives_while_it_waits(listener, monkeypatch, capsys):
    oob.main(["reach", "--json"])
    tok = json.loads(capsys.readouterr().out)["token"]
    fired = []
    real_time = time

    def sleep(s):
        if s == 0.5 and not fired:                     # the --wait loop's first pause
            fired.append(1)
            _callback(listener.port, f"/{tok}/reach", "198.51.100.9")
        real_time.sleep(min(s, 0.2))

    monkeypatch.setattr(oob, "time", types.SimpleNamespace(time=real_time.time, monotonic=real_time.monotonic,
                                                           sleep=sleep))
    assert oob.main(["reach", "--wait", "20"]) == 0
    assert fired == [1]
    assert "REACH CONFIRMED" in capsys.readouterr().out


def test_reach_without_a_listener_is_unusable_and_connects_nowhere(monkeypatch, capsys):
    monkeypatch.setattr(oob, "running", lambda: {})
    monkeypatch.setattr(oob, "interfaces", lambda text=None: IFACES)
    monkeypatch.setattr(oob, "event_ranges", lambda: RANGES)
    monkeypatch.setattr(oob, "firewall_state", lambda: "")
    monkeypatch.setattr(oob.socket, "create_connection", lambda *a, **k: pytest.fail("no connection expected"))
    assert oob.main(["reach", "--target", "10.200.7.7"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("REACH UNUSABLE") and "the listener is not up" in out
    assert oob.reach_report()["verdict"] == "unusable"
