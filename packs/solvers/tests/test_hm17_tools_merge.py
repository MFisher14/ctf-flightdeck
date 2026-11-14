"""B-001 hand merge hm-17: tools/target.py, tools/vpn.py, tools/oob.py, tools/run.py (+ tools/archive_expand.py).

What the merge restored or moved, each checked here:
  * target.py refuses the event platform in code (exact host from the event config / platform URL,
    platform_words anywhere, URL-decoded), says whether an address is in the event VPN's ranges, and
    takes a platform adapter's base_of rule for ids that share a target (no timed rule in master).
  * vpn.py ensure does not bring the VPN up for an address outside the declared ranges; the profile
    name comes from $CTF_VPN_PROFILE or the event config, and is refused when neither names one.
  * oob.py picks the one utun tunnel address when the event config declares vpn_ranges, and refuses
    to guess without them.
  * run.py's expander lives in tools/archive_expand.py (importable without the Game Master client) and
    is re-exported; the attempt runner keeps the Huntress opener's env names and refuses loudly when
    its platform modules are missing.
Every fixture is synthetic; nothing connects, nothing reads .ctf/.
"""
import io
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import target  # noqa: E402
import vpn  # noqa: E402
import oob  # noqa: E402

PLATFORM_URL = "https://board.example-ctf.test"


@pytest.fixture(autouse=True)
def _event(monkeypatch, tmp_path):
    """A synthetic event config in place of ctf.config (never .ctf/config.json)."""
    for k in ("CTF_VPN_RANGES", "CTF_PLATFORM_URL", "CTF_VPN_PROFILE", "CTF_VPN_OSASCRIPT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    cfg = {}
    monkeypatch.setattr(target, "_event_config", lambda: (PLATFORM_URL, cfg))
    return cfg


def _policy(**cfg):
    return target.event_policy(dict(cfg))


# ------------------------------------------------------------------------------------------ target.py

def test_platform_url_host_is_refused_but_its_subdomain_is_filed(_event):
    with pytest.raises(ValueError, match="event platform"):
        target.parse("https://board.example-ctf.test/api")
    entry = target.parse("http://web-1.board.example-ctf.test:8080/x")
    assert entry["host"] == "web-1.board.example-ctf.test" and entry["port"] == 8080


def test_platform_hosts_and_words_from_the_event_config(_event):
    _event.update({"platform_hosts": ["10.0.0.219", "gm.example.test"],
                   "platform_words": ["10-0-0-219", "ctf-proxy"]})
    for addr in ("10.0.0.219:443", "gm.example.test", "nc 10.0.0.219 80"):
        with pytest.raises(ValueError, match="event platform"):
            target.parse(addr)
    with pytest.raises(ValueError, match="platform_words"):
        target.parse("http://10.1.2.3/%2563tf-proxy/a")        # double-encoded "ctf-proxy" in the path
    with pytest.raises(ValueError, match="platform_words"):
        target.parse("ip-10-0-0-219.example.test")
    assert target.parse("10.0.0.218")["host"] == "10.0.0.218"   # a neighbour of a platform host is filed


def test_vpn_flag_follows_declared_ranges_and_is_none_without(_event):
    assert target.parse("10.1.2.3:31337")["vpn"] is None       # no ranges declared: nothing said
    _event["vpn_ranges"] = ["10.1.0.0/16", "10.200.0.0/16"]
    assert target.parse("10.1.2.3:31337")["vpn"] is True
    assert target.parse("10.2.0.1")["vpn"] is False
    assert target.parse("host.example.test")["vpn"] is False   # a name is never resolved


def test_env_ranges_replace_the_config_and_bad_ranges_are_loud(_event, monkeypatch):
    _event["vpn_ranges"] = ["10.1.0.0/16"]
    monkeypatch.setenv("CTF_VPN_RANGES", "192.168.50.0/24")
    assert target.event_ranges() == ("192.168.50.0/24",)
    assert target.in_event_ranges("10.1.0.5") is False
    monkeypatch.delenv("CTF_VPN_RANGES")
    _event["vpn_ranges"] = ["10.1.0.0/16", "not-a-range"]
    with pytest.raises(ValueError, match="vpn_ranges"):
        target.event_ranges()
    _event["vpn_ranges"] = 5
    with pytest.raises(ValueError, match="vpn_ranges"):
        target.event_ranges()


def test_add_prints_the_range_hint(_event, capsys):
    _event["vpn_ranges"] = ["10.1.0.0/16"]
    assert target.main(["add", "web-a", "10.1.2.3:8080"]) == 0
    assert "inside the VPN's ranges: tools/vpn.py ensure 10.1.2.3:8080" in capsys.readouterr().out
    assert target.main(["add", "web-b", "172.20.0.4"]) == 0
    assert "outside the VPN's ranges" in capsys.readouterr().out
    assert target.main(["add", "web-c", PLATFORM_URL]) == 2
    assert "refused" in capsys.readouterr().err
    assert target.lookup("web-c") is None


def test_lookup_base_of_hook_and_no_timed_rule_in_master(_event):
    rows = {"metadata-7": {"address": "10.1.2.3", "url": None}}
    assert target.lookup("metadata-7/time_trial", rows=rows) is None
    strip = lambda cid: cid.split("/")[0]                      # noqa: E731  (an adapter's rule)
    hit = target.lookup("metadata-7/time_trial", rows=rows, base_of=strip)
    assert hit["key"] == "metadata-7" and hit["address"] == "10.1.2.3"
    lanes = {"web": {"address": "10.9.9.9"}}
    assert target.lookup("web-12/mastery", rows=lanes, base_of=strip)["key"] == "web"


# --------------------------------------------------------------------------------------------- vpn.py

class FakeTunnelblick:
    def __init__(self, st="EXITING"):
        self.st, self.calls = st, []

    def __call__(self, lines, timeout=None):
        text = " ".join(lines)
        self.calls.append(text)
        if " connect " in text:
            self.st = "CONNECTED"
            return 0, ""
        if "get state" in text:
            return 0, self.st
        return 0, ""


def test_ensure_refuses_outside_the_ranges_without_touching_the_vpn(_event, monkeypatch):
    _event["vpn_ranges"] = ["10.1.0.0/16"]
    monkeypatch.setenv("CTF_VPN_PROFILE", "event")
    tb = FakeTunnelblick()
    ok, line = vpn.ensure(target.parse("172.20.0.4:80"), wait=1, runner=tb, probe_fn=lambda h, p: "silent",
                          sleep=lambda s: None)
    assert not ok and "outside the event VPN's ranges (10.1.0.0/16)" in line
    assert not any(" connect " in c for c in tb.calls)


def test_ensure_connects_for_an_address_inside_the_ranges(_event, monkeypatch):
    _event["vpn_ranges"] = ["10.1.0.0/16"]
    monkeypatch.setenv("CTF_VPN_PROFILE", "event")
    tb = FakeTunnelblick()
    seen = iter(["silent", "open"])
    ok, line = vpn.ensure(target.parse("10.1.2.3:80"), wait=5, runner=tb, probe_fn=lambda h, p: next(seen),
                          sleep=lambda s: None)
    assert ok and line.startswith("VPN up: connected") and "10.1.2.3:80 answers" in line
    assert any('connect "event"' in c for c in tb.calls)


def test_vpn_profile_from_env_or_config_and_refused_when_unnamed(_event, monkeypatch):
    with pytest.raises(ValueError, match="no VPN profile named"):
        vpn.profile()
    _event["vpn_profile"] = "my event"
    assert vpn.profile() == "my event"
    monkeypatch.setenv("CTF_VPN_PROFILE", 'x"; do shell script "id')
    with pytest.raises(ValueError, match="not a plain profile name"):
        vpn.profile()


# --------------------------------------------------------------------------------------------- oob.py

IFACES = [("lo0", "127.0.0.1"), ("en0", "10.1.40.7"), ("utun4", "10.200.3.9"), ("utun2", "172.16.1.1")]


def test_oob_auto_detects_the_one_tunnel_when_ranges_are_declared():
    addr, notes = oob.choose_address(IFACES, None, ranges=("10.1.0.0/16", "10.200.0.0/16"))
    assert addr == "10.200.3.9" and notes == []                  # en0 in range is never the tunnel


def test_oob_refuses_without_ranges_and_without_a_tunnel():
    with pytest.raises(oob.Refused, match="declares no vpn_ranges"):
        oob.choose_address(IFACES, None, ranges=())
    with pytest.raises(oob.Refused, match="no utun interface.*10.1.40.7 on en0 is in the ranges"):
        oob.choose_address(IFACES, None, ranges=("10.1.0.0/16",))
    two = IFACES + [("utun7", "10.200.8.8")]
    with pytest.raises(oob.Refused, match="more than one tunnel address"):
        oob.choose_address(two, None, ranges=("10.200.0.0/16",))


def test_oob_bind_warns_off_tunnel_and_reads_ranges_from_the_event_config(_event):
    _event["vpn_ranges"] = ["10.200.0.0/16"]
    addr, notes = oob.choose_address(IFACES, "10.200.3.9")       # ranges read via target.py
    assert addr == "10.200.3.9" and notes == []
    addr, notes = oob.choose_address(IFACES, "10.1.40.7")
    assert addr == "10.1.40.7" and "not the event VPN tunnel" in notes[0]
    with pytest.raises(oob.Refused, match="wildcard"):
        oob.choose_address(IFACES, "0.0.0.0")
    assert oob.choose_address(IFACES)[0] == "10.200.3.9"


# --------------------------------------------------------------------------------------- run.py split

def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_archive_expand_imports_without_the_platform_client_and_expands_nested(tmp_path):
    inner = _zip({"flag.txt": b"inner-bytes"})
    outer = _zip({"inner.zip": inner, "readme.txt": b"r"})
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import archive_expand as ae\n"
        "out = {}; ae.expand('d.zip', open(sys.argv[2], 'rb').read(), out)\n"
        "assert 'gm' not in sys.modules and 'lanes' not in sys.modules, 'platform client imported'\n"
        "print(sorted(out))\n"
    )
    tmp = tmp_path / "outer.zip"
    tmp.write_bytes(outer)
    done = subprocess.run([sys.executable, "-I", "-c", code, str(TOOLS), str(tmp)],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "'inner.zip -> flag.txt'" in done.stdout and "'d.zip -> inner.zip'" in done.stdout


def test_run_reexports_the_expander_and_keeps_the_huntress_opener_env_names():
    import archive_expand
    import run
    for name in ("expand", "expand_7z", "Keys", "pw", "unwrap", "SEVENZ_MAGIC", "_collision_keys"):
        assert getattr(run, name) is getattr(archive_expand, name), name
    assert run.RFT_SUPPORTED == "CTF_RFT_SUPPORTED"
    assert run._TIMING_ENV == "CTF_TIMING_FILE"
    assert run.OWN_ATTEMPT == "CTF_OWN_ATTEMPT"
    assert run.PROBE413_MARK_ENV == "CTF_PROBE413_MARK"
    if run.lanes is None:                                        # no guessed timed-window budget
        assert run.SUBMIT_MARGIN is None and run.MIN_SOLVE_BUDGET is None and run.MIN_SOLVE_LEFT is None


def test_run_main_refuses_loudly_when_the_platform_modules_are_missing(monkeypatch):
    import run
    monkeypatch.setattr(run, "RUNNER_MISSING", ["tools/gm.py (the Game Master client): stand-in"])
    monkeypatch.setattr(sys, "argv", ["run.py", "some-id", "solver.py", "--offline"])
    with pytest.raises(SystemExit) as e:
        run.main()
    msg = str(e.value.code)
    assert "refused" in msg and "tools/gm.py" in msg and "Nothing was requested" in msg
