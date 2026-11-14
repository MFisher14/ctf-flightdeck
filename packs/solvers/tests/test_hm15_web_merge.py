"""hm-15 hand-merge of solvers/toolkits/web.py (Huntress + CSCTF).

Pins the behaviour the merge decision names: flag detection follows the shared flag spec (not a
hard-coded CSCTF regex), the Game Master refusal and target_from_file are restored, and the
Huntress event-pack entries (/api/clues, the objective file) sit beside the CSCTF ones.
No network: WebClient construction sends nothing, and the GM refusal fires before any request.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env, event, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env, event, flagfmt

REPO = Path(__file__).resolve().parent.parent


def _load_web():
    spec = importlib.util.spec_from_file_location("hm15_toolkit_web", REPO / "solvers" / "toolkits" / "web.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def web(monkeypatch):
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    return _load_web()


def test_flag_format_comes_from_the_event_profile(web, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert web.flag_re().pattern == flagfmt.current().pattern
    assert web.find_flags(b"x CSCTF{a_b} y flag{c} z") == {"CSCTF{a_b}", "flag{c}"}
    assert web.is_flag("CSCTF{ok}") and not web.is_flag("CSCTF{ok} trailing")
    assert not web.is_flag("PINK{x}")


def test_flag_format_follows_the_active_event(web, monkeypatch):
    # The old hard-coded CSCTF regex matched nothing on PINK{...}/spooky{...} events.
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert web.find_flags("a PINK{one} b CSCTF{two}") == {"PINK{one}"}
    assert web.is_flag("PINK{one}") and not web.is_flag("CSCTF{two}")
    monkeypatch.setenv("CTF_EVENT", "spooky")
    assert web.find_flags("SPOOKY{boo} CSCTF{x}") == {"SPOOKY{boo}"}


def test_no_environment_override_and_no_event_fails_loudly(web, monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    with pytest.raises(event.EventError, match="CTF_EVENT"):
        web.find_flags("x")


def test_game_master_is_refused(web, monkeypatch):
    # B-001c: a past event's platform is outside the current profile's live_service_scope.
    with pytest.raises(web.OutOfScope, match="live_service_scope"):
        web.WebClient("https://2026.huntress.ctf.games/")
    with pytest.raises(web.OutOfScope, match="live_service_scope"):
        web.WebClient("https://2026.huntress.ctf.games./api")
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    monkeypatch.setenv(env.legacy_names("CTF_PLATFORM_URL")[1], "http://198.51.100.7:8080/")   # legacy spelling, mapped by ctf.env
    with pytest.warns(DeprecationWarning), pytest.raises(web.OutOfScope, match="event platform"):
        web.WebClient("http://198.51.100.7:8080/")
    # same host, other port: an ordinary target
    with pytest.warns(DeprecationWarning):
        c = web.WebClient("http://198.51.100.7:8081/")
    assert c.base.startswith("http://198.51.100.7:8081")


def test_smuggling_probe_refuses_game_master(web, monkeypatch):
    cls = next(v for k, v in vars(web).items()
               if isinstance(v, type) and "send_raw" in vars(v))
    with pytest.raises(web.OutOfScope, match="live_service_scope"):
        cls("2026.huntress.ctf.games", 443, use_tls=True)
    for name in env.legacy_names("CTF_PLATFORM_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://gm.example-event.test/")
    with pytest.raises(web.OutOfScope, match="event platform"):
        cls("gm.example-event.test", 443, use_tls=True)


def test_target_from_file_and_target_for_order(web, monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    tools = str(REPO / "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import target as target_mod
    (tmp_path / target_mod.FILE).write_text(json.dumps({"targets": {
        "web-day-09-shop": {"url": "http://10.1.2.3:8080/app", "address": "10.1.2.3:8080"},
        "pwn": {"address": "10.200.4.5:31337"},
    }}))
    assert web.target_from_file("web-day-09-shop") == "http://10.1.2.3:8080/app"
    assert web.target_from_file("pwn-day-09-stack") == "http://10.200.4.5:31337/"
    assert web.target_from_file("osint-x") is None
    assert web.target_from_file({"id": "web-day-09-shop"}) == "http://10.1.2.3:8080/app"
    # attempt URL first, then the challenge dict's own URL, then the filed one
    assert web.target_for("web-day-09-shop", {"target": "http://10.9.9.9/"}) == "http://10.9.9.9/"
    assert web.target_for({"id": "web-day-09-shop", "url": "http://10.8.8.8/"}) == "http://10.8.8.8/"
    assert web.target_for("web-day-09-shop") == "http://10.1.2.3:8080/app"


def test_event_pack_entries_kept_beside_generic(web):
    assert "/api/clues" in web.COMMON_PATHS and "/api/notes" in web.COMMON_PATHS
    ladder = list(web.SSRF_LADDER)
    for u in ("file:///flag", "file:///flag.txt", "file:///run/huntress/objective.txt"):
        assert u in ladder
    assert len(ladder) == len(set(ladder))
