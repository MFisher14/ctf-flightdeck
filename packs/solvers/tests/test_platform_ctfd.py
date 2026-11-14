"""B-005: CTFd adapter contract tests against hand-written recorded fixtures (no live calls)."""
from __future__ import annotations

import datetime

import pytest

from ctf import env, event
from ctf.platform import (NotAllowed, NotSupported, PlatformError, SubmitStatus, get_adapter,
                          supports_instances)
from ctf.platform import ctfd
from ctf.platform.base import InstancesUnavailable, PlatformAdapter
from platform_fixture_session import FakeSession, load

FX = load("ctfd_api.json")
BASE = FX["base_url"]
ATTEMPT = BASE + "/api/v1/challenges/attempt"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make(tmp_path, clock):
    def _make(token="tok-test-value", cookie=None, instances=None, anon=None, **kw):
        s = FakeSession(FX["routes"])
        anon = anon if anon is not None else FakeSession(FX["routes"])
        cls_kw = dict(token=token, cookie=cookie, session=s, anon_session=anon,
                      pacer_state_dir=tmp_path / "pace", sleep=clock.sleep, clock=clock, **kw)
        if instances is not None:
            a = ctfd.CTFdInstanceAdapter(BASE, instances=instances, **cls_kw)
        else:
            a = ctfd.CTFdAdapter(BASE, **cls_kw)
        return a, s, anon
    return _make


def test_adapter_implements_the_protocol(make):
    a, _, _ = make()
    assert isinstance(a, PlatformAdapter) and a.kind == "ctfd"
    assert not supports_instances(a)


def test_list_challenges_maps_fields_and_sends_token(make):
    a, s, _ = make()
    chs = a.list_challenges()
    assert [c.id for c in chs] == ["1", "2", "3"]
    assert (chs[0].name, chs[0].category, chs[0].points, chs[0].tags) == ("Warm Up", "Web", 100, ("easy",))
    assert chs[1].solved_by_team and not chs[0].solved_by_team
    assert chs[2].tags == ("remote",)
    call = s.calls[0]
    assert call["headers"]["Authorization"] == "Token tok-test-value"


def test_get_challenge_maps_detail(make):
    a, _, _ = make()
    ch = a.get_challenge("1")
    assert ch.description == "Find the flag in the archive."
    assert ch.connection_info == "nc warmup.ctf.example 31337"
    assert [f.name for f in ch.files] == ["chall.zip", "notes v2.txt"]
    assert ch.raw["hints"][0]["cost"] == 50


def test_non_integer_id_is_refused_without_a_request(make):
    a, s, _ = make()
    with pytest.raises(PlatformError, match="integers"):
        a.get_challenge("abc")
    assert s.calls == []


def test_download_files_keeps_credentials_on_the_platform_host(make, tmp_path):
    a, s, anon = make()
    out = a.download_files("1", tmp_path / "dl")
    assert [p.name for p in out] == ["chall.zip", "notes v2.txt"]
    assert out[0].read_bytes() == b"PK\x03\x04hello"
    assert out[1].read_text() == "notes from the object store\n"
    on_host = s.sent("GET", BASE + "/files/0a1b2c/chall.zip")
    assert on_host and on_host[0]["headers"]["Authorization"].startswith("Token ")
    # The object-store link went through the credential-free session, never the platform one.
    assert not any("cdn.other.example" in c["url"] for c in s.calls)
    assert anon.calls and all("Authorization" not in c["headers"] for c in anon.calls)


def test_download_failure_names_the_file(make, tmp_path):
    a, s, _ = make()
    s.add({"method": "GET", "url": BASE + "/files/0a1b2c/chall.zip", "status": 404, "text": "nope"})
    with pytest.raises(PlatformError, match=r"chall.zip of challenge 1 -> HTTP 404"):
        a.download_files("1", tmp_path / "dl")


@pytest.mark.parametrize("cid, flag, status, judged", [
    ("1", "CSCTF{right}", SubmitStatus.CORRECT, True),
    ("1", "CSCTF{wrong}", SubmitStatus.INCORRECT, True),
    ("2", "CSCTF{again}", SubmitStatus.ALREADY_SOLVED, True),
    ("3", "CSCTF{fast}", SubmitStatus.RATE_LIMITED, False),
    ("3", "CSCTF{proxy}", SubmitStatus.RATE_LIMITED, False),
    ("4", "CSCTF{paused}", SubmitStatus.PAUSED, False),
    ("5", "CSCTF{late}", SubmitStatus.NOT_ALLOWED, False),
    ("6", "CSCTF{anon}", SubmitStatus.NOT_ALLOWED, False),
])
def test_submit_verdicts(make, cid, flag, status, judged):
    a, s, _ = make()
    res = a.submit(cid, flag)
    assert res.status is status and res.status.judged is judged and res.sent
    assert s.sent("POST", ATTEMPT)[0]["json"] == {"challenge_id": int(cid), "submission": flag}


def test_rate_limit_carries_retry_after(make):
    a, _, _ = make()
    assert a.submit("3", "CSCTF{fast}").retry_after == 30.0
    assert a.submit("3", "CSCTF{proxy}").retry_after is None


def test_unknown_verdict_and_http_error_are_platform_errors(make):
    a, _, _ = make()
    with pytest.raises(PlatformError, match="'partial'.*not a CTFd verdict"):
        a.submit("7", "CSCTF{odd}")
    with pytest.raises(PlatformError, match="HTTP 404"):
        a.submit("8", "CSCTF{gone}")


def test_submits_are_paced_machine_wide(make, clock):
    a, _, _ = make()
    a.submit("1", "CSCTF{wrong}")
    assert clock.slept == []
    a.submit("1", "CSCTF{wrong}")
    assert clock.slept and abs(sum(clock.slept) - ctfd.DEFAULT_SUBMIT_INTERVAL_S) < 1e-6


def test_rate_limit_pauses_the_next_submit(make, clock):
    a, _, _ = make()
    a.submit("3", "CSCTF{fast}")
    clock.t += 5
    a.submit("1", "CSCTF{right}")
    assert sum(clock.slept) >= 20.0 - 5 - 1e-6     # the carried shared pause after a rate limit


@pytest.mark.parametrize("path", ["/unlocks", "/hints/3", "/hints/3/"])
def test_hint_unlocks_are_refused_before_any_request(make, path):
    a, s, _ = make()
    with pytest.raises(NotAllowed, match="paid hint"):
        a._call("GET", path, "hint")
    assert s.calls == []


def test_listing_hints_is_not_a_spend(make):
    with pytest.raises(AssertionError, match="no fixture route"):   # reached the wire: not refused
        make()[0]._call("GET", "/hints", "hint")


def test_no_credentials_fails_loudly_without_a_request(make):
    a, s, _ = make(token=None)
    with pytest.raises(PlatformError, match="CTF_TOKEN.*CTF_COOKIE"):
        a.list_challenges()
    assert s.calls == []


def test_cookie_auth_reads_csrf_nonce_before_a_post(make):
    a, s, _ = make(token=None, cookie="sess-cookie")
    assert s.cookies["session"] == "sess-cookie"
    a.list_challenges()
    assert not s.sent("GET", BASE + "/")          # a read needs no nonce
    a.submit("1", "CSCTF{right}")
    assert s.sent("GET", BASE + "/")
    post = s.sent("POST", ATTEMPT)[0]
    assert post["headers"]["CSRF-Token"] == "9f3c2a" and "Authorization" not in post["headers"]


def test_cookie_auth_without_nonce_fails(make):
    a, s, _ = make(token=None, cookie="sess-cookie")
    s.add({"method": "GET", "url": BASE + "/", "status": 200, "text": "<html>login</html>"})
    with pytest.raises(PlatformError, match="csrfNonce"):
        a.submit("1", "CSCTF{right}")
    assert not s.sent("POST", ATTEMPT)


def test_team_solves_teams_mode(make):
    a, _, _ = make()
    [solve] = a.team_solves()
    assert (solve.challenge_id, solve.solver) == ("2", "alice")
    want = datetime.datetime(2026, 11, 6, 13, 5, tzinfo=datetime.timezone.utc).timestamp()
    assert solve.at == want


def test_team_solves_falls_back_to_users_mode(make):
    a, s, _ = make()
    s.add({"method": "GET", "url": BASE + "/api/v1/teams/me/solves", "status": 403,
           "body": {"success": False, "message": "teams mode is off"}})
    [solve] = a.team_solves()
    assert (solve.challenge_id, solve.solver) == ("1", "solo")


def test_team_solves_server_error_is_not_masked(make):
    a, s, _ = make()
    s.add({"method": "GET", "url": BASE + "/api/v1/teams/me/solves", "status": 500, "text": "boom"})
    with pytest.raises(PlatformError, match="HTTP 500"):
        a.team_solves()
    assert not s.sent("GET", BASE + "/api/v1/users/me/solves")


def test_scoreboard(make):
    a, _, _ = make()
    rows = a.scoreboard()
    assert [(r.rank, r.team, r.score) for r in rows] == [(1, "top-team", 1200), (2, "our-team", 982)]


def test_non_json_answer_is_a_platform_error(make):
    a, s, _ = make()
    s.add({"method": "GET", "url": BASE + "/api/v1/challenges", "status": 200, "text": "<html>login</html>"})
    with pytest.raises(PlatformError, match="list_challenges.*non-JSON"):
        a.list_challenges()


def test_success_false_is_a_platform_error(make):
    a, s, _ = make()
    s.add({"method": "GET", "url": BASE + "/api/v1/scoreboard", "status": 200,
           "body": {"success": False, "errors": ["scoreboard hidden"]}})
    with pytest.raises(PlatformError, match="scoreboard hidden"):
        a.scoreboard()


def test_plain_adapter_names_the_instance_seam(make):
    a, _, _ = make()
    with pytest.raises(InstancesUnavailable, match="B-003") as e:
        a.start_instance("1")
    assert isinstance(e.value, NotSupported)
    assert not hasattr(a, "stop_instance")


# ------------------------------------------------------------------------------- container plugins

DOCKER_PER_TEAM = {"endpoints": {"plugin": "docker_per_team"}, "cap": 3}


def test_docker_per_team_start_status_stop(make, clock):
    a, s, _ = make(instances=DOCKER_PER_TEAM)
    assert supports_instances(a)
    info = a.start_instance("1")
    assert (info.state, info.connection_info) == ("running", "inst.ctf.example:31337")
    assert info.expires_at == pytest.approx(clock.t + 3600)
    req = s.sent("POST", BASE + "/containers/api/request")[0]
    assert req["json"] == {"chal_id": 1} and req["headers"]["Authorization"].startswith("Token ")
    assert a.instance_status("1").expires_at == pytest.approx(clock.t + 1800)
    assert a.stop_instance("1").state == "stopped"
    assert s.sent("POST", BASE + "/containers/api/stop")


def test_plugin_refusal_takes_no_slot(make):
    a, s, _ = make(instances={"endpoints": {"plugin": "docker_per_team"}, "cap": 1})
    with pytest.raises(PlatformError, match="Max containers"):
        a.start_instance("2")
    assert a.start_instance("1").state == "running"     # the cap of 1 was not consumed by the refusal


def test_instance_scope_lock_refuses_unlisted_challenge(make):
    a, s, _ = make(instances=DOCKER_PER_TEAM)
    with pytest.raises(PlatformError, match="scope lock"):
        a.start_instance("99")
    assert not s.sent("POST", BASE + "/containers/api/request")


def test_instance_local_cap(make):
    a, s, _ = make(instances={"endpoints": {"plugin": "docker_per_team"}, "cap": 1})
    a.start_instance("1")
    with pytest.raises(PlatformError, match="instance cap"):
        a.start_instance("3")


def test_ctfd_docker_template_shape_lives_under_the_api(make):
    a, s, _ = make(instances={"endpoints": {"plugin": "ctfd_docker"}, "cap": None})
    assert a.start_instance("3").connection_info == "10.0.0.9:4444"
    url = BASE + "/api/v1/plugins/ctfd-docker/container"
    assert s.sent("POST", url)[0]["params"] == {"challenge_id": "3"} and s.sent("POST", url)[0]["json"] is None
    assert a.instance_status("3").state == "running"
    assert a.stop_instance("3").state == "stopped"
    assert s.sent("DELETE", url)


def test_instance_config_is_validated(make):
    with pytest.raises(PlatformError, match="cap"):
        make(instances={"endpoints": {"plugin": "docker_per_team"}})
    with pytest.raises(PlatformError, match="unknown instance plugin"):
        make(instances={"endpoints": {"plugin": "nope"}, "cap": 1})


# ------------------------------------------------------------------------------- selection + gate

@pytest.fixture
def wired(monkeypatch, tmp_path):
    """get_adapter() on the csctf profile with requests.Session replaced by the fixture session."""
    import requests
    s = FakeSession([dict(r, url=r["url"].replace(BASE, "https://2026.ctf-platform.example"))
                     for r in FX["routes"]])
    monkeypatch.setattr(requests, "Session", lambda: s)
    monkeypatch.setenv("CTF_TOKEN", "tok-from-env")
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL"), "CTF_COOKIE", *env.legacy_names("CTF_COOKIE")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_SUBMIT_STATE_DIR", str(tmp_path / "pace"))
    return s


def test_get_adapter_selects_ctfd_and_gates_submit(wired):
    gate = get_adapter(event.load("csctf"))
    assert gate.kind == "ctfd" and isinstance(gate._adapter, ctfd.CTFdAdapter)
    assert [c.id for c in gate.list_challenges()] == ["1", "2", "3"]
    assert wired.calls[0]["headers"]["Authorization"] == "Token tok-from-env"
    refused = gate.submit("1", "not a flag", provenance="p")
    assert refused.status is SubmitStatus.NOT_ALLOWED and not refused.sent
    assert not wired.sent("POST")
    assert gate.submit("1", "CSCTF{right}", provenance="strings on the archive").accepted
    assert len(wired.sent("POST")) == 1


def test_get_adapter_instance_calls_name_the_seam(wired):
    gate = get_adapter(event.load("csctf"))
    assert not supports_instances(gate._adapter)
    with pytest.raises(InstancesUnavailable, match="B-003"):
        gate.start_instance("1")


def test_platform_url_override_must_match_profile(wired, monkeypatch):
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://elsewhere.example")
    with pytest.raises(PlatformError, match="CTF_PLATFORM_URL.*differs"):
        get_adapter(event.load("csctf"))


def test_token_with_a_line_break_is_refused_without_echo(wired, monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "abc\ndef-secret")
    with pytest.raises(PlatformError) as e:
        get_adapter(event.load("csctf"))
    assert "def-secret" not in str(e.value) and "CTF_TOKEN" in str(e.value)


def test_make_adapter_refuses_wrong_kind():
    with pytest.raises(PlatformError, match="gamemaster"):
        ctfd.make_adapter(event.load("huntress"))
