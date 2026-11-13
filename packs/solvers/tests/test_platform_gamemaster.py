"""B-005: Game Master adapter contract tests against hand-written recorded fixtures (no live calls)."""
from __future__ import annotations

import datetime

import pytest

from ctf import env, event
from ctf.platform import (NotAllowed, NotSupported, PlatformError, SubmitStatus, get_adapter,
                          supports_instances)
from ctf.platform import gamemaster
from ctf.platform.base import PlatformAdapter

from platform_fixture_session import FakeSession, load

_HUNTRESS_TOKEN_SPELLING = env.legacy_names("CTF_TOKEN")[1]   # Huntress's old token variable

FX = load("gamemaster_api.json")
GM = FX["base_url"]


@pytest.fixture
def make():
    def _make(token="gm-test-token", base=GM):
        routes = [dict(r, url=r["url"].replace(GM, base)) for r in FX["routes"]]
        s = FakeSession(routes)
        return gamemaster.GameMasterAdapter(base, token=token, session=s), s
    return _make


def posts(s):
    return s.sent("POST")


def test_protocol_and_instances(make):
    a, _ = make()
    assert isinstance(a, PlatformAdapter) and a.kind == "gamemaster"
    assert supports_instances(a)


def test_list_challenges_maps_rows_and_sends_bearer(make):
    a, s = make()
    chs = {c.id: c for c in a.list_challenges()}
    assert chs["metadata-day-01"].category == "metadata"
    assert chs["metadata-day-01"].tags == ("single_solve", "day-1")
    assert chs["binary-day-02"].solved_by_team and not chs["metadata-day-01"].solved_by_team
    assert chs["mobile-day-04/mastery"].tags == ("mastery", "day-4")
    assert s.calls[0]["headers"]["Authorization"] == "Bearer gm-test-token"
    assert s.calls[0]["params"] == {"op": "list", "all": "true"}


@pytest.mark.parametrize("token", [None, "gm-test-token"])
def test_loopback_rehearsal_sends_no_bearer_and_needs_no_token(make, token):
    a, s = make(token=token, base="http://127.0.0.1:8765/")
    assert a.loopback
    assert a.list_challenges()
    assert "Authorization" not in s.calls[0]["headers"]


def test_loopback_profile_never_reads_the_token(tmp_path, monkeypatch):
    src = event.load("huntress").path.read_text().replace(
        'base_url = "https://gamemaster.huntress.example"', 'base_url = "http://127.0.0.1:8765"')
    (tmp_path / "huntress").mkdir()
    (tmp_path / "huntress" / "event.toml").write_text(src)
    prof = event.load("huntress", root=tmp_path)
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL"), *env.legacy_names("CTF_TOKEN")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_TOKEN", "bad\ntoken")      # would be refused if it were read
    a = gamemaster.make_adapter(prof)
    assert a.loopback and a._token is None


def test_missing_token_fails_loudly_without_a_request(make):
    a, s = make(token=None)
    with pytest.raises(PlatformError, match="CTF_TOKEN"):
        a.list_challenges()
    assert s.calls == []


def test_get_challenge_merges_list_row_and_status(make):
    a, _ = make()
    ch = a.get_challenge("metadata-day-01")
    assert ch.name == "Who Wrote It" and ch.category == "metadata"
    assert ch.description.startswith("Inspect evidence.zip.") and "author name only" in ch.description
    assert [f.url for f in ch.files] == ["/?op=download&capability=cap-0001"]
    assert ch.raw["status"]["answer_ids"] == ["d01-author"]


def test_get_challenge_unknown_id(make):
    a, _ = make()
    with pytest.raises(PlatformError, match="not on the Game Master's list"):
        a.get_challenge("nope-day-99")


def test_download_single_delivery_is_sha_checked(make, tmp_path):
    a, s = make()
    [out] = a.download_files("metadata-day-01", tmp_path)
    assert out == tmp_path / "evidence.zip" and out.read_bytes() == b"PK\x03\x04evidence"
    art = s.sent("GET")[-1]
    assert art["params"] == {"op": "artifact", "challenge": "metadata-day-01", "delivery": "0"}


def test_download_multi_delivery_gets_numbered_folders(make, tmp_path):
    a, _ = make()
    out = a.download_files("mobile-day-04/mastery", tmp_path)
    assert out == [tmp_path / "delivery-01" / "blob.txt", tmp_path / "delivery-02" / "blob.txt"]
    assert [p.read_text() for p in out] == ["first delivery\n", "second delivery\n"]


def test_download_sha_mismatch_writes_nothing(make, tmp_path):
    a, _ = make()
    with pytest.raises(PlatformError, match="sha256 .* does not match"):
        a.download_files("warmups-day-06", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_download_never_starts_an_attempt(make, tmp_path):
    a, s = make()
    with pytest.raises(PlatformError, match="has no attempt yet .start_required.; start it first"):
        a.download_files("script-day-05", tmp_path)
    assert posts(s) == []


def test_submit_single_answer_challenge(make):
    a, s = make()
    res = a.submit("metadata-day-01", "Alice Example")
    assert res.status is SubmitStatus.CORRECT and "flag{0123456789abcdef0123456789abcdef}" in res.message
    assert posts(s)[0]["json"] == {"challenge": "metadata-day-01", "answers": {"d01-author": "Alice Example"}}


@pytest.mark.parametrize("value, status, judged", [
    ("Bob", SubmitStatus.INCORRECT, True),
    ("Carol", SubmitStatus.RATE_LIMITED, False),
    ("Dave", SubmitStatus.NOT_ALLOWED, False),
])
def test_submit_verdicts(make, value, status, judged):
    a, _ = make()
    res = a.submit("metadata-day-01", value)
    assert res.status is status and res.status.judged is judged


def test_rate_limit_retry_after(make):
    a, _ = make()
    assert a.submit("metadata-day-01", "Carol").retry_after == 12.0


def test_unknown_word_is_never_a_verdict(make):
    a, _ = make()
    with pytest.raises(PlatformError, match="training_rotation_invalid"):
        a.submit("metadata-day-01", "Eve")


def test_multi_answer_needs_an_answer_address(make):
    a, s = make()
    with pytest.raises(PlatformError, match=r"takes 2 answers \(m4-a, m4-b\).*#<answer id>"):
        a.submit("mobile-day-04/mastery", "pixel")
    assert posts(s) == []
    res = a.submit("mobile-day-04/mastery#m4-a", "pixel")
    assert res.status is SubmitStatus.CORRECT and "1 answer(s) remaining" in res.message
    assert posts(s)[0]["json"] == {"challenge": "mobile-day-04/mastery", "answers": {"m4-a": "pixel"}}


def test_already_solved_and_start_required(make):
    a, _ = make()
    assert a.submit("binary-day-02", "upx").status is SubmitStatus.ALREADY_SOLVED
    res = a.submit("script-day-05", "k")
    assert res.status is SubmitStatus.NOT_ALLOWED and "start_required" in res.message


def test_unsure_answer_is_never_sent(make):
    a, s = make()
    res = a.submit("metadata-day-01", "?? maybe Alice")
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert s.calls == []


def test_unauthorized_names_the_token_problem(make):
    a, s = make()
    s.add({"method": "GET", "url": GM, "params": {"op": "list"}, "status": 401, "body": {"error": "unauthorized"}})
    with pytest.raises(PlatformError, match="unauthorized"):
        a.list_challenges()


def test_start_instance_returns_targets_and_deadline(make):
    a, s = make()
    info = a.start_instance("web-exploitation-day-20")
    assert info.state == "running" and info.connection_info == "https://t1.huntress.example/"
    want = datetime.datetime(2026, 10, 20, 16, 0, tzinfo=datetime.timezone.utc).timestamp()
    assert info.expires_at == want
    assert posts(s)[0]["json"] == {"challenge": "web-exploitation-day-20"}


@pytest.mark.parametrize("cid", ["metadata-day-01/time_trial", "mobile-day-04/mastery", "x/Mastery/"])
def test_timed_ids_are_never_started(make, cid):
    a, s = make()
    with pytest.raises(NotAllowed, match="timed id"):
        a.start_instance(cid)
    assert s.calls == []


def test_start_refusal_is_a_platform_error(make):
    a, _ = make()
    with pytest.raises(PlatformError, match="HTTP 503 artifact_unavailable"):
        a.start_instance("script-day-05")


def test_instance_status_and_unsupported_ops(make):
    a, _ = make()
    assert a.instance_status("script-day-05").state == "stopped"
    assert a.instance_status("metadata-day-01").state == "running"
    with pytest.raises(NotSupported, match="no stop op"):
        a.stop_instance("metadata-day-01")
    with pytest.raises(NotSupported, match="no scoreboard"):
        a.scoreboard()


def test_team_solves_from_the_list(make):
    a, _ = make()
    assert [t.challenge_id for t in a.team_solves()] == ["binary-day-02"]


# ------------------------------------------------------------------------------- selection + gate

@pytest.fixture
def wired(monkeypatch, tmp_path):
    import requests
    s = FakeSession([dict(r, url=r["url"].replace(GM, "https://gamemaster.huntress.example/"))
                     for r in FX["routes"]])
    monkeypatch.setattr(requests, "Session", lambda: s)
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL"), "CTF_TOKEN", *env.legacy_names("CTF_TOKEN")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(_HUNTRESS_TOKEN_SPELLING, "legacy-token")   # the adapter reads the token through ctf.env
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    return s


def test_get_adapter_selects_gamemaster_and_gates_submit(wired):
    with pytest.warns(DeprecationWarning, match="HUNTRESS_GM_TOKEN"):
        gate = get_adapter(event.load("huntress"))
    assert gate.kind == "gamemaster"
    # A Game Master answer is not a flag{...}: the gate refuses it unless the caller says the brief
    # defines the answer.
    refused = gate.submit("metadata-day-01", "Alice Example", provenance="docProps/core.xml creator")
    assert refused.status is SubmitStatus.NOT_ALLOWED and "flag format" in refused.message
    assert posts(wired) == []
    res = gate.submit("metadata-day-01", "Alice Example", provenance="docProps/core.xml creator",
                      allow_nonstandard=True)
    assert res.accepted
    assert posts(wired)[0]["headers"]["Authorization"] == "Bearer legacy-token"


def test_make_adapter_refuses_wrong_kind():
    with pytest.raises(PlatformError, match="ctfd"):
        gamemaster.make_adapter(event.load("csctf"))
