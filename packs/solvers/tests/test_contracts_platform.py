"""B-001 contracts: ctf.platform (adapter protocol, kind registry by module, submit policy gate).

The adapter here is a test double for the *platform* (the thing B-005 builds); what is under test
is the registry and the gate in front of it, which are real.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from ctf import event, platform
from ctf.platform import PlatformError, SubmitStatus, get_adapter, supports_instances
from ctf.platform.base import Challenge, InstanceInfo, ScoreRow, SubmitResult, TeamSolve


class RecordingAdapter:
    kind = "ctfd"

    def __init__(self, profile):
        self.profile = profile
        self.sent = []

    def list_challenges(self):
        return [Challenge(id="1", name="a", category="Web")]

    def get_challenge(self, challenge_id):
        return Challenge(id=challenge_id, name="a", category="Web")

    def download_files(self, challenge_id, dest: Path):
        return []

    def submit(self, challenge_id, flag):
        self.sent.append((challenge_id, flag))
        return SubmitResult(SubmitStatus.CORRECT, "ok")

    def team_solves(self):
        return [TeamSolve("1")]

    def scoreboard(self):
        return [ScoreRow(1, "us", 100)]


class WithInstances(RecordingAdapter):
    def start_instance(self, cid): return InstanceInfo(cid, "running", "nc host 1")
    def stop_instance(self, cid): return InstanceInfo(cid, "stopped")
    def instance_status(self, cid): return InstanceInfo(cid, "running")


@pytest.fixture
def adapter_module(monkeypatch, tmp_path):
    """Install ctf.platform.ctfd as a module exposing make_adapter (as B-005 will ship it). The gate
    records to the ledger and the submit queue keeps state in the workdir: point it at tmp_path."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    made = []
    mod = types.ModuleType("ctf.platform.ctfd")

    def make_adapter(profile):
        a = RecordingAdapter(profile)
        made.append(a)
        return a

    mod.make_adapter = make_adapter
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    return made


def test_missing_adapter_module_fails_loudly(monkeypatch):
    # None in sys.modules makes the import fail as if the file were absent, whatever B-005 ships.
    monkeypatch.setitem(sys.modules, "ctf.platform.gamemaster", None)
    with pytest.raises(PlatformError, match="no adapter for platform kind 'gamemaster'"):
        get_adapter(event.load("huntress"))


def test_adapter_without_make_adapter_or_protocol_fails(monkeypatch):
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", types.ModuleType("ctf.platform.ctfd"))
    with pytest.raises(PlatformError, match="has no make_adapter"):
        get_adapter(event.load("csctf"))
    bad = types.ModuleType("ctf.platform.ctfd")
    bad.make_adapter = lambda p: object()
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", bad)
    with pytest.raises(PlatformError, match="does not implement PlatformAdapter"):
        get_adapter(event.load("csctf"))


def test_gate_passes_reads_through_and_sends_a_valid_flag(adapter_module):
    gate = get_adapter(event.load("csctf"))
    raw = adapter_module[0]
    assert gate.kind == "ctfd" and gate.profile.slug == "csctf"
    assert gate.list_challenges()[0].category == "Web"
    assert gate.scoreboard()[0].score == 100
    res = gate.submit(7, " CSCTF{ok} ", provenance="xor of body")
    assert res.accepted and res.sent
    assert raw.sent == [("7", "CSCTF{ok}")]


@pytest.mark.parametrize("flag, kw, reason", [
    ("CSCTF{ok}", dict(provenance=""), "provenance"),
    ("not-a-flag", dict(provenance="p"), "not in the event flag format"),
    ("PINK{x}", dict(provenance="p"), "not in the event flag format"),
])
def test_gate_refuses_without_sending(adapter_module, flag, kw, reason):
    gate = get_adapter(event.load("csctf"))
    res = gate.submit("7", flag, **kw)
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent and reason in res.message
    assert adapter_module[0].sent == []


def test_nonstandard_answer_needs_explicit_opt_in(adapter_module):
    gate = get_adapter(event.load("csctf"))
    assert gate.submit("7", "44.4268,26.1025", provenance="osint pin", allow_nonstandard=True).sent
    assert adapter_module[0].sent == [("7", "44.4268,26.1025")]


def test_manual_event_never_sends(monkeypatch):
    prof = event.load("spooky")
    raw = RecordingAdapter(prof)
    gate = platform.SubmitGate(raw, prof)
    res = gate.submit("1", "spooky{x}", provenance="p", confirmed=True)
    assert res.status is SubmitStatus.NOT_ALLOWED and "manual" in res.message
    assert raw.sent == []


def test_confirm_mode_requires_confirmation(tmp_path):
    src = (event.load("pink").path).read_text().replace('submit_mode = "auto"', 'submit_mode = "confirm"')
    (tmp_path / "pink").mkdir()
    (tmp_path / "pink" / "event.toml").write_text(src)
    prof = event.load("pink", root=tmp_path)
    raw = RecordingAdapter(prof)
    gate = platform.SubmitGate(raw, prof)
    assert "confirm" in gate.submit("1", "PINK{x}", provenance="p").message
    assert raw.sent == []
    assert gate.submit("1", "PINK{x}", provenance="p", confirmed=True).accepted
    assert raw.sent == [("1", "PINK{x}")]


def test_extra_checks_plug_in_without_editing_adapters():
    prof = event.load("pink")
    raw = RecordingAdapter(prof)
    gate = platform.SubmitGate(raw, prof)
    seen = []

    def wrong_quota(profile, req):
        seen.append(req.challenge_id)
        return "wrong-answer stop reached" if req.challenge_id == "9" else None

    gate.add_check(wrong_quota)
    assert gate.submit("9", "PINK{x}", provenance="p").message == "wrong-answer stop reached"
    assert gate.submit("8", "PINK{x}", provenance="p").sent
    assert seen == ["9", "8"] and raw.sent == [("8", "PINK{x}")]


def test_instance_capability_is_optional():
    prof = event.load("pink")
    assert not supports_instances(RecordingAdapter(prof))
    assert supports_instances(WithInstances(prof))
    gate = platform.SubmitGate(WithInstances(prof), prof)
    assert gate.start_instance("3").connection_info == "nc host 1"


def test_submit_status_vocabulary():
    assert {s.value for s in SubmitStatus} == {
        "correct", "incorrect", "already_solved", "rate_limited", "paused", "not_allowed"}
    assert SubmitStatus.RATE_LIMITED.judged is False and SubmitStatus.INCORRECT.judged is True
    r = SubmitResult(SubmitStatus.RATE_LIMITED, retry_after=30.0)
    assert not r.accepted and r.retry_after == 30.0
