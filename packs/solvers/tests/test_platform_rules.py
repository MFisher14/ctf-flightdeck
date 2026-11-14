"""B-005: every submit goes through the event rules (wrong_answer_stop, guess_budget, flag_sharing).

The adapter here is a test double for the platform; the gate, the rules and the ledger are real.
"""
from __future__ import annotations

import json
import re

import pytest

from ctf import event, ledger
from ctf.platform import RecordError, SubmitGate, SubmitStatus, rules
from ctf.platform.base import SubmitResult


class ScriptedAdapter:
    """Answers each submit with the next scripted status (the platform under test is the gate)."""
    kind = "ctfd"

    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.sent = []

    def submit(self, challenge_id, flag):
        self.sent.append((challenge_id, flag))
        return SubmitResult(self.statuses.pop(0) if self.statuses else SubmitStatus.INCORRECT)

    def list_challenges(self): return []
    def get_challenge(self, cid): raise NotImplementedError
    def download_files(self, cid, dest): return []
    def team_solves(self): return []
    def scoreboard(self): return []


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    return tmp_path / "work"


def gate_for(prof, adapter):
    g = SubmitGate(adapter, prof)
    rules.install(g)
    return g


def profile(tmp_path, slug, **edits):
    src = event.load(slug).path.read_text()
    for key, new in edits.items():
        src, n = re.subn(rf"^{key} = .*$", f"{key} = {new}", src, flags=re.M)
        assert n == 1, key
    (tmp_path / "profiles" / slug).mkdir(parents=True)
    (tmp_path / "profiles" / slug / "event.toml").write_text(src)
    return event.load(slug, root=tmp_path / "profiles")


def test_wrong_answer_stop_after_three(work):
    prof = event.load("csctf")
    a = ScriptedAdapter()
    g = gate_for(prof, a)
    for i in range(3):
        assert g.submit("5", f"CSCTF{{w{i}}}", provenance="p").status is SubmitStatus.INCORRECT
    res = g.submit("5", "CSCTF{w3}", provenance="p")
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert "wrong_answer_stop" in res.message and "3 wrong" in res.message
    assert len(a.sent) == 3
    # Another challenge is unaffected. B-006: a bare confirmed=True no longer passes the stop; the
    # player's counted approval plus confirmed=True does (tests/test_submit_queue.py has the rest).
    assert g.submit("6", "CSCTF{x}", provenance="p").sent
    assert not g.submit("5", "CSCTF{w4}", provenance="p", confirmed=True).sent
    rules.EventRules(prof).grant("5", "player: one more", 1)
    assert g.submit("5", "CSCTF{w4}", provenance="p", confirmed=True).sent
    assert len(a.sent) == 5


def test_unjudged_answers_do_not_count(work):
    prof = event.load("csctf")
    a = ScriptedAdapter(*[SubmitStatus.RATE_LIMITED] * 5, SubmitStatus.PAUSED, SubmitStatus.CORRECT)
    g = gate_for(prof, a)
    for _ in range(6):
        assert g.submit("5", "CSCTF{v}", provenance="p").sent
    assert g.submit("5", "CSCTF{v}", provenance="p").accepted


def test_limit_follows_the_profile(work, tmp_path):
    prof = profile(tmp_path, "csctf", wrong_answer_stop="1")
    g = gate_for(prof, ScriptedAdapter())
    g.submit("5", "CSCTF{a}", provenance="p")
    assert "limit 1" in g.submit("5", "CSCTF{b}", provenance="p").message


def test_answer_addresses_count_against_their_challenge(work):
    prof = event.load("huntress")
    a = ScriptedAdapter()
    g = gate_for(prof, a)
    for aid in ("a", "b", "c"):
        g.submit(f"mobile-day-04/mastery#{aid}", "x", provenance="p", allow_nonstandard=True)
    res = g.submit("mobile-day-04/mastery#d", "x", provenance="p", allow_nonstandard=True)
    assert res.status is SubmitStatus.NOT_ALLOWED and "mobile-day-04/mastery" in res.message


def test_guess_budget_zero_refuses_any_guess(work):
    prof = event.load("csctf")
    a = ScriptedAdapter()
    g = gate_for(prof, a)
    res = g.submit("5", "CSCTF{v2}", provenance="leet variant of v1", guess=True)
    assert res.status is SubmitStatus.NOT_ALLOWED and "guess_budget" in res.message and a.sent == []
    assert g.submit("5", "CSCTF{v1}", provenance="decoded body").sent


def test_guess_budget_counts_judged_guesses(work, tmp_path):
    prof = profile(tmp_path, "csctf", guess_budget="1", wrong_answer_stop="9")
    a = ScriptedAdapter(SubmitStatus.RATE_LIMITED, SubmitStatus.INCORRECT)
    g = gate_for(prof, a)
    assert g.submit("5", "CSCTF{g1}", provenance="p", guess=True).sent        # rate limited: not spent
    assert g.submit("5", "CSCTF{g1}", provenance="p", guess=True).sent        # judged: spends the 1
    res = g.submit("5", "CSCTF{g2}", provenance="p", guess=True)
    assert "guess_budget: 1 guess(es) used" in res.message and len(a.sent) == 2
    assert g.submit("5", "CSCTF{reasoned}", provenance="p").sent


def test_flag_sharing_forbidden_keeps_only_a_hash(work):
    prof = event.load("pink")
    assert prof.rules.flag_sharing == "forbidden"
    g = gate_for(prof, ScriptedAdapter(SubmitStatus.CORRECT))
    g.submit("3", "PINK{do_not_share}", provenance="stego lsb")
    text = (work / "ledger.jsonl").read_text()
    assert "do_not_share" not in text
    [rec] = list(ledger.read(work))
    assert rec["event"] == "platform.submit" and rec["status"] == "correct"
    assert len(rec["flag_sha256"]) == 64 and "flag" not in rec


def test_flag_sharing_allowed_keeps_the_value(work):
    prof = event.load("csctf")
    g = gate_for(prof, ScriptedAdapter(SubmitStatus.CORRECT))
    g.submit("3", "CSCTF{team_ok}", provenance="p")
    [rec] = list(ledger.read(work))
    assert rec["flag"] == "CSCTF{team_ok}" and rec["provenance"] == "p" and rec["judged"] is True


def test_records_of_another_event_do_not_count(work):
    for _ in range(3):
        ledger.append("platform.submit", workdir=work, event_slug="pink", challenge_id="5",
                      status="incorrect", judged=True, guess=False)
    g = gate_for(event.load("csctf"), ScriptedAdapter())
    assert g.submit("5", "CSCTF{x}", provenance="p").sent


def test_refused_submissions_are_not_recorded(work):
    g = gate_for(event.load("csctf"), ScriptedAdapter())
    g.submit("5", "not a flag", provenance="p")
    assert not (work / "ledger.jsonl").exists()


def test_failed_record_raises_with_the_result(work, monkeypatch):
    g = gate_for(event.load("csctf"), ScriptedAdapter(SubmitStatus.CORRECT))

    def broken(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(ledger, "append", broken)
    with pytest.raises(RecordError, match="answered correct, but recording it failed") as e:
        g.submit("5", "CSCTF{x}", provenance="p")
    assert e.value.result.accepted


def test_get_adapter_installs_the_rules(work, monkeypatch):
    import sys
    import types
    a = ScriptedAdapter()
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda p: a
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    from ctf.platform import get_adapter
    g = get_adapter(event.load("csctf"))
    for i in range(3):
        g.submit("5", f"CSCTF{{{i}}}", provenance="p")
    assert "wrong_answer_stop" in g.submit("5", "CSCTF{3}", provenance="p").message
    assert json.loads((work / "ledger.jsonl").read_text().splitlines()[0])["challenge_id"] == "5"
