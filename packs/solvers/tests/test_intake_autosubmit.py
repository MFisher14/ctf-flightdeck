"""Fastlane decoders inside intake + capped auto-submit through the SubmitGate (B-012).

Every handout is built here synthetically; no challenge binary is run and no network is used. The
platform is a fake adapter or a scripted SubmitGate; a manual event is exercised through the real
ctf.platform.get_adapter so the manual refusal is the production path, not a test stub.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from ctf import event, ledger
from ctf import intake as I
from ctf.intake import autosubmit as A
from ctf.platform import get_adapter
from ctf.platform.base import Challenge, FileRef, PlatformError, SubmitResult, SubmitStatus
from ctf.platform.policy import SubmitGate

CSCTF = event.load("csctf")
SPOOKY = event.load("spooky")       # platform kind manual, submit_mode manual


# ---------------------------------------------------------------- fakes

class FakeAdapter:
    kind = "fake"

    def __init__(self, challenges: dict):
        self.challenges = challenges          # id -> (Challenge, {relpath: bytes})
        self.submits = []

    def list_challenges(self):
        return [c for c, _ in self.challenges.values()]

    def get_challenge(self, cid):
        if cid not in self.challenges:
            raise PlatformError(f"get_challenge({cid}): 404")
        return self.challenges[cid][0]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.challenges[cid][1].items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        self.submits.append((cid, flag))
        raise AssertionError("intake itself must never submit")

    def team_solves(self):
        return []

    def scoreboard(self):
        return []


class ScriptedGateAdapter:
    """A platform adapter that answers submit() with scripted verdicts (for SubmitGate tests)."""
    kind = "scripted"

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def submit(self, cid, flag):
        self.calls.append((cid, flag))
        a = self.answers.pop(0) if self.answers else SubmitStatus.INCORRECT
        return a if isinstance(a, SubmitResult) else SubmitResult(a)


def _ch(cid, name="Chal", category="misc", description="", points=100, files=()):
    return Challenge(id=cid, name=name, category=category, points=points, description=description,
                     files=tuple(FileRef(f) for f in files))


def _reversed_b64(flag: str) -> bytes:
    """base64 of the flag, then the whole token reversed: a decode chain the flat sweep does not undo
    (reversed base64 decodes to garbage), but the fastlane crib decoder does (reverse, then base64)."""
    return base64.b64encode(flag.encode()).decode()[::-1].encode()


# ================================================================ eligible()

def test_eligible_takes_one_unambiguous_flag():
    flag, why = A.eligible("solved", ["CSCTF{the_only_one}"], CSCTF)
    assert flag == "CSCTF{the_only_one}" and "one unambiguous" in why


def test_eligible_refuses_several_candidates():
    flag, why = A.eligible("candidate", ["CSCTF{a}", "CSCTF{b}"], CSCTF)
    assert flag is None and "ambiguous" in why and "2 distinct" in why


def test_eligible_refuses_when_status_not_solved_even_with_one_flag():
    # a single flag but a non-solved status is still not auto-submittable.
    flag, why = A.eligible("candidate", ["CSCTF{lonely}"], CSCTF)
    assert flag is None and "status 'candidate'" in why


def test_eligible_refuses_placeholder_flag():
    for ph in ("CSCTF{...}", "CSCTF{example}", "CSCTF{----}"):
        flag, why = A.eligible("solved", [ph], CSCTF)
        assert flag is None and "placeholder" in why, ph


def test_eligible_refuses_when_nothing_is_in_format():
    flag, why = A.eligible("solved", ["not a flag", "WRONG{x}"], CSCTF)
    assert flag is None and "flag format" in why


# ================================================================ auto_submit() through the gate

def _gate(adapter, profile=CSCTF):
    return SubmitGate(adapter, profile)


def test_auto_submit_sends_unambiguous_flag_and_records(tmp_path):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitStatus.CORRECT)
    a = A.auto_submit("9076", "solved", ["CSCTF{free}"], _gate(ad), profile=CSCTF,
                      provenance="intake: decoded from handout", cap=1, workdir=wd)
    assert a.submitted and a.accepted and a.flag == "CSCTF{free}"
    assert ad.calls == [("9076", "CSCTF{free}")]
    recs = [r for r in ledger.read(wd) if r["event"] == A.LEDGER_EVENT]
    assert len(recs) == 1 and recs[0]["challenge_id"] == "9076" and recs[0]["sent"] and recs[0]["accepted"]


def test_auto_submit_cap_blocks_a_second_send_on_the_same_challenge(tmp_path):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT)
    first = A.auto_submit("5", "solved", ["CSCTF{try}"], _gate(ad), profile=CSCTF,
                          provenance="p", cap=1, workdir=wd)
    assert first.submitted and not first.accepted
    second = A.auto_submit("5", "solved", ["CSCTF{try}"], _gate(ad), profile=CSCTF,
                           provenance="p", cap=1, workdir=wd)
    assert not second.submitted and second.flag == "CSCTF{try}" and "cap 1 reached" in second.reason
    assert len(ad.calls) == 1, "the capped second attempt must not reach the platform"


def test_auto_submit_cap_two_allows_two_then_blocks(tmp_path):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, SubmitStatus.CORRECT)
    for _ in range(2):
        assert A.auto_submit("7", "solved", ["CSCTF{real_body}"], _gate(ad), profile=CSCTF,
                             provenance="p", cap=2, workdir=wd).submitted
    blocked = A.auto_submit("7", "solved", ["CSCTF{real_body}"], _gate(ad), profile=CSCTF,
                            provenance="p", cap=2, workdir=wd)
    assert not blocked.submitted and len(ad.calls) == 2


def test_auto_submit_refusal_does_not_consume_the_cap(tmp_path):
    # A manual-mode event refuses at the gate (sent=False); that refusal is not a send, so it must not
    # eat the per-challenge cap and must never reach a platform adapter.
    wd = tmp_path / "wd"
    gate = get_adapter(SPOOKY)
    a = A.auto_submit("13", "solved", ["spooky{real_one}"], gate, profile=SPOOKY,
                      provenance="p", cap=1, workdir=wd)
    assert a.flag == "spooky{real_one}" and not a.submitted and not a.accepted
    assert "manual" in a.reason.lower()
    assert A.prior_sends("13", wd) == 0, "a refused attempt leaves the cap untouched"
    recs = [r for r in ledger.read(wd) if r["event"] == A.LEDGER_EVENT]
    assert len(recs) == 1 and recs[0]["sent"] is False


def test_auto_submit_ambiguous_result_is_never_sent(tmp_path):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitStatus.CORRECT)
    a = A.auto_submit("8", "candidate", ["CSCTF{a}", "CSCTF{b}"], _gate(ad), profile=CSCTF,
                      provenance="p", cap=1, workdir=wd)
    assert a.flag is None and not a.submitted and ad.calls == []
    assert [r for r in ledger.read(wd) if r["event"] == A.LEDGER_EVENT] == []


# ================================================================ fastlane decoders inside intake

def _opts(**kw):
    kw.setdefault("net_guard", "hook")
    kw.setdefault("engines", False)
    kw.setdefault("record", False)
    return I.Options(**kw)


def test_intake_runs_fastlane_decoders_and_finds_a_chained_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    flag = "CSCTF{deep_decode_me}"
    ad = FakeAdapter({"42": (_ch("42", category="crypto"), {"chef.txt": _reversed_b64(flag)})})
    rep = I.intake_one("42", CSCTF, adapter=ad, workdir=tmp_path / "wd", options=_opts())
    assert ad.submits == [], "intake must not submit"
    assert "fastlane" in rep.stages
    assert flag in rep.flags, rep.flags
    where = rep.flags[flag]
    assert any("fastlane decode" in w for w in where), where
    assert not any("sweep" in w for w in where), "the flat sweep should not already have this flag"
    assert rep.status == "solved"


def test_intake_fastlane_flag_from_handout_feeds_auto_submit(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    flag = "CSCTF{chain_to_submit}"
    ad = FakeAdapter({"43": (_ch("43", category="crypto"), {"blob.txt": _reversed_b64(flag)})})
    rep = I.intake_one("43", CSCTF, adapter=ad, workdir=tmp_path / "wd", options=_opts())
    # the fastlane-surfaced flag is what the capped auto-submit then sends.
    gate_ad = ScriptedGateAdapter(SubmitStatus.CORRECT)
    a = A.auto_submit(rep.challenge_id, rep.status, rep.result.flags, _gate(gate_ad), profile=CSCTF,
                      provenance="intake", cap=1, workdir=tmp_path / "wd")
    assert a.accepted and gate_ad.calls == [("43", flag)]


def test_intake_notes_a_missing_fastlane_decoder_loudly(tmp_path, monkeypatch):
    # rule 6: a missing decoder is a named note, never a silent skip.
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import fastlane
    monkeypatch.setattr(fastlane, "_crib", None)
    ad = FakeAdapter({"44": (_ch("44"), {"a.txt": b"nothing special"})})
    rep = I.intake_one("44", CSCTF, adapter=ad, workdir=tmp_path / "wd", options=_opts())
    assert any("crib_decode" in n and "unavailable" in n for n in rep.notes), rep.notes


# ================================================================ round-1 fixes: eligibility, cap, failures, CLI

def test_eligible_refuses_two_flags_even_when_status_says_solved():
    # A caller (watcher, dispatcher) may hand auto_submit a 'solved' status with several flags: the
    # distinct-count guard alone must stop it.
    flag, why = A.eligible("solved", ["CSCTF{a}", "CSCTF{b}"], CSCTF)
    assert flag is None and "ambiguous" in why and "2 distinct" in why


def test_eligible_refuses_a_control_character_body():
    flag, why = A.eligible("solved", ["CTF{mo]Vs\x02M\x03u}"], CSCTF)
    assert flag is None and "control" in why


def test_auto_submit_never_sends_a_control_character_body(tmp_path):
    ad = ScriptedGateAdapter(SubmitStatus.INCORRECT)
    a = A.auto_submit("3", "solved", ["CTF{mo]Vs\x02M\x03u}"], _gate(ad), profile=CSCTF,
                      provenance="p", cap=1, workdir=tmp_path / "wd")
    assert a.flag is None and not a.submitted and ad.calls == []


@pytest.mark.parametrize("unjudged", [SubmitStatus.RATE_LIMITED, SubmitStatus.PAUSED, SubmitStatus.NOT_ALLOWED])
def test_an_unjudged_send_does_not_consume_the_cap(tmp_path, unjudged):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitResult(unjudged, "try later"), SubmitStatus.INCORRECT, SubmitStatus.CORRECT)
    first = A.auto_submit("4", "solved", ["CSCTF{later}"], _gate(ad), profile=CSCTF,
                          provenance="p", cap=1, workdir=wd)
    assert first.submitted and first.status == unjudged.value and A.prior_sends("4", wd) == 0
    second = A.auto_submit("4", "solved", ["CSCTF{later}"], _gate(ad), profile=CSCTF,
                           provenance="p", cap=1, workdir=wd)
    assert second.submitted and second.status == "incorrect" and A.prior_sends("4", wd) == 1
    third = A.auto_submit("4", "solved", ["CSCTF{later}"], _gate(ad), profile=CSCTF,
                          provenance="p", cap=1, workdir=wd)
    assert not third.submitted and "cap 1 reached" in third.reason
    assert len(ad.calls) == 2


class RaisingAdapter(ScriptedGateAdapter):
    def __init__(self, fail_ids, *answers):
        super().__init__(*answers)
        self.fail_ids = set(fail_ids)

    def submit(self, cid, flag):
        if cid in self.fail_ids:
            self.calls.append((cid, flag))
            raise PlatformError(f"submit({cid}): HTTP 502")
        return super().submit(cid, flag)


def test_a_send_that_raises_is_recorded_and_counts_against_the_cap(tmp_path):
    wd = tmp_path / "wd"
    ad = RaisingAdapter({"6"})
    a = A.auto_submit("6", "solved", ["CSCTF{maybe}"], _gate(ad), profile=CSCTF,
                      provenance="p", cap=1, workdir=wd)
    assert a.submitted and not a.accepted and a.status == A.ERROR and "HTTP 502" in a.error
    assert "outcome unknown" in a.line()
    recs = [r for r in ledger.read(wd) if r["event"] == A.LEDGER_EVENT]
    assert len(recs) == 1 and recs[0]["sent"] is True and recs[0]["status"] == A.ERROR
    again = A.auto_submit("6", "solved", ["CSCTF{maybe}"], _gate(ad), profile=CSCTF,
                          provenance="p", cap=1, workdir=wd)
    assert not again.submitted and "cap 1 reached" in again.reason and len(ad.calls) == 1


def test_a_record_error_after_the_answer_is_still_recorded_and_counted(tmp_path):
    wd = tmp_path / "wd"
    ad = ScriptedGateAdapter(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT)
    gate = _gate(ad)

    def broken(profile, req, result):
        raise OSError("disk full")

    gate.add_observer(broken)
    a = A.auto_submit("8", "solved", ["CSCTF{rec}"], gate, profile=CSCTF, provenance="p", cap=1, workdir=wd)
    assert a.submitted and a.status == "incorrect" and a.error is None and "could not record" in a.reason
    assert A.prior_sends("8", wd) == 1
    again = A.auto_submit("8", "solved", ["CSCTF{rec}"], gate, profile=CSCTF, provenance="p", cap=1, workdir=wd)
    assert not again.submitted and len(ad.calls) == 1


# ---------------------------------------------------------------- the CLI --submit path

def _outs(*rows):
    return [I.Outcome(cid, 0, 0.0, 0.1, {"challenge_id": cid, "status": st, "flags": fl, "dir": None,
                                         "line": f"intake {cid}: {st}"}) for cid, st, fl in rows]


def test_cli_auto_submit_carries_on_past_a_failing_challenge(tmp_path, capsys):
    from ctf.cli import intake as C
    wd = tmp_path / "wd"
    ad = RaisingAdapter({"2"}, SubmitStatus.CORRECT, SubmitStatus.CORRECT)
    outs = _outs(("1", "solved", ["CSCTF{one}"]), ("2", "solved", ["CSCTF{two}"]),
                 ("3", "solved", ["CSCTF{three}"]), ("4", "candidate", ["CSCTF{a}", "CSCTF{b}"]))
    failed = C._auto_submit(outs, CSCTF, 1, gate=_gate(ad), workdir=wd)
    out = capsys.readouterr().out
    assert failed == 1
    assert [c for c, _ in ad.calls] == ["1", "2", "3"], "challenge 3 must still be tried after 2 failed"
    assert "autosubmit 2:" in out and "FAILED" in out and "autosubmit 3: CSCTF{three} sent -> ACCEPTED" in out
    assert "autosubmit: 2 accepted, 3 sent, 1 failed (cap 1/challenge)" in out
    assert A.prior_sends("2", wd) == 1, "an unknown-outcome send is in the ledger and counts"


def test_cli_auto_submit_carries_on_past_a_ledger_failure(tmp_path, monkeypatch, capsys):
    from ctf.cli import intake as C
    real = A.prior_sends

    def flaky(cid, workdir):
        if str(cid) == "2":
            raise OSError("ledger unreadable")
        return real(cid, workdir)

    monkeypatch.setattr(A, "prior_sends", flaky)
    ad = ScriptedGateAdapter(SubmitStatus.CORRECT, SubmitStatus.CORRECT)
    outs = _outs(("1", "solved", ["CSCTF{one}"]), ("2", "solved", ["CSCTF{two}"]), ("3", "solved", ["CSCTF{three}"]))
    assert C._auto_submit(outs, CSCTF, 1, gate=_gate(ad), workdir=tmp_path / "wd") == 1
    out = capsys.readouterr().out
    assert "autosubmit 2: FAILED (OSError: ledger unreadable)" in out
    assert [c for c, _ in ad.calls] == ["1", "3"]


def test_cli_auto_submit_names_a_gate_that_cannot_be_built(tmp_path, monkeypatch, capsys):
    from ctf import platform
    from ctf.cli import intake as C

    def no_gate(profile):
        raise PlatformError("no credentials for csctf")

    monkeypatch.setattr(platform, "get_adapter", no_gate)
    assert C._auto_submit(_outs(("1", "solved", ["CSCTF{one}"])), CSCTF, 1, workdir=tmp_path) == 1
    assert "NOT RUN" in capsys.readouterr().out


def test_cli_intake_submit_end_to_end_prints_summary_and_exits_1_on_a_failed_send(tmp_path, monkeypatch, capsys):
    from ctf import cli, platform
    wd = tmp_path / "wd"
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    monkeypatch.setattr(I, "intake_many", lambda ids, profile, **kw: _outs(
        ("1", "solved", ["CSCTF{one}"]), ("2", "solved", ["CSCTF{two}"])))
    ad = RaisingAdapter({"1"}, SubmitStatus.CORRECT)
    monkeypatch.setattr(platform, "get_adapter", lambda profile: _gate(ad, profile))
    assert cli.main(["intake", "1", "2", "--event", "csctf", "--submit"]) == 1
    out = capsys.readouterr().out
    assert "intake: 2/2 ran" in out
    assert out.index("intake: 2/2 ran") < out.index("autosubmit 1:")
    assert "autosubmit 2: CSCTF{two} sent -> ACCEPTED" in out
    assert [c for c, _ in ad.calls] == ["1", "2"]
    # a second run: 1's unknown send and 2's accepted send both hold the cap
    assert cli.main(["intake", "1", "2", "--event", "csctf", "--submit"]) == 0
    out = capsys.readouterr().out
    assert out.count("cap 1 reached") == 2 and len(ad.calls) == 2


def test_cli_intake_without_submit_never_builds_a_gate(tmp_path, monkeypatch, capsys):
    from ctf import cli, platform
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(I, "intake_many", lambda ids, profile, **kw: _outs(("1", "solved", ["CSCTF{one}"])))

    def no(profile):
        raise AssertionError("intake without --submit must not touch the submit gate")

    monkeypatch.setattr(platform, "get_adapter", no)
    assert cli.main(["intake", "1", "--event", "csctf"]) == 0
    assert "autosubmit" not in capsys.readouterr().out


def test_cli_negative_submit_cap_fails_before_intake_runs(tmp_path, monkeypatch, capsys):
    from ctf import cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))

    def never(*a, **kw):
        raise AssertionError("intake must not start with a bad --submit-cap")

    monkeypatch.setattr(I, "intake_many", never)
    assert cli.main(["intake", "1", "--event", "csctf", "--submit", "--submit-cap", "-1"]) == 2
    assert "--submit-cap must be >= 0" in capsys.readouterr().err
