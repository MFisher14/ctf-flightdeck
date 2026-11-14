"""B-006: `ctf submit`, `ctf submit-queue`, the [submit] profile table and the CTFd adapter's part.

The platform is a scripted double installed as ctf.platform.ctfd; get_adapter, the gate, the rules,
the queue, the ledger and the CLI are real.
"""
from __future__ import annotations

import sys
import types

import pytest

import ctf.cli as cli
from ctf import env, event, ledger
from ctf.event import SubmitPace
from ctf.platform import PlatformError, SubmitStatus, ctfd, get_adapter, rules
from ctf.platform.base import SubmitResult
from ctf.platform.queue import SubmitQueue

from platform_fixture_session import FakeSession
from test_submit_queue import ScriptedAdapter, flag, make_profile, records, write_profile


@pytest.fixture
def board(tmp_path, monkeypatch):
    """An automation CTFd event (no pacing waits) whose platform is a scripted adapter."""
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    state = {"profile": make_profile(tmp_path), "adapter": ScriptedAdapter()}
    monkeypatch.setattr(event, "current", lambda root=None: state["profile"])
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda profile: state["adapter"]
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    state["work"] = work
    return state


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ------------------------------------------------------------------------------- get_adapter
def test_get_adapter_attaches_the_queue(board):
    gate = get_adapter(board["profile"])
    assert isinstance(gate.queue, SubmitQueue) and gate.queue.profile is board["profile"]
    assert gate.queue.check in gate._checks, "dedupe runs as a gate check"


# ------------------------------------------------------------------------------- ctf submit
def test_submit_sends_once_and_records(board, capsys):
    board["adapter"].answers = [SubmitStatus.CORRECT]
    code, out, _ = run(capsys, "submit", "5", flag("ok"), "--note", "xor of body")
    assert code == 0 and out.startswith("correct")
    assert board["adapter"].sent == [("5", flag("ok"))]
    [rec] = records(board["work"])
    assert rec["provenance"] == "xor of body" and rec["status"] == "correct"


def test_submit_exit_codes_incorrect_then_duplicate(board, capsys):
    board["adapter"].answers = [SubmitStatus.INCORRECT]
    assert run(capsys, "submit", "5", flag("no"))[0] == 1
    code, _, err = run(capsys, "submit", "5", flag("no"))
    assert code == 4 and "ctf submit: refused: duplicate" in err
    assert len(board["adapter"].sent) == 1


def test_submit_notes_an_existing_workspace_folder(board, capsys):
    d = board["work"] / "5-warm-up"
    d.mkdir(parents=True)
    board["adapter"].answers = [SubmitStatus.CORRECT]
    run(capsys, "submit", "5", flag("ws"), "--note", "strings")
    assert f"- submit {flag('ws')} -> correct (strings)" in (d / "notes.md").read_text()
    assert (d / "flag.txt").read_text() == flag("ws") + "\n"


def test_submit_creates_no_workspace_folder_and_hides_a_team_only_flag(board, tmp_path, capsys):
    board["profile"] = make_profile(tmp_path / "f", sharing="forbidden")
    d = board["work"] / "6-other"
    d.mkdir(parents=True)
    run(capsys, "submit", "6", flag("team_only"))
    assert "team_only" not in (d / "notes.md").read_text() and "<flag>" in (d / "notes.md").read_text()
    run(capsys, "submit", "7", flag("x"))
    assert sorted(p.name for p in board["work"].iterdir()) == ["6-other", "ledger.jsonl", "submitq"]


def test_submit_nonstandard_answer_needs_the_flag(board, capsys):
    board["adapter"].answers = [SubmitStatus.CORRECT]
    assert run(capsys, "submit", "5", "44.4268,26.1025")[0] == 4
    assert run(capsys, "submit", "5", "44.4268,26.1025", "--nonstandard", "--note", "osint pin")[0] == 0
    assert board["adapter"].sent == [("5", "44.4268,26.1025")]


def test_past_the_stop_the_player_approves_and_confirms(board, capsys):
    for i in range(3):
        run(capsys, "submit", "5", flag(f"w{i}"))
    code, _, err = run(capsys, "submit", "5", flag("w3"), "--confirm")
    assert code == 4 and "no unused player approval" in err
    code, out, _ = run(capsys, "submit-queue", "approve", "5", "--reason", "player: try the v2 key")
    assert code == 0 and "unused now: 1" in out
    board["adapter"].answers = [SubmitStatus.CORRECT]
    assert run(capsys, "submit", "5", flag("w3"), "--confirm")[0] == 0
    assert len(board["adapter"].sent) == 4
    [appr] = [r for r in ledger.read(board["work"]) if r["event"] == rules.APPROVAL]
    assert appr["reason"] == "player: try the v2 key" and appr["count"] == 1


def test_approve_without_a_reason_is_an_error(board, capsys):
    code, _, err = run(capsys, "submit-queue", "approve", "5", "--reason", " ")
    assert code == 2 and "needs a reason" in err


def test_python_m_ctf_submit_send_uses_the_same_gate(board, capsys):
    from ctf import submit as S
    board["adapter"].answers = [SubmitStatus.CORRECT]
    assert S.main(["send", "5", flag("mod"), "--note", "n"]) == 0
    assert S.main(["send", "5", flag("mod2")]) == S.REFUSED_EXIT       # the challenge is accepted now
    assert "refused: solved" in capsys.readouterr().err
    assert board["adapter"].sent == [("5", flag("mod"))]


# ------------------------------------------------------------------------------- ctf submit-queue
def test_status_reports_the_shared_budget_and_pause(board, capsys):
    board["adapter"].answers = [SubmitStatus.CORRECT, SubmitResult(SubmitStatus.RATE_LIMITED, retry_after=90)]
    board["profile"] = make_profile(board["work"].parent / "s", per_minute=7, hold=0)
    run(capsys, "submit", "1", flag("a"))
    run(capsys, "submit", "2", flag("b"))
    code, out, _ = run(capsys, "submit-queue", "status")
    assert code == 0
    assert "2/7 sends in the last 60s" in out
    assert "shared pause: 90s left (rate_limited)" in out or "shared pause: 89s left (rate_limited)" in out
    assert "spooled: 0 in flight, 1 orphaned" in out


def test_pending_and_drain(board, capsys):
    board["profile"] = make_profile(board["work"].parent / "d", hold=0)
    # The pause must outlast the gap between the 429 and the call's next pass even under suite load:
    # once it has expired the same call re-sends (correctly), and nothing is left for drain.
    board["adapter"].answers = [SubmitResult(SubmitStatus.RATE_LIMITED, retry_after=0.5), SubmitStatus.CORRECT]
    assert run(capsys, "submit", "3", flag("later"))[0] == 1
    code, out, _ = run(capsys, "submit-queue", "pending")
    assert code == 0 and "orphaned  challenge 3" in out and flag("later") in out
    import time
    time.sleep(0.6)
    code, out, _ = run(capsys, "submit-queue", "drain")
    assert code == 0 and "challenge 3: correct" in out
    assert run(capsys, "submit-queue", "pending")[1].strip() == "no spooled sends"
    assert run(capsys, "submit-queue", "drain")[1].strip() == "nothing orphaned to drain"


def test_drain_refuses_a_manual_event(board, capsys):
    board["profile"] = event.load("spooky")
    code, _, err = run(capsys, "submit-queue", "drain")
    assert code == 4 and "'spooky' is manual" in err


# ------------------------------------------------------------------------------- the [submit] table
def test_profiles_get_the_documented_submit_defaults():
    assert event.load("csctf").submit == SubmitPace(per_minute=10, interval_s=1.0,
                                                    per_challenge_interval_s=3.0, max_hold_s=600.0,
                                                    rotating_miss_budget=6)


def test_submit_table_values_are_read(tmp_path):
    p = make_profile(tmp_path, per_minute=4, interval=2.5, per_ch=9, hold=30)
    assert p.submit == SubmitPace(4, 2.5, 9.0, 30.0, 6)
    path = write_profile(tmp_path / "r")
    path.write_text(path.read_text() + "rotating_miss_budget = 2\n")
    assert event.load_path(path).submit.rotating_miss_budget == 2


@pytest.mark.parametrize("line, match", [
    ("per_minute = 0", "submit.per_minute must be >= 1"),
    ("interval_s = -1.0", "must be >= 0"),
    ("max_hold_s = -5", "must be >= 0"),
    ("per_minute = true", "submit.per_minute must be int"),
    ("rotating_miss_budget = -1", "submit.rotating_miss_budget must be >= 0"),
    ("rotating_miss_budget = 1.5", "submit.rotating_miss_budget must be int"),
    ("burst = 3", "unknown key.*submit.burst"),
])
def test_bad_submit_table_is_an_error(tmp_path, line, match):
    path = write_profile(tmp_path)
    text = path.read_text()
    key = line.split(" ")[0]
    lines = [ln for ln in text.splitlines() if not ln.startswith(key + " ")]
    path.write_text("\n".join(lines) + "\n" + line + "\n")
    with pytest.raises(event.EventError, match=match):
        event.load_path(path)


# ------------------------------------------------------------------------------- the CTFd adapter
@pytest.fixture
def no_url_override(monkeypatch):
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(name, raising=False)


def test_ctfd_adapter_paces_at_the_profile_interval(tmp_path, no_url_override):
    prof = make_profile(tmp_path, interval=2.5)
    a = ctfd.make_adapter(prof, session=FakeSession([]))
    assert a._interval == 2.5
    assert ctfd.make_adapter(prof, session=FakeSession([]), submit_interval_s=7.0)._interval == 7.0


def test_ctfd_server_time_reads_the_date_header(tmp_path, no_url_override):
    prof = make_profile(tmp_path)
    base = prof.platform.base_url
    s = FakeSession([{"method": "HEAD", "url": base + "/", "status": 200,
                      "headers": {"Date": "Wed, 05 Nov 2025 13:00:00 GMT"}, "text": ""}])
    a = ctfd.make_adapter(prof, session=s)
    assert a.server_time() == 1762347600.0 + 0.5
    assert s.calls[0]["method"] == "HEAD"


def test_ctfd_server_time_without_a_date_fails_loudly(tmp_path, no_url_override):
    prof = make_profile(tmp_path)
    s = FakeSession([{"method": "HEAD", "url": prof.platform.base_url + "/", "status": 200, "text": ""}])
    with pytest.raises(PlatformError, match="no Date header"):
        ctfd.make_adapter(prof, session=s).server_time()


# ------------------------------------------------------------------------------- template and scaffold
def test_agent_rules_tell_every_solver_to_submit_on_sight():
    import dataclasses
    from ctf import eventrules
    base = event.load("csctf")
    auto = eventrules.render(base)
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert "Submit it yourself, at once." in auto[name] and "submit-queue approve" in auto[name]
        assert "Never run it yourself" in auto[name], "agents are told the approval is the player's"
    confirm = eventrules.render(dataclasses.replace(
        base, rules=dataclasses.replace(base.rules, submit_mode="confirm")))["AGENTS.md"]
    assert "Submit it yourself" not in confirm and "submit-queue approve" in confirm
    manual = eventrules.render(event.load("spooky"))["CLAUDE.md"]
    assert "Submit it yourself" not in manual and "submit-queue approve" not in manual


def test_new_profiles_spell_out_the_submit_queue():
    import datetime as dt
    from ctf import eventscaffold as sc
    data = sc.profile_data("acme", name="ACME", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2),
                           kind="ctfd", base_url="https://acme.example", prefixes=["ACME"],
                           submit_mode="auto", ai_on_platform="allowed")
    assert data["submit"] == {"per_minute": 10, "interval_s": 1.0, "per_challenge_interval_s": 3.0,
                              "max_hold_s": 600.0, "rotating_miss_budget": 6}
    assert sc.validate(data, "acme").submit == SubmitPace()


# ------------------------------------------------------------------------------- named errors
def test_submit_without_credentials_names_them(tmp_path, monkeypatch, capsys, no_url_override):
    for name in ("CTF_TOKEN", "CTF_COOKIE", *env.legacy_names("CTF_TOKEN"), *env.legacy_names("CTF_COOKIE")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_SUBMIT_STATE_DIR", str(tmp_path / "pace"))
    prof = make_profile(tmp_path)
    monkeypatch.setattr(event, "current", lambda root=None: prof)
    code, _, err = run(capsys, "submit", "5", flag("x"))
    assert code == 2 and "ctf submit: error:" in err and "CTF_TOKEN" in err
    assert "submit-queue drain" in err, "the operator is told the send is kept and how to resend it"
    [p] = SubmitQueue(prof).pending()
    assert p["state"] == "orphaned" and p["challenge_id"] == "5", "a send that raised stays spooled"
    [rec] = [r for r in ledger.read(tmp_path / "work") if r["event"] == "platform.submit"]
    assert rec["status"] == "error" and rec["judged"] is False and "CTF_TOKEN" in rec["error"]


def test_corrupt_spool_is_a_named_error(board, capsys):
    pend = board["work"] / "submitq" / "pending"
    pend.mkdir(parents=True)
    (pend / "torn.json").write_text("{")
    for action in ("pending", "drain", "status"):
        code, _, err = run(capsys, "submit-queue", action)
        assert code == 2 and "torn.json" in err, action
