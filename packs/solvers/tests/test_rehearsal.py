"""B-039: the wave rehearsal (ctf/rehearsal.py), the fake CTFd it runs against (ctf/fakectfd.py),
`ctf rehearse`, and the two pre-event hooks B-008 left as stubs (ctf/preevent.py). Everything runs on
127.0.0.1 against the fake; no model is called (the Codex binary is a stub or refused)."""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from ctf import client, event, paths, preevent, rehearsal, workspace
from ctf.fakectfd import FakeChallenge, FakeCTFd

UTC = dt.timezone.utc
FAST = dict(submit_interval=0.05, poll_interval=0.01)


def profile(categories=("Web", "Crypto"), kind="ctfd", submit_mode="auto", slug="demo"):
    plat = {"kind": kind}
    if kind != "manual":
        plat["base_url"] = "https://demo.example/"
    return event.parse({
        "slug": slug, "name": "Demo CTF", "categories": list(categories),
        "dates": {"start": dt.datetime(2030, 3, 1, tzinfo=UTC), "end": dt.datetime(2030, 3, 3, tzinfo=UTC)},
        "platform": plat, "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": submit_mode, "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


# ------------------------------------------------------------------------------- the fake

def _get(fake, path, token=None):
    h = {"Authorization": f"Token {token or fake.token}"}
    s = requests.Session()
    s.trust_env = False
    return s.get(fake.base_url + path, headers=h, timeout=5)


def _post(fake, path, body):
    s = requests.Session()
    s.trust_env = False
    return s.post(fake.base_url + path, json=body, headers={"Authorization": f"Token {fake.token}"}, timeout=5)


def test_fake_ctfd_is_closed_then_open_and_judges_attempts():
    board = [FakeChallenge(1, "a", "Web", files={"f.txt": b"x"}, flag="DEMO{a}"),
             FakeChallenge(2, "b", "Web", flag="DEMO{b}", solved=True)]
    with FakeCTFd(board, token="tok", open_after=1, min_attempt_gap=0.0) as fake:
        assert fake.base_url.startswith("http://127.0.0.1:")
        assert _get(fake, "/api/v1/challenges").status_code == 403
        assert _get(fake, "/api/v1/challenges/1").status_code == 403         # nothing before the open
        rows = _get(fake, "/api/v1/challenges").json()["data"]
        assert [r["id"] for r in rows] == [1, 2] and rows[1]["solved_by_me"]
        assert _get(fake, "/files/1/f.txt").content == b"x"
        verdict = lambda f, c=1: _post(fake, "/api/v1/challenges/attempt",
                                       {"challenge_id": c, "submission": f}).json()["data"]["status"]
        assert verdict("DEMO{wrong}") == "incorrect"
        assert verdict("DEMO{a}") == "correct"
        assert verdict("DEMO{a}") == "already_solved"
        assert {r["challenge_id"] for r in _get(fake, "/api/v1/teams/me/solves").json()["data"]} == {1, 2}


def test_fake_ctfd_rate_limits_fast_attempts_records_hints_and_refuses_bad_tokens():
    board = [FakeChallenge(1, "a", "Web", flag="DEMO{a}")]
    with FakeCTFd(board, token="tok", min_attempt_gap=5.0) as fake:
        first = _post(fake, "/api/v1/challenges/attempt", {"challenge_id": 1, "submission": "DEMO{x}"})
        second = _post(fake, "/api/v1/challenges/attempt", {"challenge_id": 1, "submission": "DEMO{a}"})
        assert first.json()["data"]["status"] == "incorrect"
        assert second.json()["data"]["status"] == "ratelimited"
        assert _get(fake, "/api/v1/hints/3").status_code == 403
        assert _get(fake, "/api/v1/challenges", token="other").status_code == 403
        assert _get(fake, "/api/v1/nope").status_code == 404
        kinds = [(r.kind, r.authed) for r in fake.log]
    assert ("hint", True) in kinds and ("unauthenticated", False) in kinds and kinds[-1] == ("unknown", True)
    assert ("unknown", False) not in kinds                # a bad token is not "a route the fake lacks"


def test_fake_ctfd_records_a_request_before_the_open_as_closed():
    with FakeCTFd([FakeChallenge(1, "a", "Web")], token="tok", open_after=1) as fake:
        assert _get(fake, "/api/v1/challenges/1").status_code == 403
        assert [r.kind for r in fake.log] == ["closed"]


def test_fake_ctfd_refuses_duplicate_ids_and_an_empty_token():
    with pytest.raises(ValueError, match="duplicate"):
        FakeCTFd([FakeChallenge(1, "a", "W"), FakeChallenge(1, "b", "W")], token="t")
    with pytest.raises(ValueError, match="token"):
        FakeCTFd([], token="")


# ------------------------------------------------------------------------------- board

def test_board_has_one_challenge_per_category_plus_three_controls():
    plan, notes = rehearsal.build_board(profile(("Web", "Crypto", "Misc")))
    assert [p.expect for p in plan] == ["correct"] * 3 + ["incorrect", "skipped-solved", "no-candidate"]
    assert [p.challenge.category for p in plan[:3]] == ["Web", "Crypto", "Misc"]
    assert len({p.planted for p in plan if p.planted}) == 5                  # every flag distinct
    wrong = plan[3]
    assert wrong.planted != wrong.challenge.flag
    assert plan[0].challenge.instance and not any(p.challenge.instance for p in plan[1:])
    assert notes == []
    _, notes = rehearsal.build_board(profile(()))
    assert notes and "stand-in categories" in notes[0]


# ------------------------------------------------------------------------------- the rehearsal

def test_ctfd_rehearsal_replays_a_wave_end_to_end(tmp_path):
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.passed, r.render()
    assert r.mode == "ctfd"
    assert [s.name for s in r.steps] == ["auth", "open", "pull", "route", "solve", "handoff", "submit", "instances",
                                         "hygiene"]
    sub = r.step("submit").detail
    assert "100 correct" in sub and "101 correct" in sub and "200 incorrect" in sub and "201 skipped-solved" in sub
    assert "3 paced attempt(s)" in sub
    work = tmp_path / "run" / "work"
    assert (work / "100-rehearsal-web" / "flag.txt").is_file()
    assert not (work / "200-rehearsal-wrong-flag" / "flag.txt").exists()
    brief = work / "202-rehearsal-decoy" / "codex_brief-rehearsal.md"
    assert brief.is_file() and "Demo CTF" in brief.read_text()
    assert set(r.timings) >= {"open_to_pulled", "open_to_first_submit", "open_to_last_submit", "total"}
    assert "REHEARSAL PASSED" in r.render()


def test_manual_rehearsal_reads_the_drop_folder_and_never_sends(tmp_path):
    r = rehearsal.rehearse(profile(kind="manual", submit_mode="manual"), workdir=tmp_path / "run", **FAST)
    assert r.passed, r.render()
    assert r.mode == "manual"
    assert [s.name for s in r.steps] == ["pull", "route", "solve", "handoff", "submit"]
    assert "refused by the gate" in r.step("submit").detail


def test_confirm_mode_ctfd_event_still_rehearses_the_carried_path(tmp_path):
    r = rehearsal.rehearse(profile(submit_mode="confirm"), workdir=tmp_path / "run", **FAST)
    assert r.passed, r.render()


def test_rehearsal_catches_a_pacer_that_does_not_pace(tmp_path, monkeypatch):
    monkeypatch.setattr(client.SubmitPacer, "wait_s", lambda self, st, now: 0.0)
    r = rehearsal.rehearse(profile(("Web", "Crypto", "Misc", "Pwn")), workdir=tmp_path / "run",
                           submit_interval=0.3, poll_interval=0.01)
    assert not r.passed
    assert r.step("submit").status == "fail" and "rate-limited" in r.step("submit").detail


def test_rehearsal_catches_a_broken_dedupe(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace.Challenge, "already_tried", lambda self, flag: False)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.step("submit").status == "fail" and "not deduped" in r.step("submit").detail


def test_rehearsal_catches_a_scan_that_misses_the_planted_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(rehearsal, "_scan", lambda files_dir, ff: [])
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.step("solve").status == "fail" and "disagrees with the board" in r.step("solve").detail


def test_rehearsal_catches_a_client_that_drops_its_token(tmp_path, monkeypatch):
    real = client.CTFd.__init__

    def init(self, cfg=None, *, profile=None):
        real(self, cfg, profile=profile)
        self.s.headers.pop("Authorization", None)
    monkeypatch.setattr(client.CTFd, "__init__", init)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert not r.passed and r.step("auth").status == "fail" and "not authenticated" in r.step("auth").detail
    assert [s.name for s in r.steps] == ["auth"]                       # nothing runs on a dead client


def test_rehearsal_open_step_names_unauthenticated_polls(tmp_path, monkeypatch):
    """A client that authenticates `ctf me` but not the list call: `ctf wait` sees only 403s, which a
    real CTFd also answers for a closed board; the rehearsal says which it was."""
    real_get = client.CTFd._get

    def get(self, path, **kw):
        if path == "/challenges":
            self.s.headers.pop("Authorization", None)
        return real_get(self, path, **kw)
    monkeypatch.setattr(client.CTFd, "_get", get)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", open_timeout=0.3, **FAST)
    assert r.step("open").status == "fail" and "carried no valid token" in r.step("open").detail


def test_rehearsal_fails_when_the_handoff_script_is_broken(tmp_path):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "codex_handoff.sh").write_text("#!/bin/bash\necho 'broken' >&2\nexit 2\n")
    for d in ("solvers",):                      # the router reads manifests from root: none here
        (root / d).mkdir()
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", root=root, **FAST)
    assert r.step("handoff").status == "fail" and "exit 2" in r.step("handoff").detail


def test_rehearsal_refuses_gamemaster_a_used_folder_and_bad_knobs(tmp_path):
    with pytest.raises(rehearsal.RehearsalError, match="gamemaster"):
        rehearsal.rehearse(profile(kind="gamemaster"), workdir=tmp_path / "gm")
    used = tmp_path / "used"
    used.mkdir()
    (used / "x").write_text("x")
    with pytest.raises(rehearsal.RehearsalError, match="not empty"):
        rehearsal.rehearse(profile(), workdir=used)
    with pytest.raises(rehearsal.RehearsalError, match="submit_interval"):
        rehearsal.rehearse(profile(), workdir=tmp_path / "a", submit_interval=0)
    with pytest.raises(rehearsal.RehearsalError, match="open_after"):
        rehearsal.rehearse(profile(), workdir=tmp_path / "b", open_after=0)


def test_rehearsal_never_sends_the_environment_token(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "real-token-must-not-travel")
    seen = []
    real = FakeCTFd._route

    def spy(self, method, path, body, authed):
        seen.append(self.token)
        return real(self, method, path, body, authed)
    monkeypatch.setattr(FakeCTFd, "_route", spy)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.passed and seen and all(t.startswith("rehearsal-") for t in seen)
    assert "real-token-must-not-travel" not in json.dumps(r.to_dict())


# ------------------------------------------------------------------------------- pre-event hooks

def stub_codex(tmp_path) -> Path:
    p = tmp_path / "codex"
    p.write_text('#!/bin/bash\n# ctf-codex-stub\nout=""\nwhile [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out="$2"; shift; }; shift; '
                 'done\necho PREFLIGHT_OK > "$out"\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def test_rehearsal_hook_passes_a_ctfd_event_and_fails_gamemaster():
    r = preevent.rehearsal_hook(profile())
    assert r.status == "ok" and r.passed, r.detail
    r = preevent.rehearsal_hook(profile(kind="gamemaster"))
    assert r.status == "fail" and "cannot rehearse" in r.detail


@pytest.mark.needs_tool("bash", "perl", "shasum")
def test_doctor_hook_passes_with_a_working_codex_stub(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("CODEX_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("CODEX_BIN", str(stub_codex(tmp_path)))
    monkeypatch.setenv("CODEX_PREFLIGHT_DIR", str(tmp_path / "pf"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex-home"))
    r = preevent.doctor_hook(profile())
    assert r.status == "ok", r.detail
    assert "skip instances" in r.detail                                  # listed, not hidden


def test_doctor_hook_fails_naming_the_failed_check(monkeypatch, tmp_path):
    monkeypatch.delenv("CODEX_BIN", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex-home"))     # never the operator's config
    monkeypatch.setenv("CTF_TESTING", "1")
    r = preevent.doctor_hook(profile())
    assert r.status == "fail" and "codex-smoke" in r.detail and not r.passed


def test_run_hooks_runs_the_real_hooks_not_stubs(monkeypatch, tmp_path):
    monkeypatch.delenv("CODEX_BIN", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex-home"))
    res = preevent.run_hooks(profile())
    assert [r.name for r in res] == ["doctor", "rehearsal"]
    assert all(r.status != "stub" for r in res)
    assert res[1].passed


# ------------------------------------------------------------------------------- CLI

def run_ctf(*args):
    return subprocess.run([sys.executable, "-m", "ctf", *args], cwd=paths.repo_root(), env=dict(os.environ),
                          capture_output=True, text=True, timeout=180)


def test_cli_rehearse_pink_json_keep_and_gamemaster(tmp_path):
    keep = tmp_path / "kept"
    r = run_ctf("rehearse", "--event", "pink", "--submit-interval", "0.05", "--json", "--keep", str(keep))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["passed"] and doc["slug"] == "pink"
    assert {s["name"]: s["status"] for s in doc["steps"]}["route"] == "warn"     # Minecraft has no engine
    assert (keep / "work").is_dir()
    r = run_ctf("rehearse", "--event", "huntress")
    assert r.returncode == 2 and "no rehearsal for a gamemaster platform" in r.stderr


def test_rehearsal_hygiene_catches_a_hint_request_and_an_unknown_route(tmp_path, monkeypatch):
    real = client.CTFd.team_solved_ids

    def leaky(self):
        self.s.get(self.api + "/hints/1", timeout=5)          # around the client's own hint guard
        self.s.get(self.api + "/scoreboard/top/10", timeout=5)
        return real(self)
    monkeypatch.setattr(client.CTFd, "team_solved_ids", leaky)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    h = r.step("hygiene")
    assert h.status == "fail" and "a hint endpoint was requested" in h.detail
    assert "GET /api/v1/scoreboard/top/10" in h.detail


def test_rehearsal_instance_step_fails_when_the_probe_breaks(tmp_path, monkeypatch):
    from ctf import instances

    def broken(self, cid):
        raise instances.InstanceError("plugin route moved")
    monkeypatch.setattr(instances.Instances, "status", broken)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.step("instances").status == "fail" and "plugin route moved" in r.step("instances").detail


def test_rehearsal_catches_a_wait_that_does_not_wait(tmp_path, monkeypatch):
    from ctf import cli
    monkeypatch.setattr(cli, "wait_for_open", lambda *a, **k: (0, "OPEN — at once"))
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.step("open").status == "fail" and "saw 0 closed polls" in r.step("open").detail


def test_rehearsal_catches_a_client_that_sends_twice(tmp_path, monkeypatch):
    real = client.CTFd.submit

    def twice(self, cid, flag):
        first = real(self, cid, flag)
        real(self, cid, flag)                                     # a silent retry nobody asked for
        return first
    monkeypatch.setattr(client.CTFd, "submit", twice)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    assert r.step("submit").status == "fail" and "the fake saw 6 attempt(s), planned 3" in r.step("submit").detail


def test_rehearsal_fails_when_the_handoff_writes_no_brief_or_a_wrong_one(tmp_path):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    (root / "solvers").mkdir()
    script = root / "tools" / "codex_handoff.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", root=root, **FAST)
    assert r.step("handoff").status == "fail" and "no brief at" in r.step("handoff").detail
    script.write_text('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = --challenge ] && d="$2"; shift; done\n'
                      'echo "some other event" > "$d/codex_brief-rehearsal.md"\n')
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run2", root=root, **FAST)
    assert r.step("handoff").status == "fail" and "does not name the event" in r.step("handoff").detail


# ------------------------------------------------------------------------------- verification round 1

def test_rehearsal_catches_a_client_that_misreads_the_verdict(tmp_path, monkeypatch):
    """A client that reads the judge's 'incorrect' as 'correct' must not get REHEARSAL PASSED."""
    import dataclasses
    real = client.CTFd.submit

    def misread(self, cid, flag):
        sub = real(self, cid, flag)
        return dataclasses.replace(sub, status="correct") if sub.status == "incorrect" else sub
    monkeypatch.setattr(client.CTFd, "submit", misread)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    s = r.step("submit")
    assert not r.passed and s.status == "fail"
    assert "200: correct" in s.detail and "planned incorrect" in s.detail


def test_manual_rehearsal_catches_a_gate_that_sends(tmp_path, monkeypatch):
    from ctf.platform import manual, policy
    from ctf.platform.base import SubmitResult, SubmitStatus
    real = policy.base_checks
    monkeypatch.setattr(policy, "base_checks", lambda prof, req: None if prof.manual else real(prof, req))
    monkeypatch.setattr(manual.ManualAdapter, "submit",
                        lambda self, cid, flag: SubmitResult(SubmitStatus.CORRECT, "sent", sent=True))
    r = rehearsal.rehearse(profile(kind="manual", submit_mode="manual"), workdir=tmp_path / "run", **FAST)
    s = r.step("submit")
    assert not r.passed and s.status == "fail"
    assert "100: the gate let a send through on a manual event (correct)" in s.detail


def test_rehearsal_instance_step_fails_on_a_wrong_connect_address(tmp_path, monkeypatch):
    from ctf import instances
    real = instances.Instances.status

    def moved(self, cid):
        info = dict(real(self, cid))
        info["connect"] = "127.0.0.1:1"
        return info
    monkeypatch.setattr(instances.Instances, "status", moved)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    s = r.step("instances")
    assert s.status == "fail" and "wanted connect 127.0.0.1:40100" in s.detail


def test_rehearsal_hygiene_catches_one_call_that_drops_its_token(tmp_path, monkeypatch):
    real = client.CTFd.team_solved_ids

    def tokenless(self):
        self.s.get(self.api + "/teams/me/solves", headers={"Authorization": None}, timeout=5)
        return real(self)
    monkeypatch.setattr(client.CTFd, "team_solved_ids", tokenless)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    h = r.step("hygiene")
    assert h.status == "fail" and "1 unauthenticated request(s): GET /api/v1/teams/me/solves" in h.detail
    assert "routes the fake does not serve" not in h.detail       # a served route, not an unknown one


def test_rehearsal_hygiene_catches_a_pull_before_the_open(tmp_path, monkeypatch):
    real = client.CTFd.me

    def eager(self):
        self.s.get(self.api + "/challenges/100", timeout=5)
        return real(self)
    monkeypatch.setattr(client.CTFd, "me", eager)
    r = rehearsal.rehearse(profile(), workdir=tmp_path / "run", **FAST)
    h = r.step("hygiene")
    assert h.status == "fail" and "requested before the board opened: GET /api/v1/challenges/100" in h.detail
    assert "routes the fake does not serve" not in h.detail
