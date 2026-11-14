"""B-004: the no-model dispatcher (ctf/dispatch.py, ctf/cli/dispatch.py).

Offline. A fake platform drives the real B-017 watcher into a real event stream; the dispatcher reads
that stream and writes claims and handouts with no model and no platform call. Nothing is submitted.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from ctf import cli, dispatch, event, flagfmt, intake, ledger, watch
from ctf.cli import dispatch as cli_dispatch
from ctf.platform.base import Challenge, FileRef, PlatformError


# ------------------------------------------------------------------------------- fake platform + stream

class HTTPErr(PlatformError):
    def __init__(self, msg, status):
        super().__init__(msg)
        self.status = status


class Board:
    """A fake CTFd-like board: the listing carries no description/files/connection (details do)."""
    kind = "fake"

    def __init__(self):
        self.rows: dict[str, Challenge] = {}

    def put(self, cid, name="Chal", category="Misc", points=100, description="", files=(),
            connection_info="", tags=()):
        self.rows[cid] = Challenge(id=cid, name=name, category=category, points=points,
                                   description=description, files=tuple(files),
                                   connection_info=connection_info, tags=tuple(tags))

    def list_challenges(self):
        return [Challenge(id=c.id, name=c.name, category=c.category, points=c.points, tags=c.tags)
                for c in self.rows.values()]

    def get_challenge(self, cid):
        if cid not in self.rows:
            raise HTTPErr(f"GET /challenges/{cid} -> 404", 404)
        return self.rows[cid]

    def download_files(self, cid, dest):
        raise AssertionError("the dispatcher never downloads")

    def submit(self, cid, flag):
        raise AssertionError("the dispatcher never submits")


@pytest.fixture
def prof():
    return event.load("csctf")


def build_stream(board, wd, *, details_per_poll=4, polls=2):
    """Drive the real watcher over `board` into <wd>/watch/events.jsonl (and brief versions)."""
    w = watch.Watcher(board, workdir=wd, details_per_poll=details_per_poll, ledger=False)
    with w:
        for _ in range(polls):
            w.tick()
    return watch.read_events(wd)


# --------------------------------------------------------------------------------------- grep + submit

def test_flag_grep_ere_is_built_from_the_event_prefixes(prof):
    ere = dispatch.flag_grep_ere(prof)
    # every profile prefix is an alternative, and the body is a brace group (derived, not hardcoded)
    assert ere.startswith("(") and ere.endswith(r"\{[^}]*\}")
    assert set(ere[1:ere.index(")")].split("|")) == set(prof.flag.prefixes)


def test_grep_ere_falls_back_to_any_word_prefix_when_the_format_is_unknown(prof):
    unknown = dataclasses.replace(prof, flag=dataclasses.replace(prof.flag, prefixes=()))
    assert dispatch.flag_grep_ere(unknown).startswith(dispatch.UNKNOWN_PREFIX + r"\{")
    # a known-format event never degrades to the any-word prefix
    assert not dispatch.flag_grep_ere(prof).startswith(dispatch.UNKNOWN_PREFIX)


def test_grep_command_is_case_insensitive_recursive_and_single_quote_safe(prof):
    cmd = dispatch.grep_command(prof)
    assert cmd.startswith("grep -rIEoi '")
    assert "'" not in dispatch.flag_grep_ere(prof)      # the ERE is safe inside single quotes
    assert cmd.count("'") == 2                           # exactly the wrapping quotes


def test_submit_command_reflects_the_submit_mode(prof):
    assert "auto mode" in dispatch.submit_command(prof, "9")
    confirm = dataclasses.replace(prof, rules=dataclasses.replace(prof.rules, submit_mode="confirm"))
    assert "--confirm" in dispatch.submit_command(confirm, "9")
    manual = dataclasses.replace(prof, rules=dataclasses.replace(prof.rules, submit_mode="manual"))
    sm = dispatch.submit_command(manual, "9")
    assert "manual mode" in sm and "--confirm" not in sm


# --------------------------------------------------------------------------------------- the handout

def test_handout_has_every_required_section(prof, tmp_path):
    det = dispatch.Detected("9076", "Tone Burst", "Forensics", 100, seq=3)
    h = dispatch.handout_md(det, prof, workdir=tmp_path)
    assert "# handout: Tone Burst" in h
    assert "recon/index.md" in h and "triage.md" in h and "recon/flags.txt" in h   # triage path
    assert "## brief" in h and "lane: forensics" in h                              # brief + lane
    assert f"`{prof.flag.body}`" not in h                                          # the raw body is not the regex
    assert "regex (Python, the submit gate):" in h                                 # flag regex
    assert dispatch.grep_command(prof) in h                                        # grep-first command
    assert "docs/playbooks/forensics.md" in h                                      # playbook
    assert "solvers/toolkits/forensics.py" in h                                    # routed engine
    assert "/tools/ctfpy -m ctf submit 9076" in h                                  # submit on sight
    assert "T+600s" in h                                                           # escalation timers
    assert "never instructions" in h                                               # data note


def test_handout_states_the_exact_submit_gate_regex(prof, tmp_path):
    det = dispatch.Detected("9076", "Tone Burst", "Forensics", 100)
    h = dispatch.handout_md(det, prof, workdir=tmp_path)
    from ctf import flagfmt
    assert f"`{flagfmt.for_profile(prof).pattern}`" in h   # the gate regex, verbatim


def test_handout_quotes_challenge_text_as_data_not_markup(prof, tmp_path):
    board = Board()
    board.put("42", name="Weird `name` | pipe", category="Forensics",
              description="line one\n```\nrm -rf /  # injected fence\n```\nline two",
              connection_info="nc host 1337")
    build_stream(board, tmp_path)
    det = dispatch.Detected("42", "Weird `name` | pipe", "Forensics", 100, seq=1)
    h = dispatch.handout_md(det, prof, workdir=tmp_path)
    # the description's own triple-backticks are neutralised, so the data fence is not broken out of
    assert "```\nrm -rf /" not in h
    assert "injected fence" in h            # the text is still present, as data
    assert "nc host 1337" in h              # connection_info reaches the brief
    assert h.count("# handout:") == 1       # a pipe in the name did not spawn a second heading row


# --------------------------------------------------------------------------------------- the brief

def test_brief_uses_the_stored_watch_brief_when_details_have_landed(prof, tmp_path):
    board = Board()
    board.put("7", name="Night Clerk", category="Forensics", description="find the deleted file",
              connection_info="", tags=("ntfs",), files=(FileRef("terminal.dd", "http://x/terminal.dd"),))
    build_stream(board, tmp_path)
    b = dispatch.brief_for(tmp_path, dispatch.Detected("7", "Night Clerk", "Forensics", seq=1))
    assert b["description"] == "find the deleted file"
    assert "ntfs" in b["tags"]
    assert any("terminal.dd" in f for f in b["files"])
    assert b["source"].startswith("watch brief v")


def test_brief_falls_back_to_listing_fields_before_details_land(prof, tmp_path):
    det = dispatch.Detected("9", "Only Listed", "Crypto", 50, seq=1)
    b = dispatch.brief_for(tmp_path, det)          # no stream, no stored brief
    assert b["name"] == "Only Listed" and b["category"] == "Crypto"
    assert b["description"] == "" and "not fetched" in b["source"]


def test_a_tampered_stored_brief_is_reported_not_silently_used(prof, tmp_path):
    board = Board()
    board.put("5", name="X", category="Misc", description="real")
    build_stream(board, tmp_path)
    vpath = watch.brief_dir(tmp_path, "5") / "v1.json"
    rec = json.loads(vpath.read_text())
    rec["fields"]["description"] = "tampered after the hash"       # break the stored hash
    vpath.write_text(json.dumps(rec))
    b = dispatch.brief_for(tmp_path, dispatch.Detected("5", "X", "Misc", seq=1))
    assert "unusable" in b["source"]                               # loud, not silent
    assert b["description"] == ""                                  # the tampered text is not used


# --------------------------------------------------------------------------------------- dispatch_one

def test_dispatch_one_writes_claim_handout_and_a_claim_ledger_record(prof, tmp_path):
    det = dispatch.Detected("9080", "Tone Burst", "rev", 100, seq=12)
    claim = dispatch.dispatch_one(det, prof, workdir=tmp_path, clock=lambda: 1234.5)
    cp = dispatch.claim_path(tmp_path, "9080")
    assert cp.is_file()
    rec = json.loads(cp.read_text())
    assert rec["challenge_id"] == "9080" and rec["lane"] == "reverse"   # alias "rev" canonicalised
    assert rec["seq"] == 12 and rec["status"] == "dispatched"
    assert (tmp_path / "9080-tone-burst" / "handout.md").is_file()
    assert claim.handout == rec["handout"]
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "claim"]
    assert len(recs) == 1 and recs[0]["challenge_id"] == "9080" and recs[0]["lane"] == "reverse"


def test_dispatch_one_can_skip_the_ledger(prof, tmp_path):
    dispatch.dispatch_one(dispatch.Detected("1", "A", "Misc"), prof, workdir=tmp_path, record=False)
    assert not any(r["event"] == "claim" for r in ledger.read(tmp_path))


# --------------------------------------------------------------------------------------- Dispatcher

def test_dispatcher_claims_each_new_challenge_once_and_starts_intake_for_the_batch(prof, tmp_path):
    board = Board()
    board.put("a", name="Aye", category="Web")
    board.put("b", name="Bee", category="Crypto")
    build_stream(board, tmp_path)
    started: list[list[str]] = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=started.append)
    claims = d.once()
    assert sorted(c.challenge_id for c in claims) == ["a", "b"]
    assert started == [["a", "b"]]                       # intake started once, for the new ids
    # a second pass finds nothing new: no new claims, intake not started again
    assert d.once() == []
    assert started == [["a", "b"]]


def test_the_claim_is_written_before_intake_is_started(prof, tmp_path):
    board = Board()
    board.put("c", name="Sea", category="Forensics")
    build_stream(board, tmp_path)
    seen: list[bool] = []

    def runner(ids):
        seen.append(all(dispatch.claim_path(tmp_path, i).is_file() for i in ids))

    dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=runner).once()
    assert seen == [True]      # the claim file existed when intake was asked to start


def test_dispatcher_without_a_runner_still_writes_claims_and_handouts(prof, tmp_path):
    board = Board()
    board.put("z", name="Zed", category="Misc")
    build_stream(board, tmp_path)
    claims = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=None).once()
    assert len(claims) == 1
    assert dispatch.claim_path(tmp_path, "z").is_file()


def test_run_follows_the_stream_and_stops_when_asked(prof, tmp_path):
    board = Board()
    board.put("m", name="Em", category="Web")
    build_stream(board, tmp_path)
    started: list[list[str]] = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=started.append)
    calls = [0]

    def stop():
        calls[0] += 1
        return calls[0] >= 1          # one pass, then stop

    claims = d.run(stop=stop, sleep=lambda s: None)
    assert [c.challenge_id for c in claims] == ["m"]
    assert started == [["m"]]


def test_dispatcher_ignores_non_challenge_events(prof, tmp_path):
    board = Board()
    board.put("w", name="Dubya", category="Web")
    build_stream(board, tmp_path)
    # board_open, wave, watch_start etc. are in the stream too; only challenge_new becomes a claim
    kinds = {e["event"] for e in watch.read_events(tmp_path)}
    assert {"board_open", "wave", "challenge_new"} <= kinds
    claims = dispatch.Dispatcher(prof, workdir=tmp_path).once()
    assert [c.challenge_id for c in claims] == ["w"]


# --------------------------------------------------------------------------------------- the CLI

def test_cli_show_prints_a_handout(prof, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = Board()
    board.put("q", name="Queue", category="Crypto", description="rsa")
    build_stream(board, tmp_path)
    assert cli.main(["dispatch", "--event", "csctf", "show", "q"]) == 0
    out = capsys.readouterr().out
    assert "# handout: Queue" in out and "docs/playbooks/crypto.md" in out


def test_cli_once_dispatches_from_the_stream_without_intake(prof, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = Board()
    board.put("k", name="Kay", category="Web")
    build_stream(board, tmp_path)
    assert cli.main(["dispatch", "--event", "csctf", "once", "--no-intake", "--json"]) == 0
    out = capsys.readouterr().out.strip()
    rec = json.loads(out.splitlines()[0])
    assert rec["challenge_id"] == "k" and rec["dispatcher"] == "no-model"
    assert dispatch.claim_path(tmp_path, "k").is_file()


# ------------------------------------------------------------------- round 1: non-blocking intake

def test_intake_runs_in_the_background_so_a_challenge_arriving_mid_intake_is_claimed(prof, tmp_path):
    board = Board()
    board.put("a", name="Aye", category="Web")
    build_stream(board, tmp_path)
    gate, a_entered, a_running = threading.Event(), threading.Event(), threading.Event()
    calls: list[list[str]] = []

    def runner(ids):                      # a slow intake: blocks until the test releases it
        calls.append(list(ids))
        if "a" in ids:
            a_entered.set()
            a_running.set()
        try:
            gate.wait(3)
        finally:
            if "a" in ids:
                a_running.clear()

    polls = [0]
    seen = {}

    def sleep(_):
        polls[0] += 1
        if polls[0] == 1:
            assert a_entered.wait(5)                    # a's intake has started and is blocked
            board.put("b", name="Bee", category="Crypto")
            build_stream(board, tmp_path, polls=1)      # a second challenge reaches the stream now
        time.sleep(0.005)

    def stop():
        if dispatch.claim_path(tmp_path, "b").is_file():
            seen["a_intake_still_running"] = a_running.is_set()
            gate.set()
            return True
        return polls[0] >= 200

    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=runner)
    claims = d.run(stop=stop, sleep=sleep)
    assert [c.challenge_id for c in claims] == ["a", "b"]
    assert seen == {"a_intake_still_running": True}     # b was claimed while a's intake was blocked
    assert calls == [["a"], ["b"]]                      # each batch got its own intake
    assert [r.status for r in d.intake_results] == ["done", "done"]
    assert json.loads(dispatch.claim_path(tmp_path, "a").read_text())["intake"] == "done"


def test_once_without_wait_returns_while_intake_is_still_running(prof, tmp_path):
    board = Board()
    board.put("a", name="Aye", category="Web")
    build_stream(board, tmp_path)
    gate = threading.Event()
    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=lambda ids: gate.wait(3))
    claims = d.once(wait=False)
    assert [c.challenge_id for c in claims] == ["a"]
    assert d.intake_results == []                       # intake has not ended: once() did not block
    gate.set()
    assert [r.status for r in d.wait(5)] == ["done"]


# ------------------------------------------------------------------- round 1: follow loop

def test_run_stops_when_until_passes_on_the_dispatcher_clock(prof, tmp_path):
    now = [1000.0]
    slept: list[float] = []

    def sleep(s):
        slept.append(s)
        assert len(slept) < 50, "run() did not stop at until"
        now[0] += s

    d = dispatch.Dispatcher(prof, workdir=tmp_path, clock=lambda: now[0])
    assert d.run(until=1003.0, poll=1.0, sleep=sleep) == []
    assert slept == [1.0, 1.0, 1.0]                     # polled at t=1000,1001,1002; stopped at 1003


def test_run_advances_the_stream_cursor(prof, tmp_path, monkeypatch):
    board = Board()
    board.put("m", name="Em", category="Web")
    evs = build_stream(board, tmp_path)
    last = max(e["seq"] for e in evs)
    real = watch.read_events
    sinces: list[int] = []

    def spy(wd=None, since=0):
        sinces.append(since)
        return real(wd, since=since)

    monkeypatch.setattr(dispatch._watch, "read_events", spy)
    n = [0]

    def stop():
        n[0] += 1
        return n[0] >= 3

    d = dispatch.Dispatcher(prof, workdir=tmp_path)
    assert [c.challenge_id for c in d.run(stop=stop, sleep=lambda s: None)] == ["m"]
    assert sinces == [0, last, last]                    # each poll reads only what is new


def test_run_on_claim_fires_for_each_claim(prof, tmp_path):
    board = Board()
    board.put("a", name="Aye", category="Web")
    board.put("b", name="Bee", category="Web")
    build_stream(board, tmp_path)
    got = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, on_claim=got.append)
    d.run(stop=lambda: True, sleep=lambda s: None)
    assert sorted(c.challenge_id for c in got) == ["a", "b"]


# ------------------------------------------------------------------- round 1: intake failure + retry

def _one_challenge(tmp_path, cid="a"):
    board = Board()
    board.put(cid, name="Aye", category="Web")
    build_stream(board, tmp_path)


def test_a_failed_intake_is_marked_named_and_retried(prof, tmp_path):
    _one_challenge(tmp_path)
    calls: list[list[str]] = []

    def runner(ids):
        calls.append(list(ids))
        if len(calls) == 1:
            raise intake.IntakeError("download refused")

    now = [0.0]
    got = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=runner, clock=lambda: now[0],
                            retry_after=10, on_intake=got.append)
    assert [c.challenge_id for c in d.once()] == ["a"]
    rec = json.loads(dispatch.claim_path(tmp_path, "a").read_text())
    assert rec["intake"] == "failed" and rec["intake_attempts"] == 1
    assert "IntakeError" in rec["intake_error"] and "download refused" in rec["intake_error"]
    assert got and got[0].challenge_id == "a" and "download refused" in got[0].reason
    assert d.once() == [] and calls == [["a"]]          # not retried before retry_after
    now[0] = 10.0
    assert d.once() == []                               # no new claim, but intake retried
    assert calls == [["a"], ["a"]]
    rec = json.loads(dispatch.claim_path(tmp_path, "a").read_text())
    assert rec["intake"] == "done" and rec["intake_attempts"] == 2 and rec["intake_error"] is None


def test_intake_retries_stop_at_max_attempts(prof, tmp_path):
    _one_challenge(tmp_path)
    calls = []

    def runner(ids):
        calls.append(list(ids))
        raise RuntimeError("always broken")

    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=runner, retry_after=0,
                            max_intake_attempts=2)
    for _ in range(4):
        d.once()
    assert len(calls) == 2
    assert json.loads(dispatch.claim_path(tmp_path, "a").read_text())["intake_attempts"] == 2
    assert [r.status for r in d.failed()] == ["failed", "failed"]


def test_a_non_zero_intake_outcome_marks_that_challenge_failed(prof, tmp_path):
    board = Board()
    board.put("a", name="Aye", category="Web")
    board.put("b", name="Bee", category="Web")
    build_stream(board, tmp_path)

    def runner(ids):
        return [intake.Outcome(i, 3 if i == "a" else 0, 0.0, 0.1, log=tmp_path / f"{i}.log") for i in ids]

    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=runner)
    d.once()
    res = {r.challenge_id: r for r in d.intake_results}
    assert res["a"].status == "failed" and "exited 3" in res["a"].reason and "a.log" in res["a"].reason
    assert res["b"].status == "done" and res["b"].reason is None


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-I", "-c", "pass"])
    p.wait()
    return p.pid


def test_a_claim_left_pending_by_a_dead_dispatcher_gets_intake(prof, tmp_path):
    _one_challenge(tmp_path)
    dispatch.dispatch_one(dispatch.Detected("a", "Aye", "Web"), prof, workdir=tmp_path,
                          intake=dispatch.INTAKE_PENDING)
    dispatch.update_claim(tmp_path, "a", dispatcher_pid=_dead_pid())   # it died before intake started
    calls = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=calls.append)
    assert d.once() == []                               # already claimed: no second claim
    assert calls == [["a"]]                             # but intake is started for it
    assert json.loads(dispatch.claim_path(tmp_path, "a").read_text())["intake"] == "done"


def test_a_pending_claim_owned_by_a_live_dispatcher_is_left_alone(prof, tmp_path):
    _one_challenge(tmp_path)
    dispatch.dispatch_one(dispatch.Detected("a", "Aye", "Web"), prof, workdir=tmp_path,
                          intake=dispatch.INTAKE_PENDING)
    dispatch.update_claim(tmp_path, "a", dispatcher_pid=os.getppid())  # another, live process owns it
    calls = []
    dispatch.Dispatcher(prof, workdir=tmp_path, intake_runner=calls.append).once()
    assert calls == []


def test_a_challenge_new_with_no_id_is_refused(prof):
    with pytest.raises(dispatch.DispatchError, match="no challenge_id"):
        dispatch.Detected.from_event({"event": "challenge_new", "seq": 4, "name": "x"})
    with pytest.raises(dispatch.DispatchError):
        dispatch.Detected.from_event({"event": "challenge_new", "seq": 4, "challenge_id": ""})


def test_a_corrupt_claim_is_reported_once_and_not_redispatched(prof, tmp_path):
    _one_challenge(tmp_path)
    cp = dispatch.claim_path(tmp_path, "a")
    cp.parent.mkdir(parents=True)
    cp.write_text("{not json")
    with pytest.raises(dispatch.DispatchError, match="unreadable claim"):
        dispatch.claimed_ids(tmp_path)
    probs = []
    d = dispatch.Dispatcher(prof, workdir=tmp_path, on_problem=probs.append)
    assert d.once() == [] and d.once() == []
    assert len(probs) == 1 and str(cp) in probs[0]      # named, and only once
    assert cp.read_text() == "{not json"                # not silently overwritten


# ------------------------------------------------------------------- round 1: handout content

def test_brief_and_handout_use_the_latest_stored_brief_version(prof, tmp_path):
    board = Board()
    board.put("7", name="Night Clerk", category="Forensics", description="first text")
    build_stream(board, tmp_path)
    v1 = watch.brief_dir(tmp_path, "7") / "v1.json"
    rec = json.loads(v1.read_text())
    rec["fields"]["description"] = "second text"
    rec["version"] = 2
    rec["sha256"] = watch.fields_sha256(rec["fields"])
    (v1.parent / "v2.json").write_text(json.dumps(rec))
    det = dispatch.Detected("7", "Night Clerk", "Forensics", seq=1)
    b = dispatch.brief_for(tmp_path, det)
    assert b["description"] == "second text" and b["source"] == "watch brief v2"
    h = dispatch.handout_md(det, prof, workdir=tmp_path)
    assert "second text" in h and "first text" not in h


def test_handout_lists_the_brief_tags_and_files(prof, tmp_path):
    board = Board()
    board.put("7", name="Night Clerk", category="Forensics", description="d",
              tags=("ntfs", "carving"), files=(FileRef("terminal.dd", "http://x/terminal.dd"),))
    build_stream(board, tmp_path)
    h = dispatch.handout_md(dispatch.Detected("7", "Night Clerk", "Forensics"), prof, workdir=tmp_path)
    tags = [ln for ln in h.splitlines() if ln.startswith("- tags: ")]
    files = [ln for ln in h.splitlines() if ln.startswith("- files: ")]
    assert tags and "`ntfs`" in tags[0] and "`carving`" in tags[0]
    assert files and "terminal.dd" in files[0]


def test_handout_states_the_proof_token_when_the_profile_has_one(prof, tmp_path):
    hunt = event.load("huntress")
    ff = flagfmt.for_profile(hunt)
    assert ff.proof_pattern
    h = dispatch.handout_md(dispatch.Detected("1", "Web One", "Web"), hunt, workdir=tmp_path)
    assert f"- proof token: `{ff.proof_pattern}`" in h
    assert "proof token" not in dispatch.handout_md(dispatch.Detected("1", "W", "Web"), prof, workdir=tmp_path)


def test_handout_names_a_missing_playbook_instead_of_a_dead_path(prof, tmp_path):
    for cat, lane in (("Hardware", "hardware"), ("Reverse Engineering", "reverse engineering")):
        h = dispatch.handout_md(dispatch.Detected("1", "X", cat), prof, workdir=tmp_path)
        body = h.split("## playbook", 1)[1].split("##", 1)[0]
        assert f"no playbook for lane `{lane}`" in body
        assert "docs/playbooks/" + lane + ".md" not in body
    h = dispatch.handout_md(dispatch.Detected("1", "X", ""), prof, workdir=tmp_path)
    assert "no playbook for lane" in h and "docs/playbooks/.md" not in h
    # a real lane names its real file
    assert dispatch.playbook_path("forensics").is_file()
    assert dispatch.playbook_path("../forensics") is None


# ------------------------------------------------------------------- round 1: hostile id

@pytest.mark.needs_tool("sh")
def test_submit_command_shell_quotes_a_hostile_id(prof, tmp_path):
    hostile = "x'$(echo PWNED)\"`echo TICK`"
    cmd = dispatch.submit_command(prof, hostile)
    args = cmd.split(" -m ctf submit ", 1)[1].split("   #", 1)[0]
    # what a shell actually passes as arguments when an agent pastes the command
    out = subprocess.run(["sh", "-c", "printf '%s\\n' " + args], capture_output=True, text=True,
                         cwd=tmp_path, timeout=10).stdout.splitlines()
    assert out == [hostile, "<FLAG>"]
    # B-043: spelled to run from the challenge folder, not only the checkout
    assert dispatch.submit_command(prof, "9076").startswith(
        f"{dispatch._paths.repo_root().resolve()}/tools/ctfpy -m ctf submit 9076 '<FLAG>'")


# ------------------------------------------------------------------- round 1: the CLI

def test_cli_run_with_a_duration_dispatches_and_stops(prof, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = Board()
    board.put("k", name="Kay", category="Web")
    build_stream(board, tmp_path)
    t0 = time.monotonic()
    assert cli.main(["dispatch", "--event", "csctf", "run", "--duration", "0.2", "--poll", "0.02",
                     "--no-intake", "--json"]) == 0
    assert time.monotonic() - t0 < 5
    lines = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(x)["challenge_id"] for x in lines] == ["k"]


def test_cli_run_names_an_intake_failure_and_exits_1(prof, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = Board()
    board.put("k", name="Kay", category="Web")
    build_stream(board, tmp_path)

    def broken(profile, wd):
        def run(ids):
            raise intake.IntakeError("no adapter configured")
        return run

    monkeypatch.setattr(cli_dispatch, "_intake_runner", broken)
    assert cli.main(["dispatch", "--event", "csctf", "run", "--duration", "0.1", "--poll", "0.02"]) == 1
    err = capsys.readouterr().err
    assert "intake failed for k" in err and "no adapter configured" in err


def test_cli_show_an_unknown_id_fails_loudly(prof, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = Board()
    board.put("q", name="Queue", category="Crypto")
    build_stream(board, tmp_path)
    assert cli.main(["dispatch", "--event", "csctf", "show", "nosuch"]) == 2
    cap = capsys.readouterr()
    assert "nosuch" in cap.err and cap.out == ""
