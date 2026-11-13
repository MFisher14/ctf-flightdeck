"""B-180: the shared cross-harness handoff board (ctf/handoff.py, ctf/cli/handoff.py).

Agents are stubs: tiny bash scripts written into tmp_path that record their argv and sleep or exit.
Nothing here starts a real Claude or Codex session or touches a network.
"""
from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ctf import handoff as H
from ctf import ledger, paths

REPO = paths.repo_root()
PINK_EXCLUSION = ("Do NOT research, reference, or reproduce how any real commercial music/streaming "
                  "product actually protects its files.")


# ------------------------------------------------------------------------------------------ fixtures

@pytest.fixture
def wd(tmp_path, monkeypatch):
    w = tmp_path / "wd"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.setenv("CTF_EVENT", "pink")
    monkeypatch.delenv("CTF_HANDOFF_AS", raising=False)
    monkeypatch.delenv("CODEX_BIN", raising=False)
    monkeypatch.delenv("CLAUDE_BIN", raising=False)
    monkeypatch.delenv("CTF_CHALLENGE", raising=False)
    yield w
    for pid in _stub_pids(tmp_path):     # the agents run in their own sessions: stop them all
        _kill(pid)


def _chal(wd: Path, folder="42-babyrev", **facts) -> Path:
    d = wd / folder
    (d / "files").mkdir(parents=True)
    if facts is not None:
        base = {"id": 42, "name": "babyrev", "category": "rev",
                "connection_info": "nc chall.pink.ctf.example 31337", "description": "find the key"}
        base.update(facts)
        (d / "challenge.json").write_text(json.dumps(base))
    return d


def _exe(path: Path, body: str) -> Path:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _stub(tmp_path: Path, name="codex", *, sleep: float = 0, exit_code: int = 0, msg: str = "") -> Path:
    """Records argv (one per line) to <tmp>/argv-<pid>.txt and whether stdin is /dev/null."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    body = f'''
if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then   # B-095: claude_launch reads the help for --effort
  printf 'Options:\\n  --effort <level>  Effort level for the current session\\n'; exit 0
fi
out="{tmp_path}/argv-$$.txt"
printf '%s\\n' "$@" > "$out.tmp"; mv "$out.tmp" "$out"
if [ -n "{msg}" ]; then echo "{msg}" >&2; fi
sleep {sleep}
exit {exit_code}
'''
    return _exe(d / name, body)


def _stub_pids(tmp_path: Path) -> list[int]:
    return [int(f.name[5:-4]) for f in tmp_path.glob("argv-*.txt")]


def _argvs(tmp_path: Path, timeout=10.0) -> list[list[str]]:
    deadline = time.time() + timeout
    while True:
        files = sorted(tmp_path.glob("argv-*.txt"))
        if files or time.time() > deadline:
            return [f.read_text().splitlines() for f in files]
        time.sleep(0.05)


def _modes_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "modes.toml"
    p.write_text(body)
    return p


CODEX_FAST = '''
[modes.fast]
harness = "codex"
model = "m-fast"
effort = "medium"
tier = "standard"
daybreak = false
launch = "detached"
'''


def _post(board, **kw):
    kw.setdefault("challenge", "42")
    kw.setdefault("mode", "fast")
    kw.setdefault("guidance", "Hypothesis: single-byte xor with 0x41. Ruled out: base64.")
    kw.setdefault("by", "claude")
    return H.post(board, **kw)


def _kill(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _cli(args, env, input_text=None, timeout=60):
    return subprocess.run([sys.executable, "-m", "ctf", "handoff", *args], cwd=str(REPO), env=env,
                          input=input_text, text=True, capture_output=True, timeout=timeout)


def _env(wd: Path, **extra) -> dict:
    e = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX_", "CLAUDE_BIN", "CTF_HANDOFF"))}
    e.update(CTF_WORKDIR=str(wd), CTF_EVENT="pink")
    e.update(extra)
    return e


# ------------------------------------------------------------------------------------------- modes

def test_repo_modes_load_and_pin_daybreak_explicitly():
    modes = H.load_modes("pink")
    assert {"fast", "deep", "cyber", "claude"} <= set(modes)
    for m in modes.values():
        assert m.tier == "standard"
        if m.harness == "codex":
            assert isinstance(m.daybreak, bool)
    assert modes["cyber"].launch == "queue" and modes["cyber"].daybreak is True


@pytest.mark.parametrize("body,needle", [
    (CODEX_FAST.replace('tier = "standard"', 'tier = "ultrafast"'), "B-009"),
    (CODEX_FAST.replace('daybreak = false\n', ''), "daybreak is required"),
    (CODEX_FAST.replace('effort = "medium"\n', ''), "effort is required"),
    (CODEX_FAST.replace('model = "m-fast"\n', ''), "model is required"),
    (CODEX_FAST + 'colour = "red"\n', "colour"),
    (CODEX_FAST.replace('launch = "detached"', 'launch = "now"'), "launch must be"),
    (CODEX_FAST.replace('harness = "codex"', 'harness = "gemini"'), "harness must be"),
    (CODEX_FAST + 'cyber_access_program = "daybreak_blue"\n', "needs daybreak = true"),
    ('[modes.c]\nharness = "claude"\nmodel = "opus"\ntier = "standard"\nlaunch = "detached"\n'
     'permission_mode = "bypassPermissions"\n', "bypassPermissions"),
    ('[modes.c]\nharness = "claude"\nmodel = "opus"\ntier = "standard"\nlaunch = "detached"\n'
     'daybreak = false\n', "not allowed for a claude mode"),
    ('[other]\nx = 1\n', "unknown top-level"),
])
def test_bad_mode_config_fails_loudly(tmp_path, body, needle):
    with pytest.raises(H.HandoffConfigError) as e:
        H.load_modes("pink", config=_modes_file(tmp_path, body))
    assert needle in str(e.value)


def test_event_modes_replace_repo_mode_whole(tmp_path):
    ev = tmp_path / "events" / "zz"
    ev.mkdir(parents=True)
    (ev / "handoff.toml").write_text(CODEX_FAST.replace("m-fast", "event-model"))
    modes = H.load_modes("zz", events_root=tmp_path / "events")
    assert modes["fast"].model == "event-model"
    assert modes["fast"].source.endswith("zz/handoff.toml")
    assert modes["deep"].model == H.load_modes(None)["deep"].model   # untouched repo mode


def test_unknown_mode_names_the_configured_ones():
    with pytest.raises(H.HandoffConfigError, match="configured: .*deep.*fast"):
        H.get_mode(H.load_modes("pink"), "turbo")


def test_missing_config_file_is_named(tmp_path):
    with pytest.raises(H.HandoffConfigError, match="does not exist"):
        H.load_modes("pink", config=tmp_path / "nope.toml")


# ------------------------------------------------------------------------------------------- brief

def test_brief_is_a_file_with_a_verifying_end_marker(wd):
    _chal(wd)
    h = _post(H.Board())
    text = Path(h.brief).read_text()
    assert text.rstrip("\n").splitlines()[-1].startswith(f"=== END OF BRIEF {h.id} sha256:")
    assert H.check_brief(h.brief) == h.id
    assert "single-byte xor with 0x41" in text


def test_truncated_brief_is_detected(wd):
    _chal(wd)
    h = _post(H.Board())
    p = Path(h.brief)
    lines = p.read_text().splitlines(keepends=True)
    p.write_text("".join(lines[:len(lines) // 2]))
    with pytest.raises(H.HandoffError, match="truncated"):
        H.check_brief(p)


def test_edited_brief_fails_its_digest(wd):
    _chal(wd)
    h = _post(H.Board())
    p = Path(h.brief)
    p.write_text(p.read_text().replace("0x41", "0x42"))
    with pytest.raises(H.HandoffError, match="sha256"):
        H.check_brief(p)


def test_brief_states_challenge_scope_from_challenge_and_profile(wd):
    _chal(wd)
    h = _post(H.Board())
    text = Path(h.brief).read_text()
    assert "babyrev (category rev" in text
    assert "nc chall.pink.ctf.example 31337" in text
    assert "*.pink.ctf.example" in text                       # profile live_service_scope
    assert "`PINK{...}`" in text                               # profile flag format
    assert "events/pink/AGENTS.md" in text                     # codex reads AGENTS.md
    assert "researching public implementations, real-world file formats" in text
    assert "Do NOT submit a flag" in text and "hint" in text


def test_claude_brief_points_at_claude_md(wd):
    _chal(wd)
    h = _post(H.Board(), mode="claude-queue")
    assert "events/pink/CLAUDE.md" in Path(h.brief).read_text()


def test_brief_says_when_there_is_no_challenge_json(wd):
    d = wd / "7-offline"
    d.mkdir()
    h = _post(H.Board(), challenge="7")
    text = Path(h.brief).read_text()
    assert "the folder has no challenge.json" in text
    assert "none listed in challenge.json" in text


def test_guidance_that_excludes_research_is_refused(wd):
    _chal(wd)
    with pytest.raises(H.HandoffError, match="closes off a technique"):
        _post(H.Board(), guidance="Recover the key.\n" + PINK_EXCLUSION)
    assert H.Board().state() == {}                             # nothing posted


@pytest.mark.parametrize("g", ["don't look up the format", "Never consult prior write-ups",
                               "solve it without researching the codec", "do not use public tools"])
def test_exclusion_detector_catches_variants(g):
    assert H.technique_exclusions(g)


@pytest.mark.parametrize("g", ["Do not submit the flag.", "no brute force against the server",
                               "Research the container format first.", "never run the binary on the host"])
def test_exclusion_detector_leaves_ordinary_guidance(g):
    assert H.technique_exclusions(g) == []


def test_exclusion_with_reason_is_posted_as_operator_exclusion(wd):
    _chal(wd)
    h = _post(H.Board(), guidance=PINK_EXCLUSION, exclusion_reason="organizer forbids it in the rules")
    text = Path(h.brief).read_text()
    assert "OPERATOR EXCLUSION" in text and "organizer forbids it in the rules" in text
    assert "Every technique is in scope" not in text


def test_empty_guidance_refused(wd):
    _chal(wd)
    with pytest.raises(H.HandoffError, match="no guidance"):
        _post(H.Board(), guidance="  \n")


# --------------------------------------------------------------------------------------- challenge

def test_resolve_challenge_unique_prefix_missing_and_ambiguous(wd):
    _chal(wd, "42-babyrev")
    assert H.resolve_challenge("42", wd) == (wd / "42-babyrev").resolve()
    assert H.resolve_challenge("42-babyrev", wd) == (wd / "42-babyrev").resolve()
    with pytest.raises(H.HandoffError, match="no challenge folder"):
        H.resolve_challenge("43", wd)
    _chal(wd, "42-other")
    with pytest.raises(H.HandoffError, match="matches 2"):
        H.resolve_challenge("42", wd)


def test_mode_and_to_must_agree(wd):
    _chal(wd)
    with pytest.raises(H.HandoffError, match="runs on codex"):
        _post(H.Board(), to="claude")


# -------------------------------------------------------------------------------------- the board

def test_concurrent_posts_get_distinct_ids(wd):
    _chal(wd)
    errs, ids = [], []

    def go():
        try:
            ids.append(_post(H.Board()).id)
        except Exception as e:   # noqa: BLE001
            errs.append(e)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs
    assert sorted(ids, key=lambda s: int(s[1:])) == [f"h{i}" for i in range(1, 9)]
    for h in H.Board().state().values():
        assert H.check_brief(h.brief) == h.id


def test_exactly_one_of_two_claimers_wins(wd):
    _chal(wd)
    h = _post(H.Board(), mode="cyber")
    script = ("import sys\nfrom ctf import handoff as H\n"
              "try:\n H.Board().claim(sys.argv[1], by='codex'); print('WON')\n"
              "except H.HandoffError as e: print('LOST', e)\n")
    procs = [subprocess.Popen([sys.executable, "-c", script, h.id], cwd=str(REPO), env=_env(wd),
                              stdout=subprocess.PIPE, text=True) for _ in range(4)]
    outs = [p.communicate(timeout=60)[0] for p in procs]
    assert sum(o.startswith("WON") for o in outs) == 1, outs
    assert all("it is claimed" in o for o in outs if o.startswith("LOST"))
    assert H.Board().get(h.id).status == "claimed"


def test_library_claim_refuses_a_truncated_brief(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    p = Path(h.brief)
    p.write_text(p.read_text()[:200])
    with pytest.raises(H.HandoffError, match="truncated"):
        b.claim(h.id, by="codex")
    assert b.get(h.id).status == "queued"


def test_stray_handoff_dir_is_skipped_not_a_crash(wd):
    """A crash between mkdir and the post record leaves handoff/hN behind; later posts go on."""
    _chal(wd)
    b = H.Board()
    (b.dir / "h1").mkdir(parents=True)
    h = _post(b)
    assert h.id == "h2" and H.check_brief(h.brief) == "h2"
    import shutil
    shutil.rmtree(b.dir / "h1")
    shutil.rmtree(b.dir / "h2")
    h3 = _post(b)                                    # ids are never reused, even with dirs gone
    assert h3.id == "h3"
    assert sorted(b.state()) == ["h2", "h3"]


def test_brief_write_failure_cleans_up_and_is_named(wd):
    _chal(wd)
    b = H.Board()

    def broken(hid, brief, result):
        brief.write_text("partial")
        raise OSError("disk full")
    with pytest.raises(H.HandoffError, match="could not write the brief for h1.*disk full"):
        b._reserve(to="codex", mode="fast", challenge="42", challenge_dir=wd / "42-babyrev", by="claude",
                   label=None, write_brief=broken)
    assert not (b.dir / "h1").exists()
    assert b.state() == {}
    assert _post(b).id == "h1"


def test_claim_respects_the_addressee(wd):
    _chal(wd)
    h = _post(H.Board(), mode="cyber")
    with pytest.raises(H.HandoffError, match="addressed to codex"):
        H.Board().claim(h.id, by="claude")


def test_done_rules(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    with pytest.raises(H.HandoffError, match="cannot done"):
        b.done(h.id, by="codex", status="stuck")
    b.claim(h.id, by="codex")
    with pytest.raises(H.HandoffError, match="result file"):
        b.done(h.id, by="codex", status="solved")
    Path(h.result).write_text("PINK{candidate}\nmethod: xor\nconfidence: high\n")
    got = b.done(h.id, by="codex", status="solved", summary="xor key 0x41")
    assert (got.status, got.done_status, got.summary) == ("done", "solved", "xor key 0x41")
    with pytest.raises(H.HandoffError, match="it is done"):
        b.claim(h.id, by="codex")
    evs = [r["event"] for r in ledger.read(wd) if r["event"].startswith("handoff.")]
    assert evs == ["handoff.post", "handoff.done"]


def test_inbox_shows_my_work_and_new_notes_once(wd):
    _chal(wd)
    b = H.Board()
    hc = _post(b, mode="cyber")
    hq = _post(b, mode="claude-queue")
    b.note("the key schedule is RC4", by="claude", hid=hc.id)
    b.note("for claude only", by="codex", to="claude")
    b.note("my own note", by="codex")
    tasks, notes = b.inbox("codex", peek=True)
    assert [t.id for t in tasks] == [hc.id]
    assert [n["text"] for n in notes] == ["the key schedule is RC4"]
    tasks, notes = b.inbox("codex")                         # advances the cursor
    assert [n["text"] for n in notes] == ["the key schedule is RC4"]
    assert b.inbox("codex")[1] == []
    b.note("second", by="claude")
    assert [n["text"] for n in b.inbox("codex")[1]] == ["second"]
    assert b.inbox("codex")[1] == []          # the last record is another actor's note: shown once
    ctasks, cnotes = b.inbox("claude")
    assert [t.id for t in ctasks] == [hq.id]
    assert {n["text"] for n in cnotes} == {"for claude only", "my own note"}
    assert [n["text"] for n in b.get(hc.id).notes] == ["the key schedule is RC4"]


def test_who_is_required_and_validated(wd, monkeypatch):
    _chal(wd)
    with pytest.raises(H.HandoffError, match="CTF_HANDOFF_AS"):
        H.check_who(None)
    with pytest.raises(H.HandoffError, match="bad name"):
        H.check_who("Codex; rm -rf")
    monkeypatch.setenv("CTF_HANDOFF_AS", "codex")
    assert H.check_who(None) == "codex"


def test_corrupt_board_line_is_named(wd):
    b = H.Board()
    b.dir.mkdir(parents=True)
    b.path.write_text('{"op": "post"\n')
    with pytest.raises(H.HandoffError, match="corrupt board line"):
        b.state()


# ---------------------------------------------------------------------------------------- launching

def test_codex_launch_argv_is_fenced_explicit_and_carries_no_guidance(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, sleep=30)
    b = H.Board()
    h = _post(b)
    r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=0.5)
    try:
        assert r.ok, r.message
        argv = _argvs(tmp_path)[0]
        assert argv[:2] == ["exec", "--skip-git-repo-check"]
        assert argv[argv.index("-m") + 1] == "gpt-6-astra"
        assert 'model_reasoning_effort="medium"' in argv
        assert argv[argv.index("daybreak=false") - 1] == "-c"
        assert "ultrafast_mode" in argv and 'default_permissions="ctf_fence"' in argv
        prompt = argv[-1]
        assert h.brief in prompt and len(prompt) <= H.POINTER_MAX
        assert not any("xor with 0x41" in a for a in argv)          # the guidance stays in the file
        st = b.get(h.id)
        assert (st.status, st.pid, st.claimed_by) == ("running", r.pid, "codex")
        evs = list(ledger.read(wd))
        assert [e["event"] for e in evs if e["event"].startswith("handoff.")] == ["handoff.post", "handoff.launch"]
        # launched through the R-09 gate: metered (--json) and recorded against the challenge
        assert "--json" in argv
        gate = [e for e in evs if e["event"] == "agent_launch"]
        assert gate and gate[0]["challenge_id"] == "42" and gate[0]["metered"] is True
    finally:
        _kill(r.pid)


def test_cyber_flags_stay_separate_argv_items(wd, tmp_path):
    _chal(wd)
    cfg = H.load_modes("pink", config=_modes_file(tmp_path, CODEX_FAST.replace(
        "[modes.fast]", "[modes.cy]").replace("m-fast", "gpt-6-astra").replace(
        "daybreak = false", 'daybreak = true\ncyber_access_program = "daybreak_blue"')))
    stub = _stub(tmp_path, sleep=30)
    b = H.Board()
    h = _post(b, mode="cy", modes=cfg)
    r = H.launch(b, h.id, by="claude", modes=cfg, codex_bin=str(stub), grace=0.3)
    try:
        argv = _argvs(tmp_path)[0]
        i = argv.index("--cyber-access-program")
        assert argv[i + 1] == "daybreak_blue"
        assert "daybreak=true" in argv and "daybreak=false" not in argv
        assert argv[argv.index("-m") + 1] == "gpt-6-astra"
    finally:
        _kill(r.pid)


def test_claude_launch_uses_fence_settings_and_model(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, "claude", sleep=30)
    b = H.Board()
    h = _post(b, mode="claude")
    r = H.launch(b, h.id, by="codex", claude_bin=str(stub), grace=0.3)
    try:
        assert r.ok, r.message
        argv = _argvs(tmp_path)[0]
        settings = Path(argv[argv.index("--settings") + 1])
        assert settings.is_file() and json.loads(settings.read_text())["sandbox"]["enabled"] is True
        assert argv[argv.index("--model") + 1] == "opus"
        assert argv[argv.index("--permission-mode") + 1] == "acceptEdits"
        assert h.brief in argv[argv.index("-p") + 1]
    finally:
        _kill(r.pid)


def test_queue_mode_is_not_launched(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    with pytest.raises(H.HandoffError, match="queue-only"):
        H.launch(b, h.id, by="claude")
    assert b.get(h.id).status == "queued"


def test_immediate_agent_failure_is_reported_with_log_tail(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, exit_code=1, msg="Daybreak is unavailable for model gpt-6-astra")
    b = H.Board()
    h = _post(b)
    r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=30)
    assert not r.ok
    st = b.get(h.id)
    assert st.status == "failed" and "status 1" in st.failure, st.failure
    rec = [x for x in b.records() if x["op"] == "launch_failed"][-1]
    assert "Daybreak is unavailable" in rec["log_tail"]
    # a failed handoff can be relaunched once fixed
    ok = _stub(tmp_path, "codex2", sleep=30)
    r2 = H.launch(b, h.id, by="claude", codex_bin=str(ok), grace=0.3)
    try:
        assert r2.ok and b.get(h.id).status == "running"
    finally:
        _kill(r2.pid)


def test_budget_gate_refusal_fails_the_launch(wd, tmp_path):
    from ctf import budget, event
    _chal(wd)
    stub = _stub(tmp_path, sleep=30)
    b = H.Board()
    h = _post(b)
    budget.LedgerMeter(event.load("pink"), workdir=wd).stop("42", "manual", by="max")
    r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=30)
    assert not r.ok and "budget gate refused challenge 42" in r.message
    assert b.get(h.id).status == "failed"
    assert _stub_pids(tmp_path) == []                       # the agent never started
    assert "resume" in [x for x in b.records() if x["op"] == "launch_failed"][-1]["log_tail"]


def test_unpriced_model_fails_loudly_at_launch(wd, tmp_path):
    _chal(wd)
    cfg = H.load_modes("pink", config=_modes_file(tmp_path, CODEX_FAST))     # model m-fast: no price
    stub = _stub(tmp_path, sleep=30)
    b = H.Board()
    h = _post(b, modes=cfg)
    r = H.launch(b, h.id, by="claude", modes=cfg, codex_bin=str(stub), grace=30)
    assert not r.ok and "status 2" in r.message
    assert "no price for codex model 'm-fast'" in [x for x in b.records() if x["op"] == "launch_failed"][-1]["log_tail"]


def test_missing_agent_binary_fails_by_name(wd, tmp_path):
    _chal(wd)
    b = H.Board()
    h = _post(b)
    r = H.launch(b, h.id, by="claude", codex_bin=str(tmp_path / "no-such-codex"), grace=0)
    assert not r.ok and "codex CLI not found" in r.message
    assert b.get(h.id).status == "failed"


def test_reap_marks_exited_unfinished_launch_failed(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, sleep=0.3)
    live_stub = _stub(tmp_path, "codex-live", sleep=60)
    b = H.Board()
    h = _post(b)
    live = _post(b, label="live")
    r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=0)
    rl = H.launch(b, live.id, by="claude", codex_bin=str(live_stub), grace=0)
    try:
        assert r.ok and b.get(h.id).status == "running"
        assert rl.ok and b.get(live.id).status == "running"
        deadline = time.time() + 10
        while H.pid_alive(r.pid) and time.time() < deadline:   # an exited child must not count as alive
            time.sleep(0.05)
        assert H.pid_alive(rl.pid)
        reaped = b.reap()
        assert [x.id for x in reaped] == [h.id]
        assert "without a result" in b.get(h.id).failure
        st = b.get(live.id)                                    # a live agent is left alone
        assert (st.status, st.failure) == ("running", None)
        assert b.reap() == []
        assert b.get(live.id).status == "running"
    finally:
        _kill(rl.pid)


def test_cancel_stops_a_running_agent(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, sleep=60)
    b = H.Board()
    h = _post(b)
    r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=0.2)
    try:
        _argvs(tmp_path)
        agent = _stub_pids(tmp_path)
        assert len(agent) == 1
        H.stop(b, h.id, by="claude", reason="solved by claude")
        deadline = time.time() + 10
        while (H.pid_alive(r.pid) or H.pid_alive(agent[0])) and time.time() < deadline:
            time.sleep(0.05)
        assert not H.pid_alive(r.pid)
        assert not H.pid_alive(agent[0])           # the agent itself, not only its launcher
        assert b.get(h.id).status == "cancelled"
    finally:
        _kill(r.pid)


def test_cancel_stops_the_agent_when_the_caller_ignores_sigint(wd, tmp_path):
    # A caller started in the background (`cmd &`, nohup, a suite runner) has SIGINT ignored, and an
    # ignored signal is inherited across fork and exec. The launcher must still stop its agent.
    _chal(wd)
    stub = _stub(tmp_path, sleep=900)      # outlives the deadline: only a real stop ends it
    b = H.Board()
    h = _post(b)
    old = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        r = H.launch(b, h.id, by="claude", codex_bin=str(stub), grace=0.2)
    finally:
        signal.signal(signal.SIGINT, old)
    agent = []
    try:
        _argvs(tmp_path, timeout=60)
        agent = _stub_pids(tmp_path)
        assert len(agent) == 1
        H.stop(b, h.id, by="claude", reason="solved by claude", wait=30)
        deadline = time.time() + 90           # wall clock; generous at load, far under the stub's sleep
        while (H.pid_alive(r.pid) or H.pid_alive(agent[0])) and time.time() < deadline:
            time.sleep(0.05)
        assert not H.pid_alive(r.pid)
        assert not H.pid_alive(agent[0])
        assert b.get(h.id).status == "cancelled"
    finally:
        _kill(r.pid)
        for pid in agent:
            _kill(pid)


def test_cancel_falls_back_to_sigterm_when_sigint_is_ignored(wd, tmp_path):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    ready = tmp_path / "ready"
    code = ("import signal, sys, time, pathlib\n"
            "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "pathlib.Path(sys.argv[1]).write_text('x')\n"
            "time.sleep(60)\n")
    p = subprocess.Popen([sys.executable, "-I", "-c", code, str(ready)], start_new_session=True)
    try:
        deadline = time.time() + 20
        while not ready.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert ready.exists()
        b._apply("launch", h.id, "claude", pid=p.pid, log=str(h.dir / "launch.log"), harness="codex")
        H.stop(b, h.id, by="claude", reason="done elsewhere", wait=0.5)
        deadline = time.time() + 10
        while H.pid_alive(p.pid) and time.time() < deadline:
            time.sleep(0.05)
        assert not H.pid_alive(p.pid)
        assert b.get(h.id).status == "cancelled"
    finally:
        _kill(p.pid)


def test_two_launchers_start_one_agent(wd, tmp_path):
    _chal(wd)
    stub = _stub(tmp_path, sleep=30)
    b = H.Board()
    h = _post(b)
    results, errs, other = [], [], []

    def go():
        try:
            results.append(H.launch(H.Board(), h.id, by="claude", codex_bin=str(stub), grace=0))
        except H.HandoffError as e:
            errs.append(str(e))
        except BaseException as e:   # noqa: BLE001  named below, not swallowed
            other.append(e)
    ts = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    try:
        if other:
            raise other[0]
        assert len(results) == 1 and len(errs) == 3, (results, errs)
        assert all("it is running" in e for e in errs)
        assert len(_argvs(tmp_path, timeout=20)) == 1     # poll: the gated launcher may start slowly
    finally:
        for r in results:
            _kill(r.pid)


# ---------------------------------------------------------------------------------------------- CLI

def test_cli_launch_does_not_hold_the_callers_pipe(wd, tmp_path):
    """CSCTF: a `| grep` held a pipe open and only 1 of 4 jobs started. The command must return and
    close its stdout while the agent keeps running."""
    _chal(wd)
    stub = _stub(tmp_path, sleep=30)
    t0 = time.time()
    p = subprocess.Popen([sys.executable, "-m", "ctf", "handoff", "post", "--as", "claude",
                          "--challenge", "42", "--mode", "fast", "--grace", "0.2"],
                         cwd=str(REPO), env=_env(wd, CODEX_BIN=str(stub)), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate("try xor", timeout=25)
    elapsed = time.time() - t0
    pid = H.Board(wd).get("h1").pid
    try:
        assert p.returncode == 0, err
        assert elapsed < 20
        assert "LAUNCHED h1" in out
        assert H.pid_alive(pid)                       # the agent outlived the command
        assert os.getpgid(pid) == pid                 # in its own session/process group
    finally:
        _kill(pid)


def test_cli_batch_launches_every_entry(wd, tmp_path):
    for i in range(4):
        _chal(wd, f"{10 + i}-chal{i}", id=10 + i, name=f"chal{i}")
    (tmp_path / "g.md").write_text("Look at the PE resources first.")
    entries = "".join(f'[[handoff]]\nchallenge = "{10 + i}"\nmode = "fast"\nlabel = "w{i}"\n'
                      f'guidance_file = "{tmp_path / "g.md"}"\n\n' for i in range(4))
    batch = tmp_path / "wave.toml"
    batch.write_text(entries)
    stub = _stub(tmp_path, sleep=30)
    r = _cli(["batch", str(batch), "--as", "claude", "--grace", "0.2"], _env(wd, CODEX_BIN=str(stub)))
    st = H.Board(wd).state()
    try:
        assert r.returncode == 0, r.stderr
        assert r.stdout.count("LAUNCHED") == 4
        assert [h.status for h in st.values()] == ["running"] * 4
        assert len(_argvs(tmp_path)) >= 1
        deadline = time.time() + 5
        while len(list(tmp_path.glob("argv-*.txt"))) < 4 and time.time() < deadline:
            time.sleep(0.05)
        assert len(list(tmp_path.glob("argv-*.txt"))) == 4
        assert {h.label for h in st.values()} == {"w0", "w1", "w2", "w3"}
    finally:
        for h in st.values():
            _kill(h.pid)


def test_cli_batch_with_one_bad_entry_posts_nothing(wd, tmp_path):
    _chal(wd)
    batch = tmp_path / "wave.toml"
    batch.write_text('[[handoff]]\nchallenge = "42"\nmode = "fast"\nguidance = "ok"\n\n'
                     '[[handoff]]\nchallenge = "42"\nmode = "turbo"\nguidance = "ok"\n\n'
                     '[[handoff]]\nchallenge = "99"\nmode = "fast"\nguidance = "ok"\n')
    r = _cli(["batch", str(batch), "--as", "claude"], _env(wd))
    assert r.returncode == 2
    assert "#2" in r.stderr and "turbo" in r.stderr and "#3" in r.stderr and "#1" not in r.stderr
    assert H.Board(wd).state() == {}


def test_cli_batch_exclusion_without_reason_posts_nothing(wd, tmp_path):
    """The exclusion lint runs in the preflight: without it, entry #1 would be posted before #2
    failed in post()."""
    _chal(wd)
    batch = tmp_path / "wave.toml"
    batch.write_text('[[handoff]]\nchallenge = "42"\nmode = "fast"\nguidance = "ok"\nlaunch = false\n\n'
                     '[[handoff]]\nchallenge = "42"\nmode = "fast"\nlaunch = false\n'
                     f'guidance = "{PINK_EXCLUSION}"\n')
    r = _cli(["batch", str(batch), "--as", "claude"], _env(wd))
    assert r.returncode == 2
    assert "nothing posted" in r.stderr and "#2" in r.stderr and "closes off a technique" in r.stderr
    assert "#1" not in r.stderr
    assert H.Board(wd).state() == {}


def test_cli_failed_launch_exits_1_and_shows_in_inbox(wd, tmp_path):
    _chal(wd)
    env = _env(wd, CODEX_BIN=str(tmp_path / "no-such-codex"))
    r = _cli(["post", "--as", "claude", "--challenge", "42", "--mode", "fast", "--grace", "0"], env, "try xor")
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert "POSTED h1" in r.stdout and "LAUNCH FAILED" in r.stderr and "codex CLI not found" in r.stderr
    assert H.Board(wd).get("h1").status == "failed"
    r = _cli(["launch", "h1", "--as", "claude", "--grace", "0"], env)
    assert r.returncode == 1 and "LAUNCH FAILED" in r.stderr
    tasks, _ = H.Board(wd).inbox("codex", peek=True)          # failed work is offered again
    assert [(t.id, t.status) for t in tasks] == [("h1", "failed")]
    r = _cli(["inbox", "--as", "codex"], env)
    assert r.returncode == 0 and "TASK h1" in r.stdout and "failed" in r.stdout


def test_cli_reap_without_as_acts_as_reaper(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    gone = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
    gone.wait()
    b._apply("launch", h.id, "claude", pid=gone.pid, log=str(h.dir / "launch.log"), harness="codex")
    r = _cli(["reap"], _env(wd))
    assert r.returncode == 0, r.stderr
    assert f"{h.id} failed" in r.stdout
    rec = [x for x in H.Board(wd).records() if x["op"] == "launch_failed"][-1]
    assert rec["by"] == "reaper"
    r = _cli(["reap"], _env(wd))
    assert r.returncode == 0 and "nothing to reap" in r.stdout
    r = _cli(["reap", "--as", "Bad Name"], _env(wd))
    assert r.returncode == 2 and "bad name" in r.stderr


def test_cli_reap_without_as_uses_ctf_handoff_as(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    gone = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
    gone.wait()
    b._apply("launch", h.id, "claude", pid=gone.pid, log=str(h.dir / "launch.log"), harness="codex")
    r = _cli(["reap"], _env(wd, CTF_HANDOFF_AS="codex"))
    assert r.returncode == 0, r.stderr
    assert f"{h.id} failed" in r.stdout
    rec = [x for x in H.Board(wd).records() if x["op"] == "launch_failed"][-1]
    assert rec["by"] == "codex"


def test_library_reap_validates_the_actor(wd):
    _chal(wd)
    b = H.Board()
    h = _post(b, mode="cyber")
    gone = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
    gone.wait()
    b._apply("launch", h.id, "claude", pid=gone.pid, log=str(h.dir / "launch.log"), harness="codex")
    with pytest.raises(H.HandoffError, match="bad name"):
        b.reap(by="Bad Name")
    assert not [x for x in b.records() if x["op"] == "launch_failed"]   # nothing written
    assert b.get(h.id).status == "running"
    assert [x.id for x in b.reap(by="ops-1")] == [h.id]
    assert [x for x in b.records() if x["op"] == "launch_failed"][-1]["by"] == "ops-1"


def test_cli_post_queue_mode_then_claim_and_done(wd, tmp_path):
    _chal(wd)
    env = _env(wd)
    r = _cli(["post", "--as", "claude", "--challenge", "42", "--mode", "cyber"], env, "use the pcap")
    assert r.returncode == 0, r.stderr
    assert "QUEUED" in r.stdout and "handoff claim h1 --as codex" in r.stdout
    r = _cli(["inbox", "--as", "codex"], env)
    assert "TASK h1" in r.stdout
    r = _cli(["claim", "h1", "--as", "codex"], env)
    assert r.returncode == 0 and "CLAIMED h1" in r.stdout
    r = _cli(["claim", "h1", "--as", "codex"], env)
    assert r.returncode == 2 and "it is claimed" in r.stderr
    Path(H.Board(wd).get("h1").result).write_text("PINK{x} via pcap\n")
    r = _cli(["done", "h1", "--as", "codex", "--status", "solved"], env)
    assert r.returncode == 0 and "verify the flag" in r.stdout
    r = _cli(["list"], env)
    assert "nothing open" in r.stdout
    r = _cli(["list", "--all"], env)
    assert "done:solved" in r.stdout


def test_cli_claim_refuses_a_truncated_brief(wd):
    _chal(wd)
    h = _post(H.Board(), mode="cyber")
    p = Path(h.brief)
    p.write_text(p.read_text()[:200])
    r = _cli(["claim", h.id, "--as", "codex"], _env(wd))
    assert r.returncode == 2 and "truncated" in r.stderr
    assert H.Board(wd).get(h.id).status == "queued"
    r = _cli(["check-brief", str(p)], _env(wd))
    assert r.returncode == 1


def test_cli_note_with_and_without_id(wd):
    _chal(wd)
    _post(H.Board(), mode="cyber")
    env = _env(wd)
    assert _cli(["note", "h1", "--as", "claude", "key", "is", "RC4"], env).returncode == 0
    assert _cli(["note", "--as", "claude", "general", "finding", "--to", "codex"], env).returncode == 0
    recs = [r for r in H.Board(wd).records() if r["op"] == "note"]
    assert [(r["id"], r["text"], r["to"]) for r in recs] == [("h1", "key is RC4", "any"),
                                                            (None, "general finding", "codex")]
    r = _cli(["note", "h1", "--as", "claude", "--bogus", "x"], env)
    assert r.returncode == 2 and "--bogus" in r.stderr


def test_cli_refused_operations_exit_2_with_reason(wd):
    _chal(wd)
    env = _env(wd)
    r = _cli(["post", "--as", "claude", "--challenge", "42", "--mode", "fast"], env, PINK_EXCLUSION)
    assert r.returncode == 2 and "closes off a technique" in r.stderr
    r = _cli(["post", "--challenge", "42", "--mode", "fast"], env, "x")
    assert r.returncode == 2 and "CTF_HANDOFF_AS" in r.stderr
    r = _cli(["modes", "--config", "/nonexistent/modes.toml"], env)
    assert r.returncode == 2 and "does not exist" in r.stderr


# --------------------------------------------------------------------------- runbook and wrappers

_CMD_RE = re.compile(r"python -m ctf handoff ([^`\n]+)")


@pytest.mark.parametrize("doc", ["docs/handoff.md", "templates/handoff/claude-skill/SKILL.md",
                                 "templates/handoff/codex-prompt.md"])
def test_runbook_and_wrapper_commands_parse(doc):
    """The harness-neutral runbook and both thin wrappers name only commands the CLI accepts."""
    import argparse
    import shlex
    from ctf.cli import handoff as cli
    text = (REPO / doc).read_text()
    cmds = _CMD_RE.findall(text)
    assert len(cmds) >= 3, f"{doc} names too few handoff commands"
    p = argparse.ArgumentParser(exit_on_error=False)
    cli.add_arguments(p)
    for c in cmds:
        c = re.sub(r"\b(solved\|stuck\|failed)\b", "solved", c)
        words = [w for w in shlex.split(c.replace("<", "").replace(">", ""), comments=True) if w not in ("...", "|")]
        try:
            ns = p.parse_args(words)
            if ns.action == "note":
                cli.parse_note(ns.args)
        except (argparse.ArgumentError, SystemExit, H.HandoffError) as e:
            raise AssertionError(f"{doc}: `python -m ctf handoff {c}` does not parse: {e}") from None
