"""B-036: the lane regression set and its warm gate (ctf/adapt/regress.py).

Each test builds a synthetic checkout (tests/adapt_repo.py) with a probe engine whose answer is a hash of
its input, so a key holds on its own fixture only. The engine really runs, under the intake audit-hook
guard, through the same runner command the openers use; nothing is mocked in the gate."""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from ctf import ledger
from ctf.adapt import AdaptError
from ctf.adapt import regress as R

import adapt_repo as AR

pytestmark = pytest.mark.needs_tool("git")

IDLE = dict(load=0.0, cpus=1, guard="hook")         # scale 1: caps are exactly what the test says


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    return root, wd


def statuses(g):
    return {c.case: c.status for c in g.cases}


# --------------------------------------------------------------------------- the set

def test_set_is_opener_cases_controls_and_event_cases(env, tmp_path):
    root, wd = env
    inp = AR.write(tmp_path, "yesterday/delivery.bin", "day seven payload\n")
    R.record_case("probe", "d07-base", engine=AR.ENGINE, input_file=inp, expect=[AR.answer_for(inp.read_bytes())],
                  workdir=wd, root=root, mode="time_trial")
    cases = R.regression_set("probe", root=root, workdir=wd)
    names = [c.name for c in cases]
    assert names == [f"opener:{AR.BASE_FIXTURE}", f"opener:{AR.CASE_FIXTURE}", f"control:{AR.CONTROL_FIXTURE}",
                     "event:d07-base"]
    ctrl = cases[2]
    # the control must not match ANY case key of its engine, the recorded event case's included
    assert (AR.answer_for(inp.read_bytes()),) in ctrl.keys and len(ctrl.keys) == 3
    ev = cases[3]
    assert ev.source == "event" and ev.mode == "time_trial" and ev.input.read_bytes() == inp.read_bytes()
    assert ev.input != inp, "the input is copied into the workdir, not referenced"


def test_a_lane_with_nothing_to_replay_is_an_error(env):
    root, wd = env
    with pytest.raises(AdaptError, match="no regression set"):
        R.regression_set("nolane", root=root, workdir=wd)


def test_a_non_offline_opener_is_one_not_run_case(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    root = AR.make_repo(tmp_path, opener=(
        '[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "toolkits.adapt_probe"\nlabel = "live"\n'
        'offline = false\nreason = "armed against a fake service only"\n'))
    g = R.gate("probe", root=root, workdir=tmp_path, record=False, **IDLE)
    assert g.verdict == R.NOT_RUN and g.cases[0].status == R.NOT_RUN
    assert "fake service only" in g.reason


@pytest.mark.parametrize("bad, match", [
    (dict(name="Bad Name"), "case name"),
    (dict(expect=[]), "expect"),
    (dict(expect=["  "]), "expect"),
    (dict(engine="toolkits.no_such_engine"), "does not resolve"),
    (dict(mode="Time Trial"), "mode"),
    (dict(within=0), "within"),
    (dict(scope=["/abs/*.py"]), "repo-relative"),
    (dict(scope="solvers/*.py"), "list"),
])
def test_record_case_refuses_bad_input(env, tmp_path, bad, match):
    root, wd = env
    inp = AR.write(tmp_path, "in.bin", "x\n")
    kw = dict(name="ok", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: x"], workdir=wd, root=root)
    kw.update(bad)
    with pytest.raises(AdaptError, match=match):
        R.record_case("probe", kw.pop("name"), **kw)


def test_record_case_needs_force_to_replace_and_a_real_file(env, tmp_path):
    root, wd = env
    inp = AR.write(tmp_path, "in.bin", "x\n")
    R.record_case("probe", "c1", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: a"], workdir=wd, root=root)
    with pytest.raises(AdaptError, match="exists"):
        R.record_case("probe", "c1", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: b"], workdir=wd, root=root)
    c = R.record_case("probe", "c1", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: b"], workdir=wd, root=root,
                      force=True)
    assert c.expect == ("ANSWER: b",)
    with pytest.raises(AdaptError, match="regular file"):
        R.record_case("probe", "c2", engine=AR.ENGINE, input_file=tmp_path / "absent", expect=["A"], workdir=wd,
                      root=root)


def test_a_tampered_or_malformed_event_case_is_refused(env, tmp_path):
    root, wd = env
    inp = AR.write(tmp_path, "in.bin", "x\n")
    c = R.record_case("probe", "c1", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: a"], workdir=wd, root=root)
    c.input.write_text("changed\n")
    with pytest.raises(AdaptError, match="changed since it was recorded"):
        R.regression_set("probe", root=root, workdir=wd)
    case_toml = c.input.parent.parent / R.CASE_FILE
    R.record_case("probe", "c1", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: a"], workdir=wd, root=root,
                  force=True)
    case_toml.write_text(case_toml.read_text() + 'surprise = "x"\n')
    with pytest.raises(AdaptError, match="unknown key"):
        R.regression_set("probe", root=root, workdir=wd)
    case_toml.unlink()
    with pytest.raises(AdaptError, match="has no case.toml"):
        R.regression_set("probe", root=root, workdir=wd)


# --------------------------------------------------------------------------- verdicts and warm reuse

def test_green_lane_says_yes_and_the_second_gate_is_warm(env):
    root, wd = env
    g1 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g1.verdict == R.YES and g1.ok, g1.reason
    assert set(statuses(g1).values()) == {R.PASS} and g1.ran == 3
    g2 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert set(statuses(g2).values()) == {R.WARM} and g2.ran == 0 and g2.ok
    assert g2.lane_key == g1.lane_key
    g3 = R.gate("probe", root=root, workdir=wd, warm=False, **IDLE)
    assert set(statuses(g3).values()) == {R.PASS} and g3.ran == 3, "warm=False reuses nothing"


def test_a_wrong_answer_is_no_after_one_re_gate_and_is_never_cached(env, monkeypatch):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "3")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g.verdict == R.NO
    base = g.cases[0]
    assert base.status == R.FAIL and base.regated and base.runs == 2
    assert "engine exited 3" in base.reason and "again on the re-gate" in base.reason
    ctrl = [c for c in g.cases if c.mode == "control"][0]
    assert ctrl.status == R.PASS, "a control only has to not match: its exit code is not a verdict"
    monkeypatch.delenv("ADAPT_PROBE_EXIT")
    g2 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g2)[base.case] == R.PASS, "a red result is not reused"
    assert statuses(g2)[ctrl.case] == R.WARM


def test_a_red_result_drops_its_warm_key(env, monkeypatch):
    root, wd = env
    g1 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g1.ok, g1.reason
    base = g1.cases[0]
    assert R.WarmCache(R.cache_path("probe", wd)).get(base.key) is not None
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "4")          # not in any key: the same key now runs red
    red = R.gate("probe", root=root, workdir=wd, warm=False, regate=False, **IDLE)
    assert red.cases[0].status == R.FAIL and red.cases[0].key == base.key
    assert R.WarmCache(R.cache_path("probe", wd)).get(base.key) is None, "the red run dropped its key"
    monkeypatch.delenv("ADAPT_PROBE_EXIT")
    g3 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g3)[base.case] == R.PASS and g3.cases[0].runs == 1, "the last real run was red: it runs again"
    ctrl = [c for c in g3.cases if c.mode == "control"][0]
    assert ctrl.status == R.WARM, "the control passed on the red gate (its exit is no verdict): still warm"


def test_no_regate_stops_on_the_first_failure(env, monkeypatch):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "1")
    g = R.gate("probe", root=root, workdir=wd, regate=False, **IDLE)
    assert g.verdict == R.NO and g.cases[0].runs == 1 and not g.cases[0].regated


def test_a_flake_is_re_gated_to_pass_but_not_cached(env, monkeypatch, tmp_path):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(tmp_path / "flaked"))
    monkeypatch.setenv("ADAPT_PROBE_ONCE_DO", "wrong")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g.verdict == R.YES, g.reason
    first = g.cases[0]
    assert first.status == R.PASS and first.regated and first.runs == 2
    g2 = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g2)[first.case] == R.PASS and g2.cases[0].runs == 1, "a re-gated pass runs again next time"
    assert all(c.status == R.WARM for c in g2.cases[1:])


def test_a_cap_cut_is_re_replayed_at_twice_the_cap_not_read_as_no(env, monkeypatch, tmp_path):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(tmp_path / "cut-once"))
    monkeypatch.setenv("ADAPT_PROBE_ONCE_DO", "hang")
    # the hang is 60 s; a cap of 8 s leaves a normal run room on a loaded host (load ~80 on 14 cpus seen)
    g = R.gate("probe", root=root, workdir=wd, cap=8.0, **IDLE)
    first = g.cases[0]
    assert g.verdict == R.YES, g.reason
    assert first.status == R.PASS and first.recut and first.runs == 2
    assert first.cap == pytest.approx(16.0), "the re-replay runs at recut (2) x the cap"
    g2 = R.gate("probe", root=root, workdir=wd, cap=8.0, **IDLE)
    assert statuses(g2)[first.case] == R.WARM, "a pass on the re-replay is a pass: it is cached"


def test_cut_twice_is_a_real_no_and_the_engine_is_killed(env, monkeypatch):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_SLEEP", "30")
    g = R.gate("probe", root=root, workdir=wd, cap=0.8, recut=2.5, **IDLE)
    assert g.verdict == R.NO
    c = g.cases[0]
    assert c.status == R.CUT and c.recut and c.runs == 2
    assert "cut at its 0.8s cap" in c.reason and "re-replay at 2.0s (2.5x)" in c.reason
    # three cases cut twice each: 3 x (0.8 + 2.0) s plus start-up; waiting the sleep out would be >= 30 s
    assert g.seconds < 30.0, "each cut run is killed at its cap, not waited out"


def test_recut_below_twice_the_cap_is_refused(env):
    root, wd = env
    with pytest.raises(AdaptError, match="no less than 2x"):
        R.gate("probe", root=root, workdir=wd, recut=1.5, **IDLE)


def test_the_cap_and_window_scale_with_load(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    ans = AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)
    root = AR.make_repo(tmp_path, opener=(
        f'[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "{AR.ENGINE}"\nlabel = "p"\n'
        f'fixture = "{AR.BASE_FIXTURE}"\nexpect = ["{ans}"]\ncontrols = ["{AR.CONTROL_FIXTURE}"]\n\n'
        f'[[opener.case]]\nmode = "time_trial"\nfixture = "{AR.BASE_FIXTURE}"\nexpect = ["{ans}"]\nwithin = 0.9\n'))
    monkeypatch.setenv("ADAPT_PROBE_SLEEP", "1.2")
    idle = R.gate("probe", root=root, workdir=tmp_path / "a", warm=False, load=0.0, cpus=4, guard="hook")
    timed = [c for c in idle.cases if c.mode == "time_trial"][0]
    assert timed.status == R.FAIL and "over its 0.9s window" in timed.reason
    busy = R.gate("probe", root=root, workdir=tmp_path / "b", warm=False, load=40.0, cpus=4, guard="hook",
                  max_scale=20.0)
    assert busy.scale == pytest.approx(10.0) and busy.cap == pytest.approx(10.0 * R.DEFAULT_CAP)
    assert [c for c in busy.cases if c.mode == "time_trial"][0].status == R.PASS, busy.reason
    capped = R.gate("probe", root=root, workdir=tmp_path / "c", warm=False, load=400.0, cpus=4, guard="hook",
                    max_scale=2.0)
    assert capped.scale == pytest.approx(2.0)


def test_a_key_that_holds_on_the_control_fails_the_lane(env, monkeypatch, tmp_path):
    root, wd = env
    base = AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)
    monkeypatch.setenv("ADAPT_PROBE_ALWAYS", base)          # the engine now prints the base answer on anything
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    ctrl = [c for c in g.cases if c.mode == "control"][0]
    assert g.verdict == R.NO and ctrl.status == R.FAIL and "also holds on this neutral input" in ctrl.reason


def test_not_run_is_never_green(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    ans = AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)
    block = (f'[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "{AR.ENGINE}"\nlabel = "p"\n'
             f'fixture = "{AR.BASE_FIXTURE}"\nexpect = ["{ans}"]\ncontrols = ["{AR.CONTROL_FIXTURE}"]\n')
    needy = AR.make_repo(tmp_path / "a", opener=block + 'needs_tools = ["py:no_such_module_b036"]\n')
    g = R.gate("probe", root=needy, workdir=tmp_path / "wa", **IDLE)
    assert g.verdict == R.NOT_RUN and "no_such_module_b036" in g.reason and g.ran == 0
    sandboxed = AR.make_repo(tmp_path / "b", opener=block + "needs_os_sandbox = true\n")
    g = R.gate("probe", root=sandboxed, workdir=tmp_path / "wb", **IDLE)
    assert g.verdict == R.NOT_RUN and "OS network sandbox" in g.reason


def test_an_event_case_with_a_wrong_answer_line_says_no(env, tmp_path):
    root, wd = env
    inp = AR.write(tmp_path, "in.bin", "yesterday\n")
    R.record_case("probe", "d02", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: 0000000000000000"],
                  workdir=wd, root=root)
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g.verdict == R.NO and statuses(g)["event:d02"] == R.FAIL
    assert "missing from output: ANSWER: 0000000000000000" in g.reason


# --------------------------------------------------------------------------- how a replay runs

def test_a_replayed_engine_cannot_reach_the_network(env, monkeypatch):
    # a fake service on 127.0.0.1: an unguarded engine would connect and print CONNECTED
    root, wd = env
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.5)
        monkeypatch.setenv("ADAPT_PROBE_CONNECT", str(srv.getsockname()[1]))
        g = R.gate("probe", root=root, workdir=wd, warm=False, regate=False, **IDLE)
        with pytest.raises(socket.timeout):
            srv.accept()                                         # nothing ever connected
    finally:
        srv.close()
    base = g.cases[0]
    assert g.verdict == R.NO and base.status == R.FAIL and base.exit_code == 9, base.reason
    assert "CONNECTED" not in base.output
    assert base.output.startswith("REFUSED intake network guard:"), base.output


def test_a_replayed_engine_sees_no_secret_and_runs_inside_the_event_workdir(env, monkeypatch):
    root, wd = env
    monkeypatch.setenv("FAKE_TOKEN", "b036-not-a-real-value")
    monkeypatch.setenv("CTF_WORKDIR", str(wd.parent / "elsewhere"))
    monkeypatch.setenv("ADAPT_PROBE_SHOW", "FAKE_TOKEN,CTF_ENGINE_LEDGER,CTF_WORKDIR")
    g = R.gate("probe", root=root, workdir=wd, warm=False, regate=False, **IDLE)
    assert g.ok, g.reason
    out = g.cases[0].output
    assert "ENV FAKE_TOKEN=<unset>" in out and "b036-not-a-real-value" not in out, "a secret-named variable leaked"
    assert "ENV CTF_ENGINE_LEDGER=0" in out
    seen = dict(line.split(" ", 1) for line in out.splitlines() if line.startswith(("INPUT ", "CWD ")))
    seen["WORKDIR"] = [ln for ln in out.splitlines() if ln.startswith("ENV CTF_WORKDIR=")][0].split("=", 1)[1]
    top = wd.resolve()
    for what, p in seen.items():
        rp = Path(p).resolve()
        assert rp.is_relative_to(top) and rp != top, f"{what} {p} is not a fresh folder inside the workdir"
    assert not list(wd.glob("adapt-gate-*")), "the run folders are removed after the gate"


def _workdir_seen(out: str) -> tuple[str, str]:
    """(the CTF_WORKDIR a replay was given, what was already in it when it started)."""
    lines = out.splitlines()
    has = [ln for ln in lines if ln.startswith("WORKDIR_HAS")]
    given = [ln for ln in lines if ln.startswith("ENV CTF_WORKDIR=")]
    assert len(has) == 1 and len(given) == 1, out
    return given[0].split("=", 1)[1], has[0][len("WORKDIR_HAS"):].strip()


def test_every_replay_gets_its_own_empty_workdir(env, monkeypatch):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_SHOW", "CTF_WORKDIR")
    monkeypatch.setenv("ADAPT_PROBE_LITTER", "1")                 # each run leaves a file in its workdir
    g = R.gate("probe", root=root, workdir=wd, warm=False, regate=False, **IDLE)
    assert g.ok, g.reason
    assert len(g.cases) == 3
    seen = [_workdir_seen(c.output) for c in g.cases]
    assert all(has == "" for _, has in seen), f"a replay started on another run's leftovers: {seen}"
    assert len({given for given, _ in seen}) == 3, f"replays shared a workdir: {seen}"


@pytest.mark.parametrize("first", ["wrong", "hang"])
def test_a_re_gate_or_re_replay_starts_on_a_fresh_workdir(env, monkeypatch, tmp_path, first):
    root, wd = env
    monkeypatch.setenv("ADAPT_PROBE_SHOW", "CTF_WORKDIR")
    monkeypatch.setenv("ADAPT_PROBE_LITTER", "1")
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(tmp_path / "once"))
    monkeypatch.setenv("ADAPT_PROBE_ONCE_DO", first)               # a wrong answer (re-gate) or a cap cut
    g = R.gate("probe", root=root, workdir=wd, warm=False, cap=8.0, **IDLE)
    assert g.ok, g.reason
    c = g.cases[0]
    assert c.runs == 2 and (c.regated if first == "wrong" else c.recut)
    given, has = _workdir_seen(c.output)                            # the output is the second run's
    assert has == "", f"the second run saw the first run's leftovers in {given}: {has}"


# --------------------------------------------------------------------------- keys

def _event_case(root, wd, tmp_path, name="d07", scope=()):
    inp = AR.write(tmp_path, f"{name}.bin", f"{name} delivery\n")
    R.record_case("probe", name, engine=AR.ENGINE, input_file=inp, expect=[AR.answer_for(inp.read_bytes())],
                  workdir=wd, root=root, scope=scope)


def test_a_new_file_in_the_engine_folder_voids_an_unscoped_key(env, tmp_path):
    root, wd = env
    _event_case(root, wd, tmp_path)
    R.gate("probe", root=root, workdir=wd, **IDLE)
    AR.write(root, "solvers/toolkits/d30.py", "X = 30\n")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g)["event:d07"] == R.PASS, "the engine folder is in the key: a new day module re-runs it"


def test_a_scoped_key_survives_another_prefix_and_not_its_own(env, tmp_path):
    root, wd = env
    AR.write(root, "solvers/toolkits/probe_d07.py", "X = 7\n")
    _event_case(root, wd, tmp_path, scope=["solvers/toolkits/probe_d07*.py"])
    R.gate("probe", root=root, workdir=wd, **IDLE)
    AR.write(root, "solvers/toolkits/probe_d30.py", "X = 30\n")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g)["event:d07"] == R.WARM, "a new d30 module leaves the d07-scoped case warm"
    AR.write(root, "solvers/toolkits/probe_d07.py", "X = 77\n")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g)["event:d07"] == R.PASS, "its own prefix's change re-runs it"


def test_a_scope_matching_nothing_is_refused(env, tmp_path):
    root, wd = env
    _event_case(root, wd, tmp_path, scope=["solvers/toolkits/nothing_*.py"])
    with pytest.raises(AdaptError, match="matches no file"):
        R.gate("probe", root=root, workdir=wd, **IDLE)


def test_the_key_follows_imports_outside_the_engine_folder(env):
    root, wd = env
    R.gate("probe", root=root, workdir=wd, **IDLE)
    before = R.current_lane_key("probe", root=root, workdir=wd)
    AR.write(root, "solvers/common/unrelated.py", "Y = 1\n")
    assert R.current_lane_key("probe", root=root, workdir=wd) == before, "a file nothing imports is not in the key"
    AR.write(root, "solvers/common/adapt_probe_lib.py", 'PREFIX = "ANSWER: "  # edited\n')
    after = R.current_lane_key("probe", root=root, workdir=wd)
    assert after != before
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert set(statuses(g).values()) == {R.PASS} and g.lane_key == after


def test_current_lane_key_matches_the_gate(env):
    root, wd = env
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert R.current_lane_key("probe", root=root, workdir=wd) == g.lane_key


def test_current_lane_key_matches_the_gate_on_a_lane_with_a_not_offline_case(tmp_path, monkeypatch):
    # the web-style opener is armed only against a service: the gate keys it "" (not run), and so must
    # current_lane_key, or the chain's wrong-answer retry would always see a changed lane
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    root = AR.make_repo(tmp_path, opener=(
        '[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "toolkits.adapt_probe"\nlabel = "live"\n'
        'offline = false\nreason = "armed against a fake service only"\n'))
    wd = tmp_path / "work"
    wd.mkdir()
    _event_case(root, wd, tmp_path)
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert statuses(g) == {"opener:probe": R.NOT_RUN, "event:d07": R.PASS}
    assert [c.key == "" for c in g.cases] == [True, False]
    assert R.current_lane_key("probe", root=root, workdir=wd) == g.lane_key


def test_the_expect_and_the_fixture_code_are_in_the_key(env, tmp_path):
    root, wd = env
    inp = AR.write(tmp_path, "in.bin", "x\n")
    R.record_case("probe", "c", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: a"], workdir=wd, root=root)
    k1 = R.current_lane_key("probe", root=root, workdir=wd)
    R.record_case("probe", "c", engine=AR.ENGINE, input_file=inp, expect=["ANSWER: b"], workdir=wd, root=root,
                  force=True)
    assert R.current_lane_key("probe", root=root, workdir=wd) != k1


# --------------------------------------------------------------------------- cache, ledger, prewarm

def test_a_corrupt_cache_is_started_afresh_and_said(env):
    root, wd = env
    p = R.cache_path("probe", wd)
    p.parent.mkdir(parents=True)
    p.write_text("{not json")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert g.ok and any("unreadable" in n for n in g.notes)
    assert json.loads(p.read_text())["version"] == R.CACHE_VERSION


def test_every_gate_writes_one_ledger_record(env, monkeypatch):
    root, wd = env
    R.gate("probe", root=root, workdir=wd, **IDLE)
    R.gate("probe", root=root, workdir=wd, **IDLE)
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "2")                       # not in any key: needs warm=False
    R.gate("probe", root=root, workdir=wd, warm=False, **IDLE)
    R.gate("probe", root=root, workdir=wd, record=False, **IDLE)
    recs = [r for r in ledger.read(wd) if r["event"] == R.LEDGER_EVENT]
    assert [r["verdict"] for r in recs] == [R.YES, R.YES, R.NO]
    assert recs[0]["ran"] == 3 and recs[0]["warm"] == 0
    assert recs[1]["ran"] == 0 and recs[1]["warm"] == 3
    assert recs[2]["regated"] == 2 and recs[2]["ran"] == 3 and recs[2]["reason"]   # both cases re-gated
    assert set(recs[0]) == {"ts", "event", "lane", "verdict", "lane_key", "cases", "ran", "warm", "recut",
                            "regated", "not_run", "seconds", "scale", "reason", "jobs", "nice"}
    assert recs[0]["jobs"] == 1 and recs[0]["nice"] == 0


def test_prewarm_makes_the_clock_gate_warm(env, tmp_path):
    root, wd = env
    _event_case(root, wd, tmp_path)
    assert R.lanes_for(None, root=root, workdir=wd) == ["probe"]
    [pre] = R.prewarm(["probe"], root=root, workdir=wd, **IDLE)
    assert pre.ok and pre.ran == 4
    clock = R.gate("probe", root=root, workdir=wd, **IDLE)
    assert clock.ran == 0 and clock.count(R.WARM) == 4


def test_watch_regates_a_lane_when_a_live_fix_lands(env):
    root, wd = env
    now = [0.0]
    ticks = []

    def sleep(s):
        ticks.append(s)
        if len(ticks) == 1:
            AR.write(root, "solvers/toolkits/live_fix_d12.py", "FIXED = True\n")   # the live fix appears
        now[0] += s

    seen = []
    out = R.watch(["probe"], interval=5.0, duration=12.0, root=root, workdir=wd, on_gate=seen.append,
                  clock=lambda: now[0], sleep=sleep, **IDLE)
    assert ticks == [5.0, 5.0, 5.0] and out == seen
    assert [g.ran for g in out] == [3, 3], "gated at start, then once after the fix, not again while unchanged"
    assert out[0].lane_key != out[1].lane_key and all(g.ok for g in out)
    with pytest.raises(AdaptError, match="interval"):
        R.watch(["probe"], interval=0, root=root, workdir=wd)
