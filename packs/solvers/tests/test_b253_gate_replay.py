"""B-253: cut gate replay and cumulative solve cost.

  * the lane key minus unrelated dNN modules (ctf/adapt/regress.py Keyer, with its import audit)
  * the pooled, deadline-aware lane gate (regress.gate jobs/nice, ctf/adapt/clocks.py)
  * the same-artifact retry rule (ctf/adapt/chain.py plan)
  * the deadline-aware busy source (tools/yield_clocks.clock_busy)
  * pooled stability and variant replays of saved attempts behind a per-prefix replay cache
    (ctf/adapt/replay.py on ctf.gate.inventory.Inventory)

Engines and solvers really run (synthetic checkouts from tests/adapt_repo.py and tests/b253_fixtures.py);
nothing under test is mocked. No timing upper bound is asserted: overlap is proved by a rendezvous."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from ctf import ledger
from ctf import paths
from ctf.adapt import AdaptError
from ctf.adapt import chain as C
from ctf.adapt import clocks as K
from ctf.adapt import regress as R
from ctf.adapt import replay as P
from ctf.gate.inventory import Inventory

import adapt_repo as AR
import b253_fixtures as F

IDLE = dict(load=0.0, cpus=1, guard="hook")
BASE = "binary-day-30"
TT = f"{BASE}/time_trial"
SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS + ("B253_RDV_DIR", "B253_RDV_WAIT"):
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    return root, wd


@pytest.fixture
def sleeper():
    """Another live process whose pid a test clock can carry (a clock of this process never counts)."""
    procs = []

    def start():
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        procs.append(p)
        return p.pid
    yield start
    for p in procs:
        p.kill()
        p.wait()


def statuses(g):
    return {c.case: c.status for c in g.cases}


# --------------------------------------------------------------------------- days

def test_day_of_names_only_day_modules():
    assert R.day_of("solvers/binary/d07.py") == "d07"
    assert R.day_of("solvers/binary/d03_container.py") == "d03"
    assert R.day_of("solvers/binary/fields_d30.py") == "d30"
    assert R.day_of("solvers/binary/d30.manifest.toml") == "d30"
    for other in ("solvers/binary/day_patch.py", "solvers/binary/generic.py", "solvers/binary/d123.py",
                  "solvers/binary/dd07.py", "solvers/script-analysis/day23_fold.py"):
        assert R.day_of(other) is None, other


def test_days_are_read_from_members_question_ids_and_archives(tmp_path):
    assert R.days_in_text("d07--sample.bin", "set3.d30_analysis_x = 1", "fields_d19_word", "nod07_x", "d7_x",
                          "d08.bin") == {"d07", "d30", "d19"}
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"\x00\x01noise d12--member.cfg\xff")
    assert R.days_in_file(plain) == {"d12"}
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("d05--a.txt", b"x" * 100)
        zf.writestr("inner/d06--b.txt", b"y")
    assert {"d05", "d06"} <= R.days_in_file(z)
    t = tmp_path / "bundle.tgz"                        # names hidden by compression: read with tarfile
    with tarfile.open(t, "w:gz") as tf:
        data = b"payload"
        info = tarfile.TarInfo("d21--member.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    assert b"d21--" not in t.read_bytes()
    assert R.days_in_file(t) == {"d21"}
    big = tmp_path / "big.bin"                         # a token across the scanner's chunk boundary
    big.write_bytes(b"\x00" * (R._SCAN_CHUNK - 3) + b"d44--x")
    assert R.days_in_file(big) == {"d44"}


def _event(root, wd, tmp_path, name, fname, body, expect=None, scope=()):
    inp = AR.write(tmp_path, f"in-{name}/{fname}", body)
    R.record_case("probe", name, engine=AR.ENGINE, input_file=inp,
                  expect=expect or [AR.answer_for(inp.read_bytes())], workdir=wd, root=root, scope=scope)


def test_a_day_scoped_case_stays_warm_when_another_day_lands(env, tmp_path):
    root, wd = env
    AR.write(root, "solvers/toolkits/d07.py", "X = 7\n")
    _event(root, wd, tmp_path, "c07", "d07--delivery.bin", "day seven\n")
    _event(root, wd, tmp_path, "nodays", "delivery.bin", "no day here\n")
    assert set(statuses(R.gate("probe", root=root, workdir=wd, **IDLE)).values()) == {R.PASS}
    AR.write(root, "solvers/toolkits/fields_d99.py", "Y = 99\n")
    AR.write(root, "solvers/toolkits/d30.py", "Z = 30\n")
    g = R.gate("probe", root=root, workdir=wd, **IDLE)
    st = statuses(g)
    assert st["event:c07"] == R.WARM, "new d30/d99 modules leave the d07 case warm"
    assert st["event:nodays"] == R.PASS, "a case with no day found keys the whole folder"
    assert st[f"opener:{AR.BASE_FIXTURE}"] == R.PASS, "opener fixtures are not day-scoped"
    AR.write(root, "solvers/toolkits/d07.py", "X = 77\n")
    assert statuses(R.gate("probe", root=root, workdir=wd, **IDLE))["event:c07"] == R.PASS, "its own day re-runs it"
    AR.write(root, "solvers/toolkits/generic.py", "G = 1\n")
    assert statuses(R.gate("probe", root=root, workdir=wd, **IDLE))["event:c07"] == R.PASS, \
        "a non-day file of the folder voids every case"


def test_day_scoping_can_be_turned_off(env, tmp_path):
    root, wd = env
    _event(root, wd, tmp_path, "c07", "d07--delivery.bin", "day seven\n")
    k = R.Keyer(root, day_scoped=False)
    R.gate("probe", root=root, workdir=wd, keyer=k, **IDLE)
    AR.write(root, "solvers/toolkits/d30.py", "Z = 30\n")
    g = R.gate("probe", root=root, workdir=wd, keyer=R.Keyer(root, day_scoped=False), **IDLE)
    assert statuses(g)["event:c07"] == R.PASS


def test_the_import_audit_keeps_days_a_kept_file_names(env, tmp_path):
    root, wd = env
    AR.write(root, "solvers/toolkits/d07.py", "import d12_tables\nX = d12_tables.T\n")
    AR.write(root, "solvers/toolkits/d12_tables.py", "T = 1\n")
    AR.write(root, "solvers/toolkits/d30.py", "Z = 30\n")
    AR.write(root, "solvers/toolkits/d31.py", "W = 31\n")
    AR.write(root, "solvers/toolkits/router.py", 'SPECIAL = {"d30": "load by name"}\n')   # a non-day file names d30
    _event(root, wd, tmp_path, "c07", "d07--delivery.bin", "day seven\n")
    keyer = R.Keyer(root)
    case = next(c for c in R.regression_set("probe", root=root, workdir=wd) if c.name == "event:c07")
    assert keyer.days(case) == {"d07"}
    files = keyer.folder_files("solvers/toolkits", keyer.days(case))
    assert "solvers/toolkits/d12_tables.py" in files, "a day module a kept one imports is kept"
    assert "solvers/toolkits/d30.py" in files, "a day a non-day file names is pinned"
    assert "solvers/toolkits/d31.py" not in files
    R.gate("probe", root=root, workdir=wd, **IDLE)
    AR.write(root, "solvers/toolkits/d31.py", "W = 3131\n")
    assert statuses(R.gate("probe", root=root, workdir=wd, **IDLE))["event:c07"] == R.WARM
    for rel, body in (("solvers/toolkits/d12_tables.py", "T = 2\n"), ("solvers/toolkits/d30.py", "Z = 3030\n")):
        AR.write(root, rel, body)
        assert statuses(R.gate("probe", root=root, workdir=wd, **IDLE))["event:c07"] == R.PASS, rel


def test_a_case_s_days_come_from_its_expect_lines_too(env, tmp_path):
    root, wd = env
    AR.write(root, "solvers/toolkits/d07.py", "X = 7\n")
    AR.write(root, "solvers/toolkits/d30.py", "Z = 30\n")
    inp = AR.write(tmp_path, "plain/delivery.bin", "no member names\n")
    R.record_case("probe", "byexpect", engine=AR.ENGINE, input_file=inp,
                  expect=[AR.answer_for(inp.read_bytes())], workdir=wd, root=root)
    keyer = R.Keyer(root)
    case = next(c for c in R.regression_set("probe", root=root, workdir=wd) if c.name == "event:byexpect")
    assert keyer.days(case) == frozenset()
    case2 = R.RegCase(**{**case.__dict__, "expect": case.expect + ("d30_analysis_x = 5",)})
    assert keyer.days(case2) == {"d30"}
    files = keyer.folder_files("solvers/toolkits", keyer.days(case2))
    assert "solvers/toolkits/d30.py" in files and "solvers/toolkits/d07.py" not in files


def test_a_kept_file_s_import_outside_the_folder_is_in_the_key(env, tmp_path):
    """A kept non-entry file (generic.py) imports solvers/common/b253_helper.py, which the entry does not:
    editing that helper must void the day-scoped case and the whole-folder case all the same."""
    root, wd = env
    AR.write(root, "solvers/common/b253_helper.py", "H = 1\n")
    AR.write(root, "solvers/toolkits/generic.py", "import b253_helper\nG = b253_helper.H\n")
    AR.write(root, "solvers/toolkits/d07.py", "X = 7\n")
    _event(root, wd, tmp_path, "c07", "d07--delivery.bin", "day seven\n")
    _event(root, wd, tmp_path, "nodays", "delivery.bin", "no day here\n")
    keyer = R.Keyer(root)
    assert "solvers/common/b253_helper.py" not in keyer.graph.closure("solvers/toolkits/adapt_probe.py")
    for days in (frozenset({"d07"}), frozenset()):
        assert "solvers/common/b253_helper.py" in keyer.folder_files("solvers/toolkits", days), days
    assert set(statuses(R.gate("probe", root=root, workdir=wd, **IDLE)).values()) == {R.PASS}
    assert statuses(R.gate("probe", root=root, workdir=wd, **IDLE))["event:c07"] == R.WARM
    AR.write(root, "solvers/common/b253_helper.py", "H = 2\n")
    st = statuses(R.gate("probe", root=root, workdir=wd, **IDLE))
    assert st["event:c07"] == R.PASS and st["event:nodays"] == R.PASS, st


def test_the_binary_lane_keys_minus_other_days(tmp_path, monkeypatch):
    """The import audit on the real binary lane: a d29 row's key leaves out d30.py, fields_d30.py and
    fields_d31.py (the Day 30 cold gate), keeps generic.py and evidence.py, and keeps the day modules a
    non-day file imports or names (generic.py imports d01/d03)."""
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    k = R.Keyer(paths.repo_root())
    lane = "solvers/binary"
    if not (paths.repo_root() / lane / "d30.py").is_file():
        pytest.fail("solvers/binary/d30.py is gone: update this audit to the lane's current day modules")
    d29 = set(k.folder_files(lane, frozenset({"d29"})))
    d30 = set(k.folder_files(lane, frozenset({"d30"})))
    whole = set(k.folder_files(lane))
    for f in ("d30.py", "fields_d30.py", "fields_d31.py"):
        assert f"{lane}/{f}" not in d29, f
    for f in ("d29.py", "generic.py", "evidence.py", "d01.py", "d03.py"):
        assert f"{lane}/{f}" in d29, f
    assert {f"{lane}/d30.py", f"{lane}/fields_d30.py"} <= d30 and f"{lane}/fields_d31.py" not in d30
    assert f"{lane}/fields_d31.py" in whole
    gen = f"{lane}/generic.py"
    assert {"d01", "d03"} <= k.day_refs(gen)


# --------------------------------------------------------------------------- pooled gate and the quiet check

def _rdv_lane(root, wd, tmp_path, n=2, expect="TOGETHER"):
    F.add_rdv_engine(root)
    for i in range(n):
        inp = AR.write(tmp_path, f"rdv/in{i}.bin", f"rdv input {i}\n")
        R.record_case("rdv", f"r{i}", engine=F.RDV_ENGINE, input_file=inp, expect=[expect], workdir=wd, root=root)


def test_jobs_replays_stale_cases_at_the_same_time(env, tmp_path, monkeypatch):
    """Each case passes on its first run only if the other case's run is alive beside it. No re-gate and a
    cap well above the wait, so a run cut at its cap (whose leftover marker a later run could meet) or a
    second chance can never turn serial replays green: every case must pass on exactly one run."""
    root, wd = env
    _rdv_lane(root, wd, tmp_path)
    monkeypatch.setenv("B253_RDV_DIR", str(tmp_path / "rdv-par"))
    monkeypatch.setenv("B253_RDV_WAIT", "60")         # a peer only has to start; no upper bound is asserted
    g = R.gate("rdv", root=root, workdir=wd, jobs=2, regate=False, cap=300.0, **IDLE)
    assert g.verdict == R.YES, g.reason
    assert g.jobs == 2 and all(c.status == R.PASS for c in g.cases)
    assert [(c.runs, c.recut, c.regated) for c in g.cases] == [(1, False, False)] * 2, g.cases
    assert [c.case for c in g.cases] == ["event:r0", "event:r1"], "outcomes keep the set's order"
    assert set(statuses(R.gate("rdv", root=root, workdir=wd, jobs=2, **IDLE)).values()) == {R.WARM}


def test_jobs_one_replays_one_at_a_time(env, tmp_path, monkeypatch):
    root, wd = env
    _rdv_lane(root, wd, tmp_path)
    monkeypatch.setenv("B253_RDV_DIR", str(tmp_path / "rdv-ser"))
    monkeypatch.setenv("B253_RDV_WAIT", "1")          # serial runs never meet, whatever the wait
    g = R.gate("rdv", root=root, workdir=wd, jobs=1, regate=False, **IDLE)
    assert g.verdict == R.NO and all("TOGETHER" in c.reason for c in g.cases)
    assert all("ALONE" in c.output for c in g.cases)


def test_a_marker_left_by_a_killed_run_is_not_a_peer(env, tmp_path, monkeypatch):
    """The rendezvous itself: a run cut at its cap leaves its marker, and the next run must not meet it."""
    root, wd = env
    _rdv_lane(root, wd, tmp_path, n=1)
    rdv = tmp_path / "rdv-stale"
    monkeypatch.setenv("B253_RDV_DIR", str(rdv))
    monkeypatch.setenv("B253_RDV_WAIT", "600")        # far past both caps: each run is cut
    g = R.gate("rdv", root=root, workdir=wd, jobs=1, regate=False, cap=10.0, recut=2.0, **IDLE)
    [c] = g.cases
    assert c.status == R.CUT and c.runs == 2 and c.recut, c
    assert list(rdv.glob("*.here")), "a cut run leaves its marker behind"
    monkeypatch.setenv("B253_RDV_WAIT", "1")
    g = R.gate("rdv", root=root, workdir=wd, jobs=1, regate=False, **IDLE)
    [c] = g.cases
    assert c.status == R.FAIL and "ALONE" in c.output, "a dead run's marker is no peer"


def test_a_red_case_in_a_pooled_gate_is_not_cached(env, tmp_path, monkeypatch):
    root, wd = env
    _rdv_lane(root, wd, tmp_path, expect="NEVER")
    monkeypatch.setenv("B253_RDV_DIR", str(tmp_path / "rdv-red"))
    monkeypatch.setenv("B253_RDV_WAIT", "1")
    g = R.gate("rdv", root=root, workdir=wd, jobs=2, regate=False, **IDLE)
    assert g.verdict == R.NO and g.count(R.FAIL) == 2
    cache = json.loads(R.cache_path("rdv", wd).read_text())["results"]
    assert not cache


@pytest.mark.parametrize("bad", [0, -1, True, "many", 2.5])
def test_a_bad_jobs_value_is_refused(env, bad):
    root, wd = env
    with pytest.raises(AdaptError, match="jobs"):
        R.gate("probe", root=root, workdir=wd, jobs=bad, **IDLE)


def test_auto_jobs_throttle_only_under_a_deadline_clock(env, tmp_path, monkeypatch, sleeper):
    root, wd = env
    _rdv_lane(root, wd, tmp_path, n=1, expect="NICE")
    monkeypatch.setenv("B253_RDV_DIR", str(tmp_path / "rdv-nice"))
    monkeypatch.setenv("B253_RDV_WAIT", "0.2")
    base = os.nice(0)
    other = sleeper()
    nodl = K.start("metadata-day-30/time_trial", deadline=None, workdir=wd, pid=other)
    kw = {**IDLE, "cpus": 4}                          # the gate's cpus, not the machine's, cap the policy
    g = R.gate("rdv", root=root, workdir=wd, jobs="auto", warm=False, **kw)
    assert g.nice == 0 and g.jobs == 4
    assert f"NICE {base}" in g.cases[0].output, "a clock with no deadline does not throttle the replays"
    assert any("without a deadline" in n for n in g.notes)
    K.stop(nodl)
    K.start("binary-day-30/time_trial", deadline=time.time() + 600, workdir=wd, pid=other)
    g = R.gate("rdv", root=root, workdir=wd, jobs="auto", warm=False, **kw)
    assert g.nice == K.NICE_BUSY and g.jobs == K.REPLAY_PROCS_BUSY
    assert f"NICE {min(base + K.NICE_BUSY, 20)}" in g.cases[0].output, "the replay really runs niced"
    assert any("binary-day-30/time_trial" in n for n in g.notes)
    rec = [r for r in ledger.read(wd) if r["event"] == R.LEDGER_EVENT][-1]
    assert rec["nice"] == K.NICE_BUSY and rec["jobs"] == g.jobs
    g2 = R.gate("rdv", root=root, workdir=wd, jobs="auto", warm=False, **{**IDLE, "cpus": 2})
    assert g2.jobs == 2, "a busy policy never asks for more replays than the gate's cpus"


# --------------------------------------------------------------------------- clocks

def test_only_another_process_s_deadline_clock_is_busy(tmp_path, sleeper):
    wd = tmp_path
    assert K.running(wd) == [] and not K.deadline_busy(wd)
    other = sleeper()
    p1 = K.start("meta/time_trial", deadline=None, workdir=wd, pid=other)
    assert [c.challenge_id for c in K.running(wd)] == ["meta/time_trial"]
    assert not K.deadline_busy(wd), "a deadline-null clock is idle"
    assert not K.replay_policy(wd, cpus=14).busy
    mine = K.start("own/mastery", deadline=time.time() + 60, workdir=wd)
    assert not K.deadline_busy(wd), "the asking process's own clock never throttles it"
    p2 = K.start("bin/mastery", deadline=time.time() + 60, workdir=wd, pid=other)
    assert K.deadline_busy(wd)
    pol = K.replay_policy(wd, cpus=14)
    assert (pol.jobs, pol.nice, pol.busy) == (K.REPLAY_PROCS_BUSY, K.NICE_BUSY, True) and "bin/mastery" in pol.reason
    assert K.replay_policy(wd, cpus=14).jobs == 3 and K.replay_policy(wd, cpus=2).jobs == 2
    for p in (p1, p2, mine):
        K.stop(p)
    pol = K.replay_policy(wd, cpus=14)
    assert (pol.jobs, pol.nice, pol.busy) == (K.REPLAY_PROCS_IDLE, 0, False)


def test_a_clock_past_its_deadline_or_of_a_dead_process_is_over(tmp_path):
    wd = tmp_path
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    dead = K.start("gone/mastery", deadline=time.time() + 600, workdir=wd, pid=p.pid)
    assert K.running(wd) == [] and not dead.exists(), "a dead runner's clock file is removed"
    K.start("late/mastery", deadline=1000.0, workdir=wd, pid=os.getppid())
    assert K.deadline_busy(wd, now=1000.0 + K.GRACE - 0.1)
    assert not K.deadline_busy(wd, now=1000.0 + K.GRACE + 0.1)


@pytest.mark.parametrize("body", ["{not json", json.dumps({"challenge_id": "x"}),
                                  json.dumps({"challenge_id": "x", "pid": "1", "deadline": None, "started": 1}),
                                  json.dumps({"challenge_id": "x", "pid": 1, "deadline": "soon", "started": 1})])
def test_a_malformed_clock_file_is_a_named_error(tmp_path, body):
    d = K.clock_dir(tmp_path)
    d.mkdir(parents=True)
    bad = d / f"1-abc{K.SUFFIX}"
    bad.write_text(body)
    with pytest.raises(AdaptError, match="clock file"):
        K.running(tmp_path)


def test_a_bad_deadline_is_refused(tmp_path):
    for bad in ("soon", True, float("nan")):
        with pytest.raises(AdaptError, match="deadline"):
            K.start("x", deadline=bad, workdir=tmp_path)


def test_the_attempt_guard_holds_a_clock_for_the_attempt(tmp_path):
    dl = time.time() + 30
    with C.AttemptGuard(TT, lane_key="k", workdir=tmp_path, deadline=dl, artifact_sha256=SHA_A) as att:
        [c] = K.running(tmp_path)
        assert (c.challenge_id, c.pid, c.deadline) == (TT, os.getpid(), dl)
        att.done("not_submitted", missing=13, learned=["bsh.one_copy"])
    assert K.running(tmp_path) == [], "the clock ends with the attempt"
    [a] = C.attempts(TT, tmp_path)
    assert (a["artifact_sha256"], a["missing"], a["learned"]) == (SHA_A, 13, ["bsh.one_copy"])
    with pytest.raises(RuntimeError):
        with C.AttemptGuard(TT, workdir=tmp_path, artifact_sha256=SHA_B):
            assert len(K.running(tmp_path)) == 1
            raise RuntimeError("killed")
    assert K.running(tmp_path) == []
    assert C.attempts(TT, tmp_path)[-1]["artifact_sha256"] == SHA_B


def test_a_deadline_attempt_in_another_process_makes_the_machine_busy(tmp_path):
    code = ("import sys, time\nfrom ctf.adapt import chain\n"
            "with chain.AttemptGuard(sys.argv[1], workdir=sys.argv[2], deadline=time.time() + 300):\n"
            "    print('IN', flush=True)\n    sys.stdin.readline()\n")
    p = subprocess.Popen([sys.executable, "-c", code, TT, str(tmp_path)], cwd=str(AR.REPO), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "IN"
        assert K.deadline_busy(tmp_path) and K.replay_policy(tmp_path).busy
    finally:
        p.communicate("go\n", timeout=60)
    assert not K.deadline_busy(tmp_path) and K.running(tmp_path) == []


@pytest.mark.parametrize("bad", [dict(missing=-1), dict(missing=True), dict(learned="key"), dict(learned=[" "]),
                                 dict(artifact_sha256="xyz"), dict(artifact_sha256="A" * 64)])
def test_record_attempt_checks_the_new_fields(tmp_path, bad):
    with pytest.raises(AdaptError):
        C.record_attempt(TT, "not_submitted", workdir=tmp_path, **bad)


def test_yield_clocks_holds_only_for_a_deadline_clock(tmp_path, sleeper):
    sys.path.insert(0, str(AR.REPO / "tools"))
    import yield_clocks
    other = sleeper()
    work = [sys.executable, "-c", "import time; time.sleep(0.6)"]
    nodl = K.start("meta/time_trial", deadline=None, workdir=tmp_path, pid=other)
    notes: list = []
    assert yield_clocks.run_held(work, busy=yield_clocks.clock_busy(tmp_path), poll=0.02, max_hold=1.0,
                                 note=notes.append) == 0
    assert not any(n.startswith("NOTE held") for n in notes), notes
    K.stop(nodl)
    K.start("bin/time_trial", deadline=time.time() + 600, workdir=tmp_path, pid=other)
    notes = []
    assert yield_clocks.run_held(work, busy=yield_clocks.clock_busy(tmp_path), poll=0.02, max_hold=1.0,
                                 note=notes.append) == 0
    assert any(n.startswith("NOTE held") for n in notes), notes
    assert "clock_busy" in yield_clocks.NO_BUSY_SOURCE


# --------------------------------------------------------------------------- the same-artifact retry

def _plan(root, wd, **kw):
    return C.plan(BASE, "probe", workdir=wd, root=root, gate_kw=IDLE, **kw)


def _gates(wd):
    return [r for r in ledger.read(wd) if r["event"] == "adapt.gate"]


def _failed_tt(root, wd, **fields):
    C.mark_closed(BASE, by="hand", workdir=wd)
    key = R.current_lane_key("probe", root=root, workdir=wd)
    C.record_attempt(TT, fields.pop("outcome", "not_submitted"), lane_key=key, workdir=wd, **fields)
    return key


def test_a_same_artifact_retry_that_can_only_repeat_stops_without_a_gate(env):
    root, wd = env
    key = _failed_tt(root, wd, artifact_sha256=SHA_A, missing=13)
    n = len(_gates(wd))
    step = _plan(root, wd, artifact_sha256=SHA_A)
    assert step.action == "stop" and step.challenge_id == TT and "same artifact" in step.reason
    assert "13 id(s)" in step.reason and step.gate is None and step.lane_key == key
    assert len(_gates(wd)) == n, "the determined NO runs no gate"


@pytest.mark.parametrize("fields, retry_sha", [
    (dict(artifact_sha256=SHA_A, missing=13, learned=["bsh.one_copy"]), SHA_A),   # learned a key: gated
    (dict(artifact_sha256=SHA_A, missing=13), SHA_B),                             # a new artifact
    (dict(artifact_sha256=SHA_A, missing=13), None),                              # artifact unknown
    (dict(artifact_sha256=SHA_A), SHA_A),                                         # a kill: no missing count
    (dict(artifact_sha256=SHA_A, missing=0), SHA_A),                              # nothing left unanswered
    (dict(missing=13), SHA_A),                                                    # no artifact recorded
    (dict(artifact_sha256=SHA_A, missing=13, outcome="expired"), SHA_B),
])
def test_a_retry_that_might_differ_goes_to_the_gate(env, fields, retry_sha):
    root, wd = env
    _failed_tt(root, wd, **fields)
    step = _plan(root, wd, artifact_sha256=retry_sha)
    assert step.action == "retry" and step.gate is not None and step.gate.ok, step.reason


def test_an_expired_same_artifact_attempt_also_stops(env):
    root, wd = env
    _failed_tt(root, wd, artifact_sha256=SHA_A, missing=2, outcome="expired")
    assert _plan(root, wd, artifact_sha256=SHA_A).action == "stop"


def test_a_same_artifact_retry_after_a_fold_goes_to_the_gate(env):
    root, wd = env
    _failed_tt(root, wd, artifact_sha256=SHA_A, missing=13)
    AR.write(root, "solvers/toolkits/adapt_probe_fallback.py", "READER = 'fallback'\n")    # the fold
    step = _plan(root, wd, artifact_sha256=SHA_A)
    assert step.action == "retry" and step.gate.ok


def test_a_wrong_answer_keeps_its_lane_key_rule(env):
    root, wd = env
    _failed_tt(root, wd, outcome="incorrect", artifact_sha256=SHA_A, missing=0, learned=["k"])
    step = _plan(root, wd, artifact_sha256=SHA_A)
    assert step.action == "stop" and "lane is unchanged" in step.reason


@pytest.mark.parametrize("fields", [dict(outcome="incorrect", artifact_sha256=SHA_A, missing=0),
                                    dict(artifact_sha256=SHA_A, missing=13)])
def test_a_fold_into_a_day_module_no_case_covers_opens_the_retry(env, tmp_path, fields):
    """A lane whose set holds only a d07 event case (no opener keying the whole folder) failed a d30
    attempt; the fix lands as a new d30.py. The d07 case stays warm, but the lane key the retry rules
    compare must change, or the chain would refuse the very retry the fix was for."""
    root, wd = env
    inp = AR.write(tmp_path, "evonly/d07--delivery.bin", "day seven\n")
    R.record_case("evonly", "c07", engine=AR.ENGINE, input_file=inp, expect=[AR.answer_for(inp.read_bytes())],
                  workdir=wd, root=root)
    assert [c.source for c in R.regression_set("evonly", root=root, workdir=wd)] == ["event"]
    g = R.gate("evonly", root=root, workdir=wd, **IDLE)
    assert g.ok and g.lane_key == R.current_lane_key("evonly", root=root, workdir=wd)
    C.mark_closed(BASE, by="hand", workdir=wd)
    C.record_attempt(TT, fields.pop("outcome", "not_submitted"), lane_key=g.lane_key, workdir=wd, **fields)
    stopped = C.plan(BASE, "evonly", workdir=wd, root=root, gate_kw=IDLE, artifact_sha256=SHA_A)
    assert stopped.action == "stop" and stopped.gate is None, "nothing folded yet: the retry would repeat"
    AR.write(root, "solvers/toolkits/d30.py", "FIX = 30\n")                 # the fold
    step = C.plan(BASE, "evonly", workdir=wd, root=root, gate_kw=IDLE, artifact_sha256=SHA_A)
    assert step.action == "retry" and step.gate.ok, step.reason
    assert step.lane_key != g.lane_key == stopped.lane_key
    assert statuses(step.gate) == {"event:c07": R.WARM}, "the warm cache stays day-scoped"
    assert step.lane_key == R.current_lane_key("evonly", root=root, workdir=wd)


def test_plan_refuses_a_malformed_artifact_sha(env):
    root, wd = env
    with pytest.raises(AdaptError, match="artifact_sha256"):
        _plan(root, wd, artifact_sha256="not-a-sha")


# --------------------------------------------------------------------------- pooled replays of saved attempts

# The set pool refuses to fork beside another thread (xdist's worker has some), so pooled in-process replays
# run in a fresh interpreter, as the stability children and the CLI do.
POOL_CHILD = '''\
import json, os, sys
from ctf.adapt import replay as P

PARENT = os.getpid()


class Echo:
    def solve_set(self, questions, files, ctx):
        return {q["qid"]: f"{ctx['set']}:{q['qid']}" for q in questions}


class Pid:
    def solve_set(self, questions, files, ctx):
        return {q["qid"]: str(os.getpid()) for q in questions}


class Flaky:
    def solve_set(self, questions, files, ctx):
        if os.getpid() != PARENT and ctx["set"] == 2:
            os._exit(3)                                  # the worker dies on set 2
        return {q["qid"]: "ok" for q in questions}


def sets(n):
    return lambda: [(i, [{"qid": f"q{i}", "answer_id": f"set{i}.q{i}"}], {"f": b"x" * i}, {"set": i})
                    for i in range(1, n + 1)]


out = {}
for name, solver, n in (("echo", Echo(), 5), ("pid", Pid(), 4), ("flaky", Flaky(), 3)):
    for pooled in (True, False):
        r = P.replay(solver, sets(n), pooled=pooled)
        out[f"{name}-{'pooled' if pooled else 'serial'}"] = {"answers": r.answers, "pooled": r.pooled,
                                                              "serial": r.serial, "notes": r.notes}
out["parent"] = PARENT
print(json.dumps(out))
'''


@pytest.fixture(scope="module")
def pool_child():
    r = subprocess.run([sys.executable, "-c", POOL_CHILD], cwd=str(AR.REPO), capture_output=True, text=True,
                       timeout=300)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_a_pooled_replay_runs_in_workers_and_equals_the_serial_one(pool_child):
    pooled, serial = pool_child["echo-pooled"], pool_child["echo-serial"]
    assert pooled["answers"] == serial["answers"] and len(pooled["answers"]) == 5
    assert sorted(pooled["pooled"]) == [1, 2, 3, 4, 5] and pooled["serial"] == []
    assert serial["pooled"] == [] and serial["serial"] == [1, 2, 3, 4, 5]
    pids = set(pool_child["pid-pooled"]["answers"].values())
    assert pids and str(pool_child["parent"]) not in pids, "every set was solved in a forked worker"
    assert set(pool_child["pid-serial"]["answers"].values()) == {str(pool_child["parent"])}


def test_a_worker_failure_falls_back_to_the_serial_path(pool_child):
    run = pool_child["flaky-pooled"]
    assert run["answers"] == {"set1.q1": "ok", "set2.q2": "ok", "set3.q3": "ok"}
    assert 2 in run["serial"] and 2 not in run["pooled"] and sorted(run["pooled"]) == [1, 3]


def test_a_replay_beside_a_thread_is_serial_and_says_so():
    import threading
    stop = threading.Event()
    t = threading.Thread(target=stop.wait)
    t.start()
    try:
        r = P.replay(type("S", (), {"solve_set": lambda self, qs, f, c: {q["qid"]: 1 for q in qs}})(),
                     lambda: [(i, [{"qid": "q", "answer_id": f"a{i}"}], {}, {"set": i}) for i in (1, 2)])
    finally:
        stop.set()
        t.join()
    assert r.answers == {"a1": 1, "a2": 1} and r.pooled == [] and r.serial == [1, 2]
    assert any("another thread" in n for n in r.notes)


def _lane(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gs"))
    root = AR.make_repo(tmp_path)
    solver = F.write_lane(root)
    rows = tmp_path / "rows"
    F.save_attempt(rows / "day-07" / "binary-day-07-mastery",
                   {1: ("d07--one.txt", b"alpha\n", ["d07_word", "d07_len"]),
                    2: ("d07--two.txt", b"beta\n", ["d07_word"])})
    F.save_attempt(rows / "day-30" / "binary-day-30-mastery",
                   {1: ("d30--one.txt", b"gamma\n", ["d30_word"]), 2: ("d30--two.txt", b"delta\n", ["d30_word"])})
    wd = tmp_path / "work"
    wd.mkdir()
    return root, solver, rows, wd


def test_a_saved_attempt_replays_pooled_and_serial_alike(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = rows / "day-07" / "binary-day-07-mastery"
    att = P.SavedAttempt.load(folder)
    assert att.days() == {"d07"}
    serial = P.replay_attempt(folder, solver, pooled=False)
    assert set(serial.answers) == {"set1.d07_word", "set1.d07_len", "set2.d07_word"}
    assert serial.answers["set1.d07_word"] == F.day_answer("seven", "d07_word", b"alpha\n"), \
        "set 1 is solved on its own delivery by the d07 module"
    assert serial.answers["set2.d07_word"] == F.day_answer("seven", "d07_word", b"beta\n")
    r = _ctf(wd, "replay", str(folder), "--solver", str(solver), "--json")      # pooled, in a fresh process
    assert r.returncode == 0, r.stderr
    pooled = json.loads(r.stdout)
    assert pooled["answers"] == serial.answers and sorted(pooled["pooled"]) == [1, 2]


def test_a_saved_attempt_with_a_changed_delivery_is_refused(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = rows / "day-07" / "binary-day-07-mastery"
    (folder / "artifact" / "delivery-01" / "d07--one.txt").write_bytes(b"tampered\n")
    with pytest.raises(AdaptError, match="sha256"):
        P.SavedAttempt.load(folder)
    with pytest.raises(AdaptError, match="no attempt.json"):
        P.SavedAttempt.load(tmp_path)
    (folder / "artifact" / "delivery-01" / "d07--one.txt").unlink()
    with pytest.raises(AdaptError, match="not saved"):
        P.SavedAttempt.load(folder)


def test_stability_runs_two_interpreters_through_the_pool(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = rows / "day-30" / "binary-day-30-mastery"
    st = P.stability(folder, solver, workdir=wd)
    assert st.status == P.STABLE, st.reason
    assert st.answers == P.replay_attempt(folder, solver, pooled=False).answers
    assert all(sorted(r.pooled) == [1, 2] for r in st.runs), "both replays went through the set pool"
    assert not list(wd.glob("adapt-replay-*")), "the children's folder is removed"


def test_an_answer_that_differs_between_processes_is_unstable(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = F.save_attempt(tmp_path / "pidrow", {1: ("d07--x.txt", b"x\n", ["d07_pid"]),
                                                  2: ("d07--y.txt", b"y\n", ["d07_word"])})
    st = P.stability(folder, solver, workdir=wd)
    assert st.status == P.UNSTABLE and list(st.diffs) == ["set1.d07_pid"]


def test_a_child_that_fails_is_not_a_stability_verdict(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    broken = AR.write(root, "solvers/lane/broken.py", "raise ImportError('no reader')\n")
    st = P.stability(rows / "day-07" / "binary-day-07-mastery", broken, workdir=wd)
    assert st.status == P.FAILED and "exited" in st.reason and not st.stable


SLOW = '''\
import time


def solve_set(questions, files, ctx):
    time.sleep(30)
    return {q["qid"]: "late" for q in questions}
'''


def test_a_budget_cut_child_is_not_a_stability_verdict(tmp_path, monkeypatch):
    """Both children run out of a tiny budget on a solver that sleeps far past it: CUT, never STABLE (the
    two cut replays would otherwise agree on the same empty answers)."""
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    slow = AR.write(root, "solvers/lane/slow.py", SLOW)
    st = P.stability(rows / "day-07" / "binary-day-07-mastery", slow, workdir=wd, budget=0.5)
    assert st.status == P.CUT and not st.stable and "budget" in st.reason, (st.status, st.reason)
    assert len(st.runs) == 2 and all(r.timed_out for r in st.runs)


def test_a_busy_policy_caps_each_child_s_set_pool(tmp_path, monkeypatch):
    """While a deadline clock runs, each stability child forks at most REPLAY_PROCS_BUSY workers (an
    eight-set attempt would otherwise fork setpool.workers_for(8)); idle, the pool's own count."""
    from ctf.adapt import setpool
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = F.save_attempt(tmp_path / "eight", {i: (f"d07--{i}.txt", f"set {i}\n".encode(), ["d07_word"])
                                                 for i in range(1, 9)})
    assert setpool.workers_for(8) > K.REPLAY_PROCS_BUSY
    busy = K.ReplayPolicy(K.REPLAY_PROCS_BUSY, 0, True, "test: a deadline clock runs")
    st = P.stability(folder, solver, workdir=wd, policy=busy)
    assert st.status == P.STABLE, st.reason
    assert [r.workers for r in st.runs] == [K.REPLAY_PROCS_BUSY] * 2
    idle = K.ReplayPolicy(K.REPLAY_PROCS_IDLE, 0, False, "test: idle")
    st = P.stability(folder, solver, workdir=wd, policy=idle)
    assert st.status == P.STABLE and [r.workers for r in st.runs] == [setpool.workers_for(8)] * 2


def test_rows_are_cached_per_prefix(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    found = P.rows_in(rows)
    assert sorted(found) == ["day-07/binary-day-07-mastery", "day-30/binary-day-30-mastery"]

    def gate():
        return P.gate_rows(found, solver, workdir=wd, lane="lane", keyer=R.Keyer(root))

    def st(g):
        return {r.row.split("/")[0]: r.status for r in g.rows}

    g = gate()
    assert g.ok and st(g) == {"day-07": P.GREEN, "day-30": P.GREEN}, g.reason
    assert {r.row: r.days for r in g.rows}["day-07/binary-day-07-mastery"] == ("d07",)
    assert st(gate()) == {"day-07": P.WARM, "day-30": P.WARM}
    AR.write(root, "solvers/lane/fields_d99.py", "X = 99\n")
    assert st(gate()) == {"day-07": P.WARM, "day-30": P.WARM}, "a new day module leaves other rows warm"
    AR.write(root, "solvers/lane/d30.py", F.DAY.format(salt="thirty-fixed"))
    assert st(gate()) == {"day-07": P.WARM, "day-30": P.GREEN}, "only the d30 row replays"
    AR.write(root, "solvers/lane/solver.py", F.SOLVER + "\n# edited\n")
    assert st(gate()) == {"day-07": P.GREEN, "day-30": P.GREEN}, "the solver itself voids every row"
    assert st(P.gate_rows(found, solver, workdir=wd, lane="lane", keyer=R.Keyer(root), warm=False)) \
        == {"day-07": P.GREEN, "day-30": P.GREEN}
    assert st(P.gate_rows(found, solver, workdir=wd, lane="lane", keyer=R.Keyer(root, day_scoped=False))) \
        == {"day-07": P.GREEN, "day-30": P.GREEN}, "keys without day scoping are other keys"
    inv = Inventory(P.cache_path("lane", wd), P.CACHE_VERSION)
    assert sorted(inv._entries) == sorted(found)


def test_a_red_row_is_never_cached(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = rows / "day-07" / "binary-day-07-mastery"
    good = P.replay_attempt(folder, solver, pooled=False).answers
    (folder / "expect.json").write_text(json.dumps({**good, "set1.d07_word": "wrong"}))
    found = P.rows_in(rows)
    for _ in range(2):
        g = P.gate_rows(found, solver, workdir=wd, lane="lane", keyer=R.Keyer(root))
        by = {r.row.split("/")[0]: r for r in g.rows}
        assert not g.ok and by["day-07"].status == P.RED and "not given" in by["day-07"].reason
    (folder / "expect.json").write_text(json.dumps(good))
    g = P.gate_rows(found, solver, workdir=wd, lane="lane", keyer=R.Keyer(root))
    assert g.ok and {r.row.split("/")[0]: r.status for r in g.rows}["day-07"] == P.GREEN


def test_inventory_discard_forgets_one_key(tmp_path):
    inv = Inventory(tmp_path / "inv.json", "v1")
    calls = []
    inv.refresh({"a": "h1", "b": "h2"}, lambda k: calls.append(k) or k.upper())
    assert inv.discard("a") is True and inv.discard("zz") is False and "a" not in inv
    inv.save()
    again = Inventory(tmp_path / "inv.json", "v1")
    again.refresh({"a": "h1", "b": "h2"}, lambda k: calls.append(k) or k.upper())
    assert calls == ["a", "b", "a"], "a discarded key is computed again, the other reused"


def test_the_profile_times_every_set_and_compares_pooled(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    pr = P.profile_attempt(rows / "day-07" / "binary-day-07-mastery", solver)
    assert pr.sets == 2 and pr.deliveries == 2 and pr.equal and set(pr.per_set) == {1, 2}
    assert pr.pooled is not None and len(pr.pooled.answers) == 3
    assert pr.heaviest[0] in (1, 2) and pr.heaviest[1] == max(pr.per_set.values())
    assert any("solve_set" in ln for ln in pr.top), "the profile names the solver's functions"
    r = _ctf(wd, "replay", str(rows / "day-07" / "binary-day-07-mastery"), "--solver", str(solver), "--profile",
             "--json")
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["equal"] and sorted(d["pooled"]["pooled"]) == [1, 2] and set(d["per_set"]) == {"1", "2"}


@pytest.mark.needs_realdata("adapt/day-24-binary-mastery")
def test_day_24_binary_mastery_profile(tmp_path, monkeypatch):
    """The one genuine solver miss (Day-24-shape Binary Mastery, about 11 s pooled): profile the saved
    attempt at <realdata>/adapt/day-24-binary-mastery with the binary lane's evidence solver. Pooled and
    serial answers must agree; the timings are printed for the operator (re-measure on a quiet box)."""
    folder = paths.realdata_root() / "adapt" / "day-24-binary-mastery"
    pr = P.profile_attempt(folder, paths.repo_root() / "solvers" / "binary" / "evidence.py")
    assert pr.sets >= 2 and pr.equal
    assert pr.pooled is not None and len(pr.pooled.answers) > 0
    print(f"day-24 binary mastery: {pr.sets} sets, serial {pr.serial_seconds:.2f}s, pooled {pr.pooled.seconds:.2f}s, "
          f"heaviest set {pr.heaviest}")


# --------------------------------------------------------------------------- the CLI

def _ctf(wd, *args, extra=None):
    e = {k: v for k, v in os.environ.items() if not k.startswith(("ADAPT_PROBE_", "B253_"))}
    e.update(CTF_WORKDIR=str(wd), CTF_GATE_STATE=str(wd.parent / "gs-cli"))
    e.pop("CTF_EVENT", None)
    e.update(extra or {})
    return subprocess.run([sys.executable, "-m", "ctf", "adapt", *args], cwd=str(AR.REPO), env=e,
                          capture_output=True, text=True, timeout=300)


def test_cli_quiet_attempt_and_chain(env, sleeper):
    root, wd = env
    r = _ctf(wd, "quiet", "--json")
    assert r.returncode == 0 and json.loads(r.stdout)["busy"] is False, r.stderr
    K.start("bin/mastery", deadline=time.time() + 600, workdir=wd, pid=sleeper())
    r = _ctf(wd, "quiet")
    assert r.returncode == 0 and r.stdout.startswith("BUSY") and "bin/mastery" in r.stdout
    C.mark_closed(BASE, by="hand", workdir=wd)
    key = R.current_lane_key("probe", root=root, workdir=wd)
    r = _ctf(wd, "attempt", TT, "--outcome", "not_submitted", "--lane-key", key, "--artifact-sha256", SHA_A,
             "--missing", "4")
    assert r.returncode == 0, r.stderr
    r = _ctf(wd, "chain", BASE, "--lane", "probe", "--root", str(root), "--guard", "hook",
             "--artifact-sha256", SHA_A)
    assert r.returncode == 1 and "same artifact" in r.stdout, r.stdout + r.stderr
    r = _ctf(wd, "chain", BASE, "--lane", "probe", "--root", str(root), "--guard", "hook", "--jobs", "2")
    assert r.returncode == 0 and r.stdout.startswith("RETRY"), r.stdout + r.stderr
    assert "2 at a time at nice 0" in r.stdout


def test_cli_replay_and_rows(tmp_path, monkeypatch):
    root, solver, rows, wd = _lane(tmp_path, monkeypatch)
    folder = rows / "day-07" / "binary-day-07-mastery"
    r = _ctf(wd, "replay", str(folder), "--solver", str(solver), "--json")
    assert r.returncode == 0, r.stderr
    assert sorted(json.loads(r.stdout)["pooled"]) == [1, 2]
    r = _ctf(wd, "replay", str(folder), "--solver", str(solver), "--stability")
    assert r.returncode == 0 and r.stdout.startswith("STABILITY STABLE"), r.stdout + r.stderr
    r = _ctf(wd, "rows", "lane", "--rows", str(rows), "--solver", str(solver), "--root", str(root), "--json")
    assert r.returncode == 0, r.stderr
    assert {x["status"] for x in json.loads(r.stdout)["rows"]} == {P.GREEN}
    r = _ctf(wd, "rows", "lane", "--rows", str(rows), "--solver", str(solver), "--root", str(root))
    assert r.returncode == 0 and "warm 2" in r.stdout
    r = _ctf(wd, "replay", str(tmp_path / "nothing"), "--solver", str(solver))
    assert r.returncode == 2 and "no attempt.json" in r.stderr
