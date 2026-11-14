"""SH-09: the flaky-list checks are load-independent, and still catch their defect.

Two things break a check under the suite's load (a load average of 50 to 170 on 14 cores):

  waiting      the process waits for a core, so wall clocks run while no work is done. Stand-in: a loaded
               wall clock (every look at time.monotonic / time.perf_counter finds 0.25 s more gone), or a
               jump of the wall clocks inside the measured call.
  slower core  under sustained all-core load this machine runs its cores at about half their top clock
               (measured: 2.0 to 2.2 GHz against 4.51 GHz), so the same work reads about twice the CPU
               seconds. Stand-in: the CPU clocks stretched 2.5x (sh09_drivers.slower_core).

Each fixed check is driven with its stand-in and must stay green; it is then driven with a stand-in for the
defect it guards (CPU time or core cycles charged to the measured path) and must turn red. No CPU burner is
started and the full suite is not run. tests/sh09_drivers.py drives the two script-style checks in a fresh
interpreter; the pytest modules are imported and their test functions called here.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import sh09_clocks as K  # noqa: E402
from sh09_drivers import loaded_wall_clock, slower_core  # noqa: E402


def _driver(tmp_path, scenario):
    corpus, work = tmp_path / "corpus", tmp_path / "work"
    corpus.mkdir()
    work.mkdir()
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "USER", "LOGNAME")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(REPO), CTF_TESTING="1", CTF_EVENT="csctf",
               CTF_REALDATA=str(corpus), CTF_WORKDIR=str(work), TMPDIR=str(tmp_path))
    p = subprocess.run([sys.executable, str(TESTS / "sh09_drivers.py"), scenario], cwd=str(tmp_path), env=env,
                       capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout.strip().splitlines()[-1])


@contextlib.contextmanager
def wall_jump_inside(module, name, seconds):
    """module.name, with the wall clocks jumping `seconds` at its first call (the process descheduled
    inside the measured call). Yields the jump so far (a one-item list)."""
    jump = [0.0]
    real_fn = getattr(module, name)
    mono, perf = time.monotonic, time.perf_counter

    def fn(*a, **k):
        if not jump[0]:
            jump[0] = seconds
        return real_fn(*a, **k)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(module, name, fn)
        mp.setattr(time, "monotonic", lambda: mono() + jump[0])
        mp.setattr(time, "perf_counter", lambda: perf() + jump[0])
        yield jump


@contextlib.contextmanager
def cpu_jump_inside(module, name, seconds, key=None):
    """module.name (or module[key] when key is given), with the CPU clocks jumping `seconds` at its first
    call (the call does that much more work)."""
    jump = [0.0]
    real_fn = getattr(module, name) if key is None else module[key]
    proc, thread = time.process_time, time.thread_time

    def fn(*a, **k):
        if not jump[0]:
            jump[0] = seconds
        return real_fn(*a, **k)
    with pytest.MonkeyPatch.context() as mp:
        if key is None:
            mp.setattr(module, name, fn)
        else:
            mp.setitem(module, key, fn)
        mp.setattr(time, "process_time", lambda: proc() + jump[0])
        mp.setattr(time, "thread_time", lambda: thread() + jump[0])
        yield jump


@contextlib.contextmanager
def cycles_charged_to(module, name, seconds):
    """module.name, with `seconds` of work at the top clock charged to the cycle counter at each call."""
    read_cycles, hz = K.meter()
    extra = [0]
    real_fn = getattr(module, name)

    def fn(*a, **k):
        extra[0] += int(seconds * hz)
        return real_fn(*a, **k)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(module, name, fn)
        mp.setitem(K._METER, "got", (lambda: read_cycles() + extra[0], hz))
        yield extra


# ---- the clocks themselves ---------------------------------------------------------------------------------

def test_cpu_clock_reads_process_time_and_restores_the_clocks():
    mono, perf, sleep = time.monotonic, time.perf_counter, time.sleep
    with pytest.raises(RuntimeError, match="inside"):
        with K.cpu_clock():
            assert time.monotonic is time.process_time and time.perf_counter is time.process_time
            raise RuntimeError("inside")
    assert time.monotonic is mono and time.perf_counter is perf and time.sleep is sleep


def test_cpu_clock_refuses_code_that_waits_instead_of_hanging():
    # A wait until a deadline read from time.monotonic never ends on the CPU clock (process time does not
    # advance while the process sleeps): inside cpu_clock it fails loudly at its first sleep.
    sleep = time.sleep
    with pytest.raises(K.CpuClockWait, match="code that waits must not run on the CPU clock"):
        with K.cpu_clock():
            deadline = time.monotonic() + 0.01
            for _ in range(20):                           # bounded here, so a missing guard is red, not a hang
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.005)
    assert time.sleep is sleep
    time.sleep(0)                                         # the real sleep is back


def test_thread_seconds_counts_work_not_waiting():
    _, slept = K.thread_seconds(time.sleep, 0.2)
    assert slept < 0.1

    def spin():
        t0 = time.thread_time()
        while time.thread_time() - t0 < 0.1:
            pass
    _, spun = K.thread_seconds(spin)
    assert spun >= 0.1


def test_work_seconds_counts_cycles_at_the_top_clock():
    K.not_run_without_meter()

    def spin(n):
        x = 0
        for i in range(n):
            x += i
        return x
    t0 = time.process_time()
    out, work = K.work_seconds(spin, 2_000_000)
    cpu = time.process_time() - t0
    assert out == sum(range(2_000_000))
    # A busy core runs well above 15% of its top clock (seen under load: 40% and more), so a top clock set
    # far too high reads less work than that.
    assert work >= 0.15 * cpu, (work, cpu)
    # No core runs above its top clock, so work at the top clock is never more than the CPU seconds: in 30
    # short slices (under load the cores run at 1.8 to 2.6 GHz, alone at up to the top clock), a top clock set
    # below the fastest the cores ran reads more work than CPU time in some slice.
    over = []
    for _ in range(30):
        t0 = time.process_time()
        _, w = K.work_seconds(spin, 200_000)
        c = time.process_time() - t0
        if w > c * 1.05 + 2e-4:
            over.append((round(w, 5), round(c, 5)))
    assert not over, over
    # Sleeping is no work, and the meter does not read the CPU clocks: a slower core changes nothing.
    _, slept = K.work_seconds(time.sleep, 0.2)
    assert slept < 0.05
    with slower_core(2.5):
        _, again = K.work_seconds(spin, 2_000_000)
    assert again < 2 * work + 0.05, (again, work)


def test_work_seconds_reports_a_missing_meter_before_running(monkeypatch):
    def missing():
        raise K.WorkMeterMissing("stand-in: no cycle counter")
    monkeypatch.setattr(K, "meter", missing)
    ran = []
    with pytest.raises(K.WorkMeterMissing, match="no cycle counter"):
        K.work_seconds(ran.append, 1)
    assert ran == []


def test_an_unlisted_chip_has_no_meter(monkeypatch):
    if sys.platform != "darwin":
        pytest.skip("not run: the chip lookup is macOS-only")
    monkeypatch.setattr(K, "TOP_CLOCK_HZ", {})
    monkeypatch.setattr(K, "_METER", {})
    with pytest.raises(K.WorkMeterMissing, match="no top clock is known for the chip"):
        K.meter()


# ---- wired esolang reads: test_wave15_esolang2 / test_wave4_esolang ::test_wired ---------------------------

@pytest.fixture(params=["test_wave15_esolang2", "test_wave4_esolang"])
def wired(request):
    W = __import__(request.param)
    state = W.rnd.getstate()
    memo = dict(W.C._READ_MEMO)
    yield W
    W.rnd.setstate(state)                                # later tests of that module see the slugs they saw
    W.C._READ_MEMO.clear()
    W.C._READ_MEMO.update(memo)


def test_wired_reads_ignore_a_loaded_wall_clock(wired):
    W = wired
    name = "shakespeare" if "shakespeare" in W.E.ENCODERS else "spoon"
    s = "zzzzz-zzzzz-zzzzz-00"
    blob = W.E.ENCODERS[name]((W.SENT + s).encode())
    with loaded_wall_clock() as looks:
        W.C._READ_MEMO.clear()
        assert W.solve(blob, budget=W.WIRED_BUDGET) == (None, None)    # on the wall clock: the SH-09 failure
        assert looks[0] > 0
        n = looks[0]
        W.C._READ_MEMO.clear()
        ans, chain = W.solve_wired(blob)                                   # what test_wired reads with
        assert ans == s and [name] in chain, (ans, chain)
        assert looks[0] == n                                               # it never read the loaded clocks
        W.test_wired()                                                     # the flaky test itself: green


def test_wired_reads_still_run_out_of_a_budget_on_the_cpu_clock(wired, monkeypatch):
    # Work over the budget still runs it out: every look at the CPU clock finds 10 s more.
    W = wired
    name = "shakespeare" if "shakespeare" in W.E.ENCODERS else "spoon"
    blob = W.E.ENCODERS[name]((W.SENT + "zzzzz-zzzzz-zzzzz-00").encode())
    proc, n = time.process_time, [0]

    def costly():
        n[0] += 1
        return proc() + n[0] * 10.0
    monkeypatch.setattr(time, "process_time", costly)
    W.C._READ_MEMO.clear()
    assert W.solve_wired(blob) == (None, None)
    assert n[0] > 0


# ---- the bounded refusals: test_wave15_esolang2::test_interp, test_esolang_more::test_refuse ---------------

@contextlib.contextmanager
def jump_in_read(owner, key, marker: bytes, clocks: str, seconds: float):
    """owner[key] (a dict) or owner.key (a module) wrapped so that the read of a program holding `marker`
    loses `seconds` on the named clocks ('wall': monotonic and perf_counter; 'cpu': process_time and
    thread_time) as it starts. Yields what a reader of those clocks saw that read take (a list)."""
    is_dict = isinstance(owner, dict)
    real = owner[key] if is_dict else getattr(owner, key)
    names = ("monotonic", "perf_counter") if clocks == "wall" else ("process_time", "thread_time")
    saved = {n: getattr(time, n) for n in names}
    jump, seen = [0.0], []

    def read(prog):
        raw = prog if isinstance(prog, bytes) else prog.encode()
        if marker not in raw:
            return real(prog)
        t0 = saved[names[0]]() + jump[0]
        jump[0] += seconds
        try:
            return real(prog)
        finally:
            seen.append(saved[names[0]]() + jump[0] - t0)
    with pytest.MonkeyPatch.context() as mp:
        (mp.setitem if is_dict else mp.setattr)(owner, key, read)
        for n in names:
            mp.setattr(time, n, (lambda f: lambda: f() + jump[0])(saved[n]))
        yield seen


def test_interp_spl_bound_ignores_a_wall_jump_and_fails_on_cpu():
    import test_wave15_esolang2 as W
    state = W.rnd.getstate()
    try:
        with jump_in_read(W.E, "d_shakespeare", b"Forever", "wall", 5.0) as seen:
            W.test_interp()                                  # green: 5 s of wall clock lost in the looping read
        assert len(seen) == 1 and seen[0] >= 5.0             # what the old wall-clock bound read: red
        W.rnd.setstate(state)
        with jump_in_read(W.E, "d_shakespeare", b"Forever", "cpu", 1.1) as seen:
            with pytest.raises(AssertionError, match="SPL non-halting goto"):
                W.test_interp()                              # the looping read does 1.1 s more work: red
        assert len(seen) == 1
    finally:
        W.rnd.setstate(state)


def test_refuse_bound_ignores_a_wall_jump_and_fails_on_cpu():
    import test_esolang_more as M
    nonhalt = b"While my counter is 1"
    with jump_in_read(M.E.BY_NAME, "rockstar", nonhalt, "wall", 5.0) as seen:
        M.test_refuse()                                      # green: 5 s of wall clock lost in the loop
    assert len(seen) == 1 and seen[0] >= 5.0                 # what the old wall-clock bound read: red
    with jump_in_read(M.E.BY_NAME, "rockstar", nonhalt, "cpu", 1.1) as seen:
        with pytest.raises(AssertionError, match="refuse: rockstar nonhalt"):
            M.test_refuse()                                  # the loop does 1.1 s more work: red
    assert len(seen) == 1


# ---- SH-08's own check: test_a_blob_after_one_that_spent_eslm_time_still_reads[rockstar] -------------------

@pytest.fixture
def sweep():
    import test_warmups_esolang_sweep as S
    C = S.C
    held = (C._ESLM_SPENT[0], C._ESLM_CUT[0], C.BUDGET)
    yield S
    C._ESLM_SPENT[0], C._ESLM_CUT[0], C.BUDGET = held
    C._READ_MEMO.clear()


@pytest.mark.parametrize("name", ["rockstar", "befunge98"])
def test_sh08_stale_eslm_check_ignores_a_loaded_wall_clock(sweep, name):
    import test_sh08_load_independence as T8
    blob = T8._other_slug(sweep, name)
    with loaded_wall_clock() as looks:
        sweep.C._READ_MEMO.clear()
        sweep.C._ESLM_SPENT[0] = sweep.C.ESLM_TIME * 10
        assert sweep.solve(blob)[0] is None                 # its old read (default budget, wall clock): the failure
        assert looks[0] > 0
        T8.test_a_blob_after_one_that_spent_eslm_time_still_reads(sweep, name)   # green
    # Its defect (no per-blob reset of the ESLM_TIME count, and the memo keeping a reading the cap cut) is an
    # engine edit, put back by hand: both parameters fail (docs/build-log/SH-09.md, mutation runs).


def test_sh08_stale_eslm_check_still_runs_out_of_its_budget_on_the_cpu_clock(sweep, monkeypatch):
    # The raised budget and the CPU clock do not make the read unbounded: every look at the CPU clock
    # finding 10 s more runs the budget out, and the check fails.
    import test_sh08_load_independence as T8
    proc, n = time.process_time, [0]

    def costly():
        n[0] += 1
        return proc() + n[0] * 10.0
    monkeypatch.setattr(time, "process_time", costly)
    sweep.C._READ_MEMO.clear()
    with pytest.raises(AssertionError):
        T8.test_a_blob_after_one_that_spent_eslm_time_still_reads(sweep, "rockstar")
    assert n[0] > 0


# ---- test_day23_warmups_edges::test_pipeline_the_flagged_surface[brotli] -----------------------------------

@pytest.mark.needs_tool("py:brotli")
def test_pipeline_brotli_bound_ignores_a_wall_jump_and_fails_on_cpu():
    import test_day23_warmups_edges as D
    with wall_jump_inside(D.C, "readings", 10.0) as jump:
        t0 = time.perf_counter()
        D.test_pipeline_the_flagged_surface("brotli")         # green: 10 s of wall clock lost in the search
        assert jump[0] == 10.0 and time.perf_counter() - t0 >= 10.0
    with cpu_jump_inside(D.C, "readings", 3.1):
        with pytest.raises(AssertionError, match="finishes within its budget"):
            D.test_pipeline_the_flagged_surface("brotli")     # the search does 3.1 s more work: red


# ---- test_carve_stego_deep_cost: the stg300-shaped scan inside solve_set's budget ---------------------------

def test_stg300_bound_ignores_a_slower_core_and_fails_on_work():
    K.not_run_without_meter()
    import test_carve_stego_deep_cost as T
    png = T._photo_png_with_red_lsb_text()
    _, idle_cpu = T._cpu(T.C.scan, "stg300.png", png, skipped=[])
    # at least the 2.5x stand-in, and more if the scan is cheap enough here that 2.5x stays under the bound
    with slower_core(max(2.5, 1.5 * T.C.BUDGET * 0.8 / max(idle_cpu, 1e-3))):
        _, cpu = T._cpu(T.C.scan, "stg300.png", png, skipped=[])
        assert cpu > T.C.BUDGET * 0.8, cpu                  # the old CPU-time check: red on the slower core
        T.test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget()   # green
    with cycles_charged_to(T.C, "lsb_deep_scan", 0.5):      # the deep readings cost 0.5 s more work
        with pytest.raises(AssertionError, match=r"^scan took .* s of work, of solve_set's"):
            T.test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget()


def test_stg300_solve_set_bound_fails_on_work_of_its_own():
    # The set's reading costs 0.5 s more work than the scan alone (charged at solve_set's own call, which the
    # scan does not make): the scan bound holds and the solve_set bound alone turns the test red.
    K.not_run_without_meter()
    import test_carve_stego_deep_cost as T
    with cycles_charged_to(T.C, "solve_set", 0.5) as extra:
        with pytest.raises(AssertionError, match=r"^solve_set took .* s of work, of its"):
            T.test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget()
        assert extra[0] > 0


def _no_meter(monkeypatch):
    def missing():
        raise K.WorkMeterMissing("stand-in: no cycle counter")
    monkeypatch.setattr(K, "meter", missing)


def _red_not_skipped(test, match=None):
    """test() must fail an answer check. A skip (the cost bound reported not run before the answer checks)
    is a failure of this proof, never a skip of it."""
    try:
        test()
    except AssertionError as e:
        if match is not None:
            assert match in str(e), str(e)[:500]
        return
    except pytest.skip.Exception as e:
        pytest.fail(f"skipped before its answer checks ran: {e}")
    pytest.fail("a wrong answer passed")


def test_stg300_without_a_meter_checks_the_answer_and_reports_only_the_cost_not_run(monkeypatch):
    import test_carve_stego_deep_cost as T
    _no_meter(monkeypatch)
    with pytest.raises(pytest.skip.Exception, match="not run: the cost bound has no work meter .*no cycle counter"):
        T.test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget()
    # the answer checks ran before that: a wrong answer is red, not skipped
    monkeypatch.setattr(T.C, "solve_set", lambda *a, **k: {"f": "0" * 32})
    _red_not_skipped(T.test_the_stg300_shape_is_answered_by_its_pattern_inside_the_budget)


# ---- test_day31_binary_hgrf (run by test_carry_checklist): the 31-member pool --------------------------------

def test_hgrf_pool_bound_ignores_a_slower_core_and_fails_on_work():
    K.not_run_without_meter()
    import test_day31_binary_hgrf as H
    with slower_core(2.5), wall_jump_inside(H.evidence, "solve_set", 10.0) as jump:
        H.test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses()   # green
        assert jump[0] == 10.0
    with cycles_charged_to(H.evidence, "solve_set", 1.1) as extra:
        with pytest.raises(AssertionError, match="s of work"):
            H.test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses()
        assert extra[0] > 0


def test_hgrf_pool_without_a_meter_checks_the_answers_and_reports_only_the_cost_not_run(monkeypatch):
    import test_day31_binary_hgrf as H
    _no_meter(monkeypatch)
    with pytest.raises(pytest.skip.Exception, match="not run: the cost bound has no work meter .*no cycle counter"):
        H.test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses()
    # the candidate-only and refusal checks ran before that: a pool solve that answers nothing is red
    real_solve = H.solve
    monkeypatch.setattr(H, "solve", lambda qs, blobs: {})
    _red_not_skipped(H.test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses)

    def answers_33(qs, blobs):                            # the 31-member pool right, the 33-member one answered
        if any("all 33 canonical" in q["question"] for q in qs):
            return {q["qid"]: "answered" for q in qs}
        return real_solve(qs, blobs)
    monkeypatch.setattr(H, "solve", answers_33)
    _red_not_skipped(H.test_finale_31_member_pool_is_fast_candidate_only_and_33_refuses, match="answered")


# ---- tests/real/test_real_carve_stego.py: the per-set cost limit (child driver) -----------------------------

def test_real_carve_limit_is_work_not_cpu(tmp_path):
    K.not_run_without_meter()
    d = _driver(tmp_path, "real_carve")
    lines, got, skipped = d["base"]
    assert got == {"f": "4E34B38257200616FB75CD869B8C3CF0"} and skipped is None
    assert [ln[:4] for ln in lines] == ["ok  "], lines
    lines, _, _ = d["slow_old"]
    assert [ln[:4] for ln in lines] == ["FAIL"], lines           # CPU time on a slower core: the SH-09 failure
    assert "s CPU (limit 1 s)" in lines[0] and d["slow_factor"] >= 2.5, (lines, d["slow_factor"])
    lines, got, _ = d["slow_new"]
    assert [ln[:4] for ln in lines] == ["ok  "] and got, lines   # work at the top clock: green
    # SH-11: the shared group-c helper (realdata_c.timed) measures work too, so the same slower core that
    # fails the CPU-seconds check leaves it green, with the same answer
    lines, got, skipped = d["slow_shared"]
    assert [ln[:4] for ln in lines] == ["ok  "] and "s of work (limit 1 s)" in lines[0], lines
    assert got == {"f": "4E34B38257200616FB75CD869B8C3CF0"} and skipped is None, (got, skipped)
    lines, _, _ = d["costly"]
    assert [ln[:4] for ln in lines] == ["FAIL"] and "s of work (limit 1 s)" in lines[0], lines
    lines, got, skipped = d["no_meter"]
    # without a meter the reading still runs and is answered; the cost limit alone is a SKIP line
    assert got == {"f": "4E34B38257200616FB75CD869B8C3CF0"} and skipped is None, (got, skipped)
    assert len(lines) == 1 and lines[0].startswith("SKIP solve_set on stg300.png: cost limit 1 s not checked"), lines
    assert "no work meter (stand-in: no cycle counter)" in lines[0], lines
    # and the real-data runner's verdict names that cause, not a missing corpus file
    import importlib.util
    spec = importlib.util.spec_from_file_location("sh09_real_conftest", TESTS / "real" / "conftest.py")
    RC = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = RC
    spec.loader.exec_module(RC)
    v = RC.verdict(RC.Script(kits=("carve_stego",)), "realdata", 0, "ok   a\n" + lines[0] + "\n")
    assert len(v["problems"]) == 1 and "SKIPped" in v["problems"][0], v
    assert "no work meter" in v["problems"][0] and "missing or differs" not in v["problems"][0], v


# ---- tests/test_tk_day27_dlog.py (run by test_carry_checklist): the R10 control on the CPU clock -----------

def test_dlog_script_runs_on_the_cpu_clock(tmp_path):
    d = _driver(tmp_path, "dlog")
    assert d["unloaded"] is True                                  # the control holds on an idle machine
    assert d["loaded_direct"] is False and d["loaded_direct_looks"] > 0   # wall clock under load: the failure
    assert d["loaded_run"] is True and d["loaded_run_looks"] == 0          # the script's run(): green
    assert d["restored"] is True
    assert d["costly_run"] is False and d["costly_looks"] > 0     # work over the budget still runs it out


R29_OVERRUN = ("R29 a discrete-log solve that overruns by 0.6 s on every call, in three question orders: every answer the "
               "older readers give is in the return value and in ctx['partial'] unchanged")
R29_DID_OVERRUN = "R29 ... and every one of those solves did overrun"


def test_dlog_r29_overrun_is_an_overrun_on_the_cpu_clock(tmp_path):
    """Round 2: run() puts the script on the CPU clock, where time.sleep raises. R29's slow solve used to sleep, so
    its overrun became an exception the toolkit catches and the pass never ran over. The overrun is now work."""
    import gmpy2  # noqa: F401  (a pinned requirement; R29 runs only with it, so its absence must fail here, not skip)
    d = _driver(tmp_path, "dlog_r29")
    assert d["work"] == [], d                                     # the toolkit as it is: every R29 check holds
    assert R29_OVERRUN in d["work_mutant"], d                     # a pass that gives up the set on an overrun: red
    # the overrun as it was before round 2 (time.sleep on the CPU clock): the solve raises, nothing overruns, the
    # mutant goes unseen by the overrun check, and the new check that the solves overran is what turns red
    assert R29_OVERRUN not in d["sleep_mutant"], d
    assert any(label.startswith(R29_DID_OVERRUN) for label in d["sleep_mutant"]), d
    assert any(label.startswith(R29_DID_OVERRUN) for label in d["sleep"]), d
