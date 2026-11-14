"""SH-08: the checks that failed only under full-suite load are load-independent, and still catch their defect.

Each fixed check is driven here with a deterministic stand-in for load (a wall-only delay: a sleep, or a jump
of the wall clocks the old check read) and with a stand-in for the defect it guards (CPU work, or CPU time
charged to the measured path, or a shrunk budget). The first must leave the check green, the second must
turn it red. No CPU burner is started and the full suite is not run: the stand-ins are injected into the
measured path only. docs/build-log/SH-08.md has the real-defect reintroductions that are too slow to keep
in the suite (every pair of 1,500 look-alike labels compared, the HNP lattice over its budget).

The two carried child-process checks (solvers/script-analysis/test_wavec2_deflate.py, run by
tests/test_saved_sections.py, and tests/real/test_review_a.py) are driven by tests/sh08_drivers.py in a
fresh interpreter; the others are pytest modules of this suite, imported and called here.
"""
from __future__ import annotations

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

from sh09_clocks import cpu_clock  # noqa: E402


def _sink_new(module, run):
    """The labels `run()` added to module.FAILED, with the list put back as it was (no state left over)."""
    n = len(module.FAILED)
    try:
        run()
        return list(module.FAILED[n:])
    finally:
        del module.FAILED[n:]


def _driver(tmp_path, scenario):
    corpus, work = tmp_path / "corpus", tmp_path / "work"
    corpus.mkdir()
    work.mkdir()
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "USER", "LOGNAME")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(REPO), CTF_TESTING="1", CTF_EVENT="huntress",
               CTF_REALDATA=str(corpus), CTF_WORKDIR=str(work), TMPDIR=str(tmp_path))
    p = subprocess.run([sys.executable, str(TESTS / "sh08_drivers.py"), scenario], cwd=str(tmp_path), env=env,
                       capture_output=True, text=True, timeout=240)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout.strip().splitlines()[-1])


# ---- test_wavec2_deflate: row 92's cost on random 100 KB blobs -------------------------------------------

def test_wavec2_row92_cost_ignores_a_wall_delay_and_counts_row92_work(tmp_path):
    d = _driver(tmp_path, "wavec2")
    limit = d["limit"]
    assert d["none_is_a_plan"]
    base, gave = d["base"]
    assert not gave and 0 < base <= limit, d
    # Load: 1 s of wall time lost inside row 92. The old measure read it as cost (the SH-08 failure);
    # the new one, in thread CPU time, does not.
    assert d["sleep_old_measure"] > limit, d
    assert d["sleep"][0] <= limit and not d["sleep"][1], d
    # The defect: 0.08 s more work inside row 92 fails the bound.
    assert d["busy"][0] > limit and d["busy"][0] >= 0.08, d
    # The premise is checked: a row-92 entry that gives a stream is reported.
    assert d["gives"][1] is True


# ---- test_review_a: the look-alike read of a mail with 1,500 domains --------------------------------------

def test_review_a_lookalike_bound_ignores_wall_time_and_counts_cpu(tmp_path):
    d = _driver(tmp_path, "review_a")
    oks, lines = d["wall_jump"]
    assert oks == ["ok"], lines                       # 10 s of wall clock inside the read: still green
    assert d["wall_jump_seen_by_monotonic"]          # ... and the jump was real for a wall-clock reader
    oks, lines = d["cpu_jump"]
    assert oks[:1] == ["FAIL"], lines                 # 2.1 s more CPU in the read: red


# ---- test_wave124: the GCM and HNP checks ----------------------------------------------------------------

@pytest.fixture
def w124():
    import test_wave124_crypto_gcm_ecdsa as W
    state = W.RND.getstate()
    yield W
    W.RND.setstate(state)                             # its fixtures come from this seeded generator


def test_wave124_cpu_seconds_counts_work_not_waiting(w124):
    _, slept = w124.cpu_seconds(time.sleep, 0.2)
    assert slept < 0.1

    def spin():
        t0 = time.process_time()
        while time.process_time() - t0 < 0.15:
            pass
    _, spun = w124.cpu_seconds(spin)
    assert spun >= 0.15


def test_wave124_forbidden_attack_ignores_a_wall_jump_and_fails_on_cpu(w124, monkeypatch):
    real = w124.cd.gcm_recover_subkey
    jump = [0.0]
    mono, perf, cpu = time.monotonic, time.perf_counter, time.process_time

    calls = [0]

    def recover(pairs, *a, **k):
        calls[0] += 1
        if calls[0] == 1:                              # the first call is the timed one
            jump[0] += 10.0
        return real(pairs, *a, **k)

    monkeypatch.setattr(w124.cd, "gcm_recover_subkey", recover)
    with monkeypatch.context() as mp:                  # load: the wall clocks jump 10 s in the timed call
        mp.setattr(time, "monotonic", lambda: mono() + jump[0])
        mp.setattr(time, "perf_counter", lambda: perf() + jump[0])
        failed = _sink_new(w124, w124.test_forbidden_attack)
    assert jump[0] == 10.0 and not failed, failed
    jump[0], calls[0] = 0.0, 0
    with monkeypatch.context() as mp:                  # the defect: the timed call costs 10 s more CPU
        mp.setattr(time, "process_time", lambda: cpu() + jump[0])
        failed = _sink_new(w124, w124.test_forbidden_attack)
    assert failed == ["forbidden attack: 3 pairs pin a unique H that reproduces every tag, in under 3 s of CPU"]


def test_wave124_toolkit_hnp_budget_is_cpu_time(w124, monkeypatch):
    tk, cd = w124.tk, w124.cd
    real_lll = cd.lll
    jump = [0.0]
    mono, perf = time.monotonic, time.perf_counter

    def lll(*a, **k):                                  # load: 10 s of wall clock pass inside the lattice
        jump[0] += 10.0
        return real_lll(*a, **k)

    monkeypatch.setattr(cd, "lll", lll)
    monkeypatch.setattr(time, "monotonic", lambda: mono() + jump[0])
    monkeypatch.setattr(time, "perf_counter", lambda: perf() + jump[0])
    curve = "secp256k1"
    cv = cd.CURVES[curve]
    d = w124.RND.randrange(1, cv["n"])
    Q = cd.ec_mul(d, cv)
    rs, ss, zs = w124._hnp_sigs(curve, d, 128, 8)
    files = {"sigs.json": json.dumps({"curve": curve, "x": str(Q[0]), "y": str(Q[1]), "r": rs, "s": ss, "z": zs}).encode()}
    question = w124.q("The ECDSA nonces are biased: only 128 bits each (secp256k1). Recover the private key d.",
                      "hnp-d", kind="integer")
    # On the wall clocks (as before SH-08) the jump runs HNP_BUDGET out and the answer is None: the failure.
    assert tk.solve_set([question], files, {})[question["qid"]] is None
    # On the CPU clock the module's solve() uses, the same jump costs nothing: d is answered.
    assert w124.solve(question, files) == str(d)
    assert jump[0] >= 20.0
    # The defect the budget guards (the lattice is too slow for it) still fails test_toolkit_hnp's checks.
    monkeypatch.setattr(tk, "HNP_BUDGET", 0.0)
    monkeypatch.setattr(tk, "BUDGET", 1e-6)
    failed = _sink_new(w124, w124.test_toolkit_hnp)
    assert any("the private scalar d is PLAIN once d*G==Q is proven" in f for f in failed), failed


def test_wave124_cpu_clock_restores_the_wall_clocks(w124):
    mono, perf = time.monotonic, time.perf_counter
    with pytest.raises(RuntimeError):
        with w124.cpu_clock():
            assert time.monotonic is time.process_time and time.perf_counter is time.process_time
            raise RuntimeError("inside")
    assert time.monotonic is mono and time.perf_counter is perf


# ---- test_day21fp_mobile: the 5 ms answering bounds -------------------------------------------------------

@pytest.fixture
def d21():
    import test_day21fp_mobile as D21
    yield D21
    D21.T.reset_results()                             # leave its check ledger empty


def _solve_set_with(d21, monkeypatch, before):
    real = d21.C.solve_set

    def solve_set(*a, **k):
        before()
        return real(*a, **k)
    monkeypatch.setattr(d21.C, "solve_set", solve_set)


def test_day21fp_bounds_ignore_a_wall_delay(d21, monkeypatch):
    _solve_set_with(d21, monkeypatch, lambda: time.sleep(0.008))     # each solve loses 8 ms of wall time
    for part in (d21.dotnet_axml, d21.timing):
        d21.T.run_part(part)                                         # raises on a failed check
        assert d21.T.PASSED and not d21.T.FAILED, d21.T.FAILED


def test_day21fp_bounds_fail_on_cpu_work(d21, monkeypatch):
    def spin():
        t0 = time.thread_time()
        while time.thread_time() - t0 < 0.011:
            pass
    _solve_set_with(d21, monkeypatch, spin)                         # each solve does 11 ms more work
    with pytest.raises(AssertionError, match=r"answered in under 5 ms of CPU"):
        d21.T.run_part(d21.dotnet_axml)
    with pytest.raises(AssertionError):                            # its one check failed: "ran no checks"
        d21.T.run_part(d21.timing)
    assert [f for f in d21.T.FAILED if "a judged document that names nothing" in f], d21.T.FAILED


# ---- test_warmups_esolang_sweep: Rockstar / Befunge-98 reads and the crib_decode state they share --------

@pytest.fixture
def sweep():
    import test_warmups_esolang_sweep as S
    C = S.C
    held = (C._ESLM_SPENT[0], C._ESLM_CUT[0], C.BUDGET)
    yield S
    C._ESLM_SPENT[0], C._ESLM_CUT[0], C.BUDGET = held


def _other_slug(S, name) -> bytes:
    """A program of `name` that prints the crib and a slug no other test uses."""
    out = S.esolang_more.ENCODERS[name]((S.C.CRIB + "zzzzz-zzzzz-zzzzz-00").encode())
    return out.encode() if isinstance(out, str) else out


def solve_unloaded(sweep, blob):
    """sweep.solve(blob) with the reads this test needs to give a slug out of load's reach (SH-09): the
    per-blob budget raised to CORRECT_BUDGET (as the sweep's own positive reads, SH-08), and every budget and
    cap the engine keeps (the blob's, the flag hunt's, ESLM_TIME) counted on the CPU clock. On the default
    0.35 s of wall clock a full-suite run cut this 10 KB Rockstar read to None; ESLM_TIME (0.12 s of wall
    clock for a read of about 10 ms of CPU) can cut it as well."""
    with pytest.MonkeyPatch.context() as mp, cpu_clock():
        mp.setattr(sweep.C, "BUDGET", sweep.CORRECT_BUDGET)
        return sweep.solve(blob)


@pytest.mark.parametrize("name", ["rockstar", "befunge98"])
def test_a_blob_after_one_that_spent_eslm_time_still_reads(sweep, name):
    # Order dependence: the previous blob's last settle left ESLM_TIME spent; the next blob's flag hunt ran on
    # it, read no Rockstar / Befunge-98, and its reading was kept for the rest of the process.
    C = sweep.C
    blob = _other_slug(sweep, name)
    C._READ_MEMO.clear()
    C._ESLM_SPENT[0] = C.ESLM_TIME * 10
    assert solve_unloaded(sweep, blob)[0] == "zzzzz-zzzzz-zzzzz-00"
    assert solve_unloaded(sweep, blob)[0] == "zzzzz-zzzzz-zzzzz-00"   # the memo did not keep a cut reading


def test_each_blob_starts_with_a_fresh_eslm_count(sweep, monkeypatch):
    # The flag hunt is the first reading of a blob, before any _settle resets the count: it must not run
    # on what the previous blob left.
    C = sweep.C
    real, seen = C._flag_hunt, []

    def hunt(*a, **k):
        seen.append(C._ESLM_SPENT[0])
        return real(*a, **k)
    monkeypatch.setattr(C, "_flag_hunt", hunt)
    C._ESLM_SPENT[0] = C.ESLM_TIME * 10
    sweep.chain(_other_slug(sweep, "rockstar"))
    assert seen == [0.0]


def test_a_reading_cut_by_eslm_time_is_not_kept(sweep):
    C = sweep.C
    payload = _other_slug(sweep, "rockstar")
    want = C.CRIB + "zzzzz-zzzzz-zzzzz-00"
    C._READ_MEMO.pop(payload, None)
    C._ESLM_SPENT[0] = C.ESLM_TIME * 10                             # the cap ran out earlier in this settle
    cut = C.readings(payload, time.perf_counter() + 30)
    assert not any(want in t for t in cut) and payload not in C._READ_MEMO
    C._ESLM_SPENT[0] = 0.0
    whole = C.readings(payload, time.perf_counter() + 30)
    assert any(want in t for t in whole) and payload in C._READ_MEMO
    C._READ_MEMO.pop(payload, None)


def test_eslm_cut_is_raised_only_for_a_payload_the_signature_takes(sweep):
    C = sweep.C
    C._ESLM_SPENT[0], C._ESLM_CUT[0] = C.ESLM_TIME * 10, False
    assert C._eslm_run("rockstar", b"plain words with no program in them at all") is None
    assert C._ESLM_CUT[0] is False
    assert C._eslm_run("rockstar", _other_slug(sweep, "rockstar")) is None
    assert C._ESLM_CUT[0] is True


def test_rockstar_read_survives_a_wall_delay_on_the_correctness_budget(sweep, monkeypatch):
    # Load: the Rockstar reader loses 0.4 s of wall time (more than the default per-blob crib share).
    C = sweep.C
    real = C.ESLM.step_fn

    def step_fn(name):
        f = real(name)

        def slow(b):
            time.sleep(0.4)
            return f(b)
        return slow
    monkeypatch.setattr(C.ESLM, "step_fn", step_fn)
    blob = _other_slug(sweep, "rockstar")
    C._READ_MEMO.clear()
    assert sweep.solve(blob)[0] is None                            # default budget: the SH-08 failure
    C._READ_MEMO.clear()
    with monkeypatch.context() as mp:                              # what the fixed test runs it on
        mp.setattr(C, "BUDGET", sweep.CORRECT_BUDGET)
        assert sweep.solve(blob)[0] == "zzzzz-zzzzz-zzzzz-00"
    C._READ_MEMO.clear()


def test_sweep_ook_rockstar_befunge98_test_survives_a_wall_delay(sweep, monkeypatch):
    # The flaky test itself, with every Rockstar and Befunge-98 read losing 0.4 s of wall time: its reads
    # that must give a slug run on the correctness budget, its cost bound is CPU time, so it stays green.
    C = sweep.C
    real, slowed = C.ESLM.step_fn, []

    def step_fn(name):
        f = real(name)

        def slow(b):
            slowed.append(name)
            time.sleep(0.4)
            return f(b)
        return slow
    monkeypatch.setattr(C.ESLM, "step_fn", step_fn)
    C._READ_MEMO.clear()
    with monkeypatch.context() as mp:
        sweep.test_ook_forms_row_546_then_rockstar_and_befunge98_row_547(mp)     # raises on a failed check
    C._READ_MEMO.clear()
    assert {"rockstar", "befunge98"} <= set(slowed), slowed     # the delay was in the reads it checks


def test_chain_passes_the_raised_budget_to_solve_blob(sweep, monkeypatch):
    seen = []
    monkeypatch.setattr(sweep.C, "solve_blob", lambda data, **k: seen.append(k) or None)
    sweep.chain(b"x")
    sweep.chain(b"x", sweep.CORRECT_BUDGET)
    assert seen == [{}, {"budget": sweep.CORRECT_BUDGET}]
