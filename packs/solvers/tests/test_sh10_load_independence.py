"""SH-10: the crypto, web and real-data checks on the flaky list are load-independent, and still catch their defect.

The SH-08 method (docs/build-log/SH-08.md): each fixed check is driven with a deterministic stand-in for load (a
jump of the wall clocks the old check read, a wall-only delay at a fake server, or a step of the injected clock)
and must stay green; it is then driven with the defect put back (the old clock, a shrunk budget, CPU time
charged to the measured path) and must turn red. No CPU burner is started and the full suite is not run.

The tests/real scripts are driven by tests/sh10_drivers.py in a fresh interpreter (their bare module names clash
with this suite's); the pytest modules are imported and their own test functions or helpers called here.
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

import loadclock  # noqa: E402


def _sink_new(module, run, name="FAILED"):
    """The labels `run()` added to module.<name>, with the list put back as it was (no state left over)."""
    sink = getattr(module, name)
    n = len(sink)
    try:
        run()
        return list(sink[n:])
    finally:
        del sink[n:]


@contextlib.contextmanager
def jumping_wall(monkeypatch, box):
    """time.monotonic and time.perf_counter read the real clock plus box[0]: a stand-in for a process
    that loses box[0] seconds of wall time while it waits for a core."""
    mono, perf = time.monotonic, time.perf_counter
    with monkeypatch.context() as mp:
        mp.setattr(time, "monotonic", lambda: mono() + box[0])
        mp.setattr(time, "perf_counter", lambda: perf() + box[0])
        yield


def _bump(box, seconds, real):
    def f(*a, **k):
        box[0] += seconds
        return real(*a, **k)
    return f


def _driver(tmp_path, scenario, corpus=None):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    if corpus is None:                               # a stand-in corpus: the scripts' folder() checks only
        corpus = tmp_path / "corpus"
        (corpus / "windows").mkdir(parents=True, exist_ok=True)
        (corpus / "windows" / "placeholder").write_bytes(b"x")
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "USER", "LOGNAME")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(REPO), CTF_TESTING="1", CTF_EVENT="huntress",
               CTF_REALDATA=str(corpus), CTF_WORKDIR=str(work), TMPDIR=str(tmp_path))
    p = subprocess.run([sys.executable, str(TESTS / "sh10_drivers.py"), scenario], cwd=str(tmp_path), env=env,
                       capture_output=True, text=True, timeout=280)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout.strip().splitlines()[-1])


# ---- tests/loadclock.py ---------------------------------------------------------------------------------

def test_cpu_clock_counts_work_and_restores_the_wall_clocks():
    mono, perf = time.monotonic, time.perf_counter
    with loadclock.cpu_clock():
        assert time.monotonic is time.process_time and time.perf_counter is time.process_time
        t0 = time.monotonic()
        time.sleep(0.2)
        assert time.monotonic() - t0 < 0.1          # waiting is not work
    assert (time.monotonic, time.perf_counter) == (mono, perf)
    with pytest.raises(RuntimeError):
        with loadclock.cpu_clock():
            raise RuntimeError("inside")
    assert (time.monotonic, time.perf_counter) == (mono, perf)


def _spin(seconds):
    t0 = time.thread_time()
    while time.thread_time() - t0 < seconds:
        pass
    return seconds


def test_cpu_and_thread_seconds_count_work_not_waiting():
    assert loadclock.cpu_seconds(time.sleep, 0.2)[1] < 0.1
    assert loadclock.thread_seconds(time.sleep, 0.2)[1] < 0.1
    assert loadclock.cpu_seconds(_spin, 0.15)[1] >= 0.15
    assert loadclock.thread_seconds(_spin, 0.15)[1] >= 0.15


def _pool_spin(n, seconds):
    """n workers spinning `seconds` each, through psearch.parallel_map: the pool the enigma break uses, so
    this test adds no start method of its own. Should parallel_map fall back to a serial map, the spin is
    counted as the parent's CPU and the 2-worker bound below fails."""
    if str(REPO / "solvers" / "common") not in sys.path:
        sys.path.append(str(REPO / "solvers" / "common"))
    import psearch
    assert psearch.parallel_map(_spin, [seconds] * n, workers=n) == [seconds] * n


def test_pool_seconds_spreads_the_reaped_workers_cpu_over_the_workers():
    _, two = loadclock.pool_seconds(_pool_spin, 2, 2, 0.3)       # 0.6 s of worker CPU on 2 workers
    assert 0.3 <= two < 0.6, two
    _, one = loadclock.pool_seconds(_pool_spin, 1, 2, 0.3)       # the same work counted for one core
    assert one >= 0.6, one
    assert loadclock.pool_seconds(time.sleep, 4, 0.2)[1] < 0.1  # a wait is no work
    with pytest.raises(ValueError):
        loadclock.pool_seconds(time.sleep, 0, 0)


# ---- test_day26_crypto_depth::test_keyless_xor ----------------------------------------------------------

@pytest.fixture
def depth():
    import test_day26_crypto_depth as T
    return T


def _offered(got):
    return isinstance(got, str) and got.startswith("??") and "Terminator" in got


def test_keyless_xor_key_survives_a_wall_jump_in_the_break(depth, monkeypatch):
    T = depth
    Q = T.q("The file is repeating-key XOR encrypted. What is the XOR key?")
    files = {"c.bin": T.rx(T.ENG * 2, b"Terminator")}
    box = [0.0]
    monkeypatch.setattr(T.tk, "_rank_keylengths", _bump(box, 10.0, T.tk._rank_keylengths))
    with jumping_wall(monkeypatch, box):
        old = T.tk.solve_set([Q], files, {})[Q["qid"]]        # the old run, on the wall clock: the SH-10 failure
        new = T.solve(Q, files)                                # the test's solve(): the budget counts CPU
    assert not _offered(old), old
    assert _offered(new), new


def test_keyless_xor_check_fails_when_the_budget_runs_out(depth, monkeypatch):
    T = depth
    state = T.RND.getstate()
    monkeypatch.setattr(T.tk, "BUDGET", 1e-6)               # the budget is spent before the break starts
    try:
        failed = _sink_new(T, T.test_keyless_xor)
    finally:
        T.RND.setstate(state)
    assert failed == ["keyless repeating-XOR on English: the key is offered, never plain"], failed


# ---- test_day26_binary_vigenere::test_lengths ----------------------------------------------------------

@pytest.fixture
def vig():
    import test_day26_binary_vigenere as T
    return T


def _vig_case(T, L):
    import random
    rng = random.Random(1300 + L)
    plain = T.cfg(rng, 12)
    key = bytes(rng.randrange(256) for _ in range(L))
    return plain, T.blob(plain, key)


# B-246: a key of up to 13 bytes is now fixed whole by the OPENING crib (one CRC-32 a length, outside the budget),
# so the budgeted column search, and these budget checks, start at 14 bytes.
@pytest.mark.parametrize("L", [14, 16])
def test_vigenere_read_survives_a_wall_jump_in_the_search(vig, monkeypatch, L):
    T = vig
    plain, data = _vig_case(T, L)
    box = [0.0]
    monkeypatch.setattr(T.hcfg, "_icm", _bump(box, 10.0, T.hcfg._icm))
    with jumping_wall(monkeypatch, box):
        T.hcfg._LONG_STATE.update(spent=0.0, last=0.0, headers=0)
        T.hcfg._LONG_MEMO.clear()
        old = T.hcfg.containers(b"\x00" * 7 + data + b"\x00" * 5, others=True)   # wall clock: cut, []
        T.hcfg._LONG_MEMO.clear()
        new = T.read(data)                                                          # the test's read()
    assert old == [], old
    assert len(new) == 1 and new[0]["plain"] == plain


def test_vigenere_read_finds_nothing_when_the_budget_is_spent(vig, monkeypatch):
    T = vig
    plain, data = _vig_case(T, 14)
    T.hcfg._LONG_MEMO.clear()
    monkeypatch.setattr(T.hcfg, "LONG_TIME", 0.0)
    assert T.read(data) == []
    T.hcfg._LONG_MEMO.clear()
    monkeypatch.setattr(T.hcfg, "LONG_TIME", 0.3)
    assert [g["plain"] for g in T.read(data)] == [plain]


# ---- test_day26_rsa_lattice::test_roca -----------------------------------------------------------------

@pytest.fixture
def lattice():
    import test_day26_rsa_lattice as T
    state = T.RND.getstate()
    yield T
    T.RND.setstate(state)


def _toy_moduli(T, monkeypatch):
    """The moduli test_roca hands to the toy ROCA search (roca_factor with n_primes=12), its answers
    stubbed to None so the search is not run (its checks then fail into the sink, which is put back)."""
    seen = []

    def factor(n, *a, **k):
        if k.get("n_primes") == 12:
            seen.append(n)
        return None
    monkeypatch.setattr(T.R, "roca_factor", factor)
    _sink_new(T, T.test_roca)
    return seen


def test_roca_toy_key_does_not_depend_on_what_drew_from_rnd_before(lattice, monkeypatch):
    T = lattice
    first = _toy_moduli(T, monkeypatch)
    T.RND.random()                                           # another test drew once more before this one
    second = _toy_moduli(T, monkeypatch)
    assert first[0] == second[0]                             # the toy key: the same, at the same search step
    assert first[1] != second[1]                             # (the safe modulus still comes from RND)
    M12 = 1
    for pr in T.R._PRIMES[:12]:
        M12 *= pr
    import random
    rnd = random.Random(2026)
    p = T.roca_prime_at(M12, 64, T.TOY_STEP_P, rnd)
    assert first[0] % p == 0 and p % M12 == pow(65537, T.TOY_STEP_P, M12)


def test_roca_toy_search_survives_a_wall_jump_and_the_old_clock_does_not(lattice, monkeypatch):
    T = lattice
    M12 = 1
    for pr in T.R._PRIMES[:12]:
        M12 *= pr
    import random
    rnd = random.Random(2026)
    p, q = T.roca_prime_at(M12, 64, T.TOY_STEP_P, rnd), T.roca_prime_at(M12, 64, T.TOY_STEP_Q, rnd)
    box = [0.0]
    monkeypatch.setattr(T.R, "coppersmith_roots", _bump(box, 200.0, T.R.coppersmith_roots))
    with jumping_wall(monkeypatch, box):
        old = T.R.roca_factor(p * q, check=False, n_primes=12, deadline=T.dl(120))     # wall: out at step 2
        with loadclock.cpu_clock():
            new = T.R.roca_factor(p * q, check=False, n_primes=12, deadline=T.dl(120))
    assert old is None
    assert new == tuple(sorted((p, q)))


# ---- test_fast_enigma::test_fast_enigma_with_plugboard -------------------------------------------------

@pytest.fixture
def enigma():
    import test_fast_enigma as T
    return T


def test_enigma_bound_ignores_a_wall_jump_and_fails_on_work(enigma, monkeypatch):
    T = enigma
    box = [0.0]
    monkeypatch.setattr(T.psearch, "parallel_map", _bump(box, 60.0, T.psearch.parallel_map))
    with jumping_wall(monkeypatch, box):
        t0 = time.perf_counter()
        T.test_fast_enigma_with_plugboard()                  # 60 s of wall lost inside the sweep: green
        assert time.perf_counter() - t0 >= 60.0              # ... which the old perf_counter bound would see
    monkeypatch.undo()
    real = loadclock._children_cpu
    charge = [0.0]
    workers = min(T.psearch.cpu_count(), 60)
    monkeypatch.setattr(loadclock, "_children_cpu", lambda: real() + charge[0])
    monkeypatch.setattr(T.psearch, "parallel_map", _bump(charge, 30.0 * workers, T.psearch.parallel_map))
    with pytest.raises(AssertionError, match="plugboard break took"):
        T.test_fast_enigma_with_plugboard()                  # 30 s more CPU per worker: red


# ---- test_web_browser_recon::test_nested_near_cap_javascript_stops_during_preprocessing -----------------

@pytest.fixture
def recon():
    import test_web_browser_recon as T
    return T


def test_browser_recon_bounds_ignore_a_wall_jump(recon, monkeypatch):
    T = recon
    box = [0.0]
    monkeypatch.setattr(T.B, "analyze", _bump(box, 10.0, T.B.analyze))
    with jumping_wall(monkeypatch, box):
        T.test_nested_near_cap_javascript_stops_during_preprocessing()          # green
        monkeypatch.setattr(T, "work_clock", time.monotonic)                     # the old clock
        with pytest.raises(AssertionError, match="promptly"):
            T.test_nested_near_cap_javascript_stops_during_preprocessing()


def test_browser_recon_bound_fails_on_cpu_work(recon, monkeypatch):
    T = recon
    charge = [0.0]
    monkeypatch.setattr(T, "work_clock", lambda: time.thread_time() + charge[0])
    real = T.B.analyze

    def analyze(*a, **k):
        if k.get("stop") is None and k.get("deadline") is None:
            charge[0] += 3.5                                # the full pass costs 3.5 s more CPU
        return real(*a, **k)
    monkeypatch.setattr(T.B, "analyze", analyze)
    with pytest.raises(AssertionError, match="completes within the bounded linear pass"):
        T.test_nested_near_cap_javascript_stops_during_preprocessing()


# ---- test_web_reset_rebind::test_fail_closed_contracts ---------------------------------------------------

@pytest.fixture
def rebind():
    import test_web_reset_rebind as T
    return T


def test_reset_rebind_fail_closed_cases_ignore_a_wall_jump(rebind, monkeypatch):
    T = rebind
    real_time = time.time
    box = [0.0]
    monkeypatch.setattr(T.Site, "handle", _bump(box, 10.0, T.Site.handle))
    monkeypatch.setattr(time, "time", lambda: real_time() + box[0])     # every request costs 10 s of wall
    assert _sink_new(T, T.test_fail_closed_contracts, "FAILS") == []    # the step clock: green
    monkeypatch.setattr(T, "engine_clock", lambda site, start: contextlib.nullcontext())   # the old, real clock
    failed = _sink_new(T, T.test_fail_closed_contracts, "FAILS")
    assert "reset contract: camelCase destructive advertised route /deleteUser => inert" in failed


def test_reset_rebind_step_clock_spends_the_deadline_per_request(rebind):
    T = rebind
    site = T.Site()
    start = 1_700_000_000.0                                  # an epoch reading, as run() passes one
    with T.engine_clock(site, start):
        assert T.RR.time.time() == start                    # it starts where it is told
        time.sleep(0.05)
        assert T.RR.time.time() == start                    # waiting spends nothing
        site.calls.append({})
        # the difference, not the epoch values: approx's relative tolerance on an epoch is about 1,700 s
        assert T.RR.time.time() - start == pytest.approx(T.REQUEST_STEP, abs=1e-5)
        site.calls.extend([{}, {}])
        assert T.RR.time.time() - start == pytest.approx(3 * T.REQUEST_STEP, abs=1e-5)
        assert T.RR.time.monotonic is time.monotonic        # the rest of `time` is real
    assert T.RR.time is time


def test_reset_rebind_deadline_is_not_charged_the_site_startup(rebind, monkeypatch):
    """The 0.79 s "time reserved for redeem" case in test_bounds_and_switch: the fake site's startup loses
    1 s of wall time (a stand-in for load), which the step clock must not charge to the deadline."""
    T = rebind
    real_time, real_served = time.time, T.served
    box = [0.0]

    @contextlib.contextmanager
    def slow_served(site):
        with real_served(site) as base:
            box[0] += 1.0
            yield base
    monkeypatch.setattr(T, "served", slow_served)
    monkeypatch.setattr(time, "time", lambda: real_time() + box[0])
    assert _sink_new(T, T.test_bounds_and_switch, "FAILS") == []          # the start read before: green
    real_clock = T.engine_clock
    monkeypatch.setattr(T, "engine_clock", lambda site, start: real_clock(site, time.time()))  # read after
    failed = _sink_new(T, T.test_bounds_and_switch, "FAILS")
    assert failed == ["reset deadline: issue is not sent without time reserved for redeem"], failed


# ---- test_web_stream_transports: the wss alias ----------------------------------------------------------

def test_wss_alias_survives_a_slow_tls_handshake_and_one_second_does_not(monkeypatch):
    import test_web_stream_transports as T

    class SlowTLS(T._Server):
        def get_request(self):                              # the server's accept thread waits for a core
            time.sleep(1.5)
            return super().get_request()

    monkeypatch.setattr(T, "_Server", SlowTLS)
    case = T.StreamTransportTests("test_wss_alias_uses_tls_and_keeps_exact_origin")
    case.test_wss_alias_uses_tls_and_keeps_exact_origin()                     # green
    monkeypatch.setattr(T, "TLS_CLIENT_TIMEOUT", 1)                            # the old timeout
    with pytest.raises(T.web.VPNRequired):
        case.test_wss_alias_uses_tls_and_keeps_exact_origin()


# ---- tests/real/test_real_classical.py (test_testing_real_runner's empty-corpus run) --------------------

def test_brutus_bound_ignores_a_wall_jump_and_fails_on_cpu(tmp_path):
    d = _driver(tmp_path, "classical")
    jump, charge, bare = d["wall_jump"], d["cpu_charge"], d["no_cpu_clock"]
    assert len(jump) == 3 and all(ln.startswith("ok") for ln in jump), jump   # 10 s of wall inside: green
    assert d["old_measure"] >= 10.0                                        # the old perf_counter saw it
    assert d["old_reading"] is None, d                                     # crack's budget on the wall: cut
    assert bare[0].startswith("FAIL") and "caesar16" in bare[0], bare     # without cpu_clock: no reading
    assert [ln[:4] for ln in charge if "under 3 s of CPU" in ln] == ["FAIL"], charge


# ---- tests/real/test_real_windows.py ---------------------------------------------------------------------

def test_windows_parse_memo_reuses_copies_and_keeps_no_cut_read(tmp_path):
    d = _driver(tmp_path, "windows_memo")
    assert d["second_read_reuses"] and d["same_content"] and d["copies_are_independent"], d
    assert d["src_restamped"] == ["one.evtx", "two.evtx"], d
    assert d["deadline_cut_not_kept"] and d["undeadlined_incomplete_kept"] and d["parser_in_key"], d


@pytest.mark.needs_realdata("windows")
def test_windows_toolkit_deadline_counts_cpu_under_the_scripts_clock(tmp_path):
    from ctf import paths
    d = _driver(tmp_path, "windows_deadline", corpus=paths.realdata_root())
    assert d["plain"] == "19", d
    assert d["real_clock"] is None, d                       # the wall clock jumping: the read is cut
    assert d["cpu_clock"] == "19", d                        # the script's cpu_clock: answered
