"""SH-09: child-process drivers for tests/test_sh09_load_independence.py (not a test module).

    python tests/sh09_drivers.py <scenario>      prints one JSON object

Two of the checks SH-09 made load-independent run as scripts in a process of their own and change that
process as they load (tests/real/test_real_carve_stego.py pins a scope and points $CTF_WORKDIR at a
temporary folder; tests/test_tk_day27_dlog.py does the same to the environment), so they are driven here, in
a fresh interpreter, with a stand-in for load or for a slower core, and with a stand-in for the defect their
bound guards. Every input is synthetic: nothing is read from the real-data corpus or a saved attempt.
"""
import contextlib
import importlib.util
import io
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path, extra_path: Path):
    if str(extra_path) not in sys.path:
        sys.path.insert(0, str(extra_path))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@contextlib.contextmanager
def loaded_wall_clock(step=0.25):
    """time.monotonic and time.perf_counter as a heavily loaded process sees them: every look at the clock
    finds `step` seconds more gone than the last (the process lost its core in between). CPU clocks are left
    as they are. Yields the number of looks taken so far (a one-item list)."""
    looks = [0]
    real_mono, real_perf = time.monotonic, time.perf_counter

    def mono():
        looks[0] += 1
        return real_mono() + looks[0] * step

    def perf():
        looks[0] += 1
        return real_perf() + looks[0] * step
    time.monotonic, time.perf_counter = mono, perf
    try:
        yield looks
    finally:
        time.monotonic, time.perf_counter = real_mono, real_perf


@contextlib.contextmanager
def slower_core(factor=2.5):
    """time.process_time and time.thread_time as on a core running at 1/factor of its clock: every second of
    work reads `factor` seconds of CPU. The cycle counter work_seconds reads is not changed (a lower clock
    does not change the cycles the work takes)."""
    real_proc, real_thread = time.process_time, time.thread_time
    p0, t0 = real_proc(), real_thread()
    time.process_time = lambda: p0 + (real_proc() - p0) * factor
    time.thread_time = lambda: t0 + (real_thread() - t0) * factor
    try:
        yield
    finally:
        time.process_time, time.thread_time = real_proc, real_thread


# ---- tests/real/test_real_carve_stego.py: the per-set cost limit -------------------------------------------

def real_carve():
    r = _load("sh09_real_carve", REPO / "tests" / "real" / "test_real_carve_stego.py", REPO / "tests" / "real")
    R, K = r.R, r.sh09_clocks
    deep = _load("sh09_deep_cost", REPO / "tests" / "test_carve_stego_deep_cost.py", REPO / "tests")
    png = deep._photo_png_with_red_lsb_text()           # stg300's shape: about 0.5 s of work
    q = r.q("f", "What is the flag hidden in the least significant bits?", pattern="^[0-9A-F]{32}$")
    out = {}

    def lines(run):
        """The check lines run() printed (status, label), and whether a Skip was raised."""
        buf, skipped = io.StringIO(), None
        with contextlib.redirect_stdout(buf):
            try:
                got = run()
            except R.Skip as e:
                got, skipped = None, str(e)
        return [ln for ln in buf.getvalue().splitlines() if "solve_set on" in ln], got, skipped

    out["base"] = lines(lambda: r.solve("stg300.png", [q], {"stg300.png": png}))
    # A slower core: the same work reads `factor` times the CPU seconds. The old check (process CPU time: what
    # realdata_c.timed measured until SH-11 moved it to the work meter, kept here as old_cpu_timed so the
    # failure it had stays shown) fails; the work meter does not read the CPU clocks, so this script's own
    # timed and the shared realdata_c.timed both stay green. Under load this machine read about
    # 2x; the factor is at least 2.5, and more when this synthetic set is cheap enough on an idle machine that
    # 2.5x would stay under the limit (seen at a load of 18: the demonstration of the old failure was then
    # green), so the old check's failure shows at any load.
    t0 = time.process_time()
    r.cs.solve_set([q], {"stg300.png": png}, {"carve_stego_budget": r.UNLOADED_BUDGET})
    warm_cpu = time.process_time() - t0
    factor = max(2.5, 1.5 * r.cs.BUDGET / max(warm_cpu, 1e-3))
    out["slow_factor"] = factor

    def old_cpu_timed(label, fn, *args, limit, **kw):
        """realdata_c.timed as it was before SH-11: the cost limit against CPU seconds of this process."""
        t0 = time.process_time()
        got = fn(*args, **kw)
        dt = time.process_time() - t0
        R.check(f"{label}: {dt:.2f} s CPU (limit {limit:g} s)", dt <= limit)
        return got

    with slower_core(factor):
        out["slow_old"] = lines(lambda: old_cpu_timed("solve_set on stg300.png (CPU)", r.cs.solve_set, [q],
                                                      {"stg300.png": png},
                                                      {"carve_stego_budget": r.UNLOADED_BUDGET}, limit=r.cs.BUDGET))
        out["slow_new"] = lines(lambda: r.solve("stg300.png", [q], {"stg300.png": png}))
        # the helper every group-c script shares (SH-11): the same reading on the same slower core
        out["slow_shared"] = lines(lambda: R.timed("solve_set on stg300.png (shared)", r.cs.solve_set, [q],
                                                   {"stg300.png": png},
                                                   {"carve_stego_budget": r.UNLOADED_BUDGET}, limit=r.cs.BUDGET))
    # The defect: the reading costs 1.1 s more work (cycles charged to it inside solve_set).
    read_cycles, hz = K.meter()
    extra = [0]
    real_solve_set = r.cs.solve_set

    def costly(*a, **k):
        extra[0] += int(1.1 * hz)
        return real_solve_set(*a, **k)
    K._METER["got"] = (lambda: read_cycles() + extra[0], hz)
    r.cs.solve_set = costly
    try:
        out["costly"] = lines(lambda: r.solve("stg300.png", [q], {"stg300.png": png}))
    finally:
        r.cs.solve_set = real_solve_set
        K._METER["got"] = (read_cycles, hz)
    # No meter: the reading still runs (the group's answer checks run) and the cost limit alone is a SKIP line
    # naming the missing meter, never an ok line.
    real_meter = K.meter

    def missing():
        raise K.WorkMeterMissing("stand-in: no cycle counter")
    K.meter = missing
    try:
        out["no_meter"] = lines(lambda: r.solve("stg300.png", [q], {"stg300.png": png}))
    finally:
        K.meter = real_meter
    return out


# ---- tests/test_tk_day27_dlog.py: the R10 control and the CPU clock the script runs on ----------------------

def dlog():
    d = _load("sh09_dlog", REPO / "tests" / "test_tk_day27_dlog.py", REPO / "tests")
    p1, f1 = d.smooth_p(10)
    g1 = d.primitive_root(p1, f1)
    a1, b1 = d.RND.randrange(2, p1 - 1), d.RND.randrange(2, p1 - 1)
    first = f"# first exchange\np = {p1}\ng = {g1}\nA = {pow(g1, a1, p1)}\nB = {pow(g1, b1, p1)}\n"
    filler = "note: nothing to see here\n" * 17500
    files = {"big.txt": (first + filler[:200000]).encode()}
    secret = pow(g1, a1 * b1, p1)

    def control():
        """The script's `R10 control: the same instance under 200 KB of unrelated lines: the secret first`."""
        return d.holds(d.solve(d.ask("What is the shared secret?"), files), secret)

    out = {"unloaded": control()}
    with loaded_wall_clock() as looks:
        out["loaded_direct"] = control()                 # the toolkit's budget on the wall clock: the failure
        out["loaded_direct_looks"] = looks[0]
        fake = time.perf_counter
        n = looks[0]
        out["loaded_run"] = d.run(control)               # the script's entry: the CPU clock
        out["loaded_run_looks"] = looks[0] - n           # the loaded clocks were not read inside run()
        out["restored"] = time.perf_counter is fake and time.monotonic is not time.process_time
    # Work over the budget still runs it out on the CPU clock: every look at the CPU clock finds 100 s more.
    real_proc = time.process_time
    jumps = [0]

    def costly():
        jumps[0] += 1
        return real_proc() + jumps[0] * 100.0
    time.process_time = costly
    try:
        out["costly_run"] = d.run(control)
    finally:
        time.process_time = real_proc
    out["costly_looks"] = jumps[0]
    return out


# ---- tests/test_tk_day27_dlog.py R29: the overrun is an overrun on the CPU clock (round 2) -------------------

# The defect R29 guards, as a source mutant of the toolkit's discrete-log pass: a pass that finds itself past its
# window after a solve gives up the whole set (the older readers' answers too, from the return value and from
# ctx["partial"]). Only a solve that really overruns the clock the pass reads sets it off.
R29_SITE = """            if value is not None:
                out[qid] = value
                partial[qid] = value
    return out
"""
R29_MUTANT = """            if time.monotonic() > end:
                partial.clear()
                return dict.fromkeys(out)
""" + R29_SITE


def _r29_toolkit(mutant: bool):
    path = REPO / "solvers" / "toolkits" / "modern_crypto.py"
    src = path.read_text()
    if mutant:
        if src.count(R29_SITE) != 1:
            raise RuntimeError("the R29 mutant site is not in solvers/toolkits/modern_crypto.py once: update R29_SITE")
        src = src.replace(R29_SITE, R29_MUTANT)
    name = "sh09_mc_r29_mutant" if mutant else "sh09_mc_r29"
    spec = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = str(path)
    sys.modules[name] = mod
    exec(compile(src, str(path), "exec"), mod.__dict__)
    return mod


def dlog_r29():
    """fix2_tests (R27 to R31) through the script's run(), on the toolkit as it is and on the R29 mutant, with the
    script's overrun (work) and with the overrun it had before round 2 (time.sleep). Returns the R29 labels that
    failed in each run."""
    d = _load("sh09_dlog_r29", REPO / "tests" / "test_tk_day27_dlog.py", REPO / "tests")
    real_tk, real_overrun = d.tk, d.overrun
    out = {}
    for name, mutant, overrun in (("work", False, real_overrun), ("work_mutant", True, real_overrun),
                                  ("sleep", False, time.sleep), ("sleep_mutant", True, time.sleep)):
        d.tk, d.overrun = _r29_toolkit(mutant), overrun
        del d.FAILED[:]
        with contextlib.redirect_stdout(io.StringIO()):
            d.run(d.fix2_tests)
        out[name] = [label for label in d.FAILED if label.startswith("R29")]
        out[name + "_all"] = len(d.FAILED)
    d.tk, d.overrun = real_tk, real_overrun
    return out


SCENARIOS = {"real_carve": real_carve, "dlog": dlog, "dlog_r29": dlog_r29}

if __name__ == "__main__":
    result = SCENARIOS[sys.argv[1]]()
    print(json.dumps(result))
