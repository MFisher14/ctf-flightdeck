"""SH-10: child-process drivers for tests/test_sh10_load_independence.py (not a test module).

    python tests/sh10_drivers.py <scenario>      prints one JSON object

The tests/real scripts SH-10 changed put their own folder first on sys.path and import modules whose bare
names clash with this suite's (`windows`, `classical`, `fetch_a`), so they are driven here, in a fresh
interpreter, as tests/sh08_drivers.py drives the SH-08 ones. Each scenario injects a stand-in for load (a
jump of the wall clocks) or a stand-in for the defect (CPU time charged to the measured path) into the path
a check measures. Inputs are synthetic, except `windows_deadline`, which reads one log of the real-data
corpus (its test is marked needs_realdata("windows")).
"""
import contextlib
import importlib.util
import io
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REAL = REPO / "tests" / "real"


def _load(name: str, path: Path):
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@contextlib.contextmanager
def wall_jump(seconds_box):
    """time.monotonic and time.perf_counter read the real clock plus seconds_box[0]."""
    mono, perf = time.monotonic, time.perf_counter
    time.monotonic = lambda: mono() + seconds_box[0]
    time.perf_counter = lambda: perf() + seconds_box[0]
    try:
        yield
    finally:
        time.monotonic, time.perf_counter = mono, perf


@contextlib.contextmanager
def cpu_charge(seconds_box):
    """time.process_time reads the real CPU clock plus seconds_box[0] (CPU time charged to a path)."""
    real = time.process_time
    time.process_time = lambda: real() + seconds_box[0]
    try:
        yield
    finally:
        time.process_time = real


# ---- tests/real/test_real_classical.py: the Brutus bound -------------------------------------------------

def _then(extra, fn):
    def f(*a, **k):
        extra()
        return fn(*a, **k)
    return f


def classical():
    T = _load("sh10_real_classical", REAL / "test_real_classical.py")
    out = {}
    real_crack = T.classical.crack
    box = [0.0]

    def crack_with(extra):
        def f(*a, **k):
            extra()
            return real_crack(*a, **k)
        return f

    def run(label):
        del T.C.FAILED[:]
        buf = io.StringIO()
        raised = None
        with contextlib.redirect_stdout(buf):
            try:
                T.test_brutus()
            except Exception as e:                          # a cut reading ([]) breaks the MD5 check's got[0]
                raised = f"raised {type(e).__name__}"
        out[label] = [ln for ln in buf.getvalue().splitlines() if "Brutus" in ln] + ([raised] if raised else [])

    # Load: the wall clocks jump 10 s inside crack's own 2 s budget window (crack reads its deadline, then
    # computes the keyless readings; the process is descheduled there), and 10 s before it starts.
    real_keyless = T.classical.keyless
    with wall_jump(box):
        T.classical.keyless = _then(lambda: box.__setitem__(0, box[0] + 10.0), real_keyless)
        T.classical.crack = crack_with(lambda: box.__setitem__(0, box[0] + 10.0))
        try:
            run("wall_jump")
            # the old measure (common_d.timed: time.perf_counter) of the same call sees the jump, and crack's
            # budget on the wall clock is spent before it scores anything: no reading at all
            got, took = T.timed(T.classical.crack, T.BRUTUS, None, None, 2.0)
            out["old_measure"] = took
            out["old_reading"] = got[0][1] if got else None
            # the defect put back: test_brutus without cpu_clock around the crack
            saved = T.loadclock.cpu_clock
            T.loadclock.cpu_clock = contextlib.nullcontext
            try:
                run("no_cpu_clock")
            finally:
                T.loadclock.cpu_clock = saved
        finally:
            T.classical.crack = real_crack
            T.classical.keyless = real_keyless
    # The defect: the crack costs 3.5 s more CPU.
    cbox = [0.0]
    with cpu_charge(cbox):
        T.classical.crack = crack_with(lambda: cbox.__setitem__(0, cbox[0] + 3.5))
        try:
            run("cpu_charge")
        finally:
            T.classical.crack = real_crack
    return out


# ---- tests/real/test_real_windows.py: the parse memo and the toolkit's deadline -------------------------

def _windows_module():
    """test_real_windows imported (its folder() needs a non-empty windows/ under CTF_REALDATA)."""
    return _load("sh10_real_windows", REAL / "test_real_windows.py")


def windows_memo():
    T = _windows_module()
    W = T.W
    calls = []

    def fake(data, deadline=None, src=""):
        calls.append((bytes(data), deadline, src))
        cut = data.startswith(b"cut")
        return [{"record": 1, "src": src, "data": {"v": data.decode()}}], not cut

    once = T.ParseOnce(fake)
    out = {}
    a = once(b"log-a", None, "one.evtx")
    b = once(b"log-a", 123.0, "two.evtx")
    out["second_read_reuses"] = len(calls) == 1 and once.reused == 1
    out["src_restamped"] = (a[0][0]["src"], b[0][0]["src"])
    out["same_content"] = a[0][0]["data"] == b[0][0]["data"] and a[1] == b[1] is True
    b[0][0]["data"]["v"] = "changed"
    c = once(b"log-a", None, "three.evtx")
    out["copies_are_independent"] = c[0][0]["data"]["v"] == "log-a"
    once(b"cut-log", 5.0, "x")                              # cut by a deadline: not kept
    once(b"cut-log", 5.0, "x")
    out["deadline_cut_not_kept"] = sum(1 for d, _, _ in calls if d == b"cut-log") == 2
    once(b"cut-whole", None, "x")                           # incomplete with no deadline: the log's own
    once(b"cut-whole", 5.0, "x")
    out["undeadlined_incomplete_kept"] = sum(1 for d, _, _ in calls if d == b"cut-whole") == 1
    saved = list(W._EVTX_RS)
    try:                                                    # another parser is another key
        W._EVTX_RS[:] = [type("fake_rs", (), {"PyEvtxParser": object})]
        once(b"log-a", None, "rs.evtx")
    finally:
        W._EVTX_RS[:] = saved
    out["parser_in_key"] = sum(1 for d, _, _ in calls if d == b"log-a") == 2
    return out


def windows_deadline():
    """W.solve_set on one real log, the wall clocks jumping 60 s inside the parse: on the real clock the read
    is cut (no count); under loadclock.cpu_clock (what the script runs in) the count is answered."""
    from ctf import paths
    T = _windows_module()
    W = T.W
    sys.path.append(str(REPO / "tests"))
    import loadclock
    log = (paths.realdata_root() / "windows" / "little_shop-HOSTB-System.evtx").read_bytes()
    qs = [T.q("n", "How many events are in System.evtx?", "integer", artifact="System.evtx")]
    real = W._evtx_finish
    box = [0.0]

    def finish(*a, **k):                                    # each record parsed: the process loses 60 s
        box[0] += 60.0
        return real(*a, **k)

    out = {}
    W._evtx_finish = finish
    try:
        with wall_jump(box):
            out["real_clock"] = W.solve_set(qs, {"System.evtx": log}, {})["n"]
            box[0] = 0.0
            with loadclock.cpu_clock():
                out["cpu_clock"] = W.solve_set(qs, {"System.evtx": log}, {})["n"]
    finally:
        W._evtx_finish = real
    out["plain"] = W.solve_set(qs, {"System.evtx": log}, {})["n"]
    return out


SCENARIOS = {"classical": classical, "windows_memo": windows_memo, "windows_deadline": windows_deadline}

if __name__ == "__main__":
    print(json.dumps(SCENARIOS[sys.argv[1]]()))
