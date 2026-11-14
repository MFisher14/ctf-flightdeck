"""SH-08: child-process drivers for tests/test_sh08_load_independence.py (not a test module).

    python tests/sh08_drivers.py <scenario>      prints one JSON object

The two carried checks this item made load-independent that run as child scripts (the row-92 cost bound of
solvers/script-analysis/test_wavec2_deflate.py and the look-alike bound of tests/real/test_review_a.py)
import modules whose bare names clash with other solver folders' (`generic`), so they are driven here, in
a fresh interpreter, with a stand-in for load (a wall-only delay or a jump of the wall clocks) or a stand-in
for the defect (CPU time charged to the measured path) injected into the measured path. Every input is the
scripts' own synthetic material; nothing is read from a saved attempt.
"""
import contextlib
import importlib.util
import io
import json
import random
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
def patched(obj, name, value):
    real = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield real
    finally:
        setattr(obj, name, real)


def first_call(real, before):
    """real, with before() run once, at its first call (an injection into the measured path)."""
    done = [False]

    def f(*a, **k):
        if not done[0]:
            done[0] = True
            before()
        return real(*a, **k)
    return f


def busy(seconds: float):
    """CPU work of `seconds` in this thread (a stand-in for a slower measured path)."""
    def run():
        t0 = time.thread_time()
        x = 0
        while time.thread_time() - t0 < seconds:
            x += 1
    return run


# ---- the row-92 cost bound (test_wavec2_deflate) ----------------------------------------------------------

def wavec2():
    w = _load("sh08_wavec2", REPO / "solvers" / "script-analysis" / "test_wavec2_deflate.py",
              REPO / "solvers" / "script-analysis")
    pc, lp = w.plan_codec, w.label_plan
    f = w.bounded_forms(random.Random(92))[("base64", "labelled")]      # the form whose wall bound failed
    out = {"limit": w.ROW92_LIMIT}
    with contextlib.redirect_stdout(io.StringIO()):
        out["none_is_a_plan"] = f() is None
        out["base"] = w._row92_cost(f, n=1)

        def off_wall():
            """The old measure's 'off' reading: f's wall time with row 92 switched off."""
            saved = [(m, n, getattr(m, n)) for m, n in w.ROW92_ENTRIES]
            for m, n, _ in saved:
                setattr(m, n, lambda *a, **k: None)
            try:
                pc._RAW.clear()
                lp._UNPACKED.clear()
                t0 = time.perf_counter()
                f()
                return time.perf_counter() - t0
            finally:
                for m, n, real in saved:
                    setattr(m, n, real)

        # Load: the process loses 1 s of wall time inside row 92 (a sleep: no CPU). The old measure (wall
        # time on minus off) reads it as row 92's cost; the new one does not. (0.2 s until SH-09: the old
        # measure is the difference of two ~0.45 s wall readings, and under load that difference moved by
        # more than 0.2 s, which made this demonstration of it read -0.17 s.)
        with patched(lp, "_raw_search", first_call(lp._raw_search, lambda: time.sleep(1.0))):
            out["sleep"] = w._row92_cost(f, n=1)
        with patched(lp, "_raw_search", first_call(lp._raw_search, lambda: time.sleep(1.0))):
            pc._RAW.clear()
            lp._UNPACKED.clear()
            t0 = time.perf_counter()
            f()
            on = time.perf_counter() - t0
        out["sleep_old_measure"] = on - off_wall()
        # The defect: row 92 does 0.08 s more work (CPU) on this blob.
        with patched(lp, "_raw_search", first_call(lp._raw_search, busy(0.08))):
            out["busy"] = w._row92_cost(f, n=1)
        # The measure's own premise: a row-92 entry that gives something is reported (`gave`).
        with patched(pc, "raw_inflate", lambda *a, **k: b"not a plan, but a stream"):
            out["gives"] = w._row92_cost(lambda: lp._inflate_raw(b"x" * 64), n=1)
    return out


# ---- the look-alike bound (tests/real/test_review_a.py) ---------------------------------------------------

def review_a():
    r = _load("sh08_review_a", REPO / "tests" / "real" / "test_review_a.py", REPO / "tests" / "real")
    E = r.E
    label = "email: a mail with 1,500 other domains"
    out = {}

    def run_checks():
        """{label prefix: ok} of the email look-alike check after one main() run."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            r.main()
        lines = [ln for ln in buf.getvalue().splitlines() if label in ln]
        return [ln[:4].strip() for ln in lines], lines

    def big_mail_only(real, extra):
        """real lookalikes, with extra() first when the mail names over 1,000 domains (the timed one)."""
        def f(mail):
            if len(E.domains(mail)) > 1000:
                extra()
            return real(mail)
        return f

    wall_jump = [0.0]
    real_mono, real_perf = time.monotonic, time.perf_counter

    def jump():
        wall_jump[0] += 10.0

    # Load: the wall clocks jump 10 s inside the timed look-alike read (the process descheduled). The
    # check reads process CPU time, so it still passes; the old check (time.monotonic) would read 10 s.
    time.monotonic = lambda: real_mono() + wall_jump[0]
    time.perf_counter = lambda: real_perf() + wall_jump[0]
    try:
        t0 = time.monotonic()
        with patched(E, "lookalikes", big_mail_only(E.lookalikes, jump)):
            out["wall_jump"] = run_checks()
        out["wall_jump_seen_by_monotonic"] = time.monotonic() - t0 >= 10.0
    finally:
        time.monotonic, time.perf_counter = real_mono, real_perf
    # The defect: the read costs 2.1 s more CPU (every pair compared again costs far more: build log).
    cpu_jump = [0.0]
    real_cpu = time.process_time
    time.process_time = lambda: real_cpu() + cpu_jump[0]
    try:
        with patched(E, "lookalikes", big_mail_only(E.lookalikes, lambda: cpu_jump.__setitem__(0, cpu_jump[0] + 2.1))):
            out["cpu_jump"] = run_checks()
    finally:
        time.process_time = real_cpu
    return out


SCENARIOS = {"wavec2": wavec2, "review_a": review_a}

if __name__ == "__main__":
    print(json.dumps(SCENARIOS[sys.argv[1]]()))
