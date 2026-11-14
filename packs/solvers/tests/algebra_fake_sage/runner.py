"""Run the real Sage worker against the fake `sage` package (B-157 tests): `runner.py worker.py job.json`.

Started by the stub `sage` and the stub `docker run` of tests/algebra_stubs.py. FAKE_SAGE_MODE picks a
misbehaviour, so the service's handling of a wrong, silent or slow backend is tested on purpose:

    (empty)        run the worker and pass its result line through, after some banner noise
    silent         print noise and no result line
    exit124        exit 124 with no result (what coreutils `timeout` does at the limit)
    hang           sleep FAKE_SAGE_HANG seconds first
    slow_lll       the fake LLL sleeps FAKE_SAGE_HANG seconds (the worker's own alarm must end it)
    noalarm        the fake cysignals has no alarm (ImportError): the worker runs without one and says so
    noversion      drop sage_version from the result
    bad_basis      add 1 to the first entry of the reduced basis
    bad_transform  add 1 to the first entry of U
    half_lattice   double the basis and U: an integer U exists, an integer V cannot
    bad_point      add 1 to the first coordinate of the first point
    bad_root       add 1 to the first root
    keep_var       multiply the first returned polynomial by x0 (an eliminated variable survives)
"""
import contextlib
import io
import json
import os
import runpy
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SENTINEL = "CTF-ALGEBRA-RESULT "


def _bump(value):
    return [value[0] + 1, value[1]] if isinstance(value, list) else value + 1


def tamper(obj, mode):
    """Apply the mode to a result it fits; a result of another kind passes through untouched."""
    data = obj.get("data") or {}
    if mode == "noversion":
        obj.pop("sage_version", None)
    elif mode == "bad_basis" and "u" in data:
        data["basis"][0][0] += 1
    elif mode == "bad_transform" and "u" in data:
        data["u"][0][0] += 1
    elif mode == "half_lattice" and "u" in data:
        data["basis"] = [[2 * x for x in row] for row in data["basis"]]
        data["u"] = [[2 * x for x in row] for row in data["u"]]
    elif mode == "bad_point" and data.get("points"):
        data["points"][0][0] = _bump(data["points"][0][0])
    elif mode == "bad_root" and data.get("roots"):
        data["roots"][0] = _bump(data["roots"][0])
    elif mode == "keep_var" and "u" not in data and ("poly" in data or data.get("basis")):
        terms = data["basis"][0] if "basis" in data else data["poly"]
        for term in terms:
            term[1][0] += 1
    return obj


def main(argv):
    mode = os.environ.get("FAKE_SAGE_MODE", "")
    print("fake SageMath banner: not a result line")
    if mode == "silent":
        return 0
    if mode == "exit124":
        return 124
    if mode == "hang":
        pidfile = os.environ.get("FAKE_SAGE_LOG", "") + ".pid"       # lets a test see this process end
        with open(pidfile, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
        time.sleep(float(os.environ.get("FAKE_SAGE_HANG", "30")))
    sys.path[:0] = [str(HERE), str(REPO / "solvers" / "common")]
    worker, job = argv[1], argv[2]
    buf = io.StringIO()
    code = 0
    sys.argv = [worker, job]
    with contextlib.redirect_stdout(buf):
        try:
            runpy.run_path(worker, run_name="__main__")
        except SystemExit as ex:
            code = ex.code or 0
    for line in buf.getvalue().splitlines():
        if line.startswith(SENTINEL) and mode:
            line = SENTINEL + json.dumps(tamper(json.loads(line[len(SENTINEL):]), mode))
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
