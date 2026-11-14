"""The seven archived Huntress modules the master still referenced (B-001b): switches, judge, grade, preflight,
proposer_gate, proposer_wire, prefix_pool. The merge plan archived them; where the feature went with them
the import is gone (switches, judge in yield_clocks), and where the Huntress runner that needs them is kept
for the Huntress adapter (B-005) the runner names each missing module instead of starting without it.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

from ctf import env

REPO = Path(__file__).resolve().parent.parent


def test_run_py_names_every_missing_runner_module_before_it_requests_anything():
    import run
    missing = "; ".join(run.RUNNER_MISSING)
    for name in ("gm", "lanes", "grade", "preflight", "proposer_gate", "proposer_wire"):
        assert f"tools/{name}.py" in missing, missing
    assert not hasattr(run, "switches")            # the archived switch file is no longer imported
    assert run.switch_on("preread") is False and run.regular_mode() is False


def test_timed_ladder_stops_at_import_naming_the_archived_modules():
    spec = importlib.util.spec_from_file_location("b001b_timed_ladder",
                                                  REPO / "solvers" / "script-analysis" / "timed_ladder.py")
    mod = importlib.util.module_from_spec(spec)
    saved = list(sys.path)
    try:
        with pytest.raises(ImportError) as e:
            spec.loader.exec_module(mod)
    finally:
        sys.path[:] = saved
    assert e.value.name == "gm"
    for name in ("gm", "judge", "lanes", "grade", "prefix_pool"):
        assert f"tools/{name}.py" in str(e.value)
    assert "B-005" in str(e.value)


def test_yield_clocks_without_a_busy_source_says_so_and_never_holds(monkeypatch):
    import yield_clocks
    for name in ("CTF_YIELD", *env.legacy_names("CTF_YIELD")):
        monkeypatch.delenv(name, raising=False)
    notes = []
    assert yield_clocks.run_held([sys.executable, "-c", "pass"], note=notes.append) == 0
    assert notes == [yield_clocks.NO_BUSY_SOURCE] and "tools/judge.py" in notes[0]
    assert not hasattr(yield_clocks, "_clock_busy_fn")


def test_yield_clocks_still_holds_with_a_caller_busy_source(monkeypatch):
    import yield_clocks
    for name in ("CTF_YIELD", *env.legacy_names("CTF_YIELD")):
        monkeypatch.delenv(name, raising=False)
    notes, calls = [], []

    def busy():
        calls.append(1)
        return len(calls) <= 3          # busy for the first three looks, then free

    code = yield_clocks.run_held([sys.executable, "-c", "import time; time.sleep(0.4)"], busy=busy, poll=0.02,
                                 note=notes.append)
    assert code == 0 and len(calls) > 3
    assert any(n.startswith("NOTE held") for n in notes) and yield_clocks.NO_BUSY_SOURCE not in notes


def test_web_patch_webpost_bridge_is_off_and_says_why():
    import web_patch
    assert web_patch.enabled() is False
    assert "tools/switches.py" in web_patch.WEBPOST_GATE and not hasattr(web_patch, "_switches")
