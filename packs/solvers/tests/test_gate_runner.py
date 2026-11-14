"""B-195: the gate runner: one pytest child per file, warm reuse by exact key, load-scaled walls, --jobs.
Each test builds a small synthetic checkout and runs real pytest children in it (no network, no binaries)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ctf.gate import config
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import Row, format_row, format_summary, parse_junit, run_gate, scaled_wall
from ctf.gate.warm import WarmResult, WarmStore, file_key, warm_key
from gate_repo import make_repo, write

FILES = {
    "lib/val.txt": "7\n",
    "tests/test_ok.py": """\
        from pathlib import Path
        VAL = "lib/val.txt"
        def test_one():
            assert (Path(__file__).parent.parent / VAL).read_text().strip().isdigit()
        def test_two():
            assert 1 + 1 == 2
        """,
    "tests/test_bad.py": "def test_fails():\n    assert 1 == 2, 'deliberate red'\n",
    "tests/test_skip.py": ("import pytest\ndef test_runs():\n    pass\n"
                           "@pytest.mark.skip(reason='needs a tool')\ndef test_skipped():\n    pass\n"),
    "tests/test_xf.py": ("import pytest\ndef test_runs():\n    pass\n"
                         "@pytest.mark.xfail(reason='known', strict=True)\ndef test_known():\n    assert 0\n"),
    "tests/test_script.py": "X = 1\n",
    "tests/test_never_warm_x.py": "def test_ok():\n    pass\n",
}


def _graph(root, state):
    return Graph(root, config.load(root, root / "gate.toml"), state / "co")


def _sel(tests, mode="impact"):
    return Selection(mode, sorted(tests), [], {})


def _run(root, state, tests, **kw):
    kw.setdefault("load_fn", lambda: 0.0)
    kw.setdefault("cpus", 4)
    lines = []
    rep = run_gate(_graph(root, state), _sel(tests), state=state, out_dir=state / "out", emit=lines.append, **kw)
    return rep, {r.test: r for r in rep.rows}, lines


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES)


ALL = [t for t in FILES if t.startswith("tests/")]


def test_scaled_wall():
    assert scaled_wall(10, 4.0, load=0.0, cpus=14) == (10.0, 1.0)        # never below the base
    assert scaled_wall(10, 4.0, load=28.0, cpus=14) == (20.0, 2.0)
    assert scaled_wall(10, 4.0, load=1000.0, cpus=14) == (40.0, 4.0)     # capped
    assert scaled_wall(10, 4.0, load=3.0, cpus=0) == (30.0, 3.0)         # a bad cpu count is one cpu


def test_one_row_per_file_with_counts_and_status(repo, tmp_path):
    rep, rows, lines = _run(repo, tmp_path / "s", ALL, jobs=2)
    assert rows["tests/test_ok.py"].status == "PASS" and rows["tests/test_ok.py"].passed == 2
    bad = rows["tests/test_bad.py"]
    assert (bad.status, bad.failed) == ("FAIL", 1) and bad.detail
    assert (rows["tests/test_skip.py"].status, rows["tests/test_skip.py"].skipped) == ("PASS", 1)
    assert (rows["tests/test_xf.py"].passed, rows["tests/test_xf.py"].xfailed) == (1, 1)
    assert rows["tests/test_script.py"].status == "EMPTY"
    assert not rep.ok
    assert len(lines) == len(ALL)                                         # one line per file, as it lands
    assert sorted(ln.split()[2] for ln in lines) == sorted(ALL)
    s = format_summary(rep)
    assert s.startswith("GATE result=fail mode=impact files=6 ran=6 warm=0 pass=4 fail=1 error=0 timeout=0 empty=1")
    assert "tests_failed=1" in s and "skipped=1" in s and "xfailed=1" in s


def test_green_complete_results_are_reused_and_others_rerun(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ALL, jobs=2)
    rep, rows, _ = _run(repo, state, ALL, jobs=2)
    assert rows["tests/test_ok.py"].warm and rows["tests/test_ok.py"].passed == 2
    assert rows["tests/test_xf.py"].warm                                  # an xfail is a known failure: green
    assert not rows["tests/test_bad.py"].warm and rows["tests/test_bad.py"].status == "FAIL"
    assert not rows["tests/test_skip.py"].warm                            # a skip depends on the host: rerun
    assert not rows["tests/test_never_warm_x.py"].warm                    # no_warm glob
    assert not rows["tests/test_script.py"].warm
    assert "ran=4 warm=2" in format_summary(rep)


def test_a_red_result_is_never_stored(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_bad.py"])
    g = _graph(repo, state)
    assert WarmStore(state).get(file_key(g, "tests/test_bad.py"), "tests/test_bad.py") is None
    assert not list(state.glob("warm/*/*.json"))


# A test that reads an environment variable the gate config does not list: its result depends on
# something outside the key, so the same key can be green once and red later (the flaky case).
FLIP = {"tests/test_flip.py": "import os\ndef test_flip():\n    assert os.environ.get('B195_FLIP') != '1'\n"}


def test_a_red_run_deletes_the_green_result_stored_under_its_key(repo, tmp_path, monkeypatch):
    write(repo, FLIP)
    state, t = tmp_path / "s", "tests/test_flip.py"
    monkeypatch.delenv("B195_FLIP", raising=False)
    _run(repo, state, [t])
    key = file_key(_graph(repo, state), t)
    assert WarmStore(state).get(key, t) is not None                       # green: stored
    monkeypatch.setenv("B195_FLIP", "1")
    _, rows, _ = _run(repo, state, [t], warm=False)                       # a full run: same key, red
    assert rows[t].status == "FAIL"
    assert file_key(_graph(repo, state), t) == key                       # the key did not move
    assert WarmStore(state).get(key, t) is None                           # the stale green is gone
    _, rows, _ = _run(repo, state, [t])                                   # so an impact run reruns it
    assert rows[t].status == "FAIL" and not rows[t].warm


def test_drop_reports_whether_a_result_was_there(tmp_path):
    store, key = WarmStore(tmp_path), "ab" * 32
    store.put(WarmResult(test="tests/test_a.py", key=key, seconds=1.0, passed=1, xfailed=0, ts=0.0))
    assert store.drop(key) is True and store.get(key, "tests/test_a.py") is None
    assert store.drop(key) is False


def test_no_reuse_files_always_run(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_ok.py", "tests/test_xf.py"])
    rep, rows, _ = _run(repo, state, ["tests/test_ok.py", "tests/test_xf.py"], no_reuse={"tests/test_ok.py"})
    assert not rows["tests/test_ok.py"].warm and rows["tests/test_ok.py"].status == "PASS"
    assert rows["tests/test_xf.py"].warm                                  # only the named file is held back
    assert "ran=1 warm=1" in format_summary(rep)


def test_changed_input_content_invalidates_the_key(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_ok.py"])
    write(repo, {"lib/val.txt": "8\n"})                                   # still green, new content
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"])
    assert rows["tests/test_ok.py"].status == "PASS" and not rows["tests/test_ok.py"].warm
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"])
    assert rows["tests/test_ok.py"].warm


def test_env_knob_and_pytest_args_enter_the_key(repo, tmp_path, monkeypatch):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_ok.py"])
    monkeypatch.setenv("CTF_GATE_TEST_KNOB", "other")
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"])
    assert not rows["tests/test_ok.py"].warm
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"], pytest_args=("-x",))
    assert not rows["tests/test_ok.py"].warm


def test_the_test_path_enters_the_key(tmp_path):
    """Two test files with the very same inputs get different keys, so neither overwrites the other's
    record and both stay warm."""
    inputs = [("lib/val.txt", "a" * 64), ("conftest.py", None)]
    ka = warm_key("tests/test_a.py", inputs, [])
    kb = warm_key("tests/test_b.py", inputs, [])
    assert ka != kb
    assert warm_key("tests/test_a.py", list(reversed(inputs)), []) == ka          # input order does not matter
    store = WarmStore(tmp_path / "s")
    for t, k in (("tests/test_a.py", ka), ("tests/test_b.py", kb)):
        store.put(WarmResult(test=t, key=k, seconds=1.0, passed=1, xfailed=0, ts=0.0))
    assert store.get(ka, "tests/test_a.py") and store.get(kb, "tests/test_b.py")


def test_warm_off_runs_everything_but_still_stores(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_ok.py"])
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"], warm=False)
    assert not rows["tests/test_ok.py"].warm
    _, rows, _ = _run(repo, state, ["tests/test_ok.py"])
    assert rows["tests/test_ok.py"].warm


SLEEPY = {
    "tests/test_sleepy.py": """\
        import time
        from pathlib import Path
        def test_sleeps():
            time.sleep(6)
            (Path(__file__).parent.parent / "finished.txt").write_text("yes")
        """,
}


@pytest.mark.slow
def test_wall_scales_with_load_and_a_timeout_is_red(tmp_path):
    root = make_repo(tmp_path / "repo", SLEEPY, extra_config="")
    (root / "gate.toml").write_text((root / "gate.toml").read_text()
                                    .replace("base_seconds = 120", "base_seconds = 3").replace("max_scale = 4.0",
                                                                                               "max_scale = 20.0"))
    state = tmp_path / "s"
    rep, rows, _ = _run(root, state, ["tests/test_sleepy.py"], load_fn=lambda: 0.0, cpus=10)
    r = rows["tests/test_sleepy.py"]
    assert r.status == "TIMEOUT" and "3s wall" in r.detail and not rep.ok
    time.sleep(5)                                                          # the child was killed, not orphaned
    assert not (root / "finished.txt").exists()
    rep, rows, _ = _run(root, state, ["tests/test_sleepy.py"], load_fn=lambda: 200.0, cpus=10)
    assert rows["tests/test_sleepy.py"].status == "PASS" and rep.ok        # wall 3 * 20 = 60 s under load
    assert rep.scale == 20.0 and rep.wall == 60.0


TIMED = {f"tests/test_t{i}.py": f"""\
    import os, time
    from pathlib import Path
    def test_record():
        out = Path(os.environ["GATE_TEST_TIMES"])
        t0 = time.time()
        time.sleep(1.5)
        (out / "t{i}.json").write_text(__import__("json").dumps([t0, time.time()]))
    """ for i in (1, 2)}


def _intervals(d: Path):
    return sorted(json.loads((d / f"t{i}.json").read_text()) for i in (1, 2))


@pytest.mark.parametrize("jobs,overlap", [(1, False), (2, True)])
def test_jobs_runs_files_concurrently(tmp_path, monkeypatch, jobs, overlap):
    root = make_repo(tmp_path / "repo", TIMED)
    times = tmp_path / "times"
    times.mkdir()
    monkeypatch.setenv("GATE_TEST_TIMES", str(times))
    rep, _, _ = _run(root, tmp_path / "s", list(TIMED), jobs=jobs, warm=False)
    assert rep.ok and rep.jobs == jobs
    (a0, a1), (b0, b1) = _intervals(times)
    assert (b0 < a1) is overlap


def test_parse_junit_counts_collection_errors(tmp_path):
    x = tmp_path / "j.xml"
    x.write_text('<testsuites><testsuite errors="2" failures="1" tests="4">'
                 '<testcase name="a"/><testcase name="b"><failure/></testcase>'
                 '<testcase name="c"><error/></testcase>'
                 '<testcase name="d"><skipped type="pytest.skip"/></testcase>'
                 '<testcase name="e"><skipped type="pytest.xfail"/></testcase>'
                 '</testsuite></testsuites>')
    assert parse_junit(x) == {"passed": 1, "failed": 1, "errors": 2, "skipped": 1, "xfailed": 1}


def test_format_row_shows_warm_and_detail():
    s = format_row(Row(test="tests/test_a.py", status="PASS", passed=3, warm="abc123", detail="reused"))
    assert s.startswith("PASS") and "tests/test_a.py" in s and "passed=3" in s and "warm abc123" in s
    assert s.endswith("| reused")
