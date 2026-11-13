"""R-01: the suite runner (tools/suite.py, tools/suite.sb) and the per-test junit comparison
(tools/junit_diff.py), on synthetic junit files and synthetic test trees built here.

Also the guard that keeps the bare `python -m pytest` collectable: no test file under tests/ may exit
the interpreter at import (that aborts the whole session at collection), and no conftest may hide
script-style files with collect_ignore.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import junit_diff
import suite

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- helpers

def junit_xml(cases) -> str:
    """cases: (classname, name, status) with status passed | failed | error | skipped | xfailed."""
    body = []
    for cls, name, st in cases:
        inner = {"passed": "",
                 "failed": '<failure message="assert 0">assert 0</failure>',
                 "error": '<error message="collection failure">ImportError</error>',
                 "skipped": '<skipped type="pytest.skip" message="needs_tool: radare2">skip</skipped>',
                 "xfailed": '<skipped type="pytest.xfail" message="known-fail: owned elsewhere"/>'}[st]
        body.append(f'<testcase classname="{cls}" name="{name}" time="0.01">{inner}</testcase>')
    return ('<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="%d">%s'
            '</testsuite></testsuites>' % (len(cases), "".join(body)))


def write_junit(path: Path, cases) -> Path:
    path.write_text(junit_xml(cases), encoding="utf-8")
    return path


def make_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(textwrap.dedent(src), encoding="utf-8")
    return root


# --------------------------------------------------------------------------- junit_diff: loading

def test_load_reads_each_status(tmp_path):
    f = write_junit(tmp_path / "r.xml", [("tests.test_a", "test_ok", "passed"),
                                         ("tests.test_a", "test_bad", "failed"),
                                         ("tests.test_a", "test_err", "error"),
                                         ("tests.test_a", "test_skip", "skipped"),
                                         ("tests.test_a", "test_xf", "xfailed"),
                                         ("", "tests.test_broken", "error")])
    assert junit_diff.load(f) == {"tests.test_a::test_ok": "passed", "tests.test_a::test_bad": "failed",
                                  "tests.test_a::test_err": "error", "tests.test_a::test_skip": "skipped",
                                  "tests.test_a::test_xf": "xfailed", "tests.test_broken": "error"}


def test_load_keeps_the_worst_status_of_a_repeated_key(tmp_path):
    # xdist reports a file's collection error once per worker; a key seen twice keeps its worst status
    f = write_junit(tmp_path / "r.xml", [("t", "a", "passed"), ("t", "a", "error"),
                                         ("t", "b", "error"), ("t", "b", "passed"),
                                         ("t", "c", "skipped"), ("t", "c", "failed"),
                                         ("t", "d", "passed"), ("t", "d", "skipped")])
    assert junit_diff.load(f) == {"t::a": "error", "t::b": "error", "t::c": "failed", "t::d": "skipped"}


def test_load_keeps_the_first_status_of_a_repeated_key_on_a_tie(tmp_path):
    # failed and error rank equal, as do skipped and xfailed: the first one seen stays
    f = write_junit(tmp_path / "r.xml", [("t", "fe", "failed"), ("t", "fe", "error"),
                                         ("t", "ef", "error"), ("t", "ef", "failed"),
                                         ("t", "sx", "skipped"), ("t", "sx", "xfailed"),
                                         ("t", "xs", "xfailed"), ("t", "xs", "skipped")])
    assert junit_diff.load(f) == {"t::fe": "failed", "t::ef": "error", "t::sx": "skipped", "t::xs": "xfailed"}


def test_load_a_testcase_with_several_children_takes_the_failure(tmp_path):
    # a test skipped in its call that then errors in teardown carries both children, in either order
    skip = '<skipped type="pytest.skip" message="needs_tool: x">s</skipped>'
    xfail = '<skipped type="pytest.xfail" message="known-fail: y"/>'
    fail, err = '<failure message="f">f</failure>', '<error message="e">e</error>'
    cases = {"skip_fail": skip + fail, "fail_skip": fail + skip, "skip_err": skip + err,
             "xfail_fail": xfail + fail, "fail_err": fail + err, "err_fail": err + fail, "skip_xfail": skip + xfail}
    body = "".join(f'<testcase classname="t" name="{n}">{inner}</testcase>' for n, inner in cases.items())
    f = tmp_path / "r.xml"
    f.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>", encoding="utf-8")
    assert junit_diff.load(f) == {"t::skip_fail": "failed", "t::fail_skip": "failed", "t::skip_err": "error",
                                  "t::xfail_fail": "failed", "t::fail_err": "failed", "t::err_fail": "error",
                                  "t::skip_xfail": "skipped"}


# --------------------------------------------------------------------------- junit_diff: comparing

OLD = {"t::stays_ok": "passed", "t::breaks": "passed", "t::was_skipped": "skipped", "t::was_xfail": "xfailed",
       "t::still_bad": "failed", "t::gets_fixed": "error", "t::bad_then_skipped": "failed", "t::gone": "passed"}
NEW = {"t::stays_ok": "passed", "t::breaks": "failed", "t::was_skipped": "failed", "t::was_xfail": "error",
       "t::still_bad": "failed", "t::gets_fixed": "passed", "t::bad_then_skipped": "skipped",
       "t::brand_new_error": "error", "t::brand_new_ok": "passed"}


def test_compare_classifies_each_test():
    res = junit_diff.compare(OLD, NEW)
    assert res["newly_bad"] == ["t::brand_new_error", "t::breaks", "t::was_skipped", "t::was_xfail"]
    assert res["fixed"] == ["t::gets_fixed"]                 # bad -> skipped is not fixed
    assert res["known_flaky_failed"] == []
    assert res["added_count"] == 2 and res["removed_count"] == 1 and res["removed"] == ["t::gone"]
    assert sorted(res["added_sample"]) == ["t::brand_new_error", "t::brand_new_ok"]
    assert res["counts_old"] == {"passed": 3, "skipped": 1, "xfailed": 1, "failed": 2, "error": 1}
    assert res["counts_new"] == {"passed": 3, "failed": 3, "error": 2, "skipped": 1}


def test_known_flaky_keys_are_reported_apart(tmp_path):
    flaky_file = tmp_path / "flaky.txt"
    flaky_file.write_text("# load-dependent timing checks\nt::breaks\n\nt::not_in_either\n", encoding="utf-8")
    flaky = junit_diff.load_known_flaky(flaky_file)
    assert flaky == {"t::breaks", "t::not_in_either"}
    res = junit_diff.compare(OLD, NEW, flaky)
    assert res["known_flaky_failed"] == ["t::breaks"]
    assert "t::breaks" not in res["newly_bad"] and "t::was_skipped" in res["newly_bad"]


def test_nodeid_maps_junit_keys_back_to_files(tmp_path):
    make_tree(tmp_path, {"tests/sub/test_x.py": "", "tests/test_y.py": ""})
    assert junit_diff.nodeid("tests.sub.test_x::test_a[1-2]", tmp_path) == "tests/sub/test_x.py::test_a[1-2]"
    assert junit_diff.nodeid("tests.sub.test_x.TestK::test_b", tmp_path) == "tests/sub/test_x.py::TestK::test_b"
    assert junit_diff.nodeid("tests.test_y::realdata", tmp_path) == "tests/test_y.py::realdata"
    assert junit_diff.nodeid("tests.test_broken", tmp_path) is None          # a collection error: no ::
    assert junit_diff.nodeid("tests.test_missing::test_a", tmp_path) is None


def test_classify_isolated_reruns():
    assert junit_diff.classify(0, 3, 3) == "regression"
    assert junit_diff.classify(1, 2, 3) == "passes_alone"
    assert junit_diff.classify(3, 0, 3) == "passes_alone"
    assert junit_diff.classify(0, 2, 3) == "unresolved"      # the third run neither passed nor failed
    assert junit_diff.classify(0, 0, 3) == "unresolved"


@pytest.mark.parametrize("outcome, expect", [
    ("timeout", (0, 0, 3)),           # a rerun that hangs past RERUN_TIMEOUT neither passed nor failed
    (5, (0, 0, 3)),                   # pytest exit 5: no test collected under that node id
    (4, (0, 0, 3)),                   # pytest exit 4: usage error
    (1, (0, 3, 0)),
    (0, (3, 0, 0)),
])
def test_rerun_counts_only_pytest_exit_1_as_a_failure(monkeypatch, tmp_path, outcome, expect):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, outcome, "", "")
    monkeypatch.setattr(junit_diff.subprocess, "run", fake_run)
    assert junit_diff.rerun("tests/test_x.py::test_a", tmp_path, 3, sandbox=False) == expect
    assert len(calls) == 3 and all(kw["timeout"] == junit_diff.RERUN_TIMEOUT and kw["cwd"] == str(tmp_path)
                                   for _, kw in calls)


def test_cli_classes_a_timed_out_rerun_as_unresolved_not_regression(monkeypatch, tmp_path):
    root = make_tree(tmp_path / "co", {"tests/test_r.py": "def test_hangs():\n    pass\n"})
    old = write_junit(tmp_path / "old.xml", [("tests.test_r", "test_hangs", "passed")])
    new = write_junit(tmp_path / "new.xml", [("tests.test_r", "test_hangs", "failed")])

    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
    monkeypatch.setattr(junit_diff.subprocess, "run", fake_run)
    out = tmp_path / "res.json"
    assert junit_diff.main([str(old), str(new), "--rerun-root", str(root), "--rerun", "2", "--no-sandbox",
                            "--json", str(out)]) == 0
    assert json.loads(out.read_text())["rerun"]["tests.test_r::test_hangs"] == {
        "class": "unresolved", "nodeid": "tests/test_r.py::test_hangs", "passes": 0, "fails": 0, "other": 2}


def test_rerun_command_uses_the_suite_sandbox_profile():
    cmd = junit_diff.rerun_command("tests/test_x.py::test_a", python="PY")
    assert cmd[:3] == ["sandbox-exec", "-f", str(REPO / "tools" / "suite.sb")]
    assert cmd[3:] == ["PY", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout", "300",
                       "tests/test_x.py::test_a"]
    assert junit_diff.rerun_command("n", sandbox=False, python="PY")[0] == "PY"


# --------------------------------------------------------------------------- junit_diff: the CLI

RERUN_TREE = {"tests/test_r.py": """
    def test_always_fails():
        assert 1 == 2

    def test_passes_alone():
        assert True
    """}


def test_cli_reruns_each_newly_bad_test_alone(tmp_path, capsys):
    root = make_tree(tmp_path / "co", RERUN_TREE)
    old = write_junit(tmp_path / "old.xml", [("tests.test_r", "test_always_fails", "passed"),
                                             ("tests.test_r", "test_passes_alone", "passed")])
    new = write_junit(tmp_path / "new.xml", [("tests.test_r", "test_always_fails", "failed"),
                                             ("tests.test_r", "test_passes_alone", "failed"),
                                             ("", "tests.test_gone", "error")])
    out = tmp_path / "res.json"
    rc = junit_diff.main([str(old), str(new), "--rerun-root", str(root), "--rerun", "2", "--no-sandbox",
                          "--json", str(out)])
    assert rc == 0
    res = json.loads(out.read_text())
    rr = res["rerun"]
    assert rr["tests.test_r::test_always_fails"] == {"class": "regression", "nodeid": "tests/test_r.py::test_always_fails",
                                                     "passes": 0, "fails": 2, "other": 0}
    assert rr["tests.test_r::test_passes_alone"]["class"] == "passes_alone"
    assert rr["tests.test_r::test_passes_alone"]["passes"] == 2
    assert rr["tests.test_gone"] == {"class": "unresolved", "nodeid": None}
    printed = capsys.readouterr().out
    assert "newly_bad 3" in printed and "NEW BAD tests.test_r::test_always_fails" in printed

    # --fail-on-regression: 1 while a regression (or an unresolved test) is left ...
    assert junit_diff.main([str(old), str(new), "--rerun-root", str(root), "--rerun", "1", "--no-sandbox",
                            "--fail-on-regression"]) == 1
    # ... 0 when every newly bad test passes alone
    only_flaky = write_junit(tmp_path / "flaky.xml", [("tests.test_r", "test_always_fails", "passed"),
                                                      ("tests.test_r", "test_passes_alone", "failed")])
    assert junit_diff.main([str(old), str(only_flaky), "--rerun-root", str(root), "--rerun", "1", "--no-sandbox",
                            "--fail-on-regression"]) == 0


def test_cli_fail_on_regression_without_reruns_counts_every_newly_bad_test(tmp_path):
    old = write_junit(tmp_path / "old.xml", [("t", "a", "passed")])
    same = write_junit(tmp_path / "same.xml", [("t", "a", "passed")])
    worse = write_junit(tmp_path / "worse.xml", [("t", "a", "failed")])
    assert junit_diff.main([str(old), str(same), "--fail-on-regression"]) == 0
    assert junit_diff.main([str(old), str(worse), "--fail-on-regression"]) == 1
    assert junit_diff.main([str(old), str(worse)]) == 0          # report only, by default


def test_cli_prints_fixed_and_removed_tests(tmp_path, capsys):
    old = write_junit(tmp_path / "old.xml", [("t", "fixed_one", "failed"), ("t", "dropped", "passed")])
    new = write_junit(tmp_path / "new.xml", [("t", "fixed_one", "passed")])
    assert junit_diff.main([str(old), str(new)]) == 0
    out = capsys.readouterr().out
    assert "FIXED t::fixed_one" in out and "REMOVED t::dropped" in out and "newly_bad 0" in out


@pytest.mark.parametrize("case", ["missing_old", "bad_xml", "missing_flaky", "bad_rerun_root"])
def test_cli_usage_errors_exit_2_with_a_reason(tmp_path, capsys, case):
    good = write_junit(tmp_path / "good.xml", [("t", "a", "passed")])
    bad = tmp_path / "bad.xml"
    bad.write_text("<testsuites><testcase", encoding="utf-8")
    argv = {"missing_old": [str(tmp_path / "nope.xml"), str(good)],
            "bad_xml": [str(good), str(bad)],
            "missing_flaky": [str(good), str(good), "--known-flaky", str(tmp_path / "nope.txt")],
            "bad_rerun_root": [str(good), str(good), "--rerun-root", str(tmp_path / "nodir")]}[case]
    assert junit_diff.main(argv) == 2
    err = capsys.readouterr().err
    assert err.startswith("junit_diff: ") and ("nope" in err or "bad.xml" in err or "nodir" in err)


# --------------------------------------------------------------------------- suite.py: the import-time exit lint

EXITS_SRC = '''\
import os, sys, pytest
sys.exit(0)
if os.environ.get("X"):
    exit(1)
try:
    import missing_mod
except ImportError:
    raise SystemExit("no module")
for _ in range(1):
    os._exit(3)
class Script:
    quit()
    def method(self):
        sys.exit(9)
pytest.exit("stop")
raise SystemExit
def helper():
    sys.exit(2)
handler = lambda: sys.exit(4)
if __name__ == "__main__":
    sys.exit(5)
else:
    sys.exit(6)
if "__main__" == __name__:
    sys.exit(7)
'''


def test_module_level_exits_finds_every_exit_that_runs_at_import():
    assert suite.module_level_exits(EXITS_SRC) == [
        (2, "sys.exit"), (4, "exit"), (8, "raise SystemExit"), (10, "os._exit"), (12, "quit"),
        (15, "pytest.exit"), (16, "raise SystemExit"), (23, "sys.exit")]


def test_module_level_exits_is_empty_for_a_pytest_module():
    src = "import sys\n\ndef test_a():\n    assert True\n\nif __name__ == '__main__':\n    sys.exit(0)\n"
    assert suite.module_level_exits(src) == []


def test_lint_tests_reports_files_and_skips_folders_whose_conftest_collects_them(tmp_path):
    make_tree(tmp_path, {
        "tests/test_bad.py": "import sys\nsys.exit(0)\n",
        "tests/test_ok.py": "def test_a():\n    assert True\n",
        "tests/helper_script.py": "import sys\nsys.exit(1)\n",          # not a test file: never collected
        "tests/test_syntax.py": "def (:\n",                             # a collection error, not an abort
        "tests/real/conftest.py": "def pytest_pycollect_makemodule(module_path, parent):\n    return None\n",
        "tests/real/test_script.py": "import sys\nsys.exit(1)\n",
        "tests/deep/test_nested.py": "raise SystemExit(3)\n",
    })
    assert suite.lint_tests(tmp_path / "tests") == ["tests/deep/test_nested.py:1: raise SystemExit at import",
                                                    "tests/test_bad.py:2: sys.exit at import"]


def test_no_repo_test_file_exits_at_import():
    """The bare `python -m pytest` aborted at collection (INTERNALERROR) while any tests/ file did this."""
    assert suite.lint_tests(REPO / "tests") == []


@pytest.mark.parametrize("name", ["test_adapt_pool_queue.py", "test_ladder_set_share.py"])
def test_game_master_runner_tests_collect_and_run_without_the_archived_modules(name):
    """These two files used to fail collection on every full run (timed_ladder.py needs the archived Game
    Master modules, B-005), then reported every test not run. B-036 carried the set pool into
    ctf/adapt/setpool.py, so they now run and pass without those modules: no error, no skip, no not-run."""
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider", f"tests/{name}"],
                       capture_output=True, text=True, cwd=str(REPO), timeout=300)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-3000:]
    assert "error" not in out.lower(), out[-3000:]
    assert re.search(r"[1-9]\d* passed", out), out[-3000:]
    assert re.search(r"\d+ skipped", out) is None and "NOT RUN:" not in out, out[-3000:]
    src = (REPO / "tests" / name).read_text()
    assert re.search(r"^\s*(import|from)\s+timed_ladder\b", src, re.M) is None, "imports the archived runner"
    assert "needs_tool(" not in src, "still marked as needing the archived Game Master modules"


def test_no_conftest_hides_test_files_and_no_script_runs_at_import():
    r = subprocess.run([sys.executable, str(REPO / "tools" / "test_audit.py"), "--rule", "not-collected",
                        "--rule", "import-time-run", "--json", str(REPO / "tests")],
                       capture_output=True, text=True, cwd=str(REPO), timeout=600)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert json.loads(r.stdout)["findings"] == []


# --------------------------------------------------------------------------- suite.py: the command

def test_build_command_reproduces_the_baseline_recipe(tmp_path):
    j = tmp_path / "out.xml"
    cmd = suite.build_command(j, python="PY")
    assert cmd[:3] == ["sandbox-exec", "-f", str(REPO / "tools" / "suite.sb")]
    assert cmd[3:6] == ["PY", "-m", "pytest"]
    for pair in (["-n", "8"], ["--timeout", "300"], ["-p", "no:cacheprovider"]):
        i = cmd.index(pair[0])
        assert cmd[i:i + 2] == pair
    assert "--continue-on-collection-errors" in cmd and f"--junitxml={j}" in cmd
    alt = suite.build_command(j, workers=3, sandbox=False, extra=["tests/test_x.py", "-k", "y"], python="PY")
    assert alt[0] == "PY" and "sandbox-exec" not in alt
    assert alt[alt.index("-n") + 1] == "3" and alt[-3:] == ["tests/test_x.py", "-k", "y"]


def test_suite_profile_denies_outbound_network_except_loopback():
    text = (REPO / "tools" / "suite.sb").read_text()
    assert "(deny network-outbound)" in text
    assert '(allow network-outbound (remote ip "localhost:*"))' in text


def test_main_refuses_a_tree_with_an_import_time_exit(tmp_path, capsys):
    repo = make_tree(tmp_path / "repo", {"tests/test_bad.py": "import sys\nsys.exit(1)\n"})
    j = tmp_path / "out.xml"
    assert suite.main(["--no-sandbox", "-n", "0", "--junit", str(j)], repo=repo) == 2
    err = capsys.readouterr().err
    assert "refusing to run" in err and "tests/test_bad.py:2: sys.exit at import" in err
    assert not j.exists()                                    # pytest never started


def test_main_without_sandbox_exec_fails_loudly(tmp_path, capsys, monkeypatch):
    repo = make_tree(tmp_path / "repo", {"tests/test_ok.py": "def test_a():\n    assert True\n"})
    monkeypatch.setattr(suite.shutil, "which", lambda name: None)
    j = tmp_path / "out.xml"
    assert suite.main(["--junit", str(j)], repo=repo) == 2
    assert "pass --no-sandbox" in capsys.readouterr().err
    assert not j.exists()


def test_main_without_the_sandbox_profile_fails_loudly(tmp_path, capsys, monkeypatch):
    repo = make_tree(tmp_path / "repo", {"tests/test_ok.py": "def test_a():\n    assert True\n"})
    missing = tmp_path / "gone" / "suite.sb"
    monkeypatch.setattr(suite, "PROFILE", missing)
    monkeypatch.setattr(suite.shutil, "which", lambda name: "/usr/bin/" + name)   # sandbox-exec "present"
    started = []
    monkeypatch.setattr(suite.subprocess, "call", lambda *a, **k: started.append(a) or 0)
    j = tmp_path / "out.xml"
    assert suite.main(["-n", "0", "--junit", str(j)], repo=repo) == 2
    assert f"sandbox profile {missing} is missing" in capsys.readouterr().err
    assert started == [] and not j.exists()                  # pytest never started
    # --no-sandbox needs no profile
    assert suite.main(["--no-sandbox", "-n", "0", "--junit", str(j)], repo=repo) == 0 and len(started) == 1


def test_main_without_a_pytest_plugin_fails_loudly(tmp_path, capsys, monkeypatch):
    repo = make_tree(tmp_path / "repo", {"tests/test_ok.py": "def test_a():\n    assert True\n"})
    real = suite.importlib.util.find_spec
    monkeypatch.setattr(suite.importlib.util, "find_spec", lambda m: None if m == "xdist" else real(m))
    assert suite.main(["--no-sandbox", "--junit", str(tmp_path / "o.xml")], repo=repo) == 2
    assert "pytest-xdist" in capsys.readouterr().err
    # -n 0 needs no xdist
    assert suite.main(["--no-sandbox", "-n", "0", "--junit", str(tmp_path / "o.xml")], repo=repo) == 0


def test_main_rejects_a_negative_worker_count(tmp_path):
    assert suite.main(["-n", "-1", "--no-sandbox"], repo=tmp_path) == 2


@pytest.mark.parametrize("workers", ["0", "2"])
def test_main_runs_pytest_and_writes_junit(tmp_path, workers):
    repo = make_tree(tmp_path / "repo", {"tests/test_s.py": """
        import time

        def test_pass():
            assert True

        def test_fail():
            assert 1 == 2
        """})
    j = tmp_path / "out" / "suite.xml"                      # the folder is created
    rc = suite.main(["--no-sandbox", "-n", workers, "--junit", str(j)], repo=repo)
    assert rc == 1                                           # pytest's own exit status: a test failed
    got = junit_diff.load(j)
    assert sorted((k.rsplit("::", 1)[1], v) for k, v in got.items()) == [("test_fail", "failed"),
                                                                        ("test_pass", "passed")]


@pytest.mark.needs_tool("sandbox-exec")
def test_suite_sandbox_blocks_outbound_but_not_loopback(tmp_path):
    """Run a child under tools/suite.sb: it reaches a listener on 127.0.0.1 and is refused (EPERM) on a
    TEST-NET-1 documentation address, which no real host owns. Seatbelt does not nest: inside another
    sandbox-exec (the suite's own) the profile cannot be applied and this is reported not run."""
    probe = textwrap.dedent("""
        import errno, json, socket
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        res = {}
        c = socket.create_connection(srv.getsockname(), timeout=5); c.close(); res["loopback"] = "ok"
        try:
            socket.create_connection(("192.0.2.1", 9), timeout=3).close(); res["outbound"] = "connected"
        except OSError as e:
            res["outbound"] = errno.errorcode.get(e.errno, str(e))
        print(json.dumps(res))
        """)
    r = subprocess.run(["sandbox-exec", "-f", str(REPO / "tools" / "suite.sb"), sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=60)
    if "sandbox_apply" in r.stderr and "Operation not permitted" in r.stderr:
        pytest.skip("already inside a sandbox-exec sandbox (Seatbelt does not nest): run outside it to check")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"loopback": "ok", "outbound": "EPERM"}


def test_runner_documented_in_building_md():
    text = (REPO / "docs" / "BUILDING.md").read_text()
    for needle in ("tools/suite.py", "tools/junit_diff.py", "--no-sandbox", "--rerun-root", "tools/suite.sb"):
        assert needle in text, needle
