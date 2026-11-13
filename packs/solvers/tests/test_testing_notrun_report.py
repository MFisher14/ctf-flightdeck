"""B-001d: the end-of-run NOT RUN report is complete and loud, CTF_STRICT_TESTS=1 fails a partly-run
suite, several needs_realdata marks all apply, the failure-sink guard turns a non-raising check() into
a failure, and tests/known_failures.toml keeps exposed failures listed without hiding new ones. Each
case runs a synthetic suite in a child pytest, so the behaviour is observed, not assumed."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import paths

SUITE = textwrap.dedent("""\
    import pytest

    def test_runs():
        assert 1 + 1 == 2

    @pytest.mark.needs_tool("definitely-not-a-tool-xyz")
    def test_missing_tool():
        raise AssertionError("must not run")

    @pytest.mark.needs_realdata("kit_a")
    @pytest.mark.needs_realdata("kit_b")
    def test_two_kits():
        pass

    @pytest.mark.live
    def test_live():
        pass

    def test_hand_skip():
        pytest.skip("hand-written reason")
    """)


def run_child(tmp_path: Path, files: dict, *args, env=None):
    tests = tmp_path / "tests"
    tests.mkdir(exist_ok=True)
    for name, body in files.items():
        (tests / name).write_text(body)
    e = {k: v for k, v in os.environ.items()
         if k not in ("CTF_RUN_LIVE", "HUNTRESS_RUN_LIVE", "CSCTF_RUN_LIVE", "PYTEST_ADDOPTS", "CTF_STRICT_TESTS",
                      "HUNTRESS_STRICT_TESTS", "CSCTF_STRICT_TESTS")}
    e["PYTHONPATH"] = str(paths.repo_root())
    e.setdefault("CTF_REALDATA", str(tmp_path / "no-realdata"))
    e.update(env or {})
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p",
                        "ctf.testing.pytest_plugin", "-o", "addopts=", "--rootdir", str(tmp_path), "tests", *args],
                       cwd=tmp_path, env=e, capture_output=True, text=True, timeout=180)
    return r.returncode, r.stdout + r.stderr


def report(out: str) -> str:
    assert "NOT RUN:" in out, out
    return out.split("NOT RUN:", 1)[1]


def test_report_counts_each_kind_and_lists_every_test(tmp_path):
    code, out = run_child(tmp_path, {"test_synth.py": SUITE})
    assert code == 0, out
    s = report(out)
    assert "4 test(s) did not run (needs_realdata 1, needs_tool 1, live 1, skip 1)" in s
    for name in ("test_missing_tool", "test_two_kits", "test_live", "test_hand_skip"):
        assert f"tests/test_synth.py::{name}" in s
    assert "test_synth.py::test_runs" not in s
    assert "Set CTF_STRICT_TESTS=1" in s


def test_strict_mode_fails_a_partly_run_suite(tmp_path):
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, env={"CTF_STRICT_TESTS": "1"})
    assert code == 1, out
    assert "CTF_STRICT_TESTS: 4 test(s) did not run, so this run fails (exit 1)" in out
    assert "1 passed, 4 skipped" in out


def test_strict_flag_works_like_the_env(tmp_path):
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "--strict-not-run")
    assert code == 1, out


def test_strict_mode_passes_when_everything_ran(tmp_path):
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "-k", "test_runs", env={"CTF_STRICT_TESTS": "1"})
    assert code == 0, out
    assert "NOT RUN:" not in out


def test_strict_mode_does_not_hide_a_real_failure_code(tmp_path):
    body = SUITE + "\ndef test_fails():\n    assert 1 == 2\n"
    code, out = run_child(tmp_path, {"test_synth.py": body}, env={"CTF_STRICT_TESTS": "1"})
    assert code == 1 and "1 failed" in out, out


@pytest.mark.needs_tool("py:xdist")
def test_strict_mode_under_xdist(tmp_path):
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "-n", "2", env={"CTF_STRICT_TESTS": "1"})
    assert code == 1, out
    assert "4 test(s) did not run" in report(out)


def test_every_needs_realdata_mark_must_be_present(tmp_path):
    rd = tmp_path / "rd"
    (rd / "kit_a").mkdir(parents=True)
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "-k", "two_kits", env={"CTF_REALDATA": str(rd)})
    assert code == 0, out
    assert "needs_realdata: kit_b not present under" in report(out)
    (rd / "kit_b").mkdir()
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "-k", "two_kits", env={"CTF_REALDATA": str(rd)})
    assert code == 0 and "1 passed" in out and "NOT RUN:" not in out, out


def test_an_empty_corpus_root_is_named_as_empty(tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    code, out = run_child(tmp_path, {"test_synth.py": SUITE}, "-k", "two_kits", env={"CTF_REALDATA": str(rd)})
    assert f"needs_realdata: {rd.resolve()} is empty (set CTF_REALDATA)" in report(out), out


def test_a_test_can_report_parts_of_itself_as_not_run(tmp_path):
    body = textwrap.dedent("""\
        from ctf.testing.pytest_plugin import record_not_run

        def test_partial(request):
            record_not_run(request.node, "group b", "known-fail: engine regression X")
            record_not_run(request.node, "group c", "known-fail: engine regression X")
            assert True is not False
        """)
    code, out = run_child(tmp_path, {"test_part.py": body})
    assert code == 0 and "1 passed" in out, out
    s = report(out)
    assert "2 test(s) did not run (known-fail 2)" in s
    assert "2 x known-fail: engine regression X" in s
    assert "tests/test_part.py::test_partial [group b]" in s
    code, out = run_child(tmp_path, {"test_part.py": body}, env={"CTF_STRICT_TESTS": "1"})
    assert code == 1, out


SINKS = textwrap.dedent("""\
    FAILED = []
    FAIL = 0
    RESULTS = []

    def check(label, ok):
        print(("ok   " if ok else "FAIL ") + label)
        if not ok:
            FAILED.append(label)

    def count(ok):
        global FAIL
        if not ok:
            FAIL += 1

    def test_list_sink_failure():
        check("two plus two is five", 2 + 2 == 5)

    def test_list_sink_pass():
        check("two plus two is four", 2 + 2 == 4)

    def test_counter_sink_failure():
        count(False)

    def test_bool_sink_failure():
        RESULTS.append(False)

    def test_bool_sink_pass():
        RESULTS.append(True)
    """)


def test_failure_sink_guard_fails_a_check_that_never_raised(tmp_path):
    code, out = run_child(tmp_path, {"test_sinks.py": SINKS}, "-rf")
    assert code == 1, out
    assert "3 failed, 2 passed" in out
    assert "FAILED: two plus two is five" in out
    assert "FAIL: counter rose by 1" in out
    assert "RESULTS: 1 failed check(s)" in out
    for name in ("test_list_sink_failure", "test_counter_sink_failure", "test_bool_sink_failure"):
        assert f"FAILED tests/test_sinks.py::{name}" in out


def known(tmp_path, text):
    tests = tmp_path / "tests"
    tests.mkdir(exist_ok=True)
    (tests / "known_failures.toml").write_text(textwrap.dedent(text))


KNOWN_SUITE = textwrap.dedent("""\
    FAILED = []

    def check(label, ok):
        if not ok:
            FAILED.append(label)

    def test_known():
        check("engine answers 42 in 0.13 s", False)

    def test_known_plus_new():
        check("engine answers 42 in 0.13 s", False)
        check("a new regression", False)

    def test_listed_but_fixed():
        check("engine answers 42", True)

    def test_flaky_listed_passes():
        check("sometimes", True)
    """)


def test_known_failures_registry(tmp_path):
    known(tmp_path, """\
        ["tests/test_known.py::test_known"]
        reason = "engine regression owned by lane X"
        checks = ["engine answers 42 in 9.99 s"]

        ["tests/test_known.py::test_known_plus_new"]
        reason = "engine regression owned by lane X"
        checks = ["engine answers 42 in 0.13 s"]

        ["tests/test_known.py::test_listed_but_fixed"]
        reason = "was broken"

        ["tests/test_known.py::test_flaky_listed_passes"]
        reason = "order-dependent"
        strict = false
        """)
    code, out = run_child(tmp_path, {"test_known.py": KNOWN_SUITE}, "-rfx")
    assert code == 1, out
    # numbers are normalised: 0.13 s matches the listed 9.99 s
    assert "XFAIL tests/test_known.py::test_known - known-fail: engine regression owned by lane X" in out
    assert "FAILED tests/test_known.py::test_known_plus_new" in out and "FAILED: a new regression" in out
    assert "FAILED tests/test_known.py::test_listed_but_fixed" in out and "remove the entry" in out
    assert "2 failed, 1 passed, 1 xfailed" in out
    s = report(out)
    assert "known-fail 1" in s and "tests/test_known.py::test_known" in s


def test_a_malformed_registry_entry_is_a_usage_error(tmp_path):
    known(tmp_path, """\
        ["tests/test_known.py::test_known"]
        checks = ["x"]
        """)
    code, out = run_child(tmp_path, {"test_known.py": KNOWN_SUITE})
    assert code != 0 and "needs a non-empty reason" in out, out


def test_the_repo_registry_parses_and_names_real_tests():
    """Every entry of tests/known_failures.toml has a reason and points at an existing test function."""
    import tomllib
    reg = tomllib.loads((paths.repo_root() / "tests" / "known_failures.toml").read_text())
    assert reg, "the registry is empty: delete the file instead"
    for nodeid, entry in reg.items():
        assert entry.get("reason"), nodeid
        path, _, func = nodeid.partition("::")
        src = (paths.repo_root() / path).read_text()
        assert f"def {func.split('[')[0]}(" in src, nodeid
