"""B-001 contracts: the test markers plugin (ctf.testing.pytest_plugin), run on a synthetic suite in a
child pytest so its skip/summary behaviour is observed, not assumed."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from ctf import paths

SUITE = textwrap.dedent("""\
    import pytest

    @pytest.mark.needs_tool("sh")
    def test_has_sh():
        pass

    @pytest.mark.needs_tool("definitely-not-a-tool-xyz")
    def test_missing_tool():
        raise AssertionError("must not run")

    @pytest.mark.needs_tool("py:json")
    def test_has_py_module():
        pass

    @pytest.mark.needs_tool("py:no_such_module_xyz")
    def test_missing_py_module():
        raise AssertionError("must not run")

    @pytest.mark.needs_realdata
    def test_realdata_root():
        pass

    @pytest.mark.needs_realdata("sub")
    def test_realdata_sub():
        pass

    @pytest.mark.live
    def test_live():
        pass

    @pytest.mark.slow
    def test_slow():
        pass

    def test_plain_skip():
        pytest.skip("hand-written reason")
    """)


def run_child(tmp_path, *args, realdata=None, extra_env=None):
    (tmp_path / "test_synth.py").write_text(SUITE)
    env = {k: v for k, v in os.environ.items()
           if k not in ("CTF_RUN_LIVE", "HUNTRESS_RUN_LIVE", "CSCTF_RUN_LIVE", "PYTEST_ADDOPTS")}
    env["PYTHONPATH"] = str(paths.repo_root())
    env["CTF_REALDATA"] = str(realdata or tmp_path / "no-realdata")
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                        "-p", "ctf.testing.pytest_plugin", "-o", "addopts=", "--rootdir", str(tmp_path),
                        str(tmp_path / "test_synth.py"), *args],
                       cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def summary(out):
    assert "NOT RUN:" in out, out
    return out.split("NOT RUN:", 1)[1]


def test_absent_dependencies_are_not_run_and_listed(tmp_path):
    code, out = run_child(tmp_path)
    assert code == 0, out
    assert "3 passed, 6 skipped" in out
    s = summary(out)
    assert "6 test(s) did not run" in s
    assert "needs_tool: definitely-not-a-tool-xyz not available" in s
    assert "needs_tool: py:no_such_module_xyz not available" in s
    assert "needs_realdata:" in s and "set CTF_REALDATA" in s
    assert "live: not run by default (pass --run-live)" in s
    assert "hand-written reason" in s
    for name in ("test_missing_tool", "test_missing_py_module", "test_realdata_root",
                 "test_realdata_sub", "test_live", "test_plain_skip"):
        assert f"test_synth.py::{name}" in s
    for name in ("test_has_sh", "test_has_py_module", "test_slow"):
        assert f"test_synth.py::{name}" not in s


def test_realdata_present_and_live_opt_in(tmp_path):
    rd = tmp_path / "rd"
    (rd / "sub").mkdir(parents=True)
    code, out = run_child(tmp_path, "--run-live", realdata=rd)
    assert code == 0, out
    assert "6 passed, 3 skipped" in out
    s = summary(out)
    assert "test_realdata_root" not in s and "test_live" not in s


def test_live_opt_in_by_env(tmp_path):
    code, out = run_child(tmp_path, "-k", "live", extra_env={"CTF_RUN_LIVE": "1"})
    assert code == 0 and "1 passed" in out, out


def test_slow_is_deselectable(tmp_path):
    code, out = run_child(tmp_path, "-m", "slow")
    assert code == 0 and "1 passed" in out, out


@pytest.mark.needs_tool("py:xdist")
def test_summary_survives_xdist(tmp_path):
    code, out = run_child(tmp_path, "-n", "2")
    assert code == 0, out
    s = summary(out)
    assert "6 test(s) did not run" in s and "test_synth.py::test_live" in s


def test_needs_tool_without_a_name_is_a_usage_error(tmp_path):
    (tmp_path / "test_bad.py").write_text("import pytest\n@pytest.mark.needs_tool\ndef test_x(): pass\n")
    env = dict(os.environ, PYTHONPATH=str(paths.repo_root()))
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p",
                        "ctf.testing.pytest_plugin", "--rootdir", str(tmp_path), str(tmp_path / "test_bad.py")],
                       cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode != 0 and "needs_tool needs at least one tool name" in r.stdout + r.stderr
