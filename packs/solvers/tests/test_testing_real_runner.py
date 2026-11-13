"""B-001d: the real-data runner (tests/real/conftest.py). Its verdict on a script's output, the
secret scrub, that every script is registered, and the acceptance: with CTF_REALDATA at an empty folder
every real-data item is reported as not run (and a strict run fails), while the corpus-free checks
still run and pass."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import paths

REAL = paths.repo_root() / "tests" / "real"
_spec = importlib.util.spec_from_file_location("real_conftest_under_test", REAL / "conftest.py")
R = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = R            # dataclasses look their module up in sys.modules
_spec.loader.exec_module(R)

SPEC = R.Script(kits=("kit",), known_fail=((r"slow thing: .* s CPU", "engine regression: slow"),))


def test_clean_run_has_no_problems():
    v = R.verdict(SPEC, "realdata", 0, "ok   a\nok   b\n")
    assert v["problems"] == [] and v["ok"] == 2 and v["known"] == [] and v["new"] == []


def test_a_new_fail_line_is_a_problem_and_a_known_one_is_not():
    out = "ok   a\nFAIL slow thing: 3.1 s CPU (limit 2 s)\n"
    v = R.verdict(SPEC, "realdata", 1, out)
    assert v["problems"] == [] and [r for _, r in v["known"]] == ["engine regression: slow"]
    v = R.verdict(SPEC, "realdata", 1, out + "FAIL wrong answer  [detail]\n")
    assert v["problems"] == ["1 check(s) FAILED"] and v["new"] == ["wrong answer  [detail]"]


def test_skip_lines_fail_a_realdata_run_but_not_a_synthetic_one():
    out = "ok   a\nSKIP group x: no cache\n"
    assert any("SKIPped" in p for p in R.verdict(SPEC, "realdata", 0, out)["problems"])
    assert R.verdict(SPEC, "synthetic", 0, out)["problems"] == []


def test_exit_code_must_agree_with_the_fail_lines():
    assert any("does not match" in p for p in R.verdict(SPEC, "realdata", 1, "ok   a\n")["problems"])
    assert any("does not match" in p for p in R.verdict(SPEC, "realdata", 2, "ok   a\n")["problems"])
    assert any("does not match" in p for p in R.verdict(SPEC, "realdata", 0, "ok   a\nFAIL slow thing: 3 s CPU\n")["problems"])


def test_a_run_with_no_check_is_a_problem():
    assert "no check ran (0 ok lines)" in R.verdict(SPEC, "synthetic", 0, "SKIP everything\n")["problems"]


def test_a_live_run_whose_sandbox_was_down_is_a_problem():
    v = R.verdict(SPEC, "live", 0, "ok   a\nNOTE sandbox down: the live tshark comparison did not run\n")
    assert any("live comparison did not run" in p for p in v["problems"])


def test_scrub_redacts_key_shaped_values():
    key = "AKIA" + "ABCDEFGHIJKLMNOP"          # built at run time: no key-shaped literal in the repo
    out = R.scrub(f"answer was {key} and ok")
    assert key not in out and "AKIA<redacted>" in out


def test_every_script_in_tests_real_is_registered_with_known_kits():
    scripts = {p.name for p in REAL.glob("test_*.py")}
    assert scripts == set(R.SCRIPTS), (scripts ^ set(R.SCRIPTS))
    for name, spec in R.SCRIPTS.items():
        assert spec.kits or spec.synthetic, name           # every script yields at least one item
        if spec.live:
            assert spec.kits, name


def run_real(env_extra, *args):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "CTF_STRICT_TESTS", "CTF_RUN_LIVE")}
    env.update(env_extra)
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                        str(REAL), *args], cwd=paths.repo_root(), env=env, capture_output=True, text=True,
                       timeout=280)
    return r.returncode, r.stdout + r.stderr


@pytest.mark.slow
def test_empty_corpus_reports_every_realdata_item_as_not_run(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out = run_real({"CTF_REALDATA": str(empty)})
    assert code == 0, out[-3000:]
    n_real = sum(1 for s in R.SCRIPTS.values() if s.kits)
    n_syn = sum(1 for s in R.SCRIPTS.values() if s.synthetic or not s.kits)
    n_live = sum(1 for s in R.SCRIPTS.values() if s.live)
    assert f"{n_syn} passed, {n_real + n_live} skipped" in out, out[-2000:]
    report = out.split("NOT RUN:", 1)[1]
    # the live items need the corpus too, and that is checked first
    assert f"{n_real + n_live} x needs_realdata: {empty.resolve()} is empty (set CTF_REALDATA)" in report
    code, out = run_real({"CTF_REALDATA": str(empty), "CTF_STRICT_TESTS": "1"})
    assert code == 1 and "CTF_STRICT_TESTS:" in out, out[-2000:]


@pytest.mark.needs_realdata("nix_host")
def test_a_realdata_item_runs_green_on_the_corpus():
    code, out = run_real({"CTF_REALDATA": str(paths.realdata_root())}, "-k", "nix_host and realdata", "-rA")
    assert code == 0 and "1 passed" in out, out[-3000:]
