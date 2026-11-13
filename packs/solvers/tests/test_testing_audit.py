"""B-001d: tools/test_audit.py finds tests that do not test, on a suite planted in a temp dir, and
leaves real tests alone."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import paths

AUDIT = paths.repo_root() / "tools" / "test_audit.py"
sys.path.insert(0, str(AUDIT.parent))
import test_audit  # noqa: E402

HOLLOW = textwrap.dedent('''\
    import sys
    from unittest import mock

    FAILS = []          # not a guarded sink name? it is: FAILS is guarded


    def check(label, ok):
        print(("ok " if ok else "FAIL ") + label)


    def main():
        return 0


    def submit(flag):
        return "sent"


    def test_empty():
        pass


    def test_docstring_only():
        """nothing here"""


    def test_only_main():
        main()


    def test_no_assert():
        x = 1 + 1


    def test_records_only():
        check("two is two", 1 + 1 == 3)


    def test_assert_true():
        assert True


    def test_assert_tuple():
        x = 3
        assert (x == 4, "x should be four")


    def test_submit_mocked():
        with mock.patch("test_hollow.submit") as submit_mock:
            submit("CTF{x}")
            submit_mock.assert_called_once()


    def test_returns_when_tool_missing():
        import shutil
        if shutil.which("no-such-tool-xyz") is None:
            return
        assert shutil.which("no-such-tool-xyz")


    def test_swallowed():
        try:
            assert 1 == 2
        except Exception:
            pass


    class TestGrouped:
        def test_method_empty(self):
            ...
    ''')

GOOD = textwrap.dedent('''\
    import pytest
    import subprocess

    FAILED = []


    def guarded_check(label, ok):
        if not ok:
            FAILED.append(label)


    def asserting_helper(x):
        assert x == 2


    class DecodeError(Exception):
        pass


    def parse(b):
        raise DecodeError("bad")


    @pytest.fixture
    def thing():
        return 2


    def test_plain_assert(thing):
        assert thing == 2


    def test_raises():
        with pytest.raises(ZeroDivisionError):
            1 / 0


    def test_helper_that_asserts():
        asserting_helper(2)


    def test_check_feeding_a_guarded_sink():
        guarded_check("two", 1 + 1 == 2)


    def test_declared_error_contract():
        for b in (b"", b"x"):
            try:
                parse(b)
            except DecodeError:
                pass


    def test_subprocess_check_true():
        subprocess.run(["true"], check=True)


    def test_mock_used_for_a_collaborator():
        from unittest import mock
        with mock.patch("os.getcwd") as cwd:
            cwd.return_value = "/x"
            import os
            assert os.getcwd() == "/x"


    def test_assert_main_result():
        assert int("0") == 0
    ''')


def plant(tmp_path: Path, **files: str) -> Path:
    d = tmp_path / "suite"
    d.mkdir(exist_ok=True)
    for name, body in files.items():
        (d / name).write_text(body)
    return d


def rules_by_test(findings):
    out: dict[str, set] = {}
    for f in findings:
        out.setdefault(f.test, set()).add(f.rule)
    return out


def test_every_planted_hollow_test_is_caught(tmp_path):
    d = plant(tmp_path, **{"test_hollow.py": HOLLOW})
    findings, notes, errors = test_audit.audit([d])
    assert not errors
    got = rules_by_test(findings)
    want = {
        "test_empty": "empty-body",
        "test_docstring_only": "empty-body",
        "test_only_main": "only-main",
        "test_no_assert": "no-assert",
        "test_records_only": "records-only",
        "test_assert_true": "assert-constant",
        "test_assert_tuple": "assert-tuple",
        "test_submit_mocked": "mock-of-unit",
        "test_returns_when_tool_missing": "return-as-skip",
        "test_swallowed": "swallowed-assert",
        "TestGrouped.test_method_empty": "empty-body",
    }
    for test, rule in want.items():
        assert rule in got.get(test, set()), (test, rule, got.get(test))


def test_real_tests_are_not_flagged(tmp_path):
    d = plant(tmp_path, **{"test_good.py": GOOD})
    findings, notes, errors = test_audit.audit([d])
    assert not errors
    assert findings == [], [f.text() for f in findings]


def test_check_feeding_an_unguarded_list_is_records_only(tmp_path):
    body = textwrap.dedent('''\
        PROBLEMS = []

        def check(label, ok):
            if not ok:
                PROBLEMS.append(label)

        def test_x():
            check("one", 1 == 2)
        ''')
    findings, _, _ = test_audit.audit([plant(tmp_path, **{"test_unguarded.py": body})])
    assert [(f.test, f.rule) for f in findings] == [("test_x", "records-only")]


def test_helper_imported_from_a_sibling_module_is_resolved(tmp_path):
    d = plant(tmp_path, **{
        "helpers_x.py": "def must_equal(a, b):\n    assert a == b\n\ndef note(a):\n    print('FAIL', a)\n",
        "test_uses_helpers.py": ("from helpers_x import must_equal, note\n\n"
                                 "def test_good():\n    must_equal(1, 1)\n\n"
                                 "def test_hollow():\n    note(1)\n"),
    })
    findings, _, _ = test_audit.audit([d])
    assert [(f.test, f.rule) for f in findings] == [("test_hollow", "records-only")]


def test_collect_ignored_and_import_time_runs_are_file_findings(tmp_path):
    d = plant(tmp_path, **{
        "conftest.py": 'collect_ignore = ["test_script.py"]\n',
        "test_script.py": "print('runs by hand')\n",
        "test_runs_at_import.py": ("import sys\nFAILED = []\n\ndef test_a():\n    assert len(FAILED) == 0\n\n"
                                   "for t in (test_a,):\n    t()\nif FAILED:\n    sys.exit(1)\n"),
        "test_guarded_main.py": ("import sys\n\ndef test_a():\n    assert sys.version_info > (3,)\n\n"
                                 "if __name__ == '__main__':\n    test_a()\n    sys.exit(0)\n"),
    })
    findings, _, _ = test_audit.audit([d])
    got = {(Path(f.path).name, f.rule) for f in findings}
    assert ("test_script.py", "not-collected") in got
    assert ("test_runs_at_import.py", "import-time-run") in got
    assert not any(name == "test_guarded_main.py" for name, _ in got), got


def test_a_folder_whose_conftest_collects_itself_is_skipped_with_a_note(tmp_path):
    d = plant(tmp_path, **{
        "conftest.py": "def pytest_pycollect_makemodule(module_path, parent):\n    return None\n",
        "test_script_style.py": "def test_x():\n    pass\n",
    })
    findings, notes, _ = test_audit.audit([d])
    assert findings == []
    assert len(notes) == 1 and "collects the test files itself" in notes[0]


def run_cli(*args, cwd):
    return subprocess.run([sys.executable, str(AUDIT), *map(str, args)], cwd=cwd,
                          capture_output=True, text=True, timeout=120)


def test_cli_exit_codes_and_json(tmp_path):
    hollow = plant(tmp_path, **{"test_hollow.py": HOLLOW})
    r = run_cli(hollow, cwd=tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "test_hollow.py" in r.stdout and "empty-body" in r.stdout and "finding(s)" in r.stdout
    r = run_cli(hollow, "--json", cwd=tmp_path)
    data = json.loads(r.stdout)
    assert {f["rule"] for f in data["findings"]} >= {"empty-body", "no-assert", "mock-of-unit"}

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "test_good.py").write_text(GOOD)
    r = run_cli(clean, cwd=tmp_path)
    assert r.returncode == 0 and "0 finding(s)" in r.stdout, r.stdout + r.stderr

    assert run_cli(tmp_path / "missing", cwd=tmp_path).returncode == 2
    (clean / "test_broken.py").write_text("def test_x(:\n")
    r = run_cli(clean, cwd=tmp_path)
    assert r.returncode == 2 and "does not parse" in r.stderr


def test_rule_filter(tmp_path):
    hollow = plant(tmp_path, **{"test_hollow.py": HOLLOW})
    r = run_cli(hollow, "--rule", "assert-tuple", "--json", cwd=tmp_path)
    assert {f["rule"] for f in json.loads(r.stdout)["findings"]} == {"assert-tuple"}


@pytest.mark.slow
def test_the_repo_suite_has_no_hollow_test_in_the_load_bearing_files():
    """The files B-001d fixed stay fixed: routing (fast lane), the carried Huntress crypto and web
    toolkits that ran at import, and this unit's own tests."""
    tests = paths.repo_root() / "tests"
    files = [tests / n for n in (
        "test_fastlane.py", "test_day26_aead_dsa.py", "test_day26_aes_modes.py", "test_day26_crypto_depth.py",
        "test_tk_osint_breadth.py", "test_tk_flask_tools.py", "test_tk_werkzeug_pin.py", "test_web_flask_forge.py",
        "test_testing_audit.py", "test_testing_notrun_report.py", "test_testing_real_runner.py",
        "test_contracts_markers.py")]
    findings, _, errors = test_audit.audit(files)
    assert not errors
    assert findings == [], [f.text() for f in findings]
