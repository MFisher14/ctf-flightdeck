"""R-05: every carried check with a saved-attempts section reads it through ctf.paths and is never green
when the saved past-event attempts are absent.

The saved attempts come only from ctf.paths.saved_challenges_root() ($CTF_REAL_CHALLENGES): None when unset,
FileNotFoundError when set to a missing folder. Two kinds of carrier exist:

  * pytest modules (R-01 converted the old check scripts): the saved section is its own test, which
    `pytest.skip("not run: CTF_REAL_CHALLENGES is not set ...")` when the variable is unset (so it is in the
    suite's NOT RUN report) and fails with the FileNotFoundError when it names a missing folder. This file
    runs each module's saved test in a child pytest in three states (unset, set to a missing folder, set to
    an empty folder) and checks exactly that, so a module that went back to os.environ (a typo reads as
    "no saved attempts") or swallowed the missing folder fails here.
  * uncollected check scripts (solvers/, outside pytest.ini testpaths; Huntress check()-style: one
    `ok` / `FAIL` / `SKIP` line per check, exit 1 on a failure): each runs in a child Python and its output
    is judged. Unset: it must say `SKIP <section>: not run: CTF_REAL_CHALLENGES is not set`, and each such
    section is listed in the NOT RUN report (record_not_run), never silently green. Set: it is passed
    through (a missing folder fails the item with the FileNotFoundError) and every section must run.
    Any other SKIP line is undeclared and fails the item.

The three day-27 scripts with saved sections are run by tests/test_carry_checklist.py (B-240) with their own
declared skip patterns, so they are not repeated here. A CLI command that only defaults its input folder to the
saved attempts (CLI_COMMANDS) is checked by its own tests, named there, for the unset and missing cases. Children get no token, cookie or platform URL, a
temporary CTF_WORKDIR and TMPDIR; the scripts get the Huntress profile (their answers are Huntress slugs).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import paths
from ctf.testing.pytest_plugin import record_not_run

REPO = paths.repo_root()
PY = sys.executable
TIMEOUT = 280             # under the suite's --timeout 300
EVENT = "huntress"

# pytest modules -> the tests that read the saved attempts.
PYTEST_MODULES = {
    "tests/test_binary_speed_solver_saved.py": ("test_speed_solver_agrees_with_every_saved_binary_key",),
    "tests/test_day24_binary_config_guard.py": ("test_6_saved_day24_base_replays_equal_to_key",),
    "tests/test_day28_metadata_disk.py": ("test_exact_saved_day28_disk", "test_exact_saved_day28_mastery"),
    "tests/test_day28_warmups.py": ("test_no_saved_warmups_payload_is_read_by_esolang4",),
    "tests/test_deliveries_split.py": ("test_every_saved_mastery_pairs_each_set_with_a_delivery_of_its_own",),
    "tests/test_accepted_formats.py": ("test_the_tracked_catalog_matches_the_judged_corpus",),
    "tests/test_metadata_dotnet.py": ("test_the_saved_day12_files_answer_their_key_plain_from_the_seed_alone",
                                      "test_the_saved_day12_files_agree_with_dnfile"),
    "tests/test_msi_reader.py": ("test_the_saved_day13_installers_answer_their_key_plain_from_the_seed_alone",
                                 "test_the_saved_day13_question_is_covered"),
    "tests/test_warmups_esolang_sweep.py": ("test_no_saved_warmups_payload_is_taken_by_the_two_new_readers",),
    "tests/test_wave122_esolang3.py": ("test_saved",),
    "tests/test_wave15_esolang2.py": ("test_saved",),
    "tests/test_wave4_esolang.py": ("test_saved",),
}
# Uncollected check scripts with a saved section, run as child scripts here.
SCRIPTS = (
    "solvers/script-analysis/test_wavec2_deflate.py",
)
# Scripts with a saved section that tests/test_carry_checklist.py runs (declared skip patterns there).
CARRY_CHECKLIST = (
    "tests/test_day27_native_image_mobile.py",
    "tests/test_day27_record_select_binary.py",
    "tests/test_day27_split_fold_mobile.py",
)
# CLI commands that read the saved attempts as their default input folder (not a check with a saved section):
# file -> (test module, tests there that check the unset and the set-to-a-missing-folder cases).
CLI_COMMANDS = {
    "ctf/cli/dexvm.py": ("tests/test_b229_dex_chain.py", ("test_dexvm_replay_without_a_folder_names_the_variable",
                                                          "test_dexvm_replay_reads_the_saved_folder_from_the_variable")),
    "ctf/lanestate.py": ("tests/test_batch47_integration.py",
                         ("test_state_without_a_root_names_the_variable",
                          "test_state_reads_the_saved_folder_from_the_variable")),
    "solvers/metadata-forensics/accepted_formats.py": ("tests/test_accepted_formats.py",
                                                       ("test_the_corpus_must_be_configured_outside_the_checkout",
                                                        "test_the_corpus_variable_is_used_when_no_path_is_given")),
    "ctf/cli/show.py": ("tests/test_b210_show.py",
                        ("test_show_day_without_a_root_names_the_variable",
                         "test_show_day_reads_the_saved_folder_from_the_variable")),
}

NOT_SET_TEXT = "not run: CTF_REAL_CHALLENGES is not set"
NOT_SET = re.compile(r"^SKIP (?P<section>.+?): not run: CTF_REAL_CHALLENGES is not set\b")
SKIP_LINE = re.compile(r"^\s*(?:SKIP|skip)\b.*$", re.M)
FAIL_LINE = re.compile(r"^\s*FAIL\b.*$", re.M)
NOT_RUN_REASON = "needs the saved past-event attempts: set CTF_REAL_CHALLENGES (ctf.paths.saved_challenges_root)"


def child_env(tmp: Path, saved: Path | None, event: str | None = EVENT) -> dict:
    """A minimal child environment: no PYTEST_/CTF_/legacy variable from this process. `event` None leaves
    CTF_EVENT to the suite's root conftest (the pytest-module children)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST_", "CTF_", "CSCTF_", "HUNTRESS_"))}
    env.update(CTF_TESTING="1", CTF_WORKDIR=str(tmp / "work"), TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE="1")
    if event is not None:
        env["CTF_EVENT"] = event
    if saved is not None:
        env["CTF_REAL_CHALLENGES"] = str(saved)
    return env


# ---- pytest modules ----------------------------------------------------------------------------------

def outcome_counts(stdout: str) -> dict[str, int]:
    """pytest's final summary line (`1 failed, 2 skipped in 0.3s`) as {outcome: count}."""
    lines = [ln for ln in stdout.splitlines() if re.search(r"\bin [\d.]+s\b", ln)]
    if not lines:
        return {}
    return {word: int(n) for n, word in re.findall(r"(\d+) (passed|failed|skipped|errors?|deselected|xfailed|"
                                                    r"xpassed|warnings?)", lines[-1])}


def judge_module(stdout: str, returncode: int, mode: str, n: int = 1) -> list[str]:
    """Problems with one child pytest run of a module's `n` saved tests. mode: unset | missing | empty."""
    counts = {k: v for k, v in outcome_counts(stdout).items() if not k.startswith("warning")}
    problems = []
    if mode == "missing":
        if returncode != 1 or counts != {"failed": n}:
            problems.append(f"set to a missing folder: expected exactly {n} failed (exit 1), got {counts} (exit {returncode})")
        if "FileNotFoundError" not in stdout or "CTF_REAL_CHALLENGES" not in stdout:
            problems.append("set to a missing folder: the failure does not name FileNotFoundError and CTF_REAL_CHALLENGES")
        return problems
    if returncode != 0 or counts != {"skipped": n}:
        problems.append(f"{mode}: expected exactly {n} skipped (exit 0), got {counts} (exit {returncode})")
    reasons = [ln for ln in stdout.splitlines() if ln.startswith("SKIPPED ")]      # -rs lines
    unset = [ln for ln in reasons if NOT_SET_TEXT in ln]
    if mode == "unset" and (not reasons or len(unset) != len(reasons)):
        problems.append(f"unset: a skip reason does not say `{NOT_SET_TEXT}`")
    if mode == "empty" and unset:
        problems.append(f"set to an empty folder: the skip reason says `{NOT_SET_TEXT}` although it is set")
    return problems


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["unset", "missing", "empty"])
@pytest.mark.parametrize("module", sorted(PYTEST_MODULES))
def test_pytest_module_saved_test(module, mode, tmp_path):
    saved = {"unset": None, "missing": tmp_path / "no-such-saved-tree", "empty": tmp_path / "saved"}[mode]
    if mode == "empty":
        saved.mkdir()
    names = PYTEST_MODULES[module]
    nodes = [f"{module}::{name}" for name in names]
    node = " ".join(nodes)
    cmd = [PY, "-m", "pytest", *nodes, "-q", "-rs", "-p", "no:cacheprovider", "-o", "addopts=", "-n", "0"]
    try:
        proc = subprocess.run(cmd, cwd=REPO, env=child_env(tmp_path, saved, event=None), capture_output=True,
                              text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{node} timed out after {TIMEOUT} s")
    problems = judge_module(proc.stdout, proc.returncode, mode, len(names))
    assert not problems, f"{node}:\n  " + "\n  ".join(problems) + "\n" + (proc.stdout + proc.stderr)[-2000:]


# ---- uncollected check scripts -----------------------------------------------------------------------

def judge(stdout: str, returncode: int, saved: Path | None) -> tuple[list[str], list[str]]:
    """(problems, sections not run) for one script run. `saved` is the corpus the run was given."""
    problems, not_run = [], []
    if returncode != 0:
        problems.append(f"exit code {returncode}")
    problems += [f"failed check: {ln.strip()}" for ln in FAIL_LINE.findall(stdout)]
    for line in (ln.strip() for ln in SKIP_LINE.findall(stdout)):
        m = NOT_SET.match(line)
        if m and saved is None:
            not_run.append(m.group("section"))
        elif m:
            problems.append(f"says CTF_REAL_CHALLENGES is not set although it is ({saved}): {line}")
        else:
            problems.append(f"undeclared skipped section: {line}")
    if saved is None and not not_run:
        problems.append("no saved section reported itself not run (expected `SKIP <section>: not run: "
                        "CTF_REAL_CHALLENGES is not set`)")
    return problems, not_run


@pytest.mark.slow
@pytest.mark.parametrize("script", SCRIPTS)
def test_carried_script(script, tmp_path, request):
    saved = paths.saved_challenges_root()      # set but missing: FileNotFoundError fails the item, loudly
    try:
        proc = subprocess.run([PY, script], cwd=REPO, env=child_env(tmp_path, saved), capture_output=True,
                              text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{script} timed out after {TIMEOUT} s")
    problems, not_run = judge(proc.stdout, proc.returncode, saved)
    for section in not_run:
        record_not_run(request.node, section, NOT_RUN_REASON)
    assert not problems, f"{script}:\n  " + "\n  ".join(problems) + "\n" + (proc.stdout + proc.stderr)[-1500:]


def test_every_saved_section_carrier_is_checked_somewhere():
    """A file that reads the saved attempts is checked by this file or run by the carry checklist."""
    git = subprocess.run(["git", "-C", str(REPO), "grep", "-l", "saved_challenges_root()", "--", "*.py"],
                         capture_output=True, text=True, check=False)
    assert git.returncode in (0, 1), git.stderr
    users = set(git.stdout.split()) - {"ctf/paths.py", "tests/test_no_home_paths.py", "tests/test_saved_sections.py"}
    assert users, "git grep found no file reading the saved attempts"
    here = set(SCRIPTS) | set(PYTEST_MODULES)
    covered = here | set(CARRY_CHECKLIST) | set(CLI_COMMANDS)
    assert users <= covered, f"files with a saved section that no test checks: {sorted(users - covered)}"
    assert here <= users, f"listed files that no longer read the saved attempts: {sorted(here - users)}"
    assert set(CLI_COMMANDS) <= users, \
        f"listed CLI commands that no longer read the saved attempts: {sorted(set(CLI_COMMANDS) - users)}"
    for rel, (module, names) in CLI_COMMANDS.items():
        text = (REPO / module).read_text(encoding="utf-8")
        for name in names:
            assert re.search(rf"^def {re.escape(name)}\(", text, re.M), f"{rel}: {module} has no test {name}()"
    for rel, names in PYTEST_MODULES.items():
        text = (REPO / rel).read_text(encoding="utf-8")
        for name in names:
            assert re.search(rf"^def {re.escape(name)}\(", text, re.M), f"{rel} has no saved test {name}()"
    carry = (REPO / "tests" / "test_carry_checklist.py").read_text(encoding="utf-8")
    for rel in CARRY_CHECKLIST:
        assert f'"{rel}": (S,' in carry, f"{rel} is not run as a script by tests/test_carry_checklist.py"


# ---- the judges, on synthetic output -----------------------------------------------------------------

def test_outcome_counts():
    assert outcome_counts("x\n1 failed, 2 skipped, 3 warnings in 0.31s\n") == {"failed": 1, "skipped": 2, "warnings": 3}
    assert outcome_counts("1 skipped in 2.00s") == {"skipped": 1}
    assert outcome_counts("no summary") == {}


SKIPPED_UNSET = ("SKIPPED [1] tests/t.py:9: not run: CTF_REAL_CHALLENGES is not set (the saved past-event "
                 "attempts)\n1 skipped in 0.50s\n")
SKIPPED_EMPTY = "SKIPPED [1] tests/t.py:9: fewer than 50 saved Warmups artifact files under /x (0)\n1 skipped in 0.5s\n"
FAILED_MISSING = ("E   FileNotFoundError: saved challenges not found at /x (CTF_REAL_CHALLENGES is set to '/x')\n"
                  "1 failed in 0.40s\n")


def test_judge_module_accepts_the_contract():
    assert judge_module(SKIPPED_UNSET, 0, "unset") == []
    assert judge_module(SKIPPED_EMPTY, 0, "empty") == []
    assert judge_module(FAILED_MISSING, 1, "missing") == []
    assert judge_module(SKIPPED_UNSET.replace("1 skipped in", "1 skipped, 2 warnings in"), 0, "unset") == []
    two = SKIPPED_UNSET.replace("[1]", "[2]").replace("1 skipped", "2 skipped")
    assert judge_module(two, 0, "unset", 2) == []
    assert judge_module(two, 0, "unset", 1)                  # one saved test more than declared
    assert judge_module(FAILED_MISSING.replace("1 failed", "2 failed"), 1, "missing", 2) == []


def test_judge_module_unset_every_skip_must_name_the_variable():
    mixed = SKIPPED_UNSET.replace("1 skipped", "2 skipped") + SKIPPED_EMPTY.splitlines()[0] + "\n"
    assert any("does not say" in p for p in judge_module(mixed, 0, "unset", 2))


def test_judge_module_unset_must_skip_naming_the_variable():
    # a pass while unset (the old SKIP-and-pass) and a skip with another reason both fail
    assert judge_module("1 passed in 0.1s\n", 0, "unset")
    assert any("does not say" in p for p in judge_module(SKIPPED_EMPTY, 0, "unset"))
    assert judge_module("ERROR not found: tests/t.py::test_saved\nno tests ran in 0.1s\n", 4, "unset")


def test_judge_module_missing_folder_must_fail_loudly():
    # swallowed into a skip (the old `not REAL.is_dir()` skip), or a failure for another reason, both fail
    assert judge_module(SKIPPED_EMPTY, 0, "missing")
    assert any("does not name" in p for p in judge_module("E   AssertionError\n1 failed in 0.1s\n", 1, "missing"))


def test_judge_module_set_must_not_claim_unset():
    assert any("although it is set" in p for p in judge_module(SKIPPED_UNSET, 0, "empty"))
    assert judge_module("1 failed in 0.1s\n", 1, "empty")


UNSET = "ok   a\nSKIP saved: not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)\nALL PASS\n"


def test_judge_unset_reports_the_section_not_run():
    assert judge(UNSET, 0, None) == ([], ["saved"])


def test_judge_two_sections():
    out = "SKIP day 7: not run: CTF_REAL_CHALLENGES is not set\nSKIP 6 saved base: not run: CTF_REAL_CHALLENGES is not set (x)\n"
    assert judge(out, 0, None) == ([], ["day 7", "6 saved base"])


def test_judge_fails_on_exit_code_and_fail_lines():
    problems, _ = judge(UNSET + "FAIL sweep ook\n", 1, None)
    assert problems == ["exit code 1", "failed check: FAIL sweep ook"]


def test_judge_fails_on_an_undeclared_skip():
    problems, not_run = judge(UNSET + "skip 6 saved Day 24 base (folder not present)\n", 0, None)
    assert problems == ["undeclared skipped section: skip 6 saved Day 24 base (folder not present)"]
    assert not_run == ["saved"]


def test_judge_requires_the_not_run_line_when_unset():
    problems, not_run = judge("ok   a\nALL PASS\n", 0, None)
    assert not_run == [] and len(problems) == 1 and "no saved section reported itself not run" in problems[0]


def test_judge_with_corpus_every_section_must_run(tmp_path):
    assert judge("ok   a\nok   saved b\n", 0, tmp_path) == ([], [])
    problems, not_run = judge(UNSET, 0, tmp_path)
    assert not_run == [] and len(problems) == 1 and "although it is" in problems[0]
    problems, _ = judge("ok a\nSKIP 6 saved Day 24 base: not run: no Day 24 base\n", 0, tmp_path)
    assert problems == ["undeclared skipped section: SKIP 6 saved Day 24 base: not run: no Day 24 base"]


def test_child_env_is_minimal(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_TOKEN", "x")
    monkeypatch.setenv("CTF_REAL_CHALLENGES", "/nowhere")
    legacy = "HUNTRESS" + "_TK_LIVE"     # a legacy name the child must not inherit (spelled so the
    monkeypatch.setenv(legacy, "1")         # legacy-name guard in test_single_sources.py does not flag it)
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    monkeypatch.setenv("CTF_EVENT", "csctf")
    env = child_env(tmp_path, None)
    assert not {"CTF_TOKEN", "CTF_REAL_CHALLENGES", legacy, "PYTEST_XDIST_WORKER"} & set(env)
    assert env["CTF_EVENT"] == EVENT and env["CTF_WORKDIR"] == str(tmp_path / "work") and env["TMPDIR"] == str(tmp_path)
    assert child_env(tmp_path, tmp_path)["CTF_REAL_CHALLENGES"] == str(tmp_path)
    assert "CTF_EVENT" not in child_env(tmp_path, None, event=None)
