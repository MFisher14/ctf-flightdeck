from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOLKITS = ROOT / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import autosolve as A  # noqa: E402
import dispatch_core as C  # noqa: E402


def test_autosolve_direct_artifact_is_ranked_and_never_submission_ready():
    report = A.autosolve("inspect the mystery", {"answer.txt": b"proof CSCTF{r5a_direct} end"})
    row = next(item for item in report["candidates"] if item["value"] == "CSCTF{r5a_direct}")
    assert row["rank"] == 1 and row["verified"] is True
    assert row["submission_ready"] is False and row["requires_human_review"] is True
    assert report["offline"] and report["network_requests"] == 0 and not report["submitted"]
    assert {item["dispatcher"] for item in report["dispatcher_selection"]} == {
        "crypto", "forensics", "exploit"}
    json.dumps(report)


def test_autosolve_description_flag_stays_unverified():
    report = A.autosolve("Example answer may be CSCTF{candidate_from_prose}", {})
    row = next(item for item in report["candidates"]
               if item["value"] == "CSCTF{candidate_from_prose}")
    assert row["verified"] is False and row["confidence"] == "low"
    assert "corroborate" in " ".join(row["warnings"]).lower()


def test_dispatcher_safety_contract_violation_is_rejected(monkeypatch):
    bad = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        "network_requests": 1,
        "submitted": True,
        "candidates": [{"value": "CSCTF{unsafe}", "derivation": ["bad"]}],
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: bad)
    report = A._run_dispatcher("crypto", "", [], "")
    assert report["candidates"] == []
    assert any("safety" in warning for warning in report["warnings"])
    assert report["attempts"][-1]["status"] == "error"


@pytest.mark.parametrize("fields", [
    {"network_requests": 0, "submitted": False},
    {"offline": False, "network_requests": 0, "submitted": False},
    {"offline": True, "network_requests": False, "submitted": False},
    {"offline": True, "network_requests": 0, "submitted": True},
    {"offline": True, "network_requests": 0, "submitted": False,
     "executed_artifacts": True},
])
def test_dispatcher_contract_requires_explicit_offline_no_submit(fields, monkeypatch):
    module = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        **fields, "candidates": [{"value": "CSCTF{unsafe}", "derivation": ["bad"]}],
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: module)
    assert A._run_dispatcher("crypto", "", [], "")["candidates"] == []


def test_category_hint_adds_obvious_dispatcher_without_suppressing_magic():
    artifacts = C.normalize_artifacts({"image.png": b"\x89PNG\r\n\x1a\n" + b"x" * 16})
    archetypes = C.classify_archetypes("base 64 text in image", artifacts)
    selected = A._apply_category_hint(C.dispatcher_scores(archetypes), "crypto")
    assert {row["dispatcher"] for row in selected} >= {"crypto", "forensics"}


def test_malformed_candidates_are_filtered_and_valid_candidates_sanitized(monkeypatch):
    module = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        "offline": True,
        "network_requests": 0,
        "submitted": False,
        "attempts": [], "observations": [], "warnings": [],
        "candidates": [
            {"value": "not-a-flag", "derivation": ["invented"]},
            {"value": "CSCTF{...}", "derivation": ["placeholder"]},
            {"value": "CSCTF{kept}", "archetype": "fixture", "engine": "fixture",
             "source": "fixture", "derivation": ["exact fixture"], "verified": True,
             "confidence": "high", "submission_ready": True},
        ],
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: module)
    report = A._run_dispatcher("crypto", "", [], "")
    assert [row["value"] for row in report["candidates"]] == ["CSCTF{kept}"]
    assert report["candidates"][0]["submission_ready"] is False
    assert any("rejected 2" in warning for warning in report["warnings"])


def test_non_json_dispatcher_rows_are_rejected_without_escape(monkeypatch):
    class RaisingIterable:
        def __iter__(self):
            raise RuntimeError("must not escape")

    module = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        "offline": True, "network_requests": 0, "submitted": False,
        "candidates": [{"value": "CSCTF{bad_iter}", "derivation": RaisingIterable()}],
        "attempts": [object()], "observations": [{"bad": object()}],
        "warnings": [],
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: module)
    report = A._run_dispatcher("crypto", "", [], "")
    assert report["candidates"] == [] and report["observations"] == []
    assert any("malformed/non-JSON" in warning for warning in report["warnings"])


def test_nonfinite_dispatcher_rows_are_rejected(monkeypatch):
    module = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        "offline": True, "network_requests": 0, "submitted": False,
        "candidates": [], "attempts": [{"elapsed_ms": float("nan")}],
        "observations": [{"score": float("inf")}], "warnings": [],
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: module)
    report = A._run_dispatcher("crypto", "", [], "")
    assert len(report["attempts"]) == 2 and report["observations"] == []
    assert sum("non-JSON" in warning for warning in report["warnings"]) == 2


def test_hostile_list_subclasses_and_huge_ints_are_rejected(monkeypatch):
    class EvilList(list):
        def __getitem__(self, _key):
            raise RuntimeError("slice escaped")

    module = SimpleNamespace(dispatch=lambda *args, **kwargs: {
        "offline": True, "network_requests": 0, "submitted": False,
        "candidates": EvilList([{}]), "attempts": EvilList([{}]),
        "observations": [{"huge": 10 ** 5000}], "warnings": EvilList(["bad"]),
    })
    monkeypatch.setattr(A.importlib, "import_module", lambda _name: module)
    report = A._run_dispatcher("crypto", "", [], "")
    assert report["candidates"] == [] and report["observations"] == []
    assert any("rejected" in warning for warning in report["warnings"])


def test_import_runtime_error_is_contained(monkeypatch):
    def fail(_name):
        raise RuntimeError("broken import")

    monkeypatch.setattr(A.importlib, "import_module", fail)
    report = A._run_dispatcher("crypto", "", [], "")
    assert report["candidates"] == [] and report["attempts"][-1]["status"] == "unavailable"


def test_top_level_is_deterministic_for_same_input():
    first = A.autosolve("base64 encoding", {"blob.txt": b"ordinary text"}, category="crypto")
    second = A.autosolve("base64 encoding", {"blob.txt": b"ordinary text"}, category="crypto")
    for report in (first, second):
        for attempt in report["attempts"]:
            attempt.pop("elapsed_ms", None)
    assert first == second


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, str(TOOLKITS / "autosolve.py"), *args],
                          cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)


def test_cli_json_and_human_output(tmp_path):
    path = tmp_path / "flag.txt"
    path.write_text("CSCTF{r5a_cli}")
    proc = _run_cli("--json", "--description", "unknown", str(path))
    assert proc.returncode == 0 and "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    assert report["candidates"][0]["value"] == "CSCTF{r5a_cli}"

    proc = _run_cli("--description", "unknown", str(path))
    assert proc.returncode == 0 and "HUMAN REVIEW REQUIRED" in proc.stdout
    assert "Traceback" not in proc.stderr


def test_cli_boundaries_have_no_traceback(tmp_path):
    missing = _run_cli(str(tmp_path / "missing.bin"))
    assert missing.returncode == 2 and "Traceback" not in missing.stderr
    assert "does not exist" in missing.stderr

    empty = _run_cli("--description", "nothing useful")
    assert empty.returncode == 1 and "Traceback" not in empty.stderr
    assert "no flag-shaped candidate" in empty.stdout

    help_result = _run_cli("--help")
    assert help_result.returncode == 0
    assert "never" in help_result.stdout and "submits" in help_result.stdout


def test_input_description_cap_fails_before_dispatch():
    with pytest.raises(C.R5AInputError):
        A.autosolve("x" * (C.MAX_DESCRIPTION + 1), {})


def test_category_is_typed_and_bounded_before_dispatch():
    with pytest.raises(C.R5AInputError):
        A.autosolve("", {}, category=object())
    with pytest.raises(C.R5AInputError):
        A.autosolve("", {}, category="x" * (C.MAX_CATEGORY + 1))


def test_cli_description_file_read_is_bounded(tmp_path):
    path = tmp_path / "huge-description.txt"
    path.write_bytes(b"x" * (C.MAX_DESCRIPTION * 4 + 1))
    proc = _run_cli("--description-file", str(path))
    assert proc.returncode == 2 and "Traceback" not in proc.stderr
    assert "bounded read" in proc.stderr


def test_cli_never_emits_terminal_control_from_flag(tmp_path):
    path = tmp_path / "escape.txt"
    path.write_bytes(b"CSCTF{safe\x1b[31mRED}")
    proc = _run_cli("--description", "unknown", str(path))
    assert "\x1b" not in proc.stdout and "RED" not in proc.stdout


def test_human_output_never_emits_terminal_control_from_artifact_name():
    report = A.autosolve("unknown", {"evil\x1b[31m.txt": b"CSCTF{safe_value_42}"})
    assert "\x1b" not in A._human(report)

