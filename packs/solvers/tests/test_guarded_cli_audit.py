"""The CLI audit itself stays offline, bounded, and recognizes new guarded engines."""
from __future__ import annotations

import importlib.util
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("guarded_cli_audit", REPO / "tools" / "guarded_cli_audit.py")
audit_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_mod)


def test_discovery_and_one_real_guarded_cli_triplet():
    paths = audit_mod.discover(["solvers/warmups/esolang_tail.py"])
    assert paths == [REPO / "solvers" / "warmups" / "esolang_tail.py"]
    report = audit_mod.audit(paths, timeout=2.0)
    assert report["files"] == 1
    assert report["cases"] == 3
    assert report["failed_files"] == 0


def test_invalid_timeout_is_guarded(capsys):
    assert audit_mod.main(["--timeout", "0"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("guarded_cli_audit: ")
    assert "Traceback" not in captured.err

