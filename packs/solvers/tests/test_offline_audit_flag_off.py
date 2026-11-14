"""B-196 round 1: the CTF_OFFLINE_AUDIT branches (tools/guarded_cli_audit.py, tools/shannon_ask.py) with the
flag OFF, so the fake-branch audit (ctf/integrity/fakes.py) sees the real path of each under test, and with
it ON, so each test shows the flag decides the path. No network: shannon_ask runs only its --usage path
against a temp state folder, and guarded_cli_audit's discovery is replaced by an empty one (it would
otherwise run every guarded CLI of the checkout)."""
from __future__ import annotations

import sys

import guarded_cli_audit
import shannon_ask


def test_guarded_cli_audit_main_without_the_flag_runs_the_audit(monkeypatch, capsys):
    monkeypatch.delenv("CTF_OFFLINE_AUDIT", raising=False)
    monkeypatch.setattr(sys, "argv", ["guarded_cli_audit.py"])
    monkeypatch.setattr(guarded_cli_audit, "discover", lambda prefixes: [])
    assert guarded_cli_audit.main() == 2
    err = capsys.readouterr().err
    assert "no guarded Python CLIs matched" in err and "usage:" not in err


def test_guarded_cli_audit_main_with_the_flag_stops_at_usage(monkeypatch, capsys):
    monkeypatch.setenv("CTF_OFFLINE_AUDIT", "1")
    monkeypatch.setattr(sys, "argv", ["guarded_cli_audit.py"])
    monkeypatch.setattr(guarded_cli_audit, "discover", lambda prefixes: [])
    assert guarded_cli_audit.main() == 2
    err = capsys.readouterr().err
    assert err.startswith("usage: guarded_cli_audit.py") and "no guarded Python CLIs" not in err


def test_shannon_ask_main_without_the_flag_answers_usage(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("CTF_OFFLINE_AUDIT", raising=False)
    monkeypatch.setenv("SHANNON_STATE", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["shannon_ask.py", "--usage"])
    assert shannon_ask.main() is None
    out = capsys.readouterr()
    assert out.out.startswith("SHANNON USAGE today 0 of ") and "disabled" not in out.err


def test_shannon_ask_main_with_the_flag_is_disabled(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CTF_OFFLINE_AUDIT", "1")
    monkeypatch.setenv("SHANNON_STATE", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["shannon_ask.py", "--usage"])
    assert shannon_ask.main() == 2
    out = capsys.readouterr()
    assert out.out == "" and "external advisor disabled by offline CLI audit" in out.err
