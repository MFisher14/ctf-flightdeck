"""B-165: the `ctf re-workbench` CLI (ctf/cli/re_workbench.py).

Covers the three sub-commands offline: readiness reporting, scaffolding a workspace from the
template, and reading a findings board. The command is also reachable through cli.main discovery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys

import pytest

import shared_findings as sf
from ctf import cli, flagfmt, paths
from ctf.cli import re_workbench as cmd


def _parse(*argv) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    cmd.add_arguments(p)
    return p.parse_args(list(argv))


# ------------------------------------------------------------------------------------- check

def test_check_json_structure(capsys):
    rc = cmd.run(_parse("check", "--json"))
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"ok", "versions", "problems"}
    assert isinstance(out["versions"], dict) and isinstance(out["problems"], list)
    assert rc in (0, 1)                                    # 0 when all import, 1 when some are absent


@pytest.mark.needs_tool("py:capstone", "py:unicorn", "py:lief", "py:pefile")
def test_check_reports_ok_when_libs_present(capsys):
    rc = cmd.run(_parse("check"))
    line = capsys.readouterr().out
    assert rc == 0 and line.startswith("STATIC_RE_READY OK")
    for lib in ("capstone=", "unicorn=", "lief=", "pefile="):
        assert lib in line


@pytest.mark.parametrize("lib", ["lief", "pefile"])
def test_check_fails_with_exit_1_when_a_library_is_missing(monkeypatch, capsys, lib):
    # lief is checked by the reused tools/static_re_check.py table, pefile by the workbench's extra
    monkeypatch.setitem(sys.modules, lib, None)        # `import <lib>` now raises ImportError
    rc = cmd.run(_parse("check"))
    line = capsys.readouterr().out
    assert rc == 1
    assert line.startswith("STATIC_RE_READY FAIL") and f"{lib}: import ModuleNotFoundError" in line
    assert cmd.run(_parse("check", "--json")) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and any(p.startswith(f"{lib}: import") for p in out["problems"])


def test_check_reuses_the_carried_static_re_check(monkeypatch, capsys):
    # the CLI must take capstone/unicorn/lief from tools/static_re_check.py, not a private copy
    src = cmd._load_static_re_check()
    monkeypatch.setitem(src.REQUIRED, "capstone", ("Cs", "NO_SUCH_ATTRIBUTE_FOR_TEST"))
    assert cmd.run(_parse("check")) == 1
    assert "capstone: missing NO_SUCH_ATTRIBUTE_FOR_TEST" in capsys.readouterr().out


# ---------------------------------------------------------------------------------- scaffold

def test_scaffold_materializes_workspace(tmp_path, capsys):
    dest = tmp_path / "wb"
    rc = cmd.run(_parse("scaffold", str(dest), "--challenge", "SHA1-Hulud", "--agents", "6", "--gate-later"))
    assert rc == 0
    for name in ("README.md", "agent-task.md", "vmspec.example.py", "findings.jsonl", "readiness.txt"):
        assert (dest / name).exists(), name
    readme = (dest / "README.md").read_text()
    assert "SHA1-Hulud" in readme and "6 racer" in readme
    assert "{{" not in readme and "}}" not in readme       # every placeholder was rendered
    assert (dest / "findings.jsonl").read_text() == ""     # the board starts empty
    assert stat.S_IMODE(os.stat(dest / "findings.jsonl").st_mode) & 0o077 == 0   # owner-only
    # the empty board reads as no findings; --gate-later asked for no gate, so none is pinned
    assert sf.FindingsBoard(dest / "findings.jsonl").entries() == []
    assert not (dest / "findings.gate.json").exists()
    # the instructions name this checkout, so they work from the workspace, not only the repo root
    assert f"{paths.repo_root()}/tools/ctfpy" in readme
    brief = (dest / "agent-task.md").read_text()
    assert "ctf submit" in brief and "pe_emu" in brief and "{{" not in brief


def test_scaffold_pins_a_digest_gate(tmp_path, capsys):
    want = hashlib.sha1(b"FLAG{pinned}").hexdigest()
    dest = tmp_path / "wb"
    assert cmd.run(_parse("scaffold", str(dest), "--gate-digest", f"sha1:{want}")) == 0
    gate = json.loads((dest / "findings.gate.json").read_text())
    assert gate == {"gate": "digest", "algo": "sha1", "expected": want, "encoding": "utf-8"}
    assert want in (dest / "README.md").read_text()
    # a racer opening the board with no gate runs the pinned one
    board = sf.FindingsBoard(dest / "findings.jsonl")
    with pytest.raises(sf.AcceptanceRejected):
        board.accept(sf.Finding(key="flag", agent="a", summary="guess", candidate="FLAG{nope}"))
    assert board.accept(sf.Finding(key="flag", agent="a", summary="ok", candidate="FLAG{pinned}")).kind == "accepted"
    # the board's first line anchors the same gate
    first = json.loads((dest / "findings.jsonl").read_text().splitlines()[0])
    assert first["gate_pin"] == gate


def test_scaffold_requires_a_gate_choice(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:                  # argparse: one of --gate-* is required
        _parse("scaffold", str(tmp_path / "wb"))
    assert exc.value.code == 2
    assert "--gate-digest" in capsys.readouterr().err
    # a programmatic Namespace with no gate is refused too, before anything is written
    ns = argparse.Namespace(cmd="scaffold", dir=str(tmp_path / "wb2"), challenge="c", agents=1, force=False,
                            gate_digest=None, gate_regex=None, gate_flagfmt=False, gate_later=False)
    assert cmd.run(ns) == 2
    assert "scaffold needs a gate" in capsys.readouterr().err
    assert not (tmp_path / "wb2").exists()


@pytest.mark.parametrize("pattern,why", [(".*", "empty string"), (".+", "arbitrary unrelated text")])
def test_scaffold_refuses_a_gate_that_constrains_nothing(tmp_path, capsys, pattern, why):
    assert cmd.run(_parse("scaffold", str(tmp_path / "wb"), "--gate-regex", pattern)) == 2
    assert why in capsys.readouterr().err
    assert not (tmp_path / "wb").exists()


def test_scaffold_pins_the_event_flag_format(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    dest = tmp_path / "wb"
    assert cmd.run(_parse("scaffold", str(dest), "--gate-flagfmt")) == 0
    gate = json.loads((dest / "findings.gate.json").read_text())
    assert gate["gate"] == "regex" and gate["pattern"] == flagfmt.current().regex.pattern


def test_scaffold_rejects_a_malformed_gate(tmp_path, capsys):
    assert cmd.run(_parse("scaffold", str(tmp_path / "a"), "--gate-digest", "sha1")) == 2
    assert "ALGO:HEX" in capsys.readouterr().err
    assert cmd.run(_parse("scaffold", str(tmp_path / "b"), "--gate-digest", "nohash:00")) == 2
    assert "unknown digest algorithm" in capsys.readouterr().err
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def _run_example(cmdline, cwd):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["CTF_PYTHON"] = sys.executable
    return subprocess.run(cmdline, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


def test_scaffolded_vmspec_example_runs_from_the_workspace(tmp_path):
    dest = tmp_path / "wb"
    assert cmd.run(_parse("scaffold", str(dest), "--gate-later")) == 0
    ctfpy = str(paths.repo_root() / "tools" / "ctfpy")
    via_ctfpy = _run_example([ctfpy, "--no-ledger", "vmspec.example.py"], dest)
    assert via_ctfpy.returncode == 0, via_ctfpy.stderr
    assert "0007: emit" in via_ctfpy.stdout and "b'A'" in via_ctfpy.stdout
    bare = _run_example([sys.executable, "-I", "vmspec.example.py"], dest)   # no kit on sys.path
    assert bare.returncode == 0, bare.stderr
    assert "b'A'" in bare.stdout


def test_scaffold_refuses_nonempty_dir_without_force(tmp_path):
    dest = tmp_path / "wb"
    dest.mkdir()
    (dest / "keep.txt").write_text("mine")
    assert cmd.run(_parse("scaffold", str(dest), "--gate-later")) == 2
    assert cmd.run(_parse("scaffold", str(dest), "--force", "--gate-later")) == 0
    assert (dest / "README.md").exists()


def test_scaffold_fails_loudly_without_template(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cmd.paths, "repo_root", lambda: tmp_path)   # a tree with no templates/static-re
    rc = cmd.run(_parse("scaffold", str(tmp_path / "wb"), "--gate-later"))
    assert rc == 2
    assert "template not found" in capsys.readouterr().err


# ---------------------------------------------------------------------------------- findings

def _seed_board(path):
    board = sf.FindingsBoard(path, gate=sf.regex_gate(r"tok-.*"))
    board.record(sf.Finding(key="op-0x1a", agent="a2", summary="xor handler", kind="hypothesis"))
    board.accept(sf.Finding(key="flag", agent="a5", summary="format match", candidate="tok-demo"))
    return path


def test_findings_lists_all_and_accepted(tmp_path, capsys):
    path = _seed_board(tmp_path / "findings.jsonl")
    assert cmd.run(_parse("findings", str(path))) == 0
    out = capsys.readouterr().out
    assert "op-0x1a" in out and "flag" in out and "tok-demo" in out

    assert cmd.run(_parse("findings", str(path), "--accepted")) == 0
    acc = capsys.readouterr().out
    assert "[accepted] flag" in acc and "op-0x1a" not in acc
    assert "gate: regex fullmatch" in acc


def test_findings_accepted_survives_a_later_record_on_the_same_key(tmp_path, capsys):
    path = _seed_board(tmp_path / "findings.jsonl")
    sf.FindingsBoard(path).record(sf.Finding(key="flag", agent="a9", summary="noise", kind="candidate",
                                             candidate="not-a-flag"))
    assert cmd.run(_parse("findings", str(path), "--accepted")) == 0
    out = capsys.readouterr().out
    assert "tok-demo" in out and "not-a-flag" not in out


def test_findings_accepted_flags_a_forged_row(tmp_path, capsys):
    path = _seed_board(tmp_path / "findings.jsonl")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"schema": 1, "ts": 2.0, "key": "flag", "agent": "forger", "kind": "accepted",
                             "status": "accepted", "summary": "trust me", "candidate": "nope{}"}) + "\n")
    assert cmd.run(_parse("findings", str(path), "--accepted")) == 1
    captured = capsys.readouterr()
    assert "[accepted] flag (a5)" in captured.out
    assert "[FLAGGED] flag (forger)" in captured.out and "fails the pinned gate" in captured.out
    assert "do not re-verify" in captured.err
    assert cmd.run(_parse("findings", str(path), "--accepted", "--json")) == 1
    out = json.loads(capsys.readouterr().out)
    assert [r["candidate"] for r in out["accepted"]] == ["tok-demo"]
    assert [f["finding"]["candidate"] for f in out["flagged"]] == ["nope{}"]
    assert out["gate"]["gate"] == "regex"


def test_findings_accepted_refuses_a_board_whose_gate_file_changed(tmp_path, capsys):
    path = _seed_board(tmp_path / "findings.jsonl")
    sf.gate_path(path).write_text(json.dumps(sf.regex_gate(r"[a-z]+").to_dict()))
    assert cmd.run(_parse("findings", str(path), "--accepted")) == 2
    captured = capsys.readouterr()
    assert "changed after pinning" in captured.err and "tok-demo" not in captured.out


def test_findings_json_output(tmp_path, capsys):
    path = _seed_board(tmp_path / "findings.jsonl")
    cmd.run(_parse("findings", str(path), "--json"))
    rows = json.loads(capsys.readouterr().out)
    assert {r["key"] for r in rows} == {"op-0x1a", "flag"}


def test_findings_missing_board_returns_2(tmp_path, capsys):
    assert cmd.run(_parse("findings", str(tmp_path / "nope.jsonl"))) == 2
    assert "no findings board" in capsys.readouterr().err


def test_findings_reports_corrupt_board(tmp_path, capsys):
    path = tmp_path / "findings.jsonl"
    path.write_text("not json at all\n")
    assert cmd.run(_parse("findings", str(path))) == 2
    assert "not JSON" in capsys.readouterr().err


# ------------------------------------------------------------------------------- discovery

def test_command_is_discoverable_through_cli_main(capsys):
    rc = cli.main(["re-workbench", "check", "--json"])
    assert rc in (0, 1)
    assert "versions" in capsys.readouterr().out


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
