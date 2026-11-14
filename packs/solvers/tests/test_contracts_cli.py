"""B-001 contracts: the CLI package (python -m ctf) with one auto-discovered module per subcommand."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from ctf import cli, paths

PY = sys.executable


def run_ctf(*args, env_extra=None):
    e = dict(os.environ)
    e.update(env_extra or {})
    return subprocess.run([PY, "-m", "ctf", *args], cwd=paths.repo_root(), env=e,
                          capture_output=True, text=True, timeout=60)


def test_help_lists_builtin_and_discovered_commands():
    r = run_ctf("--help")
    assert r.returncode == 0, r.stderr
    for name in ("submit", "wait", "doctor", "event"):
        assert name in r.stdout
    assert "list, show or validate event profiles" in r.stdout


def test_event_subcommand_end_to_end():
    r = run_ctf("event", "check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert {"ok    huntress", "ok    csctf", "ok    pink", "ok    spooky"} <= set(r.stdout.splitlines())
    r = run_ctf("event", "show", "spooky")
    assert r.returncode == 0 and "platform   manual" in r.stdout and "submit     manual" in r.stdout
    r = run_ctf("event", "show", "nope")
    assert r.returncode == 2 and "no event profile 'nope'" in r.stderr


@pytest.fixture
def scratch_pkg(tmp_path, monkeypatch):
    pkg = tmp_path / "scratchcli"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "good_cmd.py").write_text(textwrap.dedent("""\
        HELP = "a good command"
        def add_arguments(p): p.add_argument("--n", type=int, default=1)
        def run(args): return args.n
        """))
    (pkg / "broken.py").write_text("import does_not_exist_anywhere\n")
    (pkg / "half.py").write_text("HELP = 'x'\n")
    (pkg / "_private.py").write_text("raise RuntimeError('never imported')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    for m in [m for m in sys.modules if m.startswith("scratchcli")]:
        monkeypatch.delitem(sys.modules, m)
    return pkg


def test_discover_reports_good_broken_and_incomplete_modules(scratch_pkg):
    found = {n: (m, e) for n, m, e in cli.discover([str(scratch_pkg)], "scratchcli")}
    assert set(found) == {"good-cmd", "broken", "half"}          # _private skipped, _ -> -
    assert found["good-cmd"][0].HELP == "a good command" and found["good-cmd"][1] is None
    assert found["broken"][0] is None and "does_not_exist_anywhere" in found["broken"][1]
    assert "lacks add_arguments, run" in found["half"][1]


def test_main_runs_discovered_and_reports_broken(monkeypatch, scratch_pkg, capsys):
    found = cli.discover([str(scratch_pkg)], "scratchcli")
    monkeypatch.setattr(cli, "discover", lambda: found)
    assert cli.main(["good-cmd", "--n", "0"]) == 0
    assert cli.main(["good-cmd", "--n", "5"]) == 5
    assert cli.main(["broken"]) == 2
    assert "this command is broken" in capsys.readouterr().err


def test_name_collision_with_builtin_is_an_error(monkeypatch, scratch_pkg):
    import importlib
    mod = importlib.import_module("scratchcli.good_cmd")
    monkeypatch.setattr(cli, "discover", lambda: [("submit", mod, None)])
    with pytest.raises(cli.CLIError, match="collides with the built-in command 'submit'"):
        cli.main(["submit", "1", "x"])
