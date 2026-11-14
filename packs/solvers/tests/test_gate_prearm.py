"""B-153: the pre-arm full gate (`ctf gate prearm`, ctf/gate/prearm.py) is separate from the lane gate:
preflight checks first (interpreter, clean tree, baseline ledger, loopback bind, the [[prearm]] commands),
every one reported, any failure refuses the full run (exit 4); then a full, index-free run with nothing
reused, in which an ENV file fails the pre-arm gate. Synthetic checkouts; the prearm commands are tiny
scripts the test writes."""
from __future__ import annotations

import argparse
import errno
import json
import sys
from pathlib import Path

import pytest

from ctf.cli import gate
from ctf.gate import GateError, config, prearm
from ctf.testing import loopback
from gate_repo import git, make_repo, write

LEDGER = ('version = 1\n[[red]]\nid = "tests/test_ok.py::test_ok"\nkind = "flaky"\n'
          'reason = "listed only to prove the check reads it"\nsince = 2026-11-01\n')
PREARM = ('\n[[prearm]]\nname = "gen"\nargv = ["tools/gen_check.py"]\n')
BASE = {
    ".gitignore": "__pycache__/\n",
    "tests/test_ok.py": "def test_ok():\n    pass\n",
    "tests/test_two.py": "def test_two():\n    pass\n",
    "base.toml": LEDGER,
    "tools/gen_check.py": "import sys\nprint('generated files current')\nsys.exit(0)\n",
}


def _repo(tmp_path, files=None, extra=PREARM, ledger=True):
    files = dict(BASE, **(files or {}))
    root = make_repo(tmp_path / "repo", files, extra_config=extra, commit=False)
    if ledger:
        toml = (root / "gate.toml").read_text().replace("no_warm =", 'baseline = "base.toml"\nno_warm =')
        (root / "gate.toml").write_text(toml)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


def _cli(root, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    return gate.run(p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                                  "--python", sys.executable, *argv]))


# --------------------------------------------------------------------------------- the checks

def test_each_preflight_check_passes_on_a_ready_checkout(tmp_path):
    root = _repo(tmp_path)
    cfg = config.load(root, root / "gate.toml")
    checks = prearm.preflight(root, cfg, python=sys.executable, source="test")
    assert [(c.name, c.ok) for c in checks] == [("python", True), ("clean", True), ("baseline", True),
                                                ("loopback", True), ("gen", True)]
    assert "pytest" in checks[0].detail and "1 known red" in checks[2].detail


def test_a_dirty_tree_fails_clean(tmp_path):
    root = _repo(tmp_path)
    write(root, {"tests/test_new.py": "def test_x():\n    pass\n"})
    c = prearm.check_clean(root)
    assert not c.ok and "tests/test_new.py" in c.detail


def test_an_interpreter_without_pytest_fails_python(tmp_path):
    bare = tmp_path / "py"
    bare.write_text("#!/bin/sh\necho 'No module named pytest' >&2\nexit 1\n")
    bare.chmod(0o755)
    c = prearm.check_python(str(bare), "test", tmp_path)
    assert not c.ok and "cannot import pytest" in c.detail and "No module named pytest" in c.detail
    assert not prearm.check_python(str(tmp_path / "missing"), "test", tmp_path).ok


def test_baseline_check_needs_a_ledger_and_refuses_a_stale_entry(tmp_path):
    root = _repo(tmp_path, ledger=False)
    cfg = config.load(root, root / "gate.toml")
    c = prearm.check_baseline(root, cfg)
    assert not c.ok and "names no baseline ledger" in c.detail
    root2 = _repo(tmp_path / "b", {"base.toml": LEDGER.replace("test_ok.py", "test_gone.py")})
    c2 = prearm.check_baseline(root2, config.load(root2, root2 / "gate.toml"))
    assert not c2.ok and "tests/test_gone.py::test_ok" in c2.detail


def test_a_sandbox_denied_loopback_fails_the_loopback_check():
    def denied(kind="tcp"):
        raise loopback.LoopbackDenied(errno.EPERM, "GATE-ENV: sandbox denied a tcp bind on 127.0.0.1:0")
    c = prearm.check_loopback(denied)
    assert not c.ok and "GATE-ENV" in c.detail
    assert prearm.check_loopback().ok                                # the real bind works here


def test_a_failing_prearm_command_reports_its_output(tmp_path):
    root = _repo(tmp_path, {"tools/gen_check.py": "import sys\nprint('requirements.txt is stale')\nsys.exit(1)\n"})
    c = prearm.check_command("gen", ["tools/gen_check.py"], sys.executable, root)
    assert not c.ok and "exit 1" in c.detail and "requirements.txt is stale" in c.detail


@pytest.mark.parametrize("extra,msg", [
    ('\n[[prearm]]\nname = "gen"\n', "needs exactly"),
    ('\n[[prearm]]\nname = "Gen!"\nargv = ["x"]\n', "short lower-case word"),
    ('\n[[prearm]]\nname = "gen"\nargv = []\n', "non-empty list"),
    ('\n[[prearm]]\nname = "gen"\nargv = ["x"]\n[[prearm]]\nname = "gen"\nargv = ["y"]\n', "duplicate"),
    ("TOP:prearm = 3\n", "array of tables"),
])
def test_a_bad_prearm_config_fails_loudly(tmp_path, extra, msg):
    top = extra.startswith("TOP:")
    root = make_repo(tmp_path / "c", {}, extra_config="" if top else extra, commit=False)
    if top:                                            # a top-level key must come before the first table
        toml = (root / "gate.toml").read_text().replace("no_warm =", extra[4:] + "no_warm =")
        (root / "gate.toml").write_text(toml)
    with pytest.raises(GateError, match=msg):
        config.load(root, root / "gate.toml")


def test_the_repo_config_wires_the_generated_file_checks():
    cfg = config.load(Path(__file__).resolve().parent.parent)
    argvs = {name: argv for name, argv in cfg.prearm}
    assert argvs["requirements"] == ("tools/requirements_gen.py", "--check")
    assert argvs["engines"] == ("-m", "ctf", "engines", "generate", "--check")
    assert argvs["coverage"] == ("-m", "ctf", "engines", "coverage", "--check")
    assert argvs["events"] == ("-m", "ctf", "check-event")
    assert argvs["guards"] == ("tools/guard_audit.py",)


# ----------------------------------------------------------------------------------- the CLI

def test_prearm_passes_after_preflight_and_a_full_run(tmp_path, capsys):
    root = _repo(tmp_path)
    st = tmp_path / "st"
    assert _cli(root, st, "prearm") == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith("PREFLIGHT ok   python")
    assert "PREFLIGHT ok   gen: tools/gen_check.py: exit 0" in out
    assert "GATE result=pass mode=full files=2" in out
    assert lines[-1].startswith("PREARM result=pass preflight=ok gate=pass files=2")
    doc = json.loads((st / prearm.LAST_PREARM).read_text())
    assert doc["result"] == "pass" and doc["gate"]["files"] == 2 and len(doc["preflight"]) == 5


def test_prearm_refuses_before_running_when_a_check_fails(tmp_path, capsys):
    root = _repo(tmp_path, {"tools/gen_check.py": "import sys\nprint('stale')\nsys.exit(1)\n"})
    write(root, {"scratch.txt": "dirty\n"})
    st = tmp_path / "st"
    assert _cli(root, st, "prearm") == prearm.EXIT_REFUSED
    out, err = capsys.readouterr()
    assert "PREFLIGHT FAIL clean" in out and "PREFLIGHT FAIL gen" in out
    assert "PREFLIGHT ok   loopback" in out                       # every check still ran and reported
    assert "GATE" not in out and not (st / "runs").exists()       # the full gate never started
    assert out.splitlines()[-1] == "PREARM result=refused preflight=fail:clean,gen"
    assert "full gate did not run" in err
    assert json.loads((st / prearm.LAST_PREARM).read_text())["result"] == "refused"


def test_prearm_never_reuses_a_warm_result(tmp_path, capsys):
    root = _repo(tmp_path)
    st = tmp_path / "st"
    assert _cli(root, st, "run", "--changed", "tests/test_ok.py") == 0   # stores a green result warm
    capsys.readouterr()
    assert _cli(root, st, "prearm") == 0
    out = capsys.readouterr().out
    assert " warm=0 " in out and "ran=2" in out


def test_prearm_fails_on_a_red_file_and_attributes_it(tmp_path, capsys):
    root = _repo(tmp_path, {"tests/test_two.py": "def test_two():\n    assert 0\n"})
    assert _cli(root, tmp_path / "st", "prearm") == 1
    last = capsys.readouterr().out.splitlines()[-1]
    assert last.startswith("PREARM result=fail preflight=ok gate=fail") and "red_new=1 red_baseline=0" in last


def test_prearm_fails_on_an_env_file_that_a_plain_run_lets_through(tmp_path, capsys):
    env_test = "def test_needs_docker():\n    raise RuntimeError('Cannot connect to the Docker daemon at unix:///x')\n"
    root = _repo(tmp_path, {"tests/test_two.py": env_test})
    st = tmp_path / "st"
    assert _cli(root, st, "run", "--full") == 0                  # a plain full run: ENV is not red
    capsys.readouterr()
    assert _cli(root, st, "prearm") == 1                         # the pre-arm gate needs every file verified
    out, err = capsys.readouterr()
    assert "blocked by the environment" in err
    assert out.splitlines()[-1].startswith("PREARM result=fail") and "env=1" in out.splitlines()[-1]
