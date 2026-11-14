"""One engine runner (B-187): ctf run / tools/ctfpy, isolated interpreter, engine sys.path, ledger hook.

Every engine here is a small script this test writes; nothing from a challenge is executed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import ledger, paths
from ctf.engines import manifest as M
from ctf.engines import runner as R

REPO = paths.repo_root()
CTFPY = REPO / "tools" / "ctfpy"


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _manifest(root, lane, name, entry, caps='["cli", "legacy-output", "analysis"]'):
    _w(root, f"solvers/{lane}/{name}.manifest.toml",
       f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "{entry}"\ncapabilities = {caps}\n'
       '[[routes]]\nkeywords = ["' + name + '"]\n')


@pytest.fixture
def root(tmp_path):
    """A throwaway checkout: the real ctf package (symlinked) plus synthetic engines."""
    r = tmp_path / "repo"
    r.mkdir()
    (r / "ctf").symlink_to(REPO / "ctf", target_is_directory=True)
    # a sibling in another lane, imported flat: proves the engine sys.path
    _w(r, "solvers/common/helper_mod.py", "VALUE = 'from-common'\n")
    _w(r, "solvers/toolkits/echo_engine.py",
       "import sys, helper_mod\n"
       "def main(argv):\n"
       "    print('ARGS', json.dumps(argv)); print('HELPER', helper_mod.VALUE)\n"
       "    print('ISOLATED', sys.flags.isolated)\n"
       "    code = int(argv[0]) if argv and argv[0].isdigit() else 0\n"
       "    return code\n"
       "import json\n"
       "if __name__ == '__main__':\n    raise SystemExit(main(sys.argv[1:]))\n")
    _manifest(r, "toolkits", "echo_engine", "cli:python solvers/toolkits/echo_engine.py")
    _w(r, "solvers/toolkits/lib_only.py", "def parse(x):\n    return x\n")
    _manifest(r, "toolkits", "lib_only", "solvers.toolkits.lib_only:parse", caps='["library"]')
    _w(r, "solvers/web/contract_fn.py",
       "from ctf.result import SolverResult, Evidence\n"
       "def solve(challenge_dir, profile, **opts):\n"
       "    data = (challenge_dir / 'f.txt').read_text()\n"
       "    flags = profile and __import__('ctf.flagfmt', fromlist=['x']).for_profile(profile).find_flags(data)\n"
       "    if not flags:\n        return SolverResult('none', notes=str(opts))\n"
       "    return SolverResult('solved', flags=flags, evidence=[Evidence('text', 'f.txt')], notes=str(opts))\n")
    _manifest(r, "web", "contract_fn", "solvers.web.contract_fn:solve", caps='["executes"]')
    _w(r, "solvers/web/contract_cli.py",
       "import sys\nfrom ctf.result import SolverResult\n"
       "if __name__ == '__main__':\n"
       "    print('working...')\n"
       "    print(SolverResult('none').to_json() if sys.argv[1:] != ['bad'] else 'not json')\n")
    _manifest(r, "web", "contract_cli", "cli:python solvers/web/contract_cli.py", caps='["analysis", "cli"]')
    return r


def _env(workdir: Path | None, **extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CTF_", "CSCTF_", "HUNTRESS_", "PYTHON"))}
    if workdir is not None:
        env["CTF_WORKDIR"] = str(workdir)
    env.update(extra)
    return env


def _run(root, engine, args, workdir, **kw):
    cmd = R.command(engine, args, root=root, **{k: v for k, v in kw.items() if k in ("record", "challenge_id")})
    return subprocess.run(cmd, capture_output=True, text=True, env=_env(workdir, **kw.get("env", {})), timeout=60)


def test_resolve_by_id_name_basename_and_path(root):
    ms = M.discover(root)
    for name in ("toolkits.echo_engine", "echo_engine", "echo_engine.py",
                 str(root / "solvers/toolkits/echo_engine.py"),
                 str(root / "solvers/toolkits/echo_engine.manifest.toml")):
        assert R.resolve(name, root=root, manifests=ms).id == "toolkits.echo_engine", name


def test_resolve_errors_name_candidates(root):
    _w(root, "solvers/common/echo_engine.py", "def solve(): pass\n")
    _manifest(root, "common", "echo_engine", "solvers.common.echo_engine:solve", caps='["library"]')
    with pytest.raises(R.EngineError, match="ambiguous: common.echo_engine, toolkits.echo_engine"):
        R.resolve("echo_engine", root=root)
    with pytest.raises(R.EngineError, match="did you mean: .*contract_fn"):
        R.resolve("contract_fm", root=root)


def test_legacy_cli_engine_runs_isolated_with_flat_imports_and_is_recorded(root, tmp_path):
    wd = tmp_path / "wd"
    p = _run(root, "echo_engine", ["--json", "x y", "$HOME"], wd, challenge_id="42",
             env={"PYTHONPATH": str(tmp_path / "nowhere")})
    assert p.returncode == 0, p.stderr
    assert 'ARGS ["--json", "x y", "$HOME"]' in p.stdout          # args passed verbatim, no shell
    assert "HELPER from-common" in p.stdout and "ISOLATED 1" in p.stdout
    recs = list(ledger.read(wd))
    assert len(recs) == 1 and recs[0]["event"] == "engine.run"
    assert recs[0]["engine"] == "toolkits.echo_engine" and recs[0]["exit_code"] == 0
    assert recs[0]["via"] == "ctf-run" and recs[0]["challenge_id"] == "42" and "status" not in recs[0]


def test_exit_code_is_passed_through_and_recorded(root, tmp_path):
    wd = tmp_path / "wd"
    p = _run(root, "toolkits.echo_engine", ["3"], wd)
    assert p.returncode == 3
    assert [r["exit_code"] for r in ledger.read(wd)] == [3]


def test_no_ledger_flag_and_env_switch_record_nothing(root, tmp_path):
    wd = tmp_path / "wd"
    assert _run(root, "echo_engine", [], wd, record=False).returncode == 0
    assert _run(root, "echo_engine", [], wd, env={"CTF_ENGINE_LEDGER": "0"}).returncode == 0
    assert list(ledger.read(wd)) == []


def test_without_a_workdir_the_run_happens_and_says_it_was_not_recorded(root):
    p = _run(root, "echo_engine", [], None)
    assert p.returncode == 0 and "HELPER from-common" in p.stdout
    assert "not recorded in the ledger" in p.stderr and "CTF_EVENT" in p.stderr


def test_library_engine_is_refused(root, tmp_path):
    p = _run(root, "lib_only", [], tmp_path / "wd")
    assert p.returncode == 2 and "import-only (library)" in p.stderr


def test_contract_function_engine_gets_dir_profile_and_opts(root, tmp_path):
    chal = tmp_path / "chal"
    _w(chal, "f.txt", "noise CSCTF{runner_ok} noise")
    wd = tmp_path / "wd"
    p = _run(root, "web.contract_fn", [str(chal), "--opt", "depth=2", "--opt", "mode=fast", "--event", "csctf"], wd)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["status"] == "solved" and out["flags"] == ["CSCTF{runner_ok}"]
    assert out["notes"] == str({"depth": 2, "mode": "fast"})
    assert [r["status"] for r in ledger.read(wd)] == ["solved"]


def test_contract_function_engine_needs_a_challenge_dir(root, tmp_path):
    p = _run(root, "web.contract_fn", [], tmp_path / "wd")
    assert p.returncode == 1 and "usage: ctf run" in p.stderr


def test_contract_cli_engine_result_is_parsed_or_flagged(root, tmp_path):
    wd = tmp_path / "wd"
    p = _run(root, "web.contract_cli", [], wd)
    assert p.returncode == 0 and "working..." in p.stdout
    p2 = _run(root, "web.contract_cli", ["bad"], wd)
    assert p2.returncode == 0 and "did not end with a SolverResult JSON line" in p2.stderr
    assert [r.get("status") for r in ledger.read(wd)] == ["none", None]


def test_ctf_run_parser_passes_engine_flags_through():
    from ctf.cli import run as cli_run
    p = argparse.ArgumentParser()
    cli_run.add_arguments(p)
    a = p.parse_args(["--no-ledger", "network", "--json", "-h", "file.pcap"])
    assert a.engine == "network" and a.args == ["--json", "-h", "file.pcap"] and a.no_ledger


def test_ctf_run_cli_reports_an_unknown_engine(capsys):
    from ctf.cli import main
    assert main(["run", "--no-ledger", "no_such_engine_zz"]) == 2
    assert "no engine 'no_such_engine_zz'" in capsys.readouterr().err


# ---- tools/ctfpy -------------------------------------------------------------------------------

def _ctfpy(args, cwd, **env):
    return subprocess.run([str(CTFPY), *args], capture_output=True, text=True, cwd=cwd, timeout=60,
                          env=_env(None, **{"CTF_PYTHON": sys.executable, **env}))


def test_ctfpy_c_mode_has_flat_engine_imports_in_isolated_mode(tmp_path):
    p = _ctfpy(["-c", "import sys, crib_decode, ctf; print(sys.flags.isolated, crib_decode.__file__, sys.argv[1:])",
                "a1"], tmp_path)
    assert p.returncode == 0, p.stderr
    iso, path, argv = p.stdout.split(" ", 2)
    assert iso == "1" and path == str(REPO / "solvers/warmups/crib_decode.py") and argv.strip() == "['a1']"


def test_ctfpy_runs_a_plain_script_like_python_and_passes_exit_codes(tmp_path):
    s = _w(tmp_path / "scripts", "s.py", "import sys, helper_here\nprint(helper_here.X)\nsys.exit(5)\n")
    _w(tmp_path / "scripts", "helper_here.py", "X = 'sibling-ok'\n")
    p = _ctfpy([str(s)], tmp_path)
    assert p.returncode == 5 and p.stdout.strip() == "sibling-ok"


def test_ctfpy_m_mode(tmp_path):
    p = _ctfpy(["-m", "ctf", "engines", "show", "warmups.crib_decode"], tmp_path)
    assert p.returncode == 0, p.stderr
    assert 'id = "warmups.crib_decode"' in p.stdout


def test_ctfpy_works_through_a_symlink_and_reports_its_checkout(tmp_path):
    link = tmp_path / "bin" / "ctfpy"
    link.parent.mkdir()
    link.symlink_to(CTFPY)
    p = subprocess.run([str(link), "--info"], capture_output=True, text=True, cwd=tmp_path, timeout=60,
                       env=_env(None, CTF_PYTHON=sys.executable))
    assert p.returncode == 0, p.stderr
    assert f"repo     {REPO}" in p.stdout and str(REPO / "solvers" / "toolkits") in p.stdout


def test_ctfpy_fails_loudly_without_an_interpreter(tmp_path):
    p = _ctfpy(["--info"], tmp_path, CTF_PYTHON=str(tmp_path / "missing-python"))
    assert p.returncode == 2 and "not an executable interpreter" in p.stderr


def test_ctfpy_unknown_engine_is_named(tmp_path):
    p = _ctfpy(["--no-ledger", "no_such_engine_zz"], tmp_path)
    assert p.returncode == 2 and "no engine 'no_such_engine_zz'" in p.stderr
