"""B-196: the new-engine audit (ctf/integrity/newengines.py) over a synthetic git checkout: manifests added
since a ref (committed or untracked), each checked for a loading manifest, a test that imports its entry,
no hollow test and no fake branch without a non-fake test. Nothing is run."""
from __future__ import annotations

import argparse
import shutil

import pytest

from ctf import paths
from ctf.cli import integrity as integrity_cli
from ctf.integrity import IntegrityError, newengines
from gate_repo import git, make_repo, write


def manifest(name: str) -> str:
    return f'id = "web.{name}"\nlane = "web"\nentry = "solvers.web.{name}:solve"\n'


ENGINE = "def solve(x):\n    return x * 2\n"
FAKE_ENGINE = ('import os\n\ndef solve(x):\n    if os.environ.get("CTF_TESTING"):\n        return 0\n'
               '    return x\n')


@pytest.fixture
def repo(tmp_path):
    root = make_repo(tmp_path / "repo", {
        "solvers/web/old.py": ENGINE, "solvers/web/old.manifest.toml": manifest("old"),
        "tests/test_old.py": "from solvers.web import old\n\ndef test_old():\n    assert old.solve(2) == 4\n",
    })
    shutil.copytree(paths.repo_root() / "tools", root / "tools", ignore=lambda d, names: [
        n for n in names if n not in ("test_audit.py",)])
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "tools")
    git(root, "tag", "base")
    # committed after base: a tested engine
    write(root, {"solvers/web/ok.py": ENGINE, "solvers/web/ok.manifest.toml": manifest("ok"),
                 "tests/test_ok.py": "from solvers.web import ok\n\ndef test_ok():\n    assert ok.solve(3) == 6\n"})
    write(root, {"solvers/web/old.manifest.toml": manifest("old") + 'cost_class = "cheap"\n'})   # modified
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "ok engine")
    # untracked: an untested engine with a fake branch, a hollow-tested one, a broken manifest
    write(root, {"solvers/web/fake.py": FAKE_ENGINE, "solvers/web/fake.manifest.toml": manifest("fake"),
                 "solvers/web/hollow.py": ENGINE, "solvers/web/hollow.manifest.toml": manifest("hollow"),
                 "tests/test_hollow.py": "from solvers.web import hollow\n\ndef test_h():\n    hollow.solve(1)\n",
                 "solvers/web/broken.manifest.toml": 'id = "Web Broken"\n'})
    return root


def _audit(repo, tmp_path, **kw):
    return {a.manifest: a for a in newengines.audit(repo, "base", state=tmp_path / "s", config=repo / "gate.toml",
                                                    **kw)}


def test_added_manifests_are_committed_or_untracked_since_the_ref(repo):
    assert newengines.added_manifests(repo, "base") == [
        "solvers/web/broken.manifest.toml", "solvers/web/fake.manifest.toml", "solvers/web/hollow.manifest.toml",
        "solvers/web/ok.manifest.toml"]
    assert newengines.added_manifests(repo, "HEAD") == [
        "solvers/web/broken.manifest.toml", "solvers/web/fake.manifest.toml", "solvers/web/hollow.manifest.toml"]
    with pytest.raises(IntegrityError, match="unknown git ref 'no-such-ref'"):
        newengines.added_manifests(repo, "no-such-ref")


def test_each_engine_is_audited(repo, tmp_path):
    got = _audit(repo, tmp_path)
    ok = got["solvers/web/ok.manifest.toml"]
    assert ok.ok and ok.engine == "web.ok" and ok.entry == "solvers/web/ok.py" and ok.tests == ["tests/test_ok.py"]
    assert ok.mutate_command() == "python -m ctf integrity mutate solvers/web/ok.py --max 40"
    fake = got["solvers/web/fake.manifest.toml"]
    assert any("no test file reaches solvers/web/fake.py" in f for f in fake.findings)
    assert any(f.startswith("MISSING solvers/web/fake.py:4 solve") for f in fake.findings)
    hollow = got["solvers/web/hollow.manifest.toml"]
    assert hollow.tests == ["tests/test_hollow.py"]
    assert hollow.findings == ["hollow test tests/test_hollow.py:3 test_h: no-assert"]
    broken = got["solvers/web/broken.manifest.toml"]
    assert broken.findings and broken.findings[0].startswith("manifest does not load")


def test_a_tree_scanning_test_is_not_a_test_of_the_engine(repo, tmp_path):
    text = (repo / "gate.toml").read_text()
    (repo / "gate.toml").write_text(text + '\n[[scan]]\nwhy = "walks the tree"\ntests = ["tests/test_old.py"]\n'
                                           'inputs = ["solvers/**"]\n')
    fake = _audit(repo, tmp_path)["solvers/web/fake.manifest.toml"]
    assert fake.tests == [] and any("no test file reaches" in f for f in fake.findings)


def test_a_missing_entry_file_is_a_finding(repo, tmp_path):
    write(repo, {"solvers/web/ghost.manifest.toml": manifest("ghost")})
    ghost = _audit(repo, tmp_path, manifests=["solvers/web/ghost.manifest.toml"])["solvers/web/ghost.manifest.toml"]
    assert ghost.findings == ["entry file solvers/web/ghost.py does not exist"]


def test_the_cli_exit_and_output(repo, tmp_path, capsys):
    p = argparse.ArgumentParser()
    integrity_cli.add_arguments(p)
    args = p.parse_args(["--root", str(repo), "engines", "--base", "HEAD", "--state", str(tmp_path / "s")])
    # the synthetic checkout keeps its gate map at gate.toml; the CLI reads tests/gate.toml
    (repo / "tests/gate.toml").write_text((repo / "gate.toml").read_text())
    assert integrity_cli.run(args) == 1
    out = capsys.readouterr().out
    assert "FINDINGS  web.fake  entry=solvers/web/fake.py  tests=0" in out
    assert "next: python -m ctf integrity mutate solvers/web/fake.py --max 40" in out
    assert out.strip().endswith("ENGINES new=3 with_findings=3")


def test_the_default_state_and_a_bad_gate_config(repo, tmp_path):
    got = newengines.audit(repo, "HEAD", config=repo / "gate.toml",
                           manifests=["solvers/web/hollow.manifest.toml"])                   # state: the repo's
    assert [a.engine for a in got] == ["web.hollow"]
    assert (repo / ".git" / "ctf-gate").is_dir()
    (repo / "gate.toml").write_text("version = 2\n")
    with pytest.raises(IntegrityError, match="gate: .*version must be 1"):
        newengines.audit(repo, "HEAD", config=repo / "gate.toml", state=tmp_path / "s")


def test_a_cli_entry_audits_its_sidecar_module(repo, tmp_path):
    write(repo, {"solvers/web/tool.manifest.toml": 'id = "web.tool"\nlane = "web"\nentry = "cli:bash run.sh"\n',
                 "solvers/web/tool.py": ENGINE})
    tool = _audit(repo, tmp_path, manifests=["solvers/web/tool.manifest.toml"])["solvers/web/tool.manifest.toml"]
    assert tool.entry == "solvers/web/tool.py"
    assert tool.findings == ["no test file reaches solvers/web/tool.py: write one"]


def test_an_entry_the_gate_cannot_narrow_says_so(repo, tmp_path):
    text = (repo / "gate.toml").read_text()
    (repo / "gate.toml").write_text(text.replace('global = ["pytest.ini", "conftest.py", "gate.toml"]',
                                                 'global = ["pytest.ini", "conftest.py", "gate.toml", "solvers/web/ok.py"]'))
    ok = _audit(repo, tmp_path, manifests=["solvers/web/ok.manifest.toml"])["solvers/web/ok.manifest.toml"]
    assert ok.tests == [] and len(ok.findings) == 1
    assert ok.findings[0].startswith("the gate cannot map the entry file to tests (full: global input changed")


def test_nothing_added_is_an_empty_audit(repo, tmp_path):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "everything")
    assert newengines.audit(repo, "HEAD", state=tmp_path / "s", config=repo / "gate.toml") == []
