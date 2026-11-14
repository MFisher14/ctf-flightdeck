"""B-179: lane checkouts and the codex lane runner, driven against a stub `codex` on PATH.

No real Codex session is started: tests/_lanes_fixtures.py writes a stub executable that reads its
behaviour from a JSON file per lane, writes files, commits, and writes result.json."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from _lanes_fixtures import behave, calls, fake_venv, git, git_env, src_repo, stub_codex  # noqa: F401
from ctf.lanes import backlog as bl
from ctf.lanes import checkout as co
from ctf.lanes import layout, runner

# The runner loops on lane state: a regression there hangs instead of failing. Bound every test.
pytestmark = pytest.mark.timeout(120)


def make_backlog(**over):
    d = {"batch": "b1", "base": "main", "concurrency": 2, "timeout_minutes": 5,
         "context": ["docs/CONTRACTS.md"],
         "lanes": [
             {"id": "alpha", "title": "Alpha", "goal": "build alpha", "acceptance": ["alpha ok"],
              "owns": ["solvers/crypto/alpha.py", "tests/test_alpha.py"], "tests": ["tests/test_alpha.py"]},
             {"id": "beta", "title": "Beta", "goal": "build beta", "acceptance": ["beta ok"],
              "owns": ["solvers/crypto/beta.py", "tests/test_beta.py"], "tests": ["tests/test_beta.py"]},
             {"id": "gamma", "title": "Gamma", "goal": "build gamma", "acceptance": ["gamma ok"],
              "owns": ["solvers/crypto/gamma.py", "tests/test_gamma.py"], "tests": ["tests/test_gamma.py"],
              "depends": ["alpha"]},
         ]}
    d.update(over)
    return bl.parse(d)


def files_for(lane):
    return {f"solvers/crypto/{lane}.py": f"def solve(d, p):\n    return '{lane}'\n",
            f"tests/test_{lane}.py": "def test_x():\n    assert True\n"}


@pytest.fixture
def dirs(tmp_path):
    return layout.batch_dirs("b1", tmp_path / "state")


# ----------------------------------------------------------------------------------------- setup

def test_setup_creates_one_clone_per_lane_on_its_branch(src_repo, dirs, fake_venv):
    git(src_repo, "config", "core.hooksPath", ".githooks")
    b = make_backlog()
    out = co.setup(src_repo, b, dirs, venv=fake_venv)
    assert out == {"alpha": "created", "beta": "created", "gamma": "created"}
    base = git(src_repo, "rev-parse", "main")
    for lid in ("alpha", "beta", "gamma"):
        c = dirs.checkout(lid)
        assert (c / ".git").is_dir(), "a clone with its own .git, not a linked worktree"
        assert git(c, "symbolic-ref", "--short", "HEAD") == f"lane/b1/{lid}"
        assert git(c, "rev-parse", "HEAD") == base
        assert git(c, "remote") == "", "origin removed: a lane cannot push into the source"
        assert git(c, "config", "core.hooksPath") == ".githooks"
        assert co.base_of(c) == base and co.start_of(c) == base
        assert (c / ".venv").is_symlink() and (c / ".venv").resolve() == fake_venv.resolve()
        assert co.uncommitted(c) == [], ".venv link is excluded from git status"
        assert (c / "docs" / "CAPABILITIES.md").is_file()
        assert co.alternates(c) == [(src_repo / ".git" / "objects").resolve()]
    # the source repo is untouched: no new branches
    assert git(src_repo, "branch", "--list", "lane/*") == ""
    assert co.setup(src_repo, b, dirs, venv=fake_venv) == {"alpha": "exists", "beta": "exists", "gamma": "exists"}


def test_setup_refuses_foreign_folder_and_wrong_branch(src_repo, dirs, fake_venv):
    b = make_backlog()
    dirs.checkout("alpha").mkdir(parents=True)
    (dirs.checkout("alpha") / "keep.txt").write_text("mine")
    with pytest.raises(co.CheckoutError, match="exists and is not a lane checkout"):
        co.setup(src_repo, b, dirs, lane_ids=["alpha"], venv=fake_venv)
    assert (dirs.checkout("alpha") / "keep.txt").read_text() == "mine"
    co.setup(src_repo, b, dirs, lane_ids=["beta"], venv=fake_venv)
    git(dirs.checkout("beta"), "checkout", "-q", "-b", "other")
    with pytest.raises(co.CheckoutError, match="is on other, expected lane/b1/beta"):
        co.setup(src_repo, b, dirs, lane_ids=["beta"], venv=fake_venv)


def test_setup_fails_on_missing_base_or_context(src_repo, dirs, fake_venv):
    with pytest.raises(co.CheckoutError, match="base ref 'nope' does not resolve"):
        co.setup(src_repo, make_backlog(base="nope"), dirs, venv=fake_venv)
    b = make_backlog(context=["docs/CONTRACTS.md", "docs/MISSING.md"])
    with pytest.raises(co.CheckoutError, match=r"docs/MISSING.md \(\*\)"):
        co.setup(src_repo, b, dirs, venv=fake_venv)
    assert not dirs.checkout("alpha").exists()


def test_find_venv_names_what_is_missing(src_repo, fake_venv):
    with pytest.raises(co.CheckoutError, match="no venv"):
        co.find_venv(src_repo)
    (src_repo / ".venv").symlink_to(fake_venv)
    assert co.find_venv(src_repo) == fake_venv.resolve()


# ------------------------------------------------------------------------------------------- run

def test_run_launches_fenced_codex_per_lane_and_records_results(src_repo, dirs, fake_venv, stub_codex,
                                                                monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "do-not-leak")
    monkeypatch.setenv("CTF_COOKIE", "do-not-leak")
    for lid in ("alpha", "beta", "gamma"):
        behave(stub_codex, lid, files=files_for(lid))
    said = []
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, poll=0.05, say=said.append)
    assert {k: (v["state"], v["result_status"]) for k, v in out.items()} == {
        "alpha": ("done", "built"), "beta": ("done", "built"), "gamma": ("done", "built")}
    cs = {c["lane"]: c for c in calls(stub_codex)}
    assert set(cs) == {"alpha", "beta", "gamma"}
    for lid, c in cs.items():
        argv = c["argv"]
        assert argv[:2] == ["exec", "--skip-git-repo-check"]
        assert argv[argv.index("-C") + 1] == str(dirs.checkout(lid))
        assert 'default_permissions="ctf_fence"' in argv
        assert 'approval_policy="never"' in argv
        assert ["--disable", "fast_mode"] == argv[argv.index("fast_mode") - 1: argv.index("fast_mode") + 1]
        assert argv[argv.index("-o") + 1] == str(dirs.last_message(lid))
        perms = next(a for a in argv if a.startswith("permissions.ctf_fence="))
        assert f'"{dirs.checkout(lid)}" = "write"' in perms and f'"{dirs.lane_dir(lid)}" = "write"' in perms
        assert f'"{fake_venv.resolve()}" = "read"' in perms
        assert not c["has_token"] and not c["has_cookie"], "platform credentials are scrubbed"
        assert dirs.last_message(lid).read_text() == f"LANE DONE {lid}"
        assert dirs.prompt(lid).is_file()
    # gamma depends on alpha: it started after alpha ended, with alpha's work merged in
    assert cs["gamma"]["start"] >= cs["alpha"]["end"]
    assert (dirs.checkout("gamma") / "solvers" / "crypto" / "alpha.py").is_file()
    assert co.start_of(dirs.checkout("gamma")) != co.base_of(dirs.checkout("gamma"))
    assert any(s.startswith("[gamma] done (built)") for s in said)
    ev = [json.loads(x) for x in dirs.events.read_text().splitlines()]
    assert [e["event"] for e in ev].count("lane.start") == 3 and [e["event"] for e in ev].count("lane.end") == 3
    rows = {r["lane"]: r for r in runner.status_rows(make_backlog(), dirs)}
    assert rows["beta"]["state"] == "done" and rows["beta"]["result"] == "built"
    assert rows["beta"]["summary"] == "stub built beta"


def _overlaps(cs):
    iv = sorted((c["start"], c["end"]) for c in cs)
    return any(iv[i + 1][0] < iv[i][1] for i in range(len(iv) - 1))


def test_concurrency_cap_is_respected(src_repo, dirs, fake_venv, stub_codex):
    b = make_backlog(lanes=[
        {"id": f"l{i}", "title": f"L{i}", "goal": "g", "acceptance": ["a"],
         "owns": [f"solvers/crypto/l{i}.py", f"tests/test_l{i}.py"], "tests": [f"tests/test_l{i}.py"]}
        for i in range(3)])
    for i in range(3):
        behave(stub_codex, f"l{i}", sleep=0.4, files=files_for(f"l{i}"))
    runner.run(b, dirs, src_repo, venv=fake_venv, poll=0.02, concurrency=1, say=lambda s: None)
    assert len(calls(stub_codex)) == 3 and not _overlaps(calls(stub_codex))


def test_concurrency_above_one_runs_lanes_in_parallel(src_repo, dirs, fake_venv, stub_codex):
    b = make_backlog(lanes=[
        {"id": f"l{i}", "title": f"L{i}", "goal": "g", "acceptance": ["a"],
         "owns": [f"solvers/crypto/l{i}.py", f"tests/test_l{i}.py"], "tests": [f"tests/test_l{i}.py"]}
        for i in range(2)])
    for i in range(2):
        behave(stub_codex, f"l{i}", sleep=0.6, files=files_for(f"l{i}"))
    runner.run(b, dirs, src_repo, venv=fake_venv, poll=0.02, concurrency=2, say=lambda s: None)
    assert _overlaps(calls(stub_codex))


def test_failed_lane_skips_its_dependents(src_repo, dirs, fake_venv, stub_codex):
    behave(stub_codex, "alpha", exit=3, result=None)
    behave(stub_codex, "beta", files=files_for("beta"), result=None)
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, poll=0.05, say=lambda s: None)
    assert out["alpha"]["state"] == "failed" and out["alpha"]["exit_code"] == 3
    assert out["beta"]["state"] == "no-result" and "no result.json" in out["beta"]["reason"]
    assert out["gamma"]["state"] == "skipped" and "dependency alpha" in out["gamma"]["reason"]
    assert {c["lane"] for c in calls(stub_codex)} == {"alpha", "beta"}


def test_blocked_or_partial_dependency_skips_dependents(src_repo, dirs, fake_venv, stub_codex):
    behave(stub_codex, "alpha", result={"schema": 1, "lane": "alpha", "status": "partial", "summary": "half"})
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, poll=0.05, say=lambda s: None)
    assert (out["alpha"]["state"], out["alpha"]["result_status"]) == ("done", "partial")
    assert out["gamma"]["state"] == "skipped"


def test_invalid_result_is_no_result(src_repo, dirs, fake_venv, stub_codex):
    behave(stub_codex, "beta", result={"schema": 1, "lane": "alpha", "status": "built", "summary": "x"})
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, lane_ids=["beta"], poll=0.05,
                     say=lambda s: None)
    assert out["beta"]["state"] == "no-result" and "names 'alpha', expected 'beta'" in out["beta"]["reason"]


def test_timeout_kills_the_lane(src_repo, dirs, fake_venv, stub_codex):
    behave(stub_codex, "beta", sleep=30)
    import time
    t0 = time.monotonic()
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, lane_ids=["beta"], poll=0.05,
                     timeout_s=0.5, say=lambda s: None)
    assert out["beta"]["state"] == "timeout" and "killed after" in out["beta"]["reason"]
    assert time.monotonic() - t0 < 15
    assert calls(stub_codex) == [], "the stub never reached its end"


def test_done_lanes_are_not_relaunched_unless_rerun(src_repo, dirs, fake_venv, stub_codex):
    behave(stub_codex, "beta", files=files_for("beta"))
    b = make_backlog()
    runner.run(b, dirs, src_repo, venv=fake_venv, lane_ids=["beta"], poll=0.05, say=lambda s: None)
    said = []
    runner.run(b, dirs, src_repo, venv=fake_venv, lane_ids=["beta"], poll=0.05, say=said.append)
    assert len(calls(stub_codex)) == 1 and "already done" in said[0]
    behave(stub_codex, "beta", result={"schema": 1, "lane": "beta", "status": "built", "summary": "again"})
    runner.run(b, dirs, src_repo, venv=fake_venv, lane_ids=["beta"], poll=0.05, rerun=True, say=lambda s: None)
    assert len(calls(stub_codex)) == 2


def test_dependency_outside_the_selection_that_never_ran_is_skipped(src_repo, dirs, fake_venv, stub_codex):
    out = runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, lane_ids=["gamma"], poll=0.05,
                     say=lambda s: None)
    assert out["gamma"]["state"] == "skipped" and "not in this run" in out["gamma"]["reason"]
    assert calls(stub_codex) == []


def test_missing_codex_fails_loudly(src_repo, dirs, fake_venv, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.delenv("CODEX_BIN", raising=False)
    with pytest.raises(runner.RunnerError, match="codex CLI not found"):
        runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, say=lambda s: None)
    with pytest.raises(runner.RunnerError, match="unknown lane"):
        runner.run(make_backlog(), dirs, src_repo, lane_ids=["zzz"], say=lambda s: None)


def test_dry_run_prints_commands_without_checkouts(src_repo, dirs, fake_venv, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")        # system tools (getconf), no codex
    monkeypatch.delenv("CODEX_BIN", raising=False)
    out = runner.run(make_backlog(codex={"model": "m1", "effort": "low", "extra": ["--json"]}), dirs, src_repo,
                     venv=fake_venv, dry_run=True, say=lambda s: None)
    argv = out["alpha"]["argv"]
    assert argv[0] == "codex" and argv[-1] == f"<prompt: {dirs.prompt('alpha')}>"
    assert argv[argv.index("-m") + 1] == "m1" and 'model_reasoning_effort="low"' in argv and "--json" in argv
    assert not dirs.checkout("alpha").exists()
    assert dirs.prompt("alpha").is_file()


def test_fence_reopens_borrowed_objects_and_honours_strict_home(src_repo, dirs, fake_venv, monkeypatch):
    b = make_backlog(codex={"strict_home": True})
    co.setup(src_repo, b, dirs, lane_ids=["alpha"], venv=fake_venv)
    f = runner.lane_fence(b, dirs, "alpha", fake_venv)
    assert f.strict_home and any(d.category == "home" for d in f.deny)
    assert (src_repo / ".git" / "objects").resolve() in f.extra_read
    assert fake_venv.resolve() in f.extra_read
    assert f.workspace == dirs.checkout("alpha") and f.repo == dirs.lane_dir("alpha")
    assert not runner.lane_fence(make_backlog(), dirs, "alpha", fake_venv).strict_home


def test_dependency_merge_conflict_is_a_lane_error(src_repo, dirs, fake_venv, stub_codex):
    b = make_backlog()
    behave(stub_codex, "alpha", files={**files_for("alpha"), "docs/CONTRACTS.md": "alpha view\n"},
           result={"schema": 1, "lane": "alpha", "status": "built", "summary": "a",
                   "shared_files": ["docs/CONTRACTS.md"]})
    co.setup(src_repo, b, dirs, venv=fake_venv)
    g = dirs.checkout("gamma")
    (g / "docs" / "CONTRACTS.md").write_text("gamma view\n")
    git(g, "commit", "-qam", "gamma local")
    out = runner.run(b, dirs, src_repo, venv=fake_venv, lane_ids=["alpha", "gamma"], poll=0.05,
                     say=lambda s: None)
    assert out["alpha"]["state"] == "done"
    assert out["gamma"]["state"] == "error" and "merging dependency lane/b1/alpha conflicts" in out["gamma"]["reason"]
    assert {c["lane"] for c in calls(stub_codex)} == {"alpha"}
    assert co.uncommitted(g) == [], "the failed merge was aborted"


def test_merge_dependencies_runs_once(src_repo, dirs, fake_venv):
    b = make_backlog()
    co.setup(src_repo, b, dirs, venv=fake_venv)
    a = dirs.checkout("alpha")
    (a / "solvers" / "crypto" / "alpha.py").write_text("x = 1\n")
    git(a, "add", "-A")
    git(a, "commit", "-qm", "alpha")
    g = dirs.checkout("gamma")
    first = co.merge_dependencies(g, [(b.branch("alpha"), a)])
    assert co.start_of(g) == first == co.head(g) and (g / "solvers/crypto/alpha.py").is_file()
    (a / "solvers" / "crypto" / "alpha.py").write_text("x = 2\n")
    git(a, "commit", "-qam", "alpha again")
    assert co.merge_dependencies(g, [(b.branch("alpha"), a)]) == first
    assert (g / "solvers/crypto/alpha.py").read_text() == "x = 1\n"


def test_cli_prompts_and_check_errors(tmp_path):
    import yaml
    from ctf import paths
    data = {"batch": "cli2", "base": "main",
            "lanes": [{"id": "alpha", "title": "Alpha", "goal": "g", "acceptance": ["a"],
                       "owns": ["solvers/crypto/alpha.py", "tests/test_alpha.py"], "tests": ["tests/test_alpha.py"]}]}
    bfile = tmp_path / "b.yaml"
    bfile.write_text(yaml.safe_dump(data))
    common = ["--lanes-dir", str(tmp_path / "st")]
    r = subprocess.run([sys.executable, "-m", "ctf", "lanes", "prompts", str(bfile), "--print", "alpha"] + common,
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "# Lane alpha: Alpha" in r.stdout and str(tmp_path / "st" / "cli2" / "prompts" / "PACK.md") in r.stdout
    data["lanes"][0]["goal"] = "Do it like the previous prompt."
    bfile.write_text(yaml.safe_dump(data))
    r = subprocess.run([sys.executable, "-m", "ctf", "lanes", "check", str(bfile), "--no-repo"] + common,
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "refers to text it does not contain" in r.stderr


def test_lane_env_scrubs_legacy_credential_spellings(monkeypatch):
    from ctf import env as _env
    legacy = _env.legacy_names("CTF_TOKEN")[0]
    monkeypatch.setenv(legacy, "x")
    monkeypatch.setenv("CTF_COOKIE", "y")
    monkeypatch.setenv("KEEP_ME", "z")
    e = runner.lane_env()
    assert legacy not in e and "CTF_COOKIE" not in e and e["KEEP_ME"] == "z"


@pytest.mark.parametrize("name", ["CTF_PLATFORM_URL", "CTF_TEAM_ID", "CTF_RUN_LIVE"])
def test_lane_env_scrubs_platform_identity_and_live_switch(monkeypatch, name):
    from ctf import env as _env
    for k in (name, *_env.legacy_names(name)):
        monkeypatch.setenv(k, "1")
    monkeypatch.setenv("CTF_TESTING", "1")
    e = runner.lane_env()
    assert not [k for k in (name, *_env.legacy_names(name)) if k in e]
    assert e["CTF_TESTING"] == "1", "only the named platform variables are removed"


@pytest.mark.parametrize("bad", [0, -1])
def test_zero_or_negative_concurrency_is_refused(src_repo, dirs, fake_venv, stub_codex, bad):
    with pytest.raises(runner.RunnerError, match=rf"concurrency must be at least 1 \(got {bad}\)"):
        runner.run(make_backlog(), dirs, src_repo, venv=fake_venv, concurrency=bad, say=lambda s: None)
    assert calls(stub_codex) == [] and not dirs.checkout("alpha").exists()


def test_cli_run_and_status_end_to_end(src_repo, tmp_path, fake_venv, stub_codex):
    bfile = tmp_path / "b.yaml"
    import yaml
    bfile.write_text(yaml.safe_dump({
        "batch": "cli1", "base": "main",
        "lanes": [{"id": "alpha", "title": "Alpha", "goal": "g", "acceptance": ["a"],
                   "owns": ["solvers/crypto/alpha.py", "tests/test_alpha.py"], "tests": ["tests/test_alpha.py"]}]}))
    behave(stub_codex, "alpha", files=files_for("alpha"))
    from ctf import paths
    base = [sys.executable, "-m", "ctf", "lanes"]
    common = ["--lanes-dir", str(tmp_path / "st")]
    r = subprocess.run(base + ["check", str(bfile), "--repo", str(src_repo)] + common, cwd=paths.repo_root(),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "base main = " in r.stdout and "alpha" in r.stdout
    r = subprocess.run(base + ["run", str(bfile), "--repo", str(src_repo), "--venv", str(fake_venv),
                               "--poll", "0.05"] + common,
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1/1 lane(s) done and built" in r.stdout
    r = subprocess.run(base + ["status", str(bfile)] + common, cwd=paths.repo_root(),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "alpha" in r.stdout and "done" in r.stdout and "built" in r.stdout
    r = subprocess.run(base + ["check", str(tmp_path / "missing.yaml"), "--no-repo"] + common,
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "backlog file not found" in r.stderr
