"""R-03: the read fence denies the repo's gitignored sensitive trees (analysis/, docs/writeups/,
writeups/, .claude/, .ctf/) and any .ctf/ directory, in every rendering (classify, Claude Code
settings, Codex profile, launchers) and in the denied-access report.

All fixtures are synthetic: a fake $HOME, repo and workspace under tmp_path. The one live test
(needs_tool codex) runs `codex sandbox` probes (no model call) on files this test wrote.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import fence, fence_report, paths

PY = sys.executable
REPO = paths.repo_root()

PRIVATE = ("analysis", "docs/writeups", "writeups", ".claude", ".ctf")


@pytest.fixture
def env3(tmp_path):
    home = tmp_path / "home" / "player"
    ws = tmp_path / "work" / "ev"
    repo = tmp_path / "src" / "ctf-tools"
    for d in (home, ws, repo):
        d.mkdir(parents=True)
    home, ws, repo = home.resolve(), ws.resolve(), repo.resolve()
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None)
    return f, home, ws, repo, tmp_path


# ------------------------------------------------------------------------------------- classify

@pytest.mark.parametrize("rel,category", [
    ("analysis/out/reports/sessions/csctf-codex.md", "repo-private"),
    ("analysis", "repo-private"),
    ("docs/writeups/pink/flag.png", "repo-private"),
    ("writeups/staging/spooky.md", "repo-private"),
    (".claude/worktrees/wf_x/analysis/out/a.json", "agent-state"),
    (".ctf/token", "credentials"),
    ("events/csctf/.ctf/cookie", "credentials"),
])
def test_repo_private_trees_are_denied(env3, rel, category):
    f, _home, _ws, repo, _ = env3
    v = f.classify(repo / rel)
    assert (v.kind, v.category) == ("denied", category), v


@pytest.mark.parametrize("rel", ["solvers/web/x.py", "ctf/fence.py", "docs/BUILDING.md",
                                 "docs/fence.md", "tools/codex_launch", "templates/a.toml",
                                 "events/csctf/event.toml", "solvers/x.ctf", "solvers/.ctfrc",
                                 "docs/writeups-index.md", "analysis.md"])
def test_rest_of_repo_stays_readable(env3, rel):
    f, _home, _ws, repo, _ = env3
    assert f.classify(repo / rel).kind == "allowed"


def test_any_ctf_directory_is_denied_wherever_it_is(env3):
    f, home, ws, _repo, tmp = env3
    for p in (ws / ".ctf" / "token", ws / "chal" / "deep" / ".ctf" / "cfg.json",
              home / "2026-ctf-x" / ".ctf" / "token", tmp / "elsewhere" / ".ctf"):
        v = f.classify(p)
        assert (v.kind, v.category) == ("denied", "credentials"), p
        assert v.root.name == ".ctf"
    assert f.classify(ws / "chal" / "a.ctf.txt").kind == "allowed"


def test_relative_path_into_repo_tree_resolves_against_cwd(env3):
    f, _home, ws, repo, _ = env3
    assert f.classify("analysis/out/x.json", cwd=repo).category == "repo-private"
    # The same relative path from the workspace is the workspace's own folder: allowed.
    assert f.classify("analysis/out/x.json", cwd=ws).kind == "allowed"
    assert f.classify(".ctf/token", cwd=ws).category == "credentials"


def test_watched_names(env3):
    f = env3[0]
    assert f.watched_names() == {"analysis", "docs", "writeups", ".claude", ".ctf"}


# --------------------------------------------------------------------------------------- build

def test_repo_carve_outs_do_not_trip_the_containment_check(env3):
    f, _home, _ws, repo, _ = env3
    carved = {str(d.path.relative_to(repo)): d for d in f.deny if d.carved_from == repo}
    assert set(carved) == set(PRIVATE)


@pytest.mark.parametrize("bad,match", [
    (dict(workspace="REPO/analysis/ws"), "inside the denied repo-private root"),
    (dict(workspace="REPO/.claude/worktrees/w"), "inside the denied agent-state root"),
    (dict(workspace="REPO"), "contains the denied"),
    (dict(workspace="TMP/x/.ctf/ws"), "inside a .ctf/ directory"),
    (dict(extra_read=["REPO/analysis/out"]), "will not re-open a denied store"),
    (dict(extra_read=["REPO/docs"]), "will not re-open a denied store"),
    (dict(extra_read=["TMP/creds/.ctf"]), "inside a .ctf/ directory"),
    (dict(drop="HOME/Downloads/ev/.ctf"), "inside a .ctf/ directory"),
    (dict(repo="TMP/src/.ctf/r"), "inside a .ctf/ directory"),
])
def test_build_refuses_roots_inside_private_trees(env3, bad, match):
    _f, home, ws, repo, tmp = env3

    roots = {"REPO": str(repo), "HOME": str(home), "TMP": str(tmp)}

    def sub(v):
        if isinstance(v, list):
            return [sub(x) for x in v]
        return re.sub(r"^(REPO|HOME|TMP)", lambda m: roots[m.group(1)], v)
    kw = dict(workspace=ws, repo=repo)
    kw.update({k: sub(v) for k, v in bad.items()})
    with pytest.raises(fence.FenceError, match=match):
        fence.build(home=home, user_dir=None, **kw)


def test_describe_lists_name_denies(env3):
    d = env3[0].describe()
    assert d["deny_names"] == [{"category": "credentials", "name": ".ctf",
                                "globs": ["/**/.ctf", "/**/.ctf/**"],
                                "reason": fence.DENY_NAMES[0][2]}]
    paths_ = {r["path"] for r in d["deny"]}
    assert str(env3[3] / "analysis") in paths_


# ---------------------------------------------------------------------------------- renderings

@pytest.mark.parametrize("strict", [False, True])
def test_claude_settings_deny_private_trees(env3, strict):
    _f, home, ws, repo, _ = env3
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None, strict_home=strict,
                    toolchain=[Path("/opt/py")])
    s = f.claude_settings()
    deny, fs = s["permissions"]["deny"], s["sandbox"]["filesystem"]
    for rel in PRIVATE:
        assert f"Read(/{repo / rel}/**)" in deny, rel          # the file tools
        assert str(repo / rel) in fs["denyRead"], rel           # sandboxed Bash
    for g in ("/**/.ctf", "/**/.ctf/**"):
        assert f"Read(/{g})" in deny and g in fs["denyRead"]
    assert str(repo) in s["permissions"]["additionalDirectories"]   # the rest stays a root
    assert len(deny) == len(set(deny))


def test_codex_profile_denies_private_trees_inside_writable_repo(env3):
    f, _home, _ws, repo, _ = env3
    prof = f.codex_profile()
    fs = prof["filesystem"]
    assert fs[str(repo)] == "write"
    for rel in PRIVATE:
        assert fs[str(repo / rel)] == "deny", rel
    assert fs["/**/.ctf"] == "deny" and fs["/**/.ctf/**"] == "deny"
    key, _, val = f.codex_config_args()[1].partition("=")
    assert tomllib.loads("v = " + val)["v"] == prof


def _run_tool(name, *args, workdir):
    e = dict(os.environ, CTF_WORKDIR=str(workdir))
    e.pop("CTF_EVENT", None)
    return subprocess.run([PY, str(REPO / "tools" / name), *args], capture_output=True, text=True,
                          env=e, timeout=60)


def test_codex_launcher_carries_the_repo_denies(env3):
    _f, _home, ws, repo, _ = env3
    r = _run_tool("codex_launch", "--dry-run", "--repo", str(repo), "x", workdir=ws)
    assert r.returncode == 0, r.stderr
    assert f'"{repo}/analysis" = "deny"' in r.stdout
    assert '"/**/.ctf" = "deny"' in r.stdout


def test_claude_launcher_settings_carry_the_repo_denies(env3):
    _f, _home, ws, repo, _ = env3
    r = _run_tool("claude_launch", "--dry-run", "--repo", str(repo), workdir=ws)
    assert r.returncode == 0, r.stderr
    data = json.loads((ws / ".fence" / "claude-settings.json").read_text())
    assert f"Read(/{repo}/analysis/**)" in data["permissions"]["deny"]
    assert str(repo / "docs" / "writeups") in data["sandbox"]["filesystem"]["denyRead"]


# ------------------------------------------------------------------------------ denied-access report

def _jsonl(path: Path, rows) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def test_report_flags_reads_of_repo_private_trees(env3):
    f, _home, ws, repo, tmp = env3

    def use(i, name, inp, cwd=ws):
        return {"type": "assistant", "cwd": str(cwd), "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}]}}

    def res(i, text, err=False):
        return {"type": "user", "cwd": str(ws), "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "is_error": err,
             "content": [{"type": "text", "text": text}]}]}}
    target = repo / "analysis" / "out" / "reports" / "sessions" / "s.md"
    log = _jsonl(tmp / "t.jsonl", [
        use(1, "Read", {"file_path": str(target)}),
        res(1, "Permission to read this file has been denied by the permission settings", err=True),
        use(2, "Bash", {"command": f"cd {repo} && cat analysis/out/usage.json | head"}),
        res(2, "cat: analysis/out/usage.json: Operation not permitted", err=True),
        use(3, "Bash", {"command": "cat .ctf/token"}),
        res(3, "cat: .ctf/token: Operation not permitted", err=True),
        use(4, "Grep", {"path": str(repo / "docs" / "writeups"), "pattern": "flag"}),
        res(4, "x"),
        use(5, "Bash", {"command": "ls .claude/worktrees", "description": "x"}, cwd=repo),
        res(5, "wf_a"),
        # Not reported: ordinary repo and workspace reads, relative paths that stay allowed.
        use(6, "Bash", {"command": f"cat {repo}/docs/fence.md && cat docs/BUILDING.md"}, cwd=repo),
        res(6, "ok"),
        use(7, "Bash", {"command": "python3 solve.py analysis/notes.txt"}),
        res(7, "ok"),
    ])
    rep = fence_report.scan_files([log], f)
    got = {(a.source, a.tool, a.category, a.outcome, a.path) for a in rep.accesses}
    assert got == {
        ("t.jsonl:1", "Read", "repo-private", "blocked", str(target)),
        ("t.jsonl:3", "Bash", "repo-private", "blocked", str(repo / "analysis/out/usage.json")),
        ("t.jsonl:5", "Bash", "credentials", "blocked", str(ws / ".ctf/token")),
        ("t.jsonl:7", "Grep", "repo-private", "ran", str(repo / "docs/writeups")),
        ("t.jsonl:9", "Bash", "agent-state", "ran", str(repo / ".claude/worktrees")),
    }
    text = fence_report.render_text(rep)
    assert "repo-private 3" in text and "credentials 1" in text and "agent-state 1" in text


def test_report_codex_rollout_python_open_of_analysis(env3):
    f, _home, ws, repo, tmp = env3
    code = "python3 -c \"print(open('analysis/out/reports/x.md').read()[:50])\""
    rows = [{"type": "response_item", "payload": {
        "type": "function_call", "name": "exec_command", "call_id": "c1",
        "arguments": json.dumps({"cmd": code, "workdir": str(repo)})}},
        {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1",
                                              "output": "PermissionError: Operation not permitted"}}]
    rep = fence_report.scan_files([_jsonl(tmp / "r.jsonl", rows)], f)
    assert [(a.category, a.outcome, a.path) for a in rep.accesses] == [
        ("repo-private", "blocked", str(repo / "analysis/out/reports/x.md"))]


@pytest.mark.parametrize("cmd,names,expected", [
    ("cat analysis/out/x.json", {"analysis"}, ["analysis/out/x.json"]),
    ("cat ./.ctf/token", {".ctf"}, ["./.ctf/token"]),
    ("ls writeups", {"writeups"}, ["writeups"]),
    ("cat analysis/out/x.json", set(), []),                  # no names: relative words ignored
    ("grep -r analysis_mode src", {"analysis"}, []),        # a name prefix is not the name
    ("python3 -c \"open('analysis/a')\"", {"analysis"}, ["analysis/a"]),
    ("cat ./ctf-tools/.ctf", {".ctf"}, ["./ctf-tools/.ctf"]),
    ("cat a/b/analysis_x/c", {"analysis"}, []),
    # An option or assignment prefix is split off; the word itself is not read as a path.
    # (A one-letter option is read as taking the rest as its argument, as for -I/usr/include.)
    ("gcc -Ictf-tools/analysis/inc x.c", {"analysis"}, ["ctf-tools/analysis/inc"]),
    ("tool --file=ctf-tools/.ctf/t", {".ctf"}, ["ctf-tools/.ctf/t"]),
    ("F=analysis/x run", {"analysis"}, ["analysis/x"]),
])
def test_extract_paths_relative_watched_names(cmd, names, expected):
    assert fence_report.extract_paths(cmd, names) == expected


def test_relative_cd_without_known_cwd_reports_nothing_relative(env3):
    f, *_ = env3
    acc = fence_report.classify_command(f, "cd somewhere && cat analysis/out/x", cwd=None,
                                        source="s:1", tool="text", outcome="unknown")
    assert acc == []


@pytest.mark.parametrize("move", ["cd {repo}", "pushd {repo}", "pushd {repo} >/dev/null",
                                  "pushd {repo} > /dev/null 2>&1", "cd {repo} &>/dev/null"])
def test_cd_and_pushd_move_the_cwd_for_later_segments(env3, move):
    f, _home, ws, repo, _ = env3
    acc = fence_report.classify_command(f, move.format(repo=repo) + " && cat analysis/out/x",
                                        cwd=str(ws), source="s:1", tool="Bash", outcome="ran")
    assert [(a.category, a.path) for a in acc] == [("repo-private", str(repo / "analysis/out/x"))]


@pytest.mark.parametrize("cmd", ["cd {repo} extra && cat analysis/out/x",
                                 "echo cd {repo} && cat analysis/out/x",
                                 "cd - && cat analysis/out/x"])
def test_non_plain_cd_does_not_move_the_cwd(env3, cmd):
    # From the workspace, analysis/out/x is the workspace's own folder: nothing to report.
    f, _home, ws, repo, _ = env3
    acc = fence_report.classify_command(f, cmd.format(repo=repo), cwd=str(ws), source="s:1",
                                        tool="Bash", outcome="ran")
    assert acc == []


@pytest.fixture
def home_repo(tmp_path):
    """A repo at $HOME/ctf-tools, so relative words from $HOME reach it."""
    home = (tmp_path / "home" / "player")
    ws = tmp_path / "work" / "ev"
    for d in (home / "ctf-tools", ws):
        d.mkdir(parents=True)
    home, ws = home.resolve(), ws.resolve()
    repo = home / "ctf-tools"
    return fence.build(home=home, workspace=ws, repo=repo, user_dir=None), home, ws, repo


def _acc(f, cmd, cwd):
    return [(a.category, a.path) for a in fence_report.classify_command(
        f, cmd, cwd=None if cwd is None else str(cwd), source="s:1", tool="Bash", outcome="ran")]


def test_relative_cd_resolves_against_the_known_cwd(home_repo):
    # `cd ctf-tools` from $HOME lands in the repo; the next read is the repo's analysis/.
    f, home, _ws, repo = home_repo
    assert _acc(f, "cd ctf-tools && cat analysis/out/x", home) == [
        ("repo-private", str(repo / "analysis/out/x"))]
    # From the workspace, the same cd lands in <ws>/ctf-tools: nothing private there.
    assert _acc(f, "cd ctf-tools && cat analysis/out/x", _ws) == []


@pytest.mark.parametrize("cmd,rel,category", [
    ("cat ctf-tools/analysis/x", "analysis/x", "repo-private"),
    ("cat ./ctf-tools/.ctf/token", ".ctf/token", "credentials"),
    ("ls ctf-tools/.ctf", ".ctf", "credentials"),
    ("cat ctf-tools/docs/writeups/a.md", "docs/writeups/a.md", "repo-private"),
    ("python3 -c \"open('ctf-tools/analysis/out/u.json')\"", "analysis/out/u.json", "repo-private"),
])
def test_watched_name_deeper_in_a_relative_word_is_reported(home_repo, cmd, rel, category):
    f, home, _ws, repo = home_repo
    assert _acc(f, cmd, home) == [(category, str(repo / rel))]


def test_any_relative_ctf_component_is_credentials(home_repo):
    f, _home, ws, _repo = home_repo
    assert _acc(f, "cat chal/deep/.ctf/cfg.json", ws) == [("credentials", str(ws / "chal/deep/.ctf/cfg.json"))]
    # Unknown cwd: a relative word cannot be placed, so nothing is guessed.
    assert _acc(f, "cat chal/deep/.ctf/cfg.json", None) == []


@pytest.mark.parametrize("cmd", ["cat ctf-tools/solvers/analysis/x",   # resolves to an allowed path
                                 "cat ctf-tools/analysis_mode/x",        # a prefix is not the name
                                 "cat $X/analysis/y",                    # unknown variable
                                 "curl https://h/analysis/x"])           # a URL
def test_relative_words_that_are_not_private_reads(home_repo, cmd):
    f, home, _ws, _repo = home_repo
    assert _acc(f, cmd, home) == []


@pytest.mark.parametrize("cmd", ["(cd ctf-tools; cat analysis/x)",
                                 "( cd ctf-tools && cat analysis/x )",
                                 "$(cd ctf-tools; cat analysis/x)"])
def test_subshell_cd_applies_inside_and_path_loses_the_paren(home_repo, cmd):
    f, home, _ws, repo = home_repo
    assert _acc(f, cmd, home) == [("repo-private", str(repo / "analysis/x"))]


def test_subshell_cd_does_not_outlive_the_subshell(home_repo):
    # After `(cd ctf-tools; ...)` the shell is back in $HOME: analysis/x there is $HOME's own
    # folder (an outside read), not the repo's.
    f, home, _ws, repo = home_repo
    assert _acc(f, "(cd ctf-tools; ls) && cat analysis/x", home) == [
        ("home-other", str(home / "analysis/x"))]
    assert _acc(f, "(cd ctf-tools; ls) && cat ctf-tools/analysis/x", home) == [
        ("repo-private", str(repo / "analysis/x"))]
    # A nested subshell and a balanced `$(...)` close only their own level.
    assert _acc(f, "(cd ctf-tools; (ls; echo $(pwd)); cat analysis/x)", home) == [
        ("repo-private", str(repo / "analysis/x"))]
    # Without parentheses the cd does persist.
    assert _acc(f, "cd ctf-tools; ls; cat analysis/x", home) == [
        ("repo-private", str(repo / "analysis/x"))]


@pytest.mark.parametrize("blank", ['cd ""', "cd ''", "pushd ' '"])
def test_blank_cd_keeps_the_known_cwd(env3, blank):
    # `cd ""` leaves the shell where it was, so a relative read after it still resolves there.
    f, _home, _ws, repo, _ = env3
    acc = fence_report.classify_command(f, f"{blank} && cat analysis/out/x", cwd=str(repo),
                                        source="s:1", tool="Bash", outcome="ran")
    assert [(a.category, a.path) for a in acc] == [("repo-private", str(repo / "analysis/out/x"))]


@pytest.mark.parametrize("strict", [False, True])
def test_claude_settings_deny_writes_into_private_trees(env3, strict):
    _f, home, ws, repo, _ = env3
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None, strict_home=strict,
                    toolchain=[Path("/opt/py")])
    s = f.claude_settings()
    deny, fs = s["permissions"]["deny"], s["sandbox"]["filesystem"]
    expect = [str(repo / rel) for rel in PRIVATE] + ["/**/.ctf", "/**/.ctf/**"]
    assert fs["denyWrite"] == expect                       # sandboxed Bash, exactly these
    for p in expect[:len(PRIVATE)]:
        assert f"Edit(/{p}/**)" in deny, p                 # the edit tools (Edit, Write, ...)
    for g in ("/**/.ctf", "/**/.ctf/**"):
        assert f"Edit(/{g})" in deny, g
    # The write roots stay writable: no Edit deny or denyWrite covers the roots themselves.
    assert not any(r in (f"Edit(/{repo}/**)", f"Edit(/{ws}/**)") for r in deny)
    assert set(fs["allowWrite"]) == {str(ws), str(repo)}


def _stub_codex(tmp: Path) -> tuple[Path, Path]:
    """A fake `codex` that logs its argv and refuses every probe like a sandbox would."""
    log = tmp / "codex-argv.log"
    stub = tmp / "bin" / "codex"
    stub.parent.mkdir(parents=True)
    stub.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n"
                    "echo 'stat: Operation not permitted' >&2\nexit 1\n")
    stub.chmod(0o755)
    return stub, log


def test_selftest_probes_repo_carve_outs_first_under_max_roots(env3):
    """With a max_roots cap the stat probes are the repo's private trees, ahead of the many home
    and system denies that also exist (stub codex: no sandbox, no model)."""
    from ctf import fence_selftest
    _f, home, ws, repo, tmp = env3
    for rel in PRIVATE:
        (repo / rel).mkdir(parents=True)
    for rel in (".ssh", ".aws", ".codex", "Library", "Downloads", "Desktop", "Documents"):
        (home / rel).mkdir()
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None)
    stub, log = _stub_codex(tmp)
    checks = fence_selftest.codex_selftest(f, codex_bin=str(stub), max_roots=len(PRIVATE))
    probed = [line.rsplit(" ", 1)[1] for line in log.read_text().splitlines()
              if "/usr/bin/stat -f %z " in line]
    assert sorted(probed) == sorted(str(repo / rel) for rel in PRIVATE)
    stat_checks = [c for c in checks if c.name.endswith(tuple(str(repo / r) for r in PRIVATE))]
    assert len(stat_checks) == len(PRIVATE) and all(c.ok for c in stat_checks)


def test_cli_check_and_report_exit_codes(env3):
    _f, home, ws, repo, tmp = env3
    base = [PY, "-m", "ctf", "fence"]
    e = dict(os.environ, HOME=str(home))
    e.pop("CTF_EVENT", None)
    opts = ["--workspace", str(ws), "--repo", str(repo), "--no-config"]
    r = subprocess.run(base + ["check", *opts, str(repo / "analysis/out/reports/x.md"),
                               str(repo / "solvers/a.py")],
                       capture_output=True, text=True, env=e, cwd=REPO, timeout=60)
    assert r.returncode == 1, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0].startswith("denied:repo-private") and lines[1].startswith("allowed")
    log = tmp / "cmds.log"
    log.write_text(f"cat {repo}/analysis/out/reports/sessions/a.md\n")
    r = subprocess.run(base + ["report", *opts, "--json", str(log)], capture_output=True, text=True,
                       env=e, cwd=REPO, timeout=60)
    assert r.returncode == 1, r.stderr
    d = json.loads(r.stdout)
    assert d["by_category"] == {"repo-private": 1}


# ------------------------------------------------------------------------------- the live probe

@pytest.mark.needs_tool("codex")
def test_codex_sandbox_blocks_repo_private_and_nested_ctf(tmp_path):
    """Real `codex sandbox` runs (no model call) against a synthetic repo: the private trees and
    a .ctf/ nested in the workspace are unreadable, while the rest of the repo is readable."""
    from ctf import fence_selftest
    repo = (tmp_path / "src" / "ctf-tools").resolve()
    ws = (tmp_path / "ws").resolve()
    for rel in PRIVATE:
        (repo / rel).mkdir(parents=True)
        (repo / rel / "secret.txt").write_text("CANARY-SHOULD-NOT-BE-READ\n")
    (repo / "solvers").mkdir()
    (repo / "solvers" / "ok.py").write_text("READABLE\n")
    f = fence.build(workspace=ws, repo=repo)
    checks = fence_selftest.codex_selftest(f, max_roots=len(PRIVATE))
    control = next(c for c in checks if c.name == "control: canary readable without the fence")
    if not control.ok and "sandbox_apply: Operation not permitted" in control.detail:
        pytest.skip("not run: nested Seatbelt not permitted (suite runs inside sandbox-exec)")
    names = {c.name: c for c in checks}
    for rel, cat in zip(PRIVATE, ("repo-private",) * 3 + ("agent-state", "credentials")):
        assert names[f"{cat}: {repo / rel}"].ok, rel
    assert names["credentials: a .ctf/ inside the workspace blocked"].ok
    r = fence_selftest._sandbox("codex", f, ["/bin/cat", str(repo / "solvers" / "ok.py")], 60)
    assert r.returncode == 0 and "READABLE" in r.stdout, r.stderr
    r = fence_selftest._sandbox("codex", f, ["/bin/cat", str(repo / "analysis" / "secret.txt")], 60)
    assert r.returncode != 0 and "CANARY" not in r.stdout
