"""B-219: the solver filesystem fence (ctf.fence), its Claude/Codex renderings and the launchers.

Every fixture is synthetic: a fake $HOME under tmp_path for the policy tests. The two live tests
(needs_tool codex / claude) probe the installed CLIs and read nothing from a denied root.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import fence, fence_launch, paths

PY = sys.executable
REPO = paths.repo_root()


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home" / "player"
    h.mkdir(parents=True)
    return h.resolve()


@pytest.fixture
def ws(tmp_path):
    w = tmp_path / "work" / "csctf"
    w.mkdir(parents=True)
    return w.resolve()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "src" / "ctf-tools"
    r.mkdir(parents=True)
    return r.resolve()


def mk(home, ws, repo, **kw):
    kw.setdefault("user_dir", None)
    return fence.build(home=home, workspace=ws, repo=repo, **kw)


# ------------------------------------------------------------------------------------------ canon

def test_canon_folds_home_forms_firmlink_and_private(home):
    assert fence.canon("~/.codex/x", home=home) == home / ".codex/x"
    assert fence.canon("$HOME/.claude", home=home) == home / ".claude"
    assert fence.canon("${HOME}/.ssh/id", home=home) == home / ".ssh/id"
    assert fence.canon(f"/System/Volumes/Data{home}/.codex", home=home) == home / ".codex"
    assert fence.canon("/var/db/diagnostics", home=home) == Path("/private/var/db/diagnostics")
    assert fence.canon("/tmp/a/../b", home=home) == Path("/private/tmp/b")
    assert fence.canon("rel/x", home=home) is None
    assert fence.canon("../x", home=home, cwd="/a/b") == Path("/a/x")


# ------------------------------------------------------------------------------------- classify

def test_classify_roots_denies_and_outside(home, ws, repo):
    f = mk(home, ws, repo, drop=home / "Downloads" / "csctf")
    c = f.classify
    assert c(ws / "chal" / "a.bin").kind == "allowed"
    assert c(repo / "solvers" / "x.py").kind == "allowed"
    v = c("~/.codex/sessions/2026/11/07/rollout.jsonl")
    assert (v.kind, v.category) == ("denied", "agent-state")
    assert c(f"/System/Volumes/Data{home}/.claude/projects").category == "agent-state"
    assert c("~/Downloads/csctf/chal.zip").kind == "allowed"          # drop beats Downloads
    assert c("~/Downloads/other.zip").category == "downloads"
    assert c("~/Library/Application Support/discord/Cache/x").category == "messaging"
    assert c("~/Library/Application Support/Microsoft Edge/Default/History").category == "browser"
    assert c("~/Library/Group Containers/group.com.apple.usernoted/db2/db").category == "notifications"
    assert c("~/Library/Preferences/x.plist").category == "app-data"
    assert c("/var/db/diagnostics/Persist/x.tracev3").category == "unified-log"
    assert c("/Volumes/com.apple.TimeMachine.localsnapshots/Backups").category == "snapshots"
    assert c("~/pentest-tools/client/notes.md").category == "customer-work"
    assert c("/usr/share/dict/words").kind == "system"
    assert c("~/old-event-repo/README.md").kind == "outside-home"
    assert c("/Volumes/USB/x").kind == "outside"
    assert c("chal/a.bin", cwd=ws).kind == "allowed"
    assert c("../../.ssh/id_ed25519", cwd=home / "a" / "b").category == "credentials"
    assert c("relative/no/cwd") is None


def test_strict_home_denies_rest_of_home_but_keeps_roots(home, ws, repo, tmp_path):
    tool = home / ".local" / "share" / "uv" / "python"
    f = mk(home, ws, repo, strict_home=True, toolchain=[tool])
    assert f.classify("~/old-event-repo/README.md").category == "home"
    assert f.classify("~/.codex/x").category == "agent-state"          # most specific wins
    assert f.classify(tool / "bin" / "python3").kind == "allowed"
    assert f.classify(ws / "x").kind == "allowed"


def test_notification_db_under_darwin_user_dir(home, ws, repo):
    f = mk(home, ws, repo, user_dir=Path("/private/var/folders/ab/cd/0"))
    v = f.classify("/var/folders/ab/cd/0/com.apple.notificationcenter/db2/db")
    assert (v.kind, v.category) == ("denied", "notifications")
    assert f.classify("/var/folders/ab/cd/T/tmp.x").kind == "system"


# ----------------------------------------------------------------------------------- build errors

@pytest.mark.parametrize("bad,match", [
    (dict(workspace="HOME"), "is \\$HOME"),
    (dict(workspace="HOME/Library/ws"), "inside the denied app-data root"),
    (dict(workspace="HOME/Downloads/ws"), "inside the denied downloads root"),
    (dict(workspace="PARENT"), "contains the denied"),
    (dict(drop="HOME/Downloads"), "cannot be ~/Downloads itself"),
    (dict(drop="HOME/.codex/x"), "overlaps the denied agent-state"),
    (dict(extra_read=["HOME/Library/Caches"]), "will not re-open a denied store"),
    (dict(workspace="relative/ws"), "must be an absolute path"),
    (dict(workspace="/"), "cannot be /"),
])
def test_build_refuses_roots_that_defeat_the_fence(home, ws, repo, bad, match):
    def sub(v):
        if isinstance(v, list):
            return [sub(x) for x in v]
        return v.replace("HOME", str(home)).replace("PARENT", str(home.parent)) \
            if isinstance(v, str) and ("HOME" in v or v == "PARENT") else v
    kw = dict(workspace=ws, repo=repo)
    kw.update({k: sub(v) for k, v in bad.items()})
    with pytest.raises(fence.FenceError, match=match):
        fence.build(home=home, user_dir=None, **kw)


# ------------------------------------------------------------------------------------- config

def test_load_config_and_merge(tmp_path, home, ws, repo):
    root = tmp_path / "events"
    (root / "ev").mkdir(parents=True)
    (root / "ev" / "fence.toml").write_text(
        f'drop_folder = "{home}/Downloads/ev"\nallow_read = ["/opt/wordlists"]\n'
        f'deny_read = ["{home}/old-event-repo"]\nstrict_home = false\n')
    cfg = fence.load_config("ev", root=root)
    assert cfg.drop_folder == home / "Downloads" / "ev" and cfg.source.endswith("fence.toml")
    f = fence.from_config(cfg, home=home, workspace=ws, repo=repo, user_dir=None,
                          extra_read=["/srv/extra"])
    assert f.drop == home / "Downloads" / "ev"
    assert {Path("/opt/wordlists"), Path("/srv/extra")} <= set(f.extra_read)
    assert f.classify("~/old-event-repo/x").category == "operator"
    assert fence.load_config("nope", root=root) == fence.FenceConfig()
    assert fence.load_config(None, root=root) == fence.FenceConfig()


@pytest.mark.parametrize("body,match", [
    ('drop = "/x"\n', "unknown key"),
    ('allow_read = "/x"\n', "list of path strings"),
    ("strict_home = 1\n", "true or false"),
    ("drop_folder = [1]\n", "path string"),
    ("allow_read = [\n", "fence.toml"),
])
def test_load_config_errors_are_named(tmp_path, body, match):
    (tmp_path / "ev").mkdir()
    (tmp_path / "ev" / "fence.toml").write_text(body)
    with pytest.raises(fence.FenceError, match=match):
        fence.load_config("ev", root=tmp_path)


# ------------------------------------------------------------------------------- Claude settings

def test_claude_settings_with_drop_folder(home, ws, repo):
    drop = home / "Downloads" / "ev"
    s = mk(home, ws, repo, drop=drop, extra_read=["/opt/wordlists"]).claude_settings()
    p, sb = s["permissions"], s["sandbox"]
    assert f"Read(/{home}/.codex/**)" in p["deny"]
    assert f"Read(/{home}/.claude.json)" in p["deny"]                   # a file, no /**
    assert f"Read(/{home}/Library/**)" in p["deny"]
    assert "Read(//private/var/folders/**/com.apple.notificationcenter/**)" in p["deny"]
    # A Read deny on ~/Downloads would beat the drop folder; it is left to the sandbox and to
    # blockReadsOutsideWorkingDirectories instead.
    assert not any("/Downloads" in r for r in p["deny"])
    assert str(home / "Downloads") in sb["filesystem"]["denyRead"]
    assert p["blockReadsExemptPaths"] == [str(drop), "/opt/wordlists"]
    assert sb["filesystem"]["allowRead"] == [str(drop), "/opt/wordlists"]
    assert p["blockReadsOutsideWorkingDirectories"] is True
    assert p["additionalDirectories"] == [str(repo), str(ws)]
    assert p["disableBypassPermissionsMode"] == "disable"
    assert sb["enabled"] is True and sb["failIfUnavailable"] is True
    assert sb["allowUnsandboxedCommands"] is False
    assert sb["filesystem"]["allowWrite"] == [str(ws), str(repo)]
    for rule in ("Bash(log show *)", "Bash(tmutil *)", "Bash(mdfind *)", "Bash(mount_apfs *)"):
        assert rule in p["deny"]
    assert len(p["deny"]) == len(set(p["deny"]))


def test_claude_settings_without_drop_denies_downloads_to_file_tools(home, ws, repo):
    s = mk(home, ws, repo).claude_settings()
    assert f"Read(/{home}/Downloads/**)" in s["permissions"]["deny"]
    assert "blockReadsExemptPaths" not in s["permissions"]
    assert "allowRead" not in s["sandbox"]["filesystem"]


def test_claude_settings_strict_home(home, ws, repo):
    tool = Path("/opt/py")
    s = mk(home, ws, repo, strict_home=True, toolchain=[tool]).claude_settings()
    fs = s["sandbox"]["filesystem"]
    assert str(home) in fs["denyRead"]
    assert set(fs["allowRead"]) == {str(ws), str(repo), str(tool)}
    assert f"Read(/{home}/**)" not in s["permissions"]["deny"]


def test_write_claude_settings_mode_and_location(home, ws, repo):
    f = mk(home, ws, repo)
    dest = fence.write_claude_settings(f)
    assert dest == ws / ".fence" / "claude-settings.json"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert json.loads(dest.read_text()) == f.claude_settings()


# Every settings key the fence emits, as a dotted path. The live test checks each against the
# installed Claude Code so a schema change on upgrade fails here instead of being ignored.
EMITTED_KEYS = ("permissions.deny", "permissions.additionalDirectories",
                "permissions.blockReadsOutsideWorkingDirectories", "permissions.blockReadsExemptPaths",
                "permissions.disableBypassPermissionsMode", "sandbox.enabled",
                "sandbox.failIfUnavailable", "sandbox.allowUnsandboxedCommands",
                "sandbox.filesystem.denyRead", "sandbox.filesystem.allowRead",
                "sandbox.filesystem.allowWrite", "sandbox.filesystem.denyWrite")


def _dotted(d, pre=""):
    for k, v in d.items():
        if k == "$schema":
            continue
        if isinstance(v, dict):
            yield from _dotted(v, f"{pre}{k}.")
        else:
            yield f"{pre}{k}"


def test_emitted_keys_list_is_complete(home, ws, repo):
    s = mk(home, ws, repo, drop=home / "Downloads" / "x").claude_settings()
    assert set(_dotted(s)) == set(EMITTED_KEYS)


@pytest.mark.needs_tool("claude")
def test_emitted_keys_exist_in_installed_claude_schema():
    binary = Path(shutil.which("claude")).resolve()
    data = binary.read_bytes()
    missing = [k for k in EMITTED_KEYS if (k.rsplit(".", 1)[-1] + ":").encode() not in data]
    assert not missing, f"keys not in {binary.name}'s settings schema: {missing}"


# ------------------------------------------------------------------------------------- Codex

def test_codex_profile_and_config_args_are_valid_toml(home, ws, repo):
    drop = home / "Downloads" / "ev"
    f = mk(home, ws, repo, drop=drop)
    prof = f.codex_profile()
    assert prof["extends"] == ":workspace"
    fs = prof["filesystem"]
    assert fs[str(home / ".codex")] == "deny"
    assert fs[str(home / "Library" / "Application Support" / "Microsoft Edge")] == "deny"
    assert fs[str(home / "Downloads")] == "deny" and fs[str(drop)] == "read"
    assert fs[str(ws)] == "write" and fs[str(repo)] == "write"
    args = f.codex_config_args()
    assert args[0] == "-c" and args[2] == "-c" and args[3] == 'default_permissions="ctf_fence"'
    key, _, val = args[1].partition("=")
    assert key == "permissions.ctf_fence"
    assert tomllib.loads("v = " + val)["v"] == prof                      # round-trips exactly


def test_toml_inline_escapes_quotes_and_backslashes():
    v = {'a "q"': ["x\\y", True, 3], "b": {"c d": "e"}}
    assert tomllib.loads("v = " + fence.toml_inline(v))["v"] == v


def test_codex_argv_sets_fence_tier_and_approvals(home, ws, repo):
    f = mk(home, ws, repo)
    a = fence_launch.codex_argv(f, model="gpt-6-sol", effort="high", extra=["--search"], prompt="go")
    assert a[:3] == ["codex", "exec", "--skip-git-repo-check"]
    assert a[a.index("-C") + 1] == str(ws)
    assert 'default_permissions="ctf_fence"' in a and 'approval_policy="never"' in a
    for feat in ("fast_mode", "ultrafast_mode", "shell_snapshot"):
        i = [j for j, x in enumerate(a) if x == feat]
        assert i and a[i[0] - 1] == "--disable"
    assert "-s" not in a and "--sandbox" not in a
    assert not any("service_tier" in x for x in a)
    assert a[-1] == "go" and "--search" in a
    assert fence_launch.codex_argv(f, headless=False)[:2] == ["codex", "-C"]


@pytest.mark.parametrize("extra", [
    ["-s", "danger-full-access"], ["--sandbox=workspace-write"],
    ["--dangerously-bypass-approvals-and-sandbox"], ["--approve-for-me"], ["--add-dir", "/"],
    ["-c", 'service_tier="ultrafast"'], ["--config=sandbox_mode=\"danger-full-access\""],
    ["-c", "permissions.x={}"], ["-c", 'default_permissions="other"'], ["--enable", "ultrafast_mode"],
    ["--enable=fast_mode"], ["-p", "fast"], ["-a", "on-request"], ["-C", "/"],
])
def test_codex_argv_refuses_fence_breaking_args(home, ws, repo, extra):
    with pytest.raises(fence_launch.LaunchError, match="refused"):
        fence_launch.codex_argv(mk(home, ws, repo), extra=extra, prompt="x")


def test_codex_argv_allows_harmless_passthrough(home, ws, repo):
    a = fence_launch.codex_argv(mk(home, ws, repo), extra=["-c", 'model_verbosity="low"', "--json",
                                                            "--enable", "web_search"], prompt="x")
    assert 'model_verbosity="low"' in a and "web_search" in a


def test_codex_argv_rejects_unknown_approval(home, ws, repo):
    with pytest.raises(fence_launch.LaunchError, match="approval must be"):
        fence_launch.codex_argv(mk(home, ws, repo), approval="always")


@pytest.mark.parametrize("extra", [["--dangerously-skip-permissions"], ["--settings", "x.json"],
                                   ["--permission-mode", "bypassPermissions"],
                                   ["--permission-mode=bypassPermissions"], ["--add-dir", "/"]])
def test_claude_argv_refusals(extra):
    with pytest.raises(fence_launch.LaunchError, match="refused"):
        fence_launch.claude_argv(Path("/w/s.json"), extra=extra)


def test_claude_argv_passthrough():
    a = fence_launch.claude_argv(Path("/w/s.json"), extra=["--permission-mode", "auto", "-n", "x"])
    assert a == ["claude", "--settings", "/w/s.json", "--permission-mode", "auto", "-n", "x"]


# --------------------------------------------------------------------------------- the launchers

def _run_tool(name, *args, workdir, input_text=None):
    e = dict(os.environ, CTF_WORKDIR=str(workdir))
    e.pop("CTF_EVENT", None)
    return subprocess.run([PY, str(REPO / "tools" / name), *args], capture_output=True, text=True,
                          env=e, timeout=60, input=input_text)


def test_codex_launch_dry_run(tmp_path):
    w = tmp_path / "ws"
    r = _run_tool("codex_launch", "--dry-run", "solve it", workdir=w)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert out.startswith("codex exec --skip-git-repo-check -C ")
    assert "default_permissions=" in out and "<prompt>" in out and "solve it" not in out
    assert "--disable ultrafast_mode" in out


def test_codex_launch_refuses_and_names_reason(tmp_path):
    r = _run_tool("codex_launch", "--dry-run", "x", "--", "-s", "danger-full-access", workdir=tmp_path / "w")
    assert r.returncode == 2 and "refused codex argument -s" in r.stderr
    r = _run_tool("codex_launch", "--dry-run", workdir=tmp_path / "w")
    assert r.returncode == 2 and "needs a prompt" in r.stderr
    r = _run_tool("codex_launch", "--dry-run", "x", "--drop", str(Path.home() / "Downloads"),
                  workdir=tmp_path / "w")
    assert r.returncode == 2 and "cannot be ~/Downloads itself" in r.stderr


def test_claude_launch_dry_run_writes_settings(tmp_path):
    w = (tmp_path / "ws").resolve()
    r = _run_tool("claude_launch", "--dry-run", "--", "--permission-mode", "auto", workdir=w)
    assert r.returncode == 0, r.stderr
    s = w / ".fence" / "claude-settings.json"
    # B-032 puts the compaction window between the cd and claude (tests/test_compaction.py)
    assert f"--settings {s}" in r.stdout and r.stdout.startswith(f"cd {w} && ") and " claude --settings " in r.stdout
    data = json.loads(s.read_text())
    assert data["sandbox"]["failIfUnavailable"] is True
    r = _run_tool("claude_launch", "--dry-run", "--", "--dangerously-skip-permissions", workdir=w)
    assert r.returncode == 2 and "refused claude argument" in r.stderr


def test_launchers_are_executable():
    for name in ("codex_launch", "claude_launch"):
        assert os.access(REPO / "tools" / name, os.X_OK), name


# ------------------------------------------------------------------------------ the live probes

@pytest.mark.needs_tool("codex")
def test_codex_sandbox_enforces_the_fence(tmp_path):
    """Real `codex sandbox` runs (no model call): a canary under a denied root is unreadable, the
    same canary is readable without the fence (control), the workspace is readable, and existing
    denied roots in the real $HOME refuse even a stat."""
    from ctf import fence_selftest
    w = (tmp_path / "ws").resolve()
    f = fence.build(workspace=w, repo=REPO)
    checks = fence_selftest.codex_selftest(f, max_roots=8)
    names = {c.name for c in checks}
    assert {"workspace readable", "canary in a denied root blocked",
            "control: canary readable without the fence"} <= names
    control = next(c for c in checks if c.name == "control: canary readable without the fence")
    if not control.ok and "sandbox_apply: Operation not permitted" in control.detail:
        # Seatbelt cannot nest: when the suite itself runs under sandbox-exec, even the unfenced
        # control cannot start, so the probe cannot run here. Reported as not run, never green.
        pytest.skip("not run: nested Seatbelt not permitted (suite runs inside sandbox-exec)")
    bad = [(c.name, c.detail) for c in checks if not c.ok]
    assert not bad, bad
