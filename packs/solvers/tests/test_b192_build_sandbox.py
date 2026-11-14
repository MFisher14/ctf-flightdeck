"""B-192: the Codex sandbox profile for repo build work (ctf/build_sandbox.py, `ctf build-sandbox`).

Synthetic git repos are built inside each test; nothing touches the real checkout's git state, no
codex session starts, and the one live check (`codex sandbox`, no model call) is reported as not run
inside a sandbox (macOS cannot nest one) or without the codex CLI.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import build_sandbox as bs
from ctf import paths, sandboxinfo
from ctf.cli import build_sandbox as cli
from ctf.fence import DENY_NAMES
from ctf.fence_launch import LaunchError

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
HOSTS = [bs.Host("pypi.org", "index")]


def git(cwd: Path, *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, env={**os.environ, **GIT_ENV}, capture_output=True,
                       text=True)
    assert r.returncode == 0, (args, r.stderr)
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A main checkout (branch main, one commit) and a linked worktree on branch feature."""
    main = tmp_path / "main"
    git(tmp_path, "init", "-q", "-b", "main", str(main))
    git(main, "commit", "-q", "--allow-empty", "-m", "init")
    wt = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "-b", "feature", str(wt))
    return main.resolve(), wt.resolve()


@pytest.fixture
def no_events(tmp_path):
    root = tmp_path / "events-empty"
    root.mkdir()
    return root


def profile(wt, home, events_root, **kw):
    kw.setdefault("hosts", HOSTS)
    return bs.build(wt, home=home, events_root=events_root, **kw)


# ----------------------------------------------------------------------------------- git layout
def test_layout_of_a_linked_worktree_and_of_the_main_checkout(repo):
    main, wt = repo
    lay = bs.git_layout(wt)
    assert lay.checkout == wt
    assert lay.common == main / ".git"
    assert lay.gitdir == main / ".git" / "worktrees" / "wt"
    assert lay.linked
    m = bs.git_layout(main)
    assert m.gitdir == m.common == main / ".git" and not m.linked


def test_layout_refuses_a_folder_that_is_not_a_checkout(tmp_path):
    with pytest.raises(bs.BuildSandboxError, match="not a git checkout"):
        bs.git_layout(tmp_path)
    with pytest.raises(bs.BuildSandboxError, match="not a directory"):
        bs.git_layout(tmp_path / "missing")


# -------------------------------------------------------------------------------------- profile
def test_filesystem_writes_checkout_gitdir_and_common_but_not_hooks_config_or_main(repo, tmp_path, no_events):
    main, wt = repo
    home = tmp_path / "home"
    fs = profile(wt, home, no_events).filesystem()
    g = main / ".git"
    assert fs[str(wt)] == "write"
    assert fs[str(g)] == "write"
    assert fs[str(g / "worktrees" / "wt")] == "write"
    assert fs[str(g / "hooks")] == "read"
    assert fs[str(g / "config")] == "read"
    # protected branches: the ref file itself (a plain write or rm moved main past a .lock-only
    # guard) and its .lock (git's update path), for main and master
    for b in ("main", "master"):
        assert fs[str(g / "refs" / "heads" / b)] == "read", b
        assert fs[str(g / "refs" / "heads" / f"{b}.lock")] == "read", b
    assert str(g / "refs" / "heads" / "feature") not in fs
    assert str(g / "refs" / "heads" / "feature.lock") not in fs
    # packed-refs can hold a protected branch; the main checkout's HEAD; per-worktree config
    assert fs[str(g / "packed-refs")] == fs[str(g / "packed-refs.lock")] == "read"
    assert fs[str(g / "HEAD")] == "read"
    assert fs[str(g / "config.worktree")] == fs[str(g / "worktrees" / "wt" / "config.worktree")] == "read"
    assert str(g / "worktrees" / "wt" / "HEAD") not in fs     # the lane's own HEAD stays writable
    for name in DENY_NAMES:
        assert fs[f"/**/{name[1]}"] == "deny" and fs[f"/**/{name[1]}/**"] == "deny"
    hr = home.resolve()
    for rel in (".codex", ".claude", ".ssh", ".netrc", "pentest-tools", "Library/Keychains"):
        assert fs[str(hr / rel)] == "deny", rel
    # ~/.config holds tool tokens (gh, gcloud, ...): denied; git's and uv's config re-opened read
    # only (a more specific entry wins), but not git's credential store
    assert fs[str(hr / ".config")] == "deny"
    assert fs[str(hr / ".config" / "git")] == fs[str(hr / ".config" / "uv")] == "read"
    assert fs[str(hr / ".config" / "git" / "credentials")] == "deny"
    assert str(hr / ".config" / "gh") not in fs
    # the build profile is not the solver fence: Downloads and the rest of $HOME stay readable
    assert str(hr / "Downloads") not in fs and str(hr) not in fs


def test_the_main_checkouts_head_is_writable_when_the_lane_is_the_main_checkout(repo, tmp_path, no_events):
    main, _ = repo
    fs = profile(main, tmp_path / "home", no_events).filesystem()
    assert str(main / ".git" / "HEAD") not in fs          # git checkout there must still work
    assert fs[str(main / ".git" / "refs" / "heads" / "main")] == "read"


@pytest.mark.parametrize("hooks_path, where", [
    (None, lambda main, wt: main / ".git" / "hooks"),
    (".hk", lambda main, wt: wt / ".hk"),                  # relative: resolved against the lane
    ("ABS", lambda main, wt: main.parent / "shared-hooks"),
])
def test_the_hooks_folder_git_runs_is_read_only(repo, tmp_path, no_events, hooks_path, where):
    """core.hooksPath (this repo points it at .githooks): hooks run outside the sandbox, so the
    folder git actually runs them from stays read only, even inside the writable checkout."""
    main, wt = repo
    if hooks_path is not None:
        git(main, "config", "core.hooksPath",
            str(main.parent / "shared-hooks") if hooks_path == "ABS" else hooks_path)
    p = profile(wt, tmp_path / "home", no_events)
    want = where(main, wt)
    assert p.layout.hooks == want
    assert p.filesystem()[str(want)] == "read"
    assert p.describe()["hooks"] == str(want)


def test_protected_branches_add_the_integration_branch_and_protect(repo, tmp_path, no_events):
    main, wt = repo
    home = tmp_path / "home"
    heads = main / ".git" / "refs" / "heads"
    p = profile(wt, home, no_events, environ={})
    assert p.protected == ("main", "master") and p.integration_branch is None
    assert p.describe()["integration_branch"] is None
    # the argument, then $CTF_INTEGRATION_BRANCH, then git config ctftools.integrationBranch
    p = profile(wt, home, no_events, integration_branch="build/phase-x", environ={})
    assert p.protected == ("main", "master", "build/phase-x")
    fs = p.filesystem()
    assert fs[str(heads / "build" / "phase-x")] == fs[str(heads / "build" / "phase-x.lock")] == "read"
    p = profile(wt, home, no_events, environ={"CTF_INTEGRATION_BRANCH": "from-env"})
    assert p.integration_branch == "from-env" and "from-env" in p.protected
    git(main, "config", "ctftools.integrationBranch", "from-config")
    p = profile(wt, home, no_events, environ={}, protect=["release", "main"])
    assert p.protected == ("main", "master", "from-config", "release")
    assert p.filesystem()[str(heads / "release")] == "read"
    assert p.describe()["protected_branches"] == ["main", "master", "from-config", "release"]
    with pytest.raises(bs.BuildSandboxError, match="not a valid branch name"):
        profile(wt, home, no_events, environ={}, protect=["bad..name"])


def test_cli_show_names_the_protected_branches_and_the_hooks_folder(repo, tmp_path, capsys, monkeypatch):
    _, wt = repo
    monkeypatch.setattr(bs, "checked_hosts", lambda **kw: tuple(HOSTS))
    monkeypatch.delenv("CTF_INTEGRATION_BRANCH", raising=False)
    assert cli.run(cli_args(["show", "--checkout", str(wt), "--protect", "keep-me"])) == 0
    out = capsys.readouterr().out
    assert "protected  main, master, keep-me" in out and "no integration branch configured" in out
    assert cli.run(cli_args(["show", "--checkout", str(wt), "--integration-branch", "integ"])) == 0
    out = capsys.readouterr().out
    assert "protected  main, master, integ" in out and "no integration branch" not in out


def test_network_is_loopback_plus_allowlist_and_docker_only_when_asked(repo, tmp_path, no_events):
    _, wt = repo
    home = tmp_path / "home"
    net = profile(wt, home, no_events).network()
    assert net == {"enabled": True, "allow_local_binding": True, "domains": {"pypi.org": "allow"}}
    dnet = profile(wt, home, no_events, docker=True).network()
    hr = home.resolve()
    assert dnet["unix_sockets"] == {"/var/run/docker.sock": "allow",
                                    str(hr / ".docker" / "run" / "docker.sock"): "allow"}
    with pytest.raises(bs.BuildSandboxError, match="absolute"):
        profile(wt, home, no_events, unix_sockets=["relative/sock"])


def test_config_args_define_select_and_always_turn_the_proxy_on(repo, tmp_path, no_events):
    _, wt = repo
    p = profile(wt, tmp_path / "home", no_events)
    args = p.codex_config_args()
    assert args[0::2] == ["-c", "-c", "-c"]
    key, _, value = args[1].partition("=")
    assert key == "permissions.ctf_build"
    assert tomllib.loads(f"v = {value}")["v"] == p.codex_profile()
    assert p.codex_profile()["extends"] == ":workspace"
    assert args[3] == 'default_permissions="ctf_build"'
    # network.enabled without the managed proxy is the whole network (verified live): never apart
    assert args[5] == "features.network_proxy=true"
    with pytest.raises(bs.BuildSandboxError, match="letters"):
        p.codex_config_args('x" = 1 #')


def test_config_toml_fragment_round_trips_and_does_not_select_the_profile(repo, tmp_path, no_events):
    _, wt = repo
    p = profile(wt, tmp_path / "home", no_events, docker=True)
    doc = tomllib.loads(p.config_toml())
    assert doc["features"] == {"network_proxy": True}
    assert doc["permissions"]["ctf_build"] == p.codex_profile()
    assert "default_permissions" not in doc


def test_a_checkout_inside_a_denied_store_is_refused(tmp_path, no_events):
    home = tmp_path / "home"
    inside = home / ".codex" / "repo"
    inside.mkdir(parents=True)
    git(inside, "init", "-q")
    with pytest.raises(bs.BuildSandboxError, match="inside a denied store"):
        bs.build(inside, home=home, hosts=HOSTS, events_root=no_events)


# ------------------------------------------------------------------------------------ allowlist
def test_the_repo_allowlist_loads_and_passes_its_checks():
    hosts = bs.checked_hosts()
    names = [h.name for h in hosts]
    assert "pypi.org" in names and "files.pythonhosted.org" in names
    assert all(h.why for h in hosts)
    assert len(names) == len(set(names))


@pytest.mark.parametrize("body, why", [
    ('[[host]]\nname = "pypi.org"\n', "non-empty why"),
    ('[[host]]\nname = "pypi.org"\nwhy = "x"\nport = 443\n', "unknown key"),
    ('[[host]]\nname = "*.github.com"\nwhy = "x"\n', "wildcard"),
    ('[[host]]\nname = "10.0.0.1"\nwhy = "x"\n', "IP address"),
    ('[[host]]\nname = "https://pypi.org/simple"\nwhy = "x"\n', "bare host name"),
    ('[[host]]\nname = "pypi.org:443"\nwhy = "x"\n', "bare host name"),
    ('[[host]]\nname = "pypi.org"\nwhy = "x"\n[[host]]\nname = "PyPI.org"\nwhy = "y"\n', "twice"),
    ('allow = ["pypi.org"]\n', "unknown key"),
    ('host = "pypi.org"\n', "array of tables"),
    ('[[host]\n', "not valid TOML"),
])
def test_load_hosts_refuses_bad_entries(tmp_path, body, why):
    f = tmp_path / "hosts.toml"
    f.write_text(body)
    with pytest.raises(bs.BuildSandboxError, match=why):
        bs.load_hosts(f)


def test_load_hosts_missing_file_fails_loudly(tmp_path):
    with pytest.raises(bs.BuildSandboxError, match="not found"):
        bs.load_hosts(tmp_path / "nope.toml")


def _event(root: Path, slug: str, base_url: str, hosts=(), scope=()) -> None:
    src = (paths.events_root() / "csctf" / "event.toml").read_text()
    src = src.replace('slug = "csctf"', f'slug = "{slug}"')
    src = src.replace('base_url = "https://2026.ctf-platform.example"',
                      f'base_url = "{base_url}"\nhosts = {list(hosts)!r}'.replace("'", '"'))
    src = src.replace('live_service_scope = ["*.ctf-platform.example"]',
                      f"live_service_scope = {list(scope)!r}".replace("'", '"'))
    (root / slug).mkdir(parents=True)
    (root / slug / "event.toml").write_text(src)


def test_host_conflicts_names_event_platforms_live_scopes_chat_and_model_apis(tmp_path):
    root = tmp_path / "events"
    _event(root, "evt", "https://plat.example.org", hosts=["proxy.example.net"], scope=["*.svc.example.com"])
    hosts = [bs.Host(n, "x") for n in ("plat.example.org", "api.plat.example.org", "proxy.example.net",
                                        "example.org", "example.net",
                                        "box.svc.example.com", "svc.example.com", "pypi.org",
                                        "cdn.discordapp.com", "api.openai.com", "anthropic.com")]
    plist = bs.host_conflicts(hosts, events_root=root)
    # a parent domain of a platform host would let the proxy reach the platform too (exact line:
    # a substring check would also match "plat.example.org: ...")
    assert "example.org: event 'evt' platform host plat.example.org" in plist
    assert "example.net: event 'evt' platform host proxy.example.net" in plist
    problems = "\n".join(plist)
    for bad in ("plat.example.org: event 'evt' platform", "api.plat.example.org: event 'evt' platform",
                "proxy.example.net: event 'evt' platform",
                "box.svc.example.com: event 'evt' live_service_scope",
                "svc.example.com: event 'evt' live_service_scope", "cdn.discordapp.com: Discord",
                "api.openai.com: a model API", "anthropic.com: a model API"):
        assert bad in problems, bad
    assert "pypi.org" not in problems
    with pytest.raises(bs.BuildSandboxError, match="plat.example.org"):
        bs.build(".", hosts=[bs.Host("plat.example.org", "x")], events_root=root)


def test_an_event_profile_that_does_not_load_is_a_conflict(tmp_path):
    root = tmp_path / "events"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / "event.toml").write_text("slug = \n")
    problems = bs.host_conflicts([bs.Host("pypi.org", "x")], events_root=root)
    assert len(problems) == 1 and "'broken' does not load" in problems[0]


def test_the_real_event_profiles_platform_hosts_are_refused():
    from ctf import event
    slugs = event.available()
    assert slugs
    for slug in slugs:
        for h in event.load(slug).platform.all_hosts():
            assert bs.host_conflicts([bs.Host(h, "x")]), h


@pytest.mark.parametrize("name", ["github.com", "api.github.com", "uploads.github.com", "gitlab.com",
                                  "bitbucket.org", "upload.pypi.org", "GitHub.com"])
def test_hosts_that_accept_a_push_or_upload_are_refused(no_events, name):
    """With github.com reachable, a lane holding a credential could `git push` over HTTPS from
    inside the sandbox; the push step runs outside it (push_plan)."""
    with pytest.raises(bs.BuildSandboxError, match="accepts a git push"):
        bs.build(".", hosts=[bs.Host(name, "x")], events_root=no_events)


@pytest.mark.parametrize("name", ["codeload.github.com", "objects.githubusercontent.com",
                                  "files.pythonhosted.org", "pypi.org"])
def test_read_only_siblings_of_push_hosts_stay_allowed(no_events, name):
    assert bs.host_conflicts([bs.Host(name, "x")], events_root=no_events) == []


def test_the_repo_allowlist_holds_no_push_host():
    names = {h.name for h in bs.load_hosts()}
    assert "github.com" not in names and not names & set(bs.PUSH_HOSTS)


# ------------------------------------------------------------------------------------- launcher
def test_launch_argv(repo, tmp_path, no_events):
    _, wt = repo
    p = profile(wt, tmp_path / "home", no_events)
    argv = bs.launch_argv(p, codex_bin="codex", model="m1", extra=["--json"], prompt="do it")
    assert argv[:4] == ["codex", "exec", "-C", str(wt)]
    assert argv[4:10] == p.codex_config_args()
    assert argv[10:12] == ["-c", 'approval_policy="never"']
    assert argv[-4:] == ["-m", "m1", "--json", "do it"]
    tui = bs.launch_argv(p, headless=False, approval="on-request")
    assert "exec" not in tui and 'approval_policy="on-request"' in tui
    with pytest.raises(LaunchError, match="approval"):
        bs.launch_argv(p, approval="always")


@pytest.mark.parametrize("extra", [
    ["-c", "features.network_proxy=false"], ["--config", "features.network_proxy = false"],
    ["--config=features.network_proxy=false"], ["-cfeatures.network_proxy=false"],
    ["-c=features.network_proxy=false"], ["--disable", "network_proxy"], ["--disable=network_proxy"],
    ["--enable", "network_proxy"],
    # the solver launcher's refusals hold here too
    ["--sandbox", "danger-full-access"], ["-c", 'default_permissions="other"'],
    ["-c", "permissions.x={}"], ["--add-dir", "/"], ["--yolo"], ["-C", "/"],
])
def test_launch_refuses_extras_that_undo_the_profile(extra):
    with pytest.raises(LaunchError):
        bs.check_launch_extra(extra)


def test_launch_keeps_harmless_extras():
    bs.check_launch_extra(["--json", "-m", "m", "-c", 'model_reasoning_effort="high"', "--disable",
                           "fast_mode", "-c", "features.other=true"])


def test_cli_launch_dry_run_prints_the_command(repo, tmp_path, capsys, monkeypatch):
    _, wt = repo
    monkeypatch.setattr(bs, "checked_hosts", lambda **kw: tuple(HOSTS))
    rc = cli.run(cli_args(["launch", "--checkout", str(wt), "--dry-run", "a prompt", "--", "--json"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("codex exec -C ") and "features.network_proxy=true" in out
    assert out.rstrip().endswith("--json '<prompt>'")
    rc = cli.run(cli_args(["launch", "--checkout", str(wt), "--dry-run", "a", "b"]))
    assert rc == 2 and "one PROMPT" in capsys.readouterr().err
    rc = cli.run(cli_args(["launch", "--checkout", str(wt), "--dry-run", "x", "--", "--disable",
                           "network_proxy"]))
    assert rc == 2 and "network_proxy" in capsys.readouterr().err
    rc = cli.run(cli_args(["launch", "--checkout", str(wt), "--dry-run"]))
    assert rc == 2 and "needs a prompt" in capsys.readouterr().err


def cli_args(argv):
    import argparse
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return p.parse_args(argv)


# ----------------------------------------------------------------------------------------- push
def _remote(main: Path, tmp_path: Path, url: str | None = None) -> Path:
    bare = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(bare))
    git(main, "remote", "add", "origin", url or str(bare))
    return bare


def test_push_plan_is_a_dry_run_for_a_new_branch(repo, tmp_path):
    main, wt = repo
    bare = _remote(main, tmp_path)
    plan = bs.push_plan(wt)
    assert plan.branch == "feature" and plan.remote == "origin"
    assert plan.command == ["git", "-C", str(wt), "push", "origin", "refs/heads/feature:refs/heads/feature"]
    assert "--force" not in plan.command and "-f" not in plan.command
    assert any("creates it" in n for n in plan.notes)
    assert git(bare, "for-each-ref") == ""            # nothing was pushed


def test_push_plan_counts_commits_ahead_and_notes_a_dirty_tree(repo, tmp_path):
    main, wt = repo
    _remote(main, tmp_path)
    base = git(wt, "rev-parse", "HEAD")
    git(wt, "update-ref", "refs/remotes/origin/feature", base)
    git(wt, "commit", "-q", "--allow-empty", "-m", "a")
    git(wt, "commit", "-q", "--allow-empty", "-m", "b")
    plan = bs.push_plan(wt)
    assert any(n.startswith("2 commit(s) ahead") for n in plan.notes)
    assert not any("uncommitted" in n for n in plan.notes)
    (wt / "f.txt").write_text("x")
    assert any("uncommitted" in n for n in bs.push_plan(wt).notes)


def test_push_plan_refuses_force_main_detached_and_unknown(repo, tmp_path):
    main, wt = repo
    _remote(main, tmp_path)
    with pytest.raises(bs.BuildSandboxError, match="protected"):
        bs.push_plan(main)
    with pytest.raises(bs.BuildSandboxError, match="protected"):
        bs.push_plan(wt, branch="main")
    with pytest.raises(bs.BuildSandboxError, match="no git remote 'upstream'"):
        bs.push_plan(wt, remote="upstream")
    with pytest.raises(bs.BuildSandboxError, match="no local branch"):
        bs.push_plan(wt, branch="nope")
    with pytest.raises(bs.BuildSandboxError, match="not a valid branch"):
        bs.push_plan(wt, branch="bad..name")
    # remote-tracking ref not an ancestor: the push would need --force
    git(wt, "commit", "-q", "--allow-empty", "-m", "other")
    other = git(wt, "rev-parse", "HEAD")
    git(wt, "reset", "-q", "--hard", "HEAD~1")
    git(wt, "commit", "-q", "--allow-empty", "-m", "mine")
    git(wt, "update-ref", "refs/remotes/origin/feature", other)
    with pytest.raises(bs.BuildSandboxError, match="--force"):
        bs.push_plan(wt)
    git(wt, "checkout", "-q", "--detach")
    with pytest.raises(bs.BuildSandboxError, match="detached"):
        bs.push_plan(wt)


def test_push_never_shows_the_remote_url(repo, tmp_path, capsys):
    main, wt = repo
    secret = "SEKRET-TOKEN-VALUE"
    _remote(main, tmp_path, url=f"https://user:{secret}@git.invalid/x.git")
    plan = bs.push_plan(wt)
    assert secret not in repr(plan)
    assert cli.run(cli_args(["push", "--checkout", str(wt)])) == 0
    out = capsys.readouterr()
    assert secret not in out.out + out.err
    assert out.out.startswith("DRY RUN: nothing was pushed")


# ------------------------------------------------------------------------------------ self-test
def test_selftest_refuses_scratch_under_the_temp_folder(tmp_path):
    # any binary on PATH passes the codex lookup; the temp check comes before anything runs
    with pytest.raises(bs.BuildSandboxError, match="temp folder"):
        bs.selftest(scratch=tmp_path, codex_bin=sys.executable)


def test_selftest_without_codex_is_a_named_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="codex CLI not found"):
        bs.selftest(scratch=tmp_path, codex_bin="definitely-not-codex-xyz")


@pytest.mark.needs_tool("codex", "curl", "git")
def test_selftest_live_under_codex_sandbox():
    if sandboxinfo.macos_sandboxed():
        pytest.skip("needs_unsandboxed: macOS cannot start `codex sandbox` inside another sandbox "
                    "(run python -m ctf build-sandbox selftest outside it)")
    scratch = paths.repo_root() / "scratchpad" / "b192"
    try:
        checks = bs.selftest(scratch=scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    failed = [(c.name, c.detail) for c in checks if c.required and not c.ok]
    assert not failed
    names = {c.name for c in checks}
    assert {"loopback bind and connect", "direct egress denied (192.0.2.1, TEST-NET-1)",
            "git commit from the linked worktree",
            "protected branch main: git update-ref main is refused",
            "protected branch main: a plain write to refs/heads/main is refused",
            "protected branch main: rm refs/heads/main is refused",
            "protected branch integ: a plain write to the integration branch's ref is refused",
            "packed-refs stays read-only",
            "core.hooksPath (.hk, inside the checkout) stays read-only",
            "~/.config (a tool token store) unreadable", "~/.config/git readable (git's config)",
            "control: commit from a linked worktree is denied under plain :workspace"} <= names
