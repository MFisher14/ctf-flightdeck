"""Codex sandbox profile for BUILD work on this repo (B-192). Not the solver fence (ctf/fence.py).

Codex's built-in workspace-write sandbox blocked work the repo needs: loopback bind (fake services
in tests), git lock files in a linked worktree (its gitdir and refs live under the main checkout's
.git), the Docker socket, package hosts, and pushes. Every lane hit them and escalated (one CTF:
1,960 escalation requests). This module renders one repo build profile, passed to Codex with `-c`
(installing it into ~/.codex is a human step):

    from ctf import build_sandbox as bs
    p = bs.build(checkout)                 # BuildProfile for a checkout (main or linked worktree)
    p.codex_profile()                      # the permission profile (extends ":workspace")
    p.codex_config_args()                  # -c permissions.ctf_build={...} -c default_permissions=...
                                           #   -c features.network_proxy=true
    bs.selftest(scratch=DIR)               # live probes under `codex sandbox`, no model call
    bs.push_plan(checkout)                 # the push command, dry run only: never pushes

What the profile allows, on top of ":workspace" (verified live under `codex sandbox`, codex-cli
0.167.0; docs/build-sandbox.md):
  - write: the checkout, its gitdir (<main>/.git/worktrees/<name>, which Codex otherwise protects)
    and the common .git (objects, refs, logs), so commit and branch work from a linked worktree;
    except, read only: the hooks folder git runs (.git/hooks, or core.hooksPath as this checkout
    resolves it) and the config files (either would run code outside the sandbox the next time
    anyone runs git), the main checkout's HEAD (from a linked worktree), packed-refs, and the
    protected branches' ref files and their .lock files (main, master, the integration branch and
    any --protect: neither git nor a plain file write can move or delete them; see "Limits")
  - network: loopback bind and connect, and the hosts in tools/build_hosts.toml through Codex's
    managed proxy. `network.enabled = true` WITHOUT `features.network_proxy = true` is the whole
    network (verified), so the -c arguments always carry both and the launcher refuses overrides.
    Hosts that accept a push or an upload (github.com, api.github.com, upload.pypi.org, ...) are
    refused on the allowlist: the one push step runs outside the sandbox (push_plan)
  - Docker: only with docker=True, the Docker socket paths as allowed unix sockets (listed, never
    exercised by build work or tests; the self-test uses a synthetic socket instead)
  - denied: agent state (~/.codex, ~/.claude, ...), credentials (~/.ssh, ~/.config, ...), customer
    work, and any .ctf/ directory (the fence's DENY_NAMES globs); ~/.config/git and ~/.config/uv
    are read only again (git and uv read their config there), except git's credential store file

Limits: the protected-branch entries stop git commands and direct writes to those paths. A lane
still writes the rest of the common .git, so one that sets out to subvert the guard (renaming the
refs folder and planting a symlink, rewriting objects) can; that is a guard against a lane's
mistakes and naive moves, not a wall against a hostile one. The merge queue's own checks stay the
authority on main and the integration branch.

JIT: Unicorn dies with SIGILL under Codex's seatbelt, and no setting fixes it: the policy denies
the sysctl hw.cachelinesize (ctf/testing/capabilities.py has the evidence). Tests that need it carry
`@pytest.mark.needs_jit` and report as not run there; they run outside Codex (the merge queue).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import event as _event
from . import fence as _fence
from . import paths

PROFILE_NAME = "ctf_build"
HOSTS_FILE = "tools/build_hosts.toml"
PROTECTED_BRANCHES = ("main", "master")      # always protected; build() adds the integration branch
# Docker Desktop's socket and the conventional one. Listed only with docker=True; never opened here.
DOCKER_SOCKETS = ("/var/run/docker.sock", "~/.docker/run/docker.sock")

# Hosts that must never be on the build allowlist, whatever the event profiles say: chat, and model
# APIs (Codex talks to its model itself, outside the sandbox; commands it runs never need to).
FORBIDDEN_HOSTS: tuple[tuple[str, str], ...] = (
    ("discord.com", "Discord"), ("discord.gg", "Discord"), ("discordapp.com", "Discord"),
    ("discordapp.net", "Discord"), ("openai.com", "a model API"), ("chatgpt.com", "a model API"),
    ("anthropic.com", "a model API"), ("claude.ai", "a model API"),
)

# Hosts that accept a git push, an API write or a package upload. Exact names, not suffixes: their
# read-only siblings (codeload.github.com, objects.githubusercontent.com, files.pythonhosted.org)
# stay allowed. With one of these on the list, a lane holding a credential could push from inside
# the sandbox; the push step is meant to run outside it (push_plan).
PUSH_HOSTS: tuple[str, ...] = (
    "github.com", "api.github.com", "uploads.github.com", "gist.github.com", "ssh.github.com",
    "gitlab.com", "bitbucket.org", "api.bitbucket.org", "codeberg.org", "git.sr.ht",
    "upload.pypi.org", "test.pypi.org", "huggingface.co",
)

# Home-relative stores the build profile denies: the fence's agent-state, customer-work and
# credentials rows (~/.config among them: gh, gcloud and other tools keep tokens there). Build work
# reads the source repos and the rest of $HOME as before (read only).
_BUILD_DENY_CATEGORIES = ("agent-state", "customer-work", "credentials")
# Re-opened read only inside a denied ~/.config: git and uv read their config there (git dies on an
# unreadable config file). A more specific entry wins (verified live), so these beat the deny ...
BUILD_HOME_READABLE = (".config/git", ".config/uv")
# ... and these beat the re-opening: git's XDG credential store (git-credential-store) holds tokens.
BUILD_HOME_DENY_AGAIN = (".config/git/credentials",)

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_HOST_KEYS = {"name", "why"}
_CODEX_FEATURE = "network_proxy"


class BuildSandboxError(ValueError):
    """The build profile cannot be made as asked. The message names why."""


# ----------------------------------------------------------------------------------- allowlist
@dataclass(frozen=True)
class Host:
    name: str
    why: str


def load_hosts(path: Path | str | None = None) -> tuple[Host, ...]:
    """The documented host allowlist (tools/build_hosts.toml). Fails loudly on a missing file, an
    unknown key, a missing reason, a malformed or duplicate name, a wildcard or an IP address."""
    path = Path(path) if path is not None else paths.repo_root() / HOSTS_FILE
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BuildSandboxError(f"build host allowlist not found: {path}") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise BuildSandboxError(f"{path}: not valid TOML: {e}") from None
    extra = set(data) - {"host"}
    if extra:
        raise BuildSandboxError(f"{path}: unknown key(s) {sorted(extra)} (only [[host]] tables)")
    rows = data.get("host", [])
    if not isinstance(rows, list):
        raise BuildSandboxError(f"{path}: host must be an array of tables ([[host]])")
    out: list[Host] = []
    seen: set[str] = set()
    for i, row in enumerate(rows):
        where = f"{path}: host #{i + 1}"
        if not isinstance(row, dict):
            raise BuildSandboxError(f"{where}: not a table")
        bad = set(row) - _HOST_KEYS
        if bad:
            raise BuildSandboxError(f"{where}: unknown key(s) {sorted(bad)}")
        name, why = row.get("name"), row.get("why")
        if not isinstance(why, str) or not why.strip():
            raise BuildSandboxError(f"{where} ({name!r}): needs a non-empty why")
        out.append(Host(check_host_name(name, where), why.strip()))
        if out[-1].name in seen:
            raise BuildSandboxError(f"{where}: {out[-1].name} is listed twice")
        seen.add(out[-1].name)
    return tuple(out)


def check_host_name(name: object, where: str = "host") -> str:
    """An exact DNS name, lowercased. No wildcard, IP address, port, scheme or path."""
    if not isinstance(name, str) or not name:
        raise BuildSandboxError(f"{where}: name must be a non-empty string")
    n = name.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(n.strip("[]"))
    except ValueError:
        pass
    else:
        raise BuildSandboxError(f"{where}: {name!r} is an IP address; list host names only")
    if "*" in n:
        raise BuildSandboxError(f"{where}: {name!r} is a wildcard; list each exact host")
    if not _HOST_RE.match(n):
        raise BuildSandboxError(f"{where}: {name!r} is not a bare host name (no scheme, port or path)")
    return n


def _suffix_match(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def host_conflicts(hosts: Iterable[Host], *, events_root: Path | None = None) -> list[str]:
    """Why each host may not be on the build allowlist: a forbidden host (Discord, model APIs), or
    a host an event profile names as its platform (base_url, hosts) or as a live service
    (live_service_scope globs). An event profile that does not load is itself a conflict: the check
    cannot vouch for a list it could not compare."""
    hosts = list(hosts)
    problems: list[str] = []
    for h in hosts:
        for suffix, what in FORBIDDEN_HOSTS:
            if _suffix_match(h.name, suffix):
                problems.append(f"{h.name}: {what} ({suffix}) is never a build host")
        if h.name in PUSH_HOSTS:
            problems.append(f"{h.name}: accepts a git push, an API write or an upload; pushes run "
                            "outside the sandbox (build-sandbox push), so it is never a build host")
    for slug in _event.available(events_root):
        try:
            prof = _event.load(slug, events_root)
        except (_event.EventError, OSError) as e:
            problems.append(f"event profile {slug!r} does not load, so the allowlist cannot be "
                            f"checked against it: {e}")
            continue
        platform_hosts = prof.platform.all_hosts()
        scope = tuple(g.lower() for g in prof.rules.live_service_scope)
        for h in hosts:
            for ph in platform_hosts:
                if _suffix_match(h.name, ph) or _suffix_match(ph, h.name):
                    problems.append(f"{h.name}: event {slug!r} platform host {ph}")
            for g in scope:
                if fnmatch.fnmatchcase(h.name, g) or fnmatch.fnmatchcase(h.name, g.lstrip("*.")):
                    problems.append(f"{h.name}: event {slug!r} live_service_scope {g!r}")
    return problems


def checked_hosts(path: Path | str | None = None, *, events_root: Path | None = None) -> tuple[Host, ...]:
    hosts = load_hosts(path)
    problems = host_conflicts(hosts, events_root=events_root)
    if problems:
        raise BuildSandboxError("build host allowlist refused:\n  " + "\n  ".join(problems))
    return hosts


# ---------------------------------------------------------------------------------- git layout
@dataclass(frozen=True)
class GitLayout:
    checkout: Path        # the working tree root
    gitdir: Path          # its git dir: <common>/worktrees/<name> for a linked worktree
    common: Path          # the shared .git (objects, refs, hooks, config)
    hooks: Path | None = None   # the hooks folder git runs here (core.hooksPath as resolved here)

    @property
    def linked(self) -> bool:
        return self.gitdir != self.common


def _git(args: Sequence[str], cwd: Path, *, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env,
                              stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise BuildSandboxError("git not found on PATH") from None


def git_layout(checkout: Path | str) -> GitLayout:
    """Ask git where the checkout's working tree, gitdir, common dir and hooks folder are (absolute,
    resolved). The hooks folder is `git rev-parse --git-path hooks`: core.hooksPath when set (a
    relative one resolves against this checkout), else <common>/hooks."""
    c = Path(checkout).expanduser()
    if not c.is_dir():
        raise BuildSandboxError(f"checkout {c} is not a directory")
    r = _git(["rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir",
              "--git-common-dir", "--git-path", "hooks"], c)
    lines = r.stdout.splitlines()
    if r.returncode != 0 or len(lines) != 4:
        raise BuildSandboxError(f"{c} is not a git checkout: {(r.stderr or r.stdout).strip()[:300]}")
    top, gitdir, common, hooks = (Path(x).resolve() for x in lines)
    return GitLayout(top, gitdir, common, hooks)


# ------------------------------------------------------------------------------------- profile
@dataclass(frozen=True)
class BuildProfile:
    layout: GitLayout
    hosts: tuple[Host, ...]
    home: Path
    unix_sockets: tuple[Path, ...] = ()
    deny: tuple[tuple[str, Path], ...] = field(default=())      # (category, path)
    protected: tuple[str, ...] = PROTECTED_BRANCHES              # branches no lane may move
    integration_branch: str | None = None                        # one of `protected`, when known

    def read_only(self) -> list[Path]:
        """Paths inside the writable roots that stay read only (a more specific entry wins)."""
        lay = self.layout
        c = lay.common
        ro = [c / "hooks", c / "config", c / "config.worktree", lay.gitdir / "config.worktree",
              # git rewrites packed-refs to delete a ref or pack refs; a write there could move or
              # drop a protected branch that lives only in packed-refs
              c / "packed-refs", c / "packed-refs.lock"]
        if lay.hooks is not None:
            ro.append(lay.hooks)
        if lay.linked:
            ro.append(c / "HEAD")       # the main checkout's HEAD: which branch it has out
        for b in self.protected:
            ref = c / "refs" / "heads" / b
            ro += [ref, ref.with_name(ref.name + ".lock")]
        return list(dict.fromkeys(ro))

    def filesystem(self) -> dict[str, str]:
        lay = self.layout
        fs: dict[str, str] = {}
        for _cat, p in self.deny:
            fs[str(p)] = "deny"
        denied = {p for _c, p in self.deny}
        for rel in BUILD_HOME_READABLE:
            if any(d == self.home / rel or d in (self.home / rel).parents for d in denied):
                fs[str(self.home / rel)] = "read"
        for rel in BUILD_HOME_DENY_AGAIN:
            fs[str(self.home / rel)] = "deny"
        fs[str(lay.checkout)] = "write"
        fs[str(lay.common)] = "write"
        fs[str(lay.gitdir)] = "write"
        # More specific entries win (verified live): these stay readable but not writable.
        for p in self.read_only():
            fs[str(p)] = "read"
        for n in _fence.DENY_NAMES:
            for g in _fence.DenyName(*n).globs:
                fs[g] = "deny"
        return fs

    def network(self) -> dict:
        net: dict = {"enabled": True, "allow_local_binding": True,
                     "domains": {h.name: "allow" for h in self.hosts}}
        if self.unix_sockets:
            net["unix_sockets"] = {str(s): "allow" for s in self.unix_sockets}
        return net

    def codex_profile(self) -> dict:
        return {"extends": ":workspace", "filesystem": self.filesystem(), "network": self.network()}

    def codex_config_args(self, name: str = PROFILE_NAME) -> list[str]:
        """The -c overrides that define and select the profile. features.network_proxy is part of
        it: without the proxy, network.enabled opens the whole network."""
        _check_profile_name(name)
        return ["-c", f"permissions.{name}={_fence.toml_inline(self.codex_profile())}",
                "-c", f'default_permissions="{name}"',
                "-c", f"features.{_CODEX_FEATURE}=true"]

    def config_toml(self, name: str = PROFILE_NAME) -> str:
        """A config.toml fragment for the human step of installing the profile into ~/.codex. It
        defines the profile and turns the proxy on; it does not select the profile by default."""
        _check_profile_name(name)
        prof = self.codex_profile()
        lines = [f"# B-192 repo build profile for {self.layout.checkout} (python -m ctf build-sandbox "
                 "config-toml). Select it per run with -c default_permissions=\"" + name + "\".",
                 "# features.network_proxy must stay true: without it network.enabled is the whole "
                 "network.",
                 "[features]", f"{_CODEX_FEATURE} = true", "",
                 f"[permissions.{name}]", f"extends = {_fence.toml_inline(prof['extends'])}", "",
                 f"[permissions.{name}.filesystem]"]
        lines += [f"{_fence.toml_inline(k)} = {_fence.toml_inline(v)}" for k, v in prof["filesystem"].items()]
        lines += ["", f"[permissions.{name}.network]"]
        lines += [f"{k} = {_fence.toml_inline(v)}" for k, v in prof["network"].items()]
        return "\n".join(lines) + "\n"

    def describe(self) -> dict:
        lay = self.layout
        return {"checkout": str(lay.checkout), "gitdir": str(lay.gitdir), "common": str(lay.common),
                "hooks": str(lay.hooks) if lay.hooks is not None else None,
                "linked_worktree": lay.linked, "protected_branches": list(self.protected),
                "integration_branch": self.integration_branch,
                "read_only": [str(p) for p in self.read_only()],
                "hosts": [{"name": h.name, "why": h.why} for h in self.hosts],
                "unix_sockets": [str(s) for s in self.unix_sockets],
                "deny": [{"category": c, "path": str(p)} for c, p in self.deny],
                "profile": self.codex_profile()}


def _check_profile_name(name: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name or ""):
        raise BuildSandboxError(f"profile name {name!r}: letters, digits and _ only")


def build_deny(home: Path) -> tuple[tuple[str, Path], ...]:
    out = []
    for cat, rel, _is_file, _why in _fence.DENY_HOME:
        if cat in _BUILD_DENY_CATEGORIES:
            out.append((cat, home / rel))
    return tuple(out)


def protected_branches(checkout: Path, *, protect: Sequence[str] = (),
                       integration_branch: str | None = None,
                       environ: dict | None = None) -> tuple[tuple[str, ...], str | None]:
    """(the branches no lane may move, the integration branch or None). Always main and master,
    then the integration branch as ctf.worktree names it (the argument, $CTF_INTEGRATION_BRANCH, or
    `git config ctftools.integrationBranch`; none set is reported by describe(), not guessed), then
    `protect`. Each name must be a valid branch name."""
    from .worktree import WorktreeError, integration_branch_name
    try:
        integ = integration_branch_name(integration_branch, repo=checkout, environ=environ)
    except WorktreeError:
        integ = None
    names = [*PROTECTED_BRANCHES, *([integ] if integ else []), *protect]
    for n in names:
        if not isinstance(n, str) or _git(["check-ref-format", "--branch", n], checkout).returncode != 0:
            raise BuildSandboxError(f"protected branch {n!r} is not a valid branch name")
    return tuple(dict.fromkeys(names)), integ


def docker_sockets(home: Path) -> tuple[Path, ...]:
    return tuple(Path(s.replace("~", str(home), 1)) if s.startswith("~") else Path(s)
                 for s in DOCKER_SOCKETS)


def build(checkout: Path | str | None = None, *, hosts: Sequence[Host] | None = None,
          docker: bool = False, unix_sockets: Sequence[Path | str] = (), home: Path | str | None = None,
          events_root: Path | None = None, protect: Sequence[str] = (),
          integration_branch: str | None = None, environ: dict | None = None) -> BuildProfile:
    """The build profile for `checkout` (default: the repo this code runs from). hosts=None loads
    and checks tools/build_hosts.toml; an explicit list is checked the same way. `protect` adds
    branches to main, master and the integration branch (protected_branches())."""
    lay = git_layout(checkout if checkout is not None else paths.repo_root())
    home_p = Path(home).expanduser().resolve() if home is not None else Path.home().resolve()
    if hosts is None:
        hs = checked_hosts(events_root=events_root)
    else:
        hs = tuple(Host(check_host_name(h.name, "host"), h.why) for h in hosts)
        problems = host_conflicts(hs, events_root=events_root)
        if problems:
            raise BuildSandboxError("build host allowlist refused:\n  " + "\n  ".join(problems))
    deny = build_deny(home_p)
    for cat, d in deny:
        for root, what in ((lay.checkout, "checkout"), (lay.common, "git common dir")):
            if root == d or d in root.parents:
                raise BuildSandboxError(f"the {what} {root} is inside a denied store ({cat}: {d})")
    socks = tuple(Path(s) for s in unix_sockets)
    for s in socks:
        if not s.is_absolute():
            raise BuildSandboxError(f"unix socket path {s} must be absolute")
    if docker:
        socks = docker_sockets(home_p) + socks
    prot, integ = protected_branches(lay.checkout, protect=protect,
                                     integration_branch=integration_branch, environ=environ)
    return BuildProfile(lay, hs, home_p, socks, deny, prot, integ)


# ------------------------------------------------------------------------------------ launcher
APPROVAL_POLICIES = ("never", "on-request", "untrusted")
_NETPROXY_OVERRIDE = re.compile(r"^features\.network_proxy\s*=")


def check_launch_extra(extra: Sequence[str]) -> None:
    """Refuse passthrough arguments that would undo the build profile: everything the solver
    launcher refuses (sandbox mode, permission profiles, -C, --add-dir, approvals, ...) plus any
    change to features.network_proxy (without the proxy the profile is the whole network)."""
    from .fence_launch import LaunchError, check_codex_extra
    check_codex_extra(extra)
    for i, a in enumerate(extra):
        nxt = extra[i + 1] if i + 1 < len(extra) else ""
        if a in ("-c", "--config"):
            val = nxt
        elif a.startswith("--config="):
            val = a.split("=", 1)[1]
        elif a.startswith("-c") and not a.startswith("--"):
            val = a[2:].lstrip("=")
        else:
            val = None
        if val is not None and _NETPROXY_OVERRIDE.match(val.strip()):
            raise LaunchError("refused codex override features.network_proxy: the build profile "
                              "needs the proxy (without it network.enabled is the whole network)")
        if a in ("--disable", "--enable"):
            feat = nxt
        elif a.startswith(("--disable=", "--enable=")):
            feat = a.split("=", 1)[1]
        else:
            feat = None
        if feat == _CODEX_FEATURE:
            raise LaunchError(f"refused {a.split('=')[0]} {_CODEX_FEATURE}: the build profile sets it")


def launch_argv(profile: BuildProfile, *, codex_bin: str = "codex", headless: bool = True,
                model: str | None = None, approval: str = "never", extra: Sequence[str] = (),
                prompt: str | None = None) -> list[str]:
    """The codex command line for a build lane in `profile`'s checkout. Pure: runs nothing."""
    from .fence_launch import LaunchError
    if approval not in APPROVAL_POLICIES:
        raise LaunchError(f"approval must be one of {', '.join(APPROVAL_POLICIES)} (got {approval!r})")
    check_launch_extra(extra)
    argv = [codex_bin]
    if headless:
        argv += ["exec"]
    argv += ["-C", str(profile.layout.checkout), *profile.codex_config_args(),
             "-c", f'approval_policy="{approval}"']
    if model:
        argv += ["-m", model]
    argv += list(extra)
    if prompt is not None:
        argv.append(prompt)
    return argv


# ---------------------------------------------------------------------------------------- push
@dataclass(frozen=True)
class PushPlan:
    branch: str
    remote: str
    command: list[str]
    notes: tuple[str, ...]


def push_plan(checkout: Path | str, *, remote: str = "origin", branch: str | None = None) -> PushPlan:
    """The one push step, as a dry run: checks and the exact command for a person (or a step
    outside the sandbox) to run. It never pushes, never forces, never prints the remote URL (it can
    hold a token), and refuses the protected branches and a push that would need --force."""
    lay = git_layout(checkout)
    c = lay.checkout
    if branch is None:
        r = _git(["symbolic-ref", "--quiet", "--short", "HEAD"], c)
        if r.returncode != 0:
            raise BuildSandboxError("HEAD is detached: name the branch to push (--branch)")
        branch = r.stdout.strip()
    if _git(["check-ref-format", "--branch", branch], c).returncode != 0:
        raise BuildSandboxError(f"{branch!r} is not a valid branch name")
    if branch in PROTECTED_BRANCHES:
        raise BuildSandboxError(f"refused: {branch} is a protected branch; build work never pushes it")
    if _git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], c).returncode != 0:
        raise BuildSandboxError(f"no local branch {branch!r}")
    remotes = _git(["remote"], c).stdout.split()
    if remote not in remotes:
        raise BuildSandboxError(f"no git remote {remote!r} (remotes: {', '.join(remotes) or 'none'})")
    notes: list[str] = []
    tracking = f"refs/remotes/{remote}/{branch}"
    if _git(["rev-parse", "--verify", "--quiet", tracking], c).returncode == 0:
        if _git(["merge-base", "--is-ancestor", tracking, f"refs/heads/{branch}"], c).returncode != 0:
            raise BuildSandboxError(f"refused: {remote}/{branch} is not an ancestor of {branch}; the "
                                    "push would need --force, which build work never uses")
        ahead = _git(["rev-list", "--count", f"{tracking}..refs/heads/{branch}"], c).stdout.strip()
        notes.append(f"{ahead} commit(s) ahead of the last fetched {remote}/{branch} "
                     "(as of the last fetch; nothing was fetched)")
    else:
        notes.append(f"{remote} has no fetched {branch}: the push creates it")
    if _git(["status", "--porcelain"], c).stdout.strip():
        notes.append("the working tree has uncommitted changes; they are not pushed")
    cmd = ["git", "-C", str(c), "push", remote, f"refs/heads/{branch}:refs/heads/{branch}"]
    return PushPlan(branch, remote, cmd, tuple(notes))


# ------------------------------------------------------------------------------------ self-test
@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True       # False: reported, never fails the self-test (a known Codex limit)


_LOOPBACK_SRC = ("import socket\nl=socket.socket()\nl.bind(('127.0.0.1',0))\nl.listen(1)\n"
                 "socket.create_connection(l.getsockname(),timeout=30).close()\nprint('LOOPBACK-OK')\n")
# 192.0.2.1 is TEST-NET-1 (RFC 5737): documentation only, never routed. A sandbox denial is an
# immediate EPERM; an allowed connect would only time out, so no real host is ever contacted.
_EGRESS_SRC = ("import socket\ns=socket.socket()\ns.settimeout(5)\ntry:\n s.connect(('192.0.2.1',9))\n"
               " print('CONNECTED')\nexcept PermissionError as e:\n print('DENIED',e)\n"
               "except OSError as e:\n print('NOT-DENIED',type(e).__name__,e)\n")
_UNIX_SRC = ("import socket,sys\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(30)\ntry:\n"
             " s.connect(sys.argv[1]); print('UNIX', s.recv(16).decode().strip())\n"
             "except OSError as e:\n print('UNIX-DENIED', e)\n")
_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
SELFTEST_ALLOWED = "allowed.invalid"     # RFC 2606: .invalid never resolves; nothing is reached
SELFTEST_BLOCKED = "blocked.invalid"


def _under_temp(p: Path) -> bool:
    roots = {Path(r).resolve() for r in _TEMP_ROOTS if Path(r).exists()}
    roots.add(Path(tempfile.gettempdir()).resolve())
    return any(p == r or r in p.parents for r in roots)


class _UnixServer:
    """A synthetic unix-socket service (stand-in for the Docker socket) that answers HELLO."""

    def __init__(self, path: Path):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            with c:
                c.sendall(b"HELLO\n")

    def close(self) -> None:
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=5)


def selftest(*, scratch: Path | str, codex_bin: str = "codex", timeout: float = 120.0,
             python: str | None = None, curl: str = "/usr/bin/curl",
             events_root: Path | None = None) -> list[Check]:
    """Probe the build profile live under `codex sandbox` (no model call, no outside host):
    a synthetic main repo with a linked worktree under `scratch` (not under the temp folder, which
    ":workspace" already makes writable, so a git check there would prove nothing), a fresh
    CODEX_HOME (so ~/.codex is never written), a synthetic unix socket in place of Docker's, and
    TEST-NET / .invalid addresses for the network checks. Controls run the same probes under plain
    ":workspace" so a pass means the profile did it."""
    from .testing.capabilities import JIT_PROBE_SRC, classify_jit
    if shutil.which(codex_bin) is None:
        raise FileNotFoundError(f"codex CLI not found ({codex_bin!r}); install it or pass --codex-bin")
    scratch = Path(scratch).expanduser().resolve()
    if _under_temp(scratch):
        raise BuildSandboxError(f"scratch {scratch} is under the temp folder, which Codex's "
                                ":workspace already makes writable; pick a folder outside it")
    python = python or sys.executable
    scratch.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="b", dir=scratch))
    codex_home = Path(tempfile.mkdtemp(prefix="codex-home-"))
    env_git = {**os.environ, "GIT_AUTHOR_NAME": "selftest", "GIT_AUTHOR_EMAIL": "selftest@invalid",
               "GIT_COMMITTER_NAME": "selftest", "GIT_COMMITTER_EMAIL": "selftest@invalid",
               "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    env_codex = {**env_git, "CODEX_HOME": str(codex_home)}
    checks: list[Check] = []
    server = None
    try:
        main, wt = run_dir / "main", run_dir / "wt"
        for args, cwd in ((["init", "-q", "-b", "main", str(main)], run_dir),
                          (["commit", "-q", "--allow-empty", "-m", "init"], main),
                          (["branch", "packed-only"], main),
                          (["pack-refs", "--all"], main),      # packed-only lives in packed-refs
                          (["commit", "-q", "--allow-empty", "-m", "two"], main),   # main: loose
                          (["branch", "integ"], main),
                          (["config", "core.hooksPath", ".hk"], main),
                          (["worktree", "add", "-q", "-b", "selftest", str(wt)], main)):
            r = _git(args, cwd, env=env_git)
            if r.returncode != 0:
                raise BuildSandboxError(f"self-test setup: git {' '.join(args[:2])} failed: "
                                        f"{r.stderr.strip()[:200]}")
        (wt / ".ctf").mkdir()
        (wt / ".ctf" / "canary").write_text("CANARY-SHOULD-NOT-BE-READ\n")
        # a synthetic home: a tool token store and git's config under .config (never the real one)
        fake_home = run_dir / "home"
        for rel, text in ((".config/gh/hosts.yml", "CANARY-TOOL-TOKEN\n"),
                          (".config/git/config", "[selftest]\n\tprobe = GIT-CONFIG-READABLE\n"),
                          (".config/git/credentials", "CANARY-GIT-CREDENTIAL\n")):
            (fake_home / rel).parent.mkdir(parents=True, exist_ok=True)
            (fake_home / rel).write_text(text)
        sock_dir = run_dir / "s"
        sock_dir.mkdir()
        sock = sock_dir / "d"
        if len(str(sock).encode()) > 103:          # sun_path is 104 bytes with the NUL
            raise BuildSandboxError(f"scratch path too long for a unix socket ({sock}); use a shorter one")
        server = _UnixServer(sock)

        ctl = [Host(SELFTEST_ALLOWED, "self-test control")]
        base = build(wt, hosts=ctl, events_root=events_root, integration_branch="integ", environ={})
        withsock = build(wt, hosts=ctl, unix_sockets=[sock_dir], events_root=events_root,
                         integration_branch="integ", environ={})
        homed = build(wt, hosts=ctl, home=fake_home, events_root=events_root,
                      integration_branch="integ", environ={})
        plain = ["-c", 'permissions.plain={extends=":workspace"}', "-c", 'default_permissions="plain"']

        def run(config: list[str], argv: list[str]) -> subprocess.CompletedProcess:
            return subprocess.run([codex_bin, "sandbox", *config, "--", *argv], cwd=wt, env=env_codex,
                                  capture_output=True, text=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL)

        def out(r: subprocess.CompletedProcess) -> str:
            return f"exit {r.returncode}: " + " | ".join((r.stdout + r.stderr).strip().splitlines()[-3:])[:300]

        args = base.codex_config_args()
        r = run(args, [python, "-I", "-c", _LOOPBACK_SRC])
        checks.append(Check("loopback bind and connect", "LOOPBACK-OK" in r.stdout, out(r)))
        r = run(plain, [python, "-I", "-c", _LOOPBACK_SRC])
        checks.append(Check("control: loopback is denied under plain :workspace",
                            "LOOPBACK-OK" not in r.stdout and r.returncode != 0, out(r)))
        r = run(args, [python, "-I", "-c", _EGRESS_SRC])
        checks.append(Check("direct egress denied (192.0.2.1, TEST-NET-1)", "DENIED" in r.stdout
                            and "NOT-DENIED" not in r.stdout, out(r)))
        if not Path(curl).is_file():
            checks.append(Check("proxy allowlist", False, f"{curl} not found: cannot probe the proxy"))
        else:
            r = run(args, [curl, "-sS", "-m", "30", "-o", os.devnull, "-D", "-", f"http://{SELFTEST_BLOCKED}/"])
            checks.append(Check("proxy refuses a host not on the allowlist",
                                "blocked-by-allowlist" in r.stdout.lower(), out(r)))
            r = run(args, [curl, "-sS", "-m", "30", "-o", os.devnull, "-D", "-", f"http://{SELFTEST_ALLOWED}/"])
            checks.append(Check("control: an allowlisted host is not refused by the allowlist",
                                "blocked-by-allowlist" not in r.stdout.lower() and "HTTP/" in r.stdout, out(r)))
        r = run(plain, ["git", "commit", "-q", "--allow-empty", "-m", "control"])
        checks.append(Check("control: commit from a linked worktree is denied under plain :workspace",
                            r.returncode != 0, out(r)))
        r = run(args, ["git", "commit", "-q", "--allow-empty", "-m", "selftest"])
        checks.append(Check("git commit from the linked worktree", r.returncode == 0, out(r)))
        r = run(args, ["git", "branch", "selftest-probe"])
        checks.append(Check("git branch (a ref in the common .git)", r.returncode == 0, out(r)))
        hook = base.layout.common / "hooks" / "selftest-probe"
        r = run(args, ["/bin/sh", "-c", f"echo x > '{hook}'"])
        checks.append(Check(".git/hooks stays read-only", r.returncode != 0 and not hook.exists(), out(r)))
        hp = base.layout.hooks
        hook = (hp or wt / ".hk") / "pre-commit"
        r = run(args, ["/bin/sh", "-c", f"mkdir -p '{hook.parent}' && echo x > '{hook}'"])
        checks.append(Check("core.hooksPath (.hk, inside the checkout) stays read-only",
                            hp == wt / ".hk" and r.returncode != 0 and not hook.exists(), out(r)))
        r = run(args, ["git", "config", "selftest.probe", "1"])
        checks.append(Check(".git/config stays read-only", r.returncode != 0, out(r)))

        def head(ref: str) -> str:
            return _git(["rev-parse", "--verify", "--quiet", ref], main, env=env_git).stdout.strip()

        new = head("refs/heads/main~1")         # a real commit to move a protected branch to
        heads = base.layout.common / "refs" / "heads"
        packed = base.layout.common / "packed-refs"
        for what, argv, ref in (
                ("git update-ref main", ["git", "update-ref", "refs/heads/main", new], "main"),
                ("a plain write to refs/heads/main",
                 ["/bin/sh", "-c", f"printf '%s\\n' {new} > '{heads / 'main'}'"], "main"),
                ("rm refs/heads/main", ["/bin/rm", "-f", str(heads / "main")], "main"),
                ("git update-ref of the integration branch", ["git", "update-ref", "refs/heads/integ", new],
                 "integ"),
                ("a plain write to the integration branch's ref",
                 ["/bin/sh", "-c", f"printf '%s\\n' {new} > '{heads / 'integ'}'"], "integ")):
            want = head(f"refs/heads/{ref}")
            r = run(args, argv)
            checks.append(Check(f"protected branch {ref}: {what} is refused",
                                r.returncode != 0 and head(f"refs/heads/{ref}") == want and bool(want),
                                out(r)))
        before = packed.read_bytes()
        r = run(args, ["/bin/sh", "-c", f"printf '%s refs/heads/main\\n' {new} >> '{packed}'"])
        checks.append(Check("packed-refs stays read-only", r.returncode != 0 and packed.read_bytes() == before,
                            out(r)))
        # The cost of a read-only packed-refs, reported (not a failure): whether git can still delete
        # an unprotected branch from inside the sandbox.
        r = run(args, ["git", "branch", "-D", "selftest-probe"])
        checks.append(Check("deleting an unprotected branch inside the sandbox", r.returncode == 0,
                            "works" if r.returncode == 0 else
                            "refused (git takes packed-refs.lock to delete a ref): delete branches "
                            "outside the sandbox; " + out(r), required=False))
        r = run(args, ["/bin/sh", "-c", f"echo ref: refs/heads/selftest > '{base.layout.common / 'HEAD'}'"])
        checks.append(Check("the main checkout's HEAD stays read-only", r.returncode != 0
                            and (base.layout.common / "HEAD").read_text().strip() == "ref: refs/heads/main",
                            out(r)))
        r = run(homed.codex_config_args(), ["/bin/cat", str(fake_home / ".config/gh/hosts.yml")])
        checks.append(Check("~/.config (a tool token store) unreadable",
                            r.returncode != 0 and "CANARY" not in r.stdout, out(r)))
        r = run(homed.codex_config_args(), ["/bin/cat", str(fake_home / ".config/git/credentials")])
        checks.append(Check("~/.config/git/credentials unreadable",
                            r.returncode != 0 and "CANARY" not in r.stdout, out(r)))
        r = run(homed.codex_config_args(), ["/bin/cat", str(fake_home / ".config/git/config")])
        checks.append(Check("~/.config/git readable (git's config)",
                            r.returncode == 0 and "GIT-CONFIG-READABLE" in r.stdout, out(r)))
        r = run(args, ["/bin/cat", str(wt / ".ctf" / "canary")])
        checks.append(Check(".ctf/ inside the checkout unreadable",
                            r.returncode != 0 and "CANARY" not in r.stdout, out(r)))
        r = run(withsock.codex_config_args(), [python, "-I", "-c", _UNIX_SRC, str(sock)])
        checks.append(Check("listed unix socket reachable (synthetic stand-in for Docker's)",
                            "UNIX HELLO" in r.stdout, out(r)))
        r = run(args, [python, "-I", "-c", _UNIX_SRC, str(sock)])
        checks.append(Check("control: an unlisted unix socket is refused", "UNIX-DENIED" in r.stdout, out(r)))
        r = run(args, [python, "-I", "-c", JIT_PROBE_SRC])
        cap = classify_jit(r.returncode, r.stdout, r.stderr)
        checks.append(Check("JIT engines (Unicorn) under Codex's seatbelt", cap.ok,
                            "works" if cap.ok else cap.reason + "; needs_jit tests report not run there",
                            required=False))
    finally:
        if server is not None:
            server.close()
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(codex_home, ignore_errors=True)
    return checks
