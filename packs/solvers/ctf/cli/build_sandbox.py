"""ctf build-sandbox -- the Codex sandbox profile for BUILD work on this repo (B-192).

    python -m ctf build-sandbox show        [PROFILE OPTIONS] [--json]
    python -m ctf build-sandbox codex-args  [PROFILE OPTIONS] [--name NAME]
    python -m ctf build-sandbox config-toml [PROFILE OPTIONS] [--name NAME]
    python -m ctf build-sandbox hosts
    python -m ctf build-sandbox launch      [PROFILE OPTIONS] [--interactive] [--model M]
                                            [--approval never|on-request|untrusted] [--dry-run]
                                            [PROMPT | -] [-- extra codex args]
    python -m ctf build-sandbox selftest    --scratch DIR [--codex-bin BIN]
    python -m ctf build-sandbox push        [--checkout DIR] [--remote R] [--branch B]

PROFILE OPTIONS: [--checkout DIR] [--docker] [--protect BRANCH]... [--integration-branch B]
(main, master and the integration branch are always protected; --protect adds more).
`codex-args` prints the -c overrides, one per line (`codex $(...)` is wrong: values hold spaces; use
`launch`, or `mapfile`). `config-toml` prints a fragment for ~/.codex/config.toml: installing it is a
human step, never done here. `selftest` probes the profile live under `codex sandbox` with a fresh
CODEX_HOME (no model call, no outside host); it must run outside any sandbox. `push` is a DRY RUN:
it prints the checks and the command for a person to run outside the sandbox and never pushes.
The solver fence is `python -m ctf fence` (ctf/fence.py); this profile is not for solvers.
Exit codes: 0 ok, 1 a self-test check failed, 2 an error (named).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys

from .. import build_sandbox as _bs

HELP = "Codex sandbox profile for repo build work (loopback, worktree git, host allowlist, push dry run)"


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--checkout", default=None, help="the checkout (default: this repo's)")
    p.add_argument("--docker", action="store_true",
                   help="also allow the Docker socket (listed, never exercised by this command)")
    p.add_argument("--protect", action="append", default=[], metavar="BRANCH",
                   help="another branch no lane may move (repeatable; main, master and the "
                        "integration branch always are)")
    p.add_argument("--integration-branch", default=None,
                   help="the integration branch (default: $CTF_INTEGRATION_BRANCH, else git config "
                        "ctftools.integrationBranch)")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    s = sp.add_parser("show", help="the profile, the git layout and the allowlist")
    _common(s)
    s.add_argument("--json", action="store_true")
    a = sp.add_parser("codex-args", help="the -c overrides that define and select the profile")
    _common(a)
    a.add_argument("--name", default=_bs.PROFILE_NAME)
    t = sp.add_parser("config-toml", help="a ~/.codex/config.toml fragment (installing it is a human step)")
    _common(t)
    t.add_argument("--name", default=_bs.PROFILE_NAME)
    sp.add_parser("hosts", help="the documented host allowlist, checked against the event profiles")
    la = sp.add_parser("launch", help="start codex in the build profile (--dry-run prints the command)")
    _common(la)
    la.add_argument("--interactive", action="store_true", help="the TUI instead of codex exec")
    la.add_argument("--model")
    la.add_argument("--approval", default="never", choices=_bs.APPROVAL_POLICIES)
    la.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    la.add_argument("--dry-run", action="store_true")
    la.add_argument("rest", nargs=argparse.REMAINDER, metavar="[PROMPT | -] [-- CODEX ARGS]",
                    help="the prompt ('-' reads stdin), then codex arguments after --")
    st = sp.add_parser("selftest", help="live probes under `codex sandbox` (no model call)")
    st.add_argument("--scratch", required=True,
                    help="a folder outside the temp folder for the synthetic repo (removed after)")
    st.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    pu = sp.add_parser("push", help="DRY RUN: the checks and the push command; never pushes")
    pu.add_argument("--checkout", default=None)
    pu.add_argument("--remote", default="origin")
    pu.add_argument("--branch", default=None)


def _profile(args) -> _bs.BuildProfile:
    return _bs.build(args.checkout, docker=args.docker, protect=args.protect,
                     integration_branch=args.integration_branch)


def _show(args) -> int:
    p = _profile(args)
    d = p.describe()
    if args.json:
        print(json.dumps(d, indent=2))
        return 0
    lay = p.layout
    print(f"checkout   {lay.checkout}")
    print(f"gitdir     {lay.gitdir}{'  (linked worktree)' if lay.linked else ''}")
    print(f"common     {lay.common}  (hooks/, config and packed-refs read only)")
    print(f"hooks      {lay.hooks}  (read only: git runs these outside the sandbox)")
    print(f"protected  {', '.join(p.protected)}  (ref files read only; a guard, not a wall: "
          "docs/build-sandbox.md)")
    if p.integration_branch is None:
        print("           no integration branch configured: pass --integration-branch or set "
              "$CTF_INTEGRATION_BRANCH / git config ctftools.integrationBranch to protect it too")
    print("network    loopback bind and connect; direct egress denied; through Codex's proxy only:")
    for h in p.hosts:
        print(f"             {h.name:40} {h.why}")
    if p.unix_sockets:
        print("unix       " + ", ".join(str(s) for s in p.unix_sockets) + "  (Docker; listed, not probed)")
    print("denied     " + ", ".join(str(path) for _c, path in p.deny) + ", any .ctf/")
    print("JIT        Unicorn cannot run under Codex's seatbelt (no setting fixes it); needs_jit tests "
          "report not run")
    return 0


def split_rest(rest: list[str]) -> tuple[str | None, list[str]]:
    """[PROMPT] [-- EXTRA...] -> (prompt, extra). More than one word before -- is an error."""
    from ..fence_launch import LaunchError
    rest = list(rest)
    if "--" in rest:
        i = rest.index("--")
        head, extra = rest[:i], rest[i + 1:]
    else:
        head, extra = rest, []
    if len(head) > 1:
        raise LaunchError(f"one PROMPT argument (quote it), then -- before codex arguments; got {head!r}")
    return (head[0] if head else None), extra


def _launch(args) -> int:
    from ..fence_launch import LaunchError
    prompt, extra = split_rest(args.rest)
    if prompt == "-":
        prompt = sys.stdin.read()
    if not args.interactive and not (prompt or "").strip():
        raise LaunchError("codex exec needs a prompt (argument or '-' for stdin); use --interactive "
                          "for the TUI")
    p = _profile(args)
    cmd = _bs.launch_argv(p, codex_bin=args.codex_bin, headless=not args.interactive, model=args.model,
                          approval=args.approval, extra=extra, prompt=prompt)
    if args.dry_run:
        shown = cmd[:-1] + ["<prompt>"] if prompt is not None else cmd
        print(" ".join(shlex.quote(x) for x in shown))
        return 0
    import shutil
    if shutil.which(args.codex_bin) is None:
        raise LaunchError(f"codex CLI not found ({args.codex_bin!r}); install it or set CODEX_BIN")
    os.chdir(p.layout.checkout)
    os.execvp(cmd[0], cmd)
    return 2  # not reached


def _selftest(args) -> int:
    checks = _bs.selftest(scratch=args.scratch, codex_bin=args.codex_bin)
    failed = 0
    for c in checks:
        tag = "ok  " if c.ok else ("FAIL" if c.required else "info")
        failed += (not c.ok) and c.required
        print(f"{tag}  {c.name}" + ("" if c.ok else f"  -- {c.detail}"))
    required = [c for c in checks if c.required]
    info = sum(1 for c in checks if not c.required and not c.ok)
    print(f"{len(required) - failed}/{len(required)} required checks passed"
          + (f"; {info} informational check(s) not ok" if info else ""))
    return 1 if failed else 0


def _push(args) -> int:
    plan = _bs.push_plan(args.checkout or ".", remote=args.remote, branch=args.branch)
    print(f"DRY RUN: nothing was pushed. Push {plan.branch} to {plan.remote} with (outside the sandbox):")
    print("  " + " ".join(shlex.quote(x) for x in plan.command))
    for n in plan.notes:
        print(f"  note: {n}")
    return 0


def run(args: argparse.Namespace) -> int:
    from ..fence_launch import LaunchError
    try:
        if args.action == "show":
            return _show(args)
        if args.action == "codex-args":
            for a in _profile(args).codex_config_args(args.name):
                print(a)
            return 0
        if args.action == "config-toml":
            sys.stdout.write(_profile(args).config_toml(args.name))
            return 0
        if args.action == "hosts":
            hosts = _bs.checked_hosts()
            for h in hosts:
                print(f"{h.name:40} {h.why}")
            print(f"{len(hosts)} host(s); none is an event platform, live service, Discord, model API "
                  "or a host that accepts a push or an upload")
            return 0
        if args.action == "launch":
            return _launch(args)
        if args.action == "selftest":
            return _selftest(args)
        if args.action == "push":
            return _push(args)
    except (_bs.BuildSandboxError, LaunchError, FileNotFoundError) as e:
        print(f"ctf build-sandbox {args.action}: {e}", file=sys.stderr)
        return 2
    raise AssertionError(args.action)
