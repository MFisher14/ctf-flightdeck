"""ctf fence show | claude-settings | codex-args | check | report | selftest — the solver read fence.

    python -m ctf fence show [--json]                   allowed roots, denied roots, commands
    python -m ctf fence claude-settings [--out F | --install | --stdout]
                                                        write the Claude Code settings for the fence
    python -m ctf fence codex-args                      the codex -c overrides (shell-quoted)
    python -m ctf fence check PATH...                   classify paths (exit 1 if any is outside)
    python -m ctf fence report LOG... [--json]          denied-access report (exit 1 if any)
    python -m ctf fence selftest [--codex-bin B]        run probes under `codex sandbox`

Common options pick the fence: --event SLUG (reads events/<slug>/fence.toml), --workspace DIR
(default: the event workdir), --repo DIR, --drop DIR, --allow-read DIR, --deny-read DIR,
--strict-home. See docs/fence.md.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .. import env
from .. import event as _event
from .. import fence as _fence
from .. import fence_report as _report

HELP = "solver filesystem fence: Claude/Codex settings, path checks, denied-access report"


def add_fence_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default $CTF_EVENT); reads events/<slug>/fence.toml")
    p.add_argument("--workspace", help="the event/challenge workspace (default: the event workdir)")
    p.add_argument("--repo", help="the master repo (default: this checkout)")
    p.add_argument("--drop", help="the one readable folder under ~/Downloads")
    p.add_argument("--allow-read", action="append", default=[], metavar="DIR", help="extra read root")
    p.add_argument("--deny-read", action="append", default=[], metavar="DIR", help="extra denied root")
    p.add_argument("--strict-home", action="store_true", help="deny all of $HOME outside the roots")
    p.add_argument("--no-config", action="store_true", help="ignore events/<slug>/fence.toml")


def fence_from_args(args: argparse.Namespace, *, quiet: bool = False) -> _fence.Fence:
    slug = args.event or env.get("CTF_EVENT")
    cfg = _fence.FenceConfig() if args.no_config else _fence.load_config(slug)
    if not quiet:
        print(f"fence config: {cfg.source or 'none'}", file=sys.stderr)
    return _fence.from_config(cfg, workspace=args.workspace, repo=args.repo, drop=args.drop,
                              extra_read=args.allow_read, extra_deny=args.deny_read,
                              strict_home=args.strict_home, slug=slug)


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    sh = sp.add_parser("show", help="print the fence")
    add_fence_options(sh)
    sh.add_argument("--json", action="store_true")
    cs = sp.add_parser("claude-settings", help="write the Claude Code settings file")
    add_fence_options(cs)
    g = cs.add_mutually_exclusive_group()
    g.add_argument("--out", help="write here (default <workspace>/.fence/claude-settings.json)")
    g.add_argument("--install", action="store_true",
                   help="also install as <workspace>/.claude/settings.json (project settings)")
    g.add_argument("--stdout", action="store_true", help="print the JSON instead of writing it")
    ca = sp.add_parser("codex-args", help="print the codex -c overrides that apply the fence")
    add_fence_options(ca)
    ck = sp.add_parser("check", help="classify paths against the fence")
    add_fence_options(ck)
    ck.add_argument("paths", nargs="+")
    rp = sp.add_parser("report", help="denied-access report over agent logs / transcripts")
    add_fence_options(rp)
    rp.add_argument("logs", nargs="+")
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--samples", type=int, default=15)
    st = sp.add_parser("selftest", help="probe the Codex fence under `codex sandbox`")
    add_fence_options(st)
    st.add_argument("--codex-bin", default="codex")
    st.add_argument("--max-roots", type=int, default=None)


def _install_project(f: _fence.Fence) -> Path:
    """<workspace>/.claude/settings.json. Project settings ignore blockReadsExemptPaths and cannot
    re-open what flag settings deny, so the launcher's --settings stays the primary route."""
    dest = f.workspace / ".claude" / "settings.json"
    new = json.dumps(f.claude_settings(), indent=2) + "\n"
    if dest.exists() and dest.read_text() != new:
        try:
            old = json.loads(dest.read_text())
        except json.JSONDecodeError:
            old = None
        if not (isinstance(old, dict) and old.get("$schema") == _fence.CLAUDE_SETTINGS_SCHEMA
                and "sandbox" in old):
            raise _fence.FenceError(f"{dest} exists and was not written by the fence; not overwriting")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(new)
    return dest


def run(args: argparse.Namespace) -> int:
    try:
        f = fence_from_args(args, quiet=getattr(args, "json", False) or args.action == "codex-args")
        if args.action == "show":
            d = f.describe()
            if args.json:
                print(json.dumps(d, indent=2))
                return 0
            print(f"workspace  {d['workspace']}")
            print(f"repo       {d['repo']}")
            print(f"drop       {d['drop'] or '-'}")
            print(f"read roots {', '.join(d['read_roots'])}")
            print(f"strict     {'yes' if d['strict_home'] else 'no'}")
            for r in d["deny"]:
                print(f"  deny {r['category']:<14} {r['path']}")
            for c in d["deny_commands"]:
                print(f"  deny {c['category']:<14} command /{c['pattern']}/")
            return 0
        if args.action == "claude-settings":
            if args.stdout:
                print(json.dumps(f.claude_settings(), indent=2))
                return 0
            dest = _fence.write_claude_settings(f, Path(args.out).expanduser() if args.out else None)
            print(dest)
            if args.install:
                print(_install_project(f))
            return 0
        if args.action == "codex-args":
            print(" ".join(shlex.quote(a) for a in f.codex_config_args()))
            return 0
        if args.action == "check":
            bad = 0
            for p in args.paths:
                v = f.classify(p, cwd=Path.cwd())
                label = v.kind + (f":{v.category}" if v.category else "")
                bad += v.reportable
                print(f"{label:<24} {v.path}")
            return 1 if bad else 0
        if args.action == "report":
            rep = _report.scan_files([Path(x) for x in args.logs], f)
            print(json.dumps(rep.to_dict(), indent=2) if args.json else _report.render_text(rep, samples=args.samples))
            return 0 if rep.clean else 1
        if args.action == "selftest":
            from .. import fence_selftest
            checks = fence_selftest.codex_selftest(f, codex_bin=args.codex_bin, max_roots=args.max_roots)
            for c in checks:
                print(f"{'ok  ' if c.ok else 'FAIL'}  {c.name}  {'' if c.ok else c.detail}")
            failed = sum(not c.ok for c in checks)
            print(f"{len(checks) - failed}/{len(checks)} checks passed")
            return 1 if failed else 0
        raise AssertionError(args.action)
    except (_fence.FenceError, _event.EventError, FileNotFoundError) as e:
        print(f"ctf fence: {e}", file=sys.stderr)
        return 2
