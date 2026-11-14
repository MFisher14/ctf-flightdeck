"""ctf lanes check | prompts | setup | run | status | integrate — programmatic Codex build lanes (B-179).

    python -m ctf lanes check BACKLOG [--repo R]          validate the backlog (+ base ref and context files)
    python -m ctf lanes prompts BACKLOG [--print ID]      write prompts/<id>.md and prompts/PACK.md
    python -m ctf lanes setup BACKLOG [--only IDS]        one git checkout per lane, .venv linked
    python -m ctf lanes run BACKLOG [--only IDS] [--concurrency N] [--codex-bin B] [--rerun] [--dry-run]
    python -m ctf lanes status BACKLOG [--json]           lane state, exit, result, reason
    python -m ctf lanes integrate BACKLOG [--target DIR] [--merge] [--apply] [--include-partial] [--json]

Every subcommand takes --lanes-dir (default $CTF_LANES_DIR, else ~/ctf-work/_lanes). See docs/lanes.md.
Exit codes: 0 ok; 1 a lane failed / was held; 2 the backlog, repo or codex is unusable.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import fence as _fence
from .. import fence_launch as _launch
from .. import paths
from ..lanes import backlog as _bl
from ..lanes import checkout as _co
from ..lanes import layout as _layout
from ..lanes import prompt as _prompt
from ..lanes import results as _res
from ..lanes import runner as _run

HELP = "Codex build lanes: backlog -> prompts, checkouts, codex exec runs, status, integration"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)

    def sub(name, help_):
        s = sp.add_parser(name, help=help_)
        s.add_argument("backlog", help="the backlog file (.yaml, .yml or .toml)")
        s.add_argument("--lanes-dir", help="lane state root (default $CTF_LANES_DIR, else ~/ctf-work/_lanes)")
        return s

    c = sub("check", "validate the backlog")
    c.add_argument("--repo", help="also check the base ref and context files in this repo (default: this checkout)")
    c.add_argument("--no-repo", action="store_true", help="validate the file only")
    pr = sub("prompts", "render the prompt pack")
    pr.add_argument("--only", help="comma-separated lane ids")
    pr.add_argument("--print", dest="print_id", metavar="ID", help="also print one lane's prompt")
    s = sub("setup", "create the lane checkouts")
    s.add_argument("--only", help="comma-separated lane ids")
    s.add_argument("--repo", help="the repo lanes clone from (default: this checkout)")
    s.add_argument("--venv", help="the venv to link as .venv (default: the master venv)")
    r = sub("run", "launch codex exec per lane")
    r.add_argument("--only", help="comma-separated lane ids")
    r.add_argument("--repo", help="the repo lanes clone from (default: this checkout)")
    r.add_argument("--venv", help="the venv to link as .venv (default: the master venv)")
    r.add_argument("--codex-bin", help="codex executable (default $CODEX_BIN, else codex on PATH)")
    r.add_argument("--concurrency", type=int, help="override the backlog's concurrency")
    r.add_argument("--timeout-minutes", type=float, help="override the backlog's timeout_minutes")
    r.add_argument("--rerun", action="store_true", help="relaunch lanes already done")
    r.add_argument("--dry-run", action="store_true", help="write the prompts and print the commands only")
    r.add_argument("--poll", type=float, default=2.0, help=argparse.SUPPRESS)
    st = sub("status", "show lane status")
    st.add_argument("--json", action="store_true")
    i = sub("integrate", "check results for collisions; optionally merge and apply CAPABILITIES entries")
    i.add_argument("--target", help="the integration checkout (default: this checkout)")
    i.add_argument("--merge", action="store_true", help="fetch and merge clean lane branches into the target")
    i.add_argument("--apply", action="store_true", help="write the CAPABILITIES entries into the target")
    i.add_argument("--include-partial", action="store_true", help="also integrate lanes that ended partial")
    i.add_argument("--json", action="store_true")


def _ids(s: str | None) -> list[str] | None:
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def _repo(a) -> Path:
    return Path(a.repo).expanduser().resolve() if getattr(a, "repo", None) else paths.repo_root()


def run(args: argparse.Namespace) -> int:
    try:
        bl = _bl.load(args.backlog)
        dirs = _layout.batch_dirs(bl.batch, args.lanes_dir)
        sel = _ids(getattr(args, "only", None))
        if sel:
            for x in sel:
                bl.lane(x)
        return _ACTIONS[args.action](args, bl, dirs, sel)
    except (_bl.BacklogError, _prompt.PromptError, _co.CheckoutError, _run.RunnerError, _res.ResultError,
            _fence.FenceError, _launch.LaunchError, KeyError, ValueError) as e:
        print(f"lanes: {e}", file=sys.stderr)
        return 2


def _check(a, bl, dirs, sel) -> int:
    print(f"batch {bl.batch}: {len(bl.lanes)} lane(s), base {bl.base}, concurrency {bl.concurrency}, "
          f"timeout {bl.timeout_minutes} min")
    for lid in bl.order():
        ln = bl.lane(lid)
        dep = f"  after {', '.join(ln.depends)}" if ln.depends else ""
        print(f"  {lid:<24} {ln.title}{dep}")
    if not a.no_repo:
        repo = _repo(a)
        sha = _co.resolve_base(repo, bl.base)
        miss = _co.missing_context(repo, bl, sha)
        for who, p in miss:
            print(f"  missing context at {bl.base}: {p} ({who})", file=sys.stderr)
        if miss:
            return 2
        print(f"base {bl.base} = {sha[:12]}; context files present")
    for ln in bl.lanes:
        _prompt.render(bl, ln, dirs)     # raises PromptError on a defect
    print(f"state folder: {dirs.root}")
    return 0


def _prompts(a, bl, dirs, sel) -> int:
    texts = _prompt.write_pack(bl, dirs, sel)
    for lid in texts:
        print(dirs.prompt(lid))
    print(dirs.prompts / "PACK.md")
    if a.print_id:
        print(texts[a.print_id] if a.print_id in texts else _prompt.render(bl, bl.lane(a.print_id), dirs))
    return 0


def _setup(a, bl, dirs, sel) -> int:
    repo = _repo(a)
    venv = Path(a.venv).expanduser() if a.venv else _co.find_venv(repo)
    for lid, what in _co.setup(repo, bl, dirs, lane_ids=sel, venv=venv).items():
        print(f"{lid:<24} {what:<8} {dirs.checkout(lid)}  ({bl.branch(lid)})")
    return 0


def _run_cmd(a, bl, dirs, sel) -> int:
    venv = Path(a.venv).expanduser() if a.venv else None
    tmo = a.timeout_minutes * 60 if a.timeout_minutes else None
    out = _run.run(bl, dirs, _repo(a), lane_ids=sel, codex=a.codex_bin, concurrency=a.concurrency,
                   rerun=a.rerun, dry_run=a.dry_run, venv=venv, poll=a.poll, timeout_s=tmo,
                   say=lambda s: print(s, flush=True))
    if a.dry_run:
        import shlex
        for lid, d in out.items():
            print(f"# {lid}\n" + " ".join(shlex.quote(x) for x in d["argv"]))
        return 0
    bad = [lid for lid, st in out.items() if st.get("state") != "done" or st.get("result_status") != "built"]
    print(f"{len(out) - len(bad)}/{len(out)} lane(s) done and built"
          + (f"; not built: {', '.join(bad)}" if bad else ""))
    return 1 if bad else 0


def _status(a, bl, dirs, sel) -> int:
    rows = _run.status_rows(bl, dirs)
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{'lane':<24} {'state':<12} {'result':<8} {'exit':>4} {'min':>6}  note")
    for r in rows:
        mins = f"{r['elapsed_s'] / 60:.1f}" if r["elapsed_s"] is not None else "-"
        ex = "-" if r["exit_code"] is None else str(r["exit_code"])
        note = r["reason"] or r["summary"] or ""
        print(f"{r['lane']:<24} {r['state']:<12} {r['result'] or '-':<8} {ex:>4} {mins:>6}  {note[:80]}")
    return 0


def _integrate(a, bl, dirs, sel) -> int:
    target = Path(a.target).expanduser().resolve() if a.target else paths.repo_root()
    rep = _res.integrate(bl, dirs, target, apply=a.apply, merge=a.merge, include_partial=a.include_partial)
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        for lid, d in rep["lanes"].items():
            verdict = d["integrated"] or "held"
            print(f"{lid:<24} {verdict}")
            for msg in d["problems"] + d["held"]:
                print(f"    - {msg}")
            for msg in d["warnings"]:
                print(f"    ~ {msg}")
        for m in rep["merged"]:
            print(f"merge: {m}")
        for c in rep["capabilities_applied"]:
            print(f"CAPABILITIES += {c}")
        if rep["capabilities_applied"]:
            print(f"review and commit {target / _res.CAPABILITIES_REL}")
        print(f"report: {dirs.integration}")
    held = [lid for lid, d in rep["lanes"].items() if not d["integrated"]]
    return 1 if held else 0


_ACTIONS = {"check": _check, "prompts": _prompts, "setup": _setup, "run": _run_cmd, "status": _status,
            "integrate": _integrate}
