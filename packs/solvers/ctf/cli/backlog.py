"""ctf backlog — the improvements backlog as data (B-138).

    python -m ctf backlog list [--status S] [--lane L] [--open] [--json] [--file F | --event SLUG]
    python -m ctf backlog open [--json] [--file F | --event SLUG]        # open rows + the open count
    python -m ctf backlog set-status ID STATUS [--file F | --event SLUG]
    python -m ctf backlog rank [--event SLUG] [--effort-budget U] [--board B] [--top N] [--json]
    python -m ctf backlog render [--out FILE] [--file F | --event SLUG]
    python -m ctf backlog sync [--write] [--no-git] [--file F]           # rebuild status from the tree

One source of truth: docs/backlog.jsonl (the master), or <workdir>/backlog.jsonl with --event (same
schema). Status is a closed vocabulary; a done status moves the row to the Done section. `rank` reuses
the build-plan value model (modeled estimates, not measured savings). `sync` recomputes each row's
status from BUILD-PLAN.md, the docs/build-log Status lines and the Merge commits, keeping any
operator-authored decision / impact / cost / risk / priority on a row.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import backlog as _bl
from .. import buildplan as _bp
from .. import event as _event

HELP = "the improvements backlog as machine-readable rows (list/open/set-status/rank/render/sync)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)

    def with_source(q: argparse.ArgumentParser) -> None:
        g = q.add_mutually_exclusive_group()
        g.add_argument("--file", help="backlog JSONL file (default: docs/backlog.jsonl)")
        g.add_argument("--event", help="use the per-event backlog <workdir>/backlog.jsonl for SLUG")

    ls = sp.add_parser("list", help="list rows (optionally filtered)")
    ls.add_argument("--status", help="only rows with this status")
    ls.add_argument("--lane", help="only rows in this lane")
    ls.add_argument("--open", action="store_true", help="only open (not-done) rows")
    ls.add_argument("--json", action="store_true")
    with_source(ls)

    op = sp.add_parser("open", help="open rows and the open count (the count is computed, not eyeballed)")
    op.add_argument("--json", action="store_true")
    with_source(op)

    ss = sp.add_parser("set-status", help="change one row's status (a done status moves it to Done)")
    ss.add_argument("id")
    ss.add_argument("status", help="one of: " + ", ".join(_bl.STATUSES))
    with_source(ss)

    rk = sp.add_parser("rank", help="rank the open rows by modeled value per effort (reuses build-plan)")
    rk.add_argument("--event", help="event slug (default: the current event)")
    rk.add_argument("--effort-budget", type=float, default=0.0,
                    help="effort units to approve (S=1 M=3 L=8 XL=20; default 0)")
    rk.add_argument("--board", help="JSON list of visible challenges (post-board ranking)")
    rk.add_argument("--top", type=int, default=25, help="rows to print (0 = all; default 25)")
    rk.add_argument("--json", action="store_true")
    rk.add_argument("--file", help="backlog JSONL file (default: docs/backlog.jsonl)")

    rn = sp.add_parser("render", help="render the backlog to Markdown")
    rn.add_argument("--out", help="write here (default: stdout)")
    rn.add_argument("--title", default="Backlog")
    with_source(rn)

    sy = sp.add_parser("sync", help="rebuild rows+status from BUILD-PLAN.md, build logs and Merge commits")
    sy.add_argument("--write", action="store_true", help="write the file (default: dry run, show counts)")
    sy.add_argument("--no-git", action="store_true", help="skip the Merge-commit scan")
    sy.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed file differs from a fresh sync (drift check; "
                         "this is an operator check, deliberately NOT in the merge-gate: the snapshot "
                         "goes stale as unrelated items merge)")
    sy.add_argument("--file", help="backlog JSONL file to write/update (default: docs/backlog.jsonl)")


def _source_path(args: argparse.Namespace) -> Path:
    if getattr(args, "event", None):
        return _bl.event_path(args.event)
    if getattr(args, "file", None):
        return Path(args.file)
    return _bl.default_path()


def _fmt_row(r: _bl.Row) -> str:
    tail = " [hard-tail]" if r.hard_tail else ""
    return (f"  {r.id:<8} {r.status:<11} {r.effort or '-':<3} {r.lane or '-':<14} "
            f"{r.title[:60]}{tail}")


def _print_counts(c: dict) -> None:
    nz = ", ".join(f"{s}={n}" for s, n in c["by_status"].items() if n)
    print(f"{c['open']} open ({c['hard_tail']} hard tail) · {c['done']} done · {c['total']} total")
    print(f"  by status: {nz or 'none'}")


def _list(args: argparse.Namespace) -> int:
    rows = _bl.load(_source_path(args))
    sel = _bl.order(rows)
    if args.open:
        sel = [r for r in sel if not r.terminal]
    if args.status:
        if args.status not in _bl.STATUSES:
            print(f"ctf backlog: unknown status {args.status!r}", file=sys.stderr)
            return 2
        sel = [r for r in sel if r.status == args.status]
    if args.lane:
        sel = [r for r in sel if r.lane == args.lane]
    if args.json:
        import json
        print(json.dumps([r.to_dict() for r in sel], indent=1))
        return 0
    _print_counts(_bl.counts(rows))
    print(f"  showing {len(sel)} row(s):")
    for r in sel:
        print(_fmt_row(r))
    return 0


def _open(args: argparse.Namespace) -> int:
    rows = _bl.load(_source_path(args))
    opens = _bl.open_rows(rows)
    if args.json:
        import json
        print(json.dumps({"open": len(opens), "rows": [r.to_dict() for r in opens]}, indent=1))
        return 0
    _print_counts(_bl.counts(rows))
    for r in opens:
        print(_fmt_row(r))
    return 0


def _set_status(args: argparse.Namespace) -> int:
    path = _source_path(args)
    rows = _bl.load(path)
    # Only the per-event backlog logs the change to that event's ledger; editing the master backlog
    # (no event, no workdir) just rewrites the file.
    wd = _bl.paths.workdir(args.event) if getattr(args, "event", None) else None
    rows, row = _bl.set_status(rows, args.id, args.status, workdir=wd, log=wd is not None)
    _bl.save(path, rows)
    where = "Done" if row.terminal else "Open"
    print(f"{row.id} -> {row.status} ({where} section); wrote {path}")
    return 0


def _profile(slug: str | None) -> _event.EventProfile:
    return _event.load(slug) if slug else _event.current()


def _rank(args: argparse.Namespace) -> int:
    rows = _bl.load(Path(args.file) if args.file else _bl.default_path())
    prof = _profile(args.event)
    board = _bp.load_board(args.board) if args.board else None
    # Rank the open rows that carry a lane and effort; name any open row that cannot be ranked
    # (loud, not silent) so the gap is visible rather than aborting the whole ranking.
    rankable, skipped = [], []
    for r in _bl.open_rows(rows):
        (rankable if (r.lane and r.effort) else skipped).append(r)
    if skipped:
        print(f"NOTE: {len(skipped)} open row(s) not ranked (no lane/effort): "
              f"{', '.join(r.id for r in skipped)}", file=sys.stderr)
    rk = _bl.rank(rankable, prof, effort_budget=args.effort_budget, board=board)
    if args.json:
        print(rk.to_json())
        return 0
    print(f"backlog ranking for {prof.slug}: {len(rk.entries)} open item(s), effort budget "
          f"{rk.effort_budget:g} units, board {'visible' if rk.board_visible else 'not visible'}")
    print(f"NOTE: value and score are MODELED ESTIMATES: {_bp.ESTIMATE_LABEL}.")
    counts = {d: sum(e.decision == d for e in rk.entries) for d in _bp.DECISIONS}
    print("  " + "  ".join(f"{d}={n}" for d, n in counts.items()))
    shown = rk.entries if args.top == 0 else rk.entries[:args.top]
    for e in shown:
        print(f"  {e.rank:>3} {e.id:<8} {e.decision:<11} score={e.score:>7.3f} "
              f"{e.effort:>3} {e.lane}: {e.reason}")
    if len(shown) < len(rk.entries):
        print(f"  ... {len(rk.entries) - len(shown)} more (--top 0 for all)")
    return 0


def _render(args: argparse.Namespace) -> int:
    rows = _bl.load(_source_path(args))
    md = _bl.render_markdown(rows, title=args.title)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(md)
    return 0


def _sync(args: argparse.Namespace) -> int:
    path = Path(args.file) if args.file else _bl.default_path()
    existing = _bl.load(path) if path.is_file() else []
    rows = _bl.sync(existing=existing, use_git=not args.no_git)
    c = _bl.counts(rows)
    if args.check:
        # Drift check (operator tool, not the merge gate): is the committed file what a fresh sync
        # would produce? Compare the row payloads, not the on-disk bytes, so key order/whitespace do
        # not matter. Fresh sync already preserves operator fields from `existing`.
        fresh = [r.to_dict() for r in rows]
        have = [r.to_dict() for r in _bl.order(existing)]
        if fresh == have:
            print(f"{path} is fresh ({len(rows)} rows; {c['open']} open / {c['done']} done)")
            return 0
        fresh_ids = {r["id"] for r in fresh}
        have_ids = {r["id"] for r in have}
        added = sorted(fresh_ids - have_ids)
        removed = sorted(have_ids - fresh_ids)
        by_id = {r["id"]: r for r in have}
        changed = sorted(r["id"] for r in fresh
                         if r["id"] in by_id and r != by_id[r["id"]])
        print(f"{path} is STALE vs the tree: +{len(added)} -{len(removed)} ~{len(changed)}; "
              f"refresh with `ctf backlog sync --write`", file=sys.stderr)
        if added:
            print(f"  added:   {', '.join(added)}", file=sys.stderr)
        if removed:
            print(f"  removed: {', '.join(removed)}", file=sys.stderr)
        if changed:
            print(f"  changed: {', '.join(changed)}", file=sys.stderr)
        return 1
    if args.write:
        _bl.save(path, rows)
        print(f"wrote {path}: {len(rows)} rows")
    else:
        print(f"(dry run; --write to save to {path})")
    _print_counts(c)
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        return {
            "list": _list, "open": _open, "set-status": _set_status,
            "rank": _rank, "render": _render, "sync": _sync,
        }[args.action](args)
    except (_bl.BacklogError, _bp.BuildPlanError, _event.EventError) as e:
        print(f"ctf backlog: {e}", file=sys.stderr)
        return 2
