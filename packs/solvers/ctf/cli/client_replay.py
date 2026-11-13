"""ctf client-replay: a shipped client's User-Agent and URLs, harvested and replayed in scope (B-131).

    python -m ctf client-replay harvest <file|dir>... [--json] [--max-bytes N] [--all]
    python -m ctf client-replay run <challenge_dir> [--url U]... [--ua A]... [--hops N]
        [--max-requests N] [--head FRAGMENT] [--include-stock] [--challenge-id ID] [--event SLUG]

`harvest` is offline: it reads the files as data and prints the custom User-Agent constants and the
URLs beside them (ctf.clientreplay.harvest). `run` is the network step: it runs the engine
web.client_replay with replay on, through the engine runner (so the run is recorded as engine.run),
and prints its SolverResult. Every URL passes the event's scope guard before a connection; a
refused URL is reported, not fetched. Exit status: harvest 0 (a custom User-Agent was found), 1
(none), 2 (unusable input); run: the runner's.
"""
from __future__ import annotations

import argparse
import json
import sys

HELP = "harvest a shipped client's User-Agent and URLs, and replay them against in-scope hosts"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sp = parser.add_subparsers(dest="action", required=True)
    hv = sp.add_parser("harvest", help="offline: User-Agent and URL constants of files, folders, raw images")
    hv.add_argument("paths", nargs="+")
    hv.add_argument("--json", action="store_true")
    hv.add_argument("--max-bytes", type=int, help="bytes read in all (default 4 GiB)")
    hv.add_argument("--all", action="store_true", help="list stock User-Agents and every URL too")
    rn = sp.add_parser("run", help="network: replay the shipped User-Agent against in-scope URLs and their links")
    rn.add_argument("challenge_dir")
    rn.add_argument("--url", action="append", default=[], help="a URL to replay as well (repeatable)")
    rn.add_argument("--ua", action="append", default=[], help="a User-Agent to replay as well (repeatable)")
    rn.add_argument("--hops", type=int, default=1, help="link depth from each URL (default 1: its first-level links)")
    rn.add_argument("--max-requests", type=int)
    rn.add_argument("--head", help="a literal first part of the flag (e.g. read off the booted screen) to join "
                                   "with a literal tail the replay receives")
    rn.add_argument("--include-stock", action="store_true", help="replay stock library/browser User-Agents too")
    rn.add_argument("--challenge-id", help="adds the submit gate's wrong-answer and guess count to the notes")
    rn.add_argument("--event", help="event slug (default: CTF_EVENT)")
    rn.add_argument("--no-ledger", action="store_true", help="do not append engine.run to the ledger")


def _harvest(args: argparse.Namespace) -> int:
    from .. import clientreplay as cr
    try:
        kw = {} if args.max_bytes is None else {"max_bytes": args.max_bytes}
        h = cr.harvest(args.paths, **kw)
    except (cr.ReplayError, OSError) as e:
        print(f"ctf client-replay: {e}", file=sys.stderr)
        return 2
    custom = h.custom_user_agents()
    if args.json:
        print(json.dumps(h.to_dict(), indent=2))
        return 0 if custom else 1
    print(f"{h.files} file(s), {h.scanned_bytes} bytes read")
    for line in h.truncated:
        print(f"  INCOMPLETE {line}")
    for line in h.skipped:
        print(f"  skipped    {line}")
    shown = h.user_agents if args.all else custom
    print(f"User-Agent constants ({len(custom)} custom, {len(h.user_agents) - len(custom)} stock):")
    for c in shown:
        tag = "stock " if c.stock else ("nearby" if c.how == "nearby" else "custom")
        print(f"  {tag}  {c.value!r}  {c.path}@{c.offset} ({c.encoding}, {c.count}x)")
    urls = h.urls if args.all else h.client_urls()
    print(f"URLs beside a custom User-Agent ({len(h.client_urls())} of {len(h.urls)} harvested):")
    for c in urls:
        print(f"  {'client' if c.near_ua else 'other '}  {c.value}  {c.path}@{c.offset}")
    if not custom:
        print("no custom User-Agent constant found")
        return 1
    return 0


def _run(args: argparse.Namespace) -> int:
    from ..engines import manifest, runner
    opts = ["--opt", "replay=true", "--opt", f"hops={args.hops}"]
    if args.url:
        opts += ["--opt", "url=" + json.dumps(args.url)]
    if args.ua:
        opts += ["--opt", "user_agent=" + json.dumps(args.ua)]
    if args.max_requests is not None:
        opts += ["--opt", f"max_requests={args.max_requests}"]
    if args.head:
        opts += ["--opt", "head=" + json.dumps(args.head)]
    if args.include_stock:
        opts += ["--opt", "include_stock=true"]
    if args.challenge_id:
        opts += ["--opt", "challenge_id=" + json.dumps(str(args.challenge_id))]
    if args.event:
        opts += ["--event", args.event]
    try:
        return runner.run("web.client_replay", [args.challenge_dir, *opts], record=not args.no_ledger,
                          challenge_id=args.challenge_id)
    except (runner.EngineError, manifest.ManifestError) as e:
        print(f"ctf client-replay: {e}", file=sys.stderr)
        return 2


def run(args: argparse.Namespace) -> int:
    return _harvest(args) if args.action == "harvest" else _run(args)
