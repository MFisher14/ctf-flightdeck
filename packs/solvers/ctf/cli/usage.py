"""ctf usage ingest | report | agents | assign | assign-role | reconcile | ttl -- the usage ledger (B-193).

    python -m ctf usage ingest [--root DIR ...] [--harness claude|codex|all] [--log PATH ...] [--json]
        read new Claude Code / Codex session-log lines of the event workdir (and each --root) into
        <workdir>/usage/responses.jsonl, one row per response; record the model served per agent
    python -m ctf usage report [--json]        totals per model and tier, per challenge, per role when
                                               any role is recorded (B-096), unattributed spend by agent
    python -m ctf usage agents [--json]        the model actually served to each agent (and tiers)
    python -m ctf usage assign AGENT CHALLENGE --by WHO [--note TEXT]
                                               attribute an agent (and its subagents) to a challenge
    python -m ctf usage assign-role AGENT ROLE --by WHO [--note TEXT]
                                               record an agent's work role (verify, solve, ...) so the
                                               report splits cost per role and per model (B-096)
    python -m ctf usage reconcile [--charge] [--json]
                                               usage vs the event ledger's `spend` per challenge;
                                               --charge tops the ledger up (source usage:reconcile)
    python -m ctf usage ttl [--window S] [--top N] [--json]
                                               per Claude thread, the 1-hour cache writes priced at
                                               the 5-minute rate: gross (next response within S
                                               seconds, 300), the re-writes a response more than S
                                               but within 1 h later would pay at 5m, and net (B-118)

Sessions are found by working folder: Claude Code projects under $CLAUDE_CONFIG_DIR (else ~/.claude)
and Codex threads in $CODEX_HOME (else ~/.codex) state_<n>.sqlite and sessions/; both are read, never
written. A response whose cwd is outside the workdir and every --root is never read into the ledger.
Prices come from tools/ledger/pricing.json at report time (--pricing to use another table).

Exit codes: 0 ok; 2 an error (no event or workdir, missing session source, corrupt store); 4 some
usage could not be priced or read (an unknown model, a Codex rollout with only legacy token_count
lines), named on stderr.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "the shipped usage ledger: per-response usage, tier pricing, model served, one attribution (B-193)"
UNPRICED_EXIT = 4


class UsageCLIError(RuntimeError):
    pass


def _tools():
    """tools.ledger owns the price table and the session-log readers. Like ctf/cli/access.py this is a
    lazy import (docs/CONTRACTS.md section 11), turned into a named error when tools/ is not importable."""
    try:
        from tools.ledger import pricing, sources, usage
    except ImportError as e:
        raise UsageCLIError(f"needs tools.ledger (the price table and session-log readers) and cannot "
                            f"import it ({e}); run from the repo root") from e
    return pricing, sources, usage


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir (default: the event's)")
    p.add_argument("--pricing", help="pricing table (default tools/ledger/pricing.json)")
    sp = p.add_subparsers(dest="action", required=True)
    ig = sp.add_parser("ingest", help="read new session-log usage into the usage ledger")
    ig.add_argument("--root", action="append", default=[],
                    help="another folder whose sessions count (repeatable; the workdir always does)")
    ig.add_argument("--harness", choices=("claude", "codex", "all"), default="all")
    ig.add_argument("--log", action="append", default=[],
                    help="read this log instead of discovering (repeatable; needs --harness claude|codex)")
    ig.add_argument("--claude-home", help="Claude Code config folder (default $CLAUDE_CONFIG_DIR, else ~/.claude)")
    ig.add_argument("--codex-home", help="Codex config folder (default $CODEX_HOME, else ~/.codex)")
    ig.add_argument("--json", action="store_true")
    rp = sp.add_parser("report", help="totals per model and tier, per challenge, unattributed spend")
    rp.add_argument("--json", action="store_true")
    ag = sp.add_parser("agents", help="the model actually served to each agent")
    ag.add_argument("--json", action="store_true")
    asg = sp.add_parser("assign", help="attribute an agent (and its subagents) to a challenge")
    asg.add_argument("agent", help="Claude session or subagent id, or Codex thread id (see `usage report`)")
    asg.add_argument("challenge", help="challenge id")
    asg.add_argument("--by", required=True, help="who decided it")
    asg.add_argument("--note")
    arl = sp.add_parser("assign-role",
                        help="record an agent's work role (verify, solve, ...) so report splits cost by role")
    arl.add_argument("agent", help="Claude session or subagent id, or Codex thread id (see `usage report`)")
    arl.add_argument("role", help="one of: solve, build, verify, doc, orchestrate, guardian, other")
    arl.add_argument("--by", required=True, help="who decided it")
    arl.add_argument("--note")
    rc = sp.add_parser("reconcile", help="usage vs the event ledger's spend, per challenge")
    rc.add_argument("--charge", action="store_true",
                    help="record the difference as spend (source usage:reconcile) where usage is higher")
    rc.add_argument("--json", action="store_true")
    tt = sp.add_parser("ttl", help="1-hour cache writes priced at the 5m rate: gross, late re-write cost, net (B-118)")
    tt.add_argument("--window", type=float, default=None,
                    help="seconds a 5-minute write stays warm (default 300)")
    tt.add_argument("--top", type=int, default=20, help="threads to list (default 20; 0 lists none)")
    tt.add_argument("--json", action="store_true")


def _workdir(args) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(args.event)


def _money(x: float) -> str:
    return f"${x:,.2f}"


def _report(args, wd: Path, pricing, usage):
    from .. import ledger as _ledger
    prices = pricing.load_prices(args.pricing)
    roles = usage.roles_from_ledger(_ledger.read(wd))       # B-096: role split when any was recorded
    return usage.summarize(usage.load(wd), prices, usage.Attributor(wd), roles=roles or None)


def _warn_unpriced(rep) -> int:
    if not rep.unpriced:
        return 0
    for u in rep.unpriced:
        print(f"UNPRICED: {u['responses']} {u['harness']} response(s) on {u['model']} tier {u['tier']}: "
              f"{u['reason']}; not in any total", file=sys.stderr)
    return UNPRICED_EXIT


def _ttl_note(rep) -> str | None:
    t = rep.ttl_assumed
    if not t.get("responses"):
        return None
    return (f"note: {t['responses']} response(s) ({_money(t['usd'])}) logged no cache TTL split; "
            "their cache writes are priced at the 5-minute rate")


def _ingest(args, wd: Path, usage) -> int:
    roots = [wd] + [Path(r).expanduser() for r in args.root]
    harnesses = usage.HARNESSES if args.harness == "all" else (args.harness,)
    refs = None
    if args.log:
        if args.harness == "all":
            raise UsageCLIError("--log needs --harness claude or --harness codex")
        refs = [usage.ref_for(p, args.harness) for p in args.log]
    res = usage.ingest(wd, roots, harnesses=harnesses, refs=refs,
                       claude_home=Path(args.claude_home).expanduser() if args.claude_home else None,
                       codex_home=Path(args.codex_home).expanduser() if args.codex_home else None)
    if args.json:
        print(json.dumps(dict(res.to_dict(), store=str(usage.store_path(wd)))))
    else:
        print(f"usage ingest: {res.logs} log(s); {res.new} new response(s), {res.superseded} superseded; "
              f"{res.served} new model-served record(s); store {usage.store_path(wd)}")
        if res.outside:
            print(f"  {res.outside} response(s) ran outside the workdir and every --root: not read")
        if res.no_cwd:
            print(f"  {res.no_cwd} response(s) carry no cwd: not read")
    for n in res.notes:
        print(f"note: {n}", file=sys.stderr)
    for f in res.legacy_rollouts:
        print(f"UNREAD: {f}: Codex rollout has only legacy token_count lines (no per-response usage); "
              "price it with python -m tools.ledger price --harness codex", file=sys.stderr)
    return UNPRICED_EXIT if res.legacy_rollouts else 0


def _print_report(rep) -> None:
    print(f"usage: {rep.responses:,} response(s), {rep.tok:,} tok, {_money(rep.usd)}")
    print(f"{'harness':<7} {'model':<28} {'tier':<10} {'responses':>9} {'tok':>14} {'usd':>12}")
    for m in rep.by_model:
        print(f"{m['harness']:<7} {str(m['model']):<28} {m['tier']:<10} {m['responses']:>9,} "
              f"{m['tok']:>14,} {m['usd']:>12,.2f}")
    print("by challenge:")
    for cid, c in rep.by_challenge.items():
        models = ", ".join(f"{k} x{v}" for k, v in sorted(c["models"].items(), key=lambda kv: -kv[1]))
        print(f"  {cid:<12} {c['responses']:>7,} resp {c['tok']:>14,} tok {c['usd']:>12,.2f}  {models}")
    if rep.by_role:
        print("by role:")
        for r in rep.by_role:
            print(f"  {r['role']:<12} {r['responses']:>7,} resp {r['tok']:>14,} tok {r['usd']:>12,.2f}")
        for rm in rep.by_role_model:
            print(f"    {rm['role']:<10} {rm['harness']:<7} {str(rm['model']):<26} {rm['tier']:<10} "
                  f"{rm['responses']:>7,} resp {rm['usd']:>12,.2f}")
    un = rep.unattributed
    if un.get("responses"):
        print(f"unattributed: {un['responses']:,} response(s), {_money(un['usd'])}:")
        for a in un["agents"]:
            print(f"  {a['harness']} {a['kind']} {a['agent']}: {a['responses']:,} resp {_money(a['usd'])} "
                  f"({a['why']}); assign with: python -m ctf usage assign {a['agent']} <challenge> --by <who>")
    n = _ttl_note(rep)
    if n:
        print(n)


def _print_agents(rep) -> None:
    print(f"{'harness':<7} {'kind':<8} {'agent':<40} {'served':<26} {'responses':>9} {'usd':>10}  models / tiers / challenges")
    for a in rep.agents:
        models = ", ".join(f"{k} x{v}" for k, v in sorted(a["models"].items(), key=lambda kv: -kv[1]))
        tiers = ", ".join(f"{k} x{v}" for k, v in sorted(a["tiers"].items()))
        chals = ", ".join(f"{k} x{v}" for k, v in sorted(a["challenges"].items()))
        flag = "  MIXED" if len(a["models"]) > 1 else ""
        print(f"{a['harness']:<7} {a['kind']:<8} {a['agent']:<40} {str(a['served']):<26} {a['responses']:>9,} "
              f"{a['usd']:>10,.2f}  {models} / {tiers} / {chals}{flag}")


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.1f}%" if d else "-"


def _ttl(args, wd: Path, pricing, usage) -> int:
    """B-118: the TTL report (gross saving, the late re-write counter-cost, net). Exit 4 when a 1h write
    or a late re-read could not be priced or a row had no timestamp (the figures would be wrong), named
    on stderr."""
    if args.top < 0:
        raise UsageCLIError(f"--top must be >= 0 (got {args.top})")
    window = usage.TTL_WINDOW_S if args.window is None else args.window
    rep = usage.ttl_report(usage.load(wd), pricing.load_prices(args.pricing), window_s=window)
    if args.json:
        print(json.dumps(rep.to_dict()))
    else:
        t = rep.total
        w = f"{rep.window_s:g} s"
        print(f"cache TTL: {t['threads']:,} Claude thread(s); {t['writes_1h']:,} response(s) wrote 1h cache "
              f"({t['tok_1h']:,} tok, {_money(t['usd_1h'])} for those responses)")
        print(f"  next response within {w}: {t['hit_5m']:,} ({_pct(t['hit_5m'], t['writes_1h'])}), "
              f"{t['tok_hit_5m']:,} tok; at the 5-minute rate: {_money(t['saving'])} saved (gross)")
        print(f"  next response after {w}: {t['late_1h']:,} ({_money(t['saving_late'])} at 5m); no next "
              f"response: {t['last_1h']:,} ({_money(t['saving_last'])} at 5m, nothing read them again)")
        print(f"  re-written at 5m: {t['reread_late']:,} response(s) came over {w} but within 1 h of the "
              f"previous one and read {t['tok_reread_late']:,} tok a 5-minute write would have let expire: "
              f"{_money(t['cost_late'])} more")
        print(f"  net at 5m (every 1h write at the 5-minute rate, minus the re-writes): {_money(t['net'])}")
        print(f"  5m writes followed after {w} (cold re-cache): {t['late_5m']:,} of {t['writes_5m']:,}, "
              f"{t['tok_late_5m']:,} tok")
        print("by kind:")
        for kind, k in rep.by_kind.items():
            print(f"  {kind:<9} {k['threads']:>5,} thr {k['writes_1h']:>8,} 1h writes "
                  f"{_pct(k['hit_5m'], k['writes_1h']):>7} within  gross {_money(k['saving']):>12}  "
                  f"re-write {_money(k['cost_late']):>12}  net {_money(k['net']):>12}  late 5m {k['late_5m']:,}")
        shown = [th for th in rep.threads if th.writes_1h][:args.top]
        if shown:
            print(f"{'kind':<9} {'agent':<40} {'1h writes':>9} {'within':>7} {'gross':>11} {'re-write':>11} "
                  f"{'net':>11} {'late 5m':>8}")
            for th in shown:
                print(f"{th.kind:<9} {th.agent:<40} {th.writes_1h:>9,} {_pct(th.hit_5m, th.writes_1h):>7} "
                      f"{th.saving:>11,.2f} {th.cost_late:>11,.2f} {th.net:>11,.2f} {th.late_5m:>8,}")
    code = 0
    if rep.no_ts.get("responses"):
        print(f"UNPLACED: {rep.no_ts['responses']:,} Claude response(s) have no usable timestamp "
              f"({rep.no_ts['tok_1h']:,} tok of 1h writes): not in any count", file=sys.stderr)
        code = UNPRICED_EXIT
    for u in rep.unpriced:
        print(f"UNPRICED: {u['responses']} claude response(s) (1h writes or late re-reads) on {u['model']} "
              f"tier {u['tier']}: "
              f"{u['reason']}; not in any total", file=sys.stderr)
        code = UNPRICED_EXIT
    return code


def _reconcile(args, wd: Path, rep, usage) -> int:
    from .. import ledger as _ledger
    recon = usage.reconcile(rep, _ledger.read(wd))
    charged = []
    if args.charge:
        from .. import budget, event
        prof = event.load(args.event) if args.event else event.current()
        meter = budget.LedgerMeter(prof, workdir=wd, on_cap=lambda st, path: None)
        charged = usage.charge(meter, recon)
    if args.json:
        print(json.dumps({"challenges": [r.to_dict() for r in recon],
                          "charged": [{"challenge_id": r.challenge_id, "usd": r.delta_usd, "outcome": o}
                                      for r, o in charged]}))
        return 0
    print(f"{'challenge':<12} {'usage usd':>11} {'ledger usd':>11} {'delta':>10}")
    for r in recon:
        print(f"{r.challenge_id:<12} {r.usage_usd:>11,.2f} {r.ledger_usd:>11,.2f} {r.delta_usd:>+10,.2f}")
    for r, o in charged:
        extra = "; the budget cap is reached (python -m ctf budget status)" if o == "at_cap" else ""
        print(f"charged {r.challenge_id}: +{_money(r.delta_usd)} as spend (source {usage.RECONCILE_SOURCE}){extra}")
    if not args.charge and any(r.delta_usd >= 0.005 for r in recon):
        print("usage is above the ledger for some challenges; --charge records the difference as spend")
    return 0


def run(args: argparse.Namespace) -> int:
    from ..event import EventError
    try:
        pricing, sources, usage = _tools()
    except UsageCLIError as e:
        print(f"ctf usage: {e}", file=sys.stderr)
        return 2
    named = (UsageCLIError, EventError, FileNotFoundError, ValueError, OSError,
             usage.UsageError, sources.SourceError)   # PricingError is a ValueError
    try:
        wd = _workdir(args)
        if args.action == "ingest":
            return _ingest(args, wd, usage)
        if args.action == "assign":
            usage.assign(wd, args.agent, args.challenge, by=args.by, note=args.note)
            print(f"assigned {args.agent} (and its subagents) to challenge {args.challenge}")
            return 0
        if args.action == "assign-role":
            usage.assign_role(wd, args.agent, args.role, by=args.by, note=args.note)
            print(f"recorded {args.agent} (and its subagents) as role {args.role}")
            return 0
        if args.action == "ttl":
            return _ttl(args, wd, pricing, usage)
        rep = _report(args, wd, pricing, usage)
        if args.action == "reconcile":
            code = _reconcile(args, wd, rep, usage)
            return max(code, _warn_unpriced(rep))
        if args.json:
            print(json.dumps(rep.to_dict() if args.action == "report" else {"agents": rep.agents}))
        elif args.action == "report":
            _print_report(rep)
        else:
            _print_agents(rep)
        return _warn_unpriced(rep)
    except named as e:
        print(f"ctf usage: {e}", file=sys.stderr)
        return 2
