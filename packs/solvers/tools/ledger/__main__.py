"""python -m tools.ledger price|feed|fallback  (run from the repo root). See tools/ledger/__init__.py."""
from __future__ import annotations

import argparse
import collections
import json
import sys

from . import fallback, live, pricing, scan

FALLBACK_EXIT = 5   # `fallback`: at least one session fell back to a fallback model


def _price(args) -> int:
    prices = pricing.load_prices(args.pricing)
    rows, fallback = scan.scan_files(args.logs, args.harness)
    agg: dict = collections.defaultdict(collections.Counter)
    for r in rows.values():
        k = (r["model"] or "unknown", r["speed"])
        agg[k]["responses"] += 1
        agg[k]["tokens"] += pricing.tokens(r)
        agg[k]["usd"] += pricing.cost(r, prices)
    total = collections.Counter()
    print(f"{'model':<28} {'tier':<10} {'responses':>9} {'tokens':>14} {'usd':>12}")
    for (model, speed), v in sorted(agg.items(), key=lambda kv: -kv[1]["usd"]):
        print(f"{model:<28} {speed:<10} {v['responses']:>9,} {v['tokens']:>14,} {v['usd']:>12,.2f}")
        total.update(v)
    print(f"{'total':<28} {'':<10} {total['responses']:>9,} {total['tokens']:>14,} {total['usd']:>12,.2f}")
    for f in fallback:
        print(f"note: {f}: no token_usage_record lines; priced from token_count fallback", file=sys.stderr)
    return 0


def _feed(args) -> int:
    from ctf import budget, event
    prof = event.load(args.event) if args.event else event.current()
    meter = budget.LedgerMeter(prof)
    try:
        res = live.feed(meter, args.challenge, args.logs, args.harness, state_path=args.state)
    except budget.BudgetExceeded as e:
        print(f"BUDGET CAP: {e}", file=sys.stderr)
        return 3
    sp = meter.spent(args.challenge)
    print(f"challenge {args.challenge}: +${res.usd:.4f} ({res.responses} new responses, {res.tokens:,} tokens); "
          f"total ${sp.usd:.2f} of ${meter.cap(args.challenge):.2f} cap")
    if res.unpriced:
        for f in res.unpriced:
            print(f"UNPRICED: {f}: Codex rollout has only token_count lines; price it after the event with "
                  "python -m tools.ledger price --harness codex", file=sys.stderr)
        return 4
    return 0


def _fallback(args) -> int:
    from ctf import event
    prof = event.load(args.event) if args.event else event.current()
    models = prof.models
    primary = args.primary or models.primary
    fb = tuple(args.fallback) if args.fallback else models.fallback
    rep = fallback.detect(args.logs, primary, fb, pricing.load_prices(args.pricing))
    recorded = fallback.record(rep, cyber_verified=models.cyber_verified, challenge_id=args.challenge) \
        if args.record else []
    warn_out = sys.stdout if not args.json else sys.stderr

    def warn_other(s):
        if s.other_responses:
            print(f"WARN      {s.log}: " + fallback.OTHER_MODELS.format(
                n=s.other_responses, models=", ".join(map(str, s.other_models)), primary=primary),
                file=warn_out)

    if args.json:
        print(json.dumps(dict(rep.to_dict(), event=prof.slug, cyber_verified=models.cyber_verified,
                              recorded=len(recorded))))
        for s in rep.sessions:
            warn_other(s)
    else:
        for s in rep.sessions:
            if not s.fell_back:
                other = f", {s.other_responses} on other model(s)" if s.other_responses else ""
                print(f"ok        {s.log}: {s.primary_responses} on {primary}{other}, no fallback")
                warn_other(s)
                continue
            kind = "FALLBACK-ONLY" if s.fallback_only else ("STUCK" if s.stuck else "FALLBACK")
            after = "" if s.minutes_to_fallback is None else f" {s.minutes_to_fallback:.0f} min in,"
            print(f"{kind:<9} {s.log}: {s.fallback_responses} response(s) on {', '.join(s.fallback_models)}"
                  f" from {s.first_fallback_ts},{after} {s.primary_responses} on {primary}; "
                  f"${s.fallback_usd:.2f} (same tokens on {primary}: ${s.at_primary_usd:.2f}, "
                  f"premium ${s.premium_usd:.2f})")
            warn_other(s)
        n = len(rep.fell_back)
        f = rep.observed_factor
        print(f"{n} of {len(rep.sessions)} session(s) fell back; fallback spend ${rep.fallback_usd:.2f}, "
              f"premium ${rep.premium_usd:.2f}" + (f" (x{f:.2f} for this token mix)" if f else ""))
        if args.record:
            print(f"recorded {len(recorded)} new {fallback.LEDGER_EVENT} ledger event(s)")
    if not rep.fell_back:
        return 0
    out = sys.stdout if not args.json else sys.stderr
    print("NOTE: " + fallback.GUIDANCE.format(primary=primary, fallback=", ".join(fb)), file=out)
    if models.verified:
        print("NOTE: " + fallback.GRANTED_BUT_FELL_BACK, file=out)
    else:
        print(fallback.HUMAN_STEP.format(slug=prof.slug), file=out)
    return FALLBACK_EXIT


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.ledger", description=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)
    pp = sp.add_parser("price", help="price session logs (totals per model and tier)")
    pp.add_argument("--harness", choices=sorted(scan.PARSERS), required=True)
    pp.add_argument("--pricing", help="pricing table (default tools/ledger/pricing.json)")
    pp.add_argument("logs", nargs="+")
    fp = sp.add_parser("feed", help="charge new spend in the logs to one challenge's budget")
    fp.add_argument("--challenge", required=True)
    fp.add_argument("--harness", choices=sorted(scan.PARSERS), required=True)
    fp.add_argument("--event", help="event slug (default: the current event)")
    fp.add_argument("--state", help="feed state file (default <workdir>/budget/feed-state.json)")
    fp.add_argument("logs", nargs="+")
    fb = sp.add_parser("fallback", help="find sessions a safety classifier moved off the primary model "
                       f"(B-100); exit {FALLBACK_EXIT} when any did")
    fb.add_argument("--event", help="event slug (default: the current event); its [models] table names "
                    "the primary and fallback models")
    fb.add_argument("--primary", help="override the profile's models.primary")
    fb.add_argument("--fallback", action="append", help="override the profile's models.fallback (repeatable)")
    fb.add_argument("--record", action="store_true",
                    help=f"append one {fallback.LEDGER_EVENT} ledger event per newly seen fallen-back session")
    fb.add_argument("--challenge", help="with --record: the challenge these logs worked on")
    fb.add_argument("--pricing", help="pricing table (default tools/ledger/pricing.json)")
    fb.add_argument("--json", action="store_true", help="one JSON object on stdout")
    fb.add_argument("logs", nargs="+", help="Claude Code session JSONLs, one session each")
    args = ap.parse_args(argv)
    if args.cmd == "fallback" and args.challenge and not args.record:
        ap.error("--challenge needs --record")
    try:
        if args.cmd == "fallback":
            return _fallback(args)
        return _price(args) if args.cmd == "price" else _feed(args)
    except (pricing.PricingError, FileNotFoundError, ValueError) as e:
        print(f"tools.ledger: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
