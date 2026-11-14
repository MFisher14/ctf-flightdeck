"""ctf access -- the model-access status for an event: is the Opus 4.8 classifier fallback expected? (B-100)

    python -m ctf access [--event SLUG] [--json]     primary/fallback models, cyber verified status,
                                                     the fallback's rate ratios, and the human step
    python -m ctf access --plan-usd 400              also: what 400 USD of primary-rate work may cost
                                                     on the fallback (the worst-case multiplier)
    python -m ctf access --check                     exit 3 unless cyber_verified = "granted"

The status comes from the event profile's [models] table (docs/CONTRACTS.md section 1). Settling it is
an access step only the player can take (BUILD-PLAN O-3); this command reports it and never changes a
model, a harness setting or the profile. To see whether sessions actually fell back, run
`python -m tools.ledger fallback --event SLUG LOG...`.

Exit codes: 0 ok, 2 error (bad profile, missing price, tools.ledger not importable), 3 with --check when the profile is not
recorded as granted.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import event as _event

HELP = "model-access status: is the Opus 4.8 classifier fallback expected, and the human step (B-100)"
NOT_GRANTED_EXIT = 3


class AccessError(RuntimeError):
    """The status cannot be computed (the token-ledger price tools are not importable)."""


def _ledger_tools():
    """tools.ledger owns the price table and the rate-ratio helpers. This is the one place ctf/ imports
    from tools/ (docs/CONTRACTS.md section 11); it is lazy so the rest of the CLI never needs tools/,
    and it fails with a named reason instead of a traceback when tools/ is not importable."""
    try:
        from tools.ledger import fallback, pricing
    except ImportError as e:
        raise AccessError(f"needs tools.ledger (the Claude price table) and cannot import it ({e}); "
                          "run from the repo root") from e
    return fallback, pricing


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--plan-usd", type=float, help="planned Claude spend at the primary model's rates")
    p.add_argument("--check", action="store_true",
                   help=f"exit {NOT_GRANTED_EXIT} unless the cyber verified profile is recorded as granted")
    p.add_argument("--json", action="store_true", help="one JSON object")


def status(prof: _event.EventProfile, prices: dict | None = None, plan_usd: float | None = None) -> dict:
    fallback, pricing = _ledger_tools()
    prices = prices if prices is not None else pricing.load_prices()
    m = prof.models
    ratios = {fb: fallback.rate_ratios(prices, m.primary, fb) for fb in m.fallback}
    worst = fallback.worst_case_factor(prices, m.primary, m.fallback)
    out = {"event": prof.slug, "primary": m.primary, "fallback": list(m.fallback),
           "cyber_verified": m.cyber_verified, "fallback_expected": not m.verified,
           "rate_ratios": ratios, "worst_case_factor": worst}
    if plan_usd is not None:
        if plan_usd < 0:
            raise ValueError("--plan-usd must be >= 0")
        out["plan_usd"] = plan_usd
        out["plan_worst_case_usd"] = plan_usd * worst
        out["plan_reserve_usd"] = plan_usd * (worst - 1.0)
    out["human_step"] = None if m.verified else fallback.HUMAN_STEP.format(slug=prof.slug)
    return out


def _text(st: dict) -> str:
    lines = [f"event {st['event']}: primary {st['primary']}, classifier fallback {', '.join(st['fallback'])}",
             f"cyber verified profile (O-3): {st['cyber_verified']}"]
    if st["fallback_expected"]:
        lines.append("fallback EXPECTED: a safety classifier may move sessions onto the fallback; budget for it "
                     "and do not engineer around it")
    else:
        lines.append("fallback not expected (granted). If `python -m tools.ledger fallback` still sees one, "
                     "confirm the profile applies to this account")
    for fb, r in st["rate_ratios"].items():
        lines.append(f"  {fb} vs {st['primary']}: " + ", ".join(f"{k} x{v:.2f}" for k, v in r.items()))
    lines.append(f"  worst-case multiplier x{st['worst_case_factor']:.2f} (a cache-read-heavy agent approaches it)")
    if "plan_usd" in st:
        lines.append(f"  plan: ${st['plan_usd']:.2f} at primary rates may cost up to "
                     f"${st['plan_worst_case_usd']:.2f} on the fallback (reserve ${st['plan_reserve_usd']:.2f})")
    if st["human_step"]:
        lines.append(st["human_step"])
    lines.append(f"watch: python -m tools.ledger fallback --event {st['event']} --record LOG...")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
        st = status(prof, plan_usd=args.plan_usd)
    except (_event.EventError, AccessError, ValueError) as e:     # PricingError is a ValueError
        print(f"ctf access: {e}", file=sys.stderr)
        return 2
    print(json.dumps(st) if args.json else _text(st))
    if args.check and st["fallback_expected"]:
        print(f"ctf access: cyber verified profile is {st['cyber_verified']!r}, not 'granted': the classifier "
              f"fallback ({', '.join(st['fallback'])}) is expected", file=sys.stderr)
        return NOT_GRANTED_EXIT
    return 0
