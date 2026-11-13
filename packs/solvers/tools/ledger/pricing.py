"""Price model usage in USD. Ported from analysis/price_ledger.py (the token-ledger study), same rates
and same formulas, so a live meter and the after-event ledger agree to the cent.

    prices = load_prices()                   # tools/ledger/pricing.json (USD per million tokens)
    usd = cost(row, prices)                  # row: {"harness", "model", "speed", <token counts>}
    n = tokens(row)

Claude rows:  input, cache_read, cache_5m, cache_1h, output (+ web_search requests); speed "fast"
              multiplies by the model's fast_multiplier (2.0 when the table names none, as the study did).
Codex rows:   input (includes cached), cached, output; speed is the service tier, multiplied by the
              model's tier_multiplier.

Differences from the study script, both loud instead of silent: an unknown model raises PricingError
(the study exited), and an unknown Codex tier raises PricingError (the study priced it at 1x).
"""
from __future__ import annotations

import json
from pathlib import Path

MT = 1_000_000
PRICING_PATH = Path(__file__).with_name("pricing.json")
HARNESSES = ("claude", "codex")


class PricingError(ValueError):
    pass


def load_prices(path: str | Path | None = None) -> dict:
    p = Path(path) if path is not None else PRICING_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PricingError(f"pricing table not found: {p}") from None
    for key in ("claude", "codex", "web_search_per_request"):
        if key not in data:
            raise PricingError(f"{p}: pricing table lacks {key!r}")
    return data


def cost(row: dict, prices: dict, overrides: dict | None = None) -> float:
    harness, model = row.get("harness"), row.get("model")
    speed = row.get("speed") or ("standard" if harness == "claude" else "default")
    if harness == "claude":
        p = prices["claude"].get(model)
        if p is None:
            raise PricingError(f"no price for claude model {model!r} (add it to tools/ledger/pricing.json)")
        mult = p.get("fast_multiplier", 2.0) if speed == "fast" else 1.0
        return mult * (row.get("input", 0) * p["input"] + row.get("cache_read", 0) * p["cache_read"]
                       + row.get("cache_5m", 0) * p["cache_5m"] + row.get("cache_1h", 0) * p["cache_1h"]
                       + row.get("output", 0) * p["output"]) / MT \
            + row.get("web_search", 0) * prices["web_search_per_request"]
    if harness == "codex":
        base = prices["codex"].get(model)
        if base is None:
            raise PricingError(f"no price for codex model {model!r} (add it to tools/ledger/pricing.json)")
        p = dict(base)
        if overrides and model in overrides:
            p.update(overrides[model])
        tiers = p.get("tier_multiplier", {"default": 1})
        if speed not in tiers:
            raise PricingError(f"no tier multiplier for codex model {model!r} tier {speed!r}")
        noncached = row.get("input", 0) - row.get("cached", 0)
        return tiers[speed] * (noncached * p["input"] + row.get("cached", 0) * p["cached"]
                               + row.get("output", 0) * p["output"]) / MT
    raise PricingError(f"unknown harness {harness!r} (one of {', '.join(HARNESSES)})")


def tokens(row: dict) -> int:
    if row.get("harness") == "claude":
        return (row.get("input", 0) + row.get("cache_read", 0) + row.get("cache_5m", 0)
                + row.get("cache_1h", 0) + row.get("output", 0))
    return row.get("input", 0) + row.get("output", 0)
