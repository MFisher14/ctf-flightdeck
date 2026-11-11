"""Model prices and what a model call cost.

The API's own figure wins when it reports one (OpenRouter returns usage.cost); a price
from the player's config is the fallback; with neither, the cost is unknown (None), and
the console shows "-" rather than a guess (D10).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    """Dollars per million tokens."""

    input: float  # prompt tokens not served from the cache
    output: float  # completion tokens
    cached_input: float | None = None  # prompt tokens served from the cache; None: same as input

    def __post_init__(self) -> None:
        for name in ("input", "output", "cached_input"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"price {name} must not be negative, got {value}")


def cost(price: Price, prompt_tokens: int, completion_tokens: int, cached_tokens: int = 0) -> float:
    """Dollars for one call. Cached tokens are part of the prompt tokens."""
    cached = max(0, min(cached_tokens, prompt_tokens))
    cached_rate = price.input if price.cached_input is None else price.cached_input
    total = (prompt_tokens - cached) * price.input + cached * cached_rate + completion_tokens * price.output
    return total / 1_000_000


def call_cost(reported: float | None, price: Price | None, prompt_tokens: int, completion_tokens: int, cached_tokens: int = 0) -> float | None:
    """The API's reported cost if any, else the config price's, else None (unknown)."""
    if reported is not None:
        return reported
    if price is not None:
        return cost(price, prompt_tokens, completion_tokens, cached_tokens)
    return None
