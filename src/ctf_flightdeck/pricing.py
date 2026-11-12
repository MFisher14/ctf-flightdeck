"""Model prices and what a model call cost.

The API's own figure wins when it reports one (OpenRouter returns usage.cost); a price
from the player's config is the fallback; with neither, the cost is unknown (None), and
the console shows "-" rather than a guess (D10).

A prompt token is priced by what the API's prompt cache did with it: read from the cache
(cached_input), written to it (cache_write), or neither (input). The Anthropic API charges
for a write: 1.25 times the input price for the 5-minute cache, the one flightdeck's
requests use (agent/anthropic_client.py); the 1-hour cache, at 2 times, is never asked for,
so no rate here is for it. The OpenAI-compatible client (agent/client.py) reads no writes:
OpenRouter reports what a call cost itself.
"""

from __future__ import annotations

from dataclasses import dataclass

RATES = ("input", "output", "cached_input", "cache_write")
"""A Price's rates, as a [prices] table in the config names them."""


@dataclass(frozen=True)
class Price:
    """Dollars per million tokens. A cache rate left out (None) is the input rate."""

    input: float  # prompt tokens neither read from the cache nor written to it
    output: float  # completion tokens
    cached_input: float | None = None  # prompt tokens read from the cache; None: the input rate
    cache_write: float | None = None  # prompt tokens written to the (5-minute) cache; None: the input rate

    def __post_init__(self) -> None:
        for name in RATES:
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"price {name} must not be negative, got {value}")

    def rates(self) -> tuple[tuple[str, float], ...]:
        """(name, dollars per million tokens) for each rate the price has, in RATES order: the
        lines of its [prices] table, a cache rate left out left out."""
        return tuple((name, value) for name in RATES if (value := getattr(self, name)) is not None)


def cost(price: Price, prompt_tokens: int, completion_tokens: int, cached_tokens: int = 0,
         cache_write_tokens: int = 0) -> float:
    """Dollars for one call. The tokens read from the cache (cached_tokens) and those written
    to it (cache_write_tokens) are part of the prompt tokens; a count past what the prompt
    can hold is cut to it (reads first)."""
    cached = max(0, min(cached_tokens, prompt_tokens))
    written = max(0, min(cache_write_tokens, prompt_tokens - cached))
    cached_rate = price.input if price.cached_input is None else price.cached_input
    write_rate = price.input if price.cache_write is None else price.cache_write
    total = ((prompt_tokens - cached - written) * price.input + cached * cached_rate + written * write_rate
             + completion_tokens * price.output)
    return total / 1_000_000


def call_cost(reported: float | None, price: Price | None, prompt_tokens: int, completion_tokens: int,
              cached_tokens: int = 0, cache_write_tokens: int = 0) -> float | None:
    """The API's reported cost if any, else the config price's, else None (unknown)."""
    if reported is not None:
        return reported
    if price is not None:
        return cost(price, prompt_tokens, completion_tokens, cached_tokens, cache_write_tokens)
    return None
