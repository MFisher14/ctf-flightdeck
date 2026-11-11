"""What a model call cost: the API's figure, else the config price, else unknown."""

from __future__ import annotations

import pytest

from ctf_flightdeck.pricing import Price, call_cost, cost


def test_cost_charges_uncached_input_cached_input_and_output_at_their_rates():
    price = Price(input=2.0, output=8.0, cached_input=0.5)
    # 1M prompt tokens of which 600k cached, 100k completion
    assert cost(price, 1_000_000, 100_000, 600_000) == pytest.approx(0.4 * 2.0 + 0.6 * 0.5 + 0.1 * 8.0)


def test_cached_tokens_cost_the_input_rate_when_no_cached_rate_is_known():
    assert cost(Price(input=3.0, output=0.0), 500_000, 0, 500_000) == pytest.approx(1.5)


def test_more_cached_than_prompt_tokens_is_clamped_to_the_prompt():
    price = Price(input=1.0, output=0.0, cached_input=0.0)
    assert cost(price, 1000, 0, 5000) == 0.0
    assert cost(price, 1000, 0, -5) == pytest.approx(0.001)


def test_the_reported_cost_wins_then_the_price_then_unknown():
    price = Price(input=1.0, output=1.0)
    assert call_cost(0.0123, price, 1_000_000, 0) == 0.0123
    assert call_cost(None, price, 1_000_000, 0) == pytest.approx(1.0)
    assert call_cost(None, None, 1_000_000, 0) is None


def test_a_negative_price_is_refused():
    with pytest.raises(ValueError, match="output"):
        Price(input=1.0, output=-1.0)
