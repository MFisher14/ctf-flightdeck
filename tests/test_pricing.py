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
    with pytest.raises(ValueError, match="cache_write"):
        Price(input=1.0, output=1.0, cache_write=-0.5)


def test_tokens_written_to_the_cache_cost_the_cache_write_rate_apart_from_reads_and_plain_input():
    # Claude Sonnet 5.5's rates: $2 input, $10 output, $0.10 cache reads, $2.50 5-minute cache writes
    price = Price(input=2.0, output=10.0, cached_input=0.10, cache_write=2.5)
    # 1M prompt tokens: 600k read from the cache, 300k written to it, 100k neither; 50k completion
    assert cost(price, 1_000_000, 50_000, 600_000, 300_000) == pytest.approx(0.1 * 2.0 + 0.6 * 0.10 + 0.3 * 2.5 + 0.05 * 10.0)
    assert call_cost(None, price, 1_000_000, 0, 0, 1_000_000) == pytest.approx(2.5)  # a call that only wrote
    assert call_cost(0.01, price, 1_000_000, 0, 0, 1_000_000) == 0.01  # the API's own figure still wins


def test_cache_writes_cost_the_input_rate_when_no_write_rate_is_known():
    assert cost(Price(input=3.0, output=0.0, cached_input=0.3), 1_000_000, 0, 0, 400_000) == pytest.approx(3.0)


def test_more_written_than_the_prompt_holds_beside_its_reads_is_cut_to_it():
    price = Price(input=1.0, output=0.0, cached_input=0.0, cache_write=10.0)
    assert cost(price, 1000, 0, 600, 5000) == pytest.approx(400 * 10.0 / 1e6)  # reads first, writes the rest
    assert cost(price, 1000, 0, 0, -5) == pytest.approx(0.001)


def test_a_prices_rates_are_its_config_keys_in_order_and_a_rate_left_out_is_left_out():
    assert Price(4.0, 20.0, 0.2, 5.0).rates() == (("input", 4.0), ("output", 20.0), ("cached_input", 0.2), ("cache_write", 5.0))
    assert Price(1.0, 2.0, cache_write=1.25).rates() == (("input", 1.0), ("output", 2.0), ("cache_write", 1.25))
