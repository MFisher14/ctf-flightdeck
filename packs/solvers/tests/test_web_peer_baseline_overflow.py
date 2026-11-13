#!/usr/bin/env python3
"""Baseline list caps must fail closed instead of hiding a late decoy."""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "solvers" / "web"), str(ROOT / "solvers" / "toolkits")]
sys.dont_write_bytecode = True

import double_spend  # noqa: E402
import forge_event  # noqa: E402
import hpp_read  # noqa: E402
import realtime_read  # noqa: E402
import reset_rebind  # noqa: E402
import ssrf_body  # noqa: E402
import xxe_read  # noqa: E402


BASE = "https://target.test/"
PROOF = "proof_0123456789ab4def8abc0123456789ab"


class _Client:
    base = BASE
    timeout = 1


CASES = (
    ("forge", forge_event._Forge, 40, "baseline_texts"),
    ("realtime", realtime_read._Reader, 40, "baselines"),
    ("reset", reset_rebind._ResetRebind, 40, "baselines"),
    ("hpp", hpp_read._Runner, 60, "baselines"),
    ("double-spend", double_spend._DoubleSpend, 80, "baselines"),
    ("xxe", xxe_read._Runner, 60, "baselines"),
    ("post-body-ssrf", ssrf_body._Runner, 60, "baselines"),
)


def _build(factory, values):
    return factory(
        {"url": BASE, "answer_id": "answer"},
        {"client": _Client(), "baseline_texts": values, "max_requests": 0},
    )


def _payoff():
    return {
        "status": 200,
        "body": json.dumps({"ok": True, "proof": PROOF}, separators=(",", ":")).encode(),
        "response_headers": {"Content-Type": "application/json"},
    }


class PeerBaselineOverflowTests(unittest.TestCase):
    def test_exact_cap_remains_complete(self):
        for label, factory, cap, attribute in CASES:
            with self.subTest(peer=label):
                values = [f"ordinary-{index}" for index in range(cap)]
                baselines = getattr(_build(factory, values), attribute)
                self.assertFalse(forge_event.baseline_set_incomplete(baselines))
                self.assertEqual(forge_event.extract_success(_payoff(), baselines)["auto"], PROOF)

    def test_overflow_marks_baseline_incomplete_and_suppresses_auto(self):
        for label, factory, cap, attribute in CASES:
            with self.subTest(peer=label):
                values = [f"ordinary-{index}" for index in range(cap)] + [PROOF]
                baselines = getattr(_build(factory, values), attribute)
                self.assertIn(forge_event.BASELINE_STRICT_INCOMPLETE, baselines)
                self.assertTrue(forge_event.baseline_set_incomplete(baselines))
                self.assertIsNone(forge_event.extract_success(_payoff(), baselines)["auto"])


if __name__ == "__main__":
    unittest.main()
