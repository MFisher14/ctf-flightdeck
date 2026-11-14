from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "toolkits"))
import osint_geo_math as G  # noqa: E402


def test_distance_and_cardinal_bearing():
    row = G.distance_bearing(0, 0, 0, 1)
    assert row["distance_m"] == pytest.approx(111_195, rel=0.002)
    assert row["initial_bearing_deg"] == pytest.approx(90, abs=1e-9)


def test_noaa_solar_equinox_equator_and_shadow_opposition():
    sun = G.solar_position("2024-03-20T12:00:00Z", 0, 0)
    assert sun["elevation_deg"] > 88
    observed = (sun["azimuth_deg"] + 180) % 360
    rows = G.rank_shadow_candidates("2024-03-20T12:00:00Z", observed,
                                    [("equator", 0, 0), ("far", 60, 120)], tolerance_deg=5)
    assert rows[0].name == "equator" and rows[0].plausible
    assert "do not submit" in rows[0].note


def test_polaris_and_general_celestial_locus_are_not_answer_verdicts():
    row = G.polaris_latitude(44.5)[0]
    assert row["latitude_deg_approx"] == 44.5 and row["longitude"] is None
    assert row["verified"] is False
    locus = G.altitude_latitude_locus(0, 0, 45)
    assert any(math.isclose(item["latitude_deg"], 45, abs_tol=1e-8) for item in locus)
    assert all(item["verified"] is False for item in locus)


def test_positive_horizon_dip_reduces_corrected_polaris_altitude():
    row = G.polaris_latitude(45.0, horizon_dip_deg=1.0, refraction_deg=0.5)[0]
    assert row["latitude_deg_approx"] == pytest.approx(43.5)


def test_cli_declines_bad_input(capsys):
    assert G.main(["sun", "not-a-date", "0", "0"]) == 2
    assert "osint_geo_math:" in capsys.readouterr().err


def test_geo_math_mutation_fuzz_5000_cases():
    rng = random.Random(0x501A4)
    for _ in range(5000):
        values = [rng.uniform(-1e5, 1e5) for _ in range(4)]
        try:
            result = G.distance_bearing(*values)
            assert math.isfinite(result["distance_m"])
        except (ValueError, OverflowError):
            pass
