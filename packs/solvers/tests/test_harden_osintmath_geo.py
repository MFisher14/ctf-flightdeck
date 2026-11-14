"""Independent geodesy/solar vectors and fail-closed coordinate fuzz.

No OCR, subprocess, image analysis, online client, or network path is invoked.
Distance bearings use an independent 3-D vector construction on the engine's
documented mean-radius sphere. Solar values come from NREL's published SPA
example for 2003-10-17 at the stated UTC instant and Boulder coordinate.
"""
from __future__ import annotations

import datetime as dt
import math
import random

import pytest

import osint_geo as geo
import osint_geo_math as geomath


def _vector_sphere_reference(lat1, lon1, lat2, lon2):
    """Great-circle oracle using Cartesian vectors, not the engine's haversine."""
    def position(lat, lon):
        phi, lam = map(math.radians, (lat, lon))
        return (math.cos(phi) * math.cos(lam),
                math.cos(phi) * math.sin(lam), math.sin(phi))

    def dot(one, two):
        return sum(a * b for a, b in zip(one, two))

    def bearing(origin, destination, lat, lon):
        projection = dot(origin, destination)
        tangent = tuple(b - projection * a for a, b in zip(origin, destination))
        phi, lam = map(math.radians, (lat, lon))
        north = (-math.sin(phi) * math.cos(lam),
                 -math.sin(phi) * math.sin(lam), math.cos(phi))
        east = (-math.sin(lam), math.cos(lam), 0.0)
        return math.degrees(math.atan2(dot(tangent, east), dot(tangent, north))) % 360.0

    one, two = position(lat1, lon1), position(lat2, lon2)
    cross = (one[1] * two[2] - one[2] * two[1],
             one[2] * two[0] - one[0] * two[2],
             one[0] * two[1] - one[1] * two[0])
    central = math.atan2(math.sqrt(dot(cross, cross)), dot(one, two))
    initial = bearing(one, two, lat1, lon1)
    final = (bearing(two, one, lat2, lon2) + 180.0) % 360.0
    return central * 6_371_008.8, initial, final


def test_london_new_york_great_circle_against_vector_oracle():
    london = (51.5074, -0.1278)
    new_york = (40.7128, -74.0060)
    expected = _vector_sphere_reference(*london, *new_york)
    assert expected[0] == pytest.approx(5_570_229.8737, abs=0.001)
    actual = geomath.distance_bearing(*london, *new_york)
    assert actual["distance_m"] == pytest.approx(expected[0], rel=1e-12)
    assert actual["initial_bearing_deg"] == pytest.approx(expected[1], abs=1e-10)
    assert actual["final_bearing_deg"] == pytest.approx(expected[2], abs=1e-10)


def test_julian_epoch_and_angular_residual_documented_semantics():
    assert geomath.julian_day("1970-01-01T00:00:00Z") == 2_440_587.5
    assert geomath.julian_day(dt.datetime(2000, 1, 1, 12, tzinfo=dt.timezone.utc)) == 2_451_545.0
    assert geomath.angular_residual(1, 359) == 2
    assert geomath.angular_residual(10, 190) == 180


def test_solar_position_against_nrel_spa_published_example():
    # NREL SPA example: 2003-10-17 12:30:30 at UTC-7,
    # 39.742476 N, 105.1786 W. The engine documents a lower-order NOAA/Meeus
    # approximation, so a 0.03-degree envelope is appropriate.
    result = geomath.solar_position("2003-10-17T12:30:30-07:00", 39.742476, -105.1786)
    assert result["timestamp_utc"] == "2003-10-17T19:30:30Z"
    assert result["azimuth_deg"] == pytest.approx(194.34024, abs=0.03)
    assert result["geometric_elevation_deg"] == pytest.approx(39.88838, abs=0.03)
    assert result["method"] == "NOAA/Meeus approximation"


def test_shadow_ranking_uses_published_solar_direction_and_supplied_places_only():
    observed_shadow = (194.34024 + 180.0) % 360.0
    rows = geomath.rank_shadow_candidates(
        "2003-10-17T12:30:30-07:00", observed_shadow,
        [("NREL example", 39.742476, -105.1786), ("distractor", 0.0, 0.0)],
        tolerance_deg=0.1,
    )
    assert [row.name for row in rows] == ["NREL example", "distractor"]
    assert rows[0].plausible is True
    # The observed direction is derived from the published NREL azimuth.  The
    # documented lower-order solar approximation must stay within the same
    # independent 0.03-degree envelope used by the vector lock above.
    assert rows[0].residual_deg <= 0.03
    assert all("do not submit" in row.note for row in rows)


def test_celestial_geometry_vectors_are_loci_not_longitudes():
    polaris = geomath.polaris_latitude(45.0, horizon_dip_deg=1.0, refraction_deg=0.5)
    assert polaris[0]["latitude_deg_approx"] == 43.5
    assert polaris[0]["longitude"] is None and polaris[0]["verified"] is False
    # sin(alt)=cos(lat) when declination=0 and hour angle=0: lat=+/-45.
    locus = geomath.altitude_latitude_locus(0, 0, 45)
    assert [item["latitude_deg"] for item in locus] == [-45.0, 45.0]
    assert all(item["longitude"] is None and item["verified"] is False for item in locus)


def test_dms_decimal_hand_vectors_and_axis_bounds():
    assert geo._dms_to_decimal(((44, 1), (25, 1), (36, 1)), "N", "lat") == 44.4266667
    assert geo._dms_to_decimal(((26, 1), (6, 1), (9, 1)), "E", "lon") == 26.1025
    assert geo._dms_to_decimal((40, 42, 46), "N", "lat") == 40.7127778
    assert geo._dms_to_decimal((74, 0, 21), "W", "lon") == -74.0058333
    assert geo._dms_to_decimal((90, 0, 0), "N", "lat") == 90.0
    assert geo._dms_to_decimal((90, 0, 0.1), "N", "lat") is None
    assert geo._dms_to_decimal((180, 0, 0), "E", "lon") == 180.0
    assert geo._dms_to_decimal((180, 0, 0.1), "E", "lon") is None


def test_coordinate_and_clue_extraction_known_values():
    text = ("Hotel Central Strada Victoriei +40 21 555 1234 Привет "
            "44.4268, 26.1025; 40°42'46.0\"N 74°00'21.0\"W CSCTF{geo}")
    assert geo.find_coords(text) == [
        "44.4268, 26.1025", "40°42'46.0\"N 74°00'21.0\"W"]
    clues = geo.extract_clues(text, [])
    assert clues["flags"] == ["CSCTF{geo}"]
    assert clues["phone_numbers"] == [
        {"number": "+40 21 555 1234", "country_hint": "Romania"}]
    assert {item["script"] for item in clues["scripts"]} == {"Cyrillic"}
    assert clues["candidate_names"][0] == "Hotel Central Strada Victoriei"


def test_search_plan_is_deterministic_offline_advice():
    exif = {"gps": {"lat": 44.4268, "lon": 26.1025}, "camera": {},
            "software": None, "timestamps": {}}
    clues = {"coords": [], "place_words": [], "candidate_names": [],
             "scripts": [], "phone_numbers": []}
    plan = geo.build_search_plan(exif, clues)
    assert plan[0].startswith("REVERSE-GEOCODE the EXIF GPS fix 44.4268, 26.1025")
    assert "nominatim.openstreetmap.org/reverse?format=jsonv2&lat=44.4268&lon=26.1025" in plan[0]
    assert any(step.startswith("REVERSE IMAGE SEARCH:") for step in plan)
    declined = geo.reverse_image_search("unused")
    assert declined["ok"] is False and declined["results"] == []


def test_malformed_coordinate_strings_and_dms_fail_closed():
    rng = random.Random(0x051A7)
    strings = ["", " ", "nan, inf", "91°60'60\"N 181°00'00\"E",
               "44 degrees north", "\ud800", "\xff" * 64]
    strings += ["".join(chr(rng.randrange(32, 127)) for _ in range(size))
                for size in range(1, 128, 7)]
    for text in strings:
        result = geo.find_coords(text)
        assert isinstance(result, list)
        assert all(isinstance(item, str) for item in result)

    malformed = [None, (), [], [1], [1, 2], [1, 2, 3, 4],
                 [None, None, None], [(1, 0), (2, 1), (3, 1)],
                 (-1, 0, 0), (0, -1, 0), (0, 0, -1),
                 (91, 0, 0), (181, 0, 0), (0, 60, 0), (0, 0, 60),
                 object(), {}, "not-dms", b"not-dms"]
    for value in malformed:
        result = geo._dms_to_decimal(value, "N", "lat")
        assert result is None or (math.isfinite(result) and -90 <= result <= 90)


def test_math_cli_malformed_values_return_cleanly(capsys):
    cases = [[], ["unknown"], ["distance", "x", "0", "0", "0"],
             ["distance", "nan", "0", "0", "0"],
             ["sun", "not-a-date", "0", "0"],
             ["sun", "9999-12-31T23:59:59-23:59", "0", "0"],
             ["polaris", "nan"], ["locus", "0", "0", "nan"]]
    for argv in cases:
        assert geomath.main(argv) == 2
    capsys.readouterr()


def test_bug_dms_nan_degree_declines():
    assert geo._dms_to_decimal((float("nan"), 0, 0), "N", "lat") is None


def test_dms_oversized_integer_is_contained_by_parser():
    assert geo._dms_to_decimal((10 ** 10_000, 0, 0), "N", "lat") is None


def test_bug_distance_malformed_type_fails_closed():
    assert geomath.distance_bearing(None, 0, 0, 0) is None


def test_bug_parse_utc_extreme_offset_fails_closed():
    assert geomath.parse_utc("9999-12-31T23:59:59-23:59") is None


class _CandidateOverread(AssertionError):
    pass


def test_bug_shadow_candidates_does_not_consume_past_bound():
    def candidates():
        for index in range(128):
            yield (f"candidate-{index}", 0.0, float(index % 180))
        raise _CandidateOverread("consumed candidate 129")

    rows = geomath.rank_shadow_candidates(
        "2024-03-20T12:00:00Z", 270.0, candidates())
    assert len(rows) == 128
