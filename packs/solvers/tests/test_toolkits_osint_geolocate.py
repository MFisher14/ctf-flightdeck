"""B-113: frozen-dataset geolocation resolvers (solvers/toolkits/osint_geolocate.py), library level.

Every fixture is built synthetically inside the test: a tiny brand directory, tiny OSM extracts in
each accepted row format, dated snapshot extracts, a synthetic DEM with a known geometry (so the
horizon math is checked against an analytic value) and a hand-packed SRTM tile. The online Overpass
path is exercised through the scope guard with an injected transport, and the default transport only
against a fake this file starts on 127.0.0.1 -- no test contacts a live service. The one test that
reads the real external dataset reports as not run (never green) when CTF_GEO_DATASET is unset.

The CLI, the opener and the dataset builders are in test_toolkits_osint_geolocate_cli.py; the
map-pin checker client is in test_toolkits_osint_geo_checker.py.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import event, paths, platform, scope
from ctf.platform.base import SubmitResult, SubmitStatus

TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))

import osint_geolocate as GEO  # noqa: E402

M_PER_DEG = GEO.METRES_PER_DEGREE


# --------------------------------------------------------------------------- helpers / fixtures

def _write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_jsonl(path: Path, rows) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def _profile(public=(), slug="geo-test", submit_mode="manual"):
    rules = {"submit_mode": submit_mode, "flag_sharing": "forbidden", "ai_on_platform": "allowed",
             "live_service_scope": ["*.ctf.example"], "public_fetch_allow": list(public)}
    return event.parse({
        "slug": slug, "name": "geo test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": ["geo"]}, "rules": rules,
    }, src="<test>")


def _offset(lat, lon, north_m=0.0, east_m=0.0):
    return lat + north_m / M_PER_DEG, lon + east_m / (M_PER_DEG * math.cos(math.radians(lat)))


def _square(lat, lon, side_m):
    """Closed (lat, lon) ring of a square of the given side centred on (lat, lon)."""
    half = side_m / 2.0
    corners = [_offset(lat, lon, -half, -half), _offset(lat, lon, -half, half),
               _offset(lat, lon, half, half), _offset(lat, lon, half, -half)]
    return corners + [corners[0]]


def _way(wid, ring, tags):
    """An Overpass `out geom` way: no lat/lon of its own, the outline in `geometry`."""
    return {"type": "way", "id": wid, "tags": tags, "geometry": [{"lat": a, "lon": b} for a, b in ring]}


def _node(nid, lat, lon, tags):
    return {"type": "node", "id": nid, "lat": lat, "lon": lon, "tags": tags}


def _brand_dataset(tmp_path: Path) -> Path:
    root = tmp_path / "geo"
    root.mkdir()
    _write_json(root / "brands.json", {
        "Luna Coffee": [
            # Alphabetical order (Old Town, Riverside) is the reverse of the distance order the
            # `near` test asks for, so a sort that drops the distance cannot pass it.
            {"name": "Luna Coffee Riverside", "lat": 44.4268, "lon": 26.1025, "country": "RO"},
            {"name": "Luna Coffee Old Town", "lat": 44.4300, "lon": 26.0960, "country": "RO"},
        ],
        "Other Cafe": [{"name": "Other Cafe", "lat": 48.8566, "lon": 2.3522}],
    })
    return root


# --------------------------------------------------------------------------- brand -> maps

def test_brand_exact_match_returns_all_branches(tmp_path):
    root = _brand_dataset(tmp_path)
    report = GEO.resolve_brand("luna coffee", dataset_root=root)
    assert report["match_kind"] == "exact"
    assert report["candidate_count"] == 2
    names = {c["name"] for c in report["candidates"]}
    assert names == {"Luna Coffee Riverside", "Luna Coffee Old Town"}
    # A resolver never names the answer on its own.
    assert report["automatic_answer"] is None and report["requires_human_pin"] is True


def test_brand_near_orders_by_distance_not_by_name(tmp_path):
    root = _brand_dataset(tmp_path)
    # Standing at the Riverside branch: it sorts first although "Old Town" precedes it by name.
    report = GEO.resolve_brand("Luna Coffee", dataset_root=root, near=(44.4268, 26.1025))
    assert [c["name"] for c in report["candidates"]] == ["Luna Coffee Riverside", "Luna Coffee Old Town"]
    assert report["candidates"][0]["distance_m"] < 1.0 < report["candidates"][1]["distance_m"]
    # Without a near point there is no distance and the order is by name.
    plain = GEO.resolve_brand("Luna Coffee", dataset_root=root)
    assert [c["name"] for c in plain["candidates"]] == ["Luna Coffee Old Town", "Luna Coffee Riverside"]
    assert plain["candidates"][0]["distance_m"] is None


def test_brand_partial_both_ways_and_miss(tmp_path):
    root = _brand_dataset(tmp_path)
    shorter = GEO.resolve_brand("luna", dataset_root=root)                  # query inside the brand
    assert shorter["match_kind"] == "partial" and shorter["candidate_count"] == 2
    longer = GEO.resolve_brand("Luna Coffee Bucharest", dataset_root=root)  # brand inside the query
    assert longer["match_kind"] == "partial"
    assert {c["brand"] for c in longer["candidates"]} == {"Luna Coffee"}
    miss = GEO.resolve_brand("nonexistent brand", dataset_root=root)
    assert miss["match_kind"] == "none" and miss["candidates"] == []


def test_absent_dataset_fails_loudly_with_named_variable(tmp_path, monkeypatch):
    # No brands.json under an existing dir -> named file error.
    empty = tmp_path / "geo"
    empty.mkdir()
    with pytest.raises(GEO.GeoLocateError, match="brand directory not found"):
        GEO.resolve_brand("x", dataset_root=empty)
    # No configured dataset at all -> the loud named-variable error from ctf.paths. A real-data
    # corpus with a geo/ folder is NOT picked up: the variable is the only source.
    monkeypatch.delenv("CTF_GEO_DATASET", raising=False)
    (tmp_path / "realdata" / "geo").mkdir(parents=True)
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "realdata"))
    with pytest.raises(GEO.GeoLocateError, match="CTF_GEO_DATASET"):
        GEO.resolve_brand("x")


# --------------------------------------------------------------------------- ctf.paths.geo_dataset_root

def test_geo_dataset_root_reads_the_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_GEO_DATASET", raising=False)
    assert paths.geo_dataset_root() is None
    with pytest.raises(FileNotFoundError, match="CTF_GEO_DATASET"):
        paths.require_geo_dataset()
    root = _brand_dataset(tmp_path)
    monkeypatch.setenv("CTF_GEO_DATASET", str(root))
    assert paths.geo_dataset_root() == root.resolve()
    assert paths.require_geo_dataset() == root.resolve()
    # ...and the resolvers use it when no dataset_root is passed.
    assert GEO.resolve_brand("luna coffee")["candidate_count"] == 2


def test_geo_dataset_root_set_to_a_missing_folder_or_a_file_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GEO_DATASET", str(tmp_path / "typo"))
    with pytest.raises(FileNotFoundError, match="CTF_GEO_DATASET"):
        paths.geo_dataset_root()
    with pytest.raises(GEO.GeoLocateError, match="CTF_GEO_DATASET"):
        GEO.resolve_brand("x")
    a_file = tmp_path / "brands.json"
    a_file.write_text("{}")
    monkeypatch.setenv("CTF_GEO_DATASET", str(a_file))
    with pytest.raises(FileNotFoundError, match="CTF_GEO_DATASET"):
        paths.geo_dataset_root()


# --------------------------------------------------------------------------- OSM constraint solver

def _osm_extract(tmp_path: Path) -> Path:
    rows = [
        {"id": 1, "lat": 44.4268, "lon": 26.1025, "name": "Luna Coffee", "tags": {"amenity": "cafe", "name": "Luna Coffee"}},
        {"id": 2, "lat": 44.4270, "lon": 26.1028, "name": "Bar None", "tags": {"amenity": "bar"}},
        {"id": 3, "lat": 48.8566, "lon": 2.3522, "name": "Far Cafe", "tags": {"amenity": "cafe"}},
    ]
    return _write_jsonl(tmp_path / "osm.jsonl", rows)


def test_osm_offline_tag_and_radius_filter(tmp_path):
    extract = _osm_extract(tmp_path)
    constraints = {"tags": {"amenity": "cafe"}, "near": [44.4268, 26.1025], "radius_m": 500}
    report = GEO.solve_osm_constraints(constraints, extract_path=extract)
    ids = [c["id"] for c in report["candidates"]]
    # The bar (wrong tag) and the far cafe (outside radius) are excluded; only the near cafe remains.
    assert ids == ["1"]
    assert report["candidates"][0]["matched_tags"] == {"amenity": "cafe"}
    assert report["candidates"][0]["distance_m"] < 1.0
    assert report["extract"] == {"rows_read": 3, "features": 3, "skipped": {}}


def test_osm_offline_name_contains_and_bbox(tmp_path):
    extract = _osm_extract(tmp_path)
    got = GEO.solve_osm_constraints({"name_contains": ["luna"]}, extract_path=extract)
    assert [c["id"] for c in got["candidates"]] == ["1"]
    box = GEO.solve_osm_constraints(
        {"tags": {"amenity": "cafe"}, "bbox": [44.0, 26.0, 45.0, 27.0]}, extract_path=extract)
    assert [c["id"] for c in box["candidates"]] == ["1"]  # the Paris cafe is outside the box


def test_osm_bbox_checks_all_four_sides(tmp_path):
    rows = [{"id": 1, "lat": 44.5, "lon": 26.5, "tags": {"amenity": "cafe"}},
            {"id": 2, "lat": 44.5, "lon": 30.0, "tags": {"amenity": "cafe"}},    # right latitude, east of the box
            {"id": 3, "lat": 44.5, "lon": 20.0, "tags": {"amenity": "cafe"}},    # right latitude, west of the box
            {"id": 4, "lat": 50.0, "lon": 26.5, "tags": {"amenity": "cafe"}},    # right longitude, north of the box
            {"id": 5, "lat": 40.0, "lon": 26.5, "tags": {"amenity": "cafe"}}]    # right longitude, south of the box
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)
    box = GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "bbox": [44.0, 26.0, 45.0, 27.0]},
                                    extract_path=extract)
    assert [c["id"] for c in box["candidates"]] == ["1"]


def test_osm_tag_wildcard_value_list_and_multivalue(tmp_path):
    extract = _osm_extract(tmp_path)
    anything = GEO.solve_osm_constraints({"tags": {"amenity": "*"}, "bbox": [44.0, 26.0, 45.0, 27.0]},
                                         extract_path=extract)
    assert [c["id"] for c in anything["candidates"]] == ["2", "1"]          # "*" = any value; ranked by name
    either = GEO.solve_osm_constraints({"tags": {"amenity": ["bar", "pub"]}}, extract_path=extract)
    assert [c["id"] for c in either["candidates"]] == ["2"]
    rows = [{"id": 9, "lat": 1.0, "lon": 1.0, "tags": {"cuisine": "Pizza;coffee_shop"}}]
    multi = _write_jsonl(tmp_path / "multi.jsonl", rows)
    assert GEO.solve_osm_constraints({"tags": {"cuisine": "coffee_shop"}}, extract_path=multi)["candidate_count"] == 1
    assert GEO.solve_osm_constraints({"tags": {"cuisine": "PIZZA"}}, extract_path=multi)["candidate_count"] == 1
    assert GEO.solve_osm_constraints({"tags": {"cuisine": "sushi"}}, extract_path=multi)["candidates"] == []


def test_osm_constraint_guards(tmp_path):
    extract = _osm_extract(tmp_path)
    with pytest.raises(GEO.GeoLocateError, match="at least one constraint"):
        GEO.solve_osm_constraints({}, extract_path=extract)
    with pytest.raises(GEO.GeoLocateError, match="near point needs a radius_m"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "near": [44.4, 26.1]}, extract_path=extract)
    with pytest.raises(GEO.GeoLocateError, match="radius_m needs a near point"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "radius_m": 50}, extract_path=extract)
    # A misspelt key is refused, never ignored (it would silently widen the search).
    with pytest.raises(GEO.GeoLocateError, match="unknown constraint key.*perimetre_m"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "perimetre_m": [1, 2]}, extract_path=extract)
    with pytest.raises(GEO.GeoLocateError, match="unknown key.*maxm"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"},
                                   "joins": [{"tags": {"amenity": "bar"}, "maxm": 5}]}, extract_path=extract)
    with pytest.raises(GEO.GeoLocateError, match="needs max_m"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "joins": [{"tags": {"amenity": "bar"}}]},
                                  extract_path=extract)
    with pytest.raises(GEO.GeoLocateError, match="attic date"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "date": "2019-06-01"}, extract_path=extract)


# ---- row formats, and what is skipped is counted

def test_extract_accepts_flat_overpass_center_and_geojson_rows(tmp_path):
    rows = [
        {"id": 1, "lat": 44.4268, "lon": 26.1025, "name": "Flat Cafe", "tags": {"amenity": "cafe"}},
        # an Overpass way from `out center`: its coordinate is under "center"
        {"type": "way", "id": 22, "center": {"lat": 44.4300, "lon": 26.0960}, "tags": {"amenity": "cafe", "name": "Way Cafe"}},
        # a GeoJSON feature as `osmium export` writes it: [lon, lat], tags in properties
        {"type": "Feature", "id": "n33", "geometry": {"type": "Point", "coordinates": [26.11, 44.44]},
         "properties": {"amenity": "cafe", "name": "Geo Cafe"}},
    ]
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)
    report = GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=extract)
    by_name = {c["name"]: c for c in report["candidates"]}
    assert set(by_name) == {"Flat Cafe", "Way Cafe", "Geo Cafe"}
    assert (by_name["Way Cafe"]["lat"], by_name["Way Cafe"]["lon"]) == (44.4300, 26.0960)
    assert by_name["Way Cafe"]["id"] == "way/22" and by_name["Way Cafe"]["center_source"] == "center"
    assert (by_name["Geo Cafe"]["lat"], by_name["Geo Cafe"]["lon"]) == (44.44, 26.11)
    assert by_name["Geo Cafe"]["id"] == "n33"
    assert report["extract"] == {"rows_read": 3, "features": 3, "skipped": {}}


def test_extract_reads_geojson_collection_and_polygon_centroid(tmp_path):
    ring = _square(47.0, 12.0, 100.0)
    collection = {"type": "FeatureCollection", "features": [
        {"type": "Feature", "properties": {"@type": "way", "@id": 77, "leisure": "swimming_pool", "name": "Pool"},
         "geometry": {"type": "Polygon", "coordinates": [[[lon, lat] for lat, lon in ring]]}},
    ]}
    extract = _write_json(tmp_path / "area.geojson", collection)
    report = GEO.solve_osm_constraints({"tags": {"leisure": "swimming_pool"}}, extract_path=extract)
    (pool,) = report["candidates"]
    assert pool["id"] == "way/77" and pool["center_source"] == "polygon_centroid"
    assert pool["lat"] == pytest.approx(47.0, abs=1e-7) and pool["lon"] == pytest.approx(12.0, abs=1e-7)
    assert pool["perimeter_m"] == pytest.approx(400.0, rel=1e-3)
    assert pool["area_m2"] == pytest.approx(10_000.0, rel=1e-3)


def _lonlat(ring):
    return [[lon, lat] for lat, lon in ring]


def test_extract_measures_the_area_shapes_of_an_rs_prefixed_geojsonseq(tmp_path):
    """`osmium export -f geojsonseq`: one feature per line behind an RS (0x1e) byte; an area is a
    Polygon or a MultiPolygon, and a closed way that is not an area is a closed LineString. Each is
    an outline the perimeter constraint can measure."""
    building = {"building": "yes"}
    features = [
        # two parts: the larger outer ring is the outline (its hole and the 20 m part are not)
        {"type": "Feature", "id": "a11", "properties": dict(building, name="Multi"),
         "geometry": {"type": "MultiPolygon", "coordinates": [
             [_lonlat(_square(27.01, 32.0, 20.0))],
             [_lonlat(_square(27.0, 32.0, 70.0)), _lonlat(_square(27.0, 32.0, 10.0))]]}},
        {"type": "Feature", "id": "w12", "properties": dict(building, name="Closed line"),
         "geometry": {"type": "LineString", "coordinates": _lonlat(_square(27.1, 32.0, 70.0))}},
        # the same way left open is a line: no outline to measure
        {"type": "Feature", "id": "w13", "properties": dict(building, name="Open line"),
         "geometry": {"type": "LineString", "coordinates": _lonlat(_square(27.2, 32.0, 70.0))[:-1]}},
        {"type": "Feature", "id": "w14", "properties": dict(building, name="Too large"),
         "geometry": {"type": "Polygon", "coordinates": [_lonlat(_square(27.3, 32.0, 150.0))]}},
    ]
    extract = tmp_path / "region.geojsonseq"
    extract.write_text("".join("\x1e" + json.dumps(f) + "\n" for f in features), encoding="utf-8")
    report = GEO.solve_osm_constraints({"tags": building, "perimeter_m": [245, 335]}, extract_path=extract)
    by_name = {c["name"]: c for c in report["candidates"]}
    assert sorted(by_name) == ["Closed line", "Multi"]
    multi = by_name["Multi"]
    assert multi["id"] == "a11" and multi["center_source"] == "polygon_centroid"
    assert multi["perimeter_m"] == pytest.approx(280.0, rel=1e-3) and multi["area_m2"] == pytest.approx(4900.0, rel=1e-3)
    assert multi["lat"] == pytest.approx(27.0, abs=1e-6) and multi["lon"] == pytest.approx(32.0, abs=1e-6)
    line = by_name["Closed line"]
    assert line["perimeter_m"] == pytest.approx(280.0, rel=1e-3) and line["center_source"] == "polygon_centroid"
    assert line["lat"] == pytest.approx(27.1, abs=1e-6)
    assert report["extract"] == {"rows_read": 4, "features": 4, "skipped": {}}
    assert report["geometry_unavailable"] == 1                     # the open line
    # the open line is still a located feature (the mean of its vertices) for a search without geometry
    plain = GEO.solve_osm_constraints({"name_contains": ["open line"]}, extract_path=extract)
    assert plain["candidates"][0]["center_source"] == "vertex_mean"


def test_skipped_rows_are_counted_and_a_bad_name_does_not_abort_the_solve(tmp_path):
    rows = [
        {"id": 1, "lat": 44.0, "lon": 26.0, "name": "Good Cafe", "tags": {"amenity": "cafe"}},
        {"id": 2, "lat": 44.0, "lon": 26.0, "name": "Bad\x07Cafe", "tags": {"amenity": "cafe"}},
        {"id": 3, "lat": 44.0, "lon": 26.0, "name": "x" * 600, "tags": {"amenity": "cafe"}},
        {"id": 4, "tags": {"amenity": "cafe"}},                               # nowhere
        {"id": 5, "lat": 444.0, "lon": 26.0, "tags": {"amenity": "cafe"}},    # off the planet
        "just a string",
    ]
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)
    report = GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=extract)
    assert [c["name"] for c in report["candidates"]] == ["Good Cafe"]
    assert report["extract"]["rows_read"] == 6 and report["extract"]["features"] == 1
    assert report["extract"]["skipped"] == {
        "bad name (control characters or overlong)": 2,
        "no usable coordinates (no lat/lon, center, geometry or bounds)": 2,
        "not a JSON object": 1,
    }


def test_a_wrong_format_extract_is_an_error_not_an_empty_result(tmp_path):
    wrong = _write_jsonl(tmp_path / "osm.jsonl", [{"osm_id": 1, "amenity": "cafe"}, {"osm_id": 2, "amenity": "cafe"}])
    with pytest.raises(GEO.GeoLocateError, match=r"none of its 2 row\(s\) is a located OSM feature"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=wrong)
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n")
    with pytest.raises(GEO.GeoLocateError, match="is empty"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=empty)
    with pytest.raises(GEO.GeoLocateError, match="OSM extract not found"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=tmp_path / "absent.jsonl")
    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"id": 1, "lat": 1, "lon": 1}\n{not json\n')
    with pytest.raises(GEO.GeoLocateError, match="line 2 is not JSON"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, extract_path=broken)


# ---- polygon geometry and distance joins (the story-constraint shape: a building of a given
#      outline, within X of one feature class and between Y and Z of another)

HOSPITAL = {"amenity": "hospital"}
UNI = {"amenity": "university"}
CHURCH = {"amenity": "place_of_worship", "denomination": "catholic"}


def _story_extract(tmp_path: Path) -> Path:
    rows = []
    # A: 70 m square (perimeter 280), university 3 km north, church 700 m east -> satisfies everything
    a = (27.80, 32.10)
    rows += [_way(101, _square(*a, 70.0), dict(HOSPITAL, name="Klinik A")),
             _node(201, *_offset(*a, north_m=3000), dict(UNI, name="Uni A")),
             _node(301, *_offset(*a, east_m=700), dict(CHURCH, name="Church A")),
             _node(302, *_offset(*a, east_m=950), dict(CHURCH, name="Church A far"))]
    # B: same building, but its only church is 100 m away (closer than the 400 m minimum)
    b = (27.90, 32.50)
    rows += [_way(102, _square(*b, 70.0), dict(HOSPITAL, name="Klinik B")),
             _node(202, *_offset(*b, north_m=3000), UNI),
             _node(303, *_offset(*b, east_m=100), CHURCH)]
    # C: neighbours fine, but a 150 m square (perimeter 600)
    c = (28.00, 32.90)
    rows += [_way(103, _square(*c, 150.0), dict(HOSPITAL, name="Klinik C")),
             _node(203, *_offset(*c, north_m=3000), UNI),
             _node(304, *_offset(*c, east_m=700), CHURCH)]
    # D: church fine, nearest university 20 km away
    d = (28.10, 33.30)
    rows += [_way(104, _square(*d, 70.0), dict(HOSPITAL, name="Klinik D")),
             _node(204, *_offset(*d, north_m=20_000), UNI),
             _node(305, *_offset(*d, east_m=700), CHURCH)]
    # E: neighbours fine, but mapped as a node: no outline to measure
    e = (28.20, 33.70)
    rows += [_node(105, *e, dict(HOSPITAL, name="Klinik E")),
             _node(205, *_offset(*e, north_m=3000), UNI),
             _node(306, *_offset(*e, east_m=700), CHURCH)]
    return _write_jsonl(tmp_path / "osm.jsonl", rows)


STORY = {
    "tags": HOSPITAL,
    "perimeter_m": [245, 335],
    "joins": [{"label": "university", "tags": UNI, "max_m": 6000},
              {"label": "church", "tags": CHURCH, "min_m": 400, "max_m": 1000}],
}


def test_story_constraints_perimeter_and_joins_leave_one_candidate(tmp_path):
    report = GEO.solve_osm_constraints(STORY, extract_path=_story_extract(tmp_path))
    (only,) = report["candidates"]
    assert only["id"] == "way/101" and only["name"] == "Klinik A"
    assert only["perimeter_m"] == pytest.approx(280.0, rel=1e-3)
    assert only["area_m2"] == pytest.approx(4900.0, rel=1e-3)
    joins = {j["label"]: j for j in only["joins"]}
    assert joins["university"]["id"] == "node/201"
    assert joins["university"]["distance_m"] == pytest.approx(3000.0, rel=1e-3)
    # two churches are in range; the nearer one is reported
    assert joins["church"]["id"] == "node/301" and joins["church"]["name"] == "Church A"
    assert joins["church"]["distance_m"] == pytest.approx(700.0, rel=1e-3)
    assert report["geometry_unavailable"] == 1                   # Klinik E: a node, no outline
    assert report["join_feature_counts"] == {"university": 5, "church": 6}


def test_each_story_constraint_removes_its_own_candidate(tmp_path):
    extract = _story_extract(tmp_path)

    def ids(constraints):
        return sorted(c["id"] for c in GEO.solve_osm_constraints(constraints, extract_path=extract)["candidates"])

    assert ids({"tags": HOSPITAL}) == ["node/105", "way/101", "way/102", "way/103", "way/104"]
    # perimeter alone: C is too large, E has no outline
    assert ids({"tags": HOSPITAL, "perimeter_m": [245, 335]}) == ["way/101", "way/102", "way/104"]
    assert ids({"tags": HOSPITAL, "area_m2": [10_000, None]}) == ["way/103"]
    # the university join alone: D's is 20 km away
    assert ids({"tags": HOSPITAL, "joins": [STORY["joins"][0]]}) == ["node/105", "way/101", "way/102", "way/103"]
    # the church join alone: B's church is nearer than min_m ...
    assert ids({"tags": HOSPITAL, "joins": [STORY["joins"][1]]}) == ["node/105", "way/101", "way/103", "way/104"]
    # ... and comes back when the minimum is dropped
    no_min = {"label": "church", "tags": CHURCH, "max_m": 1000}
    assert ids({"tags": HOSPITAL, "joins": [no_min]}) == ["node/105", "way/101", "way/102", "way/103", "way/104"]
    # a too-small maximum drops everything (A's nearest church is 700 m away)
    assert ids({"tags": HOSPITAL, "joins": [{"tags": CHURCH, "max_m": 50}]}) == []


def test_a_feature_is_not_its_own_join_neighbour(tmp_path):
    extract = _story_extract(tmp_path)
    alone = GEO.solve_osm_constraints({"tags": HOSPITAL, "joins": [{"tags": HOSPITAL, "max_m": 500}]},
                                      extract_path=extract)
    assert alone["candidates"] == []          # every hospital is > 500 m from every OTHER hospital
    # an extract that lists one element twice (a saved Overpass reply prints it once per `out`
    # statement): the second row is the same feature, not a neighbour 0 m away
    cafe = {"amenity": "cafe"}
    twice = _write_jsonl(tmp_path / "twice.jsonl", [_node(1, 27.0, 32.0, cafe), _node(1, 27.0, 32.0, cafe)])
    listed_twice = GEO.solve_osm_constraints({"tags": cafe, "joins": [{"tags": cafe, "max_m": 500}]}, extract_path=twice)
    assert listed_twice["candidates"] == []


def test_a_row_without_an_id_is_not_its_own_join_neighbour(tmp_path):
    """An extract cut without element ids: a feature is still told apart from itself."""
    cafe = {"amenity": "cafe"}
    another = {"tags": cafe, "joins": [{"label": "another cafe", "tags": cafe, "max_m": 500}]}
    lone = [{"lat": 27.0, "lon": 32.0, "name": "Lone Cafe", "tags": cafe}]
    extract = _write_jsonl(tmp_path / "lone.jsonl", lone)
    assert GEO.solve_osm_constraints(another, extract_path=extract)["candidates"] == []
    # a second id-less cafe 200 m east: each is now the other's neighbour, at 200 m, not itself at 0
    lat, lon = _offset(27.0, 32.0, east_m=200)
    pair = _write_jsonl(tmp_path / "pair.jsonl", lone + [{"lat": lat, "lon": lon, "name": "Second Cafe", "tags": cafe}])
    report = GEO.solve_osm_constraints(another, extract_path=pair)
    assert [(c["name"], c["joins"][0]["name"]) for c in report["candidates"]] == [
        ("Lone Cafe", "Second Cafe"), ("Second Cafe", "Lone Cafe")]
    assert [c["joins"][0]["distance_m"] for c in report["candidates"]] == pytest.approx([200.0, 200.0], rel=1e-3)
    assert all("id" in c and c["id"] is None for c in report["candidates"])
    # two id-less rows at one spot under one name are two features: each has the other at 0 m
    twins = _write_jsonl(tmp_path / "twins.jsonl", lone + lone)
    assert GEO.solve_osm_constraints(another, extract_path=twins)["candidate_count"] == 2


def test_geometry_constraint_over_an_extract_without_outlines_is_an_error(tmp_path):
    extract = _osm_extract(tmp_path)          # nodes only
    with pytest.raises(GEO.GeoLocateError, match="none carries polygon geometry"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "perimeter_m": [10, 500]}, extract_path=extract)


def test_ring_metrics_of_a_known_rectangle():
    lat, lon = 47.5, 11.0
    corners = [_offset(lat, lon, 0, 0), _offset(lat, lon, 0, 200), _offset(lat, lon, 100, 200), _offset(lat, lon, 100, 0)]
    m = GEO.ring_metrics(corners)                     # an open ring is closed for you
    assert m["perimeter_m"] == pytest.approx(600.0, rel=1e-3)
    assert m["area_m2"] == pytest.approx(20_000.0, rel=1e-3)
    centre = _offset(lat, lon, 50, 100)
    assert m["centroid"][0] == pytest.approx(centre[0], abs=1e-6)
    assert m["centroid"][1] == pytest.approx(centre[1], abs=1e-6)
    with pytest.raises(GEO.GeoLocateError, match="three distinct vertices"):
        GEO.ring_metrics([(0, 0), (0, 1), (0, 0)])


# ---- Overpass QL

def test_build_overpass_query_shape():
    query = GEO.build_overpass_query(
        {"tags": {"amenity": "cafe"}, "name_contains": ["luna"], "near": [44.4, 26.1], "radius_m": 300})
    assert query.startswith("[out:json][timeout:25];")
    assert 'node["amenity"="cafe"][~"name"~"luna",i](around:300.0,44.4,26.1);' in query
    for kind in ("way", "relation"):
        assert f'  {kind}["amenity"="cafe"]' in query
    assert ".primary out center 2000;" in query
    assert "[date:" not in query and "join" not in query


def test_overpass_query_escapes_name_needles_as_literals():
    query = GEO.build_overpass_query({"name_contains": ["c++", "St. Mary (old)"], "bbox": [1, 2, 3, 4]})
    assert r'[~"name"~"c\\+\\+",i]' in query                      # QL string for the regex c\+\+
    assert r'[~"name"~"st\\. mary \\(old\\)",i]' in query
    quoted = GEO.build_overpass_query({"tags": {"name": 'The "Old" Inn'}, "bbox": [1, 2, 3, 4]})
    assert r'["name"="The \"Old\" Inn"]' in quoted
    listed = GEO.build_overpass_query({"tags": {"amenity": ["hospital", "clinic"], "building": "*"}, "bbox": [1, 2, 3, 4]})
    assert '["amenity"~"^(hospital|clinic)$"]["building"]' in listed


def test_overpass_query_geometry_joins_and_attic_date():
    query = GEO.build_overpass_query(dict(STORY, bbox=[27.0, 31.0, 29.0, 34.0], date="2019-06-01"))
    assert query.startswith('[out:json][timeout:25][date:"2019-06-01T00:00:00Z"];')
    assert ".primary out geom 2000;" in query                      # perimeter needs the outline
    assert ')->.join0;\n.join0 out center;' in query and ')->.join1;\n.join1 out center;' in query
    assert 'node["amenity"="university"](' in query
    assert 'node["amenity"="place_of_worship"]["denomination"="catholic"](' in query
    # each join searches the region widened by its own max_m: 6 km of latitude is ~0.054 degrees
    widened = query.split('node["amenity"="university"](')[1].split(")")[0].split(",")
    assert float(widened[0]) == pytest.approx(27.0 - 6000 / M_PER_DEG, abs=1e-6)
    assert float(widened[2]) == pytest.approx(29.0 + 6000 / M_PER_DEG, abs=1e-6)
    assert float(widened[1]) < 31.0 - 6000 / M_PER_DEG              # longitude widens more, away from the equator
    explicit = GEO.build_overpass_query({"tags": HOSPITAL, "bbox": [1, 2, 3, 4]}, date="2020-02-29T12:00:00Z")
    assert '[date:"2020-02-29T12:00:00Z"]' in explicit
    for bad in ("2019-13-01", "yesterday", "2019-06-01T00:00:00"):
        with pytest.raises(GEO.GeoLocateError, match="date"):
            GEO.build_overpass_query({"tags": HOSPITAL, "bbox": [1, 2, 3, 4]}, date=bad)
    with pytest.raises(GEO.GeoLocateError, match="needs a bbox or near"):
        GEO.build_overpass_query(STORY)


# --------------------------------------------------------------------------- live Overpass (gated)

def test_overpass_refused_unless_profile_allows_host(tmp_path):
    calls = []

    def transport(url, query, timeout):
        calls.append((url, query, timeout))
        return b'{"elements": []}'

    prof = _profile(public=[])  # nothing allow-listed
    with pytest.raises(scope.OutOfScope, match="public_fetch_allow"):
        GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}}, online=True, profile=prof,
                                  transport=transport)
    assert calls == []  # the guard refused before any request


def test_overpass_allowed_with_injected_transport():
    captured = {}

    def transport(url, query, timeout):
        captured["url"] = url
        captured["query"] = query
        return json.dumps({"elements": [
            {"type": "node", "id": 7, "lat": 44.4268, "lon": 26.1025,
             "tags": {"amenity": "cafe", "name": "Luna C++ Coffee"}},
            {"type": "node", "id": 8, "lat": 44.4, "lon": 26.1, "tags": {"amenity": "bar", "name": "C++ Bar"}},
        ]}).encode("utf-8")

    prof = _profile(public=["overpass-api.de"])
    report = GEO.solve_osm_constraints({"tags": {"amenity": "cafe"}, "name_contains": ["c++"],
                                        "near": [44.4268, 26.1025], "radius_m": 1000},
                                       online=True, profile=prof, transport=transport)
    assert captured["url"] == GEO.DEFAULT_OVERPASS_ENDPOINT
    assert '["amenity"="cafe"]' in captured["query"]
    # The bar is filtered out by the tag constraint even though Overpass returned it, and the "c++"
    # needle matches literally, as it does offline.
    assert [c["id"] for c in report["candidates"]] == ["node/7"]
    assert report["source"] == "live_overpass:overpass-api.de"


def test_overpass_online_solves_joins_and_geometry_from_the_response():
    captured = {}
    a = (27.80, 32.10)
    elements = [_way(101, _square(*a, 70.0), dict(HOSPITAL, name="Klinik A")),
                _way(102, _square(27.9, 32.5, 70.0), dict(HOSPITAL, name="Klinik B")),      # no neighbours returned
                _node(201, *_offset(*a, north_m=3000), UNI),
                {"type": "way", "id": 301, "center": dict(zip(("lat", "lon"), _offset(*a, east_m=700))), "tags": CHURCH}]

    def transport(url, query, timeout):
        captured["query"] = query
        return json.dumps({"elements": elements}).encode()

    report = GEO.solve_osm_constraints(dict(STORY, bbox=[27.0, 31.0, 29.0, 34.0], date="2019-06-01"),
                                       online=True, profile=_profile(public=["overpass-api.de"]), transport=transport)
    assert '[date:"2019-06-01T00:00:00Z"]' in captured["query"] and ".join1 out center;" in captured["query"]
    assert [c["id"] for c in report["candidates"]] == ["way/101"]
    assert [j["id"] for j in report["candidates"][0]["joins"]] == ["node/201", "way/301"]
    assert report["constraints"]["date"] == "2019-06-01T00:00:00Z"


@pytest.mark.parametrize("join_print_first", [False, True])
def test_overpass_online_solves_an_element_once_however_often_it_is_printed(join_print_first):
    """When a join's class overlaps the primary class, Overpass prints the element once per `out`
    statement: `out geom` for the primary, `out center` for the join. It is one feature, and its
    outline is kept whichever print comes first."""
    cafe = {"amenity": "cafe"}
    a = (27.0, 32.0)
    b = _offset(*a, east_m=200)
    primary = [_way(1, _square(*a, 20.0), dict(cafe, name="One")), _node(2, *b, dict(cafe, name="Two"))]
    join = [{"type": "way", "id": 1, "center": {"lat": a[0], "lon": a[1]}, "tags": dict(cafe, name="One")},
            _node(2, *b, dict(cafe, name="Two"))]
    elements = join + primary if join_print_first else primary + join

    def transport(url, query, timeout):
        return json.dumps({"elements": elements}).encode()

    constraints = {"tags": cafe, "bbox": [26.0, 31.0, 28.0, 33.0],
                   "joins": [{"label": "another cafe", "tags": cafe, "min_m": 50, "max_m": 500}]}
    report = GEO.solve_osm_constraints(constraints, online=True, profile=_profile(public=["overpass-api.de"]),
                                       transport=transport)
    assert [c["id"] for c in report["candidates"]] == ["way/1", "node/2"]       # two cafes, not four
    assert [c["joins"][0]["id"] for c in report["candidates"]] == ["node/2", "way/1"]
    assert report["join_feature_counts"] == {"another cafe": 2}
    one = report["candidates"][0]
    assert one["center_source"] == "polygon_centroid" and one["perimeter_m"] == pytest.approx(80.0, rel=1e-3)


def test_flag_or_secret_shaped_constraints_never_reach_a_public_service():
    calls = []

    def transport(url, query, timeout):
        calls.append(query)
        return b'{"elements": []}'

    prof = _profile(public=["overpass-api.de"])
    with pytest.raises(GEO.GeoLocateError, match="flag format"):
        GEO.solve_osm_constraints({"name_contains": ["geo{not_for_overpass}"], "bbox": [1, 2, 3, 4]},
                                  online=True, profile=prof, transport=transport)
    with pytest.raises(GEO.GeoLocateError, match="secret-shaped"):
        GEO.solve_osm_constraints({"tags": {"note": "password=hunter2hunter2"}, "bbox": [1, 2, 3, 4]},
                                  online=True, profile=prof, transport=transport)
    assert calls == []


class _FakeOverpass:
    """A fake Overpass on 127.0.0.1: /api answers, /hop-in redirects to it on the same host, /hop-out
    redirects to it under another host name (localhost), which the test's profile does not list."""

    def __init__(self):
        fake = self
        self.seen = []            # (method, Host header, path, body)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                fake.seen.append((method, self.headers.get("Host"), self.path, body))
                port = self.server.server_address[1]
                if self.path == "/hop-out":
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{port}/api")
                    self.end_headers()
                    return
                if self.path == "/hop-in":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{port}/api")
                    self.end_headers()
                    return
                payload = json.dumps({"elements": [
                    {"type": "node", "id": 5, "lat": 1.5, "lon": 2.5, "tags": {"amenity": "cafe", "name": "Loopback"}}]})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload.encode())

            def do_POST(self):
                self._serve("POST")

            def do_GET(self):
                self._serve("GET")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_overpass():
    fake = _FakeOverpass()
    yield fake
    fake.close()


CAFES = {"tags": {"amenity": "cafe"}, "bbox": [1, 2, 3, 4]}


def test_default_overpass_transport_posts_the_query_to_an_allow_listed_host(fake_overpass):
    prof = _profile(public=["127.0.0.1"])
    report = GEO.solve_osm_constraints(CAFES, online=True, profile=prof, endpoint=fake_overpass.url("/api"))
    assert [c["id"] for c in report["candidates"]] == ["node/5"]
    (method, _host, path, body) = fake_overpass.seen[0]
    assert (method, path) == ("POST", "/api") and body == GEO.build_overpass_query(CAFES)


def test_default_overpass_transport_rechecks_scope_on_a_redirect(fake_overpass):
    prof = _profile(public=["127.0.0.1"])       # localhost is NOT listed
    with pytest.raises(scope.OutOfScope, match="localhost"):
        GEO.solve_osm_constraints(CAFES, online=True, profile=prof, endpoint=fake_overpass.url("/hop-out"))
    assert [(m, p) for m, _h, p, _b in fake_overpass.seen] == [("POST", "/hop-out")]   # the hop was never followed
    # a redirect that stays on a listed host is followed
    report = GEO.solve_osm_constraints(CAFES, online=True, profile=prof, endpoint=fake_overpass.url("/hop-in"))
    assert [c["id"] for c in report["candidates"]] == ["node/5"]
    assert fake_overpass.seen[-1][2] == "/api"


def test_default_overpass_transport_speaks_https_except_to_loopback():
    prof = _profile(public=["overpass.mirror.test"])
    with pytest.raises(GEO.GeoLocateError, match="must be https"):
        GEO.solve_osm_constraints(CAFES, online=True, profile=prof, endpoint="http://overpass.mirror.test/api")


# --------------------------------------------------------------------------- snapshot sweep

def _snapshots(tmp_path: Path) -> dict:
    old = [_node(1, 47.0, 12.0, dict(HOSPITAL, name="Old Klinik")), _node(2, 47.1, 12.1, dict(HOSPITAL, name="Stable Klinik"))]
    new = [_node(1, 47.0, 12.0, {"amenity": "clinic", "name": "Old Klinik"}),               # re-tagged since
           _node(2, 47.1, 12.1, dict(HOSPITAL, name="Stable Klinikum")),                   # renamed, still a hospital
           _node(3, 47.2, 12.2, dict(HOSPITAL, name="New Klinik"))]
    return {"2019-01-01": _write_jsonl(tmp_path / "2019.jsonl", old),
            "2024-01-01": _write_jsonl(tmp_path / "2024.jsonl", new)}


def test_snapshot_sweep_reports_which_candidates_changed(tmp_path):
    report = GEO.sweep_osm_snapshots({"tags": HOSPITAL}, snapshots=_snapshots(tmp_path))
    assert [s["label"] for s in report["snapshots"]] == ["2019-01-01", "2024-01-01"]
    assert [s["candidate_count"] for s in report["snapshots"]] == [2, 2]
    assert report["presence"]["node/1"]["snapshots"] == ["2019-01-01"]
    assert report["presence"]["node/2"]["snapshots"] == ["2019-01-01", "2024-01-01"]
    assert report["presence"]["node/2"]["names"] == ["Stable Klinik", "Stable Klinikum"]
    assert report["unstable"] == ["node/1", "node/3"]            # gone since, and new since
    assert report["candidate_count"] == 3


def test_snapshot_sweep_finds_dated_extracts_in_the_dataset(tmp_path):
    root = tmp_path / "geo"
    (root / "snapshots").mkdir(parents=True)
    with pytest.raises(GEO.GeoLocateError, match="no snapshot extracts"):
        GEO.sweep_osm_snapshots({"tags": HOSPITAL}, dataset_root=root)
    for label, path in _snapshots(tmp_path).items():
        (root / "snapshots" / f"{label}.jsonl").write_text(path.read_text())
    report = GEO.sweep_osm_snapshots({"tags": HOSPITAL}, dataset_root=root)
    assert [s["label"] for s in report["snapshots"]] == ["2019-01-01", "2024-01-01"]
    with pytest.raises(GEO.GeoLocateError, match="online sweep"):
        GEO.sweep_osm_snapshots({"tags": HOSPITAL}, dataset_root=root, dates=["2019-01-01"])


def test_online_sweep_sends_one_attic_query_per_date():
    queries = []

    def transport(url, query, timeout):
        queries.append(query)
        present = '[date:"2019-01-01T00:00:00Z"]' in query
        rows = [_node(2, 47.1, 12.1, dict(HOSPITAL, name="Stable Klinik"))]
        if present:
            rows.append(_node(1, 47.0, 12.0, dict(HOSPITAL, name="Old Klinik")))
        return json.dumps({"elements": rows}).encode()

    prof = _profile(public=["overpass-api.de"])
    report = GEO.sweep_osm_snapshots({"tags": HOSPITAL, "bbox": [46, 11, 48, 13]}, online=True, profile=prof,
                                     transport=transport, dates=["2019-01-01", "2024-01-01"])
    assert ['[date:"2019-01-01T00:00:00Z"]' in q for q in queries] == [True, False]
    assert ['[date:"2024-01-01T00:00:00Z"]' in q for q in queries] == [False, True]
    assert report["unstable"] == ["node/1"]
    with pytest.raises(GEO.GeoLocateError, match="at least one attic date"):
        GEO.sweep_osm_snapshots({"tags": HOSPITAL}, online=True, profile=prof, transport=transport)
    with pytest.raises(scope.OutOfScope):
        GEO.sweep_osm_snapshots({"tags": HOSPITAL}, online=True, profile=_profile(), transport=transport,
                                dates=["2019-01-01"])


# --------------------------------------------------------------------------- name spellings

def test_name_variants_cover_digraphs_ascii_separators_and_case():
    values = [v["value"] for v in GEO.name_variants("Grün Werk")]
    assert values[0] == "Grün Werk"                                 # most literal first
    for wanted in ("Grün_Werk", "GRÜN_WERK", "Gruen Werk", "Gruen_Werk", "GRUEN_WERK",
                   "gruen_werk", "Grun Werk", "GRUN_WERK"):
        assert wanted in values
    assert len(values) == len(set(values))
    by_value = {v["value"]: v for v in GEO.name_variants("Grün Werk")}
    assert by_value["GRUEN_WERK"]["changes"] == ["digraphs", "spaces:_", "case:upper"]
    assert by_value["Grun Werk"]["changes"] == ["ascii"]


def test_name_variants_read_the_osm_name_tags():
    tags = {"name": "Straße 1", "official_name": "Große Straße Eins", "alt_name": "Alt A;Alt B",
            "name:en": "Street One", "amenity": "hospital"}
    rows = GEO.name_variants(tags=tags, limit=200)
    sources = {r["value"]: r["source"] for r in rows}
    assert sources["Straße 1"] == "name" and sources["Strasse_1"] == "name"
    assert sources["Große Straße Eins"] == "official_name" and sources["GROSSE_STRASSE_EINS"] == "official_name"
    assert sources["Alt A"] == "alt_name" and sources["Alt B"] == "alt_name"
    assert sources["Street One"] == "name:en"
    assert "hospital" not in sources                                   # not a name tag
    assert len(GEO.name_variants(tags=tags, limit=5)) == 5
    punct = [v["value"] for v in GEO.name_variants("St. Mary's-Field")]
    assert "St_Mary_s_Field" in punct and "ST_MARY_S_FIELD" in punct
    with pytest.raises(GEO.GeoLocateError, match="give a name"):
        GEO.name_variants(tags={"amenity": "hospital"})


# --------------------------------------------------------------------------- named venue -> centre

def test_resolve_venue_gives_the_polygon_centre_and_its_entrances(tmp_path):
    site = (12.30, 45.60)
    ring = _square(*site, 100.0)
    rows = [
        _node(1, *_offset(*site, north_m=10), {"amenity": "kiosk", "name": "Testbad Kiosk"}),
        _node(6, *_offset(*site, north_m=-20), {"tourism": "information", "name": "Testbad"}),
        _way(2, ring, {"leisure": "sports_centre", "name": "Testbad"}),
        _node(3, *_offset(*site, north_m=50, east_m=0), {"entrance": "main"}),         # on the outline
        _node(4, *_offset(*site, north_m=5000), {"entrance": "yes"}),                  # another site's door
        _node(5, 48.0, 10.0, {"leisure": "sports_centre", "name": "Anderes Bad"}),
    ]
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)
    report = GEO.resolve_venue("testbad", extract_path=extract)
    # exact names first, and among them the outline before the point (which the extract lists first)
    assert [c["id"] for c in report["candidates"]] == ["way/2", "node/6", "node/1"]
    best = report["candidates"][0]
    assert best["exact_name"] and best["has_polygon"] and best["center_source"] == "polygon_centroid"
    assert best["lat"] == pytest.approx(site[0], abs=1e-7) and best["lon"] == pytest.approx(site[1], abs=1e-7)
    assert best["perimeter_m"] == pytest.approx(400.0, rel=1e-3)
    assert [e["id"] for e in best["entrances"]] == ["node/3"]
    assert best["entrances"][0]["entrance"] == "main"
    assert report["candidates"][1]["entrances"] == [] and report["candidates"][1]["has_polygon"] is False
    assert report["candidates"][2]["exact_name"] is False
    assert GEO.resolve_venue("no such place", extract_path=extract)["candidates"] == []


def test_resolve_venue_orders_equal_matches_by_distance(tmp_path):
    rows = [_node(1, 10.0, 10.0, {"name": "Stadtbad"}), _node(2, 20.0, 20.0, {"name": "Stadtbad"})]
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)
    near_second = GEO.resolve_venue("Stadtbad", extract_path=extract, near=(20.0, 20.1))
    assert [c["id"] for c in near_second["candidates"]] == ["node/2", "node/1"]
    near_first = GEO.resolve_venue("Stadtbad", extract_path=extract, near=(10.0, 10.1))
    assert [c["id"] for c in near_first["candidates"]] == ["node/1", "node/2"]


def test_resolve_venue_pads_the_outline_when_it_collects_entrances(tmp_path):
    """A door is often mapped a few metres off the outline (on the fence, at the gate): entrances
    within `entrance_pad_m` (default 30 m) of the outline's bounding box count, north-south and
    east-west alike; farther ones belong to something else."""
    site = (12.30, 45.60)
    rows = [
        _way(2, _square(*site, 100.0), {"leisure": "sports_centre", "name": "Testhalle"}),   # edges 50 m out
        _node(3, *_offset(*site, north_m=65), {"entrance": "main"}),        # 15 m north of the outline
        _node(4, *_offset(*site, east_m=65), {"entrance": "yes"}),          # 15 m east of it
        _node(5, *_offset(*site, north_m=-90), {"entrance": "service"}),    # 40 m south: past the pad
        _node(6, *_offset(*site, east_m=-90), {"entrance": "service"}),     # 40 m west: past the pad
    ]
    extract = _write_jsonl(tmp_path / "osm.jsonl", rows)

    def doors(**kw):
        (hall,) = GEO.resolve_venue("Testhalle", extract_path=extract, **kw)["candidates"]
        return [e["id"] for e in hall["entrances"]]

    assert doors() == ["node/3", "node/4"]
    assert doors(entrance_pad_m=45) == ["node/3", "node/4", "node/5", "node/6"]
    assert doors(entrance_pad_m=10) == [] and doors(entrance_pad_m=0) == []
    with pytest.raises(GEO.GeoLocateError, match="entrance_pad_m must be 0..1000"):
        doors(entrance_pad_m=1001)


# --------------------------------------------------------------------------- DEM skyline matcher

def _wall_dem():
    """A flat plain with a 500 m vertical wall east of column 140. cell = 0.0005 deg (~55.66 m).
    Observer at the centre (row/col 100) sees the wall edge at 0.02 deg east."""
    nrows = ncols = 201
    wall_col = 140
    height = 500.0
    rows = [[height if c >= wall_col else 0.0 for c in range(ncols)] for _ in range(nrows)]
    return GEO.DEMGrid(lat_min=0.0, lon_min=0.0, cell_deg=0.0005, elevations=rows), height, wall_col


def test_destination_point_cardinal_sanity():
    one_deg_m = GEO.EARTH_RADIUS_M * math.radians(1.0)
    lat, lon = GEO.destination_point(0.0, 0.0, 0.0, one_deg_m)   # due north
    assert lat == pytest.approx(1.0, abs=1e-6) and lon == pytest.approx(0.0, abs=1e-6)
    lat, lon = GEO.destination_point(0.0, 0.0, 90.0, one_deg_m)  # due east at the equator
    assert lat == pytest.approx(0.0, abs=1e-6) and lon == pytest.approx(1.0, abs=1e-3)


def test_dem_horizon_profile_matches_analytic_wall_angle():
    dem, height, wall_col = _wall_dem()
    obs_lat = obs_lon = 100 * 0.0005  # cell-centre of the observer
    profile = GEO.dem_horizon_profile(dem, obs_lat, obs_lon, eye_height_m=0.0, earth_curvature=False,
                                       step_m=20.0, max_distance_m=8000.0, azimuth_step_deg=5.0)
    by_az = {round(p["azimuth_deg"]): p["elevation_deg"] for p in profile}
    # East edge of the wall: (wall_col-100) cells * 0.0005 deg = 0.02 deg -> metres at the equator.
    edge_m = (wall_col - 100) * 0.0005 * math.radians(1.0) * GEO.EARTH_RADIUS_M
    expected = math.degrees(math.atan2(height, edge_m))
    assert by_az[90] == pytest.approx(expected, abs=1.5)
    # The plain in the other cardinal directions has a flat (zero) horizon.
    assert by_az[0] == pytest.approx(0.0, abs=0.3)
    assert by_az[270] == pytest.approx(0.0, abs=0.3)
    assert by_az[90] > by_az[0] + 5.0


def _first_sample_inside_wall(wall_col, step_m):
    """Distance of the first east-going ray sample that lands on the wall (nearest-cell lookup: the
    wall starts half a cell before its first column's centre)."""
    boundary_m = (wall_col - 0.5 - 100) * 0.0005 * M_PER_DEG
    return math.ceil(boundary_m / step_m) * step_m


def test_dem_horizon_subtracts_the_eye_height():
    dem, height, wall_col = _wall_dem()
    obs = 100 * 0.0005
    step = 20.0
    d1 = _first_sample_inside_wall(wall_col, step)
    for eye in (0.0, 100.0, 300.0):
        profile = GEO.dem_horizon_profile(dem, obs, obs, eye_height_m=eye, earth_curvature=False, step_m=step,
                                           max_distance_m=8000.0, azimuths=[90.0, 270.0])
        east = {round(p["azimuth_deg"]): p["elevation_deg"] for p in profile}[90]
        assert east == pytest.approx(math.degrees(math.atan2(height - eye, d1)), abs=1e-6)


def _sea_plain():
    """A sea-level plain 1.2 degrees wide along the equator (cells of 0.01 deg), observer mid-way."""
    return GEO.DEMGrid(lat_min=-0.01, lon_min=0.0, cell_deg=0.01, elevations=[[0.0] * 121 for _ in range(3)])


def test_dem_horizon_curvature_gives_the_classical_dip_of_the_horizon():
    """Over a sea-level plain an eye at height h sees the horizon dip by sqrt(2 h (1 - k) / R) radians
    (k = the refraction coefficient): the maximum over distance d of atan((-h - (1-k) d^2 / 2R) / d)."""
    dem = _sea_plain()
    h, k = 100.0, GEO.DEFAULT_REFRACTION_COEFF
    dip_deg = math.degrees(math.sqrt(2.0 * h * (1.0 - k) / GEO.EARTH_RADIUS_M))
    kwargs = dict(eye_height_m=h, step_m=100.0, max_distance_m=60_000.0, azimuths=[90.0, 270.0])
    curved = GEO.dem_horizon_profile(dem, 0.0, 0.6, **kwargs)
    assert [p["elevation_deg"] for p in curved] == pytest.approx([-dip_deg, -dip_deg], abs=2e-4)
    assert dip_deg == pytest.approx(0.2994, abs=1e-3)                       # ~0.3 deg from 100 m up
    # with no refraction the dip is larger; with no curvature the plain rises towards 0 at the far end
    vacuum = GEO.dem_horizon_profile(dem, 0.0, 0.6, refraction_coeff=0.0, **kwargs)
    assert vacuum[0]["elevation_deg"] == pytest.approx(-math.degrees(math.sqrt(2.0 * h / GEO.EARTH_RADIUS_M)), abs=2e-4)
    flat = GEO.dem_horizon_profile(dem, 0.0, 0.6, earth_curvature=False, **kwargs)
    assert flat[0]["elevation_deg"] == pytest.approx(math.degrees(math.atan2(-h, 60_000.0)), abs=1e-6)
    assert curved[0]["elevation_deg"] < flat[0]["elevation_deg"] < 0.0


def test_dem_horizon_profile_rejects_observer_off_grid():
    dem, _, _ = _wall_dem()
    with pytest.raises(GEO.GeoLocateError, match="outside the DEM"):
        GEO.dem_horizon_profile(dem, 10.0, 10.0)


WALL_KWARGS = {"eye_height_m": 0.0, "earth_curvature": False, "step_m": 20.0,
               "max_distance_m": 8000.0, "azimuth_step_deg": 5.0}


def test_match_skyline_ranks_the_true_observer_first_and_lists_what_it_skipped():
    dem, _, _ = _wall_dem()
    center = (100 * 0.0005, 100 * 0.0005)
    observed = GEO.dem_horizon_profile(dem, center[0], center[1], **WALL_KWARGS)
    candidates = {"far_west": [100 * 0.0005, 50 * 0.0005], "center": list(center), "off_the_map": [45.0, 9.0]}
    report = GEO.match_skyline(observed, candidates, dem=dem, horizon_kwargs=WALL_KWARGS, tolerance_deg=2.0)
    ranked = report["candidates"]
    assert [r["name"] for r in ranked] == ["center", "far_west"]
    assert ranked[0]["rmse_deg"] == pytest.approx(0.0, abs=1e-9) and ranked[1]["rmse_deg"] > 1.0
    assert (ranked[0]["lat"], ranked[0]["lon"]) == center
    assert [s["name"] for s in report["skipped"]] == ["off_the_map"]
    assert "outside the DEM" in report["skipped"][0]["reason"]
    with pytest.raises(GEO.GeoLocateError, match="no observer candidate produced"):
        GEO.match_skyline(observed, {"off_the_map": [45.0, 9.0]}, dem=dem, horizon_kwargs=WALL_KWARGS)


def test_match_skyline_tries_the_north_offset_hypotheses():
    dem, _, _ = _wall_dem()
    center = (100 * 0.0005, 100 * 0.0005)
    true_profile = GEO.dem_horizon_profile(dem, center[0], center[1], **WALL_KWARGS)
    # a photo whose "north" is really east: every azimuth reads 90 degrees low
    rotated = [{"azimuth_deg": (p["azimuth_deg"] - 90.0) % 360.0, "elevation_deg": p["elevation_deg"]}
               for p in true_profile]
    plain = GEO.match_skyline(rotated, {"center": list(center)}, dem=dem, horizon_kwargs=WALL_KWARGS)
    assert plain["candidates"][0]["rmse_deg"] > 1.0
    tried = GEO.match_skyline(rotated, {"center": list(center)}, dem=dem, horizon_kwargs=WALL_KWARGS,
                              north_offset_hypotheses_deg=(0.0, 90.0, 180.0))
    assert tried["candidates"][0]["best_north_offset_deg"] == 90.0
    assert tried["candidates"][0]["rmse_deg"] == pytest.approx(0.0, abs=1e-9)


def test_load_dem_missing_file_is_named_error(tmp_path):
    with pytest.raises(GEO.GeoLocateError, match="DEM not found"):
        GEO.load_dem(tmp_path / "nope.json")


def test_dem_grid_roundtrips_from_mapping(tmp_path):
    serialised = {"format": "ctf-dem-grid-v1", "lat_min": 0.0, "lon_min": 0.0, "cell_deg": 0.0005,
                  "elevations": [[0.0, 1.0], [2.0, -9999.0]], "nodata": -9999.0}
    path = _write_json(tmp_path / "dem.json", serialised)
    loaded = GEO.load_dem(path)
    assert loaded.elevation(0.0, 0.0) == 0.0
    assert loaded.elevation(0.0005, 0.0) == 2.0
    assert loaded.elevation(0.0005, 0.0005) is None  # the nodata cell
    assert loaded.elevation(5.0, 5.0) is None  # off grid
    with pytest.raises(GEO.GeoLocateError, match="unsupported DEM format"):
        GEO.DEMGrid.from_mapping(dict(serialised, format="geotiff"))


# ---- SRTM .hgt tiles

def _write_hgt(path: Path, side: int, value) -> Path:
    """An SRTM-layout tile: big-endian int16, rows north to south. value(file_row, col) -> metres."""
    samples = [value(r, c) for r in range(side) for c in range(side)]
    path.write_bytes(struct.pack(f">{side * side}h", *samples))
    return path


def test_hgt_tile_is_read_north_up_big_endian_with_voids(tmp_path):
    tile = _write_hgt(tmp_path / "N10E020.hgt", 5, lambda r, c: -32768 if (r, c) == (2, 2) else 100 * r + c)
    dem = GEO.load_dem(tile)
    assert (dem.lat_min, dem.lon_min, dem.cell_deg, dem.nrows, dem.ncols) == (10.0, 20.0, 0.25, 5, 5)
    assert dem.elevation(11.0, 20.0) == 0.0          # file row 0 is the NORTH edge
    assert dem.elevation(10.0, 20.0) == 400.0        # file row 4 is the south edge
    assert dem.elevation(10.0, 21.0) == 404.0
    assert dem.elevation(10.75, 20.25) == 101.0
    assert dem.elevation(10.5, 20.5) is None         # the -32768 void
    assert dem.elevation(11.5, 20.0) is None         # north of the tile
    south_west = GEO.DEMGrid.from_hgt(_write_hgt(tmp_path / "S01W002.hgt", 3, lambda r, c: 7))
    assert (south_west.lat_min, south_west.lon_min, south_west.cell_deg) == (-1.0, -2.0, 0.5)
    assert south_west.elevation(-0.5, -1.5) == 7.0


def test_hgt_tile_errors_are_named(tmp_path):
    with pytest.raises(GEO.GeoLocateError, match="named like N45E010.hgt"):
        GEO.load_dem(_write_hgt(tmp_path / "tile.hgt", 3, lambda r, c: 0))
    odd = tmp_path / "N01E001.hgt"
    odd.write_bytes(b"\0" * 20)                       # 10 samples: not a square
    with pytest.raises(GEO.GeoLocateError, match="not a square of 16-bit samples"):
        GEO.load_dem(odd)
    with pytest.raises(GEO.GeoLocateError, match="DEM tile not found"):
        GEO.load_dem(tmp_path / "N02E002.hgt")


def test_dem_folder_is_a_mosaic_and_the_dataset_prefers_it(tmp_path):
    root = tmp_path / "geo"
    (root / "dem").mkdir(parents=True)
    with pytest.raises(GEO.GeoLocateError, match="holds no .hgt or .json tile"):
        GEO.load_dem(root / "dem")
    _write_hgt(root / "dem" / "N10E020.hgt", 3, lambda r, c: 100)
    _write_hgt(root / "dem" / "N10E021.hgt", 3, lambda r, c: 200)
    mosaic = GEO.load_dem(root / "dem")
    assert isinstance(mosaic, GEO.DEMMosaic) and len(mosaic.tiles) == 2
    assert mosaic.elevation(10.5, 20.25) == 100.0 and mosaic.elevation(10.5, 21.75) == 200.0
    assert mosaic.elevation(10.5, 23.0) is None
    # match_skyline finds <dataset>/dem/ by itself: a flat tile gives a flat horizon for an observer on it
    flat = [{"azimuth_deg": a, "elevation_deg": 0.0} for a in (0, 90, 180, 270)]
    kwargs = {"eye_height_m": 0.0, "earth_curvature": False, "step_m": 2000.0, "max_distance_m": 20_000.0,
              "azimuth_step_deg": 90.0}
    report = GEO.match_skyline(flat, {"on_tile": [10.5, 20.5]}, dataset_root=root, horizon_kwargs=kwargs)
    assert report["candidates"][0]["rmse_deg"] == pytest.approx(0.0, abs=1e-9)
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(GEO.GeoLocateError, match="neither a dem/ folder of .hgt tiles nor dem.json"):
        GEO.match_skyline(flat, {"on_tile": [10.5, 20.5]}, dataset_root=empty)


@pytest.mark.parametrize("packed", ["N10E021.hgt.zip", "N10E021.SRTMGL1.hgt.gz", "n10e021.HGT.ZIP"])
def test_dem_folder_with_a_packed_tile_is_an_error_not_a_smaller_mosaic(tmp_path, packed):
    """SRTM tiles arrive zipped. A tile left packed must not just be missing from the mosaic: every
    observer on it would be skipped as "outside the DEM"."""
    folder = tmp_path / "dem"
    folder.mkdir()
    _write_hgt(folder / "N10E020.hgt", 3, lambda r, c: 100)
    (folder / "README.txt").write_text("tiles for the test region")       # other files are ignored
    assert len(GEO.load_dem(folder).tiles) == 1
    (folder / packed).write_bytes(b"PK\x03\x04")
    with pytest.raises(GEO.GeoLocateError, match=r"1 packed tile\(s\).*" + packed.replace(".", r"\.") + ".*unpack"):
        GEO.load_dem(folder)
    with pytest.raises(GEO.GeoLocateError, match="is packed: unpack it"):
        GEO.load_dem(folder / packed)
    (folder / packed).unlink()
    assert GEO.load_dem(folder).elevation(10.5, 20.5) == 100.0


# --------------------------------------------------------------------------- submit gate

class _RecordingAdapter:
    """A platform adapter that records what reaches it. The gate in front of it is the real one."""
    kind = "ctfd"

    def __init__(self):
        self.sent = []

    def submit(self, challenge_id, flag):
        self.sent.append((challenge_id, flag))
        return SubmitResult(SubmitStatus.CORRECT, "ok")


def _gate(submit_mode):
    prof = _profile(submit_mode=submit_mode)
    raw = _RecordingAdapter()
    return platform.SubmitGate(raw, prof), raw


def test_submit_named_location_sends_a_flag_through_the_real_gate():
    gate, raw = _gate("auto")
    result = GEO.submit_named_location("geo{Grün3_pin}", "chal-1", provenance="flag from the page checker", gate=gate)
    assert result.accepted and result.sent
    assert raw.sent == [("chal-1", "geo{Grün3_pin}")]              # spelled exactly as given


def test_submit_does_not_force_nonstandard():
    gate, raw = _gate("auto")
    answer = GEO.format_coordinate_answer(44.4268, 26.1025)
    assert answer == "44.4268, 26.1025"
    refused = GEO.submit_named_location(answer, "chal-1", provenance="model named the venue", gate=gate)
    assert refused.status is SubmitStatus.NOT_ALLOWED and not refused.sent
    assert "not in the event flag format" in refused.message
    assert raw.sent == []
    sent = GEO.submit_named_location(answer, "chal-1", provenance="model named the venue", gate=gate,
                                     allow_nonstandard=True)
    assert sent.accepted and raw.sent == [("chal-1", "44.4268, 26.1025")]


def test_submit_does_not_confirm_on_the_players_behalf():
    gate, raw = _gate("confirm")
    held = GEO.submit_named_location("geo{pin}", "chal-1", provenance="p", gate=gate)
    assert held.status is SubmitStatus.NOT_ALLOWED and not held.sent and "confirm" in held.message
    assert raw.sent == []
    assert GEO.submit_named_location("geo{pin}", "chal-1", provenance="p", gate=gate, confirmed=True).accepted
    assert raw.sent == [("chal-1", "geo{pin}")]


def test_submit_runs_the_plausibility_check_before_the_gate():
    gate, raw = _gate("auto")
    blocked = GEO.submit_named_location("geo{}", "chal-1", provenance="p", gate=gate)
    assert blocked.status is SubmitStatus.NOT_ALLOWED and not blocked.sent
    assert "plausibility" in blocked.message and "empty_body" in blocked.message
    assert raw.sent == []


def test_submit_requires_a_provenance_note_and_a_manual_event_never_sends():
    gate, raw = _gate("auto")
    with pytest.raises(GEO.GeoLocateError, match="provenance"):
        GEO.submit_named_location("geo{pin}", "chal-1", provenance="", gate=gate)
    manual, manual_raw = _gate("manual")
    refused = GEO.submit_named_location("geo{pin}", "chal-1", provenance="p", gate=manual, confirmed=True)
    assert refused.status is SubmitStatus.NOT_ALLOWED and not refused.sent
    assert raw.sent == [] and manual_raw.sent == []


def test_format_coordinate_answer_bounds():
    with pytest.raises(GEO.GeoLocateError, match="Earth bounds"):
        GEO.format_coordinate_answer(200.0, 0.0)
    assert GEO.format_coordinate_answer(1.23456789, -2.0, precision=3) == "1.235, -2.0"


# --------------------------------------------------------------------------- real external dataset

def test_real_geo_dataset_files_load():
    """The frozen dataset at $CTF_GEO_DATASET: every file the resolvers read must be there and load.
    Unset, the test reports as not run (never green); set, a missing or unreadable file fails it."""
    root = paths.geo_dataset_root()
    if root is None:
        pytest.skip("not run: CTF_GEO_DATASET is not set (the frozen geo dataset lives outside the repo)")
    assert GEO.load_brand_directory(dataset_root=root), "brands.json holds no brand"
    stats = GEO.new_extract_stats()
    count = sum(1 for _ in GEO.iter_osm_extract(root / "osm.jsonl", stats))
    GEO.require_features(stats, "osm.jsonl")
    assert count == stats["features"] > 0
    dem = GEO._dataset_dem(root)
    tiles = dem.tiles if isinstance(dem, GEO.DEMMosaic) else [dem]
    assert all(t.nrows >= 2 and t.ncols >= 2 for t in tiles)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
