"""B-113: osint_geolocate.py as an engine -- every CLI command, the SolverResult line the engine
runner reads, the opener (sign OCR -> candidates) and the dataset builders.

Fixtures are synthetic and built here. The map-pin page is a fake on 127.0.0.1; the one test that
runs real OCR draws its own sign and is marked needs_tool, so it reports as not run without
tesseract. Nothing here contacts a platform: every `check --submit` test injects the real SubmitGate
over a recording adapter, built from a profile this file writes.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import ledger, paths
from ctf.result import SolverResult

TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))

import osint_geolocate as GEO  # noqa: E402

REPO = paths.repo_root()
M_PER_DEG = GEO.METRES_PER_DEGREE


def _write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_jsonl(path: Path, rows) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def _dataset(tmp_path: Path) -> Path:
    root = tmp_path / "geo"
    root.mkdir()
    _write_json(root / "brands.json", {
        "Luna Coffee": [{"name": "Luna Coffee Riverside", "lat": 44.4268, "lon": 26.1025},
                        {"name": "Luna Coffee Old Town", "lat": 44.4300, "lon": 26.0960}],
        "Brava Fuel": [{"name": "Brava Fuel Plaza", "lat": -5.5, "lon": 30.5}],
        "Zed": [{"name": "Zed", "lat": 1.0, "lon": 1.0}],
    })
    _write_jsonl(root / "osm.jsonl", [
        {"type": "node", "id": 1, "lat": 44.4268, "lon": 26.1025, "tags": {"amenity": "cafe", "name": "Luna Coffee"}},
        {"type": "node", "id": 2, "lat": 44.4290, "lon": 26.1000, "tags": {"highway": "pedestrian", "name": "Piata Mare"}},
        {"type": "node", "id": 3, "lat": 35.2, "lon": 40.4, "tags": {"tourism": "information", "name": "Kestrel Lookout"}},
        {"type": "node", "id": 4, "lat": 48.0, "lon": 2.0, "tags": {"amenity": "bar", "name": "Le"}},
    ])
    return root


def _run(capsys, argv):
    """Run the CLI in-process: (exit code, report or None, SolverResult or None, stderr)."""
    code = GEO.main(argv)
    out, err = capsys.readouterr()
    lines = [line for line in out.splitlines() if line.strip()]
    if not lines:
        return code, None, None, err
    result = SolverResult.from_json(lines[-1])         # the engine contract: the LAST stdout line
    head = "\n".join(out.splitlines()[:-1]).strip()
    return code, (json.loads(head) if head else None), result, err


# --------------------------------------------------------------------------- resolver commands

def test_cli_brand_prints_report_then_a_solver_result(tmp_path, capsys):
    root = _dataset(tmp_path)
    code, report, result, err = _run(capsys, ["brand", "Luna Coffee", "--dataset", str(root),
                                              "--near", "44.4268", "26.1025"])
    assert code == 0 and err == ""
    assert report["kind"] == "brand_to_maps" and report["candidates"][0]["name"] == "Luna Coffee Riverside"
    assert result.status == "unsure" and result.engine == "toolkits.osint_geolocate" and result.flags == ()
    assert result.evidence[0].kind == "match"
    assert result.evidence[0].detail.startswith("Luna Coffee Riverside | 44.426800, 26.102500")
    assert "2 candidate(s)" in result.notes
    # an explicit directory file replaces the dataset's
    other = _write_json(tmp_path / "mine.json", {"Luna Coffee": [{"name": "Only One", "lat": 1.0, "lon": 2.0}]})
    code, report, result, _ = _run(capsys, ["brand", "Luna Coffee", "--directory", str(other)])
    assert [c["name"] for c in report["candidates"]] == ["Only One"]


def test_cli_no_candidate_is_status_none(tmp_path, capsys):
    code, report, result, err = _run(capsys, ["brand", "Nobody Sells This", "--dataset", str(_dataset(tmp_path))])
    assert code == 0 and report["candidates"] == []
    assert result.status == "none" and result.evidence == ()


def test_cli_missing_dataset_is_a_blocked_result_naming_the_variable(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CTF_GEO_DATASET", raising=False)
    code, report, result, err = _run(capsys, ["brand", "Luna Coffee"])
    assert code == 0 and report is None                      # a result, not a crash: exit 0
    assert result.status == "blocked" and "CTF_GEO_DATASET" in result.notes and result.notes.startswith("brand: ")
    assert "CTF_GEO_DATASET" in err
    monkeypatch.setenv("CTF_GEO_DATASET", str(_dataset(tmp_path)))
    code, report, result, err = _run(capsys, ["brand", "Luna Coffee"])
    assert result.status == "unsure" and report["candidate_count"] == 2


def test_cli_usage_error_exits_2_without_a_result(tmp_path, capsys):
    for argv in (["teleport", "x"], [], ["brand"], ["brand", "x", "--no-such-option"]):
        code, report, result, err = _run(capsys, argv)
        assert code == 2 and result is None and report is None
        assert err.startswith("osint_geolocate: usage:")


@pytest.mark.parametrize("error", ["event", "platform", "checker"])
def test_cli_named_errors_are_blocked_results_not_tracebacks(error, capsys, monkeypatch):
    """No resolvable event, a platform error (no token, a failed POST) and a checker refusal all end
    as a `blocked` result with the reason, exit 0 -- never an uncaught traceback."""
    from ctf import event
    from ctf.platform.base import PlatformError
    import _osint_geo_checker as CHK
    raised = {"event": event.EventError("no event: set CTF_EVENT"),
              "platform": PlatformError("no CTF_TOKEN or CTF_COOKIE for the platform"),
              "checker": CHK.CheckRefused("challenge 7 has used 3 of 3 checker posts")}[error]

    def boom(args):
        raise raised

    monkeypatch.setattr(GEO, "_run", boom)
    code, report, result, err = _run(capsys, ["check", "http://127.0.0.1:1/", "7", "1", "1", "--provenance", "p"])
    assert code == 0 and report is None and result.status == "blocked"
    assert result.notes == f"check: {raised}" and str(raised) in err


def test_cli_osm_solves_a_constraints_file(tmp_path, capsys):
    root = _dataset(tmp_path)
    constraints = _write_json(tmp_path / "c.json", {"tags": {"amenity": "cafe"}})
    code, report, result, _ = _run(capsys, ["osm", str(constraints), "--dataset", str(root)])
    assert code == 0 and [c["id"] for c in report["candidates"]] == ["node/1"]
    assert report["extract"]["rows_read"] == 4 and result.status == "unsure"
    assert "node/1" in result.evidence[0].detail
    # an explicit extract; a malformed constraints file; an attic date without --online
    only_bars = _write_jsonl(tmp_path / "bars.jsonl", [{"id": 9, "lat": 1.0, "lon": 1.0, "tags": {"amenity": "bar"}}])
    code, report, result, _ = _run(capsys, ["osm", str(constraints), "--extract", str(only_bars)])
    assert report["candidates"] == [] and result.status == "none"
    bad = _write_json(tmp_path / "bad.json", {"tags": {"amenity": "cafe"}, "colour": "red"})
    code, report, result, err = _run(capsys, ["osm", str(bad), "--dataset", str(root)])
    assert code == 0 and result.status == "blocked" and "unknown constraint key" in result.notes
    code, report, result, err = _run(capsys, ["osm", str(constraints), "--dataset", str(root), "--date", "2019-06-01"])
    assert result.status == "blocked" and "--online" in result.notes
    code, report, result, err = _run(capsys, ["osm", str(tmp_path / "absent.json"), "--dataset", str(root)])
    assert result.status == "blocked" and "constraints not found" in result.notes


def test_cli_osm_online_is_refused_by_the_scope_guard(tmp_path, capsys):
    # The suite's event lists no public fetch host: the live query is refused before any request.
    constraints = _write_json(tmp_path / "c.json", {"tags": {"amenity": "cafe"}, "bbox": [1, 2, 3, 4]})
    code, report, result, err = _run(capsys, ["osm", str(constraints), "--online", "--date", "2019-06-01"])
    assert code == 0 and result.status == "blocked" and "public_fetch_allow" in result.notes


def test_cli_sweep_over_dated_extracts(tmp_path, capsys):
    hospital = {"amenity": "hospital"}
    old = _write_jsonl(tmp_path / "old.jsonl", [{"type": "node", "id": 1, "lat": 1.0, "lon": 1.0, "tags": dict(hospital, name="Gone")}])
    new = _write_jsonl(tmp_path / "new.jsonl", [{"type": "node", "id": 2, "lat": 2.0, "lon": 2.0, "tags": dict(hospital, name="Here")}])
    constraints = _write_json(tmp_path / "c.json", {"tags": hospital})
    code, report, result, _ = _run(capsys, ["sweep", str(constraints), "--snapshot", f"2019={old}",
                                            "--snapshot", f"2024={new}"])
    assert code == 0 and report["unstable"] == ["node/1", "node/2"]
    assert [s["label"] for s in report["snapshots"]] == ["2019", "2024"] and result.status == "unsure"
    code, report, result, _ = _run(capsys, ["sweep", str(constraints), "--snapshot", "no-equals-sign"])
    assert result.status == "blocked" and "LABEL=FILE" in result.notes


def test_cli_venue_and_variants(tmp_path, capsys):
    root = _dataset(tmp_path)
    code, report, result, _ = _run(capsys, ["venue", "Kestrel Lookout", "--dataset", str(root)])
    assert code == 0 and report["candidates"][0]["id"] == "node/3" and report["candidates"][0]["exact_name"]
    assert result.status == "unsure" and "35.200000, 40.400000" in result.evidence[0].detail
    code, report, result, _ = _run(capsys, ["variants", "Grün Werk", "--limit", "4"])
    assert [c["value"] for c in report["candidates"]] == ["Grün Werk", "GRÜN WERK", "grün werk", "Grün_Werk"]
    assert result.status == "unsure" and result.evidence[0].detail == "Grün Werk"
    tags = _write_json(tmp_path / "tags.json", {"name": "Nordhof", "official_name": "Alter Nordhof Eins"})
    code, report, result, _ = _run(capsys, ["variants", "--tags", str(tags)])
    assert "Alter_Nordhof_Eins" in [c["value"] for c in report["candidates"]]
    code, report, result, _ = _run(capsys, ["variants"])
    assert result.status == "blocked" and "give a name" in result.notes


# --------------------------------------------------------------------------- skyline options

def _skyline_files(tmp_path: Path):
    """A wall DEM as dem.json, the true observer's profile (eye 0 m, no curvature) rotated so its
    "north" is really east, and two observer candidates."""
    ncols = nrows = 121
    rows = [[400.0 if c >= 90 else 0.0 for c in range(ncols)] for _ in range(nrows)]
    root = tmp_path / "geo"
    root.mkdir(exist_ok=True)
    _write_json(root / "dem.json", {"format": "ctf-dem-grid-v1", "lat_min": 0.0, "lon_min": 0.0,
                                    "cell_deg": 0.001, "elevations": rows})
    dem = GEO.load_dem(root / "dem.json")
    center = (0.060, 0.060)
    truth = GEO.dem_horizon_profile(dem, *center, eye_height_m=0.0, earth_curvature=False, step_m=50.0,
                                    max_distance_m=5000.0, azimuth_step_deg=10.0)
    rotated = [{"azimuth_deg": (p["azimuth_deg"] - 90.0) % 360.0, "elevation_deg": p["elevation_deg"]} for p in truth]
    observed = _write_json(tmp_path / "observed.json", rotated)
    candidates = _write_json(tmp_path / "cands.json", {"center": list(center), "west": [0.060, 0.020]})
    return root, observed, candidates


def test_cli_skyline_passes_the_horizon_options_and_offsets_through(tmp_path, capsys):
    root, observed, candidates = _skyline_files(tmp_path)
    exact = ["skyline", str(observed), str(candidates), "--dataset", str(root), "--eye-height", "0",
             "--no-curvature", "--step", "50", "--max-distance", "5000", "--azimuth-step", "10",
             "--north-offset", "0", "--north-offset", "90"]
    code, report, result, _ = _run(capsys, exact)
    assert code == 0 and report["candidates"][0]["name"] == "center"
    assert report["candidates"][0]["best_north_offset_deg"] == 90.0
    assert report["candidates"][0]["rmse_deg"] == pytest.approx(0.0, abs=1e-9)
    assert report["orientation_hypotheses_deg"] == [0.0, 90.0]
    assert result.status == "unsure" and "skyline rmse 0.00 deg" in result.evidence[0].detail
    # without the offset hypothesis the rotated photo no longer fits ...
    code, report, _, _ = _run(capsys, exact[:-4])
    assert report["candidates"][0]["rmse_deg"] > 0.5
    # ... and each horizon option changes the computed profile: a 300 m eye lowers the wall's angle,
    # a longer step misses its near edge, a short range never reaches it
    for flag, value in (("--eye-height", "300"), ("--step", "700"), ("--max-distance", "1000"),
                        ("--azimuth-step", "45")):       # a coarse candidate profile, interpolated
        argv = list(exact)
        argv[argv.index(flag) + 1] = value
        code, report, _, _ = _run(capsys, argv)
        center = {c["name"]: c for c in report["candidates"]}["center"]
        assert center["rmse_deg"] > 0.05, flag
    curved = [a for a in exact if a != "--no-curvature"]
    code, report, _, _ = _run(capsys, curved)
    assert {c["name"]: c for c in report["candidates"]}["center"]["rmse_deg"] > 1e-4
    # the tolerance decides what counts as a fitting sample: the far-west observer fits at 30 deg, not at 3
    west = lambda rep: {c["name"]: c for c in rep["candidates"]}["west"]["within_tolerance_fraction"]
    code, loose, _, _ = _run(capsys, exact + ["--tolerance", "30"])
    code, default, _, _ = _run(capsys, exact)
    assert west(loose) == 1.0 and west(default) < 1.0
    # an explicit --dem beats the dataset; a missing one is a blocked result
    code, report, result, _ = _run(capsys, ["skyline", str(observed), str(candidates), "--dem", str(tmp_path / "x.json")])
    assert result.status == "blocked" and "DEM not found" in result.notes


# --------------------------------------------------------------------------- opener

SIGN_TEXT = "LUNA COFFEE\nopen daily 8-20\nPiata Mare 4\nBRAVA mercado\nle zed\n"


def test_open_clues_finds_brands_and_named_features_in_sign_text(tmp_path):
    root = _dataset(tmp_path)
    report = GEO.open_clues(SIGN_TEXT, dataset_root=root)
    brands = [(c["brand"], c["match_kind"]) for c in report["brand_candidates"]]
    # whole brand names first (Luna Coffee, and the three-letter Zed), then a brand sharing a word
    assert brands == [("Luna Coffee", "exact"), ("Luna Coffee", "exact"), ("Zed", "exact"), ("Brava Fuel", "word")]
    # named features whose whole name is on the sign, longest name first; "Le" is too short to count
    assert [(c["id"], c["matched_text"]) for c in report["osm_name_candidates"]] == [
        ("node/1", "luna coffee"), ("node/2", "piata mare")]
    assert report["candidate_count"] == 6
    assert {c["source_kind"] for c in report["candidates"]} == {"brand", "osm_name"}
    assert report["extract"]["rows_read"] == 4
    assert report["automatic_answer"] is None and report["requires_human_pin"] is True


def test_open_clues_takes_osint_geo_clues_and_orders_by_a_gps_fix(tmp_path):
    root = _dataset(tmp_path)
    clues = {"ocr_text": "", "candidate_names": ["Luna Coffee"], "place_words": ["Kestrel Lookout 2 km"]}
    report = GEO.open_clues(clues, dataset_root=root, near=(44.4300, 26.0960))
    assert [c["name"] for c in report["brand_candidates"]] == ["Luna Coffee Old Town", "Luna Coffee Riverside"]
    assert report["brand_candidates"][0]["distance_m"] < 1.0
    assert [c["id"] for c in report["osm_name_candidates"]] == ["node/3", "node/1"]     # the longer name first
    # names of one length: the one nearest the GPS fix first
    twins = _write_jsonl(tmp_path / "twins.jsonl", [
        {"type": "node", "id": 7, "lat": 10.0, "lon": 10.0, "tags": {"name": "Stadtbad"}},
        {"type": "node", "id": 8, "lat": 20.0, "lon": 20.0, "tags": {"name": "Stadtbad"}}])
    for near, order in (((20.0, 20.1), ["node/8", "node/7"]), ((10.0, 10.1), ["node/7", "node/8"])):
        got = GEO.open_clues("STADTBAD", extract_path=twins, sources=("osm",), near=near)
        assert [c["id"] for c in got["osm_name_candidates"]] == order
    nothing = GEO.open_clues("lorem ipsum dolor", dataset_root=root)
    assert nothing["candidate_count"] == 0 and nothing["candidates"] == []
    with pytest.raises(GEO.GeoLocateError, match="no OCR text"):
        GEO.open_clues("   \n", dataset_root=root)


def test_open_clues_sources_and_missing_dataset_files(tmp_path):
    root = _dataset(tmp_path)
    (root / "osm.jsonl").unlink()
    with pytest.raises(GEO.GeoLocateError, match="OSM extract not found"):
        GEO.open_clues(SIGN_TEXT, dataset_root=root)                 # a missing source is an error ...
    only = GEO.open_clues(SIGN_TEXT, dataset_root=root, sources=("brands",))    # ... unless it was not asked for
    assert only["brand_candidate_count"] == 4 and only["osm_name_candidates"] == [] and only["extract"] is None
    with pytest.raises(GEO.GeoLocateError, match="sources must be drawn from"):
        GEO.open_clues(SIGN_TEXT, dataset_root=root, sources=("maps",))


def test_open_image_needs_ocr_or_supplied_text(tmp_path, monkeypatch):
    root = _dataset(tmp_path)
    from PIL import Image
    image = tmp_path / "blank.png"
    Image.new("RGB", (64, 64), "white").save(image)
    supplied = GEO.open_image(image, ocr_text=SIGN_TEXT, dataset_root=root)
    assert supplied["ocr_source"] == "supplied" and supplied["brand_candidate_count"] == 4
    assert supplied["image"] == str(image) and supplied["exif_gps"] is None
    assert supplied["ocr_chars"] == len(SIGN_TEXT.strip())
    # an EXIF GPS fix (here: at the Old Town branch) orders the candidates; without one, by name
    assert [c["name"] for c in supplied["brand_candidates"][:2]] == ["Luna Coffee Old Town", "Luna Coffee Riverside"]
    tagged = tmp_path / "tagged.jpg"
    for lat_dms, lon_dms, first in (((44.0, 25.0, 48.0), (26.0, 5.0, 45.6), "Luna Coffee Old Town"),
                                    ((44.0, 25.0, 36.48), (26.0, 6.0, 9.0), "Luna Coffee Riverside")):
        exif = Image.Exif()
        gps = exif.get_ifd(0x8825)
        gps[1], gps[2], gps[3], gps[4] = "N", lat_dms, "E", lon_dms
        Image.new("RGB", (64, 64), "white").save(tagged, exif=exif)
        located = GEO.open_image(tagged, ocr_text=SIGN_TEXT, dataset_root=root)
        assert located["exif_gps"] == pytest.approx([lat_dms[0] + lat_dms[1] / 60 + lat_dms[2] / 3600,
                                                     lon_dms[0] + lon_dms[1] / 60 + lon_dms[2] / 3600], abs=1e-6)
        assert located["brand_candidates"][0]["name"] == first
        assert located["brand_candidates"][0]["distance_m"] < 5.0
    # no tesseract: a named error, not an empty candidate list
    monkeypatch.setattr(GEO.shutil, "which", lambda name: None)
    with pytest.raises(GEO.GeoLocateError, match="tesseract not installed"):
        GEO.open_image(image, dataset_root=root)
    with pytest.raises(GEO.GeoLocateError, match="give an image"):
        GEO.open_image(dataset_root=root)
    with pytest.raises(GEO.GeoLocateError, match="image not found"):
        GEO.open_image(tmp_path / "absent.png", ocr_text="x", dataset_root=root)


@pytest.mark.needs_tool("tesseract", "py:PIL")
def test_open_image_reads_a_drawn_sign_with_tesseract(tmp_path):
    from PIL import Image, ImageDraw, ImageFont
    image = tmp_path / "sign.png"
    canvas = Image.new("RGB", (1400, 420), "white")
    ImageDraw.Draw(canvas).text((60, 120), "LUNA COFFEE", fill="black", font=ImageFont.load_default(size=150))
    canvas.save(image)
    report = GEO.open_image(image, dataset_root=_dataset(tmp_path))
    assert report["ocr_source"] == "tesseract" and report["ocr_chars"] > 0
    assert {c["brand"] for c in report["brand_candidates"] if c["match_kind"] == "exact"} == {"Luna Coffee"}
    assert "node/1" in [c["id"] for c in report["osm_name_candidates"]]


def test_cli_open_with_supplied_text(tmp_path, capsys):
    root = _dataset(tmp_path)
    text = tmp_path / "sign.txt"
    text.write_text(SIGN_TEXT, encoding="utf-8")
    code, report, result, _ = _run(capsys, ["open", "--ocr-text", str(text), "--dataset", str(root)])
    assert code == 0 and report["kind"] == "ocr_open" and report["candidate_count"] == 6
    assert result.status == "unsure" and "6 candidate(s)" in result.notes
    code, report, result, _ = _run(capsys, ["open", "--ocr-text", str(text), "--dataset", str(root), "--only", "osm"])
    assert report["brand_candidates"] == [] and len(report["osm_name_candidates"]) == 2
    code, report, result, _ = _run(capsys, ["open", "--dataset", str(root)])
    assert result.status == "blocked" and "--ocr-text" in result.notes
    code, report, result, _ = _run(capsys, ["open", "--ocr-text", str(tmp_path / "nope.txt"), "--dataset", str(root)])
    assert result.status == "blocked" and "OCR text file not found" in result.notes


# --------------------------------------------------------------------------- brand directory builder

def _business_extract(tmp_path: Path) -> Path:
    return _write_jsonl(tmp_path / "region.jsonl", [
        {"type": "node", "id": 1, "lat": 1.0, "lon": 1.0, "tags": {"shop": "supermarket", "brand": "Zentro Markt", "name": "Zentro Markt Nord",
                                                                   "addr:street": "Hauptweg", "addr:housenumber": "5", "addr:city": "Teststadt", "addr:country": "DE"}},
        {"type": "way", "id": 2, "center": {"lat": 2.0, "lon": 2.0}, "tags": {"shop": "supermarket", "brand": "ZENTRO  markt"}},
        {"type": "node", "id": 3, "lat": 3.0, "lon": 3.0, "tags": {"amenity": "fuel", "operator": "Zentro Markt", "name": "Tank Ost"}},
        {"type": "node", "id": 4, "lat": 4.0, "lon": 4.0, "tags": {"amenity": "cafe", "name": "Blue Door Cafe"}},
        {"type": "node", "id": 5, "lat": 5.0, "lon": 5.0, "tags": {"highway": "residential", "name": "Long Street"}},
        {"type": "node", "id": 6, "tags": {"shop": "kiosk", "brand": "Nowhere"}},
    ])


def test_build_brand_directory_from_brand_operator_and_business_names(tmp_path):
    directory, stats = GEO.build_brand_directory(_business_extract(tmp_path))
    assert sorted(directory) == ["Blue Door Cafe", "Tank Ost", "Zentro Markt", "Zentro Markt Nord"]
    zentro = directory["Zentro Markt"]                    # brand twice (case and spacing folded), operator once
    assert [row["osm_id"] for row in zentro] == ["node/1", "way/2", "node/3"]
    assert zentro[0] == {"name": "Zentro Markt Nord", "lat": 1.0, "lon": 1.0, "country": "DE",
                         "address": "Hauptweg 5 Teststadt", "osm_id": "node/1"}
    assert zentro[1]["name"] == "Zentro Markt" and zentro[2]["name"] == "Tank Ost"
    assert "Long Street" not in directory                 # a named street is not a business
    assert stats["rows_read"] == 6 and stats["features"] == 5 and stats["labels"] == 4
    assert stats["skipped"] == {"no usable coordinates (no lat/lon, center, geometry or bounds)": 1}
    assert stats["truncated"] == {}
    only_brand, _ = GEO.build_brand_directory(_business_extract(tmp_path), keys=("brand",))
    assert sorted(only_brand) == ["Zentro Markt"] and len(only_brand["Zentro Markt"]) == 2
    with pytest.raises(GEO.GeoLocateError, match="brand key must be one of"):
        GEO.build_brand_directory(_business_extract(tmp_path), keys=("website",))


def test_built_directory_round_trips_through_the_resolver(tmp_path):
    directory, _ = GEO.build_brand_directory(_business_extract(tmp_path))
    out = GEO.write_brand_directory(directory, tmp_path / "brands.json")
    report = GEO.resolve_brand("zentro markt", directory=GEO.load_brand_directory(out), near=(3.0, 3.0))
    assert [c["osm_id"] for c in report["candidates"]] == ["node/3", "way/2", "node/1"]
    assert report["candidates"][2]["address"] == "Hauptweg 5 Teststadt"
    with pytest.raises(GEO.GeoLocateError, match="exists; pass force"):
        GEO.write_brand_directory({}, out)
    GEO.write_brand_directory({"Solo": [{"name": "Solo", "lat": 0.0, "lon": 0.0}]}, out, force=True)
    assert list(GEO.load_brand_directory(out)) == ["solo"]


def test_build_brand_directory_reports_what_it_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(GEO, "MAX_CANDIDATES", 2)
    directory, stats = GEO.build_brand_directory(_business_extract(tmp_path))
    assert len(directory["Zentro Markt"]) == 2 and stats["truncated"] == {"Zentro Markt": 3}


def test_cli_build_brands_writes_the_file(tmp_path, capsys):
    out = tmp_path / "brands.json"
    code, report, result, _ = _run(capsys, ["build-brands", str(_business_extract(tmp_path)), "--out", str(out)])
    assert code == 0 and report["kind"] == "brand_directory_built" and report["stats"]["labels"] == 4
    assert result.status == "none" and "4 brand label(s)" in result.notes
    assert sorted(json.loads(out.read_text())) == ["Blue Door Cafe", "Tank Ost", "Zentro Markt", "Zentro Markt Nord"]
    code, report, result, _ = _run(capsys, ["build-brands", str(_business_extract(tmp_path)), "--out", str(out)])
    assert result.status == "blocked" and "--force" in result.notes
    code, report, result, _ = _run(capsys, ["build-brands", str(_business_extract(tmp_path)), "--out", str(out), "--force"])
    assert result.status == "none"


# --------------------------------------------------------------------------- check (the page's own checker)

TARGET = (12.3456, 65.4321)          # an invented pin
PAGE_HTML = ("<html><script src='leaflet.js'></script><script>var m = L.map('map');"
             "fetch('?check=1', {method: 'POST', body: new URLSearchParams({lat: p.lat, lon: p.lng})})"
             "</script></html>")


def _serve_page(page_html=PAGE_HTML, lat="lat", lon="lon", json_body=False):
    """A map-pin page on 127.0.0.1: GET is `page_html`; POST judges the pin read from the fields
    `lat` / `lon` of a form body (or a JSON body). Returns (server, page URL, posts)."""
    posts = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, status, body, ctype):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._reply(200, page_html, "text/html")

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            try:
                fields = json.loads(raw) if json_body else {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                pin = (float(fields[lat]), float(fields[lon]))
            except (ValueError, KeyError, TypeError):
                posts.append((self.path, raw))
                self._reply(400, json.dumps({"ok": False, "message": "bad request"}), "application/json")
                return
            posts.append((self.path, fields))
            near = abs(pin[0] - TARGET[0]) < 0.001 and abs(pin[1] - TARGET[1]) < 0.001
            self._reply(200, json.dumps({"ok": near, "message": "spooky{synthetic_pin}" if near else "too far"}),
                        "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/pin/", posts


@pytest.fixture
def fake_page():
    server, url, posts = _serve_page()
    yield url, posts
    server.shutdown()
    server.server_close()


def _inject_gate(monkeypatch, submit_mode):
    """Put the real SubmitGate, over a recording adapter and a profile written here, behind the CLI's
    `check --submit`, so no test depends on a real event's submit mode. Returns what the adapter got."""
    import datetime as dt
    from ctf import event, platform
    from ctf.platform.base import SubmitResult, SubmitStatus

    sent = []

    class Adapter:
        kind = "ctfd"

        def submit(self, challenge_id, flag):
            sent.append((challenge_id, flag))
            return SubmitResult(SubmitStatus.CORRECT, "ok")

    prof = event.parse({"slug": f"geo-{submit_mode}", "name": f"{submit_mode} mode",
                        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
                        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
                        "flag": {"prefixes": ["spooky"]},
                        "rules": {"submit_mode": submit_mode, "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                                  "live_service_scope": ["127.0.0.1"]}}, src="<test>")
    gate = platform.SubmitGate(Adapter(), prof)
    real = GEO.check_and_submit
    monkeypatch.setattr(GEO, "check_and_submit", lambda *a, **kw: real(*a, gate=gate, **kw))
    return sent


def test_cli_check_posts_the_pin_and_reports_the_flag_as_solved(fake_page, tmp_path, capsys, monkeypatch):
    url, posts = fake_page
    sent = _inject_gate(monkeypatch, "manual")             # the gate is this test's own, never a real event's
    monkeypatch.setenv("CTF_EVENT", "spooky")              # read for the spooky{...} flag format only
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    code, report, result, _ = _run(capsys, ["check", url, "chal-4", "48.0", "11.0", "--provenance", "first guess"])
    assert code == 0 and report["check"]["ok"] is False and report["check"]["attempts_left"] == 2
    assert result.status == "none" and "2 check(s) left" in result.notes and result.challenge_id == "chal-4"
    assert report["detection"]["signals"] == ["leaflet"] and report["submit"] is None
    code, report, result, _ = _run(capsys, ["check", url, "chal-4", str(TARGET[0]), str(TARGET[1]),
                                            "--provenance", "model named the venue", "--submit", "--confirm"])
    assert code == 0 and result.status == "solved" and result.flags == ("spooky{synthetic_pin}",)
    assert result.evidence[0].kind == "oracle" and result.challenge_id == "chal-4"
    # the flag went to the submit gate, which refuses a manual event before the adapter is called
    assert report["submit"] == {"status": "not_allowed", "sent": False, "accepted": False,
                                "message": report["submit"]["message"]}
    assert "manual" in report["submit"]["message"] and "not_allowed" in result.notes
    assert sent == []
    assert [path for path, _ in posts] == ["/pin/?check=1", "/pin/?check=1"]
    assert posts[1][1] == {"lat": "12.3456", "lon": "65.4321"}
    # the cap is the ledger's: a third pin passes, a fourth is a blocked result and never reaches the page
    _run(capsys, ["check", url, "chal-4", "47.0", "10.0", "--provenance", "p"])
    code, report, result, err = _run(capsys, ["check", url, "chal-4", "46.0", "9.0", "--provenance", "p"])
    assert code == 0 and result.status == "blocked" and "used 3 of 3" in result.notes
    assert len(posts) == 3
    events = [r["event"] for r in ledger.read(tmp_path / "work")]
    assert events.count("geo.check") == 3


def test_cli_check_passes_confirm_through_to_the_gate(fake_page, tmp_path, capsys, monkeypatch):
    """--submit sends the checker's flag through the gate; --confirm (and only --confirm) is the
    player's confirmation. The gate is the real one over a recording adapter, in confirm mode."""
    sent = _inject_gate(monkeypatch, "confirm")
    url, posts = fake_page
    monkeypatch.setenv("CTF_EVENT", "spooky")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    pin = [str(TARGET[0]), str(TARGET[1])]
    code, report, result, _ = _run(capsys, ["check", url, "chal-7", *pin, "--provenance", "p", "--submit"])
    assert result.status == "solved" and report["submit"]["sent"] is False and "confirm" in report["submit"]["message"]
    assert sent == []
    code, report, result, _ = _run(capsys, ["check", url, "chal-7", str(TARGET[0] + 0.0001), pin[1],
                                            "--provenance", "p", "--submit", "--confirm"])
    assert report["submit"]["status"] == "correct" and report["submit"]["sent"] is True
    assert sent == [("chal-7", "spooky{synthetic_pin}")]
    assert "submit gate: correct (sent=True)" in result.notes


def test_cli_check_with_a_named_endpoint_and_without_submit(fake_page, tmp_path, capsys, monkeypatch):
    url, posts = fake_page
    monkeypatch.setenv("CTF_EVENT", "spooky")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    base = ["check", url, "chal-5", str(TARGET[0]), str(TARGET[1]), "--provenance", "p",
            "--check-url", url + "?check=1", "--max-attempts", "1"]
    named = ["--encoding", "form", "--lat-field", "lat", "--lon-field", "lon"]
    # --check-url skips reading the page, so nothing says what the endpoint takes: each must be named
    for cut in (0, 2, 4):
        code, report, result, err = _run(capsys, base + named[:cut] + named[cut + 2:])
        assert code == 0 and result.status == "blocked" and f"{named[cut]} must be named" in result.notes
    code, report, result, err = _run(capsys, base)
    assert result.status == "blocked" and "--encoding, --lat-field, --lon-field must be named" in result.notes
    assert posts == [] and list(ledger.read(tmp_path / "work")) == []
    code, report, result, _ = _run(capsys, base + named)
    assert result.status == "solved" and report["detection"] is None
    assert report["submit"] is None and report["submit_skipped"] == "no --submit"
    assert "not submitted: no --submit" in result.notes and report["check"]["attempts_left"] == 0
    code, report, result, _ = _run(capsys, ["check", "http://198.18.0.1/pin/", "chal-6", "1", "1", "--provenance", "p"])
    assert code == 0 and result.status == "blocked" and "live_service_scope" in result.notes
    assert len(posts) == 1


BARE_PAGE = ("<html><script src='leaflet.js'></script><script>L.map('map').on('click', "
             "e => fetch('?check=1', {method: 'POST', body: pack(e.latlng)}))</script></html>")


def test_cli_check_names_what_the_page_does_not_show(tmp_path, capsys, monkeypatch):
    """A page that shows its endpoint but not its field names or encoding: `check` posts nothing on a
    guess, and --lat-field / --lon-field / --encoding each reach the checker when the page is read."""
    server, url, posts = _serve_page(BARE_PAGE, lat="y", lon="x", json_body=True)
    try:
        monkeypatch.setenv("CTF_EVENT", "spooky")
        monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
        base = ["check", url, "chal-8", str(TARGET[0]), str(TARGET[1]), "--provenance", "p"]
        named = ["--lat-field", "y", "--lon-field", "x", "--encoding", "json"]
        code, report, result, err = _run(capsys, base)
        assert code == 0 and report is None and result.status == "blocked"
        for flag in ("--lat-field", "--lon-field", "--encoding"):
            assert flag in result.notes and flag in err
        for cut in (0, 2, 4):                      # any one left out is still a guess
            code, report, result, err = _run(capsys, base + named[:cut] + named[cut + 2:])
            assert result.status == "blocked" and named[cut] in result.notes, named[cut]
        assert posts == [] and list(ledger.read(tmp_path / "work")) == []
        code, report, result, err = _run(capsys, base + named)
        assert result.status == "solved" and result.flags == ("spooky{synthetic_pin}",)
        assert posts == [("/pin/?check=1", {"y": 12.3456, "x": 65.4321})]
        assert report["detection"]["fields_source"] == "default" and report["check"]["attempts_left"] == 2
    finally:
        server.shutdown()
        server.server_close()


def test_cli_check_raising_the_cap_needs_a_note_that_reaches_the_ledger(fake_page, tmp_path, capsys, monkeypatch):
    url, posts = fake_page
    monkeypatch.setenv("CTF_EVENT", "spooky")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    base = ["check", url, "chal-9", "48.0", "11.0", "--provenance", "p", "--max-attempts", "5"]
    code, report, result, err = _run(capsys, base)
    assert code == 0 and result.status == "blocked" and "--cap-note" in result.notes and posts == []
    code, report, result, err = _run(capsys, base + ["--cap-note", "player: five tries, no penalty"])
    assert result.status == "none" and report["check"]["attempts_left"] == 4
    caps = [r for r in ledger.read(tmp_path / "work") if r["event"] == "geo.check_cap_raised"]
    assert [(r["challenge_id"], r["max_checks"], r["default_checks"], r["note"]) for r in caps] == [
        ("chal-9", 5, 3, "player: five tries, no penalty")]
    # without --max-attempts the event's default holds again: 1 of 3 used
    code, report, result, err = _run(capsys, ["check", url, "chal-9", "47.0", "10.0", "--provenance", "p"])
    assert report["check"]["attempts_left"] == 1 and len(posts) == 2
    # the note is taken on the --check-url road too
    named = ["--check-url", url + "?check=1", "--encoding", "form", "--lat-field", "lat", "--lon-field", "lon"]
    again = ["check", url, "chal-9", "46.0", "9.0", "--provenance", "p", "--max-attempts", "4"]
    code, report, result, err = _run(capsys, again + named)
    assert result.status == "blocked" and "--cap-note" in result.notes and len(posts) == 2
    code, report, result, err = _run(capsys, again + named + ["--cap-note", "player: one more"])
    assert result.status == "none" and report["check"]["attempts_left"] == 1 and len(posts) == 3
    caps = [r for r in ledger.read(tmp_path / "work") if r["event"] == "geo.check_cap_raised"]
    assert [(r["max_checks"], r["note"]) for r in caps] == [(5, "player: five tries, no penalty"), (4, "player: one more")]


# --------------------------------------------------------------------------- through the engine runner

def _ctf_run(args, workdir):
    env = dict(os.environ, CTF_WORKDIR=str(workdir), CTF_EVENT="csctf")
    env.pop("CTF_GEO_DATASET", None)
    return subprocess.run([sys.executable, "-m", "ctf", "run", *args], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=600)


def test_engine_runner_parses_the_solver_result_and_records_its_status(tmp_path):
    root = _dataset(tmp_path)
    work = tmp_path / "work"
    proc = _ctf_run(["toolkits.osint_geolocate", "brand", "Luna Coffee", "--dataset", str(root)], work)
    assert proc.returncode == 0, proc.stderr
    assert "did not end with a SolverResult" not in proc.stderr
    assert SolverResult.from_json(proc.stdout.strip().splitlines()[-1]).status == "unsure"
    runs = [r for r in ledger.read(work) if r["event"] == "engine.run"]
    assert [(r["engine"], r["exit_code"], r["status"]) for r in runs] == [("toolkits.osint_geolocate", 0, "unsure")]
    # no dataset configured: still exit 0, recorded as blocked
    proc = _ctf_run(["toolkits.osint_geolocate", "brand", "Luna Coffee"], work)
    assert proc.returncode == 0 and "CTF_GEO_DATASET" in proc.stderr
    runs = [r for r in ledger.read(work) if r["event"] == "engine.run"]
    assert [r["status"] for r in runs] == ["unsure", "blocked"]


def test_manifest_declares_an_analysis_cli_engine():
    from ctf.engines import manifest
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.osint_geolocate"]
    assert m.capabilities[0] == "analysis" and m.has("cli") and not m.has("legacy-output")
    assert math.isclose(max(r.effective_priority for r in m.routes), 61)


@pytest.mark.parametrize("brief, priority", [
    ("Wanderlust. Find the spot.", 42),                           # no geolocation word at all
    ("We lost our friend on holiday: drop the pin on the map where she stood.", 42),
    ("A reverse image search will not be enough. Where was this taken?", 61),      # the keyword nudge
])
def test_router_offers_the_engine_for_any_osint_brief(brief, priority):
    """The handout lists only routed engines, and a geolocation brief rarely says "geolocation": the
    engine is routed for every OSINT challenge at a low priority, and higher on its keywords."""
    from ctf.engines import router
    hits = {h.manifest.id: h for h in router.route("osint", brief, root=REPO)}
    assert hits["toolkits.osint_geolocate"].priority == priority
    # ... below its offline siblings on the bare category, and not at all outside OSINT
    if priority == 42:
        assert hits["toolkits.osint_geo"].priority > 42 and hits["toolkits.osint_geo_math"].priority > 42
    assert "toolkits.osint_geolocate" not in {h.manifest.id for h in router.route("crypto", brief, root=REPO)}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
