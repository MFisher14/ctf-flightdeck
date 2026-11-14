#!/usr/bin/env python3
"""Frozen-dataset geolocation resolvers for OSINT reverse-image challenges (B-113).

An image-geolocation challenge hands you a photo, or a story, and asks *where is this*.  The offline
clue extraction (EXIF, tiled OCR, a search plan) lives in :mod:`osint_geo`; the reverse-image manifest
and the manual-caption ingest live in :mod:`osint_depth`; sun/shadow and skyline-profile ranking live
in :mod:`osint_geo_math` and :mod:`osint_depth`.  This module is the part that works over a *frozen
dataset at a configured path outside the repo* (``$CTF_GEO_DATASET`` via
:func:`ctf.paths.geo_dataset_root`; unset or missing fails loudly, naming the variable):

  (1) OPENER.  ``open_image`` / ``open_clues`` chain osint_geo's tiled sign OCR into brand and OSM
      name candidates: every brand of the frozen directory and every named OSM feature whose name
      appears in the OCR text comes back as a located candidate.
  (2) BRAND -> MAPS.  A recognised shopfront brand resolves to candidate store locations from the
      frozen brand directory (``brands.json``; ``build_brand_directory`` cuts one from an OSM
      extract's brand / operator / name tags).
  (3) OSM / OVERPASS CONSTRAINT SOLVER.  Structured constraints -- tags, name substrings, a bbox or
      near+radius, polygon perimeter and area ranges, and distance joins to other feature classes
      ("a church 400-1000 m away", "under 6 km from a university") -- are solved against a frozen
      OSM extract (``osm.jsonl``).  ``online=True`` sends the same constraints to live Overpass, but
      only after :func:`ctf.scope.check_public_fetch` clears the host (and every redirect) against the
      event profile's ``rules.public_fetch_allow``; an ``[date:...]`` attic snapshot and a snapshot
      sweep cover challenges written against an older map.  ``name_variants`` enumerates the
      spellings of a feature's name (name tags, umlaut digraphs, ASCII) for a ``prefix{NAME}`` flag;
      ``resolve_venue`` turns a named venue into its polygon centre and entrances.
  (4) DEM SKYLINE MATCHER.  A measured skyline profile is matched against horizon profiles ray-cast
      from a frozen DEM (SRTM ``.hgt`` tiles, read in pure Python, or a JSON grid) at each candidate
      observer coordinate, ranked through :func:`osint_depth.rank_terrain_horizons`.
  (5) CHECKER POST.  Once a model or player *names* a coordinate, ``check`` posts it to the
      challenge page's own map-pin checker (:mod:`_osint_geo_checker`: live-target scope guard, a
      per-challenge attempt cap, pacing), reads the flag from the JSON reply and, with ``--submit``,
      sends that flag through the submit gate (``submit_named_location``).  A plain venue or
      coordinate answer for the platform itself goes through ``python -m ctf submit <id> <value>
      --note <why> --nonstandard``: this module adds no second submit command.

None of this decides *which* venue or post is the answer -- that identification is the human/model
judgment the hard-tail blocker names.  Every resolver returns ranked evidence with
``requires_human_pin=True`` and ``automatic_answer=None``.  Challenge images are never uploaded to a
third party.

CLI.  Each command prints its report as indented JSON, then one ``SolverResult`` JSON line (the last
stdout line, docs/CONTRACTS.md section 6) and exits 0: ``unsure`` when it has candidates for a human
or model to read, ``none`` when it has none, ``solved`` when the page checker returned a flag,
``blocked`` (the reason in ``notes`` and on stderr) when the dataset, a tool, the scope or an input is
missing or wrong.  A usage error (unknown command or option) exits 2.

  osint_geolocate.py open [IMAGE] [--ocr-text FILE] [--dataset DIR]
  osint_geolocate.py brand "Luna Coffee" [--near LAT LON] [--dataset DIR] [--directory FILE]
  osint_geolocate.py osm CONSTRAINTS.json [--dataset DIR] [--extract FILE] [--online] [--date ISO]
  osint_geolocate.py sweep CONSTRAINTS.json [--snapshot LABEL=FILE]... | --online --date ISO...
  osint_geolocate.py venue "Luna Sports Hall" [--near LAT LON] [--dataset DIR] [--extract FILE]
  osint_geolocate.py variants "Grün Werk" [--tags TAGS.json]
  osint_geolocate.py skyline OBSERVED.json CANDIDATES.json [--dem PATH] [--dataset DIR]
                             [--eye-height M] [--step M] [--max-distance M] [--azimuth-step DEG]
                             [--no-curvature] [--north-offset DEG]...
  osint_geolocate.py build-brands EXTRACT --out brands.json [--force]
  osint_geolocate.py check PAGE_URL CHALLENGE_ID LAT LON --provenance NOTE [--check-url URL]
                             [--encoding form|json] [--lat-field NAME] [--lon-field NAME]
                             [--max-attempts N --cap-note WHY] [--submit] [--confirm]

``check`` reads the page for the endpoint, the field names and the encoding, and posts nothing on a
guess: what the page does not show must be named (with ``--check-url`` the page is not read, so all
three are).  Posts are capped per challenge and per checker endpoint; a cap above the event's default
needs ``--cap-note`` (the player's say), which goes to the ledger.
"""
from __future__ import annotations

import argparse
import array
import bisect
import datetime as _dt
import json
import math
import re
import shutil
import sys
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths, scope
except ModuleNotFoundError:  # pragma: no cover - only when run as a bare file off the path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import paths, scope
from ctf import event as _event, flagcheck as _flagcheck, flagfmt as _flagfmt
from ctf.platform.base import PlatformError, SubmitResult, SubmitStatus
from ctf.result import Evidence, ResultError, SolverResult

import osint_geo_math as geo_math  # EARTH_RADIUS_M
import osint_depth as depth  # rank_terrain_horizons
import _osint_geo_checker as checker  # the map-pin checker client

ENGINE = "toolkits.osint_geolocate"
EARTH_RADIUS_M = geo_math.EARTH_RADIUS_M
METRES_PER_DEGREE = EARTH_RADIUS_M * math.pi / 180.0

# Bounds (untrusted dataset / caller input is always bounded before use).
MAX_DATASET_BYTES = 256 * 1024 * 1024
MAX_POI_ROWS = 5_000_000
MAX_CANDIDATES = 2_000
MAX_JOIN_FEATURES = 500_000
MAX_JOINS = 8
MAX_RESULTS = 200
MAX_TEXT = 512
MAX_TAGS = 256
MAX_DEM_CELLS = 64_000_000
MAX_DEM_TILES = 64
MAX_AZIMUTHS = 720
MAX_SNAPSHOTS = 12
MAX_ONLINE_DATES = 6
MAX_PHRASES = 20_000

# Default public Overpass endpoint.  A live query is sent here ONLY after scope.check_public_fetch
# clears the host against the event profile; it is never contacted from a test.
DEFAULT_OVERPASS_ENDPOINT = "https://overpass-api.de/api/interpreter"
OVERPASS_USER_AGENT = "Public-OSINT-Research-Client/1.0 (single-item; contact: none)"

# Default DEM horizon ray-casting parameters.
DEFAULT_EYE_HEIGHT_M = 1.7
DEFAULT_STEP_M = 30.0
DEFAULT_MAX_DISTANCE_M = 60_000.0
# Standard terrestrial-refraction coefficient: apparent curvature drop is reduced by this fraction.
DEFAULT_REFRACTION_COEFF = 0.13
HGT_NODATA = -32768
_PACKED_SUFFIXES = (".zip", ".gz", ".bz2", ".xz", ".7z")       # how DEM tiles are distributed

# Secret-shaped strings never go into a query for a public service (same shapes osint_online refuses).
_SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})", re.I)


class GeoLocateError(ValueError):
    """A resolver input or frozen-dataset file was missing, malformed, or out of bounds."""


class UsageError(GeoLocateError):
    """The command line itself is wrong (unknown command or option): exit 2, no result line."""


# =====================================================================================
#  Bounded parsing helpers
# =====================================================================================

def _text(value: Any, field: str, *, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise GeoLocateError(f"{field} must be text")
    raw = str(value)
    result = raw.strip()
    if not result or len(result) > limit or any(ord(ch) < 0x20 and ch not in "\t" for ch in raw):
        raise GeoLocateError(f"{field} is empty, overlong, or contains control characters")
    return result


def _finite(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise GeoLocateError(f"{field} must be a number, not a boolean")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GeoLocateError(f"{field} is not a number") from exc
    if not math.isfinite(number):
        raise GeoLocateError(f"{field} is not finite")
    return number


def _coordinate(value: Any, field: str = "coordinate") -> tuple[float, float]:
    if isinstance(value, Mapping):
        lat = value.get("lat", value.get("latitude"))
        lon = value.get("lon", value.get("longitude"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 2:
        lat, lon = value
    else:
        raise GeoLocateError(f"{field} must be a [lat, lon] pair or a lat/lon mapping")
    lat = _finite(lat, f"{field} latitude")
    lon = _finite(lon, f"{field} longitude")
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise GeoLocateError(f"{field} is outside Earth bounds")
    return lat, lon


def _opt_coordinate(value: Any, field: str = "coordinate") -> tuple[float, float] | None:
    if value in (None, ""):
        return None
    return _coordinate(value, field)


def _limit(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise GeoLocateError(f"limit must be 1..{MAX_RESULTS}") from exc
    if not 1 <= number <= MAX_RESULTS:
        raise GeoLocateError(f"limit must be 1..{MAX_RESULTS}")
    return number


def _as_list(value: Any, field: str, *, cap: int) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise GeoLocateError(f"{field} must be a list")
    rows = list(value)
    if len(rows) > cap:
        raise GeoLocateError(f"{field} has more than {cap} entries")
    return rows


def _read_json_file(path: Path, what: str) -> Any:
    if not path.is_file():
        raise GeoLocateError(f"{what} not found at {path}")
    size = path.stat().st_size
    if size > MAX_DATASET_BYTES:
        raise GeoLocateError(f"{what} at {path} exceeds the {MAX_DATASET_BYTES} byte cap")
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError) as exc:
        raise GeoLocateError(f"{what} at {path} is not readable JSON: {exc}") from exc


def _dataset_dir(dataset_root: str | Path | None) -> Path:
    """The frozen dataset directory, from an explicit override or $CTF_GEO_DATASET.

    No silent fallback: an absent dataset raises a named error (ctf.paths.require_geo_dataset)."""
    if dataset_root is not None:
        p = Path(dataset_root).expanduser()
        if not p.is_dir():
            raise GeoLocateError(f"geo dataset directory not found at {p}")
        return p
    try:
        return paths.require_geo_dataset()
    except FileNotFoundError as exc:
        raise GeoLocateError(str(exc)) from exc


def _human_report(kind: str, **fields: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        **fields,
        "automatic_answer": None,
        "requires_human_pin": True,
        "note": ("ranked evidence over a frozen dataset only; independently corroborate the scene "
                 "and let the player make the final location pin"),
    }


def _normalise(value: Any) -> str:
    return " ".join(str(value).casefold().split())


_normalise_brand = _normalise  # the name the first cut of this module used


# =====================================================================================
#  Geodesy: distance, destination point, polygon metrics
# =====================================================================================

def distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine great-circle distance in metres on a sphere of radius EARTH_RADIUS_M."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2.0 * EARTH_RADIUS_M * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


def destination_point(lat: float, lon: float, bearing_deg: float, distance_m: float) -> tuple[float, float]:
    """The point reached from (lat, lon) going `distance_m` along `bearing_deg` (deg clockwise from
    true north) on a sphere of radius EARTH_RADIUS_M.  Returns (lat, lon) in degrees."""
    phi1 = math.radians(lat)
    lam1 = math.radians(lon)
    theta = math.radians(bearing_deg % 360.0)
    delta = distance_m / EARTH_RADIUS_M
    sin_phi2 = math.sin(phi1) * math.cos(delta) + math.cos(phi1) * math.sin(delta) * math.cos(theta)
    sin_phi2 = max(-1.0, min(1.0, sin_phi2))
    phi2 = math.asin(sin_phi2)
    y = math.sin(theta) * math.sin(delta) * math.cos(phi1)
    x = math.cos(delta) - math.sin(phi1) * sin_phi2
    lam2 = lam1 + math.atan2(y, x)
    lat2 = math.degrees(phi2)
    lon2 = (math.degrees(lam2) + 540.0) % 360.0 - 180.0
    return lat2, lon2


def ring_metrics(ring: Sequence[tuple[float, float]]) -> dict[str, Any]:
    """Perimeter (haversine, metres), area (shoelace on a local equirectangular plane, square metres)
    and area centroid of a closed polygon ring of (lat, lon) vertices.  The ring is closed if it is
    not already.  Meant for building- to town-sized polygons; it does not handle the antimeridian."""
    points = list(ring)
    if len(points) >= 2 and points[0] == points[-1]:
        points = points[:-1]
    if len(points) < 3:
        raise GeoLocateError("a polygon ring needs at least three distinct vertices")
    lat0 = sum(p[0] for p in points) / len(points)
    lon0 = sum(p[1] for p in points) / len(points)
    scale = math.cos(math.radians(lat0))
    xy = [(math.radians(lon - lon0) * scale * EARTH_RADIUS_M, math.radians(lat - lat0) * EARTH_RADIUS_M)
          for lat, lon in points]
    perimeter = 0.0
    twice_area = cx = cy = 0.0
    for i, (lat, lon) in enumerate(points):
        nlat, nlon = points[(i + 1) % len(points)]
        perimeter += distance_m(lat, lon, nlat, nlon)
        x1, y1 = xy[i]
        x2, y2 = xy[(i + 1) % len(points)]
        cross = x1 * y2 - x2 * y1
        twice_area += cross
        cx += (x1 + x2) * cross
        cy += (y1 + y2) * cross
    if abs(twice_area) < 1e-9:
        centroid = (lat0, lon0)
    else:
        cx /= 3.0 * twice_area
        cy /= 3.0 * twice_area
        centroid = (lat0 + math.degrees(cy / EARTH_RADIUS_M),
                    lon0 + math.degrees(cx / (EARTH_RADIUS_M * scale)) if scale > 1e-12 else lon0)
    return {"perimeter_m": perimeter, "area_m2": abs(twice_area) / 2.0, "centroid": centroid}


# =====================================================================================
#  Frozen OSM extract: one normalised feature per row, with a count of what was skipped
# =====================================================================================

_OSM_TYPES = ("node", "way", "relation")
_LINE_SUFFIXES = (".jsonl", ".ndjson", ".geojsonl", ".geojsonseq")


def new_extract_stats() -> dict[str, Any]:
    return {"rows_read": 0, "features": 0, "skipped": {}}


def _skip(stats: dict[str, Any] | None, reason: str) -> None:
    if stats is not None:
        stats["skipped"][reason] = stats["skipped"].get(reason, 0) + 1


def _valid_latlon(lat: Any, lon: Any) -> tuple[float, float] | None:
    try:
        lat, lon = _finite(lat, "lat"), _finite(lon, "lon")
    except GeoLocateError:
        return None
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        return None
    return lat, lon


def _element_points(geometry: Any) -> list[tuple[float, float]]:
    """(lat, lon) vertices of an Overpass ``out geom`` geometry list."""
    points = []
    if isinstance(geometry, list):
        for vertex in geometry:
            if isinstance(vertex, Mapping):
                pair = _valid_latlon(vertex.get("lat"), vertex.get("lon"))
                if pair is not None:
                    points.append(pair)
    return points


def _geojson_positions(coords: Any, out: list[tuple[float, float]]) -> None:
    if (isinstance(coords, (list, tuple)) and len(coords) >= 2
            and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in coords[:2])):
        pair = _valid_latlon(coords[1], coords[0])      # GeoJSON is [lon, lat]
        if pair is not None:
            out.append(pair)
        return
    if isinstance(coords, (list, tuple)):
        for item in coords:
            _geojson_positions(item, out)


def _closed_ring(points: list[tuple[float, float]]) -> list[tuple[float, float]] | None:
    return points if len(points) >= 4 and points[0] == points[-1] else None


def _largest_ring(rings: list[list[tuple[float, float]]]) -> list[tuple[float, float]] | None:
    best, best_area = None, -1.0
    for points in rings:
        ring = _closed_ring(points)
        if ring is None:
            continue
        try:
            area = ring_metrics(ring)["area_m2"]
        except GeoLocateError:
            continue
        if area > best_area:
            best, best_area = ring, area
    return best


def _feature_name(raw: Any) -> tuple[str | None, bool]:
    """(name, ok).  A missing name is fine; a name with control characters or an absurd length is not."""
    if raw in (None, ""):
        return None, True
    if not isinstance(raw, (str, int, float)) or isinstance(raw, bool):
        return None, False
    text = str(raw)
    if len(text) > MAX_TEXT or any(ord(ch) < 0x20 and ch != "\t" for ch in text):
        return None, False
    return text.strip() or None, True


def normalise_feature(record: Any) -> tuple[dict[str, Any] | None, str | None]:
    """One extract row -> ``(feature, None)``, or ``(None, reason)`` when it cannot be a located feature.

    Accepted rows: a flat POI ``{id, lat, lon, name, tags}``; an Overpass element (a node with
    lat/lon; a way or relation with ``center``, with ``geometry`` from ``out geom``, or with
    ``bounds``); a GeoJSON ``Feature`` as ``osmium export`` writes it (Point, LineString, Polygon,
    MultiPolygon; tags in ``properties``).  A feature is ``{id, name, lat, lon, tags, ring,
    center_source}``: `ring` is the closed outer ring as (lat, lon) vertices when the row carries
    one, and the coordinate is then the polygon's area centroid."""
    if not isinstance(record, Mapping):
        return None, "not a JSON object"
    ring: list[tuple[float, float]] | None = None
    point: tuple[float, float] | None = None
    source = "point"
    if record.get("type") == "Feature":
        geometry = record.get("geometry")
        props = record.get("properties")
        props = props if isinstance(props, Mapping) else {}
        if not isinstance(geometry, Mapping):
            return None, "GeoJSON feature without a geometry"
        nested = props.get("tags")
        tags = nested if isinstance(nested, Mapping) else {k: v for k, v in props.items()
                                                           if not str(k).startswith("@")}
        raw_id = record.get("id", props.get("@id"))
        if props.get("@type") in _OSM_TYPES and props.get("@id") not in (None, ""):
            raw_id = f"{props['@type']}/{props['@id']}"
        gtype, coords = geometry.get("type"), geometry.get("coordinates")
        positions: list[tuple[float, float]] = []
        if gtype == "Polygon" and isinstance(coords, list) and coords:
            outer: list[tuple[float, float]] = []
            _geojson_positions(coords[0], outer)
            ring, positions = _closed_ring(outer), outer
        elif gtype == "MultiPolygon" and isinstance(coords, list):
            outers = []
            for polygon in coords:
                if isinstance(polygon, list) and polygon:
                    outer = []
                    _geojson_positions(polygon[0], outer)
                    outers.append(outer)
                    positions.extend(outer)
            ring = _largest_ring(outers)
        else:
            _geojson_positions(coords, positions)
            if gtype == "LineString":
                ring = _closed_ring(positions)
        if not positions:
            return None, "GeoJSON feature without usable coordinates"
        raw_name = tags.get("name")
        if ring is None:
            point = (sum(p[0] for p in positions) / len(positions),
                     sum(p[1] for p in positions) / len(positions))
            source = "point" if gtype == "Point" else "vertex_mean"
    else:
        raw_tags = record.get("tags")
        tags = raw_tags if isinstance(raw_tags, Mapping) else {}
        raw_id = record.get("id")
        if record.get("type") in _OSM_TYPES and raw_id not in (None, ""):
            raw_id = f"{record['type']}/{raw_id}"
        raw_name = record.get("name") or tags.get("name")
        points = _element_points(record.get("geometry"))
        ring = _closed_ring(points)
        if ring is None:
            point = _valid_latlon(record.get("lat", record.get("latitude")),
                                  record.get("lon", record.get("longitude")))
            if point is None and isinstance(record.get("center"), Mapping):
                point = _valid_latlon(record["center"].get("lat"), record["center"].get("lon"))
                source = "center"
            if point is None and points:
                point = (sum(p[0] for p in points) / len(points), sum(p[1] for p in points) / len(points))
                source = "vertex_mean"
            if point is None and isinstance(record.get("bounds"), Mapping):
                b = record["bounds"]
                south = _valid_latlon(b.get("minlat"), b.get("minlon"))
                north = _valid_latlon(b.get("maxlat"), b.get("maxlon"))
                if south is not None and north is not None:
                    point = ((south[0] + north[0]) / 2.0, (south[1] + north[1]) / 2.0)
                    source = "bounds"
            if point is None:
                return None, "no usable coordinates (no lat/lon, center, geometry or bounds)"
    metrics = None
    if ring is not None:
        try:
            metrics = ring_metrics(ring)
        except GeoLocateError:
            return None, "degenerate polygon ring"
        point, source = metrics["centroid"], "polygon_centroid"
    name, ok = _feature_name(raw_name)
    if not ok:
        return None, "bad name (control characters or overlong)"
    if len(tags) > MAX_TAGS:
        return None, f"more than {MAX_TAGS} tags"
    assert point is not None
    feature = {
        "id": None if raw_id in (None, "") else str(raw_id),
        "name": name,
        "lat": point[0],
        "lon": point[1],
        "tags": {str(k): str(v) for k, v in tags.items()},
        "ring": ring,
        "center_source": source,
    }
    if metrics is not None:
        feature["perimeter_m"] = metrics["perimeter_m"]
        feature["area_m2"] = metrics["area_m2"]
    return feature, None


def _raw_rows(path: Path) -> Iterator[Any]:
    if not path.is_file():
        raise GeoLocateError(f"OSM extract not found at {path}")
    if path.suffix.lower() in _LINE_SUFFIXES:
        with path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                line = line.strip(" \t\r\n\x1e")      # \x1e: the RS that starts a geojsonseq record
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    raise GeoLocateError(f"OSM extract {path.name} line {number} is not JSON: {exc}") from exc
        return
    data = _read_json_file(path, "OSM extract")
    if isinstance(data, Mapping):
        rows = data.get("elements", data.get("features"))
    else:
        rows = data
    if not isinstance(rows, list):
        raise GeoLocateError("OSM extract must be line-delimited JSON, a list, an Overpass "
                             "{'elements': [...]} object or a GeoJSON FeatureCollection")
    yield from rows


def iter_osm_extract(path: str | Path, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Yield the normalised features of a frozen OSM extract (see :func:`normalise_feature`).

    ``.jsonl`` / ``.ndjson`` / ``.geojsonl`` / ``.geojsonseq`` files are streamed one JSON object per
    line; a ``.json`` / ``.geojson`` file holding a list, an Overpass ``{"elements": [...]}`` object
    or a GeoJSON ``FeatureCollection`` is loaded whole.  Rows that are not located features are not
    dropped silently: `stats` (:func:`new_extract_stats`) counts ``rows_read``, ``features`` and
    ``skipped`` per reason, and :func:`require_features` turns "nothing parsed" into an error.

    Cut extracts with element ids (``osmium export -u type_id``, or ``-a type,id``; Overpass output
    has them): candidates are reported, and tracked across snapshots, by id.  ``osmium export -f
    geojsonseq`` writes one feature per line behind an RS (0x1e) byte, which is stripped; an area
    comes out as a Polygon or MultiPolygon (the largest outer ring is measured), and a closed way
    that is not an area as a closed LineString, which is measured as a ring too."""
    for record in _raw_rows(Path(path).expanduser()):
        if stats is not None:
            stats["rows_read"] += 1
            if stats["rows_read"] > MAX_POI_ROWS:
                raise GeoLocateError(f"OSM extract exceeds {MAX_POI_ROWS} rows")
        feature, reason = normalise_feature(record)
        if feature is None:
            _skip(stats, reason or "unreadable row")
            continue
        if stats is not None:
            stats["features"] += 1
        yield feature


def require_features(stats: Mapping[str, Any], what: str) -> None:
    """Raise when an extract was read to the end and not one row was a located feature: a wrong-format
    dataset must not look like "no candidates"."""
    if stats["features"]:
        return
    if not stats["rows_read"]:
        raise GeoLocateError(f"{what} is empty: no rows to search")
    reasons = ", ".join(f"{count} x {reason}" for reason, count in sorted(stats["skipped"].items()))
    raise GeoLocateError(f"{what}: none of its {stats['rows_read']} row(s) is a located OSM feature "
                         f"({reasons}); expected flat POIs, Overpass elements or GeoJSON features")


# =====================================================================================
#  (2) brand -> maps resolver (frozen brand POI directory) and its builder
# =====================================================================================

def _location_rows(entries: Iterable[Any], brand_label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise GeoLocateError("each brand location must be a mapping")
        coord = _coordinate(entry.get("coordinate", entry), "brand location")
        row = {
            "brand": brand_label,
            "name": _text(entry.get("name", brand_label), "brand location name"),
            "lat": coord[0],
            "lon": coord[1],
            "country": (None if not entry.get("country")
                        else _text(entry["country"], "brand location country", limit=128)),
            "address": (None if not entry.get("address")
                        else _text(entry["address"], "brand location address", limit=MAX_TEXT)),
            "source": "frozen_brand_directory",
        }
        if entry.get("osm_id"):
            row["osm_id"] = _text(entry["osm_id"], "brand location osm_id", limit=64)
        rows.append(row)
    return rows


def load_brand_directory(path: str | Path | None = None, *, dataset_root: str | Path | None = None) -> dict[str, list[dict[str, Any]]]:
    """Load the frozen brand POI directory (``brands.json`` under the dataset, or `path`).

    Accepts either a mapping {brand name: [locations]} or a list of POI records each carrying a
    ``brand`` field.  Each location is {name, lat/lon, country?, address?, osm_id?}.
    :func:`build_brand_directory` writes the mapping form from an OSM extract."""
    directory_path = Path(path).expanduser() if path is not None else _dataset_dir(dataset_root) / "brands.json"
    data = _read_json_file(directory_path, "brand directory")
    index: dict[str, list[dict[str, Any]]] = {}
    if isinstance(data, Mapping):
        items = data.items()
    elif isinstance(data, list):
        grouped: dict[str, list[Any]] = {}
        for record in data:
            if not isinstance(record, Mapping):
                raise GeoLocateError("brand directory list entries must be mappings")
            brand = _text(record.get("brand", record.get("name", "")), "brand name")
            grouped.setdefault(brand, []).append(record)
        items = grouped.items()
    else:
        raise GeoLocateError("brand directory must be a mapping or a list of records")
    for raw_brand, entries in items:
        brand_label = _text(raw_brand, "brand name")
        if not isinstance(entries, list):
            raise GeoLocateError(f"brand {brand_label!r} must map to a list of locations")
        if len(entries) > MAX_CANDIDATES:
            raise GeoLocateError(f"brand {brand_label!r} has more than {MAX_CANDIDATES} locations")
        index.setdefault(_normalise(brand_label), []).extend(_location_rows(entries, brand_label))
    return index


def _order_by_distance(rows: list[dict[str, Any]], near: tuple[float, float] | None,
                       tie: Callable[[dict[str, Any]], tuple]) -> None:
    for row in rows:
        row["distance_m"] = None if near is None else distance_m(near[0], near[1], row["lat"], row["lon"])
    rows.sort(key=lambda r: (r["distance_m"] is None,
                             r["distance_m"] if r["distance_m"] is not None else 0.0, *tie(r)))


def resolve_brand(brand: str, *, directory: Mapping[str, list[dict[str, Any]]] | None = None,
                  dataset_root: str | Path | None = None, near: Any = None,
                  limit: int = MAX_RESULTS) -> dict[str, Any]:
    """Resolve a recognised brand / business name to candidate store locations from the frozen
    directory.  An exact (case-insensitive) brand match wins; otherwise brands whose normalised name
    contains, or is contained by, the query are returned.  With `near`, candidates are ordered by
    great-circle distance to that point."""
    query = _text(brand, "brand query")
    limit = _limit(limit)
    index = directory if directory is not None else load_brand_directory(dataset_root=dataset_root)
    key = _normalise(query)
    near_point = _opt_coordinate(near, "near point")

    exact = list(index.get(key, ()))
    partial: list[dict[str, Any]] = []
    if not exact:
        for brand_key, rows in index.items():
            if brand_key != key and (key in brand_key or brand_key in key):
                partial.extend(rows)
    matched = exact or partial
    match_kind = "exact" if exact else ("partial" if partial else "none")

    candidates = [dict(row) for row in matched]
    _order_by_distance(candidates, near_point, lambda r: (r["brand"], r["name"]))
    return _human_report(
        "brand_to_maps",
        query=query,
        match_kind=match_kind,
        candidate_count=len(candidates),
        candidates=candidates[:limit],
        caveat=("a brand can have many branches; signage, geometry and other clues must pick the right "
                "one, and a franchise directory may be stale"),
    )


# OSM keys whose presence makes a *named* feature a business worth listing under its own name.
_BUSINESS_KEYS = ("shop", "amenity", "tourism", "office", "craft", "leisure", "healthcare")
BRAND_KEYS = ("brand", "operator", "name")


def build_brand_directory(extract_path: str | Path, *, keys: Sequence[str] = BRAND_KEYS) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Cut a brand directory from a frozen OSM extract: ``({label: [locations]}, stats)``.

    Each feature is listed under its ``brand`` tag, its ``operator`` tag and, when it is a business
    (it carries one of shop / amenity / tourism / office / craft / leisure / healthcare), its
    ``name``.  A label is listed once per feature.  `stats` carries the extract's read counts and
    ``truncated``: labels with more than MAX_CANDIDATES locations, cut to the first MAX_CANDIDATES
    in extract order, with their full count."""
    for key in keys:
        if key not in BRAND_KEYS:
            raise GeoLocateError(f"brand key must be one of {', '.join(BRAND_KEYS)}; got {key!r}")
    path = Path(extract_path).expanduser()
    stats = new_extract_stats()
    labels: dict[str, str] = {}
    directory: dict[str, list[dict[str, Any]]] = {}
    totals: dict[str, int] = {}
    for feature in iter_osm_extract(path, stats):
        tags = feature["tags"]
        seen: set[str] = set()
        for key in keys:
            raw = feature["name"] if key == "name" else tags.get(key)
            if key == "name" and not any(k in tags for k in _BUSINESS_KEYS):
                continue
            label, ok = _feature_name(raw)
            if not ok or not label:
                continue
            norm = _normalise(label)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            totals[norm] = totals.get(norm, 0) + 1
            label = labels.setdefault(norm, label)          # the first spelling seen names the brand
            rows = directory.setdefault(label, [])
            if len(rows) >= MAX_CANDIDATES:
                continue
            address = " ".join(part for part in (tags.get("addr:street"), tags.get("addr:housenumber"),
                                                 tags.get("addr:postcode"), tags.get("addr:city")) if part)
            row: dict[str, Any] = {"name": feature["name"] or label, "lat": feature["lat"], "lon": feature["lon"]}
            if tags.get("addr:country"):
                row["country"] = tags["addr:country"][:128]
            if address:
                row["address"] = address[:MAX_TEXT]
            if feature["id"]:
                row["osm_id"] = feature["id"][:64]
            rows.append(row)
    require_features(stats, f"OSM extract {path.name}")
    stats["labels"] = len(directory)
    stats["truncated"] = {labels[norm]: total for norm, total in sorted(totals.items())
                          if total > MAX_CANDIDATES}
    return directory, stats


def write_brand_directory(directory: Mapping[str, list[dict[str, Any]]], out_path: str | Path, *,
                          force: bool = False) -> Path:
    """Write a built directory as ``brands.json``.  An existing file is kept unless `force`."""
    out = Path(out_path).expanduser()
    if out.exists() and not force:
        raise GeoLocateError(f"{out} exists; pass force (--force) to replace it")
    if not out.parent.is_dir():
        raise GeoLocateError(f"output folder {out.parent} does not exist")
    out.write_text(json.dumps(directory, ensure_ascii=False, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    return out


# =====================================================================================
#  (3) OSM / Overpass constraint solver (frozen extract; live via scope.check_public_fetch)
# =====================================================================================

OverpassTransport = Callable[[str, str, float], bytes]
_CONSTRAINT_KEYS = ("tags", "name_contains", "near", "radius_m", "bbox", "perimeter_m", "area_m2",
                    "joins", "date")
_JOIN_KEYS = ("label", "tags", "name_contains", "min_m", "max_m")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z)?\Z")


class _Parsed(dict):
    """Constraints that have been through _parse_constraints (never built from caller input)."""


def _parse_selector(raw: Mapping[str, Any], field: str) -> dict[str, Any]:
    tags: dict[str, Any] = {}
    raw_tags = raw.get("tags", {})
    if not isinstance(raw_tags, Mapping):
        raise GeoLocateError(f"{field}.tags must be a mapping of OSM key -> value, list of values or '*'")
    if len(raw_tags) > 64:
        raise GeoLocateError(f"{field}.tags has too many keys")
    for raw_key, raw_value in raw_tags.items():
        key = _text(raw_key, "tag key", limit=128)
        if raw_value in ("*", None):
            tags[key] = "*"
        elif isinstance(raw_value, (list, tuple)):
            values = [_text(v, "tag value") for v in _as_list(raw_value, f"tag {key!r} values", cap=16)]
            if not values:
                raise GeoLocateError(f"tag {key!r} has an empty value list")
            tags[key] = values
        else:
            tags[key] = [_text(raw_value, "tag value")]
    needles = [_normalise(_text(n, "name_contains entry"))
               for n in _as_list(raw.get("name_contains", []), f"{field}.name_contains", cap=32)]
    return {"tags": tags, "name_contains": needles,
            "tags_norm": {k: (None if v == "*" else frozenset(_normalise(x) for x in v))
                          for k, v in tags.items()}}


def _parse_range(raw: Any, field: str, ceiling: float) -> tuple[float, float] | None:
    if raw in (None, ""):
        return None
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)) or len(raw) != 2:
        raise GeoLocateError(f"{field} must be [min, max] (either may be null)")
    low = 0.0 if raw[0] is None else _finite(raw[0], f"{field} min")
    high = ceiling if raw[1] is None else _finite(raw[1], f"{field} max")
    if not 0 <= low <= high <= ceiling:
        raise GeoLocateError(f"{field} must satisfy 0 <= min <= max <= {ceiling:g}")
    return low, high


def _parse_date(raw: Any, field: str = "date") -> str | None:
    """An Overpass attic date: ``YYYY-MM-DD`` or ``YYYY-MM-DDTHH:MM:SSZ``, normalised to the long form."""
    if raw in (None, ""):
        return None
    text = _text(raw, field, limit=32)
    if not _DATE_RE.match(text):
        raise GeoLocateError(f"{field} must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ; got {text!r}")
    full = text if "T" in text else text + "T00:00:00Z"
    try:
        _dt.datetime.strptime(full, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GeoLocateError(f"{field} is not a real date: {text!r}") from exc
    return full


def _parse_constraints(constraints: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(constraints, Mapping):
        raise GeoLocateError("constraints must be a mapping")
    if isinstance(constraints, _Parsed):
        return _Parsed(constraints)
    unknown = sorted(str(k) for k in constraints if k not in _CONSTRAINT_KEYS)
    if unknown:
        raise GeoLocateError(f"unknown constraint key(s): {', '.join(unknown)} "
                             f"(known: {', '.join(_CONSTRAINT_KEYS)})")
    parsed = _parse_selector(constraints, "constraints")
    near = _opt_coordinate(constraints.get("near"), "constraints.near")
    radius_m = None
    if constraints.get("radius_m") not in (None, ""):
        radius_m = _finite(constraints["radius_m"], "constraints.radius_m")
        if not 0 < radius_m <= 200_000:
            raise GeoLocateError("constraints.radius_m must be in 0..200000")
    if near is not None and radius_m is None:
        raise GeoLocateError("a near point needs a radius_m")
    if radius_m is not None and near is None:
        raise GeoLocateError("a radius_m needs a near point")
    bbox = None
    if constraints.get("bbox") not in (None, ""):
        raw_bbox = constraints["bbox"]
        if (not isinstance(raw_bbox, Sequence) or isinstance(raw_bbox, (str, bytes)) or len(raw_bbox) != 4):
            raise GeoLocateError("constraints.bbox must be [south, west, north, east]")
        south, west, north, east = (_finite(v, "bbox value") for v in raw_bbox)
        if not (-90 <= south < north <= 90 and -180 <= west < east <= 180):
            raise GeoLocateError("constraints.bbox must be a valid south<north, west<east box")
        bbox = (south, west, north, east)
    joins = []
    for number, raw_join in enumerate(_as_list(constraints.get("joins"), "constraints.joins", cap=MAX_JOINS)):
        field = f"constraints.joins[{number}]"
        if not isinstance(raw_join, Mapping):
            raise GeoLocateError(f"{field} must be a mapping")
        unknown = sorted(str(k) for k in raw_join if k not in _JOIN_KEYS)
        if unknown:
            raise GeoLocateError(f"{field} has unknown key(s): {', '.join(unknown)} (known: {', '.join(_JOIN_KEYS)})")
        join = _parse_selector(raw_join, field)
        if not join["tags"] and not join["name_contains"]:
            raise GeoLocateError(f"{field} needs tags or name_contains: what to measure the distance to")
        if raw_join.get("max_m") in (None, ""):
            raise GeoLocateError(f"{field} needs max_m (the farthest the other feature may be)")
        low = 0.0 if raw_join.get("min_m") in (None, "") else _finite(raw_join["min_m"], f"{field}.min_m")
        high = _finite(raw_join["max_m"], f"{field}.max_m")
        if not 0 <= low <= high <= 200_000:
            raise GeoLocateError(f"{field} must satisfy 0 <= min_m <= max_m <= 200000")
        join["min_m"], join["max_m"] = low, high
        join["label"] = (_text(raw_join["label"], f"{field}.label", limit=64) if raw_join.get("label")
                         else ",".join(f"{k}={'|'.join(v) if v != '*' else '*'}" for k, v in join["tags"].items())
                         or "name~" + "+".join(join["name_contains"]))
        joins.append(join)
    perimeter = _parse_range(constraints.get("perimeter_m"), "constraints.perimeter_m", 1e7)
    area = _parse_range(constraints.get("area_m2"), "constraints.area_m2", 1e13)
    if not (parsed["tags"] or parsed["name_contains"] or near is not None or bbox is not None
            or perimeter is not None or area is not None):
        raise GeoLocateError("give at least one constraint (tags, name_contains, near+radius, bbox, "
                             "perimeter_m or area_m2)")
    parsed.update(near=near, radius_m=radius_m, bbox=bbox, perimeter_m=perimeter, area_m2=area,
                  joins=joins, date=_parse_date(constraints.get("date"), "constraints.date"))
    return _Parsed(parsed)


def _constraints_echo(parsed: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "tags": {k: (v if v == "*" or len(v) > 1 else v[0]) for k, v in parsed["tags"].items()},
        "name_contains": list(parsed["name_contains"]),
        "near": list(parsed["near"]) if parsed["near"] else None,
        "radius_m": parsed["radius_m"],
        "bbox": list(parsed["bbox"]) if parsed["bbox"] else None,
        "perimeter_m": list(parsed["perimeter_m"]) if parsed["perimeter_m"] else None,
        "area_m2": list(parsed["area_m2"]) if parsed["area_m2"] else None,
        "joins": [{"label": j["label"], "min_m": j["min_m"], "max_m": j["max_m"],
                   "tags": {k: (v if v == "*" or len(v) > 1 else v[0]) for k, v in j["tags"].items()},
                   "name_contains": list(j["name_contains"])} for j in parsed["joins"]],
        "date": parsed["date"],
    }


def _name_blob(feature: Mapping[str, Any]) -> str:
    parts = [feature.get("name") or ""]
    parts.extend(value for key, value in feature["tags"].items() if "name" in key)
    return _normalise(" ".join(parts))


def _selector_matches(feature: Mapping[str, Any], selector: Mapping[str, Any]) -> dict[str, str] | None:
    """The feature's values for the selector's tag keys when it satisfies the selector, else None.
    A tag value matches case-insensitively, whole or as one part of a ``a;b`` multi-value."""
    tags = feature["tags"]
    matched: dict[str, str] = {}
    for key, want in selector["tags_norm"].items():
        have = tags.get(key)
        if have is None:
            return None
        if want is not None:
            norm = _normalise(have)
            if norm not in want and not any(_normalise(part) in want for part in have.split(";")):
                return None
        matched[key] = have
    if selector["name_contains"]:
        blob = _name_blob(feature)
        if any(needle not in blob for needle in selector["name_contains"]):
            return None
    return matched


def _candidate_row(feature: Mapping[str, Any], matched: dict[str, str]) -> dict[str, Any]:
    row = {
        "id": feature["id"],
        "name": feature["name"],
        "lat": feature["lat"],
        "lon": feature["lon"],
        "center_source": feature["center_source"],
        "matched_tags": matched,
        "distance_m": None,
        "tags": dict(list(feature["tags"].items())[:64]),
    }
    if feature["ring"] is not None:
        row["perimeter_m"] = feature["perimeter_m"]
        row["area_m2"] = feature["area_m2"]
    return row


def _in_range(value: float, bounds: tuple[float, float] | None) -> bool:
    return bounds is None or bounds[0] <= value <= bounds[1]


def _solve_features(features: Iterable[Mapping[str, Any]], parsed: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every feature that satisfies the parsed constraints, with what the solve saw on the way.

    One pass keeps the primary matches and, per join, the features of the joined class; a second step
    keeps a primary match only when each join has a feature at a distance inside [min_m, max_m] and
    records the nearest such feature.  Distances are between centres (a polygon's area centroid).
    A feature is never its own join neighbour: it is told apart by its place in the input (so a row
    without an id is safe too) and by its id (so a second row of the same element is)."""
    wants_geometry = parsed["perimeter_m"] is not None or parsed["area_m2"] is not None
    joins = parsed["joins"]
    join_sets: list[list[tuple[float, float, str | None, str | None, int]]] = [[] for _ in joins]
    candidates: list[dict[str, Any]] = []
    rows_of: list[int] = []                 # rows_of[i]: the input position of candidates[i]
    no_geometry = 0
    for number, feature in enumerate(features):
        for index, join in enumerate(joins):
            if _selector_matches(feature, join) is not None:
                if len(join_sets[index]) >= MAX_JOIN_FEATURES:
                    raise GeoLocateError(f"join {join['label']!r} matches more than {MAX_JOIN_FEATURES} "
                                         "features; tighten it or cut a smaller extract")
                join_sets[index].append((feature["lat"], feature["lon"], feature["id"], feature["name"], number))
        matched = _selector_matches(feature, parsed)
        if matched is None:
            continue
        lat, lon = feature["lat"], feature["lon"]
        if parsed["bbox"] is not None:
            south, west, north, east = parsed["bbox"]
            if not (south <= lat <= north and west <= lon <= east):
                continue
        distance = None
        if parsed["near"] is not None:
            distance = distance_m(parsed["near"][0], parsed["near"][1], lat, lon)
            if distance > parsed["radius_m"]:
                continue
        if wants_geometry:
            if feature["ring"] is None:
                no_geometry += 1
                continue
            if not (_in_range(feature["perimeter_m"], parsed["perimeter_m"])
                    and _in_range(feature["area_m2"], parsed["area_m2"])):
                continue
        row = _candidate_row(feature, matched)
        row["distance_m"] = distance
        candidates.append(row)
        rows_of.append(number)
        if len(candidates) > MAX_CANDIDATES:
            raise GeoLocateError(f"more than {MAX_CANDIDATES} features matched before the joins; "
                                 "tighten the constraints")
    if wants_geometry and no_geometry and not candidates:
        raise GeoLocateError(
            f"{no_geometry} feature(s) matched the tag, name and region constraints but none carries "
            "polygon geometry, so perimeter_m / area_m2 cannot be checked: cut the extract with way "
            "geometry (Overpass `out geom`, or `osmium export` GeoJSON)")
    for index, join in enumerate(joins):
        pool = sorted(join_sets[index], key=lambda other: other[0])
        lats = [row[0] for row in pool]
        pad = join["max_m"] / METRES_PER_DEGREE * 1.01 + 1e-9
        kept, kept_rows = [], []
        for row, number in zip(candidates, rows_of):
            best: tuple[float, tuple] | None = None
            for other in pool[bisect.bisect_left(lats, row["lat"] - pad):bisect.bisect_right(lats, row["lat"] + pad)]:
                if other[4] == number or (other[2] is not None and other[2] == row["id"]):
                    continue                      # a feature is never its own neighbour
                d = distance_m(row["lat"], row["lon"], other[0], other[1])
                if join["min_m"] <= d <= join["max_m"] and (best is None or d < best[0]):
                    best = (d, other)
            if best is None:
                continue
            row.setdefault("joins", []).append({"label": join["label"], "id": best[1][2], "name": best[1][3],
                                                 "lat": best[1][0], "lon": best[1][1], "distance_m": best[0]})
            kept.append(row)
            kept_rows.append(number)
        candidates, rows_of = kept, kept_rows
    info = {"geometry_unavailable": no_geometry,
            "join_feature_counts": {join["label"]: len(join_sets[i]) for i, join in enumerate(joins)}}
    return candidates, info


def _rank_candidates(candidates: list[dict[str, Any]]) -> None:
    candidates.sort(key=lambda r: (r["distance_m"] is None, r["distance_m"] if r["distance_m"] is not None else 0.0,
                                   r["name"] or "", r["id"] or ""))


def solve_osm_constraints(constraints: Mapping[str, Any], *, dataset_root: str | Path | None = None,
                          extract_path: str | Path | None = None, limit: int = MAX_RESULTS,
                          online: bool = False, profile: Any = None,
                          endpoint: str = DEFAULT_OVERPASS_ENDPOINT,
                          transport: OverpassTransport | None = None,
                          timeout_s: float = 25.0) -> dict[str, Any]:
    """Solve observed OSM constraints to a ranked candidate list.

    Constraints (a mapping; an unknown key is an error, never ignored):

      tags           {key: value | [values] | "*"}: every key must be present; a value matches
                     case-insensitively, a list is any-of, "*" is any value
      name_contains  [text, ...]: each must appear in the feature's name tags (any ``*name*`` key)
      near, radius_m a [lat, lon] point and the farthest a feature may be from it, in metres
      bbox           [south, west, north, east]
      perimeter_m    [min, max] of the feature's polygon outline, metres (needs way geometry)
      area_m2        [min, max] of the feature's polygon, square metres (needs way geometry)
      joins          [{label?, tags, name_contains?, min_m?, max_m}, ...]: another feature of that
                     class must lie between min_m (default 0) and max_m from the candidate; the
                     nearest one in range is reported
      date           an Overpass attic date for the online query (the frozen extract is one snapshot)

    Offline (default): the frozen extract (``<dataset>/osm.jsonl`` or `extract_path`) is searched and
    the result carries ``extract`` (rows read, features, rows skipped per reason).  Online
    (`online=True`): the constraints build an Overpass QL query; the endpoint host is cleared through
    :func:`ctf.scope.check_public_fetch` against the event profile's ``rules.public_fetch_allow``
    before any request, and so is every redirect of the default transport.  Candidates are ranked by
    distance to the near point (when given), then by name."""
    parsed = _parse_constraints(constraints)
    limit = _limit(limit)
    extract_stats = None
    if online:
        candidates, info, source = _solve_osm_online(parsed, profile=profile, endpoint=endpoint,
                                                     transport=transport, timeout_s=timeout_s)
    else:
        if parsed["date"] is not None:
            raise GeoLocateError("constraints.date is an Overpass attic date: it applies to an online "
                                 "query only. The frozen extract is one snapshot; solve dated extracts "
                                 "with sweep_osm_snapshots (`sweep --snapshot LABEL=FILE`)")
        path = (Path(extract_path).expanduser() if extract_path is not None
                else _dataset_dir(dataset_root) / "osm.jsonl")
        extract_stats = new_extract_stats()
        candidates, info = _solve_features(iter_osm_extract(path, extract_stats), parsed)
        require_features(extract_stats, f"OSM extract {path.name}")
        source = f"frozen_osm_extract:{path.name}"
    _rank_candidates(candidates)
    return _human_report(
        "osm_constraint_solution",
        source=source,
        constraints=_constraints_echo(parsed),
        extract=extract_stats,
        geometry_unavailable=info["geometry_unavailable"],
        join_feature_counts=info["join_feature_counts"],
        candidate_count=len(candidates),
        candidates=candidates[:limit],
        caveat=("constraint satisfaction narrows the field; it does not prove a single feature is the "
                "answer, and a challenge may have been written against an older map snapshot"),
    )


def _overpass_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _overpass_regex(literal: str) -> str:
    """`literal` as an Overpass (POSIX extended) regular expression matching it literally, escaped
    for a QL string: only the ERE metacharacters get a backslash, so "c++" and "st. mary (old)"
    match themselves instead of being read as a pattern."""
    return _overpass_escape(re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", literal))


def _overpass_selectors(selector: Mapping[str, Any]) -> str:
    out = ""
    for key, want in selector["tags"].items():
        if want == "*":
            out += f'["{_overpass_escape(key)}"]'
        elif len(want) == 1:
            out += f'["{_overpass_escape(key)}"="{_overpass_escape(want[0])}"]'
        else:
            out += f'["{_overpass_escape(key)}"~"^({"|".join(_overpass_regex(v) for v in want)})$"]'
    for needle in selector["name_contains"]:
        # any *name* key (name, alt_name, name:de ...), like the offline match; the needle is literal
        out += f'[~"name"~"{_overpass_regex(needle)}",i]'
    return out


def _overpass_region(parsed: Mapping[str, Any], pad_m: float = 0.0) -> str:
    if parsed["bbox"] is not None:
        south, west, north, east = parsed["bbox"]
        if pad_m:
            dlat = pad_m / METRES_PER_DEGREE
            dlon = dlat / max(0.01, math.cos(math.radians(max(abs(south), abs(north)))))
            south, north = max(-90.0, south - dlat), min(90.0, north + dlat)
            west, east = max(-180.0, west - dlon), min(180.0, east + dlon)
        return f"({south},{west},{north},{east})"
    if parsed["near"] is not None:
        return f"(around:{parsed['radius_m'] + pad_m},{parsed['near'][0]},{parsed['near'][1]})"
    return ""


def build_overpass_query(constraints: Mapping[str, Any], *, timeout_s: int = 25,
                         limit: int = MAX_CANDIDATES, date: str | None = None) -> str:
    """Build the Overpass QL query for raw or parsed constraints.

    The primary statement selects node+way+relation by the tag and name filters inside the bbox or
    around-filter and prints ``out geom`` when a perimeter or area constraint needs polygon
    geometry, else ``out center``.  Each join adds its own statement over the region widened by the
    join's max_m.  `date` (or ``constraints["date"]``) adds an ``[date:"..."]`` attic setting, so the
    query is answered from the map as it was then.  Name needles are sent as literal regexes."""
    parsed = _parse_constraints(constraints)
    when = _parse_date(date) if date is not None else parsed["date"]
    settings = f"[out:json][timeout:{int(timeout_s)}]" + (f'[date:"{when}"]' if when else "")
    selectors = _overpass_selectors(parsed)
    region = _overpass_region(parsed)
    geometry = parsed["perimeter_m"] is not None or parsed["area_m2"] is not None
    lines = [settings + ";", "("]
    lines += [f"  {kind}{selectors}{region};" for kind in _OSM_TYPES]
    lines += [")->.primary;", f".primary out {'geom' if geometry else 'center'} {int(limit)};"]
    for index, join in enumerate(parsed["joins"]):
        if not region:
            raise GeoLocateError("an online query with joins needs a bbox or near+radius: without a "
                                 "region the join would ask Overpass for the whole planet")
        jsel, jregion = _overpass_selectors(join), _overpass_region(parsed, pad_m=join["max_m"])
        lines.append("(")
        lines += [f"  {kind}{jsel}{jregion};" for kind in _OSM_TYPES]
        lines += [f")->.join{index};", f".join{index} out center;"]
    return "\n".join(lines)


def _constraint_strings(parsed: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for selector in (parsed, *parsed["joins"]):
        for key, want in selector["tags"].items():
            out.append(key)
            out.extend([] if want == "*" else want)
        out.extend(selector["name_contains"])
    return out


def _screen_public_query(parsed: Mapping[str, Any], profile: Any) -> None:
    """Nothing flag-shaped or secret-shaped is sent to a public service.  The constraint values are
    screened as given, before the query escapes them."""
    text = "\n".join(_constraint_strings(parsed))
    if _SECRET_RE.search(text):
        raise GeoLocateError("the constraints carry a secret-shaped value; it is never sent to a public service")
    try:
        prof = profile if profile is not None else _event.current()
    except _event.EventError:
        prof = scope.pinned()                      # the scope guard passed, so a profile is in force
    if prof is not None and _flagfmt.for_profile(prof).find_flags(text):
        raise GeoLocateError("the constraints carry a value in the event flag format; a flag is never "
                             "sent to a public service")


def _solve_osm_online(parsed: Mapping[str, Any], *, profile: Any, endpoint: str,
                      transport: OverpassTransport | None, timeout_s: float):
    # The scope guard opens no connection; it raises ctf.scope.OutOfScope when the endpoint host is
    # not in the event profile's rules.public_fetch_allow, so a live query is refused before any I/O.
    purpose = "osint_geolocate Overpass constraint lookup"
    scope.check_public_fetch(endpoint, purpose=purpose, profile=profile)
    _screen_public_query(parsed, profile)
    query = build_overpass_query(parsed)
    sender = transport if transport is not None else overpass_transport(profile)
    raw = sender(endpoint, query, float(timeout_s))
    if not isinstance(raw, (bytes, bytearray)):
        raise GeoLocateError("Overpass transport must return bytes")
    if len(raw) > MAX_DATASET_BYTES:
        raise GeoLocateError("Overpass response exceeds the size cap")
    try:
        data = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise GeoLocateError(f"Overpass response is not JSON: {exc}") from exc
    elements = data.get("elements") if isinstance(data, Mapping) else None
    if not isinstance(elements, list):
        raise GeoLocateError("Overpass response has no 'elements' list")
    if len(elements) > MAX_POI_ROWS:
        raise GeoLocateError(f"Overpass response exceeds {MAX_POI_ROWS} elements")
    stats = new_extract_stats()
    # Overpass prints an element once per `out` statement it is in: a feature of both the primary
    # class and a join's class comes back twice.  Each element is solved once, keeping the print
    # that carries its outline (the primary's `out geom`).
    features: list[dict[str, Any]] = []
    place: dict[str, int] = {}
    for element in elements:
        stats["rows_read"] += 1
        feature, reason = normalise_feature(element)
        if feature is None:
            _skip(stats, reason or "unreadable element")
            continue
        fid = feature["id"]
        if fid is not None and fid in place:
            _skip(stats, "repeated element (printed by more than one out statement)")
            if feature["ring"] is not None and features[place[fid]]["ring"] is None:
                features[place[fid]] = feature
            continue
        if fid is not None:
            place[fid] = len(features)
        stats["features"] += 1
        features.append(feature)

    candidates, info = _solve_features(features, parsed)
    info["response"] = stats
    return candidates, info, f"live_overpass:{scope.split_url(endpoint)[0]}"


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "::1") or host.startswith("127.")


def overpass_transport(profile: Any = None) -> OverpassTransport:
    """The default live transport: one POST of the query, the body read under the size cap.

    The caller clears the endpoint through the scope guard first; this transport then re-runs
    :func:`ctf.scope.check_public_fetch` on every redirect target before following it, so a 3xx can
    never carry the query to a host the event profile does not list.  Only https is spoken, except
    to a loopback host (a local mirror, or a test's fake)."""
    import urllib.error
    import urllib.parse
    import urllib.request

    purpose = "osint_geolocate Overpass constraint lookup (redirect)"

    def require_scheme(url: str) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" and not (parts.scheme == "http" and _is_loopback(parts.hostname or "")):
            raise GeoLocateError(f"Overpass endpoint {url!r} must be https (plain http only to loopback)")

    class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            require_scheme(newurl)
            scope.check_public_fetch(newurl, purpose=purpose, profile=profile)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    def send(endpoint: str, query: str, timeout_s: float) -> bytes:
        require_scheme(endpoint)
        opener = urllib.request.build_opener(_ScopedRedirect())
        request = urllib.request.Request(
            endpoint, data=query.encode("utf-8"),
            headers={"User-Agent": OVERPASS_USER_AGENT, "Content-Type": "text/plain; charset=utf-8"},
            method="POST")
        try:
            with opener.open(request, timeout=timeout_s) as response:  # noqa: S310 - host cleared by scope
                return response.read(MAX_DATASET_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise GeoLocateError(f"Overpass answered HTTP {exc.code} for the query") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (scope.OutOfScope, GeoLocateError)):
                raise exc.reason from exc
            raise GeoLocateError(f"Overpass endpoint not reachable: {exc.reason}") from exc

    return send


def sweep_osm_snapshots(constraints: Mapping[str, Any], *, snapshots: Mapping[str, str | Path] | None = None,
                        dataset_root: str | Path | None = None, dates: Iterable[str] | None = None,
                        online: bool = False, profile: Any = None,
                        endpoint: str = DEFAULT_OVERPASS_ENDPOINT,
                        transport: OverpassTransport | None = None, limit: int = MAX_RESULTS) -> dict[str, Any]:
    """Solve the same constraints against several map snapshots and report what changes between them.

    A challenge is often written against an older map: a feature renamed, re-tagged or redrawn since
    then drops out of today's result.  Offline, `snapshots` maps a label (a date) to a frozen extract
    cut at that date; without it every ``<dataset>/snapshots/*.jsonl`` is used, labelled by file
    name.  Online, each of `dates` (at most MAX_ONLINE_DATES) is one attic query through
    :func:`solve_osm_constraints` and its scope guard.  The result lists every snapshot's candidates
    and, per candidate id, the snapshots it satisfied the constraints in; ``unstable`` are the ids
    that are not in all of them -- the ones a single-date solve can miss."""
    parsed = _parse_constraints(constraints)
    limit = _limit(limit)
    runs: list[tuple[str, dict[str, Any]]] = []
    if online:
        wanted = [_parse_date(d, "sweep date") for d in _as_list(dates, "dates", cap=MAX_ONLINE_DATES)]
        if not wanted:
            raise GeoLocateError("an online sweep needs at least one attic date")
        for when in wanted:
            dated = _Parsed(parsed, date=when)
            runs.append((when, solve_osm_constraints(dated, online=True, profile=profile, endpoint=endpoint,
                                                     transport=transport, limit=limit)))
    else:
        if dates:
            raise GeoLocateError("attic dates are for an online sweep; offline, pass dated extracts as snapshots")
        if snapshots is None:
            folder = _dataset_dir(dataset_root) / "snapshots"
            found = sorted(folder.glob("*.jsonl")) if folder.is_dir() else []
            if not found:
                raise GeoLocateError(f"no snapshot extracts: {folder} holds no *.jsonl (name each by its date)")
            snapshots = {p.stem: p for p in found}
        if not isinstance(snapshots, Mapping) or not 1 <= len(snapshots) <= MAX_SNAPSHOTS:
            raise GeoLocateError(f"give 1..{MAX_SNAPSHOTS} snapshot extracts as {{label: path}}")
        for raw_label, path in snapshots.items():
            label = _text(raw_label, "snapshot label", limit=64)
            runs.append((label, solve_osm_constraints(parsed, extract_path=path, limit=limit)))
    presence: dict[str, dict[str, Any]] = {}
    for label, report in runs:
        for row in report["candidates"]:
            key = row["id"] or f"{row['name']}@{row['lat']:.6f},{row['lon']:.6f}"
            entry = presence.setdefault(key, {"id": row["id"], "names": [], "snapshots": []})
            if row["name"] and row["name"] not in entry["names"]:
                entry["names"].append(row["name"])
            entry["snapshots"].append(label)
    labels = [label for label, _ in runs]
    unstable = sorted(key for key, entry in presence.items() if len(entry["snapshots"]) != len(labels))
    return _human_report(
        "osm_snapshot_sweep",
        constraints=_constraints_echo(parsed),
        snapshots=[{"label": label, "source": report["source"], "candidate_count": report["candidate_count"],
                    "candidates": report["candidates"]} for label, report in runs],
        presence=presence,
        unstable=unstable,
        candidate_count=len(presence),
        candidates=[{"id": entry["id"], "name": (entry["names"] or [None])[0], "names": entry["names"],
                     "snapshots": entry["snapshots"]} for _, entry in sorted(presence.items())][:limit],
        caveat="a candidate present in only some snapshots was renamed, re-tagged, redrawn, added or removed",
    )


# --- name-spelling enumerator -------------------------------------------------------

NAME_TAG_KEYS = ("name", "official_name", "alt_name", "short_name", "old_name", "loc_name", "int_name")
_DIGRAPHS = {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss", "ẞ": "SS"}
_ASCII_EXTRA = {"ß": "ss", "ẞ": "SS", "æ": "ae", "Æ": "AE", "œ": "oe", "Œ": "OE", "ø": "o", "Ø": "O",
                "đ": "d", "Đ": "D", "ł": "l", "Ł": "L", "ı": "i", "þ": "th", "Þ": "TH"}


def _ascii_fold(text: str) -> str:
    out = []
    for ch in text:
        if ch in _ASCII_EXTRA:
            out.append(_ASCII_EXTRA[ch])
        else:
            out.append("".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)))
    return "".join(out)


def name_variants(name: str | None = None, *, tags: Mapping[str, Any] | None = None,
                  limit: int = 64) -> list[dict[str, Any]]:
    """The spellings a feature's name can take as a ``prefix{NAME}`` flag body, most literal first.

    Sources: `name`, then the OSM name tags of `tags` (name, official_name, alt_name, short_name,
    old_name, loc_name, int_name and every ``name:<lang>``; a ``a;b`` value is split).  Each source is
    spelled as written, with German digraphs (ä -> ae, ß -> ss) and ASCII-folded (ä -> a); each of
    those with spaces kept, as underscores, and with every run of non-alphanumerics as one
    underscore; each of those as written, upper-case and lower-case.  Returns ``[{value, source,
    changes}]`` without duplicates, at most `limit`.  It only enumerates: try them through
    ``python -m ctf flag variants`` / ``ctf.flagcheck.try_variants`` so the event's guess budget
    holds."""
    if not 1 <= int(limit) <= 512:
        raise GeoLocateError("limit must be 1..512")
    sources: list[tuple[str, str]] = []
    if name not in (None, ""):
        sources.append(("name", _text(name, "name")))
    if tags is not None:
        if not isinstance(tags, Mapping):
            raise GeoLocateError("tags must be a mapping of OSM key -> value")
        ordered = [k for k in NAME_TAG_KEYS if k in tags] + sorted(
            str(k) for k in tags if str(k).startswith("name:"))
        for key in ordered:
            for part in str(tags[key]).split(";"):
                spelled, ok = _feature_name(part)
                if ok and spelled:
                    sources.append((key, spelled))
    if not sources:
        raise GeoLocateError("give a name, or tags with at least one name tag")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source, spelled in sources:
        spellings = [(spelled, [])]
        digraph = "".join(_DIGRAPHS.get(ch, ch) for ch in spelled)
        if digraph != spelled:
            spellings.append((digraph, ["digraphs"]))
        folded = _ascii_fold(spelled)
        if folded not in (spelled, digraph):
            spellings.append((folded, ["ascii"]))
        for text, changes in spellings:
            separated = [(text, changes)]
            if " " in text:
                separated.append((text.replace(" ", "_"), changes + ["spaces:_"]))
            squeezed = re.sub(r"[^0-9A-Za-zÀ-￿]+", "_", text).strip("_")
            if squeezed and squeezed not in (text, text.replace(" ", "_")):
                separated.append((squeezed, changes + ["punctuation:_"]))
            for value, changed in separated:
                for cased, case_change in ((value, None), (value.upper(), "case:upper"), (value.lower(), "case:lower")):
                    if cased in seen:
                        continue
                    seen.add(cased)
                    out.append({"value": cased, "source": source,
                                "changes": changed + ([case_change] if case_change else [])})
                    if len(out) >= int(limit):
                        return out
    return out


# --- named venue -> polygon centre and entrances ------------------------------------

def resolve_venue(name: str, *, dataset_root: str | Path | None = None,
                  extract_path: str | Path | None = None, near: Any = None,
                  entrance_pad_m: float = 30.0, limit: int = 20) -> dict[str, Any]:
    """Resolve a *named* venue to coordinates a map-pin checker can be given: the features of the
    frozen extract whose name tags contain `name`, each with its centre (the area centroid of its
    polygon when the extract carries the outline, else the node / way centre), its outline's
    perimeter and area, and the ``entrance=*`` nodes inside its bounding box padded by
    `entrance_pad_m`.  An exact name match ranks first, then polygons before points, then distance
    to `near`.  It lists candidates; which one is the scene stays the reader's call."""
    query = _text(name, "venue name")
    limit = _limit(limit)
    near_point = _opt_coordinate(near, "near point")
    pad = _finite(entrance_pad_m, "entrance_pad_m")
    if not 0 <= pad <= 1000:
        raise GeoLocateError("entrance_pad_m must be 0..1000")
    path = (Path(extract_path).expanduser() if extract_path is not None
            else _dataset_dir(dataset_root) / "osm.jsonl")
    needle = _normalise(query)
    stats = new_extract_stats()
    candidates: list[dict[str, Any]] = []
    entrances: list[tuple[float, float, str | None, str]] = []
    for feature in iter_osm_extract(path, stats):
        if "entrance" in feature["tags"] and len(entrances) < MAX_JOIN_FEATURES:
            entrances.append((feature["lat"], feature["lon"], feature["id"], feature["tags"]["entrance"]))
        if needle not in _name_blob(feature):
            continue
        row = _candidate_row(feature, {})
        row["exact_name"] = _normalise(feature["name"] or "") == needle
        row["has_polygon"] = feature["ring"] is not None
        if feature["ring"] is not None:
            lats = [p[0] for p in feature["ring"]]
            lons = [p[1] for p in feature["ring"]]
            row["bounds"] = [min(lats), min(lons), max(lats), max(lons)]
        candidates.append(row)
        if len(candidates) > MAX_CANDIDATES:
            raise GeoLocateError(f"more than {MAX_CANDIDATES} features carry that name; add words to it")
    require_features(stats, f"OSM extract {path.name}")
    for row in candidates:
        row["entrances"] = []
        if "bounds" in row:
            south, west, north, east = row["bounds"]
            dlat = pad / METRES_PER_DEGREE
            dlon = dlat / max(0.01, math.cos(math.radians(row["lat"])))
            row["entrances"] = [{"id": eid, "entrance": kind, "lat": lat, "lon": lon}
                                for lat, lon, eid, kind in entrances
                                if south - dlat <= lat <= north + dlat and west - dlon <= lon <= east + dlon][:32]
    _order_by_distance(candidates, near_point, lambda r: ())
    candidates.sort(key=lambda r: (not r["exact_name"], not r["has_polygon"]))    # stable: distance order kept
    return _human_report(
        "venue_to_coordinates",
        query=query,
        source=f"frozen_osm_extract:{path.name}",
        extract=stats,
        candidate_count=len(candidates),
        candidates=candidates[:limit],
        caveat=("a venue name can match several features (the site, a building on it, a pool in it); "
                "a checker's target may be any of them, or the camera position rather than the venue"),
    )


# =====================================================================================
#  (1) opener: sign OCR text -> brand and OSM name candidates
# =====================================================================================

_WORD_RE = re.compile(r"[^\W_]+(?:[.'&-][^\W_]+)*", re.UNICODE)
OPEN_SOURCES = ("brands", "osm")


def _clue_text(clues: Any) -> str:
    if isinstance(clues, str):
        return clues
    if isinstance(clues, Mapping):
        parts = [str(clues.get("ocr_text") or "")]
        for key in ("candidate_names", "place_words"):
            value = clues.get(key)
            if isinstance(value, (list, tuple)):
                parts.extend(str(v) for v in value)
        return "\n".join(parts)
    raise GeoLocateError("clues must be OCR text or an osint_geo clues mapping")


def _phrases(text: str) -> set[str]:
    """Every run of 1..5 consecutive words of each OCR line, normalised: what a name is looked up as."""
    out: set[str] = set()
    for line in text.splitlines():
        words = [_normalise(w) for w in _WORD_RE.findall(line)]
        for start in range(len(words)):
            for size in range(1, 6):
                if start + size > len(words):
                    break
                phrase = " ".join(words[start:start + size])
                if len(phrase) >= 3 and not phrase.isdigit():
                    out.add(phrase)
                    if len(out) > MAX_PHRASES:
                        raise GeoLocateError(f"the OCR text yields more than {MAX_PHRASES} phrases; crop it")
    return out


def _words(text: str) -> str:
    return " ".join(_normalise(w) for w in _WORD_RE.findall(text))


def open_clues(clues: Any, *, dataset_root: str | Path | None = None,
               directory: Mapping[str, list[dict[str, Any]]] | None = None,
               extract_path: str | Path | None = None, sources: Sequence[str] = OPEN_SOURCES,
               near: Any = None, limit: int = 20) -> dict[str, Any]:
    """Turn sign / storefront OCR text into located candidates from the frozen dataset.

    `clues` is OCR text, or the clues mapping of ``osint_geo.extract_clues`` (its ``ocr_text``,
    ``candidate_names`` and ``place_words`` are read).  Two lookups run over it (`sources`):

      brands  a brand of the frozen directory whose whole name is in the text ("exact"), then a brand
              sharing a word of four or more letters with the text ("word"); each with its branches
      osm     a named feature of the frozen extract whose whole name (three characters or more) is
              in the text, longest name first

    Names are compared word-wise, case-insensitively.  With `near` (an EXIF GPS fix) each list is
    ordered by distance to it within its match kind.  A source whose dataset file is missing is an
    error, not an empty list; pass `sources` to run only one."""
    text = _clue_text(clues)
    limit = _limit(limit)
    near_point = _opt_coordinate(near, "near point")
    chosen = tuple(sources)
    if not chosen or any(s not in OPEN_SOURCES for s in chosen):
        raise GeoLocateError(f"sources must be drawn from {', '.join(OPEN_SOURCES)}")
    if not text.strip():
        raise GeoLocateError("no OCR text to open: the image produced none (pass the sign text by hand)")
    phrases = _phrases(text)
    single_words = {p for p in phrases if " " not in p and len(p) >= 4}
    brand_hits: list[dict[str, Any]] = []
    if "brands" in chosen:
        index = directory if directory is not None else load_brand_directory(dataset_root=dataset_root)
        for brand_key, rows in index.items():
            brand_words = _words(brand_key)
            if not brand_words:
                continue
            if brand_words in phrases:
                kind = "exact"
            elif single_words & {w for w in brand_words.split() if len(w) >= 4}:
                kind = "word"
            else:
                continue
            for row in rows:
                brand_hits.append(dict(row, match_kind=kind))
        _order_by_distance(brand_hits, near_point, lambda r: (r["brand"], r["name"]))
        brand_hits.sort(key=lambda r: r["match_kind"] != "exact")
    osm_hits: list[dict[str, Any]] = []
    extract_stats = None
    if "osm" in chosen:
        path = (Path(extract_path).expanduser() if extract_path is not None
                else _dataset_dir(dataset_root) / "osm.jsonl")
        extract_stats = new_extract_stats()
        for feature in iter_osm_extract(path, extract_stats):
            if not feature["name"]:
                continue
            name_words = _words(feature["name"])
            if name_words not in phrases:       # a phrase is three characters or more
                continue
            row = _candidate_row(feature, {})
            row["matched_text"] = name_words
            osm_hits.append(row)
            if len(osm_hits) > MAX_CANDIDATES:
                raise GeoLocateError(f"more than {MAX_CANDIDATES} named features appear in the OCR text; "
                                     "cut a smaller extract or crop the text")
        require_features(extract_stats, f"OSM extract {path.name}")
        _order_by_distance(osm_hits, near_point, lambda r: (r["name"] or "", r["id"] or ""))
        osm_hits.sort(key=lambda r: -len(r["matched_text"]))
    candidates = ([dict(c, source_kind="brand") for c in brand_hits[:limit]]
                  + [dict(c, source_kind="osm_name") for c in osm_hits[:limit]])
    return _human_report(
        "ocr_open",
        sources=list(chosen),
        phrase_count=len(phrases),
        brand_candidates=brand_hits[:limit],
        brand_candidate_count=len(brand_hits),
        osm_name_candidates=osm_hits[:limit],
        osm_name_candidate_count=len(osm_hits),
        extract=extract_stats,
        candidate_count=len(brand_hits) + len(osm_hits),
        candidates=candidates,
        caveat=("OCR of signage is noisy and a pasted overlay can be a decoy; a name in the text places "
                "a candidate on the map, it does not say the photo was taken there"),
    )


def open_image(image_path: str | Path | None = None, *, ocr_text: str | None = None,
               dataset_root: str | Path | None = None,
               directory: Mapping[str, list[dict[str, Any]]] | None = None,
               extract_path: str | Path | None = None, sources: Sequence[str] = OPEN_SOURCES,
               limit: int = 20) -> dict[str, Any]:
    """The opener: read an image's EXIF and sign text with :mod:`osint_geo` (tiled tesseract OCR),
    then resolve that text through :func:`open_clues`.  An EXIF GPS fix orders the candidates.

    `ocr_text` replaces the OCR step (text read by a model or a person).  Without it, a missing
    tesseract or Pillow is an error naming the tool: osint_geo would return empty text, and "no
    text" must not look like "no candidates".  The image stays on this machine."""
    import osint_geo  # the offline EXIF + tiled OCR toolkit; imported late, it pulls Pillow

    if image_path is None and ocr_text is None:
        raise GeoLocateError("give an image, or the OCR text of one")
    exif_gps = None
    clues: Any
    path = None
    if image_path is not None:
        path = Path(image_path).expanduser()
        if not path.is_file():
            raise GeoLocateError(f"image not found at {path}")
        gps = osint_geo.read_exif(str(path)).get("gps")
        if isinstance(gps, Mapping):
            exif_gps = _valid_latlon(gps.get("lat"), gps.get("lon"))
    if ocr_text is not None:
        clues = osint_geo.extract_clues(str(ocr_text), [])
        ocr_source = "supplied"
    else:
        missing = [tool for tool, present in (("tesseract", shutil.which("tesseract") is not None),
                                              ("Pillow (py:PIL)", osint_geo.Image is not None)) if not present]
        if missing:
            raise GeoLocateError(f"sign OCR cannot run: {', '.join(missing)} not installed; install it "
                                 "or pass the sign text with ocr_text (--ocr-text FILE)")
        full_text, tiles = osint_geo.ocr_image(str(path))
        clues = osint_geo.extract_clues(full_text, tiles)
        ocr_source = "tesseract"
    report = open_clues(clues, dataset_root=dataset_root, directory=directory, extract_path=extract_path,
                        sources=sources, near=exif_gps, limit=limit)
    report.update(image=None if path is None else str(path), ocr_source=ocr_source,
                  ocr_chars=len(clues.get("ocr_text") or ""),
                  exif_gps=None if exif_gps is None else list(exif_gps))
    return report


# =====================================================================================
#  (4) DEM skyline matcher (frozen DEM: SRTM .hgt tiles or a JSON grid)
# =====================================================================================

class DEMGrid:
    """A regular lat/lon elevation grid.

    ``lat_min``/``lon_min`` is the south-west cell centre, ``cell_deg`` the cell size in degrees, and
    ``elevations[row][col]`` runs north (row 0 = lat_min) and east (col 0 = lon_min), in metres;
    ``nodata`` marks absent cells.  Two sources: a self-describing JSON file (``format:
    "ctf-dem-grid-v1"``, :meth:`from_mapping`), which a test can build with no raster library, and an
    SRTM ``.hgt`` tile (:meth:`from_hgt`)."""

    __slots__ = ("lat_min", "lon_min", "cell_deg", "nrows", "ncols", "nodata", "_rows")

    def __init__(self, lat_min: float, lon_min: float, cell_deg: float,
                 elevations: Sequence[Sequence[Any]], nodata: float | None = None, *, _trusted: bool = False):
        self.lat_min = _finite(lat_min, "DEM lat_min")
        self.lon_min = _finite(lon_min, "DEM lon_min")
        self.cell_deg = _finite(cell_deg, "DEM cell_deg")
        if not 0 < self.cell_deg <= 1.0:
            raise GeoLocateError("DEM cell_deg must be in 0..1 degrees")
        if not isinstance(elevations, Sequence) or isinstance(elevations, (str, bytes)) or not elevations:
            raise GeoLocateError("DEM elevations must be a non-empty row list")
        self.nrows = len(elevations)
        first = elevations[0]
        self.ncols = len(first) if isinstance(first, (Sequence, array.array)) and not isinstance(first, (str, bytes)) else 0
        if not self.ncols:
            raise GeoLocateError("DEM elevation rows must be non-empty")
        if self.nrows * self.ncols > MAX_DEM_CELLS:
            raise GeoLocateError(f"DEM exceeds {MAX_DEM_CELLS} cells")
        self.nodata = None if nodata is None else _finite(nodata, "DEM nodata")
        if _trusted:            # typed int16 rows from from_hgt: already numbers of one length
            self._rows = list(elevations)
            return
        rows: list[list[float | None]] = []
        for row in elevations:
            if not isinstance(row, Sequence) or isinstance(row, (str, bytes)) or len(row) != self.ncols:
                raise GeoLocateError("DEM elevation rows must all have the same length")
            rows.append([None if value is None else _finite(value, "DEM elevation") for value in row])
        self._rows = rows

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DEMGrid":
        if not isinstance(data, Mapping):
            raise GeoLocateError("DEM file must be a JSON object")
        if data.get("format") not in (None, "ctf-dem-grid-v1"):
            raise GeoLocateError(f"unsupported DEM format {data.get('format')!r}")
        return cls(data.get("lat_min"), data.get("lon_min"), data.get("cell_deg"),
                   data.get("elevations"), data.get("nodata"))

    @classmethod
    def from_hgt(cls, path: str | Path) -> "DEMGrid":
        """Read one SRTM ``.hgt`` tile in pure Python.

        The file name gives the south-west corner (``N45E010.hgt``); the body is a square of
        big-endian signed 16-bit metres, rows north to south, 3601 x 3601 (1 arc-second) or 1201 x
        1201 (3 arc-seconds) covering one degree with the edge rows shared; -32768 is a void."""
        p = Path(path).expanduser()
        match = re.fullmatch(r"([NS])(\d{2})([EW])(\d{3})\.hgt", p.name, re.I)
        if match is None:
            raise GeoLocateError(f"{p.name}: an SRTM tile is named like N45E010.hgt (its south-west corner)")
        if not p.is_file():
            raise GeoLocateError(f"DEM tile not found at {p}")
        size = p.stat().st_size
        side = math.isqrt(size // 2)
        if size % 2 or side * side * 2 != size or side < 2:
            raise GeoLocateError(f"{p.name}: {size} bytes is not a square of 16-bit samples "
                                 "(SRTM1 is 3601 x 3601, SRTM3 1201 x 1201)")
        if side * side > MAX_DEM_CELLS:
            raise GeoLocateError(f"{p.name} exceeds {MAX_DEM_CELLS} cells")
        samples = array.array("h")
        with p.open("rb") as handle:
            samples.frombytes(handle.read())
        if sys.byteorder == "little":
            samples.byteswap()
        lat = int(match.group(2)) * (1 if match.group(1).upper() == "N" else -1)
        lon = int(match.group(4)) * (1 if match.group(3).upper() == "E" else -1)
        rows = [samples[(side - 1 - r) * side:(side - r) * side] for r in range(side)]   # south row first
        return cls(lat, lon, 1.0 / (side - 1), rows, HGT_NODATA, _trusted=True)

    def elevation(self, lat: float, lon: float) -> float | None:
        """Nearest-cell elevation at (lat, lon), or None when outside the grid or on a nodata cell."""
        row = round((lat - self.lat_min) / self.cell_deg)
        col = round((lon - self.lon_min) / self.cell_deg)
        if not (0 <= row < self.nrows and 0 <= col < self.ncols):
            return None
        value = self._rows[row][col]
        if value is None or (self.nodata is not None and value == self.nodata):
            return None
        return float(value)


class DEMMosaic:
    """Several DEM tiles read as one surface: the first tile that has a value at a point answers."""

    def __init__(self, tiles: Sequence[DEMGrid]):
        if not tiles:
            raise GeoLocateError("a DEM mosaic needs at least one tile")
        if len(tiles) > MAX_DEM_TILES:
            raise GeoLocateError(f"a DEM mosaic takes at most {MAX_DEM_TILES} tiles")
        self.tiles = list(tiles)

    def elevation(self, lat: float, lon: float) -> float | None:
        for tile in self.tiles:
            value = tile.elevation(lat, lon)
            if value is not None:
                return value
        return None


def load_dem(path: str | Path) -> DEMGrid | DEMMosaic:
    """Load a frozen DEM: an SRTM ``.hgt`` tile, a ``ctf-dem-grid-v1`` JSON grid, or a folder of
    either (read as one mosaic, tiles in name order).  A packed tile (``.hgt.zip``, ``.hgt.gz``, as
    SRTM is distributed) is an error naming it, never a tile left out of the mosaic."""
    p = Path(path).expanduser()
    if p.is_dir():
        packed = sorted(f.name for f in p.iterdir() if f.suffix.lower() in _PACKED_SUFFIXES and f.is_file())
        if packed:
            raise GeoLocateError(f"DEM folder {p} holds {len(packed)} packed tile(s) that cannot be read "
                                 f"({', '.join(packed[:5])}{', ...' if len(packed) > 5 else ''}): unpack "
                                 "each to its .hgt, or move it out of the folder")
        files = sorted(f for f in p.iterdir() if f.suffix.lower() in (".hgt", ".json") and f.is_file())
        if not files:
            raise GeoLocateError(f"DEM folder {p} holds no .hgt or .json tile")
        if len(files) > MAX_DEM_TILES:
            raise GeoLocateError(f"DEM folder {p} holds more than {MAX_DEM_TILES} tiles; keep the area's only")
        return DEMMosaic([load_dem(f) for f in files])
    if p.suffix.lower() in _PACKED_SUFFIXES:
        raise GeoLocateError(f"DEM tile {p.name} is packed: unpack it to its .hgt first")
    if p.suffix.lower() == ".hgt":
        return DEMGrid.from_hgt(p)
    return DEMGrid.from_mapping(_read_json_file(p, "DEM"))


def _dataset_dem(dataset_root: str | Path | None) -> DEMGrid | DEMMosaic:
    """The dataset's DEM: the ``dem/`` tile folder when the dataset has one, else ``dem.json``."""
    root = _dataset_dir(dataset_root)
    if (root / "dem").is_dir():
        return load_dem(root / "dem")
    if (root / "dem.json").is_file():
        return load_dem(root / "dem.json")
    raise GeoLocateError(f"DEM not found: {root} has neither a dem/ folder of .hgt tiles nor dem.json")


def dem_horizon_profile(dem: Any, lat: float, lon: float, *, eye_height_m: float = DEFAULT_EYE_HEIGHT_M,
                        azimuth_step_deg: float = 5.0, azimuths: Iterable[float] | None = None,
                        step_m: float = DEFAULT_STEP_M, max_distance_m: float = DEFAULT_MAX_DISTANCE_M,
                        refraction_coeff: float = DEFAULT_REFRACTION_COEFF,
                        earth_curvature: bool = True) -> list[dict[str, float]]:
    """Compute the DEM horizon elevation angle at each azimuth for an observer at (lat, lon).

    For each azimuth a ray is stepped outward; at each step the terrain elevation is sampled and the
    apparent elevation angle to that point is computed (observer eye height, and optionally Earth
    curvature with standard refraction, subtracted).  The horizon is the maximum angle along the ray.
    Returns ``[{azimuth_deg, elevation_deg}, ...]`` -- the shape osint_depth.rank_terrain_horizons
    consumes.  Azimuths with no valid terrain sample are omitted."""
    observer_ground = dem.elevation(lat, lon)
    if observer_ground is None:
        raise GeoLocateError("observer coordinate is outside the DEM or on a nodata cell")
    eye = observer_ground + _finite(eye_height_m, "eye height")
    step = _finite(step_m, "step_m")
    max_distance = _finite(max_distance_m, "max_distance_m")
    if not 0 < step <= max_distance <= 500_000:
        raise GeoLocateError("need 0 < step_m <= max_distance_m <= 500000")
    refraction = _finite(refraction_coeff, "refraction_coeff")
    if azimuths is not None:
        az_list = [_finite(a, "azimuth") % 360.0 for a in list(azimuths)[:MAX_AZIMUTHS]]
    else:
        az_step = _finite(azimuth_step_deg, "azimuth_step_deg")
        if not 0 < az_step <= 180:
            raise GeoLocateError("azimuth_step_deg must be in 0..180")
        az_list = [i * az_step for i in range(int(360.0 / az_step))]
    if len(az_list) < 2:
        raise GeoLocateError("need at least two azimuths for a profile")

    profile: list[dict[str, float]] = []
    for azimuth in az_list:
        best = None
        distance = step
        while distance <= max_distance:
            plat, plon = destination_point(lat, lon, azimuth, distance)
            ground = dem.elevation(plat, plon)
            if ground is not None:
                drop = 0.0
                if earth_curvature:
                    drop = (1.0 - refraction) * distance * distance / (2.0 * EARTH_RADIUS_M)
                angle = math.degrees(math.atan2(ground - eye - drop, distance))
                if best is None or angle > best:
                    best = angle
            distance += step
        if best is not None:
            profile.append({"azimuth_deg": azimuth, "elevation_deg": max(-90.0, min(90.0, best))})
    if len(profile) < 2:
        raise GeoLocateError("the DEM produced fewer than two horizon samples around this observer")
    return profile


def match_skyline(observed_profile: Iterable[Any], observer_candidates: Mapping[str, Any], *,
                  dem: Any = None, dem_path: str | Path | None = None,
                  dataset_root: str | Path | None = None, tolerance_deg: float = 3.0,
                  north_offset_hypotheses_deg: Iterable[float] = (0.0,),
                  horizon_kwargs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Rank supplied candidate observer coordinates by how well the DEM-derived horizon at each
    matches a measured skyline profile.  `observer_candidates` maps a name to a coordinate; the DEM
    comes from `dem`, `dem_path` (a tile, a grid or a folder of tiles), or the dataset (``dem/``,
    else ``dem.json``).  Matching runs through osint_depth.rank_terrain_horizons (orientation
    hypotheses, RMSE, tolerance).  A candidate the DEM does not cover is listed under ``skipped``."""
    if dem is None:
        dem = load_dem(dem_path) if dem_path is not None else _dataset_dem(dataset_root)
    if not isinstance(observer_candidates, Mapping) or not observer_candidates:
        raise GeoLocateError("observer_candidates must be a non-empty {name: coordinate} mapping")
    if len(observer_candidates) > MAX_CANDIDATES:
        raise GeoLocateError(f"more than {MAX_CANDIDATES} observer candidates")
    kwargs = dict(horizon_kwargs or {})
    coords: dict[str, tuple[float, float]] = {}
    profiles: dict[str, list[dict[str, float]]] = {}
    skipped: list[dict[str, str]] = []
    for raw_name, raw_coord in observer_candidates.items():
        name = _text(raw_name, "observer candidate name")
        coord = _coordinate(raw_coord, f"observer candidate {name!r}")
        coords[name] = coord
        try:
            profiles[name] = dem_horizon_profile(dem, coord[0], coord[1], **kwargs)
        except GeoLocateError as exc:
            skipped.append({"name": name, "reason": str(exc)})
    if not profiles:
        raise GeoLocateError("no observer candidate produced a DEM horizon profile "
                             "(all outside the DEM or on nodata); check the dataset covers the area")
    try:
        ranking = depth.rank_terrain_horizons(observed_profile, profiles,
                                               north_offset_hypotheses_deg=north_offset_hypotheses_deg,
                                               tolerance_deg=tolerance_deg)
    except GeoLocateError:
        raise
    except ValueError as exc:
        raise GeoLocateError(f"skyline profile: {exc}") from exc
    for row in ranking["candidates"]:
        coord = coords.get(row["name"])
        if coord is not None:
            row["lat"], row["lon"] = coord
    return _human_report(
        "dem_skyline_match",
        candidate_count=len(ranking["candidates"]),
        candidates=ranking["candidates"],
        orientation_hypotheses_deg=ranking.get("orientation_hypotheses_deg"),
        skipped=skipped,
        caveat=ranking.get("caveat"),
    )


# =====================================================================================
#  (5) checker POST: the page's map-pin checker, then the flag through the submit gate
# =====================================================================================

def format_coordinate_answer(lat: float, lon: float, *, precision: int = 6) -> str:
    """Canonical ``"lat, lon"`` answer string for a coordinate the player/model named."""
    lat = _finite(lat, "answer latitude")
    lon = _finite(lon, "answer longitude")
    if not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise GeoLocateError("answer coordinate is outside Earth bounds")
    if not 0 <= int(precision) <= 10:
        raise GeoLocateError("precision must be 0..10")
    return f"{round(lat, int(precision))}, {round(lon, int(precision))}"


def submit_named_location(answer: str, challenge_id: str, *, provenance: str, profile: Any = None,
                          gate: Any = None, allow_nonstandard: bool = False,
                          confirmed: bool = False) -> SubmitResult:
    """Send an answer a model, a player or a page checker *named* through the one road to a platform
    submission: :func:`ctf.platform.get_adapter` -> :meth:`SubmitGate.submit`.

    The plausibility check every submitter runs first (:func:`ctf.flagcheck.check`, docs/CONTRACTS.md
    section 40) runs here too: a value that can never be an answer (empty body, control characters)
    comes back ``not_allowed`` with ``sent=False`` and nothing reaches the gate.  `allow_nonstandard`
    is False by default, as at the gate: a flag read from a page checker is in the event format; pass
    True only for a coordinate or venue answer the brief defines.  `confirmed` is passed through
    unchanged, so an event in confirm mode still needs the player's confirmation.  `provenance` is
    required.  A `gate` may be injected; otherwise it is built from `profile` or the current event.
    The command-line form of a plain answer is ``python -m ctf submit``; this function is for a
    caller that already holds the value, such as :func:`check_and_submit`."""
    text = _text(answer, "answer", limit=4096)
    cid = _text(challenge_id, "challenge id", limit=256)
    note = _text(provenance, "provenance", limit=1000)
    if gate is None:
        from ctf.platform import get_adapter
        if profile is None:
            profile = _event.current()
        gate = get_adapter(profile)
    prof = profile if profile is not None else getattr(gate, "profile", None)
    if prof is None:
        raise GeoLocateError("submit needs the event profile (pass profile=, or a gate that carries one)")
    try:
        verdict = _flagcheck.check(text, prof, allow_nonstandard=bool(allow_nonstandard))
    except _flagcheck.FlagCheckError as exc:
        raise GeoLocateError(f"plausibility check: {exc}") from exc
    if verdict.refuses:
        codes = ", ".join(sorted(set(verdict.codes()) & set(_flagcheck.REFUSE_CODES))) or "blocked"
        return SubmitResult(SubmitStatus.NOT_ALLOWED, sent=False,
                            message=f"the plausibility check blocks this value ({codes}); nothing sent")
    return gate.submit(cid, text, provenance=note, allow_nonstandard=bool(allow_nonstandard),
                       confirmed=bool(confirmed))


def check_and_submit(geo_checker: "checker.GeoChecker", lat: float, lon: float, *, provenance: str,
                     gate: Any = None, profile: Any = None, confirmed: bool = False) -> dict[str, Any]:
    """Post a named coordinate to the page checker and, when the reply carries exactly one flag in
    the event format, send that flag through the submit gate as a flag (never as a non-standard
    answer).  Returns ``{"check": CheckOutcome, "submit": SubmitResult | None, "submit_skipped":
    reason | None}``.  The flag goes to the gate exactly as the checker spelled it."""
    outcome = geo_checker.check(lat, lon)
    result: SubmitResult | None = None
    skipped = None
    if not outcome.flags:
        skipped = "the checker returned no flag in the event format"
    elif len(outcome.flags) > 1:
        skipped = f"the checker returned {len(outcome.flags)} flag-shaped values; a reader picks one"
    else:
        result = submit_named_location(
            outcome.flags[0], geo_checker.challenge_id,
            provenance=f"{_text(provenance, 'provenance', limit=800)} [flag returned by the challenge page's "
                       f"map-pin checker for {format_coordinate_answer(lat, lon)}]",
            gate=gate, profile=profile if profile is not None else geo_checker.profile,
            allow_nonstandard=False, confirmed=confirmed)
    return {"check": outcome, "submit": result, "submit_skipped": skipped}


# =====================================================================================
#  CLI
# =====================================================================================

def _emit(report: Mapping[str, Any], result: SolverResult) -> int:
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str, allow_nan=False))
    print(result.to_json())
    return 0


def _candidate_line(row: Mapping[str, Any]) -> str:
    label = row.get("name") or row.get("id") or row.get("value") or "candidate"
    parts = [str(label)]
    if row.get("lat") is not None and row.get("lon") is not None:
        parts.append(f"{float(row['lat']):.6f}, {float(row['lon']):.6f}")
    if row.get("id") and row.get("id") != label:
        parts.append(str(row["id"]))
    if row.get("distance_m") is not None:
        parts.append(f"{row['distance_m']:.0f} m from the near point")
    if row.get("rmse_deg") is not None:
        parts.append(f"skyline rmse {row['rmse_deg']:.2f} deg")
    return " | ".join(parts)[:300]


def result_for(report: Mapping[str, Any]) -> SolverResult:
    """The SolverResult of a resolver report: ``unsure`` with the top candidates as evidence (a
    reader names the place), ``none`` when there is no candidate."""
    rows = list(report.get("candidates") or [])
    total = report.get("candidate_count", len(rows))
    if not rows:
        return SolverResult(status="none", engine=ENGINE, notes=f"{report['kind']}: no candidate")
    evidence = tuple(Evidence("match", _candidate_line(row)) for row in rows[:10])
    return SolverResult(status="unsure", engine=ENGINE, evidence=evidence,
                        notes=f"{report['kind']}: {total} candidate(s), ranked evidence only; a model or "
                              "the player names the location")


def _checker_result(report: Mapping[str, Any], challenge_id: str) -> SolverResult:
    check = report["check"]
    where = f"map-pin checker at {check['check_host']}"
    if check["flags"]:
        note = "flag read from the checker's reply"
        if report.get("submit") is not None:
            note += f"; submit gate: {report['submit']['status']} (sent={report['submit']['sent']})"
        elif report.get("submit_skipped"):
            note += f"; not submitted: {report['submit_skipped']}"
        return SolverResult(status="solved", flags=tuple(check["flags"]), engine=ENGINE, challenge_id=challenge_id,
                            evidence=(Evidence("oracle", f"{where} answered the named coordinate with a flag"),),
                            notes=note)
    if check["ok"]:
        return SolverResult(status="unsure", engine=ENGINE, challenge_id=challenge_id,
                            evidence=(Evidence("oracle", f"{where} accepted the coordinate but its reply "
                                                         "carries no value in the event flag format"),),
                            notes="read the checker's message by hand")
    return SolverResult(status="none", engine=ENGINE, challenge_id=challenge_id,
                        notes=f"{where} rejected the coordinate; {check['attempts_left']} check(s) left "
                              "for this challenge")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def _build_parser() -> _Parser:
    parser = _Parser(prog="osint_geolocate.py", description="frozen-dataset OSINT geolocation resolvers (B-113)")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    opener = sub.add_parser("open", help="sign OCR of an image -> brand and OSM name candidates")
    opener.add_argument("image", nargs="?")
    opener.add_argument("--ocr-text", help="a text file to use instead of running tesseract")
    opener.add_argument("--dataset")
    opener.add_argument("--only", choices=OPEN_SOURCES, action="append", help="run one lookup (repeatable)")

    brand = sub.add_parser("brand", help="resolve a brand/business name to candidate map locations")
    brand.add_argument("name")
    brand.add_argument("--near", nargs=2, type=float, metavar=("LAT", "LON"))
    brand.add_argument("--dataset")
    brand.add_argument("--directory", help="explicit brands.json path")

    osm = sub.add_parser("osm", help="solve OSM/Overpass constraints to candidate features")
    osm.add_argument("constraints", help="path to a constraints JSON file")
    osm.add_argument("--dataset")
    osm.add_argument("--extract", help="explicit frozen OSM extract path")
    osm.add_argument("--online", action="store_true",
                     help="query live Overpass (allowed only if the event profile lists the host)")
    osm.add_argument("--date", help="Overpass attic date for --online (YYYY-MM-DD)")

    sweep = sub.add_parser("sweep", help="solve the constraints against several map snapshots")
    sweep.add_argument("constraints")
    sweep.add_argument("--dataset")
    sweep.add_argument("--snapshot", action="append", default=[], metavar="LABEL=FILE",
                       help="a dated frozen extract (repeatable); default <dataset>/snapshots/*.jsonl")
    sweep.add_argument("--online", action="store_true")
    sweep.add_argument("--date", action="append", default=[], help="attic date for --online (repeatable)")

    venue = sub.add_parser("venue", help="a named venue -> polygon centre and entrances")
    venue.add_argument("name")
    venue.add_argument("--near", nargs=2, type=float, metavar=("LAT", "LON"))
    venue.add_argument("--dataset")
    venue.add_argument("--extract")

    variants = sub.add_parser("variants", help="spellings of a feature name for a prefix{NAME} flag")
    variants.add_argument("name", nargs="?")
    variants.add_argument("--tags", help="a JSON file with the feature's OSM tags")
    variants.add_argument("--limit", type=int, default=64)

    skyline = sub.add_parser("skyline", help="match a measured skyline against DEM horizon profiles")
    skyline.add_argument("observed", help="observed horizon profile JSON ([{azimuth_deg,elevation_deg}])")
    skyline.add_argument("candidates", help="{name: [lat, lon]} observer-candidate JSON")
    skyline.add_argument("--dem", help="an .hgt tile, a DEM grid JSON, or a folder of tiles")
    skyline.add_argument("--dataset")
    skyline.add_argument("--tolerance", type=float, default=3.0)
    skyline.add_argument("--eye-height", type=float, default=DEFAULT_EYE_HEIGHT_M)
    skyline.add_argument("--step", type=float, default=DEFAULT_STEP_M, help="ray step, metres")
    skyline.add_argument("--max-distance", type=float, default=DEFAULT_MAX_DISTANCE_M)
    skyline.add_argument("--azimuth-step", type=float, default=5.0)
    skyline.add_argument("--no-curvature", action="store_true", help="ignore Earth curvature and refraction")
    skyline.add_argument("--north-offset", type=float, action="append", default=[],
                         help="a camera north-offset hypothesis in degrees (repeatable; default 0)")

    build = sub.add_parser("build-brands", help="cut brands.json from a frozen OSM extract")
    build.add_argument("extract")
    build.add_argument("--out", required=True)
    build.add_argument("--force", action="store_true")

    check = sub.add_parser("check", help="post a named coordinate to the challenge page's map-pin checker")
    check.add_argument("page_url")
    check.add_argument("challenge_id")
    check.add_argument("lat", type=float)
    check.add_argument("lon", type=float)
    check.add_argument("--provenance", required=True, help="where the coordinate came from (for the write-up)")
    check.add_argument("--check-url", help="the checker endpoint, when the page is not to be read for it")
    check.add_argument("--encoding", choices=checker.ENCODINGS)
    check.add_argument("--lat-field")
    check.add_argument("--lon-field")
    check.add_argument("--max-attempts", type=int,
                       help="posts allowed for this challenge and endpoint (default: 3 or the event's "
                            "wrong_answer_stop, whichever is lower; above that needs --cap-note)")
    check.add_argument("--cap-note", help="the player's say for a raised --max-attempts (goes to the ledger)")
    check.add_argument("--submit", action="store_true", help="send a returned flag through the submit gate")
    check.add_argument("--confirm", action="store_true", help="the player confirmed the submit (confirm mode)")
    return parser


def _run_check(args: argparse.Namespace) -> tuple[dict[str, Any], SolverResult]:
    _text(args.provenance, "provenance", limit=800)
    if args.check_url:
        # The page is not read, so nothing says what the endpoint takes: the caller names all of it.
        unnamed = [flag for flag, value in (("--encoding", args.encoding), ("--lat-field", args.lat_field),
                                            ("--lon-field", args.lon_field)) if not value]
        if unnamed:
            raise GeoLocateError(f"--check-url skips reading the page, so {', '.join(unnamed)} must be named "
                                 "too: nothing is posted with guessed field names or encoding")
        geo_checker = checker.GeoChecker(args.page_url, args.challenge_id, check_url=args.check_url,
                                         encoding=args.encoding, lat_field=args.lat_field, lon_field=args.lon_field,
                                         max_checks=args.max_attempts, cap_note=args.cap_note)
        detection = None
    else:
        geo_checker = checker.GeoChecker.from_page(args.page_url, args.challenge_id, max_checks=args.max_attempts,
                                                   cap_note=args.cap_note, encoding=args.encoding,
                                                   lat_field=args.lat_field, lon_field=args.lon_field)
        detection = geo_checker.detection
    if args.submit:
        both = check_and_submit(geo_checker, args.lat, args.lon, provenance=args.provenance, confirmed=args.confirm)
        outcome, sent, skipped = both["check"], both["submit"], both["submit_skipped"]
    else:
        outcome, sent, skipped = geo_checker.check(args.lat, args.lon), None, "no --submit"
    report = {
        "kind": "geo_checker_post",
        "challenge_id": geo_checker.challenge_id,
        "detection": detection,
        "check": outcome.to_dict(),
        "submit": None if sent is None else {"status": sent.status.value, "sent": sent.sent,
                                             "accepted": sent.accepted, "message": sent.message},
        "submit_skipped": skipped if sent is None else None,
    }
    return report, _checker_result(report, geo_checker.challenge_id)


def _run(args: argparse.Namespace) -> tuple[dict[str, Any], SolverResult]:
    if args.command == "open":
        if args.image is None and args.ocr_text is None:
            raise GeoLocateError("give an image, or --ocr-text FILE")
        text = None
        if args.ocr_text:
            text_path = Path(args.ocr_text).expanduser()
            if not text_path.is_file():
                raise GeoLocateError(f"OCR text file not found at {text_path}")
            text = text_path.read_text(encoding="utf-8", errors="replace")
        report = open_image(args.image, ocr_text=text, dataset_root=args.dataset,
                            sources=tuple(args.only) if args.only else OPEN_SOURCES)
    elif args.command == "brand":
        directory = load_brand_directory(path=args.directory) if args.directory else None
        report = resolve_brand(args.name, dataset_root=args.dataset, directory=directory,
                               near=(tuple(args.near) if args.near else None))
    elif args.command == "osm":
        constraints = _read_json_file(Path(args.constraints).expanduser(), "constraints")
        if args.date:
            if not args.online:
                raise GeoLocateError("--date is an Overpass attic date: it needs --online (the frozen "
                                     "extract is one snapshot; use `sweep` for dated extracts)")
            if not isinstance(constraints, Mapping):
                raise GeoLocateError("constraints must be a mapping")
            constraints = dict(constraints, date=args.date)
        report = solve_osm_constraints(constraints, dataset_root=args.dataset,
                                       extract_path=args.extract, online=args.online)
    elif args.command == "sweep":
        constraints = _read_json_file(Path(args.constraints).expanduser(), "constraints")
        snapshots = None
        if args.snapshot:
            snapshots = {}
            for item in args.snapshot:
                label, sep, file = item.partition("=")
                if not sep or not label or not file:
                    raise GeoLocateError(f"--snapshot takes LABEL=FILE; got {item!r}")
                snapshots[label] = file
        report = sweep_osm_snapshots(constraints, snapshots=snapshots, dataset_root=args.dataset,
                                     dates=args.date or None, online=args.online)
    elif args.command == "venue":
        report = resolve_venue(args.name, dataset_root=args.dataset, extract_path=args.extract,
                               near=(tuple(args.near) if args.near else None))
    elif args.command == "variants":
        tags = _read_json_file(Path(args.tags).expanduser(), "tags") if args.tags else None
        rows = name_variants(args.name, tags=tags, limit=args.limit)
        report = {"kind": "name_variants", "candidate_count": len(rows), "candidates": rows,
                  "note": "spellings only; send them through `python -m ctf flag variants` so the guess budget holds"}
    elif args.command == "skyline":
        observed = _read_json_file(Path(args.observed).expanduser(), "observed profile")
        raw_candidates = _read_json_file(Path(args.candidates).expanduser(), "observer candidates")
        if not isinstance(raw_candidates, Mapping):
            raise GeoLocateError("observer candidates file must be a {name: [lat, lon]} object")
        report = match_skyline(
            observed, raw_candidates, dem_path=args.dem, dataset_root=args.dataset, tolerance_deg=args.tolerance,
            north_offset_hypotheses_deg=tuple(args.north_offset) or (0.0,),
            horizon_kwargs={"eye_height_m": args.eye_height, "step_m": args.step,
                            "max_distance_m": args.max_distance, "azimuth_step_deg": args.azimuth_step,
                            "earth_curvature": not args.no_curvature})
    elif args.command == "build-brands":
        directory, stats = build_brand_directory(args.extract)
        out = write_brand_directory(directory, args.out, force=args.force)
        report = {"kind": "brand_directory_built", "out": str(out), "stats": stats}
        return report, SolverResult(status="none", engine=ENGINE,
                                    notes=f"wrote {stats['labels']} brand label(s) to {out.name}; a dataset "
                                          "build step, not a solve")
    else:
        return _run_check(args)
    return report, result_for(report)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        print(f"osint_geolocate: usage: {exc}", file=sys.stderr)
        return 2
    try:
        report, result = _run(args)
    except (GeoLocateError, checker.GeoCheckError, scope.OutOfScope, _event.EventError, PlatformError,
            ResultError, FileNotFoundError) as exc:
        # A result, not a crash (docs/CONTRACTS.md section 6): the reason on stderr and in `notes`.
        print(f"osint_geolocate: {exc}", file=sys.stderr)
        print(SolverResult(status="blocked", engine=ENGINE,
                           notes=f"{args.command}: {exc}"[:2000]).to_json())
        return 0
    return _emit(report, result)


__all__ = [
    "GeoLocateError", "UsageError", "DEMGrid", "DEMMosaic", "destination_point", "distance_m", "ring_metrics",
    "normalise_feature", "iter_osm_extract", "new_extract_stats", "require_features",
    "load_brand_directory", "resolve_brand", "build_brand_directory", "write_brand_directory",
    "solve_osm_constraints", "build_overpass_query", "overpass_transport", "sweep_osm_snapshots",
    "name_variants", "resolve_venue", "open_clues", "open_image",
    "load_dem", "dem_horizon_profile", "match_skyline",
    "format_coordinate_answer", "submit_named_location", "check_and_submit", "result_for", "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
