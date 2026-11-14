#!/usr/bin/env python3
"""Geo-sensor reconciliation + schema-shaped report harness (B-111).

CSCTF 9101 handed out a per-team instance serving two sensor logs of the same vessels (a broadcast AIS
log in UTC, an anonymous radar log on a skewed clock), a reference point with a fault window, a method
note and a ``/schema`` for the report; a correct report POSTed to ``/reconcile`` returned the flag.
The geometry was written by hand. This module is that pipeline as a configurable method:

  * **Time alignment.** Each sensor's clock offset is a number, a hint read from the evidence
    (``local_time = UTC+60 min``) or an estimate (the offset that makes the tracks agree).
  * **Projection.** Positions go to a local east/north plane about an origin: the method-note form
    (``east = R cos(lat0) dlon, north = R dlat``) or a WGS-84 ENU tangent plane.
  * **Nearest-track association.** A residual statistic per (radar track, AIS id) and an optimal
    one-to-one assignment over it.
  * **Divergence.** Per associated pair, the windows where AIS-minus-radar leaves the threshold: the
    displaced (spoofed) broadcast, with its constant east/north offset.
  * **Closest approach.** The interpolated closest approach of a track to a point (or another track),
    optionally inside a time window.
  * **Schema-shaped report.** The report is built by walking the instance's ``/schema`` (a JSON Schema
    subset, or an example-shaped document) and filling each leaf from the computed facts, then
    validated against that schema. A required leaf with no known source leaves the report incomplete,
    by name; nothing is guessed.

Every choice the method did not state (a detected column, a clock hint, the pairing mode) is listed in
``decisions`` so a model or the player can check it before anything is sent. The method is a JSON
document (``default_method()``); a per-case adapter is an edited copy of it.

Live side. Evidence and ``/schema`` are fetched through B-081's mirror (``ics_mirror.mirror_http`` on
a GET-only ``web.WebClient``, scope-checked by ``ctf.scope``) and written as a B-081 evidence pack.
``POST /reconcile`` is a rate-limited judge, so the default is a dry run. A send needs the event
profile's ``rules.web_state_changing = true`` AND explicit player approval
(``ics_mirror.authorize_state_change``), a complete and schema-valid report, and room in the POST
ledger: sends are paced, capped, never repeated for a report that was already judged, and a 429 is
retried at most as often as the method allows. A flag in the response is returned as a candidate; this
module never submits it to the platform.

Everything the instance returns is DATA: parsed, measured and written to the pack, never executed and
never treated as an instruction.

CLI: ``python -m ctf geo-reconcile run|offline|method`` (ctf/cli/geo_reconcile.py). As a script:

  .venv/bin/python solvers/toolkits/geo_reconcile.py method              # print the default method
  .venv/bin/python solvers/toolkits/geo_reconcile.py offline <pack-dir>  # recompute from a mirrored pack
"""
from __future__ import annotations

import bisect
import contextlib
import copy
import csv
import datetime as _dt
import fcntl
import hashlib
import io
import json
import math
import os
import re
import socket
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(HERE), str(COMMON)):
    if _p not in sys.path:
        sys.path.insert(1, _p)

try:
    from ctf import flagfmt as _flagfmt
except ModuleNotFoundError:  # pragma: no cover - only when run as a bare script outside the checkout
    sys.path.append(str(HERE.parents[1]))
    from ctf import flagfmt as _flagfmt
from ctf import scope as _ctf_scope  # noqa: E402  (web.OutOfScope is a ctf.scope.OutOfScope)

import ics_mirror  # noqa: E402  (B-081: the GET-only mirror, the evidence pack, the state-change gate)
import osint_geo_math as _geomath  # noqa: E402  (the shared lat/lon range check)

ENGINE_ID = "toolkits.geo_reconcile"
MEAN_EARTH_RADIUS_M = 6_371_008.8
WGS84_A = 6_378_137.0
WGS84_F = 1 / 298.257223563
REPORT_NAME = "report.json"
RECONCILIATION_NAME = "reconciliation.json"
POST_LEDGER_NAME = "posts.jsonl"
RESPONSE_NAME = "post-response.bin"
_UNASSIGNABLE = 1e15


class ReconcileError(RuntimeError):
    """A reconciliation problem with a named reason (no silent fallback)."""


class EvidenceError(ReconcileError):
    """An evidence file is missing, unparseable or lacks a column the method needs."""


class MethodError(ReconcileError):
    """The method is malformed, or leaves a choice open that the evidence does not settle."""


class ReportError(ReconcileError):
    """The report cannot be shaped from the schema (unsupported schema construct, bad mapping)."""


class PostRefused(ReconcileError):
    """A POST was not sent: the report is not ready, or the POST ledger's pacing or budget forbids it."""


# ======================================================================================
#  The method (a JSON document; a per-case adapter is an edited copy)
# ======================================================================================

_DEFAULT_METHOD: dict = {
    # Documented routes on the instance, by role. `schema` and the two sensors are required.
    "routes": {"schema": "/schema", "ais": "/files/ais.ndjson", "radar": "/files/radar.csv",
               "reference": "/files/cable-fault.txt", "note": "/files/method-note.txt"},
    "submit": "/reconcile",
    "date": None,                # YYYY-MM-DD for time-only stamps; default: the other sensor's date
    # Column names; null = detect from the usual spellings (recorded as a decision).
    "ais": {"id": None, "time": None, "lat": None, "lon": None, "clock_offset_s": 0},
    "radar": {"id": None, "time": None, "lat": None, "lon": None, "range_m": None, "bearing_deg": None,
              "site": None,      # {"lat","lon"} of the radar, for range/bearing logs
              "clock_offset_s": "auto"},   # seconds the sensor clock is AHEAD of UTC | "auto" | "hint" | "estimate"
    "origin": "auto",            # {"lat","lon"} | "auto" (the reference point, else the radar centroid)
    "reference": {"point": "auto", "window": "auto"},   # point: {"lat","lon"}; window: [start, end] | null
    "projection": {"model": "local_plane",   # local_plane | wgs84_enu
                   "radius_m": "auto"},      # sphere radius for local_plane: a number, or the note's, else the mean
    "match": {"pairing": "auto",             # exact | interpolate | auto
              "tolerance_s": 1.0, "max_gap_s": 600.0, "min_common": 2,
              "statistic": "median",         # median | mean | rms | max
              "assignment": "optimal",       # optimal | mutual_nearest
              "max_residual_m": None},
    "divergence": {"threshold_m": 50.0, "min_samples": 2, "constant_tolerance_m": 5.0,
                   "pick": "only"},          # only | longest | largest | <ais id>
    "closest_approach": {"source": "radar",  # radar | ais
                         "target": "divergent",   # divergent | all | <id on the source sensor>
                         "to": "reference",  # reference | {"lat","lon"} | {"sensor","id"}
                         "window": "reference",   # reference | null | [start, end]
                         "interpolate": True},
    "report": {"schema_pointer": "",         # JSON pointer inside the /schema document to the report shape
               "fields": {},                 # schema path -> fact path ("-" prefix negates) | {"value": x}
               "decimals": 3, "time_format": "iso_z", "time_decimals": 0},
    "post": {"min_interval_s": 30.0, "max_posts": 3, "ratelimit_retries": 1, "max_wait_s": 120.0},
}


def default_method() -> dict:
    """A fresh copy of the default method (the CSCTF 9101 shape, every unknown left on auto)."""
    return copy.deepcopy(_DEFAULT_METHOD)


def _merge(base: dict, user: Mapping, where: str) -> dict:
    for key, value in user.items():
        if key not in base:
            raise MethodError(f"unknown method key {where + str(key)!r} (known: {', '.join(sorted(base))})")
        # `routes` and `report.fields` are open maps; every other table has a fixed key set.
        open_map = (where + key) in ("routes", "report.fields")
        if isinstance(base[key], dict) and not isinstance(value, Mapping):
            raise MethodError(f"method key {where + str(key)!r} must be an object; got {value!r}")
        if open_map:
            base[key] = {**base[key], **copy.deepcopy(dict(value))}
        elif isinstance(base[key], dict):
            _merge(base[key], value, f"{where}{key}.")
        else:
            base[key] = copy.deepcopy(dict(value) if isinstance(value, Mapping) else value)
    return base


def load_method(user: Mapping | None = None) -> dict:
    """The default method with `user` merged over it. An unknown key is a MethodError naming it."""
    method = default_method()
    if user is None:
        return method
    if not isinstance(user, Mapping):
        raise MethodError("a method is a JSON object")
    return _merge(method, user, "")


def _choice(value: Any, allowed: Sequence[str], where: str) -> str:
    if value not in allowed:
        raise MethodError(f"{where} must be one of {', '.join(allowed)}; got {value!r}")
    return value


# ======================================================================================
#  Time
# ======================================================================================

_TIME_ONLY = re.compile(r"^(\d{1,2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?\s*(Z|UTC)?$", re.I)
_NUMERIC = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_UTC = _dt.timezone.utc


def parse_time(value: Any, *, date: _dt.date | None = None) -> tuple[float, bool]:
    """One timestamp as (seconds since the epoch, carried_its_own_offset).

    Accepts epoch seconds (or milliseconds, above 1e11), ISO-8601 with ``Z``/an offset (explicit: the
    second element is True), ISO-8601 without one, and ``HH:MM[:SS]`` (needs `date`). A stamp with no
    offset is read on the sensor's own clock: the caller subtracts that clock's offset from UTC."""
    if isinstance(value, bool) or value is None:
        raise EvidenceError(f"not a timestamp: {value!r}")
    if isinstance(value, (int, float)) or _NUMERIC.match(str(value).strip()):
        number = float(value)
        if not math.isfinite(number):
            raise EvidenceError(f"not a timestamp: {value!r}")
        return (number / 1000.0 if abs(number) > 1e11 else number), True
    text = str(value).strip()
    m = _TIME_ONLY.match(text)
    if m:
        if date is None:
            raise EvidenceError(f"time-only stamp {text!r} needs a date: set method \"date\": \"YYYY-MM-DD\"")
        seconds = float(m.group(3) or 0.0)
        base = _dt.datetime(date.year, date.month, date.day, int(m.group(1)) % 24, int(m.group(2)),
                            tzinfo=_UTC)
        return base.timestamp() + seconds, bool(m.group(4))
    iso = re.sub(r"\s*(?:Z|UTC)$", "+00:00", text, flags=re.I).replace(" ", "T", 1)
    try:
        stamp = _dt.datetime.fromisoformat(iso)
    except ValueError:
        raise EvidenceError(f"not a timestamp: {text!r}") from None
    if stamp.tzinfo is None:
        return stamp.replace(tzinfo=_UTC).timestamp(), False
    return stamp.timestamp(), True


def format_time(t: float, fmt: str = "iso_z", decimals: int = 0) -> Any:
    """Epoch seconds as the report wants them: ``iso_z`` (2026-11-06T11:31:38Z), ``iso_offset``
    (+00:00), ``epoch`` (a number), or a strftime pattern. Seconds are rounded to `decimals`."""
    t = round(float(t), int(decimals))
    if fmt == "epoch":
        return int(t) if decimals <= 0 else t
    stamp = _dt.datetime.fromtimestamp(t, _UTC)
    if fmt in ("iso_z", "iso_offset"):
        text = stamp.strftime("%Y-%m-%dT%H:%M:%S")
        if decimals > 0:
            text += f"{t % 1:.{int(decimals)}f}"[1:]
        return text + ("Z" if fmt == "iso_z" else "+00:00")
    if "%" not in fmt:
        raise MethodError(f"report.time_format {fmt!r} is not iso_z, iso_offset, epoch or a strftime pattern")
    return stamp.strftime(fmt)


_OFFSET_HINT = re.compile(
    r"UTC\s*([+-])\s*(\d{1,2}):(\d{2})"                                         # UTC+01:00
    r"|UTC\s*([+-])\s*(\d+(?:\.\d+)?)\s*(hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)?\b",
    re.I)


def clock_offset_hints(text: str) -> list[tuple[float, str]]:
    """Every ``UTC+60 min`` / ``UTC-2h`` / ``UTC+01:00`` / ``UTC+1`` in `text`, as (seconds the local
    clock is ahead of UTC, the matched text). A bare number is hours up to 14, minutes above. A hint for the method's
    ``clock_offset_s = "auto"``; an explicit number always wins."""
    out: list[tuple[float, str]] = []
    for m in _OFFSET_HINT.finditer(text or ""):
        if m.group(1):
            seconds = int(m.group(2)) * 3600 + int(m.group(3)) * 60
            sign = m.group(1)
        else:
            unit = (m.group(6) or ("h" if float(m.group(5)) <= 14 else "m")).lower()
            scale = 3600 if unit.startswith("h") else 60 if unit.startswith("m") else 1
            seconds = float(m.group(5)) * scale
            sign = m.group(4)
        out.append((-seconds if sign == "-" else seconds, m.group(0)))
    return out


# ======================================================================================
#  Projection
# ======================================================================================

def _coord(lat: Any, lon: Any, what: str = "position") -> tuple[float, float]:
    """osint_geo_math's lat/lon check (finite, on Earth), with the failure named as evidence."""
    try:
        return _geomath._coord(lat, lon)
    except (TypeError, ValueError):
        raise EvidenceError(f"{what} is not a lat/lon pair on Earth: {lat!r}, {lon!r}") from None


def _ecef(lat: float, lon: float) -> tuple[float, float, float]:
    e2 = WGS84_F * (2 - WGS84_F)
    p, l = math.radians(lat), math.radians(lon)
    n = WGS84_A / math.sqrt(1 - e2 * math.sin(p) ** 2)
    return n * math.cos(p) * math.cos(l), n * math.cos(p) * math.sin(l), n * (1 - e2) * math.sin(p)


@dataclass(frozen=True)
class Plane:
    """A local east/north plane about (lat0, lon0).

    ``local_plane``: east = R cos(lat0) dlon, north = R dlat on a sphere of `radius_m` (the form a
    method note usually states). ``wgs84_enu``: the WGS-84 tangent plane (geodetic -> ECEF -> ENU,
    height 0), which differs from the sphere by up to 0.6% in the north component."""
    lat0: float
    lon0: float
    model: str = "local_plane"
    radius_m: float = MEAN_EARTH_RADIUS_M

    def project(self, lat: float, lon: float) -> tuple[float, float]:
        lat, lon = _coord(lat, lon)
        if self.model == "local_plane":
            dlon = (lon - self.lon0 + 180.0) % 360.0 - 180.0
            return (self.radius_m * math.cos(math.radians(self.lat0)) * math.radians(dlon),
                    self.radius_m * math.radians(lat - self.lat0))
        if self.model == "wgs84_enu":
            x0, y0, z0 = _ecef(self.lat0, self.lon0)
            x, y, z = _ecef(lat, lon)
            dx, dy, dz = x - x0, y - y0, z - z0
            p, l = math.radians(self.lat0), math.radians(self.lon0)
            east = -math.sin(l) * dx + math.cos(l) * dy
            north = -math.sin(p) * math.cos(l) * dx - math.sin(p) * math.sin(l) * dy + math.cos(p) * dz
            return east, north
        raise MethodError(f"projection.model must be local_plane or wgs84_enu; got {self.model!r}")


def polar_to_en(range_m: float, bearing_deg: float) -> tuple[float, float]:
    """A radar range/bearing (degrees clockwise from north) as an east/north offset from the site."""
    b = math.radians(float(bearing_deg))
    return float(range_m) * math.sin(b), float(range_m) * math.cos(b)


# ======================================================================================
#  Evidence parsing
# ======================================================================================

def _text(data: Any) -> str:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("utf-8", "replace")
    return str(data)


def parse_ndjson(data: Any, what: str = "ndjson") -> list[dict]:
    """One JSON object per line (a single JSON array of objects is accepted too). A line that is not a
    JSON object is an EvidenceError naming its line number, never dropped."""
    text = _text(data).strip()
    if text.startswith("["):
        try:
            rows = json.loads(text)
        except ValueError as e:
            raise EvidenceError(f"{what}: not JSON ({e})") from None
    else:
        rows = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as e:
                raise EvidenceError(f"{what}: line {n} is not JSON ({e})") from None
    if not rows or not all(isinstance(r, dict) for r in rows):
        raise EvidenceError(f"{what}: expected JSON objects, one per line")
    return rows


def parse_csv(data: Any, what: str = "csv") -> tuple[list[str], list[dict]]:
    """A CSV with optional ``#`` comment lines: (the comment lines, the rows as dicts). The delimiter
    is the one of ``, ; tab |`` the header line uses most."""
    comments, body = [], []
    for line in _text(data).splitlines():
        if line.lstrip().startswith("#"):
            comments.append(line.lstrip()[1:].strip())
        elif line.strip():
            body.append(line)
    if len(body) < 2:
        raise EvidenceError(f"{what}: no header line and data rows")
    delimiter = max(",;\t|", key=body[0].count)
    reader = csv.DictReader(io.StringIO("\n".join(body)), delimiter=delimiter, skipinitialspace=True)
    rows = [{(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            for row in reader]
    if not rows:
        raise EvidenceError(f"{what}: no data rows")
    return comments, rows


_ALIASES = {
    "ais.id": ("mmsi", "ais_mmsi", "vessel_id", "ship_id", "id", "name"),
    "radar.id": ("track", "track_id", "radar_track", "radar_id", "contact", "contact_id", "target", "id"),
    "time": ("utc", "time_utc", "timestamp", "ts", "datetime", "time", "t", "local_time", "time_local"),
    "lat": ("lat", "latitude", "lat_deg"),
    "lon": ("lon", "lng", "long", "longitude", "lon_deg"),
    "range_m": ("range_m", "range"),
    "bearing_deg": ("bearing_deg", "bearing", "azimuth_deg", "azimuth"),
}


def _column(rows: list[dict], given: Any, alias_key: str, what: str, decisions: list[str],
            *, required: bool = True) -> str | None:
    """The column to read: the method's name (it must exist), else the first usual spelling present."""
    columns = list(rows[0])
    if given is not None:
        if given not in columns:
            raise EvidenceError(f"{what}: no column {given!r} (columns: {', '.join(columns)})")
        return str(given)
    lowered = {c.lower(): c for c in columns}
    for alias in _ALIASES[alias_key]:
        if alias in lowered:
            decisions.append(f"{what}: read from column {lowered[alias]!r} (detected)")
            return lowered[alias]
    if required:
        raise EvidenceError(f"{what}: no column found (tried {', '.join(_ALIASES[alias_key])}; columns: "
                            f"{', '.join(columns)}); name it in the method")
    return None


@dataclass
class Track:
    """One sensor track: an id as the evidence spells it, and time-sorted samples on the plane."""
    id: Any
    t: list[float] = field(default_factory=list)
    east: list[float] = field(default_factory=list)
    north: list[float] = field(default_factory=list)

    def shifted(self, seconds: float) -> "Track":
        return Track(self.id, [x + seconds for x in self.t], list(self.east), list(self.north))

    def position(self, t: float) -> tuple[float, float] | None:
        """The linearly interpolated position at `t`, or None outside the track's time span."""
        if not self.t or t < self.t[0] or t > self.t[-1]:
            return None
        i = bisect.bisect_left(self.t, t)
        if self.t[i] == t:
            return self.east[i], self.north[i]
        t0, t1 = self.t[i - 1], self.t[i]
        u = (t - t0) / (t1 - t0)
        return (self.east[i - 1] + u * (self.east[i] - self.east[i - 1]),
                self.north[i - 1] + u * (self.north[i] - self.north[i - 1]))


def _raw_samples(rows: list[dict], spec: Mapping, sensor: str, decisions: list[str],
                 date: _dt.date | None) -> tuple[list[tuple], bool, bool]:
    """(id, time, lat|None, lon|None, range|None, bearing|None) per row, whether any stamp carried its
    own UTC offset, and whether any stamp was time-only (read on `date`)."""
    id_col = _column(rows, spec.get("id"), f"{sensor}.id", f"{sensor} id", decisions)
    time_col = _column(rows, spec.get("time"), "time", f"{sensor} time", decisions)
    polar = spec.get("range_m") is not None or spec.get("bearing_deg") is not None
    lat_col = lon_col = rng_col = brg_col = None
    if not polar:
        lat_col = _column(rows, spec.get("lat"), "lat", f"{sensor} latitude", decisions, required=False)
        lon_col = _column(rows, spec.get("lon"), "lon", f"{sensor} longitude", decisions, required=False)
    if lat_col is None or lon_col is None:
        rng_col = _column(rows, spec.get("range_m"), "range_m", f"{sensor} range", decisions, required=False)
        brg_col = _column(rows, spec.get("bearing_deg"), "bearing_deg", f"{sensor} bearing", decisions,
                          required=False)
        if rng_col is None or brg_col is None:
            raise EvidenceError(f"{sensor}: no lat/lon columns and no range/bearing columns (columns: "
                                f"{', '.join(rows[0])}); name them in the method")
    out, explicit, time_only = [], False, False
    for n, row in enumerate(rows, 1):
        try:
            time_only = time_only or bool(_TIME_ONLY.match(str(row.get(time_col)).strip()))
            t, own = parse_time(row.get(time_col), date=date)
            if rng_col is not None:
                sample = (row.get(id_col), t, None, None, float(row[rng_col]), float(row[brg_col]))
            else:
                lat, lon = _coord(row.get(lat_col), row.get(lon_col))
                sample = (row.get(id_col), t, lat, lon, None, None)
        except (EvidenceError, TypeError, ValueError, KeyError) as e:
            raise EvidenceError(f"{sensor} row {n}: {e}") from None
        if sample[0] in (None, ""):
            raise EvidenceError(f"{sensor} row {n}: empty id in column {id_col!r}")
        explicit = explicit or own
        out.append(sample)
    return out, explicit, time_only


def _tracks(samples: list[tuple], plane: Plane, site: tuple[float, float] | None, sensor: str) -> list[Track]:
    by_id: dict[Any, list[tuple[float, float, float]]] = {}
    for ident, t, lat, lon, rng, brg in samples:
        if rng is not None:
            if site is None:
                raise MethodError(f"{sensor} is a range/bearing log: set method {sensor}.site to the "
                                  "sensor's {\"lat\", \"lon\"}")
            de, dn = polar_to_en(rng, brg)
            east, north = site[0] + de, site[1] + dn
        else:
            east, north = plane.project(lat, lon)
        by_id.setdefault(ident, []).append((t, east, north))
    tracks = []
    for ident, points in by_id.items():
        points.sort(key=lambda p: p[0])
        if any(a[0] == b[0] and (a[1], a[2]) != (b[1], b[2]) for a, b in zip(points, points[1:])):
            raise EvidenceError(f"{sensor} id {ident!r} has two different positions at one time")
        points = [p for i, p in enumerate(points) if i == 0 or p[0] != points[i - 1][0]]
        tracks.append(Track(ident, [p[0] for p in points], [p[1] for p in points], [p[2] for p in points]))
    return tracks


_PAIR = re.compile(r"(?<![\d.])(-?\d{1,2}\.\d{3,})\s*°?\s*[NS]?\s*[,;/ ]\s*(-?\d{1,3}\.\d{3,})(?![\d.])")
_STAMP = r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?|\d{1,2}:\d{2}(?::\d{2})?\s?Z?)"
_WINDOW = re.compile(_STAMP + r"\s*(?:-|–|—|\.\.+|to|until|through|->)\s*" + _STAMP, re.I)
_RADIUS = re.compile(r"\bR\s*=\s*(6[23]\d{5}(?:\.\d+)?)\b|\b(6[23]\d{2}(?:\.\d+)?)\s*km\b")


def reference_hints(text: str) -> dict:
    """What a reference text (a fault notice, a method note) states, as hints: every distinct
    ``lat, lon`` pair, every ``start - end`` time window (as written), every Earth radius in metres."""
    text = text or ""
    points, windows, radii = [], [], []
    for m in _PAIR.finditer(text):
        try:
            pair = _coord(m.group(1), m.group(2))
        except EvidenceError:
            continue
        if pair not in points:
            points.append(pair)
    for m in _WINDOW.finditer(text):
        window = (m.group(1).strip(), m.group(2).strip())
        if window not in windows:
            windows.append(window)
    for m in _RADIUS.finditer(text):
        radius = float(m.group(1)) if m.group(1) else float(m.group(2)) * 1000.0
        if radius not in radii:
            radii.append(radius)
    return {"points": points, "windows": windows, "radii": radii}


# ======================================================================================
#  Pairing, association, divergence, closest approach
# ======================================================================================

def residuals(ais: Track, radar: Track, *, pairing: str = "exact", tolerance_s: float = 1.0,
              max_gap_s: float = 600.0) -> list[tuple[float, float, float]]:
    """AIS-minus-radar at each AIS sample time that the radar track covers: (t, east, north).

    ``exact`` pairs the radar sample nearest in time within `tolerance_s`; ``interpolate`` reads the
    radar track at the AIS time, between two samples no more than `max_gap_s` apart."""
    out = []
    for i, t in enumerate(ais.t):
        if pairing == "exact":
            j = bisect.bisect_left(radar.t, t)
            best = min((k for k in (j - 1, j) if 0 <= k < len(radar.t)),
                       key=lambda k: abs(radar.t[k] - t), default=None)
            if best is None or abs(radar.t[best] - t) > tolerance_s:
                continue
            pos = radar.east[best], radar.north[best]
        elif pairing == "interpolate":
            j = bisect.bisect_left(radar.t, t)
            if j < len(radar.t) and radar.t[j] == t:
                pos = radar.east[j], radar.north[j]
            elif 0 < j < len(radar.t) and radar.t[j] - radar.t[j - 1] <= max_gap_s:
                pos = radar.position(t)
            else:
                continue
        else:
            raise MethodError(f"match.pairing must be exact, interpolate or auto; got {pairing!r}")
        out.append((t, ais.east[i] - pos[0], ais.north[i] - pos[1]))
    return out


def _statistic(values: Sequence[float], name: str) -> float:
    if name == "median":
        return statistics.median(values)
    if name == "mean":
        return statistics.fmean(values)
    if name == "rms":
        return math.sqrt(statistics.fmean(v * v for v in values))
    if name == "max":
        return max(values)
    raise MethodError(f"match.statistic must be median, mean, rms or max; got {name!r}")


def residual_matrix(radar: Sequence[Track], ais: Sequence[Track], *, pairing: str, tolerance_s: float,
                    max_gap_s: float, statistic: str, min_common: int) -> list[list[float]]:
    """cost[radar][ais]: the residual statistic of that pairing in metres; ``inf`` when the two share
    fewer than `min_common` paired samples."""
    cost = []
    for r in radar:
        row = []
        for a in ais:
            res = residuals(a, r, pairing=pairing, tolerance_s=tolerance_s, max_gap_s=max_gap_s)
            row.append(_statistic([math.hypot(e, n) for _, e, n in res], statistic)
                       if len(res) >= max(1, min_common) else math.inf)
        cost.append(row)
    return cost


def assign_optimal(cost: Sequence[Sequence[float]]) -> list[tuple[int, int]]:
    """The one-to-one assignment (row, column) of minimum total cost (Hungarian method, O(n^3)).

    Rectangular matrices leave the surplus side unassigned. An ``inf`` cell is never chosen while a
    finite assignment exists; pairs that could only be made through one are left out."""
    if not cost or not cost[0]:
        return []
    rows, cols = len(cost), len(cost[0])
    if rows > cols:
        flipped = [[cost[r][c] for r in range(rows)] for c in range(cols)]
        return sorted((r, c) for c, r in assign_optimal(flipped))
    c = [[_UNASSIGNABLE if not math.isfinite(v) else float(v) for v in row] for row in cost]
    u, v = [0.0] * (rows + 1), [0.0] * (cols + 1)
    match, way = [0] * (cols + 1), [0] * (cols + 1)
    for i in range(1, rows + 1):
        match[0], j0 = i, 0
        minv, used = [math.inf] * (cols + 1), [False] * (cols + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = match[j0], math.inf, 0
            for j in range(1, cols + 1):
                if not used[j]:
                    cur = c[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(cols + 1):
                if used[j]:
                    u[match[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if match[j0] == 0:
                break
        while j0:
            j1 = way[j0]
            match[j0] = match[j1]
            j0 = j1
    return sorted((match[j] - 1, j - 1) for j in range(1, cols + 1)
                  if match[j] and math.isfinite(cost[match[j] - 1][j - 1]))


def assign_mutual_nearest(cost: Sequence[Sequence[float]]) -> list[tuple[int, int]]:
    """Pairs (row, column) that are each other's nearest: stricter than the optimal assignment, and
    leaves contested tracks unmatched instead of forcing a pairing."""
    out = []
    for r, row in enumerate(cost):
        if not row:
            continue
        c = min(range(len(row)), key=row.__getitem__)
        if math.isfinite(row[c]) and min(range(len(cost)), key=lambda k: cost[k][c]) == r:
            out.append((r, c))
    return out


def divergence_windows(res: Sequence[tuple[float, float, float]], *, threshold_m: float,
                       min_samples: int = 2, constant_tolerance_m: float = 5.0) -> list[dict]:
    """The runs of consecutive paired samples whose AIS-minus-radar offset exceeds `threshold_m`.

    Each window: start/end time, the mean east/north offset, its magnitude, the sample count, the
    largest departure of a sample from that mean (`spread_m`) and whether the offset is constant."""
    out, run = [], []

    def close():
        if len(run) >= max(1, min_samples):
            east = statistics.fmean(e for _, e, _ in run)
            north = statistics.fmean(n for _, _, n in run)
            spread = max(math.hypot(e - east, n - north) for _, e, n in run)
            out.append({"start_utc": run[0][0], "end_utc": run[-1][0], "east_m": east, "north_m": north,
                        "magnitude_m": math.hypot(east, north), "samples": len(run),
                        "duration_s": run[-1][0] - run[0][0], "spread_m": spread,
                        "constant": spread <= constant_tolerance_m})
        run.clear()

    for sample in res:
        if math.hypot(sample[1], sample[2]) > threshold_m:
            run.append(sample)
        else:
            close()
    close()
    return out


def _segment_min(p0, p1, q0, q1, t0, t1, lo, hi):
    """The closest approach of two points moving linearly over [t0, t1], restricted to [lo, hi]."""
    lo, hi = max(lo, t0), min(hi, t1)
    if lo > hi:
        return None
    span = t1 - t0
    rx0, ry0 = p0[0] - q0[0], p0[1] - q0[1]
    dx, dy = (p1[0] - q1[0]) - rx0, (p1[1] - q1[1]) - ry0
    u_lo = (lo - t0) / span if span else 0.0
    u_hi = (hi - t0) / span if span else 0.0
    dd = dx * dx + dy * dy
    u = min(max(-(rx0 * dx + ry0 * dy) / dd, u_lo), u_hi) if dd > 0 else u_lo
    return math.hypot(rx0 + u * dx, ry0 + u * dy), t0 + u * span, u


def closest_approach(track: Track, to: Track | tuple[float, float] = (0.0, 0.0), *,
                     window: tuple[float, float] | None = None, interpolate: bool = True) -> dict | None:
    """The closest approach of `track` to a point (east, north) or to another track.

    With `interpolate` the tracks are piecewise linear in time and the minimum may fall between
    samples; without it only `track`'s own samples are compared. `window` (start, end) restricts the
    search. Returns {"utc", "distance_m", "east_m", "north_m"} (the position of `track` at that time),
    or None when the track has no coverage in the window (or no overlap with the other track)."""
    lo, hi = window if window is not None else (-math.inf, math.inf)
    other = to if isinstance(to, Track) else None
    point = None if other is not None else (float(to[0]), float(to[1]))
    best = None

    def consider(distance, t):
        nonlocal best
        if best is None or distance < best[0] - 1e-12:
            best = (distance, t)

    if not interpolate:
        for i, t in enumerate(track.t):
            if lo <= t <= hi:
                target = point if other is None else other.position(t)
                if target is not None:
                    consider(math.hypot(track.east[i] - target[0], track.north[i] - target[1]), t)
    else:
        times = sorted(set(track.t) | (set(other.t) if other is not None else set()))
        times = [t for t in times if track.position(t) is not None
                 and (other is None or other.position(t) is not None)]
        if len(times) == 1 and lo <= times[0] <= hi:
            p = track.position(times[0])
            q = point if other is None else other.position(times[0])
            consider(math.hypot(p[0] - q[0], p[1] - q[1]), times[0])
        for t0, t1 in zip(times, times[1:]):
            q0 = point if other is None else other.position(t0)
            q1 = point if other is None else other.position(t1)
            found = _segment_min(track.position(t0), track.position(t1), q0, q1, t0, t1, lo, hi)
            if found is not None:
                consider(found[0], found[1])
    if best is None:
        return None
    at = min(max(best[1], track.t[0]), track.t[-1])
    east, north = track.position(at)
    return {"utc": at, "distance_m": best[0], "east_m": east, "north_m": north}


def estimate_clock_offset(ais: Sequence[Track], radar: Sequence[Track], *, pairing: str = "exact",
                          tolerance_s: float = 1.0, max_gap_s: float = 600.0, min_common: int = 2,
                          candidates: Iterable[float] | None = None) -> tuple[float, float]:
    """The radar clock offset (seconds ahead of UTC) under which the radar tracks best agree with AIS.

    Each candidate (default: every quarter hour within +-14 h) is scored by the sum, over radar tracks,
    of the median residual to the nearest AIS track. Returns (offset, score). A candidate must give
    every radar track a partner; the best must beat the runner-up by a factor of two, else the offset
    is ambiguous (parallel or stationary traffic) and a MethodError asks for the number."""
    if candidates is None:
        candidates = [q * 900.0 for q in range(-56, 57)]
    scored = []
    for offset in candidates:
        shifted = [r.shifted(-offset) for r in radar]
        cost = residual_matrix(shifted, ais, pairing=pairing, tolerance_s=tolerance_s,
                               max_gap_s=max_gap_s, statistic="median", min_common=min_common)
        best_per_track = [min(row) for row in cost]
        if best_per_track and all(math.isfinite(b) for b in best_per_track):
            scored.append((sum(best_per_track), offset))
    if not scored:
        raise MethodError("no candidate clock offset pairs every radar track with an AIS track; set "
                          "radar.clock_offset_s, or match.pairing = \"interpolate\"")
    scored.sort()
    if len(scored) > 1 and scored[1][0] < 2.0 * scored[0][0] + 1.0:
        raise MethodError(f"the radar clock offset is ambiguous (candidates {scored[0][1]:.0f} s and "
                          f"{scored[1][1]:.0f} s score {scored[0][0]:.1f} m and {scored[1][0]:.1f} m); "
                          "set radar.clock_offset_s")
    return scored[0][1], scored[0][0]


# ======================================================================================
#  The pipeline: evidence + method -> facts
# ======================================================================================

@dataclass
class Reconciliation:
    """What the method computed. `facts` is what a report is built from; times are epoch seconds.
    `decisions` lists every choice the method left open and how it was settled; `warnings` the things
    a reader should look at before trusting the facts."""
    facts: dict
    decisions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"facts": self.facts, "decisions": list(self.decisions), "warnings": list(self.warnings)}


def _id_key(value: Any) -> tuple:
    """Natural order for ids: R-2 before R-10, numbers before text."""
    parts = re.split(r"(\d+)", str(value))
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts if p != "")


def _point(value: Any, where: str) -> tuple[float, float]:
    if not isinstance(value, Mapping) or "lat" not in value or "lon" not in value:
        raise MethodError(f"{where} must be {{\"lat\": .., \"lon\": ..}}; got {value!r}")
    return _coord(value["lat"], value["lon"], where)


def _find_track(tracks: Sequence[Track], ident: Any, where: str) -> Track:
    for track in tracks:
        if track.id == ident or str(track.id) == str(ident):
            return track
    raise MethodError(f"{where}: no track with id {ident!r}")


def reconcile(evidence: Mapping[str, Any], method: Mapping | None = None) -> Reconciliation:
    """Run the method over the evidence (role -> bytes/text: ``ais``, ``radar``, and optionally
    ``reference`` and ``note``) and return the facts. No network; nothing is sent."""
    method = load_method(method)
    decisions: list[str] = []
    warnings: list[str] = []
    for role in ("ais", "radar"):
        if evidence.get(role) in (None, b"", ""):
            raise EvidenceError(f"no {role} evidence (route {method['routes'].get(role)!r})")
    ais_rows = parse_ndjson(evidence["ais"], "ais") if _text(evidence["ais"]).lstrip()[:1] in "[{" \
        else parse_csv(evidence["ais"], "ais")[1]
    radar_text = _text(evidence["radar"])
    if radar_text.lstrip()[:1] in "[{":
        radar_comments, radar_rows = [], parse_ndjson(radar_text, "radar")
    else:
        radar_comments, radar_rows = parse_csv(radar_text, "radar")
    reference_text = _text(evidence.get("reference") or "")
    note_text = _text(evidence.get("note") or "")

    # --- dates and raw samples -------------------------------------------------------------------
    date = None
    if method["date"] is not None:
        try:
            date = _dt.date.fromisoformat(str(method["date"]))
        except ValueError:
            raise MethodError(f"date must be YYYY-MM-DD; got {method['date']!r}") from None
    ais_raw, _, _ = _raw_samples(ais_rows, method["ais"], "ais", decisions, date)
    date_note = None
    if date is None:
        date = _dt.datetime.fromtimestamp(min(s[1] for s in ais_raw), _UTC).date()
        date_note = f"time-only stamps are read on {date.isoformat()} (the first AIS sample's date)"
    radar_raw, radar_explicit, radar_time_only = _raw_samples(radar_rows, method["radar"], "radar",
                                                              decisions, date)
    if date_note and radar_time_only:
        decisions.append(date_note)

    # --- reference point, origin, plane ----------------------------------------------------------
    hints = reference_hints(reference_text)
    ref_point = None
    spec = method["reference"]["point"]
    if spec == "auto":
        if len(hints["points"]) == 1:
            ref_point = hints["points"][0]
            decisions.append(f"reference point {ref_point[0]}, {ref_point[1]} (the one lat/lon pair in the "
                             "reference text)")
        elif len(hints["points"]) > 1:
            raise MethodError("the reference text names several lat/lon pairs ("
                              + "; ".join(f"{a}, {b}" for a, b in hints["points"])
                              + "); set reference.point")
    elif spec is not None:
        ref_point = _point(spec, "reference.point")
    if method["origin"] == "auto":
        if ref_point is not None:
            origin = ref_point
        else:
            located = [(s[2], s[3]) for s in radar_raw + ais_raw if s[2] is not None]
            if not located:
                raise MethodError("no reference point and no lat/lon samples: set origin")
            origin = (statistics.fmean(p[0] for p in located), statistics.fmean(p[1] for p in located))
            decisions.append(f"origin {origin[0]:.6f}, {origin[1]:.6f} (the mean sample position; no "
                             "reference point)")
    else:
        origin = _point(method["origin"], "origin")
    model = _choice(method["projection"]["model"], ("local_plane", "wgs84_enu"), "projection.model")
    radius = method["projection"]["radius_m"]
    if radius == "auto":
        radii = sorted(set(reference_hints(note_text)["radii"]))
        if len(radii) > 1:
            raise MethodError(f"the method note names several Earth radii ({radii}); set projection.radius_m")
        radius = radii[0] if radii else MEAN_EARTH_RADIUS_M
        if model == "local_plane":
            decisions.append(f"sphere radius {radius:.1f} m ("
                             + ("stated in the method note" if radii else "the mean Earth radius; the note "
                                "names none") + ")")
    elif isinstance(radius, bool) or not isinstance(radius, (int, float)) or radius <= 0:
        raise MethodError(f"projection.radius_m must be a positive number or \"auto\"; got {radius!r}")
    plane = Plane(origin[0], origin[1], model, float(radius))
    ref_en = plane.project(*ref_point) if ref_point is not None else None

    site = method["radar"].get("site")
    site_en = plane.project(*_point(site, "radar.site")) if site is not None else None
    ais_tracks = _tracks(ais_raw, plane, None, "ais")
    radar_tracks = _tracks(radar_raw, plane, site_en, "radar")

    # --- time alignment --------------------------------------------------------------------------
    match = method["match"]
    tolerance, max_gap, min_common = float(match["tolerance_s"]), float(match["max_gap_s"]), int(match["min_common"])
    ais_offset = method["ais"]["clock_offset_s"]
    if isinstance(ais_offset, bool) or not isinstance(ais_offset, (int, float)):
        raise MethodError(f"ais.clock_offset_s must be a number of seconds; got {ais_offset!r}")
    if ais_offset:
        ais_tracks = [t.shifted(-ais_offset) for t in ais_tracks]
    radar_offset = method["radar"]["clock_offset_s"]
    if isinstance(radar_offset, bool) or not (isinstance(radar_offset, (int, float))
                                              or radar_offset in ("auto", "hint", "estimate")):
        raise MethodError("radar.clock_offset_s must be a number of seconds, \"auto\", \"hint\" or "
                          f"\"estimate\"; got {radar_offset!r}")
    if isinstance(radar_offset, str):
        found = clock_offset_hints("\n".join(radar_comments)) + clock_offset_hints(note_text)
        distinct = sorted({h[0] for h in found})
        if radar_offset in ("auto", "hint") and len(distinct) > 1:
            raise MethodError("the evidence states several clock offsets ("
                              + ", ".join(repr(h[1]) for h in found) + "); set radar.clock_offset_s")
        if radar_offset in ("auto", "hint") and distinct and radar_explicit:
            radar_offset = 0.0
            decisions.append(f"radar clock: the evidence says {found[0][1]!r}, but the radar stamps carry "
                             "their own UTC offset, so none was subtracted")
        elif radar_offset in ("auto", "hint") and distinct:
            radar_offset = distinct[0]
            decisions.append(f"radar clock is {radar_offset:+.0f} s from UTC (the evidence says "
                             f"{found[0][1]!r}); subtracted")
        elif radar_offset == "hint":
            raise MethodError("radar.clock_offset_s = \"hint\", but neither the radar header nor the "
                              "method note states an offset from UTC")
        else:
            pairing = "exact" if match["pairing"] == "auto" else match["pairing"]
            radar_offset, score = estimate_clock_offset(
                ais_tracks, radar_tracks, pairing=pairing, tolerance_s=tolerance, max_gap_s=max_gap,
                min_common=min_common)
            decisions.append(f"radar clock is {radar_offset:+.0f} s from UTC (estimated: the offset under "
                             f"which the tracks agree, total residual {score:.1f} m); subtracted")
    elif radar_offset and radar_explicit:
        warnings.append("radar stamps carry their own UTC offset and radar.clock_offset_s was subtracted "
                        "as well; check the skew is not applied twice")
    radar_offset = float(radar_offset)
    if radar_offset:
        radar_tracks = [t.shifted(-radar_offset) for t in radar_tracks]

    # --- pairing mode, association ---------------------------------------------------------------
    pairing = _choice(match["pairing"], ("auto", "exact", "interpolate"), "match.pairing")
    if pairing == "auto":
        radar_times = sorted({t for track in radar_tracks for t in track.t})
        ais_times = [t for track in ais_tracks for t in track.t]

        def near(t):
            j = bisect.bisect_left(radar_times, t)
            return any(0 <= k < len(radar_times) and abs(radar_times[k] - t) <= tolerance for k in (j - 1, j))

        share = sum(1 for t in ais_times if near(t)) / max(1, len(ais_times))
        pairing = "exact" if share >= 0.5 else "interpolate"
        decisions.append(f"sample pairing: {pairing} ({share:.0%} of AIS samples have a radar sample "
                         f"within {tolerance:g} s)")
    statistic = match["statistic"]
    cost = residual_matrix(radar_tracks, ais_tracks, pairing=pairing, tolerance_s=tolerance,
                           max_gap_s=max_gap, statistic=statistic, min_common=min_common)
    assignment = _choice(match["assignment"], ("optimal", "mutual_nearest"), "match.assignment")
    pairs = assign_optimal(cost) if assignment == "optimal" else assign_mutual_nearest(cost)
    limit = match["max_residual_m"]
    if limit is not None:
        pairs = [(r, a) for r, a in pairs if cost[r][a] <= float(limit)]
    if not pairs:
        raise ReconcileError("no radar track could be associated with an AIS track (no common sample "
                             "times after alignment?): check the clock offset and match.pairing")
    associations, series = [], {}
    for r, a in pairs:
        res = residuals(ais_tracks[a], radar_tracks[r], pairing=pairing, tolerance_s=tolerance,
                        max_gap_s=max_gap)
        runner_up = min([cost[r][k] for k in range(len(ais_tracks)) if k != a]
                        + [cost[k][a] for k in range(len(radar_tracks)) if k != r], default=math.inf)
        associations.append({"radar_id": radar_tracks[r].id, "ais_id": ais_tracks[a].id,
                             "residual_m": cost[r][a], "samples": len(res),
                             "runner_up_m": runner_up if math.isfinite(runner_up) else None})
        series[(r, a)] = res
        if math.isfinite(runner_up) and runner_up <= 2.0 * cost[r][a] + 1.0:
            warnings.append(f"association {radar_tracks[r].id} <-> {ais_tracks[a].id} is not clear-cut: "
                            f"residual {cost[r][a]:.1f} m, next best {runner_up:.1f} m")
    order = sorted(range(len(pairs)), key=lambda i: _id_key(associations[i]["radar_id"]))
    pairs = [pairs[i] for i in order]
    associations = [associations[i] for i in order]
    matched_r, matched_a = {r for r, _ in pairs}, {a for _, a in pairs}
    unmatched = {"radar": sorted((t.id for i, t in enumerate(radar_tracks) if i not in matched_r), key=_id_key),
                 "ais": sorted((t.id for i, t in enumerate(ais_tracks) if i not in matched_a), key=_id_key)}
    if unmatched["radar"] or unmatched["ais"]:
        warnings.append(f"not a bijection: unmatched radar {unmatched['radar']}, unmatched AIS {unmatched['ais']}")

    # --- divergence ------------------------------------------------------------------------------
    dv = method["divergence"]
    divergences = []
    for (r, a) in pairs:
        for window in divergence_windows(series[(r, a)], threshold_m=float(dv["threshold_m"]),
                                         min_samples=int(dv["min_samples"]),
                                         constant_tolerance_m=float(dv["constant_tolerance_m"])):
            divergences.append({"radar_id": radar_tracks[r].id, "ais_id": ais_tracks[a].id, **window})
    pick = dv["pick"]
    divergence = None
    if len(divergences) == 1:
        divergence = divergences[0]
    elif divergences:
        if pick == "longest":
            divergence = max(divergences, key=lambda d: (d["samples"], d["magnitude_m"]))
        elif pick == "largest":
            divergence = max(divergences, key=lambda d: (d["magnitude_m"], d["samples"]))
        elif pick != "only":
            chosen = [d for d in divergences if str(d["ais_id"]) == str(pick)]
            if len(chosen) != 1:
                raise MethodError(f"divergence.pick = {pick!r} selects {len(chosen)} windows (diverging: "
                                  + ", ".join(str(d["ais_id"]) for d in divergences) + ")")
            divergence = chosen[0]
        if divergence is None:
            warnings.append(f"{len(divergences)} divergence windows ("
                            + ", ".join(f"{d['ais_id']}" for d in divergences)
                            + "); set divergence.pick to longest, largest or an AIS id")
        else:
            decisions.append(f"divergence: {divergence['ais_id']} chosen from {len(divergences)} windows "
                             f"(divergence.pick = {pick!r})")
    if divergence is not None and not divergence["constant"]:
        warnings.append(f"the divergence offset is not constant (samples depart {divergence['spread_m']:.1f} m "
                        "from its mean)")

    # --- closest approach ------------------------------------------------------------------------
    ca = method["closest_approach"]
    source = _choice(ca["source"], ("radar", "ais"), "closest_approach.source")
    pool = radar_tracks if source == "radar" else ais_tracks
    window, window_spec = None, ca["window"]
    reference_window = None
    ref_window_spec = method["reference"]["window"]
    if ref_window_spec == "auto":
        if len(hints["windows"]) == 1:
            raw = hints["windows"][0]
            reference_window = tuple(parse_time(x, date=date)[0] for x in raw)
            decisions.append(f"reference window {raw[0]} to {raw[1]}, read as UTC (the one time range in the "
                             "reference text)")
        elif len(hints["windows"]) > 1:
            warnings.append("the reference text names several time ranges; none used. Set reference.window")
    elif ref_window_spec is not None:
        if not isinstance(ref_window_spec, (list, tuple)) or len(ref_window_spec) != 2:
            raise MethodError("reference.window must be [start, end], null or \"auto\"")
        reference_window = tuple(parse_time(x, date=date)[0] for x in ref_window_spec)
    if window_spec == "reference":
        window = reference_window
    elif window_spec is not None:
        if not isinstance(window_spec, (list, tuple)) or len(window_spec) != 2:
            raise MethodError("closest_approach.window must be [start, end], null or \"reference\"")
        window = tuple(parse_time(x, date=date)[0] for x in window_spec)
    if window is not None and window[0] > window[1]:
        raise MethodError("the closest-approach window ends before it starts")
    to_spec = ca["to"]
    if to_spec == "reference":
        target: Any = ref_en
    elif isinstance(to_spec, Mapping) and "sensor" in to_spec:
        other_pool = radar_tracks if _choice(to_spec["sensor"], ("radar", "ais"), "closest_approach.to.sensor") \
            == "radar" else ais_tracks
        target = _find_track(other_pool, to_spec.get("id"), "closest_approach.to")
    else:
        target = plane.project(*_point(to_spec, "closest_approach.to"))
    closest = None
    by_source = {(r if source == "radar" else a): (r, a) for r, a in pairs}
    if target is None:
        warnings.append("no closest approach: there is no reference point (set reference.point or "
                        "closest_approach.to)")
    else:
        if ca["target"] == "divergent":
            if divergence is None:
                candidates = []
                warnings.append("no closest approach: closest_approach.target = \"divergent\" and no single "
                                "divergence was found")
            else:
                key = "radar_id" if source == "radar" else "ais_id"
                candidates = [_find_track(pool, divergence[key], "closest approach")]
        elif ca["target"] == "all":
            candidates = [t for t in pool if t is not target]
        else:
            candidates = [_find_track(pool, ca["target"], "closest_approach.target")]
        for track in candidates:
            found = closest_approach(track, target, window=window, interpolate=bool(ca["interpolate"]))
            if found is not None and (closest is None or found["distance_m"] < closest["distance_m"]):
                index = pool.index(track)
                r, a = by_source.get(index, (None, None))
                closest = {**found, "source": source,
                           "radar_id": radar_tracks[r].id if r is not None else (track.id if source == "radar" else None),
                           "ais_id": ais_tracks[a].id if a is not None else (track.id if source == "ais" else None)}
        if candidates and closest is None:
            warnings.append("no closest approach: the chosen track has no samples inside the window")

    facts = {
        "clock_offset_s": {"ais": float(ais_offset), "radar": radar_offset},
        "origin": {"lat": origin[0], "lon": origin[1]},
        "projection": {"model": model, "radius_m": float(radius)},
        "reference": None if ref_point is None else {
            "lat": ref_point[0], "lon": ref_point[1],
            "window_start_utc": reference_window[0] if reference_window else None,
            "window_end_utc": reference_window[1] if reference_window else None},
        "pairing": pairing,
        "associations": associations,
        "unmatched": unmatched,
        "divergences": divergences,
        "divergence": divergence,
        "closest_approach": closest,
    }
    return Reconciliation(facts, decisions, warnings)


# ======================================================================================
#  The schema-shaped report
# ======================================================================================

_TIME_FACTS = frozenset({"start_utc", "end_utc", "utc", "window_start_utc", "window_end_utc"})
_CONTAINERS = {
    "associations": ("associations", "association", "pairs", "pairings", "matches", "bijection",
                     "track_associations", "correlations", "mapping"),
    "divergence": ("divergence", "spoof", "spoofed", "displacement", "anomaly", "false_broadcast",
                   "false_track", "deviation", "offset"),
    "closest_approach": ("closest_approach", "cpa", "closest_point_of_approach", "actual_closest_approach",
                         "approach"),
}
_IDS = {
    "ais_id": ("mmsi", "ais_mmsi", "ais", "ais_id", "vessel", "vessel_mmsi", "vessel_id", "ship"),
    "radar_id": ("radar_track", "track", "track_id", "radar", "radar_id", "radar_track_id", "contact"),
}
_LEAVES = {
    "associations": {"residual_m": ("residual_m", "median_residual_m"), "samples": ("samples", "n_samples")},
    "divergence": {"start_utc": ("start_utc", "start", "start_time", "from_utc", "from", "begin_utc"),
                   "end_utc": ("end_utc", "end", "end_time", "to_utc", "to", "until_utc"),
                   "magnitude_m": ("displacement_m", "magnitude_m", "offset_m", "distance_m"),
                   "samples": ("samples", "n_samples"), "duration_s": ("duration_s",)},
    "closest_approach": {"utc": ("utc", "time", "time_utc", "cpa_utc", "at_utc", "timestamp", "at"),
                         "distance_m": ("distance_m", "cpa_m", "range_m", "min_distance_m", "cpa_distance_m")},
}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")


def _alias(container: str | None, leaf: str) -> tuple[str, bool] | None:
    """The fact key a schema leaf name stands for inside `container`, and whether it is negated."""
    if container is None:
        return None
    n = _norm(leaf)
    for fact, names in _IDS.items():
        if n in names:
            return fact, False
    for fact, names in _LEAVES.get(container, {}).items():
        if n in names:
            return fact, False
    if container == "divergence":
        for axis in ("east", "north"):
            if n in (axis, f"d{axis}_m", f"d_{axis}_m") or n.endswith(f"{axis}_m") or n.endswith(f"_{axis}"):
                return f"{axis}_m", "radar_minus_ais" in n
    return None


def _container_of(name: str) -> str | None:
    n = _norm(name)
    for container, names in _CONTAINERS.items():
        if n in names:
            return container
    return None


def schema_kind(schema: Any) -> str:
    """``json-schema`` when the document speaks JSON Schema (a ``type``/``properties``/``$ref`` at its
    root), else ``example`` (a sample document whose leaves are type names or sample values)."""
    if isinstance(schema, Mapping) and (
            "$schema" in schema or "$ref" in schema or isinstance(schema.get("properties"), Mapping)
            or (isinstance(schema.get("type"), str) and schema["type"] in _JSON_TYPES)):
        return "json-schema"
    return "example"


_JSON_TYPES = ("object", "array", "string", "number", "integer", "boolean", "null")
_TYPE_WORDS = {"string": "string", "str": "string", "text": "string", "number": "number",
               "float": "number", "double": "number", "decimal": "number", "integer": "integer",
               "int": "integer", "boolean": "boolean", "bool": "boolean", "iso8601": "string",
               "datetime": "string", "date-time": "string", "timestamp": "string"}


def json_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 pointer (``""`` is the document itself). A missing step is a ReportError."""
    node = document
    for raw in [p for p in (pointer or "").lstrip("#").split("/") if p != ""]:
        key = raw.replace("~1", "/").replace("~0", "~")
        try:
            node = node[int(key)] if isinstance(node, list) else node[key]
        except (KeyError, IndexError, ValueError, TypeError):
            raise ReportError(f"schema pointer {pointer!r}: no {key!r}") from None
    return node


@dataclass
class BuiltReport:
    """A report shaped by the schema. `unresolved` names every required leaf that has no source (the
    report is then incomplete and is never sent); `trace` records where each filled leaf came from."""
    report: Any
    kind: str
    trace: list[dict] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.unresolved


_MISSING = object()


class _Builder:
    def __init__(self, root: Any, facts: Mapping, fields: Mapping, decimals: int, time_format: str,
                 time_decimals: int):
        self.root, self.facts, self.fields = root, facts, dict(fields or {})
        self.decimals, self.time_format, self.time_decimals = int(decimals), time_format, int(time_decimals)
        self.trace: list[dict] = []
        self.unresolved: list[str] = []
        self.used_fields: set[str] = set()

    # -- schema access ---------------------------------------------------------------------------
    def deref(self, node: Any, kind: str) -> Any:
        seen = 0
        while kind == "json-schema" and isinstance(node, Mapping) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#"):
                raise ReportError(f"unsupported $ref {ref!r}: only local references (#/...) are followed")
            node = json_pointer(self.root, ref)
            seen += 1
            if seen > 32:
                raise ReportError(f"$ref cycle at {ref!r}")
        return node

    def node_type(self, node: Any, kind: str, path: str) -> str:
        if kind == "example":
            if isinstance(node, Mapping):
                return "object"
            if isinstance(node, list):
                return "array"
            if isinstance(node, bool):
                return "boolean"
            if isinstance(node, int):
                return "integer"
            if isinstance(node, float):
                return "number"
            if isinstance(node, str):
                return _TYPE_WORDS.get(node.strip().lower(), "string")
            raise ReportError(f"{path or '<root>'}: an example leaf of type {type(node).__name__} has no shape")
        for word in ("oneOf", "anyOf", "allOf", "not", "if"):
            if word in node:
                raise ReportError(f"{path or '<root>'}: schema keyword {word!r} is not supported by the "
                                  "report builder; map this part by hand (report.fields with {\"value\": ...})")
        t = node.get("type")
        if isinstance(t, list):
            t = next((x for x in t if x != "null"), None)
        if t is None:
            if "properties" in node:
                return "object"
            if "items" in node:
                return "array"
            if "enum" in node or "const" in node:
                return "any"
            raise ReportError(f"{path or '<root>'}: schema node has no type")
        if t not in _JSON_TYPES:
            raise ReportError(f"{path or '<root>'}: unknown schema type {t!r}")
        return t

    # -- fact lookup -----------------------------------------------------------------------------
    def fact(self, dotted: str, item: Mapping | None) -> Any:
        negate = dotted.startswith("-")
        node: Any = self.facts
        parts = dotted.lstrip("-").split(".")
        if parts[0] == "item":
            node, parts = item, parts[1:]
        for part in parts:
            if not isinstance(node, Mapping) or part not in node:
                return _MISSING
            node = node[part]
        if node is None:
            return _MISSING
        if negate:
            if isinstance(node, bool) or not isinstance(node, (int, float)):
                raise ReportError(f"report.fields: cannot negate {dotted!r} (not a number)")
            node = -node
        return node

    def lookup(self, path: str, leaf: str, container: str | None, item: Mapping | None):
        """(value, how, time_like) for the leaf at `path`, or (_MISSING, reason, False)."""
        if path in self.fields:
            self.used_fields.add(path)
            spec = self.fields[path]
            if isinstance(spec, Mapping):
                if set(spec) != {"value"}:
                    raise ReportError(f"report.fields[{path!r}] must be a fact path or {{\"value\": ...}}")
                return spec["value"], "report.fields (literal)", False
            if not isinstance(spec, str) or not spec:
                raise ReportError(f"report.fields[{path!r}] must be a fact path or {{\"value\": ...}}")
            value = self.fact(spec, item)
            if value is _MISSING:
                return _MISSING, f"report.fields maps it to {spec!r}, which the method did not produce", False
            return value, f"report.fields -> {spec}", spec.lstrip("-").rsplit(".", 1)[-1] in _TIME_FACTS
        found = _alias(container, leaf)
        if found is None and container is None:
            # a flat schema: "cpa_distance_m", "divergence_start_utc", "spoofed_mmsi"
            n = _norm(leaf)
            for section, names in _CONTAINERS.items():
                for prefix in sorted(names, key=len, reverse=True):
                    if n.startswith(prefix + "_") and _alias(section, n[len(prefix) + 1:]) is not None:
                        container, found = section, _alias(section, n[len(prefix) + 1:])
                        break
                if found is not None:
                    break
        if found is None:
            where = f"inside {container!r}" if container else "outside any known section"
            return _MISSING, f"no known source for {leaf!r} {where}; add it to report.fields", False
        key, negate = found
        source = item if container == "associations" else self.facts.get(container)
        if not isinstance(source, Mapping) or source.get(key) is None:
            return _MISSING, f"the method produced no {container}.{key}", False
        value = -source[key] if negate else source[key]
        how = f"{container}.{key}" + (" (negated: the field is radar-minus-AIS)" if negate else "")
        return value, how, key in _TIME_FACTS

    # -- coercion --------------------------------------------------------------------------------
    def coerce(self, value: Any, want: str, node: Any, kind: str, time_like: bool, path: str) -> Any:
        if want == "string":
            if time_like and isinstance(value, (int, float)) and not isinstance(value, bool):
                fmt = self.time_format if self.time_format != "epoch" else "iso_z"
                return format_time(value, fmt, self.time_decimals)
            if isinstance(value, float) and value.is_integer():
                return str(int(value))
            return value if isinstance(value, str) else str(value)
        if want in ("number", "integer"):
            if isinstance(value, bool):
                raise ReportError(f"{path}: wants a {want}, the source is a boolean")
            if isinstance(value, str):
                if not _NUMERIC.match(value.strip()):
                    raise ReportError(f"{path}: wants a {want}, the source is {value!r}")
                value = float(value) if "." in value else int(value)
            if time_like:
                value = round(float(value), self.time_decimals)
            if want == "integer":
                return int(round(value))
            if isinstance(value, int):
                return value
            # round() can return -0.0; a report says 0.0
            return round(float(value), self.decimals) + 0.0
        if want == "boolean":
            if not isinstance(value, bool):
                raise ReportError(f"{path}: wants a boolean, the source is {value!r}")
            return value
        return value

    # -- the walk --------------------------------------------------------------------------------
    def build(self, node: Any, kind: str, path: str, name: str, container: str | None,
              item: Mapping | None, required: bool) -> Any:
        node = self.deref(node, kind)
        if kind == "json-schema" and not isinstance(node, Mapping):
            raise ReportError(f"{path or '<root>'}: schema node is not an object")
        want = self.node_type(node, kind, path)
        here = _container_of(name) if name else None
        container = here or container
        if kind == "json-schema" and "const" in node and path not in self.fields:
            self.trace.append({"path": path, "source": "schema const"})
            return node["const"]
        if want == "object":
            if path in self.fields:
                value, how, _ = self.lookup(path, name, container, item)
                if value is _MISSING:
                    return self.miss(path, how, required)
                self.trace.append({"path": path, "source": how})
                return value
            props = node if kind == "example" else node.get("properties") or {}
            needed = set(props) if kind == "example" else set(node.get("required") or ())
            marks = len(self.unresolved), len(self.trace)
            out = {}
            for key, child in props.items():
                value = self.build(child, kind, f"{path}.{key}" if path else key, key, container, item,
                                   key in needed)
                if value is not _MISSING:
                    out[key] = value
            if not required and (len(self.unresolved) > marks[0] or not out):
                # an optional section that cannot be filled completely is left out, not sent half-built
                del self.unresolved[marks[0]:], self.trace[marks[1]:]
                return _MISSING
            return out
        if want == "array":
            if path in self.fields:
                value, how, _ = self.lookup(path, name, container, item)
                if value is _MISSING:
                    return self.miss(path, how, required)
                self.trace.append({"path": path, "source": how})
                return value
            if kind == "example":
                if len(node) != 1:
                    raise ReportError(f"{path}: an example array must hold exactly one sample item")
                template = node[0]
            else:
                template = node.get("items")
                if not isinstance(template, Mapping):
                    raise ReportError(f"{path}: array schema has no single items schema")
            source = self.facts.get(container) if container else None
            if not isinstance(source, list):
                return self.miss(path, f"no known list for {name!r}; add it to report.fields", required)
            out = []
            for element in source:
                value = self.build(template, kind, f"{path}[]", "", container, element, required)
                if value is _MISSING:
                    return _MISSING
                out.append(value)
            self.trace.append({"path": path, "source": f"{container} ({len(out)} items)"})
            return out
        if want == "null":
            return None
        value, how, time_like = self.lookup(path, name, container, item)
        if value is _MISSING:
            return self.miss(path, how, required)
        value = self.coerce(value, want, node, kind, time_like, path)
        if kind == "json-schema" and "enum" in node and value not in node["enum"]:
            return self.miss(path, f"{value!r} is not one of the schema's enum values {node['enum']}", required)
        if not any(t["path"] == path for t in self.trace):     # one entry per leaf path, not per list item
            self.trace.append({"path": path, "source": how})
        return value

    def miss(self, path: str, reason: str, required: bool) -> Any:
        if required:
            entry = f"{path or '<root>'}: {reason}"
            if entry not in self.unresolved:
                self.unresolved.append(entry)
        return _MISSING


def build_report(schema: Any, facts: Mapping, *, fields: Mapping | None = None, decimals: int = 3,
                 time_format: str = "iso_z", time_decimals: int = 0, pointer: str = "") -> BuiltReport:
    """Shape a report from `schema` and fill it from `facts`.

    `schema` is a JSON Schema (object/array/string/number/integer/boolean, ``properties``,
    ``required``, ``items``, ``enum``, ``const``, local ``$ref``) or an example-shaped document. A leaf
    is filled from ``report.fields[path]`` when given (a fact path such as ``divergence.east_m``,
    ``-divergence.east_m`` to negate, ``item.ais_id`` inside a list, or ``{"value": literal}``), else
    by its name inside a recognised section (associations / divergence / closest approach). Paths are
    dotted, with ``[]`` for list items: ``associations[].mmsi``. Optional leaves with no source are
    left out; required ones are listed in ``unresolved``. A ``report.fields`` key that matches no
    schema path is a ReportError (a typo would otherwise be silently ignored)."""
    shape = json_pointer(schema, pointer)
    kind = schema_kind(shape)
    builder = _Builder(schema, facts, fields or {}, decimals, time_format, time_decimals)
    report = builder.build(shape, kind, "", "", None, None, True)
    stray = sorted(set(builder.fields) - builder.used_fields)
    if stray:
        raise ReportError(f"report.fields names path(s) the schema does not have: {', '.join(stray)}")
    if report is _MISSING:
        report = None
    return BuiltReport(report, kind, builder.trace, builder.unresolved)


_CHECKED = frozenset({"type", "properties", "required", "additionalProperties", "items", "enum", "const",
                      "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minItems", "maxItems",
                      "minLength", "maxLength", "pattern", "format", "$ref"})
_ANNOTATIONS = frozenset({"$schema", "$id", "title", "description", "examples", "default", "definitions",
                          "$defs", "$comment"})


def _is_type(value: Any, want: str) -> bool:
    if want == "object":
        return isinstance(value, Mapping)
    if want == "array":
        return isinstance(value, list)
    if want == "string":
        return isinstance(value, str)
    if want == "boolean":
        return isinstance(value, bool)
    if want == "null":
        return value is None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return want == "number" or float(value).is_integer()


def validate_report(schema: Any, report: Any, *, pointer: str = "") -> tuple[list[str], list[str]]:
    """Check `report` against `schema`: (problems, unchecked).

    For a JSON Schema: type, properties, required, additionalProperties (false or a schema), items,
    enum, const, numeric and length bounds, pattern, ``format: date-time`` and local ``$ref``. Any
    other validation keyword is NOT applied and is named in `unchecked`, so a pass never claims more
    than was checked. For an example-shaped schema: the same keys, list items and leaf types."""
    root = schema
    shape = json_pointer(schema, pointer)
    kind = schema_kind(shape)
    problems: list[str] = []
    unchecked: list[str] = []

    def example(node, value, path):
        label = path or "<root>"
        if isinstance(node, Mapping):
            if not isinstance(value, Mapping):
                problems.append(f"{label}: expected an object")
                return
            for key in node:
                if key not in value:
                    problems.append(f"{label}: missing {key!r}")
                else:
                    example(node[key], value[key], f"{path}.{key}" if path else key)
            for key in value:
                if key not in node:
                    problems.append(f"{label}: unexpected {key!r}")
        elif isinstance(node, list):
            if not isinstance(value, list):
                problems.append(f"{label}: expected a list")
            elif node:
                for i, element in enumerate(value):
                    example(node[0], element, f"{path}[{i}]")
        else:
            want = ("boolean" if isinstance(node, bool) else "integer" if isinstance(node, int)
                    else "number" if isinstance(node, float)
                    else _TYPE_WORDS.get(str(node).strip().lower(), "string"))
            if not _is_type(value, want):
                problems.append(f"{label}: expected {want}, got {type(value).__name__}")

    def check(node, value, path, depth=0):
        label = path or "<root>"
        if depth > 64:
            raise ReportError(f"schema nests or refers too deeply at {label}")
        if node is True or node == {}:
            return
        if not isinstance(node, Mapping):
            raise ReportError(f"{label}: schema node is not an object")
        if "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#"):
                raise ReportError(f"unsupported $ref {ref!r}: only local references (#/...) are followed")
            check(json_pointer(root, ref), value, path, depth + 1)
        for key in node:
            if key not in _CHECKED and key not in _ANNOTATIONS:
                note = f"{label}: {key}"
                if note not in unchecked:
                    unchecked.append(note)
        types = node.get("type")
        if types is not None:
            options = types if isinstance(types, list) else [types]
            if not any(_is_type(value, t) for t in options):
                problems.append(f"{label}: expected {' or '.join(map(str, options))}, got {type(value).__name__}")
                return
        if "enum" in node and value not in node["enum"]:
            problems.append(f"{label}: {value!r} is not one of {node['enum']}")
        if "const" in node and value != node["const"]:
            problems.append(f"{label}: must be {node['const']!r}")
        if isinstance(value, Mapping):
            props = node.get("properties") or {}
            for key in node.get("required") or ():
                if key not in value:
                    problems.append(f"{label}: missing required {key!r}")
            extra = node.get("additionalProperties", True)
            for key, child in value.items():
                sub = f"{path}.{key}" if path else key
                if key in props:
                    check(props[key], child, sub, depth + 1)
                elif extra is False:
                    problems.append(f"{label}: unexpected property {key!r}")
                elif isinstance(extra, Mapping):
                    check(extra, child, sub, depth + 1)
        elif isinstance(value, list):
            if "minItems" in node and len(value) < node["minItems"]:
                problems.append(f"{label}: fewer than {node['minItems']} items")
            if "maxItems" in node and len(value) > node["maxItems"]:
                problems.append(f"{label}: more than {node['maxItems']} items")
            if isinstance(node.get("items"), Mapping):
                for i, element in enumerate(value):
                    check(node["items"], element, f"{path}[{i}]", depth + 1)
        elif isinstance(value, str):
            if "minLength" in node and len(value) < node["minLength"]:
                problems.append(f"{label}: shorter than {node['minLength']}")
            if "maxLength" in node and len(value) > node["maxLength"]:
                problems.append(f"{label}: longer than {node['maxLength']}")
            if "pattern" in node:
                try:
                    if re.search(node["pattern"], value) is None:
                        problems.append(f"{label}: does not match pattern {node['pattern']!r}")
                except re.error:
                    unchecked.append(f"{label}: pattern (not a Python regex)")
            if "format" in node:
                if node["format"] == "date-time":
                    try:
                        if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt ]", value) or not parse_time(value)[1]:
                            raise EvidenceError("no offset")
                    except EvidenceError:
                        problems.append(f"{label}: not an RFC 3339 date-time: {value!r}")
                else:
                    unchecked.append(f"{label}: format {node['format']}")
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            for key, bad in (("minimum", lambda b: value < b), ("maximum", lambda b: value > b),
                             ("exclusiveMinimum", lambda b: value <= b),
                             ("exclusiveMaximum", lambda b: value >= b)):
                bound = node.get(key)
                if isinstance(bound, (int, float)) and not isinstance(bound, bool) and bad(bound):
                    problems.append(f"{label}: {value} violates {key} {bound}")

    if kind == "example":
        example(shape, report, "")
    else:
        check(shape, report, "")
    return problems, unchecked


# ======================================================================================
#  Live side: fetch (GET-only, B-081 mirror), evidence pack, paced POST
# ======================================================================================

REQUIRED_ROLES = ("schema", "ais", "radar")


def default_fetch_client(base_url: str):
    """The GET-only, scope-checked web.WebClient the evidence is mirrored with (B-081's)."""
    return ics_mirror.default_http_client(base_url)


def default_post_client(base_url: str):
    """A scope-checked web.WebClient that may POST. Built only after the state-change gate passed."""
    import web as _web
    return _web.WebClient(base_url)


def fetch_evidence(client: Any, routes: Mapping[str, str]) -> tuple[ics_mirror.EvidencePack, dict]:
    """GET each documented route once through B-081's mirror: (the evidence pack, {role: bytes}).

    A required role (schema, ais, radar) that is unreachable or not a 200 is an EvidenceError naming
    the route and status; an optional one (reference, note) is recorded in the pack's notes."""
    if not isinstance(routes, Mapping) or not routes:
        raise MethodError("method.routes must map roles to documented routes")
    for role in REQUIRED_ROLES:
        if not routes.get(role):
            raise MethodError(f"method.routes has no route for {role!r}")
    roles = [(role, route) for role, route in routes.items() if route]
    mirrored = ics_mirror.mirror_http(
        client, [ics_mirror.DocumentedRoute(route, note=role) for role, route in roles])
    pack = ics_mirror.EvidencePack(challenge_id="")
    pack.http = mirrored
    evidence: dict[str, bytes] = {}
    for (role, route), res in zip(roles, mirrored):
        ok = res.error is None and res.status == 200
        if ok:
            evidence[role] = res.body
        elif role in REQUIRED_ROLES:
            raise EvidenceError(f"could not fetch {role} evidence from {route!r}: "
                                + (res.error or f"HTTP {res.status}"))
        else:
            pack.notes.append(f"optional {role} route {route!r} not fetched: "
                              + (res.error or f"HTTP {res.status}"))
    return pack, evidence


def load_pack(pack_dir: Path | str, routes: Mapping[str, str]) -> dict:
    """{role: bytes} read back from a mirrored evidence pack (``index.json`` + ``http/``), or from a
    plain folder holding the routes' basenames (``ais.ndjson``, ``radar.csv``, ``schema[.json]``, ...).
    No network. A folder with neither is an EvidenceError."""
    root = Path(pack_dir)
    if not root.is_dir():
        raise EvidenceError(f"no evidence folder at {root}")
    evidence: dict[str, bytes] = {}
    index = root / "index.json"
    if index.is_file():
        try:
            listed = json.loads(index.read_text(encoding="utf-8")).get("http") or []
        except (ValueError, AttributeError) as e:
            raise EvidenceError(f"{index}: not an evidence pack index ({e})") from None
        by_route = {entry.get("route"): entry.get("saved_as") for entry in listed if isinstance(entry, dict)}
        for role, route in routes.items():
            saved = by_route.get(route)
            if saved and (root / saved).resolve().is_relative_to(root.resolve()) and (root / saved).is_file():
                evidence[role] = (root / saved).read_bytes()
        if not evidence:
            raise EvidenceError(f"{index} lists none of the method's routes "
                                f"({', '.join(map(str, routes.values()))})")
        return evidence
    for role, route in routes.items():
        name = str(route).rstrip("/").rsplit("/", 1)[-1]
        candidates = [name] + ([f"{name}.json"] if "." not in name else [])
        for candidate in candidates:
            hits = sorted(p for p in root.rglob(candidate) if p.is_file())
            if hits:
                evidence[role] = hits[0].read_bytes()
                break
    if not evidence:
        raise EvidenceError(f"{root} holds no evidence pack (index.json) and none of the evidence files "
                            f"({', '.join(str(r).rsplit('/', 1)[-1] for r in routes.values())})")
    return evidence


def _parse_schema(data: Any) -> Any:
    try:
        return json.loads(_text(data))
    except ValueError as e:
        raise EvidenceError(f"/schema is not JSON ({e})") from None


@dataclass
class Prepared:
    """A dry run's output: the facts, the shaped report, and whether it may be sent."""
    reconciliation: Reconciliation
    built: BuiltReport
    problems: list[str]
    unchecked: list[str]
    method: dict

    @property
    def report(self) -> Any:
        return self.built.report

    @property
    def ready(self) -> bool:
        """Complete (no unresolved required leaf) and valid against the schema."""
        return self.built.complete and not self.problems

    def blockers(self) -> list[str]:
        return [f"unresolved: {u}" for u in self.built.unresolved] + [f"invalid: {p}" for p in self.problems]

    def to_dict(self) -> dict:
        return {"item": "B-111", "ready": self.ready, "report": self.report,
                "schema_kind": self.built.kind, "unresolved": list(self.built.unresolved),
                "problems": list(self.problems), "unchecked_schema_keywords": list(self.unchecked),
                "trace": list(self.built.trace), **self.reconciliation.to_dict()}


def prepare(evidence: Mapping[str, Any], method: Mapping | None = None) -> Prepared:
    """Evidence -> facts -> schema-shaped report -> validation. No network; nothing is sent."""
    method = load_method(method)
    if evidence.get("schema") in (None, b"", ""):
        raise EvidenceError(f"no schema evidence (route {method['routes'].get('schema')!r}): the report "
                            "cannot be shaped without it")
    schema = _parse_schema(evidence["schema"])
    rec = reconcile(evidence, method)
    rp = method["report"]
    built = build_report(schema, rec.facts, fields=rp["fields"], decimals=rp["decimals"],
                         time_format=rp["time_format"], time_decimals=rp["time_decimals"],
                         pointer=rp["schema_pointer"])
    problems, unchecked = ([], [])
    if built.complete:
        problems, unchecked = validate_report(schema, built.report, pointer=rp["schema_pointer"])
    return Prepared(rec, built, problems, unchecked, method)


def write_outputs(prepared: Prepared, out_dir: Path | str) -> Path:
    """Write ``report.json`` (exactly the body a send would POST) and ``reconciliation.json`` (facts,
    decisions, warnings, trace, blockers) under `out_dir`."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / REPORT_NAME).write_text(report_body(prepared.report) + "\n", encoding="utf-8")
    (out / RECONCILIATION_NAME).write_text(json.dumps(prepared.to_dict(), indent=2, default=str) + "\n",
                                           encoding="utf-8")
    return out


def report_body(report: Any) -> str:
    """The canonical JSON body of a report (what is hashed for the ledger and what is POSTed)."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)


# -- the POST ledger ----------------------------------------------------------------------

ANSWERED = ("accepted", "rejected", "judged")     # the judge gave a verdict: never resend that report
# No verdict and no look used: a 429, a judge that provably got nothing (refused connection, no such
# host), or a request the scope guard stopped before it was built. Everything else counts, including
# ``unknown``: the request may have reached the judge but no answer came back (a dropped connection, a
# read timeout, an ambiguous response), or the process died mid-send.
NOT_JUDGED = ("ratelimited", "unreachable", "not_sent")
NO_RESEND = ANSWERED + ("unknown",)               # resent only on an explicit override (resend_unknown)


def post_ledger_path(work_dir: Path | str, *, challenge_id: str = "", base_url: str = "") -> Path:
    """The POST ledger for one judge: ``<work_dir>/geo-reconcile/posts/<key>.jsonl``, keyed by the
    challenge id when there is one, else by the instance's host:port. Never by the output folder, so a
    new ``--out`` does not reset the budget, the pacing or the no-resend rule."""
    cid = str(challenge_id or "").strip()
    if cid:
        key = "challenge-" + re.sub(r"[^A-Za-z0-9._-]", "_", cid)
    elif base_url:
        try:
            ep = ics_mirror.parse_endpoint(base_url)
        except ics_mirror.MirrorError as e:
            raise PostRefused(f"cannot key the POST ledger by {base_url!r}: {e}") from None
        key = "instance-" + re.sub(r"[^A-Za-z0-9._-]", "_", f"{ep.host}_{ep.port}")
    else:
        raise PostRefused("no challenge id and no instance address to key the POST ledger by")
    return Path(work_dir) / "geo-reconcile" / "posts" / f"{key}.jsonl"


@contextlib.contextmanager
def _ledger_lock(path: Path):
    """An exclusive flock on ``<ledger>.lock`` for the whole check-and-send, so two runs against one
    ledger cannot both pass the pacing and budget checks and both send."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)            # closing the descriptor releases the flock


def _causes(exc: BaseException):
    """`exc`, its causes and contexts, and a URLError's `reason`, each once."""
    seen, todo = set(), [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        reason = getattr(e, "reason", None)
        todo.extend([e.__cause__, e.__context__, reason if isinstance(reason, BaseException) else None])


def send_failure_outcome(exc: BaseException) -> str:
    """The ledger outcome of a POST that raised instead of answering.

    ``not_sent``: the scope guard (or a GET-only client) refused it before it was built. ``unreachable``:
    the connection was refused or the host did not resolve, so no byte of the request left. Anything
    else (a reset or drop after connecting, a timeout, an ambiguous response) is ``unknown``: the judge
    may have read the report, so it counts against the budget and is not resent without an override."""
    if isinstance(exc, _ctf_scope.OutOfScope):
        return "not_sent"
    if any(isinstance(e, (ConnectionRefusedError, socket.gaierror)) for e in _causes(exc)):
        return "unreachable"
    return "unknown"


def _ledger_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise PostRefused(f"POST ledger {path} line {n} is unreadable; fix or remove it after checking "
                              "what was sent (nothing is sent on an unreadable ledger)") from None
        if not isinstance(row, dict) or row.get("kind") not in ("intent", "result"):
            raise PostRefused(f"POST ledger {path} line {n} is not a ledger row; nothing is sent")
        rows.append(row)
    return rows


def _append(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def ledger_state(path: Path | str) -> dict:
    """What the POST ledger says: {"judged": n, "last_ts": t | None, "by_sha": {sha: outcome}, "rows"}.
    Every send counts against the budget except the outcomes in NOT_JUDGED. An intent with no result
    (a crash mid-send) counts, with outcome ``unknown``."""
    rows = _ledger_rows(Path(path))
    results = {r.get("n"): r for r in rows if r["kind"] == "result"}
    judged, by_sha, last = 0, {}, None
    for row in rows:
        ts = row.get("ts")
        if isinstance(ts, (int, float)):
            last = ts if last is None else max(last, ts)
        if row["kind"] != "intent":
            continue
        result = results.get(row.get("n"))
        outcome = result.get("outcome") if result else "unknown"
        if outcome not in NOT_JUDGED:
            judged += 1
            by_sha[row.get("sha256")] = outcome
    return {"judged": judged, "last_ts": last, "by_sha": by_sha, "rows": len(rows)}


def _retry_after(entry: Mapping) -> float | None:
    for key, value in (entry.get("response_headers") or {}).items():
        if str(key).lower() == "retry-after":
            try:
                return max(0.0, float(str(value).strip()))
            except ValueError:
                return None
    return None


def classify_response(entry: Mapping, profile: Any = None) -> tuple[str, list[str]]:
    """(outcome, flags) for a judge response: ``ratelimited`` (429), ``accepted`` (a value in the
    event's flag format came back), ``rejected`` (400/409/422: the report was refused), ``judged``
    (another 2xx: an answer without a flag), else ``error``."""
    status = entry.get("status")
    body = entry.get("body") or b""
    if status == 429:
        return "ratelimited", []
    flags = _flagfmt.find_flags(body, profile) if body else []
    if flags and isinstance(status, int) and 200 <= status < 300:
        return "accepted", list(dict.fromkeys(flags))
    if status in (400, 409, 422):
        return "rejected", []
    if isinstance(status, int) and 200 <= status < 300:
        return "judged", []
    return "error", []


def submit_report(client_factory: Callable[[], Any], path: str, prepared: Prepared, *, profile: Any,
                  approved: bool, ledger_path: Path | str, clock: Callable[[], float] = time.time,
                  sleep: Callable[[float], None] = time.sleep, resend_unknown: bool = False) -> dict:
    """Send the prepared report to the judge route, once, under every guard. Returns the outcome dict
    ``{"outcome", "status", "flags", "posts", "waited_s", "retry_after_s", "body"}``.

    Order of checks, each before any byte is sent: the report is ready (complete and schema-valid);
    the event profile allows state-changing requests and the player approved this one
    (``ics_mirror.authorize_state_change``); then, under an exclusive lock on the ledger: this exact
    report was not already judged (nor sent with no answer back, unless `resend_unknown`); the judged
    count is under ``post.max_posts``; the pacing interval since the last POST has passed (waited out
    through `sleep` when it is at most ``post.max_wait_s``, refused otherwise). The intent is written
    to the ledger before the send and the result after, so a crash mid-send still counts. A 429 is
    not a judgement: it is retried after ``Retry-After`` (at least the pacing interval) at most
    ``post.ratelimit_retries`` times, and only when that wait is within ``post.max_wait_s``.

    A POST that raises is classified by ``send_failure_outcome``: a scope refusal is re-raised as it
    is (nothing was sent); an unreachable judge is a ReconcileError that uses no look; anything after
    the connection was made is ``unknown``, counts, and is a ReconcileError.

    `client_factory` is called only after every check passed, so no POST-capable client exists
    before then. A flag in the response is returned, never submitted."""
    policy = prepared.method["post"]
    interval, budget = float(policy["min_interval_s"]), int(policy["max_posts"])
    retries, max_wait = int(policy["ratelimit_retries"]), float(policy["max_wait_s"])
    if not prepared.ready:
        raise PostRefused("the report is not ready to send: " + "; ".join(prepared.blockers()))
    ics_mirror.authorize_state_change(f"POST {path}", approved=approved, profile=profile)
    ledger = Path(ledger_path)
    body = report_body(prepared.report)
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    with _ledger_lock(ledger):
        state = ledger_state(ledger)
        previous = state["by_sha"].get(sha)
        if previous in ANSWERED:
            raise PostRefused(f"this exact report was already sent and came back {previous!r} "
                              f"({ledger}); change the method before sending again")
        if previous in NO_RESEND and not resend_unknown:
            raise PostRefused(f"this exact report was already sent and no answer came back (outcome "
                              f"{previous!r}, {ledger}): the judge may have counted it. Resending it is "
                              "the player's call (--resend-unknown)")
        if state["judged"] >= budget:
            raise PostRefused(f"the POST budget is used up ({state['judged']} of post.max_posts = {budget} "
                              f"judged, see {ledger}); raising it is the player's call")
        client = None
        waited, posts, n = 0.0, 0, state["rows"]
        attempt, retry_after = 0, None
        while True:
            last = ledger_state(ledger)["last_ts"]
            wait = 0.0 if last is None else last + interval - clock()
            if attempt and retry_after is not None:
                wait = max(wait, retry_after)
            if wait > 0:
                if wait > max_wait:
                    if attempt:
                        return {"outcome": "ratelimited", "status": 429, "flags": [], "posts": posts,
                                "waited_s": waited, "retry_after_s": wait, "body": b""}
                    raise PostRefused(f"paced: the next POST is allowed in {wait:.0f} s (post.min_interval_s "
                                      f"= {interval:g}, post.max_wait_s = {max_wait:g})")
                sleep(wait)
                waited += wait
            if client is None:
                client = client_factory()
            n += 1
            _append(ledger, {"kind": "intent", "n": n, "ts": clock(), "sha256": sha, "route": path})
            try:
                entry = client.post(path, data=body, headers={"Content-Type": "application/json"})
            except Exception as e:  # noqa: BLE001 - recorded, then raised with its name
                outcome = send_failure_outcome(e)
                _append(ledger, {"kind": "result", "n": n, "ts": clock(), "outcome": outcome,
                                 "error": f"{type(e).__name__}: {e}"[:300]})
                if outcome == "not_sent":
                    raise
                if outcome == "unreachable":
                    raise ReconcileError(f"POST {path} did not reach the judge: {type(e).__name__}: {e}") from e
                raise ReconcileError(f"POST {path} may have reached the judge but no answer came back "
                                     f"({type(e).__name__}: {e}); it counts as a judged send (outcome "
                                     f"'unknown', {ledger}) and this report is not resent without "
                                     "--resend-unknown") from e
            posts += 1
            outcome, flags = classify_response(entry, profile)
            retry_after = _retry_after(entry) if outcome == "ratelimited" else None
            _append(ledger, {"kind": "result", "n": n, "ts": clock(), "outcome": outcome,
                             "status": entry.get("status"), "retry_after_s": retry_after,
                             "response_sha256": hashlib.sha256(entry.get("body") or b"").hexdigest()})
            if outcome != "ratelimited" or attempt >= retries:
                return {"outcome": outcome, "status": entry.get("status"), "flags": flags, "posts": posts,
                        "waited_s": waited, "retry_after_s": retry_after, "body": entry.get("body") or b""}
            attempt += 1


@dataclass
class RunResult:
    out_dir: Path
    prepared: Prepared
    post: dict | None = None

    @property
    def flags(self) -> list[str]:
        return list(self.post["flags"]) if self.post else []


def run_live(base_url: str, method: Mapping | None, out_dir: Path | str, *, profile: Any,
             challenge_id: str = "", send: bool = False, approved: bool = False,
             ledger_path: Path | str | None = None, resend_unknown: bool = False,
             fetch_client_factory: Callable[[str], Any] = default_fetch_client,
             post_client_factory: Callable[[str], Any] = default_post_client,
             clock: Callable[[], float] = time.time,
             sleep: Callable[[float], None] = time.sleep) -> RunResult:
    """Fetch /schema and the evidence (GET-only), write the evidence pack, reconcile, shape and
    validate the report, write it; and only with `send` -- and the profile rule, the player's
    approval and the leave of the POST ledger at `ledger_path` (``submit_report``; the CLI keys it
    by challenge or instance with ``post_ledger_path``) -- POST it once.

    Default is a dry run: no POST-capable client is built and nothing is sent."""
    method = load_method(method)
    if send and ledger_path is None:
        raise PostRefused("a send needs a POST ledger (ledger_path; see post_ledger_path)")
    client = fetch_client_factory(base_url)
    pack, evidence = fetch_evidence(client, method["routes"])
    pack.challenge_id = str(challenge_id)
    try:
        pack.endpoint = ics_mirror.parse_endpoint(base_url)
    except ics_mirror.MirrorError:
        pack.endpoint = None
    out = ics_mirror.write_pack(pack, out_dir)
    prepared = prepare(evidence, method)
    write_outputs(prepared, out)
    result = RunResult(out, prepared)
    if send:
        result.post = submit_report(lambda: post_client_factory(base_url), method["submit"], prepared,
                                    profile=profile, approved=approved, ledger_path=ledger_path,
                                    clock=clock, sleep=sleep, resend_unknown=resend_unknown)
        (out / RESPONSE_NAME).write_bytes(result.post["body"])
    return result


def run_offline(pack_dir: Path | str, method: Mapping | None = None, *,
                out_dir: Path | str | None = None) -> RunResult:
    """Recompute the report from a mirrored pack (or a folder of evidence files). No network."""
    method = load_method(method)
    evidence = load_pack(pack_dir, method["routes"])
    prepared = prepare(evidence, method)
    out = write_outputs(prepared, out_dir if out_dir is not None else pack_dir)
    return RunResult(out, prepared)


# ======================================================================================
#  Engine contract entry (offline) and script CLI
# ======================================================================================

def summarize(prepared: Prepared) -> list[str]:
    """The facts a reader checks before a send, one line each."""
    facts = prepared.reconciliation.facts
    lines = [f"{len(facts['associations'])} radar/AIS associations (pairing {facts['pairing']}, radar clock "
             f"{facts['clock_offset_s']['radar']:+.0f} s)"]
    d = facts["divergence"]
    if d:
        lines.append(f"divergence: AIS {d['ais_id']} / radar {d['radar_id']} "
                     f"{format_time(d['start_utc'])}..{format_time(d['end_utc'])}, AIS-minus-radar "
                     f"east {d['east_m']:+.1f} m north {d['north_m']:+.1f} m ({d['samples']} samples)")
    else:
        lines.append(f"divergence: none singled out ({len(facts['divergences'])} windows)")
    c = facts["closest_approach"]
    if c:
        lines.append(f"closest approach: {c['source']} track {c['radar_id'] if c['source'] == 'radar' else c['ais_id']}"
                     f" at {format_time(c['utc'])}, {c['distance_m']:.1f} m")
    else:
        lines.append("closest approach: not computed")
    return lines


def solve(challenge_dir, profile=None, **opts):
    """Offline: reconcile a mirrored evidence pack under `challenge_dir` and shape the report.

    No flag exists offline (it comes from the judge's answer to an approved POST), so this returns
    ``unsure`` with the facts as evidence and the report path in the notes, ``none`` when the folder
    holds no sensor evidence, and ``blocked`` naming what is missing when the evidence cannot be
    reconciled. Options: ``method=<path to a method JSON>``, ``pack=<folder>`` (default: the first of
    ``geo-reconcile``, ``evidence``, ``files`` and the challenge folder itself that holds evidence)."""
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    try:
        user = json.loads(Path(opts["method"]).read_text(encoding="utf-8")) if opts.get("method") else None
        method = load_method(user)
    except (OSError, ValueError, MethodError) as e:
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=f"method not usable: {e}")
    folders = [Path(opts["pack"])] if opts.get("pack") else [
        challenge_dir / name for name in ("geo-reconcile", "evidence", "files")] + [challenge_dir]
    evidence, used = None, None
    for folder in folders:
        try:
            evidence, used = load_pack(folder, method["routes"]), folder
            break
        except EvidenceError:
            continue
    if not evidence or not (evidence.get("ais") and evidence.get("radar")):
        return SolverResult(status="none", engine=ENGINE_ID,
                            notes="no AIS + radar evidence under the challenge folder (mirror it first: "
                                  "ctf geo-reconcile run)")
    try:
        prepared = prepare(evidence, method)
    except ReconcileError as e:
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=f"{type(e).__name__}: {e}")
    out = write_outputs(prepared, used if opts.get("pack") else challenge_dir / "geo-reconcile")
    try:
        rel = str((out / REPORT_NAME).relative_to(challenge_dir))
    except ValueError:
        rel = None
    evidence_items = [Evidence("geometry", line, path=rel) for line in summarize(prepared)]
    state = "ready to send" if prepared.ready else "NOT ready: " + "; ".join(prepared.blockers())
    notes = (f"report written to {out / REPORT_NAME} ({state}). Nothing was sent: the POST needs "
             "rules.web_state_changing and player approval (ctf geo-reconcile run --send "
             "--player-approved). " + " ".join(prepared.reconciliation.warnings))
    return SolverResult(status="unsure", engine=ENGINE_ID, evidence=evidence_items, notes=notes.strip())


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip().splitlines()[0])
        print("usage: geo_reconcile.py {method | offline <pack-dir> [method.json]}")
        return 0 if argv else 2
    try:
        if argv[0] == "method":
            print(json.dumps(default_method(), indent=2))
            return 0
        if argv[0] == "offline" and len(argv) >= 2:
            user = json.loads(Path(argv[2]).read_text(encoding="utf-8")) if len(argv) > 2 else None
            result = run_offline(argv[1], user)
            print(json.dumps(result.prepared.to_dict(), indent=2, default=str))
            return 0 if result.prepared.ready else 1
    except (ReconcileError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"unknown command {argv[0]!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
