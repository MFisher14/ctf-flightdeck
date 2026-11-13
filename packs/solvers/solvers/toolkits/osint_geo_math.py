#!/usr/bin/env python3
"""Offline geolocation math for distances, bearings, sun/shadow and simple celestial loci.

These helpers rank supplied candidates; they do not invent a location or turn the first row into an
answer.  Solar calculations use the bounded NOAA/Meeus approximation (normally within a fraction of
a degree away from the horizon).  Near-horizon refraction, terrain and image orientation can dominate,
so every result carries an explicit human-verification note.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import itertools
import json
import math
import sys
from typing import Iterable


EARTH_RADIUS_M = 6_371_008.8


def _coord(lat: float, lon: float) -> tuple[float, float]:
    lat, lon = float(lat), float(lon)
    if not math.isfinite(lat) or not math.isfinite(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise ValueError("invalid Earth coordinate")
    return lat, lon


def angular_residual(a: float, b: float) -> float:
    """Smallest unsigned separation between bearings, in degrees."""
    return abs((float(a) - float(b) + 180.0) % 360.0 - 180.0)


def distance_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> dict:
    """Haversine great-circle distance and initial/final bearings."""
    try:
        lat1, lon1 = _coord(lat1, lon1)
        lat2, lon2 = _coord(lat2, lon2)
    except TypeError:
        return None
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    dp = p2 - p1
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    central = 2 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    initial = math.degrees(math.atan2(y, x)) % 360.0
    # Reverse initial + 180 gives the forward-path final bearing.
    y2 = math.sin(-dl) * math.cos(p1)
    x2 = math.cos(p2) * math.sin(p1) - math.sin(p2) * math.cos(p1) * math.cos(-dl)
    final = (math.degrees(math.atan2(y2, x2)) + 180.0) % 360.0
    return {
        "distance_m": central * EARTH_RADIUS_M,
        "initial_bearing_deg": initial,
        "final_bearing_deg": final,
    }


def parse_utc(value: str | dt.datetime) -> dt.datetime:
    if isinstance(value, dt.datetime):
        stamp = value
    else:
        raw = str(value).strip().replace("Z", "+00:00")
        stamp = dt.datetime.fromisoformat(raw)
    if stamp.tzinfo is None:
        raise ValueError("timestamp must carry a UTC offset")
    try:
        return stamp.astimezone(dt.timezone.utc)
    except OverflowError:
        return None


def julian_day(value: str | dt.datetime) -> float:
    stamp = parse_utc(value)
    return stamp.timestamp() / 86400.0 + 2440587.5


def solar_position(value: str | dt.datetime, lat: float, lon: float) -> dict:
    """Approximate apparent solar azimuth/elevation for a UTC instant and WGS84 coordinate.

    Azimuth is degrees clockwise from true north.  Elevation includes NOAA's small atmospheric
    refraction correction only between roughly -0.6 and 85 degrees.
    """
    lat, lon = _coord(lat, lon)
    stamp = parse_utc(value)
    jd = julian_day(stamp)
    t = (jd - 2451545.0) / 36525.0
    geom_long = (280.46646 + t * (36000.76983 + t * 0.0003032)) % 360.0
    geom_anom = 357.52911 + t * (35999.05029 - 0.0001537 * t)
    ecc = 0.016708634 - t * (0.000042037 + 0.0000001267 * t)
    mr = math.radians(geom_anom)
    center = ((1.914602 - t * (0.004817 + 0.000014 * t)) * math.sin(mr)
              + (0.019993 - 0.000101 * t) * math.sin(2 * mr)
              + 0.000289 * math.sin(3 * mr))
    true_long = geom_long + center
    omega = 125.04 - 1934.136 * t
    app_long = true_long - 0.00569 - 0.00478 * math.sin(math.radians(omega))
    mean_obliq = 23.0 + (26.0 + (21.448 - t * (46.815 + t * (0.00059 - t * 0.001813))) / 60.0) / 60.0
    obliq = mean_obliq + 0.00256 * math.cos(math.radians(omega))
    decl = math.degrees(math.asin(math.sin(math.radians(obliq)) * math.sin(math.radians(app_long))))
    y = math.tan(math.radians(obliq) / 2.0) ** 2
    eqtime = 4.0 * math.degrees(
        y * math.sin(2 * math.radians(geom_long))
        - 2 * ecc * math.sin(mr)
        + 4 * ecc * y * math.sin(mr) * math.cos(2 * math.radians(geom_long))
        - 0.5 * y * y * math.sin(4 * math.radians(geom_long))
        - 1.25 * ecc * ecc * math.sin(2 * mr)
    )
    minutes = stamp.hour * 60 + stamp.minute + stamp.second / 60 + stamp.microsecond / 60_000_000
    true_solar = (minutes + eqtime + 4 * lon) % 1440.0
    hour_angle = true_solar / 4.0 - 180.0
    pr, dr, hr = map(math.radians, (lat, decl, hour_angle))
    cos_zenith = math.sin(pr) * math.sin(dr) + math.cos(pr) * math.cos(dr) * math.cos(hr)
    zenith = math.degrees(math.acos(max(-1.0, min(1.0, cos_zenith))))
    elevation = 90.0 - zenith
    if zenith < 1e-12:
        azimuth = 180.0
    else:
        azimuth = (math.degrees(math.atan2(
            math.sin(hr), math.cos(hr) * math.sin(pr) - math.tan(dr) * math.cos(pr)
        )) + 180.0) % 360.0
    refraction = 0.0
    if 5 < elevation <= 85:
        tangent = math.tan(math.radians(elevation))
        refraction = (58.1 / tangent - 0.07 / tangent ** 3 + 0.000086 / tangent ** 5) / 3600.0
    elif -0.575 < elevation <= 5:
        refraction = (1735 + elevation * (-518.2 + elevation * (103.4 + elevation *
                      (-12.79 + elevation * 0.711)))) / 3600.0
    return {
        "timestamp_utc": stamp.isoformat().replace("+00:00", "Z"),
        "latitude": lat,
        "longitude": lon,
        "azimuth_deg": azimuth,
        "elevation_deg": elevation + refraction,
        "geometric_elevation_deg": elevation,
        "declination_deg": decl,
        "equation_of_time_minutes": eqtime,
        "method": "NOAA/Meeus approximation",
    }


@dataclasses.dataclass(frozen=True)
class ShadowCandidate:
    rank: int
    name: str
    latitude: float
    longitude: float
    expected_shadow_bearing_deg: float
    observed_shadow_bearing_deg: float
    residual_deg: float
    solar_elevation_deg: float
    plausible: bool
    note: str = ("orientation/time metadata and true-north calibration must be independently verified; "
                 "do not submit the top row automatically")


def rank_shadow_candidates(value: str | dt.datetime, shadow_bearing_deg: float,
                           candidates: Iterable[tuple[str, float, float]], *,
                           tolerance_deg: float = 12.0) -> list[ShadowCandidate]:
    """Rank supplied places by shadow direction at one instant.

    ``shadow_bearing_deg`` is where a vertical object's shadow points, clockwise from true north.
    Camera-up is not true north unless calibrated; callers must account for that before using this.
    """
    observed = float(shadow_bearing_deg) % 360.0
    if not math.isfinite(observed) or not 0 < tolerance_deg <= 90:
        raise ValueError("invalid shadow bearing/tolerance")
    rows = []
    for name, lat, lon in itertools.islice(candidates, 128):
        sun = solar_position(value, lat, lon)
        expected = (sun["azimuth_deg"] + 180.0) % 360.0
        residual = angular_residual(expected, observed)
        daylight = sun["elevation_deg"] > 0
        plausible = daylight and residual <= tolerance_deg
        rows.append(ShadowCandidate(
            rank=max(0, round(100 - residual * 2 - (0 if daylight else 50))),
            name=str(name)[:256], latitude=float(lat), longitude=float(lon),
            expected_shadow_bearing_deg=expected, observed_shadow_bearing_deg=observed,
            residual_deg=residual, solar_elevation_deg=sun["elevation_deg"], plausible=plausible,
        ))
    return sorted(rows, key=lambda row: (-row.rank, row.residual_deg, row.name))


def polaris_latitude(altitude_deg: float, *, horizon_dip_deg: float = 0.0,
                     refraction_deg: float = 0.0) -> list[dict]:
    """Return northern-latitude candidates from Polaris altitude, with error caveats.

    This is intentionally approximate: Polaris is offset from the celestial pole and apparent
    altitude depends on timestamp/refraction.  It is a locus, not a unique location.
    """
    # A positive dip means the visible horizon lies below the astronomical horizontal, so a
    # sextant altitude measured from that visible horizon is too large by the dip angle.
    alt = float(altitude_deg) - float(horizon_dip_deg) - float(refraction_deg)
    if not math.isfinite(alt) or not 0 <= alt <= 90:
        raise ValueError("invalid Polaris altitude")
    return [{
        "rank": 70,
        "latitude_deg_approx": alt,
        "longitude": None,
        "uncertainty_deg_at_least": 1.0,
        "verified": False,
        "note": "Polaris altitude gives only an approximate northern latitude; timestamp/refraction are required",
    }]


def altitude_latitude_locus(declination_deg: float, hour_angle_deg: float,
                            altitude_deg: float) -> list[dict]:
    """Solve the two possible observer latitudes for star declination/hour-angle/altitude."""
    dec, hour, alt = map(float, (declination_deg, hour_angle_deg, altitude_deg))
    if not all(math.isfinite(x) for x in (dec, hour, alt)) or not -90 <= dec <= 90 or not -90 <= alt <= 90:
        raise ValueError("invalid celestial angles")
    a = math.sin(math.radians(dec))
    b = math.cos(math.radians(dec)) * math.cos(math.radians(hour))
    c = math.sin(math.radians(alt))
    radius = math.hypot(a, b)
    if radius < 1e-15 or abs(c) > radius + 1e-12:
        return []
    phase = math.atan2(b, a)
    base = math.asin(max(-1.0, min(1.0, c / radius)))
    solutions = []
    for raw in (base - phase, math.pi - base - phase):
        # Normalize latitude to [-180,180], then retain physical [-90,90].
        deg = (math.degrees(raw) + 180) % 360 - 180
        if -90 <= deg <= 90 and all(abs(deg - x) > 1e-8 for x in solutions):
            solutions.append(deg)
    return [{
        "rank": 60,
        "latitude_deg": value,
        "longitude": None,
        "verified": False,
        "note": "celestial altitude defines a latitude locus only if hour angle and clock are correct",
    } for value in sorted(solutions)]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline OSINT distance/sun/celestial calculations")
    sub = parser.add_subparsers(dest="command", required=True)
    distance = sub.add_parser("distance")
    distance.add_argument("lat1", type=float); distance.add_argument("lon1", type=float)
    distance.add_argument("lat2", type=float); distance.add_argument("lon2", type=float)
    sun = sub.add_parser("sun")
    sun.add_argument("timestamp"); sun.add_argument("lat", type=float); sun.add_argument("lon", type=float)
    polaris = sub.add_parser("polaris")
    polaris.add_argument("altitude", type=float)
    locus = sub.add_parser("locus")
    locus.add_argument("declination", type=float); locus.add_argument("hour_angle", type=float)
    locus.add_argument("altitude", type=float)
    try:
        args = parser.parse_args(argv)
        if args.command == "distance":
            result = distance_bearing(args.lat1, args.lon1, args.lat2, args.lon2)
        elif args.command == "sun":
            result = solar_position(args.timestamp, args.lat, args.lon)
        elif args.command == "polaris":
            result = polaris_latitude(args.altitude)
        else:
            result = altitude_latitude_locus(args.declination, args.hour_angle, args.altitude)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OverflowError) as exc:
        print(f"osint_geo_math: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
