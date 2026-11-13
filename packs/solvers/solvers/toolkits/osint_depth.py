#!/usr/bin/env python3
"""Round-5g OSINT reasoning depth built on the guarded Round-5 client.

The older OSINT modules already own byte parsing and network policy.  This module
does not duplicate either.  It adds bounded, offline evidence correlation plus a
small orchestrator which routes one reviewed lead through ``PublicOSINTClient``.
There is no arbitrary URL fetcher, image uploader, account-variant generator, or
answer/flag submitter here.  Every report leaves the final pin to a human.

Network-facing tests inject a transport.  Production callers must explicitly
construct ``osint_online.PublicOSINTClient``; all throttling, caps, allow-lists,
redirect checks, identity guards, and the generic user-agent remain authoritative
in that existing class.
"""
from __future__ import annotations

import bisect
import dataclasses
import hashlib
import ipaddress
import itertools
import math
import re
import unicodedata
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import osint_geo_math as geo_math
import osint_online as online


MAX_OBSERVATIONS = 64
MAX_CANDIDATES = 128
MAX_PROFILE_POINTS = 720
MAX_EVIDENCE_ROWS = 512
MAX_MANUAL_RESULTS = 48
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_TEXT = 4096
MAX_JSON_NODES = 8192

HUMAN_NOTE = (
    "ranked evidence only; independently corroborate it and let the player make "
    "the final location/identity pin"
)


def _bounded_text(value: object, *, limit: int = MAX_TEXT, field: str = "text") -> str:
    text = str(value).strip()
    if (not text or len(text) > limit
            or any((ord(ch) < 0x20 and ch not in "\t")
                   or unicodedata.category(ch) == "Cs" for ch in text)):
        raise ValueError(f"{field} is empty, overlong, or contains control characters")
    return text


def _identifier_text(value: object, *, limit: int, field: str) -> str:
    """NFKC-normalize a network identifier and reject invisible/control smuggling."""
    text = unicodedata.normalize("NFKC", _bounded_text(value, limit=limit, field=field))
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in text):
        raise ValueError(f"{field} contains invisible/control characters")
    return text


def _take_bounded(values: Iterable[Any], cap: int, *, field: str,
                  minimum: int = 0) -> list[Any]:
    """Materialize at most ``cap + 1`` items, so infinite iterators fail promptly."""
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ValueError(f"{field} must be iterable") from exc
    rows = list(itertools.islice(iterator, cap + 1))
    if len(rows) > cap:
        raise ValueError(f"{field} accepts at most {cap} items")
    if len(rows) < minimum:
        raise ValueError(f"{field} needs at least {minimum} item(s)")
    return rows


def _bounded_json_value(value: object, *, budget: list[int] | None = None,
                        depth: int = 0) -> Any:
    """Copy untrusted provider data into a JSON-safe, globally bounded tree."""
    if budget is None:
        budget = [MAX_JSON_NODES]
    if budget[0] <= 0:
        return "<truncated: output node cap>"
    budget[0] -= 1
    if depth > 6:
        return "<truncated: depth cap>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else f"<{value}>"
    if isinstance(value, str):
        if re.match(r"(?i)^https?://", value.strip()):
            try:
                return _safe_reference_url(value.strip())
            except ValueError:
                return "<blocked unsafe public-reference URL>"
        return value[:MAX_TEXT] + ("…" if len(value) > MAX_TEXT else "")
    if isinstance(value, bytes):
        prefix = value[:256].hex()
        return {"bytes_hex": prefix, "truncated": len(value) > 256}
    if dataclasses.is_dataclass(value):
        value = {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        items = list(itertools.islice(value.items(), 129))
        for key, child in items[:128]:
            if budget[0] <= 0:
                break
            output[str(key)[:256]] = _bounded_json_value(child, budget=budget, depth=depth + 1)
        if len(items) > 128 or budget[0] <= 0:
            output["<truncated>"] = True
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = list(itertools.islice(iter(value), 129))
        output = [_bounded_json_value(child, budget=budget, depth=depth + 1)
                  for child in items[:128] if budget[0] > 0]
        if len(items) > 128 or budget[0] <= 0:
            output.append("<truncated>")
        return output
    return str(value)[:MAX_TEXT]


def _finite(value: object, *, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric, not boolean")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field} must be finite")
    return number


def _human_report(kind: str, **fields: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        **fields,
        "requires_human_pin": True,
        "automatic_answer": None,
        "note": HUMAN_NOTE,
    }


# ---------------------------------------------------------------------------
# Sun/shadow geometry and multi-observation consistency
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ShadowLengthObservation:
    """One measured vertical-object shadow on locally level ground.

    ``shadow_bearing_deg`` is optional and means the compass direction in which
    the shadow points.  ``terrain_horizon_deg`` is the local skyline altitude in
    the sun direction; it is used only as a visibility constraint.  Neither a
    camera-up direction nor an unreferenced pixel angle should be put here.
    """

    timestamp: str
    object_height_m: float
    shadow_length_m: float
    shadow_bearing_deg: float | None = None
    terrain_horizon_deg: float = 0.0
    label: str = ""


def shadow_elevation_deg(object_height_m: float, shadow_length_m: float) -> float:
    """Infer solar elevation from a vertical height and level-ground shadow."""
    height = _finite(object_height_m, field="object height")
    length = _finite(shadow_length_m, field="shadow length")
    if height <= 0 or length <= 0:
        raise ValueError("object height and shadow length must be positive")
    return math.degrees(math.atan2(height, length))


def _coerce_shadow(row: ShadowLengthObservation | Mapping[str, Any]) -> ShadowLengthObservation:
    if isinstance(row, ShadowLengthObservation):
        result = ShadowLengthObservation(
            timestamp=_identifier_text(row.timestamp, limit=128, field="timestamp"),
            object_height_m=_finite(row.object_height_m, field="object height"),
            shadow_length_m=_finite(row.shadow_length_m, field="shadow length"),
            shadow_bearing_deg=(None if row.shadow_bearing_deg is None else
                                _finite(row.shadow_bearing_deg, field="shadow bearing")),
            terrain_horizon_deg=_finite(row.terrain_horizon_deg, field="terrain horizon"),
            label=("" if not row.label else
                   _bounded_text(row.label, limit=256, field="observation label")),
        )
    elif isinstance(row, Mapping):
        try:
            result = ShadowLengthObservation(
                timestamp=_identifier_text(row["timestamp"], limit=128, field="timestamp"),
                object_height_m=_finite(row["object_height_m"], field="object height"),
                shadow_length_m=_finite(row["shadow_length_m"], field="shadow length"),
                shadow_bearing_deg=(None if row.get("shadow_bearing_deg") is None else
                                    _finite(row["shadow_bearing_deg"], field="shadow bearing")),
                terrain_horizon_deg=_finite(row.get("terrain_horizon_deg", 0.0),
                                            field="terrain horizon"),
                label=("" if not row.get("label") else
                       _bounded_text(row["label"], limit=256, field="observation label")),
            )
        except KeyError as exc:
            raise ValueError(f"shadow observation lacks {exc.args[0]}") from exc
    else:
        raise ValueError("shadow observations must be mappings or ShadowLengthObservation values")
    shadow_elevation_deg(result.object_height_m, result.shadow_length_m)
    if result.shadow_bearing_deg is not None and not 0 <= result.shadow_bearing_deg <= 360:
        raise ValueError("shadow bearing must be in 0..360 degrees")
    if not -20 <= result.terrain_horizon_deg <= 90:
        raise ValueError("terrain horizon must be in -20..90 degrees")
    # Validate timezone-bearing timestamp with the existing parser.
    geo_math.parse_utc(result.timestamp)
    return result


def _coerce_candidate(row: Mapping[str, Any] | Sequence[Any]) -> tuple[str, float, float]:
    if isinstance(row, Mapping):
        try:
            name, lat, lon = row["name"], row["latitude"], row["longitude"]
        except KeyError as exc:
            raise ValueError(f"candidate lacks {exc.args[0]}") from exc
    elif isinstance(row, Sequence) and not isinstance(row, (str, bytes)) and len(row) == 3:
        name, lat, lon = row
    else:
        raise ValueError("candidate must be {name,latitude,longitude} or a three-item sequence")
    name = _bounded_text(name, limit=256, field="candidate name")
    # distance_bearing performs the canonical coordinate validation without
    # duplicating it; using the same point is harmless.
    geo_math.distance_bearing(lat, lon, lat, lon)
    return name, float(lat), float(lon)


def rank_shadow_length_candidates(
    observations: Iterable[ShadowLengthObservation | Mapping[str, Any]],
    candidates: Iterable[Mapping[str, Any] | Sequence[Any]],
    *,
    elevation_tolerance_deg: float = 3.0,
    bearing_tolerance_deg: float = 12.0,
) -> dict[str, Any]:
    """Rank supplied coordinates against several measured shadows.

    This extends the existing direction-only helper with shadow length and a
    multi-time consistency check.  It never searches coordinates or invents a
    place.  Camera orientation, sloped ground, object lean, uncertain height,
    refraction, and timestamp provenance remain human-review caveats.
    """
    obs = [_coerce_shadow(row) for row in _take_bounded(
        observations, MAX_OBSERVATIONS, field="shadow observations", minimum=1
    )]
    places = [_coerce_candidate(row) for row in _take_bounded(
        candidates, MAX_CANDIDATES, field="supplied candidates", minimum=1
    )]
    elev_tol = _finite(elevation_tolerance_deg, field="elevation tolerance")
    bearing_tol = _finite(bearing_tolerance_deg, field="bearing tolerance")
    if not 0 < elev_tol <= 30 or not 0 < bearing_tol <= 90:
        raise ValueError("shadow tolerances are outside useful bounds")

    ranked: list[dict[str, Any]] = []
    for name, lat, lon in places:
        fits: list[dict[str, Any]] = []
        penalties: list[float] = []
        all_consistent = True
        for index, item in enumerate(obs):
            observed_elevation = shadow_elevation_deg(item.object_height_m, item.shadow_length_m)
            sun = geo_math.solar_position(item.timestamp, lat, lon)
            expected_elevation = float(sun["geometric_elevation_deg"])
            elevation_residual = abs(expected_elevation - observed_elevation)
            visible = expected_elevation > item.terrain_horizon_deg
            bearing_residual = None
            expected_shadow_bearing = (float(sun["azimuth_deg"]) + 180.0) % 360.0
            if item.shadow_bearing_deg is not None:
                bearing_residual = geo_math.angular_residual(
                    expected_shadow_bearing, item.shadow_bearing_deg % 360.0
                )
            consistent = (
                visible
                and elevation_residual <= elev_tol
                and (bearing_residual is None or bearing_residual <= bearing_tol)
            )
            all_consistent = all_consistent and consistent
            penalty = min(100.0, elevation_residual / elev_tol * 30.0)
            if bearing_residual is not None:
                penalty += min(50.0, bearing_residual / bearing_tol * 20.0)
            if not visible:
                penalty += 60.0
            penalties.append(penalty)
            fits.append({
                "observation": item.label or f"observation-{index + 1}",
                "timestamp_utc": sun["timestamp_utc"],
                "observed_elevation_deg": observed_elevation,
                "expected_elevation_deg": expected_elevation,
                "elevation_residual_deg": elevation_residual,
                "terrain_horizon_deg": item.terrain_horizon_deg,
                "sun_visible_above_terrain": visible,
                "observed_shadow_bearing_deg": item.shadow_bearing_deg,
                "expected_shadow_bearing_deg": expected_shadow_bearing,
                "bearing_residual_deg": bearing_residual,
                "consistent": consistent,
            })
        mean_penalty = sum(penalties) / len(penalties)
        ranked.append({
            "name": name,
            "latitude": lat,
            "longitude": lon,
            "rank": max(0, round(100 - mean_penalty)),
            "consistent_across_all_observations": all_consistent,
            "mean_elevation_residual_deg": sum(
                fit["elevation_residual_deg"] for fit in fits
            ) / len(fits),
            "observations": fits,
            "caveat": (
                "assumes a vertical object and locally level ground; verify height, true north, "
                "camera orientation, terrain horizon, and timestamp independently"
            ),
        })
    ranked.sort(key=lambda row: (
        not row["consistent_across_all_observations"],
        -row["rank"],
        row["mean_elevation_residual_deg"],
        row["name"],
    ))
    return _human_report(
        "shadow_length_candidate_ranking",
        observation_count=len(obs),
        candidates=ranked,
    )


# ---------------------------------------------------------------------------
# Terrain horizon and landmark/skyline evidence scoring
# ---------------------------------------------------------------------------


def _profile(points: Iterable[Mapping[str, Any] | Sequence[Any]]) -> list[tuple[float, float]]:
    rows = _take_bounded(points, MAX_PROFILE_POINTS, field="horizon profile", minimum=2)
    values: dict[float, float] = {}
    for row in rows:
        if isinstance(row, Mapping):
            az, el = row.get("azimuth_deg"), row.get("elevation_deg")
        elif isinstance(row, Sequence) and not isinstance(row, (str, bytes)) and len(row) == 2:
            az, el = row
        else:
            raise ValueError("profile points must be {azimuth_deg,elevation_deg} or pairs")
        azimuth = _finite(az, field="profile azimuth") % 360.0
        elevation = _finite(el, field="profile elevation")
        if not -90 <= elevation <= 90:
            raise ValueError("profile elevation must be in -90..90 degrees")
        values[azimuth] = elevation
    if len(values) < 2:
        raise ValueError("a horizon profile needs two distinct azimuths")
    return sorted(values.items())


def _circular_interpolate(profile: Sequence[tuple[float, float]], angle: float) -> float:
    azimuths = [point[0] for point in profile]
    target = angle % 360.0
    index = bisect.bisect_right(azimuths, target)
    if index == 0:
        left_az, left_el = profile[-1][0] - 360.0, profile[-1][1]
        right_az, right_el = profile[0]
    elif index == len(profile):
        left_az, left_el = profile[-1]
        right_az, right_el = profile[0][0] + 360.0, profile[0][1]
    else:
        left_az, left_el = profile[index - 1]
        right_az, right_el = profile[index]
    if right_az == left_az:
        return left_el
    fraction = (target - left_az) / (right_az - left_az)
    return left_el + fraction * (right_el - left_el)


def rank_terrain_horizons(
    observed_profile: Iterable[Mapping[str, Any] | Sequence[Any]],
    candidate_profiles: Mapping[str, Iterable[Mapping[str, Any] | Sequence[Any]]],
    *,
    north_offset_hypotheses_deg: Iterable[float] = (0.0,),
    tolerance_deg: float = 3.0,
) -> dict[str, Any]:
    """Compare a measured terrain/skyline elevation profile with supplied profiles.

    The optional offsets are explicit orientation hypotheses: the function does
    not silently assume camera-up is north and does not crawl a terrain service.
    """
    observed = _profile(observed_profile)
    if not isinstance(candidate_profiles, Mapping) or not 1 <= len(candidate_profiles) <= MAX_CANDIDATES:
        raise ValueError(f"give 1..{MAX_CANDIDATES} named candidate profiles")
    offsets = [_finite(value, field="north offset") % 360.0 for value in _take_bounded(
        north_offset_hypotheses_deg, 360, field="north-offset hypotheses", minimum=1
    )]
    tolerance = _finite(tolerance_deg, field="terrain tolerance")
    if not 0 < tolerance <= 30:
        raise ValueError("terrain tolerance must be in 0..30 degrees")

    rows: list[dict[str, Any]] = []
    for raw_name, raw_profile in candidate_profiles.items():
        name = _bounded_text(raw_name, limit=256, field="candidate name")
        candidate = _profile(raw_profile)
        best: tuple[float, float, float, list[float]] | None = None
        for offset in offsets:
            residuals = [
                abs(observed_elevation - _circular_interpolate(candidate, observed_azimuth + offset))
                for observed_azimuth, observed_elevation in observed
            ]
            rmse = math.sqrt(sum(value * value for value in residuals) / len(residuals))
            trial = (rmse, max(residuals), offset, residuals)
            if best is None or trial[:3] < best[:3]:
                best = trial
        assert best is not None
        rmse, maximum, offset, residuals = best
        rows.append({
            "name": name,
            "rank": max(0, round(100 - rmse / tolerance * 35 - maximum / tolerance * 10)),
            "best_north_offset_deg": offset,
            "rmse_deg": rmse,
            "max_residual_deg": maximum,
            "within_tolerance_fraction": sum(value <= tolerance for value in residuals) / len(residuals),
            "sample_count": len(residuals),
        })
    rows.sort(key=lambda row: (-row["rank"], row["rmse_deg"], row["name"]))
    return _human_report(
        "terrain_horizon_ranking",
        candidates=rows,
        orientation_hypotheses_deg=offsets,
        caveat=(
            "profiles are sensitive to lens distortion, camera roll/pitch, observer altitude, "
            "weather, vegetation, and an incorrect north reference"
        ),
    )


_FEATURE_WEIGHTS = {
    "signage": 5.0,
    "landmark_names": 5.0,
    "skyline": 3.5,
    "architecture": 2.5,
    "terrain": 2.5,
    "scripts": 2.0,
    "transport": 1.5,
    "vegetation": 1.0,
    "reverse_caption": 2.5,
}


def _norm_phrase(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value)).casefold()
    text = " ".join(re.findall(r"[^\W_]+", text, re.UNICODE))
    return text[:512]


def _phrases(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        # Feature lists come from untrusted captions/provider JSON.  Truncation is
        # intentional here: it limits output without turning surplus hints into an
        # exception after a guarded network request has already completed.
        values = list(itertools.islice(iter(value), 128))
    else:
        raise ValueError("feature sets must be strings or bounded iterables")
    return {phrase for phrase in (_norm_phrase(item) for item in values) if phrase}


def _token_overlap(left: str, right: str) -> float:
    a, b = set(left.split()), set(right.split())
    return len(a & b) / max(1, len(a | b))


def _feature_similarity(observed: set[str], candidate: set[str]) -> tuple[float, list[str]]:
    if not observed:
        return 0.0, []
    matched: list[str] = []
    total = 0.0
    for clue in sorted(observed):
        best = max((1.0 if clue == option else _token_overlap(clue, option)
                    for option in candidate), default=0.0)
        total += best
        if best >= 0.5:
            matched.append(clue)
    return total / len(observed), matched


def _coordinate(value: object) -> tuple[float, float] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        lat, lon = value.get("lat", value.get("latitude")), value.get("lon", value.get("longitude"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 2:
        lat, lon = value
    else:
        raise ValueError("coordinate must be a lat/lon mapping or pair")
    geo_math.distance_bearing(lat, lon, lat, lon)
    return float(lat), float(lon)


def rank_landmark_candidates(
    observed: Mapping[str, Any],
    candidates: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Rank supplied landmarks using signage, skyline, terrain, and coordinate evidence."""
    if not isinstance(observed, Mapping):
        raise ValueError("observed landmark evidence must be a mapping")
    rows = _take_bounded(candidates, MAX_CANDIDATES,
                         field="supplied landmarks", minimum=1)
    observed_features = {key: _phrases(observed.get(key)) for key in _FEATURE_WEIGHTS}
    observed_coordinate = _coordinate(observed.get("coordinate"))
    if not any(observed_features.values()) and observed_coordinate is None:
        raise ValueError("give at least one observed landmark feature or coordinate")

    ranked: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, Mapping):
            raise ValueError("landmark candidates must be mappings")
        name = _bounded_text(item.get("name", ""), limit=256, field="landmark name")
        aliases = _phrases(item.get("aliases")) | {_norm_phrase(name)}
        candidate_features = {key: _phrases(item.get(key)) for key in _FEATURE_WEIGHTS}
        candidate_features["landmark_names"] |= aliases
        weighted_score = 0.0
        possible = 0.0
        matched: dict[str, list[str]] = {}
        for key, weight in _FEATURE_WEIGHTS.items():
            if not observed_features[key]:
                continue
            similarity, hits = _feature_similarity(observed_features[key], candidate_features[key])
            possible += weight
            weighted_score += weight * similarity
            if hits:
                matched[key] = hits
        distance = None
        coordinate_score = 0.0
        candidate_coordinate = _coordinate(item.get("coordinate"))
        if observed_coordinate is not None and candidate_coordinate is not None:
            distance = geo_math.distance_bearing(*observed_coordinate, *candidate_coordinate)["distance_m"]
            possible += 5.0
            if distance <= 100:
                coordinate_score = 5.0
            elif distance <= 1_000:
                coordinate_score = 4.0
            elif distance <= 10_000:
                coordinate_score = 2.0
            elif distance <= 50_000:
                coordinate_score = 0.5
            weighted_score += coordinate_score
        score = 100.0 * weighted_score / possible if possible else 0.0
        ranked.append({
            "name": name,
            "rank": round(score),
            "matched_evidence": matched,
            "coordinate_distance_m": distance,
            "coordinate_score": coordinate_score,
            "evidence_coverage": weighted_score / possible if possible else 0.0,
        })
    ranked.sort(key=lambda row: (-row["rank"], row["coordinate_distance_m"] is None,
                                 row["coordinate_distance_m"] or math.inf, row["name"]))
    return _human_report(
        "landmark_candidate_ranking",
        candidates=ranked,
        caveat="a high feature overlap is a search lead, not proof that two scenes are the same place",
    )


# ---------------------------------------------------------------------------
# Manual reverse-image orchestration: metadata only, never an upload
# ---------------------------------------------------------------------------


def build_reverse_image_manifest(
    image_bytes: bytes,
    *,
    source_name: str,
    width: int,
    height: int,
    crops: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Create deterministic review metadata for manual reverse-image searches.

    Crop entries describe rectangles only; this function neither decodes nor writes
    image pixels.  ``crop_id`` binds each rectangle to the original SHA-256 so a
    player can record which manually prepared crop was used.
    """
    if not isinstance(image_bytes, bytes) or not 1 <= len(image_bytes) <= MAX_IMAGE_BYTES:
        raise ValueError(f"image bytes must be 1..{MAX_IMAGE_BYTES} bytes")
    try:
        parsed_width = _finite(width, field="image width")
        parsed_height = _finite(height, field="image height")
        if not parsed_width.is_integer() or not parsed_height.is_integer():
            raise ValueError("image dimensions must be integers")
        width = int(parsed_width)
        height = int(parsed_height)
    except (OverflowError, TypeError) as exc:
        raise ValueError("image dimensions must be finite integers") from exc
    if not 1 <= width <= 200_000 or not 1 <= height <= 200_000:
        raise ValueError("image dimensions are outside bounded positive limits")
    raw_name = _identifier_text(source_name, limit=512, field="source name")
    if online.EMAIL_ANY_RE.search(raw_name) or online.SECRET_RE.search(raw_name):
        raise ValueError("source name must not contain an e-mail address or secret")
    name = Path(raw_name.replace("\\", "/")).name
    digest = hashlib.sha256(image_bytes).hexdigest()
    crop_rows = _take_bounded(crops, 32, field="manual crop descriptors")
    descriptors: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int, int]] = set()
    for index, crop in enumerate(crop_rows):
        if not isinstance(crop, Mapping):
            raise ValueError("crop descriptors must be mappings")
        box = crop.get("box")
        if not isinstance(box, Sequence) or isinstance(box, (str, bytes)) or len(box) != 4:
            raise ValueError("crop box must be [left, top, right, bottom]")
        coords_list: list[int] = []
        for value in box:
            number = _finite(value, field="crop coordinate")
            if not number.is_integer():
                raise ValueError("crop coordinates must be integers")
            coords_list.append(int(number))
        left, top, right, bottom = coords_list
        if not (0 <= left < right <= width and 0 <= top < bottom <= height):
            raise ValueError("crop box lies outside the declared image dimensions")
        coords = (left, top, right, bottom)
        if coords in seen:
            continue
        seen.add(coords)
        reason = _bounded_text(crop.get("reason", "distinctive visual clue"),
                               limit=300, field="crop reason")
        bound = f"{digest}:{left},{top},{right},{bottom}".encode("ascii")
        descriptors.append({
            "crop_id": hashlib.sha256(bound).hexdigest()[:20],
            "box": [left, top, right, bottom],
            "reason": reason,
            "pixel_bytes_in_manifest": False,
        })
    return {
        "kind": "manual_reverse_image_manifest",
        "source_name": name,
        "sha256": digest,
        "size_bytes": len(image_bytes),
        "width": width,
        "height": height,
        "crops": descriptors,
        "automatic_upload": False,
        "image_bytes_in_manifest": False,
        "instructions": (
            "after privacy review, the player may manually upload at most the chosen image/crop; "
            "bring captions and cited public result URLs back as evidence"
        ),
        "requires_human_pin": True,
        "automatic_answer": None,
    }


def _canonical_public_host(value: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    raw = unicodedata.normalize("NFKC", value).rstrip(".").casefold()
    try:
        address = ipaddress.ip_address(raw.strip("[]"))
    except ValueError:
        address = None
    if address is not None:
        return str(address), address
    try:
        canonical = raw.encode("idna").decode("ascii").casefold()
        canonical = online._domain(canonical)
    except (UnicodeError, online.OSINTGuardError) as exc:
        raise ValueError("reference URL has an invalid public hostname") from exc
    return canonical, None


def _contains_blocked_target(value: str, extra: Iterable[str] = ()) -> bool:
    text = unicodedata.normalize("NFKC", value).casefold()
    for _ in range(2):
        text = urllib.parse.unquote(text)
    text = text.replace("。", ".").replace("．", ".").replace("｡", ".")
    suffixes = list(online.BLOCKED_SUFFIXES) + [
        str(item).casefold().rstrip(".") for item in itertools.islice(iter(extra), 64)
    ]
    for suffix in suffixes:
        if not suffix:
            continue
        # Conservative by design: also reject a blocked hostname embedded in a
        # redirect parameter or deceptive super-domain such as ctf.example.evil.
        pattern = rf"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*{re.escape(suffix)}(?=$|[^a-z0-9-])"
        if re.search(pattern, text):
            return True
    return False


def _contains_nonpublic_ip(value: str) -> bool:
    text = value.casefold()
    tokens = re.findall(r"(?<![0-9a-f:.])(?:[0-9a-f:.]{2,})(?![0-9a-f:.])", text)
    for token in tokens:
        try:
            address = ipaddress.ip_address(token.strip("[]"))
        except ValueError:
            continue
        if not address.is_global:
            return True
    if re.search(r"(?<!\d)(?:10|127)(?:\.\d{1,3}){1,3}(?!\d)", text):
        return True
    if re.search(r"(?<!\d)(?:169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){1,2}(?!\d)", text):
        return True
    for raw in re.findall(r"(?<![a-z0-9])(?:0x[0-9a-f]{1,8}|\d{7,10})(?![a-z0-9])", text):
        try:
            integer = int(raw, 0)
            if 0 <= integer <= 0xFFFFFFFF and not ipaddress.IPv4Address(integer).is_global:
                return True
        except ValueError:
            continue
    return False


def _safe_reference_url(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = _identifier_text(value, limit=2048, field="reference URL")
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("manual evidence URL is malformed") from exc
    if (parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or port not in (None, 80, 443)):
        raise ValueError("manual evidence URL must be a plain HTTP(S) public reference")
    host, address = _canonical_public_host(parsed.hostname)
    if (_contains_blocked_target(text) or online._is_blocked_name(host)
            or host in {"localhost", "localhost.localdomain"}):
        raise ValueError("CTF/local infrastructure is forbidden in manual evidence URLs")
    if address is not None and not address.is_global:
        raise ValueError("private/reserved evidence URL is forbidden")
    forbidden = {"token", "key", "api_key", "apikey", "secret", "password", "auth", "session"}
    decoded = urllib.parse.unquote(urllib.parse.unquote(text))
    if (any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in decoded)
            or re.search(r"(?<![a-z0-9.-])localhost(?:\.localdomain)?(?![a-z0-9.-])", decoded.casefold())
            or _contains_nonpublic_ip(decoded)):
        raise ValueError("local/private or control-smuggled evidence URL is forbidden")
    if (any(key.casefold() in forbidden for key, _ in urllib.parse.parse_qsl(parsed.query))
            or online.SECRET_RE.search(decoded) or online.EMAIL_ANY_RE.search(decoded)):
        raise ValueError("credential-shaped query parameters are forbidden in evidence URLs")
    netloc = f"[{host}]" if address is not None and address.version == 6 else host
    if port is not None:
        netloc += f":{port}"
    return urllib.parse.urlunsplit((parsed.scheme.casefold(), netloc, parsed.path,
                                   parsed.query, parsed.fragment))


def ingest_manual_reverse_image_results(
    manifest: Mapping[str, Any],
    results: Iterable[Mapping[str, Any]],
    *,
    observed: Mapping[str, Any],
    landmark_candidates: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Fuse captions from player-run reverse-image searches with local clues."""
    if (manifest.get("automatic_upload") is not False
            or manifest.get("image_bytes_in_manifest") is not False
            or not re.fullmatch(
        r"[0-9a-f]{64}", str(manifest.get("sha256", ""))
    )):
        raise ValueError("a valid non-uploading reverse-image manifest is required")
    manual = _take_bounded(results, MAX_MANUAL_RESULTS,
                           field="manual result rows", minimum=1)
    landmarks = _take_bounded(landmark_candidates, MAX_CANDIDATES,
                              field="landmark candidates", minimum=1)
    try:
        raw_manifest_width = _finite(manifest["width"], field="manifest width")
        raw_manifest_height = _finite(manifest["height"], field="manifest height")
        if not raw_manifest_width.is_integer() or not raw_manifest_height.is_integer():
            raise ValueError("manifest dimensions must be integers")
        manifest_width = int(raw_manifest_width)
        manifest_height = int(raw_manifest_height)
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("manifest dimensions are missing or invalid") from exc
    if not 1 <= manifest_width <= 200_000 or not 1 <= manifest_height <= 200_000:
        raise ValueError("manifest dimensions are outside bounded positive limits")
    manifest_crops = _take_bounded(manifest.get("crops", ()), 32,
                                   field="manifest crop descriptors")
    valid_crop_ids: set[str] = set()
    for crop in manifest_crops:
        if not isinstance(crop, Mapping):
            raise ValueError("manifest crop descriptors must be mappings")
        box = crop.get("box")
        if not isinstance(box, Sequence) or isinstance(box, (str, bytes)) or len(box) != 4:
            raise ValueError("manifest crop box is invalid")
        try:
            left, top, right, bottom = (int(value) for value in box)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("manifest crop box is invalid") from exc
        if not (0 <= left < right <= manifest_width and 0 <= top < bottom <= manifest_height):
            raise ValueError("manifest crop box lies outside its dimensions")
        expected = hashlib.sha256(
            f"{manifest['sha256']}:{left},{top},{right},{bottom}".encode("ascii")
        ).hexdigest()[:20]
        if crop.get("crop_id") != expected:
            raise ValueError("manifest crop_id does not match image hash and box")
        valid_crop_ids.add(expected)
    sanitized: list[dict[str, Any]] = []
    providers_by_candidate: dict[str, set[str]] = defaultdict(set)
    captions: list[str] = []
    named: list[str] = []
    for item in manual:
        if not isinstance(item, Mapping):
            raise ValueError("manual results must be mappings")
        provider = _identifier_text(item.get("provider", ""), limit=128, field="provider")
        caption = _bounded_text(item.get("caption", ""), limit=1000, field="caption")
        candidate = ("" if not item.get("candidate") else
                     _bounded_text(item["candidate"], limit=256, field="candidate"))
        reference = _safe_reference_url(item.get("source_url"))
        crop_id = (None if not item.get("crop_id") else
                   _identifier_text(item["crop_id"], limit=64, field="crop_id"))
        if crop_id is not None and crop_id not in valid_crop_ids:
            raise ValueError("manual result references an unknown crop_id")
        normalized_candidate = _norm_phrase(candidate) if candidate else ""
        if normalized_candidate:
            providers_by_candidate[normalized_candidate].add(provider.casefold())
            named.append(candidate)
        captions.append(caption)
        sanitized.append({
            "provider": provider,
            "caption": caption,
            "candidate": candidate or None,
            "source_url": reference,
            "crop_id": crop_id,
            "status": "unverified_manual_observation",
        })
    if not isinstance(observed, Mapping):
        raise ValueError("observed reverse-image evidence must be a mapping")
    combined = {key: observed.get(key) for key in (*_FEATURE_WEIGHTS, "coordinate")}
    combined["reverse_caption"] = list(_phrases(combined.get("reverse_caption"))) + captions
    combined["landmark_names"] = list(_phrases(combined.get("landmark_names"))) + named
    ranking = rank_landmark_candidates(combined, landmarks)
    for candidate in ranking["candidates"]:
        keys = {_norm_phrase(candidate["name"])}
        source = next((row for row in landmarks
                       if _norm_phrase(row.get("name", "")) == _norm_phrase(candidate["name"])), None)
        if source:
            keys |= _phrases(source.get("aliases"))
        provider_support = set().union(*(providers_by_candidate.get(key, set()) for key in keys))
        candidate["manual_provider_support"] = sorted(provider_support)
        candidate["manual_provider_count"] = len(provider_support)
        candidate["rank"] = min(100, candidate["rank"] + min(12, len(provider_support) * 4))
    ranking["candidates"].sort(key=lambda row: (-row["rank"], -row["manual_provider_count"], row["name"]))
    return _human_report(
        "manual_reverse_image_evidence",
        image_sha256=manifest["sha256"],
        automatic_upload=False,
        results=sanitized,
        candidates=ranking["candidates"],
        caveat="provider captions can copy one another; corroborate with signage, geometry, and maps",
    )


# ---------------------------------------------------------------------------
# Existing-adapter evidence fusion: domain, handle, and GPS provenance
# ---------------------------------------------------------------------------


def _evidence_dict(row: object, *, budget: list[int] | None = None) -> dict[str, Any]:
    if dataclasses.is_dataclass(row):
        data = {field.name: getattr(row, field.name) for field in dataclasses.fields(row)}
    elif isinstance(row, Mapping):
        data = row
    else:
        raise ValueError("evidence rows must be mappings or dataclass values")
    provider = _identifier_text(data.get("provider", "unknown"), limit=128, field="provider")
    kind = _identifier_text(data.get("kind", "observation"), limit=128, field="evidence kind")
    raw_source = data.get("source_url")
    source = _safe_reference_url(raw_source) if raw_source not in (None, "") else None
    note = str(data.get("note", ""))[:1000]
    return {
        "provider": provider,
        "kind": kind,
        "value": _bounded_json_value(data.get("value"), budget=budget),
        "source_url": source,
        "note": note,
    }


def _provider_family(provider: str, kind: str) -> str:
    text = f"{provider} {kind}".casefold()
    if "rdap" in text or "whois" in text:
        return "rdap"
    if "certificate" in text or "crt.sh" in text:
        return "ct"
    if "dns" in text:
        return "dns"
    if "wayback" in text or "archive" in text or kind.casefold() == "capture":
        return "wayback"
    return re.sub(r"[^a-z0-9]+", "_", provider.casefold()).strip("_") or "other"


def _same_domain(host: str, domain: str) -> bool:
    host = host.rstrip(".").casefold()
    return host == domain or host.endswith("." + domain)


def _host_from_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip().strip('"').rstrip(".")
    try:
        return online._domain(raw)  # reuse canonical IDNA/domain validation
    except online.OSINTGuardError:
        return None


def build_domain_evidence_graph(domain: str, evidence_rows: Iterable[object]) -> dict[str, Any]:
    """Correlate existing RDAP/DNS/CT/Wayback observations without fetching."""
    canonical = online._domain(domain)
    if online._is_blocked_name(canonical):
        raise ValueError("CSCTF/Chronos infrastructure is forbidden even as an online pivot")
    raw_rows = _take_bounded(evidence_rows, MAX_EVIDENCE_ROWS,
                             field="bounded evidence rows", minimum=1)
    root = f"domain:{canonical}"
    nodes: dict[str, dict[str, Any]] = {
        root: {"id": root, "type": "domain", "value": canonical, "providers": []}
    }
    edges: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    chronology: list[dict[str, str]] = []

    def add_node(node_type: str, value: str, family: str, relation: str, source: str | None) -> None:
        if len(nodes) >= 1024:
            return
        node_id = f"{node_type}:{value}"
        node = nodes.setdefault(node_id, {
            "id": node_id, "type": node_type, "value": value, "providers": []
        })
        if family not in node["providers"]:
            node["providers"].append(family)
            node["providers"].sort()
        edge = {"from": root, "to": node_id, "relation": relation, "provider": family}
        if source:
            edge["source_url"] = source
        if edge not in edges:
            edges.append(edge)

    value_budget = [MAX_JSON_NODES]
    for raw in raw_rows:
        row = _evidence_dict(raw, budget=value_budget)
        family = _provider_family(row["provider"], row["kind"])
        value = row["value"]
        source = row["source_url"]
        if family == "wayback" and isinstance(value, Mapping):
            original = str(value.get("original", ""))[:2048]
            try:
                parsed = urllib.parse.urlsplit(original)
                valid_web_url = (parsed.scheme.casefold() in {"http", "https"}
                                 and parsed.hostname is not None
                                 and parsed.username is None and parsed.password is None
                                 and parsed.port in (None, 80, 443))
                host = _canonical_public_host(parsed.hostname)[0] if valid_web_url else ""
            except ValueError:
                host = ""
            if host and not online._is_blocked_name(host) and _same_domain(host, canonical):
                add_node("host", host, family, "archived_host", source)
                timestamp = str(value.get("timestamp", ""))
                if re.fullmatch(r"\d{14}", timestamp):
                    chronology.append({"provider": family, "event": "capture", "timestamp": timestamp})
            elif host:
                ignored.append({"provider": family, "reason": "out_of_domain_host", "value": host})
            else:
                ignored.append({"provider": family, "reason": "invalid_archive_url", "value": original[:512]})
            continue
        host = _host_from_value(value)
        if host is not None:
            if online._is_blocked_name(host):
                ignored.append({"provider": family, "reason": "blocked_ctf_host", "value": host})
            elif _same_domain(host, canonical):
                add_node("host", host, family, row["kind"], source)
            elif row["kind"].casefold() in {"nameserver", "mx", "cname", "ns"}:
                add_node("related_host", host, family, row["kind"], source)
            else:
                ignored.append({"provider": family, "reason": "out_of_domain_host", "value": host})
            continue
        if isinstance(value, str):
            compact = value.strip().strip('"')
            try:
                address = ipaddress.ip_address(compact)
            except ValueError:
                address = None
            if address is not None and address.is_global:
                add_node("ip", str(address), family, row["kind"], source)
            elif re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T[^ ]+)?", compact):
                chronology.append({"provider": family, "event": row["kind"], "timestamp": compact[:64]})
            elif compact and len(compact) <= 512:
                add_node("attribute", compact, family, row["kind"], source)
    correlations = [
        {"node": node["id"], "providers": node["providers"], "provider_count": len(node["providers"])}
        for node in nodes.values() if len(node["providers"]) >= 2
    ]
    correlations.sort(key=lambda row: (-row["provider_count"], row["node"]))
    chronology.sort(key=lambda row: row["timestamp"])
    return _human_report(
        "domain_evidence_graph",
        domain=canonical,
        nodes=sorted(nodes.values(), key=lambda row: row["id"]),
        edges=edges[:2048],
        correlations=correlations,
        chronology=chronology[:512],
        ignored=ignored[:128],
        exact_same_domain_pivots=sorted(
            node["value"] for node in nodes.values()
            if node["type"] == "host" and _same_domain(node["value"], canonical)
        )[:128],
    )


_HANDLE_KEYS = {"login", "username", "user_name", "screen_name", "name"}


def _canonical_handle(value: object) -> str:
    raw = _identifier_text(value, limit=129, field="handle")
    if raw.startswith("@@"):
        raise ValueError("handle may have at most one leading @")
    handle = raw[1:] if raw.startswith("@") else raw
    if "@" in handle or not online.USERNAME_RE.fullmatch(handle):
        raise ValueError("invalid exact public handle")
    return handle


def _find_handle_records(value: object, *, depth: int = 0,
                         budget: list[int] | None = None) -> list[tuple[str, str]]:
    if budget is None:
        budget = [512]
    if depth > 5 or budget[0] <= 0:
        return []
    found: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, item in itertools.islice(value.items(), 128):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            key_text = str(key).casefold()
            if key_text in _HANDLE_KEYS and isinstance(item, (str, int)):
                found.append((key_text, str(item)))
            elif isinstance(item, (Mapping, list, tuple)):
                found.extend(_find_handle_records(item, depth=depth + 1, budget=budget))
    elif isinstance(value, (list, tuple)):
        for item in itertools.islice(iter(value), 128):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            found.extend(_find_handle_records(item, depth=depth + 1, budget=budget))
    return found[:512]


def _profile_attributes(value: object) -> dict[str, set[str]]:
    wanted = {"display_name", "name", "location", "website", "blog", "bio", "created_at"}
    out: dict[str, set[str]] = defaultdict(set)

    budget = [256]

    def walk(item: object, depth: int = 0) -> None:
        if depth > 4 or budget[0] <= 0:
            return
        if isinstance(item, Mapping):
            for key, child in itertools.islice(item.items(), 128):
                if budget[0] <= 0:
                    break
                budget[0] -= 1
                folded = str(key).casefold()
                if folded in wanted and isinstance(child, (str, int, float)) and str(child).strip():
                    out[folded].add(str(child).strip()[:256])
                elif isinstance(child, (Mapping, list, tuple)):
                    walk(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in itertools.islice(iter(item), 128):
                if budget[0] <= 0:
                    break
                budget[0] -= 1
                walk(child, depth + 1)

    walk(value)
    return out


def fuse_exact_handle_evidence(handle: str, evidence_rows: Iterable[object]) -> dict[str, Any]:
    """Fuse exact-handle profile observations without declaring common ownership."""
    exact = _canonical_handle(handle)
    rows = _take_bounded(evidence_rows, MAX_EVIDENCE_ROWS,
                         field="handle evidence rows", minimum=1)
    observations: list[dict[str, Any]] = []
    absences: list[str] = []
    attribute_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    value_budget = [MAX_JSON_NODES]
    for raw in rows:
        row = _evidence_dict(raw, budget=value_budget)
        provider = row["provider"]
        if row["kind"] == "profile_absence":
            absent_handles = _find_handle_records(row["value"])
            if any(key != "name" and value.casefold().lstrip("@") == exact.casefold()
                   for key, value in absent_handles):
                absences.append(provider)
            continue
        handles = _find_handle_records(row["value"])
        exact_keys = sorted({
            key for key, value in handles
            if value.casefold().lstrip("@") == exact.casefold()
            and (key != "name" or "reddit" in provider.casefold())
        })
        if not exact_keys:
            continue
        attrs = _profile_attributes(row["value"])
        serial_attrs = {key: sorted(values) for key, values in attrs.items()}
        for key, values in attrs.items():
            for value in values:
                attribute_sources[(key, _norm_phrase(value))].add(provider.casefold())
        observations.append({
            "provider": provider,
            "exact_handle_fields": exact_keys,
            "attributes": serial_attrs,
            "source_url": row["source_url"],
        })
    shared = [
        {"field": field, "normalized_value": value, "providers": sorted(providers)}
        for (field, value), providers in attribute_sources.items() if value and len(providers) >= 2
    ]
    shared.sort(key=lambda item: (-len(item["providers"]), item["field"], item["normalized_value"]))
    return _human_report(
        "exact_handle_evidence_fusion",
        handle=exact,
        exact_provider_count=len({item["provider"].casefold() for item in observations}),
        observations=observations[:64],
        point_in_time_absences=sorted(set(absences)),
        shared_attributes=shared[:512],
        identity_verdict=None,
        caveat="the same public handle on multiple services does not by itself prove common ownership",
    )


_GPS_SOURCE_WEIGHT = {
    "exif_gps": 100,
    "xmp_gps": 90,
    "container_iso6709": 85,
    "gpx": 80,
    "kml": 80,
    "reverse_geocode": 60,
    "ocr_coordinate": 45,
    "manual": 40,
}


def score_gps_provenance(
    records: Iterable[Mapping[str, Any]], *, conflict_distance_m: float = 100.0
) -> dict[str, Any]:
    """Cluster coordinates from EXIF/XMP/container/OCR sources and expose conflicts."""
    rows = _take_bounded(records, MAX_EVIDENCE_ROWS,
                         field="GPS provenance rows", minimum=1)
    threshold = _finite(conflict_distance_m, field="GPS conflict distance")
    if not 0 < threshold <= 1_000_000:
        raise ValueError("GPS conflict distance is outside useful bounds")
    parsed: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError("GPS provenance rows must be mappings")
        coordinate = _coordinate(row)
        assert coordinate is not None
        source = _bounded_text(row.get("source", "manual"), limit=128,
                               field="GPS source").casefold().replace("-", "_")
        weight = _finite(row.get("weight", _GPS_SOURCE_WEIGHT.get(source, 35)),
                         field="GPS source weight")
        if not weight.is_integer() or not 0 <= weight <= 100:
            raise ValueError("GPS source weight must be an integer in 0..100")
        reference = (None if not row.get("reference") else
                     _bounded_text(row["reference"], limit=512, field="GPS reference"))
        parsed.append({
            "index": index,
            "source": source,
            "latitude": coordinate[0],
            "longitude": coordinate[1],
            "weight": int(weight),
            "reference": reference,
            "polarity_attested": bool(row.get("polarity_attested", False)),
        })
    distances: dict[tuple[int, int], float] = {}
    for left in range(len(parsed)):
        for right in range(left + 1, len(parsed)):
            distance = geo_math.distance_bearing(
                parsed[left]["latitude"], parsed[left]["longitude"],
                parsed[right]["latitude"], parsed[right]["longitude"],
            )["distance_m"]
            distances[(left, right)] = distance
    # Complete-link clusters prevent transitive chains (A near B, B near C, but
    # A far from C) from hiding a real provenance conflict.
    groups: list[list[int]] = []
    ordering = sorted(range(len(parsed)), key=lambda index: (-parsed[index]["weight"], index))
    for index in ordering:
        matching = []
        for group_index, members in enumerate(groups):
            if all(distances[tuple(sorted((index, other)))] <= threshold
                   for other in members if other != index):
                matching.append(group_index)
        if matching:
            groups[matching[0]].append(index)
        else:
            groups.append([index])
    clusters: list[dict[str, Any]] = []
    for members in groups:
        # Pick the weighted medoid: an actually observed coordinate, never an invented midpoint.
        def medoid_cost(candidate: int) -> float:
            total = 0.0
            for other in members:
                if candidate == other:
                    continue
                key = tuple(sorted((candidate, other)))
                total += distances[key] * parsed[other]["weight"]
            return total

        medoid = min(members, key=lambda index: (medoid_cost(index), index))
        sources = sorted({parsed[index]["source"] for index in members})
        total_weight = sum(max(0, parsed[index]["weight"]) for index in members)
        clusters.append({
            "rank": min(100, total_weight),
            "latitude": parsed[medoid]["latitude"],
            "longitude": parsed[medoid]["longitude"],
            "sources": sources,
            "record_count": len(members),
            "records": [parsed[index] for index in members],
            "coordinate_is_observed_medoid": True,
        })
    clusters.sort(key=lambda row: (-row["rank"], -row["record_count"], row["latitude"], row["longitude"]))
    return _human_report(
        "gps_provenance_conflict_report",
        conflict=len(clusters) > 1,
        conflict_distance_m=threshold,
        candidates=clusters,
        caveat="embedded coordinates can be stale, edited, or refer to the asset rather than the camera position",
    )


# ---------------------------------------------------------------------------
# Guarded one-lead online orchestration through the existing client
# ---------------------------------------------------------------------------


_DOMAIN_PROVIDERS = ("rdap", "dns", "ct", "wayback")
_PROFILE_PROVIDERS = ("github", "gitlab", "reddit", "keybase")
_DNS_TYPES = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV"}


def _serialize_evidence(rows: Iterable[object]) -> list[dict[str, Any]]:
    bounded = _take_bounded(rows, MAX_EVIDENCE_ROWS, field="serialized evidence rows")
    budget = [MAX_JSON_NODES]
    return [_evidence_dict(row, budget=budget) for row in bounded]


def _exact_public_search_lead(value: str) -> str:
    lead = _identifier_text(value, limit=256, field="public-search lead")
    if online.EMAIL_ANY_RE.search(lead):
        raise online.OSINTGuardError("raw e-mail is forbidden for public record/breach/paste search")
    if _contains_blocked_target(lead):
        raise online.OSINTGuardError("CSCTF/Chronos infrastructure is forbidden")
    if "://" in lead:
        raise online.OSINTGuardError("public record/breach/paste lead must be an identifier, not a URL")
    if any(symbol in lead for symbol in ('"', "*", "?", "|", "{", "}", "\n", "\r")) or re.search(
        r"(?:^|\s)(?:site|inurl|intitle|filetype):|\b(?:OR|AND)\b", lead
    ):
        raise online.OSINTGuardError("search operators and variant/sweep queries are forbidden")
    if _contains_nonpublic_ip(lead):
        raise online.OSINTGuardError("private/reserved IP lookups are forbidden")
    return lead


class GuardedOSINTOrchestrator:
    """One reviewed lead, sequential public sources, existing guards unchanged."""

    def __init__(self, client: online.PublicOSINTClient) -> None:
        if not isinstance(client, online.PublicOSINTClient):
            raise TypeError("client must be PublicOSINTClient")
        self.client = client

    def investigate(
        self,
        kind: str,
        value: str,
        *,
        providers: Iterable[str] | None = None,
        record_type: str = "A",
    ) -> dict[str, Any]:
        normalized = str(kind).strip().casefold().replace("-", "_")
        if normalized == "domain":
            return self.domain(value, providers=providers, record_type=record_type)
        if normalized in {"handle", "username"}:
            return self.handle(value, providers=providers)
        if normalized in {"public_record", "record", "paste", "breach"}:
            return self.public_search(normalized, value)
        raise ValueError("kind must be domain, handle, public_record, paste, or breach")

    def domain(
        self,
        value: str,
        *,
        providers: Iterable[str] | None = None,
        record_type: str = "A",
    ) -> dict[str, Any]:
        domain = online._domain(value)
        selected = [
            _identifier_text(provider, limit=32, field="domain provider").casefold()
            for provider in _take_bounded(
                providers if providers is not None else _DOMAIN_PROVIDERS,
                len(_DOMAIN_PROVIDERS), field="domain providers", minimum=1
            )
        ]
        if len(set(selected)) != len(selected):
            raise online.OSINTGuardError("choose one to four distinct domain providers")
        if any(provider not in _DOMAIN_PROVIDERS for provider in selected):
            raise online.OSINTGuardError("unsupported domain provider")
        record_type = _identifier_text(record_type, limit=16, field="DNS record type").upper()
        if "dns" in selected and record_type not in _DNS_TYPES:
            raise online.OSINTGuardError("unsupported DNS record type")
        # Bind only after every local option has validated.  Provider methods
        # repeat the same guard at their final transport boundary.
        self.client._guard_value("domain", domain)
        evidence: list[object] = []
        for provider in selected:
            if provider == "rdap":
                evidence.extend(self.client.rdap(domain))
            elif provider == "dns":
                evidence.extend(self.client.dns(domain, record_type))
            elif provider == "ct":
                evidence.extend(self.client.certificate_transparency(domain))
            else:
                evidence.extend(self.client.wayback(domain))
        serialized = _serialize_evidence(evidence)
        graph = build_domain_evidence_graph(domain, serialized) if serialized else None
        return _human_report(
            "guarded_domain_investigation",
            lead=domain,
            providers=selected,
            requests=self.client.request_count,
            evidence=serialized,
            correlation=graph,
        )

    def handle(self, value: str, *, providers: Iterable[str] | None = None) -> dict[str, Any]:
        try:
            handle = _canonical_handle(value)
        except ValueError as exc:
            raise online.OSINTGuardError(str(exc)) from exc
        selected = tuple(
            _identifier_text(provider, limit=32, field="profile provider").casefold()
            for provider in _take_bounded(
                providers if providers is not None else ("github", "gitlab", "reddit"),
                3, field="profile providers", minimum=1
            )
        )
        if len(set(selected)) != len(selected):
            raise online.OSINTGuardError("choose one to three distinct exact-profile providers")
        if any(provider not in _PROFILE_PROVIDERS for provider in selected):
            raise online.OSINTGuardError("unsupported exact-profile provider")
        self.client._guard_value("username", handle)
        evidence = _serialize_evidence(self.client.username(handle, selected))
        fusion = fuse_exact_handle_evidence(handle, evidence) if evidence else None
        return _human_report(
            "guarded_exact_handle_investigation",
            lead=handle,
            providers=list(selected),
            requests=self.client.request_count,
            evidence=evidence,
            fusion=fusion,
        )

    def public_search(self, kind: str, value: str) -> dict[str, Any]:
        if kind not in {"public_record", "record", "paste", "breach"}:
            raise ValueError("unsupported public-search evidence kind")
        lead = _exact_public_search_lead(value)
        if _contains_blocked_target(lead, self.client.blocked_targets):
            raise online.OSINTGuardError("CSCTF/Chronos or another forbidden target is out of scope")
        # search() performs this guard again at the final transport boundary.
        self.client._guard_value("search", lead)
        evidence = _serialize_evidence(self.client.search(lead))
        return _human_report(
            "guarded_exact_public_search",
            evidence_kind=kind,
            lead=lead,
            requests=self.client.request_count,
            evidence=evidence,
            warning=(
                "public indexed pages only: no breach dumps, credential APIs, raw player e-mail, "
                "paid people-search, or attribution verdict"
            ),
        )


__all__ = [
    "GuardedOSINTOrchestrator",
    "ShadowLengthObservation",
    "build_domain_evidence_graph",
    "build_reverse_image_manifest",
    "fuse_exact_handle_evidence",
    "ingest_manual_reverse_image_results",
    "rank_landmark_candidates",
    "rank_shadow_length_candidates",
    "rank_terrain_horizons",
    "score_gps_provenance",
    "shadow_elevation_deg",
]
