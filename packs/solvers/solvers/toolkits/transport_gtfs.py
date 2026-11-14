#!/usr/bin/env python3
"""Offline GTFS ZIP/CSV and GTFS-Realtime protobuf inspection.

No extraction, fetches, generated code, or execution of input. ``parse_gtfs_zip``
accepts partial feeds; it is an artifact reader, not a full GTFS validator.
``trip_itinerary`` joins IDs and applies calendar exceptions. Realtime decoding
implements the published wire schema independently; unsupported fields survive
as numbered raw values in ``_unknown``. Groups and duplicate singular fields are
rejected deliberately. No automatic DIFFERENTIAL-feed state is inferred.

Sources: https://gtfs.org/documentation/schedule/reference/ and
https://github.com/google/transit/blob/master/gtfs-realtime/proto/gtfs-realtime.proto
CLI: ./.venv/bin/python solvers/toolkits/transport_gtfs.py feed.zip --trip T1
     ./.venv/bin/python solvers/toolkits/transport_gtfs.py feed.pb --format realtime
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import functools
import io
import json
import math
from pathlib import Path
import re
import struct
import sys
import zipfile

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_ROWS = 200_000
MAX_FIELDS = 300_000
_GTFS_TABLES = frozenset((
    "agency.txt", "stops.txt", "routes.txt", "trips.txt", "stop_times.txt",
    "calendar.txt", "calendar_dates.txt", "fare_attributes.txt", "fare_rules.txt",
    "shapes.txt", "frequencies.txt", "transfers.txt", "pathways.txt", "levels.txt",
    "feed_info.txt", "translations.txt", "attributions.txt", "fare_products.txt",
    "fare_leg_rules.txt", "fare_transfer_rules.txt", "areas.txt", "stop_areas.txt",
    "networks.txt", "route_networks.txt", "location_groups.txt", "location_group_stops.txt",
    "booking_rules.txt",
))


class TransportGTFSError(ValueError):
    """Unsupported or malformed GTFS artifact (including resource limits)."""


def _guard(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TransportGTFSError:
            raise
        except Exception as exc:
            raise TransportGTFSError(f"{fn.__name__}: {type(exc).__name__}: {exc}") from None
    return wrapped


def _blob(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TransportGTFSError("input must be bytes")
    if len(data) > MAX_INPUT:
        raise TransportGTFSError("input exceeds 32 MiB limit")
    return bytes(data)


@_guard
def parse_gtfs_zip(data: bytes) -> dict:
    """Read bounded root-level UTF-8 CSV .txt members without extracting them.

    Preserves string identifiers, extra columns and text, including leading zeros.
    Rejects duplicate names/headers, ragged CSV, unsafe paths and encrypted files.
    Non-.txt files (e.g. locations.geojson) are listed as unparsed artifacts.
    """
    raw = _blob(data)
    tables, skipped, flags = {}, [], set()
    row_count = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) > 128 or sum(m.file_size for m in members) > MAX_EXPANDED:
            raise TransportGTFSError("archive member/expanded size limit")
        seen = set()
        for member in members:
            name = member.filename
            if name in seen or "/" in name or "\\" in name or name in ("", ".", ".."):
                raise TransportGTFSError("duplicate or non-root archive name")
            seen.add(name)
            if member.flag_bits & 1:
                raise TransportGTFSError("encrypted ZIP member")
            if not name.endswith(".txt"):
                skipped.append(name)
                continue
            if member.file_size > MAX_INPUT:
                raise TransportGTFSError("CSV member exceeds limit")
            text = archive.read(member).decode("utf-8-sig")
            if "\x00" in text:
                raise TransportGTFSError("NUL in CSV")
            flags.update(flagfmt.TEXT.findall(text))
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            headers = next(reader, None)
            if not headers or any(not h for h in headers) or len(set(headers)) != len(headers):
                raise TransportGTFSError(f"invalid or duplicate CSV header: {name}")
            if len(headers) > 256:
                raise TransportGTFSError("too many CSV columns")
            rows = []
            for fields in reader:
                if not fields:
                    continue
                if len(fields) != len(headers):
                    raise TransportGTFSError(f"ragged CSV row: {name}")
                row_count += 1
                if row_count > MAX_ROWS:
                    raise TransportGTFSError("CSV row limit")
                rows.append(dict(zip(headers, fields)))
            tables[name] = rows
    if not _GTFS_TABLES.intersection(tables):
        raise TransportGTFSError("no GTFS CSV tables")
    return {"format": "gtfs", "tables": tables, "unparsed_files": skipped,
            "flags": sorted(flags)}


@_guard
def service_seconds(value: str) -> int:
    """GTFS service-day clock, including hours beyond 24 (no timezone inference)."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,3}:[0-5]\d:[0-5]\d", value):
        raise TransportGTFSError("expected HHH:MM:SS service-day time")
    hour, minute, second = map(int, value.split(":"))
    return hour * 3600 + minute * 60 + second


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{8}", value):
        raise TransportGTFSError("expected YYYYMMDD service date")
    return dt.datetime.strptime(value, "%Y%m%d").date()


def _index(rows, key):
    result = {}
    for row in rows:
        value = row[key]
        if not isinstance(value, str) or not value or value in result:
            raise TransportGTFSError(f"missing/duplicate {key}")
        result[value] = row
    return result


@_guard
def trip_itinerary(feed: dict, trip_id: str, service_date: str | None = None) -> dict:
    """Join a trip, route, ordered stop times/stops and optional shape/calendar.

    On service_date, ``active`` is None when no calendar evidence for that service
    exists, otherwise boolean. Calendar_dates overrides weekly calendar entries.
    Shape points are reported as coordinates, never executed or rendered remotely.
    """
    if not isinstance(feed, dict) or not isinstance(trip_id, str) or not trip_id:
        raise TransportGTFSError("expected parsed feed and nonempty trip_id")
    tables = feed["tables"]
    trip = _index(tables.get("trips.txt", []), "trip_id").get(trip_id)
    if trip is None:
        raise TransportGTFSError(f"unknown trip_id: {trip_id}")
    route = _index(tables.get("routes.txt", []), "route_id").get(trip["route_id"])
    stop_index = _index(tables.get("stops.txt", []), "stop_id")
    stops, sequences = [], set()
    for row in tables.get("stop_times.txt", []):
        if row["trip_id"] != trip_id:
            continue
        seq = _uint(row["stop_sequence"])
        if seq in sequences:
            raise TransportGTFSError("duplicate trip stop_sequence")
        sequences.add(seq)
        stop = stop_index.get(row.get("stop_id"))
        if stop is None:
            raise TransportGTFSError("missing stop_id join (flex locations unsupported)")
        item = {"stop_sequence": seq, "stop": stop, "stop_time": row}
        for field in ("arrival_time", "departure_time"):
            if row.get(field):
                item[field + "_seconds"] = service_seconds(row[field])
        stops.append(item)
    stops.sort(key=lambda row: row["stop_sequence"])
    shape = []
    shape_id = trip.get("shape_id")
    if shape_id:
        shape_sequences = set()
        for row in tables.get("shapes.txt", []):
            if row["shape_id"] != shape_id:
                continue
            seq = _uint(row["shape_pt_sequence"])
            if seq in shape_sequences:
                raise TransportGTFSError("duplicate shape_pt_sequence")
            shape_sequences.add(seq)
            lat, lon = float(row["shape_pt_lat"]), float(row["shape_pt_lon"])
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise TransportGTFSError("invalid shape coordinate")
            shape.append({"sequence": seq, "latitude": lat, "longitude": lon})
        shape.sort(key=lambda row: row["sequence"])
    active = None
    if service_date is not None:
        day, service = _date(service_date), trip["service_id"]
        cal = _index(tables.get("calendar.txt", []), "service_id").get(service)
        if cal:
            weekday = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")[day.weekday()]
            if any(cal[k] not in ("0", "1") for k in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")):
                raise TransportGTFSError("calendar weekday must be 0/1")
            start, end = _date(cal["start_date"]), _date(cal["end_date"])
            if start > end:
                raise TransportGTFSError("reversed calendar dates")
            active = start <= day <= end and cal[weekday] == "1"
        exceptions = [r for r in tables.get("calendar_dates.txt", []) if r["service_id"] == service]
        if exceptions and active is None:
            active = False
        dates = set()
        for exc in exceptions:
            exc_day = _date(exc["date"])
            if exc_day in dates or exc["exception_type"] not in ("1", "2"):
                raise TransportGTFSError("duplicate/invalid calendar exception")
            dates.add(exc_day)
            if exc_day == day:
                active = exc["exception_type"] == "1"
    return {"trip": trip, "route": route, "stops": stops, "shape": shape,
            "service_date": service_date, "active": active}


def _uint(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,10}", value):
        raise TransportGTFSError("invalid unsigned sequence")
    return int(value)


# Field number: (published name, wire value/message type). ! required; * repeated.
# Unknown experimental fields and agency extensions remain available in _unknown.
_SCHEMAS = {
    "FeedMessage": {1: ("header", "FeedHeader!"), 2: ("entity", "FeedEntity*")},
    "FeedHeader": {1: ("gtfs_realtime_version", "s!"), 2: ("incrementality", "u32"), 3: ("timestamp", "u"), 4: ("feed_version", "s")},
    "FeedEntity": {1: ("id", "s!"), 2: ("is_deleted", "b"), 3: ("trip_update", "TripUpdate"), 4: ("vehicle", "VehiclePosition"), 5: ("alert", "Alert"), 6: ("shape", "Shape")},
    "TripUpdate": {1: ("trip", "TripDescriptor!"), 2: ("stop_time_update", "StopTimeUpdate*"), 3: ("vehicle", "VehicleDescriptor"), 4: ("timestamp", "u"), 5: ("delay", "i32"), 6: ("trip_properties", "TripProperties")},
    "StopTimeEvent": {1: ("delay", "i32"), 2: ("time", "i64"), 3: ("uncertainty", "i32"), 4: ("scheduled_time", "i64")},
    "StopTimeUpdate": {1: ("stop_sequence", "u32"), 2: ("arrival", "StopTimeEvent"), 3: ("departure", "StopTimeEvent"), 4: ("stop_id", "s"), 5: ("schedule_relationship", "u32"), 6: ("stop_time_properties", "StopTimeProperties"), 7: ("departure_occupancy_status", "u32")},
    "StopTimeProperties": {1: ("assigned_stop_id", "s"), 2: ("stop_headsign", "s"), 3: ("pickup_type", "u32"), 4: ("drop_off_type", "u32")},
    "TripProperties": {1: ("trip_id", "s"), 2: ("start_date", "s"), 3: ("start_time", "s"), 4: ("shape_id", "s"), 5: ("trip_headsign", "s"), 6: ("trip_short_name", "s")},
    "TripDescriptor": {1: ("trip_id", "s"), 2: ("start_time", "s"), 3: ("start_date", "s"), 4: ("schedule_relationship", "u32"), 5: ("route_id", "s"), 6: ("direction_id", "u32"), 7: ("modified_trip", "ModifiedTripSelector")},
    "ModifiedTripSelector": {1: ("modifications_id", "s"), 2: ("affected_trip_id", "s"), 3: ("start_time", "s"), 4: ("start_date", "s")},
    "VehicleDescriptor": {1: ("id", "s"), 2: ("label", "s"), 3: ("license_plate", "s"), 4: ("wheelchair_accessible", "u32")},
    "VehiclePosition": {1: ("trip", "TripDescriptor"), 2: ("position", "Position"), 3: ("current_stop_sequence", "u32"), 4: ("current_status", "u32"), 5: ("timestamp", "u"), 6: ("congestion_level", "u32"), 7: ("stop_id", "s"), 8: ("vehicle", "VehicleDescriptor"), 9: ("occupancy_status", "u32"), 10: ("occupancy_percentage", "u32"), 11: ("multi_carriage_details", "CarriageDetails*")},
    "CarriageDetails": {1: ("id", "s"), 2: ("label", "s"), 3: ("occupancy_status", "u32"), 4: ("occupancy_percentage", "i32"), 5: ("carriage_sequence", "u32")},
    "Position": {1: ("latitude", "f!"), 2: ("longitude", "f!"), 3: ("bearing", "f"), 4: ("odometer", "d"), 5: ("speed", "f")},
    "Alert": {1: ("active_period", "TimeRange*"), 2: ("communication_period", "TimeRange*"), 3: ("impact_period", "TimeRange*"), 5: ("informed_entity", "EntitySelector*"), 6: ("cause", "u32"), 7: ("effect", "u32"), 8: ("url", "TranslatedString"), 10: ("header_text", "TranslatedString"), 11: ("description_text", "TranslatedString"), 12: ("tts_header_text", "TranslatedString"), 13: ("tts_description_text", "TranslatedString"), 14: ("severity_level", "u32"), 16: ("image_alternative_text", "TranslatedString"), 17: ("cause_detail", "TranslatedString"), 18: ("effect_detail", "TranslatedString")},
    "TimeRange": {1: ("start", "u"), 2: ("end", "u")},
    "EntitySelector": {1: ("agency_id", "s"), 2: ("route_id", "s"), 3: ("route_type", "i32"), 4: ("trip", "TripDescriptor"), 5: ("stop_id", "s"), 6: ("direction_id", "u32")},
    "TranslatedString": {1: ("translation", "Translation*")},
    "Translation": {1: ("text", "s!"), 2: ("language", "s")},
    "Shape": {1: ("shape_id", "s"), 2: ("encoded_polyline", "s")},
}


def _varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise TransportGTFSError("truncated protobuf varint")
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise TransportGTFSError("protobuf varint exceeds 64 bits")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise TransportGTFSError("unterminated protobuf varint")


def _message(data, schema_name, budget, depth=0):
    if depth > 16:
        raise TransportGTFSError("protobuf nesting limit")
    schema, result, pos = _SCHEMAS[schema_name], {}, 0
    while pos < len(data):
        budget[0] -= 1
        if budget[0] < 0:
            raise TransportGTFSError("protobuf field limit")
        tag, pos = _varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 536870911:
            raise TransportGTFSError("invalid protobuf field number")
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, pos = _varint(data, pos)
            else:
                size = 8 if wire == 1 else 4
            if size > len(data) - pos:
                raise TransportGTFSError("truncated protobuf field")
            value = data[pos:pos + size]
            pos += size
        else:
            raise TransportGTFSError("protobuf groups/unknown wire types unsupported")
        if number not in schema:
            result.setdefault("_unknown", []).append({"field": number, "wire": wire,
                "value": value.hex() if isinstance(value, bytes) else value})
            continue
        name, kind = schema[number]
        repeated = kind.endswith("*")
        kind = kind.rstrip("!*")
        expected = 2 if kind == "s" or kind in _SCHEMAS else {"f": 5, "d": 1}.get(kind, 0)
        if wire != expected:
            raise TransportGTFSError(f"wrong protobuf wire type for {schema_name}.{name}")
        if kind in _SCHEMAS:
            value = _message(value, kind, budget, depth + 1)
        elif kind == "s":
            value = value.decode("utf-8")
        elif kind in ("f", "d"):
            value = struct.unpack("<" + kind, value)[0]
            if not math.isfinite(value):
                raise TransportGTFSError("nonfinite protobuf float")
        elif kind in ("i32", "i64"):
            bits = int(kind[1:])
            value &= (1 << bits) - 1
            if value >= 1 << (bits - 1):
                value -= 1 << bits
        elif kind == "u32" and value > 0xffffffff:
            raise TransportGTFSError("uint32 overflow")
        elif kind == "b":
            if value not in (0, 1):
                raise TransportGTFSError("noncanonical protobuf boolean")
            value = bool(value)
        if repeated:
            result.setdefault(name, []).append(value)
        elif name in result:
            raise TransportGTFSError("duplicate singular protobuf field")
        else:
            result[name] = value
    for name, kind in schema.values():
        if kind.endswith("!") and name not in result:
            raise TransportGTFSError(f"missing required {schema_name}.{name}")
    if schema_name == "Position":
        if not (-90 <= result["latitude"] <= 90 and -180 <= result["longitude"] <= 180):
            raise TransportGTFSError("invalid realtime coordinate")
    return result


@_guard
def decode_gtfs_rt(data: bytes) -> dict:
    """Decode core realtime entities; preserve unsupported fields as raw evidence.

    Numeric enum values and absent optional fields are preserved. Proto2 required
    fields are checked, but this is not a full GTFS semantic validator. New Stop,
    TripModifications, image and extension messages are retained in _unknown.
    """
    result = _message(_blob(data), "FeedMessage", [MAX_FIELDS])
    if result["header"]["gtfs_realtime_version"] not in ("1.0", "2.0"):
        raise TransportGTFSError("unsupported GTFS-Realtime version")
    ids = set()
    for entity in result.get("entity", []):
        if not entity["id"] or entity["id"] in ids:
            raise TransportGTFSError("empty/duplicate realtime entity ID")
        ids.add(entity["id"])
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--format", choices=("auto", "static", "realtime"), default="auto")
    parser.add_argument("--trip", help="static GTFS trip_id to join")
    parser.add_argument("--date", help="service date YYYYMMDD for --trip")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        mode = args.format if args.format != "auto" else ("static" if raw.startswith(b"PK") else "realtime")
        if mode == "realtime" and (args.trip or args.date):
            raise TransportGTFSError("--trip/--date need static GTFS")
        if args.date and not args.trip:
            raise TransportGTFSError("--date requires --trip")
        result = parse_gtfs_zip(raw) if mode == "static" else decode_gtfs_rt(raw)
        if args.trip:
            result = trip_itinerary(result, args.trip, args.date)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (TransportGTFSError, OSError, ValueError) as exc:
        print(f"transport_gtfs: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
