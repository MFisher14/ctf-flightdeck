#!/usr/bin/env python3
"""Unified, bounded DFIR super-timeline normalizer.

This engine ingests bodyfile, ordinary CSV, JSON, or JSONL records emitted by the repository's
MFT/USN/EVTX/registry/prefetch/LNK/JumpList/browser readers.  It normalizes known timestamp field
names to UTC events, sorts them, filters by time/keyword/IOC, and emits JSON, bodyfile, or mactime
CSV.  It parses data only: no mounting, subprocesses, artifact execution, or network access.

Library callers can pass reader dictionaries directly to :func:`ingest_records`, avoiding an
intermediate file.  Unknown numeric epochs are accepted only when their magnitude identifies a
standard Unix unit; Windows/WebKit epochs require either a named field or a value in their
unambiguous range.  Malformed rows are skipped and summarized rather than crashing a run.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import io
import json
import math
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

UTC = dt.timezone.utc
_EPOCH_1970 = dt.datetime(1970, 1, 1, tzinfo=UTC)
# 1601-01-01 -> 1970-01-01 and 1970-01-01 -> 2001-01-01, in whole microseconds.
_WIN_EPOCH_US = 11_644_473_600_000_000
_COCOA_EPOCH_US = 978_307_200_000_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 500_000
MAX_FIELD = 1 << 20
MAX_METADATA_BYTES = 64 * 1024
MAX_METADATA_FIELDS = 256


@dataclasses.dataclass(frozen=True)
class TimelineEvent:
    timestamp: dt.datetime
    source: str
    action: str
    path: str = ""
    description: str = ""
    time_type: str = "event"
    metadata: dict = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        stamp = self.timestamp
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        else:
            stamp = stamp.astimezone(UTC)
        object.__setattr__(self, "timestamp", stamp)

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "source": self.source,
            "action": self.action,
            "path": self.path,
            "description": self.description,
            "time_type": self.time_type,
            "metadata": self.metadata,
        }


TIME_FIELDS: dict[str, str] = {
    "mtime": "m", "modified": "m", "modified_time": "m", "modification_time": "m",
    "last_modified": "m", "write_time": "m", "last_write_time": "m", "last_written": "m",
    "atime": "a", "accessed": "a", "access_time": "a", "last_access": "a",
    "last_access_time": "a", "last_used": "a", "last_run": "a", "last_run_time": "a",
    "ctime": "c", "changed": "c", "change_time": "c", "metadata_changed": "c",
    "btime": "b", "birth_time": "b", "created": "b", "create_time": "b",
    "creation_time": "b", "crtime": "b",
    "timestamp": "event", "time": "event", "datetime": "event", "date": "event",
    "time_created": "event", "systemtime": "event", "event_time": "event",
    "first_record_timestamp": "event", "visit_time": "event", "last_visit": "event",
    "last_visit_time": "event", "start_time": "event", "end_time": "event",
    "deletion_time": "event", "deleted_at": "event", "run_time": "event",
}

PATH_FIELDS = ("path", "filename", "file_name", "name", "target_path", "local_path", "url", "key_path")
ACTION_FIELDS = ("action", "event", "event_name", "operation", "reason", "event_id", "type", "kind")
DESCRIPTION_FIELDS = ("description", "message", "details", "command", "command_line", "title", "provider")
SOURCE_FIELDS = ("source", "artifact", "parser", "channel", "table")


def _key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _text(value: object, cap: int = MAX_FIELD) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value)
    return str(value)[:cap].replace("\x00", "")


def _from_iso(text: str) -> dt.datetime | None:
    value = text.strip()
    if not value or len(value) > 128:
        return None
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    # EVTX occasionally emits seven fractional digits; datetime accepts six.
    value = re.sub(r"(\.\d{6})\d+(?=(?:[+-]\d\d:\d\d)?$)", r"\1", value)
    candidates = (value, value.replace("/", "-"))
    for candidate in candidates:
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
        except ValueError:
            continue
    for fmt in ("%a %b %d %H:%M:%S %Y", "%m/%d/%Y %H:%M:%S", "%Y%m%d%H%M%S"):
        try:
            return dt.datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def parse_timestamp(value: object, field: str = "timestamp") -> dt.datetime | None:
    """Normalize one known timestamp representation to UTC, or return ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, (tuple, list)):
        # Reader wrappers commonly return (Y,M,D,h,m,s[,microsecond][,metadata flag]).
        nums = [x for x in value if isinstance(x, (int, float)) and not isinstance(x, bool)]
        if any(isinstance(x, float) and not math.isfinite(x) for x in nums):
            return None
        if len(nums) >= 3 and 1601 <= int(nums[0]) <= 9999:
            padded = [int(x) for x in nums[:6]] + [0] * max(0, 6 - len(nums))
            micro = int(nums[6]) if len(nums) > 6 and 0 <= int(nums[6]) < 1_000_000 else 0
            try:
                return dt.datetime(*padded[:6], microsecond=micro, tzinfo=UTC)
            except ValueError:
                return None
        if len(value) == 2 and value[0] is not None:
            return parse_timestamp(value[0], field)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        # A bare integer/float string is an epoch value, never a compact calendar date.
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", stripped):
            try:
                value = float(stripped) if "." in stripped else int(stripped)
            except (ValueError, OverflowError):
                return None
        else:
            return _from_iso(value)
    if not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    name = _key(field)
    named_unix = any(tag in name for tag in ("unix", "prtime", "epoch"))
    # Non-positive values are valid only when a field explicitly names a Unix epoch.
    if value <= 0 and not named_unix:
        return None
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None

    def _floor_div(v: int | float, divisor: int) -> int:
        return v // divisor if isinstance(v, int) else round(v / divisor)

    try:
        # Named Windows FILETIME: 100-ns ticks since 1601.
        if "filetime" in name:
            micros = _floor_div(value, 10) - _WIN_EPOCH_US
        # Chromium/WebKit timestamps: microseconds since 1601.
        elif "webkit" in name or "chrome" in name:
            micros = (value if isinstance(value, int) else round(value)) - _WIN_EPOCH_US
        elif "mac_absolute" in name or "cocoa" in name:
            micros = round(numeric * 1_000_000) + _COCOA_EPOCH_US
        elif "prtime" in name or "unix_us" in name or "unix_micro" in name:
            micros = value if isinstance(value, int) else round(value)
        elif "unix_ns" in name or "unix_nano" in name:
            micros = _floor_div(value, 1_000)
        elif "unix_ms" in name or "unix_milli" in name:
            micros = value * 1_000 if isinstance(value, int) else round(value * 1_000)
        elif "unix_s" in name or name == "unix" or "epoch" in name:
            micros = round(numeric * 1_000_000)
        # Unnamed numeric: disambiguate by magnitude.
        elif numeric >= 10**18:  # Unix nanoseconds
            micros = _floor_div(value, 1_000)
        elif numeric >= 5 * 10**16:  # modern Windows FILETIME magnitude
            micros = _floor_div(value, 10) - _WIN_EPOCH_US
        elif numeric >= 10**15:  # modern WebKit microseconds since 1601
            micros = (value if isinstance(value, int) else round(value)) - _WIN_EPOCH_US
        elif numeric >= 10**12:  # Unix milliseconds
            micros = value * 1_000 if isinstance(value, int) else round(value * 1_000)
        else:
            micros = round(numeric * 1_000_000)
        parsed = _EPOCH_1970 + dt.timedelta(microseconds=micros)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed if 1601 <= parsed.year <= 9999 else None


def _first(record: Mapping, names: Sequence[str]) -> tuple[str, object] | tuple[None, None]:
    normalized = {_key(k): v for k, v in record.items()}
    for name in names:
        if name in normalized and normalized[name] not in (None, ""):
            return name, normalized[name]
    return None, None


def _time_values(record: Mapping) -> Iterator[tuple[str, str, object]]:
    for original, value in record.items():
        normalized = _key(original)
        base = normalized
        # Accept reader-specific prefixes/suffixes: e.g. si_mtime, fn_creation_time,
        # registry_last_written_timestamp, browser_visit_time.
        time_type = TIME_FIELDS.get(base)
        if time_type is None:
            matches = [(name, kind) for name, kind in TIME_FIELDS.items()
                       if base.endswith("_" + name) or base.startswith(name + "_")]
            if matches:
                _name, time_type = max(matches, key=lambda item: len(item[0]))
        if time_type is not None:
            yield str(original), time_type, value


def events_from_record(record: Mapping, *, source_hint: str = "record") -> list[TimelineEvent]:
    """Convert an MFT/USN/EVTX/registry/prefetch/LNK/browser-style mapping to events."""
    if not isinstance(record, Mapping) or len(record) > 10_000:
        return []
    _path_key, path_value = _first(record, PATH_FIELDS)
    _action_key, action_value = _first(record, ACTION_FIELDS)
    _desc_key, desc_value = _first(record, DESCRIPTION_FIELDS)
    _source_key, source_value = _first(record, SOURCE_FIELDS)
    path = _text(path_value, 8192)
    action = _text(action_value, 4096) or "artifact event"
    description = _text(desc_value, 32 * 1024)
    source = _text(source_value, 512) or source_hint
    safe_meta = {}
    meta_bytes = 0
    for key, value in record.items():
        if len(safe_meta) >= MAX_METADATA_FIELDS or _key(key) in TIME_FIELDS:
            continue
        rendered = _text(value, 4096)
        cost = len(rendered.encode("utf-8", "replace"))
        if meta_bytes + cost > MAX_METADATA_BYTES:
            continue
        safe_meta[str(key)[:256]] = rendered
        meta_bytes += cost
    output: list[TimelineEvent] = []
    seen: set[tuple[dt.datetime, str]] = set()
    for field, time_type, value in _time_values(record):
        stamp = parse_timestamp(value, field)
        if stamp is None or (stamp, time_type) in seen:
            continue
        seen.add((stamp, time_type))
        event_action = action if time_type == "event" else f"{action} [{time_type}]"
        metadata = dict(safe_meta)
        metadata["timestamp_field"] = field
        output.append(TimelineEvent(stamp, source, event_action, path, description,
                                    time_type, metadata))
    return output


def ingest_records(records: Iterable[Mapping], *, source_hint: str = "reader",
                   max_records: int = MAX_RECORDS) -> list[TimelineEvent]:
    """Normalize an iterable of existing-reader dictionaries, bounded by ``max_records``."""
    if not 1 <= max_records <= MAX_RECORDS:
        raise ValueError(f"max_records must be 1..{MAX_RECORDS}")
    events: list[TimelineEvent] = []
    for index, record in enumerate(records):
        if index >= max_records:
            break
        if isinstance(record, Mapping):
            events.extend(events_from_record(record, source_hint=source_hint))
    events.sort(key=lambda event: (event.timestamp, event.source, event.path, event.action))
    return events


def parse_bodyfile(text: str, *, source: str = "bodyfile") -> list[TimelineEvent]:
    """Parse Sleuth Kit bodyfile rows (11 pipe-separated fields)."""
    if not isinstance(text, str):
        raise ValueError("bodyfile input must be text")
    if len(text.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return []
    output: list[TimelineEvent] = []
    slots = ((7, "a"), (8, "m"), (9, "c"), (10, "b"))
    for line_number, line in enumerate(text.splitlines(), 1):
        if line_number > MAX_RECORDS:
            break
        fields = line.split("|")
        if len(fields) < 11:
            continue
        metadata = {"md5": _text(fields[0], 256), "inode": _text(fields[2], 256),
                    "mode": _text(fields[3], 256), "uid": _text(fields[4], 256),
                    "gid": _text(fields[5], 256), "size": _text(fields[6], 256),
                    "bodyfile_line": line_number}
        for index, time_type in slots:
            stamp = parse_timestamp(fields[index], "unix")
            if stamp is not None:
                output.append(TimelineEvent(stamp, source, f"filesystem [{time_type}]", _text(fields[1], 8192),
                                            "", time_type, metadata))
    output.sort(key=lambda event: (event.timestamp, event.path, event.time_type))
    return output


def _json_records(obj: object) -> list[Mapping]:
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, Mapping)]
    if isinstance(obj, Mapping):
        for key in ("events", "records", "rows", "artifacts", "data"):
            value = obj.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
        return [obj]
    return []


def parse_json_text(text: str, *, source: str = "json") -> list[TimelineEvent]:
    """Parse a JSON document or JSONL export from an existing reader."""
    if len(text.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return []
    try:
        obj = json.loads(text)
        records = _json_records(obj)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines()[:MAX_RECORDS]:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                records.append(value)
    return ingest_records(records, source_hint=source)


def parse_csv_text(text: str, *, source: str = "csv") -> list[TimelineEvent]:
    """Parse bodyfile or headered CSV exported by common DFIR tools."""
    if not isinstance(text, str):
        raise ValueError("CSV input must be text")
    if len(text.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        return []
    first = next((line for line in text.splitlines() if line.strip()), "")
    if first.count("|") >= 10 and not any(x in first.lower() for x in ("timestamp", "date", "time")):
        return parse_bodyfile(text, source=source)
    reader = csv.DictReader(io.StringIO(text))
    return ingest_records(reader, source_hint=source)


def ingest_path(path: str | Path) -> list[TimelineEvent]:
    """Read one bounded text export and auto-select bodyfile/CSV/JSON/JSONL."""
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"{p}: input exceeds {MAX_INPUT_BYTES} bytes")
    raw = p.read_bytes()
    if b"\x00" in raw[:4096]:
        raise ValueError(f"{p}: binary input is not a reader export")
    text = raw.decode("utf-8-sig", "replace")
    suffix = p.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"} or text.lstrip().startswith(("{", "[")):
        return parse_json_text(text, source=p.name)
    return parse_csv_text(text, source=p.name)


def filter_events(events: Iterable[TimelineEvent], *, start: dt.datetime | str | None = None,
                  end: dt.datetime | str | None = None, keywords: Sequence[str] = (),
                  iocs: Sequence[str] = ()) -> list[TimelineEvent]:
    """Apply an inclusive UTC window and case-insensitive keyword/IOC filters."""
    def boundary(value: dt.datetime | str | None, label: str) -> dt.datetime | None:
        if value is None:
            return None
        parsed = parse_timestamp(value, label)
        if parsed is None:
            raise ValueError(f"invalid {label} timestamp")
        return parsed

    lo, hi = boundary(start, "start"), boundary(end, "end")
    if lo and hi and lo > hi:
        raise ValueError("start is after end")
    words = [word.casefold() for word in keywords if word][:100]
    indicators = [word.casefold() for word in iocs if word][:1000]
    output = []
    for event in events:
        if lo and event.timestamp < lo or hi and event.timestamp > hi:
            continue
        haystack = " ".join((event.source, event.action, event.path, event.description,
                             _text(event.metadata))).casefold()
        if words and not all(word in haystack for word in words):
            continue
        if indicators and not any(ioc in haystack for ioc in indicators):
            continue
        output.append(event)
    return sorted(output, key=lambda event: (event.timestamp, event.source, event.path, event.action))


def to_bodyfile(events: Iterable[TimelineEvent]) -> str:
    """Emit one bodyfile row per event, placing its epoch in the matching MACB slot."""
    lines = []
    slot_index = {"a": 7, "m": 8, "c": 9, "b": 10, "event": 8}
    for event in events:
        fields = ["0", event.path.replace("|", "%7C"), "0", "0", "0", "0", "0", "0", "0", "0", "0"]
        fields[slot_index.get(event.time_type, 8)] = str(int(event.timestamp.timestamp()))
        lines.append("|".join(fields))
    return "\n".join(lines) + ("\n" if lines else "")


def to_mactime_csv(events: Iterable[TimelineEvent]) -> str:
    """Emit the conventional mactime CSV columns."""
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("Date", "Size", "Type", "Mode", "UID", "GID", "Meta", "File Name"))
    for event in events:
        meta = event.metadata
        writer.writerow((event.timestamp.isoformat().replace("+00:00", "Z"), meta.get("size", 0),
                         event.time_type, meta.get("mode", ""), meta.get("uid", ""),
                         meta.get("gid", ""), meta.get("inode", ""), event.path or event.description))
    return stream.getvalue()


def render_json(events: Iterable[TimelineEvent]) -> str:
    return json.dumps([event.as_dict() for event in events], indent=2, ensure_ascii=False, default=str) + "\n"


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="normalize reader exports into a DFIR super-timeline")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--start", help="inclusive ISO-8601 UTC window start")
    parser.add_argument("--end", help="inclusive ISO-8601 UTC window end")
    parser.add_argument("--keyword", action="append", default=[])
    parser.add_argument("--ioc", action="append", default=[])
    parser.add_argument("--format", choices=("json", "bodyfile", "mactime"), default="mactime")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:  # argparse --help exits 0; surface it as a return code.
            return int(exc.code) if exc.code is not None else 0
        events: list[TimelineEvent] = []
        for path in args.files:
            events.extend(ingest_path(path))
            if len(events) > MAX_RECORDS * 4:
                raise ValueError("combined event cap exceeded")
        events = filter_events(events, start=args.start, end=args.end,
                               keywords=args.keyword, iocs=args.ioc)
        output_format = "json" if args.json else args.format
        if output_format == "json":
            sys.stdout.write(render_json(events))
        elif output_format == "bodyfile":
            sys.stdout.write(to_bodyfile(events))
        else:
            sys.stdout.write(to_mactime_csv(events))
        return 0
    except (ValueError, OSError, UnicodeError, csv.Error) as exc:
        print(f"timeline: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
