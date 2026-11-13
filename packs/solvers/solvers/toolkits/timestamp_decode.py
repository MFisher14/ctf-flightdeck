#!/usr/bin/env python3
"""Decode a mystery number as every common timestamp format, offline.

A frequent forensics/misc step: a challenge hands you a big integer (or hex) and you need to know which
epoch+unit it is — Unix s/ms/us/ns, Windows FILETIME, Chrome/WebKit, Apple Cocoa/HFS+, OLE automation
date, DOS packed datetime.  This prints the UTC datetime under each interpretation, ranking the ones
that land in a plausible year range first.  Distinct from `timeline.py` (which parses timestamps IN
forensic artifacts to build a super-timeline) — this is the paste-one-number triage tool.  Offline,
read-only, ranked candidates; it never submits.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from typing import Iterable

UTC = _dt.timezone.utc
EPOCH_1970 = _dt.datetime(1970, 1, 1, tzinfo=UTC)
EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=UTC)
EPOCH_1904 = _dt.datetime(1904, 1, 1, tzinfo=UTC)
EPOCH_2001 = _dt.datetime(2001, 1, 1, tzinfo=UTC)
EPOCH_OLE = _dt.datetime(1899, 12, 30, tzinfo=UTC)


def _from_seconds(epoch: _dt.datetime, seconds) -> _dt.datetime | None:
    if seconds is None:
        return None
    try:
        return epoch + _dt.timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return None


def _from_ticks(epoch: _dt.datetime, value, ticks_per_us: int) -> _dt.datetime | None:
    """epoch + value sub-second ticks, via exact integer division (no float64 rounding).

    FILETIME/unix-nanos carry sub-microsecond resolution; float division (_div) loses the
    last 1-2 us once the quotient exceeds float64's ~15.95 significant digits. Integer
    divmod to whole microseconds (floored) keeps the microsecond field exact.
    """
    if value is None:
        return None
    try:
        total_us = int(value) // ticks_per_us
        return epoch + _dt.timedelta(microseconds=total_us)
    except (OverflowError, ValueError):
        return None


def _div(value: int, divisor: float):
    """value / divisor, or None when value is too large to convert to float (huge garbage input)."""
    try:
        return value / divisor
    except (OverflowError, ValueError):
        return None


def _dos(value: int) -> _dt.datetime | None:
    # 32-bit packed: high 16 = date (year-1980<<9 | month<<5 | day), low 16 = time (h<<11|m<<5|s/2).
    if not 0 <= value <= 0xFFFFFFFF:
        return None
    date, time = value >> 16, value & 0xFFFF
    year = ((date >> 9) & 0x7F) + 1980
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = (time >> 11) & 0x1F
    minute = (time >> 5) & 0x3F
    sec = (time & 0x1F) * 2
    try:
        return _dt.datetime(year, month, day, hour, minute, sec, tzinfo=UTC)
    except ValueError:
        return None


def _parse(value: object) -> tuple[int | None, float | None]:
    """Return (int_value, float_value) parsed from the input, or (None, None)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (int(value), float(value))
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return (None, None)
    if not isinstance(value, str):
        return (None, None)
    s = value.strip()
    if not s:
        return (None, None)
    try:
        if s.lower().startswith("0x"):
            return (int(s, 16), None)
        if "." in s:
            return (int(float(s)), float(s))
        return (int(s), float(s))
    except ValueError:
        # bare hex (letters present) as a last resort
        try:
            return (int(s, 16), None)
        except ValueError:
            return (None, None)


def decode(value: object, *, min_year: int = 1990, max_year: int = 2040) -> list[dict]:
    """Ranked [{format, utc, plausible}] interpretations of a mystery timestamp. Empty if unparseable."""
    ival, fval = _parse(value)
    if ival is None:
        return []
    out = []

    def add(fmt, dtobj):
        if dtobj is None:
            return
        plausible = min_year <= dtobj.year <= max_year
        out.append({"format": fmt, "utc": dtobj.replace(microsecond=dtobj.microsecond).isoformat(),
                    "year": dtobj.year, "plausible": plausible})

    add("unix_seconds", _from_seconds(EPOCH_1970, _div(ival, 1)))
    add("unix_millis", _from_seconds(EPOCH_1970, _div(ival, 1e3)))
    add("unix_micros", _from_ticks(EPOCH_1970, ival, 1))
    add("unix_nanos", _from_ticks(EPOCH_1970, ival, 1000))
    add("windows_filetime (100ns since 1601)", _from_ticks(EPOCH_1601, ival, 10))
    add("chrome/webkit (us since 1601)", _from_ticks(EPOCH_1601, ival, 1))
    add("apple_hfs (s since 1904)", _from_seconds(EPOCH_1904, _div(ival, 1)))
    add("apple_cocoa (s since 2001)", _from_seconds(EPOCH_2001, _div(ival, 1)))
    if fval is not None:
        add("ole_automation (days since 1899-12-30)", _from_seconds(EPOCH_OLE, _div(fval, 1 / 86400)))
    add("dos_datetime (packed 32-bit)", _dos(ival))
    # plausible first, then by how central the year is to the window.
    mid = (min_year + max_year) / 2
    out.sort(key=lambda d: (0 if d["plausible"] else 1, abs(d["year"] - mid)))
    return out


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Decode a number as every common timestamp format "
                                            "(offline; ranked by plausibility).")
    p.add_argument("value", help="the mystery number (decimal, 0x-hex, or float for OLE)")
    p.add_argument("--min-year", type=int, default=1990)
    p.add_argument("--max-year", type=int, default=2040)
    p.add_argument("--all", action="store_true", help="show implausible interpretations too")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    results = decode(a.value, min_year=a.min_year, max_year=a.max_year)
    if not a.all:
        results = [r for r in results if r["plausible"]] or results[:3]
    if a.json:
        import json
        print(json.dumps(results, indent=1))
    else:
        for r in results:
            mark = "*" if r["plausible"] else " "
            print(f"{mark} {r['format']:42} {r['utc']}")
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
