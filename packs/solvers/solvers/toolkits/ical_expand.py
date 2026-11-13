#!/usr/bin/env python3
"""iCalendar (RFC 5545) recurrence expander: RRULE/RDATE/EXDATE, RECURRENCE-ID overrides, TZID to UTC (B-103).

A pure, offline expander for an exported `.ics`: it parses the calendar, builds each event's
recurrence set and returns every instance as a UTC `Occurrence`. No network, no model; the input is
data only (parsed, never run).

What it implements, per RFC 5545:

* Content lines: unfolding (CRLF or LF followed by one space/tab), quoted parameter values, TEXT
  escapes, nested components (VCALENDAR / VEVENT / VTIMEZONE ...).
* Values: DATE, DATE-TIME (UTC `Z`, `TZID=`, floating), PERIOD (start/end, start/duration), DURATION.
* Recurrence set (3.8.5): DTSTART is always the first instance; RRULE (every rule part, through
  python-dateutil's rrule) and RDATE (dates, date-times, periods) add; EXDATE and EXRULE remove.
  UNTIL is applied exactly in UTC. A rule with neither COUNT nor UNTIL needs a window.
* Overrides: a component with the master's UID and a RECURRENCE-ID replaces the instance whose
  original start equals it (compared in UTC, so `Z` and `TZID` spellings match), wherever that
  instance falls: an override can move an instance into or out of a window. `RANGE=THISANDFUTURE`
  shifts that instance and every later one. dateutil's `rruleset` knows nothing of overrides, so this
  module does that part itself.
* Durations: DTEND gives an exact duration applied to every instance; DURATION is nominal (days and
  weeks are added in local wall-clock time, so `P1D` across a DST change is 23 or 25 hours).
* Time zones: a VTIMEZONE in the file is authoritative for its TZID (RFC 5545 3.6.5); otherwise the
  TZID is looked up in the IANA database through `zoneinfo`. Expansion runs in the DTSTART's local
  wall-clock time (a 09:00 New York series stays 09:00 local across DST), then each instance goes to
  UTC. A local time in a DST gap uses the offset before the gap; an ambiguous one takes the first.
  Floating times and all-day dates need an explicit `floating_tz`; there is no default zone.

What it refuses to guess: where RFC 5545 leaves the result undefined, or the file breaks a MUST, the
instances carry `flags` (`dtstart-unsynced`, `orphan-override`, `exdate-override`, `until-type`,
`count-and-until`, `duplicate-override`, `inherited:<PROP>`), so a caller can tell a mechanical answer
from one that rests on a reading. A component that cannot be expanded at all (unknown TZID, malformed
value, unbounded rule with no window) is skipped and named in `errors`, never dropped silently.

Library use:

    import ical_expand as ix
    exp = ix.expand_text(text, start=lo, end=hi)          # lo/hi: aware datetimes (any zone)
    sel = ix.select(exp.occurrences, lo, hi, basis="start", end_inclusive=False)

CLI (offline):

    tools/ctfpy solvers/toolkits/ical_expand.py case.ics [--from ISO] [--to ISO] [--basis start|overlap]
        [--end-inclusive] [--keep-cancelled] [--floating-tz ZONE] [--json]

Engine entry `solve(challenge_dir, profile)`: expands every calendar in a handout (intake, offline)
and reports it as `unsure`: an expansion is data for a mapping, never a flag by itself.
"""
from __future__ import annotations

import argparse
import bisect
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    from dateutil import rrule as _du
except ImportError as _e:   # pinned in requirements.in; reported by name, never a silent fallback
    _du = None
    _DU_ERROR = str(_e)
else:
    _DU_ERROR = ""

UTC = dt.timezone.utc

MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 16
DEFAULT_MAX_INSTANCES = 100_000
VTIMEZONE_HORIZON_YEAR = 2200
ENGINE_ID = "toolkits.ical_expand"

# Instance flags: where RFC 5545 leaves the answer undefined or the file breaks a MUST.
FLAG_DTSTART_UNSYNCED = "dtstart-unsynced"      # DTSTART is not on its RRULE's pattern (set undefined)
FLAG_ORPHAN = "orphan-override"                 # a RECURRENCE-ID that names no instance of the master
FLAG_EXDATE_OVERRIDE = "exdate-override"        # an override of an instance EXDATE/EXRULE removed
FLAG_UNTIL_TYPE = "until-type"                  # UNTIL's value type does not match DTSTART's
FLAG_COUNT_AND_UNTIL = "count-and-until"        # both COUNT and UNTIL (RFC: MUST NOT); both honoured
FLAG_DUPLICATE_OVERRIDE = "duplicate-override"  # two overrides of one instance; highest SEQUENCE kept
INHERITED_PREFIX = "inherited:"                 # the override did not state <PROP>; the master's was used
# Properties an override inherits from its master when it does not state them (common practice; RFC
# 5545 does not say). Each inheritance is flagged "inherited:<PROP>" on that instance.
INHERITABLE = ("SUMMARY", "CATEGORIES", "LOCATION", "DESCRIPTION", "STATUS")
# Properties that never pass from a master to an override and are not descriptive text.
_STRUCTURAL = frozenset({"DTSTART", "DTEND", "DURATION", "RRULE", "RDATE", "EXDATE", "EXRULE",
                         "RECURRENCE-ID", "SEQUENCE", "UID", "DTSTAMP", "CREATED", "LAST-MODIFIED"})


class IcalError(ValueError):
    """Malformed or unexpandable iCalendar input. Always names what and where."""


def _need_dateutil() -> None:
    if _du is None:
        raise IcalError(f"python-dateutil is not installed ({_DU_ERROR}); install the pin in requirements.in")


# ======================================================================================
#  Content lines and components
# ======================================================================================

@dataclass(frozen=True)
class Prop:
    name: str                             # upper-case property name
    params: tuple[tuple[str, str], ...]   # (UPPER-NAME, value); a multi-valued param is comma-joined
    value: str                            # raw value text (TEXT escapes not undone)
    line: int = 0                         # first physical line, for error messages

    def param(self, name: str) -> str | None:
        name = name.upper()
        for k, v in self.params:
            if k == name:
                return v
        return None


@dataclass
class Component:
    name: str
    props: list[Prop] = field(default_factory=list)
    children: list["Component"] = field(default_factory=list)
    line: int = 0

    def get(self, name: str) -> Prop | None:
        name = name.upper()
        for p in self.props:
            if p.name == name:
                return p
        return None

    def all(self, name: str) -> list[Prop]:
        name = name.upper()
        return [p for p in self.props if p.name == name]

    def walk(self) -> Iterable["Component"]:
        yield self
        for c in self.children:
            yield from c.walk()


_NAME_RE = re.compile(r"[A-Za-z0-9-]+")


def unfold(text: str) -> list[tuple[int, str]]:
    """Unfold content lines: a line starting with one space or tab continues the previous one (that
    one character is dropped). Returns (first physical line number, logical line); blank lines go."""
    out: list[tuple[int, str]] = []
    for n, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if raw[:1] in (" ", "\t"):
            if not out:
                raise IcalError(f"line {n}: a continuation line with nothing to continue")
            ln, prev = out[-1]
            out[-1] = (ln, prev + raw[1:])
        elif raw.strip():
            out.append((n, raw))
    return out


def parse_line(line: str, lineno: int = 0) -> Prop:
    """One unfolded content line -> Prop. Quoted parameter values may hold ':' ';' ','."""
    m = _NAME_RE.match(line)
    if not m:
        raise IcalError(f"line {lineno}: no property name in {line[:60]!r}")
    name, i, n = m.group(0).upper(), m.end(), len(line)
    params: list[tuple[str, str]] = []
    while i < n and line[i] == ";":
        pm = _NAME_RE.match(line, i + 1)
        if not pm or pm.end() >= n or line[pm.end()] != "=":
            raise IcalError(f"line {lineno}: malformed parameter in {line[:60]!r}")
        pname, i = pm.group(0).upper(), pm.end() + 1
        values = []
        while True:
            if i < n and line[i] == '"':
                j = line.find('"', i + 1)
                if j < 0:
                    raise IcalError(f"line {lineno}: unterminated quoted parameter value")
                values.append(line[i + 1:j])
                i = j + 1
            else:
                j = i
                while j < n and line[j] not in ';:,"':
                    j += 1
                values.append(line[i:j])
                i = j
            if i < n and line[i] == ",":
                i += 1
                continue
            break
        params.append((pname, ",".join(values)))
    if i >= n or line[i] != ":":
        raise IcalError(f"line {lineno}: expected ':' after the property name/parameters in {line[:60]!r}")
    return Prop(name, tuple(params), line[i + 1:], lineno)


def parse(text: str | bytes) -> list[Component]:
    """Parse iCalendar text into its top-level components (normally one VCALENDAR)."""
    if isinstance(text, (bytes, bytearray)):
        if len(text) > MAX_TEXT_BYTES:
            raise IcalError(f"calendar is {len(text)} bytes, over the {MAX_TEXT_BYTES}-byte limit")
        try:
            text = bytes(text).decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise IcalError(f"calendar is not UTF-8: {e}") from None
    elif len(text) > MAX_TEXT_BYTES:
        raise IcalError(f"calendar is {len(text)} characters, over the {MAX_TEXT_BYTES} limit")
    text = text.lstrip("﻿")
    roots: list[Component] = []
    stack: list[Component] = []
    for lineno, line in unfold(text):
        p = parse_line(line, lineno)
        if p.name == "BEGIN":
            if len(stack) >= MAX_DEPTH:
                raise IcalError(f"line {lineno}: components nested deeper than {MAX_DEPTH}")
            c = Component(p.value.strip().upper(), line=lineno)
            (stack[-1].children if stack else roots).append(c)
            stack.append(c)
        elif p.name == "END":
            want = p.value.strip().upper()
            if not stack or stack[-1].name != want:
                have = stack[-1].name if stack else "nothing"
                raise IcalError(f"line {lineno}: END:{want} but {have} is open")
            stack.pop()
        else:
            if not stack:
                raise IcalError(f"line {lineno}: property {p.name} outside any component")
            stack[-1].props.append(p)
    if stack:
        raise IcalError(f"unterminated component(s): {', '.join(c.name for c in stack)}")
    if not roots:
        raise IcalError("no iCalendar component found (no BEGIN line)")
    return roots


def unescape_text(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append("\n" if nxt in "nN" else nxt)
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def split_text_list(value: str) -> list[str]:
    """A comma-separated TEXT list (CATEGORIES): split on unescaped commas, then unescape each."""
    parts, cur, i = [], [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            cur.append(value[i:i + 2])
            i += 2
            continue
        if ch == ",":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [unescape_text(p).strip() for p in parts if p.strip()]


# ======================================================================================
#  Values: DATE, DATE-TIME, DURATION, PERIOD, UTC offsets
# ======================================================================================

@dataclass(frozen=True)
class When:
    """A DATE or DATE-TIME value as written. kind: utc | tz | floating | date."""
    value: dt.datetime | dt.date
    kind: str
    tzid: str | None = None

    @property
    def naive(self) -> dt.datetime:
        v = self.value
        return v if isinstance(v, dt.datetime) else dt.datetime(v.year, v.month, v.day)


@dataclass(frozen=True)
class Duration:
    """`days` (weeks folded in) are nominal, added in local time; `seconds` are exact."""
    days: int = 0
    seconds: int = 0

    @property
    def upper(self) -> dt.timedelta:
        return dt.timedelta(days=abs(self.days) + 1, seconds=abs(self.seconds))


_DT_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$")
_DATE_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})$")
_DUR_RE = re.compile(r"^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")
_OFFSET_RE = re.compile(r"^([+-])(\d{2})(\d{2})(\d{2})?$")


def parse_datetime_value(s: str, *, tzid: str | None = None, value_type: str | None = None,
                         what: str = "value") -> When:
    """One DATE or DATE-TIME. The RFC form is basic (20260720T070000Z); the extended ISO spelling
    (2026-07-20T07:00:00Z) is accepted too. A UTC value that also has a TZID is an error."""
    raw = s.strip()
    t = raw.replace("-", "").replace(":", "") if ("-" in raw[:10] or ":" in raw) else raw
    vt = (value_type or "").upper()
    m = _DATE_RE.match(t)
    if m and vt in ("", "DATE"):
        try:
            return When(dt.date(int(m[1]), int(m[2]), int(m[3])), "date")
        except ValueError as e:
            raise IcalError(f"{what}: bad DATE {raw!r} ({e})") from None
    m = _DT_RE.match(t)
    if not m or vt == "DATE":
        raise IcalError(f"{what}: not a {'DATE' if vt == 'DATE' else 'DATE-TIME'} value: {raw!r}")
    sec = min(int(m[6]), 59)        # a leap second (60) is read as :59
    try:
        v = dt.datetime(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), sec)
    except ValueError as e:
        raise IcalError(f"{what}: bad DATE-TIME {raw!r} ({e})") from None
    if m[7]:
        if tzid:
            raise IcalError(f"{what}: {raw!r} is UTC ('Z') but also has TZID={tzid}")
        return When(v, "utc")
    if tzid:
        return When(v, "tz", tzid)
    return When(v, "floating")


def parse_duration(s: str, *, what: str = "DURATION") -> Duration:
    m = _DUR_RE.match(s.strip().upper())
    if not m or not any(m.group(i) for i in range(2, 7)):
        raise IcalError(f"{what}: not a DURATION value: {s!r}")
    sign = -1 if m[1] == "-" else 1
    w, d, h, mi, se = (int(m[i] or 0) for i in range(2, 7))
    return Duration(days=sign * (7 * w + d), seconds=sign * (3600 * h + 60 * mi + se))


def parse_offset(s: str, *, what: str = "offset") -> dt.timedelta:
    m = _OFFSET_RE.match(s.strip())
    if not m:
        raise IcalError(f"{what}: not a UTC offset: {s!r}")
    sign = -1 if m[1] == "-" else 1
    return sign * dt.timedelta(hours=int(m[2]), minutes=int(m[3]), seconds=int(m[4] or 0))


def prop_when(p: Prop) -> When:
    return parse_datetime_value(p.value, tzid=p.param("TZID"), value_type=p.param("VALUE"),
                                what=f"line {p.line} {p.name}")


def prop_whens(p: Prop) -> list:
    """RDATE/EXDATE: a comma list of When, or (When, When | Duration) for a PERIOD."""
    out: list = []
    vt = (p.param("VALUE") or "").upper()
    tzid = p.param("TZID")
    what = f"line {p.line} {p.name}"
    for item in p.value.split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item or vt == "PERIOD":
            if "/" not in item:
                raise IcalError(f"{what}: PERIOD value without '/': {item!r}")
            a, b = item.split("/", 1)
            start = parse_datetime_value(a, tzid=tzid, what=what)
            if start.kind == "date":
                raise IcalError(f"{what}: a PERIOD starts with a DATE-TIME, not {a!r}")
            other = parse_duration(b, what=what) if b.strip()[:1] in "+-P" else \
                parse_datetime_value(b, tzid=tzid, what=what)
            out.append((start, other))
        else:
            out.append(parse_datetime_value(item, tzid=tzid, value_type=vt or None, what=what))
    return out


# ======================================================================================
#  Time zones
# ======================================================================================

class Zone:
    """Local wall-clock <-> UTC for one zone. to_utc: naive local -> aware UTC."""
    name = "?"

    def to_utc(self, local: dt.datetime) -> dt.datetime:
        raise NotImplementedError

    def to_local(self, instant: dt.datetime) -> dt.datetime:
        raise NotImplementedError


class FixedZone(Zone):
    def __init__(self, name: str, offset: dt.timedelta = dt.timedelta(0)):
        self.name, self.offset = name, offset

    def to_utc(self, local):
        return (local - self.offset).replace(tzinfo=UTC)

    def to_local(self, instant):
        return (instant.astimezone(UTC) + self.offset).replace(tzinfo=None)


UTC_ZONE = FixedZone("UTC")


class IanaZone(Zone):
    """An IANA zone through zoneinfo. fold=0: a gap time uses the offset before the gap (RFC 5545
    3.3.5) and an ambiguous time takes its first occurrence."""

    def __init__(self, name: str, tz):
        self.name, self.tz = name, tz

    def to_utc(self, local):
        return local.replace(tzinfo=self.tz, fold=0).astimezone(UTC)

    def to_local(self, instant):
        return instant.astimezone(self.tz).replace(tzinfo=None, fold=0)


class VTimezoneZone(Zone):
    """A zone defined by a VTIMEZONE's STANDARD/DAYLIGHT observances (onsets up to VTIMEZONE_HORIZON_YEAR)."""

    def __init__(self, name: str, transitions: list[tuple[dt.datetime, dt.timedelta, dt.timedelta]]):
        if not transitions:
            raise IcalError(f"VTIMEZONE {name!r} has no STANDARD/DAYLIGHT observance")
        self.name = name
        self.trans = sorted(transitions, key=lambda t: t[0])   # (onset as naive UTC, offset_from, offset_to)
        self._keys = [t[0] for t in self.trans]
        self.offsets = sorted({o for t in self.trans for o in (t[1], t[2])})

    def offset_at(self, utc_naive: dt.datetime) -> dt.timedelta:
        i = bisect.bisect_right(self._keys, utc_naive) - 1
        return self.trans[0][1] if i < 0 else self.trans[i][2]

    def to_utc(self, local):
        valid = [local - o for o in self.offsets if self.offset_at(local - o) == o]
        if valid:
            return min(valid).replace(tzinfo=UTC)        # ambiguous: the first occurrence
        for onset, off_from, off_to in self.trans:        # in a gap: the offset before it
            if onset + off_from <= local < onset + off_to:
                return (local - off_from).replace(tzinfo=UTC)
        raise IcalError(f"VTIMEZONE {self.name!r}: local time {local} matches no offset")

    def to_local(self, instant):
        u = instant.astimezone(UTC).replace(tzinfo=None)
        return u + self.offset_at(u)


_FREQS = ("YEARLY", "MONTHLY", "WEEKLY", "DAILY", "HOURLY", "MINUTELY", "SECONDLY")
_DAYS = ("MO", "TU", "WE", "TH", "FR", "SA", "SU")
# rule part -> (dateutil keyword, min |n|, max |n|, negative allowed)
_BY_PARTS = {"BYSECOND": ("bysecond", 0, 60, False), "BYMINUTE": ("byminute", 0, 59, False),
             "BYHOUR": ("byhour", 0, 23, False), "BYMONTHDAY": ("bymonthday", 1, 31, True),
             "BYYEARDAY": ("byyearday", 1, 366, True), "BYWEEKNO": ("byweekno", 1, 53, True),
             "BYMONTH": ("bymonth", 1, 12, False), "BYSETPOS": ("bysetpos", 1, 366, True)}


def rrule_kwargs(value: str, what: str = "RRULE") -> tuple[dict, dict]:
    """Parse an RRULE/EXRULE value into dateutil.rrule keyword arguments, plus its raw COUNT/UNTIL.
    Unknown or repeated rule parts and out-of-range values raise IcalError."""
    _need_dateutil()
    days = {d: getattr(_du, d) for d in _DAYS}
    parts: dict[str, str] = {}
    for chunk in value.strip().strip(";").split(";"):
        if "=" not in chunk:
            raise IcalError(f"{what}: rule part without '=': {chunk!r}")
        k, v = chunk.split("=", 1)
        k = k.strip().upper()
        if k in parts:
            raise IcalError(f"{what}: rule part {k} given twice")
        parts[k] = v.strip()
    unknown = sorted(set(parts) - {"FREQ", "INTERVAL", "COUNT", "UNTIL", "BYDAY", "WKST"} - set(_BY_PARTS))
    if unknown:
        raise IcalError(f"{what}: unknown rule part(s) {unknown}")
    freq = parts.get("FREQ", "").upper()
    if freq not in _FREQS:
        raise IcalError(f"{what}: FREQ missing or unknown: {parts.get('FREQ')!r}")
    kw: dict = {"freq": getattr(_du, freq)}

    def posint(k):
        try:
            n = int(parts[k])
        except ValueError:
            raise IcalError(f"{what}: {k}={parts[k]!r} is not an integer") from None
        if n < 1:
            raise IcalError(f"{what}: {k} must be >= 1, got {n}")
        return n

    if "INTERVAL" in parts:
        kw["interval"] = posint("INTERVAL")
    if "COUNT" in parts:
        kw["count"] = posint("COUNT")
    for k, (dukey, lo, hi, signed) in _BY_PARTS.items():
        if k not in parts:
            continue
        vals = []
        for x in parts[k].split(","):
            try:
                n = int(x)
            except ValueError:
                raise IcalError(f"{what}: {k} value {x!r} is not an integer") from None
            if not (lo <= abs(n) <= hi) or (n < 0 and not signed) or (signed and n == 0):
                raise IcalError(f"{what}: {k} value {n} out of range")
            vals.append(min(n, 59) if k == "BYSECOND" else n)
        kw[dukey] = tuple(vals)
    if "BYDAY" in parts:
        wd = []
        for x in parts["BYDAY"].split(","):
            m = re.fullmatch(r"([+-]?\d{1,2})?(MO|TU|WE|TH|FR|SA|SU)", x.strip().upper())
            if not m:
                raise IcalError(f"{what}: BYDAY value {x!r} is not [+-n]MO..SU")
            if m[1]:
                n = int(m[1])
                if n == 0 or abs(n) > 53:
                    raise IcalError(f"{what}: BYDAY ordinal {n} out of range")
                wd.append(days[m[2]](n))
            else:
                wd.append(days[m[2]])
        kw["byweekday"] = tuple(wd)
    if "WKST" in parts:
        w = parts["WKST"].upper()
        if w not in days:
            raise IcalError(f"{what}: WKST {w!r} is not MO..SU")
        kw["wkst"] = days[w]
    return kw, {"COUNT": parts.get("COUNT"), "UNTIL": parts.get("UNTIL")}


def build_vtimezone(comp: Component) -> VTimezoneZone:
    tzp = comp.get("TZID")
    if tzp is None or not tzp.value.strip():
        raise IcalError(f"line {comp.line}: VTIMEZONE without TZID")
    name = tzp.value.strip()
    horizon = dt.datetime(VTIMEZONE_HORIZON_YEAR, 1, 1)
    trans = []
    for ob in comp.children:
        if ob.name not in ("STANDARD", "DAYLIGHT"):
            continue
        what = f"VTIMEZONE {name!r} {ob.name} (line {ob.line})"
        need = {k: ob.get(k) for k in ("DTSTART", "TZOFFSETFROM", "TZOFFSETTO")}
        missing = [k for k, v in need.items() if v is None]
        if missing:
            raise IcalError(f"{what}: missing {missing}")
        start = prop_when(need["DTSTART"])
        if start.kind != "floating":
            raise IcalError(f"{what}: DTSTART must be a local DATE-TIME, got {need['DTSTART'].value!r}")
        off_from = parse_offset(need["TZOFFSETFROM"].value, what=what)
        off_to = parse_offset(need["TZOFFSETTO"].value, what=what)
        onsets = {start.naive}
        for rp in ob.all("RRULE"):
            kw, raw = rrule_kwargs(rp.value, what)
            if raw["UNTIL"]:
                u = parse_datetime_value(raw["UNTIL"], what=what)
                # an observance's UNTIL is UTC; its onsets are local time in TZOFFSETFROM
                kw["until"] = u.naive + off_from if u.kind == "utc" else u.naive
            onsets.update(_du.rrule(dtstart=start.naive, **kw).between(start.naive, horizon, inc=True))
        for rp in ob.all("RDATE"):
            for w in prop_whens(rp):
                w = w[0] if isinstance(w, tuple) else w
                onsets.add(w.naive + off_from if w.kind == "utc" else w.naive)
        trans += [(o - off_from, off_from, off_to) for o in onsets]
    return VTimezoneZone(name, trans)


class Resolver:
    """TZID -> Zone: the file's VTIMEZONEs first, then IANA via zoneinfo; floating -> `floating_tz`."""

    def __init__(self, vtimezones: dict[str, VTimezoneZone] | None = None, floating_tz: str | None = None):
        self.vtz = dict(vtimezones or {})
        self._cache: dict[str, Zone] = {}
        self.warnings: list[str] = []
        self.floating: Zone | None = self._iana(floating_tz, "floating_tz") if floating_tz else None

    @staticmethod
    def _iana(name: str, what: str) -> Zone:
        if name.upper() in ("UTC", "Z", "GMT", "ETC/UTC"):
            return UTC_ZONE
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            return IanaZone(name, ZoneInfo(name))
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise IcalError(f"{what}: unknown time zone {name!r} ({type(e).__name__})") from None

    def zone(self, tzid: str) -> Zone:
        if tzid in self._cache:
            return self._cache[tzid]
        if tzid in self.vtz:
            z: Zone | None = self.vtz[tzid]
        else:
            try:
                z = self._iana(tzid, f"TZID={tzid}")
            except IcalError:
                # "/vendor/20190914_1/America/New_York": the longest IANA-looking suffix, with a warning
                segs = [s for s in tzid.strip("/").split("/") if s]
                z = None
                for i in range(1, len(segs)):
                    cand = "/".join(segs[i:])
                    try:
                        z = self._iana(cand, f"TZID={tzid}")
                    except IcalError:
                        continue
                    self.warnings.append(f"TZID {tzid!r} read as IANA zone {cand!r} (no VTIMEZONE for it)")
                    break
                if z is None:
                    raise IcalError(f"TZID {tzid!r}: no VTIMEZONE in the file and not an IANA zone") from None
        self._cache[tzid] = z
        return z

    def basis(self, w: When) -> Zone:
        if w.kind == "utc":
            return UTC_ZONE
        if w.kind == "tz":
            return self.zone(w.tzid or "")
        if self.floating is None:
            raise IcalError(f"{'DATE' if w.kind == 'date' else 'floating DATE-TIME'} {w.value} has no time "
                            "zone: pass floating_tz (e.g. 'UTC') to say which zone it is in")
        return self.floating

    def to_utc(self, w: When, series: Zone | None = None) -> dt.datetime:
        """UTC of `w`. A floating time or date inside a series is read in the series' zone."""
        if series is not None and w.kind in ("floating", "date"):
            return series.to_utc(w.naive)
        return self.basis(w).to_utc(w.naive)


# ======================================================================================
#  Expansion
# ======================================================================================

@dataclass(frozen=True)
class Occurrence:
    uid: str
    recurrence_id: dt.datetime          # the instance's original (nominal) start, UTC
    start: dt.datetime                  # actual start after overrides, UTC
    end: dt.datetime                    # UTC
    all_day: bool = False
    summary: str | None = None
    categories: tuple[str, ...] = ()
    status: str | None = None           # upper-case STATUS (CONFIRMED, CANCELLED, ...)
    location: str | None = None
    description: str | None = None
    overridden: bool = False            # a RECURRENCE-ID component replaced or shifted it
    source: str = "dtstart"             # dtstart | rrule | rdate | override
    sequence: int = 0
    flags: tuple[str, ...] = ()
    props: tuple[tuple[str, str], ...] = ()   # the effective component's non-structural properties

    @property
    def category(self) -> str | None:
        return self.categories[0] if self.categories else None

    @property
    def cancelled(self) -> bool:
        return self.status == "CANCELLED"

    def prop(self, name: str) -> str | None:
        name = name.upper()
        for k, v in self.props:
            if k == name:
                return v
        return None

    def to_dict(self) -> dict:
        return {"uid": self.uid, "recurrence_id": iso_z(self.recurrence_id), "start": iso_z(self.start),
                "end": iso_z(self.end), "all_day": self.all_day, "summary": self.summary,
                "categories": list(self.categories), "status": self.status, "location": self.location,
                "overridden": self.overridden, "source": self.source, "sequence": self.sequence,
                "flags": list(self.flags)}


@dataclass
class Expansion:
    occurrences: list[Occurrence]
    errors: list[str] = field(default_factory=list)      # components that could not be expanded
    warnings: list[str] = field(default_factory=list)
    window: tuple[dt.datetime, dt.datetime] | None = None

    def to_dict(self) -> dict:
        return {"window": [iso_z(self.window[0]), iso_z(self.window[1])] if self.window else None,
                "occurrences": [o.to_dict() for o in self.occurrences],
                "errors": list(self.errors), "warnings": list(self.warnings)}


def iso_z(t: dt.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aware(t: dt.datetime, what: str) -> dt.datetime:
    if not isinstance(t, dt.datetime):
        raise IcalError(f"{what} must be a datetime, got {type(t).__name__}")
    if t.tzinfo is None:
        raise IcalError(f"{what} {t} is naive: give an aware datetime (e.g. UTC)")
    return t.astimezone(UTC)


@dataclass
class _Rule:
    rule: object
    until_utc: dt.datetime | None
    finite: bool


@dataclass
class _Master:
    uid: str
    start: When
    basis: Zone
    start_utc: dt.datetime
    exact: dt.timedelta | None          # duration from DTEND (exact)
    nominal: Duration | None            # duration from DURATION or the all-day default (nominal)
    rules: list[_Rule]
    exrules: list[_Rule]
    rdates: dict                        # UTC start -> exact timedelta | Duration | None (a PERIOD's length)
    exdates: set
    exdate_days: set
    flags: tuple[str, ...] = ()


def _end(basis: Zone, local_start: dt.datetime, start_utc: dt.datetime,
         exact: dt.timedelta | None, nominal: Duration | None) -> dt.datetime:
    if exact is not None:
        return start_utc + exact
    if nominal is not None:
        return basis.to_utc(local_start + dt.timedelta(days=nominal.days)) + dt.timedelta(seconds=nominal.seconds)
    return start_utc


def _build_rule(value: str, m_start: When, basis: Zone, what: str, flags: list[str]) -> _Rule:
    kw, raw = rrule_kwargs(value, what)
    until_utc = None
    if raw["UNTIL"]:
        u = parse_datetime_value(raw["UNTIL"], what=f"{what} UNTIL")
        if u.kind == "date":
            if m_start.kind != "date":
                flags.append(FLAG_UNTIL_TYPE)        # a DATE UNTIL on a DATE-TIME series: that whole local day
            until_utc = basis.to_utc(u.naive + dt.timedelta(days=1)) - dt.timedelta(microseconds=1)
        elif u.kind == "utc":
            if m_start.kind in ("date", "floating"):
                flags.append(FLAG_UNTIL_TYPE)
            until_utc = u.naive.replace(tzinfo=UTC)
        else:                                        # floating UNTIL: right only for a floating DTSTART
            if m_start.kind != "floating":
                flags.append(FLAG_UNTIL_TYPE)
            until_utc = basis.to_utc(u.naive)
        if raw["COUNT"]:
            # both (RFC: MUST NOT): honour both; dateutil gets COUNT only, UNTIL is the exact UTC cut
            flags.append(FLAG_COUNT_AND_UNTIL)
        else:
            kw["until"] = basis.to_local(until_utc) + dt.timedelta(days=1)   # slack; exact cut is in UTC
    return _Rule(_du.rrule(dtstart=m_start.naive, **kw), until_utc, bool(raw["UNTIL"] or raw["COUNT"]))


def _rule_has(m: _Master, r: _Rule, utc: dt.datetime) -> bool:
    """Whether `utc` is an instance of rule `r` (exact, in UTC; a DST-gap instance included)."""
    if r.until_utc is not None and utc > r.until_utc:
        return False
    local = m.basis.to_local(utc)
    span = dt.timedelta(hours=3)
    return any(m.basis.to_utc(h) == utc for h in r.rule.between(local - span, local + span, inc=True))


def _rule_instances(m: _Master, r: _Rule, lo: dt.datetime | None, hi: dt.datetime | None,
                    cap: int) -> list[dt.datetime]:
    """UTC starts of rule `r` inside [lo, hi], or every instance of a finite rule when lo is None."""
    locals_: list[dt.datetime] = []
    if lo is None:
        if not r.finite:
            raise IcalError(f"UID {m.uid}: RRULE has neither COUNT nor UNTIL, so it never ends: give a "
                            "window (start/end) to expand it in")
        it, b = iter(r.rule), None
    else:
        it = r.rule.xafter(m.basis.to_local(lo) - dt.timedelta(days=1), inc=True)
        b = m.basis.to_local(hi) + dt.timedelta(days=1)
    for x in it:
        if b is not None and x > b:
            break
        if len(locals_) >= cap:
            raise IcalError(f"UID {m.uid}: more than {cap} instances{' in the window' if lo else ''}; "
                            "narrow the window or raise max_instances")
        locals_.append(x)
    out = []
    for x in locals_:
        u = m.basis.to_utc(x)
        if r.until_utc is not None and u > r.until_utc:
            continue
        if lo is not None and not (lo <= u <= hi):
            continue
        out.append(u)
    return out


def _master(comp: Component, uid: str, resolver: Resolver) -> _Master:
    sp = comp.get("DTSTART")
    if sp is None:
        raise IcalError(f"UID {uid}: no DTSTART")
    start = prop_when(sp)
    basis = resolver.basis(start)
    start_utc = basis.to_utc(start.naive)
    flags: list[str] = []
    exact = nominal = None
    ep, dp = comp.get("DTEND"), comp.get("DURATION")
    if ep is not None and dp is not None:
        raise IcalError(f"UID {uid}: both DTEND and DURATION (RFC 5545 allows one)")
    if ep is not None:
        exact = resolver.to_utc(prop_when(ep), basis) - start_utc
        if exact < dt.timedelta(0):
            raise IcalError(f"UID {uid}: DTEND is before DTSTART")
    elif dp is not None:
        nominal = parse_duration(dp.value, what=f"UID {uid} DURATION")
    elif start.kind == "date":
        nominal = Duration(days=1)
    rules = [_build_rule(p.value, start, basis, f"UID {uid} RRULE (line {p.line})", flags)
             for p in comp.all("RRULE")]
    exrules = [_build_rule(p.value, start, basis, f"UID {uid} EXRULE (line {p.line})", flags)
               for p in comp.all("EXRULE")]
    rdates: dict = {}
    for p in comp.all("RDATE"):
        for w in prop_whens(p):
            if isinstance(w, tuple):
                s, other = w
                su = resolver.to_utc(s, basis)
                rdates.setdefault(su, (resolver.to_utc(other, basis) - su) if isinstance(other, When) else other)
            else:
                rdates.setdefault(resolver.to_utc(w, basis), None)
    exdates: set = set()
    exdays: set = set()
    for p in comp.all("EXDATE"):
        for w in prop_whens(p):
            if isinstance(w, tuple):
                raise IcalError(f"UID {uid}: EXDATE cannot be a PERIOD (line {p.line})")
            if w.kind == "date" and start.kind != "date":
                exdays.add(w.value)                  # a DATE EXDATE on a DATE-TIME series: that local day
            else:
                exdates.add(resolver.to_utc(w, basis))
    m = _Master(uid, start, basis, start_utc, exact, nominal, rules, exrules, rdates, exdates, exdays)
    if any(not _rule_has(m, r, start_utc) for r in rules):
        flags.append(FLAG_DTSTART_UNSYNCED)
    m.flags = tuple(dict.fromkeys(flags))
    return m


def _excluded(m: _Master, utc: dt.datetime) -> bool:
    if utc in m.exdates:
        return True
    if m.exdate_days and m.basis.to_local(utc).date() in m.exdate_days:
        return True
    return any(_rule_has(m, r, utc) for r in m.exrules)


def _nominal_source(m: _Master, utc: dt.datetime) -> str | None:
    """How `utc` belongs to the master's recurrence set before exclusions, or None."""
    if utc == m.start_utc:
        return "dtstart"
    if any(_rule_has(m, r, utc) for r in m.rules):
        return "rrule"
    if utc in m.rdates:
        return "rdate"
    return None


def _text_props(comp: Component) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in comp.props:
        if p.name in _STRUCTURAL or p.name in out:
            continue
        out[p.name] = p.value
    return out


def _sequence(comp: Component) -> int:
    p = comp.get("SEQUENCE")
    try:
        return int(p.value) if p is not None else 0
    except ValueError:
        raise IcalError(f"line {p.line}: SEQUENCE {p.value!r} is not an integer") from None


def _make(uid: str, rid: dt.datetime, start: dt.datetime, end: dt.datetime, all_day: bool,
          props: dict[str, str], *, overridden: bool, source: str, sequence: int,
          flags: Iterable[str]) -> Occurrence:
    def txt(k):
        return unescape_text(props[k]) if k in props else None

    status = txt("STATUS")
    return Occurrence(uid=uid, recurrence_id=rid, start=start, end=end, all_day=all_day,
                      summary=txt("SUMMARY"),
                      categories=tuple(split_text_list(props["CATEGORIES"])) if "CATEGORIES" in props else (),
                      status=status.strip().upper() if status else None, location=txt("LOCATION"),
                      description=txt("DESCRIPTION"), overridden=overridden, source=source,
                      sequence=sequence, flags=tuple(dict.fromkeys(flags)),
                      props=tuple((k, unescape_text(v)) for k, v in props.items()))


def _override_occ(m: _Master | None, uid: str, ov: Component, rid: dt.datetime, resolver: Resolver,
                  flags: list[str], master_props: dict[str, str]) -> Occurrence:
    """One instance replaced by its RECURRENCE-ID component."""
    flags = list(flags)
    series = m.basis if m else None
    sp = ov.get("DTSTART")
    if sp is not None:
        w = prop_when(sp)
        basis = series if (series is not None and w.kind in ("floating", "date")) else resolver.basis(w)
        start, local, all_day = basis.to_utc(w.naive), w.naive, w.kind == "date"
    else:
        basis = series or UTC_ZONE
        start, local = rid, basis.to_local(rid)
        all_day = bool(m and m.start.kind == "date")
    ep, dp = ov.get("DTEND"), ov.get("DURATION")
    if ep is not None:
        end = resolver.to_utc(prop_when(ep), series)
        if end < start:
            raise IcalError(f"UID {uid}: override DTEND is before its DTSTART (line {ep.line})")
    elif dp is not None:
        end = _end(basis, local, start, None, parse_duration(dp.value, what=f"UID {uid} override DURATION"))
    elif m is not None:
        end = _end(basis, local, start, m.exact, m.nominal)
        if m.exact or m.nominal:
            flags.append(INHERITED_PREFIX + "END")
    else:
        end = start
    props = _text_props(ov)
    for k in INHERITABLE:
        if k not in props and k in master_props:
            flags.append(INHERITED_PREFIX + k)
    for k, v in master_props.items():
        props.setdefault(k, v)
    return _make(uid, rid, start, end, all_day, props, overridden=True, source="override",
                 sequence=_sequence(ov), flags=flags)


def _expand_uid(uid: str, master_comp: Component | None, overrides: list[Component], resolver: Resolver,
                lo: dt.datetime | None, hi: dt.datetime | None, cap: int) -> list[Occurrence]:
    m = _master(master_comp, uid, resolver) if master_comp is not None else None
    series = m.basis if m else None
    # overrides keyed by UTC RECURRENCE-ID: the highest SEQUENCE wins, the later one on a tie
    by_rid: dict[dt.datetime, tuple[Component, bool]] = {}
    dup: set[dt.datetime] = set()
    for ov in overrides:
        rp = ov.get("RECURRENCE-ID")
        rid = resolver.to_utc(prop_when(rp), series)
        rng = (rp.param("RANGE") or "").upper()
        if rng not in ("", "THISANDFUTURE"):
            raise IcalError(f"UID {uid}: RECURRENCE-ID RANGE={rng} is not THISANDFUTURE (line {rp.line})")
        if rid in by_rid:
            dup.add(rid)
            if _sequence(ov) < _sequence(by_rid[rid][0]):
                continue
        by_rid[rid] = (ov, rng == "THISANDFUTURE")

    def dflag(rid):
        return [FLAG_DUPLICATE_OVERRIDE] if rid in dup else []

    if m is None:     # overrides with no master: every one is an orphan
        return [_override_occ(None, uid, ov, rid, resolver, [FLAG_ORPHAN] + dflag(rid), {})
                for rid, (ov, _t) in sorted(by_rid.items())]

    mprops = _text_props(master_comp)
    all_day = m.start.kind == "date"
    taf = sorted((rid, ov) for rid, (ov, t) in by_rid.items() if t)
    pad = dt.timedelta(days=2) + (m.exact if m.exact is not None else
                                  (m.nominal.upper if m.nominal else dt.timedelta(0)))
    for rid, ov in taf:
        sp = ov.get("DTSTART")
        if sp is not None:
            pad += abs(resolver.to_utc(prop_when(sp), series) - rid)
    glo = ghi = None
    if lo is not None:
        glo, ghi = lo - pad, hi + pad

    nominal: dict[dt.datetime, str] = {m.start_utc: "dtstart"}
    for r in m.rules:
        for u in _rule_instances(m, r, glo, ghi, cap):
            nominal.setdefault(u, "rrule")
    for u in m.rdates:
        nominal.setdefault(u, "rdate")
    if glo is not None:
        nominal = {u: s for u, s in nominal.items() if glo <= u <= ghi}
    nominal = {u: s for u, s in nominal.items() if not _excluded(m, u)}
    for rid in by_rid:               # every override's own instance, inside the window or not
        if rid not in nominal and not _excluded(m, rid):
            src = _nominal_source(m, rid)
            if src is not None:
                nominal[rid] = src

    out: list[Occurrence] = []
    base = list(m.flags)
    for rid in sorted(nominal):
        src = nominal[rid]
        fl = base + dflag(rid)
        if rid in by_rid:
            out.append(_override_occ(m, uid, by_rid[rid][0], rid, resolver, fl, mprops))
            continue
        exact, nom = m.exact, m.nominal
        rd = m.rdates.get(rid)
        if rd is not None:
            exact, nom = (rd, None) if isinstance(rd, dt.timedelta) else (None, rd)
        applies = [(r, ov) for r, ov in taf if r <= rid]
        if not applies:
            end = _end(m.basis, m.basis.to_local(rid), rid, exact, nom)
            out.append(_make(uid, rid, rid, end, all_day, mprops, overridden=False, source=src,
                             sequence=_sequence(master_comp), flags=fl))
            continue
        r0, ov = applies[-1]         # the latest THISANDFUTURE at or before this instance
        sp, ep, dp = ov.get("DTSTART"), ov.get("DTEND"), ov.get("DURATION")
        delta = (resolver.to_utc(prop_when(sp), series) - r0) if sp is not None else dt.timedelta(0)
        start = rid + delta
        if ep is not None and sp is not None:
            exact, nom = resolver.to_utc(prop_when(ep), series) - resolver.to_utc(prop_when(sp), series), None
        elif dp is not None:
            exact, nom = None, parse_duration(dp.value, what=f"UID {uid} override DURATION")
        props = dict(mprops)
        props.update(_text_props(ov))
        end = _end(m.basis, m.basis.to_local(start), start, exact, nom)
        out.append(_make(uid, rid, start, end, all_day, props, overridden=True, source="override",
                         sequence=_sequence(ov), flags=fl))
    for rid, (ov, _t) in sorted(by_rid.items()):
        if rid in nominal:
            continue
        removed = _nominal_source(m, rid) is not None      # a real instance that EXDATE/EXRULE removed
        fl = base + [FLAG_EXDATE_OVERRIDE if removed else FLAG_ORPHAN] + dflag(rid)
        out.append(_override_occ(m, uid, ov, rid, resolver, fl, mprops))
    return out


def expand(components: list[Component], *, start: dt.datetime | None = None, end: dt.datetime | None = None,
           floating_tz: str | None = None, kinds: Iterable[str] = ("VEVENT",),
           max_instances: int = DEFAULT_MAX_INSTANCES) -> Expansion:
    """Every instance of every `kinds` component, in UTC, sorted by (start, uid, recurrence_id).

    With `start`/`end` (aware datetimes) the recurrence set is generated around that window (padded
    for durations and THISANDFUTURE shifts; every override is placed exactly wherever its original
    instance falls), so unbounded rules can be expanded; use `select()` for membership. Without them
    every rule must be finite. Components that cannot be expanded are listed in `errors`."""
    _need_dateutil()
    if (start is None) != (end is None):
        raise IcalError("give both start and end, or neither")
    lo = hi = None
    if start is not None:
        lo, hi = _aware(start, "start"), _aware(end, "end")
        if hi < lo:
            raise IcalError(f"window end {hi} is before its start {lo}")
    kinds = {k.upper() for k in kinds}
    errors: list[str] = []
    vtz: dict[str, VTimezoneZone] = {}
    for root in components:
        for c in root.walk():
            if c.name == "VTIMEZONE":
                try:
                    z = build_vtimezone(c)
                    vtz[z.name] = z
                except IcalError as e:
                    errors.append(str(e))
    resolver = Resolver(vtz, floating_tz)
    groups: dict[str, tuple[list[Component], list[Component]]] = {}
    anon = 0
    for root in components:
        for c in root.walk():
            if c.name not in kinds:
                continue
            up = c.get("UID")
            uid = up.value.strip() if up is not None else ""
            if not uid:
                anon += 1
                uid = f"<no-uid #{anon}>"
                resolver.warnings.append(f"{c.name} at line {c.line} has no UID; named {uid!r}")
            groups.setdefault(uid, ([], []))[1 if c.get("RECURRENCE-ID") is not None else 0].append(c)
    occs: list[Occurrence] = []
    for uid, (masters, overrides) in groups.items():
        if len(masters) > 1:
            errors.append(f"UID {uid}: {len(masters)} master components (lines "
                          f"{', '.join(str(c.line) for c in masters)}); refusing to pick one")
            continue
        try:
            occs.extend(_expand_uid(uid, masters[0] if masters else None, overrides, resolver, lo, hi,
                                    max_instances))
        except IcalError as e:
            msg = str(e)
            errors.append(msg if msg.startswith("UID ") else f"UID {uid}: {msg}")
    occs.sort(key=lambda o: (o.start, o.uid, o.recurrence_id))
    return Expansion(occs, errors, list(resolver.warnings), (lo, hi) if lo is not None else None)


def expand_text(text: str | bytes, **kw) -> Expansion:
    return expand(parse(text), **kw)


BASES = ("start", "overlap")


def in_window(o: Occurrence, lo: dt.datetime, hi: dt.datetime, *, basis: str = "start",
              start_inclusive: bool = True, end_inclusive: bool = False) -> bool:
    """Membership of one occurrence. basis "start": its actual start lies in the window (bounds per
    the inclusive flags); "overlap": its [start, end) interval meets the window (an interval that
    ends exactly at the window start does not; a zero-length event is judged by its start)."""
    lo, hi = _aware(lo, "window start"), _aware(hi, "window end")
    before_hi = o.start <= hi if end_inclusive else o.start < hi
    if basis == "start" or (basis == "overlap" and o.end <= o.start):
        after_lo = o.start >= lo if start_inclusive else o.start > lo
        return after_lo and before_hi
    if basis == "overlap":
        return before_hi and o.end > lo
    raise IcalError(f"basis must be one of {BASES}, got {basis!r}")


def select(occs: Iterable[Occurrence], lo: dt.datetime, hi: dt.datetime, *, basis: str = "start",
           start_inclusive: bool = True, end_inclusive: bool = False, cancelled: str = "drop") -> list[Occurrence]:
    """The occurrences in the window, in input order. cancelled: drop | keep (STATUS:CANCELLED)."""
    if cancelled not in ("drop", "keep"):
        raise IcalError(f"cancelled must be 'drop' or 'keep', got {cancelled!r}")
    return [o for o in occs
            if in_window(o, lo, hi, basis=basis, start_inclusive=start_inclusive, end_inclusive=end_inclusive)
            and not (cancelled == "drop" and o.cancelled)]


def parse_instant(s: str, *, what: str = "time") -> dt.datetime:
    """An aware UTC datetime from ISO 8601 (with Z or an offset) or RFC 5545 basic UTC form. A value
    with no zone is refused: the caller says which zone it means."""
    raw = str(s).strip()
    try:
        t = dt.datetime.fromisoformat(raw[:-1] + "+00:00" if raw[-1:] in "Zz" and raw else raw)
    except ValueError:
        w = parse_datetime_value(raw, what=what)
        if w.kind != "utc":
            raise IcalError(f"{what}: {raw!r} has no UTC offset; give one (e.g. a trailing Z)") from None
        return w.naive.replace(tzinfo=UTC)
    if t.tzinfo is None:
        raise IcalError(f"{what}: {raw!r} has no UTC offset; give one (e.g. a trailing Z)")
    return t.astimezone(UTC)


# ======================================================================================
#  Engine entry (offline handout) and CLI
# ======================================================================================

MAX_ICS_FILES = 16
_SKIP_DIRS = {".git", "node_modules", "__pycache__"}
ICS_SUFFIXES = (".ics", ".ical", ".icalendar")


def find_calendars(root: Path) -> list[Path]:
    """`.ics` files, and files that start with BEGIN:VCALENDAR, under `root` (at most MAX_ICS_FILES)."""
    found = []
    for p in sorted(Path(root).rglob("*")):
        if len(found) >= MAX_ICS_FILES:
            break
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        try:
            if not p.is_file():
                continue
            if p.suffix.lower() in ICS_SUFFIXES:
                found.append(p)
            elif p.stat().st_size <= MAX_TEXT_BYTES:
                with p.open("rb") as fh:
                    if fh.read(64).lstrip(b"\xef\xbb\xbf \r\n\t").upper().startswith(b"BEGIN:VCALENDAR"):
                        found.append(p)
        except OSError:
            continue
    return found


def summarize(exp: Expansion, limit: int = 40) -> str:
    lines = [f"{len(exp.occurrences)} instance(s)"]
    for o in exp.occurrences[:limit]:
        tag = f" [{','.join(o.flags)}]" if o.flags else ""
        lines.append(f"  {iso_z(o.start)} .. {iso_z(o.end)}  {o.uid}  rid={iso_z(o.recurrence_id)}"
                     f"{'  (override)' if o.overridden else ''}{'  CANCELLED' if o.cancelled else ''}{tag}")
    if len(exp.occurrences) > limit:
        lines.append(f"  ... {len(exp.occurrences) - limit} more")
    lines += [f"  error: {e}" for e in exp.errors] + [f"  warning: {w}" for w in exp.warnings]
    return "\n".join(lines)


def solve(challenge_dir, profile=None, *, floating_tz: str | None = None, **_opts):
    """Expand every calendar in the handout (offline). `unsure` with the expansion in the notes (the
    window and attestation rules live in the brief: toolkits.ical_attest); `none` with no calendar;
    `blocked` without python-dateutil."""
    import time
    from ctf.result import Cost, Evidence, SolverResult
    t0 = time.process_time()
    if _du is None:
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes=f"python-dateutil is not installed ({_DU_ERROR}); install the pin in "
                                  "requirements.in")
    root = Path(challenge_dir)
    cals = find_calendars(root)
    if not cals:
        return SolverResult(status="none", engine=ENGINE_ID, notes=f"no iCalendar file under {root}")
    notes, ev = [], []
    for p in cals:
        rel = str(p.relative_to(root))
        try:
            exp = expand_text(p.read_bytes(), floating_tz=floating_tz)
        except IcalError as e:
            notes.append(f"{rel}: not expandable: {e}")
            continue
        ev.append(Evidence("decode", f"RFC 5545 expansion: {len(exp.occurrences)} instance(s), "
                                     f"{len(exp.errors)} component error(s)", path=rel))
        notes.append(f"{rel}: " + summarize(exp))
    return SolverResult(status="unsure", engine=ENGINE_ID, evidence=ev,
                        cost=Cost(seconds=round(time.process_time() - t0, 3)),
                        notes="\n".join(notes) + "\nNext: the window and attestation rules are in the "
                              "brief; run toolkits.ical_attest, or this script with --from/--to.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ical_expand", description=__doc__.split("\n")[0])
    ap.add_argument("ics", help="the .ics file (read as data)")
    ap.add_argument("--from", dest="lo", help="window start, ISO 8601 with offset (2026-07-20T00:00:00Z)")
    ap.add_argument("--to", dest="hi", help="window end")
    ap.add_argument("--basis", choices=BASES, default="start")
    ap.add_argument("--end-inclusive", action="store_true")
    ap.add_argument("--keep-cancelled", action="store_true")
    ap.add_argument("--floating-tz", help="zone for floating times and all-day dates (e.g. UTC)")
    ap.add_argument("--max-instances", type=int, default=DEFAULT_MAX_INSTANCES)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if (a.lo is None) != (a.hi is None):
        ap.error("give both --from and --to, or neither")
    try:
        lo = parse_instant(a.lo, what="--from") if a.lo else None
        hi = parse_instant(a.hi, what="--to") if a.hi else None
        exp = expand_text(Path(a.ics).read_bytes(), start=lo, end=hi, floating_tz=a.floating_tz,
                          max_instances=a.max_instances)
        if lo is not None:
            exp.occurrences = select(exp.occurrences, lo, hi, basis=a.basis, end_inclusive=a.end_inclusive,
                                     cancelled="keep" if a.keep_cancelled else "drop")
    except (IcalError, OSError) as e:
        print(f"ical_expand: {e}", file=sys.stderr)
        return 2
    print(json.dumps(exp.to_dict(), indent=1) if a.json else summarize(exp, limit=10_000))
    return 1 if exp.errors else 0


if __name__ == "__main__":
    sys.exit(main())
