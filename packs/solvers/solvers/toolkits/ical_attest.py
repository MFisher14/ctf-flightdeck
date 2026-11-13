#!/usr/bin/env python3
"""Live iCalendar attestation engine (B-103): spawn the instance, pull /brief and /case.ics, expand, attest.

The "rebuild the calendar" challenge family (CSCTF 9102 shape): a per-team container serves a JSON
brief (the response window, the membership and ordering rules, the attestation format) and an
exported `.ics`; the player expands the recurrences to UTC, keeps the instances in the window, and
POSTs one JSON attestation that returns the flag.

What runs with no model:

1. Lifecycle (B-003 path): with `challenge_id`, the instance is started (or re-read) through the
   event's platform adapter and the cross-process slot ledger (`ctf.instsched.start_capped`, the
   same cap `python -m ctf instance start` honours); its connect string becomes the target. Or pass
   `target` for an instance already running. The instance is never stopped by default: on this
   family the flag is per instance, so it must outlive the submission (`stop_after=1` tears it down
   after a flag is found).
2. Fetch: `GET /brief` and `GET /case.ics` through the scope-locked `web.WebClient` (ctf.scope:
   the host must be in `rules.live_service_scope`; the event platform is never a target).
3. Expand: `ical_expand` (RRULE/RDATE/EXDATE, RECURRENCE-ID overrides, TZID to UTC).
4. Map: a pluggable mapping turns brief + expansion into the attestation. The built-in `auto`
   mapping reads only what the brief states as structured JSON (window bounds, interval brackets,
   field lists, an example record or attestation, sort keys, time format) and merges a player spec
   (`spec=<file.json>`) over it. A rule it cannot read is `unknown`; an unknown that would change
   the answer (checked by computing every reading) makes the result `unsure`, with the draft and the
   missing parts named. Prose rules are never interpreted. `spec` is the strict mapping (every part
   given by the player). Others register with `register_mapping(name, fn)`.
5. Attest: only for a confident mapping, and only when the event allows state-changing web actions
   (`rules.web_state_changing`, BUILD-PLAN O-2): POST the JSON to `/attest` and read the flag from
   the response with the event flag format. Otherwise the attestation is written out for the player.

Everything the target returns (brief, calendar, attest response) is untrusted data: parsed, saved and
quoted as data, never followed as an instruction. Nothing is submitted to the platform.

Entry: `solve(challenge_dir, profile, *, target=None, challenge_id=None, ...) -> SolverResult`
(`python -m ctf run toolkits.ical_attest <dir> --opt challenge_id=9102`). Results: `solved` (flag in
the /attest response), `unsure` (mapping incomplete, attest not allowed, or rejected), `blocked`
(no target, out of scope, unreachable, no instance plugin, at the slot cap).

Spec file (JSON; any part may be left out in `auto` mode):

    {"window": {"start": "brief:window.start", "end": "2026-08-04T00:00:00Z",
                "start_inclusive": true, "end_inclusive": false, "basis": "start"},
     "cancelled": "drop",
     "order": ["start", "uid"],                        # sources or output names; "-x" = descending
     "fields": {"uid": "uid", "recurrence_id_utc": "recurrence_id", "start_utc": "start",
                "end_utc": "end", "category": "category"},
     "time_format": "iso-z",                           # iso-z | iso-ms-z | iso-offset | ical | epoch | epoch-ms | strftime
     "envelope": {"records": "activations", "extra": {"count": "$count"}},   # null = a bare JSON list
     "accept_flags": ["inherited:END"]}
"""
from __future__ import annotations

import datetime as dt
import itertools
import json
import re
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
import ical_expand as ix     # noqa: E402  (the RFC 5545 expander, same lane)

ENGINE_ID = "toolkits.ical_attest"
UTC = dt.timezone.utc
MAX_BRIEF_ECHO = 1500
MAX_RESPONSE_ECHO = 800

TIME_FORMATS = ("iso-z", "iso-ms-z", "iso-offset", "ical", "epoch", "epoch-ms")
SOURCES = ("uid", "recurrence_id", "start", "end", "summary", "category", "categories", "status",
           "location", "description", "duration_seconds", "all_day")
TIME_SOURCES = frozenset({"recurrence_id", "start", "end"})
# the iCalendar property each descriptive source reads (for "inherited:<PROP>" relevance)
_SOURCE_PROP = {"summary": "SUMMARY", "category": "CATEGORIES", "categories": "CATEGORIES",
                "status": "STATUS", "location": "LOCATION", "description": "DESCRIPTION"}
DEFAULT_ORDER = (("start", False), ("uid", False), ("recurrence_id", False))
DEFAULT_FIELDS = (("uid", "uid"), ("recurrence_id", "recurrence_id"), ("start", "start"), ("end", "end"))


class AttestError(ValueError):
    """A spec, brief or mapping problem, named."""


# ======================================================================================
#  The attestation spec
# ======================================================================================

@dataclass(frozen=True)
class Envelope:
    records: str | None = None                   # None: the attestation is a bare JSON list
    extra: tuple[tuple[str, Any], ...] = ()      # other top-level keys; "$count", "$window.start", "$window.end"


@dataclass(frozen=True)
class AttestSpec:
    """Every part None = unknown. `apply_spec` needs all of them; `auto` resolves what it can."""
    window_start: dt.datetime | None = None
    window_end: dt.datetime | None = None
    start_inclusive: bool | None = None
    end_inclusive: bool | None = None
    basis: str | None = None                     # start | overlap
    cancelled: str | None = None                 # drop | keep
    order: tuple[tuple[str, bool], ...] | None = None    # (source, descending)
    fields: tuple[tuple[str, str], ...] | None = None    # (output name, source)
    time_format: str | None = None
    envelope: Envelope | None = None
    accept_flags: tuple[str, ...] = ()
    envelope_known: bool = False                 # envelope=None can mean "bare list" (known) or unknown

    def unknown(self) -> list[str]:
        out = [n for n in ("window_start", "window_end", "start_inclusive", "end_inclusive", "basis",
                           "cancelled", "order", "fields", "time_format") if getattr(self, n) is None]
        if not self.envelope_known:
            out.append("envelope")
        return out

    def to_dict(self) -> dict:
        def b(t):
            return ix.iso_z(t) if t is not None else None
        return {"window": {"start": b(self.window_start), "end": b(self.window_end),
                           "start_inclusive": self.start_inclusive, "end_inclusive": self.end_inclusive,
                           "basis": self.basis},
                "cancelled": self.cancelled,
                "order": [("-" if d else "") + s for s, d in self.order] if self.order is not None else None,
                "fields": dict(self.fields) if self.fields is not None else None,
                "time_format": self.time_format,
                "envelope": (({"records": self.envelope.records, "extra": dict(self.envelope.extra)}
                              if self.envelope and self.envelope.records else None)
                             if self.envelope_known else "UNKNOWN"),
                "accept_flags": list(self.accept_flags), "unknown": self.unknown()}


def _bool(v: Any, what: str) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):        # `ctf run --opt x=0` arrives as an int
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"):
        return True
    if isinstance(v, str) and v.strip().lower() in ("0", "false", "no", "off"):
        return False
    raise AttestError(f"{what} must be true/false, got {v!r}")


def _dig(obj: Any, path: str) -> Any:
    cur = obj
    for part in [p for p in path.split(".") if p]:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            raise AttestError(f"brief has no {path!r} (stopped at {part!r})")
    return cur


def _instant(v: Any, what: str, brief: Any = None) -> dt.datetime:
    if isinstance(v, str) and v.startswith("brief:"):
        if brief is None:
            raise AttestError(f"{what} refers to the brief ({v!r}) but there is no brief")
        v = _dig(brief, v[len("brief:"):])
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return dt.datetime.fromtimestamp(v / 1000 if v > 1e11 else v, UTC)
    try:
        return ix.parse_instant(str(v), what=what)
    except ix.IcalError as e:
        raise AttestError(str(e)) from None


def _source(name: str, what: str) -> str:
    s = str(name).strip()
    if s in SOURCES or (s.lower().startswith("prop:") and len(s) > 5):
        return s if s in SOURCES else "prop:" + s[5:].upper()
    raise AttestError(f"{what}: unknown source {name!r}; known: {list(SOURCES)} or prop:<NAME>")


def _check_format(fmt: str, what: str = "time_format") -> str:
    if fmt in TIME_FORMATS or "%" in fmt:
        return fmt
    raise AttestError(f"{what} {fmt!r} is not one of {list(TIME_FORMATS)} or a strftime pattern")


def spec_from_dict(d: dict, *, brief: Any = None) -> AttestSpec:
    """A (possibly partial) spec from its JSON form. Unknown keys and bad values raise AttestError."""
    if not isinstance(d, dict):
        raise AttestError(f"a spec is a JSON object, got {type(d).__name__}")
    extra = set(d) - {"window", "cancelled", "order", "fields", "time_format", "envelope", "accept_flags"}
    if extra:
        raise AttestError(f"unknown spec key(s): {sorted(extra)}")
    kw: dict = {}
    w = d.get("window") or {}
    if not isinstance(w, dict):
        raise AttestError("spec window must be an object")
    wextra = set(w) - {"start", "end", "start_inclusive", "end_inclusive", "basis"}
    if wextra:
        raise AttestError(f"unknown spec window key(s): {sorted(wextra)}")
    if w.get("start") is not None:
        kw["window_start"] = _instant(w["start"], "window.start", brief)
    if w.get("end") is not None:
        kw["window_end"] = _instant(w["end"], "window.end", brief)
    for k in ("start_inclusive", "end_inclusive"):
        if w.get(k) is not None:
            kw[k] = _bool(w[k], f"window.{k}")
    if w.get("basis") is not None:
        if w["basis"] not in ix.BASES:
            raise AttestError(f"window.basis must be one of {ix.BASES}, got {w['basis']!r}")
        kw["basis"] = w["basis"]
    if d.get("cancelled") is not None:
        if d["cancelled"] not in ("drop", "keep"):
            raise AttestError(f"cancelled must be 'drop' or 'keep', got {d['cancelled']!r}")
        kw["cancelled"] = d["cancelled"]
    fields = None
    if d.get("fields") is not None:
        if not isinstance(d["fields"], dict) or not d["fields"]:
            raise AttestError("spec fields must be a non-empty object {output name: source}")
        fields = tuple((str(k), _source(v, f"fields.{k}")) for k, v in d["fields"].items())
        kw["fields"] = fields
    if d.get("order") is not None:
        kw["order"] = parse_order(d["order"], fields)
    if d.get("time_format") is not None:
        kw["time_format"] = _check_format(str(d["time_format"]))
    if "envelope" in d:
        kw["envelope_known"] = True
        env = d["envelope"]
        if env is None:
            kw["envelope"] = None
        elif isinstance(env, dict) and isinstance(env.get("records"), str) and env["records"]:
            eextra = set(env) - {"records", "extra"}
            if eextra:
                raise AttestError(f"unknown spec envelope key(s): {sorted(eextra)}")
            ex = env.get("extra") or {}
            if not isinstance(ex, dict):
                raise AttestError("envelope.extra must be an object")
            if env["records"] in ex:
                raise AttestError(f"envelope.extra repeats the records key {env['records']!r}")
            kw["envelope"] = Envelope(env["records"], tuple(ex.items()))
        else:
            raise AttestError("spec envelope must be null (a bare list) or {\"records\": KEY, \"extra\": {...}}")
    if d.get("accept_flags") is not None:
        af = d["accept_flags"]
        if not isinstance(af, list) or not all(isinstance(x, str) for x in af):
            raise AttestError("accept_flags must be a list of flag names")
        kw["accept_flags"] = tuple(af)
    return AttestSpec(**kw)


def parse_order(v: Any, fields: tuple[tuple[str, str], ...] | None = None) -> tuple[tuple[str, bool], ...]:
    """["start", "-uid"], [["start", "asc"]], or "start_utc asc, uid desc". Output names map to sources."""
    names = dict(fields or ())
    items: list = []
    if isinstance(v, str):
        items = [x.strip().split() for x in v.split(",") if x.strip()]
    elif isinstance(v, list):
        for x in v:
            items.append(x if isinstance(x, list) else str(x).split())
    else:
        raise AttestError(f"order must be a list or a string, got {type(v).__name__}")
    out = []
    for it in items:
        if not it or len(it) > 2:
            raise AttestError(f"bad order item {it!r}")
        name, desc = str(it[0]), False
        if name.startswith("-"):
            name, desc = name[1:], True
        if len(it) == 2:
            d = str(it[1]).lower()
            if d not in ("asc", "desc", "ascending", "descending"):
                raise AttestError(f"order direction {it[1]!r} is not asc/desc")
            desc = d.startswith("desc")
        src = names.get(name) or _alias(name) or name
        out.append((_source(src, "order"), desc))
    if not out:
        raise AttestError("order is empty")
    return tuple(out)


def merge(base: AttestSpec, over: AttestSpec) -> AttestSpec:
    """`over`'s known parts win over `base`'s."""
    kw = {}
    for f in ("window_start", "window_end", "start_inclusive", "end_inclusive", "basis", "cancelled",
              "order", "fields", "time_format"):
        v = getattr(over, f)
        kw[f] = v if v is not None else getattr(base, f)
    if over.envelope_known:
        kw["envelope"], kw["envelope_known"] = over.envelope, True
    else:
        kw["envelope"], kw["envelope_known"] = base.envelope, base.envelope_known
    kw["accept_flags"] = tuple(dict.fromkeys(base.accept_flags + over.accept_flags))
    return AttestSpec(**kw)


# ======================================================================================
#  Applying a complete spec
# ======================================================================================

def format_time(t: dt.datetime, fmt: str) -> Any:
    t = t.astimezone(UTC)
    if fmt == "iso-z":
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    if fmt == "iso-ms-z":
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    if fmt == "iso-offset":
        return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    if fmt == "ical":
        return t.strftime("%Y%m%dT%H%M%SZ")
    if fmt == "epoch":
        return int(t.timestamp())
    if fmt == "epoch-ms":
        return int(t.timestamp() * 1000)
    return t.strftime(_check_format(fmt))


def _value(o: ix.Occurrence, src: str, fmt: str) -> Any:
    if src in TIME_SOURCES:
        return format_time(getattr(o, src), fmt)
    if src == "duration_seconds":
        return int((o.end - o.start).total_seconds())
    if src == "categories":
        return list(o.categories)
    if src.startswith("prop:"):
        return o.prop(src[5:])
    return getattr(o, src)


def _sort_key(o: ix.Occurrence, src: str) -> Any:
    v = getattr(o, src) if src in TIME_SOURCES else _value(o, src, "iso-z")
    if isinstance(v, list):
        v = ",".join(v)
    return (v is None, v if v is not None else "")


def order_occurrences(occs: list[ix.Occurrence], order: tuple[tuple[str, bool], ...]) -> list[ix.Occurrence]:
    out = list(occs)
    for src, desc in reversed(order):                  # stable sorts, least significant key first
        out.sort(key=lambda o, s=src: _sort_key(o, s), reverse=desc)
    return out


def apply_spec(spec: AttestSpec, occs: list[ix.Occurrence]) -> tuple[Any, list[ix.Occurrence]]:
    """(attestation payload, the selected occurrences in order). Every spec part must be known."""
    missing = spec.unknown()
    if missing:
        raise AttestError(f"spec is incomplete: {missing}")
    sel = ix.select(occs, spec.window_start, spec.window_end, basis=spec.basis,
                    start_inclusive=spec.start_inclusive, end_inclusive=spec.end_inclusive,
                    cancelled=spec.cancelled)
    sel = order_occurrences(sel, spec.order)
    records = [{name: _value(o, src, spec.time_format) for name, src in spec.fields} for o in sel]
    env = spec.envelope
    if env is None or env.records is None:
        return records, sel
    payload: dict = {}
    for k, v in env.extra:
        payload[k] = {"$count": len(records), "$window.start": format_time(spec.window_start, spec.time_format),
                      "$window.end": format_time(spec.window_end, spec.time_format)}.get(v, v) \
            if isinstance(v, str) else v
    payload[env.records] = records
    return payload, sel


def relevant_flags(o: ix.Occurrence, spec: AttestSpec) -> list[str]:
    """The instance flags that could change this attestation (minus accept_flags)."""
    used = {src for _n, src in (spec.fields or DEFAULT_FIELDS)} | {s for s, _d in (spec.order or ())}
    props = {_SOURCE_PROP[s] for s in used if s in _SOURCE_PROP} | {s[5:] for s in used if s.startswith("prop:")}
    out = []
    for f in o.flags:
        if f in spec.accept_flags:
            continue
        if f.startswith(ix.INHERITED_PREFIX):
            what = f[len(ix.INHERITED_PREFIX):]
            if what == "END" and not ({"end", "duration_seconds"} & used or spec.basis != "start"):
                continue
            if what == "STATUS" and not (o.cancelled or "STATUS" in props):
                continue
            if what not in ("END", "STATUS") and what not in props:
                continue
        out.append(f)
    return out


# ======================================================================================
#  Reading the brief (structured JSON only; prose is never interpreted)
# ======================================================================================

_ALIASES = {
    "uid": ("uid", "event_uid", "master_uid", "calendar_uid"),
    "recurrence_id": ("recurrence_id", "recurrence_id_utc", "rid", "original_start", "original_start_utc",
                      "recurrenceid", "recurrence_id_z"),
    "start": ("start", "start_utc", "dtstart", "actual_start", "actual_start_utc", "start_time", "starts_at",
              "dtstart_utc"),
    "end": ("end", "end_utc", "dtend", "actual_end", "actual_end_utc", "end_time", "ends_at", "dtend_utc"),
    "summary": ("summary", "title"),
    "category": ("category",),
    "categories": ("categories",),
    "status": ("status",),
    "location": ("location",),
    "description": ("description",),
    "duration_seconds": ("duration_seconds", "duration_s", "duration_sec"),
}
_ALIAS = {a: src for src, names in _ALIASES.items() for a in names}


def _norm(k: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(k).strip().lower())


def _alias(name: str) -> str | None:
    return _ALIAS.get(_norm(name))


_WINDOW_KEYS = re.compile(r"window|range|period|interval|span")
_START_KEYS = {"start": None, "from": None, "begin": None, "start_utc": None, "starts": None,
               "window_start": None, "start_time": None, "since": None,
               "not_before": True, "after": False, "start_inclusive": True, "start_exclusive": False,
               "inclusive_start": True, "exclusive_start": False}
_END_KEYS = {"end": None, "to": None, "end_utc": None, "ends": None, "window_end": None, "end_time": None,
             "until": None, "before": False, "not_after": True, "end_inclusive": True, "end_exclusive": False,
             "inclusive_end": True, "exclusive_end": False}
_INTERVAL = re.compile(r"^\s*([\[\(])\s*([^,;\s]+)\s*[,;]\s*([^,;\s\]\)]+)\s*([\]\)])\s*$")
_FIELD_LIST_KEYS = {"fields", "record_fields", "columns", "keys", "schema", "record_schema", "record",
                    "record_format", "attestation_fields", "record_keys", "required_fields"}
_EXAMPLE_KEYS = {"example", "sample", "example_record", "sample_record", "record_example"}
_ATTEST_EXAMPLE_KEYS = {"example_attestation", "attestation_example", "sample_attestation",
                        "attestation", "format", "attestation_format"}
_ORDER_KEYS = {"order", "ordering", "sort", "sort_by", "sorted_by", "order_by", "sort_order"}
_FORMAT_KEYS = {"time_format", "timestamp_format", "datetime_format", "date_format", "time_encoding"}
_BASIS_KEYS = {"basis", "membership", "filter_on", "compare", "match_on", "membership_basis"}
_BASIS_VALUES = {"start": "start", "dtstart": "start", "actual_start": "start", "start_utc": "start",
                 "actual_dtstart": "start", "overlap": "overlap", "overlaps": "overlap",
                 "intersect": "overlap", "intersects": "overlap"}
_CANCEL_KEYS = {"include_cancelled": "keep", "exclude_cancelled": "drop", "drop_cancelled": "drop",
                "keep_cancelled": "keep"}
_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ISO_MS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_ISO_OFF = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
_ICAL_Z = re.compile(r"^\d{8}T\d{6}Z$")
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FORMAT_WORDS = {"yyyy-mm-ddthh:mm:ssz": "iso-z", "%y-%m-%dt%h:%m:%sz": "iso-z",
                 "yyyymmddthhmmssz": "ical", "%y%m%dt%h%m%sz": "ical",
                 "yyyy-mm-ddthh:mm:ss.sssz": "iso-ms-z", "unix": "epoch", "epoch": "epoch",
                 "unix_seconds": "epoch", "epoch_seconds": "epoch", "epoch_ms": "epoch-ms",
                 "unix_ms": "epoch-ms"}


def _detect_format(v: Any) -> str | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return "epoch-ms" if v > 1e11 else ("epoch" if v > 1e8 else None)
    if not isinstance(v, str):
        return None
    for rx, name in ((_ISO_Z, "iso-z"), (_ISO_MS_Z, "iso-ms-z"), (_ISO_OFF, "iso-offset"), (_ICAL_Z, "ical")):
        if rx.match(v.strip()):
            return name
    return None


def _walk(obj: Any, depth: int = 0, path: tuple = ()):
    """(path, key, value) for every dict entry, at most 4 levels deep, not inside lists of records."""
    if depth > 4 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        yield path, str(k), v
        if isinstance(v, dict):
            yield from _walk(v, depth + 1, path + (str(k),))


def _mentions_utc(brief: Any) -> bool:
    return "utc" in json.dumps(brief, default=str).lower()


@dataclass
class Inference:
    spec: AttestSpec
    notes: list[str] = field(default_factory=list)


def infer_spec(brief: Any) -> Inference:
    """Read the attestation spec from a JSON brief, part by part. A part the brief does not state as
    structured data stays unknown (None). Prose is never read for rules."""
    notes: list[str] = []
    if not isinstance(brief, dict):
        return Inference(AttestSpec(), ["the brief is not a JSON object: every rule is prose to the engine"])
    kw: dict = {}
    utc_ok = _mentions_utc(brief)

    def bound(v, what):
        if isinstance(v, str) and _DATE_ONLY.match(v.strip()):
            if not utc_ok:
                notes.append(f"{what} {v!r} is a date with no zone and the brief never says UTC: left unknown")
                return None
            v = v.strip() + "T00:00:00Z"
            notes.append(f"{what}: date {v[:10]} read as 00:00 UTC (the brief says UTC)")
        try:
            return _instant(v, what)
        except AttestError as e:
            notes.append(f"{what}: {e}")
            return None

    # -- window
    for path, k, v in _walk(brief):
        nk = _norm(k)
        if _WINDOW_KEYS.search(nk) and isinstance(v, str):
            m = _INTERVAL.match(v)
            if m and "window_start" not in kw:
                a, b = bound(m[2], f"{k} start"), bound(m[3], f"{k} end")
                if a and b:
                    kw.update(window_start=a, window_end=b, start_inclusive=m[1] == "[",
                              end_inclusive=m[4] == "]")
                    notes.append(f"window from interval {v!r}")
            elif re.fullmatch(r"\S+/\S+", v.strip()) and "window_start" not in kw:
                a_s, _, b_s = v.partition("/")
                a, b = bound(a_s, f"{k} start"), bound(b_s, f"{k} end")
                if a and b:
                    kw.update(window_start=a, window_end=b)
                    notes.append(f"window from ISO interval {v!r} (bound inclusivity not stated)")
    candidates = [((), "(brief)", brief)] + [t for t in _walk(brief) if isinstance(t[2], dict)]
    for path, k, v in candidates:
        if "window_start" in kw:
            break
        sv = {_norm(kk): vv for kk, vv in v.items()}
        explicit = "window_start" in sv and "window_end" in sv
        named = k != "(brief)" and bool(_WINDOW_KEYS.search(_norm(k)))
        if not (explicit or named):
            continue                          # a dict is a window by its name, or by window_start/_end keys
        if explicit:
            s_hits, e_hits = [("window_start", None)], [("window_end", None)]
        else:
            s_hits = [(kk, inc) for kk, inc in _START_KEYS.items() if kk in sv and not isinstance(sv[kk], bool)]
            e_hits = [(kk, inc) for kk, inc in _END_KEYS.items() if kk in sv and not isinstance(sv[kk], bool)]
        if len(s_hits) != 1 or len(e_hits) != 1:
            if s_hits or e_hits:
                notes.append(f"{k}: start/end keys are ambiguous ({[h for h, _ in s_hits + e_hits]}): "
                             "left unknown")
            continue
        a = bound(sv[s_hits[0][0]], f"{k}.{s_hits[0][0]}")
        b = bound(sv[e_hits[0][0]], f"{k}.{e_hits[0][0]}")
        if not (a and b):
            continue
        kw.update(window_start=a, window_end=b)
        if s_hits[0][1] is not None:
            kw["start_inclusive"] = s_hits[0][1]
        if e_hits[0][1] is not None:
            kw["end_inclusive"] = e_hits[0][1]
        for flag_key, target, same in (("end_inclusive", "end_inclusive", True),
                                       ("end_exclusive", "end_inclusive", False),
                                       ("start_inclusive", "start_inclusive", True),
                                       ("start_exclusive", "start_inclusive", False)):
            if isinstance(sv.get(flag_key), bool):
                kw[target] = sv[flag_key] if same else not sv[flag_key]
        notes.append(f"window from {'.'.join(path + (k,)) if k != '(brief)' else 'the brief top level'}")
    # -- basis / cancelled / order / format / fields / envelope
    example_records: list[dict] = []
    for path, k, v in _walk(brief):
        nk = _norm(k)
        if nk in _BASIS_KEYS and isinstance(v, str) and _norm(v) in _BASIS_VALUES and "basis" not in kw:
            kw["basis"] = _BASIS_VALUES[_norm(v)]
        if nk in _CANCEL_KEYS and isinstance(v, bool) and "cancelled" not in kw:
            pol = _CANCEL_KEYS[nk]
            kw["cancelled"] = pol if v else ("drop" if pol == "keep" else "keep")
        if nk in _FORMAT_KEYS and isinstance(v, str) and "time_format" not in kw:
            fmt = _FORMAT_WORDS.get(v.strip().lower()) or (_check_format(v) if "%" in v else None)
            if fmt:
                kw["time_format"] = fmt
            else:
                notes.append(f"{k} {v!r}: not a time format the engine knows: left unknown")
        if nk in _EXAMPLE_KEYS and isinstance(v, dict):
            example_records.append(v)
        if nk in _ATTEST_EXAMPLE_KEYS and isinstance(v, (dict, list)):
            lists = [(kk, vv) for kk, vv in (v.items() if isinstance(v, dict) else [(None, v)])
                     if isinstance(vv, list) and vv and all(isinstance(r, dict) for r in vv)]
            if len(lists) == 1:
                rk, recs = lists[0]
                example_records.extend(recs)
                if rk is None:
                    kw["envelope"], kw["envelope_known"] = None, True
                else:
                    extra, unknown = [], []
                    for kk, vv in v.items():
                        if kk == rk:
                            continue
                        nkk = _norm(kk)
                        if nkk in ("count", "total", "n", "record_count", "activation_count"):
                            extra.append((kk, "$count"))
                        elif nkk in ("window_start", "start"):
                            extra.append((kk, "$window.start"))
                        elif nkk in ("window_end", "end"):
                            extra.append((kk, "$window.end"))
                        else:
                            unknown.append(kk)
                    if unknown:
                        notes.append(f"example attestation keys {unknown}: meaning not stated: envelope unknown")
                    else:
                        kw["envelope"], kw["envelope_known"] = Envelope(rk, tuple(extra)), True
                        notes.append(f"envelope from the example attestation: records under {rk!r}")
    for path, k, v in _walk(brief):
        nk = _norm(k)
        if nk in _ORDER_KEYS and "order" not in kw and isinstance(v, (str, list)):
            try:
                kw["order"] = parse_order(v)
                notes.append(f"order from {k!r}")
            except AttestError as e:
                notes.append(f"{k}: {e}: left unknown")
        if nk in _FIELD_LIST_KEYS and "fields" not in kw:
            names = v if isinstance(v, list) else (list(v) if isinstance(v, dict) else None)
            if names and all(isinstance(x, str) for x in names):
                mapped = [(n, _alias(n)) for n in names]
                bad = [n for n, s in mapped if s is None]
                if bad:
                    notes.append(f"record fields {bad} have no known source: fields unknown")
                else:
                    kw["fields"] = tuple(mapped)
                    notes.append(f"fields from {k!r}: {names}")
    if "fields" not in kw and example_records:
        names = list(example_records[0])
        mapped = [(n, _alias(n)) for n in names]
        bad = [n for n, s in mapped if s is None]
        if bad:
            notes.append(f"example record fields {bad} have no known source: fields unknown")
        else:
            kw["fields"] = tuple(mapped)
            notes.append(f"fields from the example record: {names}")
    if "time_format" not in kw and example_records and kw.get("fields"):
        seen = {_detect_format(r.get(n)) for r in example_records for n, s in kw["fields"]
                if s in TIME_SOURCES and n in r}
        seen.discard(None)
        if len(seen) == 1:
            kw["time_format"] = seen.pop()
            notes.append(f"time format {kw['time_format']} from the example values")
        elif len(seen) > 1:
            notes.append(f"example time values disagree on format ({sorted(seen)}): left unknown")
    return Inference(AttestSpec(**kw), notes)


# ======================================================================================
#  Mappings (pluggable)
# ======================================================================================

@dataclass
class MappingOutcome:
    status: str                                  # ok | unsure
    payload: Any = None                          # the attestation (a draft when unsure), or None
    spec: AttestSpec | None = None               # the spec actually applied (defaults filled in)
    unknown: list[str] = field(default_factory=list)      # parts that change the answer and are unknown
    defaulted: list[str] = field(default_factory=list)    # unknown parts that provably do not matter
    flagged: list[str] = field(default_factory=list)      # instance flags that could change the answer
    notes: list[str] = field(default_factory=list)
    expansion: ix.Expansion | None = None
    selected: list[ix.Occurrence] = field(default_factory=list)


MappingFn = Callable[..., MappingOutcome]
_MAPPINGS: dict[str, MappingFn] = {}


def register_mapping(name: str, fn: MappingFn) -> None:
    """Add a mapping: fn(brief, components, *, spec, floating_tz, max_instances) -> MappingOutcome."""
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", name or ""):
        raise AttestError(f"mapping name {name!r} must be lower-case [a-z0-9_-]")
    if not callable(fn):
        raise AttestError(f"mapping {name!r} is not callable")
    _MAPPINGS[name] = fn


def get_mapping(name: str) -> MappingFn:
    if name not in _MAPPINGS:
        raise AttestError(f"unknown mapping {name!r}; registered: {sorted(_MAPPINGS)}")
    return _MAPPINGS[name]


def mappings() -> list[str]:
    return sorted(_MAPPINGS)


_MEMBERSHIP = ("start_inclusive", "end_inclusive", "basis", "cancelled")
_MEMBERSHIP_DEFAULTS = {"start_inclusive": True, "end_inclusive": False, "basis": "start", "cancelled": "drop"}
_MEMBERSHIP_CHOICES = {"start_inclusive": (True, False), "end_inclusive": (False, True),
                       "basis": ("start", "overlap"), "cancelled": ("drop", "keep")}


def resolve(spec: AttestSpec, components: list, *, floating_tz: str | None = None,
            max_instances: int = ix.DEFAULT_MAX_INSTANCES) -> MappingOutcome:
    """Expand in the spec's window, fill every unknown part that provably does not change the
    answer, and say which unknown parts (and which instance flags) would."""
    if spec.window_start is None or spec.window_end is None:
        return MappingOutcome("unsure", unknown=[p for p in ("window_start", "window_end")
                                                 if getattr(spec, p) is None],
                              notes=["no response window: give it in the spec (window.start/end)"], spec=spec)
    exp = ix.expand(components, start=spec.window_start, end=spec.window_end, floating_tz=floating_tz,
                    max_instances=max_instances)
    unknown, defaulted, notes = [], [], []
    filled = {}
    unknown_m = [p for p in _MEMBERSHIP if getattr(spec, p) is None]
    if unknown_m:
        readings = set()
        for combo in itertools.product(*(_MEMBERSHIP_CHOICES[p] for p in unknown_m)):
            s = replace(spec, **dict(zip(unknown_m, combo)))
            readings.add(tuple((o.uid, o.recurrence_id) for o in ix.select(
                exp.occurrences, s.window_start, s.window_end, basis=s.basis,
                start_inclusive=s.start_inclusive, end_inclusive=s.end_inclusive, cancelled=s.cancelled)))
        if len(readings) == 1:
            defaulted += unknown_m
        else:
            unknown += unknown_m
            notes.append(f"membership differs across the unstated rules {unknown_m}: "
                         f"{sorted(len(r) for r in readings)} instances depending on the reading")
        filled.update({p: _MEMBERSHIP_DEFAULTS[p] for p in unknown_m})
    s = replace(spec, **filled)
    sel = ix.select(exp.occurrences, s.window_start, s.window_end, basis=s.basis,
                    start_inclusive=s.start_inclusive, end_inclusive=s.end_inclusive, cancelled=s.cancelled)
    if s.order is None:
        (unknown if len(sel) > 1 else defaulted).append("order")
        s = replace(s, order=DEFAULT_ORDER)
    if s.fields is None:
        unknown.append("fields")
        s = replace(s, fields=DEFAULT_FIELDS)
    if s.time_format is None:
        uses_time = any(src in TIME_SOURCES for _n, src in s.fields) or any(
            v in ("$window.start", "$window.end") for _k, v in (s.envelope.extra if s.envelope else ()))
        (unknown if uses_time else defaulted).append("time_format")
        s = replace(s, time_format="iso-z")
    if not s.envelope_known:
        unknown.append("envelope")
        s = replace(s, envelope=None, envelope_known=True)
    payload, ordered = apply_spec(s, exp.occurrences)
    # flags on any instance some reading of the window would take
    near = ix.select(exp.occurrences, s.window_start, s.window_end, basis="overlap", start_inclusive=True,
                     end_inclusive=True, cancelled="keep")
    near += [o for o in ix.select(exp.occurrences, s.window_start, s.window_end, basis="start",
                                  end_inclusive=True, cancelled="keep") if o not in near]
    flagged = sorted({f"{o.uid}@{ix.iso_z(o.recurrence_id)}: {f}" for o in near for f in relevant_flags(o, s)})
    if exp.errors:
        notes += [f"calendar error: {e}" for e in exp.errors]
    status = "ok" if not (unknown or flagged or exp.errors) else "unsure"
    return MappingOutcome(status, payload, s, unknown, defaulted, flagged, notes, exp, ordered)


def _auto(brief: Any, components: list, *, spec: AttestSpec | None = None, floating_tz: str | None = None,
          max_instances: int = ix.DEFAULT_MAX_INSTANCES) -> MappingOutcome:
    inf = infer_spec(brief)
    s = merge(inf.spec, spec) if spec is not None else inf.spec
    out = resolve(s, components, floating_tz=floating_tz, max_instances=max_instances)
    out.notes = inf.notes + out.notes
    return out


def _strict(brief: Any, components: list, *, spec: AttestSpec | None = None, floating_tz: str | None = None,
            max_instances: int = ix.DEFAULT_MAX_INSTANCES) -> MappingOutcome:
    if spec is None:
        raise AttestError("mapping 'spec' needs a spec (opt spec=<file.json>)")
    missing = spec.unknown()
    if missing:
        raise AttestError(f"mapping 'spec' needs every part; missing {missing} (or use mapping=auto)")
    return resolve(spec, components, floating_tz=floating_tz, max_instances=max_instances)


register_mapping("auto", _auto)
register_mapping("spec", _strict)


# ======================================================================================
#  Lifecycle, fetch, attest
# ======================================================================================

class _Blocked(Exception):
    pass


def target_url(connect: str) -> str:
    """A base URL from a plugin connect string: a URL as is; 'host:port', 'host port' or
    'nc host port' as http://host:port; a bare host as http://host."""
    c = (connect or "").strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", c, re.I):
        return c
    m = re.fullmatch(r"(?:nc\s+)?(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(?:\s+|:)(\d{1,5})", c)
    if m:
        return f"http://{m[1]}:{m[2]}"
    if re.fullmatch(r"[A-Za-z0-9.-]+", c):
        return f"http://{c}"
    raise AttestError(f"cannot read a URL from the instance connect info {connect!r}")


def instance_target(profile, challenge_id: str, *, spawn: bool, gate=None) -> tuple[str, Any]:
    """Start (or read) our instance through the B-003 path and return (base URL, gate)."""
    from ctf import instsched, paths
    from ctf.platform import NotSupported, PlatformError, get_adapter, supports_instances
    ins = getattr(profile, "instances", None)
    if gate is None:
        if ins is None:
            raise _Blocked(f"event {profile.slug!r} has no [instances] section: its platform starts no "
                           "per-team instance from here; pass --opt target=<url> for a running one")
        try:
            gate = get_adapter(profile)
        except Exception as e:      # noqa: BLE001 - any adapter build failure is reported by name
            raise _Blocked(f"platform adapter for {profile.slug!r} unavailable: {type(e).__name__}: {e}") from None
        if not supports_instances(gate):
            raise _Blocked(f"event {profile.slug!r}: the platform adapter starts no instances")
    cid = str(challenge_id)
    try:
        if spawn:
            led = instsched.SlotLedger(instsched.slot_ledger_path(paths.workdir(profile.slug)))
            with led:
                info = instsched.start_capped(gate, led, cid, cap=ins.cap if ins is not None else None,
                                              errors=PlatformError)
        else:
            info = gate.instance_status(cid)
    except instsched.CapReached as e:
        raise _Blocked(f"instance slot cap: {e}") from None
    except (PlatformError, NotSupported, instsched.ScheduleError) as e:
        raise _Blocked(f"instance {cid}: {type(e).__name__}: {e}") from None
    state = getattr(info, "state", None)
    connect = getattr(info, "connection_info", "") or ""
    if state not in instsched.LIVE_STATES or not connect:
        raise _Blocked(f"instance {cid} is {state!r} with no connect info"
                       + ("" if spawn else " (spawn=0: start it with `python -m ctf instance start`)"))
    try:
        return target_url(connect), gate
    except AttestError as e:
        raise _Blocked(str(e)) from None


def _excerpt(data: bytes | str, n: int) -> str:
    s = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    s = s.replace("\r", "")
    return s if len(s) <= n else s[:n] + f"... [{len(s) - n} more chars]"


def _load_spec(spec: Any, brief: Any) -> AttestSpec | None:
    if spec is None or spec == "":
        return None
    if isinstance(spec, AttestSpec):
        return spec
    if isinstance(spec, dict):
        return spec_from_dict(spec, brief=brief)
    p = Path(str(spec)).expanduser()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AttestError(f"spec {p}: {type(e).__name__}: {e}") from None
    return spec_from_dict(d, brief=brief)


def _write(out: Path | None, name: str, data: Any) -> str | None:
    if out is None:
        return None
    out.mkdir(parents=True, exist_ok=True)
    p = out / name
    if isinstance(data, (bytes, bytearray)):
        p.write_bytes(bytes(data))
    elif isinstance(data, str):
        p.write_text(data, encoding="utf-8")
    else:
        p.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    return str(p)


def solve(challenge_dir, profile=None, *, target: str | None = None, challenge_id: str | None = None,
          spawn: Any = True, brief_path: str = "/brief", ics_path: str = "/case.ics",
          attest_path: str = "/attest", mapping: str = "auto", spec: Any = None, attest: Any = True,
          floating_tz: str | None = None, out_dir: str | None = None, stop_after: Any = False,
          max_instances: Any = ix.DEFAULT_MAX_INSTANCES, gate=None, **_opts):
    """Spawn/read the instance, fetch the brief and calendar, expand, map, and (when allowed and
    confident) attest. See the module docstring for the result statuses."""
    from ctf import event as _event
    from ctf import flagfmt
    from ctf.result import Cost, Evidence, SolverResult

    t0 = time.process_time()
    cid = str(challenge_id) if challenge_id not in (None, "") else None

    stop_wanted: list = [None]      # the cid whose stop_after=1 is pending, once the options are read

    def res(status, notes, flags=(), evidence=()):
        if status != "solved" and stop_wanted[0]:    # stop_after acts only on a solve: say so, never drop it
            notes += (f"\nstop_after=1 not applied: the run ended {status}, not solved, so this run did "
                      f"not stop instance {stop_wanted[0]}; if it is running, stop it yourself with: "
                      f"python -m ctf instance stop {stop_wanted[0]}")
        return SolverResult(status=status, engine=ENGINE_ID, challenge_id=cid, flags=tuple(flags),
                            evidence=tuple(evidence), notes=notes,
                            cost=Cost(seconds=round(time.process_time() - t0, 3)))

    try:
        profile = profile if profile is not None else _event.current()
        spawn_b, attest_b, stop_b = _bool(spawn, "spawn"), _bool(attest, "attest"), _bool(stop_after, "stop_after")
        cap = int(max_instances)
        map_fn = get_mapping(str(mapping))
    except (AttestError, ValueError, _event.EventError) as e:
        return res("blocked", f"bad options: {e}")
    stop_wanted[0] = cid if stop_b else None
    if ix._du is None:
        return res("blocked", f"python-dateutil is not installed ({ix._DU_ERROR}); install the pin in "
                              "requirements.in")
    if not target and not cid:
        return res("blocked", "no target: pass --opt challenge_id=<id> (the engine starts the instance) or "
                              "--opt target=http://host:port (an instance already running)")
    try:
        if not target:
            target, gate = instance_target(profile, cid, spawn=spawn_b, gate=gate)
    except _Blocked as e:
        return res("blocked", str(e))

    import web as _web      # the scope-locked HTTP client (flat owner: solvers/toolkits/web.py)
    try:
        client = _web.WebClient(target)
    except _web.OutOfScope as e:
        return res("blocked", f"target out of scope: {e}")
    cdir = Path(challenge_dir) if challenge_dir else None
    out = Path(out_dir) if out_dir else ((cdir / "ical_attest") if cdir is not None and cdir.is_dir() else None)

    def fetch(path):
        try:
            r = client.get(path)
        except (_web.VPNRequired, _web.OutOfScope, ValueError) as e:
            raise _Blocked(f"GET {path}: {type(e).__name__}: {e}") from None
        if r.get("status") != 200:
            raise _Blocked(f"GET {path}: HTTP {r.get('status')}: {_excerpt(r.get('body') or b'', 200)}")
        if r.get("truncated"):      # never parse a cut brief or calendar as if it were whole
            raise _Blocked(f"GET {path}: the response is larger than the scope-locked client's "
                           f"{_web.MAX_BODY}-byte body cap (web.MAX_BODY) and was cut; a partial brief or "
                           "calendar is not parsed. Fetch it yourself and map it offline: python "
                           "solvers/toolkits/ical_attest.py <brief> <case.ics>")
        return r.get("body") or b""

    try:
        brief_raw = fetch(brief_path)
        ics_raw = fetch(ics_path)
    except _Blocked as e:
        return res("blocked", str(e))
    try:
        brief: Any = json.loads(brief_raw.decode("utf-8"))
        _write(out, "brief.json", brief_raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        brief = brief_raw.decode("utf-8", "replace")
        _write(out, "brief.txt", brief_raw)
    _write(out, "case.ics", ics_raw)
    brief_note = f"brief (untrusted data, verbatim, truncated):\n{_excerpt(brief_raw, MAX_BRIEF_ECHO)}"

    try:
        components = ix.parse(ics_raw)
        user_spec = _load_spec(spec, brief)
        outcome = map_fn(brief, components, spec=user_spec, floating_tz=floating_tz, max_instances=cap)
    except (ix.IcalError, AttestError) as e:
        return res("unsure", f"could not map {ics_path}: {e}\n{brief_note}")

    ev = []
    if outcome.expansion is not None:
        ev.append(Evidence("decode", f"RFC 5545 expansion of {ics_path}: {len(outcome.expansion.occurrences)} "
                                     f"instance(s) generated, {len(outcome.selected)} in the window"))
        _write(out, "expansion.json", outcome.expansion.to_dict())
    if outcome.spec is not None:
        _write(out, "spec.json", outcome.spec.to_dict())
    att_file = _write(out, "attestation.json", outcome.payload) if outcome.payload is not None else None
    summary = [f"mapping {mapping}: {outcome.status}; {len(outcome.selected)} record(s)"]
    if outcome.unknown:
        summary.append(f"unknown and answer-changing: {outcome.unknown} (state them in --opt spec=<file.json>)")
    if outcome.defaulted:
        summary.append(f"unstated but answer-neutral (defaulted): {outcome.defaulted}")
    summary += [f"flag on an instance: {f}" for f in outcome.flagged]
    summary += outcome.notes
    if att_file:
        summary.append(f"attestation{' draft' if outcome.status != 'ok' else ''}: {att_file}")
    elif outcome.payload is not None:
        summary.append(f"attestation: {_excerpt(json.dumps(outcome.payload), 1200)}")
    if out is not None:
        summary.append(f"spec template to complete: {out / 'spec.json'}")
    if outcome.status != "ok":
        return res("unsure", "\n".join(summary + [brief_note]), evidence=ev)
    if not attest_b:
        return res("unsure", "\n".join(summary + ["not posted: attest=0"]), evidence=ev)
    if not profile.rules.web_state_changing:
        return res("unsure", "\n".join(summary + [
            f"not posted: POST {attest_path} is a state-changing web action and rules.web_state_changing "
            f"is false for {profile.slug!r} (BUILD-PLAN O-2, the player's call). Send the attestation "
            "yourself, or set the switch in the event profile."]), evidence=ev)
    try:
        r = client.request("POST", attest_path, data=json.dumps(outcome.payload),
                           headers={"Content-Type": "application/json"})
    except (_web.VPNRequired, _web.OutOfScope, ValueError) as e:
        return res("blocked", "\n".join(summary + [f"POST {attest_path}: {type(e).__name__}: {e}"]), evidence=ev)
    body = r.get("body") or b""
    _write(out, "attest_response.txt", body)
    flags = list(dict.fromkeys(flagfmt.for_profile(profile).find_flags(body)))
    if not flags:
        return res("unsure", "\n".join(summary + [
            f"POST {attest_path}: HTTP {r.get('status')}, no flag in the response (untrusted data, "
            f"truncated):\n{_excerpt(body, MAX_RESPONSE_ECHO)}"]), evidence=ev)
    ev.append(Evidence("oracle", f"POST {attest_path} with {len(outcome.selected)} record(s): HTTP "
                                 f"{r.get('status')}, flag in the response"))
    tail = []
    if stop_b and cid:
        try:
            from ctf import instsched, paths
            led = instsched.SlotLedger(instsched.slot_ledger_path(paths.workdir(profile.slug)))
            with led:
                instsched.stop_tracked(gate, led, cid)
            tail.append(f"instance {cid} stopped (stop_after=1)")
        except Exception as e:      # noqa: BLE001 - a failed teardown is reported, never hidden
            tail.append(f"instance {cid} NOT stopped: {type(e).__name__}: {e}")
    elif cid:
        tail.append(f"instance {cid} left running (the flag may be per instance); after the flag is "
                    f"accepted: python -m ctf instance stop {cid}")
    return res("solved", "\n".join(summary + tail), flags=flags, evidence=ev)


def main(argv: list[str] | None = None) -> int:
    """Offline: map a saved brief + calendar (no network). Prints the outcome as JSON."""
    import argparse
    ap = argparse.ArgumentParser(prog="ical_attest", description="offline: brief.json + case.ics -> attestation")
    ap.add_argument("brief", help="the saved /brief (JSON or text)")
    ap.add_argument("ics", help="the saved /case.ics")
    ap.add_argument("--spec", help="a spec JSON file (partial is fine with --mapping auto)")
    ap.add_argument("--mapping", default="auto")
    ap.add_argument("--floating-tz")
    a = ap.parse_args(argv)
    try:
        raw = Path(a.brief).read_bytes()
        try:
            brief: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            brief = raw.decode("utf-8", "replace")
        comps = ix.parse(Path(a.ics).read_bytes())
        o = get_mapping(a.mapping)(brief, comps, spec=_load_spec(a.spec, brief), floating_tz=a.floating_tz)
    except (OSError, ix.IcalError, AttestError) as e:
        print(f"ical_attest: {e}", file=sys.stderr)
        return 2
    print(json.dumps({"status": o.status, "unknown": o.unknown, "defaulted": o.defaulted, "flagged": o.flagged,
                      "notes": o.notes, "spec": o.spec.to_dict() if o.spec else None,
                      "attestation": o.payload}, indent=1, default=str))
    return 0 if o.status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
