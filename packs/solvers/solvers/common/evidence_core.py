#!/usr/bin/env python3
"""The shared evidence layer (toolkit key `evidence_core`): rows, queries, times, a cross-artifact
indicator index and a question router with an exactly-one rule. Built on solvers/common/triage.py,
which it imports and does not change. Offline: no Game Master request, no token, standard library
only, so it may run on a clock.

  .venv/bin/python solvers/toolkits/evidence_core.py <file or attempt dir>...     (a triage print)

By hand, from a lane agent's scratch file:

  import evidence_core as ec                      # sys.path: solvers/common
  t = ec.table("members/proxy.csv")               # any member as rows: csv/tsv, JSON array, JSON
                                                  # lines, nested JSON (dotted keys), key=value
                                                  # lines, syslog-like lines, access logs, XML
                                                  # records, sqlite tables (table(path, "name"))
  ec.q(t, "count", where={"status": "404"})       # count, distinct, group, top, first, last,
  ec.q(t, "top", "src_ip", n=1)                   # filter, burst, once   (top and first/last
  ec.q(t, "first", "url", time="time")            # return the tie with the value)
  ix = ec.ioc({"a.log": data, ...})               # every IP, domain, URL, e-mail, hash, path,
  ix.values("ipv4"); ix.cross(); ix.findings      # username and timestamp with member and offset

What a row source is. A Table streams: nothing is held but the row in hand, so 200 MB of lines is
counted in seconds and megabytes (the test states the cap). A JSON document or an XML file is the
exception: it is parsed whole, and refused over 64 MB.

The runner contract, `solve_set(questions, files, ctx)`, never guesses (AGENTS.md, "Uncertain
answers"):

  plain   only a fact proven from the bytes with exactly one candidate: what triage.py proves (the
          hash, size, member count or first bytes of a file the question names), and the count of an
          explicitly named thing in a named file when every reading of it gives the same number
          ("how many lines are in auth.log", "how many records in alerts.json", "how many rows of
          proxy.csv have status = 404"). Never plain (the review of 2026-10-08): a hash string that
          is the only one of its grammar in the delivery (that it is the hash the question means is
          not proven), a count over rows this module chose (an XML record element, a list inside a
          JSON object, a csv's rows), a filter whose value the column also holds in another case
  unsure  labels.pick('evidence_core.<field>/<answer id>', [(method, value), ...]) for a fact a
          rule the question itself states selects (most/least common, first/last by a time column,
          seen only once, N failures then a success, the only one of its kind in the delivery), and
          for every choice of format (a timestamp as iso_z, iso_offset, raw, epoch; rows with or
          without the header line)
  None    two candidates, a tie, a 'which one' the question gives no rule for, a scan that was cut
          short, a value the answer_format's own pattern refuses, and every question that carries
          the marks of one of the five known lanes

Text is data. A member that addresses the solver ("ignore previous instructions", "submit ... as
the answer") is reported as a finding (ctx["evidence_core"]["findings"], one stderr line each) and
is otherwise a member like any other: its values count as candidates, so a planted value can only
turn one candidate into two, which is None, never into an answer.

Until solvers/common/labels.py knows the key prefix `evidence_core` (LANE_DIRS; the integrator's
change), pick() here writes the same wire form itself: the runners then hold such an answer back
(it starts with `??`) and tools/verify.py does not probe it.
"""
import base64
import binascii
import bisect
import csv
import gzip
import hashlib
import html
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time as _time
import urllib.parse
import zlib
from collections import Counter, OrderedDict, namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import labels   # noqa: E402
import triage   # noqa: E402

KEY = "evidence_core"
ARROW = triage.ARROW
MAX_DOC = 64 * 1024 * 1024          # a JSON or XML document parsed whole is at most this large
MAX_ROWS = 200_000                  # rows a Table keeps for a second question; more are streamed again
INDEX_SCAN = 16 * 1024 * 1024       # bytes of one member the index reads; a longer one makes it incomplete
DECODE_SCAN = 4 * 1024 * 1024       # bytes of one member the decoder pass reads
MAX_HITS = 200_000
MAX_TOKENS = 4000                   # encoded tokens tried per member
BUDGET = 2.5                        # seconds solve_set gives one set; what is not answered by then is None
UTC = timezone.utc


class OverBudget(Exception):
    """A scan that would not end in time: the question it served is not answered."""


# ---- unsure answers --------------------------------------------------------------------------------

def _shape(text) -> str:
    return re.sub(r"[^a-z0-9_.+-]+", "_", str(text or "").lower()).strip("_") or "q"


def pick(field: str, shape: str, options):
    """labels.pick under 'evidence_core.<field>/<shape>'. While labels.py does not know the prefix,
    the same wire form without a ledger: unsure, never sent, not probed."""
    key = f"{KEY}.{_shape(field)}/{_shape(shape)}"
    try:
        return labels.pick(key, options)
    except ValueError:
        pairs = labels._pairs(options)[:labels.MAX_OPTIONS]
        if not pairs:
            return None
        return labels.SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in pairs]}, separators=(",", ":"))


def options_of(value) -> list:
    """[(name, value)] of an unsure answer made here or by labels.pick; [] for anything else."""
    if not (isinstance(value, str) and value.startswith(labels.SENTINEL)):
        return []
    try:
        return [(o[0], o[1]) for o in json.loads(value[len(labels.SENTINEL):])["o"]]
    except (ValueError, KeyError, TypeError, IndexError):
        return []


# ---- time --------------------------------------------------------------------------------------------

_E1601 = datetime(1601, 1, 1, tzinfo=UTC)
_E1970 = datetime(1970, 1, 1, tzinfo=UTC)
_E2001 = datetime(2001, 1, 1, tzinfo=UTC)
_MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}


def _since(epoch, micro):
    try:
        return epoch + timedelta(microseconds=int(micro))
    except (OverflowError, ValueError):
        return None


def from_unix(n, unit="s"):
    """Unix time in s, ms, us or ns (PRTime is Unix microseconds). Malformed input (a bad unit,
    None, NaN/inf) is a clean None, never a leaked ValueError/KeyError/TypeError/OverflowError."""
    per = {"s": 1_000_000, "ms": 1000, "us": 1}
    try:
        if unit == "ns":
            return _since(_E1970, int(n) // 1000)
        return _since(_E1970, n * per[unit] if isinstance(n, int) else round(float(n) * per[unit]))
    except (TypeError, ValueError, OverflowError, KeyError):
        return None


def from_prtime(n):
    try:
        return from_unix(int(n), "us")
    except (TypeError, ValueError, OverflowError):
        return None


def from_filetime(n):
    """Windows FILETIME: 100 ns steps since 1601-01-01 UTC."""
    try:
        return _since(_E1601, int(n) // 10)
    except (TypeError, ValueError, OverflowError):
        return None


def from_webkit(n):
    """WebKit/Chrome time: microseconds since 1601-01-01 UTC."""
    try:
        return _since(_E1601, int(n))
    except (TypeError, ValueError, OverflowError):
        return None


def from_mac_absolute(n):
    """Mac absolute (Cocoa, CFAbsoluteTime): seconds since 2001-01-01 UTC."""
    try:
        return _since(_E2001, round(float(n) * 1_000_000))
    except (TypeError, ValueError, OverflowError):
        return None


def from_dos(date16: int, time16: int):
    """A DOS date and time word pair (zip, FAT): a naive local time, or None for an impossible one.
    An out-of-range seconds field (DOS stores 0..29, doubled, so 30/31 yield 60/62) is rejected,
    not clamped."""
    try:
        return datetime(1980 + (date16 >> 9), (date16 >> 5) & 15, date16 & 31,
                        time16 >> 11, (time16 >> 5) & 63, (time16 & 31) * 2)
    except (ValueError, TypeError):
        return None


def from_dos32(n: int):
    """A 32-bit DOS timestamp, date in the high word."""
    try:
        return from_dos((int(n) >> 16) & 0xFFFF, int(n) & 0xFFFF)
    except (TypeError, ValueError, OverflowError):
        return None


EPOCHS = (("unix_s", lambda n: from_unix(n, "s")), ("unix_ms", lambda n: from_unix(n, "ms")),
          ("unix_us", lambda n: from_unix(n, "us")), ("unix_ns", lambda n: from_unix(n, "ns")),
          ("filetime", from_filetime), ("webkit", from_webkit), ("mac_absolute", from_mac_absolute))


def guess_epoch(n, lo: int = 2000, hi: int = 2040) -> list:
    """[(kind, datetime)] for every epoch reading of a number that lands in [lo, hi] (years). More
    than one entry means the number alone does not say which clock it is."""
    out = []
    for kind, f in EPOCHS:
        try:
            dt = f(n)
        except (OverflowError, ValueError, TypeError):
            dt = None
        if dt is not None and lo <= dt.year <= hi:
            out.append((kind, dt))
    return out


_ISO = re.compile(r"(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d{1,9}))?)?)?\s*(Z|[+-]\d\d(?::?\d\d)?)?$")
_EXIF = re.compile(r"(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)$")
_CLF = re.compile(r"(\d\d)/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-]\d{4}))?$")
_BSD = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d)$")
_NUM = re.compile(r"\d{9,19}(?:\.\d+)?$")


def _tz(text):
    if not text:
        return None
    if text == "Z":
        return UTC
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)))


def parse_iso(text):
    """An ISO 8601 date or date-time (T or space, optional fraction, Z or an offset): aware when it
    names a zone, naive when it does not. None for anything else."""
    m = _ISO.match(str(text).strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        return datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0),
                        int((frac or "0")[:6].ljust(6, "0")), tzinfo=_tz(tz))
    except ValueError:
        return None


def parse_time(text, year=None):
    """One timestamp as a datetime, or None: ISO, EXIF (`2026:10:08 12:00:00`), access-log
    (`08/Oct/2026:12:00:00 +0000`), RFC 2822, BSD syslog (`Oct  8 12:00:00`, only with `year`), and a
    bare number when exactly one epoch reading of it is plausible. A day/month order that the text
    does not settle (`03/04/2026`) is None."""
    s = str(text).strip()
    if not s:
        return None
    dt = parse_iso(s)
    if dt is not None:
        return dt
    try:
        m = _EXIF.match(s)
        if m:
            return datetime(*map(int, m.groups()))
        m = _CLF.match(s)
        if m:
            d, mon, y, h, mi, sec, tz = m.groups()
            return datetime(int(y), _MONTHS[mon.lower()], int(d), int(h), int(mi), int(sec), tzinfo=_tz(tz))
        m = _BSD.match(s)
        if m:
            if year is None:
                return None
            mon, d, h, mi, sec = m.groups()
            return datetime(int(year), _MONTHS[mon.lower()], int(d), int(h), int(mi), int(sec))
    except (ValueError, KeyError):
        return None
    if _NUM.match(s):
        got = guess_epoch(float(s) if "." in s else int(s))
        return got[0][1] if len(got) == 1 else None
    if re.search(r"\d{1,2} [A-Za-z]{3} \d{4} \d\d:\d\d", s):
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(s)
        except (TypeError, ValueError, IndexError):
            return None
    return None


def time_options(dt, raw=None, prefer=None) -> list:
    """The spellings of one moment as labels.pick options, best first: (name, value) with the names
    raw, iso_z, iso_offset, iso_space, epoch, epoch_ms (and iso_naive for a time with no zone, whose
    iso_z and epoch are then offered last under `*_assumed_utc`). `prefer` moves one name first."""
    out = []
    if raw is not None and str(raw).strip():
        out.append(("raw", str(raw).strip()))
    if dt is not None:
        frac = f".{dt.microsecond:06d}".rstrip("0") if dt.microsecond else ""
        if dt.tzinfo is not None:
            u = dt.astimezone(UTC)
            off = dt.strftime("%z")
            out += [("iso_z", u.strftime("%Y-%m-%dT%H:%M:%S") + (f".{u.microsecond:06d}".rstrip("0") if u.microsecond else "") + "Z"),
                    ("iso_offset", dt.strftime("%Y-%m-%dT%H:%M:%S") + frac + off[:3] + ":" + off[3:5]),
                    ("iso_space", u.strftime("%Y-%m-%d %H:%M:%S")),
                    ("epoch", str(int((u - _E1970).total_seconds()))),
                    ("epoch_ms", str(int((u - _E1970) / timedelta(milliseconds=1))))]
        else:
            u = dt.replace(tzinfo=UTC)
            out += [("iso_naive", dt.strftime("%Y-%m-%dT%H:%M:%S") + frac),
                    ("iso_space", dt.strftime("%Y-%m-%d %H:%M:%S")),
                    ("iso_z_assumed_utc", dt.strftime("%Y-%m-%dT%H:%M:%S") + frac + "Z"),
                    ("epoch_assumed_utc", str(int((u - _E1970).total_seconds())))]
    if prefer:
        out.sort(key=lambda nv: nv[0] != prefer and not nv[0].startswith(prefer))
    return out


# ---- loaders: any member as rows -------------------------------------------------------------------

_KV = re.compile(r"(?:^|(?<=[\s,;|]))([A-Za-z_@][\w.\-@]*)=(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s,;|]*)")
_TS = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_SYSLOG = re.compile(r"(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|" + _TS + r")\s+(?P<host>[\w.\-]+)\s+"
                     r"(?P<process>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$")
# A real syslog has tags the strict form does not: `syslogd 1.4.1: restart.` (a blank in the tag) and
# ` -- root[2421]: ROOT LOGIN` (loghub's Linux sample has eight such lines in 2,000). They are rows
# of a file already known to be syslog, never the reason a file is read as one.
_SYSLOG_LOOSE = re.compile(r"(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|" + _TS + r")\s+(?P<host>[\w.\-]+)\s+"
                           r"(?:--\s+)?(?P<process>[^\s\[:][^\[:]{0,47}?)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$")
_TIMED = re.compile(r"\[?(?P<time>" + _TS + r")\]?\s+(?P<message>.*)$")
_ACCESS = re.compile(r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)'
                     r'(?: (?P<protocol>[^"]*))?" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?')
_IPV4 = triage.IOC["ipv4"]
_USER_IN = re.compile(r"\bfor (?:invalid user |illegal user |user )?([A-Za-z0-9_.$@-]{1,64}) from\b"
                      r"|\buser(?:name)?[=: ]\s*[\"']?([A-Za-z0-9_.$@\\-]{1,64})", re.I)
_OUTCOME = re.compile(r"\b(fail(?:ed|ure)?|invalid|denied|rejected|incorrect|unauthori[sz]ed|refused)\b"
                      r"|\b(accepted|succe(?:ss|eded|ssful(?:ly)?)|granted|session opened|logged in)\b", re.I)
# W3C extended logs (IIS: `#Fields: date time s-ip ...`, cells split on blanks) and Zeek logs
# (`#fields<TAB>ts<TAB>uid ...`, cells split on the tab): the file names its own columns.
_W3C_FIELDS = re.compile(r"^#[Ff]ields:?[ \t]+(.+?)\s*$", re.M)
# Apache's error log and its kin: [Sun Dec 04 04:47:44 2005] [notice] [client 1.2.3.4] text
_BRACKETED = re.compile(r"\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?P<level>[\w:.-]+)\] "
                        r"(?:\[pid (?P<pid>\d+)(?::tid \d+)?\] )?(?:\[client (?P<client>[^\]]+)\] )?(?P<message>.*)$")
DERIVED = ("ip", "user", "outcome")     # syslog/timed columns read out of the message text: never a plain answer
_NS = re.compile(r"^\{[^}]*\}")


_MAX_FLATTEN_DEPTH = 400


def flatten(obj, prefix: str = "", out=None, _depth: int = 0) -> dict:
    """A nested JSON value as one row: dotted keys, list items by their index, scalars as text
    (true/false, an empty string for null). A pathologically deep object is refused with OverBudget
    rather than left to overflow the interpreter stack with a RecursionError."""
    out = {} if out is None else out
    if _depth > _MAX_FLATTEN_DEPTH:
        raise OverBudget("flatten depth")
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, _depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, f"{prefix}.{i}" if prefix else str(i), out, _depth + 1)
    else:
        out[prefix or "value"] = ("" if obj is None else "true" if obj is True else "false" if obj is False else str(obj))
    return out


def _derive(row: dict, message: str):
    ips = set(_IPV4.findall(message))
    row["ip"] = ips.pop() if len(ips) == 1 else ""
    m = _USER_IN.search(message)
    row["user"] = (m.group(1) or m.group(2) or "") if m else ""
    kinds = {("failure" if a else "success") for a, b in _OUTCOME.findall(message)}
    row["outcome"] = kinds.pop() if len(kinds) == 1 else ""


def _text_lines(stream, enc: str):
    if enc.startswith("utf-16"):
        for line in io.TextIOWrapper(stream, encoding=enc, errors="replace"):
            yield line.rstrip("\r\n")
        return
    first = True
    for raw in stream:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if first:
            first, line = False, line.lstrip("\ufeff")
        yield line


class Table:
    """One member as rows. Iterating streams the member again each time; `rows()` keeps up to
    MAX_ROWS of them. `kind` is csv, json-array, json-records, jsonl, kv, syslog, access, timed,
    w3c (IIS and Zeek: the file's own `#Fields` line), bracketed (Apache's error log), xml, sqlite or lines (the fallback: one column, `line`; not a table for the router). `bad` is
    the number of lines of the last pass that did not parse; `derived` names columns that were read
    out of free text."""

    def __init__(self, name, kind, opener, columns=(), enc="utf-8", **meta):
        self.name, self.kind, self._open, self.enc = name, kind, opener, enc
        self.columns = list(columns)
        self.meta = meta
        self.bad = 0
        self.derived = set(DERIVED) if kind in ("syslog", "timed") else set()
        self.deadline = None
        self._rows = None
        self.too_long = False

    def __repr__(self):
        return f"<Table {self.name} {self.kind} columns={self.columns[:12]}>"

    @property
    def is_table(self) -> bool:
        return self.kind != "lines"

    def __iter__(self):
        if self._rows is not None:
            yield from self._rows
            return
        self.bad = 0
        n = 0
        for row in self._generate():
            n += 1
            if self.deadline is not None and not n & 0xFFF and _time.monotonic() > self.deadline:
                raise OverBudget(self.name)
            yield row

    def rows(self, cap: int = MAX_ROWS):
        """The rows as a list, kept for the next question; None (and `too_long`) past `cap` rows."""
        if self._rows is None and not self.too_long:
            got = []
            for row in self:
                got.append(row)
                if len(got) > cap:
                    self.too_long = True
                    return None
            self._rows = got
        return self._rows

    def _generate(self):
        k = self.kind
        if k == "sqlite":
            yield from self._sqlite()
            return
        if k in ("json-array", "json-records", "xml"):
            yield from self.meta["records"]()
            return
        with self._open() as stream:
            if k == "csv":
                text = io.TextIOWrapper(stream, encoding=self.enc if self.enc != "utf-8" else "utf-8-sig", errors="replace", newline="")
                reader = csv.reader(text, delimiter=self.meta["delimiter"])
                cols, header = self.columns, self.meta["header"]
                for i, cells in enumerate(reader):
                    if not cells or (i == 0 and header):
                        continue
                    row = dict(zip(cols, cells))
                    if len(cells) != len(cols):
                        self.bad += 1
                        if len(cells) > len(cols):
                            row["_extra"] = self.meta["delimiter"].join(cells[len(cols):])
                    yield row
                return
            for line in _text_lines(stream, self.enc):
                if not line.strip():
                    continue
                if k == "jsonl":
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        self.bad += 1
                        yield {"_raw": line}
                        continue
                    yield flatten(obj) if isinstance(obj, (dict, list)) else {"value": flatten(obj)["value"]}
                elif k == "kv":
                    pairs = _KV.findall(line)
                    if not pairs:
                        self.bad += 1
                        yield {"_raw": line}
                        continue
                    row = {}
                    m = re.match(r"\[?(" + _TS + r")\]?", line)
                    if m:
                        row["_time"] = m.group(1)
                    for key, v in pairs:
                        row[key] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v
                    yield row
                elif k == "w3c":
                    if line.startswith("#"):
                        m = _W3C_FIELDS.match(line)
                        if m:                           # IIS writes the header again after every restart
                            cols = m.group(1).split("\t") if self.meta["tab"] else m.group(1).split()
                            for c in cols:
                                if c not in self.columns:
                                    self.columns.append(c)
                            self.meta["now"] = cols
                        continue
                    cells = line.rstrip("\r\n").split("\t") if self.meta["tab"] else line.split()
                    cols = self.meta.get("now") or self.columns
                    row = dict(zip(cols, cells))
                    if len(cells) != len(cols):
                        self.bad += 1
                    yield row
                elif k == "bracketed":
                    m = _BRACKETED.match(line)
                    if not m:
                        self.bad += 1
                        yield {"_raw": line}
                        continue
                    yield {a: (b or "") for a, b in m.groupdict().items()}
                elif k in ("syslog", "timed", "access"):
                    m = (_SYSLOG if k == "syslog" else _TIMED if k == "timed" else _ACCESS).match(line)
                    if not m and k == "syslog":
                        m = _SYSLOG_LOOSE.match(line)
                    if not m:
                        self.bad += 1
                        yield {"_raw": line}
                        continue
                    row = {a: (b or "") for a, b in m.groupdict().items()}
                    if k != "access":
                        _derive(row, row["message"])
                    yield row
                else:
                    yield {"line": line}

    def _sqlite(self):
        con = sqlite3.connect(f"file:{urllib.parse.quote(self.meta['path'])}?mode=ro&immutable=1", uri=True)
        try:
            con.execute("PRAGMA trusted_schema=OFF")
            cur = con.execute('SELECT * FROM "' + self.meta["table"].replace('"', '""') + '"')
            cols = [d[0] for d in cur.description]
            for values in cur:
                yield {c: ("" if v is None else v.hex() if isinstance(v, bytes) else str(v)) for c, v in zip(cols, values)}
        finally:
            con.close()


_TMP = None


def _scratch() -> Path:
    global _TMP
    if _TMP is None:
        import atexit
        _TMP = Path(tempfile.mkdtemp(prefix="evidence_core_"))
        atexit.register(shutil.rmtree, str(_TMP), True)
    return _TMP


def _sqlite_tables(name, source) -> list:
    """Tables of a sqlite database, read from a private copy opened read-only and immutable (the
    delivered bytes are never opened in place, and no journal or WAL beside them is replayed)."""
    copy = _scratch() / (hashlib.sha256(f"{name}{id(source)}{_time.monotonic()}".encode()).hexdigest() + ".sqlite")
    if isinstance(source, (bytes, bytearray)):
        copy.write_bytes(source)
    else:
        shutil.copyfile(str(source), str(copy))
    out = []
    try:
        con = sqlite3.connect(f"file:{urllib.parse.quote(str(copy))}?mode=ro&immutable=1", uri=True)
        try:
            names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            for t in names:
                cols = [r[1] for r in con.execute('PRAGMA table_info("' + t.replace('"', '""') + '")')]
                out.append(Table(f"{name}#{t}", "sqlite", None, cols, path=str(copy), table=t, member=name))
        finally:
            con.close()
    except sqlite3.Error:
        return []
    return out


def _record_lists(obj, path="", depth=0, out=None) -> list:
    """[(dotted path, list)] of every list of objects inside a JSON value, at most four levels down."""
    out = [] if out is None else out
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            out.append((path, obj))
        return out
    if isinstance(obj, dict) and depth < 4:
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _record_lists(v, f"{path}.{k}" if path else str(k), depth + 1, out)
    return out


def _columns(rows, limit=500) -> list:
    cols = []
    for i, row in enumerate(rows):
        for k in row:
            if k not in cols:
                cols.append(k)
        if i >= limit:
            break
    return cols


def _json_tables(name, read_all) -> list:
    try:
        doc = json.loads(read_all().decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return []
    if isinstance(doc, list):
        rows = [flatten(x) if isinstance(x, (dict, list)) else {"value": flatten(x)["value"]} for x in doc]
        return [Table(name, "json-array", None, _columns(rows), records=lambda: iter(rows), count=len(doc), member=name)]
    out = []
    for path, items in _record_lists(doc):
        rows = [flatten(x) for x in items]
        out.append(Table(f"{name}#{path}", "json-records", None, _columns(rows),
                         records=(lambda r=rows: iter(r)), count=len(items), member=name, path=path))
    return out


def _xml_rows(el) -> dict:
    row = {}

    def walk(e, prefix):
        for a, v in e.attrib.items():
            row[f"{prefix.rstrip('.')}@{_NS.sub('', a)}"] = v
        kids = list(e)
        text = (e.text or "").strip()
        if text and not kids:
            row[prefix.rstrip(".") or "#text"] = text
        seen = Counter()
        for c in kids:
            tag = _NS.sub("", c.tag) if isinstance(c.tag, str) else "#"
            named = c.attrib.get("Name") or c.attrib.get("name")
            if named and not list(c):                       # <Data Name="TargetUserName">bob</Data>
                row[f"{prefix}{named}"] = (c.text or "").strip()
                continue
            seen[tag] += 1
            walk(c, f"{prefix}{tag}{'.' + str(seen[tag] - 1) if seen[tag] > 1 else ''}.")

    walk(el, "")
    return row


def _xml_tables(name, read_all) -> list:
    data = read_all()
    if b"<!ENTITY" in data or b"<!entity" in data:
        return []                   # entity definitions are not expanded here
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(data)
    except Exception:
        return []
    best, level = None, [root]
    for _ in range(5):              # the outermost element whose children repeat one tag (most often at that depth)
        nxt = []
        for el in level:
            tags = Counter(c.tag for c in el if isinstance(c.tag, str))
            if tags:
                tag, n = tags.most_common(1)[0]
                if n >= 2 and (best is None or n > best[2]):
                    best = (el, tag, n)
            nxt.extend(list(el))
        # The first depth with a repeat is the record list: a deeper one (the five <Data> of one
        # <Event>) is a record's own fields, however many they are.
        if best is not None:
            break
        level = nxt[:20000]
        if not level:
            break
    if best is None:
        return []
    items = [c for c in best[0] if c.tag == best[1]]
    rows = [_xml_rows(c) for c in items]
    return [Table(name, "xml", None, _columns(rows), records=lambda: iter(rows), count=len(items), member=name,
                  record_tag=_NS.sub("", best[1]))]


def _sniff_delimiter(lines):
    best = None
    for delim in ("\t", ",", ";", "|"):
        try:
            rows = [r for r in csv.reader(lines[:30], delimiter=delim) if r]
        except csv.Error:
            continue
        widths = Counter(len(r) for r in rows)
        if not widths:
            continue
        width, n = widths.most_common(1)[0]
        if width >= 2 and len(rows) >= 2 and n >= 0.9 * len(rows) and (best is None or width > best[1]):
            best = (delim, width, rows)
    return best


def tables(name: str, source) -> list:
    """Every Table one member gives: `source` is its bytes or a path (a path is streamed). An empty
    list for a binary member; a text member nothing else fits gives one `lines` table."""
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        head, size = data[:65536], len(data)
        opener, read_all = (lambda: io.BytesIO(data)), (lambda: data)
    else:
        path = Path(source)
        size = path.stat().st_size
        with open(path, "rb") as f:
            head = f.read(65536)
        opener, read_all = (lambda: open(path, "rb")), (lambda: path.read_bytes())
    if head.startswith(b"SQLite format 3\x00"):
        return _sqlite_tables(name, source)
    enc = "utf-16" if head.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    try:
        sample = head.decode("utf-16" if enc == "utf-16" else "utf-8-sig", "strict" if size <= 65536 else "ignore")
    except UnicodeDecodeError:
        return []
    if not sample.strip() or sum(1 for c in sample if c.isprintable() or c in "\r\n\t") < 0.95 * len(sample):
        return []
    ext = Path(name.split(ARROW)[-1]).suffix.lower()
    lines = [ln for ln in sample.splitlines() if ln.strip()]
    if size > 65536 and len(lines) > 1:
        lines = lines[:-1]                                  # the sample's last line may be cut
    first = sample.lstrip()[:1]
    probe = lines[:20]

    def share(test):
        return sum(1 for ln in probe if test(ln)) >= max(1, 0.8 * len(probe))

    def is_obj(ln):
        try:
            return isinstance(json.loads(ln), dict)
        except ValueError:
            return False

    if first in "{[" and ext not in (".csv", ".tsv"):
        if first == "{" and (len(probe) >= 2 or size > 65536) and share(is_obj):
            return [Table(name, "jsonl", opener, _columns(flatten(json.loads(ln)) for ln in probe if is_obj(ln)), enc, member=name)]
        if size <= MAX_DOC:
            got = _json_tables(name, read_all)
            if got:
                return got
            try:
                json.loads(read_all().decode("utf-8-sig"))
                return []                                    # a JSON document with no list of records: not rows
            except (ValueError, UnicodeDecodeError, RecursionError):
                pass
    if first == "<" and size <= MAX_DOC and enc == "utf-8":
        got = _xml_tables(name, read_all)
        if got:
            return got
        if re.match(r"\s*<(\?xml|!doctype|html|\w+[\s>])", sample, re.I):
            return [Table(name, "lines", opener, ["line"], enc, member=name)]
    if "script" in triage.identify(head, name.split(ARROW)[-1]) or ext in triage.SCRIPT_EXT:
        return [Table(name, "lines", opener, ["line"], enc, member=name)]
    fields = _W3C_FIELDS.search(sample)
    if fields and sample.lstrip().startswith("#"):
        tab = "\t" in fields.group(0)
        cols = fields.group(1).split("\t") if tab else fields.group(1).split()
        if len(cols) >= 2:
            return [Table(name, "w3c", opener, cols, enc, tab=tab, member=name)]
    if share(lambda ln: _BRACKETED.match(ln)):
        return [Table(name, "bracketed", opener, list(_BRACKETED.groupindex), enc, member=name)]
    csv_first = ext in (".csv", ".tsv")
    for attempt in ((0, 1) if csv_first else (1, 0)):
        if attempt == 0:
            best = _sniff_delimiter(lines)
            if best and (csv_first or not share(lambda ln: len(_KV.findall(ln)) >= 2)):
                delim, width, rows = best
                top = rows[0]
                header = len(top) == width and len(set(top)) == width and all(
                    c.strip() and not re.fullmatch(r"[-+]?\d+(\.\d+)?", c.strip()) and not parse_iso(c) and not _IPV4.fullmatch(c.strip())
                    for c in top)
                cols = [c.strip() for c in top] if header else [f"c{i + 1}" for i in range(width)]
                return [Table(name, "csv", opener, cols, enc, delimiter=delim, header=header, member=name)]
        else:
            if share(lambda ln: _ACCESS.match(ln)):
                return [Table(name, "access", opener, list(_ACCESS.groupindex), enc, member=name)]
            if share(lambda ln: _SYSLOG.match(ln)) and not csv_first:
                return [Table(name, "syslog", opener, ["time", "host", "process", "pid", "message", *DERIVED], enc, member=name)]
            if share(lambda ln: len(_KV.findall(ln)) >= 2) and not csv_first:
                cols = []
                for ln in probe:
                    if re.match(r"\[?" + _TS, ln) and "_time" not in cols:
                        cols.append("_time")
                    for k, _ in _KV.findall(ln):
                        if k not in cols:
                            cols.append(k)
                return [Table(name, "kv", opener, cols, enc, member=name)]
    if share(lambda ln: _TIMED.match(ln)):
        return [Table(name, "timed", opener, ["time", "message", *DERIVED], enc, member=name)]
    return [Table(name, "lines", opener, ["line"], enc, member=name)]


def table(path, which=None, name=None):
    """The Table of a file on disk (or of bytes, with `name`): the only one, or the one whose name
    ends with `which` (a sqlite table, a JSON record path). None for a binary file."""
    got = tables(name or str(path), path)
    if which is not None:
        got = [t for t in got if t.name.endswith("#" + which) or t.meta.get("table") == which or t.meta.get("path") == which]
    return got[0] if got else None


# ---- queries ---------------------------------------------------------------------------------------

def match(row: dict, where) -> bool:
    """`where` is None, a function of the row, or {column: text (equal), compiled regex (search), a
    function of the value, or a list/set of texts (any of them)}."""
    if where is None:
        return True
    if callable(where):
        return bool(where(row))
    for col, want in where.items():
        v = row.get(col, "")
        if isinstance(want, re.Pattern):
            if not want.search(v):
                return False
        elif callable(want):
            if not want(v):
                return False
        elif isinstance(want, (list, tuple, set, frozenset)):
            if v not in {str(w) for w in want}:
                return False
        elif v != str(want):
            return False
    return True


def where_rows(t, where=None):
    return (row for row in t if match(row, where))


def count(t, where=None) -> int:
    return sum(1 for _ in where_rows(t, where))


def group_count(t, col, where=None) -> Counter:
    """Counter of a column's values over the matching rows; rows without the column (or with an
    empty value) are not counted."""
    c = Counter()
    for row in where_rows(t, where):
        v = row.get(col, "")
        if v != "":
            c[v] += 1
    return c


def distinct(t, col, where=None) -> list:
    return list(group_count(t, col, where))


def top(t, col, n: int = 1, where=None, least: bool = False):
    """(the n values with the most rows as [(value, rows)], tie): tie is True when the value after
    the n-th has as many rows as the n-th, so that 'the top n' is not one answer. `least` asks for
    the fewest."""
    ranked = sorted(group_count(t, col, where).items(), key=lambda kv: (kv[1] if least else -kv[1]))
    return ranked[:n], len(ranked) > n and ranked[n][1] == ranked[n - 1][1]


def seen_once(t, col, where=None) -> list:
    return [v for v, n in group_count(t, col, where).items() if n == 1]


def _order_key(value, state):
    """A sortable key for one time cell, or None. Numbers order as numbers; texts by parse_time. A
    BSD syslog time has no year: it orders within one year, and a column holding both January and
    December is refused (`state['wrap']`)."""
    s = str(value).strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        state["kinds"].add("n")
        return float(s)
    dt = parse_time(s, year=2000)
    if dt is None:
        return None
    if _BSD.match(s):
        state["months"].add(dt.month)
    state["kinds"].add("a" if dt.tzinfo is not None else "v")
    return dt.timestamp() if dt.tzinfo is not None else (dt - datetime(1970, 1, 1)).total_seconds()


def edge(t, time_col, where=None, last: bool = False):
    """(rows at the earliest (or latest) parsed time, problem): the rows that share the extreme
    time, in file order, and a text saying why the order is not proven (a cell that is no time,
    zones mixed with no zone, a yearless column spanning a new year), else None."""
    state = {"kinds": set(), "months": set()}
    best, rows, unread = None, [], 0
    for row in where_rows(t, where):
        key = _order_key(row.get(time_col, ""), state)
        if key is None:
            unread += 1
            continue
        if best is None or (key > best if last else key < best):
            best, rows = key, [row]
        elif key == best:
            rows.append(row)
    problem = None
    if unread:
        problem = f"{unread} row(s) have no readable time in {time_col}"
    elif len(state["kinds"]) > 1:
        problem = "the column mixes numbers, times with a zone and times without one"
    elif {1, 12} <= state["months"]:
        problem = "times without a year in both January and December"
    return rows, problem


def first(t, time_col, where=None):
    return edge(t, time_col, where, last=False)


def last(t, time_col, where=None):
    return edge(t, time_col, where, last=True)


def burst(t, key_col, outcome_col="outcome", n: int = 3, fail="failure", ok="success", where=None) -> list:
    """Keys with at least `n` failures in a row and then a success, in file order:
    [{key, failures, row (the success)}]. `fail` and `ok` are texts, regexes or functions, as in
    `match`."""
    def is_(want, v):
        return bool(want.search(v)) if isinstance(want, re.Pattern) else bool(want(v)) if callable(want) else v == want

    run, out = Counter(), []
    for row in where_rows(t, where):
        k, v = row.get(key_col, ""), row.get(outcome_col, "")
        if k == "":
            continue
        if is_(fail, v):
            run[k] += 1
        elif is_(ok, v):
            if run[k] >= n:
                out.append({"key": k, "failures": run[k], "row": row})
            run[k] = 0
    return out


def q(t, op: str, *args, **kw):
    """One query by name: count, distinct, group, top, least, once, first, last, filter, burst.
    q(t, 'count', where={...}); q(t, 'top', 'src_ip', n=3); q(t, 'first', 'url', time='time')
    gives (the values of `url` in the earliest rows, problem)."""
    if op == "count":
        return count(t, *args, **kw)
    if op == "distinct":
        return distinct(t, *args, **kw)
    if op == "group":
        return group_count(t, *args, **kw)
    if op in ("top", "least"):
        return top(t, *args, least=(op == "least"), **kw)
    if op == "once":
        return seen_once(t, *args, **kw)
    if op in ("first", "last"):
        col = args[0] if args else None
        rows, problem = edge(t, kw.pop("time"), kw.get("where"), last=(op == "last"))
        return ([r.get(col, "") for r in rows] if col else rows), problem
    if op == "filter":
        return list(where_rows(t, *args, **kw))
    if op == "burst":
        return burst(t, *args, **kw)
    raise ValueError(f"evidence_core.q: no query named {op!r}")


# ---- the cross-artifact index ------------------------------------------------------------------------

Hit = namedtuple("Hit", "kind value member offset via")

# triage's domain pattern with one change: a name starts where no word character or dot stands
# before it. With `\b` alone every label of a long dotted run (a.b.c.d..., a decimal blob written
# 104.116.116...) is a start that reads to the run's end: 20 KB of it took 6.7 s, and no deadline
# can interrupt a regex.
# Since the Day 9 integration triage.py carries that start itself; an older triage.py still has `\b`.
_TRIAGE_DOMAIN = triage.IOC["domains"].pattern
assert _TRIAGE_DOMAIN.startswith((r"\b(?:", r"(?<![\w.])(?:"))
_DOMAIN = re.compile(r"(?<![\w.])" + _TRIAGE_DOMAIN[_TRIAGE_DOMAIN.index("(?:"):], re.I)

IOC = {
    "url": triage.IOC["urls"], "email": triage.IOC["emails"], "ipv4": _IPV4, "domain": _DOMAIN,
    "sha512": re.compile(r"\b[a-fA-F0-9]{128}\b"), "sha256": triage.IOC["sha256"], "sha1": triage.IOC["sha1"],
    "md5": triage.IOC["md5"],
    "timestamp": re.compile(triage.IOC["timestamps"].pattern + r"|\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"),
    "windows_path": triage.IOC["windows_paths"],
    "unix_path": re.compile(r"(?<![\w.:/\\<])/(?:[\w.+@-]+/)+[\w.+@-]+"),
    "registry": triage.IOC["registry"],
    # a GUID/UUID, bare or in braces: 8-4-4-4-12 hex. A longer hex run around it is not one (a SHA
    # would otherwise be split), so no hex digit or dash may touch either end.
    "guid": re.compile(r"(?<![0-9A-Fa-f{-])\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?(?![0-9A-Fa-f}-])"),
}
_USERNAME = re.compile(
    r"\b(?:user(?:[_ ]?name)?|account(?:[_ ]?name)?|login|logon|TargetUserName|SubjectUserName)\"?\s*[=:]\s*[\"']?([A-Za-z0-9_.$@\\-]{2,64})"
    r"|\bfor (?:invalid user |illegal user |user )?([A-Za-z0-9_.$@-]{2,64}) from\b"
    r"|[A-Za-z]:\\+Users\\+([^\\\s\"'<>|:]{1,64})\\"
    r"|(?<![\w.])/home/([\w.-]{1,64})/", re.I)
HASHES = ("sha512", "sha256", "sha1", "md5")
_LOWER = {"domain", "email", "guid", *HASHES}      # a GUID is compared case-insensitively

INSTRUCTIONS = [(name, re.compile(rx, re.I)) for name, rx in (
    ("ignore_instructions", r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b(?:instructions?|rules|prompts?|guidance|directives?)"),
    ("addresses_a_model", r"\b(?:you are|as) (?:an? )?(?:ai|a\.i\.|llm|language model|assistant|chatbot|agent|gpt|claude)\b"
                          r"|\b(?:ai|llm) (?:agents?|assistants?|models?|solvers?)\b[^.\n]{0,40}\b(?:must|should|shall|need to|are required)\b"
                          r"|\battention[,:]? (?:ai|llm|agent|assistant|model)"),
    ("system_prompt", r"\bsystem prompt\b|<\s*/?\s*system\s*>|\[\s*system\s*\]|\bnew instructions?\s*:|\bBEGIN (?:SYSTEM|INSTRUCTIONS?)\b"),
    ("names_the_answer", r"\b(?:submit|answer with|respond with|reply with|report|enter)\b[^.\n]{0,60}\bas (?:the|your) (?:final |correct )?(?:answer|flag|response)\b"
                         r"|\bthe (?:correct|real|true|final) (?:answer|flag) (?:is|to (?:every|all|this))\b"),
    ("asks_for_secrets", r"\b(?:reveal|print|send|show|post|upload|exfiltrate|include)\b[^.\n]{0,40}\b(?:api[_ ]?key|token|credentials?|system prompt|environment variables?|\.env|ssh key|password file)"),
    ("stops_the_work", r"\b(?:do not|don't|stop|cease)\b[^.\n]{0,30}\b(?:analy[sz](?:e|ing)|solv(?:e|ing)|submit(?:ting)?|continu(?:e|ing))\b[^.\n]{0,40}\b(?:challenge|task|evidence|questions?|answers?)"),
)]

_WIDE = re.compile(rb"(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){6,}")
_CONTROL = bytes(10 if (c < 32 and c not in (9, 10, 13)) or c == 127 else c for c in range(256))
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}")
_HEXRUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")
_PCT_TOKEN = re.compile(r"[^\s\"'<>]+")     # a token, read once (linear); the percent test is a second step:
_PCT_IN = re.compile(r"%[0-9A-Fa-f]{2}")    # `[^..]*%XX[^..]*` in one pattern is quadratic on a long blob
_DEFANG = re.compile(r"\[\.\]|\(\.\)|\[dot\]|\[:\]|hxxp", re.I)
_ARCHIVES = ("zip", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab")


def _printable(b: bytes) -> bool:
    if len(b) < 6:
        return False
    good = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return good >= 0.9 * len(b)


def _bytes_to_text(raw: bytes):
    """(text, how) for decoded bytes worth reading: gzip/zlib inside, UTF-16LE, or printable text."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return _bytes_to_text(gzip.GzipFile(fileobj=io.BytesIO(raw)).read(1 << 20))[0], "gzip"
        except (OSError, EOFError, zlib.error, TypeError):
            return None, None
    if raw[:1] == b"\x78" and len(raw) > 8 and raw[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
        try:
            return _bytes_to_text(zlib.decompressobj().decompress(raw, 1 << 20))[0], "zlib"
        except (zlib.error, TypeError):
            pass
    if len(raw) >= 12 and len(raw) % 2 == 0 and raw[1::2].count(0) >= 0.9 * (len(raw) // 2) and _printable(raw[0::2]):
        return raw.decode("utf-16-le", "replace"), "utf-16le"
    if _printable(raw):
        return raw.decode("latin-1"), ""
    return None, None


def decoded_views(text: str, depth: int = 0, via: str = "", limit=None):
    """Every encoded token of a text, decoded: (decoded text, offset of the token, how), for base64
    (also url-safe, then gzip, zlib or UTF-16LE inside), hex runs and percent-encoding, three levels
    deep. A token is kept only when it decodes to text."""
    limit = limit if limit is not None else [MAX_TOKENS]
    if depth >= 3:
        return

    def emit(decoded, off, how):
        if decoded and decoded != text:
            chain = f"{via}>{how}" if via else how
            yield decoded, off, chain
            for inner, _, how2 in decoded_views(decoded, depth + 1, chain, limit):
                yield inner, off, how2

    for m in _B64.finditer(text):
        if limit[0] <= 0:
            return
        tok = m.group()
        if re.fullmatch(r"[0-9A-Fa-f]+", tok) and len(tok) in (32, 40, 64, 128):
            continue                # a hash string is not an encoding
        limit[0] -= 1
        body = tok.rstrip("=")
        if len(body) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded, how = _bytes_to_text(raw)
        yield from emit(decoded, m.start(), "base64" + (">" + how if how else ""))
    for m in _HEXRUN.finditer(text):
        if limit[0] <= 0:
            return
        if len(m.group()) in (32, 40, 64, 128):
            continue
        limit[0] -= 1
        decoded, how = _bytes_to_text(bytes.fromhex(m.group()))
        yield from emit(decoded, m.start(), "hex" + (">" + how if how else ""))
    if "%" in text:
        for m in _PCT_TOKEN.finditer(text):
            if "%" not in m.group() or not _PCT_IN.search(m.group()):
                continue
            if limit[0] <= 0:
                return
            limit[0] -= 1
            try:
                decoded = urllib.parse.unquote(m.group(), errors="strict")
            except (UnicodeDecodeError, ValueError):
                continue
            yield from emit(decoded if decoded != m.group() else None, m.start(), "url")


def _refang(text: str):
    """(text with [.] (.) [dot] [:] hxxp written back, a function from a new offset to the old one)."""
    marks, parts, pos, shift = [], [], 0, 0
    for m in _DEFANG.finditer(text):
        parts.append(text[pos:m.start()])
        new = {"hxxp": "http", "[:]": ":"}.get(m.group().lower(), ".")
        parts.append(new if m.group().lower() != "hxxp" or m.group().islower() else "HTTP")
        shift += len(m.group()) - len(parts[-1])
        marks.append((m.end() - shift, shift))
        pos = m.end()
    parts.append(text[pos:])
    starts = [a for a, _ in marks]

    def back(off):
        i = bisect.bisect_right(starts, off) - 1
        return off + (marks[i][1] if i >= 0 else 0)

    return "".join(parts), back


class Index:
    """Every indicator of a set of files with where it came from. `hits` is a list of
    Hit(kind, value, member, offset, via): kind is one of ipv4, domain, url, email, sha512, sha256,
    sha1, md5, windows_path, unix_path, registry, username, timestamp, guid; offset is the byte offset
    in the member (of the encoded token for a decoded value, -1 when unknown); via is '' for a value
    in the clear, else the decoders it was under ('base64>utf-16le', 'utf-16le', 'hex', 'url',
    'refang', 'json'). The `guid` kind is scanned from raw bytes; the `key` and `password` kinds are
    not scanned (too noisy) -- a reader adds them by hand (solvers/common/evidence_ledger.py, B-068),
    its `via` naming the reader ('lnk', 'hive', 'history', 'pcap', 'pax', 'powershell'). `complete`
    is False when a member was too long to read to its end: 'exactly one' is then not proven.
    `findings` lists instruction-like text."""

    def __init__(self):
        self.hits, self.findings, self.members, self.complete, self.notes = [], [], [], True, []
        self._seen = set()

    def add(self, kind, value, member, offset, via):
        value = value.rstrip(".,;:)]}'\"") if kind in ("url", "domain", "email", "windows_path", "unix_path", "registry") else value
        if kind == "guid":
            value = value.strip("{}")      # {GUID} and GUID are one indicator
        if kind in _LOWER:
            value = value.lower()
        k = (kind, value, member, offset, via)
        if value and k not in self._seen and len(self.hits) < MAX_HITS:
            self._seen.add(k)
            self.hits.append(Hit(*k))

    def values(self, kind, member=None, clear_only=False) -> "OrderedDict":
        """{value: [Hit, ...]} of one kind (`hash` means every hash kind), first seen first."""
        kinds = HASHES if kind == "hash" else ("windows_path", "unix_path") if kind == "path" else (kind,)
        out = OrderedDict()
        for h in self.hits:
            if h.kind in kinds and (member is None or h.member == member or h.member.split(ARROW)[-1] == member) \
                    and not (clear_only and h.via):
                out.setdefault(h.value, []).append(h)
        return out

    def cross(self, kinds=None) -> list:
        """[(kind, value, [members])] for every value seen in two or more members: the pivots."""
        where = OrderedDict()
        for h in self.hits:
            if kinds is None or h.kind in kinds:
                where.setdefault((h.kind, h.value), [])
                if h.member not in where[(h.kind, h.value)]:
                    where[(h.kind, h.value)].append(h.member)
        return [(k, v, ms) for (k, v), ms in where.items() if len(ms) >= 2]

    def summary(self) -> dict:
        out = OrderedDict()
        for h in self.hits:
            out.setdefault(h.kind, OrderedDict()).setdefault(h.value, 0)
            out[h.kind][h.value] += 1
        return out

    # -- building

    def _scan(self, text, member, base, via, back=None, orig=None, exact=True):
        """Scan one text. `base` is its offset in the member; `exact` says whether a position in the
        text is a position in the member (not so for decoded text: every hit then has the offset of
        the encoded token). `back` and `orig` are given for a refanged text."""
        def off(m_start):
            return base if base < 0 or not exact else base + (back(m_start) if back else m_start)

        def how(value):
            return via if orig is None or value in orig else (via + ">" if via else "") + "refang"

        for kind, rx in IOC.items():
            for m in rx.finditer(text):
                self.add(kind, m.group(), member, off(m.start()), how(m.group()))
        for m in _USERNAME.finditer(text):
            v = next((g for g in m.groups() if g), "")
            self.add("username", v.split("\\")[-1], member, off(m.start()), via)
        for name, rx in INSTRUCTIONS:
            for m in rx.finditer(text):
                a, b = max(0, m.start() - 40), min(len(text), m.end() + 80)
                snippet = " ".join(text[a:b].split())[:200]
                f = {"member": member, "offset": off(m.start()), "via": via, "pattern": name, "text": snippet}
                if not any(x["member"] == member and x["pattern"] == name and x["text"] == snippet for x in self.findings) \
                        and len(self.findings) < 200:
                    self.findings.append(f)

    def _text(self, text, member, base, via, exact=True):
        if _DEFANG.search(text):    # a defanged text is read once, written back: hxxp://a[.]b is one URL, not two
            fixed, back = _refang(text)
            self._scan(fixed, member, base, via, back, orig=text, exact=exact)
        else:
            self._scan(text, member, base, via, exact=exact)

    def _leaf(self, text, member, base, via, limit, exact=True):
        self._text(text, member, base, via, exact)
        for decoded, o, how in decoded_views(text, limit=limit):
            self._text(decoded, member, base if base < 0 or not exact else base + o, (via + ">" if via else "") + how, exact=False)

    def _cells(self, member, data, deadline, limit) -> bool:
        """A delimited, XML or sqlite member cell by cell, so a value ends where its cell ends. False
        when the member is no such table."""
        try:
            got = [t for t in tables(member, data) if t.kind in ("csv", "xml", "sqlite")]
        except Exception:
            got = []
        if not got:
            return False
        raw, cursor = data.decode("latin-1"), 0
        for t in got:
            t.deadline = deadline
            for col in t.columns:
                self._text(col, member, -1, "")
            for n, row in enumerate(t):
                if n >= MAX_ROWS:
                    self.complete = False
                    self.notes.append(f"{member}: only the first {MAX_ROWS} rows were read")
                    break
                for cell in row.values():
                    if len(cell) < 4:
                        continue
                    p = raw.find(cell, cursor) if t.kind == "csv" else -1
                    cursor = p if p >= 0 else cursor
                    self._leaf(cell, member, p, "", limit)
        return True

    def add_member(self, member: str, data: bytes, deadline=None):
        self.members.append(member)
        if len(data) > INDEX_SCAN:
            self.complete = False
            self.notes.append(f"{member}: only the first {INDEX_SCAN} of {len(data)} bytes were read")
            data = data[:INDEX_SCAN]
        limit = [MAX_TOKENS]
        doc = None
        if data[:1] in (b"{", b"[") or data[:4] in (b"\xef\xbb\xbf{", b"\xef\xbb\xbf["):
            try:
                doc = [json.loads(data.decode("utf-8-sig"))]
            except (ValueError, UnicodeDecodeError, RecursionError):
                try:
                    doc = [json.loads(ln) for ln in data.decode("utf-8-sig").splitlines() if ln.strip()]
                    doc = doc if doc and all(isinstance(x, (dict, list)) for x in doc) else None
                except (ValueError, UnicodeDecodeError, RecursionError):
                    doc = None
        if doc is not None:
            # A JSON member is read leaf by leaf, so an escaped value (\/ \\ \u0041) is read as written.
            raw, cursor = data.decode("utf-8", "replace"), [0]

            def where(s):
                frag = json.dumps(s, ensure_ascii=False)[1:-1][:48]
                p = raw.find(frag, cursor[0]) if frag else -1
                if p < 0:
                    p = raw.find(json.dumps(s)[1:-1][:48], cursor[0])
                if p >= 0:
                    cursor[0] = p
                    return len(raw[:p].encode("utf-8")) if not raw.isascii() else p
                return -1

            def walk(o, path):
                if deadline is not None and _time.monotonic() > deadline:
                    raise OverBudget(member)
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(k, str) and len(k) > 6:
                            self._leaf(k, member, where(k), "", limit)
                        walk(v, path)
                elif isinstance(o, list):
                    for v in o:
                        walk(v, path)
                elif isinstance(o, str) and o:
                    self._leaf(o, member, where(o), "", limit)

            for d in doc:
                walk(d, "")
            return
        if self._cells(member, data, deadline, limit):
            return
        step = 4 * 1024 * 1024
        for start in range(0, len(data), step):
            if deadline is not None and _time.monotonic() > deadline:
                raise OverBudget(member)
            lo = max(0, start - 4096)
            chunk = data[lo:start + step]
            text = chunk.translate(_CONTROL).decode("latin-1")
            self._text(text, member, lo, "")
            if lo < DECODE_SCAN:
                for decoded, o, how in decoded_views(text, limit=limit):
                    self._text(decoded, member, lo + o, how, exact=False)
                for m in _WIDE.finditer(chunk):
                    self._leaf(m.group().decode("utf-16-le", "replace"), member, lo + m.start(), "utf-16le", limit)
        if len(data) > DECODE_SCAN:
            self.complete = False
            self.notes.append(f"{member}: the decoder pass read the first {DECODE_SCAN} of {len(data)} bytes")


def member_files(files: dict) -> list:
    """[(name, bytes)] of the members to read: each file once, with what triage unpacks further, and
    without an archive whose members are there (its bytes would only repeat them)."""
    allf = dict(files)
    allf.update(triage.expand_more(files))
    parents = {k.split(ARROW)[0] for k in allf if ARROW in k} | {k.split(ARROW)[-2] for k in allf if k.count(ARROW) >= 2}
    out = []
    for name, data in triage.unique_files(allf):
        short = name.split(ARROW)[-1]
        kind = triage.identify(data[:300], short)
        if (short in parents or name in parents) and kind.split(" ")[0] in _ARCHIVES:
            continue
        out.append((name, data))
    return out


def ioc(files, deadline=None) -> Index:
    """The index of {name: bytes} (as a solver is handed its files), of a list of paths, or of one path."""
    if isinstance(files, (str, Path)):
        files = [files]
    if not isinstance(files, dict):
        files = {str(p): Path(p).read_bytes() for p in files}
    ix = Index()
    for name, data in member_files(files):
        ix.add_member(name, data, deadline)
    return ix


def findings(files) -> list:
    """Instruction-like text in the files: [{member, offset, via, pattern, text}]. A report, never an input."""
    return ioc(files).findings


# ---- the router --------------------------------------------------------------------------------------

_KNOWN_LANE = (
    lambda aid, text, f: "ANS-" in text,
    lambda aid, text, f: re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", text) is not None,
    lambda aid, text, f: re.search(r"-(?:role|attack|steps|adapter|campaign)$", aid) is not None or f.get("kind") == "mitre_attack_id",
    lambda aid, text, f: re.match(r"d\d\d_", aid) is not None,
    lambda aid, text, f: aid == "message",
)

# noun -> (how the question says it, column names that hold it, index kind)
NOUNS = (
    ("user_agent", r"\buser[- ]?agents?\b", r"(?:^|[^a-z])(?:user[-_ ]?agent|useragent|ua|http_user_agent)$", None),
    ("hash", r"\b(?:sha-?256|sha-?1|sha-?512|md5|hash(?:es)?|digest|checksum)\b", r"sha-?256|sha-?1|md5|hash|digest|checksum", "hash"),
    ("email", r"\be-?mail(?: address(?:es)?)?\b|\bsenders?\b|\brecipients?\b", r"e-?mail|sender|recipient|^from$|^to$", "email"),
    ("url", r"\burls?\b|\buris?\b|\blinks?\b", r"url|uri|link|request$", "url"),
    ("domain", r"\bdomains?(?: names?)?\b|\bhost ?names?\b|\bfqdns?\b", r"domain|host(?:name)?$|fqdn|sni|qname", "domain"),
    ("ipv4", r"\bip(?:v4)?(?: address(?:es)?)?\b|\bips\b", r"(?:^|[^a-z])ip(?:$|[^a-z])|ip$|addr(?:ess)?$|^(?:src|dst|source|destination|client|remote)$", "ipv4"),
    ("username", r"\busers?(?: ?names?)?\b|\baccounts?(?: names?)?\b|\blogin names?\b|\bwho\b", r"(?:^|[^a-z])user(?:[._ -]?(?:name|id))?$|account(?:[._ -]?name)?$|login$|principal", "username"),
    ("filename", r"\bfile ?names?\b|\bname of the file\b", r"file(?:_?name)?$|^name$", None),
    ("path", r"\b(?:file )?paths?\b", r"path$|^file$", "path"),
    ("timestamp", r"\btimestamps?\b|\bwhen\b|\b(?:what|which) time\b|\bdate and time\b|\bdate\b|\btime\b", None, "timestamp"),
)
_TIME_COLS = re.compile(r"^(?:_?time|@?timestamp|ts|date|datetime|date_?time|event_?time|utc_?time|created(?:_at)?|"
                        r"time_?created|logged_?at|when|eventtime|time_generated|timegenerated|systemtime|.*@systemtime)$", re.I)
_SIDES = (("src", r"\b(?:source|src|client|attacker|attacking|origin(?:ating)?|remote)\b", r"src|source|client|remote|orig|^c-?ip$|^ip$"),
          ("dst", r"\b(?:destination|dst|dest|server|target|victim)\b", r"dst|dest|server|target|^s-?ip$"))
_FAIL_WORDS = r"failed|failing|failures?|unsuccessful|denied|rejected"
_OK_WORDS = r"successful|succeeded|accepted|success(?:es)?"
_RECORD_WORDS = r"rows?|records?|entries|entry|lines?|items?|objects?|elements?"
_STOP = set("""how many number of the total count are is there in inside within file does do contain contains have has having
with where whose that which and a an log table column field value values equal equals to was were recorded present listed
delivered evidence archive exactly data set for all its it be been each on at by from named called what s used use uses using appear
appears appeared exist exists occur occurs occurred did show shows shown""".split())


def _fmt(qn) -> dict:
    f = qn.get("answer_format")
    return f if isinstance(f, dict) else {}


def _aid(qn) -> str:
    return re.sub(r"^set\d+\.", "", str(qn.get("answer_id") or qn.get("qid") or qn.get("id") or ""))


_SCRIPT_FIELD = re.compile(r"-(?:role|attack|steps|adapter|campaign)$")


def known_lane(qn, components=()) -> bool:
    """True for a question that carries the marks of one of the five registered lanes: theirs, not
    ours. `components` are the Script Analysis specimens of the set (lane_components): every
    question about one of them is that lane's, whatever it asks (`<specimen>-url`)."""
    aid, f = _aid(qn), _fmt(qn)
    text = " ".join(str(x or "") for x in (qn.get("question"), f.get("syntax"), f.get("pattern")))
    return any(test(aid, text, f) for test in _KNOWN_LANE) or any(aid.startswith(c + "-") for c in components)


def lane_components(questions) -> tuple:
    """The answer-id prefixes of a set that have a `-role`, `-attack`, `-steps`, `-adapter` or
    `-campaign` question: the Script Analysis lane's specimens."""
    return tuple(sorted({_SCRIPT_FIELD.sub("", _aid(qn)) for qn in questions if _SCRIPT_FIELD.search(_aid(qn))}))


def classify(qn, components=()) -> dict:
    """What a question asks, read from its words alone (no bytes): {op, noun, distinct, n, words}.
    op is count, top, least, first, last, once, burst, which, or None."""
    text = " ".join(str(qn.get("question") or "").split())
    low = text.lower()
    kind = str(_fmt(qn).get("kind") or "")
    out = {"op": None, "noun": None, "distinct": False, "text": text, "kind": kind}
    if not low or known_lane(qn, components) or kind in ("mitre_attack_id", "json", "ordered_tokens"):
        return out
    ask = re.search(r"\b(?:which|what|who|whose|when|name the|identify the|give the|provide the|list the|find the)\b", low)
    start = ask.start() if ask else 0
    best = None
    for noun, rx, _, _ in NOUNS:
        m = re.search(rx, low[start:]) or re.search(rx, low)
        if m:
            pos = m.start() + (start if re.search(rx, low[start:]) else -len(low))
            if best is None or pos < best[0]:
                best = (pos, noun)
    out["noun"] = best[1] if best else None
    if re.search(r"\bhow many\b|\bnumber of\b|\bcount of\b|\btotal (?:number|count)\b|\bhow often\b", low):
        out["op"] = "count"
        out["distinct"] = re.search(r"\b(?:distinct|unique|different)\b", low) is not None
    elif re.search(r"\bbrute[- ]?forc|\bpassword spray|\bafter (?:\d+|several|multiple|repeated|many) (?:failed|failures|unsuccessful)"
                   r"|\bfail(?:ed|ures?)\b.{0,60}\b(?:then|before|followed by|until)\b.{0,40}\bsucce", low):
        out["op"] = "burst"
        m = re.search(r"\b(\d+) (?:or more )?(?:consecutive )?(?:failed|failures|unsuccessful)", low)
        out["n"] = int(m.group(1)) if m else None
    elif re.search(r"\b(?:only|exactly|just) once\b|\b(?:a )?single time\b|\bappears? once\b|\bseen once\b|\bone[- ]off\b", low):
        out["op"] = "once"
    elif re.search(r"\bmost (?:common|frequent|frequently|often|active|requests|times|rows|records|events|entries|hits|connections|logins|attempts|alerts)\b"
                   r"|\b(?:the )?most\b.{0,40}\b(?:requests|times|rows|records|events|entries|hits|connections|logins|attempts|alerts)\b"
                   r"|\bhighest (?:number|count)\b|\blargest (?:number|count)\b|\btop (?:talker|source|user|ip|domain|url)\b", low):
        out["op"] = "top"
    elif re.search(r"\bleast (?:common|frequent|frequently|often|active)\b|\bfewest\b|\brarest\b|\blowest (?:number|count)\b", low):
        out["op"] = "least"
    elif re.search(r"\b(?:first|earliest|initial(?:ly)?|oldest)\b", low) and not re.search(r"\bfirst \d+ bytes\b", low):
        out["op"] = "first"
    elif re.search(r"\b(?:last|latest|most recent|final|newest)\b", low):
        out["op"] = "last"
    elif out["noun"]:
        out["op"] = "which"
    return out


class Evidence:
    """What one set's questions are answered from, built on first use: the members, their tables,
    the index. Nothing is read for a question that is not ours."""

    def __init__(self, files: dict, budget: float = BUDGET, components=()):
        self.files = files
        self.components = tuple(components)
        self.deadline = _time.monotonic() + budget
        self._members = self._tables = self._index = None
        self.index_failed = False

    @property
    def members(self):
        if self._members is None:
            self._members = member_files(self.files)
        return self._members

    @property
    def tables(self):
        if self._tables is None:
            self._tables = []
            for name, data in self.members:
                try:
                    got = tables(name, data)
                except Exception:
                    got = []
                for t in got:
                    t.deadline = self.deadline
                    t.data = data
                    self._tables.append(t)
        return self._tables

    @property
    def index(self):
        """The index, or None when it could not be finished in time (then nothing is 'the only one')."""
        if self._index is None and not self.index_failed:
            try:
                ix = Index()
                for name, data in self.members:
                    ix.add_member(name, data, self.deadline)
                self._index = ix
            except OverBudget:
                self.index_failed = True
        return self._index

    def named(self, qn) -> list:
        """The members a question names in its text (or as its artifact's member): [(name, bytes)]."""
        text = str(qn.get("question") or "")
        hits = []
        for name, data in self.members:
            short = name.split(ARROW)[-1]
            for n in {short, Path(short).name}:
                if len(n) > 2 and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", text, re.I):
                    hits.append((name, data))
                    break
        member = qn.get("member")
        if member and not hits:
            hits = [(n, d) for n, d in self.members if Path(n.split(ARROW)[-1]).name == Path(str(member)).name]
        return hits


def _fits(qn, value) -> bool:
    return triage._fits(qn, str(value))


def _keep(qn, options) -> list:
    """The options whose value the answer_format's own pattern does not refuse, each value once."""
    out, seen = [], set()
    for name, value in options:
        if value is None or str(value) == "" or str(value) in seen or not _fits(qn, value):
            continue
        seen.add(str(value))
        out.append((name, str(value)))
    return out


def _residue(text: str, used: list) -> list:
    """The content words of a question that no recognized part accounts for."""
    low = text.lower()
    for u in sorted({u.lower() for u in used if u}, key=len, reverse=True):
        low = low.replace(u, " ")
    return [w for w in re.findall(r"[a-z0-9_]+", low) if w not in _STOP and not re.fullmatch(_RECORD_WORDS, w)]


def _line_readings(data: bytes) -> dict:
    """The line counts of a text member: newline-ended lines, the non-empty ones, and the count
    with every line end a text reader knows (a bare CR, a form feed). One number is proven only
    when all three agree. UTF-16 is decoded first: a 0x0A byte inside U+010A is no line end."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", "replace").lstrip("﻿")
    else:
        text = data.decode("latin-1")
    physical = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    # `newlines` is what `wc -l` prints: one less than the lines of a file whose last line has no line
    # end (every loghub sample is such a file: 2,000 log lines, 1,999 newlines)
    return {"lines": physical, "non_empty_lines": sum(1 for ln in text.split("\n") if ln.strip()),
            "universal_lines": len(text.splitlines()), "newlines": text.count("\n")}


def _folded_rivals(t, where: dict) -> bool:
    """True when a filter's column holds a cell that differs from the asked value only by case or
    outer blanks (`404` beside ` 404`, `POST` beside `post`): the count then has two readings."""
    rows = t.rows() or []
    for col, want in where.items():
        w = str(want).strip().lower()
        if any(r.get(col, "") != want and str(r.get(col, "")).strip().lower() == w for r in rows):
            return True
    return False


def _tables_for(ev: Evidence, qn) -> list:
    named = ev.named(qn)
    ts = [t for t in ev.tables if t.is_table]
    if named:
        names = {n for n, _ in named}
        ts = [t for t in ts if t.meta.get("member") in names]
        low = str(qn.get("question") or "").lower()
        inner = [t for t in ts if "#" in t.name and re.search(r"(?<![\w.])" + re.escape(t.name.split("#")[-1].lower()) + r"(?![\w.])", low)]
        ts = inner or ts
    return ts


def _column(t: Table, qn, noun, cls):
    """The one column of a table a question means, or None: a column the question names by its own
    name, else the columns of the noun, narrowed by the side the question says (source, destination)."""
    low = cls["text"].lower()
    exact = [c for c in t.columns if len(c) >= 3 and not c.startswith("_")
             and re.search(r"(?<![\w.@-])" + re.escape(c.lower()) + r"(?![\w.-])", low)]
    spec = next((n for n in NOUNS if n[0] == noun), None)
    if spec is None or spec[2] is None:
        cand = []
    else:
        cand = [c for c in t.columns if not c.startswith("_") and re.search(spec[2], c, re.I)]
    if noun and exact:
        both = [c for c in exact if c in cand]
        if len(both) == 1:
            return both[0], True
    if len(cand) > 1:
        for _, said, colrx in _SIDES:
            if re.search(said, low):
                side = [c for c in cand if re.search(colrx, c, re.I)]
                if len(side) == 1:
                    return side[0], False
        return None, False
    if len(cand) == 1:
        return cand[0], cand[0] in exact
    if not noun and len(exact) == 1:
        return exact[0], True
    return None, False


def _time_column(t: Table):
    cols = [c for c in t.columns if _TIME_COLS.match(c.split(".")[-1])]
    return cols[0] if len(cols) == 1 else None


def _filters(t: Table, text: str, skip=()):
    """(explicit, anchored, used): explicit filters are written with the column's own name
    ("status = 404", "method is POST"); anchored ones are values of the question (an IP, a quoted
    text, a number) that are cells of exactly one column. `used` lists the words they account for."""
    explicit, anchored, used = {}, {}, []
    rows = t.rows()
    if rows is None:
        return None, None, used
    cells = {}
    for c in t.columns:
        if not c.startswith("_"):
            cells[c] = {r.get(c, "") for r in rows}
    for c in sorted(cells, key=len, reverse=True):
        if c in skip or len(c) < 2:
            continue
        m = re.search(r"(?<![\w.@-])" + re.escape(c) + r"(?:\s+(?:is|was|equals?|of|equal to|code)\s+|\s*(?:==?|:)\s*|\s+)"
                      r"(?:\"([^\"]+)\"|'([^']+)'|`([^`]+)`|([^\s\"'`?,]+))", text, re.I)
        if m:
            v = next(g for g in m.groups() if g)
            v = v.rstrip(".?") if v not in cells[c] else v
            if v in cells[c]:
                explicit[c] = v
                used.append(m.group())
    quoted = [a or b or c for a, b, c in re.findall(r"\"([^\"]+)\"|'([^']+)'|`([^`]+)`", text)]
    tokens = quoted + _IPV4.findall(text) + re.findall(r"(?<![\w.])\d{3,}(?![\w.])", text) \
        + re.findall(r"(?<![\w@.-])[\w-]+(?:\.[\w-]+)+(?![\w-])", text)
    for tok in dict.fromkeys(tokens):
        if tok in explicit.values():
            continue
        cols = [c for c, vals in cells.items() if tok in vals and c not in skip]
        if len(cols) == 1 and cols[0] not in explicit:
            anchored[cols[0]] = tok
            used.append(tok)
    return explicit, anchored, used


def _answer_count(qn, ev: Evidence, cls):
    text, aid = cls["text"], _aid(qn)
    low = text.lower()
    named = ev.named(qn)
    word = re.search(r"\b(?:how many|number of|count of|total (?:number|count) of)\s+(?:(?:distinct|unique|different|total)\s+)*([a-z][a-z _-]*?)"
                     r"(?=\s+(?:are|is|were|was|in|inside|within|of|does|do|did|appear|exist|have|has|with|where|whose|that|which|from|for|on|made|occur)\b|\?|$)", low)
    subject = word.group(1).strip() if word else ""
    generic = re.fullmatch(_RECORD_WORDS, subject) is not None
    ts = _tables_for(ev, qn)
    used = [n.split(ARROW)[-1] for n, _ in named] + [Path(n.split(ARROW)[-1]).name for n, _ in named]
    if cls["distinct"]:
        # distinct values of a column of the one table, else of an indicator kind in the index
        for t in ts if len(ts) == 1 else []:
            col, exact = _column(t, qn, cls["noun"], cls)
            if col:
                explicit, anchored, fused = _filters(t, text, skip=(col,))
                if explicit is None:
                    return None
                where = {**explicit, **anchored}
                values = distinct(t, col, where or None)
                if not values or t.bad:
                    return None
                folded = len({v.strip().lower() for v in values})
                readings = _keep(qn, [(f"distinct.{col}", len(values)), (f"distinct_folded.{col}", folded)])
                plain = exact and named and not anchored and col not in t.derived and len(readings) == 1 \
                    and t.kind not in ("json-records", "xml") and not _folded_rivals(t, explicit) \
                    and not _residue(text, used + fused + [col, "distinct", "unique", "different", subject])
                return readings[0][1] if plain else pick("count", aid, readings)
        spec = next((n for n in NOUNS if n[0] == cls["noun"]), None)
        if spec and spec[3] and ev.index is not None and ev.index.complete:
            members = [n for n, _ in named] or [None]
            if len(members) != 1:
                return None
            every = ev.index.values(spec[3], members[0])
            clear = ev.index.values(spec[3], members[0], clear_only=True)
            if not every:
                return None
            return pick("count", aid, _keep(qn, [(f"distinct_{spec[3]}", len(clear) or None), (f"distinct_{spec[3]}_decoded", len(every))]))
        return None
    if len(named) != 1:
        return None
    name, data = named[0]
    ts = [t for t in ts if t.meta.get("member") == name]
    if subject in ("lines", "line") and not re.search(r"\b(?:that|which|where|with|whose|contain|containing|match|matching)\b", low):
        if not any(t.meta.get("member") == name and t.kind != "sqlite" for t in ev.tables):
            return None             # a binary member has no lines
        r = _line_readings(data)
        opts = _keep(qn, [("lines", r["lines"]), ("non_empty_lines", r["non_empty_lines"]), ("universal_lines", r["universal_lines"]),
                          ("newlines", r["newlines"])])
        if len(opts) == 1 and not _residue(text, used):
            return opts[0][1]
        return pick("count", aid, opts)
    if len(ts) != 1:
        return None
    t = ts[0]
    explicit, anchored, fused = _filters(t, text)
    if explicit is None:
        return None
    words = subject.split()
    if "outcome" in t.columns:      # "failed logins", "successful logons": the outcome column, read from the message
        for w in list(words):
            side = "failure" if re.fullmatch(_FAIL_WORDS, w) else "success" if re.fullmatch(_OK_WORDS, w) else None
            if side and "outcome" not in explicit:
                anchored["outcome"] = side
                words.remove(w)
    if not generic and len(words) > 1:
        return None                 # a count of something these rules cannot name ("lateral movement attempts")
    where = {**explicit, **anchored}
    n = count(t, where or None)
    if t.bad or (where and n == 0):
        return None
    # Which rows are "the records" is this module's reading, not a fact of the bytes, for a list
    # found inside a JSON object, for an XML record element, and for a csv (is its first line a
    # header?): a count over those is never plain.
    chosen = t.kind in ("json-records", "xml") or (t.kind == "csv" and not t.meta.get("header"))
    if where:
        cols = "+".join(sorted(where))
        if _residue(text, used + fused + [subject]):
            return None
        rivals = _folded_rivals(t, where)
        plain = generic and not anchored and not (set(where) & t.derived) and not _residue(text, used + fused) \
            and _fits(qn, n) and not chosen and not rivals
        if plain:
            return str(n)
        opts = [(f"rows_where.{cols}", n)]
        if rivals:
            folded = {c: (lambda v, w=str(w).strip().lower(): v.strip().lower() == w) for c, w in where.items()}
            opts.append((f"rows_where_folded.{cols}", count(t, folded)))
        return pick("count", aid, _keep(qn, opts))
    if _residue(text, used + [subject]):
        return None                 # the question says more than "how many <rows> in <file>": a filter that was not read
    if t.kind == "csv":
        lines = _line_readings(data)
        opts = [("data_rows", n), ("lines", lines["lines"]), ("non_empty_lines", lines["non_empty_lines"])]
        if not t.meta.get("header"):
            opts.insert(1, ("data_rows_less_header", n - 1 if n > 1 else None))
    elif t.kind in ("json-array", "json-records", "xml", "sqlite"):
        opts = [("records" + (("." + _shape(t.meta.get("record_tag") or t.meta.get("path"))) if chosen else ""), n)]
    else:
        opts = [("records", n), ("lines", _line_readings(data)["lines"])]
    opts = _keep(qn, opts)
    if generic and len(opts) == 1 and not chosen:
        return opts[0][1]
    return pick("count", aid, opts)


def _time_pick(qn, aid, field, method, raw):
    syntax = (str(_fmt(qn).get("syntax") or "") + " " + str(qn.get("question") or "")).lower()
    prefer = "epoch" if re.search(r"\bepoch\b|\bunix\b", syntax) else "iso_z" if re.search(r"\biso\b|\butc\b|rfc ?3339", syntax) else None
    opts = _keep(qn, [(f"{method}:{n}", v) for n, v in time_options(parse_time(raw), raw, prefer)])
    return pick(field, aid, opts)


def _answer_table(qn, ev: Evidence, cls):
    """top, least, first, last, once, burst: a rule the question states, over the one table that has
    the column it means. Always unsure (the column and the method are read from words); a tie is None."""
    op, noun, aid, text = cls["op"], cls["noun"], _aid(qn), cls["text"]
    found = []
    for t in _tables_for(ev, qn):
        tcol = _time_column(t)
        if noun == "timestamp":
            col = tcol
        else:
            col, _ = _column(t, qn, noun, cls)
            if col is None and noun in ("ipv4", "username") and t.kind in ("syslog", "timed"):
                col = {"ipv4": "ip", "username": "user"}[noun]
        if col and (op not in ("first", "last") or tcol):
            found.append((t, col, tcol))
    if len(found) != 1:
        return None
    t, col, tcol = found[0]
    explicit, anchored, _ = _filters(t, text, skip=(col,))
    if explicit is None:
        return None
    where = {**explicit, **anchored}
    suffix = (".where." + "+".join(sorted(where))) if where else ""
    if op == "burst":
        if "outcome" not in t.columns:
            return None
        hits = burst(t, col, "outcome", n=cls.get("n") or 3, where=where or None)
        keys = list(dict.fromkeys(h["key"] for h in hits))
        if len(keys) != 1 or t.bad:
            return None
        return pick(noun or "value", aid, _keep(qn, [(f"burst.{col}{suffix}", keys[0])]))
    if op == "once":
        values = seen_once(t, col, where or None)
        if len(values) != 1 or t.bad:
            return None
        if noun == "timestamp":
            return _time_pick(qn, aid, "timestamp", f"once.{col}{suffix}", values[0])
        return pick(noun or "value", aid, _keep(qn, [(f"once.{col}{suffix}", values[0])]))
    if op in ("top", "least"):
        ranked, tie = top(t, col, 1, where or None, least=(op == "least"))
        if not ranked or tie or t.bad:
            return None
        name = ("most_common" if op == "top" else "least_common") + f".{col}{suffix}"
        return pick(noun or "value", aid, _keep(qn, [(name, ranked[0][0])]))
    rows, problem = edge(t, tcol, where or None, last=(op == "last"))
    values = list(dict.fromkeys(r.get(col, "") for r in rows))
    if problem or len(values) != 1 or values[0] == "" or t.bad:
        return None
    if noun == "timestamp":
        return _time_pick(qn, aid, "timestamp", f"{op}.{col}{suffix}", values[0])
    return pick(noun or "value", aid, _keep(qn, [(f"{op}.{col}{suffix}", values[0])]))


def _answer_which(qn, ev: Evidence, cls):
    """No rule stated: only 'the only one of its kind' is an answer. A hash is plain when exactly one
    string of its grammar exists in the whole delivery (in the members the question names, when it
    names any); every other kind is unsure under the method `only_one`; two candidates are None."""
    noun, aid, text = cls["noun"], _aid(qn), cls["text"]
    spec = next((n for n in NOUNS if n[0] == noun), None)
    ix = ev.index
    if spec is None or spec[3] is None or ix is None or not ix.complete:
        return None
    named = [n for n, _ in ev.named(qn)]
    kind = spec[3]
    if noun == "hash":
        algos = {m.group().lower().replace("-", "") for m in triage._ANY_ALGO.finditer(text)}
        if len(algos) > 1 or (algos and next(iter(algos)) not in HASHES):
            return None
        kind = next(iter(algos)) if algos else "hash"
    values = OrderedDict()
    for member in (named or [None]):
        for v, hits in ix.values(kind, member).items():
            values.setdefault(v, []).extend(hits)
    if len(values) != 1:
        return None
    value = next(iter(values))
    if noun == "hash":
        f = _fmt(qn)
        words = str(f.get("syntax") or "") + " " + text
        if re.search(r"\b0x\b|\bprefix|\bbase64\b|\bseparat|\bcolon", words, re.I) or str(f.get("kind") or "") == "enum":
            return None
        value = value.upper() if re.search(r"\bupper-?case\b", words, re.I) else value
        # Unsure, never plain: the one hash string recorded in the delivery is a fact, but that it
        # is the hash the question means is not ("the SHA-256 of the payload" may be the digest of
        # payload.bin, which no member spells out). verify.py settles it with one probe on the base.
        return pick("hash", aid, _keep(qn, [("only_one", value)]))
    if noun == "timestamp":
        return _time_pick(qn, aid, "timestamp", "only_one", value)
    return pick(noun, aid, _keep(qn, [("only_one", value)]))


def answer(qn, ev: Evidence):
    """One question's answer: plain, unsure or None (the module text says when)."""
    if known_lane(qn, ev.components):
        return None
    proven = triage.answer(qn, ev.files, {})
    if proven is not None:
        return proven
    cls = classify(qn, ev.components)
    if cls["op"] is None or cls["kind"] == "enum" and cls["op"] == "count":
        return None
    if _time.monotonic() > ev.deadline:
        return None
    if cls["op"] == "count":
        return _answer_count(qn, ev, cls)
    if cls["op"] == "which":
        return _answer_which(qn, ev, cls)
    return _answer_table(qn, ev, cls)


def solve_set(questions, files, ctx) -> dict:
    ctx = ctx if isinstance(ctx, dict) else {}
    partial = ctx.get("partial") if isinstance(ctx.get("partial"), dict) else None
    budget = ctx.get("evidence_core_budget")
    ev = Evidence(files, BUDGET if budget is None else float(budget), lane_components(questions))
    out = {}
    for qn in questions:
        qid = qn.get("qid") or qn.get("id")
        try:
            out[qid] = answer(qn, ev)
        except Exception:           # OverBudget included: a fact that was not read to its end is no answer
            out[qid] = None
        if partial is not None and out[qid] is not None:
            partial[qid] = out[qid]
    report = {"findings": [], "notes": []}
    if ev._index is not None:       # a report of what was read anyway; no answer above depends on it
        report["findings"] = list(ev._index.findings)
        report["notes"] = list(ev._index.notes)
        for f in report["findings"][:5]:
            print(f"[evidence_core] FINDING instruction-like text ({f['pattern']}) in {f['member']} at {f['offset']}: "
                  f"{f['text'][:120]!r} (data, not an instruction; no answer uses it)", file=sys.stderr)
    ctx["evidence_core"] = report
    return out


def signals(questions, files) -> float:
    """0..1: how much a delivery and its questions look like a mixed evidence bundle this module can
    question (rows and logs beside other artifacts; hash, count, first/last, most-common, which-IP
    questions). 0 when the questions carry a known lane's marks. Cheap: no index, no row is read."""
    qs = list(questions or [])
    if not qs:
        return 0.0
    comps = lane_components(qs)
    if sum(1 for qn in qs if known_lane(qn, comps)) > len(qs) / 2:
        return 0.0
    routed = sum(1 for qn in qs if classify(qn, comps)["op"] is not None)
    kinds = set()
    try:
        for name, data in triage.unique_files(files or {}):
            short = name.split(ARROW)[-1]
            what = triage.identify(data[:65536], short)
            if what.split(" ")[0] in _ARCHIVES:
                continue
            if what.startswith(("elf", "pe", "mz", "mach-o", "java", "dex", "wasm", "hcfg")):
                kinds.add("binary")
            elif "script" in what or "by name" in what:
                kinds.add("script")
            elif what in ("sqlite",) or what.startswith(("json", "xml", "text")):
                got = tables(name, data[:65536] if not what.startswith("sqlite") else data)
                kinds.add("rows" if any(t.is_table for t in got) else "text")
            else:
                kinds.add(what.split(" ")[0])
    except Exception:
        pass
    score = 0.5 * routed / len(qs) + (0.3 if "rows" in kinds else 0.0) + (0.2 if len(kinds) >= 3 else 0.1 if len(kinds) == 2 else 0.0)
    return round(max(0.0, min(1.0, score)), 3)


# ---- the command -------------------------------------------------------------------------------------

def _load_paths(paths) -> tuple:
    """({name: bytes}, [(questions, files, ctx)]) for files, folders and saved attempt folders."""
    import zipfile
    files, sets = {}, []
    for p in map(Path, paths):
        if p.is_dir() and ((p / "attempt.json").is_file() or (p / "status.json").is_file()):
            _, got, _ = triage.load(p)
            sets.extend(got)
            for _, f, _ in got:
                for k, v in f.items():
                    files.setdefault(k, v)
            continue
        for f in (sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]):
            data = f.read_bytes()
            files[f.name if f.name not in files else str(f)] = data
            if data[:4] == b"PK\x03\x04":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        for info in zf.infolist():
                            if not info.is_dir() and not info.flag_bits & 1 and info.file_size <= MAX_DOC:
                                body = zf.read(info)
                                files[f"{f.name}{ARROW}{info.filename}"] = body
                                files.setdefault(info.filename, body)
                except Exception:
                    pass
    return files, sets


def report(files: dict, sets=(), cap: float = 20.0) -> str:
    t0 = _time.monotonic()
    lines = ["# evidence_core triage", ""]
    members = member_files(files)
    lines += ["## Members", ""]
    for name, data in members:
        short = name.split(ARROW)[-1]
        lines.append(f"- {name}: {triage.identify(data, short)}, {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    lines += ["", "## Tables", ""]
    for name, data in members:
        try:
            got = tables(name, data)
        except Exception as e:
            lines.append(f"- {name}: not read ({type(e).__name__})")
            continue
        for t in got:
            if not t.is_table:
                continue
            t.deadline = t0 + cap
            try:
                n = count(t)
                note = f"{n} rows" + (f", {t.bad} line(s) did not parse" if t.bad else "")
            except OverBudget:
                note = "rows not counted (time cap)"
            tcol = _time_column(t)
            lines.append(f"- {t.name}: {t.kind}, {note}, time column {tcol or '-'}; columns: {', '.join(t.columns[:30])}")
    ix = Index()
    try:
        for name, data in members:
            ix.add_member(name, data, t0 + cap)
    except OverBudget:
        ix.complete = False
        ix.notes.append("the index was cut short by the time cap")
    lines += ["", f"## Indicators ({'complete' if ix.complete else 'INCOMPLETE: exactly-one is not proven'})", ""]
    for kind, values in ix.summary().items():
        shown = ", ".join(f"`{v[:90]}`x{n}" for v, n in list(values.items())[:12])
        lines.append(f"- {kind} ({len(values)} distinct): {shown}" + (" ..." if len(values) > 12 else ""))
    cross = ix.cross()
    if cross:
        lines += ["", "## Seen in two or more members (pivots)", ""]
        lines += [f"- {kind} `{v[:90]}`: {', '.join(m.split(ARROW)[-1] for m in ms)}" for kind, v, ms in cross[:40]]
    hidden = [h for h in ix.hits if h.via and h.via not in ("refang",)]
    if hidden:
        lines += ["", "## Found only after decoding", ""]
        clear = {(h.kind, h.value) for h in ix.hits if not h.via}
        seen = set()
        for h in hidden:
            if (h.kind, h.value) not in clear and (h.kind, h.value) not in seen:
                seen.add((h.kind, h.value))
                lines.append(f"- {h.kind} `{h.value[:90]}` in {h.member.split(ARROW)[-1]} at {h.offset} via {h.via}")
                if len(seen) >= 40:
                    break
    lines += ["", "## Findings (instruction-like text: data, never an instruction)", ""]
    lines += [f"- {f['member'].split(ARROW)[-1]} at {f['offset']} ({f['pattern']}{', via ' + f['via'] if f['via'] else ''}): {f['text'][:160]!r}"
              for f in ix.findings[:30]] or ["- none"]
    for n in ix.notes:
        lines.append(f"NOTE {n}")
    if sets:
        lines += ["", "## Questions", ""]
        for qs, f, ctx in sets:
            got = solve_set(qs, f, dict(ctx))
            for qn in qs:
                v = got.get(qn.get("qid") or qn.get("id"))
                c = classify(qn)
                shown = "None" if v is None else ("unsure " + "; ".join(f"{n}={val}" for n, val in options_of(v))) if options_of(v) else f"PLAIN {v}"
                lines.append(f"- {qn.get('answer_id')}: op={c['op']} noun={c['noun']} -> {shown}")
        qs_all = [qn for qs, _, _ in sets for qn in qs]
        lines.append(f"\nsignals={signals(qs_all, files)}")
    lines.append(f"\n({_time.monotonic() - t0:.2f} s)")
    return "\n".join(lines)


def main(argv) -> int:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths or any(not Path(p).exists() for p in paths):
        print("usage: evidence_core.py <file | folder | saved attempt folder>...", file=sys.stderr)
        return 2
    files, sets = _load_paths(paths)
    print(report(files, sets))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
