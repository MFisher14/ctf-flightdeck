#!/usr/bin/env python3
"""Metadata Forensics Day-26 forensic wiring pack (oracle-audit row 8): the forensic parsers that existed only in
the disconnected toolkit layer (solvers/toolkits/windows.py, ese_reader.py), reached from the metadata lane.

properties_strict.py loads this file by name (MORE_FILES, last) and calls register(M). NOTHING here is plain: every
name is registered unconfirmed on a namespace no earlier pack reads (or, in an existing namespace, only a name that
nothing else reads: free()), so the strict wrapper offers each through labels.pick until the judge accepts a format
for its key, and no saved answer can move. The toolkit modules are loaded LAZILY, by path, at the first question
about a file whose own magic matched (never at import, never for another file type); a toolkit that is missing
costs only these readers (Unknown).

  amcache     Amcache.hve (a regf hive whose root holds InventoryApplicationFile, or the old File/Programs keys):
              entry count, program names, file paths, SHA-1 values, the most recently written entry.
  shimcache   the AppCompatCache value of a SYSTEM hive (Windows 7, 8, 8.1, 10): entry count, the paths, the
              position-0 and last paths, the position-0 modified time.
  userassist  the UserAssist Count keys of an NTUSER.DAT (ROT13 names): entry count (with and without the
              UEME_CTL session markers), program names, run counts, total, maximum, most-run program, latest run.
  ese         an Extensible Storage Engine database (SRUDB.dat, WebCacheV01.dat, Windows.edb, ntds.dit): header
              page size, format version and revision, stated and file page counts, the catalog's table names and count
              (only when the catalog read was exact), and under `srum` and `webcache` (told by their own tables) the
              table list and the row count of SruDbIdMapTable / Containers (only a row count the walk proved exact).
  evtx        names no earlier pack reads: chunk count, the distinct event ids, providers, channels, computers, the
              earliest and latest event time. Read through python-evtx and ONLY when every record rendered.
  prefetch    (1) the MAM (Xpress-Huffman, Windows 10) wrapper is peeled for EVERY existing unconfirmed prefetch.*
              reader: the decompressed image is accepted only when its length equals the header's, it starts SCCA,
              its own file-size field equals that length, its version is 17, 23, 26, 30 or 31 and its section
              offsets fit; anything else stays Unknown, as before. (2) new names: the referenced-file strings (list,
              count) and the file-metrics count.

Never-wrong rules used throughout: values are walked by the structures' own offsets; a stated count that disagrees
with the walk is an Ambiguous pair (walked first), never one value; a list that cannot be represented, a damaged,
cut, forged or ambiguous structure is Unknown (None); a flag, a hash or a secret is never read.

Declined, with the reason (never-wrong over coverage):
  - Per-table ESE row VALUES and per-named-table counts other than SruDbIdMapTable / Containers: no property name states
    the table or column, and the reader contract never sees the question text.
  - dfir_chain: a cross-artifact correlation (a chain of facts across files), not a property of one file.
  - MAM variants other than the 0x04 header (the 8-byte form seen on Windows 10 files): the toolkit's other branch is
    unverified by any sample here.
  - A UserAssist/AppCompatCache/Amcache entry's ordering is the hive's own order; no alternative orderings are offered.
"""
import hashlib
import importlib.util
import struct
import sys
import time
from pathlib import Path

M = None
SECTIONS = []
NEW_FNS = []

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"

HIVE_MAX = 64 << 20
ESE_MAX = 256 << 20
EVTX_MAX = 16 << 20
EVTX_SECONDS = 2.5
MAM_IN_MAX = 4 << 20
MAM_OUT_MAX = 8 << 20
PF_VERSIONS = (17, 23, 26, 30, 31)
WALK = 1 << 16


def section(fn):
    SECTIONS.append(fn)
    return fn


def U(msg):
    raise M.Unknown(msg)


def free(ns, names):
    if ns == "evtx":
        # lookup() would compile readers_day14's late-compiled evtx families at import (a test pins that they stay
        # lazy); none of this pack's evtx names can match them (tests/test_day26_forensic_wiring.py proves it)
        return [x for x in names if M.canon(f"{ns}.{x}") not in M.REG]
    return [x for x in names if M.canon(f"{ns}.{x}") not in M.REG and M.lookup(f"{ns}.{x}") is None]


def _page():
    """True while the facts page asks every reader of a file: the costly readers decline there (like readers_msi)."""
    try:
        return M.FACTS_PAGE[0] > 0
    except Exception:
        return False


def reg(ns, names, fmt, fn):
    names = free(ns, list(names))
    if names:
        M.prop(*[f"{ns}.{x}" for x in names], fmt=fmt)(fn)
        NEW_FNS.append(fn)


def namespace(ns, tokens=(), test=None, alias=()):
    if ns not in M.NAMESPACES:
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, *tokens})
        M.RELATED.setdefault(ns, (ns,))
        if test is not None:
            M.MORE_TYPES.append((ns, test))
    M.NS_ALIAS.update({a: ns for a in alias if a not in M.NS_ALIAS and a not in M.NAMESPACES})


def register(module):
    global M
    M = module
    before = dict(M.REG)
    families = len(M.FAMILIES)
    NEW_FNS.clear()
    for s in SECTIONS:
        s()
    M.TIE_FREE.update(f for f in NEW_FNS)
    return len(M.REG) - len(before), len(M.FAMILIES) - families


# ------------------------------------------------------------------ lazy toolkit load and a small memo
_MODS = {}


def _toolkit(name):
    if name not in _MODS:
        mod = None
        path = TOOLKITS / (name + ".py")
        try:
            if path.is_file():
                spec = importlib.util.spec_from_file_location("metadata_toolkit_" + name, str(path))
                mod = importlib.util.module_from_spec(spec)
                saved = list(sys.path)
                try:
                    spec.loader.exec_module(mod)
                finally:
                    sys.path[:] = saved
        except Exception:
            mod = None
        _MODS[name] = mod
    if _MODS[name] is None:
        U(f"the {name} toolkit is not available")
    return _MODS[name]


_MEMO = {}


def _memo(tag, d, fn):
    """fn(d) once per (tag, content); a raise is kept and re-raised (never a second parse of a bad file)."""
    # `hash(bytes)` is a process-randomized table hash, not a content identity.  A collision here would reuse a
    # successful parse (or an Unknown) from a different artifact.  Keep the bounded memo's footprint small while
    # keying it by a collision-resistant digest of every byte.
    key = (tag, len(d), hashlib.sha256(d).digest())
    if key not in _MEMO:
        if len(_MEMO) >= 12:
            _MEMO.pop(next(iter(_MEMO)))
        try:
            _MEMO[key] = ("ok", fn(d))
        except M.Unknown as e:
            _MEMO[key] = ("unknown", str(e))
        except Exception as e:  # a parser that breaks on a forged file is Unknown, never an answer
            _MEMO[key] = ("unknown", f"{type(e).__name__} while reading the structure")
    state, value = _MEMO[key]
    if state != "ok":
        U(value)
    return value


def _ft(stamp):
    return None if stamp is None else M._filetime(int(stamp))


# ============================================================ registry hives (windows.Hive)
def _hive(d: bytes):
    if d[:4] != b"regf" or len(d) < 0x1020:
        return None
    if len(d) > HIVE_MAX:
        U("a hive larger than is read")
    w = _toolkit("windows")

    def build(d):
        try:
            h = w.Hive(d)
            h.kind  # the root's subkeys must read
            return h
        except (ValueError, struct.error, IndexError, RecursionError):
            U("the hive does not read")
    return _memo("hive", d, build)


def _kind(d):
    h = _hive(d)
    return None if h is None else h.kind


# ---- Amcache
def _amcache(d: bytes):
    h = _hive(d)
    if h is None:
        return None
    w = _toolkit("windows")

    def build(d):
        inv = h.find("Root\\InventoryApplicationFile\\*") or h.find("InventoryApplicationFile\\*")
        old = h.find("Root\\File\\*\\*") or h.find("File\\*\\*")
        if not inv and not old and h.kind != "AMCACHE":
            return None
        rows = w.amcache(h)
        # the toolkit reads an old-layout key only when it holds value 15 or 101; count the keys the same way
        old_keys = [k for k in old if "15" in k.values() or "101" in k.values()]
        return {"rows": rows, "keys": len(inv) + len(old_keys)}
    return _memo("amcache", d, build)


def _am_count(n, d):
    a = _amcache(d)
    if a is None:
        return None
    rows = a["rows"]
    if a["keys"] != len(rows):
        raise M.Ambiguous([("with_data", str(len(rows))), ("all_keys", str(a["keys"]))])
    return len(rows)


def _am_list(key):
    def fn(n, d):
        a = _amcache(d)
        if a is None:
            return None
        vals = [r.get(key) for r in a["rows"]]
        if not vals:
            return None
        if any(not isinstance(v, str) or not v for v in vals):
            U("an entry lacks this value, so the list cannot be whole")
        return vals
    return fn


def _am_latest(want):
    def fn(n, d):
        a = _amcache(d)
        if a is None:
            return None
        rows = [r for r in a["rows"] if r.get("time") is not None]
        if not rows:
            return None
        best = max(int(r["time"]) for r in rows)
        top = [r for r in rows if int(r["time"]) == best]
        if len(top) != 1:
            U("two entries share the latest write time")
        r = top[0]
        return _ft(r["time"]) if want == "time" else (r.get(want) or U("the latest entry lacks this value"))
    return fn


@section
def _reg_amcache():
    namespace("amcache", tokens=("amcache_hve", "inventoryapplicationfile"),
              test=lambda d: _safe_am(d), alias=("amcache_hve", "inventoryapplicationfile"))
    reg("amcache", ("entry_count", "number_of_entries", "application_count", "program_count", "file_entry_count",
                    "inventory_entry_count", "entries"), "integer", _am_count)
    reg("amcache", ("program_names", "application_names", "entry_names", "file_names", "names"), "list",
        _am_list("name"))
    reg("amcache", ("file_paths", "entry_paths", "program_paths", "paths"), "list", _am_list("path"))
    reg("amcache", ("sha1_hashes", "entry_sha1_hashes", "file_sha1_hashes", "sha1s"), "list", _am_list("sha1"))
    reg("amcache", ("latest_entry_name", "most_recent_entry_name", "newest_entry_name", "most_recent_program_name"),
        "text", _am_latest("name"))
    reg("amcache", ("latest_entry_path", "most_recent_entry_path", "newest_entry_path"), "text", _am_latest("path"))
    reg("amcache", ("latest_entry_time", "most_recent_entry_time", "newest_entry_time", "last_written_time"),
        "filetime", _am_latest("time"))


def _safe_am(d):
    try:
        return _amcache(d) is not None
    except Exception:
        return False


def _safe_kind(d):
    try:
        return _kind(d)
    except Exception:
        return None


# ---- ShimCache
def _shim(d: bytes):
    h = _hive(d)
    if h is None or h.kind != "SYSTEM":
        return None
    w = _toolkit("windows")
    rows = _memo("shim", d, lambda d: w.shimcache(h))
    return rows or None


def _shim_count(n, d):
    r = _shim(d)
    return None if r is None else len(r)


def _shim_paths(n, d):
    r = _shim(d)
    if r is None:
        return None
    if any(not x.get("path") for x in r):
        U("an entry has no path")
    return [x["path"] for x in r]


def _shim_at(idx, what):
    def fn(n, d):
        r = _shim(d)
        if r is None:
            return None
        e = r[idx]
        if what == "path":
            return e["path"] or U("the entry has no path")
        return _ft(e["modified"]) if e["modified"] is not None else U("the entry has no modified time")
    return fn


@section
def _reg_shimcache():
    namespace("shimcache", tokens=("appcompatcache", "appcompat"), test=lambda d: _safe_kind(d) == "SYSTEM" and bool(_shim(d)),
              alias=("appcompatcache", "app_compat_cache", "appcompat", "app_compat"))
    reg("shimcache", ("entry_count", "number_of_entries", "cached_entry_count", "cache_entry_count", "entries"),
        "integer", _shim_count)
    reg("shimcache", ("paths", "entry_paths", "file_paths", "cached_paths"), "list", _shim_paths)
    reg("shimcache", ("first_entry_path", "most_recent_entry_path", "top_entry_path", "newest_entry_path"), "text",
        _shim_at(0, "path"))
    reg("shimcache", ("last_entry_path", "oldest_entry_path", "final_entry_path"), "text", _shim_at(-1, "path"))
    reg("shimcache", ("first_entry_modified_time", "most_recent_entry_modified_time", "top_entry_modified_time"),
        "filetime", _shim_at(0, "time"))


# ---- UserAssist
def _ua(d: bytes):
    h = _hive(d)
    if h is None:
        return None
    w = _toolkit("windows")

    def build(d):
        rows = w.userassist(h)
        total = 0
        markers = 0
        keys = w._many(h, w._CV + "Explorer\\UserAssist\\*\\Count")
        for k in keys:
            for name in k.values():
                total += 1
                if w.rot13(name).startswith("UEME_CTL"):
                    markers += 1
        if not keys:
            return None
        if len(rows) != total - markers:
            U("a UserAssist value is not in a layout that is read, so the list cannot be whole")
        return {"rows": rows, "total": total, "markers": markers}
    return _memo("ua", d, build)


def _ua_count(n, d):
    u = _ua(d)
    if u is None or not u["rows"]:
        return None
    if u["markers"]:
        raise M.Ambiguous([("without_session_markers", str(len(u["rows"]))), ("all_values", str(u["total"]))])
    return len(u["rows"])


def _ua_names(n, d):
    u = _ua(d)
    if u is None or not u["rows"]:
        return None
    return [r["name"] for r in u["rows"]]


def _ua_counts(n, d):
    u = _ua(d)
    if u is None or not u["rows"]:
        return None
    return [int(r["run_count"]) for r in u["rows"]]


def _ua_agg(what):
    def fn(n, d):
        u = _ua(d)
        if u is None or not u["rows"]:
            return None
        rows = u["rows"]
        if what == "total":
            return sum(int(r["run_count"]) for r in rows)
        if what == "max":
            return max(int(r["run_count"]) for r in rows)
        if what in ("program", "program_count"):
            best = max(int(r["run_count"]) for r in rows)
            top = [r for r in rows if int(r["run_count"]) == best]
            if len(top) != 1:
                U("two entries share the highest run count")
            return top[0]["name"]
        times = [r["last_run"] for r in rows if r["last_run"] is not None]
        if not times:
            return None
        return _ft(max(int(t) for t in times))
    return fn


@section
def _reg_userassist():
    namespace("userassist", tokens=("user_assist",), test=lambda d: bool(_safe_ua(d)), alias=("user_assist",))
    reg("userassist", ("entry_count", "number_of_entries", "program_count", "value_count", "entries"), "integer", _ua_count)
    reg("userassist", ("program_names", "entry_names", "names", "decoded_names"), "list", _ua_names)
    reg("userassist", ("run_counts", "execution_counts"), "intlist", _ua_counts)
    reg("userassist", ("total_run_count", "total_execution_count", "sum_of_run_counts"), "integer", _ua_agg("total"))
    reg("userassist", ("max_run_count", "highest_run_count", "maximum_run_count"), "integer", _ua_agg("max"))
    reg("userassist", ("most_run_program", "most_executed_program", "most_run_program_name", "top_program"), "text",
        _ua_agg("program"))
    reg("userassist", ("latest_run_time", "last_run_time", "most_recent_run_time", "latest_execution_time"),
        "filetime", _ua_agg("time"))


def _safe_ua(d):
    try:
        u = _ua(d)
        return bool(u and u["rows"])
    except Exception:
        return False


# ============================================================ ESE databases
ESE_SIG = b"\xef\xcd\xab\x89"
ESE_PAGES = (2048, 4096, 8192, 16384, 32768)


def _is_ese(d: bytes) -> bool:
    return len(d) >= 668 and d[4:8] == ESE_SIG and struct.unpack_from("<I", d, 236)[0] in ESE_PAGES


def _ese(d: bytes):
    if not _is_ese(d):
        return None
    if len(d) > ESE_MAX:
        U("a database larger than is read")
    e = _toolkit("ese_reader")

    def build(d):
        rep = e.classify(d)
        if rep is None:
            U("the database does not read")
        db = e.Database(d)
        return {"rep": rep, "db": db}
    return _memo("ese", d, build)


def _ese_fact(key):
    def fn(n, d):
        s = _ese(d)
        if s is None:
            return None
        v = s["rep"]["facts"].get(key)
        return U("the header does not settle this") if v is None else v
    return fn


def _tables(d, user_only=False):
    s = _ese(d)
    if s is None:
        return None
    if not s["rep"]["catalog_complete"]:
        U("the catalog was not read exactly")
    names = [t["name"] for t in s["rep"]["tables"] if isinstance(t["name"], str) and t["name"]]
    if len(names) != len(s["rep"]["tables"]):
        U("a table has no readable name")
    if user_only:
        names = [x for x in names if not x.startswith("MSys")]
    return names or None


def _ese_table_count(user_only):
    def fn(n, d):
        t = _tables(d, user_only)
        return None if t is None else len(t)
    return fn


def _ese_table_names(user_only):
    def fn(n, d):
        return _tables(d, user_only)
    return fn


def _ese_all_count(n, d):
    t = _tables(d)
    if t is None:
        return None
    user = [x for x in t if not x.startswith("MSys")]
    if len(user) != len(t):
        raise M.Ambiguous([("all_tables", str(len(t))), ("user_tables", str(len(user)))])
    return len(t)


def _ese_kind(d):
    """'srum', 'webcache' or '' by the catalog's own table names (exact catalog only)."""
    try:
        t = _tables(d)
    except M.Unknown:
        return ""
    if not t:
        return ""
    low = {x.lower() for x in t}
    if "sru" in "".join(sorted(low)) and "srudbidmaptable" in low:
        return "srum"
    if {"containers", "partitions", "leakfiles"} <= low:
        return "webcache"
    return ""


def _row_count(table, kind):
    def fn(n, d):
        if not _is_ese(d) or _ese_kind(d) != kind:
            return None
        if _page():
            U("rows are not counted for the facts page")
        s = _ese(d)
        want = [oid for oid, t in s["db"].tables().items() if t["name"] == table]
        if len(want) != 1:
            U("the table is not in the catalog exactly once")
        cnt, complete = s["db"].count_rows(want[0])
        if not complete or cnt is None:
            U("the row walk was not proved exact")
        return cnt
    return fn


def _kind_names(kind, user_only):
    def fn(n, d):
        if not _is_ese(d) or _ese_kind(d) != kind:
            return None
        return _tables(d, user_only)
    return fn


def _kind_count(kind):
    def fn(n, d):
        if not _is_ese(d) or _ese_kind(d) != kind:
            return None
        t = _tables(d, True)
        return None if t is None else len(t)
    return fn


@section
def _reg_ese():
    namespace("ese", tokens=("esedb", "edb", "jet_blue"), test=_is_ese,
              alias=("esedb", "edb", "jet", "jet_blue", "ese_database"))
    reg("ese", ("page_size", "page_size_bytes", "database_page_size"), "integer", _ese_fact("page_size"))
    reg("ese", ("format_version", "database_format_version", "version"), "number", _ese_fact("format_version"))
    reg("ese", ("format_revision", "database_format_revision", "revision"), "number", _ese_fact("format_revision"))
    reg("ese", ("page_count", "header_page_count", "stated_page_count"), "integer", _ese_fact("page_count"))
    reg("ese", ("file_page_count", "total_pages", "pages_in_file"), "integer", _ese_fact("total_pages"))
    reg("ese", ("table_count", "number_of_tables", "catalog_table_count", "tables"), "integer", _ese_all_count)
    reg("ese", ("user_table_count", "number_of_user_tables"), "integer", _ese_table_count(True))
    reg("ese", ("table_names", "catalog_table_names", "all_table_names"), "list", _ese_table_names(False))
    reg("ese", ("user_table_names", "non_system_table_names"), "list", _ese_table_names(True))

    namespace("srum", tokens=("srudb", "sru"), test=lambda d: _is_ese(d) and _ese_kind(d) == "srum", alias=("srudb", "sru"))
    reg("srum", ("table_names", "user_table_names", "tables_names"), "list", _kind_names("srum", True))
    reg("srum", ("table_count", "number_of_tables", "user_table_count"), "integer", _kind_count("srum"))
    reg("srum", ("id_map_row_count", "id_map_table_row_count", "idmap_row_count", "sru_db_id_map_table_row_count"),
        "integer", _row_count("SruDbIdMapTable", "srum"))
    namespace("webcache", tokens=("webcachev01", "web_cache"), test=lambda d: _is_ese(d) and _ese_kind(d) == "webcache",
              alias=("webcachev01", "web_cache"))
    reg("webcache", ("table_names", "user_table_names"), "list", _kind_names("webcache", True))
    reg("webcache", ("table_count", "number_of_tables", "user_table_count"), "integer", _kind_count("webcache"))
    reg("webcache", ("container_count", "containers_count", "number_of_containers", "containers_row_count"), "integer",
        _row_count("Containers", "webcache"))


# ============================================================ EVTX aggregates
EVTX_MAGIC = b"ElfFile\x00"


def _evtx(d: bytes):
    if d[:8] != EVTX_MAGIC:
        return None
    if len(d) > EVTX_MAX:
        U("a log larger than is read")
    if _page():
        U("an event log is not rendered for the facts page")
    w = _toolkit("windows")

    def build(d):
        events, complete = w.evtx_events(d, deadline=time.monotonic() + EVTX_SECONDS)
        if not complete or not events:
            U("not every record rendered, so no aggregate is established")
        return {"events": events, "chunks": len(w.evtx_chunks(d))}
    return _memo("evtx", d, build)


def _ev_chunks(n, d):
    e = _evtx(d)
    return None if e is None else e["chunks"]


def _ev_set(field, as_int):
    def fn(n, d):
        e = _evtx(d)
        if e is None:
            return None
        vals = [ev.get(field) for ev in e["events"]]
        if any(v is None or v == "" for v in vals):
            U("a record lacks this field, so the set cannot be whole")
        return sorted(set(int(v) for v in vals)) if as_int else sorted(set(str(v) for v in vals))
    return fn


def _ev_distinct(field):
    def fn(n, d):
        e = _evtx(d)
        if e is None:
            return None
        vals = [ev.get(field) for ev in e["events"]]
        if any(v is None or v == "" for v in vals):
            U("a record lacks this field, so the count cannot be whole")
        return len(set(vals))
    return fn


def _ev_time(which):
    def fn(n, d):
        e = _evtx(d)
        if e is None:
            return None
        ts = [ev.get("time") for ev in e["events"]]
        if any(t is None for t in ts):
            U("a record lacks a time")
        return _ft(min(ts) if which == "min" else max(ts))
    return fn


@section
def _reg_evtx():
    reg("evtx", ("chunk_count", "number_of_chunks", "chunks"), "integer", _ev_chunks)
    reg("evtx", ("distinct_event_ids", "event_id_set", "unique_event_ids", "event_ids_distinct"), "intlist",
        _ev_set("id", True))
    reg("evtx", ("distinct_event_id_count", "unique_event_id_count", "event_id_count"), "integer", _ev_distinct("id"))
    reg("evtx", ("provider_names", "distinct_providers", "unique_providers", "providers"), "list", _ev_set("provider", False))
    reg("evtx", ("channel_names", "distinct_channels", "unique_channels", "channels"), "list", _ev_set("channel", False))
    reg("evtx", ("computer_names", "distinct_computers", "unique_computers", "computers"), "list",
        _ev_set("computer", False))
    reg("evtx", ("earliest_event_time", "earliest_record_time", "oldest_event_time", "min_event_time"), "filetime",
        _ev_time("min"))
    reg("evtx", ("latest_event_time", "latest_record_time", "newest_event_time", "max_event_time"), "filetime",
        _ev_time("max"))


# ============================================================ prefetch: MAM and the referenced-file strings
def _mam(d: bytes):
    """The SCCA image inside a MAM (Xpress Huffman) prefetch file, accepted only when it proves itself."""
    if len(d) < 12 or len(d) > MAM_IN_MAX:
        U("a MAM prefetch file that is cut or larger than is read")
    if d[3] != 0x04:
        U("a MAM header variant that is not read")
    if _page():
        U("a MAM prefetch file is not decompressed for the facts page")
    size = struct.unpack_from("<I", d, 4)[0]
    if size < 0x98 or size > MAM_OUT_MAX:
        U("a MAM stated size that is not read")
    w = _toolkit("windows")

    def build(d):
        try:
            out = w.lzxpress_huffman(d[8:], size)
        except (ValueError, IndexError, struct.error):
            U("the Xpress Huffman stream does not decode")
        if len(out) != size or out[4:8] != b"SCCA":
            U("the decompressed image is not a prefetch file of the stated size")
        version, _, _, fsize = struct.unpack_from("<I4sII", out, 0)
        if fsize != size or version not in PF_VERSIONS:
            U("the decompressed header disagrees with the stated size or names an unknown version")
        m_off, m_n, _, _, n_off, n_size, v_off, v_n, _ = struct.unpack_from("<9I", out, 0x54)
        if m_off > size or n_off + n_size > size or (v_n and v_off > size) or n_size % 2:
            U("the decompressed section offsets do not fit the image")
        return out
    return _memo("mam", d, build)


def _pf_plain(d: bytes):
    if d[:3] == b"MAM":
        return _mam(d)
    return d if d[4:8] == b"SCCA" else None


def _sync_identity(orig, new):
    """Every module-level dict or set of properties_strict that holds an extractor by identity also holds its wrapper."""
    try:
        g = type(M).__getattr__.__globals__
    except Exception:
        return
    for val in list(g.values()):
        try:
            if isinstance(val, dict) and orig in val:
                val.setdefault(new, val[orig])
            elif isinstance(val, set) and orig in val:
                val.add(new)
        except TypeError:
            continue


def _wrap_prefetch_mam():
    done = {}
    for p in list(M.REG.values()):
        if not p.name.lower().startswith("prefetch.") or p.confirmed:
            continue
        orig = p.fn
        wrapped = done.get(orig)
        if wrapped is None:
            def make(orig):
                def fn(n, d):
                    if d[:3] == b"MAM":
                        return orig(n, _mam(d))
                    return orig(n, d)
                fn.__wrapped__ = orig
                return fn
            wrapped = done[orig] = make(orig)
            _sync_identity(orig, wrapped)
        p.fn = wrapped


def _pf_strings(d):
    img = _pf_plain(d)
    if img is None:
        return None
    if len(img) < 0x78:
        U("a prefetch header that is cut")
    m_off, m_n, _, _, n_off, n_size, _, _, _ = struct.unpack_from("<9I", img, 0x54)
    if n_off + n_size > len(img) or n_size % 2:
        U("the filename strings section does not fit the file")
    try:
        text = img[n_off:n_off + n_size].decode("utf-16-le")
    except UnicodeDecodeError:
        U("the filename strings do not decode")
    return {"names": [s for s in text.split("\x00") if s], "metrics": m_n}


def _pf_count(n, d):
    s = _pf_strings(d)
    if s is None:
        return None
    if s["names"] and s["metrics"] != len(s["names"]):
        raise M.Ambiguous([("strings", str(len(s["names"]))), ("metrics", str(s["metrics"]))])
    return len(s["names"]) if s["names"] else None


def _pf_names(n, d):
    s = _pf_strings(d)
    return None if s is None or not s["names"] else s["names"]


def _pf_metrics(n, d):
    s = _pf_strings(d)
    return None if s is None else s["metrics"]


@section
def _reg_prefetch():
    _wrap_prefetch_mam()
    reg("prefetch", ("referenced_file_count", "referenced_files_count", "filename_strings_count", "file_name_count"),
        "integer", _pf_count)
    reg("prefetch", ("referenced_files", "referenced_file_names", "filename_strings", "file_names"), "list", _pf_names)
    reg("prefetch", ("file_metrics_count", "file_metrics_entries", "metrics_entry_count", "metrics_count"), "integer",
        _pf_metrics)
