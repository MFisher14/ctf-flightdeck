#!/usr/bin/env python3
"""Windows host-forensics toolkit (backlog row 86, toolkit key `windows`).

  .venv/bin/python solvers/toolkits/windows.py <file>...            a triage of each file
  .venv/bin/python solvers/toolkits/windows.py --json <file>...     the same as JSON
  .venv/bin/python solvers/toolkits/windows.py --persistence <file>...   only the persistence summary

Offline: no Game Master request, no token, nothing written. Everything is read from the bytes
that are handed in; a file's name is used only to tell `$I...` and `$MFT` apart from other data.

What it reads (each a function an agent can call by hand, all taking bytes):

  event logs   evtx_events (python-evtx, pure Python), xml_events (wevtutil style XML, one Event
               or many), json_events (JSON or JSON lines: raw, winlogbeat, EvtxECmd shapes),
               csv_events. One event shape for all: {id, provider, channel, computer, time,
               record, sid, data{}}. script_blocks() joins PowerShell 4104 blocks in order.
  registry     Hive (a regf reader of its own: nk, vk, lf/lh/li/ri, big data) and RegText (a
               .reg export); both answer .find(path), .walk(). On top of either: run_keys,
               services, winlogon, ifeo, appinit, userassist (ROT13), shimcache (Windows 7, 8,
               10), amcache, system_info, sam_users, usbstor, run_mru, typed_paths, shellbags
               (folder names only, best effort). regipy stays available: hive_regipy(data).
  prefetch     prefetch(data): versions 17, 23, 26, 30, 31, MAM-compressed ones included
               (lzxpress_huffman is here, pure Python).
  shortcuts    lnk(data): header times, target, arguments, working directory, the tracker
               block's machine id and MAC address.
  tasks        task_xml(data): a Task Scheduler XML (URI, author, principal, triggers, actions).
  recycle bin  recycle_i(data): a $I file (original path, size, deletion time).
  NTFS         mft_records(data) with $SI and $FN times side by side, named streams, parent
               paths; usn_records(data) for a $J extract (version 2 records).
  hints        wmi_hints(data) (event filter / consumer names in an OBJECTS.DATA or a MOF),
               tabstate(data) (text of a Notepad TabState file). Never used for an answer.
  summary      persistence(arts): every autostart found, Huntress style: mechanism, where,
               name, command, ATT&CK technique, and why it looks wrong.

The runner contract (solve_set) and never-guess (AGENTS.md, "Uncertain answers"). Nothing of a
Windows lane has been judged, so:

  plain     a count, a number, a true/false or an enum value the question lists, read by a rule
            that names it in so many words (an event id in the question, a field name that is a
            Data name of those events, a registry key path and value name, a dotted property
            such as prefetch.run_count); and a text or a time when the question's own syntax
            leaves exactly one of this file's spellings (a pattern, 'lowercase', 'base filename',
            a YYYY-MM-DDTHH:MM:SSZ template).
  unsure    every other established fact: labels.pick('windows.<type>/<artifact>.<field>',
            options), the options being spellings of the one value (raw first, then lowercase,
            base name; for a time iso_z first). A fact reached through a concept ("the source
            IP", "the account that was created") is always unsure.
  None      no fact, two different facts, an incomplete read (a log this file could not parse
            to its end answers no count), a question another lane's ids mark as theirs.

Tightened by the review (day9/tk-windows-r). A plain answer also needs every word of the
question accounted for (_unexplained): a neutral word, a word of the asked field's own
vocabulary, a name, path, id or value the answer used, or a format instruction. One word left
over ('before', 'parent', 'not', 'per', 'malicious', another program's name) makes it unsure.
Never plain: a boolean without accepted values or a pattern (true, True, yes and 1 are four
spellings), the timestomp hint, a zero count of events, a count narrowed by a value found in
some field, a count over two event ids, a time with a sub-second part spelled to the second, a
count from a hive key whose lists were not read in full, a HKCU path read from a hive of
unknown kind. An unproven fact is keyed '<key>@<answer id>', so a name the judge accepts for
one question never answers another question plain. A text file longer than MAX_TEXT is read
in part and answers nothing; the same bytes under two names are one file; a HKCU path is not
answered from a machine hive. A timed set has SET_TIMED seconds in all: what is not answered
by then is None, and a delivery not read whole in that time answers nothing.

solvers/common/labels.py knows five lane prefixes and refuses `windows.`; until LANE_DIRS holds
it, an unsure answer here is still a well-formed '??' string (never sent), but nothing probes it.

signals(questions, files) is the cheap score for tools/lane_match.py: 0 when neither the bytes
nor the questions look like Windows host forensics.

Nothing here starts a process or needs the sandbox; python-evtx is the slow part (about a
millisecond a record), so a timed set reads a log for at most EVTX_TIMED seconds and then
answers nothing that needs the whole log.
"""
import csv
import hashlib
import io
import json
import os
import re
import struct
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, flagfmt

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
try:
    import labels       # noqa: E402
except Exception:       # a copy with no labels.py beside it still reads files
    labels = None

KEY = "windows"
ARROW = " -> "
SENTINEL = "??"
EVTX_TIMED = 1.2        # seconds a timed set may spend reading event logs
SET_TIMED = 2.5         # seconds a timed set may spend in all; what is not answered by then is None
EVTX_UNTIMED = 25.0
MAX_TEXT = 32 * 1024 * 1024
MAX_KEYS = 200000       # registry keys walked
MAX_MFT = 200000        # MFT records read


# ---- times ----------------------------------------------------------------------------------------

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX = 116444736000000000
_FT_MAX = 2650467743999999999          # 9999-12-31


class Stamp(int):
    """A UTC time, kept as a FILETIME (100 ns steps since 1601-01-01) so nothing is rounded."""

    @property
    def dt(self):
        return _EPOCH + timedelta(microseconds=int(self) // 10)

    def iso(self):
        frac = int(self) % 10000000
        return self.dt.strftime("%Y-%m-%dT%H:%M:%S") + (f".{frac:07d}".rstrip("0") if frac else "") + "Z"

    def __repr__(self):
        return f"Stamp({self.iso()})"

    __str__ = iso


def filetime(v):
    """Stamp of a FILETIME integer; None for 0 and for a value outside 1601..9999."""
    try:
        v = int(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return Stamp(v) if 0 < v <= _FT_MAX else None


def from_unix(seconds):
    try:
        return filetime(int(round(float(seconds) * 10000000)) + _UNIX)
    except (TypeError, ValueError, OverflowError):
        return None


_TIME = re.compile(r"^\s*(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d{1,9}))?)?\s*(Z|UTC|GMT|[+-]\d\d:?\d\d)?\s*$")


def parse_time(text, assume_utc=True):
    """Stamp of 'YYYY-MM-DD[T ]HH:MM[:SS[.fffffff]][Z|+HH:MM]'. A time with no zone is UTC only
    when assume_utc (event logs write UTC; a task's StartBoundary is local, and is not parsed)."""
    m = _TIME.match(str(text or ""))
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    if zone is None and not assume_utc:
        return None
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), tzinfo=timezone.utc)
        if zone and zone[0] in "+-":
            off = int(zone[1:3]) * 60 + int(zone[-2:])
            dt -= timedelta(minutes=off if zone[0] == "+" else -off)
    except (ValueError, OverflowError):
        return None
    ticks = int((frac or "0").ljust(7, "0")[:7])
    return filetime(int((dt - _EPOCH).total_seconds()) * 10000000 + ticks)


def time_options(s: Stamp) -> list:
    """Spellings of one UTC time, best first: [(name, value)]."""
    dt, frac = s.dt, int(s) % 10000000
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    space = dt.strftime("%Y-%m-%d %H:%M:%S")
    out = [("iso_z", base + "Z")]
    if frac:
        out += [("iso_7_z", f"{base}.{frac:07d}Z"), ("iso_micro_z", f"{base}.{frac // 10:06d}Z"),
                ("iso_ms_z", f"{base}.{frac // 10000:03d}Z"), ("space_micro", f"{space}.{frac // 10:06d}")]
    out += [("space", space), ("iso", base), ("iso_offset", base + "+00:00"), ("space_utc", space + " UTC"),
            ("epoch", str((int(s) - _UNIX) // 10000000)), ("filetime", str(int(s))), ("date", dt.strftime("%Y-%m-%d"))]
    return out


# ---- small readers -----------------------------------------------------------------------------------

def _text(data: bytes, limit=MAX_TEXT):
    """The text of a file by its BOM (UTF-16 either way, UTF-8), else UTF-8, else UTF-16LE when
    every other byte is NUL; None when it is not text."""
    data = data[:limit]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return data.decode("utf-16", "replace")
    if len(data) >= 8 and data[1:8:2] == b"\x00\x00\x00\x00" and 0 not in data[0:8:2]:
        return data[:len(data) & ~1].decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _wstr(b: bytes) -> str:
    """UTF-16LE up to the first NUL character."""
    b = b[:len(b) & ~1]
    for i in range(0, len(b), 2):
        if b[i:i + 2] == b"\x00\x00":
            b = b[:i]
            break
    return b.decode("utf-16-le", "replace")


def _cstr(b: bytes, enc="cp1252") -> str:
    return b.split(b"\x00", 1)[0].decode(enc, "replace")


def rot13(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


def basename(path: str) -> str:
    return PureWindowsPath(str(path).strip().strip('"')).name


# ---- event logs --------------------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _event_of(elem, src="") -> dict:
    """One <Event> element as {id, provider, channel, computer, time, record, sid, pid, data}."""
    ev = {"id": None, "provider": None, "channel": None, "computer": None, "time": None, "record": None,
          "sid": None, "pid": None, "data": {}, "src": src}
    for part in elem:
        name = _local(part.tag)
        if name == "System":
            for c in part:
                t = _local(c.tag)
                if t == "Provider":
                    ev["provider"] = c.get("Name") or c.get("EventSourceName")
                elif t == "EventID":
                    try:
                        ev["id"] = int((c.text or "").strip())
                    except ValueError:
                        pass
                elif t == "TimeCreated":
                    ev["time"] = parse_time(c.get("SystemTime"))
                elif t == "EventRecordID":
                    try:
                        ev["record"] = int((c.text or "").strip())
                    except ValueError:
                        pass
                elif t == "Channel":
                    ev["channel"] = (c.text or "").strip() or None
                elif t == "Computer":
                    ev["computer"] = (c.text or "").strip() or None
                elif t == "Security":
                    ev["sid"] = c.get("UserID") or None
                elif t == "Execution":
                    ev["pid"] = c.get("ProcessID")
        elif name == "EventData":
            n = 0
            for c in part:
                key = c.get("Name")
                if key is None:
                    key = f"{_local(c.tag)}{n}" if _local(c.tag) == "Data" else _local(c.tag)
                    n += 1
                _put(ev["data"], key, "".join(c.itertext()))
        elif name == "UserData":
            for leaf in part.iter():
                if len(leaf) == 0 and leaf is not part:
                    _put(ev["data"], _local(leaf.tag), leaf.text or "")
                    for k, v in leaf.attrib.items():
                        _put(ev["data"], f"{_local(leaf.tag)}@{k}", v)
        elif name == "RenderingInfo":
            for c in part:
                if _local(c.tag) == "Message":
                    ev["message"] = c.text or ""
    return ev


def _put(d: dict, key: str, value):
    """Keep the first value under the name; a repeat goes under name#2, name#3."""
    if key not in d:
        d[key] = value
        return
    n = 2
    while f"{key}#{n}" in d:
        n += 1
    d[f"{key}#{n}"] = value


def _safe_xml(text: str):
    """ElementTree root of the text, or None. A document that declares a DTD or an entity is not parsed."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        try:
            return ET.fromstring(_XML_BAD.sub("", text))
        except ET.ParseError:
            return None


def evtx_chunks(data: bytes) -> list:
    """Offsets of the chunks of an .evtx by their magic (the header's own count is 16 bits and stale in a dirty log)."""
    return [o for o in range(0x1000, len(data) - 0x200 + 1, 0x10000) if data[o:o + 8] == b"ElfChnk\x00"]


def evtx_record_count(data: bytes) -> int:
    """Records by walking each chunk's record chain (magic 2a 2a 00 00, size), no XML rendered."""
    n = 0
    for base in evtx_chunks(data):
        end = min(base + 0x10000, len(data))
        free = _u32(data, base + 0x30)
        o = base + 0x200
        while o + 24 <= end and o < base + free and data[o:o + 4] == b"\x2a\x2a\x00\x00":
            size = _u32(data, o + 4)
            if size < 24 or o + size > end:
                break
            n += 1
            o += size
    return n


_GUID_BARE = re.compile(r"[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}")
_HEX_PADDED = re.compile(r"0x0+([0-9a-fA-F]+)")
_EVTX_RS = []           # [module or None] once looked for


def evtx_rs():
    """The pyevtx-rs module (`evtx`, a Rust parser: about sixty times python-evtx's speed and Windows'
    own rendering of numbers, booleans and binary), or None. It is looked for in
    <venv>/lib/huntress-side and never in site-packages: its package folder `evtx` is python-evtx's
    `Evtx` on a case-insensitive disk (an install into site-packages overwrites python-evtx).
    CTF_EVTX=python turns it off."""
    if not _EVTX_RS:
        mod = None
        if ctf_env.get("CTF_EVTX") != "python":
            side = str(Path(ctf_env.get("CTF_SIDE") or Path(sys.prefix) / "lib" / "huntress-side"))
            if os.path.isdir(os.path.join(side, "evtx")):
                sys.path.insert(0, side)
                try:
                    import evtx as mod            # noqa: F811
                    if not hasattr(mod, "PyEvtxParser"):
                        mod = None
                except Exception:
                    mod = None
                finally:
                    if side in sys.path:
                        sys.path.remove(side)
        _EVTX_RS.append(mod)
    return _EVTX_RS[0]


def evtx_header_times(data: bytes) -> dict:
    """{record number: FILETIME} from each record's own header (no XML rendered): the time to the
    100 ns Windows shows, where a rendered SystemTime is cut or rounded to the microsecond."""
    out = {}
    for base in evtx_chunks(data):
        end = min(base + 0x10000, len(data))
        free = _u32(data, base + 0x30)
        o = base + 0x200
        while o + 24 <= end and o < base + free and data[o:o + 4] == b"\x2a\x2a\x00\x00":
            size = _u32(data, o + 4)
            if size < 24 or o + size > end:
                break
            out[struct.unpack_from("<Q", data, o + 8)[0]] = struct.unpack_from("<Q", data, o + 16)[0]
            o += size
    return out


def _evtx_finish(ev, number, times):
    """The event's time to the 100 ns (the record header's, when it is the rendered time to within
    5 microseconds: python-evtx goes through a float), and the values spelt as Windows spells them:
    a GUID in braces and lowercase, a hex number without padding, nothing for an empty element."""
    t = times.get(number)
    if t is not None and ev["time"] is not None and abs(int(ev["time"]) - t) <= 50:
        ev["time"] = filetime(t)
    d = ev["data"]
    for k, v in d.items():
        if not isinstance(v, str) or not v:
            continue
        if v[0] in " \n\t\r" and not v.strip():
            d[k] = ""
        elif len(v) == 36 and _GUID_BARE.fullmatch(v):
            d[k] = "{" + v.lower() + "}"
        elif v.startswith("0x0") and len(v) in (10, 18) and ev.get("renderer") == "python-evtx" and v == v.lower():
            # python-evtx pads a HexInt32/HexInt64 to its width, in lowercase; Windows and pyevtx-rs do
            # not pad. A string that only looks like one (Sysmon's StartAddress 0x00007FFB..., in
            # capitals) is the provider's own text and is kept as written; pyevtx-rs output is never touched.
            m = _HEX_PADDED.fullmatch(v)
            if m:
                d[k] = "0x" + m.group(1)
    return ev


def _split_strings(d: dict) -> dict:
    """python-evtx writes a classic event's strings as one Data of <string> items; Windows (and
    pyevtx-rs) write one Data each. The same dict with Data0, Data1, ... one per string."""
    out, n = {}, 0
    for k, v in d.items():
        if re.fullmatch(r"Data\d+", k):
            items = re.findall(r"<string>(.*?)</string>", v, re.S) if isinstance(v, str) and v.startswith("<string>") else [v]
            for item in items:
                out[f"Data{n}"] = item
                n += 1
        else:
            out[k] = v
    return out


def _evtx_fast(data: bytes, deadline, src, times):
    """(events, complete) through pyevtx-rs, or None when it is not there or did not read the log."""
    rs = evtx_rs()
    if rs is None:
        return None
    import io
    events = []
    try:
        for n, rec in enumerate(rs.PyEvtxParser(io.BytesIO(data)).records()):
            if deadline is not None and not n & 127 and time.monotonic() > deadline:
                return events, False
            root = _safe_xml(rec["data"])
            if root is None:
                return None
            ev = _event_of(root, src)
            if ev["record"] is None:
                ev["record"] = rec["event_record_id"]
            events.append(_evtx_finish(ev, rec["event_record_id"], times))
    except Exception:
        return None
    except BaseException as e:      # a Rust panic reaches Python as pyo3's PanicException, which is not an Exception
        if type(e).__name__ != "PanicException":
            raise
        return None
    if len(events) != len(times):
        return None
    return events, True


def evtx_events(data: bytes, deadline=None, src=""):
    """(events, complete) of an .evtx: through pyevtx-rs when evtx_rs() finds it and it reads every
    record of the log, else through python-evtx (pure Python, about 500 records a second; its
    booleans are True/False, its binary values base64 and its FILETIME values off by up to two
    microseconds, where Windows and pyevtx-rs write true/false, hex and the exact time). complete
    is False when the time ran out or a record did not render: then the list is a part, and
    nothing may be counted from it."""
    times = evtx_header_times(data)
    cut = evtx_cut(data)
    fast = _evtx_fast(data, deadline, src, times)
    if fast is not None:
        return fast[0], fast[1] and not cut
    from Evtx.Evtx import ChunkHeader      # pure Python; imported late so the other readers do not need it
    events, complete = [], True
    for base in evtx_chunks(data):
        try:
            chunk = ChunkHeader(data, base)
            for rec in chunk.records():
                if deadline is not None and time.monotonic() > deadline:
                    return events, False
                try:
                    root = _safe_xml(rec.xml())
                except Exception:
                    root = None
                if root is None:
                    complete = False
                    continue
                ev = _event_of(root, src)
                if ev["record"] is None:
                    ev["record"] = rec.record_num()
                ev["renderer"] = "python-evtx"
                if any(isinstance(v, str) and v.startswith("<string>") for v in ev["data"].values()):
                    ev["data"] = _split_strings(ev["data"])
                events.append(_evtx_finish(ev, rec.record_num(), times))
        except Exception:
            complete = False
    if len(events) != evtx_record_count(data) or cut:
        complete = False
    return events, complete


def evtx_cut(data: bytes) -> bool:
    """True when the file ends inside a chunk (every chunk of a whole .evtx is 64 KiB: the header's
    4096 bytes, then whole chunks): the records of the part that is there are a part of the log,
    and nothing may be counted from it."""
    chunks = evtx_chunks(data)
    last = (len(data) - 0x1000) // 0x10000 * 0x10000 + 0x1000
    tail = data[last:last + 8] if 0x1000 <= last < len(data) else b""
    return bool(chunks) and (chunks[-1] + 0x10000 > len(data) or tail == b"ElfChnk\x00")


def evtx_slack(data: bytes, deadline=None, src="", known=()):
    """Records still in a chunk past what its header owns: a cleared log keeps the old records in the
    chunk until new ones overwrite them (a real cleared Application.evtx held 61 behind a header that
    said none). Each chunk is walked by record size and the size's copy at the record's end; a chunk
    that holds more records than its header says is read again from a copy with the header set right.
    [events] with 'slack': True, without the record numbers in `known`. Never counted as the log's."""
    import zlib
    fixed, found = None, False
    for base in evtx_chunks(data):
        end = min(base + 0x10000, len(data))
        free = _u32(data, base + 0x30)
        o, owned, recs = base + 0x200, 0, []
        while o + 28 <= end and data[o:o + 4] == b"\x2a\x2a\x00\x00":
            size = _u32(data, o + 4)
            if size < 28 or o + size > end or _u32(data, o + size - 4) != size:
                break
            if o < base + free:
                owned += 1
            recs.append((o - base, struct.unpack_from("<Q", data, o + 8)[0]))
            o += size
        if len(recs) <= owned:
            continue
        found = True
        if fixed is None:
            fixed = bytearray(data)
        struct.pack_into("<QQQQ", fixed, base + 8, 1, len(recs), recs[0][1], recs[-1][1])
        struct.pack_into("<II", fixed, base + 44, recs[-1][0], o - base)
        struct.pack_into("<I", fixed, base + 52, zlib.crc32(bytes(fixed[base + 0x200:o])) & 0xFFFFFFFF)
        struct.pack_into("<I", fixed, base + 124, zlib.crc32(bytes(fixed[base:base + 120]) + bytes(fixed[base + 128:base + 512])) & 0xFFFFFFFF)
    if not found:
        return []
    try:
        events, _ = evtx_events(bytes(fixed), deadline, src)
    except Exception:
        return []
    known = set(known)
    out = [e for e in events if e["record"] not in known]
    for e in out:
        e["slack"] = True
    return out


def xml_events(data: bytes, src=""):
    """(events, complete) of an XML export: one <Event>, an <Events> list, or Events written one after another."""
    text = _text(data)
    if text is None or "<Event" not in text:
        return [], False
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = _safe_xml(body)
    if root is None:
        root = _safe_xml("<Events>" + body + "</Events>")
    if root is None:
        return [], False
    nodes = [root] if _local(root.tag) == "Event" else [e for e in root.iter() if _local(e.tag) == "Event"]
    events = [_event_of(e, src) for e in nodes]
    return [e for e in events if e["id"] is not None], bool(events) and all(e["id"] is not None for e in events)


def _ci(d, *names):
    """d[name] for the first name d has, letter case ignored; None otherwise."""
    if not isinstance(d, dict):
        return None
    low = {str(k).lower(): k for k in d}
    for n in names:
        k = low.get(n.lower())
        if k is not None and d[k] is not None:
            return d[k]
    return None


def _scalar(v):
    if isinstance(v, dict):
        return _ci(v, "#text", "Value", "value", "text", "@SystemTime", "SystemTime")
    return v


def _json_event(d: dict, src="") -> dict:
    event = _ci(d, "Event") if isinstance(_ci(d, "Event"), dict) else d
    system = _ci(event, "System") if isinstance(_ci(event, "System"), dict) else None
    winlog = _ci(d, "winlog") if isinstance(_ci(d, "winlog"), dict) else None
    head = system or winlog or d
    eid = _scalar(_ci(head, "EventID", "EventId", "event_id", "Id"))
    if eid is None and isinstance(_ci(d, "event"), dict):
        eid = _ci(_ci(d, "event"), "code")
    try:
        eid = int(str(eid).strip())
    except (TypeError, ValueError):
        return None
    data = None
    for holder in (event, winlog, d):
        got = _ci(holder, "EventData", "event_data", "UserData", "user_data") if holder else None
        if isinstance(got, dict):
            data = got
            break
    if data is None and isinstance(_ci(d, "Payload"), str):         # EvtxECmd: the EventData as a JSON string
        try:
            data = _ci(json.loads(_ci(d, "Payload")), "EventData")
        except ValueError:
            data = None
    flat = {}
    if isinstance(data, dict):
        items = _ci(data, "Data")
        if isinstance(items, list) and all(isinstance(i, dict) for i in items):
            for i, item in enumerate(items):
                _put(flat, str(_ci(item, "@Name", "Name") or f"Data{i}"), _str(_ci(item, "#text", "text", "Value")))
        else:
            for k, v in data.items():
                if not isinstance(v, (dict, list)):
                    _put(flat, str(k), _str(v))
                elif isinstance(v, dict):
                    for k2, v2 in v.items():
                        if not isinstance(v2, (dict, list)):
                            _put(flat, str(k2), _str(v2))
    else:
        for k, v in d.items():
            if not isinstance(v, (dict, list)):
                _put(flat, str(k), _str(v))
    provider = _ci(head, "Provider", "provider_name", "ProviderName", "SourceName")
    if isinstance(provider, dict):
        provider = _ci(provider, "@Name", "Name")
    when = _ci(head, "TimeCreated", "SystemTime", "time_created")
    when = _scalar(when) if when is not None else _ci(d, "@timestamp", "TimeCreated", "UtcTime", "timestamp", "TimeGenerated")
    record = _scalar(_ci(head, "EventRecordID", "record_id", "RecordId", "RecordNumber"))
    try:
        record = int(str(record))
    except (TypeError, ValueError):
        record = None
    sec = _ci(head, "Security")
    return {"id": eid, "provider": _str(provider) if provider is not None else None,
            "channel": _strn(_scalar(_ci(head, "Channel", "channel"))), "computer": _strn(_scalar(_ci(head, "Computer", "computer_name", "ComputerName"))),
            "time": parse_time(when), "record": record, "sid": _ci(sec, "@UserID", "UserID") if isinstance(sec, dict) else None,
            "pid": None, "data": flat, "src": src}


def _str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _strn(v):
    return None if v is None else str(v)


def json_events(data: bytes, src=""):
    """(events, complete) of a JSON array, a JSON object holding one, or JSON lines of event records."""
    text = _text(data)
    if text is None:
        return [], False
    stripped = text.lstrip()
    if stripped[:1] not in "{[":
        return [], False
    items = None
    try:
        doc = json.loads(stripped)
        if isinstance(doc, list):
            items = doc
        elif isinstance(doc, dict):
            lists = [v for v in doc.values() if isinstance(v, list) and v and all(isinstance(i, dict) for i in v)]
            items = lists[0] if len(lists) == 1 and _json_event(doc) is None else [doc]
    except ValueError:
        items = []
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except ValueError:
                return [], False
    items = [i for i in (items or []) if isinstance(i, dict)]
    events = [_json_event(i, src) for i in items]
    good = [e for e in events if e is not None]
    return good, bool(items) and len(good) == len(items)


_CSV_ID = re.compile(r"^(event[ _]?id|eventcode|event[ _]?code)$", re.I)


def csv_events(data: bytes, src=""):
    """(events, complete) of a CSV export whose header has an EventID column."""
    text = _text(data)
    if text is None:
        return [], False
    first = text.lstrip().split("\n", 1)[0]
    if "," not in first and "\t" not in first:
        return [], False
    try:
        rows = list(csv.DictReader(io.StringIO(text.lstrip()), delimiter="\t" if first.count("\t") > first.count(",") else ","))
    except csv.Error:
        return [], False
    if not rows:
        return [], False
    id_col = next((c for c in rows[0] if c and _CSV_ID.match(c.strip())), None)
    if id_col is None:
        return [], False
    events = []
    for r in rows:
        try:
            eid = int(str(r.get(id_col) or "").strip())
        except ValueError:
            return events, False
        flat = {str(k).strip(): _str(v) for k, v in r.items() if k}
        events.append({"id": eid, "provider": _ci(flat, "Provider", "ProviderName", "Source", "SourceName"),
                       "channel": _ci(flat, "Channel", "LogName", "Log"), "computer": _ci(flat, "Computer", "ComputerName", "MachineName"),
                       "time": parse_time(_ci(flat, "TimeCreated", "SystemTime", "UtcTime", "Timestamp", "Time", "Date and Time")),
                       "record": None, "sid": None, "pid": None, "data": flat, "src": src})
    return events, True


def script_blocks(events) -> dict:
    """{ScriptBlockId: {"text", "complete", "path", "parts"}} of the PowerShell 4104 events, the
    parts joined by MessageNumber. complete is False when a part of MessageTotal is missing."""
    blocks = {}
    for ev in events:
        if ev["id"] != 4104:
            continue
        d = ev["data"]
        bid = d.get("ScriptBlockId") or f"record-{ev.get('record')}"
        try:
            num, total = int(d.get("MessageNumber") or 1), int(d.get("MessageTotal") or 1)
        except ValueError:
            num, total = 1, 1
        b = blocks.setdefault(bid, {"parts": {}, "total": total, "path": d.get("Path") or ""})
        b["parts"].setdefault(num, d.get("ScriptBlockText") or "")
        b["total"] = max(b["total"], total)
    out = {}
    for bid, b in blocks.items():
        out[bid] = {"text": "".join(b["parts"][n] for n in sorted(b["parts"])), "parts": len(b["parts"]),
                    "complete": sorted(b["parts"]) == list(range(1, b["total"] + 1)), "path": b["path"]}
    return out


# What an event id is called, for the triage and for the concept rules. (id, needs Sysmon) -> label.
EVENT_NAMES = {
    4624: "logon_success", 4625: "logon_failure", 4634: "logoff", 4648: "explicit_credential_logon", 4672: "special_privileges",
    4688: "process_creation", 4697: "service_installed", 4698: "scheduled_task_created", 4699: "scheduled_task_deleted",
    4700: "scheduled_task_enabled", 4702: "scheduled_task_updated", 4720: "account_created", 4722: "account_enabled",
    4724: "password_reset", 4726: "account_deleted", 4728: "added_to_global_group", 4732: "added_to_local_group",
    4738: "account_changed", 4756: "added_to_universal_group", 4768: "kerberos_tgt_request", 4769: "kerberos_service_ticket",
    4771: "kerberos_preauth_failed", 4776: "ntlm_validation", 5140: "share_accessed", 5145: "share_object_checked",
    1102: "audit_log_cleared", 104: "log_cleared", 7045: "service_installed", 7036: "service_state_change",
    4103: "powershell_module_logging", 4104: "powershell_script_block", 400: "powershell_engine_start",
    1116: "defender_detection", 1117: "defender_action", 5001: "defender_realtime_disabled", 1149: "rdp_authentication",
    106: "scheduled_task_registered", 200: "scheduled_task_action_started", 5861: "wmi_permanent_subscription",
}
SYSMON_NAMES = {1: "process_creation", 2: "file_time_changed", 3: "network_connection", 5: "process_terminated",
                6: "driver_loaded", 7: "image_loaded", 8: "create_remote_thread", 10: "process_access", 11: "file_created",
                12: "registry_key_event", 13: "registry_value_set", 15: "file_stream_created", 17: "pipe_created",
                19: "wmi_filter", 20: "wmi_consumer", 21: "wmi_binding", 22: "dns_query", 23: "file_deleted"}


def is_sysmon(ev) -> bool:
    return "sysmon" in str(ev.get("provider") or "").lower() or "sysmon" in str(ev.get("channel") or "").lower()


def event_name(ev) -> str:
    if is_sysmon(ev):
        return "sysmon_" + SYSMON_NAMES.get(ev["id"], str(ev["id"]))
    return EVENT_NAMES.get(ev["id"], "")


# ---- registry: a hive (regf) and a .reg export, one view ----------------------------------------------

REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
             6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
             10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}
CCS = "<CCS>"           # in a path: the current control set (CurrentControlSet in an export, ControlSet00N in a hive)
_ROOT_ALIASES = {"hklm", "hkey_local_machine", "hkcu", "hkey_current_user", "hku", "hkey_users", "hkcr",
                 "hkey_classes_root", "hkcc", "hkey_current_config", "computer", "registry", "machine", "user"}


class Val:
    """One registry value: name ('' for the default value), type number, data (str, int, list, or bytes), raw bytes."""
    __slots__ = ("name", "type", "data", "raw")

    def __init__(self, name, vtype, raw):
        self.name, self.type, self.raw = name, vtype, raw
        self.data = _reg_decode(vtype, raw)

    @property
    def type_name(self):
        return REG_TYPES.get(self.type, f"REG_{self.type}")

    def __repr__(self):
        return f"Val({self.name!r}, {self.type_name}, {self.data!r})"


def _reg_decode(vtype, raw: bytes):
    if vtype in (1, 2, 6):
        return _wstr(raw)
    if vtype == 4 and len(raw) >= 4:
        return _u32(raw, 0)
    if vtype == 5 and len(raw) >= 4:
        return struct.unpack_from(">I", raw, 0)[0]
    if vtype == 11 and len(raw) >= 8:
        return _u64(raw, 0)
    if vtype == 7:
        text = raw[:len(raw) & ~1].decode("utf-16-le", "replace")
        return [s for s in text.split("\x00") if s]
    return bytes(raw)


class _HKey:
    """A key of a hive, read from its nk cell when asked."""

    def __init__(self, hive, off, parent_path):
        self.hive, self.off = hive, off
        c = hive.cell(off)
        if c[:2] != b"nk":
            raise ValueError("not a key cell")
        self._c = c
        flags = _u16(c, 2)
        n = _u16(c, 0x48)
        raw = c[0x4C:0x4C + n]
        self.name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
        self.ts = filetime(_u64(c, 4))
        self._root = parent_path is None
        self.path = self.name if not parent_path else parent_path + "\\" + self.name
        self._subs = self._vals = None

    def subkeys(self) -> list:
        if self._subs is None:
            out, seen = [], set()
            base = "" if self._root else self.path
            count, lst = _u32(self._c, 0x14), _u32(self._c, 0x1C)
            if count and lst != 0xFFFFFFFF:
                for off in self.hive.list_offsets(lst, 0):
                    if off in seen:
                        continue
                    seen.add(off)
                    try:
                        out.append(_HKey(self.hive, off, base))
                    except (ValueError, struct.error, IndexError):
                        continue
            self._subs = out
        return self._subs

    def values(self) -> dict:
        if self._vals is None:
            out = {}
            count, lst = _u32(self._c, 0x24), _u32(self._c, 0x28)
            if count and lst != 0xFFFFFFFF and count < 100000:
                try:
                    cell = self.hive.cell(lst)
                    for i in range(min(count, len(cell) // 4)):
                        try:
                            v = self.hive.value(_u32(cell, 4 * i))
                        except (ValueError, struct.error, IndexError):
                            continue
                        out.setdefault(v.name, v)
                except (ValueError, struct.error, IndexError):
                    pass
            self._vals = out
        return self._vals


class _View:
    """What Hive and RegText share: find(), walk(), value()."""
    current = None

    def find(self, path) -> list:
        """The keys a path names, letter case ignored. '*' is every subkey, CCS (or
        CurrentControlSet) the current control set. A hive root's own name (SOFTWARE, SYSTEM) and
        the HKLM/HKCU prefixes may be given or left out."""
        comps = _comps(path)
        if not comps:
            return []
        out = []
        for start in self.starts():
            out += _resolve([start], comps, self.current)
        if not out and len(comps) > 1 and self.strip_first:
            for start in self.starts():
                out += _resolve([start], comps[1:], self.current)
        seen, uniq = set(), []
        for k in out:
            if id(k) not in seen:
                seen.add(id(k))
                uniq.append(k)
        return uniq

    def value(self, path, name):
        """The one Val under that key and name over every key the path names; None when there is none or they differ."""
        found = []
        for k in self.find(path):
            for vname, v in k.values().items():
                if vname.lower() == name.lower():
                    found.append(v)
        if not found or any(f.raw != found[0].raw or f.type != found[0].type for f in found):
            return None
        return found[0]

    def walk(self, limit=MAX_KEYS):
        """Every key, parents first; stops after `limit` keys."""
        stack, n = list(reversed(self.tops())), 0
        while stack and n < limit:
            k = stack.pop()
            n += 1
            yield k
            stack.extend(reversed(k.subkeys()))


class Hive(_View):
    """A registry hive file (regf). ValueError when the bytes are not one."""
    strip_first = True

    def __init__(self, data: bytes):
        if data[:4] != b"regf" or len(data) < 0x1020:
            raise ValueError("not a registry hive")
        self.data = data
        self.written = filetime(_u64(data, 0x0C))
        self.file_name = _wstr(data[0x30:0x70])
        self.root = _HKey(self, _u32(data, 0x24), None)
        sel = next((k for k in self.root.subkeys() if k.name.lower() == "select"), None)
        cur = sel.values().get("Current") if sel else None
        self.current = f"controlset{cur.data:03d}" if cur is not None and isinstance(cur.data, int) else None

    def cell(self, off: int) -> bytes:
        o = 0x1000 + off
        if off == 0xFFFFFFFF or o + 4 > len(self.data):
            raise ValueError("cell offset outside the hive")
        size = abs(struct.unpack_from("<i", self.data, o)[0])
        if size < 4 or o + size > len(self.data):
            raise ValueError("cell size outside the hive")
        return self.data[o + 4:o + size]

    def list_offsets(self, off, depth) -> list:
        if depth > 8:
            return []
        try:
            c = self.cell(off)
        except ValueError:
            return []
        sig, count = c[:2], _u16(c, 2)
        if sig in (b"lf", b"lh"):
            return [_u32(c, 4 + 8 * i) for i in range(min(count, (len(c) - 4) // 8))]
        if sig == b"li":
            return [_u32(c, 4 + 4 * i) for i in range(min(count, (len(c) - 4) // 4))]
        if sig == b"ri":
            out = []
            for i in range(min(count, (len(c) - 4) // 4)):
                out += self.list_offsets(_u32(c, 4 + 4 * i), depth + 1)
            return out
        return []

    def value(self, off) -> Val:
        c = self.cell(off)
        if c[:2] != b"vk":
            raise ValueError("not a value cell")
        nlen, size, doff, vtype, flags = _u16(c, 2), _u32(c, 4), _u32(c, 8), _u32(c, 0xC), _u16(c, 0x10)
        raw_name = c[0x14:0x14 + nlen]
        name = raw_name.decode("latin-1") if flags & 1 else raw_name.decode("utf-16-le", "replace")
        if size & 0x80000000:
            raw = c[8:8 + min(size & 0x7FFFFFFF, 4)]
        elif size == 0:
            raw = b""
        else:
            d = self.cell(doff)
            if size > 16344 and d[:2] == b"db":
                segs = self.cell(_u32(d, 4))
                raw = b"".join(self.cell(_u32(segs, 4 * i))[:16344] for i in range(_u16(d, 2)))[:size]
            else:
                raw = d[:size]
        return Val(name, vtype, raw)

    def starts(self):
        return [self.root]

    def tops(self):
        return self.root.subkeys()

    @property
    def kind(self) -> str:
        """SYSTEM, AMCACHE, SAM, SECURITY, SOFTWARE, NTUSER, USRCLASS or '' by the keys under the root."""
        names = {k.name.lower() for k in self.root.subkeys()}
        if "select" in names and any(n.startswith("controlset") for n in names):
            return "SYSTEM"
        if "inventoryapplicationfile" in names or ("file" in names and "programs" in names):
            return "AMCACHE"
        if "sam" in names and len(names) <= 3:
            return "SAM"
        if "policy" in names and "rxact" in names:
            return "SECURITY"
        if "microsoft" in names and "classes" in names:
            return "SOFTWARE"
        if "software" in names and names & {"environment", "control panel", "volatile environment", "console", "printers"}:
            return "NTUSER"
        if "local settings" in names:
            return "USRCLASS"
        return ""


# ---- registry transaction-log replay (dirty-hive recovery) -------------------------------------------
#
# windows.py's Hive reader above reads the committed base-block image only. A hive whose primary
# and secondary sequence numbers differ is DIRTY: writes were made that live in the .LOG1/.LOG2
# transaction logs and not yet in the hive body. Reading such a hive without replaying its logs
# gives a STALE value -- a deception shape. The functions here apply the new-format (HvLE) logs,
# each log entry gated by its two Marvin32 checksums, so the real post-replay value is read.
#
# Never-wrong contract (see _reg_demote and _replay_dirty_hives): a value identical committed-vs-
# recovered is plain-eligible as before; a value the replay CHANGED is demoted to an unsure pick;
# a dirty hive whose logs do not fully cover the sequence gap (or an old DIRT-format log we do not
# apply) demotes EVERY registry value of that hive to unsure. Fail closed.

_MARVIN_SEED = 0x82EF4D887A4E55C5
_MAX_HBINS = 512 * 1024 * 1024          # a recovered image never grows past this
_MAX_LOG_ENTRIES = 100000


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _marvin32(data: bytes, seed: int = _MARVIN_SEED) -> int:
    """The Marvin32 checksum Windows uses for registry log entries (seed 0x82EF4D887A4E55C5),
    returned as the 64-bit value lo | (hi << 32), the form the log entry's 8-byte hash fields
    store."""
    lo = seed & 0xFFFFFFFF
    hi = (seed >> 32) & 0xFFFFFFFF

    def mix(lo, hi):
        lo = (lo + hi) & 0xFFFFFFFF
        hi ^= lo
        lo = _rotl32(lo, 20)
        lo = (lo + hi) & 0xFFFFFFFF
        hi = _rotl32(hi, 9)
        hi ^= lo
        lo = _rotl32(lo, 27)
        lo = (lo + hi) & 0xFFFFFFFF
        hi = _rotl32(hi, 19)
        return lo, hi

    i, n = 0, len(data)
    while n - i >= 4:
        lo = (lo + int.from_bytes(data[i:i + 4], "little")) & 0xFFFFFFFF
        lo, hi = mix(lo, hi)
        i += 4
    tail = data[i:]
    t = len(tail)
    if t == 0:
        fin = 0x80
    elif t == 1:
        fin = 0x8000 | tail[0]
    elif t == 2:
        fin = 0x800000 | tail[0] | (tail[1] << 8)
    else:
        fin = 0x80000000 | tail[0] | (tail[1] << 8) | (tail[2] << 16)
    lo = (lo + fin) & 0xFFFFFFFF
    lo, hi = mix(lo, hi)
    lo, hi = mix(lo, hi)
    return lo | (hi << 32)


def hive_dirty(data: bytes) -> bool:
    """True when a hive's primary and secondary sequence numbers differ (the base image is behind
    its transaction logs). False for a clean hive or bytes that are not a hive."""
    return len(data) >= 0x200 and data[:4] == b"regf" and _u32(data, 4) != _u32(data, 8)


def _first_hvle(data: bytes):
    for off in range(0x200, min(len(data), 0x4000) + 1, 0x200):
        if data[off:off + 4] == b"HvLE":
            return off
    return None


def is_hive_log(data: bytes) -> bool:
    """True when regf bytes are a new-format transaction log (HvLE entries), not a primary hive.
    A primary hive always carries an 'hbin' at offset 0x1000; a log carries its entries there."""
    return (len(data) >= 0x600 and data[:4] == b"regf"
            and data[0x1000:0x1004] != b"hbin" and _first_hvle(data) is not None)


def _parse_log_entries(data: bytes):
    """[(sequence, [(page_offset, page_bytes), ...])] for the hash-validated HvLE entries of one
    .LOG file, in file order; [] when it is not a new-format log. Each entry's Hash-1 and Hash-2
    Marvin32 checksums must verify, or the walk stops at that entry (fail closed)."""
    start = _first_hvle(data)
    if start is None:
        return []
    out, o, n = [], start, len(data)
    while o + 40 <= n and len(out) < _MAX_LOG_ENTRIES:
        if data[o:o + 4] != b"HvLE":
            break
        size = _u32(data, o + 4)
        if size < 0x200 or size % 0x200 != 0 or o + size > n:
            break
        seq = _u32(data, o + 12)
        dirty_count = _u32(data, o + 20)
        hash1 = _u64(data, o + 24)
        hash2 = _u64(data, o + 32)
        refs_off = o + 40
        pages_off = refs_off + dirty_count * 8
        if dirty_count > (size // 8) or pages_off > o + size:
            break
        if _marvin32(data[o:o + 32]) != hash2 or _marvin32(data[o + 40:o + size]) != hash1:
            break
        body = data[pages_off:o + size]
        pages, cum, ok = [], 0, True
        for i in range(dirty_count):
            poff = _u32(data, refs_off + 8 * i)
            psize = _u32(data, refs_off + 8 * i + 4)
            if psize <= 0 or cum + psize > len(body) or poff > _MAX_HBINS:
                ok = False
                break
            pages.append((poff, body[cum:cum + psize]))
            cum += psize
        if not ok:
            break
        out.append((seq, pages))
        o += size
    return out


def _hive_snapshot(view, limit=MAX_KEYS, stop=None) -> dict:
    """{key path lower: ({value name lower: (type, raw bytes)}, subkey count, last-write ticks)}."""
    snap = {}
    for k in view.walk(limit):
        if stop is not None and time.monotonic() > stop:
            raise OutOfTime("hive snapshot")
        vals = {vn.lower(): (v.type, bytes(v.raw)) for vn, v in k.values().items()}
        snap[k.path.lower()] = (vals, len(k.subkeys()), int(k.ts) if k.ts else 0)
    return snap


def _diff_hives(before, after, stop=None):
    """(changed_values, changed_keys): the (key, value) pairs whose data differs committed-vs-
    recovered, and the keys whose value/subkey count or last-write time differs or that appear or
    disappear. Raises OutOfTime when the walk runs past `stop`."""
    a = _hive_snapshot(before, stop=stop)
    b = _hive_snapshot(after, stop=stop)
    changed_values, changed_keys = set(), set()
    for kp in set(a) | set(b):
        av, bv = a.get(kp), b.get(kp)
        if av is None or bv is None:
            changed_keys.add(kp)
            for vn in (bv or av)[0]:
                changed_values.add((kp, vn))
            continue
        avals, asub, ats = av
        bvals, bsub, bts = bv
        if asub != bsub or ats != bts or len(avals) != len(bvals):
            changed_keys.add(kp)
        for vn in set(avals) | set(bvals):
            if avals.get(vn) != bvals.get(vn):
                changed_values.add((kp, vn))
    return changed_values, changed_keys


def replay_registry(hive: bytes, logs, stop=None) -> dict:
    """Apply the .LOG transaction logs to a dirty hive and report the recovery. Returns
    {dirty, replayed, data, reason, changed_values, changed_keys}: `data` is the recovered hive
    bytes (None when nothing usable was applied); `changed_values`/`changed_keys` are what the
    replay moved (see _diff_hives). `replayed` is True only when the logs cover the whole sequence
    gap, every entry's Marvin32 checks out, the recovered image parses AND the before/after diff
    completed -- anything short leaves replayed False, and the caller then treats the dirty hive's
    every value as unreliable (never plain)."""
    report = {"dirty": False, "replayed": False, "data": None, "reason": "",
              "changed_values": set(), "changed_keys": set()}
    if not hive_dirty(hive):
        report["reason"] = "clean"
        return report
    report["dirty"] = True
    primary, secondary = _u32(hive, 4), _u32(hive, 8)
    if primary < secondary:
        report["reason"] = "secondary sequence ahead of primary"
        return report
    entries, saw_old = {}, False
    for lg in logs or ():
        if not (isinstance(lg, (bytes, bytearray)) and lg[:4] == b"regf"):
            continue
        lg = bytes(lg)
        parsed = _parse_log_entries(lg)
        if not parsed and lg[0x200:0x204] == b"DIRT":
            saw_old = True
        for seq, pages in parsed:
            entries.setdefault(seq, pages)
    needed = list(range(secondary + 1, primary + 1))
    if not needed or any(s not in entries for s in needed):
        report["reason"] = ("old DIRT-format log not applied" if saw_old and not entries
                            else "log entries do not cover the sequence gap")
        return report
    try:
        img = bytearray(hive)
        for seq in needed:
            for poff, page in entries[seq]:
                end = 0x1000 + poff + len(page)
                if end > _MAX_HBINS:
                    report["reason"] = "recovered image too large"
                    return report
                if end > len(img):
                    img.extend(b"\x00" * (end - len(img)))
                img[0x1000 + poff:end] = page
        struct.pack_into("<I", img, 8, primary)      # the recovered image is now clean (seq matches)
        recovered = Hive(bytes(img))
        before = Hive(hive)
        cv, ck = _diff_hives(before, recovered, stop=stop)
    except OutOfTime:
        report["reason"] = "diff budget ran out"
        return report
    except Exception as e:
        report["reason"] = f"{type(e).__name__}: {str(e)[:80]}"
        return report
    report.update(replayed=True, data=bytes(img), reason="ok", changed_values=cv, changed_keys=ck)
    return report


def _reg_demote(a, keypath, vname) -> bool:
    """True when a value or key read from hive artifact `a` must NOT be answered plain: either the
    hive is dirty and could not be recovered (every value unreliable), or the replay changed this
    particular value or key (the deception shape). Unchanged values of a fully recovered hive are
    not demoted."""
    if getattr(a, "dirty_unreplayed", False):
        return True
    if getattr(a, "replayed", False):
        kp = str(keypath).lower()
        if vname is not None:
            return (kp, str(vname).lower()) in getattr(a, "changed_values", frozenset())
        return kp in getattr(a, "changed_keys", frozenset())
    return False


def _replay_dirty_hives(arts, files, stop=None):
    """After the artifacts are read, upgrade every dirty hive that ships its .LOG files to its
    recovered image, recording what changed so the answerer never reports a stale (or changed)
    value plain. A dirty hive with no usable logs is marked dirty_unreplayed (every value unsure)."""
    hives = [a for a in arts if a.kind == "hive" and isinstance(getattr(a, "view", None), Hive)]
    if not hives:
        return
    logs_by_base = {}
    for name, data in _unique(files):
        if not (isinstance(data, (bytes, bytearray)) and data[:4] == b"regf"):
            continue
        base = basename(name.split(ARROW)[-1]).lower()
        m = re.match(r"(.+)\.log\d+$", base)
        if m:
            logs_by_base.setdefault(m.group(1), []).append(bytes(data))
    for a in hives:
        try:
            if not hive_dirty(a.data):
                continue
            logs = logs_by_base.get(a.file.lower(), [])
            rep = replay_registry(a.data, logs, stop=stop)
            if not rep["dirty"]:
                continue
            a.dirty = True
            if rep["replayed"] and rep["data"]:
                a.view = Hive(rep["data"])
                a.replayed = True
                a.changed_values = rep["changed_values"]
                a.changed_keys = rep["changed_keys"]
                a.replay_reason = rep["reason"]
            else:
                a.dirty_unreplayed = True
                a.replay_reason = rep["reason"]
        except Exception:                 # recovery never breaks reading; an unrecoverable dirty hive demotes to unsure
            a.dirty = True
            a.dirty_unreplayed = True


class _TKey:
    def __init__(self, name, parent):
        self.name, self.parent, self.ts = name, parent, None
        self.path = name if parent is None or not parent.path else parent.path + "\\" + name
        self._kids, self._vals, self.deleted = {}, {}, False

    def subkeys(self):
        return list(self._kids.values())

    def values(self):
        return self._vals


_REG_LINE = re.compile(r'^(@|"((?:[^"\\]|\\.)*)")\s*=\s*(.*)$', re.S)


class RegText(_View):
    """A .reg export (regedit 4 or 5). ValueError when the text is not one."""
    strip_first = False
    kind = "REG"

    def __init__(self, data: bytes):
        text = _text(data)
        if text is None or not re.match(r"\s*(Windows Registry Editor Version 5\.00|REGEDIT4)", text):
            raise ValueError("not a .reg export")
        self.root = _TKey("", None)
        self._all = []
        key = None
        for line in re.sub(r"\\\r?\n[ \t]*", "", text).splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            m = re.match(r"^\[(-?)(.+)\]$", line)
            if m:
                key = self.root
                for comp in m.group(2).split("\\"):
                    nxt = key._kids.get(comp.lower())
                    if nxt is None:
                        nxt = key._kids[comp.lower()] = _TKey(comp, key)
                        self._all.append(nxt)
                    key = nxt
                key.deleted = bool(m.group(1))
                continue
            m = _REG_LINE.match(line)
            if not m or key is None:
                continue
            name = "" if m.group(1) == "@" else re.sub(r"\\(.)", r"\1", m.group(2))
            v = _reg_text_value(name, m.group(3).strip())
            if v is not None:
                key._vals.setdefault(name, v)

    def starts(self):
        return [self.root] + self._all

    def tops(self):
        return self.root.subkeys()


def _reg_text_value(name, rhs):
    if rhs.startswith('"'):
        m = re.match(r'^"((?:[^"\\]|\\.)*)"', rhs, re.S)
        if not m:
            return None
        return Val(name, 1, (re.sub(r"\\(.)", r"\1", m.group(1)) + "\x00").encode("utf-16-le"))
    m = re.match(r"^dword:([0-9a-fA-F]{1,8})$", rhs)
    if m:
        return Val(name, 4, struct.pack("<I", int(m.group(1), 16)))
    m = re.match(r"^hex(?:\(([0-9a-fA-F]+)\))?:(.*)$", rhs, re.S)
    if m:
        try:
            raw = bytes(int(b, 16) for b in re.split(r"[,\s]+", m.group(2).strip()) if b)
        except ValueError:
            return None
        return Val(name, int(m.group(1), 16) if m.group(1) else 3, raw)
    return None


def _comps(path) -> list:
    comps = [c for c in str(path).strip().strip("[]").replace("/", "\\").split("\\") if c]
    while comps and comps[0].lower().rstrip(":") in _ROOT_ALIASES:
        comps = comps[1:]
    return [CCS if c.lower() == "currentcontrolset" else c for c in comps]


def _resolve(keys, comps, current=None) -> list:
    for c in comps:
        nxt = []
        for k in keys:
            subs = k.subkeys()
            if c == "*":
                nxt += subs
            elif c == CCS:
                sets = [s for s in subs if re.fullmatch(r"currentcontrolset|controlset\d{3}", s.name.lower())]
                live = [s for s in sets if s.name.lower() == "currentcontrolset"] or [s for s in sets if s.name.lower() == current]
                nxt += live or sets
            else:
                low = c.lower()
                nxt += [s for s in subs if s.name.lower() == low]
        keys = nxt
        if not keys:
            break
    return keys


def open_registry(data: bytes):
    """Hive or RegText of the bytes; None when they are neither."""
    for cls in (Hive, RegText):
        try:
            return cls(data)
        except (ValueError, struct.error, IndexError):
            continue
    return None


def hive_regipy(data: bytes):
    """regipy's RegistryHive of the bytes (it wants a path: a temporary file is written and removed at exit)."""
    import atexit
    import os
    import tempfile
    from regipy.registry import RegistryHive
    fd, path = tempfile.mkstemp(prefix="tk_windows_", suffix=".hive")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    atexit.register(lambda: os.path.exists(path) and os.remove(path))
    return RegistryHive(path)


def _many(view, rel, prefixes=("", "Software\\")) -> list:
    out, seen = [], set()
    for pre in prefixes:
        for k in view.find(pre + rel):
            if id(k) not in seen and not getattr(k, "deleted", False):
                seen.add(id(k))
                out.append(k)
    return out


_CV = "Microsoft\\Windows\\CurrentVersion\\"
_NT = "Microsoft\\Windows NT\\CurrentVersion\\"
RUN_PATHS = (_CV + "Run", _CV + "RunOnce", _CV + "RunOnceEx", _CV + "RunServices", _CV + "RunServicesOnce",
             _CV + "Policies\\Explorer\\Run")
_WOW = ("", "Software\\", "Wow6432Node\\", "Software\\Wow6432Node\\")


def run_keys(view) -> list:
    """[{key, name, command, time}] of the Run, RunOnce and Policies\\Explorer\\Run keys (32-bit views too)."""
    out = []
    for rel in RUN_PATHS:
        for k in _many(view, rel, _WOW):
            for name, v in k.values().items():
                if v.type in (1, 2) and v.data:
                    out.append({"key": k.path, "name": name, "command": v.data, "time": k.ts})
    return out


def services(view) -> list:
    """[{name, image_path, display_name, start, type, account, dll, time}] of <control set>\\Services."""
    out = []
    for k in view.find(CCS + "\\Services\\*"):
        vals = {n.lower(): v for n, v in k.values().items()}
        if "imagepath" not in vals and "type" not in vals:
            continue
        g = lambda n: vals[n].data if n in vals else None        # noqa: E731
        params = next((s for s in k.subkeys() if s.name.lower() == "parameters"), None)
        dll = next((v.data for n, v in (params.values().items() if params else ()) if n.lower() == "servicedll"), None)
        out.append({"name": k.name, "image_path": g("imagepath"), "display_name": g("displayname"), "start": g("start"),
                    "type": g("type"), "account": g("objectname"), "dll": dll, "description": g("description"),
                    "key": k.path, "time": k.ts})
    return out


def winlogon(view) -> list:
    out = []
    for k in _many(view, _NT + "Winlogon", _WOW):
        for name, v in k.values().items():
            if name.lower() in ("shell", "userinit", "taskman") and v.type in (1, 2) and v.data:
                out.append({"key": k.path, "name": name, "command": v.data, "time": k.ts})
    return out


def ifeo(view) -> list:
    out = []
    for rel, wanted in ((_NT + "Image File Execution Options\\*", ("debugger", "verifierdlls")),
                        (_NT + "SilentProcessExit\\*", ("monitorprocess",))):
        for k in _many(view, rel, _WOW):
            for name, v in k.values().items():
                if name.lower() in wanted and v.type in (1, 2) and v.data:
                    out.append({"key": k.path, "name": name, "target": k.name, "command": v.data, "time": k.ts})
    return out


def appinit(view) -> list:
    out = []
    for k in _many(view, _NT + "Windows", _WOW):
        for name, v in k.values().items():
            if name.lower() == "appinit_dlls" and v.type in (1, 2) and v.data.strip():
                out.append({"key": k.path, "name": name, "command": v.data, "time": k.ts})
    return out


def userassist(view) -> list:
    """[{name, run_count, focus_count, focus_ms, last_run, guid}]; the value names are ROT13 in the hive."""
    out = []
    for k in _many(view, _CV + "Explorer\\UserAssist\\*\\Count"):
        guid = k.path.split("\\")[-2]
        for name, v in k.values().items():
            raw, plain = v.raw, rot13(name)
            if plain.startswith("UEME_CTL"):
                continue
            if len(raw) == 72:
                out.append({"name": plain, "run_count": _u32(raw, 4), "focus_count": _u32(raw, 8), "focus_ms": _u32(raw, 12),
                            "last_run": filetime(_u64(raw, 60)), "guid": guid})
            elif len(raw) == 16:
                n = _u32(raw, 4)
                out.append({"name": plain, "run_count": n - 5 if n >= 5 else n, "focus_count": None, "focus_ms": None,
                            "last_run": filetime(_u64(raw, 8)), "guid": guid})
    return out


def parse_shimcache(raw: bytes) -> list:
    """[{path, modified, position}] of an AppCompatCache value: Windows 10 and 11 (header 0x30 or
    0x34, '10ts'), 8.0 ('00ts') and 8.1 ('10ts' after a 0x80 header), 7 and 2008 R2 (0xBADC0FEE).
    Any other layout gives []."""
    out = []
    if len(raw) < 0x34:
        return out
    head = _u32(raw, 0)
    try:
        if head in (0x30, 0x34) or (head == 0x80 and raw[0x80:0x84] in (b"00ts", b"10ts")):
            win10 = head != 0x80
            o = head
            while o + 14 <= len(raw) and raw[o:o + 4] in (b"10ts", b"00ts"):
                sig, size, plen = raw[o:o + 4], _u32(raw, o + 8), _u16(raw, o + 12)
                p = o + 14
                path = raw[p:p + plen].decode("utf-16-le", "replace")
                p += plen
                if not win10:
                    if sig == b"10ts":              # 8.1: a package name comes first
                        p += 2 + _u16(raw, p)
                    p += 8                          # insertion flags, shim flags
                out.append({"path": path, "modified": filetime(_u64(raw, p)) if p + 8 <= len(raw) else None, "position": len(out)})
                o += 12 + size
        elif head == 0xBADC0FEE:
            count = _u32(raw, 4)
            wide = _u32(raw, 0x80 + 4) == 0
            step = 48 if wide else 32
            for i in range(min(count, 2048)):
                o = 0x80 + i * step
                if o + step > len(raw):
                    break
                plen = _u16(raw, o)
                poff, ft = (_u64(raw, o + 8), _u64(raw, o + 16)) if wide else (_u32(raw, o + 4), _u64(raw, o + 8))
                if poff + plen > len(raw):
                    break
                out.append({"path": raw[poff:poff + plen].decode("utf-16-le", "replace"), "modified": filetime(ft), "position": i})
    except (struct.error, IndexError):
        pass
    return out


def shimcache(view) -> list:
    for k in view.find(CCS + "\\Control\\Session Manager\\AppCompatCache"):
        for name, v in k.values().items():
            if name.lower() == "appcompatcache" and isinstance(v.raw, bytes):
                got = parse_shimcache(v.raw)
                if got:
                    return got
    return []


def _sha1_of_file_id(fid) -> str:
    fid = str(fid or "")
    return fid[4:] if len(fid) == 44 and fid.startswith("0000") else (fid or None)


def amcache(view) -> list:
    """[{path, name, sha1, size, publisher, version, product, time}] from InventoryApplicationFile, and the older Root\\File."""
    out = []
    for k in view.find("Root\\InventoryApplicationFile\\*") or view.find("InventoryApplicationFile\\*"):
        vals = {n.lower(): v.data for n, v in k.values().items()}
        if not (vals.get("lowercaselongpath") or vals.get("name") or vals.get("fileid")):
            continue                    # a key of that shape in another hive (seen: ten empty rows from a real NTUSER.DAT)
        out.append({"path": vals.get("lowercaselongpath"), "name": vals.get("name") or basename(str(vals.get("lowercaselongpath") or "")) or None,
                    "sha1": _sha1_of_file_id(vals.get("fileid")),
                    "size": vals.get("size"), "publisher": vals.get("publisher"), "version": vals.get("version"),
                    "product": vals.get("productname"), "link_date": vals.get("linkdate"), "time": k.ts})
    for k in view.find("Root\\File\\*\\*") or view.find("File\\*\\*"):
        vals = {n.lower(): v.data for n, v in k.values().items()}
        if "15" not in vals and "101" not in vals:
            continue
        out.append({"path": vals.get("15"), "name": basename(vals.get("15") or "") or None, "sha1": _sha1_of_file_id(vals.get("101")),
                    "size": vals.get("6"), "publisher": vals.get("1"), "version": vals.get("5"), "product": vals.get("0"),
                    "link_date": None, "time": k.ts})
    return out


_SYSINFO = (
    ("computer_name", CCS + "\\Control\\ComputerName\\ComputerName", "ComputerName"),
    ("timezone", CCS + "\\Control\\TimeZoneInformation", "TimeZoneKeyName"),
    ("shutdown_time", CCS + "\\Control\\Windows", "ShutdownTime"),
    ("hostname", CCS + "\\Services\\Tcpip\\Parameters", "Hostname"),
    ("domain", CCS + "\\Services\\Tcpip\\Parameters", "Domain"),
    ("product_name", _NT[:-1], "ProductName"), ("current_build", _NT[:-1], "CurrentBuild"),
    ("display_version", _NT[:-1], "DisplayVersion"), ("edition", _NT[:-1], "EditionID"),
    ("registered_owner", _NT[:-1], "RegisteredOwner"), ("install_date", _NT[:-1], "InstallDate"),
)


def system_info(view) -> dict:
    """{field: value} of the facts a SYSTEM or SOFTWARE hive states once; a field two keys state differently is left out."""
    out = {}
    for field, rel, name in _SYSINFO:
        found = []
        for k in _many(view, rel):
            for vname, v in k.values().items():
                if vname.lower() == name.lower():
                    found.append(v)
        if not found or any(f.raw != found[0].raw for f in found):
            continue
        v = found[0]
        if field == "shutdown_time":
            val = filetime(_u64(v.raw, 0)) if len(v.raw) == 8 else None
        elif field == "install_date":
            val = from_unix(v.data) if isinstance(v.data, int) and v.data else None
        else:
            val = v.data if isinstance(v.data, str) and v.data else None
        if val is not None:
            out[field] = val
    return out


def sam_users(view) -> list:
    out = []
    for k in view.find("SAM\\Domains\\Account\\Users\\Names\\*"):
        d = k.values().get("")
        out.append({"name": k.name, "rid": d.type if d is not None else None, "created": k.ts})
    return out


def usbstor(view) -> list:
    out = []
    for k in view.find(CCS + "\\Enum\\USBSTOR\\*\\*"):
        vals = {n.lower(): v.data for n, v in k.values().items()}
        out.append({"device": k.path.split("\\")[-2], "serial": k.name, "friendly_name": vals.get("friendlyname"), "time": k.ts})
    return out


def run_mru(view) -> list:
    """What was typed into Win+R, most recent first."""
    out = []
    for k in _many(view, _CV + "Explorer\\RunMRU"):
        vals = {n: v.data for n, v in k.values().items() if isinstance(v.data, str)}
        order = vals.get("MRUList") or "".join(sorted(n for n in vals if len(n) == 1))
        out += [re.sub(r"\\1$", "", vals[c]) for c in order if c in vals]
    return out


def recent_docs(view) -> list:
    """[{name, key, position, time}] of Explorer\\RecentDocs and its per-extension subkeys, most recent
    first inside each key (MRUListEx); time is the key's last write, on the most recent entry only."""
    out = []
    for k in _many(view, _CV + "Explorer\\RecentDocs") + _many(view, _CV + "Explorer\\RecentDocs\\*"):
        vals = k.values()
        names, order = {}, []
        for n, v in vals.items():
            raw = v.raw
            if n.lower() == "mrulistex":
                for i in range(0, len(raw) - 3, 4):
                    if _u32(raw, i) == 0xFFFFFFFF:
                        break
                    order.append(_u32(raw, i))
            elif n.isdigit():
                end = next((i for i in range(0, len(raw) - 1, 2) if raw[i:i + 2] == b"\x00\x00"), len(raw) - len(raw) % 2)
                names[int(n)] = raw[:end].decode("utf-16-le", "replace")
        seq = [i for i in order if i in names] + [i for i in sorted(names) if i not in order]
        for pos, i in enumerate(seq):
            out.append({"name": names[i], "key": k.path.rsplit("\\", 1)[-1], "position": pos, "time": k.ts if pos == 0 else None})
    return out


_FLAG_RX = re.compile(r"[A-Za-z0-9_]{2,16}\{(?![0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})[^{}\s]{1,200}\}")
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _radix(text: str, alphabet: str) -> bytes:
    n = 0
    for c in text:
        n = n * len(alphabet) + alphabet.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def decodings(text: str) -> list:
    """[(method, text)]: the readings of a name or value under base64, base64url, hex, base32, base58
    and base62 that come out as four or more printable ASCII characters. Most strings have none."""
    import base64
    import binascii
    t, out = str(text).strip(), []

    def keep(method, fn):
        try:
            b = fn()
            v = b.decode("ascii")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return
        if len(v) >= 4 and all(32 <= ord(c) < 127 for c in v) and (method, v) not in out:
            out.append((method, v))

    if len(t) < 8 or len(t) > 4096:
        return out
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t.rstrip("=")) % 4 != 1:
        keep("base64", lambda: base64.b64decode(t.rstrip("=") + "=" * (-len(t.rstrip("=")) % 4), validate=True))
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", t) and ("-" in t or "_" in t) and len(t.rstrip("=")) % 4 != 1:
        keep("base64url", lambda: base64.urlsafe_b64decode(t.rstrip("=") + "=" * (-len(t.rstrip("=")) % 4)))
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t):
        keep("hex", lambda: bytes.fromhex(t))
    if re.fullmatch(r"[A-Z2-7]+=*", t) and len(t) % 8 == 0:
        keep("base32", lambda: base64.b32decode(t))
    if re.fullmatch(r"[0-9A-Za-z]+", t):
        if all(c in _B58 for c in t):
            keep("base58", lambda: _radix(t, _B58))
        keep("base62", lambda: _radix(t, _B62))
    return out


def encoded_names(view) -> list:
    """[{source, name, method, decoded}]: file and program names of a user hive (UserAssist,
    RecentDocs, the Run dialog, typed paths) whose stem decodes to printable text."""
    names = [("userassist", r["name"]) for r in userassist(view)] + [("recent_docs", r["name"]) for r in recent_docs(view)] \
        + [("run_mru", x) for x in run_mru(view)] + [("typed_paths", x) for x in typed_paths(view)]
    out, seen = [], set()
    for source, name in names:
        leaf = str(name).replace("/", "\\").rsplit("\\", 1)[-1]
        stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf
        for method, text in decodings(stem):
            if (name, method) not in seen:
                seen.add((name, method))
                out.append({"source": source, "name": name, "method": method, "decoded": text})
    return out


_NET_USER = re.compile(r"""\bnet1?(?:\.exe)?"?\s+user\s+("[^"]+"|\S+)\s+("[^"]+"|[^\s/]\S*)(?=[^|&]*\s/add\b)""", re.I)
_FINDINGS = {}          # {ids of the artifacts: (findings, the artifacts)}; a set asks about a few groups of files
_FIND_STOP = [None, 0]  # time.monotonic() after which findings() gives up (set by a timed solve_set); scans made


def findings(arts) -> dict:
    """What a reader looks for first, across the artifacts (every row is a reading for a person or
    an unsure answer, never a proven one):
      flags              flag-shaped texts (name{...}) in event values, in their base64 readings, in
                         decoded hive names and in Recycle Bin sizes read as characters
      stream_contents    Sysmon event 15 (a named stream was written): target, Contents, its decoding
      net_user_passwords `net user NAME PASSWORD /add` command lines of process-creation events
      encoded_names      encoded_names() of every hive
      recycle            for eight or more $I files: their sizes as characters, by deletion time and by name
    Every value of every event is read (about 30,000 events a second), so the result is kept per
    group of artifacts, and a timed set that runs out of time raises OutOfTime: no finding, no answer."""
    key = tuple(id(a) for a in arts)
    if key in _FINDINGS:
        return _FINDINGS[key][0]
    flags, streams, passwords, enc, recycle = [], [], [], [], {}
    stop, seen_flags, n = _FIND_STOP[0], set(), 0
    _FIND_STOP[1] += 1

    def flag(text, where):
        for m in _FLAG_RX.finditer(text):
            # a broad name{...} shape: CSS (btn{color:red}) is never a flag finding (R-16)
            if m.group() not in seen_flags and flagfmt.shape_reportable(m.group()):
                seen_flags.add(m.group())
                flags.append({"flag": m.group(), "where": where})

    for a in arts:
        if a.kind in EVENT_KINDS:
            for e in list(a.events) + list(a.slack):
                n += 1
                if stop is not None and not n & 255 and time.monotonic() > stop:
                    raise OutOfTime("findings")
                d = e["data"]
                for k, v in d.items():
                    if not isinstance(v, str) or len(v) < 6:
                        continue
                    if "{" in v:
                        flag(v, f"{a.file} {'slack record' if e.get('slack') else 'event'} {e['id']} {k}")
                    for tok in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", v) if len(v) < 65536 else ():
                        for method, text in decodings(tok):
                            if "{" in text:
                                flag(text, f"{a.file} event {e['id']} {k} ({method})")
                if e["id"] == 15 and is_sysmon(e) and str(d.get("Contents") or "").strip():
                    raw = str(d.get("Contents")).strip()
                    streams.append({"file": a.file, "target": d.get("TargetFilename"), "contents": raw,
                                    "decoded": [t for _, t in decodings(raw)][:1], "hash": d.get("Hash"), "time": e["time"]})
                cmd = d.get("CommandLine") or d.get("ProcessCommandLine")
                if isinstance(cmd, str) and "user" in cmd.lower():
                    for m in _NET_USER.finditer(cmd):
                        if m.group(2).strip('"') == "*":
                            continue
                        passwords.append({"user": m.group(1).strip('"'), "password": m.group(2).strip('"'), "command": cmd,
                                          "file": a.file, "time": e["time"]})
        elif a.kind in REG_KINDS:
            for r in encoded_names(a.view):
                enc.append(dict(r, file=a.file))
                flag(r["decoded"], f"{a.file} {r['source']} {r['name']} ({r['method']})")
    bins = [a for a in arts if a.kind == "recycle" and isinstance(a.obj, dict) and isinstance(a.obj.get("file_size"), int)]
    if len(bins) >= 8:
        def text(rows):
            sizes = [r.obj["file_size"] for r in rows]
            return "".join(chr(n) for n in sizes) if all(32 <= n < 127 or n in (9, 10, 13) for n in sizes) else None

        def collapsed(t):
            for k in (2, 3, 4, 5):
                if t and len(t) % k == 0 and all(len(set(t[i:i + k])) == 1 for i in range(0, len(t), k)):
                    return t[::k]
            return None
        timed = [a for a in bins if isinstance(a.obj.get("deleted_time"), Stamp)]
        by_time = text(sorted(timed, key=lambda a: (int(a.obj["deleted_time"]), a.file))) if len(timed) == len(bins) else None
        by_name = text(sorted(bins, key=lambda a: a.file))
        recycle = {"files": len(bins), "paths": sorted({str(a.obj.get("original_path")) for a in bins})[:20],
                   "sizes_by_deletion_time": by_time, "sizes_by_deletion_time_collapsed": collapsed(by_time),
                   "sizes_by_name": by_name}
        for label in ("sizes_by_deletion_time", "sizes_by_deletion_time_collapsed"):
            if recycle[label]:
                flag(recycle[label], f"Recycle Bin $I {label}")
    out = {"flags": flags, "stream_contents": streams, "net_user_passwords": passwords, "encoded_names": enc, "recycle": recycle}
    if len(_FINDINGS) >= 8:
        _FINDINGS.clear()
    _FINDINGS[key] = (out, list(arts))      # the artifacts are kept so that their ids stay theirs
    return out


def typed_paths(view) -> list:
    out = []
    for k in _many(view, _CV + "Explorer\\TypedPaths"):
        vals = {n.lower(): v.data for n, v in k.values().items() if isinstance(v.data, str)}
        out += [vals[n] for n in sorted(vals, key=lambda n: int(n[3:]) if n[3:].isdigit() else 0) if n.startswith("url")]
    return out


def _shell_item_name(raw: bytes):
    if len(raw) < 4:
        return None
    kind = raw[2]
    p = raw.find(b"\x04\x00\xef\xbe")
    if p >= 4:
        ext = p - 4
        ver = _u16(raw, ext + 2)
        off = ext + (46 if ver >= 9 else 42 if ver >= 8 else 38 if ver >= 7 else 20)
        name = _wstr(raw[off:])
        if name:
            return name
    if kind & 0x70 == 0x30 and len(raw) > 0x0E:
        return (_wstr(raw[0x0E:]) if kind & 0x04 else _cstr(raw[0x0E:])) or None       # bit 2: the short name is UTF-16
    if kind & 0x70 == 0x20:
        return _cstr(raw[3:]) or None
    return None


def shellbags(view, limit=5000) -> list:
    """Folder paths of the BagMRU tree, names from each shell item (best effort; an item this cannot name is '?')."""
    out = []

    def rec(key, prefix, depth):
        if depth > 32 or len(out) >= limit:
            return
        kids = {s.name: s for s in key.subkeys()}
        for name, v in key.values().items():
            if name.isdigit() and isinstance(v.raw, bytes):
                path = (prefix + "\\" if prefix else "") + (_shell_item_name(v.raw) or "?")
                out.append(path)
                if name in kids:
                    rec(kids[name], path, depth + 1)

    for rel in ("Microsoft\\Windows\\Shell\\BagMRU", "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Microsoft\\Windows\\ShellNoRoam\\BagMRU"):
        for k in _many(view, rel):
            rec(k, "", 0)
    return out


# ---- prefetch -----------------------------------------------------------------------------------------

def lzxpress_huffman(data: bytes, out_size: int) -> bytes:
    """LZXPRESS Huffman (MS-XCA 2.2), the compression of a MAM prefetch file. ValueError on a broken stream."""
    out = bytearray()
    ip, n = 0, len(data)

    def u16(p):
        return data[p] | (data[p + 1] << 8) if p + 1 < n else (data[p] if p < n else 0)

    while len(out) < out_size:
        if ip + 256 > n:
            raise ValueError("lzxpress: the table is cut")
        lengths = [0] * 512
        for i in range(256):
            b = data[ip + i]
            lengths[2 * i], lengths[2 * i + 1] = b & 15, b >> 4
        table = [0] * 32768              # the 15 leading bits -> symbol
        code = 0
        for bits in range(1, 16):
            for sym in range(512):
                if lengths[sym] == bits:
                    span = 1 << (15 - bits)
                    if code + span > 32768:
                        raise ValueError("lzxpress: the code lengths are not a prefix code")
                    table[code:code + span] = [sym] * span
                    code += span
        ip += 256
        nxt = (u16(ip) << 16) | u16(ip + 2)
        ip += 4
        extra = 16
        block_end = min(len(out) + 65536, out_size)
        while len(out) < block_end:
            sym = table[nxt >> 17]
            bits = lengths[sym]
            if not bits:
                raise ValueError("lzxpress: a code that is not in the table")
            nxt = (nxt << bits) & 0xFFFFFFFF
            extra -= bits
            if extra < 0:
                nxt |= u16(ip) << (-extra)
                extra += 16
                ip += 2
            if sym < 256:
                out.append(sym)
                continue
            sym -= 256
            length, dbits = sym & 15, sym >> 4
            if length == 15:
                length = data[ip] if ip < n else 0
                ip += 1
                if length == 255:
                    length = u16(ip)
                    ip += 2
                    if length < 15:
                        raise ValueError("lzxpress: a match length under 15")
                    length -= 15
                length += 15
            length += 3
            dist = ((nxt >> (32 - dbits)) if dbits else 0) + (1 << dbits)
            nxt = (nxt << dbits) & 0xFFFFFFFF
            extra -= dbits
            if extra < 0:
                nxt |= u16(ip) << (-extra)
                extra += 16
                ip += 2
            if dist > len(out):
                raise ValueError("lzxpress: a match before the start")
            for _ in range(min(length, out_size - len(out))):
                out.append(out[-dist])
    return bytes(out)


_PF_RUNS = {17: (0x78, 1, 0x90), 23: (0x80, 1, 0x98), 26: (0x80, 8, 0xD0)}
_PF_VOL = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}


def prefetch(data: bytes) -> dict:
    """A .pf file: {version, compressed, executable_name, hash, run_count, last_run_time,
    last_run_times, files, volumes[{device_path, created, serial}], executable_path}. ValueError
    when the bytes are not one. run_count is None for a layout this does not know."""
    compressed = data[:3] == b"MAM"
    if compressed:
        if len(data) < 12:
            raise ValueError("not a prefetch file")
        data = lzxpress_huffman(data[12 if data[3] & 0x80 else 8:], _u32(data, 4))
    if len(data) < 0x98 or data[4:8] != b"SCCA":
        raise ValueError("not a prefetch file")
    ver = _u32(data, 0)
    out = {"version": ver, "compressed": compressed, "executable_name": _wstr(data[0x10:0x4C]), "hash": _u32(data, 0x4C),
           "file_size": _u32(data, 0x0C), "run_count": None, "last_run_times": [], "last_run_time": None, "files": [],
           "volumes": [], "executable_path": None}
    m_off, m_n, _, _, n_off, n_size, v_off, v_n, _ = struct.unpack_from("<9I", data, 0x54)
    out["file_count"] = m_n
    try:
        if ver in _PF_RUNS:
            t_off, t_n, c_off = _PF_RUNS[ver]
        elif ver in (30, 31) and m_off in (0x130, 0x128):
            t_off, t_n, c_off = 0x80, 8, (0xD0 if m_off == 0x130 else 0xC8)
        else:
            t_off = None
        if t_off is not None:
            out["last_run_times"] = [s for s in (filetime(_u64(data, t_off + 8 * i)) for i in range(t_n)) if s is not None]
            out["last_run_time"] = out["last_run_times"][0] if out["last_run_times"] else None
            out["run_count"] = _u32(data, c_off)
        if n_off and n_off + n_size <= len(data):
            names = data[n_off:n_off + (n_size & ~1)].decode("utf-16-le", "replace")
            out["files"] = [s for s in names.split("\x00") if s]
        step = _PF_VOL.get(ver)
        for i in range(v_n if step else 0):
            o = v_off + i * step
            if o + 20 > len(data):
                break
            p_off, p_len = _u32(data, o), _u32(data, o + 4)
            out["volumes"].append({"device_path": data[v_off + p_off:v_off + p_off + 2 * p_len].decode("utf-16-le", "replace"),
                                   "created": filetime(_u64(data, o + 8)), "serial": _u32(data, o + 16)})
    except (struct.error, IndexError):
        pass
    exe = out["executable_name"].lower()
    hits = sorted({f for f in out["files"] if basename(f).lower() == exe or (len(exe) == 29 and basename(f).lower().startswith(exe))})
    out["executable_path"] = hits[0] if len(hits) == 1 else None
    return out


# ---- shortcuts (.lnk) -----------------------------------------------------------------------------------

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}
_SHOW = {1: "normal", 3: "maximized", 7: "minimized"}


def lnk(data: bytes) -> dict:
    """A shell link: {target_path, relative_path, working_dir, arguments, icon_location,
    description, creation_time, access_time, write_time, file_size, show_command, drive_type,
    volume_serial, volume_label, machine_id, mac_address, env_target, command_line}. ValueError
    when the bytes are not one. A field the link does not hold is None."""
    if len(data) < 76 or _u32(data, 0) != 0x4C or data[4:20] != _LNK_CLSID:
        raise ValueError("not a shell link")
    flags = _u32(data, 0x14)
    out = {"flags": flags, "attributes": _u32(data, 0x18), "creation_time": filetime(_u64(data, 0x1C)),
           "access_time": filetime(_u64(data, 0x24)), "write_time": filetime(_u64(data, 0x2C)), "file_size": _u32(data, 0x34),
           "icon_index": struct.unpack_from("<i", data, 0x38)[0], "show_command": _SHOW.get(_u32(data, 0x3C), str(_u32(data, 0x3C))),
           "target_path": None, "relative_path": None, "working_dir": None, "arguments": None, "icon_location": None,
           "description": None, "drive_type": None, "volume_serial": None, "volume_label": None, "machine_id": None,
           "mac_address": None, "env_target": None, "net_name": None, "command_line": None, "id_list_path": None}
    o = 76
    try:
        if flags & 0x1:
            # The items are walked to their terminator, as the shell does: a link padded to hide its
            # arguments may state a list size that is not the list's (seen in a real one).
            end, p, parts = o + 2 + _u16(data, o), o + 2, []
            while p + 2 <= len(data):
                n = _u16(data, p)
                if n < 2:
                    p += 2
                    break
                item = data[p:p + n]
                kind = item[2] if len(item) > 2 else 0
                if kind & 0x70 in (0x20, 0x30):
                    name = _shell_item_name(item)
                    parts.append(name.rstrip("\\") if name else "?")
                p += n
            if parts and re.match(r"^[A-Za-z]:$", parts[0]) and "?" not in parts:
                out["id_list_path"] = "\\".join(parts)
            o = p if p <= len(data) else end
        if flags & 0x2:
            size, hsize, lflags = _u32(data, o), _u32(data, o + 4), _u32(data, o + 8)
            vol, base, cnrl, suffix = struct.unpack_from("<4I", data, o + 12)
            wbase = _u32(data, o + 28) if hsize >= 0x24 else 0
            wsuffix = _u32(data, o + 32) if hsize >= 0x24 else 0
            block = data[o:o + size]
            tail = (_wstr(block[wsuffix:]) if wsuffix else "") or (_cstr(block[suffix:]) if suffix else "")
            if lflags & 1:
                local = (_wstr(block[wbase:]) if wbase else "") or (_cstr(block[base:]) if base else "")
                out["target_path"] = (local + tail) or None
                if vol and vol + 16 <= len(block):
                    out["drive_type"] = _DRIVE_TYPES.get(_u32(block, vol + 4), str(_u32(block, vol + 4)))
                    out["volume_serial"] = _u32(block, vol + 8)
                    lab = _u32(block, vol + 12)
                    out["volume_label"] = (_wstr(block[vol + _u32(block, vol + 16):]) if lab == 0x14 else _cstr(block[vol + lab:])) or None
            if lflags & 2 and cnrl and cnrl + 20 <= len(block):
                net = _cstr(block[cnrl + _u32(block, cnrl + 8):])
                out["net_name"] = net or None
                if not out["target_path"] and net:
                    out["target_path"] = net + ("\\" + tail if tail and not net.endswith("\\") else tail)
            o += size
        for bit, field in ((0x4, "description"), (0x8, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"), (0x40, "icon_location")):
            if flags & bit:
                n = _u16(data, o)
                if bit in (0x4, 0x8, 0x10) and n > 260:
                    # NAME, RELATIVE_PATH and WORKING_DIR hold at most 260 characters whatever the
                    # count says; a link that hides its arguments overstates it (seen in a real one)
                    n = 260
                o += 2
                if flags & 0x80:
                    out[field] = data[o:o + 2 * n].decode("utf-16-le", "replace")
                    o += 2 * n
                else:
                    out[field] = data[o:o + n].decode("cp1252", "replace")
                    o += n
        while o + 8 <= len(data):
            size, sig = _u32(data, o), _u32(data, o + 4)
            if size < 8 or o + size > len(data):
                break
            if sig == 0xA0000003 and size >= 0x60:
                out["machine_id"] = _cstr(data[o + 16:o + 32], "ascii") or None
                droid_file = data[o + 48:o + 64]
                if droid_file[7] >> 4 == 1:                 # a version 1 GUID carries the MAC address
                    out["mac_address"] = ":".join(f"{b:02x}" for b in droid_file[10:16])
            elif sig == 0xA0000001 and size >= 0x314:
                out["env_target"] = _wstr(data[o + 268:o + 788]) or _cstr(data[o + 8:o + 268]) or None
            o += size
    except (struct.error, IndexError):
        pass
    if not out["target_path"] and out["env_target"]:
        out["target_path"] = out["env_target"]
    if not out["target_path"] and out["id_list_path"]:
        out["target_path"] = out["id_list_path"]      # no LinkInfo: the item list is all that names the target
        out["target_source"] = "id_list"              # ... and an item may carry only its 8.3 name: a reading, never proven
    if out["target_path"]:
        out["command_line"] = out["target_path"] + (" " + out["arguments"] if out["arguments"] else "")
    return out


# ---- jump lists (automaticDestinations-ms / customDestinations-ms) --------------------------------------
#
# Two files record which items a program opened. automaticDestinations-ms is an OLE/CFB container
# (read with maldoc.py's CFB reader) of numbered streams, each a shell link, plus a DestList index
# stream whose header counts the entries. customDestinations-ms is a small header then shell-link
# blocks back to back. Each destination is a real LNK, so lnk() above reads its target, times,
# arguments and tracker. The count of destinations is byte-proven; every per-entry fact is this
# reader's reading (the author names the fields), so it is an unsure pick or None, never plain.

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK_SIG = b"L\x00\x00\x00" + _LNK_CLSID
_JL_HEX = re.compile(r"[0-9a-fA-F]{1,16}$")


def _lnk_safe(data: bytes):
    try:
        return lnk(data)
    except Exception:
        return None


def _jl_cfb(data: bytes):
    """maldoc.py's CFB reader, imported lazily so windows.py never pulls it in at import time."""
    sys.path.insert(0, str(HERE))
    try:
        import maldoc                      # noqa: E402
    finally:
        if sys.path and sys.path[0] == str(HERE):
            sys.path.pop(0)
    return maldoc.cfb(data)


def _jumplist_auto(data: bytes) -> dict:
    cfb = _jl_cfb(data)
    destlist = None
    for p in cfb.paths("stream"):
        if p.rsplit("/", 1)[-1].lower() == "destlist":
            try:
                destlist = cfb.stream(p)
            except Exception:
                destlist = None
            break
    dl_version = dl_count = pinned = None
    if destlist is not None and len(destlist) >= 16:
        dl_version, dl_count, pinned = _u32(destlist, 0), _u32(destlist, 4), _u32(destlist, 8)
    entries, hex_streams = [], 0
    for p in cfb.paths("stream"):
        leaf = p.rsplit("/", 1)[-1]
        if leaf.lower() == "destlist" or not _JL_HEX.fullmatch(leaf):
            continue
        hex_streams += 1
        try:
            raw = cfb.stream(p)
        except Exception:
            continue
        link = _lnk_safe(raw)
        if link is not None:
            entries.append({"stream": leaf, "number": int(leaf, 16), "lnk": link})
    entries.sort(key=lambda e: e["number"])
    # A count is plain-eligible only when the container is whole, every numbered stream parsed as a
    # shell link, AND the DestList index agrees with the streams found: all three, or the count is
    # this reader's own and is offered unsure. A jump list with no DestList to cross-check is never
    # plain (fail closed; never-wrong).
    complete = (cfb.intact() and len(entries) == hex_streams
                and dl_count is not None and dl_count == len(entries))
    return {"type": "automatic", "destlist_version": dl_version, "entry_count": len(entries),
            "pinned_count": pinned, "entries": entries, "complete": complete}


def _jumplist_custom(data: bytes) -> dict:
    offs = []
    start = 4
    while True:
        i = data.find(_LNK_SIG, start)
        if i < 0:
            break
        offs.append(i)
        start = i + len(_LNK_SIG)
    entries = []
    for n, off in enumerate(offs):
        end = offs[n + 1] if n + 1 < len(offs) else len(data)
        link = _lnk_safe(data[off:end])
        if link is not None:
            entries.append({"stream": n, "number": n, "lnk": link})
    version = _u32(data, 0) if len(data) >= 4 else None
    # customDestinations-ms has no index stream to cross-check the destination count against (the
    # per-category structure is version-dependent and holds non-link items), so the count is this
    # reader's reading of a shell-link scan: offered unsure, never plain. Per-entry facts still read.
    return {"type": "custom", "destlist_version": None, "header_version": version,
            "entry_count": len(entries), "pinned_count": None, "entries": entries, "complete": False}


def jumplist(data: bytes) -> dict:
    """A Windows Jump List. automaticDestinations-ms (OLE/CFB) or customDestinations-ms (header +
    shell-link blocks): {type, destlist_version, entry_count, pinned_count, entries:[{stream,
    number, lnk{...}}], complete}. ValueError when the bytes are neither."""
    if data[:8] == _OLE_MAGIC:
        return _jumplist_auto(data)
    if _LNK_SIG in data[4:65536]:        # a header, then at least one shell link (never a bare .lnk at offset 0)
        return _jumplist_custom(data)
    raise ValueError("not a jump list")


# ---- scheduled task XML ---------------------------------------------------------------------------------

def task_xml(data: bytes) -> dict:
    """A Task Scheduler XML: {uri, author, date, description, user_id, run_level, logon_type,
    hidden, enabled, triggers[{type, start_boundary, enabled, interval}], actions[{command,
    arguments, working_directory}], command, arguments, command_line, trigger_type,
    start_boundary}. The single-valued fields are None when the task has two. ValueError when
    the bytes are not a task."""
    text = _text(data)
    if text is None or "<Task" not in text[:4096]:
        raise ValueError("not a task XML")
    root = _safe_xml(re.sub(r"<\?xml[^>]*\?>", "", text))
    if root is None or _local(root.tag) != "Task":
        raise ValueError("not a task XML")

    def first(path):
        node = root
        for name in path.split("/"):
            node = next((c for c in node if _local(c.tag) == name), None)
            if node is None:
                return None
        return (node.text or "").strip() or None

    out = {"uri": first("RegistrationInfo/URI"), "author": first("RegistrationInfo/Author"), "date": first("RegistrationInfo/Date"),
           "description": first("RegistrationInfo/Description"), "user_id": first("Principals/Principal/UserId"),
           "group_id": first("Principals/Principal/GroupId"), "run_level": first("Principals/Principal/RunLevel"),
           "logon_type": first("Principals/Principal/LogonType"), "hidden": first("Settings/Hidden"),
           "enabled": first("Settings/Enabled"), "triggers": [], "actions": []}
    for part in root:
        if _local(part.tag) == "Triggers":
            for t in part:
                kids = {_local(c.tag): c for c in t}
                rep = {_local(c.tag): (c.text or "").strip() for c in kids.get("Repetition", ())}
                out["triggers"].append({"type": _local(t.tag), "start_boundary": (kids["StartBoundary"].text or "").strip() if "StartBoundary" in kids else None,
                                        "enabled": (kids["Enabled"].text or "").strip() if "Enabled" in kids else None,
                                        "interval": rep.get("Interval"), "user_id": (kids["UserId"].text or "").strip() if "UserId" in kids else None})
        elif _local(part.tag) == "Actions":
            for a in part:
                kids = {_local(c.tag): (c.text or "").strip() for c in a}
                if _local(a.tag) == "Exec":
                    out["actions"].append({"type": "Exec", "command": kids.get("Command"), "arguments": kids.get("Arguments"),
                                           "working_directory": kids.get("WorkingDirectory")})
                else:
                    out["actions"].append({"type": _local(a.tag), "command": kids.get("ClassId"), "arguments": kids.get("Data"),
                                           "working_directory": None})
    one = out["actions"][0] if len(out["actions"]) == 1 else {}
    out["command"], out["arguments"], out["working_directory"] = one.get("command"), one.get("arguments"), one.get("working_directory")
    out["command_line"] = (one["command"] + (" " + one["arguments"] if one.get("arguments") else "")) if one.get("command") else None
    trig = out["triggers"][0] if len(out["triggers"]) == 1 else {}
    out["trigger_type"], out["start_boundary"], out["interval"] = trig.get("type"), trig.get("start_boundary"), trig.get("interval")
    return out


# ---- recycle bin $I, NTFS records -------------------------------------------------------------------------

def recycle_i(data: bytes) -> dict:
    """A Recycle Bin $I file: {version, file_size, deleted_time, original_path}. ValueError when the bytes are not one."""
    if len(data) < 28:
        raise ValueError("not a $I file")
    ver = _u64(data, 0)
    if ver == 1 and len(data) == 544:
        path = _wstr(data[24:544])
    elif ver == 2 and len(data) >= 28 and 28 + 2 * _u32(data, 24) <= len(data) + 2 and 0 < _u32(data, 24) <= 32768:
        path = _wstr(data[28:28 + 2 * _u32(data, 24)])
    else:
        raise ValueError("not a $I file")
    when = filetime(_u64(data, 16))
    if when is None or not re.match(r"^(?:[A-Za-z]:\\|\\\\)", path):
        raise ValueError("not a $I file")
    return {"version": ver, "file_size": _u64(data, 8), "deleted_time": when, "original_path": path}


def mft_record(rec: bytes, number=None):
    """One FILE record: {record, in_use, is_directory, name, parent, si_created, si_modified,
    si_changed, si_accessed, fn_created, fn_modified, fn_changed, fn_accessed, size, resident,
    streams, timestomp_hint}; None when the bytes are not a record. timestomp_hint is True when
    $STANDARD_INFORMATION says the file was created before $FILE_NAME does, or its time has no
    sub-second part while $FILE_NAME's has."""
    if len(rec) < 56 or rec[:4] != b"FILE":
        return None
    rec = bytearray(rec)
    try:
        usa, n = _u16(rec, 4), _u16(rec, 6)
        for i in range(1, n):
            end = i * 512
            if end <= len(rec) and usa + 2 * i + 2 <= len(rec):
                rec[end - 2:end] = rec[usa + 2 * i:usa + 2 * i + 2]
        flags = _u16(rec, 0x16)
        out = {"record": _u32(rec, 0x2C) if _u16(rec, 4) >= 0x30 else number, "in_use": bool(flags & 1), "is_directory": bool(flags & 2),
               "name": None, "parent": None, "size": None, "resident": None, "streams": [], "data": None}
        if out["record"] is None:
            out["record"] = number
        o, space = _u16(rec, 0x14), -1
        while o + 16 <= len(rec):
            atype, alen = _u32(rec, o), _u32(rec, o + 4)
            if atype == 0xFFFFFFFF or alen < 16 or o + alen > len(rec):
                break
            nonres, nlen, noff = rec[o + 8], rec[o + 9], _u16(rec, o + 10)
            aname = bytes(rec[o + noff:o + noff + 2 * nlen]).decode("utf-16-le", "replace") if nlen else ""
            body = bytes(rec[o + _u16(rec, o + 0x14):o + _u16(rec, o + 0x14) + _u32(rec, o + 0x10)]) if not nonres else b""
            if atype == 0x10 and len(body) >= 32:
                for i, f in enumerate(("si_created", "si_modified", "si_changed", "si_accessed")):
                    out[f] = filetime(_u64(body, 8 * i))
            elif atype == 0x30 and len(body) >= 0x42:
                ns = body[0x41]
                if out["name"] is None or (ns in (1, 3) and space not in (1, 3)) or (space == 2 and ns != 2):
                    space = ns
                    out["name"] = body[0x42:0x42 + 2 * body[0x40]].decode("utf-16-le", "replace")
                    out["parent"] = _u64(body, 0) & 0xFFFFFFFFFFFF
                    for i, f in enumerate(("fn_created", "fn_modified", "fn_changed", "fn_accessed")):
                        out[f] = filetime(_u64(body, 8 + 8 * i))
            elif atype == 0x80:
                size = len(body) if not nonres else _u64(rec, o + 0x30)
                if aname:
                    out["streams"].append({"name": aname, "size": size, "data": body if not nonres else None})
                else:
                    out["size"], out["resident"] = size, not nonres
                    out["data"] = body if not nonres else None
            o += alen
    except (struct.error, IndexError):
        return None
    si, fn = out.get("si_created"), out.get("fn_created")
    out["timestomp_hint"] = bool(si and fn and (si < fn or (int(si) % 10000000 == 0 and int(fn) % 10000000 != 0)))
    return out


def mft_records(data: bytes, limit=MAX_MFT) -> list:
    """The FILE records of an $MFT (or of one record), each with 'path' when its parents are in the data."""
    if data[:4] != b"FILE":
        return []
    size = _u32(data, 0x1C) if len(data) >= 0x20 else 1024
    if size not in (1024, 4096):
        size = 1024
    recs = []
    for i in range(min(len(data) // size, limit)):
        r = mft_record(data[i * size:(i + 1) * size], i)
        if r is not None:
            recs.append(r)
    by = {r["record"]: r for r in recs}
    for r in recs:
        parts, cur, hops = [], r, 0
        while cur is not None and cur.get("name") and hops < 64:
            if cur["record"] == 5:
                parts.append("")
                break
            parts.append(cur["name"])
            nxt = by.get(cur.get("parent"))
            cur = None if nxt is cur else nxt
            hops += 1
        r["path"] = "\\".join(reversed(parts)) if parts and parts[-1] == "" else None
    return recs


USN_REASONS = ((0x1, "data_overwrite"), (0x2, "data_extend"), (0x4, "data_truncation"), (0x10, "named_data_overwrite"),
               (0x20, "named_data_extend"), (0x40, "named_data_truncation"), (0x100, "file_create"), (0x200, "file_delete"),
               (0x400, "ea_change"), (0x800, "security_change"), (0x1000, "rename_old_name"), (0x2000, "rename_new_name"),
               (0x4000, "indexable_change"), (0x8000, "basic_info_change"), (0x10000, "hard_link_change"),
               (0x20000, "compression_change"), (0x40000, "encryption_change"), (0x80000, "object_id_change"),
               (0x100000, "reparse_point_change"), (0x200000, "stream_change"), (0x80000000, "close"))


def usn_records(data: bytes, limit=500000) -> list:
    """Version 2 records of a $UsnJrnl:$J extract: [{usn, time, name, reasons, file, parent, attributes}]. Zero runs are skipped."""
    out, o, n = [], 0, len(data)
    while o + 60 <= n and len(out) < limit:
        size = _u32(data, o)
        if size == 0:
            o = (o + 8) & ~7 if data[o:o + 8] == b"\x00" * 8 else o + 8
            while o + 4096 <= n and data[o:o + 4096] == b"\x00" * 4096:
                o += 4096
            continue
        if size < 60 or size > 4096 or o + size > n or _u16(data, o + 4) != 2 or size % 8:
            o += 8
            continue
        nlen, noff = _u16(data, o + 56), _u16(data, o + 58)
        reason = _u32(data, o + 40)
        out.append({"usn": _u64(data, o + 24), "time": filetime(_u64(data, o + 32)),
                    "name": data[o + noff:o + noff + nlen].decode("utf-16-le", "replace"),
                    "reasons": [label for bit, label in USN_REASONS if reason & bit], "file": _u64(data, o + 8) & 0xFFFFFFFFFFFF,
                    "parent": _u64(data, o + 16) & 0xFFFFFFFFFFFF, "attributes": _u32(data, o + 52)})
        o += size
    return out


# ---- hints: WMI repository, Notepad TabState --------------------------------------------------------------

_WMI_CLASSES = ("__EventFilter", "__FilterToConsumerBinding", "CommandLineEventConsumer", "ActiveScriptEventConsumer",
                "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer")
_PRINT = re.compile(rb"[\x20-\x7e]{6,}")
_PRINT_W = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def wmi_hints(data: bytes) -> dict:
    """What an OBJECTS.DATA or a MOF says of permanent event subscriptions: the consumer and
    filter class names seen, and the strings that look like a query, a command or a script.
    A hint for a reader; never an answer."""
    strings = [m.group().decode("ascii") for m in _PRINT.finditer(data[:MAX_TEXT])]
    strings += [m.group().decode("utf-16-le") for m in _PRINT_W.finditer(data[:MAX_TEXT])]
    classes = Counter()
    for s in strings:
        for c in _WMI_CLASSES:
            if c in s:
                classes[c] += 1
    pick = lambda rx: sorted({s.strip()[:400] for s in strings if re.search(rx, s, re.I)})[:40]      # noqa: E731
    return {"classes": dict(classes), "queries": pick(r"\bselect\b.+\bfrom\b.+(__Instance|Win32_|__Timer)"),
            "commands": pick(r"(cmd(\.exe)?\s*/c|powershell|wscript|cscript|mshta|rundll32|regsvr32|\.exe\b.*\s-)"),
            "bindings": pick(r"(EventConsumer|__EventFilter)\.Name\s*=")}


def tabstate(data: bytes) -> list:
    """The UTF-16 text runs of a Windows 11 Notepad TabState .bin (magic 'NP'): the saved path, if any, and the buffer."""
    if data[:2] != b"NP":
        return []
    return [m.group().decode("utf-16-le") for m in re.finditer(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}", data)]


# ---- what a file is, and the artifacts of a delivery -------------------------------------------------------

EVENT_KINDS = ("evtx", "event_xml", "event_json", "event_csv")
REG_KINDS = ("hive", "reg")
STRONG = ("evtx", "hive", "prefetch", "lnk", "mft", "recycle", "usn", "jumplist")
_EVENT_NS = "schemas.microsoft.com/win/2004/08/events/event"
_TASK_NS = "schemas.microsoft.com/windows/2004/02/mit/task"


def sniff(name: str, data: bytes) -> str:
    """The artifact kind by the first bytes alone (a jump list also by its file name, as $I/$J
    are): evtx, hive, hivelog, prefetch, lnk, jumplist, mft, recycle, usn, reg, task, event_xml,
    event_json, event_csv, wmi, tabstate, or ''."""
    head = data[:16]
    base = basename(name.split(ARROW)[-1]).lower()
    if head[:8] == b"ElfFile\x00":
        return "evtx"
    if head[:4] == b"regf":
        # a transaction log (.LOG1/.LOG2) also starts with regf; it is not a primary hive and is
        # read only to recover a dirty hive, never to answer a question from its own stale body.
        return "hivelog" if is_hive_log(data) else "hive"
    if base.endswith("automaticdestinations-ms") and head[:8] == _OLE_MAGIC:
        return "jumplist"
    if base.endswith("customdestinations-ms") and _LNK_SIG in data[4:65536]:
        return "jumplist"
    if head[:3] == b"MAM" or head[4:8] == b"SCCA":
        return "prefetch"
    if len(data) >= 76 and head[:4] == b"L\x00\x00\x00" and data[4:20] == _LNK_CLSID:
        return "lnk"
    if head[:4] == b"FILE" and len(data) >= 1024 and _u16(data, 4) in (0x30, 0x2A):
        return "mft"
    if len(data) >= 28 and head[:8] in (b"\x01" + b"\x00" * 7, b"\x02" + b"\x00" * 7) and (base.startswith("$i") or len(data) == 544):
        return "recycle"
    if len(data) >= 64 and (base in ("$j", "$usnjrnl", "$usnjrnl_$j", "usnjrnl") or "usnjrnl" in base or base.endswith("$j")):
        return "usn"
    if head[:2] == b"NP" and base.endswith(".bin"):
        return "tabstate"
    if base == "objects.data" or (b"__EventFilter" in data[:1 << 20] and b"\x00" in data[:4096] and base.endswith((".data", ".btr", ".map"))):
        return "wmi"
    probe = data[:4096]
    if probe[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            probe = probe[:len(probe) & ~1].decode("utf-16", "replace").encode("utf-8")
        except UnicodeDecodeError:
            return ""
    low = probe.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if low.startswith((b"windows registry editor version 5.00", b"regedit4")):
        return "reg"
    if _TASK_NS.encode() in low or (low.startswith((b"<?xml", b"<task")) and b"<task" in low and b"<registrationinfo" in low):
        return "task"
    if _EVENT_NS.encode() in low or (b"<event" in low and b"<system>" in low and b"<eventid" in low):
        return "event_xml"
    if low[:1] in (b"{", b"[") and re.search(rb'"(event_?id|eventcode|eventdata|event_data)"', low):
        return "event_json"
    if re.match(rb"[^\n]*\b(event[ _]?id|eventcode)\b[^\n]*[,\t]", low) or re.match(rb"(event[ _]?id|eventcode)[,\t]", low):
        return "event_csv"
    if base.endswith(".mof") and b"__eventfilter" in data[:1 << 20].lower():
        return "wmi"
    return ""


class Artifact:
    """One recognised file: name, kind, and what its reader returned (obj). An event log has
    events and complete (False: a part only); a registry file has view."""

    def __init__(self, name, kind, data):
        self.name, self.kind, self.data = name, kind, data
        self.obj, self.events, self.complete, self.view, self.error = None, [], True, None, None
        self.slack = []                 # an .evtx: records past what the chunk headers own (evtx_slack)
        # a dirty hive recovered from its transaction logs (see _replay_dirty_hives); defaults keep
        # a clean hive and every other artifact unchanged.
        self.dirty = self.replayed = self.dirty_unreplayed = False
        self.changed_values = self.changed_keys = frozenset()

    @property
    def file(self):
        return basename(self.name.split(ARROW)[-1]) or self.name

    def __repr__(self):
        return f"Artifact({self.file!r}, {self.kind})"


def read(name: str, data: bytes, deadline=None):
    """The Artifact of one file, parsed; None when the file is not one this toolkit reads."""
    kind = sniff(name, data)
    if not kind:
        return None
    a = Artifact(name, kind, data)
    if kind in ("reg", "task") and len(data) > MAX_TEXT:
        return None                        # only its first MAX_TEXT bytes would be read: not read at all
    try:
        if kind == "evtx":
            a.events, a.complete = evtx_events(data, deadline, a.file)
            if a.complete:
                a.slack = evtx_slack(data, deadline, a.file, {e["record"] for e in a.events})
        elif kind == "event_xml":
            a.events, a.complete = xml_events(data, a.file)
        elif kind == "event_json":
            a.events, a.complete = json_events(data, a.file)
        elif kind == "event_csv":
            a.events, a.complete = csv_events(data, a.file)
        elif kind in REG_KINDS:
            a.view = Hive(data) if kind == "hive" else RegText(data)
        elif kind == "prefetch":
            a.obj = prefetch(data)
        elif kind == "lnk":
            a.obj = lnk(data)
        elif kind == "jumplist":
            a.obj = jumplist(data)
        elif kind == "hivelog":
            a.obj = _parse_log_entries(data)       # read only to recover a dirty hive, never for answers
        elif kind == "task":
            a.obj = task_xml(data)
        elif kind == "recycle":
            a.obj = recycle_i(data)
        elif kind == "mft":
            a.obj = mft_records(data)
        elif kind == "usn":
            a.obj = usn_records(data)
        elif kind == "wmi":
            a.obj = wmi_hints(data)
        elif kind == "tabstate":
            a.obj = tabstate(data)
    except Exception as e:                 # a file that only looked like one
        a.error = f"{type(e).__name__}: {str(e)[:120]}"
        return None
    if kind in ("event_xml", "event_json", "event_csv") and len(data) > MAX_TEXT:
        a.complete = False                 # _text() read a part of it: nothing may be counted
    if kind == "mft" and a.obj and len(data) // 1024 > MAX_MFT:
        a.complete = False
    if kind in EVENT_KINDS and not a.events and not a.slack:
        return None
    if kind in ("mft", "usn", "hivelog") and not a.obj:
        return None
    return a


_ONE_BY_CONTENT = ("evtx", "hive", "mft", "usn", "event_xml", "event_json", "event_csv", "reg")


def _unique(files: dict) -> list:
    """[(name, bytes)] once per file; a member is filed under '<archive> -> <member>' and its bare name.
    Two files with the same bytes and different names are two files (a real Recycle Bin folder held
    117 $I files with 39 different contents, and the answer was in how often each occurred)."""
    seen, whole, out = set(), set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)):
            continue
        leaf = key.split(ARROW)[-1].replace("\\", "/").rsplit("/", 1)[-1].lower()
        digest = (len(data), hashlib.sha256(data).digest())
        if digest in whole and sniff(key, data) in _ONE_BY_CONTENT:
            continue        # an event log, a hive or an $MFT a second time under another name is the same log: its records are not counted twice
        mark = (leaf,) + digest      # one name, one content: a runner may hand a member twice
        if mark not in seen:
            seen.add(mark)
            whole.add(digest)
            out.append((key, bytes(data) if isinstance(data, bytearray) else data))
    return sorted(out, key=lambda kv: kv[0])


class OutOfTime(Exception):
    """A timed set's budget ran out before every file was read: nothing is answered from a part of the delivery."""


def artifacts(files: dict, deadline=None, stop=None) -> list:
    out = []
    for name, data in _unique(files):
        if stop is not None and time.monotonic() > stop:
            raise OutOfTime(name)
        a = read(name, data, deadline)
        if a is not None:
            out.append(a)
    _replay_dirty_hives(out, files, stop)
    return out


def all_events(arts) -> list:
    return [e for a in arts if a.kind in EVENT_KINDS for e in a.events]


# ---- persistence, Huntress style -----------------------------------------------------------------------------

MECHANISMS = {
    "registry_run_key": ("T1547.001", ("registry_run_key", "run_key", "registry_run_keys", "registry_autorun", "autorun")),
    "windows_service": ("T1543.003", ("windows_service", "service", "service_installation", "new_service", "malicious_service")),
    "scheduled_task": ("T1053.005", ("scheduled_task", "schtasks", "task_scheduler", "scheduled_tasks")),
    "wmi_event_subscription": ("T1546.003", ("wmi_event_subscription", "wmi_subscription", "wmi_persistence", "wmi")),
    "winlogon_helper": ("T1547.004", ("winlogon_helper", "winlogon", "winlogon_helper_dll", "winlogon_shell")),
    "ifeo_debugger": ("T1546.012", ("ifeo_debugger", "image_file_execution_options", "ifeo", "ifeo_injection")),
    "appinit_dll": ("T1546.010", ("appinit_dll", "appinit_dlls")),
    "startup_folder": ("T1547.001", ("startup_folder", "startup_shortcut", "startup_item")),
    "local_account": ("T1136.001", ("local_account", "account_creation", "create_account", "new_local_account")),
}
_LOLBIN = re.compile(r"\b(powershell|pwsh|cmd(?:\.exe)?\s*/[ck]|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|msiexec|"
                     r"curl|wget|wmic|installutil|msbuild|odbcconf|forfiles|schtasks|bash|ssh)\b", re.I)
_WRITABLE = re.compile(r"\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\|%TEMP%|%APPDATA%|%LOCALAPPDATA%|%PUBLIC%|"
                       r"\\Downloads\\|\\PerfLogs\\|\$Recycle\.Bin|\\Windows\\Tasks\\|\\Windows\\Temp\\", re.I)
_ENCODED = re.compile(r"\s-e(?:nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String|\bIEX\b|Invoke-Expression|DownloadString|"
                      r"DownloadFile|https?://|-w(?:indowstyle)?\s+hidden|-nop\b", re.I)
_DEFAULT_WINLOGON = {"shell": ("explorer.exe",), "userinit": ("c:\\windows\\system32\\userinit.exe,", "userinit.exe,", "c:\\windows\\system32\\userinit.exe", "userinit.exe")}


def why_suspicious(command) -> list:
    """Reasons a command line looks wrong for an autostart: a script host or LOLBin, a user-writable folder, an encoded or
    downloading command, a UNC path. A reader's hint; it selects 'the' entry only for an unsure answer."""
    c = str(command or "")
    out = []
    if _LOLBIN.search(c):
        out.append("script_host_or_lolbin")
    if _WRITABLE.search(c):
        out.append("user_writable_path")
    if _ENCODED.search(c):
        out.append("encoded_or_download")
    if re.match(r'^\s*"?\\\\[^\\]', c):
        out.append("unc_path")
    return out


def persistence(arts) -> list:
    """Every autostart the artifacts state: [{mechanism, technique, name, command, where, time, source, why}].
    From a registry file: Run keys, services (in a full hive only the ones why_suspicious flags),
    Winlogon values that are not the defaults, IFEO debuggers, AppInit_DLLs. From task XML: the
    task. From event logs: 7045/4697, 4698, Sysmon 13 on a Run key, Sysmon 11 into a Startup
    folder, Sysmon 19-21 and 5861 (WMI), 4720."""
    out = []

    def add(mech, name, command, where, when, source, extra=None):
        row = {"mechanism": mech, "technique": MECHANISMS[mech][0], "name": name, "command": command, "where": where,
               "time": when, "source": source, "why": why_suspicious(command)}
        row.update(extra or {})
        if not any(r["mechanism"] == mech and r["name"] == name and r["command"] == command and r["source"] == source for r in out):
            out.append(row)

    for a in arts:
        if a.kind in REG_KINDS:
            v = a.view
            for r in run_keys(v):
                add("registry_run_key", r["name"], r["command"], r["key"], r["time"], a.file)
            svc = services(v)
            for s in svc:
                cmd = s["image_path"] or s["dll"]
                if cmd and (a.kind == "reg" or len(svc) <= 5 or why_suspicious(cmd) or why_suspicious(s["dll"])):
                    add("windows_service", s["name"], cmd, s["key"], s["time"], a.file, {"start": s["start"], "account": s["account"]})
            for r in winlogon(v):
                if r["command"].strip().lower() not in _DEFAULT_WINLOGON.get(r["name"].lower(), ()):
                    add("winlogon_helper", r["name"], r["command"], r["key"], r["time"], a.file)
            for r in ifeo(v):
                add("ifeo_debugger", r["target"], r["command"], r["key"], r["time"], a.file)
            for r in appinit(v):
                add("appinit_dll", r["name"], r["command"], r["key"], r["time"], a.file)
        elif a.kind == "task":
            t = a.obj
            add("scheduled_task", t["uri"] or a.file, t["command_line"] or "; ".join(str(x.get("command")) for x in t["actions"]) or None,
                t["uri"], None, a.file, {"user": t["user_id"], "trigger": t["trigger_type"]})
        elif a.kind in EVENT_KINDS:
            for ev in a.events:
                d, eid = ev["data"], ev["id"]
                if is_sysmon(ev):
                    if eid == 13 and re.search(r"\\CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)\\", str(d.get("TargetObject") or "") + "\\", re.I):
                        add("registry_run_key", str(d.get("TargetObject")).rsplit("\\", 1)[-1], d.get("Details"), d.get("TargetObject"), ev["time"], a.file)
                    elif eid == 11 and re.search(r"\\Start Menu\\Programs\\Startup\\", str(d.get("TargetFilename") or ""), re.I):
                        add("startup_folder", basename(d.get("TargetFilename")), d.get("TargetFilename"), d.get("TargetFilename"), ev["time"], a.file)
                    elif eid in (19, 20, 21):
                        add("wmi_event_subscription", d.get("Name") or d.get("Consumer") or d.get("Filter"),
                            d.get("Destination") or d.get("Query") or d.get("Consumer"), d.get("EventNamespace"), ev["time"], a.file)
                elif eid in (7045, 4697):
                    add("windows_service", d.get("ServiceName"), d.get("ImagePath") or d.get("ServiceFileName"), None, ev["time"], a.file,
                        {"account": d.get("AccountName") or d.get("ServiceAccount")})
                elif eid == 4698:
                    cmd = None
                    try:
                        cmd = task_xml(str(d.get("TaskContent") or "").encode("utf-8")).get("command_line")
                    except ValueError:
                        pass
                    add("scheduled_task", d.get("TaskName"), cmd, d.get("TaskName"), ev["time"], a.file, {"user": d.get("SubjectUserName")})
                elif eid == 5861:
                    add("wmi_event_subscription", d.get("CONSUMER") or d.get("Consumer"), d.get("PossibleCause") or d.get("ESS"), d.get("NamespaceName") or d.get("Namespace"), ev["time"], a.file)
                elif eid == 4720:
                    add("local_account", d.get("TargetUserName"), None, d.get("TargetDomainName"), ev["time"], a.file, {"user": d.get("SubjectUserName")})
    return out


# ---- the triage ------------------------------------------------------------------------------------------------

def _j(v):
    if isinstance(v, Stamp):
        return v.iso()
    if isinstance(v, bytes):
        return v[:64].hex() + ("..." if len(v) > 64 else "")
    if isinstance(v, dict):
        return {str(k): _j(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_j(x) for x in v]
    return v


def summary(a: Artifact) -> dict:
    """The facts of one artifact for a reader (JSON-ready)."""
    s = {"file": a.file, "kind": a.kind}
    if a.kind in EVENT_KINDS:
        ev = a.events
        times = sorted(e["time"] for e in ev if e["time"] is not None)
        ids = Counter((e["id"], event_name(e)) for e in ev)
        s.update(events=len(ev), complete=a.complete, first=times[0] if times else None, last=times[-1] if times else None,
                 computers=sorted({e["computer"] for e in ev if e["computer"]}), channels=sorted({e["channel"] for e in ev if e["channel"]}),
                 ids=[{"id": i, "name": n, "count": c} for (i, n), c in sorted(ids.items())],
                 script_blocks=[{"id": k, "complete": b["complete"], "parts": b["parts"], "path": b["path"], "text": b["text"][:2000]}
                                for k, b in script_blocks(ev).items()])
        notable = []
        for e in ev:
            if e["id"] in (4720, 4732, 4728, 7045, 4697, 4698, 1102, 104, 1116, 5861) or (is_sysmon(e) and e["id"] in (1, 3, 11, 13, 15, 19, 20, 21, 22)):
                notable.append({"id": e["id"], "name": event_name(e), "time": e["time"], "data": {k: str(v)[:300] for k, v in list(e["data"].items())[:24]}})
        if a.slack:
            st = sorted(e["time"] for e in a.slack if e["time"] is not None)
            s["slack_note"] = (f"{len(a.slack)} records are still in the file past what its chunk headers own (a cleared log keeps them): "
                               f"recovered, never counted as the log's" + (f"; {st[0].iso()} to {st[-1].iso()}" if st else ""))
            s["slack_ids"] = [{"id": i, "provider": pv, "count": c} for (i, pv), c in sorted(Counter((e["id"], e["provider"]) for e in a.slack).items())]
            s["slack"] = [{"record": e["record"], "id": e["id"], "provider": e["provider"], "time": e["time"],
                           "data": {k: str(v)[:200] for k, v in list(e["data"].items())[:12]}} for e in a.slack[:200]]
        rare = [n for n in notable if n["id"] in (15, 1102, 104, 4720, 7045, 4697, 4698, 5861)]      # never crowded out by the common ones
        s["notable"] = (rare + [n for n in notable if n not in rare])[:60]
    elif a.kind in REG_KINDS:
        v = a.view
        s.update(hive=v.kind, root=getattr(v.root, "name", ""), system=system_info(v), run_keys=run_keys(v),
                 winlogon=winlogon(v), ifeo=ifeo(v), appinit=appinit(v), userassist=userassist(v)[:200],
                 shimcache=shimcache(v)[:200], amcache=amcache(v)[:200], sam_users=sam_users(v), usbstor=usbstor(v),
                 run_mru=run_mru(v), typed_paths=typed_paths(v), shellbags=shellbags(v)[:200],
                 recent_docs=recent_docs(v)[:200], encoded_names=encoded_names(v)[:100])
        svc = services(v)
        s["services"] = [x for x in svc if a.kind == "reg" or len(svc) <= 20 or why_suspicious(x["image_path"]) or x["dll"]][:200]
        s["service_count"] = len(svc)
    elif a.kind == "mft":
        recs = a.obj
        s.update(records=len(recs), timestomp_hints=[r for r in recs if r["timestomp_hint"]][:50],
                 named_streams=[{"path": r.get("path") or r["name"], "stream": st["name"], "data": st["data"]} for r in recs for st in r["streams"]][:50],
                 sample=[{k: r.get(k) for k in ("record", "path", "name", "in_use", "si_created", "fn_created", "size")} for r in recs[:40]])
    elif a.kind == "usn":
        s.update(records=len(a.obj), sample=a.obj[:60])
    elif a.kind == "tabstate":
        s["text"] = a.obj[:40]
    else:
        s.update(a.obj if isinstance(a.obj, dict) else {"value": a.obj})
    return _j(s)


def triage(files: dict, deadline=None) -> dict:
    arts = artifacts(files, deadline)
    return {"made_by": "solvers/toolkits/windows.py", "artifacts": [summary(a) for a in arts],
            "persistence": _j(persistence(arts)), "findings": _j({k: v for k, v in findings(arts).items() if k != "encoded_names"}),
            "not_read": sorted(basename(n.split(ARROW)[-1]) for n, d in _unique(files) if not sniff(n, d))}


def render(t: dict) -> str:
    lines = []
    for s in t["artifacts"]:
        lines.append(f"== {s['file']}  [{s['kind']}]")
        for k, v in s.items():
            if k in ("file", "kind") or v in (None, [], {}, ""):
                continue
            if isinstance(v, list) and v and isinstance(v[0], (dict, list)):
                lines.append(f"  {k} ({len(v)}):")
                lines += ["    " + json.dumps(x, ensure_ascii=False)[:400] for x in v[:40]]
                if len(v) > 40:
                    lines.append(f"    ... {len(v) - 40} more")
            else:
                lines.append(f"  {k}: {json.dumps(v, ensure_ascii=False)[:600] if not isinstance(v, str) else v[:600]}")
    lines.append("== persistence")
    for p in t["persistence"]:
        flag = " !" + ",".join(p["why"]) if p["why"] else ""
        lines.append(f"  {p['mechanism']} {p['technique']} name={p['name']!r} command={str(p['command'])[:300]!r} where={p['where']!r} "
                     f"time={p['time']} source={p['source']}{flag}")
    if not t["persistence"]:
        lines.append("  none found")
    f = t.get("findings") or {}
    if any(f.values()):
        lines.append("== findings (readings for a person; an answer built from one is unsure)")
        for k in ("flags", "stream_contents", "net_user_passwords"):
            lines += [f"  {k}: " + json.dumps(x, ensure_ascii=False)[:500] for x in f.get(k) or []]
        if f.get("recycle"):
            lines += [f"  recycle {k}: {json.dumps(v, ensure_ascii=False)[:500]}" for k, v in f["recycle"].items() if v]
    if t["not_read"]:
        lines.append("== not read (no Windows artifact by its bytes): " + ", ".join(t["not_read"][:40]))
    return "\n".join(lines)


# ---- signals: how much a delivery looks like Windows host forensics ------------------------------------------------

_Q_WORDS = re.compile(r"\b(event ?id|event log|evtx|sysmon|security log|logon|log ?on type|registry|hive|run key|hk(?:lm|cu)|ntuser|"
                      r"prefetch|\.pf\b|shortcut|\.lnk\b|scheduled task|task scheduler|schtasks|amcache|shimcache|appcompatcache|"
                      r"userassist|shellbags?|recycle bin|\$mft|mft record|usn journal|persistence|autorun|service (?:was )?install|"
                      r"jump ?list|destinations-ms|script ?block|4624|4625|4688|4720|7045|4104|wmi (?:event )?subscription|timestomp)\b", re.I)
_Q_DOTTED = re.compile(r"\bDetermine\s+(evtx|eventlog|event|lnk|shortcut|prefetch|pf|registry|reg|regf|hive|task|scheduled_task|"
                       r"recycle|recycle_bin|mft|ntfs|usn|amcache|shimcache|userassist)\.[a-z0-9_.]+\s+for\b", re.I)
_FOREIGN_ID = re.compile(r"^(?:message|answer)$|^d\d\d_|-(?:role|attack|steps|adapter|campaign|scenario|syntax|carrier|obfuscation)$")


def signals(questions, files) -> float:
    """0..1: how strongly the questions and the bytes look like this category. Cheap: magic bytes
    and the first 4 KB of each file, a word list over the questions; nothing is parsed."""
    kinds = {sniff(n, d) for n, d in _unique(files or {})} - {""}
    by_bytes = 0.6 if kinds & set(STRONG) else 0.5 if kinds & {"reg", "task", "event_xml"} else 0.3 if kinds else 0.0
    qs = list(questions or [])
    hits = foreign = 0
    for q in qs:
        text = f"{q.get('question') or ''} {q.get('answer_id') or q.get('id') or ''}".replace("-", " ").replace("_", " ")
        if _Q_WORDS.search(text) or _Q_DOTTED.search(str(q.get("question") or "")):
            hits += 1
        if _FOREIGN_ID.search(re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("id") or ""))):
            foreign += 1
    by_words = 0.4 * min(1.0, 2.0 * hits / len(qs)) if qs else 0.0
    score = min(1.0, by_bytes + by_words)
    if qs and foreign * 2 >= len(qs):
        score *= 0.3
    return round(score, 3)


# ---- the answer's form: plain, unsure or nothing ---------------------------------------------------------------------

def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _accepted(q) -> list:
    f = _fmt(q)
    for key in ("accepted_values", "options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            return [str(v) for v in f[key]]
    return []


_TEMPLATE = re.compile(r"YYYY[-/]MM[-/]DD(?:[T ]HH:MM(?::SS(?:\.[fFsS]{1,9})?)?)?(?:Z|[+-]HH:MM| UTC)?")


def _time_templates(text: str) -> list:
    """Regular expressions for the time templates a syntax spells out (YYYY-MM-DDTHH:MM:SSZ and the like)."""
    out = []
    for m in _TEMPLATE.finditer(text):
        tpl, rx = m.group(0), ""
        tail = ""
        if tpl.endswith(" UTC"):
            tpl, tail = tpl[:-4], " UTC"
        for i, ch in enumerate(tpl):
            if ch == "T" and i == 10:
                rx += "T"
            elif ch == "Z":
                rx += "Z"
            elif ch.isalpha():
                rx += r"\d"
            elif ch in "+-" and i > 10:
                rx += "[+-]"
            else:
                rx += re.escape(ch)
        out.append(re.compile(rx + re.escape(tail)))
    return out


def _is_json(v: str) -> bool:
    try:
        json.loads(v)
        return True
    except ValueError:
        return False


def _filters(q, vtype):
    """(hard, soft, case_blind). A hard rule is the question's own contract (a pattern, the
    accepted values, an integer, an ATT&CK id): a value that fails one is not an answer. A soft
    rule is this file's reading of the syntax prose; it only narrows, and never to nothing."""
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    syntax = str(f.get("syntax") or "")
    words = (syntax + " " + str(q.get("question") or "")).lower()
    case_blind = str(q.get("normalization") or "").lower() in ("case_insensitive", "casefold", "lower", "lowercase") \
        or re.search(r"case is ignored|case[- ]insensitive|letter case (?:is |are )?(?:ignored|accepted)", words) is not None
    hard, soft = [], []
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            crx = re.compile(rx, re.I if case_blind else 0)
            hard.append(lambda v: crx.fullmatch(v) is not None)
        except re.error:
            pass
    acc = _accepted(q)
    if acc:
        pool = {a.lower() for a in acc} if case_blind else set(acc)
        hard.append(lambda v: (v.lower() if case_blind else v) in pool)
    if kind == "integer":
        hard.append(lambda v: re.fullmatch(r"-?\d+", v) is not None)
    elif kind == "mitre_attack_id":
        hard.append(lambda v: re.fullmatch(r"T\d{4}(?:\.\d{3})?", v) is not None)
    elif kind == "json":
        hard.append(_is_json)
    if vtype in ("text", "path", "hex", "serial", "digest", "regint", "bytes") and not case_blind:
        lower, upper = re.search(r"\blower-?case\b", words), re.search(r"\bupper-?case\b", words)
        if lower and not upper:
            soft.append(lambda v: v == v.lower())
        elif upper and not lower:
            soft.append(lambda v: v == v.upper())
    if vtype in ("hex", "serial", "regint", "bytes"):
        if re.search(r"no 0x|without (?:a |the |any )?(?:0x )?prefix|use no prefix|no prefix", words):
            soft.append(lambda v: not v.lower().startswith("0x"))
        elif re.search(r"0x[- ]prefix|with (?:a |the )?0x|prefixed with 0x|leading 0x", words):
            soft.append(lambda v: v.lower().startswith("0x"))
        if re.search(r"\bdecimal\b|base-10", words) and not re.search(r"hexadecimal", words):
            soft.append(lambda v: v.isdigit())
        elif re.search(r"\bhex(?:adecimal)?\b", words) and not re.search(r"\bdecimal\b|base-10", words):
            soft.append(lambda v: not v.isdigit() or v.lower().startswith("0x") or len(v) == 8)
    if vtype == "path":
        if re.search(r"base ?(?:file)?name|no directory path|without (?:the |a |any )?(?:directory|path)|file ?name only|just the file ?name", words):
            soft.append(lambda v: "\\" not in v and "/" not in v)
        elif re.search(r"full path|absolute path|complete path|including (?:the |its )?(?:drive|directory)|fully[- ]qualified", words):
            soft.append(lambda v: "\\" in v or "/" in v)
    if vtype == "time":
        templates = _time_templates(syntax + " " + str(q.get("question") or ""))
        if templates:
            soft.append(lambda v: any(t.fullmatch(v) for t in templates))
        elif re.search(r"\bunix\b|\bepoch\b", words):
            soft.append(lambda v: v.isdigit() and len(v) <= 11)
        elif "filetime" in words:
            soft.append(lambda v: v.isdigit() and len(v) > 11)
        elif re.search(r"iso[- ]?8601|rfc ?3339", words):
            soft.append(lambda v: "T" in v)
    return hard, soft, case_blind


def _options(value, vtype) -> list:
    """Spellings of one value, best first: [(name, text)]."""
    if isinstance(value, Stamp):
        return time_options(value)
    if isinstance(value, bool):
        return [("lower", "true"), ("title", "True"), ("yes_no", "yes"), ("digit", "1")] if value else \
            [("lower", "false"), ("title", "False"), ("yes_no", "no"), ("digit", "0")]
    if vtype in ("hex", "serial") and isinstance(value, int):
        up, lo = f"{value:08X}", f"{value:08x}"
        out = [("upper", up), ("lower", lo), ("0x_lower", "0x" + lo), ("0x_upper", "0x" + up)]
        if vtype == "serial":
            out.insert(1, ("dashed", f"{up[:4]}-{up[4:]}"))
        return out + [("decimal", str(value))]
    if vtype == "regint" and isinstance(value, int):
        return [("decimal", str(value)), ("0x_8", f"0x{value:08x}"), ("0x", f"0x{value:x}")]
    if isinstance(value, int):
        return [("decimal", str(value))]
    if isinstance(value, (bytes, bytearray)):
        return [("hex_lower", bytes(value).hex()), ("hex_upper", bytes(value).hex().upper())] if value else []
    if isinstance(value, (list, tuple)):
        if vtype == "label":
            return [(str(v), str(v)) for v in value]
        vals = [_j(v) for v in value]
        strs = [str(v) for v in vals]
        return [("json", json.dumps(vals, separators=(",", ":"), ensure_ascii=False)), ("arrow", ">".join(strs)),
                ("comma", ",".join(strs)), ("comma_space", ", ".join(strs))]
    v = str(value)
    if not v.strip():
        return []
    if vtype == "digest":
        return [("lower", v.lower()), ("upper", v.upper())]
    out = [("raw", v)]
    stripped = v.strip().strip('"')
    if stripped != v:
        out.append(("unquoted", stripped))
    if vtype == "path" and ("\\" in v or "/" in v):
        base = basename(stripped) or stripped.replace("/", "\\").rsplit("\\", 1)[-1]
        out += [("lower", v.lower()), ("basename", base), ("basename_lower", base.lower())]
    elif v.lower() != v:
        out.append(("lower", v.lower()))
    return out


def _pick(key: str, options: list):
    key = re.sub(r"[^a-z0-9_.+/@-]+", "_", key.lower())
    if labels is not None:
        try:
            return labels.pick(key, options)
        except ValueError:      # labels.py does not know the `windows` prefix yet: still unsure, never plain
            pass
    return SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in options[:12]]}, separators=(",", ":"))


_WHOLE_SECOND = ("iso_z", "space", "iso", "iso_offset", "space_utc", "epoch", "date")


def decide(q, key, vtype, value, proven, aid=""):
    """The answer for one established value: plain, an unsure pick, or None (see the module text).
    A fact that is not proven (the question's reading is this file's own) is keyed by its answer
    id, so a name the judge accepts for one question never answers another one plain."""
    opts, seen = [], set()
    for name, v in _options(value, vtype):
        if isinstance(v, str) and v != "" and v not in seen:
            seen.add(v)
            opts.append((name, v))
    if not opts:
        return None
    before = len(opts)
    hard, soft, case_blind = _filters(q, vtype)
    for rule in hard:
        opts = [o for o in opts if rule(o[1])]
        if not opts:
            return None
    for rule in soft:
        keep = [o for o in opts if rule(o[1])]
        if keep:
            opts = keep
    uniq, seen = [], set()
    for name, v in opts:
        k = v.lower() if case_blind else v
        if k not in seen:
            seen.add(k)
            uniq.append((name, v))
    natural = (isinstance(value, int) and not isinstance(value, (bool, Stamp))) or \
        (str(_fmt(q).get("kind") or "") == "integer" and not isinstance(value, bool))
    # a time with a sub-second part, spelled to the second: cut or rounded is the judge's choice
    cut = isinstance(value, Stamp) and int(value) % 10000000 != 0 and len(uniq) == 1 and uniq[0][0] in _WHOLE_SECOND
    if proven and len(uniq) == 1 and vtype != "label" and not cut and (len(uniq) < before or natural):
        return uniq[0][1]
    if not proven and aid:
        key = f"{key}@{aid}"
    return _pick(f"{KEY}.{key}", uniq)


class Hit:
    """One established value. explains: the strings (names, paths, phrases) of the question this
    value accounts for; patterns: the regular expressions whose words it does. _unexplained() reads them."""
    __slots__ = ("key", "vtype", "value", "proven", "explains", "patterns")

    def __init__(self, key, vtype, value, proven, explains=(), patterns=()):
        self.key, self.vtype, self.value, self.proven = key, vtype, value, bool(proven)
        self.explains, self.patterns = [str(e) for e in explains if e], [p for p in patterns if p]


# ---- every word of a question must be accounted for before an answer is plain --------------------------------

_NEUTRAL = set("""a an the of in on at for to from by with is are was were be been does do did has have had it its this that
there what which who when where how many much number count total file files artifact artifacts evidence delivery
delivered provided given attached supplied contain contains contained present found shown listed stored give provide
determine find identify report state answer enter submit please according as""".split())
_KIND_NEUTRAL = {
    "evtx": "event events log logs eventlog evtx record records entry entries logged recorded security system application "
            "sysmon powershell windows id ids eid value values appear appears occur occurs occurred",
    "registry": "registry hive key keys subkey subkeys value values",
    "prefetch": "prefetch pf", "lnk": "shortcut lnk link", "task": "scheduled task", "recycle": "recycle bin recycled",
    "mft": "mft ntfs",
    "jumplist": "jump list jumplist destination destinations entry entries item items link links "
                "target targets file files document documents automaticdestinations customdestinations",
}
_FORMAT_WORDS = re.compile(
    r"\blower-?case\b|\bupper-?case\b|base ?(?:file)?name(?: only)?|no directory path|without (?:the |a |any )?(?:directory|path)|"
    r"file ?name only|just the file ?name|fully[- ]qualified|no 0x(?: prefix)?|without (?:a |the |any )?(?:0x )?prefix|use no prefix|"
    r"no prefix|0x[- ]prefix|with (?:a |the )?0x(?: prefix)?|prefixed with 0x|leading 0x|\bdecimal\b|base-10|\bhex(?:adecimal)?\b|"
    r"\bunix\b|\bepoch\b|\bfiletime\b|iso[- ]?8601|rfc ?3339|letter case (?:is |are )?(?:ignored|accepted)|case is ignored|"
    r"case[- ]insensitive|\butc\b|\binteger\b|\bdigits\b|\bonly\b|\bformat(?:ted)?\b|\buse\b|\bbytes\b")


def _tokens(text: str) -> list:
    return re.findall(r"[a-z0-9$_]+", str(text).lower())


def _rx_words(src: str) -> set:
    """The literal words of a regular expression's source ('times?' gives times and time)."""
    src = re.sub(r"\\[A-Za-z]", " ", src.lower())
    out = set()
    for m in re.finditer(r"[a-z]{2,}", src):
        out.add(m.group(0))
        if src[m.end():m.end() + 1] == "?" and len(m.group(0)) > 2:
            out.add(m.group(0)[:-1])
    return out


def _unexplained(text: str, hit) -> list:
    """The words of a question that nothing accounts for: not a neutral word, not a word of the
    asked field's own vocabulary, not a name, path, id or value the hit used, not a format
    instruction. One such word ('before', 'parent', 'not', 'malicious', another program's name)
    means the question may ask for something else, and the answer is not plain."""
    kind = hit.key.split("/", 1)[-1].split(".", 1)[0]
    known = set(_NEUTRAL) | set(_KIND_NEUTRAL.get(kind, "").split())
    stems = set()
    for src in hit.patterns:
        words = _rx_words(src)
        known |= words
        stems |= {w for w in words if len(w) >= 5}
    for e in hit.explains:
        known |= set(_tokens(e))
    body = _TEMPLATE.sub(" ", text).lower()
    body = re.sub(r"['’]s\b", " ", _FORMAT_WORDS.sub(" ", body))
    return [t for t in _tokens(body) if t not in known and not any(t.startswith(w) for w in stems)]


# ---- what a question asks -----------------------------------------------------------------------------------------

# (field, value type, what a question calls it, other exact names). The longest match wins; a tie answers nothing.
FIELDS = {
    "prefetch": (
        ("executable_name", "path", r"executable(?: file)? ?name|exe(?:cutable)? name|name of the (?:executable|program|binary|application|process)|which (?:executable|program|binary|application)|process name", ("executable", "exe_name", "process_name", "name")),
        ("hash", "hex", r"prefetch hash|path hash|\bhash\b", ("prefetch_hash", "path_hash")),
        ("run_count", "int", r"run count|execution count|times? (?:was|has|did|were|had)\b.{0,60}\b(?:run|ran|executed|launched|started)|(?:run|ran|executed|launched|started) how many times|number of (?:runs|executions|times)", ("execution_count", "runs")),
        ("last_run_time", "time", r"last (?:run|ran|executed|execution|launched|started)(?: time)?|most recent(?:ly)? (?:run|ran|execut\w+|launch\w*)|when was .{0,60} (?:last )?(?:run|ran|executed|launched)", ("last_run", "last_executed", "last_execution_time")),
        ("last_run_times", "list", r"last run times|all (?:of the )?run times|previous run times|execution times", ("run_times",)),
        ("version", "int", r"prefetch (?:format )?version|format version", ("format_version",)),
        ("volume_serial", "serial", r"volume serial(?: number)?|serial number", ("volume_serial_number", "serial")),
        ("volume_created", "time", r"volume (?:was )?creat\w+(?: time)?", ("volume_creation_time",)),
        ("volume_device_path", "text", r"volume (?:device )?path|device path", ("device_path",)),
        ("executable_path", "path", r"full path|executable path|path of the (?:executable|program|binary)|(?:run|ran|executed|launched) from|where was .{0,40} located", ("path",)),
        ("file_count", "int", r"how many (?:files|dlls|modules) (?:were |are |did |does )?(?:it )?(?:loaded?|referenced?|accessed|listed|mapped)|number of (?:loaded|referenced) (?:files|modules|dlls)|file reference count|loaded file count", ("files_loaded", "file_references", "metrics_count")),
        ("compressed", "bool", r"\bcompressed\b", ("is_compressed", "mam_compressed")),
    ),
    "lnk": (
        ("target_path", "path", r"target(?: file)?(?: path)?|link target|points? to|local base path|what (?:file|program|executable) does", ("target", "local_base_path", "local_path")),
        ("arguments", "text", r"(?:command[- ]line )?arguments?|parameters", ("command_line_arguments", "args")),
        ("working_dir", "path", r"working dir(?:ectory)?|start in", ("working_directory",)),
        ("relative_path", "text", r"relative path", ()),
        ("icon_location", "path", r"icon (?:location|path|file)", ("icon",)),
        ("description", "text", r"description|comment|name string", ("comment", "name")),
        ("creation_time", "time", r"(?:target )?creat(?:ion|ed)(?: time| date| timestamp)?", ("created", "target_created", "header_creation_time")),
        ("access_time", "time", r"(?:last )?access(?:ed)?(?: time| date| timestamp)?", ("accessed", "target_accessed", "header_access_time")),
        ("write_time", "time", r"(?:last )?(?:write|written|modif\w+)(?: time| date| timestamp)?", ("modified", "target_modified", "header_write_time", "modification_time")),
        ("file_size", "int", r"(?:target )?(?:file )?size", ("target_size", "target_file_size", "size")),
        ("machine_id", "text", r"machine (?:id|identifier|name)|netbios(?: name)?|host ?name|computer ?name|which (?:computer|machine|host)", ("tracker_machine_id", "hostname", "netbios_name")),
        ("mac_address", "text", r"mac address", ("mac", "tracker_mac_address")),
        ("volume_serial", "serial", r"(?:drive|volume) serial(?: number)?|serial number", ("drive_serial", "volume_serial_number", "drive_serial_number")),
        ("volume_label", "text", r"volume (?:label|name)", ()),
        ("drive_type", "text", r"drive type", ()),
        ("show_command", "text", r"show command|window (?:style|state)", ("window_style",)),
        ("command_line", "text", r"full command(?: line)?|whole command|command line(?! arguments)", ("command",)),
    ),
    "task": (
        ("uri", "path", r"task (?:name|uri|path)|name of the (?:scheduled )?task|uri", ("name", "task_name", "task_uri", "registration_uri")),
        ("author", "text", r"author|registered by|created by|who (?:created|registered)", ("registration_author",)),
        ("date", "text", r"registration (?:date|time)|(?:was |it )?(?:registered|created)(?: on| at)?|creation (?:date|time)|\bdate\b", ("registration_date", "created")),
        ("description", "text", r"description", ()),
        ("user_id", "text", r"user ?id|runs? as|principal|which (?:user|account)|run under", ("principal_user_id", "principal", "run_as")),
        ("run_level", "text", r"run ?level|privilege level", ("principal_run_level",)),
        ("logon_type", "text", r"logon ?type", ()),
        ("command", "path", r"command|executable|program|binary|action|what does .{0,30} (?:run|execute|launch)", ("exec_command", "action_command", "action")),
        ("arguments", "text", r"arguments?|parameters", ("exec_arguments", "action_arguments")),
        ("working_directory", "path", r"working dir(?:ectory)?", ("exec_working_directory",)),
        ("trigger_type", "text", r"trigger(?: type)?|what triggers|when does .{0,30} (?:run|fire|start)", ("trigger",)),
        ("start_boundary", "text", r"start ?boundary|start (?:time|date)|first (?:run|start)", ("trigger_start_boundary",)),
        ("interval", "text", r"interval|repetition|how often", ("repetition_interval",)),
        ("hidden", "text", r"\bhidden\b", ("settings_hidden",)),
        ("enabled", "text", r"\benabled\b", ("settings_enabled",)),
        ("command_line", "text", r"full command(?: line)?|whole command|command line(?! arguments)", ()),
    ),
    "recycle": (
        ("original_path", "path", r"original (?:path|location|file ?name|name)|deleted file|which file|what file|full path|file ?name", ("path", "original_file_path", "original_filename")),
        ("deleted_time", "time", r"delet(?:ed|ion)(?: time| date| timestamp)?|when was", ("deletion_time", "deleted", "deletion_timestamp")),
        ("file_size", "int", r"(?:original )?(?:file )?size", ("size", "original_size", "original_file_size")),
        ("version", "int", r"(?:format|header) version", ("header_version",)),
    ),
    "mft": (
        ("name", "text", r"file ?name|name of the file", ("filename", "file_name")),
        ("path", "path", r"full path|path", ()),
        ("record", "int", r"(?:mft )?(?:record|entry) number", ("record_number", "entry_number")),
        ("parent", "int", r"parent (?:record|entry|directory)(?: number)?", ("parent_record",)),
        ("si_created", "time", r"\$?standard[_ ]information creat\w+(?: time)?|\$?si creat\w+(?: time)?", ("si_creation_time", "standard_information_created")),
        ("si_modified", "time", r"\$?standard[_ ]information modif\w+(?: time)?|\$?si modif\w+(?: time)?", ("si_modification_time",)),
        ("fn_created", "time", r"\$?file[_ ]name creat\w+(?: time)?|\$?fn creat\w+(?: time)?|(?:real|true|actual|original) creat\w+(?: time)?", ("fn_creation_time", "file_name_created")),
        ("fn_modified", "time", r"\$?file[_ ]name modif\w+(?: time)?|\$?fn modif\w+(?: time)?", ("fn_modification_time",)),
        ("size", "int", r"(?:file |data )?size", ("file_size", "data_size")),
        ("timestomp_hint", "bool", r"timestomp\w*", ("timestomped", "is_timestomped")),
        ("in_use", "bool", r"in use|allocated", ("is_in_use",)),
        ("is_directory", "bool", r"\bis\b.{0,40}\ba (?:directory|folder)\b", ()),
    ),
}

# A field a bare word would reach ("size") is asked for only when the question also says whose.
REQUIRES = {("lnk", "file_size"): r"target|linked|referenced|points? to|record(?:s|ed)?\b|stored|header",
            ("recycle", "file_size"): r"original|deleted|recycled|recorded|stored",
            ("mft", "size"): r"\bmft\b|record|\$data|logical|resident",
            ("prefetch", "hash"): r"prefetch|path hash",
            ("lnk", "volume_serial"): r"shortcut|\blnk\b|link|drive|volume",
            ("task", "date"): r"task|regist"}

PREFIX_KINDS = {"evtx": EVENT_KINDS, "eventlog": EVENT_KINDS, "event": EVENT_KINDS, "events": EVENT_KINDS, "winevt": EVENT_KINDS,
                "lnk": ("lnk",), "shortcut": ("lnk",), "shell_link": ("lnk",), "prefetch": ("prefetch",), "pf": ("prefetch",),
                "scca": ("prefetch",), "registry": REG_KINDS, "reg": REG_KINDS, "regf": REG_KINDS, "hive": REG_KINDS,
                "task": ("task",), "scheduled_task": ("task",), "schtasks": ("task",), "recycle": ("recycle",),
                "recycle_bin": ("recycle",), "recyclebin": ("recycle",), "mft": ("mft",), "ntfs": ("mft",), "usn": ("usn",)}

_KIND_WORDS = (
    ("prefetch", ("prefetch",), r"\bprefetch\b|\.pf\b"),
    ("jumplist", ("jumplist",), r"\bjump ?list\b|automatic ?destinations|custom ?destinations|destinations-ms"),
    ("lnk", ("lnk",), r"\bshortcut\b|\.lnk\b|\blnk\b|\blink file\b|\bshell link\b"),
    ("task", ("task",), r"\bscheduled task\b|\btask\b"),
    ("recycle", ("recycle",), r"\brecycle\b|\$i\b|\brecycled\b"),
    ("mft", ("mft",), r"\bmft\b|\bntfs\b|\$standard_information|\$file_name|\btimestomp"),
    ("registry", REG_KINDS, r"\bregistry\b|\bhive\b|\bhk(?:lm|cu|u|cr)\b|\bhkey_|\buserassist\b|\bshimcache\b|\bappcompatcache\b|\bamcache\b|\brun ?key\b|\brun dialog\b|\brunmru\b|\btyped ?paths?\b|\bdebugger\b"),
    ("event", EVENT_KINDS, r"\bevents?\b|\bevent ?logs?\b|\bevtx\b|\bsysmon\b|\blogged\b|\blogs?\b"),
)


def _kinds_named(low: str, arts) -> set:
    """The artifact kinds a question names in words, among the kinds delivered; empty when it names none."""
    have = {a.kind for a in arts}
    out = set()
    for _, kinds, rx in _KIND_WORDS:
        if re.search(rx, low) and have & set(kinds):
            out |= set(kinds)
    return out


def _match(table, words, exact=None, kind=""):
    """(field entry, proven) for the words; (None, False) when nothing or two things match."""
    if exact:
        for entry in table:
            if exact == entry[0] or exact in entry[3]:
                return entry, True
    best = []
    for entry in table:
        m = re.search(entry[2], words)
        need = REQUIRES.get((kind, entry[0]))
        if m and exact is None and need and not re.search(need, words):
            continue
        if m:
            best.append((len(m.group(0)), entry))
    if not best:
        return None, False
    best.sort(key=lambda b: -b[0])
    if len(best) > 1 and best[0][0] == best[1][0] and best[0][1][0] != best[1][1][0]:
        return None, False
    return best[0][1], exact is None


def _word_in(needle: str, text: str) -> bool:
    return len(needle) >= 3 and needle.lower() in text.lower() and re.search(r"(?<![\w.$-])" + re.escape(needle) + r"(?![\w-])", text, re.I) is not None


def _aliases(a) -> list:
    o = a.obj if isinstance(a.obj, dict) else {}
    if a.kind == "prefetch":
        n = o.get("executable_name") or ""
        return [n, n.rsplit(".", 1)[0]]
    if a.kind == "lnk":
        b = basename(o.get("target_path") or "")
        return [b, b.rsplit(".", 1)[0]]
    if a.kind == "task":
        return [o.get("uri") or "", basename(o.get("uri") or "")]
    if a.kind == "recycle":
        return [basename(o.get("original_path") or "")]
    return []


def _narrow(group, text):
    hit = [a for a in group if any(_word_in(x, text) for x in _aliases(a))]
    return hit if hit and len(hit) < len(group) else group


def _records(a, text) -> list:
    if a.kind != "mft":
        return [a.obj]
    recs = a.obj
    if len(recs) == 1:
        return recs
    low = text.lower()
    hit = [r for r in recs if r.get("name") and r["name"].lower() in low and _word_in(r["name"], text)]
    live = [r for r in hit if r["in_use"]]
    return live or hit


def _q_fields(text, words, id_words, targets, exact=None, kinds=None, named=None, alone=True) -> list:
    """Hits from the field tables. In a worded question (no dotted property) an artifact is asked
    about only when the question names its kind (`named`), its file or what it is about (a
    program, a task), or when it is the only artifact delivered (`alone`)."""
    hits = []
    for kind, table in FIELDS.items():
        group = [a for a in targets if a.kind == kind]
        if exact is None and not alone and kind not in (named or ()):
            group = [a for a in group if _word_in(a.file, text) or any(_word_in(x, text) for x in _aliases(a))]
        if not group or (kinds is not None and kind not in kinds):
            continue
        entry, proven = _match(table, words, exact, kind)
        if exact is None:
            by_id, _ = _match(table, id_words, None, kind)
            if entry is not None and by_id is not None and by_id[0] != entry[0]:
                continue
            if entry is None and by_id is not None:
                entry, proven = by_id, True
        if entry is None:
            continue
        name, vtype = entry[0], entry[1]
        for a in _narrow(group, text):
            for rec in _records(a, text):
                if name == "volume_serial" and kind == "prefetch":
                    vols = rec.get("volumes") or []
                    v = vols[0]["serial"] if len(vols) == 1 else None
                elif name in ("volume_created", "volume_device_path"):
                    vols = rec.get("volumes") or []
                    v = vols[0]["created" if name == "volume_created" else "device_path"] if len(vols) == 1 else None
                else:
                    v = rec.get(name)
                if v is None or v == "" or v == []:
                    continue
                sure = proven and name != "timestomp_hint" and a.complete      # the hint is a heuristic, never a fact
                if kind == "lnk" and name in ("target_path", "command_line") and rec.get("target_source") == "id_list":
                    sure = False
                names = [a.file] + _aliases(a) + [rec.get("name") or ""]
                hits.append(Hit(f"{vtype}/{kind}.{name}", vtype, v, sure, names, (entry[2], REQUIRES.get((kind, name)))))
    return hits


# ---- jump lists ----------------------------------------------------------------------------------------------------

_JL_COUNT = re.compile(r"how many|number of|count of|total (?:number )?of")
_JL_THING = re.compile(r"\b(?:destinations?|entr(?:y|ies)|items?|links?|targets?|files?|documents?|records?)\b")


def _jl_select(entries, text):
    """The jump-list entries a question is about: all when one entry, else the entries whose target
    file name the question names. [] when the question names no one entry (never-wrong: a per-entry
    fact is answered only when the question picks exactly one)."""
    if len(entries) == 1:
        return entries
    named = []
    for e in entries:
        tp = (e.get("lnk") or {}).get("target_path") or ""
        bn = basename(tp)
        if bn and (_word_in(bn, text) or _word_in(bn.rsplit(".", 1)[0], text)):
            named.append(e)
    return named


def _q_jumplist(q, text, low, targets) -> list:
    """Jump-list hits. A count of destinations is byte-proven (plain-eligible); every per-entry
    fact (target, times, arguments, host, MAC) is this reader's reading of an author-named field,
    so it is an unsure pick, never plain -- the lnk field table supplies the vocabulary."""
    hits = []
    for a in targets:
        if a.kind != "jumplist" or not isinstance(a.obj, dict):
            continue
        obj = a.obj
        entries = obj.get("entries") or []
        if _JL_COUNT.search(low) and _JL_THING.search(low):
            if re.search(r"\bpinned\b", low) and obj.get("pinned_count"):
                hits.append(Hit("int/jumplist.pinned_count", "int", obj["pinned_count"], False, [a.file]))
            else:
                n = obj.get("entry_count")
                if isinstance(n, int) and n > 0:
                    hits.append(Hit("int/jumplist.entry_count", "int", n, bool(obj.get("complete")), [a.file],
                                    (r"how many|number of|count|destination|entr|item|link|target|file|document|jump|list",)))
            continue
        recs = _jl_select(entries, text)
        if len(recs) != 1:
            continue
        link = recs[0].get("lnk") or {}
        entry, _ = _match(FIELDS["lnk"], low, None, "lnk")
        if entry is None:
            continue
        name, vtype = entry[0], entry[1]
        v = link.get(name)
        if v is None or v == "" or v == []:
            continue
        bn = basename(link.get("target_path") or "")
        hits.append(Hit(f"{vtype}/jumplist.{name}", vtype, v, False, [a.file, bn], (entry[2],)))
    return hits


# ---- events ------------------------------------------------------------------------------------------------------------

_EID = re.compile(r"\b(?:events?(?:\s*ids?)?|eids?|event\s*codes?)\s*[#:=]?\s*(\d{1,5})\b|\b(\d{3,5})\s+events?\b")
CONCEPT_IDS = (
    (r"account (?:was |were |got )?created|new (?:local )?(?:user|account)|created (?:a |an |the )?(?:new )?(?:local )?(?:user|account)|user (?:account )?creat", (4720,)),
    (r"service (?:was |were |got )?(?:install|creat)\w*|new service|install\w* (?:a |the |new |malicious )*service|malicious service", (7045, 4697)),
    (r"failed log ?(?:on|in)s?|log ?(?:on|in) failures?|brute[- ]?forc", (4625,)),
    (r"success\w* log ?(?:on|in)s?|log(?:ged|s)? ?(?:on|in) success\w*", (4624,)),
    (r"logs? (?:was |were |got )?cleared|cleared the (?:\w+ )?logs?|log clear", (1102, 104)),
    (r"scheduled task (?:was |were |got )?(?:creat|regist)\w*|created (?:a |the )?scheduled task", (4698, 106)),
    (r"added to (?:the )?(?:local |global |domain )?(?:\w+ )?group", (4732, 4728, 4756)),
    (r"script ?block", (4104,)),
    (r"process (?:was )?creat\w+|process creation|parent process|child process|command ?line of|\bprocess\b.{0,40}\b(?:command ?line|spawned|launched|started)", (4688, 1)),
    (r"network connection|outbound connection|connect\w* to|\bc2 (?:server|address|ip|host)", (3,)),
    (r"dns (?:query|quer\w+|lookup|request)|domain (?:name )?(?:was )?(?:queried|resolved|looked up)", (22,)),
    (r"file (?:was |were )?(?:creat\w+|dropped|written)|dropped (?:a |the )?file|\bdrop\w* (?:by|to|in)\b", (11,)),
    (r"registry value (?:was )?set|registry (?:modif|chang)\w+", (13,)),
)
CONCEPT_FIELDS = (
    (r"source (?:ip|address)|ip address|from (?:which|what) ip|attacker'?s? ip|remote (?:ip|address)|originat\w+ (?:ip|address)", ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress", "ClientIPAddress")),
    (r"destination (?:ip|address)|(?:connect\w* to|contacted|remote|\bc2\b).{0,40}\bip(?: address)?\b|\bip(?: address)?\b.{0,60}(?:connect\w* to|contacted)", ("DestinationIp", "DestAddress")),
    (r"destination port|(?:connect\w* to|contacted|remote|\bc2\b).{0,40}\bport\b|\bport\b.{0,60}(?:connect\w* to|contacted)", ("DestinationPort", "DestPort")),
    (r"\bip(?: address)?\b", ("IpAddress", "SourceIp", "DestinationIp", "SourceAddress", "DestAddress", "ClientAddress")),
    (r"\bport\b", ("DestinationPort", "SourcePort", "IpPort", "DestPort")),
    (r"source port", ("SourcePort", "IpPort")),
    (r"workstation(?: name)?|source (?:host|computer|machine)", ("WorkstationName", "Workstation")),
    (r"logon ?type", ("LogonType",)),
    (r"parent command ?line", ("ParentCommandLine",)),
    (r"command ?line", ("CommandLine", "ProcessCommandLine")),
    (r"parent (?:process|image)(?: name| path)?", ("ParentImage", "ParentProcessName")),
    (r"process (?:name|image|path)|image(?: path)?|which (?:process|executable|program|binary)", ("NewProcessName", "Image", "ProcessName")),
    (r"service name|name of the (?:new |installed |malicious )?service", ("ServiceName",)),
    (r"(?:image|binary|service) (?:path|file)|service (?:binary|executable|file ?name)|path of the service", ("ImagePath", "ServiceFileName")),
    (r"task name|name of the (?:scheduled )?task", ("TaskName",)),
    (r"(?:who|which (?:user|account)) (?:created|added|performed|installed|cleared)|by (?:which|what) (?:user|account)|subject (?:user|account)", ("SubjectUserName",)),
    (r"(?:target )?(?:user|account) ?name|which (?:user|account)|name of the (?:new |created )?(?:user|account)|what (?:user|account)", ("TargetUserName", "User", "AccountName", "SamAccountName")),
    (r"domain (?:name )?(?:was )?quer\w+|quer(?:y|ied) (?:name|domain)|dns (?:query|name)|which domain", ("QueryName",)),
    (r"target ?file ?name|file (?:was )?(?:created|dropped|written)|which file|what file", ("TargetFilename",)),
    (r"registry (?:key|path|value name)|target ?object", ("TargetObject",)),
    (r"registry (?:data|value data)|details", ("Details",)),
    (r"hash(?:es)?", ("Hashes",)),
    (r"member (?:name|sid)", ("MemberName", "MemberSid")),
    (r"threat name|malware name|detection name", ("Threat Name", "ThreatName")),
)
_SYSTEM_FIELDS = ((r"computer ?name|host ?name|which (?:computer|host|machine)|name of the (?:computer|host|machine)", "@computer"),
                  (r"\bwhen\b|what time|at what time|timestamp|date and time|time (?:of|was|did)|what date", "@time"),
                  (r"\bchannel\b", "@channel"), (r"\bprovider\b", "@provider"), (r"record (?:id|number)", "@record"))
_TOTAL = re.compile(r"\bhow many (?:total )?(?:events?|records?|event records?|log entries|entries)\b|\bnumber of (?:total )?(?:events?|records?|event records?)\b|"
                    r"\b(?:event|record) count\b|\btotal (?:number|count) of (?:events?|records?)\b")
_QUALIFIED = re.compile(r"\b(that|which|whose|with|where|failed|fail|success\w*|from|by|for|named?|naming|targeting|against|types?|users?|accounts?|"
                        r"address(?:es)?|hosts?|ips?|related|involv\w*|show\w*|indicat\w*|logons?|logins?|errors?|warnings?|critical)\b")
_LOG_WORDS = r"\bevents?\b|\bevent ?logs?\b|\bevtx\b|\bsysmon\b|\b(?:the|this|security|system|application|powershell) logs?\b(?! ?(?:on|in)\b)"
_EVENT_PROPS = {"record_count": "count", "event_count": "count", "events": "count", "records": "count", "total_events": "count",
                "first_event_time": "first", "first_record_time": "first", "oldest_event_time": "first", "earliest_event_time": "first",
                "last_event_time": "last", "last_record_time": "last", "newest_event_time": "last", "latest_event_time": "last",
                "computer": "computer", "computer_name": "computer", "channel": "channel", "provider": "provider", "provider_name": "provider"}


_COUNT_WORDS = r"how many|number of|count of|event count|record count|total number|total count"


def _base(key: str) -> str:
    return key.split("#", 1)[0]


def _ev_get(ev, field):
    if field.startswith("@"):
        return ev.get(field[1:])
    return ev["data"].get(field)


def _event_ids(low, aid, events):
    """(ids, explicit, asked): the event ids a question names (explicit), or the ones its words stand for."""
    present = {e["id"] for e in events}
    ids = {int(a or b) for a, b in _EID.findall(low)}
    ids |= {int(x) for x in re.findall(r"(?:event|eid)[-_ ]?(?:id[-_ ]?)?(\d{3,5})", aid.lower())}
    if ids or re.search(r"\bevents?\b|\bsysmon\b|\bevent ?ids?\b", low):
        known = set(EVENT_NAMES) | present
        ids |= {int(x) for x in re.findall(r"(?<![\w.:-])(\d{3,5})(?![\w.:-])", low)} & known
    if ids:
        return ids, True, True
    for rx, cids in CONCEPT_IDS:
        if re.search(rx, low):
            ids |= set(cids)
    return ids, False, bool(ids)


def _event_field(low, raw_text, aid, sel):
    """(field, strong): the Data name a question asks for. strong: the name itself is in the question."""
    keys = {_base(k) for e in sel[:5000] for k in e["data"]}
    aid_norm = re.sub(r"[^a-z0-9]", "", aid.lower())
    named = [k for k in keys if len(k) >= 3 and re.search(r"(?<![A-Za-z0-9])" + re.escape(k.lower()) + r"(?![A-Za-z0-9])", low)]
    named += [k for k in keys if len(k) >= 6 and k.lower() in aid_norm and k not in named]
    named = [k for k in named if not any(k != o and k.lower() in o.lower() for o in named)]
    if len(named) == 1:
        k = named[0]
        strong = (len(k) >= 8 or sum(c.isupper() for c in k) >= 2) and (re.search(r"(?<![A-Za-z0-9])" + re.escape(k) + r"(?![A-Za-z0-9])", raw_text) is not None or k.lower() in aid_norm)
        return k, strong
    if len(named) > 1:
        return None, False
    found = []
    for rx, names in CONCEPT_FIELDS:
        m = re.search(rx, low)
        if m:
            present = [n for n in names if n in keys]
            if present:
                found.append((len(m.group(0)), present))
    if found:
        found.sort(key=lambda f: -f[0])
        if len(found) > 1 and found[0][0] == found[1][0] and found[0][1] != found[1][1]:
            return None, False
        return (found[0][1][0], False) if len(found[0][1]) == 1 else (None, False)
    for rx, field in _SYSTEM_FIELDS:
        if re.search(rx, low):
            return field, False
    return None, False


def _value_filter(sel, text, skip):
    """Events narrowed to those holding a value the question quotes (a user, an address, a file name); the filter used or None."""
    if not sel or len(sel) > 5000:
        return sel, None
    values = {}
    for e in sel:
        for v in e["data"].values():
            v = str(v or "").strip()
            if 3 <= len(v) <= 80 and v not in skip and not (v.isdigit() and len(v) < 3):
                values.setdefault(v, []).append(e)
                b = basename(v) if "\\" in v else ""
                if 3 <= len(b) and b != v:
                    values.setdefault(b, []).append(e)
                    if "." in b and len(b.rsplit(".", 1)[0]) >= 4:
                        values.setdefault(b.rsplit(".", 1)[0], []).append(e)
    used = [v for v in values if _word_in(v, text) and not v.isdigit()]
    used = [v for v in used if not any(v != o and v in o for o in used)]
    out = sel
    for v in used:
        ids = {id(e) for e in values[v]}
        narrowed = [e for e in out if id(e) in ids]
        if narrowed:
            out = narrowed
    return (out, used) if used and len(out) < len(sel) else (sel, None)


def _field_vtype(field) -> str:
    if field == "@time":
        return "time"
    return "path" if re.search(r"(?i)(image|path|filename|targetobject|processname)$", field) else "text"


def _q_events(q, text, low, aid, targets) -> list:
    arts = [a for a in targets if a.kind in EVENT_KINDS]
    if not arts or any(not a.complete for a in arts):
        return []
    events = all_events(arts)
    ids, explicit, asked = _event_ids(low, aid, events)
    sel = [e for e in events if e["id"] in ids] if asked else events
    if asked and not explicit:              # a concept's Sysmon ids (1, 3, 11, 13, 22) mean Sysmon's events only
        sel = [e for e in sel if e["id"] >= 100 or is_sysmon(e)]
    if "sysmon" in low:
        sel = [e for e in sel if is_sysmon(e)]
    m = re.search(r"logon[ _-]?type\s*(?:of|=|:|is)?\s*(\d{1,2})\b", low)
    by_type = bool(m) and not re.search(r"(?:what|which) (?:is the |was the )?logon[ _-]?type", low)
    if by_type:
        sel = [e for e in sel if str(e["data"].get("LogonType") or "").strip() == m.group(1)]
    bare_text = text
    for a in arts:                          # the log's own file name is not a value the question quotes ("security.evtx")
        bare_text = re.sub(re.escape(a.file), " ", bare_text, flags=re.I)
    sel, used = _value_filter(sel, bare_text, {str(i) for i in ids})
    tag = "+".join(str(i) for i in sorted(ids)) or "any"
    field, strong = _event_field(low, text, aid, sel or events)
    counting = re.search(r"\bhow many\b|\bnumber of\b|\bcount of\b|\b(?:event|record) count\b|\btotal (?:number|count)\b", low)
    said = [g.group(0) for g in _EID.finditer(low)] + [str(i) for i in ids] + ([m.group(0)] if by_type else []) + [a.file for a in arts]
    if counting:
        if re.search(r"\b(?:distinct|unique|different)\b", low):
            if not field:
                return []
            vals = {str(_ev_get(e, field)) for e in sel if _ev_get(e, field) not in (None, "", "-")}
            holes = any(_ev_get(e, field) in ("", "-") for e in sel)      # whether an empty value or '-' counts as one is the author's
            return [Hit(f"int/evtx.{tag}.distinct.{field}", "int", len(vals), explicit and strong and len(ids) == 1 and used is None and bool(vals) and not holes,
                        said + [field], (_COUNT_WORDS, r"distinct|unique|different"))]
        bare = re.sub(r"(?:\b(?:with|having|of|for)\s+)?(?:the\s+)?(?:" + _EID.pattern + ")", " ", low)
        timed = re.search(r"\b(?:after|before|between|since|until|during|within|earlier|later)\b|\d{1,2}:\d{2}|\d{4}-\d{2}-\d{2}", bare) is not None
        if asked:
            holders = sum(1 for a in arts if any(e["id"] in ids for e in a.events))
            # one event id, counted whole or by its LogonType field; a value found in some field is a reading, not a proof
            # ... and never a zero: nothing found may be a log this file did not read (an .evt, a nested archive)
            sure = explicit and len(ids) == 1 and holders <= 1 and not timed and used is None and (by_type or not _QUALIFIED.search(bare)) and bool(sel)
            extra = sum(1 for a in arts for e in a.slack if e["id"] in ids)
            if extra and not by_type and used is None:
                # recovered records of that id: with or without them is the author's choice, so both are offered
                both = [str(len(sel)), str(len(sel) + extra)]
                return [Hit(f"label/evtx.{tag}.count_or_with_slack", "label", both if sel else both[::-1], False, said, (_COUNT_WORDS,))]
            return [Hit(f"int/evtx.{tag}.count", "int", len(sel), sure, said, (_COUNT_WORDS,))]
        about = re.search(_LOG_WORDS, low) or any(_word_in(a.file, text) for a in arts)
        if _TOTAL.search(low) and about and used is None and not by_type and ("sysmon" not in low or len(sel) == len(events)) and len(arts) == 1 and not timed and not _QUALIFIED.search(bare):
            if arts[0].slack:
                both = [str(len(sel)), str(len(sel) + len(arts[0].slack))]
                return [Hit("label/evtx.any.count_or_with_slack", "label", both if sel else both[::-1], False, [a.file for a in arts], (_COUNT_WORDS,))]
            return [Hit("int/evtx.any.count", "int", len(sel), bool(sel), [a.file for a in arts], (_COUNT_WORDS,))]
        return []
    if not asked:
        # No event id and no concept: only a question about the log itself is answered.
        if not re.search(_LOG_WORDS, low):
            return []
        if field == "@time" and not re.search(r"\b(?:first|last|earliest|latest|oldest|newest|most recent) (?:event|record|entry|log entry)\b", low):
            return []
    if not sel or not field:
        return []
    vals = [(e, _ev_get(e, field)) for e in sel]
    vals = [(e, v) for e, v in vals if v not in (None, "", "-")]
    if not vals:
        return []
    first = re.search(r"\b(?:first|earliest|oldest|initial)\b", low)
    last = re.search(r"\b(?:last|latest|newest|most recent|final)\b", low)
    value = None
    if bool(first) != bool(last):
        if all(e["time"] is not None for e, _ in vals):
            order = sorted(vals, key=lambda p: (int(p[0]["time"]), p[0]["record"] or 0))
        elif all(e["record"] is not None for e, _ in vals):
            order = sorted(vals, key=lambda p: p[0]["record"])
        else:
            return []
        edge = order[0] if first else order[-1]
        same = {str(v) for e, v in order if e["time"] == edge[0]["time"]} if edge[0]["time"] is not None else {str(edge[1])}
        if len(same) != 1:
            return []
        value, strong = edge[1], False
    elif re.search(r"\bmost (?:common|frequent|often|targeted|used|active)\b|\bthe most\b", low):
        top = Counter(str(v) for _, v in vals).most_common(2)
        if len(top) > 1 and top[0][1] == top[1][1]:
            return []
        value, strong = top[0][0], False
    else:
        distinct = {str(v) if not isinstance(v, Stamp) else v for _, v in vals}
        if len(distinct) != 1:
            return []
        value = next(iter(distinct))
    vtype = _field_vtype(field)
    return [Hit(f"{vtype}/evtx.{tag}.{field.lstrip('@')}", vtype, value, explicit and strong and len(ids) == 1 and used is None,
                said + [field.lstrip("@")])]


def _q_event_property(prop, targets) -> list:
    arts = [a for a in targets if a.kind in EVENT_KINDS]
    if not arts or any(not a.complete for a in arts):
        return []
    events = all_events(arts)
    m = re.fullmatch(r"(?:event_?(?:id_?)?|eid_?)(\d{1,5})_(?:count|events|records)", prop) or re.fullmatch(r"count_(?:event_?(?:id_?)?|eid_?)(\d{1,5})", prop)
    if m:
        return [Hit(f"int/evtx.{m.group(1)}.count", "int", sum(1 for e in events if e["id"] == int(m.group(1))), True)]
    what = _EVENT_PROPS.get(prop)
    if what == "count":
        return [Hit("int/evtx.any.count", "int", len(events), True)]
    if what in ("first", "last"):
        times = sorted(e["time"] for e in events if e["time"] is not None)
        if len(times) != len(events) or not times:
            return []
        return [Hit(f"time/evtx.{what}_event_time", "time", times[0] if what == "first" else times[-1], True)]
    if what in ("computer", "channel", "provider"):
        vals = {e[what] for e in events if e[what]}
        return [Hit(f"text/evtx.{what}", "text", next(iter(vals)), True)] if len(vals) == 1 else []
    return []


# ---- registry ----------------------------------------------------------------------------------------------------------

_REG_PATH = re.compile(r"((?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]+|SOFTWARE|SYSTEM|SAM|SECURITY|Software|System|ControlSet\d{3}|CurrentControlSet|Root|Microsoft)"
                       r"\\[^\"'`?\n\]\[]*)")
_SYS_WORDS = (("computer_name", "text", r"computer ?name|host ?name|name of the (?:computer|machine|host|system)"),
              ("timezone", "text", r"time ?zone"), ("shutdown_time", "time", r"(?:last )?shut ?down(?: time)?"),
              ("product_name", "text", r"product name|operating system|os name|windows (?:version|edition)|version of windows"),
              ("current_build", "text", r"(?:current )?build(?: number)?"), ("display_version", "text", r"display version|feature update"),
              ("registered_owner", "text", r"registered owner|\bowner\b"), ("install_date", "time", r"install(?:ation)? (?:date|time)|(?:was )?installed(?: on| at)?"),
              ("domain", "text", r"\bdomain\b"), ("edition", "text", r"edition id"))
_SVC_WORDS = (("image_path", "path", r"image ?path|binary(?: path)?|executable|command|what does .{0,30} (?:run|execute|launch)|\bpath\b"),
              ("display_name", "text", r"display ?name"), ("start", "regint", r"start (?:type|mode|value)|\bstart\b"),
              ("account", "text", r"account|run as|runs as|object ?name|which user"), ("dll", "path", r"service ?dll|\bdll\b"),
              ("description", "text", r"description"))


def _resolve_reg(view, cand: str):
    """(keys, value name or None, the path as the question spells it) for a path a question
    spells out; ([], None, '') when it names nothing in the file."""
    cand = cand.strip().rstrip(" .,;:)")
    while cand:
        keys = view.find(cand)
        if keys:
            return keys, None, cand
        if "\\" in cand:
            parent, leaf = cand.rsplit("\\", 1)
            pk = view.find(parent)
            if pk and leaf and any(n.lower() == leaf.lower() for k in pk for n in k.values()):
                return pk, leaf, cand
        if " " not in cand:
            break
        cand = cand.rsplit(" ", 1)[0].rstrip(" .,;:)")
    return [], None, ""


_USER_ROOTS = ("hkcu", "hkey_current_user", "hku", "hkey_users")
_MACHINE_ROOTS = ("hklm", "hkey_local_machine")


def _root_family(path: str):
    head = str(path).strip().strip("[]").replace("/", "\\").split("\\", 1)[0].lower().rstrip(":")
    return "user" if head in _USER_ROOTS else "machine" if head in _MACHINE_ROOTS else None


def _of_root(view, keys, cand):
    """(keys, sure) for the root a question's path names: a HKCU path is not answered from a
    machine hive (nor HKLM from a user's), and a hive whose kind is not known proves nothing."""
    fam = _root_family(cand)
    if fam is None or not keys:
        return keys, True
    if isinstance(view, Hive):
        kind = view.kind
        mine = "user" if kind in ("NTUSER", "USRCLASS") else "machine" if kind in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "AMCACHE") else None
        if mine is None:
            return keys, False
        return (keys, True) if mine == fam else ([], False)
    return [k for k in keys if _root_family(k.path) in (None, fam)], True


def _whole(key) -> bool:
    """A hive key whose value and subkey lists were read in full (a .reg key always is)."""
    c = getattr(key, "_c", None)
    if c is None:
        return True
    try:
        return _u32(c, 0x24) == len(key.values()) and _u32(c, 0x14) == len(key.subkeys())
    except (struct.error, IndexError):
        return False


def _reg_value_hit(keys, name, tag, proven, explains=()):
    found = [v for k in keys for n, v in k.values().items() if n.lower() == name.lower()]
    if not found or any(f.raw != found[0].raw or f.type != found[0].type for f in found):
        return []
    v = found[0]
    d = v.data
    vtype = "regint" if isinstance(d, int) else "list" if isinstance(d, list) else "bytes" if isinstance(d, bytes) else \
        ("path" if re.search(r"^\"?(?:[A-Za-z]:\\|%|\\\\)", d) and " " not in d.strip('"') else "text")
    return [Hit(f"{vtype}/registry.{tag}", vtype, d, proven, list(explains) + [name], (r"value|data|under|below|beneath|key",))]


def _memo(view, fn):
    """fn(view), computed once per file: a set asks many questions of one hive."""
    cache = view.__dict__.setdefault("_memo", {})
    if fn.__name__ not in cache:
        cache[fn.__name__] = fn(view)
    return cache[fn.__name__]


def _q_registry(q, text, low, targets) -> list:
    hits = []
    for a in [t for t in targets if t.kind in REG_KINDS]:
        view = a.view
        got = False
        for m in _REG_PATH.finditer(text):
            keys, vname, spelled = _resolve_reg(view, m.group(1))
            found = bool(keys)
            keys, rooted = _of_root(view, keys, spelled)
            if not keys:
                got = got or found      # the path is another root's: this file is not asked, by the path or by its words
                continue
            got = True
            said = [spelled, a.file]
            rest = text[:m.start()] + " " + text[m.end():]
            tag = re.sub(r"[^a-z0-9]+", "_", keys[0].path.lower())[-60:]
            if vname is None:
                names = sorted({n for k in keys for n in k.values() if n})
                quoted = [s for s in re.findall(r"[\"'`\u201c]([^\"'`\u201d]{1,80})[\"'`\u201d]", rest)]
                named = [n for n in names if any(n.lower() == s.lower() for s in quoted)] or [n for n in names if _word_in(n, rest)]
                named = [n for n in named if not any(n != o and n.lower() in o.lower() for o in named)]
                if len(named) == 1:
                    vname = named[0]
            clean = not _reg_demote(a, keys[0].path, None)      # a dirty hive's unrecovered or changed key is never plain
            if re.search(r"how many (?:values|entries)|number of (?:values|entries)|value count", low) and len(keys) == 1:
                hits.append(Hit(f"int/registry.{tag}.value_count", "int", len(keys[0].values()), rooted and _whole(keys[0]) and clean, said,
                                (r"how many (?:values|entries)|number of (?:values|entries)|value count|under|below|beneath",)))
            elif re.search(r"how many (?:sub ?keys|keys)|number of (?:sub ?keys|keys)|subkey count", low) and len(keys) == 1:
                hits.append(Hit(f"int/registry.{tag}.subkey_count", "int", len(keys[0].subkeys()), rooted and _whole(keys[0]) and clean, said,
                                (r"how many (?:sub ?keys|keys)|number of (?:sub ?keys|keys)|subkey count|under|below|beneath",)))
            elif vname is None and re.search(r"last (?:write|written|modif\w+)|write time|(?:key|last) timestamp", low) and len(keys) == 1 and keys[0].ts:
                hits.append(Hit(f"time/registry.{tag}.last_write", "time", keys[0].ts, rooted and clean, said,
                                (r"last (?:write|written|modified|modification)|write time|(?:key|last) timestamp|time",)))
            elif vname is not None:
                if re.search(r"\b(?:value|data|registry) type\b|what type", low):
                    types = {v.type_name for k in keys for n, v in k.values().items() if n.lower() == vname.lower()}
                    if len(types) == 1:
                        t = next(iter(types))
                        hits.append(Hit(f"label/registry.value_type.{t.lower()}", "label", [t, t.lower(), t[4:].lower(), t[4:]], False))
                else:
                    hits += _reg_value_hit(keys, vname, f"{tag}.{vname.lower()}", rooted and not _reg_demote(a, keys[0].path, vname), said)
            elif len(keys) == 1 and len(keys[0].values()) == 1:
                (n, v), = keys[0].values().items()
                if re.search(r"value name|name of the value|what is the name|which value", low):
                    hits.append(Hit(f"text/registry.{tag}.value_name", "text", n, False))
                elif re.search(r"\b(?:value|data|command|executable|program|binary|path|run|launch\w*|execut\w*|point\w*)\b", low):
                    hits += _reg_value_hit(keys, n, f"{tag}.only_value", False)
        if got:
            continue
        info = _memo(view, system_info)
        best = [(len(m.group(0)), f, vt) for f, vt, rx in _SYS_WORDS for m in [re.search(rx, low)] if m and f in info]
        if best:
            best.sort(reverse=True)
            if len(best) == 1 or best[0][0] != best[1][0]:
                hits.append(Hit(f"{best[0][2]}/registry.system.{best[0][1]}", best[0][2], info[best[0][1]], False))
                continue
        hits += _q_registry_lists(view, text, low)
    return hits


def _q_registry_lists(view, text, low) -> list:
    hits = []
    if "service" in low:
        named = [s for s in _memo(view, services) if _word_in(s["name"], text)]
        if len(named) == 1:
            best = [(len(m.group(0)), f, vt) for f, vt, rx in _SVC_WORDS for m in [re.search(rx, low)] if m and named[0].get(f) not in (None, "")]
            if best:
                best.sort(reverse=True)
                if len(best) == 1 or best[0][0] != best[1][0]:
                    return [Hit(f"{best[0][2]}/registry.service.{best[0][1]}", best[0][2], named[0][best[0][1]], False)]
    ua = [u for u in _memo(view, userassist) if _word_in(basename(u["name"]), text) or _word_in(basename(u["name"]).rsplit(".", 1)[0], text)]
    if len(ua) == 1 and ("userassist" in low or re.search(r"\b(?:run|ran|executed|launched|opened|started|used)\b", low)):
        u = ua[0]
        if re.search(r"how many times|run count|execution count|number of (?:times|runs|executions)", low):
            return [Hit("int/registry.userassist.run_count", "int", u["run_count"], False)]
        if re.search(r"focus (?:time|duration)|how long", low) and u["focus_ms"] is not None:
            return [Hit("int/registry.userassist.focus_ms", "int", u["focus_ms"], False)]
        if re.search(r"\bwhen\b|\blast\b|\btime\b", low) and u["last_run"]:
            return [Hit("time/registry.userassist.last_run", "time", u["last_run"], False)]
    if re.search(r"shimcache|appcompatcache", low):
        sc = _memo(view, shimcache)
        if re.search(r"how many (?:entries|records)|number of (?:entries|records)", low) and sc:
            return [Hit("int/registry.shimcache.count", "int", len(sc), False)]
        named = [s for s in sc if _word_in(basename(s["path"]), text)]
        if len(named) == 1:
            if re.search(r"\bwhen\b|\btime\b|\bmodif", low) and named[0]["modified"]:
                return [Hit("time/registry.shimcache.modified", "time", named[0]["modified"], False)]
            if re.search(r"\bpath\b|\bwhere\b|\blocat", low):
                return [Hit("path/registry.shimcache.path", "path", named[0]["path"], False)]
    am = _memo(view, amcache)
    if am and ("amcache" in low or view.kind == "AMCACHE"):
        named = [r for r in am if _word_in(str(r["name"] or ""), text) or _word_in(basename(str(r["path"] or "")), text)]
        if len(named) == 1:
            r = named[0]
            if re.search(r"sha-?1|\bhash\b", low) and r["sha1"]:
                return [Hit("digest/registry.amcache.sha1", "digest", r["sha1"], False)]
            if re.search(r"\bpath\b|\bwhere\b|\blocat", low) and r["path"]:
                return [Hit("path/registry.amcache.path", "path", r["path"], False)]
            if re.search(r"publisher|vendor|signed by", low) and r["publisher"]:
                return [Hit("text/registry.amcache.publisher", "text", r["publisher"], False)]
    if re.search(r"run dialog|runmru|win ?\+ ?r\b|run box", low):
        mru = _memo(view, run_mru)
        if len(mru) == 1 or (mru and re.search(r"\b(?:last|latest|most recent(?:ly)?)\b", low)):
            return [Hit("text/registry.run_mru.latest", "text", mru[0], False)]
        return []
    if re.search(r"\bdebugger\b|image file execution|\bifeo\b", low):
        dbg = _memo(view, ifeo)
        named = [r for r in dbg if _word_in(r["target"], text)] or dbg
        if len(named) == 1:
            if re.search(r"which (?:program|executable|binary|process) (?:is|was) (?:targeted|hijacked|affected)|target(?:ed)? (?:program|executable|binary)", low):
                return [Hit("text/registry.ifeo.target", "text", named[0]["target"], False)]
            return [Hit("text/registry.ifeo.debugger", "text", named[0]["command"], False)]
        return []
    if re.search(r"\brun ?(?:once ?)?keys?\b|\bautorun|\bauto-?start|\bstart ?up (?:entry|program|item)", low):
        rk = _memo(view, run_keys)
        if len(rk) == 1:
            if re.search(r"value name|name of the (?:value|entry|run key)|what is (?:it|the entry) (?:called|named)|entry name", low):
                return [Hit("text/registry.run_key.name", "text", rk[0]["name"], False)]
            if re.search(r"\b(?:command|executable|program|binary|path|data|value|launch\w*|run|runs|execut\w*|start\w*|point\w*)\b", low):
                return [Hit("text/registry.run_key.command", "text", rk[0]["command"], False)]
    return hits


# ---- persistence ---------------------------------------------------------------------------------------------------------

def _q_persistence(q, low, arts) -> list:
    if not re.search(r"persist|autorun|auto-?start|surviv\w* (?:a )?reboot|foothold|maintain\w* access", low):
        return []
    found, seen = [], set()
    for p in persistence(arts):
        k = (p["mechanism"], str(p["name"]).lower(), str(p["command"]).lower())
        if k not in seen:
            seen.add(k)
            found.append(p)
    said = [m for m, (_, spellings) in MECHANISMS.items() if any(sp.replace("_", " ") in low for sp in spellings if len(sp) > 5)]
    if said and any(p["mechanism"] in said for p in found):
        found = [p for p in found if p["mechanism"] in said]
    if len(found) != 1:
        flagged = [p for p in found if p["why"]]
        if len(flagged) != 1:
            return []
        found = flagged
    p = found[0]
    mech = p["mechanism"]
    kind = str(_fmt(q).get("kind") or "")
    if kind == "mitre_attack_id" or re.search(r"att&ck|mitre|technique id|\bt\d{4}\b", low):
        return [Hit(f"attack/persistence.{mech}", "label", [p["technique"], p["technique"].split(".")[0]], False)]
    if re.search(r"mechanism|method|technique|what (?:type|kind)|how (?:did|does|is|was)", low):
        return [Hit(f"label/persistence.mechanism.{mech}", "label", list(MECHANISMS[mech][1]), False)]
    if re.search(r"(?:value|task|service|key|entry|subscription|account|user) ?name|name of the (?:value|task|service|key|entry|subscription|account|user|persistence)|called\b|named\b", low) and p["name"]:
        return [Hit(f"text/persistence.{mech}.name", "text", p["name"], False)]
    if re.search(r"registry (?:key|path)|which key|where (?:is|was)|location", low) and p["where"]:
        return [Hit(f"text/persistence.{mech}.where", "text", p["where"], False)]
    if re.search(r"\b(?:command|executable|binary|program|payload|path|file|script|launch\w*|run|runs|execut\w*|start\w*)\b", low) and p["command"]:
        return [Hit(f"path/persistence.{mech}.command", "path" if " " not in str(p["command"]).strip('"') else "text", p["command"], False)]
    if re.search(r"\bwhen\b|\btime\b|\bdate\b", low) and p["time"]:
        return [Hit(f"time/persistence.{mech}.time", "time", p["time"], False)]
    return []


# ---- the runner contract ---------------------------------------------------------------------------------------------------

_HASH_OF_FILE = re.compile(r"\b(?:sha-?256|sha-?512|sha-?384|md5|crc-?32|ssdeep|imphash|tlsh)\b", re.I)
_DOTTED = re.compile(r"\bDetermine\s+([A-Za-z0-9_]+)\.([A-Za-z0-9_.]+?)\s+for\b")


# A question about the thing and not for it: negated, counted, ordered, or asking where and when.
_ABOUT = re.compile(r"\bnot\b|n't\b|\bhow (?:many|long)\b|\blength\b|\bsecond\b|\bthird\b|\bother\b|\bbefore\b|\bafter\b|\bwhere\b|\bwhen\b|"
                    r"\bwhich (?:file|host|event|record|log|key|value|user|account|process)\b|\bflag'?s\b|\bformat of\b|\bwhat format\b|\bflag format\s*\??$")


def _q_special(low, targets) -> list:
    """Hits built from findings(): a flag (the only flag-shaped text there is), the password of a
    `net user ... /add`, what was written to a named stream. Each is this file's reading of the
    question and of the evidence: never proven, so never plain. findings() is read only for a
    question of one of these three kinds (it reads every value of every event), and a question
    ABOUT the thing (which file holds the flag, how long it is, what is not in the stream, the
    password's hash, who wrote the stream) is none of them."""
    flag = re.search(r"\bflag\b", low) is not None
    password = re.search(r"\bpassword\b", low) and re.search(r"\b(?:user|account)\b", low) and \
        re.search(r"\bcreat\w+|\badded\b|\bnew\b|\bgiven\b|\bset\b|\bassigned\b", low) and \
        not re.search(r"\bhash\b|\blength\b|\bpolicy\b|\bwhen\b|\bexpir|\bchanged\b|\bwho\b|\bhow (?:many|long)\b|\blog(?:ged)? ?(?:in|on)\b", low)
    stream = re.search(r"alternate data stream|\bads\b|\bdata stream\b|\bhidden stream\b|\bnamed stream\b", low) and \
        re.search(r"\bcontents?\b|\bdata\b|\bhidden\b|\bstored\b|\binside\b|\bwritten\b|\bholds?\b|\bsecret\b|\bmessage\b", low) and \
        not re.search(r"\bhash\b|\bsha-?\d+\b|\bmd5\b|\bname\b|\bpath\b|\bwhen\b|\btime\b|\bhow many\b|\bprocess\b|\bprogram\b|\bimage\b|\bwho\b|"
                      r"\buser\b|\bsize\b|\blength\b|\bwhich (?:file|host|event|record)\b", low)
    if not (flag or password or stream) or _ABOUT.search(low):
        return []
    try:
        f = findings(targets)
    except OutOfTime:
        return []
    if flag:
        vals = list(dict.fromkeys(x["flag"] for x in f["flags"]))
        return [Hit("label/flag.only", "label", vals, False)] if len(vals) == 1 else []
    if password:
        named = [p for p in f["net_user_passwords"] if _word_in(p["user"].lower(), low)]
        pw = list(dict.fromkeys(p["password"] for p in (named or f["net_user_passwords"])))
        return [Hit("text/evtx.net_user.password", "text", pw[0], False)] if len(pw) == 1 else []
    rows = f["stream_contents"]
    if len(rows) == 1:
        return [Hit("label/evtx.15.contents", "label", rows[0]["decoded"] + [rows[0]["contents"]], False)]
    return []


def _targets(q, arts) -> list:
    """The artifacts a question is about: the member its artifact names, else a file its text names, else all."""
    art = str(q.get("artifact") or "")
    member = q.get("member") or (art.split(ARROW)[-1] if ARROW in art else None)
    text = str(q.get("question") or "")
    if member:
        want = basename(str(member)).lower()
        hit = [a for a in arts if a.file.lower() == want]
        if hit:
            return hit
        inside = [a for a in arts if (ARROW + str(member) + ARROW) in (ARROW + a.name) or a.name.startswith(str(member) + ARROW)]
        return inside
    # a hive named SOFTWARE is not named by the component of a path (HKCU\\Software\\...): that path may be another hive's
    hit = [a for a in arts if _word_in(a.file, text) and
           re.search(r"(?<![\w.$\\-])" + re.escape(a.file) + r"(?![\w\\-])", text, re.I) is not None]
    return hit or arts


def answer(q, arts):
    """One question's answer from the artifacts: plain, an unsure '??' string, or None."""
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    text = " ".join(str(q.get("question") or "").split())
    low = text.lower()
    if _FOREIGN_ID.search(aid) or "ANS-" in str(_fmt(q).get("syntax") or ""):
        return None
    targets = _targets(q, arts)
    if not targets:
        return None
    id_words = re.sub(r"[-_.]+", " ", aid.lower())
    m = _DOTTED.search(text)
    if m:
        kinds = PREFIX_KINDS.get(m.group(1).lower())
        prop = m.group(2).lower().replace(".", "_")
        if not kinds:
            return None
        group = [a for a in targets if a.kind in kinds]
        if kinds == EVENT_KINDS:
            hits = _q_event_property(prop, group)
        elif kinds == REG_KINDS:
            hits = []
            for a in group:
                info = system_info(a.view)
                if prop in info:
                    hits.append(Hit(f"text/registry.system.{prop}", "time" if isinstance(info[prop], Stamp) else "text",
                                    info[prop], not getattr(a, "dirty", False)))      # a dirty hive's system info is unsure
        else:
            hits = _q_fields(text, prop.replace("_", " "), "", group, exact=prop, kinds=set(kinds))
    else:
        if _HASH_OF_FILE.search(text):
            return None                 # the hash of a file is solvers/common/triage.py's to prove
        named = _kinds_named(low, targets)
        allow = lambda kinds: not named or bool(named & set(kinds))       # noqa: E731
        hits = _q_special(low, targets) or _q_persistence(q, low, targets)
        if not hits:
            if allow(EVENT_KINDS):
                hits += _q_events(q, text, low, aid, targets)
            if allow(REG_KINDS):
                hits += _q_registry(q, text, low, targets)
            if allow(("jumplist",)):
                hits += _q_jumplist(q, text, low, targets)
            field_kinds = {k for k in FIELDS if allow((k,))}
            if field_kinds:
                hits += _q_fields(text, low, id_words, targets, kinds=field_kinds, named=named, alone=len(arts) == 1)
    if not hits:
        return None
    first = hits[0]
    same = lambda h: type(h.value) is type(first.value) and h.value == first.value and h.vtype == first.vtype     # noqa: E731
    if not all(same(h) for h in hits):
        return None
    lead = next((h for h in hits if h.proven), first)
    proven = lead.proven
    if proven and not m and _unexplained(text, lead):
        proven = False                  # a word nothing accounts for: the question may ask for something else
    return decide(q, lead.key, lead.vtype, lead.value, proven, re.sub(r"[^a-z0-9_.-]+", "_", aid.lower()))


def _timed(ctx) -> bool:
    attempt = (ctx or {}).get("attempt") if isinstance(ctx, dict) else None
    mode = str((attempt or {}).get("mode") or "") if isinstance(attempt, dict) else ""
    return mode in ("time_trial", "mastery") or bool(isinstance(attempt, dict) and attempt.get("deadline") and mode != "single_solve")


def _deadline(ctx):
    return time.monotonic() + (EVTX_TIMED if _timed(ctx) else EVTX_UNTIMED)


def solve_set(questions, files, ctx) -> dict:
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if not any(sniff(n, d) for n, d in _unique(files or {})):
        return out                      # nothing here is a Windows artifact: nothing is parsed, nothing answered
    stop = time.monotonic() + SET_TIMED if _timed(ctx) else None
    try:
        arts = artifacts(files, _deadline(ctx), stop)
    except Exception:                   # OutOfTime too: a part of the delivery answers nothing
        return out
    if not arts:
        return out
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    _FINDINGS.clear()
    _FIND_STOP[0] = stop
    try:
        for q in questions:
            qid = q.get("qid") or q.get("id")
            if stop is not None and time.monotonic() > stop:
                break                       # the rest stay None: the runner submits what is ready
            try:
                out[qid] = answer(q, arts)
            except Exception:               # a fact that cannot be read is no answer
                out[qid] = None
            if partial is not None and out[qid] is not None:
                partial[qid] = out[qid]
    finally:
        _FIND_STOP[0] = None
        _FINDINGS.clear()
    return out


# ---- the command ---------------------------------------------------------------------------------------------------------------

def _load(paths) -> dict:
    """{name: bytes} of the paths; a zip's members are added under '<zip> -> <member>' (stdlib zipfile, one level)."""
    import zipfile
    files = {}
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for sub in sorted(x for x in path.rglob("*") if x.is_file()):
                files[str(sub.relative_to(path))] = sub.read_bytes()
            continue
        data = path.read_bytes()
        files[path.name] = data
        if data[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist()[:2000]:
                        if not info.is_dir() and info.file_size <= 512 * 1024 * 1024 and not info.flag_bits & 1:
                            files[f"{path.name}{ARROW}{info.filename}"] = z.read(info)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                pass
    return files


def main(argv) -> int:
    flags = {a for a in argv if a.startswith("--") and a != "--ask"}
    ask = None
    if "--ask" in argv:
        i = argv.index("--ask")
        ask = argv[i + 1] if i + 1 < len(argv) else None
        argv = argv[:i] + argv[i + 2:]
    paths = [a for a in argv if not a.startswith("--")]
    if not paths or flags - {"--json", "--persistence"}:
        print("usage: windows.py [--json] [--persistence] [--ask 'question'] <file or folder>...", file=sys.stderr)
        return 2
    try:
        files = _load(paths)
    except OSError as e:
        print(f"windows.py: {e}", file=sys.stderr)
        return 1
    if ask is not None:
        got = solve_set([{"id": "ask", "qid": "ask", "answer_id": "ask", "question": ask}], files, {})["ask"]
        print(got if got is not None else "None (no proven fact for that question)")
        return 0
    t = triage(files)
    if "--persistence" in flags:
        t = {"artifacts": [], "persistence": t["persistence"], "not_read": []}
    print(json.dumps(t, indent=1, ensure_ascii=False) if "--json" in flags else render(t))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
