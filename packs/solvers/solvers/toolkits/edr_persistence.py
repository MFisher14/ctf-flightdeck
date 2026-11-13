#!/usr/bin/env python3
"""Toolkit `edr_persistence`: exported endpoint telemetry and a persistence table with ATT&CK ids.

  .venv/bin/python solvers/toolkits/edr_persistence.py <file|dir|zip>...        triage of the file(s)
  .venv/bin/python solvers/toolkits/edr_persistence.py --json <file>...         the same as JSON

Offline, plain Python, standard library only on the answering path (the Script lane's PowerShell
reader is loaded by path for `-EncodedCommand`). Binary EVTX is not read here (backlog row 86).

What it reads
  events       Sysmon, Security, System, PowerShell and Defender events exported as JSON (one
               document, a list, JSON lines; winlogbeat, the raw Event/System/EventData shape,
               Get-WinEvent | ConvertTo-Json, EvtxECmd), as XML (wevtutil, with or without a root)
               and as CSV; EDR-style process records (ECS `process.*`, nested `children`).
               Every record becomes {time_utc, channel, event_id, host, fields, provider, source}.
  queries      by event id (Security 4624/4625/4648/4672/4688/4697/4698/4720/4732/1102, System
               7045, Sysmon 1/3/7/8/10/11/12/13/15/22/23, PowerShell 4103/4104, Defender
               1116/1117): select(), count(), brute_force(), script_blocks(), processes(), tree()
  PowerShell   decode_command_line(): `-EncodedCommand` (UTF-16LE base64) and the layers under it
               (base64, gzip, deflate, XOR) through solvers/script-analysis/powershell.py
  persistence  persistence(files): rows {mechanism, location, name, command, author, trigger} from
               a `.reg` text export, an Autoruns CSV, a Task Scheduler XML, service, task, registry
               and WMI events, WMI subscriptions (MOF/text, or carved from OBJECTS.DATA), a Startup
               `.lnk`, crontabs, systemd units and launchd plists
  ATT&CK       MECHANISMS: mechanism -> technique, with the spellings offered for its name

solve_set (the runner contract) never guesses (AGENTS.md, "Uncertain answers"):
  plain    a field read from the bytes, under exactly-one: the question's events or rows, narrowed
           by the event id, the file and every value the question names, hold ONE distinct value
           (parent image, command line, a count of an event id, a new service's name, a created
           user, a key path or value name of a .reg export, a task's command)
  unsure   labels.pick('edr_persistence.<field>/<shape>', ...): the mechanism's name, its ATT&CK
           technique, a trigger's name, a time whose format the question does not fix, a task's
           name (leaf or URI), a key read from a Sysmon TargetObject, anything carved
  None     everything else: two candidates, a question it does not understand, a file it lacks

signals(questions, files) -> 0..1 says how much a delivery and its questions look like this
category; it is cheap (the first 64 KiB of each file).
"""
import base64
import binascii
import csv
import hashlib
import html
import importlib.util
import io
import json
import plistlib
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

KEY = "edr_persistence"
HERE = Path(__file__).resolve().parent
SOLVERS = HERE.parent
if str(SOLVERS / "common") not in sys.path:
    sys.path.insert(0, str(SOLVERS / "common"))
import labels  # noqa: E402

# labels.py knows the five lanes of Days 1 to 8. A toolkit's keys need a lane of their own, or
# labels.pick raises and labels.parse (tools/grade.py) reads the unsure string as nothing to probe.
# Registered here, in the process that loaded this file; setdefault, so an entry the integrator
# writes into labels.py wins.
labels.LANE_DIRS.setdefault(KEY, "toolkits/seeds/" + KEY)

ARROW = " -> "
MAX_FILE = 48 * 1024 * 1024     # bytes of one file parsed
MAX_EVENTS = 250000
MAX_LAYERS = 5

# ---- text and time ---------------------------------------------------------------------------------


def text_of(data: bytes):
    """The text of an export (UTF-16 with or without a mark, UTF-8), or None for binary."""
    if not data:
        return ""
    data = data[:MAX_FILE]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    head = data[:4096]
    if len(head) >= 8 and head[1::2].count(0) > len(head) * 0.4 and head[0::2].count(0) < len(head) * 0.05:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    if b"\x00" in head:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


_ISO = re.compile(r"^\s*(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d{1,9}))?)?\s*"
                  r"(Z|UTC|GMT|[+-]\d\d:?\d\d)?\s*$", re.I)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_time(value):
    """(aware UTC datetime or None, naive) of a recorded time. naive: the text carried no zone and
    is read as UTC (Sysmon's UtcTime is; anything else is the exporter's choice). A US or European
    date with slashes is not read: day and month cannot be told apart."""
    if isinstance(value, dict):
        attrs = value.get("#attributes") if isinstance(value.get("#attributes"), dict) else value
        value = attrs.get("SystemTime") or attrs.get("@SystemTime") or value.get("#text")
    if value is None or isinstance(value, bool):
        return None, False
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{10,19}(\.\d+)?", value.strip())):
        n = float(value)
        try:
            if n >= 1e17:                       # FILETIME, 100 ns since 1601
                return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n / 10), False
            if n >= 1e15:
                return _EPOCH + timedelta(microseconds=n), False
            if n >= 1e12:
                return _EPOCH + timedelta(milliseconds=n), False
            if n >= 1e9:
                return _EPOCH + timedelta(seconds=n), False
        except OverflowError:
            pass
        return None, False
    s = str(value)
    m = re.search(r"/Date\((-?\d+)\)/", s)
    if m:
        return _EPOCH + timedelta(milliseconds=int(m.group(1))), False
    m = _ISO.match(s)
    if not m:
        return None, False
    y, mo, d, h, mi, sec, frac, zone = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0),
                      int(((frac or "") + "000000")[:6]), tzinfo=timezone.utc)
    except ValueError:
        return None, False
    if zone and zone[0] in "+-":
        z = zone.replace(":", "")
        off = timedelta(hours=int(z[1:3]), minutes=int(z[3:5]))
        dt = dt - off if zone[0] == "+" else dt + off
    return dt, not zone


def iso(dt, frac=True) -> str:
    out = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if frac and dt.microsecond:
        out += (".%06d" % dt.microsecond).rstrip("0")
    return out + "Z"


# ---- events ----------------------------------------------------------------------------------------

EVENT_NAMES = {
    ("security", 4624): "logon success", ("security", 4625): "logon failure",
    ("security", 4648): "logon with explicit credentials", ("security", 4672): "special privileges assigned",
    ("security", 4688): "process creation", ("security", 4697): "service installed",
    ("security", 4698): "scheduled task created", ("security", 4720): "user account created",
    ("security", 4732): "member added to a local group", ("security", 1102): "audit log cleared",
    ("system", 7045): "service installed", ("system", 104): "log cleared",
    ("sysmon", 1): "process create", ("sysmon", 3): "network connection", ("sysmon", 7): "image loaded",
    ("sysmon", 8): "CreateRemoteThread", ("sysmon", 10): "process access", ("sysmon", 11): "file create",
    ("sysmon", 12): "registry object create/delete", ("sysmon", 13): "registry value set",
    ("sysmon", 15): "file stream created", ("sysmon", 19): "WMI filter", ("sysmon", 20): "WMI consumer",
    ("sysmon", 21): "WMI binding", ("sysmon", 22): "DNS query", ("sysmon", 23): "file delete",
    ("powershell", 4103): "module logging", ("powershell", 4104): "script block",
    ("defender", 1116): "malware detected", ("defender", 1117): "malware action taken",
}
DEFAULT_CHANNEL = {eid: ch for (ch, eid) in EVENT_NAMES}
DEFAULT_CHANNEL.update({4728: "security", 4756: "security", 4634: "security", 4776: "security", 4768: "security",
                        4769: "security", 4722: "security", 4724: "security", 4726: "security", 4699: "security",
                        4700: "security", 4702: "security", 4663: "security", 4657: "security", 5140: "security",
                        5145: "security", 5156: "security", 7036: "system", 7040: "system"})

_ID_KEYS = ("EventID", "EventId", "event_id", "eventid", "Id", "id", "EventCode", "event_code", "EventIdentifier")
_TIME_KEYS = ("TimeCreated", "@timestamp", "UtcTime", "timestamp", "time", "TimeGenerated", "SystemTime", "time_utc",
              "EventTime", "_time", "Timestamp", "TimeCreatedUtc", "time_created")
_CHANNEL_KEYS = ("Channel", "LogName", "log_name", "channel", "Log", "logname")
_HOST_KEYS = ("Computer", "ComputerName", "MachineName", "computer_name", "hostname", "Hostname", "host", "computer")
_PROVIDER_KEYS = ("ProviderName", "Provider", "provider_name", "SourceName", "provider", "Source")
_META = set(_ID_KEYS + _TIME_KEYS[:2] + _TIME_KEYS[3:] + _CHANNEL_KEYS + _HOST_KEYS + _PROVIDER_KEYS)


def _norm(name) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return str(v)


def _flat(d: dict, out=None, depth=0) -> dict:
    """Scalar leaves of a nested mapping under their own names (first seen wins) ."""
    out = {} if out is None else out
    for k, v in d.items():
        if isinstance(v, dict) and depth < 4:
            if "#text" in v and not isinstance(v["#text"], (dict, list)):
                out.setdefault(str(k), _s(v["#text"]))
            else:
                _flat(v, out, depth + 1)
        else:
            out.setdefault(str(k), _s(v))
    return out


def _first(d, *keys):
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return None


def _event(time_value, channel, event_id, host, fields, provider="", source="") -> dict:
    dt, naive = parse_time(time_value)
    try:
        eid = int(str(event_id).strip()) if event_id not in (None, "") else None
    except ValueError:
        eid = None
    fields = {str(k): _s(v) for k, v in fields.items()}
    if dt is None and fields.get("UtcTime"):
        dt, naive = parse_time(fields["UtcTime"])
        time_value = fields["UtcTime"]
    return {"time_utc": iso(dt) if dt else None, "channel": _s(channel), "event_id": eid, "host": _s(host),
            "fields": fields, "provider": _s(provider), "source": source, "time_raw": _s(time_value) if not
            isinstance(time_value, dict) else _s(_first(time_value.get("#attributes", time_value), "SystemTime", "@SystemTime")),
            "naive": naive, "_dt": dt, "_low": {_norm(k): v for k, v in fields.items()}}


def fget(e: dict, *names) -> str:
    """A field of an event by any of its names, whatever the exporter's spelling (TargetUserName,
    target_user_name, 'Target User Name'); '' when absent."""
    low = e["_low"]
    for n in names:
        v = low.get(_norm(n))
        if v not in (None, ""):
            return v
    return ""


def chan(e: dict) -> str:
    """The short channel of an event: sysmon, security, system, powershell, defender, taskscheduler,
    wmi, edr, the channel's own lowercase name, or '' when the export does not say."""
    c = (e["channel"] + " " + e["provider"]).lower()
    if "sysmon" in c:
        return "sysmon"
    if "powershell" in c:
        return "powershell"
    if "windows defender" in c or "defender" in c:
        return "defender"
    if "taskscheduler" in c:
        return "taskscheduler"
    if "wmi-activity" in c:
        return "wmi"
    ch = e["channel"].strip().lower()
    if ch == "security" or "security-auditing" in c or "eventlog" in e["provider"].lower() and e["event_id"] == 1102:
        return "security"
    if ch == "system" or "service control manager" in c:
        return "system"
    return ch


def _kv_message(message: str) -> dict:
    """'Name: value' lines of a rendered message (Get-WinEvent's Message, a CSV's Message column)."""
    out = {}
    for line in str(message).splitlines():
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 _]{1,40}?)\s*:\s?(.*)$", line)
        if m and m.group(2).strip():
            out.setdefault(m.group(1).strip().replace(" ", ""), m.group(2).strip())
    return out


def _event_data(ed) -> dict:
    """EventData in any of its JSON spellings: a mapping, or Data: [{@Name, #text}, ...]."""
    out = {}
    if not isinstance(ed, dict):
        return out
    data = ed.get("Data")
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                attrs = item.get("#attributes") if isinstance(item.get("#attributes"), dict) else item
                name = attrs.get("Name") or attrs.get("@Name") or f"Data{i}"
                out.setdefault(str(name), _s(item.get("#text", item.get("Value", ""))))
            else:
                out.setdefault(f"Data{i}", _s(item))
    for k, v in ed.items():
        if k in ("Data", "#attributes") and isinstance(v, (list, dict)):
            continue
        if isinstance(v, dict):
            _flat({k: v}, out)
        else:
            out.setdefault(str(k), _s(v))
    return out


def _hash_text(h) -> str:
    if isinstance(h, dict):
        return ",".join(f"{str(k).upper()}={v}" for k, v in h.items() if isinstance(v, str) and v)
    return _s(h)


def _edr(o: dict, source: str, parent=None, out=None, depth=0) -> list:
    """An EDR-style process record (ECS process.*, a flat record, nested children) as events of
    channel 'edr' with Sysmon's field names."""
    out = [] if out is None else out
    p = o.get("process") if isinstance(o.get("process"), dict) else o
    image = _first(p, "executable", "image", "image_path", "path", "Image", "exe", "ImagePath", "process_path")
    name = _first(p, "name", "process_name", "ProcessName")
    cmd = _first(p, "command_line", "cmdline", "commandline", "CommandLine", "cmd", "args")
    if isinstance(cmd, list):
        cmd = " ".join(str(x) for x in cmd)
    if not (image or name or cmd) or depth > 40:
        return out
    par = _first(p, "parent", "parent_process") or _first(o, "parent", "parent_process")
    par = par if isinstance(par, dict) else {}
    user = _first(p, "user", "username", "User") or _first(o, "user", "username", "User")
    if isinstance(user, dict):
        dom, nm = _first(user, "domain"), _first(user, "name", "username")
        user = f"{dom}\\{nm}" if dom and nm else nm
    host = _first(o, "hostname", "host", "computer", "Computer", "device_name", "endpoint")
    if isinstance(host, dict):
        host = _first(host, "name", "hostname")
    fields = {
        "Image": image or "", "ProcessName": name or "", "CommandLine": cmd or "",
        "ProcessId": _first(p, "pid", "process_id", "ProcessId"),
        "ProcessGuid": _first(p, "entity_id", "guid", "process_guid", "ProcessGuid", "unique_id", "id"),
        "ParentImage": _first(par, "executable", "image", "image_path", "path", "Image") or _first(p, "parent_image", "parent_executable", "parent_path", "ParentImage") or (parent or {}).get("Image"),
        "ParentProcessName": _first(par, "name", "process_name") or _first(p, "parent_name", "parent_process_name"),
        "ParentCommandLine": _first(par, "command_line", "cmdline", "CommandLine") or _first(p, "parent_command_line", "parent_cmdline", "ParentCommandLine") or (parent or {}).get("CommandLine"),
        "ParentProcessId": _first(par, "pid", "process_id") or _first(p, "ppid", "parent_pid", "parent_process_id", "ParentProcessId") or (parent or {}).get("ProcessId"),
        "ParentProcessGuid": _first(par, "entity_id", "guid", "process_guid") or _first(p, "parent_guid", "parent_entity_id", "ParentProcessGuid") or (parent or {}).get("ProcessGuid"),
        "User": user,
        "Hashes": _hash_text(_first(p, "hash", "hashes", "Hashes") or {k: p[k] for k in ("sha256", "sha1", "md5") if isinstance(p.get(k), str)}),
    }
    fields = {k: v for k, v in fields.items() if v not in (None, "")}
    ev = _event(_first(o, "@timestamp", "timestamp", "time", "start_time", "start", "created", "event_time") or _first(p, "start", "start_time", "timestamp"),
                "edr", None, host or (parent or {}).get("_host"), fields, source=source)
    out.append(ev)
    kids = _first(p, "children", "child_processes") or _first(o, "children")
    if isinstance(kids, list):
        me = dict(fields, _host=ev["host"])
        for k in kids:
            if isinstance(k, dict):
                _edr(k, source, me, out, depth + 1)
    return out


def _norm_obj(o: dict, source: str) -> list:
    if isinstance(o.get("_source"), dict):
        o = o["_source"]
    w = o.get("winlog")
    if isinstance(w, dict):
        fields = {}
        if isinstance(w.get("event_data"), dict):
            _flat(w["event_data"], fields)
        if isinstance(w.get("user_data"), dict):
            _flat(w["user_data"], fields)
        host = w.get("computer_name") or _first(o.get("host") if isinstance(o.get("host"), dict) else {}, "name", "hostname")
        eid = w.get("event_id") if w.get("event_id") not in (None, "") else _first(o.get("event") if isinstance(o.get("event"), dict) else {}, "code")
        if not fields and o.get("message"):
            fields = _kv_message(o["message"])
        return [_event(o.get("@timestamp") or w.get("time_created"), w.get("channel"), eid, host, fields,
                       w.get("provider_name"), source)]
    ev = o.get("Event")
    if isinstance(ev, dict) and isinstance(ev.get("System"), dict):
        sy = ev["System"]
        eid = sy.get("EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text", eid.get("Value"))
        prov = sy.get("Provider")
        if isinstance(prov, dict):
            a = prov.get("#attributes") if isinstance(prov.get("#attributes"), dict) else prov
            prov = a.get("Name") or a.get("@Name")
        fields = _event_data(ev.get("EventData"))
        if isinstance(ev.get("UserData"), dict):
            _flat(ev["UserData"], fields)
        return [_event(sy.get("TimeCreated"), sy.get("Channel"), eid, sy.get("Computer"), fields, prov, source)]
    eid = _first(o, *_ID_KEYS)
    if isinstance(eid, dict):
        eid = _first(eid, "#text", "Value", "code")
    if isinstance(o.get("event"), dict) and eid is None:
        eid = o["event"].get("code")
    ok = eid is not None and re.fullmatch(r"\d{1,5}", str(eid).strip()) is not None
    if not ok:
        return _edr(o, source)
    fields = {}
    for k in ("EventData", "event_data", "UserData", "Data"):
        if isinstance(o.get(k), dict):
            fields.update(_event_data(o[k]))
    payload = o.get("Payload")
    if isinstance(payload, str) and payload.lstrip()[:1] == "{":
        try:
            fields.update(_event_data(json.loads(payload).get("EventData")))
        except (ValueError, AttributeError):
            pass
    for k, v in o.items():
        if k in _META or k in ("EventData", "event_data", "UserData", "Data", "Payload", "Message", "message", "Properties"):
            continue
        if isinstance(v, dict):
            _flat(v, fields)
        else:
            fields.setdefault(str(k), _s(v))
    msg = o.get("Message") or o.get("message")
    if isinstance(msg, str):
        for k, v in _kv_message(msg).items():
            if _norm(k) not in {_norm(x) for x in fields}:
                fields[k] = v
        fields.setdefault("Message", msg)
    host = _first(o, *_HOST_KEYS)
    if isinstance(host, dict):
        host = _first(host, "name", "hostname")
    return [_event(_first(o, *_TIME_KEYS), _first(o, *_CHANNEL_KEYS), eid, host, fields, _first(o, *_PROVIDER_KEYS), source)]


def _unwrap(doc) -> list:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        hits = doc.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            return hits["hits"]
        for k in ("events", "Events", "records", "Records", "hits", "data", "results", "logs", "value", "processes",
                  "telemetry", "process_tree", "items"):
            if isinstance(doc.get(k), list):
                host = _first(doc, "hostname", "host", "computer", "Computer", "device_name", "endpoint")
                if isinstance(host, str):       # the wrapper names the host once, for every record in it
                    for o in doc[k]:
                        if isinstance(o, dict) and _first(o, "hostname", "host", "computer", "Computer") is None:
                            o["hostname"] = host
                return doc[k]
        return [doc]
    return []


def _note(notes, source, why):
    """Record that a file was not read whole (a cut line, a cap, a document that does not parse).
    An answer that needs every record (a count, 'the only one') is not proven from such a file."""
    if notes is not None:
        notes.append((source, why))


def events_from_json(text: str, source: str = "", notes=None) -> list:
    objs = []
    try:
        objs = _unwrap(json.loads(text))
    except ValueError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            if line.startswith("{"):
                try:
                    objs.append(json.loads(line))
                    continue
                except ValueError:
                    pass
            _note(notes, source, "a line that is not a JSON record")
    out = []
    for o in objs:
        if not isinstance(o, dict):
            continue
        if len(out) >= MAX_EVENTS:
            _note(notes, source, "more records than MAX_EVENTS")
            break
        out.extend(_norm_obj(o, source))
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_root(text: str):
    """The parsed document, or None: a DOCTYPE or an entity declaration is refused (untrusted XML)."""
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):      # anywhere: a declaration can sit behind any padding
        return None
    try:
        return ET.fromstring(text.lstrip("\ufeff"))
    except (ET.ParseError, ValueError):
        return None


def events_from_xml(text: str, source: str = "", notes=None) -> list:
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = _xml_root("<r>" + body + "</r>")
    if root is None:
        _note(notes, source, "XML with events that does not parse")
        return []
    out = []
    for ev in root.iter():
        if _local(ev.tag) != "Event":
            continue
        sy = next((c for c in ev if _local(c.tag) == "System"), None)
        if sy is None:
            continue
        meta = {_local(c.tag): c for c in sy}
        fields, n = {}, 0
        for part in ev:
            tag = _local(part.tag)
            if tag == "EventData":
                for d in part:
                    name = d.get("Name")
                    if not name:
                        name, n = f"Data{n}", n + 1
                    fields.setdefault(name, d.text or "")
            elif tag == "UserData":
                for d in part.iter():
                    if len(d) == 0 and (d.text or "").strip():
                        fields.setdefault(_local(d.tag), d.text)
        text_of_ = lambda k: (meta[k].text or "") if k in meta else ""     # noqa: E731
        out.append(_event(meta["TimeCreated"].get("SystemTime") if "TimeCreated" in meta else None, text_of_("Channel"),
                          text_of_("EventID"), text_of_("Computer"), fields,
                          meta["Provider"].get("Name") if "Provider" in meta else "", source))
        if len(out) >= MAX_EVENTS:
            _note(notes, source, "more records than MAX_EVENTS")
            break
    return out


def _csv_rows(text: str):
    """(header, [row dict]) of a CSV, the delimiter read from the header line; None if it is none."""
    first = text.lstrip("\ufeff").split("\n", 1)[0]
    delim = max(",\t;|", key=first.count)
    if first.count(delim) < 1:
        return None
    csv.field_size_limit(MAX_FILE)
    try:
        rd = csv.DictReader(io.StringIO(text.lstrip("\ufeff")), delimiter=delim)
        rows = [r for r in rd]
    except csv.Error:
        return None
    return [h.strip() for h in (rd.fieldnames or []) if h], rows


def events_from_csv(text: str, source: str = "", notes=None) -> list:
    got = _csv_rows(text)
    if not got:
        return []
    header, rows = got
    hn = {_norm(h) for h in header}
    if not hn & {_norm(k) for k in _ID_KEYS}:
        return []
    out = []
    if len(rows) > MAX_EVENTS:
        _note(notes, source, "more records than MAX_EVENTS")
    if any(None in r or None in r.values() for r in rows):
        _note(notes, source, "a CSV row with fewer or more cells than the header")
    for r in rows[:MAX_EVENTS]:
        o = {(k or "").strip(): v for k, v in r.items() if k and v is not None}
        if _first(o, *_ID_KEYS) is None:
            continue
        got = _norm_obj(o, source)
        out.extend(e for e in got if e["event_id"] is not None)
    return out


def read_events(name: str, data: bytes, notes=None) -> list:
    """Every event of one exported file (JSON, JSON lines, XML or CSV); [] for anything else.
    notes, when given, receives (name, reason) for a file that could not be read whole."""
    if len(data) > MAX_FILE:
        _note(notes, name, "larger than MAX_FILE")
    text = text_of(data)
    if not text or not text.strip():
        return []
    head = text.lstrip("\ufeff \r\n\t")[:1]
    if head in "{[":
        got, mine = [], []
        got = events_from_json(text, name, mine)
        # a JSON file that is no event export says nothing about events
        if notes is not None and (got or re.search(r"EventID|event_id|winlog|ProcessGuid|EventData|command_line", text[:1 << 16])):
            notes.extend(mine)
        return got
    if head == "<":
        return events_from_xml(text, name, notes) if "<Event" in text[:1 << 16] else []
    return events_from_csv(text, name, notes)


def _looks_sysmon(e) -> bool:
    return bool(e["_low"].keys() & {"processguid", "utctime", "rulename", "sourceprocessguid"})


def select(events, event_id: int, channel=None) -> list:
    """Events of one id. channel: 'sysmon', 'security', ... (None: the id's usual channel, see
    DEFAULT_CHANNEL; an id with none matches every channel). An event whose export names no
    channel counts, except for Sysmon's small ids, where it must carry Sysmon's fields."""
    ch = channel or DEFAULT_CHANNEL.get(event_id)
    out = []
    for e in events:
        if e["event_id"] != event_id:
            continue
        c = chan(e)
        if ch is None or c == ch or (c == "" and (ch != "sysmon" or _looks_sysmon(e))):
            out.append(e)
    return out


def count(events, event_id: int, channel=None) -> int:
    return len(select(events, event_id, channel))


def summary(events) -> list:
    """[(channel, event id, count, name)] sorted by channel and id."""
    c = Counter((chan(e), e["event_id"]) for e in events)
    return [(ch, eid, n, EVENT_NAMES.get((ch, eid), "")) for (ch, eid), n in sorted(c.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0))]


def by_time(events) -> list:
    return sorted(events, key=lambda e: (e["_dt"] is None, e["_dt"] or _EPOCH))


def _src_ip(e) -> str:
    v = fget(e, "IpAddress", "SourceNetworkAddress", "SourceIp", "ClientAddress")
    return "" if v in ("-", "") else v


def brute_force(events) -> list:
    """Failed logons (4625) by source address: [{source, failures, users, first, last, successes:
    [4624 events from the same source at or after its first failure]}], most failures first."""
    out = {}
    for e in select(events, 4625):
        src = _src_ip(e) or fget(e, "WorkstationName") or "-"
        r = out.setdefault(src, {"source": src, "failures": 0, "users": [], "events": [], "successes": []})
        r["failures"] += 1
        r["events"].append(e)
        u = fget(e, "TargetUserName")
        if u and u not in r["users"]:
            r["users"].append(u)
    for r in out.values():
        times = [e["_dt"] for e in r["events"] if e["_dt"]]
        r["first"], r["last"] = (min(times), max(times)) if times else (None, None)
        for e in select(events, 4624):
            src = _src_ip(e) or fget(e, "WorkstationName") or "-"
            if src == r["source"] and r["first"] and e["_dt"] and e["_dt"] >= r["first"]:
                r["successes"].append(e)
    return sorted(out.values(), key=lambda r: -r["failures"])


def script_blocks(events) -> list:
    """PowerShell 4104 script blocks put back together: [{id, text, parts, total, complete, host,
    time_utc, path}] in the order first seen."""
    blocks, order = {}, []
    for e in select(events, 4104):
        bid = fget(e, "ScriptBlockId") or f"event-{len(order)}"
        if bid not in blocks:
            blocks[bid] = {"id": bid, "pieces": {}, "total": 0, "host": e["host"], "time_utc": e["time_utc"],
                           "path": fget(e, "Path"), "source": e["source"]}
            order.append(bid)
        b = blocks[bid]
        try:
            n, total = int(fget(e, "MessageNumber") or 1), int(fget(e, "MessageTotal") or 1)
        except ValueError:
            n, total = len(b["pieces"]) + 1, 0
        b["pieces"].setdefault(n, fget(e, "ScriptBlockText"))
        b["total"] = max(b["total"], total)
    out = []
    for bid in order:
        b = blocks[bid]
        b["text"] = "".join(b["pieces"][n] for n in sorted(b["pieces"]))
        b["parts"] = len(b["pieces"])
        b["complete"] = b["total"] in (0, b["parts"]) and sorted(b["pieces"]) == list(range(1, b["parts"] + 1))
        del b["pieces"]
        out.append(b)
    return out


# ---- processes --------------------------------------------------------------------------------------

def _int(v):
    try:
        return int(str(v), 0)
    except (ValueError, TypeError):
        return None


def hashes_of(text: str) -> dict:
    """{'sha256': value, ...} of Sysmon's Hashes field ('SHA256=..,MD5=..'), values as recorded."""
    out = {}
    for m in re.finditer(r"\b(SHA-?256|SHA-?1|MD5|IMPHASH)\s*[=:]\s*([0-9A-Fa-f]{32,64})\b", text or "", re.I):
        out.setdefault(m.group(1).lower().replace("-", ""), m.group(2))
    return out


def base(path: str) -> str:
    return re.split(r"[\\/]", str(path).strip().strip('"'))[-1]


def processes(events) -> list:
    """Process creations from Sysmon 1, Security 4688 and EDR records: [{time_utc, host, pid, guid,
    image, command_line, user, hashes, parent_pid, parent_guid, parent_image, parent_command_line,
    origin, source}]."""
    out = []
    for e in events:
        c, eid = chan(e), e["event_id"]
        if eid == 1 and (c == "sysmon" or (c == "" and _looks_sysmon(e))) or c == "edr":
            p = {"image": fget(e, "Image") or fget(e, "ProcessName"), "command_line": fget(e, "CommandLine"),
                 "pid": _int(fget(e, "ProcessId")), "guid": fget(e, "ProcessGuid"), "user": fget(e, "User"),
                 "hashes": hashes_of(fget(e, "Hashes")), "parent_pid": _int(fget(e, "ParentProcessId")),
                 "parent_guid": fget(e, "ParentProcessGuid"), "parent_image": fget(e, "ParentImage") or fget(e, "ParentProcessName"),
                 "parent_command_line": fget(e, "ParentCommandLine"), "origin": "edr" if c == "edr" else "sysmon:1"}
        elif eid == 4688 and c in ("security", ""):
            p = {"image": fget(e, "NewProcessName"), "command_line": fget(e, "CommandLine"),
                 "pid": _int(fget(e, "NewProcessId")), "guid": "", "user": fget(e, "SubjectUserName"), "hashes": {},
                 "parent_pid": _int(fget(e, "ProcessId")), "parent_guid": "", "parent_image": fget(e, "ParentProcessName"),
                 "parent_command_line": "", "origin": "security:4688"}
        else:
            continue
        p.update(time_utc=e["time_utc"], host=e["host"], source=e["source"], _dt=e["_dt"], _event=e)
        out.append(p)
    return out


def tree(procs) -> dict:
    """{'roots': [index], 'children': {index: [index]}, 'parent': {index: index}} over processes():
    linked by ProcessGuid, else by host and pid (the latest earlier process with that pid)."""
    by_guid = {p["guid"]: i for i, p in enumerate(procs) if p["guid"]}
    parent, children = {}, {}
    for i, p in enumerate(procs):
        j = by_guid.get(p["parent_guid"]) if p["parent_guid"] else None
        if j is None and p["parent_pid"] is not None:
            best = None
            for k, o in enumerate(procs):
                if k != i and o["pid"] == p["parent_pid"] and o["host"] == p["host"]:
                    if p["_dt"] and o["_dt"] and o["_dt"] > p["_dt"]:
                        continue
                    if best is None or (o["_dt"] or _EPOCH) >= (procs[best]["_dt"] or _EPOCH):
                        best = k
            j = best
        if j is not None and j != i:
            parent[i] = j
            children.setdefault(j, []).append(i)
    return {"roots": [i for i in range(len(procs)) if i not in parent], "children": children, "parent": parent}


def _wmi_text(v: str) -> str:
    """A Sysmon 19/20/21 value as the text it records: Sysmon writes ' "text"' (a space, then the text
    in quotes), and a JSON export may keep the event's XML escaping (&lt; &gt; &amp; &quot;)."""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    if re.search(r"&(?:lt|gt|amp|quot|apos|#\d+);", v):
        v = html.unescape(v)
    return v


def render_tree(procs, limit=200) -> list:
    t, lines, seen = tree(procs), [], set()

    def walk(i, depth):
        if i in seen or len(lines) >= limit:
            return
        seen.add(i)
        p = procs[i]
        lines.append(f"{'  ' * depth}{base(p['image']) or '?'} [{p['pid'] if p['pid'] is not None else '?'}] "
                     f"{p['time_utc'] or ''} {p['command_line'][:160]}".rstrip())
        for k in t["children"].get(i, []):
            walk(k, depth + 1)

    for r in t["roots"]:
        if procs[r]["parent_image"]:
            lines.append(f"({base(procs[r]['parent_image'])} [{procs[r]['parent_pid'] if procs[r]['parent_pid'] is not None else '?'}])")
            walk(r, 1)
        else:
            walk(r, 0)
    return lines


# ---- PowerShell: -EncodedCommand and the layers under it ---------------------------------------------

_ps_module = None
_ENC = re.compile(r"(?i)(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|"
                  r"encodedcomma|encodedcomman|encodedcommand)\s+[\"']?([A-Za-z0-9+/]{8,}={0,2})")


def ps_reader():
    """The Script lane's PowerShell reader (solvers/script-analysis/powershell.py), loaded by path;
    None when it cannot be loaded, and then nothing is decoded."""
    global _ps_module
    if _ps_module is None:
        path = SOLVERS / "script-analysis" / "powershell.py"
        try:
            spec = importlib.util.spec_from_file_location("script_lane_powershell_reader", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _ps_module = mod
        except Exception:
            _ps_module = False
    return _ps_module or None


def _plausible(t) -> bool:
    if not t or len(t) < 4:
        return False
    good = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\r\n\t")
    return good >= 0.9 * len(t) and re.search(r"[A-Za-z]{3}", t) is not None


def _inner(text: str):
    """The one text a script's own decoding yields (FromBase64String, with the gzip, deflate or
    XOR it spells out), by the Script lane's reader; None when there is none or more than one."""
    ps = ps_reader()
    if ps is None or not re.search(r"(?i)frombase64string|\[byte\[\]\]|-bxor|\[char\[\]\]|-join", text):
        return None
    found = []
    fns = [lambda b: b] + list(ps.declared_transforms(text))
    for raw in ps.encoded_candidates(text):
        for fn in fns:
            try:
                b = fn(raw)
            except Exception:
                continue
            outs = [ps.as_text(b)]
            if re.search(r"(?i)deflatestream", text):
                try:
                    outs.append(ps.as_text(zlib.decompress(b, -15)))
                except zlib.error:
                    pass
            for t in outs:
                if _plausible(t) and t.strip() and t not in found and t.strip() not in text:
                    found.append(t)
    return found[0] if len(found) == 1 else None


def decode_command_line(cmd: str) -> list:
    """The decoded layers of a PowerShell command line, outermost first: the `-EncodedCommand`
    argument (base64 of UTF-16LE), then whatever that text decodes itself. [] when nothing decodes."""
    layers = []
    ps = ps_reader()
    if ps is None or not cmd:
        return layers
    cur = None
    m = _ENC.search(cmd)
    if m and re.search(r"(?i)powershell|pwsh", cmd):
        blob = m.group(1)
        try:
            # PowerShell refuses a blob that is not padded to four, and UTF-16 has no odd length:
            # either means the recorded command line was cut, and half a command is no answer.
            raw = base64.b64decode(blob, validate=True) if len(blob) % 4 == 0 else None
            cur = ps.as_text(raw) if raw is not None and len(raw) % 2 == 0 else None
        except (binascii.Error, ValueError):
            cur = None
        if not _plausible(cur):
            cur = None
    if cur is None:
        cur = _inner(cmd)
    while cur is not None and len(layers) < MAX_LAYERS:
        layers.append(cur)
        cur = _inner(cur)
    return layers


# ---- persistence ------------------------------------------------------------------------------------

# mechanism -> (ATT&CK technique, spellings of its name offered to the judge, best first)
MECHANISMS = {
    "registry_run_key": ("T1547.001", ["registry_run_key", "run_key", "registry_run_keys", "run_keys", "registry_run",
                                       "run_registry_key", "registry_autorun", "autorun_key", "registry"]),
    "startup_folder": ("T1547.001", ["startup_folder", "startup_shortcut", "startup_lnk", "startup_item", "startup"]),
    "scheduled_task": ("T1053.005", ["scheduled_task", "schtasks", "task_scheduler", "scheduled_tasks", "task"]),
    "windows_service": ("T1543.003", ["windows_service", "service", "service_install", "new_service", "service_creation",
                                      "services"]),
    "wmi_event_subscription": ("T1546.003", ["wmi_event_subscription", "wmi_subscription", "wmi_event_consumer", "wmi_persistence",
                                             "wmi_consumer", "wmi"]),
    "ifeo_debugger": ("T1546.012", ["ifeo_debugger", "image_file_execution_options", "ifeo", "ifeo_injection", "debugger"]),
    "com_hijack": ("T1546.015", ["com_hijack", "com_hijacking", "component_object_model_hijacking", "com_object_hijack", "clsid_hijack"]),
    "cron": ("T1053.003", ["cron", "cron_job", "crontab", "cronjob"]),
    "systemd_service": ("T1543.002", ["systemd_service", "systemd_unit", "systemd"]),
    "launch_agent": ("T1543.001", ["launch_agent", "launchagent", "launchd_agent", "launchd"]),
    "launch_daemon": ("T1543.004", ["launch_daemon", "launchdaemon", "launchd_daemon", "launchd"]),
    "systemd_timer": ("T1053.006", ["systemd_timer", "timer", "systemd_timers"]),
    "winlogon_helper": ("T1547.004", ["winlogon_helper", "winlogon_helper_dll", "winlogon", "winlogon_userinit", "winlogon_shell"]),
    "appinit_dll": ("T1546.010", ["appinit_dll", "appinit_dlls", "appinit"]),
    "active_setup": ("T1547.014", ["active_setup", "active_setup_stubpath"]),
    "screensaver": ("T1546.002", ["screensaver", "screen_saver"]),
    "logon_script": ("T1037.001", ["logon_script", "logon_script_windows", "userinitmprlogonscript"]),
}
REGISTRY_MECHANISMS = ("registry_run_key", "ifeo_debugger", "com_hijack", "winlogon_helper", "appinit_dll", "active_setup",
                       "screensaver", "logon_script")
TRIGGER_NAMES = {
    "logon": ["logon", "at_logon", "on_logon", "logon_trigger", "user_logon", "at_log_on"],
    "boot": ["boot", "at_boot", "on_boot", "boot_trigger", "at_startup", "startup", "system_startup"],
    "time": ["time", "one_time", "once", "time_trigger", "at_time"],
    "calendar": ["calendar", "calendar_trigger", "scheduled", "schedule"],
    "daily": ["daily", "calendar", "schedule_by_day", "calendar_trigger"],
    "weekly": ["weekly", "calendar", "schedule_by_week", "calendar_trigger"],
    "monthly": ["monthly", "calendar", "schedule_by_month", "calendar_trigger"],
    "idle": ["idle", "on_idle", "idle_trigger"],
    "event": ["event", "on_event", "event_trigger"],
    "registration": ["registration", "on_registration", "registration_trigger", "at_creation"],
    "session_state_change": ["session_state_change", "session_state_change_trigger", "on_unlock"],
    "auto": ["auto_start", "automatic", "auto", "auto_start_service", "service_auto_start"],
    "demand": ["demand_start", "manual", "demand", "on_demand", "service_demand_start"],
    "boot_start": ["boot_start", "boot", "service_boot_start"],
    "system_start": ["system_start", "system", "service_system_start"],
    "disabled": ["disabled", "service_disabled"],
    "run_at_load": ["run_at_load", "runatload", "at_load", "on_load"],
    "keep_alive": ["keep_alive", "keepalive"],
    "start_interval": ["start_interval", "startinterval", "interval"],
}
_START = {"0": "boot_start", "1": "system_start", "2": "auto", "3": "demand", "4": "disabled",
          "boot start": "boot_start", "system start": "system_start", "auto start": "auto", "demand start": "demand",
          "disabled": "disabled"}


def row(mechanism, location=None, name=None, command=None, author=None, trigger=None, source="", origin="", **extra) -> dict:
    return {"mechanism": mechanism, "location": location or None, "name": name or None, "command": command or None,
            "author": author or None, "trigger": trigger or None, "source": source, "origin": origin,
            "technique": MECHANISMS.get(mechanism, (None,))[0], "extra": extra}


def technique_of(mechanism):
    return MECHANISMS.get(mechanism, (None,))[0]


_HIVES = (("hkey_local_machine", "hklm"), ("hkey_current_user", "hkcu"), ("hkey_users", "hku"),
          ("hkey_classes_root", "hkcr"), ("hkey_current_config", "hkcc"))


def _short_key(key: str) -> str:
    k = key.strip().strip("\\").lower()
    for long_, short in _HIVES:
        if k == long_ or k.startswith(long_ + "\\"):
            return short + k[len(long_):]
    return k


def classify_registry(key: str, value: str):
    """(mechanism, entry name) of a registry value by its key and value name, or (None, None).
    value None: classify by the key alone (a Sysmon 12 key event, an Autoruns location)."""
    k = _short_key(key)
    v = None if value is None else value.strip().lower()
    if re.search(r"\\currentversion\\(run|runonce|runonceex|runservices|runservicesonce)(\\[^\\]+)*$", k) \
            or k.endswith("\\policies\\explorer\\run"):
        return "registry_run_key", value
    if k.endswith("\\windows nt\\currentversion\\winlogon") and (v is None or v in ("userinit", "shell", "taskman", "vmapplet")):
        return "winlogon_helper", value
    m = re.search(r"\\(image file execution options|silentprocessexit)\\([^\\]+)$", k)
    if m and (v is None or v in ("debugger", "monitorprocess", "verifierdlls")):
        return "ifeo_debugger", key.strip("\\").rsplit("\\", 1)[-1]
    m = re.match(r"(hkcu|hku\\[^\\]+)\\(software\\classes|[^\\]*_classes)?\\?(wow6432node\\)?clsid\\(\{[^}]+\})\\"
                 r"(inprocserver32|localserver32|treatas|scriptleturl)$", k)
    if m:
        return "com_hijack", key.strip("\\").split("\\")[-2]
    m = re.search(r"\\(currentcontrolset|controlset\d+)\\services\\([^\\]+)(\\parameters)?$", k)
    if m and (v is None or (v == "servicedll" if m.group(3) else v == "imagepath")):
        parts = key.strip("\\").split("\\")
        return "windows_service", parts[-2] if m.group(3) else parts[-1]
    if k.endswith("\\windows nt\\currentversion\\windows") and v in ("appinit_dlls",):
        return "appinit_dll", value
    if re.search(r"\\active setup\\installed components\\[^\\]+$", k) and (v is None or v == "stubpath"):
        return "active_setup", key.strip("\\").rsplit("\\", 1)[-1]
    if k.endswith("\\control panel\\desktop") and v == "scrnsave.exe":
        return "screensaver", value
    if k.endswith("\\environment") and v == "userinitmprlogonscript":
        return "logon_script", value
    m = re.search(r"\\schedule\\taskcache\\tree\\(.+)$", k)
    if m and v is None:
        return "scheduled_task", key.strip("\\").rsplit("\\", 1)[-1]
    return None, None


_WINLOGON_DEFAULT = {"userinit": ("c:\\windows\\system32\\userinit.exe,", "userinit.exe,", "c:\\windows\\system32\\userinit.exe"),
                     "shell": ("explorer.exe",)}


def parse_reg(text: str, notes=None, source: str = "") -> list:
    """A `.reg` text export as [(key, {value name: (type, data)}, deleted)]; '@' is the default value.
    Types: sz, dword, qword, expand_sz, multi_sz (data: list), binary (hex text), delete.
    A line that is no whole key or value (a cut export) is left out and noted in `notes`."""
    out, cur = [], None
    lines, buf = [], ""
    for line in text.lstrip("\ufeff").splitlines():
        if buf:
            line = buf + line.strip()
            buf = ""
        if line.rstrip().endswith("\\") and re.search(r"=\s*hex", line):
            buf = line.rstrip()[:-1]
            continue
        lines.append(line)
    if buf:
        _note(notes, source, "a .reg hex value cut in a continuation line")
    for line in lines:
        s = line.strip()
        if not s or s.startswith(";") or re.match(r"(?i)^(windows registry editor version|regedit4)", s):
            continue
        m = re.match(r"^\[(-?)(.+)\]$", s)
        if m:
            cur = (m.group(2), {}, bool(m.group(1)))
            out.append(cur)
            continue
        m = re.match(r'^(@|"(?:[^"\\]|\\.)*")\s*=\s*(.*)$', s)
        if not m or cur is None:
            _note(notes, source, "a .reg line that is no whole key or value")
            continue
        name = "@" if m.group(1) == "@" else re.sub(r"\\(.)", r"\1", m.group(1)[1:-1])
        d = m.group(2).strip()
        if d == "-":
            val = ("delete", None)
        elif d.startswith('"'):
            mm = re.match(r'^"((?:[^"\\]|\\.)*)"\s*$', d)
            if not mm:              # no closing quote: the value was cut, and part of a value is no value
                _note(notes, source, "a .reg string value with no closing quote")
                continue
            val = ("sz", re.sub(r"\\(.)", r"\1", mm.group(1)))
        elif d.lower().startswith("dword:"):
            if not re.fullmatch(r"[0-9a-fA-F]{8}", d[6:].strip()):
                _note(notes, source, "a .reg dword that is not eight hex digits")
                continue
            val = ("dword", _int("0x" + d[6:].strip()))
        else:
            mm = re.match(r"^hex(?:\(([0-9a-fA-F]+)\))?:(.*)$", d, re.S)
            if not mm:
                _note(notes, source, "a .reg value of no known type")
                continue
            try:
                raw = bytes(int(x, 16) for x in mm.group(2).replace(" ", "").split(",") if x)
            except ValueError:
                _note(notes, source, "a .reg hex value that is not hex")
                continue
            t = int(mm.group(1), 16) if mm.group(1) else 3
            if t in (1, 2, 7):
                s16 = raw.decode("utf-16-le", "replace")
                val = (("sz", "expand_sz")[t - 1], s16.rstrip("\x00")) if t != 7 else ("multi_sz", [x for x in s16.split("\x00") if x])
            elif t == 11 and len(raw) == 8:
                val = ("qword", struct.unpack("<Q", raw)[0])
            elif t == 4 and len(raw) == 4:
                val = ("dword", struct.unpack("<I", raw)[0])
            else:
                val = ("binary", raw.hex())
        cur[1][name] = val
    return out


def _data(val) -> str:
    t, d = val
    if d is None:
        return ""
    return " ".join(d) if isinstance(d, list) else str(d)


def persistence_from_reg(text: str, source: str = "", notes=None) -> list:
    out = []
    for key, values, deleted in parse_reg(text, notes, source):
        if deleted:
            continue
        mech_key, _ = classify_registry(key, None)
        if mech_key == "scheduled_task":
            out.append(row("scheduled_task", key, key.rsplit("\\", 1)[-1], source=source, origin="reg"))
        svc = None
        for vname, val in values.items():
            if val[0] == "delete":
                continue
            mech, name = classify_registry(key, "" if vname == "@" else vname)
            data = _data(val)
            if mech is None or not data.strip():
                continue
            if mech == "windows_service":
                svc = svc or row(mech, key, name, source=source, origin="reg")
                svc["command"] = data
                continue
            r = row(mech, key, name if mech in ("ifeo_debugger", "com_hijack", "active_setup") else vname, data,
                    source=source, origin="reg", value_name=vname, value_type=val[0])
            if mech == "winlogon_helper" and data.strip().lower() in _WINLOGON_DEFAULT.get(vname.lower(), ()):
                r["extra"]["default"] = True
            out.append(r)
        if svc:
            low = {k.lower(): v for k, v in values.items()}
            svc["author"] = _data(low["objectname"]) if "objectname" in low else None
            if "start" in low:
                svc["trigger"] = _START.get(_data(low["start"]))
            if "displayname" in low:
                svc["extra"]["display_name"] = _data(low["displayname"])
            out.append(svc)
    return out


_AUTORUNS_CATEGORY = {"tasks": "scheduled_task", "scheduled tasks": "scheduled_task", "services": "windows_service",
                      "wmi": "wmi_event_subscription", "image hijacks": "ifeo_debugger", "appinit": "appinit_dll",
                      "winlogon": "winlogon_helper"}


def is_autoruns(header) -> bool:
    hn = {_norm(h) for h in header}
    return "entrylocation" in hn and bool(hn & {"launchstring", "imagepath"})


def persistence_from_autoruns(text: str, source: str = "", notes=None) -> list:
    """An Autoruns CSV (autorunsc -c, or the GUI's save): one row per entry that has a launch string
    or an image path. extra: category, image_path, enabled, signer, verified, hashes, time."""
    got = _csv_rows(text)
    if not got or not is_autoruns(got[0]):
        return []
    if any(None in r or None in r.values() for r in got[1]):
        _note(notes, source, "an Autoruns row with fewer or more cells than the header")
    out = []
    for r in got[1]:
        g = {_norm(k): (v or "").strip() for k, v in r.items() if k}
        loc, entry = g.get("entrylocation", ""), g.get("entry", "")
        launch, image = g.get("launchstring", ""), g.get("imagepath", "")
        if not (launch or image) or not entry:
            continue
        cat = g.get("category", "")
        mech = _AUTORUNS_CATEGORY.get(cat.lower())
        if mech is None:
            mech, _ = classify_registry(loc, None)
            if mech is None and re.search(r"(?i)\\start menu\\programs\\startup", loc):
                mech = "startup_folder"
            if mech is None and re.search(r"(?i)^task scheduler", loc):
                mech = "scheduled_task"
        signer = g.get("signer", "") or g.get("company", "")
        out.append(row(mech, loc, entry, launch or image, signer, None, source=source, origin="autoruns", category=cat,
                       image_path=image, enabled=g.get("enabled", ""), signer=signer, company=g.get("company", ""),
                       verified="(verified)" in signer.lower(), time=g.get("time", ""),
                       hashes={k: g[n] for k, n in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")) if g.get(n)}))
    return out


_TASK_TRIGGERS = {"LogonTrigger": "logon", "BootTrigger": "boot", "TimeTrigger": "time", "CalendarTrigger": "calendar",
                  "IdleTrigger": "idle", "EventTrigger": "event", "RegistrationTrigger": "registration",
                  "SessionStateChangeTrigger": "session_state_change"}


def parse_task_xml(text: str):
    """A Task Scheduler XML document as {uri, author, description, date, user, run_level, triggers:
    [{kind, start, interval}], actions: [{command, arguments, working_directory} or {class_id}]},
    or None when the text is no task."""
    if "<Task" not in text[:4096] and "<Task" not in text:
        return None
    root = _xml_root(re.sub(r"<\?xml[^>]*\?>", "", text, count=1))
    if root is None or _local(root.tag) != "Task":
        return None

    def find(node, *path):
        for name in path:
            node = next((c for c in node if _local(c.tag) == name), None) if node is not None else None
        return node

    def txt(node, *path):
        n = find(node, *path)
        return (n.text or "").strip() if n is not None else ""

    t = {"uri": txt(root, "RegistrationInfo", "URI"), "author": txt(root, "RegistrationInfo", "Author"),
         "description": txt(root, "RegistrationInfo", "Description"), "date": txt(root, "RegistrationInfo", "Date"),
         "user": "", "run_level": "", "triggers": [], "actions": [],
         "hidden": txt(root, "Settings", "Hidden"), "enabled": txt(root, "Settings", "Enabled")}
    pr = find(root, "Principals", "Principal")
    if pr is not None:
        t["user"] = txt(pr, "UserId") or txt(pr, "GroupId")
        t["run_level"] = txt(pr, "RunLevel")
    for tr in (find(root, "Triggers") if find(root, "Triggers") is not None else []):
        kind = _TASK_TRIGGERS.get(_local(tr.tag), _local(tr.tag))
        if kind == "calendar":
            for sub, name in (("ScheduleByDay", "daily"), ("ScheduleByWeek", "weekly"), ("ScheduleByMonth", "monthly"),
                              ("ScheduleByMonthDayOfWeek", "monthly")):
                if find(tr, sub) is not None:
                    kind = name
        t["triggers"].append({"kind": kind, "start": txt(tr, "StartBoundary"), "interval": txt(tr, "Repetition", "Interval"),
                              "user": txt(tr, "UserId")})
    for ac in (find(root, "Actions") if find(root, "Actions") is not None else []):
        if _local(ac.tag) == "Exec":
            t["actions"].append({"command": txt(ac, "Command"), "arguments": txt(ac, "Arguments"),
                                 "working_directory": txt(ac, "WorkingDirectory")})
        elif _local(ac.tag) == "ComHandler":
            t["actions"].append({"class_id": txt(ac, "ClassId"), "data": txt(ac, "Data")})
    return t


def _task_rows(t: dict, source: str, origin: str, name_hint=None) -> list:
    kinds = []
    for tr in t["triggers"]:
        if tr["kind"] not in kinds:
            kinds.append(tr["kind"])
    trigger = kinds[0] if len(kinds) == 1 else None
    uri = t["uri"] or name_hint or ""
    out = []
    for a in t["actions"] or [{}]:
        exe, args = a.get("command", ""), a.get("arguments", "")
        cmd = (exe + (" " + args if args else "")) if exe else (a.get("class_id") or "")
        out.append(row("scheduled_task", uri, uri, cmd, t["author"], trigger, source=source, origin=origin,
                       exe=exe, args=args, user=t["user"], run_level=t["run_level"], triggers=kinds,
                       start=[tr["start"] for tr in t["triggers"] if tr["start"]], description=t["description"],
                       date=t["date"], name_from="uri" if (t["uri"] or name_hint) else None))
    return out


def persistence_from_events(events) -> list:
    """Rows from service installs (System 7045, Security 4697), task creation (Security 4698),
    registry value sets (Sysmon 13), Startup-folder file creates (Sysmon 11) and WMI subscription
    events (Sysmon 19 and 20)."""
    out = []
    for e in events:
        c, eid, src = chan(e), e["event_id"], e["source"]
        org = f"{c or 'event'}:{eid}"
        if eid == 7045 and c in ("system", ""):
            out.append(row("windows_service", None, fget(e, "ServiceName"), fget(e, "ImagePath", "ServiceFileName"),
                           fget(e, "AccountName"), _START.get(fget(e, "StartType").lower()), source=src, origin=org,
                           time_utc=e["time_utc"], host=e["host"], service_type=fget(e, "ServiceType")))
        elif eid == 4697 and c in ("security", ""):
            out.append(row("windows_service", None, fget(e, "ServiceName"), fget(e, "ServiceFileName", "ImagePath"),
                           fget(e, "ServiceAccount"), _START.get(fget(e, "ServiceStartType").lower()), source=src, origin=org,
                           time_utc=e["time_utc"], host=e["host"], installed_by=fget(e, "SubjectUserName")))
        elif eid == 4698 and c in ("security", ""):
            name, content = fget(e, "TaskName"), fget(e, "TaskContent")
            if content and content.lstrip()[:4] == "&lt;":
                content = html.unescape(content)
            t = parse_task_xml(content) if content else None
            if t:
                rows_ = _task_rows(t, src, org, name_hint=name)
                for r in rows_:
                    r["name"] = r["location"] = name or r["name"]
                    r["extra"].update(time_utc=e["time_utc"], host=e["host"], created_by=fget(e, "SubjectUserName"))
                out.extend(rows_)
            elif name:
                out.append(row("scheduled_task", name, name, source=src, origin=org, time_utc=e["time_utc"], host=e["host"],
                               created_by=fget(e, "SubjectUserName"), name_from="uri"))
        elif eid == 13 and c == "sysmon":
            obj = fget(e, "TargetObject")
            if "\\" not in obj:
                continue
            key, vname = obj.rsplit("\\", 1)
            mech, name = classify_registry(key, "" if vname == "(Default)" else vname)
            details = fget(e, "Details")
            if mech and details:
                out.append(row(mech, key, name if mech in ("ifeo_debugger", "com_hijack", "active_setup", "windows_service") else vname,
                               details, fget(e, "User"), None, source=src, origin=org, time_utc=e["time_utc"], host=e["host"],
                               target_object=obj, image=fget(e, "Image"), value_name=vname))
        elif eid == 11 and c == "sysmon":
            tf = fget(e, "TargetFilename")
            if re.search(r"(?i)\\start menu\\programs\\startup\\[^\\]+$", tf):
                out.append(row("startup_folder", tf.rsplit("\\", 1)[0], base(tf), None, fget(e, "User"), None, source=src,
                               origin=org, time_utc=e["time_utc"], host=e["host"], image=fget(e, "Image"), path=tf))
        elif eid == 20 and c == "sysmon":
            out.append(row("wmi_event_subscription", _wmi_text(fget(e, "EventNamespace")), _wmi_text(fget(e, "Name")),
                           _wmi_text(fget(e, "Destination")),
                           fget(e, "User"), None, source=src, origin=org, consumer_type=fget(e, "Type"), time_utc=e["time_utc"]))
        elif eid == 19 and c == "sysmon":
            out.append(row("wmi_event_subscription", _wmi_text(fget(e, "EventNamespace")), _wmi_text(fget(e, "Name")), None, fget(e, "User"),
                           _wmi_text(fget(e, "Query")), source=src, origin=org, part="filter", time_utc=e["time_utc"]))
    # A WMI filter's query is the trigger of the consumer it is bound to; with one of each that is known.
    cons = [r for r in out if r["origin"] == "sysmon:20"]
    filt = [r for r in out if r["origin"] == "sysmon:19"]
    if len(cons) == 1 and len(filt) == 1:
        cons[0]["trigger"] = filt[0]["trigger"]
        cons[0]["extra"]["filter"] = filt[0]["name"]
    return [r for r in out if r["extra"].get("part") != "filter" or not cons]


_MOF_PROP = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:)\s*(.*?)\s*;?\s*$')


def wmi_from_text(text: str, source: str = "", notes=None) -> list:
    """WMI subscriptions written out as text: MOF (`instance of CommandLineEventConsumer { ... }`)
    or PowerShell's list output (`__CLASS : ...`, `Name : ...`). One row per consumer; the filter's
    query is its trigger when exactly one filter is bound or present."""
    if "EventConsumer" not in text and "__EventFilter" not in text:
        return []
    objs, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^\s*instance\s+of\s+(\w+)", line, re.I)
        if m:
            cur = {"__class": m.group(1)}
            objs.append(cur)
            continue
        if not line.strip() or line.strip() in ("};", "}"):
            if not line.strip() or cur is None or "__class" in cur:
                cur = None if not line.strip() or line.strip() in ("};", "}") else cur
            continue
        m = _MOF_PROP.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if re.match(r"^\s*\w+\s*=", line) and not re.fullmatch(r'"(?:[^"\\]|\\.)*"|-?\d+|(?i:true|false|null)|\{.*\}', v):
            _note(notes, source, "a MOF property whose value is no whole string, number or list")      # a cut or run-together line
            continue
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        if cur is None:
            cur = {}
            objs.append(cur)
        if k.lower() == "__class":
            cur["__class"] = v
        cur.setdefault(k.lower(), v)
    cons = [o for o in objs if "eventconsumer" in o.get("__class", "").lower()]
    filt = [o for o in objs if o.get("__class", "").lower() == "__eventfilter"]
    binds = [o for o in objs if o.get("__class", "").lower() == "__filtertoconsumerbinding"]
    out = []
    for o in cons:
        cmd = o.get("commandlinetemplate") or o.get("scripttext") or o.get("executablepath") or ""
        query = fname = None
        bound = [b for b in binds if re.search(r'Name\s*=\s*\\?"?' + re.escape(o.get("name", "\x00")) + r'\\?"?', b.get("consumer", ""))]
        if len(bound) == 1:
            fn = re.search(r'Name\s*=\s*\\?"?([^"\\]+)', bound[0].get("filter", ""))
            match = [f for f in filt if fn and f.get("name") == fn.group(1)]
            query = match[0].get("query") if len(match) == 1 else None
            fname = fn.group(1) if fn else None
        elif len(filt) == 1 and len(cons) == 1:
            query, fname = filt[0].get("query"), filt[0].get("name")
        out.append(row("wmi_event_subscription", o.get("__namespace") or None, o.get("name"), cmd, o.get("creatorsid") or None,
                       query, source=source, origin="wmi_text", consumer_type=o.get("__class"), filter=fname))
    return out


def wmi_from_objects_data(data: bytes, source: str = "") -> list:
    """WMI subscriptions carved from a repository file (OBJECTS.DATA): the binding strings name the
    consumer and the filter; the command is the string after the consumer's class name, and is
    carved (extra['carved']), so solve_set answers it only as unsure."""
    data = data[:MAX_FILE]
    strs = [(m.start(), m.group().decode("ascii", "replace")) for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    strs += [(m.start(), m.group().decode("utf-16-le", "replace")) for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]
    strs.sort()
    joined = "\n".join(s for _, s in strs)
    out, seen = [], set()
    queries = []
    for _, s in strs:
        m = re.search(r"(?i)\bselect\s+.{1,400}?\s+from\s+\S+.*", s)
        if m and m.group().strip() not in queries:
            queries.append(m.group().strip())
    for m in re.finditer(r'(\w*EventConsumer)\.Name=\\?"([^"\\]+)\\?"', joined):
        cls, name = m.group(1), m.group(2)
        if (cls, name) in seen:
            continue
        seen.add((cls, name))
        fm = re.search(r'__EventFilter\.Name=\\?"([^"\\]+)\\?"', joined)
        cmd = None
        idx = [i for i, (_, s) in enumerate(strs) if s == cls]
        cands = []
        for i in idx:
            nxt = [s for _, s in strs[i + 1:i + 8] if s not in (cls, name) and not s.startswith("__") and len(s) >= 6]
            if nxt and nxt[0] not in cands:
                cands.append(nxt[0])
        if len(cands) == 1:
            cmd = cands[0]
        out.append(row("wmi_event_subscription", None, name, cmd, None, queries[0] if len(queries) == 1 else None,
                       source=source, origin="objects_data", consumer_type=cls, filter=fm.group(1) if fm else None,
                       carved=True, queries=queries))
    return out


def parse_lnk(data: bytes):
    """A shell link's {target, arguments, working_directory, relative_path, name, icon} from its
    header, LinkInfo and StringData, or None when the bytes are no .lnk."""
    if len(data) < 76 or data[:4] != b"L\x00\x00\x00" or data[4:20] != bytes.fromhex("0114020000000000c000000000000046"):
        return None
    flags = struct.unpack_from("<I", data, 20)[0]
    off, out = 76, {"target": "", "arguments": "", "working_directory": "", "relative_path": "", "name": "", "icon": ""}
    try:
        if flags & 0x01:                                    # HasLinkTargetIDList
            off += 2 + struct.unpack_from("<H", data, off)[0]
        if flags & 0x02:                                    # HasLinkInfo
            size, hdr, lflags, _, base_off, _, suffix_off = struct.unpack_from("<7I", data, off)
            if lflags & 0x01 and base_off:
                def cstr(o):
                    end = data.index(b"\x00", off + o)
                    return data[off + o:end].decode("cp1252", "replace")
                out["target"] = cstr(base_off) + (cstr(suffix_off) if suffix_off else "")
                if hdr >= 0x24:
                    ubase = struct.unpack_from("<I", data, off + 28)[0]
                    if ubase:
                        end = off + ubase
                        while data[end:end + 2] not in (b"\x00\x00", b""):
                            end += 2
                        out["target"] = data[off + ubase:end].decode("utf-16-le", "replace")
            off += size
        for bit, key in ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_directory"), (0x20, "arguments"), (0x40, "icon")):
            if flags & bit:
                n = struct.unpack_from("<H", data, off)[0]
                off += 2
                if off + (2 * n if flags & 0x80 else n) > len(data):
                    raise ValueError("a string that runs past the end of the file")     # a cut link: no part of it
                if flags & 0x80:
                    out[key] = data[off:off + 2 * n].decode("utf-16-le", "replace")
                    off += 2 * n
                else:
                    out[key] = data[off:off + n].decode("cp1252", "replace")
                    off += n
    except (struct.error, ValueError, IndexError):
        out["cut"] = True       # the link ends before what its header promises
    return out


_CRON_TIME = r"(?:@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|(?:[\d*/,\-A-Za-z?LW#]+\s+){4}[\d*/,\-A-Za-z?LW#]+)"
_CRON_LINE = re.compile(r"^\s*(" + _CRON_TIME + r")\s+(\S.*)$")
_CRON_NAME = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|sun|mon|tue|wed|thu|fri|sat)"
_CRON_FIELD = re.compile(r"^(\*|\d+|" + _CRON_NAME + r")(?:[-/,](\*|\d+|" + _CRON_NAME + r"))*$|^\*/\d+$|^\?$", re.I)


def cron_lines(text: str) -> list:
    """[(schedule, rest of the line)] of a crontab's job lines; None when a line is neither a job,
    a comment nor an assignment (the text is no crontab)."""
    jobs = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
            continue
        m = _CRON_LINE.match(s)
        if not m or (not m.group(1).startswith("@") and not all(_CRON_FIELD.match(f) for f in m.group(1).split())):
            return None
        jobs.append((" ".join(m.group(1).split()), m.group(2).strip()))
    return jobs


def persistence_from_cron(text: str, name: str, source: str = "") -> list:
    jobs = cron_lines(text)
    if not jobs:
        return []
    path = name.replace("\\", "/").lower()
    system = bool(re.search(r"(^|/)etc/crontab$|(^|/)cron\.d/", path))
    user_tab = bool(re.search(r"(^|/)(var/spool/cron|crontabs|tabs)/", path))
    out = []
    for sched, rest in jobs:
        parts = rest.split(None, 1)
        if system and len(parts) == 2:
            out.append(row("cron", name, None, parts[1], parts[0], sched, source=source, origin="cron"))
        elif user_tab or len(parts) < 2:
            out.append(row("cron", name, None, rest, base(name) if user_tab else None, sched, source=source, origin="cron"))
        else:       # neither path says which form: both readings are kept, and the command is unsure
            out.append(row("cron", name, None, rest, None, sched, source=source, origin="cron",
                           command_if_system=parts[1], user_if_system=parts[0], form_unknown=True))
    return out


def parse_unit(text: str):
    """{section: {key: [values]}} of a systemd unit, or None."""
    if not re.search(r"(?m)^\s*\[(Unit|Service|Timer|Install|Socket|Path)\]\s*$", text):
        return None
    out, cur = {}, None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^\[([A-Za-z]+)\]$", s)
        if m:
            cur = out.setdefault(m.group(1), {})
        elif cur is not None and "=" in s and not s.startswith(("#", ";")):
            k, v = s.split("=", 1)
            cur.setdefault(k.strip(), []).append(v.strip())
    return out


def persistence_from_unit(text: str, name: str, source: str = "") -> list:
    u = parse_unit(text)
    if not u:
        return []
    one = lambda sec, key: (u.get(sec, {}).get(key) or [""])[-1]       # noqa: E731
    if "Timer" in u:
        sched = [f"{k}={v}" for k, vs in u["Timer"].items() if k.startswith("On") for v in vs]
        return [row("systemd_timer", name, base(name), one("Timer", "Unit") or None, None, sched[0] if len(sched) == 1 else None,
                    source=source, origin="systemd", description=one("Unit", "Description"), schedules=sched)]
    if "Service" in u and one("Service", "ExecStart"):
        return [row("systemd_service", name, base(name), one("Service", "ExecStart"), one("Service", "User") or None,
                    one("Install", "WantedBy") or None, source=source, origin="systemd",
                    description=one("Unit", "Description"), restart=one("Service", "Restart"))]
    return []


def persistence_from_plist(data: bytes, name: str, source: str = "") -> list:
    head = data[:512]
    if not (head.startswith(b"bplist00") or b"<plist" in data[:2048]):
        return []
    try:
        p = plistlib.loads(data[:MAX_FILE])
    except Exception:
        return []
    if not isinstance(p, dict) or "Label" not in p or not ("ProgramArguments" in p or "Program" in p):
        return []
    args = p.get("ProgramArguments")
    cmd = " ".join(str(a) for a in args) if isinstance(args, list) and args else str(p.get("Program") or "")
    path = name.replace("\\", "/").lower()
    mech = "launch_daemon" if "/launchdaemons/" in "/" + path else "launch_agent" if "/launchagents/" in "/" + path else "launchd"
    trig = [t for t, on in (("run_at_load", p.get("RunAtLoad") is True), ("keep_alive", bool(p.get("KeepAlive"))),
                            ("start_interval", "StartInterval" in p), ("calendar", "StartCalendarInterval" in p),
                            ("watch_paths", "WatchPaths" in p)) if on]
    return [row(mech if mech in MECHANISMS else None, name, str(p["Label"]), cmd, str(p.get("UserName") or "") or None,
                trig[0] if len(trig) == 1 else None, source=source, origin="launchd", triggers=trig,
                program=str(p.get("Program") or (args[0] if isinstance(args, list) and args else "")),
                start_interval=p.get("StartInterval"), launchd=True)]


def persistence_from_file(name: str, data: bytes, notes=None) -> list:
    """The persistence rows one file states by itself (events are read by persistence()).
    notes, when given, receives (name, reason) for a file that was not read whole."""
    tail = name.split(ARROW)[-1]
    low = tail.replace("\\", "/").lower()
    lnk = parse_lnk(data)
    if lnk is not None:
        if lnk.get("cut"):
            _note(notes, name, "a shell link that ends before what its header promises")
        startup = re.search(r"/start menu/programs/startup/|/startup/", "/" + low) is not None
        cmd = (lnk["target"] or lnk["relative_path"]) + (" " + lnk["arguments"] if lnk["arguments"] else "")
        return [row("startup_folder" if startup else None, tail, base(tail), cmd.strip(), None, None, source=name, origin="lnk",
                    exe=lnk["target"] or lnk["relative_path"], args=lnk["arguments"], working_directory=lnk["working_directory"],
                    icon=lnk["icon"], description=lnk["name"])]
    if data[:8] == b"bplist00":
        return persistence_from_plist(data, tail, name)
    if base(low) == "objects.data" or (b"\x00" in data[:4096] and b"__FilterToConsumerBinding" in data[:MAX_FILE]):
        return wmi_from_objects_data(data, name)
    text = text_of(data)
    if not text or not text.strip():
        return []
    head = text.lstrip("\ufeff \r\n\t")

    def lined(rows_):
        # a format read line by line, in a file with no final line end: its last line may be cut
        if rows_ and not text.endswith(("\n", "\r")):
            _note(notes, name, "no line end after the last line")
        return rows_

    if head.startswith(("Windows Registry Editor", "REGEDIT4")):
        return lined(persistence_from_reg(text, name, notes))
    if head.startswith("<"):
        if "<plist" in head[:2048]:
            return persistence_from_plist(data, tail, name)
        t = parse_task_xml(text) if "<Task" in head[:4096] else None
        if t:
            stem = re.sub(r"\.xml$", "", base(tail), flags=re.I)
            rows_ = _task_rows(t, name, "task_xml")
            for r in rows_:
                if not t["uri"]:
                    r["name"], r["location"] = stem, None
                    r["extra"]["name_from"] = "file_stem"
            return rows_
        return []
    if head[:1] == "{" or (head[:1] == "[" and not re.match(r"\[[A-Za-z]+\]\s*(\r?\n|$)", head)):
        return []
    first = head.split("\n", 1)[0]
    if "Entry Location" in first:
        return persistence_from_autoruns(text, name, notes)
    if "EventConsumer" in text or "__EventFilter" in text:
        got = wmi_from_text(text, name, notes)
        if got:
            return lined(got)
    if re.search(r"(?m)^\s*\[(Service|Timer)\]\s*$", text):
        return lined(persistence_from_unit(text, tail, name))
    if re.search(r"(^|/)(crontab|cron\.d/[^/]+|cron\.(daily|hourly|weekly|monthly)/[^/]+|crontabs/[^/]+|var/spool/cron/.+)$|\.cron$", low) \
            or cron_lines(text):
        return lined(persistence_from_cron(text, tail, name))
    return []


# ---- the model of one delivery ------------------------------------------------------------------------

def unique_files(files: dict) -> list:
    """[(name, bytes)] once per file (tools/run.py files a member under two names, the same object)."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        mark = (len(data), hashlib.blake2b(data, digest_size=16).digest())
        if mark in seen:            # the same bytes under another name are the same file, not more events
            continue
        seen.add(mark)
        out.append((key, bytes(data)))
    return sorted(out)


def _gunzip(data: bytes):
    """The content of a gzip file up to MAX_FILE, or None (not gzip, cut, or larger)."""
    try:
        d = zlib.decompressobj(31)
        body = d.decompress(data, MAX_FILE)
        return body if d.eof and not d.unconsumed_tail else None
    except zlib.error:
        return None


def _is_container(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06") or data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:2] == b"\x1f\x8b"


class Model:
    """Everything read from one set's files: events, processes, script blocks, persistence rows."""

    def __init__(self, files: dict):
        self.files = files
        self.events, self.rows, self.sources = [], [], []
        self.damaged = []       # (file, why): what was delivered but not read whole
        for name, data in unique_files(files):
            if data[:2] == b"\x1f\x8b":
                body = _gunzip(data)
                if body is None or _is_container(body):
                    self.damaged.append((name, "a gzip file that was not read"))
                    continue
                data = body
            if data[:4] == b"PK\x05\x06":      # an empty zip holds nothing to miss
                continue
            if _is_container(data):
                # tools/run.py files an archive's members under "<archive> -> <member>"; an archive
                # with none was not opened, and what it holds is not counted here
                if not any(k.startswith(name + ARROW) or k.startswith(name.split(ARROW)[-1] + ARROW) for k in files):
                    self.damaged.append((name, "an archive whose members were not delivered"))
                continue
            if len(data) > MAX_FILE:
                self.damaged.append((name, "larger than MAX_FILE"))
                continue
            try:
                ev = read_events(name, data, self.damaged)
            except Exception:
                ev = []
                self.damaged.append((name, "the reader failed"))
            try:
                rw = [] if ev else persistence_from_file(name, data, self.damaged)
            except Exception:
                rw = []
                self.damaged.append((name, "the reader failed"))
            if ev or rw:
                self.sources.append(name)
            self.events.extend(ev)
            self.rows.extend(rw)
        try:
            self.rows.extend(persistence_from_events(self.events))
        except Exception:
            pass
        self.procs = processes(self.events)
        self._decoded, self.cache = {}, {}

    def decoded(self, cmd: str) -> list:
        if cmd not in self._decoded:
            try:
                self._decoded[cmd] = decode_command_line(cmd)
            except Exception:
                self._decoded[cmd] = []
        return self._decoded[cmd]

    def empty(self) -> bool:
        return not (self.events or self.rows)


def persistence(files: dict) -> list:
    """The persistence table of a set of files ({name: bytes}): rows from every reader above."""
    return Model(files).rows


# ---- signals --------------------------------------------------------------------------------------

_FILE_MARKS = (rb'"winlog"', rb"Microsoft-Windows-Sysmon", rb"<Event xmlns", rb"ProcessGuid", rb"EventID", rb'"event_id"',
               rb"Windows Registry Editor", rb"REGEDIT4", rb"Entry Location", rb"schemas.microsoft.com/windows/2004/02/mit/task",
               rb"__FilterToConsumerBinding", rb"EventConsumer", rb"ParentCommandLine", rb"parent_command_line",
               rb"TargetUserName", rb"ScriptBlockText", rb"ExecStart=", rb"ProgramArguments", rb'"command_line"',
               rb"Microsoft-Windows-Security-Auditing", rb"EventRecordID", rb'"RecordNumber"', rb"Microsoft-Windows-PowerShell",
               rb'"Channel":"Security"', rb'"SourceName":"Microsoft-Windows', rb"SubjectUserSid", rb"<EventID")
_Q_MARKS = re.compile(r"\b(event\s*id|sysmon|event log|logon|parent (image|process)|command ?line|process tree|persist\w*|"
                      r"scheduled task|autoruns?|run key|registry key|value name|service (name|install\w*)|new service|"
                      r"created (user|account)|encodedcommand|encoded command|script ?block|wmi|launch ?agent|cron|systemd|"
                      r"edr|telemetry|brute.?force)\b", re.I)


def signals(questions, files) -> float:
    """0..1: how strongly the delivery and its questions look like exported endpoint telemetry or
    persistence artefacts. Cheap: the first 64 KiB of each file and the question text."""
    hits = 0
    for name, data in unique_files(files or {}):
        if _is_container(data):
            continue
        head = data[:65536]
        if head[:20] == b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F":
            hits += 2
            continue
        if b"\x00" in head[:512] and head[:2] not in (b"\xff\xfe", b"\xfe\xff") and head[1:2] != b"\x00" \
                and b"__FilterToConsumerBinding" not in head:
            continue
        flat = head.replace(b"\x00", b"")
        hits += sum(1 for m in _FILE_MARKS if m in flat)
    f = min(1.0, hits / 3.0)
    qs = list(questions or [])
    qhit = sum(1 for q in qs if _Q_MARKS.search(f"{q.get('question') or ''} {str(q.get('answer_id') or q.get('id') or '').replace('-', ' ').replace('_', ' ')}"))
    qf = (qhit / len(qs)) if qs else 0.0
    if not hits:
        return round(0.2 * qf, 3)
    return round(min(1.0, 0.6 * f + 0.4 * qf), 3)


# ---- the runner contract ------------------------------------------------------------------------------

NA = object()       # a handler's "this is not my question"
_FOREIGN = re.compile(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+")
_QUOTED = re.compile(r"[`\"\u201c\u2018']([^`\"'\u201d\u2019\n]{2,200})[`\"\u201d\u2019']")
_FILELIKE = re.compile(r"(?<![\w\\/.-])([\w.$-]+\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|scr|sys|msi|hta|py|sh|lnk|com|cpl|"
                       r"jar|wsf|service|timer|plist))(?![\w-])", re.I)
_WINPATH = re.compile(r"(?<![\w\\])([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,80}\\){0,12}[^\\/:*?\"<>|\s]{1,80}\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|"
                      r"js|jse|scr|sys|msi|hta|lnk|com|cpl|wsf))(?![\w-])", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GUID = re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27}\}")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\]\[{}`,;]{3,300}", re.I)
_KNOWN_IDS = "|".join(str(i) for i in sorted(DEFAULT_CHANNEL) if i >= 100)
_PID = re.compile(r"\b(?:pid|process id)\s*(?:of|is|=|:|#)?\s*(\d{1,7})\b", re.I)
_EID = re.compile(r"\bevent\s*(?:ids?|codes?)?\s*(?:of|is|=|:|#)?\s*(\d{1,5})\b|"
                  r"(?<!process )(?<!parent )(?<!logon )(?<!thread )\b(?:e?id|code)\s*[:#=]?\s*(\d{1,5})\b|"
                  r"\b(" + _KNOWN_IDS + r")\b", re.I)
PHRASES = (
    (r"failed (?:\w+ )?log-?[oi]n|log-?[oi]n failures?|unsuccessful log-?[oi]n|failed (?:authentication|login) attempts?|failed attempts?", (("security", 4625),)),
    (r"successful(?:ly)? log-?[oi]n|log-?[oi]n success|log(?:ged)? (?:on|in) successfully|successful (?:authentication|login)", (("security", 4624),)),
    (r"explicit credentials?", (("security", 4648),)),
    (r"special privileges?", (("security", 4672),)),
    (r"service (?:was |were |got )?install\w*|new service|installed (?:a )?service|service creat\w*", (("system", 7045), ("security", 4697))),
    (r"(?:scheduled )?task (?:was |were )?creat\w*|new (?:scheduled )?task|created (?:a )?(?:scheduled )?task", (("security", 4698),)),
    (r"(?:user|account) (?:was |were )?creat\w*|new (?:local )?(?:user|account)|created (?:a )?(?:new )?(?:local )?(?:user|account)", (("security", 4720),)),
    (r"added to (?:the |a )?(?:[\w ]+ )?group|group member\w*", (("security", 4732), ("security", 4728), ("security", 4756))),
    (r"logs? (?:was |were )?clear\w*|clear\w* (?:the )?(?:\w+ )?(?:event )?logs?|audit log", (("security", 1102), ("system", 104))),
    (r"script ?blocks?", (("powershell", 4104),)),
    (r"module logging|pipeline execution", (("powershell", 4103),)),
    (r"defender|antivirus|malware (?:was )?detect\w*|threat (?:name|detect\w*)|detection name", (("defender", 1116), ("defender", 1117))),
    (r"network connections?", (("sysmon", 3),)),
    (r"image loads?|dll loads?|loaded (?:dll|module|image)|module loads?", (("sysmon", 7),)),
    (r"remote threads?|createremotethread", (("sysmon", 8),)),
    (r"process access\w*", (("sysmon", 10),)),
    (r"file creat\w*|created (?:a )?file|files? (?:was |were )?(?:created|dropped|written)|dropped (?:a )?file", (("sysmon", 11),)),
    (r"registry (?:value )?(?:set|modif\w*|writ\w*|chang\w*)|set (?:a |the )?registry", (("sysmon", 13),)),
    (r"alternate data stream|stream hash|zone\.identifier", (("sysmon", 15),)),
    (r"dns (?:quer\w*|lookups?|requests?)|domain (?:was |were )?(?:queried|resolved|looked up)|query ?name", (("sysmon", 22),)),
    (r"file delet\w*|deleted (?:a )?file", (("sysmon", 23),)),
    (r"process creat\w*|process start\w*|new process\w*|processes (?:were |was )?(?:created|started|launched)", (("sysmon", 1), ("security", 4688))),
)
MECH_WORDS = (
    (r"systemd|unit file|\.service\b", ("systemd_service", "systemd_timer")),
    (r"\bwmi\b|event consumer|event subscription|event ?filter", ("wmi_event_subscription",)),
    (r"scheduled tasks?|\btasks?\b|schtasks", ("scheduled_task",)),
    (r"\bservices?\b", ("windows_service", "systemd_service")),
    (r"run ?keys?|autorun key|\\run\b", ("registry_run_key",)),
    (r"startup folder|startup (?:item|shortcut|lnk)|\.lnk\b|shortcut", ("startup_folder",)),
    (r"\bifeo\b|image file execution|debugger", ("ifeo_debugger",)),
    (r"com hijack\w*|clsid|inprocserver", ("com_hijack",)),
    (r"cron\w*", ("cron",)),
    (r"\btimers?\b", ("systemd_timer",)),
    (r"launch ?agents?|launch ?daemons?|launchd|\bplist\b", ("launch_agent", "launch_daemon")),
    (r"winlogon|userinit", ("winlogon_helper",)),
    (r"registry", REGISTRY_MECHANISMS + ("windows_service",)),
)


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _fits(q, value) -> bool:
    f = _fmt(q)
    value = str(value)
    if str(f.get("kind") or "") == "integer" and not re.fullmatch(r"-?\d+", value):
        return False
    if str(f.get("kind") or "") == "mitre_attack_id" and not re.fullmatch(r"T\d{4}(\.\d{3})?", value):
        return False
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, value) is not None
        except re.error:
            return False
    return True


def pick(key: str, options):
    try:
        return labels.pick(f"{KEY}.{key}", options)
    except ValueError:
        return None


def one(values):
    """The single distinct non-empty value, or None."""
    seen = []
    for v in values:
        v = "" if v is None else str(v).strip()
        if v and v not in seen:
            seen.append(v)
    return seen[0] if len(seen) == 1 else None


def _same(value, token) -> bool:
    v, t = str(value or "").strip().strip('"').lower(), token.lower()
    if not v or not v.endswith(t):      # every match below ends with the token: the cheap test first
        return False
    return v == t or base(v) == t or v.split("\\")[-1] == t


class Ask:
    """One question against the model: its text, the events, processes and rows in its scope, and
    the values it names."""

    twins = None        # a bare program name of the question that two different files carry (set by narrow)

    def __init__(self, q, model: Model):
        self.q, self.m = q, model
        self.raw = " ".join(str(q.get("question") or "").split())
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        self.aid = aid
        self.text = (self.raw + " | " + re.sub(r"[-_.]+", " ", aid)).lower()
        self.kind = str(_fmt(q).get("kind") or "")
        self.syntax = str(_fmt(q).get("syntax") or "")
        names = self._scope_names()
        in_scope = lambda src: not names or any(                    # noqa: E731
            base(part) in names or part in names for part in src.split(ARROW))
        ev = [e for e in model.events if in_scope(e["source"])]
        rw = [r for r in model.rows if in_scope(r["source"])]
        if names and not ev and not rw:         # the file the question names is not what was delivered
            ev, rw = model.events, model.rows
        self.events, self.rows = ev, [r for r in rw if not r["extra"].get("default")]
        srcs = {id(e) for e in ev}
        self.procs = [p for p in model.procs if id(p["_event"]) in srcs]
        if "file_names" not in model.cache:
            model.cache["file_names"] = {base(p).lower() for n in model.files for p in n.split(ARROW)}
        self.file_names = model.cache["file_names"]
        self.tokens = self._tokens()

    def _scope_names(self) -> set:
        names = set()
        member = self.q.get("member")
        known = {}
        for key in self.m.files:
            for part in key.split(ARROW):
                known.setdefault(base(part).lower(), set()).add(base(part))
                known.setdefault(part.lower(), set()).add(part)
        if member and (str(member).lower() in known or base(str(member)).lower() in known):
            names |= {str(member), base(str(member))}
        for name in known:
            if len(name) > 3 and re.search(r"(?<![\w.\\/-])" + re.escape(name) + r"(?![\w-])", self.raw.lower()):
                names |= known[name]
        return names

    def _tokens(self) -> list:
        """Values the question names: quoted or backticked strings, file names of programs, IPv4
        addresses, GUIDs, and bare words equal to a user or host recorded in the events."""
        out = []
        for rx in (_QUOTED, _WINPATH, _FILELIKE, _IPV4, _GUID, _PID):
            for m in rx.finditer(self.raw):
                t = (m.group(1) if rx.groups else m.group()).strip()
                if t and t.lower() not in [o.lower() for o in out] and t.lower() not in self.file_names:
                    out.append(t)
        slot = ("idents", frozenset(e["source"] for e in self.events[:1] + self.events[-1:]), len(self.events), len(self.rows))
        idents = self.m.cache.get(slot)
        fresh = idents is None
        idents = set() if fresh else idents
        for e in (self.events if fresh else ()):
            for f in ("TargetUserName", "SubjectUserName", "User", "AccountName"):
                v = fget(e, f)
                if v and v != "-":
                    idents.add(v.lower())
                    idents.add(v.split("\\")[-1].lower())
            for f in ("ServiceName", "TaskName"):
                v = fget(e, f)
                if v:
                    idents.add(v.strip("\\").split("\\")[-1].lower())
            if e["host"]:
                idents.add(e["host"].lower())
        for r in (self.rows if fresh else ()):
            for v in (r["name"], r["extra"].get("value_name")):
                if v and len(str(v)) >= 4:
                    idents.add(str(v).strip("\\").split("\\")[-1].lower())
        self.m.cache[slot] = idents
        for w in re.findall(r"[A-Za-z0-9_.$\\-]{3,}", self.raw):
            lw = w.strip(".").lower()
            if lw in idents and lw not in [o.lower() for o in out] and lw not in ("system", "user", "users", "service", "services", "network", "task", "tasks", "shell", "debugger", "name", "default"):
                out.append(w.strip("."))
        return out

    def has(self, rx) -> bool:
        return re.search(rx, self.text) is not None

    # -- narrowing --------------------------------------------------------------------------------

    def narrow(self, items, values_of, strict=True):
        """items narrowed by every named value that some item carries. A named program (x.exe) or
        address that no item carries empties the list when strict: the question is about something
        that is not here. Returns (items, number of tokens that narrowed)."""
        used = 0
        for t in self.tokens:
            hit = [it for it in items if any(_same(v, t) for v in values_of(it))]
            if hit:
                if "\\" not in t and "/" not in t and _FILELIKE.fullmatch(t):
                    # a bare program name that two different files carry (the real svchost.exe and one
                    # in C:\ProgramData): which is meant is not said, so nothing counted or read over
                    # both is a fact about either (review, 2026-10-08)
                    paths = {str(v).strip().strip('"').lower() for it in hit for v in values_of(it)
                             if isinstance(v, str) and ("\\" in v or "/" in v) and _same(v, t) and " " not in v.strip().strip('"').rsplit("\\", 1)[-1]}
                    if len(paths) > 1:
                        self.twins = t
                items, used = hit, used + 1
            elif strict and (_FILELIKE.fullmatch(t) or _WINPATH.fullmatch(t) or _IPV4.fullmatch(t) or _GUID.fullmatch(t)):
                return [], used
        return items, used

    def eventset(self):
        """(events, label) the question points at by an event id or a phrase, or None. A phrase or
        id that maps to more than one (channel, id) present in the data is ambiguous: None."""
        ids = []
        for m in _EID.finditer(_PID.sub(" ", self.raw)):
            n = int(next(g for g in m.groups() if g))
            if n not in ids:
                ids.append(n)
        hint = next((c for c, rx in (("sysmon", r"\bsysmon\b"), ("security", r"\bsecurity (?:event )?log|\bsecurity event|\bsecurity channel"),
                                     ("powershell", r"\bpowershell (?:operational|log|event)"), ("system", r"\bsystem (?:event )?log"),
                                     ("defender", r"\bdefender\b")) if self.has(rx)), None)
        if len(ids) > 1:
            return None
        if ids:
            eid = ids[0]
            if eid < 100 and not hint and not self.has(r"\bevent\b"):
                return NA
            got = select(self.events, eid, hint)
            if len({chan(e) for e in got}) > 1:
                return None
            return got, f"{hint or DEFAULT_CHANNEL.get(eid) or 'any'}:{eid}"
        said = [pairs for rx, pairs in PHRASES if self.has(rx)]
        if len(said) > 1:
            return None
        for pairs in said:
            present = [(c, i, select(self.events, i, c)) for c, i in pairs]
            present = [p for p in present if p[2]]
            if len(present) > 1:
                return None
            if present:
                return present[0][2], f"{present[0][0]}:{present[0][1]}"
            return [], f"{pairs[0][0]}:{pairs[0][1]}"
        return NA

    def candidates(self):
        """Persistence rows the question can mean: those of the mechanisms it words, of the entries
        it names, and (Autoruns) unsigned or disabled ones when it says so."""
        rows = self.rows
        mechs = []
        for rx, ms in MECH_WORDS:
            if self.has(rx):
                mechs = [m for m in ms]
                break
        if mechs:
            rows = [r for r in rows if r["mechanism"] in mechs]
        if self.has(r"\bunsigned\b|not (?:digitally )?(?:signed|verified)|unverified"):
            rows = [r for r in rows if r["origin"] == "autoruns" and not r["extra"].get("verified")]
        if self.has(r"\bdisabled\b") and any(r["origin"] == "autoruns" for r in rows):
            rows = [r for r in rows if r["extra"].get("enabled", "").lower() == "disabled"]
        rows, _ = self.narrow(rows, lambda r: [r["name"], r["location"], r["extra"].get("exe"), r["extra"].get("image_path"),
                                                r["extra"].get("value_name"), r["extra"].get("image"), r["source"].split(ARROW)[-1]]
                              + re.findall(r"[^\s\"',]+", r["command"] or ""))
        return rows, mechs


# -- handlers: each returns an answer, None (no answer), or NA (not its question) ------------------------

def _plain(a: Ask, value):
    if value is None or value == "":
        return None
    return str(value) if _fits(a.q, value) else None


def _mechanism_options(a: Ask, mech: str) -> list:
    names = list(MECHANISMS[mech][1])
    listed = []
    f = _fmt(a.q)
    for key in ("options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            listed = [str(v) for v in f[key]]
    listed = listed or labels.enum_from_question(a.raw, raw=True)
    if listed:
        squash = {re.sub(r"[^a-z0-9]", "", n) for n in names}
        ours = [o for o in listed if re.sub(r"[^a-z0-9]", "", o.lower()) in squash]
        return ours        # the question lists its names: only a listed one can be right
    return names


def h_technique(a: Ask):
    if not (a.kind == "mitre_attack_id" or a.has(r"att&ck|\bmitre\b|technique id|sub-?technique|\bt-?code\b|\battack id\b")):
        return NA
    rows, mechs = a.candidates()
    if a.events and not (mechs or a.has(r"persist\w*|autoruns?|auto-?start|startup")):
        return None             # the delivery holds more than persistence: which behaviour is meant is not said
    mech = one(r["mechanism"] for r in rows)
    if not mech or any(r["mechanism"] is None for r in rows):
        return None
    tid = technique_of(mech)
    opts = [o for o in (tid, tid.split(".")[0]) if _fits(a.q, o)]
    if a.has(r"sub-?technique"):
        opts = [o for o in opts if "." in o]
    return pick(f"technique/{mech}", list(dict.fromkeys(opts)))


def h_mechanism(a: Ask):
    if not a.has(r"persistence (?:mechanism|method|type|technique|category)|\bmechanism\b|how (?:did|does|was|is) .{0,80}persist\w*|"
                 r"(?:kind|type|form|method) of persistence|persistence .{0,40}(?:used|established|achieved)"):
        return NA
    rows, _ = a.candidates()
    mech = one(r["mechanism"] for r in rows)
    if not mech or any(r["mechanism"] is None for r in rows):
        return None
    return pick(f"mechanism/{mech}", [o for o in _mechanism_options(a, mech) if _fits(a.q, o)])


def _process_set(a: Ask, subject="image"):
    procs, used = a.narrow(a.procs, lambda p: [p[subject]] + ([p["user"], p["host"], str(p["pid"])] if subject == "image" else []))
    return procs, used


def _texts(a: Ask) -> list:
    """Every text of the scope an indicator can sit in: command lines, their decoded layers,
    script blocks, persistence commands."""
    procs, _ = _process_set(a)
    out = []
    for p in procs:
        out.append(p["command_line"])
        out.extend(a.m.decoded(p["command_line"]))
    for b in script_blocks(a.events):
        out.append(b["text"])
        out.extend(a.m.decoded(b["text"]))
    for r in a.rows:
        if r["command"]:
            out.append(r["command"])
            out.extend(a.m.decoded(r["command"]))
    return [t for t in out if t]


def _indicator(a: Ask, texts):
    """The one URL, domain or address the texts hold, when the question asks for one; else NA."""
    if a.has(r"\burls?\b|\blinks?\b|download\w* from|web address|\buri\b"):
        return _plain(a, one(m.group().rstrip(".") for t in texts for m in _URL.finditer(t)))
    if a.has(r"\bdomain\b|\bfqdn\b|\bhost ?name\b") and texts:
        hosts = [re.sub(r"^[a-z]+://", "", m.group(), flags=re.I).split("/")[0].split("@")[-1].split(":")[0]
                 for t in texts for m in _URL.finditer(t)]
        return _plain(a, one(h for h in hosts if not _IPV4.fullmatch(h)))
    if a.has(r"\bip(?:v4)?(?: address)?\b") and texts:
        return _plain(a, one(m.group() for t in texts for m in _IPV4.finditer(t)))
    return NA


def h_decoded(a: Ask):
    if not a.has(r"decod\w*|deobfuscat\w*|encoded ?command|-enc\b|base64"):
        return NA
    cmds = [p["command_line"] for p in _process_set(a)[0]] + [r["command"] for r in a.candidates()[0] if r["command"]]
    layered = {c: a.m.decoded(c) for c in dict.fromkeys(cmds)}
    layered = {c: ls for c, ls in layered.items() if ls}
    if not layered:
        return None
    texts = [t for ls in layered.values() for t in ls]
    # a decoded text that ends inside a quote or a bracket was cut where it was recorded
    cut = any(t.count('"') % 2 or t.count("'") % 2 or t.count("(") != t.count(")") for t in texts)
    got = _indicator(a, texts)
    if got is not NA:
        return pick("indicator/cut_command", [("as_decoded", got)]) if cut and got is not None and not labels.is_unsure(got) else got
    if len(layered) != 1 or not a.has(r"decod\w*|deobfuscat\w*"):
        return None
    layers = next(iter(layered.values()))
    final = layers[-1].strip()
    if len(layers) == 1:
        return pick("decoded/cut_command", [("as_decoded", final)] if _fits(a.q, final) else []) if cut else _plain(a, final)
    return pick("decoded/layers", [(n, v) for n, v in (("final", final), ("first", layers[0].strip())) if _fits(a.q, v)])


def _count(a: Ask, n: int):
    """A count as an answer. Zero is never one: nothing found is as likely an export this reader
    does not know (another channel name, another field) as a true zero."""
    return _plain(a, n) if n > 0 else None


def h_count(a: Ask):
    if not a.has(r"how many|number of|\bcount\b|how often|total (?:number|count)"):
        return NA
    if a.has(r"\b(unique|distinct|different|each|per|between|during)\b"):
        return None
    if re.search(r"\bbefore\b.{0,60}\bsuccess\w*", a.text) and a.has(PHRASES[0][0]) and not _EID.search(a.raw):
        bf = [r for r in brute_force(a.events) if r["successes"]]
        if len(bf) != 1 or any(e["_dt"] is None for e in bf[0]["events"] + bf[0]["successes"]):
            return None
        first = min(e["_dt"] for e in bf[0]["successes"])
        events, _ = a.narrow([e for e in bf[0]["events"] if e["_dt"] < first], lambda e: list(e["fields"].values()) + [e["host"]])
        every, _ = a.narrow([e for e in select(a.events, 4625) if e["_dt"] is None or e["_dt"] < first],
                            lambda e: list(e["fields"].values()) + [e["host"]])
        if len(every) != len(events):
            # failures from another source came first too: whose are meant is not said
            opts = [(n, str(v)) for n, v in (("same_source", len(events)), ("all_sources", len(every))) if v > 0 and _fits(a.q, v)]
            return None if a.m.damaged else pick("count/failures_before_success", opts)
        return _count(a, len(events))
    if a.has(r"brute.?forc\w*|password (?:spray|guess)\w*") and not _EID.search(a.raw) and not a.has(PHRASES[0][0]) \
            and not a.has(r"\b(before|after|successful\w*|succeed\w*)\b"):
        bf = brute_force(a.events)
        cand = [r for r in bf if r["successes"]] or bf
        if len(cand) != 1 or a.m.damaged:
            return None
        n = len(cand[0]["events"])
        return pick("count/brute_force.failed_logons", [("failed_logons_from_source", str(n))]) if n > 0 and _fits(a.q, n) else None
    es = a.eventset()
    if es is None:
        return None
    if es is NA:
        if not a.has(r"how many|number of|\bcount\b"):
            return NA
        rows, mechs = a.candidates()
        if (mechs or a.has(r"autoruns?|\bentries\b")) and rows and len({r["source"] for r in rows}) == 1 and a.has(r"how many|number of") \
                and not a.has(r"\b(that|which|whose|where|with|from|by)\b"):
            return _count(a, len(rows))
        return None
    events, label = es
    if a.has(r"\b(before|after)\b"):
        return None
    events, used = a.narrow(events, lambda e: list(e["fields"].values()) + [e["host"]])
    residual = a.text
    for rx, _ in PHRASES:
        residual = re.sub(rx, " ", residual)
    if not used and re.search(r"\b(from|by|against|targeting|whose|where|user|account|host|address|ip|type)\b", residual.split("|")[0]):
        return None
    head = _EID.sub(" ", _PID.sub(" ", residual.split("|")[0]))
    named = " ".join(t.lower() for t in a.tokens)
    if re.search(r"\b(?:ports?|protocols?|rdp|smb|ssh|winrm|http|https|dns|inbound|outbound|incoming|outgoing|internal|external|public|private|"
                 r"successful|failed|unsuccessful|blocked|allowed|denied|malicious|suspicious|encoded|obfuscated|hidden|elevated)\b", head) \
            or any(n not in named for n in re.findall(r"\b\d{2,}\b", head)):
        return None             # a port, a protocol, a direction or a judgement the count was not narrowed by (8 for 6 "to port 3389")
    if label == "powershell:4104" and not _EID.search(a.raw) and len(script_blocks(events)) != len(events):
        return None             # a block logged in several parts: blocks or events is not said
    if label in ("sysmon:1", "security:4688"):
        # A program the question names is the new process of some creations and the parent of others
        # (cmd.exe is started once and starts ten): "created by cmd.exe" counts its children, and
        # "for net.exe" is its own starts or every event that names it (11 for 10, 18 for 9 before).
        progs = [t for t in a.tokens if _FILELIKE.fullmatch(t) or _WINPATH.fullmatch(t)]
        if len(progs) == 1:
            own = [e for e in events if _same(fget(e, "NewProcessName", "Image"), progs[0])]
            kids = [e for e in events if _same(fget(e, "ParentProcessName", "ParentImage"), progs[0])]
            if own and kids:
                if a.has(r"\b(?:created|spawned|launched|started|run|ran|executed|invoked) by\b|\bchild(?:ren)?\b|\bspawn\w*\b|\bdid\b.{0,40}\b(?:create|start|launch|run)\b"):
                    return _count(a, len(kids))
                opts = [(n, str(v)) for n, v in (("as_new_process", len(own)), ("as_parent", len(kids)), ("either", len(events))) if _fits(a.q, v)]
                return pick("count/process.role", opts) if opts and not a.m.damaged else None
    return _count(a, len(events))


def _time_options(a: Ask, e) -> list:
    dt = e["_dt"]
    sec = dt.replace(microsecond=0)
    ms = "%03d" % (dt.microsecond // 1000)
    opts = [("raw", e["time_raw"].strip()), ("iso_z", iso(sec)), ("iso_ms_z", sec.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "Z"),
            ("space", sec.strftime("%Y-%m-%d %H:%M:%S")), ("space_ms", sec.strftime("%Y-%m-%d %H:%M:%S.") + ms),
            ("iso", sec.strftime("%Y-%m-%dT%H:%M:%S")), ("iso_offset", sec.strftime("%Y-%m-%dT%H:%M:%S+00:00")),
            ("space_utc", sec.strftime("%Y-%m-%d %H:%M:%S UTC")), ("iso_micro_z", iso(dt))]
    out, seen = [], set()
    for n, v in opts:
        if v and v not in seen and _fits(a.q, v):
            seen.add(v)
            out.append((n, v))
    return out


_TEMPLATE = re.compile(r"YYYY([-/])MM\1DD([T ])HH:MM(:SS)?(\.(?:fff|SSS|mmm))?( ?UTC|Z)?")


def h_time(a: Ask):
    if not a.has(r"\bwhen\b|what time|timestamp|\btime of\b|date and time|at what time|\butctime\b|\btime ?created\b|"
                 r"what (?:is|was) the (?:utc )?(?:date|time)"):
        return NA
    es = a.eventset()
    if es is NA:
        return NA
    if es is None:
        return None
    events, label = es
    events, _ = a.narrow(events, lambda e: list(e["fields"].values()) + [e["host"]])
    if not events or any(e["_dt"] is None for e in events):
        return None
    first, last = a.has(r"\b(first|earliest|initial|begin\w*|start\w*)\b"), a.has(r"\b(last|latest|final|most recent|end\w*)\b")
    if first == last:
        if len({e["_dt"] for e in events}) != 1:
            return None
        e = events[0]
    else:
        e = (min if first else max)(events, key=lambda x: x["_dt"])
    m = _TEMPLATE.search(a.syntax) or _TEMPLATE.search(a.raw)
    zm = _ISO.match(e["time_raw"])
    shifted = bool(zm and zm.group(8) and zm.group(8)[0] in "+-" and zm.group(8).replace(":", "")[1:] != "0000")
    if m and not e["naive"] and shifted and not m.group(5):
        # recorded with an offset and asked for with no zone: UTC or the recorded clock is not said
        sep, t, secs, frac, _z = m.groups()
        fmt_ = f"%Y{sep}%m{sep}%d{t}%H:%M" + (":%S" if secs else "")
        sign = 1 if zm.group(8)[0] == "+" else -1
        z = zm.group(8).replace(":", "")
        local = e["_dt"] + sign * timedelta(hours=int(z[1:3]), minutes=int(z[3:5]))
        tail = lambda d: ("." + "%03d" % (d.microsecond // 1000)) if frac else ""      # noqa: E731
        opts = [("utc", e["_dt"].strftime(fmt_) + tail(e["_dt"])), ("as_recorded", local.strftime(fmt_) + tail(local))]
        return pick(f"time/{label.split(':')[0]}.offset", [(n, v) for n, v in opts if _fits(a.q, v)])
    if m and not e["naive"]:
        sep, t, secs, frac, zone = m.groups()
        v = e["_dt"].strftime(f"%Y{sep}%m{sep}%d{t}%H:%M" + (":%S" if secs else ""))
        v += ("." + "%03d" % (e["_dt"].microsecond // 1000)) if frac else ""
        return _plain(a, v + (zone or ""))
    opts = _time_options(a, e)
    f = _fmt(a.q)
    if (f.get("pattern") or f.get("regex")) and len(opts) == 1 and not e["naive"]:
        return opts[0][1]
    return pick(f"time/{label.split(':')[0]}{'.naive' if e['naive'] else ''}", opts)


def _column(a: Ask):
    """(column, both) the persistence question asks for: location, trigger, author, command, name."""
    t = a.text
    if re.search(r"key path|registry (?:key|path|location)|which key|what key|\blocation\b|file path|path of the (?:key|unit|plist|task|shortcut)|\bwhere\b", t):
        return "location", False
    if re.search(r"service file ?name|binary ?path(?: ?name)?", t):
        return "command", False         # 7045's 'Service File Name' and sc's binPath are the command, not a name
    if re.search(r"\btriggers?\b|\bschedule\b|when does|how often|\binterval\b|start ?type|start ?mode|wql|\bquery\b", t):
        return "trigger", False
    if re.search(r"\bauthor\b|\bsigner\b|\bpublisher\b|\bcompany\b|run ?as\b|service account|which (?:user|account)|what (?:user|account)|"
                 r"created by|\bcreator\b", t):
        return "author", False
    if re.search(r"\b(?:value|task|service|entry|unit|job|consumer|filter) name\b|"
                 r"name of the (?:new |installed |malicious |scheduled |rogue )*(?:service|task|entry|value|unit|consumer|job)\b|\blabel\b", t):
        return "name", False
    cmdw = re.search(r"launch string|\bcommand\b|\bexecutable\b|\bbinary\b|\bprogram\b|\bpayload\b|image ?path|value data|\bdata\b|"
                     r"\bactions?\b|\bexecstart\b|\bscript\b|\btarget\b|what (?:does|did) .{0,60}\b(?:run|execute|launch|start)\b|"
                     r"what is (?:run|executed|launched|started)\b|\b(?:runs|executes|executed|launches|launched)\b|\barguments?\b", t)
    namew = re.search(r"\bnamed?\b|\bcalled\b|\blabel\b|which (?:service|task|entry|value|unit)|what (?:service|task|entry|value|unit)", t)
    if cmdw:
        return "command", bool(namew)
    if namew:
        return "name", False
    return None, False


def h_persistence(a: Ask):
    rows, mechs = a.candidates()
    named = any(_same(r["name"], t) for r in rows for t in a.tokens)
    wants = a.has(r"persist\w*|autoruns?|auto-?start|startup") or bool(mechs) or named
    if not wants or not rows:
        return NA
    mech_ = one(r["mechanism"] for r in rows)
    extra = lambda key: (one(r["extra"].get(key) for r in rows) if all(r["extra"].get(key) for r in rows) else None)   # noqa: E731
    if mech_ == "wmi_event_subscription" and a.has(r"\bfilter\b") and not a.has(r"\bquery\b|\bwql\b"):
        return _plain(a, extra("filter")) if a.has(r"\bname\b|\bnamed\b|\bcalled\b") and not any(r["extra"].get("carved") for r in rows) \
            else (pick("wmi_filter/objects_data", [("binding", extra("filter"))]) if a.has(r"\bname\b|\bnamed\b|\bcalled\b") else None)
    if mech_ == "scheduled_task" and a.has(r"run ?as\b|\b(?:runs?|running|executes?) (?:as|under)\b|\bprincipal\b|user ?id\b"):
        u = extra("user")
        if u and re.fullmatch(r"S-1-[\d-]+", u) and not a.has(r"user ?id\b|\bsid\b"):
            names_ = {"S-1-5-18": "SYSTEM", "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE"}
            return pick("task_user/sid", [(n, o) for n, o in (("as_recorded", u), ("well_known_name", names_.get(u))) if o and _fits(a.q, o)])
        return _plain(a, u)
    if mech_ == "scheduled_task" and a.has(r"run ?level"):
        return _plain(a, extra("run_level"))
    if a.has(r"display ?name"):
        return _plain(a, extra("display_name"))
    if a.has(r"\bdescription\b"):
        return _plain(a, extra("description"))
    if all(r["origin"] == "autoruns" for r in rows):
        if a.has(r"\bsign\w*|\bpublisher\b"):
            v = extra("signer")
            if v is None:
                return None
            bare = re.sub(r"^\((?:Verified|Not verified)\)\s*", "", v, flags=re.I)
            return _plain(a, v) if bare == v else pick("signer/autoruns", [(n, o) for n, o in (("name", bare), ("as_recorded", v)) if _fits(a.q, o)])
        if a.has(r"\bcompany\b"):
            return _plain(a, extra("company"))
        if a.has(r"image ?path") and not a.has(r"launch string|\bcommand\b"):
            return _plain(a, extra("image_path"))
    if a.has(r"\b(?:process|image|program|executable|binary) (?:that|which) (?:\w+ )?(?:created|set|wrote|added|modified|installed|"
             r"registered|made|dropped)\b|(?:which|what) (?:process|image)\b"):
        imgs = [r["extra"].get("image") for r in rows]
        v = one(imgs) if all(imgs) else None
        if v is None:
            return None
        opts = [(n, o) for n, o in (("image", v), ("basename", base(v))) if _fits(a.q, o)]
        return _plain(a, v) if a.has(r"\bimage\b|\bpath\b") else pick("actor/process", opts)
    if a.has(r"name of the (?:process|program|user|account|host|computer|file|parent|image|group|domain|attacker|malware|threat|tool)\b"):
        return NA
    col, both = _column(a)
    if col is None:
        return NA
    if a.has(r"\barguments?\b") and col == "command":
        return _plain(a, one(r["extra"].get("args") for r in rows)) if all("args" in r["extra"] for r in rows) else None
    if col == "name" and a.has(r"value name"):
        rows = [r for r in rows if r["extra"].get("value_name") is not None] or rows
        v = one(r["extra"].get("value_name", r["name"]) for r in rows)
        return _plain(a, v)
    if one(r["mechanism"] for r in rows) == "ifeo_debugger" and col == "command" \
            and a.has(r"(?:which|what) (?:executable|binary|program|process|image)\b.{0,60}\b(?:has|have|had|is|was|targeted)\b"):
        col, both = "name", False       # the program the debugger is attached to is the entry's name
    if col == "author" and not a.has(r"\bauthor\b|\bsigner\b|\bpublisher\b|\bcompany\b|run ?as\b|service account|"
                                     r"\b(?:runs?|running|executes?) (?:as|under)\b|log ?on as"):
        mech_ = one(r["mechanism"] for r in rows)
        if mech_ in ("windows_service", "scheduled_task"):     # who installed or created it, not whom it runs as
            who = [r["extra"].get("installed_by") or r["extra"].get("created_by") for r in rows]
            return _user_value(a, one(who)) if all(who) else None
    values = [r[col] for r in rows]
    if any(v in (None, "") for v in values):
        return None
    v = one(values)
    if v is None:
        return None
    r = rows[0]
    mech = one(x["mechanism"] for x in rows) or "unknown"
    if col == "trigger":
        if v in TRIGGER_NAMES:
            return pick(f"trigger/{mech}.{v}", [o for o in TRIGGER_NAMES[v] if _fits(a.q, o)])
        if a.has(r"how often|\binterval\b|when does|\bfrequency\b") and not a.has(r"\bschedule\b|\bexpression\b|\bcron ?tab\b|\bwql\b|\bquery\b"):
            # the schedule as written is one way to say how often; words ('every 5 minutes') are another
            return pick(f"trigger/{mech}.as_written", [("as_written", v)] if _fits(a.q, v) else [])
        return _plain(a, v) if not any(x["extra"].get("carved") for x in rows) else pick("trigger/carved", [("carved", v)])
    if any(x["extra"].get("carved") for x in rows) and col == "command":
        return pick("wmi_command/objects_data", [("after_class_name", v)] if _fits(a.q, v) else [])
    if any(x["extra"].get("form_unknown") for x in rows) and col in ("command", "author"):
        alt = one(x["extra"].get("command_if_system") for x in rows)
        if col == "author":
            return pick("cron_user/form", [("system_crontab", one(x["extra"].get("user_if_system") for x in rows))])
        return pick("cron_command/form", [(n, o) for n, o in (("user_crontab", v), ("system_crontab", alt)) if o and _fits(a.q, o)])
    if col == "name" and mech == "scheduled_task" and (one(x["extra"].get("name_from") for x in rows) == "uri" or "\\" in v.strip("\\")):
        leaf = v.strip("\\").rsplit("\\", 1)[-1]
        if leaf == v:
            return _plain(a, v)
        return pick("task_name/uri", [(n, o) for n, o in (("leaf", leaf), ("uri", v)) if _fits(a.q, o)])
    if col == "name" and any(x["extra"].get("name_from") == "file_stem" for x in rows):
        return pick("task_name/file", [("file_stem", v)] if _fits(a.q, v) else [])
    if col == "location" and all(x["origin"] == "sysmon:13" for x in rows):
        full = one(x["extra"].get("target_object") for x in rows)
        return pick("key_path/sysmon", [(n, o) for n, o in (("key", v), ("target_object", full)) if o and _fits(a.q, o)])
    if col == "command":
        exe, args = one(x["extra"].get("exe") for x in rows), one(x["extra"].get("args") for x in rows)
        asks_exe = a.has(r"\bexecutable\b|\bbinary\b|\bprogram\b|\btarget\b|\bfile\b(?! ?name)") \
            and not a.has(r"\bcommand\b|launch string|image ?path|value data|\bdata\b|\barguments?\b|service file ?name|binary ?path")
        if asks_exe and not exe:
            # no reader split the command: the program is its quoted head, else the text up to the
            # first program-like extension, else its first word (offered unsure, never plain)
            mm = re.match(r'\s*"([^"]+)"', v) or re.match(r"\s*(.+?\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|scr|sh|py))(?=\s|$)", v, re.I) \
                or re.match(r"\s*(\S+)", v)
            exe = mm.group(1) if mm else None
            args = args or (v.strip() != exe and "rest") or None
        if both or (a.has(r"\bexecutable\b|\bbinary\b|\bprogram\b|image ?path") and not a.has(r"\bcommand\b|launch string") and exe and args) \
                or (asks_exe and exe and v.strip() != exe):
            exe = exe or v.strip().strip('"').split(" ")[0]
            opts = [("command", v), ("executable", exe), ("basename", base(exe))] if not both else \
                   [("basename", base(exe)), ("executable", exe), ("command", v)]
            opts = [(n, o) for n, o in opts if o and _fits(a.q, o)]
            if len({o for _, o in opts}) == 1:
                return opts[0][1]
            return pick(f"command/{'name' if both else 'executable'}.{r['origin'].split(':')[0]}", opts)
    return _plain(a, v)


# The program a question names is not the one it asks about: 'the child of X', 'the file dropped by X',
# 'the process that spawned X'.
_REL = (r"\b(?:child(?:ren)?|parent|grandparent) of\b|\b(?:process|program|image|executable|binary|file|script|parent|child) "
        r"(?:that|which) (?:\w+ ){0,2}(?:spawned|launched|started|created|dropped|wrote|downloaded|executed|ran|installed|loaded|opened)\b")
_BY = r"\b(?:spawned|launched|started|created|dropped|written|downloaded|executed|run|installed|loaded|opened) by\b"


def _named_process(a: Ask, col: str, subject="image"):
    procs, used = _process_set(a, subject)
    if not procs:
        return None
    return one(p[col] for p in procs) if all(p[col] for p in procs) else None


def h_parent_cmd(a: Ask):
    if not a.has(r"parent(?:'s)? command ?line|command ?line of (?:the|its) parent"):
        return NA
    return _plain(a, _named_process(a, "parent_command_line"))


def h_parent(a: Ask):
    if not a.has(r"\bparent\b|spawned by|launched by|started by|which process (?:spawned|launched|started|created)|"
                 r"what process (?:spawned|launched|started|created)"):
        return NA
    if a.has(r"(?:created|wrote|dropped) (?:the |a )?file\b|file creat\w*") and not a.has(r"\bparent\b"):
        return NA               # who wrote a file is Sysmon 11's Image, not a process's parent
    if a.has(r"grandparent|parent of the parent|parent's parent|\bchild(?:ren)? of\b|command ?line|\bsha-?\d+\b|\bmd5\b") \
            or re.search(r"(?:spawned|launched|started|created|executed) by (?:the )?(?:\w+ )?[`\"']?[\w.\\:$-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr)\b",
                         a.raw, re.I):
        return None             # the parent of something other than the program named, or its child ('spawned by X')
    if a.has(r"\bpid\b|process id|\bguid\b|\bhash\b|\buser\b"):
        procs, used = _process_set(a)
        if not a.has(r"\bpid\b|process id") or not procs or any(p["parent_pid"] is None for p in procs):
            return None
        return _plain(a, one(p["parent_pid"] for p in procs))
    v = _named_process(a, "parent_image")
    if v is None:
        return None
    if a.has(r"parent ?image|\bpath\b|full path|parentimage"):
        return _plain(a, v)
    opts = [(n, o) for n, o in (("image", v), ("basename", base(v))) if _fits(a.q, o)]
    if len({o for _, o in opts}) == 1:
        return opts[0][1]
    return pick("parent/process", opts)


def h_child(a: Ask):
    if not a.has(r"child process|children|what (?:process|program|executable) did .{0,80}(?:spawn|launch|start|execute|run|create)|"
                 r"which (?:process|program|executable) did .{0,80}(?:spawn|launch|start|execute|run|create)|\bspawn(?:s|ed)?\b"):
        return NA
    procs, used = _process_set(a, "parent_image")
    if not used or not procs:
        return None
    if a.has(r"command ?line"):
        return _plain(a, one(p["command_line"] for p in procs))
    v = one(p["image"] for p in procs)
    if v is None:
        return None
    if a.has(r"\bimage\b|\bpath\b"):
        return _plain(a, v)
    opts = [(n, o) for n, o in (("image", v), ("basename", base(v))) if _fits(a.q, o)]
    return opts[0][1] if len({o for _, o in opts}) == 1 else pick("child/process", opts)


def h_hash(a: Ask):
    m = re.search(r"\b(sha-?256|sha-?1|md5|imphash)\b", a.text)
    if not m:
        return NA
    algo = m.group(1).replace("-", "")
    if a.has(_REL) or a.has(_BY):
        return None
    procs, used = _process_set(a)
    vals = [p["hashes"].get(algo) for p in procs]
    rows, mechs = a.candidates()
    if rows and all(r["extra"].get("hashes") for r in rows) and (mechs or a.has(r"autoruns?|\bentry\b|persist\w*")):
        procs, vals = [None], [r["extra"]["hashes"].get(algo) for r in rows]
    if not procs:
        events, used = a.narrow([e for e in a.events if fget(e, "Hashes")],
                                lambda e: [fget(e, "ImageLoaded"), fget(e, "TargetFilename"), fget(e, "Image")])
        vals = [hashes_of(fget(e, "Hashes")).get(algo) for e in events]
        rows, _ = a.candidates()
        if not events and rows:
            vals = [r["extra"].get("hashes", {}).get(algo) for r in rows]
    if not vals or any(not v for v in vals):
        return None
    v = one(vals)
    if v is None:
        return None
    opts = [(n, o) for n, o in (("lower", v.lower()), ("as_recorded", v)) if _fits(a.q, o)]
    if re.search(r"upper-?case", a.syntax + " " + a.raw, re.I):
        return _plain(a, v.upper())
    if re.search(r"lower-?case", a.syntax + " " + a.raw, re.I) or len({o for _, o in opts}) == 1:
        return opts[0][1] if opts else None
    return pick("hash/case", opts)


def h_pid(a: Ask):
    if not a.has(r"\bpid\b|process id\b"):
        return NA
    if a.has(_REL) or a.has(_BY):
        return None
    procs, used = _process_set(a)
    if not used or not procs or any(p["pid"] is None for p in procs):
        return None
    return _plain(a, one(p["pid"] for p in procs))


def h_cmdline(a: Ask):
    if not a.has(r"command ?line|full command|what command (?:was|did)|which command (?:was|did)"):
        return NA
    if a.has(_REL) or a.has(_BY):
        return None
    return _plain(a, _named_process(a, "command_line"))


_FIELD_BY_ID = {4624: "TargetUserName", 4625: "TargetUserName", 4648: "TargetUserName", 4672: "SubjectUserName",
                4688: "SubjectUserName", 1102: "SubjectUserName", 4698: "SubjectUserName", 4697: "SubjectUserName",
                104: "SubjectUserName"}


def _user_value(a: Ask, v):
    if v is None:
        return None
    if "\\" in v:
        opts = [(n, o) for n, o in (("as_recorded", v), ("no_domain", v.split("\\")[-1])) if _fits(a.q, o)]
        return pick("user/domain", opts)
    return _plain(a, v)


def h_created_user(a: Ask):
    if not a.has(r"(?:user|account)(?: name)? (?:was |were |did .{0,40})?creat\w*|new (?:local )?(?:user|account)|"
                 r"created (?:a |the )?(?:new )?(?:local )?(?:user|account)|creat\w* (?:user|account)|rogue (?:user|account)|"
                 r"backdoor (?:user|account)"):
        return NA
    events = select(a.events, 4720)
    if not events:
        return NA
    if a.has(r"\bsid\b"):
        return _plain(a, one(fget(e, "TargetSid") for e in events)) if all(fget(e, "TargetSid") for e in events) else None
    if a.has(r"password|privilege|\bgroup\b|\bhost\b|\bcomputer\b|address|\bip\b|\bdomain\b|description|full name|"
             r"command ?line|\bcommands?\b|\bprocess\w*|\bparent\b|\bimage\b|\bpath\b|\bhash\b|\btool\b|\bprogram\b|\bbinary\b|"
             r"\bexecutable\b|\bscript\b|\bpid\b|logon ?type|\bevent ?id\b|\bworkstation\b"):
        return None             # something about the creation other than the name: not read here
    if a.has(r"\bwho\b|which (?:user|account) created|what (?:user|account) created|creator"):
        return _plain(a, one(fget(e, "SubjectUserName") for e in events))
    return _plain(a, one(fget(e, "TargetUserName") for e in events))


def h_group(a: Ask):
    if not a.has(r"(?:which|what) (?:local |security )?group|group(?:'s)? name|name of the (?:local |security )?group|added to"):
        return NA
    events = [e for i in (4732, 4728, 4756) for e in select(a.events, i)]
    if not events:
        return NA
    if not a.has(r"(?:which|what) (?:local |security )?group|group(?:'s)? name|name of the (?:local |security )?group"):
        return None             # who was added: the event names a SID, and which form is wanted is not said
    events, _ = a.narrow(events, lambda e: list(e["fields"].values()))
    return _plain(a, one(fget(e, "TargetUserName", "GroupName") for e in events))


def h_bruteforce(a: Ask):
    if not a.has(r"brute.?forc\w*|password (?:spray|guess)\w*|attack(?:er|ing)(?:'s)? (?:ip|address|host|source)|"
                 r"source (?:ip|address)|ip address|from (?:which|what) (?:ip|address|host)|compromised (?:account|user)|"
                 r"\bworkstation\b"):
        return NA
    if not a.has(r"brute|password|log-?[oi]n|logged|authenticat\w*|attack\w*|compromis\w*|\brdp\b|\bsmb\b|\bssh\b") \
            or any(_FILELIKE.fullmatch(t) for t in a.tokens):
        return NA
    bf = brute_force(a.events)
    if not bf:
        return NA
    if a.has(r"\bdomain\b|\bsid\b|\bpassword\b|\bport\b|logon ?type|\bhash\b"):
        return None             # a property of the account or logon that this reader does not answer
    hit = [r for r in bf if r["successes"]]
    cand = hit if hit else bf
    if len(cand) != 1:
        return None
    r = cand[0]
    if a.has(r"which (?:account|user)|what (?:account|user)|user ?name|account name|compromised (?:account|user)"):
        if not a.has(r"compromis\w*|target\w*|victim|against|guess\w*|success\w*|brute.?forced|logged (?:on|in)|gain\w* access"):
            return None         # who attacked is not in a logon event; only whom
        return _plain(a, one(fget(e, "TargetUserName") for e in r["successes"])) if r["successes"] else _plain(a, one(r["users"]))
    if a.has(r"\bworkstation\b"):
        return _plain(a, one(fget(e, "WorkstationName") for e in r["events"]))
    if a.has(r"\bip\b|address|source|from (?:which|what)"):
        if not a.has(r"brute|password|log-?[oi]n|logged|authenticat\w*|\brdp\b|\bsmb\b|\bssh\b|failed") and select(a.events, 3, "sysmon"):
            return None         # 'the attacker's address' with network connections in the same delivery: which one is not said
        return _plain(a, r["source"]) if _IPV4.fullmatch(r["source"]) or ":" in r["source"] else None
    return NA


def _camel_words(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name).replace("_", " ").lower()


def h_field(a: Ask):
    """A field the question names in so many words (TargetFilename, 'target filename', LogonType),
    read from the events of the id or phrase it gives."""
    es = a.eventset()
    if es is None:
        return None
    if es is NA:
        return NA
    events, label = es
    if not events:
        return None
    names = {}
    for e in events:
        for k in e["fields"]:
            names.setdefault(k, None)
    best = None
    for k in names:
        if len(k) < 4:
            continue
        words = _camel_words(k)
        hit = re.search(r"(?<![A-Za-z0-9])" + re.escape(k) + r"(?![A-Za-z0-9])", a.raw) is not None and k != k.lower()
        if " " in words:        # a name of two words or more, spelled out or as the answer id writes it
            hit = hit or re.search(r"(?<![a-z0-9])" + re.escape(words) + r"(?![a-z0-9])", a.text) is not None
        else:                   # one word (Image, User, Details): only when the question marks it as a field
            hit = re.search(r"(?:\bfield\s+[`'\"]?" + re.escape(k) + r"\b|[`'\"]" + re.escape(k) + r"[`'\"]|\b" + re.escape(k)
                            + r"[`'\"]?\s+(?:field|value)\b|\bvalue of\s+[`'\"]?" + re.escape(k) + r"\b)", a.raw, re.I) is not None \
                or (k[:1].isupper() and re.search(r"\bthe " + re.escape(k) + r" (?:of|in|for)\b", a.raw) is not None)
        if hit and (best is None or len(k) > len(best)):
            best = k
    if best is None:
        return NA
    events, _ = a.narrow(events, lambda e: [v for k, v in e["fields"].items() if k != best] + [e["host"]])
    first, last = a.has(r"\b(first|earliest)\b"), a.has(r"\b(last|latest|most recent)\b")
    if first != last and events and all(e["_dt"] for e in events):
        events = [(min if first else max)(events, key=lambda x: x["_dt"])]
    return _plain(a, one(fget(e, best) for e in events)) if all(fget(e, best) for e in events) else None


_SEMANTIC = (
    # (question words, (channel, id) list, field names, value shaping)
    (r"logon type", (("security", 4624), ("security", 4625)), ("LogonType",), None),
    (r"\bdns\b|domain (?:name )?(?:was |were )?(?:queried|resolved|looked up|requested)|query ?name|"
     r"(?:queried|resolved|looked up)\b.{0,30}\bdomain|domain\b.{0,40}\b(?:quer|resolv|look)", (("sysmon", 22),), ("QueryName",),
     (None, r"resolv\w* to\b|query ?results?|\banswers?\b|\bip(?:v4)?\b|\baddress\b|\bstatus\b|\bprocess\b|\bimage\b")),
    (r"destination port|remote port|(?:which|what) port\b.{0,60}\bconnect\w*|port\b.{0,40}\bconnect\w*", (("sysmon", 3),), ("DestinationPort",), None),
    (r"destination (?:ip|address|host)|remote (?:ip|address)|\b(?:ip|address)\b.{0,60}\bconnect\w*|connect\w* to|"
     r"network connection\b.{0,60}\b(?:ip|address|go|to)\b", (("sysmon", 3),), ("DestinationIp",),
     (r"\bip(?:v4)?\b|\baddress\b", r"\bdomain\b|\bhost ?name\b|\bfqdn\b|\burl\b|\bsource (?:ip|address)\b")),
    (r"threat name|detection name|(?:which|what) (?:malware|threat)|malware name", (("defender", 1116), ("defender", 1117)), ("ThreatName", "Threat Name"), None),
    (r"files? (?:was |were )?(?:created|dropped|written)|created file|dropped file|target ?file ?name|file creat\w*|"
     r"\b(?:drop(?:s|ped)?|wrote|writes?)\b.{0,40}\bfile", (("sysmon", 11),), ("TargetFilename",), None),
    (r"target ?object", (("sysmon", 13), ("sysmon", 12)), ("TargetObject",), None),
)


def h_actor(a: Ask):
    if not a.has(r"(?:which|what) (?:process|image|program|executable|binary)\b|name of the (?:process|program|executable)\b"):
        return NA
    es = a.eventset()
    if es is None:
        return None
    if es is NA:
        return NA
    events, label = es
    if not label.startswith("sysmon") or label.endswith(":1"):
        return NA if label.endswith(":1") else None
    events, _ = a.narrow(events, lambda e: [v for k, v in e["fields"].items() if _norm(k) != "image"] + [e["host"]])
    field = "SourceImage" if label.endswith((":8", ":10")) else "Image"
    if not events or any(not fget(e, field) for e in events):
        return None
    v = one(fget(e, field) for e in events)
    if v is None:
        return None
    opts = [(n, o) for n, o in (("image", v), ("basename", base(v))) if _fits(a.q, o)]
    return _plain(a, v) if a.has(r"\bimage\b|\bpath\b") else pick("actor/process", opts)


def h_semantic(a: Ask):
    for rx, pairs, fields, shape in _SEMANTIC:
        if not a.has(rx):
            continue
        present = [(c, i, select(a.events, i, c)) for c, i in pairs]
        present = [p for p in present if p[2]]
        if not present:
            continue
        needs, never = shape or (None, None)
        if (needs and not a.has(needs)) or (never and a.has(never)):
            return None         # the event is the one meant, the field asked for is another
        vals = []
        for c, i, events in present:
            events, _ = a.narrow(events, lambda e: list(e["fields"].values()) + [e["host"]])
            if any(not fget(e, *fields) for e in events):
                return None
            if (c, i) == ("sysmon", 3):
                # Sysmon writes an accepted connection with Initiated=false: its destination is the
                # host itself, and the program "connected to" nothing. And "which address connected
                # to X" asks for the source. Neither is the DestinationIp/Port of these events.
                if a.has(r"\b(?:ips?|address(?:es)?|hosts?)\s+(?:that\s+|which\s+)?(?:connect(?:ed|s)|reach(?:ed|es))\b|\binbound\b|\bincoming\b|"
                         r"\bconnect\w* from\b|\blisten\w*\b"):
                    return None
                if a.has(r"connect\w*|\bc2\b|beacon\w*|call\w* (?:back|out)|reach\w*|outbound") \
                        and any(str(fget(e, "Initiated") or "").strip().lower() == "false" for e in events):
                    return None
            vals += [fget(e, *fields) for e in events]
        v = one(vals)
        if v is None:
            return None
        return _plain(a, v)
    return NA


def h_user(a: Ask):
    if not a.has(r"(?:which|what) (?:user|account)|user ?name|account name|\bwho\b|under (?:which|what) (?:user|account)"):
        return NA
    es = a.eventset()
    if es is None:
        return None
    if es is not NA:
        events, label = es
        eid = int(label.split(":")[1])
        events, _ = a.narrow(events, lambda e: list(e["fields"].values()) + [e["host"]])
        field = _FIELD_BY_ID.get(eid, "User" if label.startswith("sysmon") else None)
        if not field or not events or any(not fget(e, field) for e in events):
            return None
        return _user_value(a, one(fget(e, field) for e in events))
    if a.has(_REL):
        return None
    procs, used = _process_set(a)
    if not used or not procs or any(not p["user"] for p in procs):
        return None
    return _user_value(a, one(p["user"] for p in procs))


def h_host(a: Ask):
    if not a.has(r"(?:computer|host|machine|endpoint|workstation) ?name|(?:which|what) (?:host|machine|computer|endpoint)"):
        return NA
    if a.has(r"\bc2\b|\bserver\b|\bdomain\b|\bremote\b|attacker|destination|\burl\b|download|connect\w*|quer\w*"):
        return NA
    es = a.eventset()
    events = a.events if es in (None, NA) else es[0]
    events, _ = a.narrow(events, lambda e: list(e["fields"].values()))
    v = one(e["host"] for e in events)
    if v is None or any(not e["host"] for e in events):
        return None
    if "." in v:
        return pick("host/fqdn", [(n, o) for n, o in (("as_recorded", v), ("short", v.split(".")[0])) if _fits(a.q, o)])
    return _plain(a, v)


def h_indicator(a: Ask):
    if not a.has(r"\burls?\b|download\w* from|web address"):
        return NA
    return _indicator(a, _texts(a))


HANDLERS = (h_technique, h_mechanism, h_decoded, h_count, h_time, h_group, h_persistence, h_created_user, h_bruteforce,
            h_parent_cmd, h_parent, h_child, h_hash, h_cmdline, h_pid, h_actor, h_field, h_semantic, h_user, h_host, h_indicator)


_NEGATED = re.compile(r"\b(?:did|does|do|was|were|is|are|has|have|had|could|can|should|would)(?: not\b|n['’]t\b)|\bnever\b|\bexcept\b|\bexcluding\b|"
                      r"\bother than\b|\bapart from\b|\bbesides\b|\baside from\b|\brather than\b|\binstead of\b|\bnot (?:the|a|an|by|from|in|run|made|created|"
                      r"started|spawned|launched|executed|signed)\b", re.I)


def answer(q, model: Model):
    """One question's answer: plain, an unsure pick, or None."""
    if model.empty():
        return None
    if _FOREIGN.search(str(q.get("question") or "")) or str(_fmt(q).get("kind") or "") in ("json", "ordered_tokens"):
        return None
    a = Ask(q, model)
    if _NEGATED.search(a.raw) and not re.search(r"\bnot (?:digitally )?(?:signed|verified)\b", a.raw, re.I):
        return None           # a negation or an exclusion: no handler applies one, and each answered as if it were not there
    for h in HANDLERS:
        a.twins = None
        got = h(a)
        if got is NA:
            continue
        if a.twins and got is not None and not labels.is_unsure(got):
            return None         # one bare name, two programs: see Ask.narrow
        if got is None or labels.is_unsure(got) or not model.damaged:
            return got
        # Part of the delivery was not read (a cut line, a cap, an unopened archive). A count is then
        # a lower bound and 'the only one' is not proven: no count, and anything else only as unsure.
        if h is h_count:
            return None
        return pick(f"incomplete/{h.__name__[2:]}", [("as_read", got)])
    return None


def solve_set(questions, files, ctx) -> dict:
    out = {}
    try:
        model = Model(files)
    except Exception:
        return {q.get("qid") or q.get("id"): None for q in questions}
    partial = ctx.setdefault("partial", {}) if isinstance(ctx, dict) and isinstance(ctx.get("partial", {}), dict) else {}
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            out[qid] = answer(q, model)
        except Exception:           # a fact that cannot be read is no answer
            out[qid] = None
        if out[qid] is not None:
            partial[qid] = out[qid]
    return out


# ---- the command ------------------------------------------------------------------------------------

_SUSPECT = ((r"(?i)-e(?:nc\w*|c)?\s+[A-Za-z0-9+/=]{20,}", "encoded command"), (r"(?i)frombase64string", "base64 decode"),
            (r"(?i)\\(?:appdata|temp|programdata|users\\public)\\|/tmp/|/dev/shm/", "user-writable path"),
            (r"(?i)\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec|curl|wget|nc|bash -c|python\d? -c)\b", "lolbin"),
            (r"(?i)https?://", "url"), (r"(?i)-w(?:indowstyle)?\s+hid|-nop\b|bypass", "hidden or bypass"))


def flags(command) -> list:
    """Why a command line deserves a look. For the reader only: no answer is built on it."""
    return [why for rx, why in _SUSPECT if command and re.search(rx, command)]


def load_paths(paths) -> dict:
    """{name: bytes} of files, of every file under a directory, and of a zip's members."""
    import zipfile
    files, budget = {}, 256 * 1024 * 1024       # of unpacked members in all: a small zip can declare a lot
    for p in paths:
        p = Path(p)
        todo = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
        for f in todo:
            data = f.read_bytes()
            name = str(f.relative_to(p)) if p.is_dir() else f.name
            files[name] = data
            if data[:4] == b"PK\x03\x04":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for info in z.infolist()[:500]:
                            if not info.is_dir() and info.file_size <= min(MAX_FILE, budget):
                                budget -= info.file_size
                                try:
                                    files[f"{name}{ARROW}{info.filename}"] = z.read(info)
                                except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                                    pass
                except zipfile.BadZipFile:
                    pass
    return files


def report(files: dict) -> dict:
    m = Model(files)
    procs = m.procs
    decoded = []
    for cmd in dict.fromkeys([p["command_line"] for p in procs] + [r["command"] or "" for r in m.rows]):
        layers = m.decoded(cmd)
        if layers:
            decoded.append({"command": cmd, "layers": layers})
    times = [e["_dt"] for e in m.events if e["_dt"]]
    return {
        "signal": signals([], files), "sources": m.sources, "events": len(m.events),
        "not_read_whole": [{"file": n, "why": w} for n, w in dict.fromkeys(m.damaged)],
        "hosts": sorted({e["host"] for e in m.events if e["host"]}),
        "first": iso(min(times)) if times else None, "last": iso(max(times)) if times else None,
        "summary": [{"channel": c, "event_id": i, "count": n, "name": nm} for c, i, n, nm in summary(m.events)],
        "process_tree": render_tree(procs), "decoded": decoded,
        "brute_force": [{"source": r["source"], "failures": r["failures"], "users": r["users"],
                         "first": iso(r["first"]) if r["first"] else None, "last": iso(r["last"]) if r["last"] else None,
                         "successes": [{"time_utc": e["time_utc"], "user": fget(e, "TargetUserName"), "logon_type": fget(e, "LogonType")}
                                       for e in r["successes"]]} for r in brute_force(m.events)],
        "created_users": [{"time_utc": e["time_utc"], "user": fget(e, "TargetUserName"), "by": fget(e, "SubjectUserName")}
                          for e in select(m.events, 4720)],
        "group_adds": [{"time_utc": e["time_utc"], "group": fget(e, "TargetUserName"), "member": fget(e, "MemberName") or fget(e, "MemberSid"),
                        "by": fget(e, "SubjectUserName")} for i in (4732, 4728, 4756) for e in select(m.events, i)],
        "logs_cleared": [{"time_utc": e["time_utc"], "by": fget(e, "SubjectUserName"), "channel": chan(e)}
                         for i in (1102, 104) for e in select(m.events, i)],
        "script_blocks": [{k: b[k] for k in ("id", "parts", "total", "complete", "time_utc", "path", "text")} for b in script_blocks(m.events)],
        "defender": [{"time_utc": e["time_utc"], "threat": fget(e, "ThreatName", "Threat Name"), "path": fget(e, "Path")}
                     for i in (1116, 1117) for e in select(m.events, i)],
        "persistence": [dict({k: r[k] for k in ("mechanism", "technique", "location", "name", "command", "author", "trigger", "origin")},
                             source=r["source"].split(ARROW)[-1], flags=flags(r["command"]),
                             default=bool(r["extra"].get("default"))) for r in m.rows],
    }


def render(rep: dict) -> str:
    out = [f"EDR/persistence triage: signal={rep['signal']} events={rep['events']} rows={len(rep['persistence'])} "
           f"sources={len(rep['sources'])}"]
    if rep.get("not_read_whole"):
        out.append("NOT READ WHOLE (no count is answered, and every other answer only as unsure):")
        out += [f"  {d['file']}: {d['why']}" for d in rep["not_read_whole"]]
    if rep["events"]:
        out.append(f"hosts: {', '.join(rep['hosts']) or '-'}   first: {rep['first']}   last: {rep['last']}")
        out.append("\nEVENTS (channel, id, count)")
        out += [f"  {r['channel'] or '?':<12} {str(r['event_id']):>5} x{r['count']:<5} {r['name']}" for r in rep["summary"]]
    if rep["process_tree"]:
        out.append("\nPROCESS TREE")
        out += ["  " + line for line in rep["process_tree"]]
    for d in rep["decoded"]:
        out.append("\nDECODED " + d["command"][:120])
        out += [f"  layer {i}: {layer.strip()[:600]}" for i, layer in enumerate(d["layers"], 1)]
    for r in rep["brute_force"]:
        out.append(f"\nFAILED LOGONS from {r['source']}: {r['failures']} ({r['first']} .. {r['last']}) users={','.join(r['users'])}")
        out += [f"  then SUCCESS {s['time_utc']} user={s['user']} type={s['logon_type']}" for s in r["successes"]]
    for key, title in (("created_users", "USER CREATED"), ("group_adds", "GROUP ADD"), ("logs_cleared", "LOG CLEARED"), ("defender", "DEFENDER")):
        out += [f"{title} " + " ".join(f"{k}={v}" for k, v in r.items()) for r in rep[key]]
    for b in rep["script_blocks"]:
        out.append(f"\nSCRIPT BLOCK {b['id']} parts={b['parts']}/{b['total']} complete={b['complete']}\n  " + b["text"].strip()[:800].replace("\n", "\n  "))
    if rep["persistence"]:
        out.append("\nPERSISTENCE (mechanism | technique | location | name | command | author | trigger)")
        for r in rep["persistence"]:
            out.append("  " + " | ".join(str(r[k] if r[k] is not None else "-") for k in
                                         ("mechanism", "technique", "location", "name", "command", "author", "trigger"))
                       + f"   [{r['origin']} {r['source']}]" + (f" FLAGS {', '.join(r['flags'])}" if r["flags"] else "")
                       + (" (default value)" if r["default"] else ""))
    if not rep["events"] and not rep["persistence"]:
        out.append("nothing read: no event export and no persistence artefact among the files (binary EVTX is row 86's)")
    return "\n".join(out)


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if not args:
        print("usage: edr_persistence.py [--json] <file|dir|zip>...", file=sys.stderr)
        return 2
    missing = [a for a in args if not Path(a).exists()]
    if missing:
        print(f"edr_persistence.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    rep = report(load_paths(args))
    print(json.dumps(rep, indent=1, ensure_ascii=False) if "--json" in argv else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
