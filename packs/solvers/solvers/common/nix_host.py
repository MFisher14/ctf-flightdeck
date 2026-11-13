#!/usr/bin/env python3
"""Linux and macOS host forensics: the readers of toolkit `nix_host` (standard library only).

Every function takes text or bytes and returns plain Python values; nothing here makes a request,
starts a process or writes a file. solvers/toolkits/nix_host.py holds the question logic, the
lane signal and the command; this file is what an agent imports to read one artifact by hand:

    sys.path.insert(0, "solvers/common"); import nix_host as nh
    recs = nh.parse_syslog(text)             # RFC 3164, RFC 5424 and ISO-stamped lines
    nh.ssh_events(recs)                      # failed / accepted / invalid_user ... per line
    nh.audit_events(nh.parse_audit(text))    # auditd records grouped by audit id, hex decoded

Linux
  parse_syslog, parse_journal_json, parse_docker_log      one record shape for all three
  ssh_events, sudo_events, account_events, cron_runs      what the records say
  ssh_summary, fail_then_success                          per-source counts, the brute-force rule
  parse_audit, audit_events, audit_exec, decode_saddr     auditd, hex arguments and PROCTITLE
  parse_utmp, is_utmp, parse_lastlog                      utmp / wtmp / btmp (384 bytes), lastlog (292)
  parse_crontab, parse_unit, unit_values, exec_strip      crontab and systemd unit files
  parse_passwd, passwd_anomalies, parse_shadow, shadow_anomalies, parse_group
  parse_authorized_keys, parse_ld_preload, parse_history
  decode_layers, innermost                                base64 / hex / \\x / rev inside a command
macOS
  read_plist, is_keyed_archive, unwrap_keyed_archive      XML and binary plists, NSKeyedArchiver
  launchd_job                                             Label, Program, ProgramArguments, RunAtLoad
  read_sqlite, quarantine_events, tcc_access              QuarantineEventsV2 and TCC.db
  parse_quarantine_xattr, parse_unified_log, filter_unified
  ds_store_records, ds_store_names                        the names a .DS_Store remembers
  mac_time                                                seconds since 2001-01-01 -> datetime

A time is never invented. A syslog line of the RFC 3164 form has no year and no zone: its record
has `time` None, `md` (month, day, hour, minute, second) and `stamp`, the text as written.
prove_year() gives the year another artifact's moment of the very same second would give; that is
a candidate, not a proof (a busy host has a record in every second). The toolkit's Evidence.year_of
asks for the same EVENT in the other artifact and for the file to be shown UTC.
"""
import base64
import binascii
import codecs
import hashlib
import ipaddress
import json
import plistlib
import re
import sqlite3
import struct
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
MAX_LINES = 400000          # lines of one text file read
MAX_ROWS = 20000            # rows read from one sqlite table
MAC_EPOCH = 978307200       # 2001-01-01T00:00:00Z as Unix seconds

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
MONTH_NAMES = {v: k for k, v in MONTHS.items()}


# ---- text ---------------------------------------------------------------------------------------------

def text_of(data):
    """The text of a file, or None when it is not text (NUL bytes outside UTF-16, or not decodable)."""
    if isinstance(data, str):
        return data
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if b"\x00" in data[:65536]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        bad = sum(1 for c in text[:65536] if ord(c) < 9 or 13 < ord(c) < 32)
        return text if bad * 50 <= max(1, len(text[:65536])) else None


def _lines(text):
    for n, line in enumerate(text.splitlines(), 1):
        if n > MAX_LINES:
            return
        yield n, line


# ---- time ---------------------------------------------------------------------------------------------

_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s?(Z|[+-]\d\d:?\d\d)?$")


def parse_iso(text):
    """(datetime, zone given?) of an ISO 8601 stamp; (None, False) when it is not one. The datetime
    is aware when the stamp carries a zone, naive (as written) when it does not."""
    m = _ISO.match(str(text).strip())
    if not m:
        return None, False
    y, mo, d, h, mi, s, frac, zone = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), int((frac or "0")[:6].ljust(6, "0")))
    except ValueError:
        return None, False
    if not zone:
        return dt, False
    if zone == "Z":
        return dt.replace(tzinfo=UTC), True
    sign = 1 if zone[0] == "+" else -1
    hh, mm = int(zone[1:3]), int(zone[-2:])
    try:
        return dt.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm))), True
    except ValueError:      # an offset of 24h or more is not a valid timezone
        return None, False


def from_epoch(seconds):
    """An aware UTC datetime for Unix seconds (int or float); None when out of range."""
    try:
        return datetime.fromtimestamp(float(seconds), UTC)
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def mac_time(seconds):
    """Mac absolute time (seconds since 2001-01-01 UTC, as Cocoa, plists and the quarantine
    database store it) as an aware UTC datetime."""
    try:
        return from_epoch(float(seconds) + MAC_EPOCH)
    except (TypeError, ValueError):
        return None


# ---- syslog -------------------------------------------------------------------------------------------

_MON = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_TAG = r"(?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:(?:\s|$)(?P<msg>.*)$"
_RFC3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<stamp>(?P<mon>" + _MON + r")\s+(?P<day>\d{1,2})\s+"
                      r"(?P<h>\d\d):(?P<mi>\d\d):(?P<s>\d\d))\s+(?P<host>\S+)\s+" + _TAG)
_ISOLINE = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<stamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
                      r"\s+(?P<host>\S+)\s+" + _TAG)
_RFC5424 = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ver>[1-9]\d?)\s(?P<stamp>\S+)\s(?P<host>\S+)\s(?P<app>\S+)\s"
                      r"(?P<pid>\S+)\s(?P<msgid>\S+)\s?(?P<rest>.*)$")
_SD = re.compile(r'\[([^\s\]=]+)((?:\s+[^\s\]=]+="(?:[^"\\]|\\.)*")*)\s*\]')
_SDP = re.compile(r'([^\s\]=]+)="((?:[^"\\]|\\.)*)"')


def _pri(rec, pri):
    if pri is not None and int(pri) <= 191:
        rec["pri"], rec["facility"], rec["severity"] = int(pri), int(pri) >> 3, int(pri) & 7


def parse_syslog_line(line, n=0):
    """One record, or None for a line that is not syslog. Keys: line, raw, fmt ('rfc3164',
    'rfc5424' or 'iso'), stamp (the time as written), time (datetime or None: RFC 3164 has no
    year), tz (zone given?), md ((month, day, h, m, s) for rfc3164), host, app, pid, msg, and
    pri/facility/severity, msgid, sd when the line has them."""
    line = line.rstrip("\r\n")
    m = _RFC5424.match(line)
    if m:
        dt, tz = (None, False) if m["stamp"] == "-" else parse_iso(m["stamp"])
        if m["stamp"] == "-" or dt is not None:
            rest, sd = m["rest"], {}
            if rest.startswith("-"):
                rest = rest[1:]
            else:
                while rest.startswith("["):
                    e = _SD.match(rest)
                    if not e:
                        break
                    sd[e.group(1)] = {k: re.sub(r'\\(["\\\]])', r"\1", v) for k, v in _SDP.findall(e.group(2))}
                    rest = rest[e.end():]
            rec = {"line": n, "raw": line, "fmt": "rfc5424", "stamp": m["stamp"], "time": dt, "tz": tz, "md": None,
                   "host": None if m["host"] == "-" else m["host"], "app": None if m["app"] == "-" else m["app"],
                   "pid": None if m["pid"] == "-" else m["pid"], "msgid": None if m["msgid"] == "-" else m["msgid"],
                   "sd": sd, "msg": rest.lstrip(" ").lstrip("\ufeff")}
            _pri(rec, m["pri"])
            return rec
    m = _RFC3164.match(line)
    if m:
        try:
            md = (MONTHS[m["mon"]], int(m["day"]), int(m["h"]), int(m["mi"]), int(m["s"]))
            datetime(2000, *md)             # 2000 is a leap year: Feb 29 is a date
        except ValueError:
            return None
        rec = {"line": n, "raw": line, "fmt": "rfc3164", "stamp": m["stamp"], "time": None, "tz": False, "md": md,
               "host": m["host"], "app": m["app"], "pid": m["pid"], "msg": m["msg"]}
        _pri(rec, m["pri"])
        return rec
    m = _ISOLINE.match(line)
    if m:
        dt, tz = parse_iso(m["stamp"])
        if dt is None:
            return None
        rec = {"line": n, "raw": line, "fmt": "iso", "stamp": m["stamp"], "time": dt, "tz": tz, "md": None,
               "host": m["host"], "app": m["app"], "pid": m["pid"], "msg": m["msg"]}
        _pri(rec, m["pri"])
        return rec
    return None


def parse_syslog(text):
    """Every syslog record of a text, in file order (see parse_syslog_line). Lines that are not
    syslog are skipped; syslog_share() says how much of the text was read."""
    out = []
    for n, line in _lines(text):
        rec = parse_syslog_line(line, n)
        if rec:
            out.append(rec)
    return out


def syslog_share(text, sample=60):
    """Share of the first non-empty lines that are syslog records (0..1)."""
    seen = hit = 0
    for _, line in _lines(text):
        if not line.strip():
            continue
        seen += 1
        hit += parse_syslog_line(line) is not None
        if seen >= sample:
            break
    return hit / seen if seen else 0.0


def stamp_with_year(rec, year):
    """The naive datetime of an RFC 3164 record in a given year (local time, zone unknown)."""
    try:
        return datetime(year, *rec["md"])
    except (ValueError, TypeError):
        return None


def prove_year(rec, moments):
    """The year of an RFC 3164 record, proven: `moments` are aware datetimes read from other
    artifacts of the same delivery (wtmp, auditd, journald). The year is the one of the moments
    that fall on the record's month, day, hour, minute and second in UTC, when they all agree on
    one year; None otherwise. The caller must know the moments are of this record's own event
    (solvers/toolkits/nix_host.py, Evidence.year_of): the same second alone is a coincidence on a
    busy host, and says nothing of the zone the log was written in."""
    if not rec.get("md"):
        return None
    years = {m.year for m in moments
             if m is not None and (m.astimezone(UTC).month, m.astimezone(UTC).day, m.astimezone(UTC).hour,
                                   m.astimezone(UTC).minute, m.astimezone(UTC).second) == tuple(rec["md"])}
    return years.pop() if len(years) == 1 else None


# ---- journald and Docker (records of the syslog shape) ----------------------------------------------

def _journal_text(v):
    if isinstance(v, list):                 # journald exports a non-UTF-8 field as a list of bytes
        try:
            return bytes(v).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return None
    return v if isinstance(v, str) else (None if v is None else str(v))


def _json_objects(text):
    """The JSON objects of a text: one document (an object or a list) or one object per line."""
    stripped = text.lstrip()
    if stripped[:1] == "[":
        try:
            doc = json.loads(stripped)
            return [(i + 1, o) for i, o in enumerate(doc) if isinstance(o, dict)]
        except ValueError:
            pass
    out = []
    for n, line in _lines(text):
        line = line.strip().rstrip(",")
        if line[:1] != "{":
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o, dict):
            out.append((n, o))
    return out


def parse_journal_json(text):
    """`journalctl -o json` / `-o export`-as-JSON records in the syslog record shape (fmt
    'journal'); `fields` holds the whole entry. __REALTIME_TIMESTAMP is microseconds, UTC."""
    out = []
    for n, o in _json_objects(text):
        if "MESSAGE" not in o and "__REALTIME_TIMESTAMP" not in o:
            continue
        us = o.get("__REALTIME_TIMESTAMP") or o.get("_SOURCE_REALTIME_TIMESTAMP")
        dt = None
        try:
            dt = from_epoch(int(us) / 1e6) if us is not None else None
        except (TypeError, ValueError, OverflowError):
            dt = None
        out.append({"line": n, "raw": json.dumps(o, ensure_ascii=False), "fmt": "journal", "stamp": str(us) if us is not None else None,
                    "time": dt, "tz": dt is not None, "md": None, "host": _journal_text(o.get("_HOSTNAME")),
                    "app": _journal_text(o.get("SYSLOG_IDENTIFIER") or o.get("_COMM")),
                    "pid": _journal_text(o.get("_PID") or o.get("SYSLOG_PID")),
                    "msg": _journal_text(o.get("MESSAGE")) or "", "fields": o})
    return out


_EXPORT_KEY = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def is_journal_export(text) -> bool:
    head = text[:4096]
    return head.startswith("__CURSOR=") and "__REALTIME_TIMESTAMP=" in head


def parse_journal_export(text):
    """`journalctl -o export` records (KEY=value lines, a blank line between entries) in the syslog
    record shape, like parse_journal_json. A field the export wrote in its binary form (a key on a
    line of its own, a length, the bytes: every multi-line message) is not read: the entry keeps
    `binary` with the key's name, and its MESSAGE is then empty."""
    out, cur, first, binary = [], {}, 1, []

    def flush():
        nonlocal cur, binary
        if cur:
            us = cur.get("__REALTIME_TIMESTAMP") or cur.get("_SOURCE_REALTIME_TIMESTAMP")
            try:
                dt = from_epoch(int(us) / 1e6) if us is not None else None
            except (TypeError, ValueError):
                dt = None
            out.append({"line": first, "raw": "\n".join(f"{k}={v}" for k, v in cur.items()), "fmt": "journal",
                        "stamp": str(us) if us is not None else None, "time": dt, "tz": dt is not None, "md": None,
                        "host": cur.get("_HOSTNAME"), "app": cur.get("SYSLOG_IDENTIFIER") or cur.get("_COMM"),
                        "pid": cur.get("_PID") or cur.get("SYSLOG_PID"), "msg": cur.get("MESSAGE") or "", "fields": dict(cur),
                        "binary": list(binary)})
        cur, binary = {}, []

    for n, line in _lines(text):
        if not line.strip():
            flush()
            continue
        if not cur:
            first = n
        m = _EXPORT_KEY.match(line)
        if m:
            cur.setdefault(m.group(1), m.group(2))
        elif re.fullmatch(r"[A-Z_][A-Z0-9_]*", line):
            binary.append(line)                 # the bytes that follow are not KEY=value lines and are skipped
            cur.setdefault("__BINARY_FIELDS__", "1")
    flush()
    return out


def parse_docker_log(text):
    """Docker json-file log lines: [{line, time (datetime or None), stamp, stream, log}]."""
    out = []
    for n, o in _json_objects(text):
        if not ("log" in o and "stream" in o):
            continue
        dt, _ = parse_iso(re.sub(r"(\.\d{6})\d+", r"\1", str(o.get("time") or "")))
        out.append({"line": n, "time": dt, "stamp": o.get("time"), "stream": o.get("stream"),
                    "log": str(o.get("log") or "").rstrip("\n")})
    return out


# ---- what the records say -----------------------------------------------------------------------------

_SSHD = re.compile(r"^sshd(?:-session|-auth)?$", re.I)
_REPEAT = re.compile(r"^message repeated (\d+) times: \[\s?(.*?)\s?\]$")
_SSH = [
    ("failed", re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)(?: \S+)?$")),
    ("accepted", re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)(?: .*)?$")),
    ("invalid_user", re.compile(r"^(?:Invalid|Illegal) user (?P<user>.*?) from (?P<ip>\S+?)(?: port (?P<port>\d+))?$")),
    ("pam_failure", re.compile(r"^pam_unix\(sshd:auth\): authentication failure;.*?\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("max_attempts", re.compile(r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?(?P<user>.*) "
                                r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("closed", re.compile(r"^Connection (?:closed|reset) by (?:(?:authenticating|invalid) user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)")),
    ("disconnect", re.compile(r"^(?:Received disconnect|Disconnected) from (?:(?:authenticating|invalid) user (?P<user>\S+) )?"
                              r"(?P<ip>\S+) port (?P<port>\d+)")),
    ("session_opened", re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)")),
    ("session_closed", re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<user>[^\s(]+)")),
]


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


_SSHD_OLD = re.compile(r"^sshd\(pam_unix\)$", re.I)
_SSH_OLD = [
    ("failed", re.compile(r"^authentication failure;.*?\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("session_opened", re.compile(r"^session opened for user (?P<user>[^\s(]+)")),
    ("session_closed", re.compile(r"^session closed for user (?P<user>[^\s(]+)")),
]


def ssh_events(records):
    """sshd lines as events, in record order: {kind, user, ip, port, method, invalid, n, rec}.
    kind is failed, accepted, invalid_user, pam_failure, max_attempts, closed, disconnect,
    session_opened or session_closed. `n` is how many times the line stands for: rsyslog's
    'message repeated N times: [ ... ]' is one event with n=N (the line it repeats came before
    it, once). `ip` is None when the source is a host name; then `host` has it."""
    out = []
    for rec in records:
        app = rec.get("app") or ""
        old = bool(_SSHD_OLD.match(app))        # the PAM tag of older systems: its lines carry no 'pam_unix(sshd:auth):'
        if not (old or _SSHD.match(app)):
            continue
        msg, n = rec["msg"].strip(), 1
        rep = _REPEAT.match(msg)
        if rep:
            n, msg = int(rep.group(1)), rep.group(2).strip()
        for kind, rx in (_SSH_OLD if old else _SSH):
            m = rx.match(msg)
            if not m:
                continue
            g = m.groupdict()
            src = g.get("ip")
            out.append({"kind": kind, "user": g.get("user"), "ip": src if src and _is_ip(src) else None,
                        "host": src, "port": int(g["port"]) if g.get("port") else None, "method": g.get("method") or ("pam" if old else None),
                        "invalid": bool(g.get("invalid")) or kind == "invalid_user", "n": n, "repeated": bool(rep), "rec": rec})
            break
    return out


FAIL_KINDS = ("failed", "invalid_user", "pam_failure", "max_attempts")


def ssh_summary(events):
    """Per source: {source: {failed, failed_lines, accepted, invalid_user, users_failed,
    users_accepted, first_failed, first_accepted}} (source is the IP, or the host name sshd
    logged). `failed` counts 'Failed <method> for' with repeats, `failed_lines` the lines."""
    out = OrderedDict()
    for e in events:
        src = e["ip"] or e["host"]
        if not src:
            continue
        s = out.setdefault(src, {"failed": 0, "failed_lines": 0, "accepted": 0, "invalid_user": 0, "users_failed": [],
                                 "users_accepted": [], "first_failed": None, "first_accepted": None})
        if e["kind"] == "failed":
            s["failed"] += e["n"]
            s["failed_lines"] += 1
            if e["user"] not in s["users_failed"]:
                s["users_failed"].append(e["user"])
            s["first_failed"] = s["first_failed"] or e["rec"]
        elif e["kind"] == "accepted":
            s["accepted"] += e["n"]
            if e["user"] not in s["users_accepted"]:
                s["users_accepted"].append(e["user"])
            s["first_accepted"] = s["first_accepted"] or e["rec"]
        elif e["kind"] == "invalid_user":
            s["invalid_user"] += e["n"]
    return out


def fail_then_success(events):
    """The sources with a failure and, later in the same record order, an accepted login: the
    brute-force rule. [(source, the accepted event)], each source once, in order."""
    failed, out, seen = Counter(), [], set()
    for e in events:
        src = e["ip"] or e["host"]
        if not src:
            continue
        if e["kind"] in FAIL_KINDS:
            failed[src] += e["n"]
        elif e["kind"] == "accepted" and failed[src] and src not in seen:
            seen.add(src)
            out.append((src, e))
    return out


_SUDO = re.compile(r"^\s*(?P<user>\S+) :\s+(?:(?P<note>[^;=]*?) ; )?(?:TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>.*?) ; USER=(?P<runas>\S+) ;"
                   r"(?: GROUP=\S+ ;)?(?: TSID=\S+ ;)?(?: ENV=.*? ;)? COMMAND=(?P<command>.*)$")
_SUDO_MORE = re.compile(r"^\s*(?P<user>\S+) :\s+\(command continued\) (?P<rest>.*)$")


def sudo_events(records):
    """sudo command lines: {user, runas, tty, pwd, command, note, rec}. `note` is sudo's own
    remark ('3 incorrect password attempts', 'user NOT in sudoers', 'command not allowed')."""
    out = []
    for rec in records:
        if (rec.get("app") or "").lower() != "sudo":
            continue
        m = _SUDO.match(rec["msg"])
        if m:
            out.append({**m.groupdict(), "cut": False, "rec": rec})
            continue
        more = _SUDO_MORE.match(rec["msg"])
        if more:
            # the rest of the command before it (sudo splits a long one): that command is not whole as logged
            for e in reversed(out):
                if e["user"] == more.group("user"):
                    e["cut"] = True
                    e["continued"] = (e.get("continued") or "") + more.group("rest")
                    break
    return out


_ACCOUNT = [
    ("new_user", ("useradd", "adduser"), re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]*), "
                                                    r"shell=(?P<shell>[^,]*)(?:, from=(?P<from>.*))?$")),
    ("new_group", ("useradd", "groupadd", "adduser", "addgroup"), re.compile(r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")),
    ("group_add", ("usermod", "gpasswd", "useradd", "adduser"), re.compile(r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    ("group_add", ("gpasswd",), re.compile(r"^user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")),
    ("user_change", ("usermod",), re.compile(r"^change user '(?P<user>[^']+)' (?P<what>.+)$")),
    ("password_changed", ("passwd", "chpasswd"), re.compile(r"^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<user>\S+)")),
    ("delete_user", ("userdel", "deluser"), re.compile(r"^delete user '(?P<user>[^']+)'")),
]


def account_events(records):
    """Account changes logged by the shadow tools: {kind, user, uid, gid, home, shell, group, rec}
    with kind new_user, new_group, group_add, user_change, password_changed or delete_user."""
    out = []
    for rec in records:
        app = (rec.get("app") or "").lower()
        for kind, apps, rx in _ACCOUNT:
            if app in apps:
                m = rx.match(rec["msg"].strip())
                if m:
                    g = m.groupdict()
                    for k in ("uid", "gid"):
                        if g.get(k) is not None:
                            g[k] = int(g[k])
                    out.append({"kind": kind, **g, "rec": rec})
                    break
    return out


_CRONRUN = re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$")


def cron_runs(records):
    """Commands cron logged as run: {user, command, rec} from 'CRON[pid]: (user) CMD (command)'."""
    out = []
    for rec in records:
        if (rec.get("app") or "").lower() in ("cron", "crond", "anacron"):
            m = _CRONRUN.match(rec["msg"].strip())
            if m:
                out.append({**m.groupdict(), "rec": rec})
    return out


# ---- auditd -------------------------------------------------------------------------------------------

_AUDIT = re.compile(r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<sec>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s?(?P<body>.*)$")
_KV = re.compile(r"([A-Za-z_][\w.\-]*(?:\[\d+\])?)=(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S*)")
_HEXISH = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
# Fields auditd writes as bare hex when the value has a space, a quote or a non-printable byte.
_AUDIT_TEXT = {"proctitle", "name", "cwd", "exe", "comm", "cmd", "data", "acct", "path", "dir", "new", "old", "vm", "filter_key"}


def audit_hex(value):
    """A bare-hex auditd value as text (NUL bytes kept); None when it is not hex."""
    if not isinstance(value, str) or not _HEXISH.match(value):
        return None
    return bytes.fromhex(value).decode("utf-8", "replace")


def _audit_fields(body, rtype):
    fields, hexed = OrderedDict(), []
    for key, raw in _KV.findall(body):
        if raw[:1] == "'" and raw[-1:] == "'" and len(raw) >= 2:
            inner, inner_hex = _audit_fields(raw[1:-1], rtype)         # msg='op=... acct="root" res=failed'
            if inner:
                for k, v in inner.items():
                    fields.setdefault(k, v)
                hexed += inner_hex
                continue
            fields[key] = raw[1:-1]
            continue
        if raw[:1] == '"' and raw[-1:] == '"' and len(raw) >= 2:
            fields[key] = raw[1:-1]
            continue
        base = key.split("[")[0]
        is_arg = rtype == "EXECVE" and re.match(r"^a\d+$", base) is not None
        if (base in _AUDIT_TEXT or is_arg) and raw not in ("(null)", "") and _HEXISH.match(raw):
            fields[key] = bytes.fromhex(raw).decode("utf-8", "replace")
            hexed.append(key)
        else:
            fields[key] = raw
    return fields, hexed


def parse_audit_line(line, n=0):
    """One auditd record, or None: {line, raw, type, time (epoch float), id ('sec.ms:serial'),
    serial, node, fields, hex (the keys whose value was hex-encoded and is decoded in fields),
    interp (the upper-case fields of an enriched record)}."""
    m = _AUDIT.match(line.rstrip("\r\n"))
    if not m:
        return None
    body, _, enriched = m["body"].partition("\x1d")
    fields, hexed = _audit_fields(body, m["type"])
    interp = _audit_fields(enriched, "")[0] if enriched else {}
    return {"line": n, "raw": line.rstrip("\r\n"), "type": m["type"], "time": int(m["sec"]) + int(m["ms"]) / (10 ** len(m["ms"])),
            "id": f"{m['sec']}.{m['ms']}:{m['serial']}", "serial": int(m["serial"]), "node": m["node"], "fields": fields,
            "hex": hexed, "interp": interp}


def parse_audit(text):
    out = []
    for n, line in _lines(text):
        rec = parse_audit_line(line, n)
        if rec:
            out.append(rec)
    return out


def audit_events(records):
    """Records grouped by audit id, in first-seen order: [{id, time, types, records}]."""
    by = OrderedDict()
    for r in records:
        e = by.setdefault((r["node"], r["id"]), {"id": r["id"], "time": r["time"], "types": [], "records": []})
        e["types"].append(r["type"])
        e["records"].append(r)
    return list(by.values())


def audit_exec(event):
    """What one audit event says was executed, or None when it holds neither EXECVE nor PROCTITLE:
    {id, time, argv, command (argv joined by one space), proctitle (NULs as spaces), hex (was an
    EXECVE argument hex-encoded? A title of two words always is, so it counts only when the event
    has no EXECVE), whole (False when the EXECVE record is cut: fewer arguments than its argc, or
    a quoted argument with no closing quote), exe, comm, pid, ppid, uid, auid, euid, cwd, key, success,
    syscall}. A long argument split as a2[0], a2[1] is joined."""
    argv, title, arg_hex, title_hex, info, argc = None, None, False, False, {}, None
    for r in event["records"]:
        f = r["fields"]
        if r["type"] == "EXECVE":
            argc = f.get("argc")
            parts = {}
            for k, v in f.items():
                m = re.match(r"^a(\d+)(?:\[(\d+)\])?$", k)
                if m:
                    parts.setdefault(int(m.group(1)), {})[int(m.group(2) or 0)] = v
            argv = ["".join(parts[i][j] for j in sorted(parts[i])) for i in sorted(parts)]
            arg_hex = arg_hex or any(re.match(r"^a\d+", k) for k in r["hex"])
        elif r["type"] == "PROCTITLE" and "proctitle" in f:
            title = f["proctitle"].replace("\x00", " ").rstrip(" ")
            title_hex = title_hex or "proctitle" in r["hex"]
        elif r["type"] == "SYSCALL":
            for k in ("exe", "comm", "pid", "ppid", "uid", "auid", "euid", "key", "success", "syscall", "tty", "ses"):
                if k in f:
                    info[k] = f[k]
            if r["interp"].get("SYSCALL"):
                info["syscall_name"] = r["interp"]["SYSCALL"]
        elif r["type"] == "CWD" and "cwd" in f:
            info["cwd"] = f["cwd"]
    if argv is None and title is None:
        return None
    # whole: every argument the record counts is there and none is a quoted value cut before its closing quote
    whole = argv is None or ((argc is None or str(argc) == str(len(argv))) and not any(a.startswith('"') for a in argv))
    return {"id": event["id"], "time": event["time"], "argv": argv, "command": " ".join(argv) if argv is not None else None,
            "whole": whole, "proctitle": title, "hex": arg_hex if argv is not None else title_hex, **{k: info.get(k) for k in
                                                 ("exe", "comm", "pid", "ppid", "uid", "auid", "euid", "cwd", "key", "success", "syscall")}}


def decode_saddr(hexvalue):
    """An auditd SOCKADDR `saddr` as {family, ip, port} (AF_INET 2, AF_INET6 10) or {family, path}
    (AF_UNIX 1); None for anything else."""
    try:
        raw = bytes.fromhex(hexvalue)
    except (ValueError, TypeError):
        return None
    if len(raw) < 2:
        return None
    fam = struct.unpack_from("<H", raw)[0]
    if fam == 2 and len(raw) >= 8:
        return {"family": "inet", "port": struct.unpack_from(">H", raw, 2)[0], "ip": str(ipaddress.IPv4Address(raw[4:8]))}
    if fam == 10 and len(raw) >= 24:
        return {"family": "inet6", "port": struct.unpack_from(">H", raw, 2)[0], "ip": str(ipaddress.IPv6Address(raw[8:24]))}
    if fam == 1:
        return {"family": "unix", "path": raw[2:].split(b"\x00")[0].decode("utf-8", "replace")}
    return None


# ---- utmp, wtmp, btmp, lastlog ----------------------------------------------------------------------

UTMP_SIZE = 384
_UTMP = struct.Struct("<hxxi32s4s32s256shhiii16s20s")
UTMP_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
              6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}
LASTLOG_SIZE = 292


def _cstr(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def is_utmp(data) -> bool:
    """True for a file of whole 384-byte Linux utmp records (x86-64 and aarch64 glibc) whose type
    fields are all 0 to 9 and whose strings are NUL-padded text."""
    if len(data) < UTMP_SIZE or len(data) % UTMP_SIZE:
        return False
    some = False
    for off in range(0, min(len(data), UTMP_SIZE * 64), UTMP_SIZE):
        t, _pid, line, _id, user, host = _UTMP.unpack_from(data, off)[:6]
        if not 0 <= t <= 9:
            return False
        for raw in (line, user, host):
            head = raw.split(b"\x00", 1)[0]
            if any(b < 32 or b > 126 for b in head) or raw[len(head):].strip(b"\x00"):
                return False
        some = some or t != 0
    return some


def parse_utmp(data):
    """The records of a utmp, wtmp or btmp file: {n, type, type_name, pid, line, id, user, host,
    time (epoch float), sec, usec, addr (the IP the record stores, or None), session, exit}.
    In wtmp a USER_PROCESS (7) record is a login and the DEAD_PROCESS (8) of its line the logout;
    in btmp every record is a failed login."""
    out = []
    for n, off in enumerate(range(0, len(data) - UTMP_SIZE + 1, UTMP_SIZE)):
        t, pid, line, id_, user, host, term, exit_, session, sec, usec, addr, _ = _UTMP.unpack_from(data, off)
        ip = None
        if addr != b"\x00" * 16:
            ip = str(ipaddress.IPv4Address(addr[:4])) if addr[4:] == b"\x00" * 12 else str(ipaddress.IPv6Address(addr))
        out.append({"n": n, "type": t, "type_name": UTMP_TYPES.get(t, str(t)), "pid": pid, "line": _cstr(line), "id": _cstr(id_),
                    "user": _cstr(user), "host": _cstr(host), "time": (sec & 0xFFFFFFFF) + usec / 1e6, "sec": sec & 0xFFFFFFFF,
                    "usec": usec, "addr": ip, "session": session, "exit": (term, exit_)})
    return out


def parse_lastlog(data):
    """The non-empty records of /var/log/lastlog: {uid (the record's index), time (epoch), line, host}."""
    out = []
    for uid, off in enumerate(range(0, len(data) - LASTLOG_SIZE + 1, LASTLOG_SIZE)):
        sec, line, host = struct.unpack_from("<I32s256s", data, off)
        if sec or line.strip(b"\x00") or host.strip(b"\x00"):
            out.append({"uid": uid, "time": sec, "line": _cstr(line), "host": _cstr(host)})
    return out


# ---- crontab ------------------------------------------------------------------------------------------

CRON_SPECIALS = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly")
_CRON_NUM = r"(?:\*|\d+(?:-\d+)?)(?:/\d+)?(?:,(?:\*|\d+(?:-\d+)?)(?:/\d+)?)*"
_CRON_NAME = r"(?:\*|\?|[\dA-Za-z#LW]+(?:-[\dA-Za-z]+)?)(?:/\d+)?(?:,(?:\*|\?|[\dA-Za-z#LW]+(?:-[\dA-Za-z]+)?)(?:/\d+)?)*"
_CRON_LINE = re.compile(r"^\s*(?P<sched>(?P<f1>" + _CRON_NUM + r")(?P<g1>[ \t]+)(?P<f2>" + _CRON_NUM + r")(?P<g2>[ \t]+)(?P<f3>" + _CRON_NAME +
                        r")(?P<g3>[ \t]+)(?P<f4>" + _CRON_NAME + r")(?P<g4>[ \t]+)(?P<f5>" + _CRON_NAME + r"))[ \t]+(?P<rest>\S.*)$")
_CRON_AT = re.compile(r"^\s*(?P<sched>@[a-z_]+)[ \t]+(?P<rest>\S.*)$")
_CRON_ENV = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
_CRON_RANGES = ((0, 59, ()), (0, 23, ()), (1, 31, ()), (1, 12, tuple(m.lower() for m in MONTHS)),
                (0, 7, ("sun", "mon", "tue", "wed", "thu", "fri", "sat")))


def _cron_field_ok(field, lo, hi, names) -> bool:
    """Is one schedule field in range? '72 101 108 108 111 ...' is a line of numbers, not a job."""
    for part in field.split(","):
        part, _, step = part.partition("/")
        if step and not (step.isdigit() and int(step) > 0):
            return False
        if part in ("*", "?", "L") or re.match(r"^\d{1,2}W$|^[0-7]#[1-5]$|^[0-7]L$", part):
            continue
        for end in part.split("-", 1):
            if end.isdigit():
                if len(end) > 2 or not lo <= int(end) <= hi:
                    return False
            elif end.lower() not in names:
                return False
    return True


def parse_crontab(text, system=None):
    """A crontab: {jobs, env, bad}. A job is {line, schedule (the five fields joined by one space,
    or the @word), raw_schedule (as written), special, command, user, alt}.
    `system` True reads the sixth field as the user (/etc/crontab, /etc/cron.d); False reads none
    (a user's crontab). None means the file's kind is not known: `command` and `user` are then the
    user-crontab reading, and `alt` holds the other one ({user, command}) whenever the first word
    of the command could be a user name. `bad` lists the lines that are neither a job, a comment
    nor an assignment: a text with any is probably not a crontab."""
    jobs, env, bad = [], OrderedDict(), []
    for n, line in _lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _CRON_LINE.match(line) or _CRON_AT.match(line)
        if not m:
            e = _CRON_ENV.match(line)
            if e:
                env[e.group(1)] = e.group(2).strip().strip("\"'")
            else:
                bad.append(n)
            continue
        raw = m["sched"]
        special = raw.startswith("@")
        if (special and raw not in CRON_SPECIALS) or \
                (not special and not all(_cron_field_ok(m[f"f{i}"], *_CRON_RANGES[i - 1]) for i in range(1, 6))):
            bad.append(n)
            continue
        rest = m["rest"].rstrip()
        words = rest.split(None, 1)
        first, after = words[0], (words[1].strip() if len(words) > 1 else "")
        could = bool(_USERNAME.match(first)) and bool(after)
        job = {"line": n, "schedule": raw if special else " ".join(m[f"f{i}"] for i in range(1, 6)), "raw_schedule": raw,
               "special": special, "command": rest, "user": None, "alt": None}
        if system is True:
            if not could:
                bad.append(n)
                continue
            job.update(user=first, command=after)
        elif system is None and could:
            job["alt"] = {"user": first, "command": after}
        jobs.append(job)
    return {"jobs": jobs, "env": env, "bad": bad}


def crontab_kind(name):
    """True for a system crontab by its path (/etc/crontab, cron.d), False for a user's
    (var/spool/cron, crontabs/<user>), None when the path does not say."""
    low = str(name).replace("\\", "/").lower()
    if re.search(r"(^|/)etc/crontab$|(^|/)cron\.d/|(^|/)anacrontab$", low):
        return True
    if re.search(r"(^|/)(var/spool/cron|crontabs|cron/tabs)/", low):
        return False
    return None


# ---- systemd units ------------------------------------------------------------------------------------

UNIT_SECTIONS = ("Unit", "Service", "Install", "Timer", "Socket", "Path", "Mount", "Automount", "Swap", "Slice", "Scope")


def parse_unit(text):
    """A systemd unit file as {section: {key: [values]}}, or None when the text has no known
    [Section]. A trailing backslash joins lines; an empty assignment clears the key, as systemd
    reads it; keys keep their spelling."""
    out, section, pending = OrderedDict(), None, None
    for _, line in _lines(text):
        if pending is not None:
            line = pending + " " + line.strip()
            pending = None
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.endswith("\\"):
            pending = s[:-1].rstrip()
            continue
        m = re.match(r"^\[([A-Za-z][A-Za-z0-9 -]*)\]$", s)
        if m:
            section = m.group(1)
            out.setdefault(section, OrderedDict())
            continue
        if section is None or "=" not in s:
            if section is None:
                return None
            continue
        key, _, value = s.partition("=")
        key, value = key.strip(), value.strip()
        if not re.match(r"^[A-Za-z][A-Za-z0-9]*$", key):
            continue
        if value == "":
            out[section][key] = []
        else:
            out[section].setdefault(key, []).append(value)
    if pending is not None and section is not None and "=" in pending:
        key, _, value = pending.partition("=")
        out[section].setdefault(key.strip(), []).append(value.strip())
    return out if any(s in UNIT_SECTIONS for s in out) else None


def unit_values(unit, key, section=None):
    """Every value of a directive, by its name without regard to case, over all sections (or one)."""
    out = []
    for sec, keys in (unit or {}).items():
        if section and sec.lower() != section.lower():
            continue
        for k, values in keys.items():
            if k.lower() == key.lower():
                out += values
    return out


def exec_strip(value):
    """An Exec* value without systemd's leading prefix characters (- @ : + !)."""
    return re.sub(r"^[-@:+!]+", "", value)


# ---- passwd, shadow, group, authorized_keys, ld.so.preload, history -----------------------------------

def _numeric_field(value) -> bool:
    """A passwd/group id field int() can parse: ASCII decimal within the 32-bit id width. str.isdigit()
    alone accepts Unicode digits (e.g. superscripts) int() rejects, and unbounded lengths int() refuses."""
    return value.isascii() and value.isdigit() and len(value) <= 10


def _colon_rows(text, width):
    rows = []
    for n, line in _lines(text):
        s = line.rstrip("\r\n")
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        parts = s.split(":")
        if len(parts) != width:
            return None
        rows.append((n, parts))
    return rows or None


def parse_passwd(text):
    """/etc/passwd rows: {line, name, passwd, uid, gid, gecos, home, shell}; None when the text is
    not a passwd file (every row has seven fields and a numeric uid and gid)."""
    rows = _colon_rows(text, 7)
    if rows is None or not all(_numeric_field(p[2]) and _numeric_field(p[3]) and p[0] for _, p in rows):
        return None
    return [{"line": n, "name": p[0], "passwd": p[1], "uid": int(p[2]), "gid": int(p[3]), "gecos": p[4], "home": p[5], "shell": p[6]}
            for n, p in rows]


_NOLOGIN = re.compile(r"(nologin|false|sync|shutdown|halt)$")


def passwd_anomalies(rows):
    """What stands out in a passwd file: [{kind, name, detail}] with kind uid0_not_root (a second
    account with uid 0), duplicate_uid, duplicate_name, empty_password (no 'x': no password at
    all), hash_in_passwd, or system_account_with_shell (uid under 1000, not root, a login shell)."""
    out = []
    by_uid, names = {}, Counter(r["name"] for r in rows)
    for r in rows:
        by_uid.setdefault(r["uid"], []).append(r["name"])
        if r["uid"] == 0 and r["name"] != "root":
            out.append({"kind": "uid0_not_root", "name": r["name"], "detail": f"uid 0, shell {r['shell']}"})
        if r["passwd"] == "":
            out.append({"kind": "empty_password", "name": r["name"], "detail": "empty password field"})
        elif r["passwd"] not in ("x", "*", "!", "!!", "*LK*", "NP") and len(r["passwd"]) >= 13:
            out.append({"kind": "hash_in_passwd", "name": r["name"], "detail": r["passwd"][:12] + "..."})
        if 0 < r["uid"] < 1000 and r["shell"] and not _NOLOGIN.search(r["shell"]) and re.search(r"sh$", r["shell"]):
            out.append({"kind": "system_account_with_shell", "name": r["name"], "detail": f"uid {r['uid']}, shell {r['shell']}"})
    for uid, who in by_uid.items():
        if len(who) > 1 and uid != 0:
            out.append({"kind": "duplicate_uid", "name": ",".join(who), "detail": f"uid {uid}"})
    for name, n in names.items():
        if n > 1:
            out.append({"kind": "duplicate_name", "name": name, "detail": f"{n} rows"})
    return out


HASH_SCHEMES = {"1": "md5crypt", "2": "bcrypt", "2a": "bcrypt", "2b": "bcrypt", "2x": "bcrypt", "2y": "bcrypt", "5": "sha256crypt",
                "6": "sha512crypt", "y": "yescrypt", "gy": "gost_yescrypt", "7": "scrypt", "sha1": "sha1crypt", "apr1": "apr1_md5",
                "argon2i": "argon2", "argon2id": "argon2", "argon2d": "argon2", "md5": "sunmd5", "3": "nthash"}


def hash_scheme(value):
    """The crypt(3) scheme of a shadow hash field: one of HASH_SCHEMES' names, 'descrypt' (13
    characters), 'locked' (! or *), 'empty', or None for anything else."""
    if value == "":
        return "empty"
    if value[:1] in "!*":
        return "locked"
    m = re.match(r"^\$([A-Za-z0-9]+)\$", value)
    if m:
        return HASH_SCHEMES.get(m.group(1))
    return "descrypt" if re.match(r"^[./A-Za-z0-9]{13}$", value) else None


def parse_shadow(text):
    """/etc/shadow rows: {line, name, hash, scheme, lastchg, min, max, warn, inactive, expire};
    None when the text is not a shadow file (nine fields a row)."""
    rows = _colon_rows(text, 9)
    if rows is None:
        return None
    return [{"line": n, "name": p[0], "hash": p[1], "scheme": hash_scheme(p[1]), "lastchg": p[2], "min": p[3], "max": p[4],
             "warn": p[5], "inactive": p[6], "expire": p[7]} for n, p in rows]


def shadow_anomalies(rows):
    out = []
    for r in rows:
        if r["scheme"] == "empty":
            out.append({"kind": "empty_hash", "name": r["name"], "detail": "no password is needed"})
        elif r["scheme"] in ("md5crypt", "descrypt", "nthash", "apr1_md5", "sha1crypt"):
            out.append({"kind": "weak_hash", "name": r["name"], "detail": r["scheme"]})
    return out


def parse_group(text):
    rows = _colon_rows(text, 4)
    if rows is None or not all(_numeric_field(p[2]) for _, p in rows):
        return None
    return [{"line": n, "name": p[0], "gid": int(p[2]), "members": [m for m in p[3].split(",") if m]} for n, p in rows]


_KEYTYPE = re.compile(r"^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com|"
                      r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521))-cert-v01@openssh\.com)$")


def _split_quoted(line):
    out, cur, quoted, esc = [], "", False, False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\" and quoted:
            cur += ch
            esc = True
        elif ch == '"':
            quoted = not quoted
            cur += ch
        elif ch in " \t" and not quoted:
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def parse_authorized_keys(text):
    """authorized_keys (and .pub) lines: {line, type, key (base64), comment, options ({name:
    value or True}), sha256 ('SHA256:...' as ssh-keygen -l prints it), md5 (colon hex)}."""
    out = []
    for n, line in _lines(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        tokens = _split_quoted(s)
        idx = next((i for i, t in enumerate(tokens[:2]) if _KEYTYPE.match(t)), None)
        if idx is None or idx + 1 >= len(tokens):
            continue
        options = OrderedDict()
        if idx == 1:
            for part in re.findall(r'([A-Za-z-]+)(?:=("(?:[^"\\]|\\.)*"|[^,]*))?(?:,|$)', tokens[0]):
                value = part[1]
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1].replace('\\"', '"')
                options[part[0]] = value if part[1] else True
        try:
            blob = base64.b64decode(tokens[idx + 1], validate=True)
        except (binascii.Error, ValueError):
            continue
        out.append({"line": n, "type": tokens[idx], "key": tokens[idx + 1], "comment": " ".join(tokens[idx + 2:]), "options": options,
                    "sha256": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
                    "md5": ":".join(f"{b:02x}" for b in hashlib.md5(blob).digest())})
    return out


def parse_ld_preload(text):
    """The libraries /etc/ld.so.preload names (whitespace or colon separated; # starts a comment).
    Any entry is worth a look: the file does not exist on a stock system."""
    out = []
    for _, line in _lines(text):
        line = line.split("#", 1)[0]
        out += [p for p in re.split(r"[\s:]+", line) if p]
    return out


_ZSH = re.compile(r"^: (\d{9,10}):(\d+);(.*)$")


def parse_history(text):
    """Shell history: [{n, time (epoch or None), command}]. bash writes '#<epoch>' on the line
    before a command when HISTTIMEFORMAT is set; zsh's extended form is ': <epoch>:<secs>;cmd'."""
    out, stamp = [], None
    for _, line in _lines(text):
        s = line.rstrip("\r\n")
        m = re.match(r"^#(\d{9,10})$", s)
        if m:
            stamp = int(m.group(1))
            continue
        z = _ZSH.match(s)
        if z:
            out.append({"n": len(out) + 1, "time": int(z.group(1)), "command": z.group(3)})
            continue
        if s.strip() or (out and out[-1].get("_open")):
            if stamp is None and out and out[-1].get("_open"):
                out[-1]["command"] += "\n" + s          # the rest of a stamped command that is still open
            else:
                out.append({"n": len(out) + 1, "time": stamp, "command": s})
            last = out[-1]
            c = last["command"]
            bare = re.sub(r"\\.", "", c)
            last["_open"] = last["time"] is not None and (c.endswith("\\") or bare.count('"') % 2 == 1 or bare.count("'") % 2 == 1)
        stamp = None
    for c in out:
        c.pop("_open", None)
    return out


# ---- what a command hides -----------------------------------------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_B64_HINT = re.compile(r"base64\s+(?:-[A-Za-z]*[dD]\b|--decode)|b64decode|frombase64string|openssl\s+(?:enc\s+)?(?:-d\s+)?-?base64|"
                       r"atob\(|decode64|-e(?:nc(?:odedcommand)?)?\s", re.I)
_HEX_HINT = re.compile(r"xxd\s+-r|fromhex|unhexlify|hex2bin|xxd\s+-p\s+-r", re.I)
_HEXRUN = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){8,})(?![0-9A-Fa-f])")
_ESCAPED = re.compile(r"((?:\\x[0-9A-Fa-f]{2}|\\[0-7]{3}){4,})")


def _printable(raw):
    for enc in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if text and all(c == "\n" or c == "\t" or c == "\r" or 32 <= ord(c) < 0x2FFF for c in text) and \
                sum(c.isascii() for c in text) * 10 >= len(text) * 9:
            return text
    return None


def decode_layers(command):
    """The encoded pieces of one command line, decoded one level: [{method, encoded, decoded}].
    method is base64 (only when the command itself decodes base64: `base64 -d`, b64decode,
    FromBase64String, -enc ...), hex (xxd -r, fromhex ...), escapes (\\x41 or \\101 runs) or rev
    (`echo ... | rev`). A piece that does not decode to text is not listed."""
    out = []
    if _B64_HINT.search(command):
        for tok in _B64.findall(command):
            if len(tok) % 4 == 1:
                continue
            try:
                raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            text = _printable(raw)
            if text is not None:
                out.append({"method": "base64", "encoded": tok, "decoded": text})
    if _HEX_HINT.search(command):
        for tok in _HEXRUN.findall(command):
            text = _printable(bytes.fromhex(tok))
            if text is not None:
                out.append({"method": "hex", "encoded": tok, "decoded": text})
    for tok in _ESCAPED.findall(command):
        try:
            text = _printable(codecs.decode(tok, "unicode_escape").encode("latin-1"))
        except (UnicodeError, ValueError):
            text = None
        if text is not None:
            out.append({"method": "escapes", "encoded": tok, "decoded": text})
    m = re.search(r"echo\s+(?:-n\s+)?(?:'([^']*)'|\"([^\"]*)\"|(\S+))\s*\|\s*rev\b", command)
    if m:
        enc = next(g for g in m.groups() if g is not None)
        out.append({"method": "rev", "encoded": enc, "decoded": enc[::-1]})
    return out


def innermost(command, depth=4):
    """Follow a command through its layers while each level hides exactly one piece:
    (the innermost text, [methods]) or (None, []) when there is no layer or a level has two."""
    methods, text = [], command
    for _ in range(depth):
        layers = decode_layers(text)
        if not layers:
            break
        if len({layer["decoded"] for layer in layers}) != 1:
            return None, []
        text = layers[0]["decoded"]
        methods.append(layers[0]["method"])
    return (text, methods) if methods else (None, [])


# ---- property lists -----------------------------------------------------------------------------------

def is_plist(data) -> bool:
    head = data[:2048]
    return head[:8] == b"bplist00" or (b"<plist" in head and (b"<?xml" in head or b"<!DOCTYPE plist" in head or head.lstrip()[:6] == b"<plist"))


def read_plist(data):
    """An XML or binary property list as Python values (plistlib), or None when it is neither."""
    if not is_plist(data):
        return None
    try:
        return plistlib.loads(data.lstrip(b"\xef\xbb\xbf \t\r\n") if data[:8] != b"bplist00" else data)
    except Exception:           # plistlib raises several kinds for a damaged list
        return None


def is_keyed_archive(obj) -> bool:
    return isinstance(obj, dict) and "$objects" in obj and "$top" in obj and isinstance(obj.get("$objects"), list)


def unwrap_keyed_archive(obj, limit=200000):
    """An NSKeyedArchiver plist as plain values: the $top object with every UID followed.
    NSDictionary becomes a dict, NSArray and NSSet a list, NSString a str, NSData bytes, NSDate
    an aware datetime (NS.time is Mac absolute time), NSURL its string; any other class a dict of
    its fields plus '$class'. Both forms of a reference are followed: the UID of a binary plist
    and the {'CF$UID': n} dict of an XML one. A reference back into the object being read comes out as None."""
    objects = obj["$objects"]
    budget = [limit]

    def uid(v):
        """The object index of a reference: plistlib.UID in a binary plist, {'CF$UID': n} in XML."""
        if isinstance(v, plistlib.UID):
            return v.data
        if isinstance(v, dict) and list(v) == ["CF$UID"] and isinstance(v["CF$UID"], int):
            return v["CF$UID"]
        return None

    def classname(o):
        c = uid(o.get("$class"))
        if c is not None and 0 <= c < len(objects) and isinstance(objects[c], dict):
            return objects[c].get("$classname")
        return None

    def res(v, stack):
        budget[0] -= 1
        if budget[0] < 0:
            return None
        i = uid(v)
        if i is not None:
            if not 0 <= i < len(objects) or i in stack:
                return None
            o = objects[i]
            return None if isinstance(o, str) and o == "$null" else conv(o, stack | {i})
        return conv(v, stack)

    def conv(o, stack):
        if isinstance(o, list):
            return [res(x, stack) for x in o]
        if not isinstance(o, dict):
            return o
        if "NS.keys" in o and "NS.objects" in o:
            keys = [res(k, stack) for k in o["NS.keys"]]
            vals = [res(x, stack) for x in o["NS.objects"]]
            return {(k if isinstance(k, (str, int, float, bool)) else repr(k)): x for k, x in zip(keys, vals)}
        if "NS.objects" in o:
            return [res(x, stack) for x in o["NS.objects"]]
        if "NS.string" in o:
            return res(o["NS.string"], stack)
        if "NS.bytes" in o:
            return o["NS.bytes"]
        if "NS.data" in o:
            return res(o["NS.data"], stack)
        if "NS.time" in o:
            return mac_time(o["NS.time"])
        if "NS.relative" in o:
            base, rel = res(o.get("NS.base"), stack), res(o["NS.relative"], stack)
            return (base or "") + (rel or "") if isinstance(rel, str) else rel
        out = {k: res(v, stack) for k, v in o.items() if k != "$class"}
        name = classname(o)
        if name:
            out["$class"] = name
        return out

    top = obj["$top"]
    if isinstance(top, dict) and list(top) == ["root"]:
        return res(top["root"], frozenset())
    return {k: res(v, frozenset()) for k, v in top.items()} if isinstance(top, dict) else res(top, frozenset())


def load_plist(data):
    """read_plist, with an NSKeyedArchiver archive unwrapped."""
    obj = read_plist(data)
    if is_keyed_archive(obj):
        try:
            return unwrap_keyed_archive(obj)
        except (KeyError, TypeError, IndexError, AttributeError, RecursionError):
            return obj
    return obj


_SUSPECT_DIR = re.compile(r"^(/tmp/|/private/tmp/|/var/tmp/|/private/var/tmp/|/Users/Shared/|/dev/shm/)|/\.[^/]+/")
_SUSPECT_ARG = re.compile(r"curl |wget |base64|osascript|python[0-9.]* -c|bash -c|sh -c|/dev/tcp/|nc -|ncat |openssl enc", re.I)


def launchd_job(obj, name=""):
    """A launchd job read from its plist, or None when the plist is not one (neither Program
    nor ProgramArguments): {label, program (the Program key), program_arguments,
    program_path (Program, else the first argument: what launchd executes), run_at_load,
    keep_alive, start_interval, start_calendar_interval, watch_paths, user, kind ('launch_agent'
    or 'launch_daemon' by the plist's folder, else None), scope, notes}."""
    if not isinstance(obj, dict) or not ("ProgramArguments" in obj or "Program" in obj):
        return None
    args = obj.get("ProgramArguments")
    args = [str(a) for a in args] if isinstance(args, list) else None
    program = obj.get("Program") if isinstance(obj.get("Program"), str) else None
    path = str(name).replace("\\", "/")
    kind = "launch_daemon" if "LaunchDaemons/" in path else "launch_agent" if "LaunchAgents/" in path else None
    scope = ("system" if re.search(r"(^|/)System/Library/Launch", path) else
             "user" if re.search(r"(^|/)Users/[^/]+/Library/Launch", path) else
             "local" if re.search(r"(^|/)Library/Launch", path) else None)
    program_path = program or (args[0] if args else None)
    notes = []
    if program_path and _SUSPECT_DIR.search(program_path):
        notes.append("program in a temporary, shared or hidden folder")
    if args and _SUSPECT_ARG.search(" ".join(args)):
        notes.append("arguments download, decode or run a script")
    label = obj.get("Label")
    if isinstance(label, str) and label.startswith("com.apple.") and scope != "system":
        notes.append("an Apple label outside /System/Library")
    return {"label": label if isinstance(label, str) else None, "program": program, "program_arguments": args,
            "program_path": program_path, "run_at_load": obj.get("RunAtLoad"), "keep_alive": obj.get("KeepAlive"),
            "start_interval": obj.get("StartInterval"), "start_calendar_interval": obj.get("StartCalendarInterval"),
            "watch_paths": obj.get("WatchPaths"), "user": obj.get("UserName"), "kind": kind, "scope": scope, "notes": notes}


# ---- sqlite: quarantine events and TCC ----------------------------------------------------------------

def read_sqlite(data, tables=None):
    """{table: [row dict, ...]} of a SQLite database held in memory (at most MAX_ROWS rows a
    table); None when the bytes are not a readable database. A database saved in WAL mode is read
    as its main file says (the header's two version bytes are set to 1 in the copy)."""
    if data[:16] != b"SQLite format 3\x00":
        return None
    image = bytearray(data)
    image[18:20] = b"\x01\x01"
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(bytes(image))
        con.row_factory = sqlite3.Row
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        out = OrderedDict()
        for name in names:
            if tables and name not in tables:
                continue
            try:
                cur = con.execute('SELECT * FROM "%s" LIMIT %d' % (name.replace('"', '""'), MAX_ROWS))
                out[name] = [dict(r) for r in cur]
            except sqlite3.Error:
                out[name] = []
        return out
    except (sqlite3.Error, AttributeError, ValueError):
        return None
    finally:
        con.close()


def quarantine_events(data):
    """Rows of ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2: {id, time
    (aware UTC datetime from LSQuarantineTimeStamp), agent, bundle, url (the file's URL), origin
    (the page it came from), sender, type}; None when the database has no LSQuarantineEvent."""
    db = read_sqlite(data, ("LSQuarantineEvent",))
    if not db or "LSQuarantineEvent" not in db:
        return None
    return [{"id": r.get("LSQuarantineEventIdentifier"), "time": mac_time(r.get("LSQuarantineTimeStamp")),
             "agent": r.get("LSQuarantineAgentName"), "bundle": r.get("LSQuarantineAgentBundleIdentifier"),
             "url": r.get("LSQuarantineDataURLString"), "origin": r.get("LSQuarantineOriginURLString"),
             "sender": r.get("LSQuarantineSenderName") or r.get("LSQuarantineSenderAddress"),
             "type": r.get("LSQuarantineTypeNumber")} for r in db["LSQuarantineEvent"]]


TCC_AUTH = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited"}
TCC_SERVICES = {"full disk access": "kTCCServiceSystemPolicyAllFiles", "camera": "kTCCServiceCamera", "microphone": "kTCCServiceMicrophone",
                "screen recording": "kTCCServiceScreenCapture", "screen capture": "kTCCServiceScreenCapture",
                "accessibility": "kTCCServiceAccessibility", "contacts": "kTCCServiceAddressBook", "calendar": "kTCCServiceCalendar",
                "photos": "kTCCServicePhotos", "reminders": "kTCCServiceReminders", "automation": "kTCCServiceAppleEvents",
                "apple events": "kTCCServiceAppleEvents", "desktop folder": "kTCCServiceSystemPolicyDesktopFolder",
                "documents folder": "kTCCServiceSystemPolicyDocumentsFolder", "downloads folder": "kTCCServiceSystemPolicyDownloadsFolder",
                "input monitoring": "kTCCServiceListenEvent", "developer tools": "kTCCServiceDeveloperTool"}


def tcc_access(data):
    """Rows of TCC.db's `access` table: {service, client, client_type, auth_value, auth (denied,
    unknown, allowed or limited; from `allowed` on an older schema), auth_reason, last_modified
    (aware UTC datetime or None)}; None when there is no such table."""
    db = read_sqlite(data, ("access",))
    if not db or "access" not in db:
        return None
    out = []
    for r in db["access"]:
        value = r.get("auth_value")
        if value is None and r.get("allowed") is not None:
            value = 2 if r.get("allowed") else 0
        out.append({"service": r.get("service"), "client": r.get("client"), "client_type": r.get("client_type"), "auth_value": value,
                    "auth": TCC_AUTH.get(value), "auth_reason": r.get("auth_reason"),
                    "last_modified": from_epoch(r["last_modified"]) if r.get("last_modified") else None})
    return out


def parse_quarantine_xattr(value):
    """The com.apple.quarantine extended attribute 'flags;hex time;agent;uuid' as {flags, time
    (aware UTC datetime), agent, id}; None when the text is not one."""
    parts = str(value).strip().split(";")
    if len(parts) < 3 or not re.match(r"^[0-9a-fA-F]{4}$", parts[0]) or not re.match(r"^[0-9a-fA-F]{6,8}$", parts[1]):
        return None
    return {"flags": parts[0], "time": from_epoch(int(parts[1], 16)), "agent": parts[2], "id": parts[3] if len(parts) > 3 else None}


# ---- the unified log ----------------------------------------------------------------------------------

def parse_unified_log(text):
    """`log show --style ndjson` (or --style json) entries: {line, stamp, time (datetime or
    None), process (the image's base name), process_path, pid, subsystem, category, message,
    type, sender, raw}."""
    out = []
    for n, o in _json_objects(text):
        if "eventMessage" not in o and "processImagePath" not in o:
            continue
        stamp = o.get("timestamp")
        dt, _ = parse_iso(re.sub(r"(\.\d{6})\d+", r"\1", str(stamp or "")))
        path = o.get("processImagePath") or ""
        out.append({"line": n, "stamp": stamp, "time": dt, "process": str(path).rsplit("/", 1)[-1] or o.get("process"),
                    "process_path": path or None, "pid": o.get("processID"), "subsystem": o.get("subsystem") or None,
                    "category": o.get("category") or None, "message": o.get("eventMessage") or "",
                    "type": o.get("messageType") or o.get("eventType"), "sender": str(o.get("senderImagePath") or "").rsplit("/", 1)[-1] or None,
                    "raw": o})
    return out


def filter_unified(records, process=None, subsystem=None, category=None, contains=None, regex=None, kind=None):
    """The unified-log entries that match every filter given (process and subsystem exact,
    without regard to case; contains a substring of the message; regex searched in it)."""
    rx = re.compile(regex, re.I) if regex else None
    out = []
    for r in records:
        if process and (r["process"] or "").lower() != process.lower():
            continue
        if subsystem and (r["subsystem"] or "").lower() != subsystem.lower():
            continue
        if category and (r["category"] or "").lower() != category.lower():
            continue
        if kind and str(r["type"] or "").lower() != kind.lower():
            continue
        if contains and contains.lower() not in r["message"].lower():
            continue
        if rx and not rx.search(r["message"]):
            continue
        out.append(r)
    return out


# ---- .DS_Store ----------------------------------------------------------------------------------------

def is_ds_store(data) -> bool:
    return data[:4] == b"\x00\x00\x00\x01" and data[4:8] == b"Bud1"


def ds_store_records(data):
    """The records of a .DS_Store file, in B-tree order: [(file name, structure id, type, value)].
    ValueError when the file is not a readable Bud1 store."""
    if not is_ds_store(data) or len(data) < 36:
        raise ValueError("not a .DS_Store file")
    body = data[4:]
    try:
        root_off, root_size, root_off2 = struct.unpack_from(">III", body, 4)
        if root_off != root_off2:
            raise ValueError("root offsets differ")
        root = body[root_off:root_off + root_size]
        count = struct.unpack_from(">I", root, 0)[0]
        if count > 65536:
            raise ValueError("too many blocks")
        addrs = struct.unpack_from(f">{count}I", root, 8)
        pos = 8 + 4 * (((count + 255) // 256) * 256)
        ndirs = struct.unpack_from(">I", root, pos)[0]
        pos += 4
        toc = {}
        for _ in range(min(ndirs, 64)):
            ln = root[pos]
            toc[bytes(root[pos + 1:pos + 1 + ln])] = struct.unpack_from(">I", root, pos + 1 + ln)[0]
            pos += 5 + ln

        def block(n):
            a = addrs[n]
            return body[a & ~0x1F:(a & ~0x1F) + (1 << (a & 0x1F))]

        top = struct.unpack_from(">I", block(toc[b"DSDB"]), 0)[0]
        out, seen = [], set()

        def record(buf, p):
            n = struct.unpack_from(">I", buf, p)[0]
            name = buf[p + 4:p + 4 + 2 * n].decode("utf-16-be")
            p += 4 + 2 * n
            sid, typ = bytes(buf[p:p + 4]), bytes(buf[p + 4:p + 8])
            p += 8
            if typ in (b"long", b"shor"):
                value, p = struct.unpack_from(">I", buf, p)[0], p + 4
            elif typ == b"bool":
                value, p = bool(buf[p]), p + 1
            elif typ == b"blob":
                ln = struct.unpack_from(">I", buf, p)[0]
                value, p = bytes(buf[p + 4:p + 4 + ln]), p + 4 + ln
            elif typ == b"type":
                value, p = bytes(buf[p:p + 4]).decode("latin-1"), p + 4
            elif typ == b"ustr":
                ln = struct.unpack_from(">I", buf, p)[0]
                value, p = buf[p + 4:p + 4 + 2 * ln].decode("utf-16-be"), p + 4 + 2 * ln
            elif typ in (b"comp", b"dutc"):
                value, p = struct.unpack_from(">Q", buf, p)[0], p + 8
            else:
                raise ValueError(f"unknown record type {typ!r}")
            out.append((name, sid.decode("latin-1"), typ.decode("latin-1"), value))
            return p

        def walk(n, depth=0):
            if n in seen or depth > 32:
                raise ValueError("a loop in the tree")
            seen.add(n)
            buf = block(n)
            nxt, cnt = struct.unpack_from(">II", buf, 0)
            p = 8
            for _ in range(cnt):
                if nxt:
                    walk(struct.unpack_from(">I", buf, p)[0], depth + 1)
                    p += 4
                p = record(buf, p)
            if nxt:
                walk(nxt, depth + 1)

        walk(top)
        return out
    except (struct.error, KeyError, IndexError, UnicodeDecodeError, RecursionError) as e:
        raise ValueError(f"damaged .DS_Store: {type(e).__name__}") from None


_DS_IDS = (b"Iloc", b"bwsp", b"lsvp", b"lsvP", b"icvp", b"vSrn", b"dscl", b"icgo", b"icvo", b"fwi0", b"fwsw", b"fwvh", b"lsvo", b"pict",
           b"BKGD", b"cmmt", b"extn", b"logS", b"lg1S", b"modD", b"moDD", b"phyS", b"ph1S", b"pBBk", b"pBB0", b"vstl", b"lssp", b"lsvC",
           b"GRP0", b"ICVO", b"LSVO", b"dilc", b"icsp", b"info", b"glvp", b"clip", b"ptbL", b"ptbN")


def ds_store_names(data):
    """The distinct file names a .DS_Store remembers, in first-seen order ('.' is the folder
    itself). The tree is walked; a damaged store is searched for name records instead."""
    try:
        names = [r[0] for r in ds_store_records(data)]
    except ValueError:
        if not is_ds_store(data):
            raise
        names = []
        for sid in _DS_IDS:
            for m in re.finditer(re.escape(sid), data):
                for n in range(1, 256):
                    start = m.start() - 2 * n - 4
                    if start < 0:
                        break
                    if struct.unpack_from(">I", data, start)[0] == n:
                        try:
                            name = data[start + 4:m.start()].decode("utf-16-be")
                        except UnicodeDecodeError:
                            break
                        if all(c.isprintable() for c in name):
                            names.append(name)
                        break
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out
