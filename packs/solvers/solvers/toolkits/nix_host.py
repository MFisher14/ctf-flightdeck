#!/usr/bin/env python3
"""Toolkit `nix_host`: Linux and macOS host forensics (logs, accounts, persistence files).

  .venv/bin/python solvers/toolkits/nix_host.py <file|dir|zip|tar.gz>...     triage of the file(s)
  .venv/bin/python solvers/toolkits/nix_host.py --json <file>...             the same as JSON
  .venv/bin/python solvers/toolkits/nix_host.py --persistence <file>...      the persistence rows only

Offline and plain Python: the standard library only (the readers are solvers/common/nix_host.py),
no process started, no request. Safe on the timed path for the kilobyte-to-megabyte text files a
host-forensics delivery holds.

What it reads (by the bytes, never by the name alone)
  Linux   auth.log / secure / syslog (RFC 3164, RFC 5424, ISO stamps), journald JSON, Docker
          json-file logs, auditd (hex arguments and PROCTITLE decoded), utmp / wtmp / btmp,
          lastlog, crontabs, systemd units, passwd, shadow, group, authorized_keys,
          ld.so.preload, bash and zsh history
  macOS   XML and binary plists (NSKeyedArchiver unwrapped), LaunchAgents / LaunchDaemons,
          QuarantineEventsV2 and TCC.db (sqlite3, in memory), unified-log ndjson, .DS_Store

solve_set (the runner contract) never guesses (AGENTS.md, "Uncertain answers"):
  plain    a field read from the bytes under exactly-one: the question's files, narrowed by every
           file, user and address the question names, hold ONE distinct value. An attacker's
           address needs a rule the question states (most failures, the one that logged in) or
           exactly one source with failures and then a success that no other source out-failed.
           A count is plain when every reading of it agrees and no two files hold the same event.
  unsure   labels.pick('nix_host.<field>/<shape>', [(method, value), ...]): a time whose format
           the question does not fix (a syslog stamp has no year: its year is never made up, and
           only another artifact holding the same EVENT at that moment proves it), a count that differs between
           log lines and 'message repeated N times', a cron command when the file may be a system
           crontab, an Exec line with a prefix character, a boolean, an argument list, the script
           or payload of a job that starts an interpreter with arguments.
  None     everything else: two candidates, no candidate, a question this file does not
           understand, a question of one of the five known lanes, a file too big to read whole.

signals(questions, files) -> 0..1: how much a delivery and its questions look like this category
(cheap: names, the first 64 KiB of each file, the question words). persistence_rows(files) gives
the cron, systemd, launchd, ld.so.preload, authorized_keys and uid-0 rows in the row shape of
solvers/toolkits/edr_persistence.py.
"""
import importlib.util
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

KEY = "nix_host"
HERE = Path(__file__).resolve().parent
SOLVERS = HERE.parent
if str(SOLVERS / "common") not in sys.path:
    sys.path.insert(0, str(SOLVERS / "common"))
import labels  # noqa: E402


def _load(name, path):
    """The readers by path: this file and solvers/common/nix_host.py share a module name."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


nh = _load("_nix_host_readers", SOLVERS / "common" / "nix_host.py")

# labels.py knows the five lanes of Days 1 to 8. A toolkit's keys need a lane of their own, or
# labels.pick raises and labels.parse (tools/grade.py) reads the unsure string as nothing to probe.
# Registered in the process that loaded this file; setdefault, so an entry the integrator writes
# into labels.py wins.
labels.LANE_DIRS.setdefault(KEY, "toolkits/seeds/" + KEY)

ARROW = " -> "
UTC = nh.UTC
MAX_FILE = 32 * 1024 * 1024         # a text file larger than this is not read, and then nothing is answered
SNIFF = 64 * 1024
NOT_MINE = object()
YEAR_SLACK = 2                      # seconds between a syslog stamp and the same event in another artifact
YEAR_CHAIN_DAYS = 31                # the longest silence a proven year is carried over


# ---- the files ----------------------------------------------------------------------------------------

class Item:
    __slots__ = ("name", "tail", "base", "data", "kind", "parsed")

    def __init__(self, name, data):
        self.name, self.data = name, data
        self.tail = name.split(ARROW)[-1].replace("\\", "/")
        self.base = PurePosixPath(self.tail).name
        self.kind = self.parsed = None


def _audit_share(text):
    seen = hit = 0
    for line in text.splitlines()[:400]:
        if line.strip():
            seen += 1
            hit += nh.parse_audit_line(line) is not None
            if seen >= 40:
                break
    return hit / seen if seen else 0.0


def classify(tail, data):
    """(kind, parsed) of one file by its bytes. Kinds: plist, quarantine, tcc, sqlite, ds_store,
    lastlog, utmp, btmp, audit, journal, docker, unified, syslog, unit, ld_preload, passwd, shadow,
    group, authorized_keys, history, crontab, text, binary, big."""
    base = PurePosixPath(tail).name.lower()
    if data[:8] == b"bplist00":
        obj = nh.load_plist(data)
        return ("plist", obj) if obj is not None else ("binary", None)
    if data[:16] == b"SQLite format 3\x00":
        q = nh.quarantine_events(data)
        if q is not None:
            return ("quarantine", q) if len(q) < nh.MAX_ROWS else ("big", None)     # read short: not read
        t = nh.tcc_access(data)
        if t is not None and len(t) >= nh.MAX_ROWS:
            return "big", None
        return ("tcc", t) if t is not None else ("sqlite", None)
    if nh.is_ds_store(data):
        try:
            return "ds_store", nh.ds_store_names(data)
        except ValueError:
            return "binary", None
    if base.startswith("lastlog") and data and len(data) % nh.LASTLOG_SIZE == 0 and b"\x00" in data[:nh.LASTLOG_SIZE]:
        return "lastlog", nh.parse_lastlog(data)
    if nh.is_utmp(data):
        return ("btmp" if "btmp" in base else "utmp"), nh.parse_utmp(data)
    if len(data) > MAX_FILE:
        return ("binary" if b"\x00" in data[:SNIFF] else "big"), None
    text = nh.text_of(data)
    if text is None:
        return "binary", None
    if not text.strip():
        return "text", None
    if text.count("\n") >= nh.MAX_LINES:
        return "big", None                  # the readers stop at MAX_LINES: a count or exactly-one of the rest cannot be shown
    if nh.is_plist(data):
        obj = nh.load_plist(data)
        if obj is not None:
            return "plist", obj
    head = text[:SNIFF]
    if nh.is_journal_export(text):
        recs = nh.parse_journal_export(text)
        if recs:
            return "journal", recs
    if "msg=audit(" in head and _audit_share(text) >= 0.6:
        return "audit", nh.audit_events(nh.parse_audit(text))
    if head.lstrip()[:1] in "{[":
        if "__REALTIME_TIMESTAMP" in head or '"MESSAGE"' in head:
            recs = nh.parse_journal_json(text)
            if recs:
                return "journal", recs
        if "eventMessage" in head or "processImagePath" in head:
            recs = nh.parse_unified_log(text)
            if recs:
                return "unified", recs
        if '"log"' in head and '"stream"' in head:
            recs = nh.parse_docker_log(text)
            if recs:
                return "docker", recs
    if nh.syslog_share(text) >= 0.6:
        return "syslog", nh.parse_syslog(text)
    unit = nh.parse_unit(text)
    if unit is not None:
        return "unit", unit
    if base == "ld.so.preload":
        return "ld_preload", nh.parse_ld_preload(text)
    rows = nh.parse_passwd(text)
    if rows:
        return "passwd", rows
    if base.startswith(("shadow", "gshadow")) or ":$" in head:
        rows = nh.parse_shadow(text)
        if rows and all(r["scheme"] for r in rows):
            return "shadow", rows
    if base.startswith("group"):
        rows = nh.parse_group(text)
        if rows:
            return "group", rows
    keys = nh.parse_authorized_keys(text)
    if keys and len(keys) == sum(1 for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")):
        return "authorized_keys", keys
    if re.search(r"(^|[._])(bash_|zsh_|sh_)?history$", base) or len(re.findall(r"(?m)^#\d{10}$", head)) >= 2:
        return "history", nh.parse_history(text)
    tab = nh.parse_crontab(text, nh.crontab_kind(tail))
    if tab["jobs"] and not tab["bad"]:
        return "crontab", tab
    return "text", None


# Names without a dot that still read as a file when a question says them ('in wtmp', 'the crontab').
# A crontab spooled as crontabs/root is named 'root': that word in a question is the user.
_FILE_WORDS = {"wtmp", "btmp", "utmp", "lastlog", "crontab", "passwd", "shadow", "gshadow", "secure", "syslog", "messages",
               "authorized_keys", "bash_history", "zsh_history", "ds_store"}


class Evidence:
    """The files of one set, each once, read on first use."""

    def __init__(self, files):
        self.items, seen = [], set()
        allf = dict(files)
        try:
            import triage                       # gzip, bzip2, xz and tar members run.py leaves packed
            allf.update(triage.expand_more(files))
        except Exception:                       # the map is a help, not a need
            pass
        # arrow names first: they say where a member lives (etc/cron.d/x, Library/LaunchAgents/x)
        for name in sorted(allf, key=lambda k: (ARROW not in k, k)):
            data = allf[name]
            if not isinstance(data, (bytes, bytearray)):
                continue
            mark = (len(data), hash(bytes(data)))
            if mark in seen:
                continue
            seen.add(mark)
            self.items.append(Item(name, bytes(data)))
        self._moments = self._years = None

    def read(self, item):
        if item.kind is None:
            try:
                item.kind, item.parsed = classify(item.tail, item.data)
            except Exception:                   # a file that cannot be read is no evidence
                item.kind, item.parsed = "binary", None
        return item.kind

    @property
    def partial(self):
        """True when a file was too big to read: exactly-one cannot be shown, so nothing is answered."""
        return any(self.read(i) == "big" for i in self.items)

    def of(self, kinds, scope=None):
        kinds = (kinds,) if isinstance(kinds, str) else kinds
        return [i for i in (self.items if scope is None else scope) if self.read(i) in kinds]

    def scope(self, q, text):
        """The files a question is about: its member, else the files it names, else all of them."""
        member = q.get("member")
        if member:
            m = str(member).replace("\\", "/")
            hit = [i for i in self.items if i.tail == m or i.base == PurePosixPath(m).name]
            if hit:
                return self._with_children(hit)
        quoted = set(_quoted(text))
        named = [i for i in self.items if len(i.base) > 2 and _has_word(text, i.base)
                 and ("." in i.base.strip(".") or i.base.lower().lstrip(".") in _FILE_WORDS or i.base in quoted)]
        if named:
            longest = [i for i in named if not any(i.base != o.base and i.base in o.base for o in named)]
            return self._with_children(longest)
        return self.items

    def _with_children(self, hit):
        out = list(hit)
        for i in self.items:
            if i not in out and any(ARROW in i.name and i.name.split(ARROW)[-2].replace("\\", "/").endswith(h.base) for h in hit):
                out.append(i)
        return out

    def records(self, scope=None):
        """[(item, syslog-shaped records)] of the syslog and journald files."""
        return [(i, i.parsed) for i in self.of(("syslog", "journal"), scope)]

    def ssh(self, scope=None):
        """[(item, sshd events)] per log file that has any."""
        out = []
        for i, recs in self.records(scope):
            ev = nh.ssh_events(recs)
            if ev:
                out.append((i, ev))
        return out

    def witnesses(self):
        """{key: [aware UTC datetime, ...]} of what other artifacts say happened and when, keyed so
        that a syslog line of the SAME event can be found: ('accepted'|'failed', user or '*',
        source) from wtmp/utmp, btmp and auditd's USER_LOGIN / USER_AUTH records, and
        ('line', app, pid, message) from journald. A bare moment proves nothing: a busy host has
        some record in every second."""
        if self._moments is None:
            out = {}

            def add(key, dt):
                if dt is not None:
                    out.setdefault(key, []).append(dt.astimezone(UTC).replace(microsecond=0))
            for kind, types, name in (("utmp", (7,), "accepted"), ("btmp", (6, 7), "failed")):
                for i in self.of(kind):
                    for r in i.parsed:
                        if r["type"] in types and r["sec"] and r["user"]:
                            for src in {r["addr"], r["host"]} - {None, ""}:
                                add((name, r["user"], src), nh.from_epoch(r["sec"]))
            for i in self.of("audit"):
                for e in i.parsed:
                    for r in e["records"]:
                        f = r["fields"]
                        if r["type"] not in ("USER_LOGIN", "USER_AUTH") or f.get("res") not in ("success", "failed"):
                            continue
                        if "sshd" not in str(f.get("exe") or "sshd"):
                            continue
                        user = f.get("acct") if f.get("acct") not in (None, "", "?", "(unknown)") else "*"
                        for src in {f.get("addr"), f.get("hostname")} - {None, "", "?"}:
                            add(("accepted" if f["res"] == "success" else "failed", user, src), nh.from_epoch(int(e["time"])))
            for i in self.of("journal"):
                for r in i.parsed:
                    if r["time"] is not None and r.get("app") and r.get("pid") and (r.get("msg") or "").strip():
                        add(("line", r["app"], str(r["pid"]), r["msg"].strip()), r["time"])
            self._moments = out
        return self._moments

    def year_of(self, rec):
        """The proven year of an RFC 3164 record, or None; a proof also says the file is written
        in UTC. Proven directly: another artifact holds the SAME EVENT (witnesses(): the same
        login or failure of the same user from the same source, or the same line of the same
        process) within YEAR_SLACK seconds of the stamp read as UTC. The file as a whole must
        show it is UTC: read with any other zone offset (half hours, -12 h to +14 h) it must
        match fewer events than read as UTC, so logins that repeat on the hour prove nothing.
        Proven by its neighbours: the record sits in the same file, in one run of stamps that
        never step back, as records proven directly that all give one year, and no gap of the
        chain from such a record to it is longer than YEAR_CHAIN_DAYS."""
        if self._years is None:
            self._years = {}
            wit = self.witnesses()
            index = {}
            for key, moments in wit.items():
                slot = index.setdefault(key, {})
                for m in moments:
                    for d in range(-YEAR_SLACK, YEAR_SLACK + 1):
                        t = m - timedelta(seconds=d)            # the stamp a line of this event would carry
                        slot.setdefault((t.month, t.day, t.hour, t.minute, t.second), set()).add(t.year)
            for item in self.of("syslog") if index else []:
                recs = [r for r in item.parsed if r.get("md")]
                pos = {id(r): n for n, r in enumerate(recs)}
                cand = []                                       # (position, key)
                for e in nh.ssh_events(recs):
                    if e["kind"] in ("accepted", "failed") and not e["repeated"] and (e["ip"] or e["host"]):
                        for user in (e["user"], "*"):
                            key = (e["kind"], user, e["ip"] or e["host"])
                            if key in index:
                                cand.append((pos[id(e["rec"])], key))
                for n, r in enumerate(recs):
                    key = ("line", r.get("app"), str(r.get("pid")), (r.get("msg") or "").strip())
                    if r.get("pid") and key in index:
                        cand.append((n, key))
                direct = {}
                for n, key in cand:
                    hit = index[key].get(tuple(recs[n]["md"]))
                    if hit:
                        direct.setdefault(n, set()).update(hit)
                if not direct or not self._utc_shown(recs, cand, index):
                    continue
                start = 0
                for n in range(1, len(recs) + 1):
                    if n == len(recs) or tuple(recs[n]["md"]) < tuple(recs[n - 1]["md"]):
                        here = [k for k in direct if start <= k < n]
                        years = set().union(*(direct[k] for k in here)) if here else set()
                        if len(years) == 1:
                            year, limit, proven = next(iter(years)), timedelta(days=YEAR_CHAIN_DAYS), set(here)
                            for order in (range(start, n), range(n - 1, start - 1, -1)):       # one pass each way
                                live, last = False, None
                                for j in order:
                                    t = _md_time(recs[j])
                                    live = j in proven or (live and abs(t - last) <= limit)
                                    last = t
                                    if live:
                                        self._years[id(recs[j])] = year
                        start = n
        return self._years.get(id(rec))

    @staticmethod
    def _utc_shown(recs, cand, index):
        """Do the events match their witnesses read as UTC, and strictly worse under every other
        zone offset? (At most about 2000 events, evenly taken.)"""
        sample = cand[::max(1, len(cand) // 2000)]
        base = [(key, _md_time(recs[n])) for n, key in sample]

        def hits(shift):
            count = 0
            for key, t in base:
                u = t + shift
                count += (u.month, u.day, u.hour, u.minute, u.second) in index[key]
            return count
        zero = hits(timedelta(0))
        return zero > 0 and all(hits(timedelta(minutes=30 * k)) < zero for k in range(-24, 29) if k)


def _md_time(rec):
    """An RFC 3164 stamp on the calendar of a leap year: only for differences inside one run."""
    return datetime(2000, *rec["md"])


# ---- small helpers -----------------------------------------------------------------------------------

def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _has_word(text, word) -> bool:
    return re.search(r"(?<![\w.-])" + re.escape(word) + r"(?![\w-])(?!\.\w)", text) is not None


def _one(values):
    """The single distinct value of a list, or None (no value, or two)."""
    distinct = []
    for v in values:
        if v is not None and v not in distinct:
            distinct.append(v)
    return distinct[0] if len(distinct) == 1 else None


def _fits(q, value) -> bool:
    f = _fmt(q)
    value = str(value)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            if re.fullmatch(rx, value) is None:
                return False
        except re.error:
            return False
    if str(f.get("kind") or "") == "integer" and not re.fullmatch(r"-?\d+", value):
        return False
    return bool(value.strip()) and "\n" not in value.strip("\n")


def _enum(q):
    f = _fmt(q)
    for key in ("accepted_values", "options", "choices", "values", "enum"):
        if isinstance(f.get(key), list) and f[key]:
            return [str(v) for v in f[key]]
    return None


def pick(q, field, shape, options):
    """labels.pick under 'nix_host.<field>/<shape>' for the options the question's own format
    allows, one name per value, best first. None when nothing is left."""
    opts, seen = [], set()
    for name, value in options:
        if value is None:
            continue
        value = str(value)
        if value in seen or not _fits(q, value):
            continue
        seen.add(value)
        opts.append((name, value))
    allowed = _enum(q)
    if allowed is not None:
        opts = [(n, v) for n, v in opts if v in allowed]
    if not opts:
        return None
    key = f"{KEY}.{field}/{shape}".lower()
    try:
        return labels.pick(key, opts)
    except ValueError:              # a labels.py that refuses the prefix: unsure by hand, never plain
        return labels.SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in opts[:labels.MAX_OPTIONS]]}, separators=(",", ":"))


def _finish(q, value):
    """A handler's value as an answer: an unsure string as it is; a plain value only when the
    question's own format (pattern, integer, enum) allows it."""
    if value is None or value is NOT_MINE:
        return None
    if isinstance(value, str) and value.startswith(labels.SENTINEL):
        return value
    if isinstance(value, bool):
        return None
    value = str(value)
    allowed = _enum(q)
    if allowed is not None:
        if value in allowed:
            return value
        low = [a for a in allowed if a.lower() == value.lower()]
        return low[0] if len(low) == 1 else None
    return value if _fits(q, value) else None


_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")


def _ips_in(text):
    return [m for m in _IPV4.findall(text) if all(int(p) < 256 for p in m.split("."))]


def _quoted(text):
    return [m.strip() for m in re.findall(r"[`'\"“‘]([^`'\"“”‘’]{1,160})[`'\"”’]", text) if m.strip()]


_NOT_A_NAME = {"the", "user", "users", "account", "accounts", "login", "logins", "test", "service", "system", "guest", "each", "any", "all",
               "attacker", "host", "server", "password", "ssh", "sshd", "sudo", "cron", "log", "logs", "file", "command", "name", "new"}


def _named_users(text, known):
    """The users a question names, among those the evidence knows."""
    known = {k for k in known if k}
    out = set()
    for m in re.finditer(r"\b(?:user(?:name)?|account|login)\s+(?:named\s+|called\s+|name\s+)?[`'\"]?([A-Za-z_][\w.-]*\$?)", text, re.I):
        if m.group(1) in known:
            out.add(m.group(1))
    for v in _quoted(text):
        if v in known:
            out.add(v)
    for name in known:              # a known name written bare ('did deploy run', 'targeted root')
        if len(name) >= 3 and name.lower() not in _NOT_A_NAME and _has_word(text, name):
            out.add(name)
    return out


_ASK = r"(?:which|what|whose|identify|provide|give|submit|enter|determine|find|list|report|state|name|how many|number of)"


def _asks(T, nouns) -> bool:
    """Does the question ask for one of these nouns? The noun follows the asking word within two
    words ('what is the source IP address', 'which account', 'the name of the user'), or ends the
    answer id (T is '<question> | <answer id words>')."""
    head, _, tail = T.rpartition(" | ")
    words = r"(?:[\w'\u2019-]+\s+){0,2}?"
    return bool(re.search(r"\b" + _ASK + r"\s+(?:(?:is|was|are|were)\s+)?(?:the\s+)?" + words + r"(?:" + nouns + r")\b", head)
                or re.search(r"\bname of\s+(?:the\s+)?" + words + r"(?:" + nouns + r")\b", head)
                or re.search(r"\b(?:" + nouns + r")$", tail.strip()))


_USER_NOUNS = r"users?|usernames?|user names?|accounts?|logins? names?"
_IP_NOUNS = r"ips?|ip address(?:es)?|address(?:es)?|source|sources?|remote hosts?|hosts?"
_OFF_TOPIC = re.compile(r"\burl\b|\bdomain\b|\bips?\b|ip address|\bhash\b|sha-?256|\bmd5\b|download")
_FAIL = re.compile(r"fail|unsuccess|invalid|incorrect|wrong|denied|reject")
_SUCCESS = re.compile(r"success|accepted|log(?:ged|s)? ?(?:in|on)\b|logins?\b|logons?\b|gain(?:ed|s)? access|compromis|breach|authenticated")
_ATTACK = re.compile(r"attack|brute|malicious|intruder|threat actor|adversar|compromis|unauthori[sz]ed|breach|hacker")
_KNOWN_LANE_ID = re.compile(r"-(?:role|attack|steps|adapter|campaign)$|^d\d\d_")


def _known_lane(q, aid, text) -> bool:
    """A question of one of the five lanes of Days 1 to 8 (the marks solvers/common/triage.py
    names): never answered here."""
    f = _fmt(q)
    words = " ".join(str(x or "") for x in (text, f.get("syntax"), f.get("pattern")))
    return bool("ANS-" in words or _KNOWN_LANE_ID.search(aid) or aid == "message" or f.get("kind") == "mitre_attack_id"
                or re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", text)
                or (re.search(r"\bslug\b", words, re.I) and re.search(r"\bdecod", words, re.I)))


# ---- times --------------------------------------------------------------------------------------------

def moment_of_record(rec, ev):
    """A log record's time as a moment: {dt, stamp, md, source}. An RFC 3164 record has no year;
    its dt is set only when another artifact proves the year (and with it that the log is UTC):
    Evidence.year_of, which asks for the same event, not only the same second."""
    if rec.get("time") is not None:
        return {"dt": rec["time"], "stamp": rec["stamp"] if rec["fmt"] != "journal" else None, "md": None,
                "source": "syslog." + rec["fmt"]}
    year = ev.year_of(rec)
    dt = nh.stamp_with_year(rec, year).replace(tzinfo=UTC) if year else None
    return {"dt": dt, "stamp": rec.get("stamp"), "md": rec.get("md"), "source": "syslog.rfc3164" + (".year_proven" if year else "")}


def moment_of_epoch(seconds, source, raw=None):
    return {"dt": nh.from_epoch(seconds), "stamp": raw, "md": None, "source": source}


def time_options(moment):
    """[(name, value)] of one moment, best first: the text as written, then the spellings the
    proven parts allow. A moment with no year offers no spelling with a year; a datetime with no
    zone offers no UTC form."""
    out = []
    dt, stamp = moment.get("dt"), moment.get("stamp")
    if stamp:
        out.append(("raw", stamp))
        if re.sub(r"\s+", " ", stamp) != stamp:
            out.append(("raw_single_space", re.sub(r"\s+", " ", stamp)))
    if dt is not None and dt.tzinfo is not None:
        u = dt.astimezone(UTC)
        out += [("iso_z", u.strftime("%Y-%m-%dT%H:%M:%SZ")), ("iso_space_utc", u.strftime("%Y-%m-%d %H:%M:%S")),
                ("iso_space", dt.strftime("%Y-%m-%d %H:%M:%S")), ("iso_offset", dt.isoformat(timespec="seconds")),
                ("iso_t", dt.strftime("%Y-%m-%dT%H:%M:%S")), ("epoch", str(int(u.timestamp())))]
        if u.microsecond:
            out.insert(1 if stamp else 0, ("iso_z_ms", u.strftime("%Y-%m-%dT%H:%M:%S.") + f"{u.microsecond // 1000:03d}Z"))
        out.append(("hms", dt.strftime("%H:%M:%S")))
    elif dt is not None:
        out += [("iso_space", dt.strftime("%Y-%m-%d %H:%M:%S")), ("iso_t", dt.strftime("%Y-%m-%dT%H:%M:%S")),
                ("hms", dt.strftime("%H:%M:%S"))]
    elif moment.get("md"):
        out.append(("hms", "%02d:%02d:%02d" % tuple(moment["md"][2:])))
    return out


def _time_format(q, text, opts):
    """The option name the question fixes, or None: a regular expression only one spelling
    matches, a template in the syntax or the question, or 'as written'."""
    f = _fmt(q)
    words = (str(f.get("syntax") or "") + " " + text).lower()
    values = dict(opts)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            hits = [n for n, v in opts if re.fullmatch(rx, v)]
        except re.error:
            hits = []
        if len({values[n] for n in hits}) == 1:
            return hits[0]
    if re.search(r"yyyy-mm-ddthh:mm:ssz|%y-%m-%dt%h:%m:%sz", words):
        return "iso_z"
    if re.search(r"yyyy-mm-ddthh:mm:ss(?![.z])|%y-%m-%dt%h:%m:%s(?!z)", words):
        return "iso_t"
    if re.search(r"yyyy-mm-dd hh:mm:ss|%y-%m-%d %h:%m:%s", words):
        if "iso_space" not in values:
            return "iso_space"                      # asked, and not provable: time_answer says None
        if values.get("iso_space_utc", values["iso_space"]) == values["iso_space"]:
            return "iso_space"
        if re.search(r"\butc\b|\bgmt\b|\bzulu\b", words):
            return "iso_space_utc"
        return None
    if re.search(r"\bepoch\b|unix (?:time|timestamp|seconds)", words):
        return "epoch"
    if re.search(r"as (?:it )?(?:is )?(?:appears|written|shown|logged|recorded)|exactly as|verbatim", words):
        return "raw"
    if re.search(r"(?<![-\w:])hh:mm:ss(?!\w)", words) and not re.search(r"yyyy|mmm|\bdd\b|date", words):
        return "hms"
    return None


def time_answer(q, text, moment):
    """The answer for one proven moment: plain in the format the question fixes, when the moment's
    proven parts can write it; otherwise unsure over the spellings, the text as written first."""
    opts = time_options(moment)
    if not opts:
        return None
    fixed = _time_format(q, text, opts)
    if fixed is not None:
        value = dict(opts).get(fixed)
        return value if value is not None else None       # the format needs a part that is not proven
    return pick(q, "time", moment["source"], opts)


# ---- handlers: one question shape each ---------------------------------------------------------------
# handler(q, ev, text, T) -> NOT_MINE (the words or the evidence are not this shape's), or the
# answer: a plain value, an unsure string, or None. `text` is the question as written, `T` the
# question and the words of the answer id, lower case.

def _bool_pick(q, value, shape):
    a = [("lower", "true"), ("title", "True"), ("yes", "yes"), ("digit", "1")]
    b = [("lower", "false"), ("title", "False"), ("yes", "no"), ("digit", "0")]
    allowed = _enum(q)
    if allowed is not None:         # the question lists its values: the one that says this, or nothing
        words = ("true", "yes", "1", "enabled", "on") if value else ("false", "no", "0", "disabled", "off")
        return _one([x for x in allowed if x.lower() in words])
    return pick(q, "bool", shape, a if value else b)


def h_plist(q, ev, text, T):
    if not re.search(r"plist|launch ?(?:agent|daemon)|launchd|run ?at ?load|program ?arguments", T):
        return NOT_MINE
    plists = [i for i in ev.of("plist", ev.scope(q, text)) if isinstance(i.parsed, dict)]
    if not plists or _OFF_TOPIC.search(T):
        return NOT_MINE
    jobs = [(i, nh.launchd_job(i.parsed, i.tail)) for i in plists]
    jobs = [(i, j) for i, j in jobs if j]
    named = [(i, j) for i, j in jobs if j["label"] and _has_word(text, j["label"])]
    cand = named or jobs
    if not named and re.search(r"(?:runs?|loads?|starts?|launch\w*) at (?:load|login|boot|startup)|with runatload", T) and \
            re.search(r"\blabel\b|program|\bpath\b|executable|binary|which (?:file|plist)|file ?name", T):
        cand = [(i, j) for i, j in jobs if j["run_at_load"] is True] or cand
    # a key the question spells as the plist does (ProgramArguments, StartInterval, Label ...)
    pool = [i for i, _ in cand] or plists
    keys = sorted({k for i in pool for k in i.parsed if isinstance(k, str) and len(k) >= 4 and re.search(r"(?<![\w.])" + re.escape(k) + r"(?![\w.])", text)},
                  key=len, reverse=True)
    if keys and keys[0] not in ("Program", "ProgramArguments"):
        key = keys[0]
        value = _one([json.dumps(i.parsed[key], sort_keys=True, default=str) for i in pool if key in i.parsed])
        if value is None:
            return None
        value = json.loads(value)
        if isinstance(value, bool):
            return _bool_pick(q, value, "plist." + key.lower())
        if isinstance(value, (str, int)):
            return str(value)
        return None
    if not cand:
        return None
    if re.search(r"argument", T) or (keys and keys[0] == "ProgramArguments"):
        args = _one([json.dumps(j["program_arguments"]) for _, j in cand if j["program_arguments"] is not None])
        if args is None:
            return None
        args = json.loads(args)
        return pick(q, "list", "plist.programarguments", [("space_joined", " ".join(args)), ("json", json.dumps(args, separators=(",", ":"))),
                                                           ("comma_joined", ",".join(args))])
    if re.search(r"\blabel\b", T):
        return _one([j["label"] for _, j in cand]) if all(j["label"] for _, j in cand) else None
    if re.search(r"(?:which|what) (?:user|account)|\buser ?name\b|runs? as\b|\bas (?:which|what) user", T):
        return _one([j["user"] for _, j in cand]) if all(isinstance(j["user"], str) and j["user"] for _, j in cand) else None
    if re.search(r"run ?at ?load", T):
        vals = [j["run_at_load"] for _, j in cand]
        v = _one([repr(x) for x in vals])
        return _bool_pick(q, vals[0], "plist.runatload") if v is not None and isinstance(vals[0], bool) else None
    if re.search(r"interval", T):
        v = _one([j["start_interval"] for _, j in cand])
        return str(v) if isinstance(v, int) and not isinstance(v, bool) and len(cand) and all(j["start_interval"] is not None for _, j in cand) else None
    if re.search(r"which (?:file|plist)|file ?name|name of the (?:plist|file)", T):
        return _one([i.base for i, _ in cand])
    if re.search(r"program|executable|binary|\bpath\b|\bruns?\b|launch(?:es|ed)|execut|command|payload|script", T):
        if len({(j["program"], json.dumps(j["program_arguments"])) for _, j in cand}) != 1:
            return None
        j = cand[0][1]
        prog, args = j["program"], j["program_arguments"] or []
        if re.search(r"command", T) and not re.search(r"program path|path", T) and len(args) > 1:
            return pick(q, "command", "plist.launchd", [("argv_joined", " ".join(args)), ("argv0", j["program_path"])])
        if prog and args and args[0] != prog:
            return pick(q, "path", "plist.program", [("program", prog), ("first_argument", args[0])])
        if len(args) > 1 and not re.search(r"program|executable|binary|\bpath\b", T):
            # 'what does it run / which script / what payload': the interpreter alone is not shown to be the answer
            return pick(q, "command", "plist.payload", [("argv_joined", " ".join(args)), ("argv_rest", " ".join(args[1:])), ("argv0", j["program_path"])])
        return j["program_path"]
    return NOT_MINE


def _unit_key(T):
    """The directive a question asks for by its meaning, or None."""
    if _asks(T, _USER_NOUNS) or re.search(r"\bruns? as\b|\brun as\b", T):
        return "User"
    if re.search(r"command|binary|executable|program|script|payload|\bpath\b", T) or \
            re.search(r"what (?:does|did) .*\b(?:run|start|launch|execute)\b", T):
        return "ExecStart"
    if re.search(r"schedule|\bwhen\b|how often|calendar", T):
        return "OnCalendar"
    if re.search(r"wanted ?by|\btarget\b", T):
        return "WantedBy"
    if re.search(r"description", T):
        return "Description"
    return None


def h_unit(q, ev, text, T):
    if not re.search(r"systemd|unit file|\bunit\b|\.service\b|\.timer\b|execstart|\bservice\b|\btimer\b", T):
        return NOT_MINE
    units = ev.of("unit", ev.scope(q, text))
    if not units or _OFF_TOPIC.search(T):
        return NOT_MINE
    present = {k for i in units for sec in i.parsed.values() for k in sec}
    named = []
    for k in present:
        camel = sum(c.isupper() for c in k) >= 2
        if camel and re.search(r"(?<![\w.])" + re.escape(k) + r"(?![\w.])", text, re.I):
            named.append(k)
        elif not camel and re.search(r"(?<![\w.])" + re.escape(k) + r"=?(?![\w.])", text) and \
                re.search(r"directive|setting|option|\bkey\b|value|field|\bline\b|=", text, re.I):
            named.append(k)
    literal = bool(named)
    if named:
        key = max(named, key=len)
    else:
        key = _unit_key(T)
        if key is None:
            return NOT_MINE
    having = [i for i in units if nh.unit_values(i.parsed, key)]
    if not having:
        return None
    per_unit = [json.dumps(nh.unit_values(i.parsed, key)) for i in having]
    values = _one(per_unit)
    if values is None:
        return None
    values = json.loads(values)
    if len(values) != 1:
        return None
    value = values[0]
    if key.lower().startswith("exec"):
        stripped = nh.exec_strip(value)
        if stripped != value:
            return pick(q, "exec", "unit.prefix", [("raw", value), ("stripped", stripped)])
        if not literal and re.search(r"binary|executable|\bpath\b|program", T) and not re.search(r"command|argument", T) and " " in value:
            return pick(q, "exec", "unit.path", [("argv0", value.split()[0]), ("full", value)])
        if not literal and re.search(r"script|payload|\bfile\b", T) and not re.search(r"command|argument", T) and " " in value:
            return pick(q, "exec", "unit.payload", [("full", value), ("argv_rest", value.split(None, 1)[1]), ("argv0", value.split()[0])])
    return value


def _cron_jobs(ev, scope):
    return [(i, job) for i in ev.of("crontab", scope) for job in i.parsed["jobs"]]


def h_cron(q, ev, text, T):
    if not re.search(r"cron|scheduled (?:job|task)|\bschedule\b", T):
        return NOT_MINE
    jobs = _cron_jobs(ev, ev.scope(q, text))
    if not jobs or _OFF_TOPIC.search(T):
        return NOT_MINE
    marks = _quoted(text) + re.findall(r"(?<![\w.])(/[\w.+-]+(?:/[\w.+-]+)+|[\w-]+\.(?:sh|py|pl|php|rb|elf|bin))(?![\w/])", text)
    narrowed = [(i, j) for i, j in jobs if any(m in j["command"] for m in marks)]
    if narrowed:
        jobs = narrowed
    if re.search(r"how many|number of", T):
        return str(len(jobs)) if not narrowed and re.search(r"\b(?:jobs?|entries|entry|tasks?|lines?)\b", T) else None
    if re.search(r"which user|what user|whose|(?:which|what) account|user account|\bowner\b|run as\b|runs as\b", T):
        out = []
        for i, j in jobs:
            if j["user"]:
                out.append(("plain", j["user"]))
            elif j["alt"]:
                out.append(("system_crontab", j["alt"]["user"]))
            elif nh.crontab_kind(i.tail) is False:
                out.append(("spool_file_name", i.base))
            else:
                return None
        one = _one(out)
        if one is None:
            return None
        return one[1] if one[0] == "plain" else pick(q, "cron_user", "crontab." + one[0], [one])
    want_schedule = _asks(T, r"(?:cron )?(?:schedule|expression|frequency|interval|timing)") or re.search(r"how often|\bwhen\b|what time", T)
    want_command = not want_schedule and (re.search(r"command", T) or re.search(r"what (?:does|did) .*\b(?:run|execute)\b", T))
    if want_schedule or (not want_command and re.search(r"schedule|expression|interval|frequency|timing", T)
                         and not _asks(T, r"scripts?|binary|binaries|programs?|files?|paths?|payloads?")):
        if _one([j["schedule"] for _, j in jobs]) is None:
            return None
        j = jobs[0][1]
        if all(x["raw_schedule"] == x["schedule"] for _, x in jobs):
            return j["schedule"]
        return pick(q, "schedule", "crontab.spacing", [("single_space", j["schedule"]), ("raw", _one([x["raw_schedule"] for _, x in jobs]))])
    if want_command or re.search(r"script|binary|program|\bpath\b|payload|\bfile\b", T):
        one = _one([(j["command"], (j["alt"] or {}).get("command")) for _, j in jobs])
        if one is None:
            return None
        if not want_command and any(" " in c or "\t" in c for c in one if c):
            return None                             # a path is asked and the command has arguments: which word is not ours to say
        if one[1] is None:
            return one[0]
        return pick(q, "cron_command", "crontab.form", [("user_crontab", one[0]), ("system_crontab", one[1])])
    return NOT_MINE


def h_quarantine(q, ev, text, T):
    if not re.search(r"quarantine|download", T):
        return NOT_MINE
    dbs = ev.of("quarantine", ev.scope(q, text))
    if not dbs:
        return NOT_MINE
    rows = [r for i in dbs for r in i.parsed]
    marks = _quoted(text)
    narrowed = [r for r in rows if any(m in str(r.get("url") or "") or m in str(r.get("origin") or "") for m in marks)]
    rows = narrowed or rows
    if re.search(r"how many|number of", T):
        return str(len(rows)) if not narrowed else None
    if re.search(r"origin|referr|\bpage\b|\bsite\b", T):
        return _one([r["origin"] for r in rows]) if all(r["origin"] for r in rows) else None
    if re.search(r"\bagent\b|browser|application|\bapp\b|which program", T):
        return _one([r["agent"] for r in rows]) if all(r["agent"] for r in rows) else None
    if re.search(r"\bwhen\b|what time|timestamp|\bdate\b", T):
        if len(rows) != 1 or rows[0]["time"] is None:
            return None
        return time_answer(q, text, {"dt": rows[0]["time"].replace(microsecond=0), "stamp": None, "md": None, "source": "mac_absolute.quarantine"})
    if re.search(r"\burl\b|\blink\b|from where|where .*from|download", T):
        return _one([r["url"] for r in rows]) if all(r["url"] for r in rows) else None
    return NOT_MINE


def h_tcc(q, ev, text, T):
    if not re.search(r"\btcc\b|full disk access|privacy|permission|camera|microphone|screen (?:recording|capture)|accessibility|ktccservice", T):
        return NOT_MINE
    dbs = ev.of("tcc", ev.scope(q, text))
    if not dbs:
        return NOT_MINE
    rows = [r for i in dbs for r in i.parsed]
    service = _one(re.findall(r"kTCCService\w+", text)) or _one([s for phrase, s in nh.TCC_SERVICES.items() if phrase in T])
    if service is None:
        return None
    want = "denied" if re.search(r"denied|refused|blocked", T) else "allowed"
    hit = [r for r in rows if r["service"] == service and r["auth"] == want]
    if re.search(r"how many|number of", T):
        return str(len({r["client"] for r in hit})) if hit else None
    if re.search(r"which|what|client|application|\bapp\b|bundle|program|binary", T):
        return _one([r["client"] for r in hit])
    return NOT_MINE


def h_preload(q, ev, text, T):
    if "preload" not in T:
        return NOT_MINE
    files = ev.of("ld_preload", ev.scope(q, text))
    if not files:
        return NOT_MINE
    return _one([e for i in files for e in i.parsed])


def h_sudo(q, ev, text, T):
    if not re.search(r"\bsudo\b", T):
        return NOT_MINE
    per_file = [nh.sudo_events(recs) for _, recs in ev.records(ev.scope(q, text))]
    events = [e for es in per_file for e in es]
    if not events:
        return NOT_MINE
    everyone = {e["user"] for e in events}
    if _stranger(text, everyone):
        return None                                 # a user sudo never logged
    head = T.rpartition(" | ")[0] or T
    if _unread(T) or re.search(r"\b(?:directory|folder|pwd|cwd|path|tty|terminal|when|time|date|timestamp|hostname|host|machine|where|"
                               r"run as|ran as|as which|as what|target user|runas|file|argument|option|flag|password|pid)\b", head):
        return None                                 # another attribute of the sudo line than its user or its command, or a negation: not read here
    users = _named_users(text, everyone)            # asked before the refused lines are set aside: a user sudo refused is still named
    if not re.search(r"attempt|tried|\btry\b|denied|refus|fail|not allowed|incorrect|unauthori[sz]ed|unsuccess|reject", T):
        events = [e for e in events if not e["note"]]      # sudo's remark (NOT in sudoers, incorrect password, not allowed): never run
        if not events:
            return None
    elif any(not e["note"] for e in events) and any(e["note"] for e in events):
        return None                                 # refused and run side by side: which ones are asked is not ours to say
    if users:
        events = [e for e in events if e["user"] in users]
        if not events:
            return None                             # the user the question names ran nothing (sudo refused it)
    if re.search(r"how many|number of", T):
        if _overlap([{k for e in es for k in _rec_keys(e["rec"])} for es in per_file]):
            return None
        return str(len(events)) if re.search(r"command", T) else None
    if (_asks(T, _USER_NOUNS) or re.search(r"\bwho\b", T)) and "command" not in T:
        return _one([e["user"] for e in events])
    if re.search(r"command|\bran\b|\brun\b|execut", T):
        if any(e.get("cut") for e in events):
            return None                             # sudo logged the command in two lines: where they join is not in the log
        return _one([e["command"] for e in events])
    return NOT_MINE


def h_account(q, ev, text, T):
    if not re.search(r"\b(?:accounts?|users?|usernames?)\b", T):
        return NOT_MINE
    uid0 = re.search(r"uid\s*(?:=|of|is|:)?\s*0\b|uid zero|root[- ](?:level|equivalent)|same uid as root|superuser", T)
    created = re.search(r"\b(?:add(?:ed)?|creat(?:ed|e|ion)|new(?:ly)?|backdoor|rogue)\b", T)
    if not (uid0 or created):
        return NOT_MINE
    scope = ev.scope(q, text)
    passwd = ev.of("passwd", scope)
    events = [e for _, recs in ev.records(scope) for e in nh.account_events(recs)]
    new = [e for e in events if e["kind"] == "new_user"]
    many = re.search(r"how many|number of", T)
    if re.search(r"\b(?:who|users?|accounts?)\s+(?:created|added|made|ran|deleted|changed)\b", T):
        return None                                 # the actor is asked, and no log line names one
    asks_name = _asks(T, _USER_NOUNS)
    if uid0:
        if not passwd and not new:
            return NOT_MINE
        rows = [r for i in passwd for r in i.parsed if r["uid"] == 0 and r["name"] != "root"]
        names = [r["name"] for r in rows] + [e["user"] for e in new if e["uid"] == 0]
        if many:
            if not (passwd and names and _asks(T, _USER_NOUNS)):
                return None
            aside = re.search(r"other than root|besides root|excluding root|except (?:for )?root|apart from root|non-?root|additional|"
                              r"\bextra\b|backdoor|rogue|\badded\b|\bcreated\b|\bnew\b", T)
            root = {r["name"] for i in passwd for r in i.parsed if r["uid"] == 0 and r["name"] == "root"}
            return str(len(set(names) | (set() if aside else root)))
        if _one(names) is None:
            return None
        if re.search(r"\bshell\b", T):
            return _one([r["shell"] for r in rows] + [e["shell"] for e in new if e["uid"] == 0])
        if re.search(r"home dir|home folder|\bhome\b", T):
            return _one([r["home"] for r in rows] + [e["home"] for e in new if e["uid"] == 0])
        return _one(names) if asks_name else NOT_MINE
    if not events:
        return NOT_MINE
    if _asks(T, r"groups?"):
        adds = [e for e in events if e["kind"] == "group_add"]
        users = _named_users(text, {e["user"] for e in adds})
        if users:
            adds = [e for e in adds if e["user"] in users]
        return _one([e["group"] for e in adds])
    if not new:
        return NOT_MINE
    if many:
        return str(len({e["user"] for e in new})) if _asks(T, _USER_NOUNS) else None
    users = _named_users(text, {e["user"] for e in new})
    if users:
        new = [e for e in new if e["user"] in users]
    if _asks(T, r"uid|user id"):
        return str(_one([e["uid"] for e in new])) if _one([e["uid"] for e in new]) is not None else None
    if _asks(T, r"(?:login )?shell"):
        return _one([e["shell"] for e in new])
    if _asks(T, r"home|home directory|home folder"):
        return _one([e["home"] for e in new])
    if re.search(r"\bwhen\b|what time|timestamp", T) and re.search(r"\b(?:add(?:ed)?|creat(?:ed|e|ion))\b", T):
        return time_answer(q, text, moment_of_record(new[0]["rec"], ev)) if len(new) == 1 else None
    if asks_name and not users:
        return _one([e["user"] for e in new])
    return NOT_MINE


def _stranger(text, known) -> bool:
    """Does the question name a user the evidence does not hold ('for user "bob"', 'the account
    mallory')? Then no count or time of ours is the one it asks for."""
    for m in re.finditer(r"\b(?:user(?:name)?|account)\s+(?:named\s+|called\s+)?(?:[`'\"]([^`'\"]+)[`'\"]|([a-z_][a-z0-9_.-]*\$?))", text):
        name = m.group(1) or m.group(2)
        if name not in known and (m.group(1) or (len(name) >= 3 and name.lower() not in _NOT_A_NAME | _NOT_A_USER)):
            return True
    # 'logged in as drewr', 'log in as "mallory"': a name after 'as' that the evidence does not hold
    for m in re.finditer(r"\b(?:in|on|ins?|ons?|authenticat\w+|session|shell|access)\s+as\s+(?:the\s+)?(?:user\s+)?(?:[`'\"]([^`'\"]+)[`'\"]|([A-Za-z_][\w.-]*\$?))",
                         text, re.I):
        name = m.group(1) or m.group(2)
        if name not in known and name.lower() not in known and (m.group(1) or (len(name) >= 3 and name.lower() not in _NOT_A_NAME | _NOT_A_USER
                                                                             | {"well", "soon", "root's", "another", "different", "someone", "anyone"})):
            return True
    return False


_NOT_A_USER = {"logged", "log", "logs", "login", "was", "were", "has", "had", "did", "does", "that", "which", "who", "with", "from", "and", "for",
               "the", "is", "are", "in", "on", "by", "to", "of", "or", "used", "added", "created", "compromised", "targeted", "tried", "failed",
               "successfully", "names", "name", "have", "having", "being", "accounts", "authenticated", "ran", "run", "running", "attempted",
               "received", "made", "got", "when", "where", "what", "whose", "after", "before", "during", "between", "over", "via", "using", "at"}


def _auth_filter(events, text):
    """The events left once the addresses and users the question names are applied; None when it
    names one the evidence does not hold."""
    known = {e["user"] for e in events}
    if _stranger(text, known):
        return None
    ips = _ips_in(text)
    if ips:
        events = [e for e in events if (e["ip"] or e["host"]) in ips]
        if not events:
            return None
    users = _named_users(text, known)
    if users:
        events = [e for e in events if e["user"] in users]
    return events


def _utmp_filter(records, text):
    """The same for utmp records; an empty list when the question names a user they do not hold."""
    known = {r["user"] for r in records}
    if _stranger(text, known):
        return []
    ips = _ips_in(text)
    if ips:
        records = [r for r in records if r["addr"] in ips or r["host"] in ips]
    users = _named_users(text, known)
    if users:
        records = [r for r in records if r["user"] in users]
    return records


# A window, an order or a rate the question adds to a count or a time: not applied here, so not answered.
_CONDITION = re.compile(r"\bbefore\b|\bafter\b|\bbetween\b|\bwithin\b|\bduring\b|\bper (?:minute|second|hour|day)\b|in a row|consecutive|"
                        r"\bprior to\b|\bfollowing\b|\bsince\b|\buntil\b|how long|duration|"
                        r"\b(?:on|at) (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|\d)")


_OTHER_FAIL = re.compile(r"FAILED (?:LOGIN|SU|su)\b|authentication failure|Failed password|[Ll]ogin failed|FAIL LOGIN|incorrect password")

# A rank other than the first, the opposite end, a negation or an exclusion: the login handlers apply
# none of them, and a question that carries one was answered as if it did not (review, 2026-10-08:
# 'the second most failed logins' gave the first, 'were not for root' counted root's).
_UNREAD = re.compile(r"\b(?:second|third|fourth|fifth|2nd|3rd|4th|5th|next|fewest|least|lowest|smallest|minimum|rarest|"
                     r"not|never|no longer|except|excluding|exclude|other than|apart from|besides|aside from|non-?root|rather than|instead of)\b|n['’]t\b")


def _unread(T) -> bool:
    return _UNREAD.search(T.rpartition(" | ")[0] or T) is not None


def h_count(q, ev, text, T):
    if not re.search(r"how many|number of|\bcount\b|\btotal\b", T):
        return NOT_MINE
    if not re.search(r"log ?[io]ns?\b|logons?|logged|password|\bssh\b|sshd|authenticat|attempt|session", T):
        return NOT_MINE
    if _CONDITION.search(T) or _unread(T):
        return None
    scope = ev.scope(q, text)
    fail = _FAIL.search(T) is not None
    succ = not fail and _SUCCESS.search(T) is not None
    ssh = ev.ssh(scope)
    if not ssh:
        kinds = ("btmp",) if fail else ("utmp",) if succ else ()
        files = ev.of(kinds, scope) if kinds else []
        if not files:
            return NOT_MINE
        if _overlap([{(r["type"], r["user"], r["line"], r["sec"]) for r in i.parsed if r["type"] in (6, 7)} for i in files]):
            return None                             # utmp beside wtmp, or a rotated copy: one login twice
        recs = [r for i in files for r in i.parsed if (r["type"] in (6, 7) if fail else r["type"] == 7)]
        recs = _utmp_filter(recs, text)
        if re.search(r"(?:distinct|unique|different)\s+(?:source\s+)?(?:ips?|address|host)|how many (?:ips?\b|ip addresses|addresses|hosts)", T):
            return str(len({r["addr"] or r["host"] for r in recs if r["addr"] or r["host"]})) if recs else None
        if re.search(r"(?:distinct|unique|different)\s+(?:user|account)|how many (?:users|usernames|accounts)", T):
            return str(len({r["user"] for r in recs})) if recs else None
        return str(len(recs)) if recs else None
    if ev.of("btmp", scope) and fail:
        return None                                 # two sources of failed logins: which one is asked is not ours to say
    if fail and not re.search(r"\bssh\b|sshd", T) and any(
            _OTHER_FAIL.search(r.get("msg") or "") and not (r.get("app") and (nh._SSHD.match(r["app"]) or nh._SSHD_OLD.match(r["app"])))
            for _, recs in ev.records(scope) for r in recs):
        return None                                 # su, login, ftp ... failed too, and the question does not say SSH: which are asked is not ours to say
    if _overlap([{k for e in es for k in _rec_keys(e["rec"])} for _, es in ssh]):
        return None                                 # two files hold the same lines (a copy, a journal export): one event twice
    events = _auth_filter([e for _, es in ssh for e in es], text)
    if events is None or not (fail or succ):
        return None
    if not fail and re.search(r"attempt|\btried\b|\btry\b|\btrying\b", T):
        # an attempt is a failure or a success: only the distinct addresses that made one are counted,
        # and only as addresses (sshd also logs reverse-DNS names for the same machines)
        if re.search(r"(?:distinct|unique|different)\s+(?:source\s+)?(?:ips?|address)|how many (?:ips?\b|ip addresses|addresses)", T):
            made = [e for e in events if e["kind"] in ("failed", "accepted", "invalid_user", "max_attempts")]
            if not made or any(not e["ip"] for e in made):
                return None                         # a source logged by name: it may be one of the addresses
            return str(len({e["ip"] for e in made}))
        return None
    if fail and re.search(r"invalid users?|non-?existent|unknown users?", T):
        a = sum(e["n"] for e in events if e["kind"] == "invalid_user")
        b = sum(e["n"] for e in events if e["kind"] == "failed" and e["invalid"])
        sel = [e for e in events if e["invalid"]]
        if re.search(r"(?:distinct|unique|different)|how many (?:users|usernames|accounts)", T):
            return str(len({e["user"] for e in sel})) if sel else None
        if a and b and a != b:
            return pick(q, "count", "ssh.invalid_user", [("invalid_user_lines", a), ("failed_for_invalid_user", b)])
        return str(a or b) if (a or b) else None
    sel = [e for e in events if e["kind"] == ("failed" if fail else "accepted")]
    if not sel:
        return None
    if _ATTACK.search(T) and not _ips_in(text) and len({e["ip"] or e["host"] for e in sel}) > 1 and \
            not re.search(r"(?:distinct|unique|different)|how many (?:ips?\b|ip addresses|addresses|hosts|sources|users|usernames|accounts)", T):
        src = _attacker(ssh)     # 'the attacker' among several sources: the rule, or nothing
        if src is None:
            return None
        sel = [e for e in sel if (e["ip"] or e["host"]) == src]
    if re.search(r"(?:distinct|unique|different)\s+(?:source\s+)?(?:ips?|address|host)|how many (?:ips?\b|ip addresses|addresses|hosts|sources)", T):
        return str(len({e["ip"] or e["host"] for e in sel}))
    if re.search(r"(?:distinct|unique|different)\s+(?:user|account)|how many (?:users|usernames|accounts)", T):
        return str(len({e["user"] for e in sel}))
    if re.search(r"password", T) and not re.search(r"publickey|public key", T):
        sel = [e for e in sel if e["method"] == "password"]
        if not sel:
            return None
    elif len({e["method"] for e in sel}) > 1 and fail:
        pw = [e for e in sel if e["method"] == "password"]
        every, only = sum(e["n"] for e in sel), sum(e["n"] for e in pw)
        if any(e["repeated"] for e in sel) or not pw:
            return None
        return pick(q, "count", "ssh.failed.methods", [("all_methods", every), ("password", only)])
    lines, total = len(sel), sum(e["n"] for e in sel)
    if lines == total:
        return str(total)
    return pick(q, "count", "ssh.repeated", [("with_repeats", total), ("lines", lines)])


def _edge(pairs, which):
    """The first or last of [(item, event)]: by file order inside one file, by time across files
    when every event has one. None when the order cannot be shown, or `which` is None and there
    is more than one event."""
    if not pairs:
        return None
    if which is None:
        return pairs[0][1] if len(pairs) == 1 else None
    if len({id(i) for i, _ in pairs}) == 1:
        return pairs[0][1] if which == "first" else pairs[-1][1]
    times = [e["rec"]["time"] for _, e in pairs]
    if any(t is None or t.tzinfo is None for t in times):
        return None
    order = sorted(pairs, key=lambda p: p[1]["rec"]["time"])
    return order[0][1] if which == "first" else order[-1][1]


def _attack_sources(ssh):
    """[(source, accepted event, item)] under the brute-force rule, per file."""
    out = []
    for item, events in ssh:
        out += [(src, e, item) for src, e in nh.fail_then_success(events)]
    return out


def _attacker(ssh):
    """The one source the brute-force rule names, or None: exactly one source has failures and
    then an accepted login, and no other source failed as often (counted with repeats and by
    lines). An administrator's one mistyped password beside another address's hundred failures
    names nobody."""
    src = _one([s for s, _, _ in _attack_sources(ssh)])
    if src is None:
        return None
    summary = nh.ssh_summary([e for _, es in ssh for e in es])
    mine = summary.get(src) or {}
    for other, s in summary.items():
        if other != src and s["failed"] and (s["failed"] >= mine.get("failed", 0) or s["failed_lines"] >= mine.get("failed_lines", 0)):
            return None
    return src


def _overlap(groups) -> bool:
    """Do two files hold the same event (the same line of the same process in the same minute and
    second, or the same utmp record)? Then a count over them counts it twice."""
    seen = {}
    for n, keys in enumerate(groups):
        for k in keys:
            if seen.setdefault(k, n) != n:
                return True
    return False


def _rec_keys(rec):
    """The keys one log record is found again under in another file: day, minute and second (the
    hour depends on the zone the file was written in), the process id and the message. A record
    with a full time gives the day before and after as well: its zone may differ from a year-less
    file's."""
    t, tail = rec.get("time"), (str(rec.get("pid")), (rec.get("msg") or "").strip())
    if rec.get("md"):
        return [(rec["md"][1], rec["md"][3], rec["md"][4]) + tail]
    if t is None:
        return [(None,) + tail]
    return [((t + timedelta(days=d)).day, t.minute, t.second) + tail for d in (-1, 0, 1)]


def h_time(q, ev, text, T):
    if not re.search(r"\bwhen\b|what time|timestamp|\btime\b|\bdate\b", T):
        return NOT_MINE
    if not re.search(r"log(?:ged|s)? ?[io]n\b|logons?|logins?|authenticat|\baccess\b|session|password|\bssh\b|brute", T):
        return NOT_MINE
    which = ("last" if re.search(r"\blast\b|most recent|latest|\bfinal\b", T) else
             "first" if re.search(r"\bfirst\b|earliest|initial", T) else None)
    if _CONDITION.search(T):
        return None
    fail = _FAIL.search(T) is not None
    began = not fail and _ATTACK.search(T) and re.search(r"\b(?:start(?:ed|s)?|began|begin|begun)\b", T) and which != "last"
    if not fail and not began and not _SUCCESS.search(T):
        return None
    scope = ev.scope(q, text)
    ssh = ev.ssh(scope)
    if began:                                       # the attack began with the first failure of its one source
        if not ssh or _ips_in(text):
            return None
        src = _attacker(ssh)
        pairs = [(i, e) for i, es in ssh for e in es if e["kind"] in nh.FAIL_KINDS and (e["ip"] or e["host"]) == src]
        e = _edge(pairs, "first") if src else None
        return time_answer(q, text, moment_of_record(e["rec"], ev)) if e else None
    if not ssh:
        files = ev.of(("btmp",) if fail else ("utmp",), scope)
        if not files:
            return NOT_MINE
        recs = _utmp_filter([r for i in files for r in i.parsed if (r["type"] in (6, 7) if fail else r["type"] == 7)], text)
        if not recs or (which is None and len(recs) != 1):
            return None
        r = min(recs, key=lambda x: x["time"]) if which != "last" else max(recs, key=lambda x: x["time"])
        return time_answer(q, text, moment_of_epoch(r["sec"], "epoch.utmp"))
    kind = "failed" if fail else "accepted"
    pairs = [(i, e) for i, es in ssh for e in es if e["kind"] == kind]
    kept = _auth_filter([e for _, e in pairs], text)
    if kept is None:
        return None
    kept = {id(k) for k in kept}
    pairs = [(i, e) for i, e in pairs if id(e) in kept]
    if _ATTACK.search(T) and not _ips_in(text):
        sources = _attack_sources(ssh)
        src = _attacker(ssh)
        if src is None:
            return None
        if kind == "accepted" and which == "first":
            mine = {id(p[1]) for p in pairs}
            pairs = [(i, e) for s, e, i in sources if id(e) in mine]   # the login the failures led to
        else:
            pairs = [(i, e) for i, e in pairs if (e["ip"] or e["host"]) == src]
    e = _edge(pairs, which)
    if e is None:
        return None
    return time_answer(q, text, moment_of_record(e["rec"], ev))


_NOT_THE_SOURCE = re.compile(r"\bc2\b|command and control|call(?:s|ed)? ?back|exfil|beacon|connect(?:s|ed)? to|reverse shell|destination|outbound|"
                             r"\bto which\b|download|server(?:'s)? ip|\bvictim\b|\btarget(?:ed)? (?:host|server|machine)|"
                             r"compromised (?:host|server|machine|system)|of the (?:web |ssh |linux )?(?:server|host|machine)\b|local (?:ip|address)")


_WHO = r"(?:attacker|intruder|adversary|threat actor|hacker)"
_IPW = r"(?:ips?|ip address(?:es)?|address(?:es)?|remote hosts?|hosts?|sources?)"
_ATTACK_SOURCE = re.compile(
    _WHO + r"(?:'s|\u2019s)?\s+(?:source\s+|remote\s+)?" + _IPW + r"\b"
    r"|\b" + _IPW + r"\b[^?.|]{0,24}\b(?:of|used by|belonging to) the (?:" + _WHO + r"|brute[- ]?forc\w*|attack\b)"
    r"|\b" + _IPW + r"\s+(?:that\s+|which\s+)?(?:was\s+|is\s+)?(?:brute|attack|perform|conduct|launch|carried|responsible|behind|guess|tried|"
    r"attempt|successfully|logged|gained|broke|compromised the (?:account|user|login))"
    r"|\b(?:from|by) (?:which|what) " + _IPW + r"\b"
    r"|\bwhere\b[^?.|]*\b(?:attack\w*|brute\w*)\b[^?.|]*\bfrom\b"
    r"|\| (?:[\w ]+ )?(?:attacker|brute ?force|malicious|source) (?:ip|address|host)$")


def h_source(q, ev, text, T):
    got = _h_source(q, ev, text, T)
    if isinstance(got, str) and re.search(r"\bips?\b|ip address", T) and not nh._is_ip(got):
        return None                                 # sshd logged a host name; an address is asked
    return got


def _h_source(q, ev, text, T):
    if not re.search(r"\bips?\b|ip address|\baddress\b|\bsource\b|\bhost\b|from where|where .*\bfrom\b", T):
        return NOT_MINE
    if not re.search(_ATTACK.pattern + r"|fail|most|log(?:ged|s)? ?[io]n\b|logins?|logons?|success|accepted|\bssh\b|password", T):
        return NOT_MINE
    if _NOT_THE_SOURCE.search(T) or re.search(r"how many|number of|\bport\b", T):
        return None
    if not (_asks(T, _IP_NOUNS) or re.search(r"from where|where .*\bfrom\b|from (?:which|what) ", T)):
        return NOT_MINE
    if _unread(T):
        return None
    if re.search(r"\b(?:most|highest|largest|greatest|maximum)\b(?: number of| count of)?(?: \w+){0,2} "
                 r"(?:users?|usernames?|user names?|accounts?|names|ports?|passwords|sessions?|commands?)\b", T):
        return None                                 # 'tried the most usernames': a count of names per address, not of failures
    scope = ev.scope(q, text)
    ssh = ev.ssh(scope)
    fail = _FAIL.search(T) is not None
    if not ssh:
        files = ev.of(("btmp",) if fail else ("utmp",), scope)
        if not files or _ATTACK.search(T):
            return NOT_MINE if not files else None
        recs = _utmp_filter([r for i in files for r in i.parsed if (r["type"] in (6, 7) if fail else r["type"] == 7)], text)
        return _one([r["addr"] or r["host"] or None for r in recs]) if recs and all(r["addr"] or r["host"] for r in recs) else None
    events = [e for _, es in ssh for e in es]
    if re.search(r"\bmost\b|highest|largest|greatest|maximum", T):
        if not (fail or re.search(r"attempt", T)):
            return None
        if any(e["kind"] == "failed" and not e["ip"] for e in events):
            return None                             # some failures are logged by host name: a name and an address may be one machine
        if not re.search(r"\bssh\b|sshd", T) and any(
                _OTHER_FAIL.search(r.get("msg") or "") and not (r.get("app") and (nh._SSHD.match(r["app"]) or nh._SSHD_OLD.match(r["app"])))
                for _, recs in ev.records(scope) for r in recs):
            return None                             # su, login, ftp ... failed too, and the question does not say SSH
        summary = nh.ssh_summary(events)
        best = []
        for field in ("failed", "failed_lines"):
            top = max((s[field] for s in summary.values()), default=0)
            best.append([src for src, s in summary.items() if s[field] == top and top > 0])
        return best[0][0] if len(best[0]) == 1 and best[0] == best[1] else None
    users = _named_users(text, {e["user"] for e in events})
    if _stranger(text, {e["user"] for e in events}):
        return None                                 # a user the log does not hold
    if _ATTACK.search(T):
        if not _ATTACK_SOURCE.search(T):
            return None                             # an address near the word 'attacker' is not asked as its source
        return _attacker(ssh)
    if fail and users:                              # 'failed to log in as fztu': that user's failures, never its login
        sel = [e for e in events if e["kind"] == "failed" and e["user"] in users]
        return _one([e["ip"] or e["host"] for e in sel]) if sel and all(e["ip"] or e["host"] for e in sel) else None
    if users or not fail:
        if not _SUCCESS.search(T):
            return None
        sel = [e for e in events if e["kind"] == "accepted" and (not users or e["user"] in users)]
        return _one([e["ip"] or e["host"] for e in sel])
    return _one([e["ip"] or e["host"] for e in events if e["kind"] == "failed"])


def h_user(q, ev, text, T):
    if not re.search(r"\b(?:users?|usernames?|accounts?)\b", T):
        return NOT_MINE
    if not (_asks(T, _USER_NOUNS) or re.search(r"\bwho\b", T)):
        return NOT_MINE
    if not re.search(_ATTACK.pattern + r"|success|log(?:ged|s)? ?[io]n\b|logins?|accepted|gain|fail|target|\bssh\b", T):
        return NOT_MINE
    if re.search(r"how many|number of", T):
        return None
    ssh = ev.ssh(ev.scope(q, text))
    if not ssh:
        return NOT_MINE
    events = [e for _, es in ssh for e in es]
    if _unread(T):
        return None
    if re.search(r"\bmost\b|highest", T):
        if not (_FAIL.search(T) or re.search(r"target|attempt", T)):
            return None
        if _ips_in(text) or re.search(r"invalid|non-?existent|unknown|\bvalid\b", T):
            return None                             # 'the invalid user tried the most', 'the user 1.2.3.4 tried the most': a subset, not applied
        best = []
        for weight in (lambda e: e["n"], lambda e: 1):
            c = Counter()
            for e in events:
                if e["kind"] == "failed":
                    c[e["user"]] += weight(e)
            top = max(c.values(), default=0)
            best.append(sorted(u for u, n in c.items() if n == top and top > 0))
        return best[0][0] if len(best[0]) == 1 and best[0] == best[1] else None
    ips = _ips_in(text)
    if _named_users(text, {e["user"] for e in events}) or _stranger(text, {e["user"] for e in events}):
        return None                                 # 'which user logged in as root': a user is named and a user is asked; that relation is not read
    if ips:
        if _FAIL.search(T) or re.search(r"\btr(?:y|ied|ies|ying)\b|attempt|target|guess", T):
            return None                             # the names an address tried are many; its accepted login is not what is asked
        return _one([e["user"] for e in events if e["kind"] == "accepted" and (e["ip"] or e["host"]) in ips])
    if _ATTACK.search(T):
        src = _attacker(ssh)
        if src is None:
            return None
        if re.search(r"target|tried|attempt|guess", T):
            return _one([e["user"] for e in events if e["kind"] == "failed" and (e["ip"] or e["host"]) == src])
        return _one([e["user"] for e in events if e["kind"] == "accepted" and (e["ip"] or e["host"]) == src])
    if _FAIL.search(T):
        return None
    if _SUCCESS.search(T):
        return _one([e["user"] for e in events if e["kind"] == "accepted"])
    return None


def _exec_value(x, T):
    """One audit exec's command: EXECVE and PROCTITLE when they agree (a title cut at its 127
    bytes is the start of the arguments), else ('differ', execve, title)."""
    c, t = x["command"], x["proctitle"]
    if c is None or t is None:
        return c if c is not None else t
    if c == t or (len(t.encode()) >= 127 and c.startswith(t)):
        return c
    if re.search(r"proctitle|process title", T):
        return t
    if re.search(r"execve|argument", T):
        return c
    return ("differ", c, t)


def h_audit(q, ev, text, T):
    if not re.search(r"command|proctitle|process title|execve|execut|\bran\b|\brun\b|argument|payload", T):
        return NOT_MINE
    files = ev.of("audit", ev.scope(q, text))
    if not files:
        return NOT_MINE
    execs = [x for i in files for e in i.parsed for x in [nh.audit_exec(e)] if x]
    if not execs or not all(x["whole"] for x in execs):
        return None                                 # a cut EXECVE record: no command of this file is shown to be the one
    if re.search(r"\bhex|encod|decod|obfuscat", T):
        execs = [x for x in execs if x["hex"]]
    for rx, field in ((r"\bpid\s*(?:=|of|is)?\s*(\d+)", "pid"), (r"\bauid\s*(?:=|of|is)?\s*(\d+)", "auid"), (r"\buid\s*(?:=|of|is)?\s*(\d+)", "uid")):
        m = re.search(rx, T)
        if m:
            execs = [x for x in execs if x[field] == m.group(1)]
    m = re.search(r"(\d{9,10}\.\d+:\d+)", text)
    if m:
        execs = [x for x in execs if x["id"] == m.group(1)]
    marks = set(_quoted(text))
    for field in ("key", "comm", "exe"):
        hit = [x for x in execs if x[field] and (x[field] in marks or (field != "key" and len(PurePosixPath(x[field]).name) >= 3
                                                                    and _has_word(text, PurePosixPath(x[field]).name)))]
        if hit:
            execs = hit
    if re.search(r"how many|number of", T):
        return None
    value = _one([_exec_value(x, T) for x in execs])
    if value is None:
        return None
    if isinstance(value, tuple):
        return pick(q, "command", "audit.execve_vs_proctitle", [("execve", value[1]), ("proctitle", value[2])])
    if re.search(r"payload|base64|\binner\b|ultimately|underlying|deobfuscat", T):
        inner, _ = nh.innermost(value)
        return inner.rstrip("\r\n") if inner else None
    return value


def h_history(q, ev, text, T):
    if "history" not in T:
        return NOT_MINE
    files = ev.of("history", ev.scope(q, text))
    if not files:
        return NOT_MINE
    cmds = [c for i in files for c in i.parsed]
    if re.search(r"how many|number of", T):
        return str(len(cmds)) if re.search(r"commands?\b", T) and len(files) == 1 else None
    if re.search(r"decod|base64|encod|payload|obfuscat|hidden", T):
        inner = [nh.innermost(c["command"])[0] for c in cmds]
        v = _one([x for x in inner if x])
        return v.rstrip("\r\n") if v else None
    return NOT_MINE


HANDLERS = (h_plist, h_unit, h_cron, h_quarantine, h_tcc, h_preload, h_sudo, h_count, h_time, h_account, h_source, h_user,
            h_audit, h_history)
_MINE = re.compile(r"plist|launch|cron|schedul|systemd|\bunit\b|service|timer|execstart|quarantine|download|tcc|privacy|permission|camera|"
                   r"microphone|screen|accessib|preload|sudo|account|user|uid|log ?[io]n|logon|password|ssh|authenticat|attempt|session|"
                   r"\bip\b|address|source|host|command|proctitle|execve|execut|\bran\b|\brun\b|argument|payload|history|brute|attack")


def _reading(q):
    """(text, T) of a question this toolkit may answer, or None: the question as written, and the
    question plus the words of its answer id, lower case."""
    f = _fmt(q)
    if str(f.get("kind") or "") in ("mitre_attack_id", "json", "ordered_tokens"):
        return None
    text = " ".join(str(q.get("question") or "").split())
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    if not text or _known_lane(q, aid, text):
        return None
    T = (text + " | " + re.sub(r"[-_.]+", " ", aid)).lower()
    return (text, T) if _MINE.search(T) else None


def answer(q, ev):
    """One question's answer: plain, unsure or None (see the module text)."""
    got = _reading(q)
    if got is None or ev.partial:
        return None
    text, T = got
    for handler in HANDLERS:
        got = handler(q, ev, text, T)
        if got is not NOT_MINE:
            return _finish(q, got)
    return None


def solve_set(questions, files, ctx) -> dict:
    out = {}
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    ev = None
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            if _reading(q) is None:         # not ours: no file is read for it
                out[qid] = None
            else:
                if ev is None:
                    ev = Evidence(files)
                out[qid] = answer(q, ev)
        except Exception:               # a fact that cannot be read is no answer
            out[qid] = None
        if partial is not None:
            partial[qid] = out[qid]
    return out


# ---- the lane signal ---------------------------------------------------------------------------------

_NAME_MARKS = re.compile(r"(^|/)(auth\.log|secure|syslog|messages|audit\.log|[wbu]tmp|lastlog|crontab|ld\.so\.preload|passwd|shadow|"
                         r"authorized_keys|\.?(bash|zsh)_history|\.DS_Store|TCC\.db|com\.apple\.LaunchServices\.QuarantineEventsV2)"
                         r"(\.\d+)?(\.gz)?$|\.(service|timer|plist)$|(^|/)cron\.d/|Launch(Agents|Daemons)/|(^|/)var/log/|(^|/)etc/systemd/", re.I)
_BYTE_MARKS = (b"sshd[", b"msg=audit(", b"<plist", b"ExecStart=", b"__REALTIME_TIMESTAMP", b"processImagePath", b"pam_unix(",
               b" ; COMMAND=", b"CRON[", b"LSQuarantineEvent", b"kTCCService",
               b"(pam_unix)[", b"sshd-session[", b"systemd-logind[", b"useradd[")      # the PAM tag of older systems (loghub's Linux_2k.log)
_Q_MARKS = re.compile(r"\b(ssh|sshd|brute.?force|failed (?:log ?ins?|passwords?)|auth\.log|sudo|cron\w*|systemd|execstart|unit file|"
                      r"launch ?(?:agent|daemon)s?|launchd|plist|auditd?|proctitle|execve|[wbu]tmp|lastlog|uid 0|authorized_keys|"
                      r"bash history|ld\.so\.preload|quarantine|tcc|unified log|linux|macos|syslog|journal(?:d|ctl)?)\b", re.I)


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like Linux or macOS host forensics.
    0.0 for the questions of a known lane. Cheap: names, the first 64 KiB of each file, words."""
    questions = list(questions or [])
    for q in questions:
        text = str(q.get("question") or "")
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        if _known_lane(q, aid, text):
            return 0.0
    f, seen = 0.0, set()
    for name, data in (files or {}).items():
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        tail = name.split(ARROW)[-1].replace("\\", "/")
        head = bytes(data[:SNIFF])
        if head[:8] == b"bplist00" or nh.is_ds_store(head) or any(m in head for m in _BYTE_MARKS) or \
                (len(data) % nh.UTMP_SIZE == 0 and nh.is_utmp(data[:nh.UTMP_SIZE * 8])):
            f = 1.0
            break
        if _NAME_MARKS.search(tail):
            f = max(f, 0.6)
    share = sum(1 for q in questions if _Q_MARKS.search(str(q.get("question") or "") + " " +
                                                        str(q.get("answer_id") or q.get("id") or "").replace("-", " ").replace("_", " "))) / len(questions) \
        if questions else 0.0
    if not f and not share:
        return 0.0
    return round(min(1.0, 0.55 * f + 0.45 * min(1.0, 2 * share)), 2)


# ---- persistence rows (the row shape of solvers/toolkits/edr_persistence.py) ---------------------------

def _row(mechanism, location, name=None, command=None, author=None, trigger=None, **extra):
    return {"mechanism": mechanism, "location": location or None, "name": name or None, "command": command or None,
            "author": author or None, "trigger": trigger or None, "source": location or "", "origin": KEY, "technique": None,
            "extra": extra}


def persistence_rows(files) -> list:
    """Rows {mechanism, location, name, command, author, trigger, source, origin, technique,
    extra} for what persists on a Linux or macOS host in these files: cron jobs, systemd services
    and timers, launchd jobs, ld.so.preload entries, authorized_keys and accounts with uid 0.
    `technique` is left None: naming it is edr_persistence's job (its MECHANISMS table)."""
    ev = files if isinstance(files, Evidence) else Evidence(files)
    rows = []
    for i in ev.of("crontab"):
        for j in i.parsed["jobs"]:
            rows.append(_row("cron", i.tail, None, j["command"], j["user"], j["schedule"], line=j["line"], alt=j["alt"]))
    for i in ev.of("unit"):
        u = i.parsed
        if "Timer" in u:
            sched = [v for k in ("OnCalendar", "OnBootSec", "OnUnitActiveSec", "OnStartupSec", "OnActiveSec") for v in nh.unit_values(u, k)]
            rows.append(_row("systemd_timer", i.tail, i.base, _one(nh.unit_values(u, "Unit")), None, _one(sched), schedules=sched))
        elif nh.unit_values(u, "ExecStart"):
            rows.append(_row("systemd_service", i.tail, i.base, _one(nh.unit_values(u, "ExecStart")), _one(nh.unit_values(u, "User")),
                             _one(nh.unit_values(u, "WantedBy")), description=_one(nh.unit_values(u, "Description")),
                             exec_start=nh.unit_values(u, "ExecStart")))
    for i in ev.of("plist"):
        j = nh.launchd_job(i.parsed, i.tail)
        if j:
            trigger = "RunAtLoad" if j["run_at_load"] is True else "StartInterval" if j["start_interval"] else \
                "StartCalendarInterval" if j["start_calendar_interval"] else "KeepAlive" if j["keep_alive"] else None
            cmd = " ".join(j["program_arguments"]) if j["program_arguments"] else j["program"]
            if j["program"] and j["program_arguments"] and j["program_arguments"][0] != j["program"]:
                cmd = f"{j['program']} [argv: {cmd}]"     # launchd executes Program; ProgramArguments is the argv it is given
            rows.append(_row(j["kind"] or "launchd_job", i.tail, j["label"], cmd,
                             j["user"], trigger, program_path=j["program_path"], notes=j["notes"], scope=j["scope"]))
    for i in ev.of("ld_preload"):
        for lib in i.parsed:
            rows.append(_row("ld_preload", i.tail, None, lib))
    for i in ev.of("authorized_keys"):
        for k in i.parsed:
            rows.append(_row("ssh_authorized_keys", i.tail, k["comment"] or None, k["options"].get("command") if k["options"] else None,
                             None, None, key_type=k["type"], sha256=k["sha256"], options=dict(k["options"])))
    for i in ev.of("passwd"):
        for a in nh.passwd_anomalies(i.parsed):
            if a["kind"] == "uid0_not_root":
                rows.append(_row("local_account_uid0", i.tail, a["name"], None, None, None, detail=a["detail"]))
    return rows


# ---- the command -------------------------------------------------------------------------------------

def _t(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if dt is not None and dt.tzinfo else (dt.isoformat() if dt else "-")


def describe(item, ev, cap=12) -> dict:
    """What one file holds, for the triage: {file, kind, size, facts: [text, ...]}."""
    kind, p, facts = ev.read(item), item.parsed, []
    if kind in ("syslog", "journal"):
        fmts = Counter(r["fmt"] for r in p)
        facts.append(f"{len(p)} records ({', '.join(f'{k} x{n}' for k, n in fmts.items())}); hosts: "
                     + ", ".join(sorted({r['host'] for r in p if r['host']})[:5]))
        if fmts.get("rfc3164"):
            years = Counter(ev.year_of(r) for r in p if r.get("md"))
            proven = {y: n for y, n in years.items() if y}
            facts.append("RFC 3164 stamps have NO YEAR and no zone: a time from them is unsure unless another artifact proves the year"
                         + ("".join(f"; year {y} PROVEN (and UTC) for {n} of {sum(years.values())} records by a wtmp, auditd or journald record of the same second"
                                    for y, n in proven.items()) if proven else ""))
        events = nh.ssh_events(p)
        for src, s in list(nh.ssh_summary(events).items())[:cap]:
            facts.append(f"ssh {src}: failed {s['failed']} (lines {s['failed_lines']}), accepted {s['accepted']}, invalid_user {s['invalid_user']}; "
                         f"users failed: {', '.join(str(u) for u in s['users_failed'][:6])}; accepted as: {', '.join(str(u) for u in s['users_accepted'][:6]) or '-'}")
        for src, e in nh.fail_then_success(events):
            facts.append(f"FAILURES THEN SUCCESS from {src}: accepted {e['method']} for {e['user']} at '{e['rec']['stamp']}' (line {e['rec']['line']})")
        for e in nh.sudo_events(p)[:cap]:
            facts.append(f"sudo {e['user']} -> {e['runas']}: {e['command']}" + (f"  [{e['note']}]" if e["note"] else ""))
        for e in nh.account_events(p)[:cap]:
            facts.append(f"account {e['kind']}: " + ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("kind", "rec") and v is not None))
        for e in nh.cron_runs(p)[:cap]:
            facts.append(f"cron ran ({e['user']}): {e['command']}")
    elif kind == "audit":
        facts.append(f"{len(p)} audit events; record types: " + ", ".join(f"{k} x{n}" for k, n in Counter(t for e in p for t in e["types"]).most_common(8)))
        shown = 0
        for e in p:
            x = nh.audit_exec(e)
            if x and shown < cap * 2:
                shown += 1
                cmd = x["command"] if x["command"] is not None else x["proctitle"]
                facts.append(f"exec {x['id']} pid={x['pid']} auid={x['auid']} uid={x['uid']} key={x['key']}" + (" [hex]" if x["hex"] else "") + f": {cmd}")
                if x["command"] is not None and x["proctitle"] is not None and x["command"] != x["proctitle"]:
                    facts.append(f"   proctitle differs: {x['proctitle']}")
                for layer in nh.decode_layers(cmd or ""):
                    facts.append(f"   {layer['method']} -> {layer['decoded']!r}")
            for r in e["records"]:
                if r["type"] == "SOCKADDR" and r["fields"].get("saddr"):
                    s = nh.decode_saddr(r["fields"]["saddr"])
                    if s and s.get("ip") and shown < cap * 3:
                        shown += 1
                        facts.append(f"sockaddr {e['id']}: {s['ip']}:{s['port']}")
                if r["type"].startswith("USER_") and r["fields"].get("res") in ("failed", "success") and shown < cap * 3:
                    shown += 1
                    f = r["fields"]
                    facts.append(f"{r['type']} {e['id']}: acct={f.get('acct')} addr={f.get('addr')} exe={f.get('exe')} res={f.get('res')}")
    elif kind in ("utmp", "btmp"):
        facts.append(f"{len(p)} records; types: " + ", ".join(f"{k} x{n}" for k, n in Counter(r["type_name"] for r in p).items()))
        for r in [r for r in p if r["type"] in (6, 7)][:cap]:
            what = "failed login" if kind == "btmp" else "login" if r["type"] == 7 else "getty (LOGIN_PROCESS, no user logged in)"
            facts.append(f"{what} {r['user']} on {r['line']} from {r['addr'] or r['host'] or '-'} at {_t(nh.from_epoch(r['sec']))}")
    elif kind == "lastlog":
        for r in p[:cap]:
            facts.append(f"uid {r['uid']}: last login {_t(nh.from_epoch(r['time']))} on {r['line']} from {r['host'] or '-'}")
    elif kind == "crontab":
        sysk = nh.crontab_kind(item.tail)
        if sysk is None and any(j["alt"] for j in p["jobs"]):
            facts.append("the path does not say whether this is a system crontab: user and command have two readings")
        else:
            facts.append("system crontab (the sixth field is the user)" if sysk else "user crontab (no user field)")
        for j in p["jobs"][:cap]:
            facts.append(f"line {j['line']}: [{j['schedule']}] user={j['user'] or (j['alt'] or {}).get('user', '-')} command={j['command']}")
        if p["env"]:
            facts.append("env: " + ", ".join(f"{k}={v}" for k, v in p["env"].items()))
    elif kind == "unit":
        for sec, keys in p.items():
            for k, values in keys.items():
                if k in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "User", "WantedBy", "OnCalendar", "OnBootSec", "Description",
                         "Restart", "Unit", "Environment", "EnvironmentFile", "Type"):
                    facts += [f"[{sec}] {k}={v}" for v in values]
    elif kind == "plist":
        j = nh.launchd_job(p, item.tail) if isinstance(p, dict) else None
        if j:
            facts.append(f"launchd job ({j['kind'] or 'folder unknown'}): Label={j['label']} program_path={j['program_path']} RunAtLoad={j['run_at_load']} "
                         f"KeepAlive={j['keep_alive']} StartInterval={j['start_interval']}")
            if j["program_arguments"]:
                facts.append("ProgramArguments: " + json.dumps(j["program_arguments"]))
            facts += ["NOTE " + n for n in j["notes"]]
        elif isinstance(p, dict):
            facts.append("keys: " + ", ".join(str(k) for k in list(p)[:20]))
        else:
            facts.append(f"top value: {type(p).__name__}")
        if item.data[:8] == b"bplist00":
            facts.append("binary plist" + (" (NSKeyedArchiver, unwrapped)" if nh.is_keyed_archive(nh.read_plist(item.data)) else ""))
    elif kind == "passwd":
        facts.append(f"{len(p)} accounts")
        facts += [f"ANOMALY {a['kind']}: {a['name']} ({a['detail']})" for a in nh.passwd_anomalies(p)]
    elif kind == "shadow":
        facts.append(f"{len(p)} rows; schemes: " + ", ".join(f"{k} x{n}" for k, n in Counter(r["scheme"] for r in p).items()))
        facts += [f"ANOMALY {a['kind']}: {a['name']} ({a['detail']})" for a in nh.shadow_anomalies(p)]
    elif kind == "group":
        facts += [f"{r['name']} ({r['gid']}): {', '.join(r['members'])}" for r in p if r["members"]][:cap]
    elif kind == "authorized_keys":
        for k in p[:cap]:
            facts.append(f"{k['type']} {k['sha256']} comment={k['comment'] or '-'}" + (f" OPTIONS {dict(k['options'])}" if k["options"] else ""))
    elif kind == "ld_preload":
        facts += [f"ANOMALY preloaded library: {e}" for e in p]
    elif kind == "history":
        facts.append(f"{len(p)} commands, {sum(1 for c in p if c['time'])} with a time")
        for c in p[:cap * 3]:
            layers = nh.decode_layers(c["command"])
            if layers or re.search(r"curl|wget|base64|chmod \+x|/tmp/|nc |ncat|useradd|crontab|authorized_keys|systemctl|history -c", c["command"]):
                facts.append(f"{_t(nh.from_epoch(c['time'])) if c['time'] else '-'}  {c['command']}")
                facts += [f"   {layer['method']} -> {layer['decoded']!r}" for layer in layers]
    elif kind == "docker":
        facts.append(f"{len(p)} lines; streams: " + ", ".join(f"{k} x{n}" for k, n in Counter(r["stream"] for r in p).items()))
        facts += [f"{r['stamp']} {r['stream']}: {r['log'][:160]}" for r in p[:5]]
    elif kind == "unified":
        facts.append(f"{len(p)} entries; processes: " + ", ".join(f"{k} x{n}" for k, n in Counter(r["process"] for r in p).most_common(8)))
        facts.append("subsystems: " + ", ".join(f"{k} x{n}" for k, n in Counter(r["subsystem"] for r in p if r["subsystem"]).most_common(8)))
    elif kind == "quarantine":
        for r in p[:cap]:
            facts.append(f"{_t(r['time'])} agent={r['agent']} url={r['url']} origin={r['origin']}")
    elif kind == "tcc":
        for r in p[:cap * 2]:
            facts.append(f"{r['service']} client={r['client']} auth={r['auth']} modified={_t(r['last_modified'])}")
    elif kind == "ds_store":
        facts.append(f"{len(p)} names: " + ", ".join(p[:40]))
    return {"file": item.name, "kind": kind, "size": len(item.data), "facts": facts}


def report(files: dict) -> dict:
    ev = Evidence(files)
    seen = [describe(i, ev) for i in ev.items]
    return {"toolkit": KEY, "signal": signals([], files), "files": [d for d in seen if d["kind"] not in ("binary", "text", "sqlite") or len(ev.items) < 30],
            "persistence": persistence_rows(ev)}


def _load_paths(paths) -> dict:
    """{name: bytes} of files, folders and archives, the way a solver is handed them (tools/run.py's
    expand when it can be imported: zips, 7z, encrypted members under the known passwords)."""
    files = {}
    try:
        sys.path.insert(0, str(SOLVERS.parent / "tools"))
        import run
        expand = run.expand
    except Exception:
        expand = None
    for raw in paths:
        p = Path(raw)
        found = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
        for x in found:
            data = x.read_bytes()
            name = str(x.relative_to(p)) if p.is_dir() else x.name
            if expand:
                try:
                    expand(name, data, files)
                    continue
                except (Exception, SystemExit):
                    pass
            files.setdefault(name, data)
    return files


def main(argv) -> int:
    flags = {a for a in argv if a.startswith("--")}
    paths = [a for a in argv if not a.startswith("--")]
    if not paths or any(not Path(p).exists() for p in paths):
        print("usage: nix_host.py [--json|--persistence] <file|dir|archive>...", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    rep = report(_load_paths(paths))
    if "--persistence" in flags:
        print(json.dumps(rep["persistence"], indent=1, default=str))
        return 0
    if "--json" in flags:
        print(json.dumps(rep, indent=1, default=str))
        return 0
    for d in rep["files"]:
        print(f"== {d['file']}  [{d['kind']}, {d['size']} bytes]")
        for fact in d["facts"]:
            print("   " + fact)
    if rep["persistence"]:
        print("== persistence rows")
        for r in rep["persistence"]:
            print(f"   {r['mechanism']}: {r['location']} name={r['name']} trigger={r['trigger']} command={r['command']}")
    print(f"NIX_HOST files={len(rep['files'])} persistence={len(rep['persistence'])} signal={rep['signal']} seconds={time.monotonic() - t0:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
