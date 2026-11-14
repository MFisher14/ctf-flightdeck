#!/usr/bin/env python3
"""Deterministic multi-stage Windows-DFIR cross-artifact LINKER (finale capstone shape).

The last two Huntress leaderboards turned on a multi-part Windows incident narrative (2024
"Palimpsest"): a failed-logon burst, then the account that finally succeeds, then the process
it spawns, then the file that process writes, each stage in a different artifact. Every
per-artifact reader already exists under solvers/toolkits/ -- windows.py (evtx / prefetch /
lnk / mft / usn / recycle, and registry hives + persistence), registry.py, memory.py,
forensics.py, email.py, cloudlogs.py -- but NOTHING chains them, so in the release minute each
stage is re-derived by hand and the link between them is retyped. This module is that missing
link, and ONLY the link: it imports the readers READ-ONLY (never edits them), runs them, and
builds a self-contained in-module cross-stage index keyed on the identifiers the readers
ALREADY emit (account name / SID, logon id, host, PID, image path, file hash, timestamps). It
then resolves a question that names a prior stage's value against the next stage.

HARD RULES (AGENTS.md "Uncertain answers", "Rules for solver authors"):

  - DETECTOR ONLY. The index is a carry dict in this module (NOT the agent findings-bus, which
    is another track). Nothing on the carry auto-submits; `solve_set` returns values that still
    pass the normal plain / unsure / None gate, and `chain_report` only describes the index.
  - NEVER-GUESS, per output:
      * a field read DIRECTLY by a reader from ONE specific parsed record -- an image path, a
        written file, a file hash, a PID -- is returned PLAIN, verbatim, with no transform: the
        link only SELECTS which record answers the id, it never synthesises a value;
      * an author-named SELECTION (which account spelling, which label, which timestamp
        rendering) is UNSURE, `labels.candidates(key, options)` under the `windows.` prefix;
      * if two records match the link equally (different values), or none match, the id is None;
      * a chained inference not grounded in a specific parsed record is None;
      * a single-stage question (no cross-stage link to resolve) is None -- that is a
        per-artifact reader's job, not the linker's.

Keys: `windows.chain_<field>/<relation>` (solvers/common/labels.py knows the `windows` prefix;
the `chain_` field names never collide with the windows toolkit's own keys).

This file is not wired into tools/lane_match.py's registry (registry.py, its doc page and its
seed folder are the registration track's; the `windows.` ledger it borrows already exists); it
is called directly as `solve_set` / `chain_report`, like the hand tools beside it.
"""
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402

KEY = "windows"
ARROW = " -> "


# --------------------------------------------------------------------------- read-only readers

# The per-artifact readers are loaded from their files under PRIVATE module names, so the
# toolkits directory is never put on sys.path: `email.py` beside us would otherwise shadow the
# standard-library `email` package that windows.py / network.py rely on. Each load is best
# effort -- a reader that cannot import (a missing optional dependency) simply contributes no
# records, and the linker runs on whatever did load.
_READER_FILES = {
    "windows": HERE / "windows.py",
    "registry": HERE / "registry.py",
    "memory": HERE / "memory.py",
    "forensics": HERE / "forensics.py",
    "email": HERE / "email.py",
    "cloudlogs": HERE / "cloudlogs.py",
}
_readers = {}


def _reader(name):
    if name in _readers:
        return _readers[name]
    mod = None
    path = _READER_FILES.get(name)
    if path and path.is_file():
        try:
            spec = importlib.util.spec_from_file_location(f"_dfir_reader_{name}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception:       # noqa: BLE001  -- an optional reader that will not import
            mod = None
    _readers[name] = mod
    return mod


# --------------------------------------------------------------------------- helpers

class _Ambiguous:
    """Sentinel: the link matched more than one record equally, so the id is None."""

    __slots__ = ()

    def __repr__(self):
        return "<ambiguous>"


AMBIGUOUS = _Ambiguous()

# Event ids the chain understands (windows.py normalises every event to {id, time, data, ...}).
ID_LOGON_FAIL = 4625
ID_LOGON_OK = 4624
ID_PROC_CREATE = 4688           # Security process creation
ID_SYSMON_PROC = 1             # Sysmon process creation
ID_SYSMON_FILE = 11            # Sysmon file create
ID_OBJ_ACCESS = 4663           # object access (a write handle)

_PROC_IDS = (ID_PROC_CREATE, ID_SYSMON_PROC)
_FILE_IDS = (ID_SYSMON_FILE, ID_OBJ_ACCESS)


def _ci(data, *names):
    """Case-insensitive first-match lookup in a reader's flat data dict; '' / None are skipped."""
    if not isinstance(data, dict):
        return None
    low = None
    for n in names:
        if n in data and data[n] not in (None, ""):
            return data[n]
    low = {str(k).lower(): v for k, v in data.items()}
    for n in names:
        v = low.get(str(n).lower())
        if v not in (None, ""):
            return v
    return None


def _strv(v):
    return None if v in (None, "") else str(v)


# Field vocabularies the readers emit. Account / logon id are read by the event's ROLE:
#   - a logon event (4624/4625/4634) establishes a session: its subject is TargetUserName and
#     the session it opens is TargetLogonId;
#   - a process event (4688/Sysmon 1) runs INSIDE a session: its actor is SubjectUserName and
#     the session it ran under is SubjectLogonId.
def _ev_account(ev):
    if ev["id"] in _PROC_IDS:
        return _strv(_ci(ev["data"], "SubjectUserName", "User", "AccountName"))
    return _strv(_ci(ev["data"], "TargetUserName", "SamAccountName", "AccountName"))


def _ev_session(ev):
    if ev["id"] in _PROC_IDS:
        return _strv(_ci(ev["data"], "SubjectLogonId", "LogonId"))
    return _strv(_ci(ev["data"], "TargetLogonId", "LogonId"))


def _ev_sid(ev):
    s = _ci(ev["data"], "TargetUserSid", "SubjectUserSid", "SidString")
    return _strv(s) if s is not None else _strv(ev.get("sid"))


def _ev_image(ev):
    return _strv(_ci(ev["data"], "NewProcessName", "Image", "ProcessName"))


def _ev_pid(ev):
    return _strv(_ci(ev["data"], "NewProcessId", "ProcessId", "ProcessID", "PID"))


def _ev_hash(ev):
    return _strv(_ci(ev["data"], "Hashes", "Hash", "SHA256", "SHA1", "MD5", "Imphash"))


def _ev_target_file(ev):
    return _strv(_ci(ev["data"], "TargetFilename", "ObjectName", "FileName"))


def _ev_host(ev):
    return _strv(ev.get("computer"))


def _ev_time(ev):
    return ev.get("time")           # windows.Stamp (int subclass) or None


# --------------------------------------------------------------------------- the cross-stage index


def _artifacts(files):
    """The windows.py Artifact objects for the delivery (evtx / event logs / registry hives /
    prefetch / lnk / mft / usn / recycle / tasks), read-only."""
    w = _reader("windows")
    if w is None:
        return []
    try:
        return w.artifacts(files or {})
    except Exception:               # noqa: BLE001
        return []


def _events_of(arts):
    w = _reader("windows")
    if w is None or not arts:
        return []
    try:
        return [e for e in w.all_events(arts) if isinstance(e, dict) and e.get("id") is not None]
    except Exception:               # noqa: BLE001
        return []


def _enrich(idx, files):
    """RUN the other named readers READ-ONLY and record the stages they emit. These records never
    feed the strict event chain (`solve_set` only grounds an answer in an identifier-bearing event
    record); they broaden `chain_report` so the agent sees every stage in one place, and they can
    only ever add ambiguity, never a wrong value."""
    w, arts = _reader("windows"), idx.get("_arts") or []
    # Registry hives + autostart persistence, through windows.py's own cross-source summary.
    if w is not None and arts:
        try:
            persist = w.persistence(arts)
        except Exception:           # noqa: BLE001
            persist = []
        for row in persist or []:
            idx["persistence"].append({"mechanism": row.get("mechanism"), "name": row.get("name"),
                                       "command": row.get("command"), "where": row.get("where"),
                                       "account": row.get("account") or row.get("user"),
                                       "source": row.get("source")})
        if persist:
            idx["sources"].append("windows.persistence")
    # The standalone registry reader is imported read-only (it is module-state driven; nothing is
    # run against the delivery here, but it is loaded so the capstone spans it).
    _reader("registry")
    # Cloud / identity sign-ins: an account that appears here and on the host is one actor.
    cl = _reader("cloudlogs")
    if cl is not None:
        try:
            log = cl.load(files or {})
            cevents = list(getattr(log, "events", []) or [])
        except Exception:           # noqa: BLE001
            cevents = []
        for e in cevents:
            acct = e.get("user") or e.get("actor") or e.get("account")
            if not acct:
                continue
            idx["cloud"].append({"account": str(acct), "src": e.get("src"),
                                 "ip": e.get("ip"), "time": e.get("time")})
            rec = idx["accounts"].get(str(acct))     # enrich a host account seen in the cloud too
            if rec is not None and e.get("ip"):
                rec["hosts"].add(str(e["ip"]))
        if cevents:
            idx["sources"].append("cloudlogs")
    # Container structure (pcap / memory image / disk), host-level context only.
    fo = _reader("forensics")
    if fo is not None:
        try:
            reps = fo.reports(files or {})
        except Exception:           # noqa: BLE001
            reps = []
        for name, rep in reps or []:
            idx["containers"].append({"file": str(name), "kind": rep.get("kind"),
                                      "facts": rep.get("facts")})
        if reps:
            idx["sources"].append("forensics")
    # Memory: carved command lines (not tied to a PID -> report only, never a linked answer).
    mem = _reader("memory")
    if mem is not None:
        cmds = set()
        for _name, data in (files or {}).items():
            if not isinstance(data, (bytes, bytearray)):
                continue
            try:
                for line in mem.carve_cmdlines(bytes(data)):
                    cmds.add(line)
            except Exception:       # noqa: BLE001
                continue
        if cmds:
            idx["memory_cmdlines"] = sorted(cmds)[:200]
            idx["sources"].append("memory")
    # E-mail reader imported read-only (delivery-shape dependent; loaded so the capstone spans it).
    _reader("email")


def _sortable(events):
    """Events that carry a comparable time, oldest first. Timeless events keep their own slot but
    are never used to order a 'following' relation (that needs a time)."""
    timed = [e for e in events if _ev_time(e) is not None]
    return sorted(timed, key=lambda e: int(_ev_time(e)))


def build_index(files):
    """The carry dict. Keyed only on identifiers the readers already emit; self-contained."""
    arts = _artifacts(files)
    events = _events_of(arts)
    idx = {
        "accounts": {},         # name -> {sids, logon_ids, hosts, logon_times}
        "sessions": {},         # logon id -> {account, host, time}
        "processes": [],        # {pid, image, logon_id, account, host, hash, time}
        "file_writes": [],      # {target, image, pid, time}
        "persistence": [],      # autostart entries (registry/task/event), read-only
        "cloud": [],            # cloud/identity sign-ins (cloudlogs)
        "containers": [],       # pcap/memory/disk structure (forensics)
        "event_count": len(events),
        "sources": [],
        "_arts": arts,
    }
    if events:
        idx["sources"].append("windows")

    for ev in events:
        acct, sess = _ev_account(ev), _ev_session(ev)
        if ev["id"] in (ID_LOGON_OK, ID_LOGON_FAIL) and acct:
            rec = idx["accounts"].setdefault(acct, {"sids": set(), "logon_ids": set(),
                                                     "hosts": set(), "logon_times": []})
            if _ev_sid(ev):
                rec["sids"].add(_ev_sid(ev))
            if _ev_host(ev):
                rec["hosts"].add(_ev_host(ev))
            if ev["id"] == ID_LOGON_OK and sess:
                rec["logon_ids"].add(sess)
                idx["sessions"].setdefault(sess, {"account": acct, "host": _ev_host(ev),
                                                  "time": _ev_time(ev)})
            if ev["id"] == ID_LOGON_OK and _ev_time(ev) is not None:
                rec["logon_times"].append(_ev_time(ev))
        if ev["id"] in _PROC_IDS and _ev_image(ev):
            idx["processes"].append({"pid": _ev_pid(ev), "image": _ev_image(ev),
                                     "logon_id": sess, "account": acct, "host": _ev_host(ev),
                                     "hash": _ev_hash(ev), "time": _ev_time(ev)})
        if ev["id"] in _FILE_IDS and _ev_target_file(ev):
            idx["file_writes"].append({"target": _ev_target_file(ev), "image": _ev_image(ev),
                                       "pid": _ev_pid(ev), "time": _ev_time(ev)})

    idx["_events"] = events         # kept for the relation resolvers (not part of the public report)
    try:
        _enrich(idx, files)
    except Exception:               # noqa: BLE001  -- enrichment never breaks the core chain
        pass
    return idx


# --------------------------------------------------------------------------- relation resolvers
#
# Each resolver returns a concrete value, the AMBIGUOUS sentinel (two records matched the link
# equally -> None), or None (no record matched). Nothing is ever synthesised: a resolver only
# selects records the readers parsed and reads one field from them.


def account_after_failures(idx):
    """The account that logged on (4624) after a failed-logon burst (4625) -- the classic 'who
    finally got in' pivot. NEVER-WRONG: the link resolves to a value only when exactly one account
    is provable.

    The first build took the FIRST success strictly after the last failure and declined only on a
    same-INSTANT tie, so whenever two or more DISTINCT accounts logged on at DIFFERENT times after
    the burst (a service / machine / ANONYMOUS 4624 almost always lands first on a real host) it
    fed the earliest -- an unproven guess -- to the PLAIN output path.

    Now: among ALL the successes strictly after the last failure, if exactly one DISTINCT account
    logged on, that account is the pivot -- a genuine single value, whatever its logon type (there
    is deliberately NO logon-type allowlist, so a lone NetworkCleartext/type-8 or type-9 success is
    never falsely declined). If more than one distinct account logged on, the only byte-grounded
    disambiguator is the account the 4625 burst TARGETED that then succeeded, and only when exactly
    one such account is among the successes. Otherwise two records match the link equally ->
    AMBIGUOUS (the id becomes None). None when there is no failure burst or no later success."""
    timed = _sortable(idx.get("_events", []))
    fails = [e for e in timed if e["id"] == ID_LOGON_FAIL]
    if not fails:
        return None
    last_fail = int(_ev_time(fails[-1]))
    targeted = {_ev_account(e) for e in fails if _ev_account(e)}      # who the burst was aimed at
    later = [e for e in timed if e["id"] == ID_LOGON_OK and int(_ev_time(e)) > last_fail]
    accounts = {_ev_account(e) for e in later if _ev_account(e)}
    if not accounts:
        return None
    if len(accounts) == 1:
        return next(iter(accounts))      # exactly one account got in -> a genuine single value
    hit = accounts & targeted            # the burst names its own pivot: the targeted account that got in
    if len(hit) == 1:
        return next(iter(hit))
    return AMBIGUOUS                      # two+ accounts match the link equally -> None, never a guess


def _sessions_of(idx, account):
    return set(idx["accounts"].get(account, {}).get("logon_ids", set()))


def _processes_of(idx, account):
    """Process records spawned under `account`: matched on the account's logon id(s) when those
    are known (precise), else on the actor account name. The list the file/image resolvers read."""
    sessions = _sessions_of(idx, account)
    if sessions:
        procs = [p for p in idx["processes"] if p["logon_id"] in sessions]
        if procs:
            return procs
    return [p for p in idx["processes"] if p["account"] == account]


def _one_value(records, field):
    """The single distinct non-empty value of `field` across `records`; AMBIGUOUS if two differ;
    None if none carry it. This is the whole never-wrong selection rule in one place."""
    vals = {r.get(field) for r in records if r.get(field)}
    if not vals:
        return None
    if len(vals) > 1:
        return AMBIGUOUS
    return next(iter(vals))


def spawned_image(idx, account):
    """The image path of the process `account` spawned (grounded literal)."""
    return _one_value(_processes_of(idx, account), "image")


def spawned_pid(idx, account):
    return _one_value(_processes_of(idx, account), "pid")


def spawned_hash(idx, account):
    return _one_value(_processes_of(idx, account), "hash")


def written_file(idx, account):
    """The file written by `account`'s spawned process. Needs a single spawned process to anchor
    the write (two distinct processes -> AMBIGUOUS), then a single written-file record."""
    procs = _processes_of(idx, account)
    img = _one_value(procs, "image")
    pid = _one_value(procs, "pid")
    if img is AMBIGUOUS or pid is AMBIGUOUS:
        return AMBIGUOUS
    if img is None and pid is None:
        return None
    writes = [w for w in idx["file_writes"]
              if (img is not None and w.get("image") == img) or (pid is not None and w.get("pid") == pid)]
    return _one_value(writes, "target")


# --------------------------------------------------------------------------- question reading


_FAIL_WORDS = re.compile(r"\b(fail(?:ed|ure)?|unsuccessful|4625|wrong password|bad password|brute[\s-]?forc)", re.I)
_SUCCESS_WORDS = re.compile(r"\b(success(?:ful)?|logged[\s-]?on|log(?:on|in)|4624|authenticat)", re.I)
_FOLLOW_WORDS = re.compile(r"\b(after|following|then|subsequent|finally|that\s+account)\b", re.I)

# A spawn/launch/execute verb: the linker only knows the image of the process the pivot account
# SPAWNED. A bare "which/what ... process" is not enough -- it also matches a parent-process or a
# "which process read X" question the chain holds no record for (see _UNGROUNDED_FIELD).
_SPAWN_VERB = re.compile(
    r"\b(spawn(?:ed|s|ing)?|launch(?:ed|es|ing)?|execut(?:e|ed|es|ing|ion|able)?|ran|run|"
    r"started?|start(?:s|ing)?|creat(?:e|ed|es|ing))\b", re.I)


def _wants_file(t):
    return bool(re.search(r"\bfile\b", t) and re.search(r"\b(wrote|written|dropp|creat|saved|modif|wr[io]te)", t)) \
        or bool(re.search(r"\b(dropped|written|created)\s+file", t))


def _wants_hash(t):
    return bool(re.search(r"\b(hash|sha-?256|sha-?1|md5|imphash)\b", t))


def _wants_pid(t):
    return bool(re.search(r"\b(pid|process\s*id)\b", t))


def _wants_image(t):
    return bool(re.search(r"\b(image|executable|binary|program|process|command[\s-]?line|cmdline)\b", t)) \
        and bool(_SPAWN_VERB.search(t))


def _wants_account(t):
    return bool(re.search(r"\b(which|what|name of the)\b", t) and re.search(r"\b(account|user(?:name)?)\b", t))


def _wants_logon_id(t):
    return bool(re.search(r"\b(logon\s*id|logon\s*session|session\s*id|login\s*id)\b", t))


def _wants_time(t):
    return bool(re.search(r"\b(when|time|timestamp|date|what\s+time)\b", t))


def _anchor_account(idx, t):
    """The account the question anchors the chain on, or AMBIGUOUS / None.

    Two anchors are supported, both deterministic: the 'account after the failed logons' pivot,
    and an account the question names literally that the index actually parsed. A question with
    neither is not a chain this linker can resolve -> None."""
    if _FAIL_WORDS.search(t) and (_SUCCESS_WORDS.search(t) or _FOLLOW_WORDS.search(t)):
        return account_after_failures(idx)
    # A literal account name the delivery parsed, named in the question (word-bounded).
    named = [name for name in idx["accounts"]
             if name and re.search(r"(?<![\w\\])" + re.escape(name.lower()) + r"(?![\w$])", t)]
    if len(named) == 1:
        return named[0]
    if len(named) > 1:
        return AMBIGUOUS
    return None


# Fields the cross-stage index holds NO record for. The linker knows a process's own image / pid /
# hash, the file it WROTE, and the logon account / session / time. A question about a parent or
# child process, a file the process READ or OPENED, a loaded module / DLL, a registry value, a
# mutex, a driver, an injected target, or a network connection has no grounding record here, and
# the loose field matchers would otherwise hand back the spawned image as a PLAIN wrong answer.
# Decline (-> None) and leave it to a per-artifact reader.
_UNGROUNDED_FIELD = re.compile(
    r"\b(parent|child|grand\w*|read|reads|opened|loaded|module|modules|dll|"
    r"registry|regkey|mutex|driver|injected|connect(?:ed|ion|s)?)\b", re.I)


# --------------------------------------------------------------------------- the never-wrong gate


def _plain_or_none(value):
    """A grounded literal: PLAIN verbatim, or None for AMBIGUOUS / missing. Never a transform."""
    if value is None or value is AMBIGUOUS:
        return None
    return str(value)


def _unsure_or_none(field, relation, value):
    """An author-named selection: UNSURE as a candidate pick, or None. The key carries the field
    and the relation so an accepted name only ever answers that same chain on the next variant."""
    if value is None or value is AMBIGUOUS:
        return None
    key = f"{KEY}.chain_{field}/{relation}"
    val = str(value)
    opts = [(f"{field}_as_read", val)]
    if "\\" in val:                         # a path spelling the author may have lowercased / based
        opts.append((f"{field}_lower", val.lower()))
    try:
        return labels.candidates(key, opts)
    except ValueError:
        return None


def _resolve(q, idx):
    """One question -> a plain value, an unsure candidate pick, or None."""
    text = " ".join(str(q.get(k) or "") for k in ("question", "answer_id", "id", "qid")).lower()
    if not text.strip():
        return None

    anchor = _anchor_account(idx, text)
    relation = "after_failures" if (_FAIL_WORDS.search(text) and
                                    (_SUCCESS_WORDS.search(text) or _FOLLOW_WORDS.search(text))) else "named"
    if anchor is None or anchor is AMBIGUOUS:
        # No resolvable cross-stage anchor (or an ambiguous one): the linker declines.
        return None

    if _UNGROUNDED_FIELD.search(text):
        # The question asks for a field the index holds no record for (a parent/child process, a
        # file the process READ, a loaded module, a registry value, a connection, ...). Returning
        # the spawned image here would be a wrong PLAIN answer, so the linker declines.
        return None

    # Output field, most specific first (a "file the process wrote" also mentions "process").
    if _wants_file(text):
        return _plain_or_none(written_file(idx, anchor))
    if _wants_hash(text):
        return _plain_or_none(spawned_hash(idx, anchor))
    if _wants_pid(text):
        return _plain_or_none(spawned_pid(idx, anchor))
    if _wants_image(text):
        return _plain_or_none(spawned_image(idx, anchor))
    if _wants_account(text):
        # The selection itself (which account) is an author-named value -> unsure.
        return _unsure_or_none("account", relation, anchor)
    if _wants_logon_id(text):
        sessions = _sessions_of(idx, anchor)
        if len(sessions) != 1:
            return None
        return _unsure_or_none("logon_id", relation, next(iter(sessions)))
    if _wants_time(text):
        times = idx["accounts"].get(anchor, {}).get("logon_times", [])
        if len(set(int(x) for x in times)) != 1:
            return None
        return _unsure_or_none("time", relation, str(times[0]))
    return None


# --------------------------------------------------------------------------- public API


def solve_set(questions, files, ctx=None) -> dict:
    """Runner contract. Resolves each cross-stage question; everything else is None."""
    idx = build_index(files or {})
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        try:
            out[qid] = _resolve(q, idx)
        except Exception:               # noqa: BLE001  -- a malformed record never yields an answer
            out[qid] = None
    return out


def chain_report(files) -> dict:
    """A detector-only description of the cross-stage index: the stages the readers produced and
    the links between them. Nothing here is submitted; it is for the agent to read."""
    idx = build_index(files or {})
    pivot = account_after_failures(idx)
    report = {
        "event_count": idx["event_count"],
        "sources": idx["sources"],
        "accounts": {name: {"sids": sorted(a["sids"]), "logon_ids": sorted(a["logon_ids"]),
                            "hosts": sorted(a["hosts"]), "logon_count": len(a["logon_times"])}
                     for name, a in idx["accounts"].items()},
        "sessions": {sid: {"account": s["account"], "host": s["host"],
                          "time": None if s["time"] is None else str(s["time"])}
                     for sid, s in idx["sessions"].items()},
        "processes": [{"pid": p["pid"], "image": p["image"], "logon_id": p["logon_id"],
                       "account": p["account"], "time": None if p["time"] is None else str(p["time"])}
                      for p in idx["processes"]],
        "file_writes": [{"target": w["target"], "image": w["image"], "pid": w["pid"],
                         "time": None if w["time"] is None else str(w["time"])}
                        for w in idx["file_writes"]],
        "persistence": idx["persistence"],
        "cloud": [{"account": c["account"], "src": c["src"], "ip": c["ip"],
                   "time": None if c.get("time") is None else str(c["time"])} for c in idx["cloud"]],
        "containers": idx["containers"],
        "links": {
            "account_after_failures": None if pivot is None else ("<ambiguous>" if pivot is AMBIGUOUS else pivot),
        },
    }
    if pivot is not None and pivot is not AMBIGUOUS:
        report["links"]["spawned_image"] = (lambda v: None if (v is None or v is AMBIGUOUS)
                                            else ("<ambiguous>" if v is AMBIGUOUS else v))(spawned_image(idx, pivot))
        wf = written_file(idx, pivot)
        report["links"]["written_file"] = None if (wf is None or wf is AMBIGUOUS) else wf
    return report


def main(argv) -> int:
    import json
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: dfir_chain.py <windows-artifact>...   (DETECTOR ONLY; cross-stage links)",
              file=sys.stderr)
        return 2
    files = {}
    for p in paths:
        try:
            files[p] = Path(p).read_bytes()
        except OSError as e:
            print(f"dfir_chain.py: {p}: {e}", file=sys.stderr)
    print(json.dumps(chain_report(files), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
