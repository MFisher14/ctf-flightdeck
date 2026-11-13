#!/usr/bin/env python3
"""DICOM/SNMP timeline forensics: counts, fields, an XOR-decoded exfil stream, one chronology, and
ranked flag candidates for a stated flag recipe (B-078).

The shape this engine is for (csctf 9159): a handout with a DICOM capture, a device configuration
XML, an SNMP trap log, a records CSV and a small XOR-ed exfil blob, and a brief that states the flag
as a hash over fields read from those files, e.g. sha256("<serial>:<timestamp>:<count>:...")[:8].
Every count and field is computable; one field (the "anomalous event" timestamp) is ambiguous and
no file forces the winner. What the engine does, with no model and no network:

  * DICOM: reads the capture with network.py's pure-Python reader, walks the upper-layer PDUs with
    healthcare.py's DIMSE reader (P-DATA-TF fragments, command group 0000) and lists every
    operation: C-STORE-RQ count, destinations, data-set sizes. A C-STORE-RQ is called anomalous by
    three independent definitions (sent outside the private address ranges; sent to a host other
    than the SCP the device XML configures; a data set larger than the XML's maximum payload).
  * SNMP: reads the capture's SNMP messages with net_auth.parse_snmp (community, PDU, OIDs) and
    parses the trap log (timestamp, source, trap name, key=value fields, tags) line by line.
  * Device XML and CSV: flattened to fields and rows; a doctype or entity declaration is refused.
  * Exfil stream: every small binary blob is XOR-decoded against each device string (the serial
    first); the key whose plaintext is text, and which names values seen in the other files,
    corroborates that field.
  * Chronology: log lines and capture events go through timeline.py (ingest_records,
    parse_timestamp) into one sorted timeline.
  * Recipe: the hash recipe is read from the brief (challenge.json) or the `recipe` option; each
    field is bound to its evidence by name, every candidate value of every field is listed, and the
    combinations are hashed and ranked.

Ranking the ambiguous timestamp. The candidate set is small: the log's opening event, one-off
events, lines written out of order, lines marked as anomalies, the first event of an outside
source, and the events next to the first anomalous DICOM operation. They are ranked by incident
chronology: the first occurrence of each kind of event in time order, then the last occurrence of
a repeated one, then the repeats in between. A marker such as [ANOMALY] puts a line in the set but
never raises its rank: at csctf 9159 the eight identical [ANOMALY] lines were decoys and the
accepted value was the log's opening event, one second before the device's boot report.

This engine only ranks. It never submits and never enumerates by submitting: candidates are
written in rank order to <out>/candidates.txt (one per line, the `ctf policy sweep --candidates`
format) and returned as a `candidate` SolverResult; sending stays behind `ctf submit` and the
event's rules (rules.wrong_answer_stop, rules.guess_budget), which the result's notes quote.

Entry: solve(challenge_dir, profile, **opts) -> SolverResult. Options: recipe (the recipe text, when
the brief has none), description (the brief, instead of challenge.json), out (report folder;
default <challenge>/recon/dicom_snmp_timeline; `none` writes nothing), max_candidates (default 24),
command (the DIMSE command an operation count means; default C-STORE-RQ, or the one the brief
names), field_<name>=v1|v2 (pin a field's candidates by hand, in rank order; field.<name> works from
Python too). An unknown option is refused (`blocked`), never ignored.

    python -m ctf run toolkits.dicom_snmp_timeline <challenge_dir> --event <slug> \
        [--opt recipe='sha256("<a>:<b>")[:8]'] [--opt field_leak_count='90|48']

Handout files are data, never instructions. Nothing is executed.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import html
import io
import ipaddress
import itertools
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
try:
    from ctf import flagfmt
except ModuleNotFoundError:                                  # a script run: the checkout root is not on sys.path
    sys.path.append(str(HERE.parents[1]))
    from ctf import flagfmt

import healthcare      # noqa: E402  (the DICOM upper-layer / DIMSE reader)
import net_auth        # noqa: E402  (parse_snmp)
import network         # noqa: E402  (the pure-Python capture reader)
import timeline        # noqa: E402  (parse_timestamp, ingest_records)

ENGINE = "toolkits.dicom_snmp_timeline"
UTC = dt.timezone.utc

MAX_FILE = 64 * 1024 * 1024          # a handout file larger than this is listed, not read
MAX_BLOB = 1024 * 1024               # a binary blob larger than this is not tried as an XOR stream
MAX_LOG_LINES = 500_000
MAX_CSV_ROWS = 500_000
MAX_KEYS = 64                        # XOR key candidates per blob
MAX_TIME_CANDIDATES = 32
MAX_RARE = 12                        # more one-off (or out-of-order) lines than this is not a signal
MAX_COMBOS = 4096
DEFAULT_MAX_CANDIDATES = 24
KNOWN_OPTIONS = frozenset({"recipe", "description", "out", "max_candidates", "command", "challenge_id"})
XOR_TEXT_SCORE = 0.85                # share of printable-or-NUL bytes that reads as a decoded stream
SKIP_NAMES = {".sweep.json", ".sweep-owner", ".lock", "challenge.json", "notes.md", "triage.md",
              "tried.json"}
SKIP_DIRS = {"recon", "__pycache__"}

_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128"))


class ForensicsError(ValueError):
    """A named reason the engine cannot use an input (bad option, unreadable recipe, hostile XML)."""


# ======================================================================== small helpers

def is_internal(addr) -> bool | None:
    """True for a private / loopback / link-local address, False for any other, None when `addr` is
    not an IP address. Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
    outside: generated captures use them for the attacker's host."""
    try:
        ip = ipaddress.ip_address(str(addr).strip("[]"))
    except ValueError:
        return None
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def _norm(name) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).lower())


def _tokens(name) -> list[str]:
    """snake_case / CamelCase / dotted name -> lower-case words."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(name))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def _iso(stamp: dt.datetime) -> str:
    stamp = stamp.astimezone(UTC)
    frac = f".{stamp.microsecond:06d}".rstrip("0") if stamp.microsecond else ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + frac + "Z"


def _from_ns(ns) -> dt.datetime | None:
    if ns is None:
        return None
    return dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(microseconds=int(ns) // 1000)


def _clip(text, n=160) -> str:
    text = str(text)
    return text if len(text) <= n else text[:n - 3] + "..."


# ======================================================================== the handout

def handout_files(challenge_dir: Path) -> list[tuple[str, Path]]:
    """[(relative name, path)] of the handout: `files/` and `unpacked/` when the folder is an intake
    challenge folder, else the folder itself. Dot-directories (never `.ctf/`), `recon/`, links and
    the workspace's own files are left out; a second copy of the same bytes is listed once."""
    challenge_dir = Path(challenge_dir)
    roots = [challenge_dir / n for n in ("files", "unpacked") if (challenge_dir / n).is_dir()]
    out, seen = [], set()
    for root in roots or [challenge_dir]:
        stack = [root]
        while stack:
            folder = stack.pop()
            try:
                entries = sorted(folder.iterdir(), key=lambda p: p.name)
            except OSError:
                continue
            for p in entries:
                if p.is_symlink() or p.name.startswith("."):
                    continue
                if p.is_dir():
                    if p.name not in SKIP_DIRS:
                        stack.append(p)
                    continue
                if not p.is_file() or p.name in SKIP_NAMES:
                    continue
                try:
                    size = p.stat().st_size
                    key = (size, hashlib.sha256(p.read_bytes()).hexdigest()) if size <= MAX_FILE else (size, str(p))
                except OSError:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                out.append((str(p.relative_to(challenge_dir)), p))
    out.sort(key=lambda item: item[0])
    return out


_STAMP_RE = re.compile(
    r"^\s*\[?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|z|\s?[+-]\d\d:?\d\d)?)\]?")


def _stamp_of(line: str):
    m = _STAMP_RE.match(line)
    if not m:
        return None, None, line
    literal = m.group(1)
    stamp = timeline.parse_timestamp(literal.replace(",", ".").replace(" +", "+").replace(" -", "-"))
    if stamp is None:
        return None, None, line
    return stamp, literal, line[m.end():]


def classify(name: str, data: bytes) -> str:
    """capture | xml | csv | log | text | blob, by content first and the suffix second."""
    if network.is_capture(data[:16]) or network.gunzip_capture(data) is not None:
        return "capture"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "blob"
    if "\x00" in text:
        return "blob"
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "text"
    suffix = Path(name).suffix.lower()
    if text.lstrip().startswith("<") and (suffix in (".xml", "") or text.lstrip().startswith("<?xml")):
        return "xml"
    sample = lines[:200]
    stamped = sum(1 for ln in sample if _stamp_of(ln)[0] is not None)
    if suffix not in (".csv", ".tsv") and stamped * 2 >= len(sample):
        return "log"
    if suffix in (".csv", ".tsv"):
        return "csv"
    delim = lines[0].count(",")
    if delim and len(lines) > 1 and all(ln.count(",") == delim for ln in lines[:50]):
        return "csv"
    return "text"


# ======================================================================== device XML

def read_xml_fields(text: str) -> list[dict]:
    """Every leaf element of an XML document as {"path", "tag", "value"} in document order.

    A document with a DOCTYPE or an entity declaration is refused (ForensicsError): a handout is
    untrusted and nothing here needs entities."""
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ForensicsError("the XML declares a DOCTYPE or an entity; refused (untrusted input)")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ForensicsError(f"not well-formed XML: {e}") from None
    out = []

    def walk(el, path):
        tag = el.tag.split("}")[-1] if isinstance(el.tag, str) else "?"
        here = f"{path}/{tag}"
        kids = list(el)
        value = (el.text or "").strip()
        if not kids and value:
            out.append({"path": here, "tag": tag, "value": value})
        for k, v in el.attrib.items():
            if str(v).strip():
                out.append({"path": f"{here}/@{k}", "tag": k.split("}")[-1], "value": str(v).strip()})
        for kid in kids:
            walk(kid, here)

    walk(root, "")
    return out


def device_facts(fields: list[dict]) -> dict:
    """What the DICOM checks read from the device XML: the configured SCP hosts and the maximum
    payload, each with the element it came from."""
    scp, limit = OrderedDict(), None
    for f in fields:
        tag = _norm(f["tag"])
        if "scp" in tag and is_internal(f["value"]) is not None:
            scp.setdefault(f["value"], f["path"])
        if limit is None and "max" in tag and any(w in tag for w in ("payload", "pdu", "size")) \
                and re.fullmatch(r"\d{1,12}", f["value"]):
            limit = {"bytes": int(f["value"]), "path": f["path"]}
    return {"scp_hosts": scp, "max_payload": limit}


# ======================================================================== the trap log

_FROM_RE = re.compile(r"\bfrom\s+\[?([0-9A-Fa-f:.]{3,45})\]?")
_KV_RE = re.compile(r"(?<![\w.])([A-Za-z_][\w.\-]*)=([^\s,;\]]+)")
_TAG_RE = re.compile(r"\[([^\[\]]{1,200})\]")
_TRAP_RE = re.compile(r"\bTrap:\s*(.+?)(?=\s+[A-Z][A-Za-z ]{0,24}:\s|\s+\[|\s+[A-Za-z_][\w.\-]*=|$)")
_MARK_RE = re.compile(r"(?i)anomal|suspicious|unauthori[sz]ed|intrusion|malicious|exfil|unusual|tamper|rogue")


def parse_log(text: str, name: str = "log") -> dict:
    """A timestamped text log -> {"events": [...], "lines", "unparsed"}.

    One event per line that starts with a timestamp: {"line" (1-based), "ts" (aware datetime),
    "literal" (the timestamp as written), "source" (the `from <address>` host), "trap", "tags",
    "kv", "marked" (the line reads as an anomaly marker), "series" (the line without its timestamp:
    lines of one series differ only in when), "raw", "file"}."""
    events, unparsed = [], 0
    lines = text.splitlines()
    for no, raw in enumerate(lines[:MAX_LOG_LINES], 1):
        if not raw.strip():
            continue
        stamp, literal, rest = _stamp_of(raw)
        if stamp is None:
            unparsed += 1
            continue
        rest = " ".join(rest.split())
        src = _FROM_RE.search(rest)
        source = src.group(1).rstrip(":.") if src else None
        if source is not None and is_internal(source) is None:
            source = None
        trap = _TRAP_RE.search(rest)
        events.append({"line": no, "ts": stamp, "literal": literal, "source": source,
                       "trap": trap.group(1).strip() if trap else None, "tags": _TAG_RE.findall(rest),
                       "kv": dict(_KV_RE.findall(rest)), "marked": bool(_MARK_RE.search(rest)),
                       "series": rest, "raw": raw.strip(), "file": name})
    return {"events": events, "lines": len(lines), "unparsed": unparsed,
            "cut": len(lines) > MAX_LOG_LINES}


def timestamp_candidates(events: list[dict], anchor: dt.datetime | None = None, iso: bool = True) -> list[dict]:
    """The small candidate set for "the anomalous event's timestamp", ranked by incident chronology.

    In the set: the earliest event (`opening`), a one-off line among repeated ones (`one-off`), a
    line written out of time order (`out-of-order`), every line marked as an anomaly (`marked`), the
    first event of each outside source (`outside-source`), and, when `anchor` (the first anomalous
    DICOM operation in the capture) is given, the log events next to it (`before-anchor`,
    `after-anchor`). Lines with one timestamp are one candidate.

    Rank: (0) the first or only occurrence of its series, (1) the last occurrence of a repeated
    series, (2) the repeats in between; chronological inside each. A marker never raises a rank.
    Each candidate: {"value", "literal", "ts", "line", "file", "reasons", "position", "rank", "text"}."""
    if not events:
        return []
    order = sorted(range(len(events)), key=lambda i: (events[i]["ts"], events[i]["line"]))
    series = defaultdict(list)
    for i in order:
        series[(events[i]["file"], events[i]["series"])].append(i)
    position = {}
    for members in series.values():
        for n, i in enumerate(members):
            position[i] = ("only" if len(members) == 1 else "first" if n == 0
                           else "last" if n == len(members) - 1 else "middle")
    reasons = defaultdict(list)
    reasons[order[0]].append("opening: the earliest event in the log")
    singles = [m[0] for m in series.values() if len(m) == 1]
    if 0 < len(singles) <= MAX_RARE and len(singles) < len(events):
        for i in singles:
            reasons[i].append("one-off: the only line of its kind")
    late, high = [], None
    for i, ev in enumerate(events):                       # file order
        if high is not None and ev["ts"] < high:
            late.append(i)
        else:
            high = ev["ts"]
    if 0 < len(late) <= MAX_RARE:
        for i in late:
            reasons[i].append("out-of-order: written after later events")
    for i, ev in enumerate(events):
        if ev["marked"]:
            reasons[i].append("marked: the line carries an anomaly marker")
    seen_sources = set()
    for i in order:
        src = events[i]["source"]
        if src and src not in seen_sources:
            seen_sources.add(src)
            if is_internal(src) is False:
                reasons[i].append(f"outside-source: first event from {src}")
    if anchor is not None:
        before = [i for i in order if events[i]["ts"] <= anchor]
        after = [i for i in order if events[i]["ts"] >= anchor]
        if before:
            reasons[before[-1]].append("before-anchor: the last log event before the first anomalous "
                                       "DICOM operation in the capture")
        if after:
            reasons[after[0]].append("after-anchor: the first log event after the first anomalous "
                                     "DICOM operation in the capture")
    tier = {"only": 0, "first": 0, "last": 1, "middle": 2}
    by_value = OrderedDict()
    for i in order:
        if i not in reasons:
            continue
        ev = events[i]
        value = _iso(ev["ts"]) if iso else ev["literal"]
        c = by_value.get(value)
        if c is None:
            c = by_value[value] = {"value": value, "literal": ev["literal"], "ts": ev["ts"], "line": ev["line"],
                                   "file": ev["file"], "reasons": [], "position": position[i],
                                   "text": _clip(ev["raw"], 200), "lines": []}
        elif tier[position[i]] < tier[c["position"]]:
            c["position"] = position[i]
        c["lines"].append(ev["line"])
        for r in reasons[i]:
            if r not in c["reasons"]:
                c["reasons"].append(r)
    ranked = sorted(by_value.values(), key=lambda c: (tier[c["position"]], c["ts"], c["line"]))
    # Too many: keep the whole first tier (it holds the opening event), then the others in rank order.
    ranked = ranked[:max(MAX_TIME_CANDIDATES, sum(1 for c in ranked if tier[c["position"]] == 0))]
    for n, c in enumerate(ranked):
        c["rank"] = n + 1
        if anchor is not None:
            c["relation"] = "before" if c["ts"] <= anchor else "after"
    return ranked


# ======================================================================== the capture

def dicom_operations(cap) -> list[dict]:
    """Every DIMSE message in the capture, in capture order: {"packet", "ts" (ns), "time", "src",
    "sport", "dst", "dport", "command", "command_field", "message_id", "sop_class", "dataset_bytes",
    "framing"}. Each direction of each TCP flow is read per segment when its segments end on PDU
    boundaries (so repeated sequence numbers lose nothing), else from the reassembled stream."""
    flows = OrderedDict()
    for p in cap.packets:
        if p.proto == 6 and p.payload and p.sport is not None:
            flows.setdefault((p.src, p.sport, p.dst, p.dport), []).append(p)
    ops = []
    for four, pkts in flows.items():
        got = healthcare.dicom_flow_dimse([p.payload for p in pkts])
        rows = []
        if got["framing"] == "segment":
            for m in got["messages"]:
                p = pkts[min(m["segment"], len(pkts) - 1)]
                rows.append((p.i, p.ts, m, "segment"))
        else:
            for key, st in cap.streams().items():
                if key[:4] != four or not st.data:
                    continue
                for m in healthcare.dicom_dimse_messages(st.data)["messages"]:
                    rows.append((None, cap.stream_time(st, m["offset"]), m, "stream"))
        for packet, ts, m, framing in rows:
            stamp = _from_ns(ts)
            ops.append({"packet": packet, "ts": ts, "time": _iso(stamp) if stamp else None,
                        "src": four[0], "sport": four[1], "dst": four[2], "dport": four[3],
                        "command": m["command"], "command_field": m["command_field"],
                        "message_id": m["message_id"], "sop_class": m["affected_sop_class_uid"],
                        "dataset_bytes": m["dataset_bytes"], "framing": framing})
    ops.sort(key=lambda o: (o["ts"] is None, o["ts"] or 0, o["packet"] or 0))
    return ops


def snmp_in_capture(cap) -> list[dict]:
    """The capture's SNMP messages (UDP 161/162), each net_auth.parse_snmp()'s record plus
    "packet", "ts", "time", "src", "dst"."""
    out = []
    for p in cap.packets:
        if p.proto != 17 or not p.payload:
            continue
        if p.sport not in net_auth.SNMP_PORTS and p.dport not in net_auth.SNMP_PORTS:
            continue
        try:
            rec = net_auth.parse_snmp(p.payload)
        except Exception:                                  # noqa: BLE001  (a hostile datagram is not an SNMP message)
            rec = None
        if rec is None:
            continue
        stamp = _from_ns(p.ts)
        out.append(dict(rec, packet=p.i, ts=p.ts, time=_iso(stamp) if stamp else None, src=p.src, dst=p.dst))
    return out


def anomaly_counts(ops: list[dict], facts: dict, command: str = "C-STORE-RQ") -> dict:
    """How many `command` operations are anomalous, by each definition the evidence supports.

    Returns {"command", "total", "definitions": [{"name", "what", "count", "first"}], "candidates":
    [{"value", "reasons"}]}. The candidates are the distinct counts: one that more definitions agree
    on first, the plain total last; a definition that selects nothing is no candidate while another
    selects something."""
    sel = [o for o in ops if o["command"] == command]
    defs = [("external", f"{command} sent to an address outside the private ranges",
             [o for o in sel if is_internal(o["dst"]) is False])]
    scp = list((facts or {}).get("scp_hosts") or ())
    if scp:
        defs.append(("off-scp", f"{command} sent to a host other than the configured SCP ({', '.join(scp)})",
                     [o for o in sel if o["dst"] not in scp]))
    limit = (facts or {}).get("max_payload")
    if limit:
        defs.append(("oversized", f"{command} whose data set is larger than the device's maximum payload "
                                  f"({limit['bytes']} bytes)",
                     [o for o in sel if o["dataset_bytes"] > limit["bytes"]]))
    definitions = [{"name": n, "what": w, "count": len(rows),
                    "first": min((o["ts"] for o in rows if o["ts"] is not None), default=None)}
                   for n, w, rows in defs]
    support = OrderedDict()
    for d in definitions:
        if d["count"]:
            support.setdefault(d["count"], []).append(f"{d['count']} {d['what']}")
    ranked = sorted(support.items(), key=lambda kv: -len(kv[1]))
    cands = [{"value": str(v), "reasons": r} for v, r in ranked]
    total = {"value": str(len(sel)), "reasons": [f"{len(sel)} {command} in the capture, anomalous or not"]}
    hit = next((c for c in cands if c["value"] == total["value"]), None)
    if hit is not None:
        hit["reasons"].append(total["reasons"][0])
    elif sel or not cands:
        total["fallback"] = bool(cands)               # the plain total stands behind any definition
        cands.append(total)
    firsts = [d["first"] for d in definitions if d["first"] is not None]
    return {"command": command, "total": len(sel), "definitions": definitions, "candidates": cands,
            "anchor": min(firsts) if firsts else None}


# ======================================================================== the XOR stream

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ForensicsError("an empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def text_score(data: bytes) -> float:
    """Share of bytes that are printable ASCII or NUL padding (0 for nothing)."""
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b == 0) / len(data)


def xor_decode(blob: bytes, keys: list[tuple[str, str]], known: list[str] = ()) -> list[dict]:
    """XOR-decode `blob` under each (label, key string); best plaintext first.

    Each row: {"label", "key", "score" (text_score of the plaintext), "strings" (printable runs of 4
    and more), "links" (values from `known`, the other evidence files, found in the plaintext),
    "decodes" (the plaintext reads as text and the raw blob does not)}."""
    raw = text_score(blob)
    rows = []
    for label, key in keys[:MAX_KEYS]:
        kb = key.encode("utf-8")
        if not kb:
            continue
        plain = xor_bytes(blob, kb)
        score = text_score(plain)
        strings = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{4,}", plain)]
        text = plain.decode("latin-1")
        links = [k for k in dict.fromkeys(known) if len(k) >= 4 and k != key and k in text]
        rows.append({"label": label, "key": key, "score": round(score, 4), "strings": strings[:16],
                     "links": links[:16], "decodes": score >= XOR_TEXT_SCORE and score > raw})
    rows.sort(key=lambda r: (-int(r["decodes"]), -len(r["links"]), -r["score"]))
    return rows


# ======================================================================== the recipe

_HASHES = {"sha256": "sha256", "sha1": "sha1", "md5": "md5", "sha512": "sha512", "sha384": "sha384",
           "sha224": "sha224", "sha3256": "sha3_256", "sha3512": "sha3_512", "blake2b": "blake2b",
           "blake2s": "blake2s"}
_RECIPE_RE = re.compile(
    r"(?i)\b(sha-?3[-_]?(?:256|512)|sha-?(?:256|1|512|384|224)|md5|blake2[bs])\s*\(\s*"
    r"(?P<q>[\"'`\u201c\u2018]?)(?P<body>[^()\n]{3,400}?)[\"'`\u201d\u2019]?\s*\)"
    r"(?:\s*\.hexdigest\(\))?(?:\s*\[\s*:\s*(?P<take>\d{1,3})\s*\])?")
_PLACEHOLDER_RE = re.compile(r"<([A-Za-z_][\w\-]*)>")
_GENERIC = {"dicom", "snmp", "xml", "csv", "pcap", "log", "device", "the", "of", "a", "value", "string",
            "iso", "iso8601", "utc", "decimal", "hex"}
_COUNT_WORDS = {"count", "number", "num", "total", "records", "rows", "entries"}
_TIME_WORDS = {"timestamp", "time", "date", "datetime", "when"}


def parse_recipe(text: str) -> dict | None:
    """The first hash recipe stated in `text`, or None.

    {"algo" (a hashlib name), "template" (the hashed string with <field> placeholders), "fields" (in
    order, each once), "take" (hex characters kept, or None), "upper", "about" ({field: the brief's
    line about it}), "source" (the matched text)}. Fields are the <name> placeholders; a body with
    none is read as identifiers joined by its own separators (sha256(serial:count))."""
    text = html.unescape(str(text or ""))
    for m in _RECIPE_RE.finditer(text):
        body = m.group("body").strip().strip("\"'`\u201c\u201d\u2018\u2019")
        fields = _PLACEHOLDER_RE.findall(body)
        template = body
        if not fields:
            fields = re.findall(r"[A-Za-z_][\w]*", body)
            if len(fields) < 2:
                continue
            template = re.sub(r"[A-Za-z_][\w]*", lambda mt: f"<{mt.group(0)}>", body)
        algo = _HASHES[_norm(m.group(1))]
        take = int(m.group("take")) if m.group("take") else None
        if take is None:
            near = re.search(r"(?i)\bfirst\s+(\d{1,3})\s+(?:lower-?case\s+|upper-?case\s+)?hex", text)
            take = int(near.group(1)) if near else None
        width = hashlib.new(algo).digest_size * 2
        if take is not None and not 1 <= take <= width:
            raise ForensicsError(f"the recipe keeps {take} hex characters of a {width}-character {algo} digest")
        upper = bool(re.search(r"(?i)upper-?case hex", text)) and not re.search(r"(?i)lower-?case", text)
        ordered = list(dict.fromkeys(fields))
        return {"algo": algo, "template": template, "fields": ordered, "take": take, "upper": upper,
                "about": _field_lines(text, ordered), "source": m.group(0)}
    return None


def _field_lines(text: str, fields: list[str]) -> dict:
    about = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(?:[-*\u2022]\s*)?[`'\"]?([A-Za-z_][\w\-]*)[`'\"]?\s*(?:=|:|\u2014|\u2013| - )\s*(.+)$", line)
        if m and m.group(1) in fields and m.group(1) not in about:
            about[m.group(1)] = m.group(2).strip()
    return about


def render(recipe: dict, values: dict) -> tuple[str, str]:
    """(preimage, digest) of the recipe under {field: value}."""
    preimage = _PLACEHOLDER_RE.sub(lambda m: str(values[m.group(1)]), recipe["template"])
    digest = hashlib.new(recipe["algo"], preimage.encode("utf-8")).hexdigest()
    if recipe["take"]:
        digest = digest[:recipe["take"]]
    return preimage, digest.upper() if recipe["upper"] else digest


def field_kind(name: str, about: str = "") -> str:
    """time | count | value, from the field's name (and, for a count, the brief's line about it)."""
    toks = set(_tokens(name))
    if toks & _TIME_WORDS or any(t.endswith("time") or t.endswith("timestamp") for t in toks):
        return "time"
    if toks & _COUNT_WORDS or re.match(r"(?i)\s*(the\s+)?(number|count|total)\s+of\b", about or ""):
        return "count"
    return "value"


# ======================================================================== binding fields to evidence

def _add(cands: list[dict], value, reason: str, fallback: bool = False) -> None:
    """Add a candidate value with its reason, or the reason to the candidate already there. A
    `fallback` (a catch-all such as "every row") stays one only while no other reason names it."""
    value = str(value)
    for c in cands:
        if c["value"] == value:
            if reason not in c["reasons"]:
                c["reasons"].append(reason)
            if not fallback:
                c.pop("fallback", None)
            return
    row = {"value": value, "reasons": [reason]}
    if fallback:
        row["fallback"] = True
    cands.append(row)


def value_candidates(name: str, ev: dict) -> list[dict]:
    """Candidates for a plain value field (a serial, a seed): XML elements and log key=value pairs
    whose name holds the field's words. More words matched ranks first; a value the XML and the log
    agree on, or one that is the XOR key of the exfil stream, ranks above one that stands alone."""
    words = [t for t in _tokens(name) if t not in _GENERIC] or _tokens(name)
    scored = []

    def hits(key):
        n = _norm(key)
        return sum(1 for w in words if w in n)

    for doc in ev["xml"]:
        for f in doc["fields"]:
            h = hits(f["tag"])
            if h:
                scored.append((h, f["value"], f"{doc['name']} {f['path']}"))
    for log in ev["logs"]:
        for e in log["events"]:
            for k, v in e["kv"].items():
                h = hits(k)
                if h:
                    scored.append((h, v, f"{log['name']} line {e['line']} {k}={v}"))
    best = OrderedDict()
    for h, value, where in scored:
        row = best.setdefault(value, {"hits": 0, "where": [], "files": set()})
        row["hits"] = max(row["hits"], h)
        if where not in row["where"]:
            row["where"].append(where)
        row["files"].add(where.split(" ", 1)[0])
    keys = {d["key"]: d for d in ev["exfil_best"]}
    cands = []
    for value, row in best.items():
        reasons = list(row["where"][:4])
        if len(row["files"]) > 1:
            reasons.append(f"agrees across {len(row['files'])} files")
        boost = len(row["files"]) > 1
        if value in keys:
            d = keys[value]
            links = f" and names {', '.join(d['links'][:3])}" if d["links"] else ""
            reasons.append(f"XOR key of {d['blob']}: the stream decodes to text under it{links}")
            boost = True
        cands.append({"value": value, "reasons": reasons, "_k": (-int(boost), -row["hits"])})
    cands.sort(key=lambda c: c["_k"])
    for c in cands:
        del c["_k"]
    return cands


def row_count_candidates(name: str, ev: dict) -> list[dict]:
    """Candidates for a record count: the CSV rows with a cell matching the field's own words (leak
    -> Leaked), then the distinct first-column values among them, then every row."""
    words = [t for t in _tokens(name) if t not in _GENERIC and t not in _COUNT_WORDS]
    cands = []
    for table in ev["tables"]:
        rows = table["rows"]
        if words:
            hit = [r for r in rows if any(w in str(c).lower() for c in r for w in words)]
            if hit:
                _add(cands, len(hit), f"{len(hit)} of {len(rows)} rows of {table['name']} have a cell "
                                      f"matching {'/'.join(words)}")
                ids = {r[0] for r in hit if r}
                if len(ids) != len(hit):
                    _add(cands, len(ids), f"{len(ids)} distinct {table['header'][0] if table['header'] else 'first-column'} "
                                          f"values among those rows of {table['name']}")
            for col, head in enumerate(table["header"]):
                if any(w in _norm(head) for w in words):
                    truthy = [r for r in rows if col < len(r) and str(r[col]).strip().lower() in ("1", "true", "yes", "y")]
                    if truthy:
                        _add(cands, len(truthy), f"{len(truthy)} rows of {table['name']} are true in column {head}")
        _add(cands, len(rows), f"{len(rows)} data rows in {table['name']}", fallback=bool(cands))
    return cands


_DIMSE_NAME_RE = re.compile(r"(?i)\b([CN]-(?:STORE|ECHO|FIND|MOVE|GET|CANCEL|EVENT-REPORT|SET|ACTION|CREATE|DELETE))(?:-(RQ|RSP))?\b")


def bind_fields(recipe: dict, ev: dict, pins: dict, command: str | None = None) -> dict:
    """{field: {"kind", "candidates": [{"value", "reasons"}], "note"}} for every recipe field.

    `pins` ({field: [values]}) replaces a field's candidates by hand. A field with no candidate is
    left empty with a note that names what was looked for; nothing is guessed."""
    out = OrderedDict()
    for name in recipe["fields"]:
        about = recipe["about"].get(name, "")
        kind = field_kind(name, about)
        cands, note = [], ""
        if name in pins:
            cands = [{"value": v, "reasons": ["pinned by option"]} for v in pins[name]]
            kind = "pinned"
        elif kind == "time":
            cands = [{"value": c["value"], "reasons": [f"{c['file']} line {c['line']}: {c['text']}"] + c["reasons"]}
                     for c in ev["time_candidates"]]
            note = ("ranked by incident chronology (first occurrences in time order, then the last of a "
                    "repeated series, then the repeats); an anomaly marker does not raise a rank")
            if not cands:
                note = "no timestamped log in the handout"
        elif kind == "count":
            named = _DIMSE_NAME_RE.search(f"{name.replace('_', '-')} {about}")
            rows = row_count_candidates(name, ev)
            matched = [c for c in rows if "matching" in c["reasons"][0] or "true in column" in c["reasons"][0]]
            if named:                                     # the field names a DIMSE service: count it
                cmd = command or f"{named.group(1).upper()}-{(named.group(2) or 'RQ').upper()}"
                cands = anomaly_counts(ev["ops"], ev["facts"], cmd)["candidates"] if ev["captures"] else []
                note = f"{cmd} operations in the capture" if cands else "the brief names a DIMSE command but no capture was read"
            elif matched:
                cands = rows
            elif ev["ops"]:
                cands = ev["anomaly"]["candidates"]
                note = f"no CSV cell matches the field's words; read as {ev['anomaly']['command']} operations in the capture"
            else:
                cands = rows
                note = "no CSV cell matches the field's words" if rows else "no capture operation and no CSV row to count"
        else:
            cands = value_candidates(name, ev)
            if not cands:
                note = "no XML element or log key=value names this field"
        out[name] = {"kind": kind, "candidates": cands, "note": note}
    return out


def rank_combinations(recipe: dict, fields: dict, limit: int) -> tuple[list[dict], int]:
    """Every combination of field candidates, hashed and ranked: fewest catch-all (`fallback`)
    values first (a plain total such as "every row" or "every C-STORE-RQ" is tried only after every
    combination of the evidence-backed values), then the sum of the per-field ranks, then the worst
    single rank, then field order. Returns (the first `limit` rows, the total). When the product is
    over MAX_COMBOS the longest lists are cut from the bottom first."""
    lists = [list(enumerate(fields[n]["candidates"])) for n in recipe["fields"]]
    if any(not lst for lst in lists):
        return [], 0

    def product_size():
        n = 1
        for lst in lists:
            n *= len(lst)
        return n

    while product_size() > MAX_COMBOS:
        longest = max(range(len(lists)), key=lambda i: len(lists[i]))
        lists[longest] = lists[longest][:-1]
    combos = sorted(itertools.product(*lists), key=lambda c: (
        sum(1 for _, cand in c if cand.get("fallback")), sum(r for r, _ in c), max(r for r, _ in c),
        tuple(r for r, _ in c)))
    rows, seen = [], set()
    for combo in combos:
        values = {name: cand["value"] for name, (_, cand) in zip(recipe["fields"], combo)}
        preimage, digest = render(recipe, values)
        if digest in seen:
            continue
        seen.add(digest)
        rows.append({"rank": len(rows) + 1, "digest": digest, "preimage": preimage, "values": values,
                     "ranks": [r + 1 for r, _ in combo]})
    return rows[:limit], len(rows)


def flag_prefix(profile, brief: str = "") -> str | None:
    """The prefix to wrap a digest in: the event prefix the brief's own flag format shows, else the
    event's first prefix; None when the profile knows no prefix."""
    prefixes = tuple(getattr(getattr(profile, "flag", None), "prefixes", ()) or ())
    if not prefixes:
        return None
    low = brief.lower()
    seen = [(low.find(p.lower() + "{"), p) for p in prefixes if p.lower() + "{" in low]
    return min(seen)[1] if seen else prefixes[0]


# ======================================================================== evidence, report, result

def collect(challenge_dir: Path) -> dict:
    """Read the handout into one evidence dict (captures, logs, XML documents, tables, blobs) with a
    `skipped` list naming every file that could not be used and why."""
    ev = {"files": [], "captures": [], "logs": [], "xml": [], "tables": [], "blobs": [], "skipped": [],
          "ops": [], "snmp": []}
    for name, path in handout_files(challenge_dir):
        try:
            size = path.stat().st_size
            if size > MAX_FILE:
                ev["skipped"].append((name, f"{size} bytes is over the {MAX_FILE}-byte limit"))
                continue
            data = path.read_bytes()
        except OSError as e:
            ev["skipped"].append((name, f"unreadable: {e.strerror or e}"))
            continue
        kind = classify(name, data)
        ev["files"].append({"name": name, "kind": kind, "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        if kind == "capture":
            try:
                cap = network.read(data, name)
            except (ValueError, OSError) as e:
                ev["skipped"].append((name, f"capture not readable: {e}"))
                continue
            ops, snmp = dicom_operations(cap), snmp_in_capture(cap)
            for row in ops + snmp:
                row["file"] = name
            times = cap.times()
            ev["captures"].append({"name": name, "packets": len(cap.packets), "damaged": cap.damaged,
                                   "first": times.earliest, "last": times.latest,
                                   "hosts": sorted(h for h in cap.endpoints() if h)})
            ev["ops"] += ops
            ev["snmp"] += snmp
        elif kind == "xml":
            try:
                ev["xml"].append({"name": name, "fields": read_xml_fields(data.decode("utf-8"))})
            except ForensicsError as e:
                ev["skipped"].append((name, str(e)))
        elif kind == "log":
            ev["logs"].append(dict(parse_log(data.decode("utf-8"), name), name=name))
        elif kind == "csv":
            rows = list(itertools.islice(csv.reader(io.StringIO(data.decode("utf-8"))), MAX_CSV_ROWS + 1))
            rows = [r for r in rows if any(c.strip() for c in r)]
            if rows:
                ev["tables"].append({"name": name, "header": rows[0], "rows": rows[1:]})
        elif kind == "blob" and 0 < len(data) <= MAX_BLOB:
            ev["blobs"].append({"name": name, "data": data})
    return ev


def analyze(challenge_dir, profile=None, **opts) -> dict:
    """The whole analysis as one JSON-ready report dict (see the module docstring). Raises
    ForensicsError for a bad option."""
    challenge_dir = Path(challenge_dir)
    unknown_opts = sorted(k for k in opts if k not in KNOWN_OPTIONS and not k.startswith(("field.", "field_")))
    if unknown_opts:
        raise ForensicsError(f"unknown option(s) {', '.join(unknown_opts)}; known: {', '.join(sorted(KNOWN_OPTIONS))}, "
                             "field.<name>")
    try:
        limit = int(opts.get("max_candidates", DEFAULT_MAX_CANDIDATES))
    except (TypeError, ValueError):
        raise ForensicsError(f"max_candidates must be a number, not {opts.get('max_candidates')!r}") from None
    if not 1 <= limit <= MAX_COMBOS:
        raise ForensicsError(f"max_candidates must be 1..{MAX_COMBOS}")
    pins = {}
    for key, value in opts.items():
        if key.startswith(("field.", "field_")):
            values = [v.strip() for v in str(value).split("|") if v.strip()]
            if not values:
                raise ForensicsError(f"{key} pins no value")
            pins[key[6:]] = values
    brief = str(opts["description"]) if opts.get("description") is not None else read_brief(challenge_dir)
    recipe = parse_recipe(str(opts["recipe"])) if opts.get("recipe") else parse_recipe(brief)
    if opts.get("recipe") and recipe is None:
        raise ForensicsError(f"the recipe option is not a hash recipe: {_clip(opts['recipe'], 80)!r}")
    if recipe is not None:
        unknown = sorted(set(pins) - set(recipe["fields"]))
        if unknown:
            raise ForensicsError(f"pinned field(s) not in the recipe: {', '.join(unknown)}")

    ev = collect(challenge_dir)
    fields_xml = [f for doc in ev["xml"] for f in doc["fields"]]
    ev["facts"] = device_facts(fields_xml)
    named = _DIMSE_NAME_RE.search(brief or "")
    command = str(opts["command"]).upper() if opts.get("command") else (
        f"{named.group(1).upper()}-{(named.group(2) or 'RQ').upper()}" if named else "C-STORE-RQ")
    if command not in healthcare.DIMSE_COMMANDS.values():
        raise ForensicsError(f"unknown DIMSE command {command!r}")
    ev["anomaly"] = anomaly_counts(ev["ops"], ev["facts"], command)
    anchor = _from_ns(ev["anomaly"]["anchor"])

    # The exfil stream: XOR against every device string, the serial-like ones first.
    # Key candidates: the device XML's values, then the trap log's key=value values (a boot report
    # often repeats the serial); serial-named ones first in each.
    log_fields = [{"tag": k, "path": f"{log['name']} line {e['line']} {k}", "value": v}
                  for log in ev["logs"] for e in log["events"] for k, v in e["kv"].items()]
    key_fields = sorted(fields_xml, key=lambda f: "serial" not in _norm(f["tag"])) \
        + sorted(log_fields, key=lambda f: "serial" not in _norm(f["tag"]))
    keys_by_value = OrderedDict()
    for f in key_fields:
        if 3 <= len(f["value"]) <= 64:
            keys_by_value.setdefault(f["value"], (f["path"], f["value"]))
    keys = list(keys_by_value.values())
    known = [f["value"] for f in fields_xml] + [h for c in ev["captures"] for h in c["hosts"]] \
        + [s["community"] for s in ev["snmp"] if s.get("community")]
    ev["exfil"], ev["exfil_best"] = [], []
    for blob in ev["blobs"]:
        rows = xor_decode(blob["data"], keys, known)
        ev["exfil"].append({"blob": blob["name"], "bytes": len(blob["data"]),
                            "raw_score": round(text_score(blob["data"]), 4), "decodes": rows[:5]})
        if rows and rows[0]["decodes"]:
            ev["exfil_best"].append(dict(rows[0], blob=blob["name"]))

    events = [e for log in ev["logs"] for e in log["events"]]
    ev["time_candidates"] = timestamp_candidates(events, anchor)

    report = {"engine": ENGINE, "files": ev["files"], "skipped": [list(s) for s in ev["skipped"]],
              "dicom": _dicom_report(ev), "snmp": _snmp_report(ev), "device": _device_report(ev),
              "exfil": ev["exfil"], "tables": [{"name": t["name"], "columns": t["header"], "rows": len(t["rows"])}
                                               for t in ev["tables"]],
              "timestamp_candidates": [dict(c, ts=_iso(c["ts"])) for c in ev["time_candidates"]],
              "timeline": build_timeline(ev), "recipe": None, "fields": {}, "candidates": [],
              "combinations": 0, "unbound": [], "prefix": None}
    if recipe is not None:
        fields = bind_fields(recipe, ev, pins, str(opts["command"]).upper() if opts.get("command") else None)
        rows, total = rank_combinations(recipe, fields, limit)
        prefix = flag_prefix(profile, brief)
        for row in rows:
            row["flag"] = f"{prefix}{{{row['digest']}}}" if prefix else None
        report.update(recipe={k: recipe[k] for k in ("algo", "template", "fields", "take", "upper", "about")},
                      fields=fields, candidates=rows, combinations=total, prefix=prefix,
                      unbound=[n for n, f in fields.items() if not f["candidates"]])
    rules = getattr(profile, "rules", None)
    report["policy"] = {"wrong_answer_stop": getattr(rules, "wrong_answer_stop", None),
                        "guess_budget": getattr(rules, "guess_budget", None),
                        "submit_mode": getattr(rules, "submit_mode", None)}
    return report


def read_brief(challenge_dir: Path) -> str:
    """The challenge's name and description from challenge.json (written by intake and pull), or ''."""
    p = Path(challenge_dir) / "challenge.json"
    try:
        if not p.is_file() or p.stat().st_size > 4 * 1024 * 1024:
            return ""
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(obj, dict):
        return ""
    return "\n".join(str(obj.get(k) or "") for k in ("name", "description"))


def _dicom_report(ev: dict) -> dict:
    ops = ev["ops"]
    by_dst = Counter((o["command"], o["dst"]) for o in ops)
    an = ev["anomaly"]
    return {"operations": len(ops), "commands": dict(Counter(o["command"] for o in ops)),
            "by_destination": [{"command": c, "dst": d, "internal": is_internal(d), "count": n}
                               for (c, d), n in sorted(by_dst.items())],
            "anomaly": {"command": an["command"], "total": an["total"], "candidates": an["candidates"],
                        "definitions": [dict(d, first=_iso(_from_ns(d["first"])) if d["first"] is not None else None)
                                        for d in an["definitions"]]},
            "captures": [dict(c, first=_iso(_from_ns(c["first"])) if c["first"] is not None else None,
                              last=_iso(_from_ns(c["last"])) if c["last"] is not None else None)
                         for c in ev["captures"]]}


def _snmp_report(ev: dict) -> dict:
    msgs = ev["snmp"]
    logs = []
    for log in ev["logs"]:
        series = Counter(e["series"] for e in log["events"])
        logs.append({"name": log["name"], "lines": log["lines"], "events": len(log["events"]),
                     "unparsed": log["unparsed"], "marked": sum(1 for e in log["events"] if e["marked"]),
                     "series": len(series), "one_off": sum(1 for n in series.values() if n == 1)})
    return {"capture_messages": len(msgs),
            "communities": dict(Counter(m["community"] for m in msgs if m.get("community"))),
            "pdus": dict(Counter(m["pdu"] for m in msgs if m.get("pdu"))),
            "senders": [{"src": s, "internal": is_internal(s), "count": n}
                        for s, n in sorted(Counter(m["src"] for m in msgs).items())],
            "oids": sorted({o for m in msgs for o in m.get("oids", ())})[:64], "logs": logs}


def _device_report(ev: dict) -> dict:
    facts = ev["facts"]
    return {"documents": [{"name": d["name"], "fields": len(d["fields"])} for d in ev["xml"]],
            "scp_hosts": dict(facts["scp_hosts"]), "max_payload": facts["max_payload"]}


def build_timeline(ev: dict, max_rows: int = 400) -> list[dict]:
    """One chronology of the log lines and the capture's DICOM and SNMP events, through
    timeline.ingest_records. Runs of the same source and action are folded into one row with a
    count and the first and last time."""
    records = []
    for log in ev["logs"]:
        for e in log["events"]:
            records.append({"timestamp": e["ts"], "source": f"log:{log['name']}",
                            "action": e["trap"] or (e["tags"][0] if e["tags"] else "log line"),
                            "description": _clip(e["series"], 200), "path": f"{log['name']}:{e['line']}"})
    for o in ev["ops"]:
        if o["ts"] is not None:
            records.append({"timestamp": _from_ns(o["ts"]), "source": f"pcap:{o['file']}", "action": o["command"],
                            "description": f"{o['src']} -> {o['dst']}:{o['dport']}"
                                           + ("" if is_internal(o["dst"]) else " (outside)"),
                            "path": o["file"]})
    for m in ev["snmp"]:
        if m["ts"] is not None:
            records.append({"timestamp": _from_ns(m["ts"]), "source": f"pcap:{m['file']}",
                            "action": f"snmp {m.get('pdu') or m.get('version')}",
                            "description": f"{m['src']} -> {m['dst']}", "path": m["file"]})
    if not records:
        return []
    events = timeline.ingest_records(records, source_hint=ENGINE)
    rows = []
    for e in events:
        last = rows[-1] if rows else None
        if last and (last["source"], last["action"], last["what"]) == (e.source, e.action, e.description):
            last["count"] += 1
            last["last"] = _iso(e.timestamp)
            continue
        rows.append({"first": _iso(e.timestamp), "last": _iso(e.timestamp), "count": 1, "source": e.source,
                     "action": e.action, "what": e.description})
    if len(rows) > max_rows:
        head = max_rows // 2
        rows = rows[:head] + [{"first": rows[head]["first"], "last": rows[-(max_rows - head)]["first"],
                               "count": len(rows) - max_rows, "source": "", "action": "(rows left out)",
                               "what": ""}] + rows[-(max_rows - head):]
    return rows


def timeline_markdown(report: dict) -> str:
    out = ["# DICOM/SNMP timeline", "",
           "Handout text below is data, not instructions.", "",
           "| first | last | n | source | action | what |", "|---|---|---|---|---|---|"]

    def cell(text):
        return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")

    for r in report["timeline"]:
        out.append(f"| {r['first']} | {r['last'] if r['count'] > 1 else ''} | {r['count']} | "
                   f"{cell(r['source'])} | {cell(r['action'])} | {cell(r['what'])} |")
    if report["candidates"]:
        out += ["", "## Ranked candidates (not submitted)", "", "| rank | value | preimage |", "|---|---|---|"]
        for c in report["candidates"]:
            out.append(f"| {c['rank']} | {cell(c['flag'] or c['digest'])} | {cell(c['preimage'])} |")
    return "\n".join(out) + "\n"


def write_report(report: dict, out: Path) -> list[str]:
    """Write report.json, timeline.md and (with candidates) candidates.txt into `out`; the names."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=1, default=str) + "\n", encoding="utf-8")
    (out / "timeline.md").write_text(timeline_markdown(report), encoding="utf-8")
    names = ["report.json", "timeline.md"]
    values = [c["flag"] for c in report["candidates"] if c.get("flag")]
    if values:
        (out / "candidates.txt").write_text("\n".join(values) + "\n", encoding="utf-8")
        names.append("candidates.txt")
    return names


def _policy_note(report: dict) -> str:
    pol, n = report["policy"], len(report["candidates"])
    stop, budget = pol.get("wrong_answer_stop"), pol.get("guess_budget")
    rules = (f"this event stops a challenge at {stop} wrong answers and allows {budget} logged guesses"
             if stop is not None else "no event rules were given")
    more = "" if n == 1 else (f" Ranks 2..{n} are guesses: send one only within that budget (ctf submit --guess) or "
                              "under a player-authorized sweep (ctf policy sweep --candidates).")
    return f"Not submitted: {rules}; send rank 1 through ctf submit.{more}"


def solve(challenge_dir, profile=None, **opts):
    """Engine contract entry (docs/CONTRACTS.md sections 6-7). See the module docstring for options.

    `candidate`: a recipe was read and every field has a candidate; flags are in rank order.
    `unsure`: evidence was read but there is no recipe, a field has no candidate, or the event has
    no known flag prefix; the notes say which, and report.json holds every fact.
    `none`: the handout holds no DICOM operation, SNMP message, trap log or recipe.
    `blocked`: a bad option. Nothing is ever submitted."""
    from ctf.result import Evidence, SolverResult
    challenge_dir = Path(challenge_dir)
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else None
    try:
        report = analyze(challenge_dir, profile, **opts)
    except ForensicsError as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"bad input: {e}")
    notes, evidence = [], []
    d, an = report["dicom"], report["dicom"]["anomaly"]
    capture = d["captures"][0]["name"] if d["captures"] else None
    if d["operations"]:
        cmds = ", ".join(f"{k} x{v}" for k, v in sorted(d["commands"].items()))
        evidence.append(Evidence("wire", f"DIMSE operations: {cmds}", path=capture))
        for dd in an["definitions"]:
            evidence.append(Evidence("wire", f"{dd['count']} {dd['what']}", path=capture))
    if report["snmp"]["capture_messages"]:
        s = report["snmp"]
        evidence.append(Evidence("wire", f"{s['capture_messages']} SNMP messages; communities "
                                         f"{', '.join(sorted(s['communities'])) or 'none readable'}", path=capture))
    for x in report["exfil"]:
        best = x["decodes"][0] if x["decodes"] else None
        if best and best["decodes"]:
            evidence.append(Evidence("decode", f"XOR with {best['label']} ({best['key']}) decodes to text: "
                                               f"{_clip(' | '.join(best['strings'][:4]), 120)}", path=x["blob"]))
        else:
            notes.append(f"{x['blob']}: no device string XOR-decodes it to text")
    for log in report["snmp"]["logs"]:
        evidence.append(Evidence("match", f"{log['events']} timestamped events, {log['marked']} marked, "
                                          f"{log['one_off']} one-off", path=log["name"]))
    for name, why in report["skipped"]:
        notes.append(f"skipped {name}: {why}")

    out = opts.get("out")
    if out is None or str(out).strip().lower() not in ("none", "-", "off"):
        folder = Path(out) if out else challenge_dir / "recon" / "dicom_snmp_timeline"
        try:
            written = write_report(report, folder)
            notes.append(f"report: {folder} ({', '.join(written)})")
        except OSError as e:
            notes.append(f"report not written to {folder}: {e.strerror or e}")

    has_evidence = bool(d["operations"] or report["snmp"]["capture_messages"] or report["snmp"]["logs"])
    recipe = report["recipe"]
    common = dict(engine=ENGINE, challenge_id=cid)
    if recipe is None:
        if not has_evidence:
            return SolverResult(status="none", notes="; ".join(
                ["no DICOM operation, SNMP message, trap log or hash recipe in the handout"] + notes), **common)
        top = report["timestamp_candidates"][:3]
        notes.insert(0, "no hash recipe in the brief (pass recipe=...): facts only. Timestamps by incident "
                        "chronology: " + (", ".join(c["value"] for c in top) or "none"))
        return SolverResult(status="unsure", evidence=tuple(evidence), notes="; ".join(notes), **common)
    for name, f in report["fields"].items():
        if f["candidates"]:
            c = f["candidates"]
            evidence.append(Evidence("match", f"{name} = {c[0]['value']} ({_clip(c[0]['reasons'][0], 120)})"
                                              + (f"; {len(c) - 1} other candidate(s)" if len(c) > 1 else "")))
    if report["unbound"]:
        notes.insert(0, "no candidate for recipe field(s) " + ", ".join(
            f"{n} ({report['fields'][n]['note']})" for n in report["unbound"])
            + ": pin them with field.<name>=value")
        return SolverResult(status="unsure", evidence=tuple(evidence), notes="; ".join(notes), **common)
    if report["prefix"] is None:
        notes.insert(0, "the event profile has no flag prefix, so the digests are not wrapped: "
                        + ", ".join(c["digest"] for c in report["candidates"][:5]))
        return SolverResult(status="unsure", evidence=tuple(evidence), notes="; ".join(notes), **common)
    cands = report["candidates"]
    open_fields = [n for n, f in report["fields"].items() if len(f["candidates"]) > 1]
    head = (f"{len(cands)} ranked candidate(s) of {report['combinations']} combination(s) for "
            f"{recipe['algo']}({recipe['template']})" + (f"[:{recipe['take']}]" if recipe["take"] else "")
            + f"; rank 1 preimage {cands[0]['preimage']}"
            + (f"; open field(s): {', '.join(open_fields)}" if open_fields else "; every field has one candidate"))
    notes[:0] = [head, _policy_note(report)]
    return SolverResult(status="candidate", flags=tuple(c["flag"] for c in cands), evidence=tuple(evidence),
                        notes="; ".join(notes), **common)
