#!/usr/bin/env python3
"""Cloud and identity log toolkit (backlog row 85, toolkit key `cloudlogs`).

  .venv/bin/python solvers/toolkits/cloudlogs.py <file>... [--json] [--top N]
  .venv/bin/python solvers/toolkits/cloudlogs.py --pivot <file|folder>... [--attacker-ip IP]...
                                                 [--brief DIR|FILE] [--template T] [--json]

Offline, plain Python (stdlib only), no Game Master request. It reads log exports in JSON (one
document, or a wrapper such as {"Records": [...]}, {"value": [...]}, {"items": [...]},
{"hits": {"hits": [...]}}), JSON lines and CSV (a JSON cell such as AuditData is unfolded), gzip
included, and knows eight sources by their own field names, never by a file name:

  m365_ual        Microsoft 365 Unified Audit Log (Operation, Workload, UserId, ClientIP, AuditData)
  entra_signin    Entra ID sign-in logs (Graph, the portal's CSV, Azure Monitor / Sentinel)
  entra_audit     Entra ID audit logs (activityDisplayName, initiatedBy, targetResources; the portal's
                  flat CSV: Activity, Actor..., Target1..., AdditionalDetail1Key...)
  cloudtrail      AWS CloudTrail (eventName, eventSource, userIdentity)
  azure_activity  Azure Activity log (operationName, caller, resourceId)
  gcp_audit       GCP Cloud Audit Logs (protoPayload.methodName, authenticationInfo)
  okta            Okta System Log (eventType, published, actor, client, outcome)
  k8s_audit       Kubernetes audit log (audit.k8s.io: verb, user, objectRef, sourceIPs)

Every record becomes one event with the same fields (time, actor, ip, ua, op, result, country,
city, lat, lon, app, target, signin, raw), so the helpers work on any of them:

  load(files) -> Log            log.events, log.sources, log.notes
  counts_by(events, field)      Counter of a field ("actor", "ip", "op", "ua", "country", ...)
  signins(events)               the sign-in events, oldest first
  suspicious_signins(events)    [(method, event)]: what each named heuristic calls the first suspicious one
  impossible_travel(events)     pairs of sign-ins of one account too far apart for the time between
  inbox_rules(events)           mailbox rules and forwarding: name, forward_to, move_to, delete, keywords
  consent_grants(events)        OAuth consents: app, app_id, scopes, admin
  access_keys(events)           created access keys (AWS CreateAccessKey, GCP service account keys)
  role_assumptions(events), role_chains(events)   AWS AssumeRole calls, chained by the issued key
  registered_devices(events)    Entra "Register device" rows: name, device_id, ip, time, actor
  device_code_signins(events)   [(how, event)]: sign-ins that carry the device-code flow marker
  downloads(events)             FileDownloaded / FileSyncDownloadedFull: file, object, ip, time
  pivot(events, named, access)  the per-IP join of all of them (and of an access log's requests), with
                                each device, rule and download judged under the two written rules

The pivot (`--pivot`, B-066) joins, per client IP, the sign-ins, the devices registered, the inbox
rules made and the files downloaded from it, and the requests the same address made in any web
access log among the files (read by web_evidence.py). It decides two things, by two rules that are
printed with every run and never widened by a guess:

  attacker IP   ATTACKER_RULE: an IP that is named (--attacker-ip), or from which a SUCCESSFUL sign-in
                carries the device-code flow marker. Nothing else names one.
  decoys        DECOY_RULE: a device, rule or download is the attacker's only when its own record's
                IP is an attacker IP (or, a device, its Device Id signs in from one) and it is not
                older than the first sign-in from that IP that opened a session (a failed or
                interrupted sign-in does not count; a Device Id seen from several attacker IPs
                takes the earliest of their first sign-ins). A device registered or a rule made from
                another address, or before that sign-in, is rejected and the reason is printed.

A flag template in the brief (--brief <challenge folder>, or --template) such as
PREFIX{<device_name>_<rule_name>_<download_count>} is filled only when every <slot> is a name in
TEMPLATE_FIELDS and has exactly one attributed value; otherwise each obstacle is printed and no
flag is. The template itself is never echoed. At intake (the manifest's [intake] table) a filled
flag is this engine's flag like any other: when it is the only flag found, intake reports `solved`
and the capped auto-submit (ctf/intake/autosubmit.py, cap 1 per challenge) may send it. It is an
inference under the two rules above, not text read from the handout.

The three contracts of a toolkit:

  signals(questions, files) -> float   0..1, how much a delivery and its questions look like cloud
                                       logs (cheap: byte markers of the field names, question words)
  solve_set(questions, files, ctx)     the runner contract; never guesses (below)
  the command above                    a triage of the files for a reader

What solve_set answers (AGENTS.md, "Uncertain answers"). A question is answered only when every
word of it is understood (a word outside this file's vocabulary means None), and:

  plain    a value read from the log that the question pins down by itself: a count under literal
           filters (an operation, an account or an IP the question names, a result, a class), the
           one inbox rule's name, the one consented app, the one created access key id, the IP, user
           agent or account of such an event, a first or last event by an unambiguous timestamp,
           the account with strictly the most events
  unsure   labels.pick('cloudlogs.<field>/<source>.<subject>', [(method, value), ...]) for a fact
           whose selection or spelling is not judged: the first suspicious sign-in (one option per
           heuristic that fires, the ones most heuristics agree on first), impossible travel, every
           timestamp (as logged, ISO with Z, ...), a list (scopes, a role chain: the joins), an IP
           logged with a port, an AWS identity (user name or ARN), a country (as logged or its name)
  None     everything else, a log that was cut or did not parse whole, and any delivery in which no
           known source is found (so this file answers nothing on the lanes of Days 1 to 8)

The label key's lane is `cloudlogs`. Until solvers/common/labels.py lists that lane, pick() refuses
the key and an unsure answer is written in the wire form directly ("??" + JSON): never sent, shown
as unsure, and probed only once the lane is registered.
"""
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import math
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Run as a script, Python puts this folder first on the path, and a sibling toolkit named like a
# standard module (email.py) would then be imported in its place (the pivot loads web_evidence.py,
# which imports the ctf package).
if __name__ == "__main__":
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != HERE]
sys.path.insert(0, str(HERE.parent / "common"))
try:
    import labels      # noqa: E402
except Exception:      # a copy of this file alone still reads logs
    labels = None

KEY = "cloudlogs"
SOURCES = ("m365_ual", "entra_signin", "entra_audit", "cloudtrail", "azure_activity", "gcp_audit", "okta", "k8s_audit")
MAX_BYTES = 96 * 1024 * 1024    # one file; a larger one is not read (and nothing is answered from it)
MAX_FILES = 200
SNIFF = 96 * 1024               # bytes of a file signals() looks at
FAIL_MIN = 3                    # failures before a success that make it "after failures"
TRAVEL_KMH = 1000.0             # faster than an airliner between two sign-ins
ARROW = " -> "
UNSURE = "??"
MAX_OPTIONS = 12
# Option names of a value that is read from the log but not proven to be what the question means (a
# stand-in field, a selection this file made). One such option alone is still an unsure answer.
SOFT = {"identity_tail", "identity", "actor_as_mailbox", "grant_target_display_name", "target_type_1", "service_principal_names",
        "target_id", "object_id", "additional_details_app_id", "country_as_logged", "signin_ops"}
# Sources in which "a sign-in" is this file's choice among the operations (Okta's user.session.start,
# CloudTrail's ConsoleLogin, GCP's login service), so an answer over that class is not plain.
SOFT_SIGNIN_SOURCES = {"okta", "cloudtrail", "gcp_audit"}
_MEMO = {}


# ---- small readers ---------------------------------------------------------------------------------

def _get(d, *paths):
    """The first non-empty value under any of the dotted paths; keys match without case, a list in
    the way is entered at its first element."""
    for path in paths:
        cur = d
        for part in path.split("."):
            if isinstance(cur, list):
                cur = cur[0] if cur else None
            if isinstance(cur, str) and cur[:1] in "{[":
                try:
                    cur = json.loads(cur)
                    if isinstance(cur, list):
                        cur = cur[0] if cur else None
                except ValueError:
                    cur = None
            if not isinstance(cur, dict):
                cur = None
                break
            if part in cur:
                cur = cur[part]
            else:
                low = part.lower()
                cur = next((v for k, v in cur.items() if isinstance(k, str) and k.lower() == low), None)
            if cur is None:
                break
        if cur not in (None, "", [], {}):
            return cur
    return None


def _listed(v) -> list:
    """A value that should be a list of objects: a list, a JSON string of one, or nothing."""
    if isinstance(v, str) and v.strip()[:1] in "[{":
        try:
            v = json.loads(v)
        except ValueError:
            return []
    if isinstance(v, dict):
        return [v]
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _nv(items, name, value_keys=("Value", "value", "NewValue", "newValue")):
    """The value of the entry called `name` in a list of {Name, Value} objects (M365 Parameters,
    ExtendedProperties, ModifiedProperties; Entra additionalDetails with key/value)."""
    want = name.lower()
    for it in _listed(items):
        n = it.get("Name", it.get("name", it.get("key", it.get("displayName"))))
        if isinstance(n, str) and n.lower() == want:
            for k in value_keys:
                if it.get(k) not in (None, ""):
                    return it[k]
    return None


def _s(v):
    if v is None or isinstance(v, (dict, list)):
        return None
    s = str(v).strip()
    return s or None


_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d+))?)?\s*(Z|UTC|GMT|[+-]\d\d:?\d\d)?$", re.I)
_US = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}),?\s+(\d{1,2}):(\d\d)(?::(\d\d))?\s*([AP]M)?$", re.I)


def parse_time(v):
    """(datetime in UTC or None, quality): 'ok' for an ISO time or an epoch, 'assumed' for a
    month/day/year time (the order of day and month is the US one, not proven), 'none'."""
    if isinstance(v, bool) or v is None:
        return None, "none"
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{10}(?:\d{3})?(?:\.\d+)?", v.strip())):
        n = float(v)
        if n > 1e11:
            n /= 1000.0
        if 1e9 <= n < 4e9:
            return datetime.fromtimestamp(n, tz=timezone.utc), "ok"
        return None, "none"
    s = str(v).strip()
    m = _ISO.match(s)
    if m:
        y, mo, d, h, mi, sec, frac, tz = m.groups()
        try:
            t = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0),
                         int(((frac or "") + "000000")[:6]), tzinfo=timezone.utc)
        except ValueError:
            return None, "none"
        if tz and tz[0] in "+-":
            hh, mm = int(tz[1:3]), int(tz[-2:])
            t -= timedelta(hours=hh, minutes=mm) * (1 if tz[0] == "+" else -1)
        return t, "ok"
    m = _US.match(s)
    if m:
        a, b, y, h, mi, sec, ap = m.groups()
        a, b, h = int(a), int(b), int(h)
        if ap:
            h = h % 12 + (12 if ap.upper() == "PM" else 0)
        mo, d = (a, b) if a <= 12 else (b, a)
        try:
            return datetime(int(y), mo, d, h, int(mi), int(sec or 0), tzinfo=timezone.utc), ("ok" if a > 12 or b > 12 or a == b else "assumed")
        except ValueError:
            return None, "none"
    return None, "none"


def clean_ip(v):
    """(address without a port, the text as logged). The address is None for anything that is not
    an IPv4 or IPv6 address (CloudTrail writes a service name there for AWS's own calls)."""
    raw = _s(v)
    if raw is None:
        return None, None
    s = raw
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::\d+)?", s) or re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", s)
    if m:
        s = m.group(1)
    try:
        ipaddress.ip_address(s)
        return s, raw
    except ValueError:
        return None, raw


def _res(v):
    s = str(v).strip().lower() if v is not None and not isinstance(v, (dict, list)) else ""
    if s in ("success", "succeeded", "successful", "true", "allow", "allowed", "ok", "0", "passed"):
        return "success"
    if s in ("failure", "failed", "fail", "false", "deny", "denied", "error", "unsuccessful"):
        return "failure"
    if s in ("interrupted", "challenge"):
        return "interrupted"
    return None


# Entra sign-in error codes the portal shows as "Interrupted" (a prompt, not a refusal).
ENTRA_INTERRUPT = {50140, 50074, 50076, 50079, 50072, 50125, 50097, 50058, 50199, 16000, 16001, 65001, 50055, 50144}

COUNTRY = {
    "US": "United States", "GB": "United Kingdom", "CA": "Canada", "DE": "Germany", "FR": "France",
    "NL": "Netherlands", "RU": "Russia", "CN": "China", "IN": "India", "BR": "Brazil", "NG": "Nigeria",
    "AU": "Australia", "JP": "Japan", "KR": "South Korea", "KP": "North Korea", "IR": "Iran", "UA": "Ukraine",
    "PL": "Poland", "RO": "Romania", "BG": "Bulgaria", "SE": "Sweden", "NO": "Norway", "FI": "Finland",
    "DK": "Denmark", "IE": "Ireland", "ES": "Spain", "PT": "Portugal", "IT": "Italy", "CH": "Switzerland",
    "AT": "Austria", "BE": "Belgium", "CZ": "Czechia", "TR": "Turkey", "IL": "Israel", "SA": "Saudi Arabia",
    "AE": "United Arab Emirates", "EG": "Egypt", "ZA": "South Africa", "KE": "Kenya", "GH": "Ghana",
    "MX": "Mexico", "AR": "Argentina", "CO": "Colombia", "CL": "Chile", "SG": "Singapore", "HK": "Hong Kong",
    "TW": "Taiwan", "VN": "Vietnam", "TH": "Thailand", "ID": "Indonesia", "MY": "Malaysia", "PH": "Philippines",
    "PK": "Pakistan", "BD": "Bangladesh", "NZ": "New Zealand", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia",
    "MD": "Moldova", "BY": "Belarus", "KZ": "Kazakhstan", "HU": "Hungary", "GR": "Greece", "RS": "Serbia",
    "PA": "Panama", "SC": "Seychelles", "IS": "Iceland", "LU": "Luxembourg",
}
COUNTRY_CODE = {v.lower(): k for k, v in COUNTRY.items()}


# ---- loading ---------------------------------------------------------------------------------------

def _text(data: bytes):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if b"\x00" in data[:2048]:
        if data[1:2] == b"\x00" and data[3:4] == b"\x00":
            return data.decode("utf-16-le", "replace")
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


_WRAP = ("Records", "records", "value", "items", "events", "Events", "logEvents", "results", "logs", "entries", "data")
_INNER_REPLACE = ("_raw", "message", "rawData", "raw")
_INNER_MERGE = ("AuditData", "auditdata", "Auditdata", "audit_data")


def _unwrap(doc) -> list:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if not isinstance(doc, dict):
        return []
    hits = doc.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        return [r for r in hits["hits"] if isinstance(r, dict)]
    for k in _WRAP:
        v = doc.get(k)
        if isinstance(v, list) and v and all(isinstance(r, dict) for r in v):
            return v
    return [doc]


def _inner(rec: dict) -> dict:
    """The log record inside an export's envelope (Elastic _source, Splunk result/_raw, CloudWatch
    message, the AuditData cell of a Purview CSV)."""
    for _ in range(3):
        if isinstance(rec.get("_source"), dict):
            rec = rec["_source"]
            continue
        if isinstance(rec.get("result"), dict) and set(rec) <= {"preview", "result", "offset", "lastrow"}:
            rec = rec["result"]
            continue
        moved = False
        for k in _INNER_MERGE:
            v = rec.get(k)
            if isinstance(v, str) and v.lstrip()[:1] == "{":
                try:
                    inner = json.loads(v)
                except ValueError:
                    continue
                if isinstance(inner, dict):
                    rec = {**{a: b for a, b in rec.items() if a != k}, **inner}
                    moved = True
                    break
            elif isinstance(v, dict):
                rec = {**{a: b for a, b in rec.items() if a != k}, **v}
                moved = True
                break
        if moved:
            continue
        for k in _INNER_REPLACE:
            v = rec.get(k)
            if isinstance(v, str) and v.lstrip()[:1] == "{":
                try:
                    inner = json.loads(v)
                except ValueError:
                    continue
                if isinstance(inner, dict) and len(inner) >= 3:
                    rec = inner
                    moved = True
                    break
        if not moved:
            break
    return rec


def load_records(data: bytes, name: str = "") -> tuple:
    """(records, form, whole) of one file. form: json, jsonl, csv or None (not a log export this file
    reads). whole is False when part of the file did not parse (nothing is answered from it then)."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_BYTES + 1)
        except (OSError, EOFError, ValueError):
            return [], None, False
    if len(data) > MAX_BYTES or data[:4] in (b"PK\x03\x04", b"7z\xbc\xaf") or data[:4] == b"\x7fELF" or data[:2] == b"MZ":
        return [], None, len(data) <= MAX_BYTES
    text = _text(data)
    if text is None:
        return [], None, True
    body = text.lstrip()
    if body[:1] in "[{":
        try:
            return [_inner(r) for r in _unwrap(json.loads(body))], "json", True
        except ValueError:
            pass
        recs, bad = [], 0
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in "[]":
                continue
            try:
                doc = json.loads(line)
            except ValueError:
                bad += 1
                continue
            recs += [_inner(r) for r in _unwrap(doc)]
        if recs:
            return recs, "jsonl", bad == 0
        # nothing parsed: any other text is not a log, but a file that carries a known source's
        # field names is a log that was cut or damaged
        return [], None, _sniff(data) is None
    head = body.split("\n", 1)[0]
    delim = max(",;\t|", key=head.count)
    if head.count(delim) < 1 or len(head) > 20000:
        return [], None, True
    try:
        csv.field_size_limit(MAX_BYTES)
        rows = list(csv.DictReader(io.StringIO(body), delimiter=delim))
    except csv.Error:
        return [], None, False
    whole = all(None not in r and None not in r.values() for r in rows)
    recs = []
    for r in rows:
        rec = {str(k).strip().strip('"'): v for k, v in r.items() if k is not None}
        for k, v in list(rec.items()):
            if isinstance(v, str) and v[:1] in "{[" and v[-1:] in "}]" and k not in _INNER_MERGE:
                try:
                    rec[k] = json.loads(v)
                except ValueError:
                    pass
        recs.append(_inner(rec))
    return recs, "csv", whole


def detect(rec: dict) -> str:
    """The source of one record, by its field names."""
    low = {str(k).lower() for k in rec}
    if ("auditid" in low and ({"requesturi", "verb"} & low)) or str(rec.get("apiVersion", "")).startswith("audit.k8s.io"):
        return "k8s_audit"
    if "eventname" in low and "eventsource" in low and ({"useridentity", "eventversion", "awsregion", "eventid"} & low):
        return "cloudtrail"
    if isinstance(_get(rec, "protoPayload"), dict) or "cloudaudit.googleapis.com" in str(_get(rec, "logName") or ""):
        return "gcp_audit"
    if "eventtype" in low and "published" in low and ({"actor", "outcome", "client"} & low):
        return "okta"
    if ({"operation", "operations"} & low) and ({"workload", "recordtype", "creationtime", "organizationid", "officeworkload",
                                                 "userid", "userids", "creationdate"} & low):
        return "m365_ual"
    cat = str(rec.get("category") or rec.get("Category") or "").lower()
    if cat in ("signinlogs", "noninteractiveusersigninlogs", "serviceprincipalsigninlogs", "managedidentitysigninlogs"):
        return "entra_signin"
    if "userprincipalname" in low and "ipaddress" in low and ({"appdisplayname", "createddatetime", "resulttype", "clientappused"} & low):
        return "entra_signin"
    if ({"username", "ip address"} <= low or {"user", "ip address"} <= low) and ({"sign-in error code", "application", "status"} & low):
        return "entra_signin"
    if cat == "auditlogs" or ("activitydisplayname" in low and ({"activitydatetime", "initiatedby", "targetresources"} & low)) \
            or ("operationname" in low and "initiatedby" in low and "targetresources" in low):
        return "entra_audit"
    # the Entra portal's "Download" of the audit log: one flat row per record (Activity, Actor..., Target1...)
    if {"activity", "date (utc)"} <= low and len({"actortype", "actoruserprincipalname", "target1type", "target1displayname"} & low) >= 2:
        return "entra_audit"
    if "operationname" in low and ({"resourceid", "caller", "calleripaddress", "resourcegroupname", "subscriptionid"} & low):
        return "azure_activity"
    if "operation_name" in low and len({"resource_id", "caller", "subscription_id", "event_timestamp", "resource_group_name"} & low) >= 2:
        return "azure_activity"
    return "unknown"


M365_SIGNIN = {"userloggedin": "success", "userloginfailed": "failure"}
OKTA_SIGNIN = {"user.session.start"}
GCP_SIGNIN = {"google.login.loginservice.loginsuccess": "success", "google.login.loginservice.loginfailure": "failure"}


def normalize(rec: dict, n: int = 0, fname: str = "", src: str = None) -> dict:
    """One record as an event (see the module text for the fields)."""
    src = src or detect(rec)
    e = {"i": n, "file": fname, "src": src, "raw": rec, "time": None, "time_raw": None, "tq": "none", "actor": None,
         "actor_alt": {}, "ip": None, "ip_raw": None, "ua": None, "op": None, "result": None, "signin": False,
         "country": None, "city": None, "lat": None, "lon": None, "app": None, "target": None, "id": None,
         "risk": None, "error": None}
    t = ip = None
    if src == "m365_ual":
        t = _get(rec, "CreationTime", "CreationDate", "TimeGenerated")
        e["actor"] = _s(_get(rec, "UserId", "UserIds", "UserKey"))
        e["op"] = _s(_get(rec, "Operation", "Operations"))
        ip = _get(rec, "ClientIP", "ClientIPAddress", "ActorIpAddress", "Client_IPAddress")
        e["ua"] = _s(_get(rec, "UserAgent") or _nv(rec.get("ExtendedProperties"), "UserAgent")
                     or _nv(_get(rec, "DeviceProperties"), "UserAgent"))
        e["app"] = _s(_get(rec, "Workload", "OfficeWorkload"))
        e["target"] = _s(_get(rec, "ObjectId", "OfficeObjectId"))
        e["id"] = _s(_get(rec, "Id"))
        e["result"] = _res(_get(rec, "ResultStatus"))
        op = (e["op"] or "").lower()
        if op in M365_SIGNIN:
            e["signin"], e["result"] = True, M365_SIGNIN[op]
            e["error"] = _s(_get(rec, "LogonError") or _nv(rec.get("ExtendedProperties"), "ResultStatusDetail"))
    elif src == "entra_signin":
        props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
        r = {**rec, **props}
        e["raw"] = r
        t = _get(r, "createdDateTime", "time", "TimeGenerated", "Date (UTC)", "Date")
        e["actor"] = _s(_get(r, "userPrincipalName", "Username", "userDisplayName", "User", "Identity"))
        ip = _get(r, "ipAddress", "IP address", "callerIpAddress")
        e["ua"] = _s(_get(r, "userAgent", "User agent"))
        e["app"] = _s(_get(r, "appDisplayName", "Application"))
        e["id"] = _s(_get(r, "id", "Request ID", "correlationId"))
        code = _get(r, "status.errorCode", "Sign-in error code", "ResultType", "resultType")
        if code is not None and re.fullmatch(r"-?\d+", str(code).strip()):
            code = int(str(code).strip())
            e["error"] = str(code)
            e["result"] = "success" if code == 0 else ("interrupted" if code in ENTRA_INTERRUPT else "failure")
        st = _res(_get(r, "Status") if not isinstance(r.get("status"), dict) else None)
        if st and (e["result"] is None or st == "interrupted"):
            e["result"] = st
        e["signin"] = True
        loc = _get(r, "location", "LocationDetails", "Location")
        if isinstance(loc, str) and loc[:1] == "{":
            try:
                loc = json.loads(loc)
            except ValueError:
                pass
        if isinstance(loc, dict):
            e["country"], e["city"] = _s(_get(loc, "countryOrRegion")), _s(_get(loc, "city"))
            e["lat"], e["lon"] = _get(loc, "geoCoordinates.latitude"), _get(loc, "geoCoordinates.longitude")
        elif isinstance(loc, str) and loc.strip():
            parts = [p.strip() for p in loc.split(",")]
            e["country"] = parts[-1] or None
            e["city"] = parts[0] if len(parts) >= 2 and parts[0] else None
        risk = [str(_get(r, k) or "").lower() for k in ("riskLevelDuringSignIn", "riskLevelAggregated", "riskState", "RiskLevelDuringSignIn")]
        types = _get(r, "riskEventTypes_v2", "riskEventTypes")
        if any(x in ("low", "medium", "high", "atrisk", "confirmedcompromised") for x in risk) or (isinstance(types, list) and types):
            e["risk"] = next((x for x in risk if x and x not in ("none", "hidden")), "flagged")
    elif src == "entra_audit":
        props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
        r = {**rec, **props}
        e["raw"] = r
        # The second run of names in each list is the portal's flat CSV (B-066). Its rows carry no record
        # id (CorrelationId is shared by the records of one request), so they are never de-duplicated by id.
        t = _get(r, "activityDateTime", "time", "TimeGenerated", "Date (UTC)")
        e["op"] = _s(_get(r, "activityDisplayName", "operationName", "OperationName", "Activity"))
        e["actor"] = _s(_get(r, "initiatedBy.user.userPrincipalName", "initiatedBy.app.displayName",
                             "initiatedBy.user.displayName", "initiatedBy.user.id",
                             "ActorUserPrincipalName", "ActorDisplayName", "ActorServicePrincipalName", "ActorObjectId"))
        ip = _get(r, "initiatedBy.user.ipAddress", "callerIpAddress", "IPAddress")
        e["result"] = _res(_get(r, "result", "Result"))
        e["target"] = _s(_get(r, "targetResources.displayName", "targetResources.userPrincipalName", "targetResources.id",
                              "Target1DisplayName", "Target1UserPrincipalName", "Target1ObjectId"))
        e["ua"] = _s(_nv(r.get("additionalDetails"), "User-Agent") or _get(r, "User Agent"))
        e["id"] = _s(_get(r, "id"))
    elif src == "cloudtrail":
        t = _get(rec, "eventTime")
        e["op"] = _s(_get(rec, "eventName"))
        ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
        alt = {"arn": _s(ui.get("arn")), "user_name": _s(ui.get("userName")), "principal_id": _s(ui.get("principalId")),
               "access_key_id": _s(ui.get("accessKeyId")), "type": _s(ui.get("type")),
               "session_issuer": _s(_get(ui, "sessionContext.sessionIssuer.arn")),
               "account_id": _s(ui.get("accountId")), "invoked_by": _s(ui.get("invokedBy"))}
        e["actor_alt"] = {k: v for k, v in alt.items() if v}
        e["actor"] = alt["arn"] or alt["user_name"] or alt["principal_id"] or alt["invoked_by"] or \
            ("root" if (alt["type"] or "").lower() == "root" else None)
        ip = _get(rec, "sourceIPAddress")
        e["ua"] = _s(_get(rec, "userAgent"))
        e["app"] = _s(_get(rec, "eventSource"))
        e["id"] = _s(_get(rec, "eventID"))
        e["error"] = _s(_get(rec, "errorCode"))
        e["result"] = "failure" if e["error"] else "success"
        e["country"] = None
        if (e["op"] or "") == "ConsoleLogin":
            e["signin"] = True
            cl = _res(_get(rec, "responseElements.ConsoleLogin"))
            e["result"] = cl or e["result"]
        e["target"] = _s(_get(rec, "requestParameters.bucketName", "requestParameters.userName", "requestParameters.roleArn",
                              "requestParameters.roleName", "requestParameters.instanceId", "resources.ARN"))
    elif src == "azure_activity":
        props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
        r = {**props, **rec}
        t = _get(r, "eventTimestamp", "event_timestamp", "time", "TimeGenerated", "submissionTimestamp", "submission_timestamp")
        op = _get(r, "operationName", "operation_name")
        e["op"] = _s(_get(op, "value", "localizedValue", "localized_value") if isinstance(op, dict) else op)
        e["actor"] = _s(_get(r, "caller", "Caller", "identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"))
        ip = _get(r, "callerIpAddress", "httpRequest.clientIpAddress", "http_request.client_ip_address", "claims.ipaddr", "identity.claims.ipaddr")
        st = _get(r, "status", "resultType", "ActivityStatusValue", "ActivityStatus")
        e["result"] = _res(_get(st, "value", "localizedValue", "localized_value") if isinstance(st, dict) else st)
        e["target"] = _s(_get(r, "resourceId", "ResourceId", "_ResourceId", "resource_id"))
        e["id"] = _s(_get(r, "eventDataId", "event_data_id"))
    elif src == "gcp_audit":
        t = _get(rec, "timestamp", "receiveTimestamp")
        e["op"] = _s(_get(rec, "protoPayload.methodName"))
        e["actor"] = _s(_get(rec, "protoPayload.authenticationInfo.principalEmail", "protoPayload.authenticationInfo.principalSubject"))
        ip = _get(rec, "protoPayload.requestMetadata.callerIp")
        e["ua"] = _s(_get(rec, "protoPayload.requestMetadata.callerSuppliedUserAgent"))
        e["app"] = _s(_get(rec, "protoPayload.serviceName"))
        e["target"] = _s(_get(rec, "protoPayload.resourceName"))
        e["id"] = _s(_get(rec, "insertId"))
        code = _get(rec, "protoPayload.status.code")
        e["result"] = "failure" if code not in (None, 0, "0") else "success"
        e["error"] = _s(_get(rec, "protoPayload.status.message"))
        op = (e["op"] or "").lower()
        if op in GCP_SIGNIN:
            e["signin"], e["result"] = True, GCP_SIGNIN[op]
    elif src == "okta":
        t = _get(rec, "published")
        e["op"] = _s(_get(rec, "eventType"))
        e["actor"] = _s(_get(rec, "actor.alternateId", "actor.displayName", "actor.id"))
        ip = _get(rec, "client.ipAddress", "request.ipChain.ip")
        e["ua"] = _s(_get(rec, "client.userAgent.rawUserAgent"))
        e["result"] = _res(_get(rec, "outcome.result"))
        e["error"] = _s(_get(rec, "outcome.reason"))
        e["country"], e["city"] = _s(_get(rec, "client.geographicalContext.country")), _s(_get(rec, "client.geographicalContext.city"))
        e["lat"], e["lon"] = _get(rec, "client.geographicalContext.geolocation.lat"), _get(rec, "client.geographicalContext.geolocation.lon")
        e["target"] = _s(_get(rec, "target.alternateId", "target.displayName"))
        e["id"] = _s(_get(rec, "uuid"))
        e["signin"] = (e["op"] or "") in OKTA_SIGNIN
    elif src == "k8s_audit":
        t = _get(rec, "requestReceivedTimestamp", "stageTimestamp", "timestamp")
        e["op"] = _s(_get(rec, "verb"))
        e["actor"] = _s(_get(rec, "user.username"))
        ips = rec.get("sourceIPs")
        ip = ips[0] if isinstance(ips, list) and ips else None
        e["ua"] = _s(_get(rec, "userAgent"))
        ref = rec.get("objectRef") if isinstance(rec.get("objectRef"), dict) else {}
        res = "/".join(str(x) for x in (ref.get("resource"), ref.get("subresource")) if x)
        e["target"] = "/".join(str(x) for x in (ref.get("namespace"), res, ref.get("name")) if x) or _s(_get(rec, "requestURI"))
        code = _get(rec, "responseStatus.code")
        if isinstance(code, int):
            e["result"] = "success" if code < 400 else "failure"
            e["error"] = str(code)
        e["id"] = _s(_get(rec, "auditID"))
        e["stage"] = _s(_get(rec, "stage"))
    else:
        t = _get(rec, "timestamp", "@timestamp", "time", "eventTime", "TimeGenerated", "datetime", "date", "created")
        e["actor"] = _s(_get(rec, "user", "username", "user_name", "userName", "actor", "principal", "account", "email"))
        ip = _get(rec, "ip", "src_ip", "source_ip", "client_ip", "clientIp", "ipAddress", "remote_addr", "sourceIPAddress")
        e["ua"] = _s(_get(rec, "user_agent", "userAgent", "useragent", "http_user_agent"))
        e["op"] = _s(_get(rec, "action", "event", "eventName", "operation", "event_type", "activity"))
        e["result"] = _res(_get(rec, "result", "status", "outcome"))
    e["time_raw"] = _s(t)
    e["time"], e["tq"] = parse_time(t)
    e["ip"], e["ip_raw"] = clean_ip(ip)
    for k in ("lat", "lon"):
        try:
            e[k] = float(e[k]) if e[k] is not None else None
        except (TypeError, ValueError):
            e[k] = None
    return e


class Log:
    """The events of a set of files. events holds only records of a known source; other holds the
    rest (shown by the command, never answered from)."""

    def __init__(self):
        self.events, self.other, self.files, self.notes = [], [], [], []
        self.whole = True

    @property
    def sources(self) -> dict:
        return dict(Counter(e["src"] for e in self.events))

    def add(self, name: str, data: bytes):
        recs, form, whole = load_records(data, name)
        _MEMO.clear()
        if form is None:
            if not whole:
                self.whole = False
                self.notes.append(f"{name}: not read (too large, a damaged gzip, or a log that was cut and does not parse)")
            return
        seen = {(e["src"], e["id"]) for e in self.events if e["id"]}
        kept = dup = repeats = 0
        mine, first = [], {}
        for rec in recs:
            e = normalize(rec, len(self.events) + len(self.other) + len(mine), name)
            if e["src"] == "unknown":
                self.other.append(e)
                continue
            if e["id"] and (e["src"], e["id"]) in seen and e["src"] != "k8s_audit":
                dup += 1
                continue
            e["copies"] = 1
            if e["id"]:
                # The same record again in the same file: one event, read once. "The same" is the same
                # id and the same value in every field this file reads; the export's own envelope
                # (a Splunk row's _cd, _indextime, ResultIndex) differs from row to row and is not compared.
                try:
                    digest = hashlib.sha256(json.dumps({a: b for a, b in e.items() if a not in ("i", "file", "raw", "copies")},
                                                       sort_keys=True, default=str).encode("utf-8", "replace")).digest()
                except (TypeError, ValueError):
                    digest = None
                k = (e["src"], e["id"])
                if digest is not None and k in first and first[k][0] == digest:
                    first[k][1]["copies"] += 1
                    repeats += 1
                    continue
                first.setdefault(k, (digest, e))
            mine.append(e)
            kept += 1
        self.events += mine
        self.files.append({"file": name, "form": form, "records": len(recs), "events": kept, "duplicates": dup, "repeats": repeats,
                           "whole": whole, "sources": dict(Counter(e["src"] for e in mine))})
        if repeats:
            self.notes.append(f"{name}: {repeats} rows repeat a record already in the file (same id, same fields); each record is "
                              "read once, and a count is offered both ways")
        if kept and not whole:
            self.whole = False
            self.notes.append(f"{name}: some lines or rows did not parse; nothing is answered from a log that is not whole")
        if dup:
            self.notes.append(f"{name}: {dup} records already read from another file (same id) were not counted twice")


def load(files: dict) -> Log:
    """A Log from {name: bytes} (the files a solver is handed: the delivery and every member)."""
    log = Log()
    seen, digests = set(), set()
    if len(files) > MAX_FILES:
        log.whole = False
        log.notes.append(f"{len(files)} files: only the first {MAX_FILES} were read, so nothing is answered")
    for name, data in list(files.items())[:MAX_FILES]:
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        digest = hashlib.sha256(data).digest()    # the same bytes under two names (a member and its copy) are one file
        if digest in digests:
            log.notes.append(f"{name}: the same bytes as a file already read; not read twice")
            continue
        digests.add(digest)
        try:
            log.add(str(name), bytes(data))
        except Exception as ex:       # a file that cannot be read is no evidence, and no reason to stop
            log.whole = False
            log.notes.append(f"{name}: {type(ex).__name__} while reading")
    return log


# ---- helpers ---------------------------------------------------------------------------------------

def _by_time(events) -> list:
    return sorted(events, key=lambda e: (e["time"] is None, e["time"] or datetime.min.replace(tzinfo=timezone.utc), e["i"]))


def counts_by(events, field) -> Counter:
    return Counter(e.get(field) for e in events if e.get(field) is not None)


def signins(events) -> list:
    return _by_time([e for e in events if e["signin"]])


def _km(a, b) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def impossible_travel(events, kmh: float = TRAVEL_KMH, window_hours: float = 2.0) -> list:
    """Consecutive successful sign-ins of one account from two places too far apart: with
    coordinates, faster than `kmh`; with countries only, two countries within `window_hours`.
    [{actor, a, b, km, hours, kmh}], oldest first; a is the earlier event."""
    out = []
    per = {}
    for e in signins(events):
        if e["result"] == "success" and e["actor"] and e["time"] is not None and (e["country"] or e["lat"] is not None):
            per.setdefault(e["actor"].lower(), []).append(e)
    for actor, evs in per.items():
        for a, b in zip(evs, evs[1:]):
            hours = (b["time"] - a["time"]).total_seconds() / 3600.0
            if None not in (a["lat"], a["lon"], b["lat"], b["lon"]):
                km = _km(a, b)
                if km < 100:
                    continue
                speed = km / hours if hours > 0 else float("inf")
                if speed > kmh:
                    out.append({"actor": actor, "a": a, "b": b, "km": round(km, 1), "hours": round(hours, 3),
                                "kmh": None if speed == float("inf") else round(speed, 1)})
            elif a["country"] and b["country"] and a["country"].lower() != b["country"].lower() and hours <= window_hours:
                out.append({"actor": actor, "a": a, "b": b, "km": None, "hours": round(hours, 3), "kmh": None})
    return sorted(out, key=lambda p: (p["b"]["time"], p["b"]["i"]))


SCRIPTED_UA = re.compile(r"python-requests|python-urllib|aiohttp|httpx|curl/|wget/|go-http-client|axios|node-fetch|okhttp|"
                         r"libwww|java/\d|powershell|postmanruntime|insomnia|bav2ropc|fasthttp|ruby|scrapy|boto3|botocore|"
                         r"aws-cli|kali|hydra|nmap|sqlmap|o365spray|msolspray|roadtools|aadinternals|trufflehog|pacu|"
                         r"evilginx|undefined|^$", re.I)

RULE_OPS = {"new-inboxrule": "create", "set-inboxrule": "modify", "updateinboxrules": "create", "enable-inboxrule": "enable",
            "disable-inboxrule": "disable", "remove-inboxrule": "remove"}
CONSENT_OPS = ("consent to application", "add delegated permission grant", "add oauth2permissiongrant",
               "add app role assignment grant to user", "add app role assignment to service principal")


def inbox_rules(events) -> list:
    """Mailbox rules and mailbox forwarding seen in the log, oldest first: {event, kind (create,
    modify, enable, disable, remove, forwarding), name, mailbox, forward_to [..], move_to, delete,
    mark_read, keywords [..], params {name: value}}."""
    out = []
    for e in _by_time(events):
        if e["src"] != "m365_ual":
            continue
        op = (e["op"] or "").lower()
        raw = e["raw"]
        params = {}
        for it in _listed(raw.get("Parameters")) + _listed(raw.get("OperationProperties")):
            n = it.get("Name", it.get("name"))
            if isinstance(n, str):
                params[n] = it.get("Value", it.get("value"))
        low = {k.lower(): v for k, v in params.items()}
        if op in RULE_OPS:
            kind = RULE_OPS[op]
        elif op == "set-mailbox" and any(low.get(k) not in (None, "", "False", False) for k in
                                         ("forwardingsmtpaddress", "forwardingaddress")):
            kind = "forwarding"
        else:
            continue
        name = _s(low.get("name") or low.get("rulename"))
        ident = None
        if name is None and kind != "forwarding":
            # Only the cmdlet's own Identity parameter names a rule (mailbox\rule); the record's ObjectId
            # is a mailbox or a store path, never read as a name. The tail is a reading, so it stays unsure.
            ident = _s(low.get("identity"))
            name = (ident.replace("/", "\\").split("\\")[-1] or None) if ident else None
        stated = _s(raw.get("MailboxOwnerUPN")) or _s(low.get("mailbox"))
        fwd = []
        for k in ("forwardto", "forwardasattachmentto", "redirectto", "forwardingsmtpaddress", "forwardingaddress"):
            v = low.get(k)
            if isinstance(v, list):
                fwd += [str(x) for x in v]
            elif isinstance(v, str) and v.strip():
                fwd += [x.strip() for x in re.split(r"[;,]", v) if x.strip()]
        words = []
        for k in ("subjectcontainswords", "bodycontainswords", "subjectorbodycontainswords", "fromaddresscontainswords"):
            v = low.get(k)
            if isinstance(v, list):
                words += [str(x) for x in v]
            elif isinstance(v, str) and v.strip():
                words += [x.strip() for x in re.split(r"[;,]", v) if x.strip()]
        out.append({"event": e, "kind": kind, "name": name, "name_from_identity": ident, "mailbox": stated or e["actor"],
                    "mailbox_stated": bool(stated),
                    "forward_to": fwd, "move_to": _s(low.get("movetofolder")),
                    "delete": str(low.get("deletemessage", "")).lower() == "true",
                    "mark_read": str(low.get("markasread", "")).lower() == "true", "keywords": words, "params": params})
    return out


def _scopes(value) -> list:
    s = str(value or "")
    m = re.findall(r"Scope:\s*([^,\]\[]+)", s)
    if m:
        out = []
        for part in m:
            out += part.split()
        return out
    return [x for x in s.strip(" \"'[]").split() if re.fullmatch(r"[A-Za-z0-9_.:/\-]+", x)]


def consent_grants(events) -> list:
    """OAuth consent and permission grants (Entra audit log and the Unified Audit Log), oldest first:
    {event, op, app (the display name, when the record states one), app_names {method: value},
    app_id, scopes [..], admin (True, False or None)}."""
    out = []
    for e in _by_time(events):
        if e["src"] not in ("entra_audit", "m365_ual"):
            continue
        op = (e["op"] or "").lower().rstrip(". ")
        if not any(op.startswith(c) for c in CONSENT_OPS):
            continue
        raw = e["raw"]
        names, ids, app_id, scopes, admin = {}, {}, None, [], None
        mods = []
        if e["src"] == "entra_audit":
            targets = _listed(raw.get("targetResources") or raw.get("TargetResources"))
            sp = next((t for t in targets if str(t.get("type", "")).lower() == "serviceprincipal"), targets[0] if targets else {})
            if _s(sp.get("displayName")):
                # Only "Consent to application" has the consented app as its target; a permission grant's
                # first target is the resource (Microsoft Graph), so its name is a candidate, not the app.
                names["target_display_name" if op.startswith("consent to application") else "grant_target_display_name"] = \
                    _s(sp.get("displayName"))
            app_id = _s(sp.get("id"))                # the service principal's object id, not proven to be the app id
            detail = _s(_nv(raw.get("additionalDetails"), "AppId"))
            if detail:
                ids["additional_details_app_id"] = detail
            if app_id:
                ids["target_id"] = app_id
            for t in targets:
                mods += _listed(t.get("modifiedProperties"))
        else:
            mods = _listed(raw.get("ModifiedProperties"))
            typed = [t for t in _listed(raw.get("Target")) if _s(t.get("ID"))]
            ones = [t["ID"] for t in typed if str(t.get("Type")) == "1"]
            if len(ones) == 1:
                names["target_type_1"] = str(ones[0])
            spn = _nv(mods, "TargetId.ServicePrincipalNames")
            if _s(spn):
                names["service_principal_names"] = _s(spn)
            app_id = _s(raw.get("ObjectId"))
            if app_id:
                ids["object_id"] = app_id
        for m in mods:
            n = str(m.get("displayName", m.get("Name", ""))).lower()
            v = m.get("newValue", m.get("NewValue"))
            if n in ("consentaction.permissions", "delegatedpermissiongrant.scope") and not scopes:
                scopes = _scopes(v)
            if n == "consentcontext.isadminconsent":
                admin = str(v).strip(" \"'").lower() == "true"
        out.append({"event": e, "op": e["op"], "app": next(iter(names.values()), None) if len(set(names.values())) == 1 else None,
                    "app_names": names, "app_id": app_id, "app_ids": ids, "scopes": scopes, "admin": admin})
    return out


def access_keys(events) -> list:
    """Access keys created (successful calls only), oldest first: {event, provider, key_id, for_user}."""
    out = []
    for e in _by_time(events):
        if e["result"] == "failure":
            continue
        if e["src"] == "cloudtrail" and e["op"] == "CreateAccessKey":
            kid = _s(_get(e["raw"], "responseElements.accessKey.accessKeyId"))
            user = _s(_get(e["raw"], "responseElements.accessKey.userName", "requestParameters.userName")) \
                or e["actor_alt"].get("user_name")
            out.append({"event": e, "provider": "aws", "key_id": kid, "for_user": user})
        elif e["src"] == "gcp_audit" and (e["op"] or "").endswith("CreateServiceAccountKey"):
            out.append({"event": e, "provider": "gcp", "key_id": _s(_get(e["raw"], "protoPayload.response.name")),
                        "for_user": _s(_get(e["raw"], "protoPayload.request.name")) or e["target"]})
    return out


def role_name(arn) -> str:
    return str(arn).rsplit("/", 1)[-1] if arn else None


def role_assumptions(events) -> list:
    """Successful AWS AssumeRole* calls, oldest first: {event, caller_arn, caller_key, role_arn,
    session_name, issued_key, assumed_arn}."""
    out = []
    for e in _by_time(events):
        if e["src"] != "cloudtrail" or not (e["op"] or "").startswith("AssumeRole") or e["result"] == "failure":
            continue
        raw = e["raw"]
        out.append({"event": e, "caller_arn": e["actor_alt"].get("arn"), "caller_key": e["actor_alt"].get("access_key_id"),
                    "role_arn": _s(_get(raw, "requestParameters.roleArn")),
                    "session_name": _s(_get(raw, "requestParameters.roleSessionName")),
                    "issued_key": _s(_get(raw, "responseElements.credentials.accessKeyId")),
                    "assumed_arn": _s(_get(raw, "responseElements.assumedRoleUser.arn"))})
    return out


def role_chains(events) -> list:
    """AssumeRole calls linked into chains: a call follows another when it was made with the access
    key that one issued (or, without keys in the log, as the assumed-role ARN it returned).
    [{origin (the first caller's ARN), roles [role ARN, ...], steps [assumption, ...], linked_by}],
    longest first."""
    steps = [a for a in role_assumptions(events) if a["role_arn"]]
    parent, how = {}, {}
    for n, b in enumerate(steps):
        for m, a in enumerate(steps):
            if m != n and b["caller_key"] and a["issued_key"] and b["caller_key"] == a["issued_key"]:
                parent[n], how[n] = m, "access_key"
                break
        if n in parent:
            continue
        prior = [m for m, a in enumerate(steps[:n]) if b["caller_arn"] and a["assumed_arn"] and b["caller_arn"] == a["assumed_arn"]]
        if prior:
            parent[n], how[n] = prior[-1], "arn"
    kids = {}
    for n, m in parent.items():
        kids.setdefault(m, []).append(n)
    chains = []

    def walk(n, path):
        path = path + [n]
        if not kids.get(n):
            chains.append(path)
        for k in kids.get(n, []):
            if k not in path:
                walk(k, path)

    for n in range(len(steps)):
        if n not in parent:
            walk(n, [])
    out = []
    for path in chains:
        links = {how[n] for n in path[1:]}
        out.append({"origin": steps[path[0]]["caller_arn"], "roles": [steps[n]["role_arn"] for n in path],
                    "steps": [steps[n] for n in path], "linked_by": "+".join(sorted(links)) or None})
    return sorted(out, key=lambda c: -len(c["roles"]))


def suspicious_signins(events) -> list:
    """[(method, event)] for every heuristic that fires, in a fixed order of trust. Each method names
    ONE event: what that rule calls the first suspicious sign-in. They are candidates for an unsure
    answer, never a plain one:

      risky_signin            the first sign-in the provider itself flagged (Entra risk fields)
      success_after_failures  the first success from an IP that failed FAIL_MIN times or more before
      success_after_user_failures  the first success of an account right after FAIL_MIN failures of it
      impossible_travel       the later sign-in of the first impossible-travel pair
      minority_country        the first success of an account from a country that is not its usual one
      scripted_user_agent     the first success with a scripting or attack tool's user agent
      notable_action_ip       the first success from the IP that later made a mailbox rule, a consent
                              grant or an access key
      minority_ip             the first success of an account from an IP that is not its usual one"""
    sig = [e for e in signins(events) if e["time"] is not None]
    succ = [e for e in sig if e["result"] == "success"]
    out = []
    risky = [e for e in succ if e["risk"]] or [e for e in sig if e["risk"]]
    if risky:
        out.append(("risky_signin", risky[0]))
    fails_ip, fails_user, hit_ip, hit_user = Counter(), Counter(), None, None
    for e in sig:
        user = (e["actor"] or "").lower()
        if e["result"] == "failure":
            if e["ip"]:
                fails_ip[e["ip"]] += 1
            fails_user[user] += 1
        elif e["result"] == "success":
            if hit_ip is None and e["ip"] and fails_ip[e["ip"]] >= FAIL_MIN:
                hit_ip = e
            if hit_user is None and fails_user[user] >= FAIL_MIN:
                hit_user = e
            fails_user[user] = 0
    if hit_ip:
        out.append(("success_after_failures", hit_ip))
    if hit_user:
        out.append(("success_after_user_failures", hit_user))
    travel = impossible_travel(events)
    if travel:
        out.append(("impossible_travel", travel[0]["b"]))

    def minority(field, least):
        per = {}
        for e in succ:
            if e["actor"] and e[field]:
                per.setdefault(e["actor"].lower(), []).append(e)
        hits = []
        for evs in per.values():
            c = Counter(str(e[field]).lower() for e in evs)
            if len(evs) < least or len(c) < 2:
                continue
            top, n = c.most_common(1)[0]
            if n * 2 <= len(evs):
                continue
            hits.append(next(e for e in evs if str(e[field]).lower() != top))
        return _by_time(hits)[0] if hits else None

    m = minority("country", 3)
    if m:
        out.append(("minority_country", m))
    scripted = [e for e in succ if e["ua"] is not None and SCRIPTED_UA.search(e["ua"])]
    if scripted and len(scripted) < len(succ):
        out.append(("scripted_user_agent", scripted[0]))
    notable = _by_time([r["event"] for r in inbox_rules(events) if r["kind"] in ("create", "forwarding")]
                       + [c["event"] for c in consent_grants(events)] + [k["event"] for k in access_keys(events)])
    ips = {e["ip"] for e in notable if e["ip"]}
    if ips:
        hit = next((e for e in succ if e["ip"] in ips), None)
        others = {e["ip"] for e in succ if e["ip"]} - ips
        if hit and others:
            out.append(("notable_action_ip", hit))
    m = minority("ip", 4)
    if m:
        out.append(("minority_ip", m))
    return out


NOTABLE = {
    "cloudtrail": ("CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy", "PutUserPolicy",
                   "AttachRolePolicy", "PutRolePolicy", "CreatePolicyVersion", "UpdateAssumeRolePolicy", "AssumeRole", "StopLogging",
                   "DeleteTrail", "UpdateTrail", "PutBucketPolicy", "PutBucketAcl", "DeleteBucket", "GetSecretValue", "RunInstances",
                   "DeactivateMFADevice", "DeleteAccessKey", "ConsoleLogin", "GetCallerIdentity", "CreateFunction20150331",
                   "AuthorizeSecurityGroupIngress", "ModifySnapshotAttribute", "GetPasswordData", "PutEventSelectors"),
    "m365_ual": ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "Add-MailboxPermission", "Consent to application.",
                 "Add service principal.", "Add member to role.", "Update user.", "Reset user password.", "Change user password.",
                 "UserLoginFailed", "FileDownloaded", "FileSyncDownloadedFull", "MailItemsAccessed", "Send", "SendAs",
                 "New-TransportRule", "Set-AdminAuditLogConfig", "SearchCreated", "AnonymousLinkCreated", "Add user.",
                 "Disable Strong Authentication.", "Update StsRefreshTokenValidFrom Timestamp."),
    "entra_audit": ("Consent to application", "Add service principal", "Add member to role", "Add app role assignment to service principal",
                    "Add delegated permission grant", "Add user", "Reset password (by admin)", "Update application – Certificates and secrets management",
                    "User registered security info", "Admin registered security info", "Add owner to application", "Disable Strong Authentication",
                    "Register device",
                    "Add application", "Update conditional access policy", "Delete conditional access policy"),
    "okta": ("user.session.start", "user.account.privilege.grant", "system.api_token.create", "user.mfa.factor.deactivate",
             "user.mfa.factor.reset_all", "user.session.impersonation.initiate", "policy.rule.update", "user.account.update_password",
             "group.user_membership.add", "application.user_membership.add", "user.lifecycle.create", "security.threat.detected"),
    "gcp_audit": ("google.iam.admin.v1.CreateServiceAccountKey", "SetIamPolicy", "google.iam.admin.v1.CreateServiceAccount",
                  "storage.setIamPermissions", "v1.compute.instances.insert", "google.logging.v2.ConfigServiceV2.DeleteSink",
                  "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"),
    "azure_activity": ("Microsoft.Authorization/roleAssignments/write", "Microsoft.Compute/virtualMachines/runCommand/action",
                       "Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.KeyVault/vaults/secrets/read",
                       "Microsoft.Compute/virtualMachines/write", "Microsoft.Insights/diagnosticSettings/delete",
                       "Microsoft.Automation/automationAccounts/runbooks/write"),
}


def notable(events) -> list:
    """Events whose operation is one an investigation usually turns on (a fixed list per source;
    for Kubernetes: exec into a pod, reads of secrets, new role bindings, anonymous callers)."""
    want = {src: {o.lower().rstrip(".") for o in ops} for src, ops in NOTABLE.items()}
    out = []
    for e in _by_time(events):
        op = (e["op"] or "").lower().rstrip(".")
        if e["src"] == "k8s_audit":
            tgt = e["target"] or ""
            if "pods/exec" in tgt or "/secrets" in "/" + tgt or "rolebindings" in tgt or (e["actor"] or "").startswith("system:anonymous"):
                out.append(e)
        elif op in want.get(e["src"], ()) or (e["src"] == "gcp_audit" and op.endswith("setiampolicy")):
            out.append(e)
    return out


# ---- devices, device-code sign-ins and the per-IP pivot (B-066) ------------------------------------------
#
# The two rules below are the whole of what the pivot decides. Everything else it prints is a table.

ATTACKER_RULE = ("An IP is an attacker IP only when (a) it is named (--attacker-ip, pivot(named=...)), or (b) a SUCCESSFUL "
                 "sign-in from it carries the device-code flow marker (Entra authenticationProtocol = deviceCode, or "
                 "originalTransferMethod = deviceCodeFlow). No other heuristic names one: the suspicious sign-in "
                 "candidates of the triage stay candidates.")
DECOY_RULE = ("A registered device, an inbox rule or a file download is the attacker's only when (1) its own record's client "
              "IP is an attacker IP, or (devices) its Device Id signs in from one, and (2) it is not older than the first "
              "sign-in from that IP (its own IP when that is an attacker IP, else the Device Id's; when the Device Id signs "
              "in from several attacker IPs, the earliest first sign-in among them) that opened a session: a "
              "sign-in recorded as failed or interrupted does not count (a password spray before the device-code success "
              "moves nothing), one whose export states no result does. Anything else is rejected with the reason "
              "(other_ip, predates_first_signin, failed) or left unattributed (no_ip, no_time). With no attacker IP "
              "nothing is attributed (no_attacker_ip).")
# Sign-in results that open no session, so never start the attacker's time window (DECOY_RULE (2)).
NO_SESSION = ("failure", "interrupted")

DEVICE_OPS = {"register device": "register", "add device": "companion", "add registered owner to device": "companion",
              "add registered users to device": "companion"}
DOWNLOAD_OPS = ("filedownloaded", "filesyncdownloadedfull")
RULE_MAKES = ("create", "modify", "forwarding")
_DEVICE_CODE = (("authentication_protocol", ("authenticationProtocol", "Authentication Protocol"), "devicecode"),
                ("original_transfer_method", ("originalTransferMethod", "Original transfer method"), "devicecodeflow"))


def ip_key(v):
    """The one spelling of an IP address logs are joined on (port and brackets dropped, IPv6 compressed,
    an IPv4-mapped IPv6 address as its IPv4 one), or None for anything that is no address.

    web_evidence.ip_key is a second copy (the access-log side of the join, so the triage here never
    needs web_evidence.py): change both together. tests/test_toolkits_cloudlogs_pivot.py
    test_ip_key_is_one_spelling_per_address pins that they agree."""
    ip, _ = clean_ip(v)
    if ip is None:
        return None
    a = ipaddress.ip_address(ip)
    return str(getattr(a, "ipv4_mapped", None) or a)


def _unq(v):
    """A modified-property value without its JSON dress: '"NAME"' and '["NAME"]' are NAME."""
    if isinstance(v, str) and v.strip()[:1] in "\"[":
        try:
            v = json.loads(v)
        except ValueError:
            return _s(v.strip().strip('"'))
    if isinstance(v, list):
        v = v[0] if len(v) == 1 else None
    return _s(v)


def _targets(raw) -> list:
    """The target resources of an Entra audit record, [{type, name, id, upn, mods {lower name: new
    value}}]: Graph's targetResources list, or the portal CSV's Target<N>... columns."""
    out = []
    for t in _listed(raw.get("targetResources") or raw.get("TargetResources")):
        mods = {}
        for m in _listed(t.get("modifiedProperties")):
            n = _s(m.get("displayName", m.get("name")))
            if n:
                mods.setdefault(n.lower(), _unq(m.get("newValue")))
        out.append({"type": _s(t.get("type")), "name": _s(t.get("displayName")), "id": _s(t.get("id")),
                    "upn": _s(t.get("userPrincipalName")), "mods": mods})
    for n in sorted({int(m.group(1)) for m in (re.fullmatch(r"Target(\d+)Type", str(k)) for k in raw) if m}):
        p = f"Target{n}"
        if not any(_s(raw.get(p + s)) for s in ("Type", "DisplayName", "ObjectId", "UserPrincipalName")):
            continue
        mods = {}
        for k in raw:
            m = re.fullmatch(p + r"ModifiedProperty(\d+)Name", str(k))
            if m and _s(raw[k]):
                mods.setdefault(_s(raw[k]).lower(), _unq(raw.get(f"{p}ModifiedProperty{m.group(1)}NewValue")))
        out.append({"type": _s(raw.get(p + "Type")), "name": _s(raw.get(p + "DisplayName")), "id": _s(raw.get(p + "ObjectId")),
                    "upn": _s(raw.get(p + "UserPrincipalName")), "mods": mods})
    return out


def _details(raw) -> dict:
    """{lower key: value} of an Entra audit record's additional details: Graph's additionalDetails
    list of {key, value}, or the portal CSV's AdditionalDetail<N>Key / AdditionalDetail<N>Value columns."""
    out = {}
    for it in _listed(raw.get("additionalDetails") or raw.get("AdditionalDetails")):
        k = _s(it.get("key", it.get("Key")))
        if k:
            out.setdefault(k.lower(), _s(it.get("value", it.get("Value"))))
    for k in raw:
        m = re.fullmatch(r"AdditionalDetail(\d+)Key", str(k))
        if m and _s(raw[k]):
            out.setdefault(_s(raw[k]).lower(), _s(raw.get(f"AdditionalDetail{m.group(1)}Value")))
    return out


def registered_devices(events) -> list:
    """Devices registered or joined in Entra ID (audit log), oldest first, one per registration:
    {event, name, device_id, object_id, ip, time, actor, result, os, trust_type, profile, record,
    companions}. record is 'register' for a "Register device" row (the one that states the client IP
    and the Device Id) and 'companion' for a device named only by the directory's own rows ("Add
    device", "Add registered owner to device", "Add registered users to device"), which state no IP."""
    out, loose = [], []
    for e in _by_time(events):
        if e["src"] != "entra_audit":
            continue
        kind = DEVICE_OPS.get((e["op"] or "").lower().rstrip(". "))
        if kind is None:
            continue
        targets = _targets(e["raw"])
        dev = next((t for t in targets if (t["type"] or "").lower() == "device"), None)
        mods = {}
        for t in targets:
            for k, v in t["mods"].items():
                mods.setdefault(k, v)
        name = (dev["name"] if dev else None) or mods.get("device.displayname") or mods.get("displayname")
        object_id = mods.get("device.objectid") or (dev["id"] if dev else None)
        if kind == "register":
            det = _details(e["raw"])
            out.append({"event": e, "name": name, "device_id": det.get("device id"), "object_id": object_id, "ip": e["ip"],
                        "time": e["time"], "actor": e["actor"], "result": e["result"], "os": det.get("device os"),
                        "trust_type": det.get("device trust type"), "profile": det.get("device profile"),
                        "record": "register", "companions": 0})
        elif name:
            loose.append((e, name, object_id))
    registered, solo = list(out), {}
    for e, name, object_id in loose:
        same = [d for d in registered if d["name"] == name]
        if same:        # the directory's rows of a registration: folded into the nearest one of that name
            d = min(same, key=lambda d: abs((d["time"] - e["time"]).total_seconds()) if d["time"] and e["time"] else float("inf"))
        elif name in solo:
            d = solo[name]
        else:
            d = solo[name] = {"event": e, "name": name, "device_id": None, "object_id": None, "ip": None, "time": e["time"],
                              "actor": e["actor"], "result": e["result"], "os": None, "trust_type": None, "profile": None,
                              "record": "companion", "companions": 0}
            out.append(d)
        d["companions"] += 1
        d["object_id"] = d["object_id"] or object_id
    return sorted(out, key=lambda d: (d["time"] is None, d["time"] or datetime.min.replace(tzinfo=timezone.utc), d["event"]["i"]))


def device_code(e):
    """How an event's record shows the device-code flow (the Entra sign-in fields): 'authentication_protocol'
    (the sign-in itself was a device-code grant), 'original_transfer_method' (its session began with one),
    or None."""
    for how, names, want in _DEVICE_CODE:
        v = _s(_get(e["raw"], *names))
        if v and re.sub(r"[\s_-]", "", v).lower() == want:
            return how
    return None


def device_code_signins(events) -> list:
    """[(how, event)] of the sign-ins that carry the device-code flow marker, oldest first."""
    return [(how, e) for how, e in ((device_code(e), e) for e in signins(events)) if how]


def signin_device_id(e):
    """The Device Id a sign-in states (Graph deviceDetail.deviceId, the portal CSV's "Device ID"), or None."""
    return _s(_get(e["raw"], "deviceDetail.deviceId", "Device ID")) if e["signin"] else None


def downloads(events) -> list:
    """File downloads in the Unified Audit Log (FileDownloaded, FileSyncDownloadedFull), oldest first:
    {event, op, file, object (the full URL or path, the identity of the file), ip, time}."""
    out = []
    for e in _by_time(events):
        if e["src"] != "m365_ual" or (e["op"] or "").lower() not in DOWNLOAD_OPS:
            continue
        raw = e["raw"]
        obj = _s(raw.get("ObjectId")) or "".join(_s(raw.get(k)) or "" for k in ("SiteUrl", "SourceRelativeUrl")) or None
        name = _s(raw.get("SourceFileName")) or (obj.rstrip("/").rsplit("/", 1)[-1] if obj else None)
        out.append({"event": e, "op": e["op"], "file": name, "object": obj or name, "ip": e["ip"], "time": e["time"]})
    return out


def _iso(t):
    return t.strftime("%Y-%m-%d %H:%M:%SZ") if t else None


def _judge(a, attackers, first) -> tuple:
    """(verdict, why, detail) of one artifact under DECOY_RULE."""
    if not attackers:
        return "undecided", "no_attacker_ip", "no attacker IP is known, so nothing is attributed"
    if a["failed"]:
        return "rejected", "failed", "the record says the operation failed"
    via = ([("ip", a["ip"])] if a["ip"] in attackers else []) + [("device_id", k) for k in a.get("id_ips", ()) if k in attackers]
    if not via:
        if a["ip"] is None and not a.get("id_ips"):
            return "unattributed", "no_ip", "the record states no client IP"
        seen = a["ip"] or ", ".join(a["id_ips"])
        return "rejected", "other_ip", f"made from {seen}, which is not an attacker IP"
    own = [k for how, k in via if how == "ip"] or [k for _, k in via]
    timed = [k for k in own if first.get(k)]
    how = "+".join(dict.fromkeys(h for h, _ in via))
    if not timed:
        return "attributed", how, f"from attacker IP {own[0]}; no sign-in from it in the logs, so the time check was not applied"
    if a["time"] is None:
        return "unattributed", "no_time", "the record has no readable time to compare with the attacker's first sign-in"
    # a Device Id seen from several attacker IPs: the window opens at the earliest of their first sign-ins
    # (DECOY_RULE), and the detail names the IP that sign-in came from
    k0 = min(timed, key=lambda k: (first[k], k))
    start = first[k0]
    if a["time"] < start:
        return "rejected", "predates_first_signin", (f"at {_iso(a['time'])}, before the first sign-in from {k0} "
                                                     f"({_iso(start)})")
    return "attributed", how, f"from attacker IP {k0}, not before its first sign-in ({_iso(start)})"


def pivot(events, named=(), access=None) -> dict:
    """The per-IP pivot: every client IP of the cloud events with its sign-ins, registered devices,
    inbox rules, downloads and (access = web_evidence.ip_activity(...)) its requests in the access
    logs; which IPs are the attacker's under ATTACKER_RULE; and every device, rule and download judged
    under DECOY_RULE. Returns {attackers {ip: {why, first_signin, device_code_signins}}, ips [row],
    artifacts [{kind, name, ip, time, verdict, why, detail, event, ...}], access_only, notes}.
    ValueError for a named attacker that is not an IP address."""
    notes = []
    sig = signins(events)
    first, dev_ips = {}, {}
    for e in sig:
        k = ip_key(e["ip"])
        if k and e["time"] is not None and e["result"] not in NO_SESSION:
            first.setdefault(k, e["time"])
        d = signin_device_id(e)
        if k and d:
            dev_ips.setdefault(d.lower(), set()).add(k)
    dc, dc_ok = Counter(), Counter()
    for _how, e in device_code_signins(events):
        k = ip_key(e["ip"])
        if k:
            dc[k] += 1
            dc_ok[k] += e["result"] == "success"
    why = {}
    for n in named:
        k = ip_key(n)
        if k is None:
            raise ValueError(f"attacker IP {n!r} is not an IP address")
        why[k] = ["named"]
    for k in sorted(k for k, n in dc_ok.items() if n):
        why.setdefault(k, []).append("device_code")
    failed_only = sorted(k for k in dc if not dc_ok[k] and k not in why)
    if failed_only:
        notes.append("device-code sign-ins from " + ", ".join(failed_only) + " never succeeded: they name no attacker IP")
    attackers = {k: {"why": w, "first_signin": first.get(k), "device_code_signins": dc.get(k, 0)} for k, w in why.items()}
    if not attackers:
        notes.append("no attacker IP: no successful device-code sign-in in the logs and none named (--attacker-ip)")

    arts = []
    for d in registered_devices(events):
        arts.append({"kind": "device", "name": d["name"], "ip": ip_key(d["ip"]), "time": d["time"], "failed": d["result"] == "failure",
                     "device_id": d["device_id"], "id_ips": sorted(dev_ips.get((d["device_id"] or "").lower(), ())),
                     "actor": d["actor"], "record": d["record"], "event": d["event"]})
    for r in inbox_rules(events):
        if r["kind"] in RULE_MAKES:
            e = r["event"]
            arts.append({"kind": "rule", "name": r["name"], "ip": ip_key(e["ip"]), "time": e["time"], "failed": e["result"] == "failure",
                         "rule_kind": r["kind"], "forward_to": r["forward_to"], "move_to": r["move_to"], "mailbox": r["mailbox"],
                         "event": e})
    for d in downloads(events):
        e = d["event"]
        arts.append({"kind": "download", "name": d["file"], "object": d["object"], "ip": ip_key(d["ip"]), "time": d["time"],
                     "failed": e["result"] == "failure", "op": d["op"], "event": e})
    for a in arts:
        a["verdict"], a["why"], a["detail"] = _judge(a, attackers, first)

    rows = {}

    def row(k):
        return rows.setdefault(k, {"ip": k, "attacker": list(why.get(k, ())), "events": 0, "ops": Counter(), "signins": Counter(),
                                   "first_signin": None, "last_signin": None, "device_code_signins": dc.get(k, 0),
                                   "accounts": Counter(), "devices": [], "rules": [], "downloads": 0, "access": None})

    for k in attackers:
        row(k)
    for e in events:
        k = ip_key(e["ip"])
        if k is None:
            continue
        r = row(k)
        r["events"] += 1
        r["ops"][e["op"] or ("sign-in" if e["signin"] else "-")] += 1
        if e["signin"]:
            r["signins"][e["result"] or "unstated"] += 1
            if e["actor"]:
                r["accounts"][e["actor"].lower()] += 1
            if e["time"] is not None:
                r["first_signin"] = min(r["first_signin"] or e["time"], e["time"])
                r["last_signin"] = max(r["last_signin"] or e["time"], e["time"])
    for a in arts:
        joined = [x for x in a.get("id_ips", ()) if x in attackers] if a["verdict"] == "attributed" else []
        for k in dict.fromkeys(([a["ip"]] if a["ip"] else []) + joined):
            if k not in rows:
                continue
            if a["kind"] == "download":
                rows[k]["downloads"] += 1
            else:
                rows[k]["devices" if a["kind"] == "device" else "rules"].append(a)
    access_only = None
    if access is not None:
        for k, r in rows.items():
            r["access"] = access.get(k)
        access_only = sum(1 for k in access if k not in rows)
        for k in attackers:
            if k not in access:
                notes.append(f"attacker IP {k}: no request in the access logs")
    for k in attackers:
        if not rows[k]["events"]:
            notes.append(f"attacker IP {k} appears in no cloud event")
    ordered = sorted(rows.values(), key=lambda r: (not r["attacker"], -r["events"], r["ip"]))
    return {"attackers": attackers, "ips": ordered, "artifacts": arts, "access_only": access_only, "notes": notes}


# A flag template is filled only from named slots, each read from the attributed artifacts and each with
# exactly one value. The names are the ones a brief uses; a bare <count> or <name> says too little and is
# left unfilled.
TEMPLATE_FIELDS = {
    "device": ("device", "device_name", "devicename", "device_display_name", "registered_device", "attacker_device"),
    "rule": ("rule", "rule_name", "rulename", "inbox_rule", "inbox_rule_name", "mailbox_rule", "forwarding_rule"),
    "downloads": ("download_count", "downloads", "downloaded", "files_downloaded", "downloaded_files", "number_of_downloads",
                  "file_count"),
    "ip": ("ip", "attacker_ip", "ip_address", "source_ip"),
    "forward_to": ("forward_to", "forwarding_address", "forward_address"),
    "device_id": ("device_id", "deviceid"),
}
_SLOT_FIELD = {name: field for field, names in TEMPLATE_FIELDS.items() for name in names}
_TEMPLATE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{0,23}\{[^{}\r\n]*<[^<>{}\r\n]{1,48}>[^{}\r\n]*\}")
_SLOT = re.compile(r"<([^<>{}\r\n]{1,48})>")


def find_templates(text) -> list:
    """The distinct flag templates of a brief (PREFIX{...<slot>...}), in the order they appear. HTML
    entities are read as their characters (a platform may send &lt;slot&gt;)."""
    import html
    return list(dict.fromkeys(m.group(0) for m in _TEMPLATE.finditer(html.unescape(str(text or "")))))


def template_values(pv) -> dict:
    """{field: [candidate values]} of TEMPLATE_FIELDS over the ATTRIBUTED artifacts of a pivot. A field
    is usable only with exactly one value; a download count is two values when the download events and
    the distinct files differ, and none (never 0) when no download is attributed."""
    mine = [a for a in pv["artifacts"] if a["verdict"] == "attributed"]
    devices = [a for a in mine if a["kind"] == "device"]
    rules = [a for a in mine if a["kind"] == "rule"]
    dl = [a for a in mine if a["kind"] == "download"]

    def distinct(values):
        return list(dict.fromkeys(str(v) for v in values if v not in (None, "")))

    counts = distinct([len(dl), len({a["object"] for a in dl})]) if dl else []
    return {"device": distinct(a["name"] for a in devices), "rule": distinct(a["name"] for a in rules), "downloads": counts,
            "ip": list(pv["attackers"]), "forward_to": distinct(x for a in rules for x in a["forward_to"]),
            "device_id": distinct(a["device_id"] for a in devices)}


def fill_template(template, pv, whole: bool = True) -> dict:
    """{slots [{slot, field, values}], flag, why}: the template with every <slot> replaced, or flag
    None and why (one reason per obstacle): the log is not whole, no attacker IP, a slot whose name is
    not in TEMPLATE_FIELDS, a slot with no value or with several."""
    values = template_values(pv)
    slots, why = [], []
    if not whole:
        why.append("a log did not parse whole, so nothing is answered from it")
    if not pv["attackers"]:
        why.append("no attacker IP, so no artifact is attributed")
    for raw in dict.fromkeys(_SLOT.findall(template)):
        field = _SLOT_FIELD.get(re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_"))
        got = values.get(field, []) if field else []
        slots.append({"slot": raw, "field": field, "values": got})
        if field is None:
            why.append(f"<{raw}>: not a slot name this file fills (TEMPLATE_FIELDS)")
        elif not got:
            why.append(f"<{raw}>: no attributed {field} value")
        elif len(got) > 1:
            why.append(f"<{raw}>: {len(got)} values ({', '.join(got)}); which one is not judged")
    if not slots:
        why.append("the template has no <slot>")
    flag = None
    if not why:
        one = {s["slot"]: s["values"][0] for s in slots}
        flag = _SLOT.sub(lambda m: one[m.group(1)], template)
    return {"slots": slots, "flag": flag, "why": why}


# ---- signals -----------------------------------------------------------------------------------------

_MARKS = {
    "cloudtrail": (b'"eventSource"', b'"eventName"', b'"userIdentity"', b'"awsRegion"', b'"sourceIPAddress"'),
    "m365_ual": (b'"Operation"', b'"Workload"', b'"RecordType"', b'"CreationTime"', b'"UserId"', b"AuditData", b"Operations",
                 b"CreationDate", b"UserIds"),
    "entra_signin": (b"userPrincipalName", b"appDisplayName", b"createdDateTime", b"ipAddress", b"SignInLogs", b"conditionalAccessStatus",
                     b"Sign-in error code", b"IP address", b"Username", b"Date (UTC)"),
    "entra_audit": (b"activityDisplayName", b"initiatedBy", b"targetResources", b"activityDateTime", b"AuditLogs"),
    "azure_activity": (b'"operationName"', b'"resourceId"', b'"callerIpAddress"', b'"caller"', b'"subscriptionId"'),
    "gcp_audit": (b'"protoPayload"', b'"methodName"', b"cloudaudit.googleapis.com", b'"authenticationInfo"'),
    "okta": (b'"eventType"', b'"published"', b'"outcome"', b'"actor"', b'"rawUserAgent"', b'"displayMessage"'),
    "k8s_audit": (b"audit.k8s.io", b'"auditID"', b'"requestURI"', b'"objectRef"', b'"sourceIPs"'),
}
# Column names (lower case) of a CSV export whose header spells the fields differently from the JSON
# one: the Entra portal's flat audit-log download.
_CSV_MARKS = {"entra_audit": (b"activity", b"actortype", b"actoruserprincipalname", b"target1type", b"target1displayname")}
_Q_WORDS = re.compile(r"sign[\s-]?ins?\b|audit log|unified audit|inbox rule|mailbox rule|cloudtrail|\btenant\b|oauth|\bconsent|"
                      r"\bentra\b|azure ad\b|\bokta\b|kubernetes|\bk8s\b|\biam\b|access key|assume[d]?[\s-]?role|impossible travel|"
                      r"microsoft 365|\bm365\b|office 365|\bo365\b|service principal|user agent|\bgcp\b|activity log|mailbox", re.I)


def _sniff(data: bytes):
    """The source whose field names the head of a file carries (three of them at least), or None."""
    head = bytes(data[:SNIFF])
    if head[:2] == b"\x1f\x8b":
        try:
            head = gzip.GzipFile(fileobj=io.BytesIO(bytes(data[:SNIFF * 4]))).read(SNIFF)
        except (OSError, EOFError, ValueError):
            return None
    if head[:2] in (b"\xff\xfe", b"\xfe\xff") or (head[1:2] == b"\x00" and head[3:4] == b"\x00"):
        head = head.decode("utf-16", "replace").encode("utf-8", "replace")
    if head[:3] == b"\xef\xbb\xbf":
        head = head[3:]
    start = head.lstrip()[:1]
    if b"\x00" in head[:1024] or not start:
        return None
    if start not in b"[{":
        # CSV: the field names are the header line's columns, whatever their case
        cols = {c.strip().strip(b'"').lower() for c in re.split(rb"[,;\t|]", head.lstrip().split(b"\n", 1)[0])}
        if len(cols) < 3:
            return None
        hits = {s: max(sum(1 for m in _MARKS[s] if m.strip(b'"').lower() in cols), sum(1 for m in _CSV_MARKS.get(s, ()) if m in cols))
                for s in _MARKS}
    else:
        hits = {s: sum(1 for m in _MARKS[s] if m in head) for s in _MARKS}
    best = max(hits, key=hits.get)
    if hits[best] >= 3:
        return best
    if b'"CloudTrailEvent"' in head and b'"EventName"' in head and b'\\"eventSource\\"' in head:
        return "cloudtrail"             # rows of `aws cloudtrail lookup-events`: the record is a JSON string
    if sum(1 for m in (b'"operation_name"', b'"event_timestamp"', b'"resource_id"', b'"subscription_id"', b'"caller"') if m in head) >= 3:
        return "azure_activity"         # the Azure CLI / SDK spelling
    return None


def signals(questions, files) -> float:
    """0..1: how strongly the delivery and its questions look like cloud or identity logs. A file
    whose head carries a known source's field names gives 0.7; the share of questions that speak
    of sign-ins, audit logs, mailbox rules, consents, IAM and the like gives up to 0.3 (the
    questions alone, with no such file: at most 0.3)."""
    score = 0.0
    seen = set()
    for n, (name, data) in enumerate((files or {}).items()):
        if n >= MAX_FILES or not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        if _sniff(data):
            score = 0.7
            break
    qs = list(questions or [])
    if qs:
        hits = sum(1 for q in qs if _Q_WORDS.search(" ".join(str(q.get(k) or "") for k in ("question", "id", "answer_id"))))
        score += 0.3 * hits / len(qs)
    return round(min(1.0, score), 3)


# ---- reading a question --------------------------------------------------------------------------------

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_ARN = re.compile(r"arn:aws[\w-]*:[\w-]*:[\w-]*:\d*:[\w+=,.@\-/:]+")

_CLASS = (
    ("travel", re.compile(r"impossible[\s-]travel", re.I)),
    ("rule", re.compile(r"\binbox[\s-]rules?\b|\bmailbox[\s-]rules?\b|\bmail[\s-]rules?\b|\bforwarding[\s-]rules?\b|\brules?\b", re.I)),
    ("consent", re.compile(r"\bconsent\w*|\boauth\b", re.I)),
    ("key", re.compile(r"\baccess[\s-]keys?\b", re.I)),
    ("assume", re.compile(r"\bassum\w*\b|\brole[\s-]chain\w*\b|\brole[\s-]assumptions?\b|\bchain(?:ed|ing)?\b", re.I)),
)
_SUSPICIOUS = re.compile(r"\bsuspicious\b|\bmalicious\b|\battacker(?:'s)?\b|\bthreat[\s-]actor(?:'s)?\b|\badversary(?:'s)?\b|\banomalous\b|"
                         r"\bunauthori[sz]ed\b|\bcompromis\w*\b|\bunusual\b|\bintruder(?:'s)?\b|\brogue\b|\billegitimate\b", re.I)
_SIGNIN = re.compile(r"\bsign(?:ed|s|ing)?[\s-]?ins?\b|\blog(?:ged|s|ging)?[\s-]?(?:ins?|ons?)\b|\blogins?\b|\blogons?\b|\bauthenticat\w*\b", re.I)
_FAILED = re.compile(r"\bfail(?:ed|ure|ures|s)?\b|\bunsuccessful\b", re.I)
_SUCCESS = re.compile(r"\bsuccess(?:ful|fully|es)?\b|\bsucceed(?:ed|s)?\b", re.I)
_FIRST = re.compile(r"\bfirst\b|\bearliest\b|\binitial\b", re.I)
_LAST = re.compile(r"\blast\b|\blatest\b|\bmost recent\b|\bfinal\b", re.I)
_MOST = re.compile(r"\b(?:the )?most\b(?! recent)|\bhighest number\b|\blargest number\b", re.I)
_DISTINCT = re.compile(r"\bunique\b|\bdistinct\b|\bdifferent\b", re.I)
_COUNT = re.compile(r"\bhow many\b|\bnumber of\b|\bcount of\b|\btotal count\b", re.I)
_TOTAL = re.compile(r"\b(?:events?|records?|entries|log entries|lines)\b", re.I)

_F_UA = re.compile(r"\buser[\s_-]?agents?\b", re.I)
_F_IP = re.compile(r"\bip(?:v4|v6)?\b|\bsource address\b", re.I)
_F_TIME = re.compile(r"\bwhen\b|\bwhat time\b|\btimestamp\b|\bdate and time\b|\btime of\b|\bat what time\b|\bwhat date\b", re.I)
_F_USER = re.compile(r"\bwho\b|\b(?:which|what) (?:\w+ )?(?:user|account|identity|principal|mailbox)\b|\busername\b|\buser name\b|\bupn\b|"
                     r"\buser principal name\b", re.I)
_F_OP = re.compile(r"\b(?:which|what) (?:\w+ ){0,3}(?:operation|api call|event name|action|activity)\b|\bname of the (?:operation|api call|event)\b", re.I)
_F_FWD = re.compile(r"\bforward\w*\b|\bredirect\w*\b", re.I)
_F_FOLDER = re.compile(r"\bfolder\b", re.I)
_F_WORDS = re.compile(r"\bkeywords?\b|\bwords?\b|\bsubject\b", re.I)
_F_SCOPE = re.compile(r"\bscopes?\b|\bpermissions?\b", re.I)
_F_APPID = re.compile(r"\b(?:app(?:lication)?|client)[\s_-]?id\b", re.I)
_F_CHAIN = re.compile(r"\bchain\w*\b|\bsequence\b|\bin order\b", re.I)

# Every word a question may hold besides the literals it names. A word outside it means the question
# says something this file does not model, and the answer is None.
VOCAB = set("""
a an the of in on at to from for by with as into via through and or it its this that these those their his her they them
is are was were be been being did do does has have had what which who whom whose when where how many much
please determine identify find give provide state name names named called list exact exactly full complete value values
log logs logged logging audit unified activity sign signed signing ins ons attempt attempts countries cities signin signins login logins logon logons authenticated authentication authenticate
session sessions event events record records recorded entry entries export exported evidence file dataset delivered set
ip ipv4 ipv6 address addresses source client user users agent agents string account accounts identity principal upn username
mailbox email mail inbox rule rules forwarding forward forwards forwarded forwarding redirect redirected redirects messages message emails
folder moved move moves keyword keywords word words subject contain contains containing filter filters match matches
created create creates creation new added add set make made making configured issued
attacker attackers threat actor adversary malicious suspicious compromised compromise anomalous unauthorized unauthorised unusual intruder rogue illegitimate
consent consented consents oauth application applications app apps grant granted grants permission permissions scope scopes delegated
access key keys id identifier iam aws role roles assume assumed assumes assumption assumptions chain chained chaining sequence order arn arns
cloudtrail azure entra microsoft 365 m365 office o365 tenant okta gcp google cloud kubernetes k8s cluster ad
first earliest initial last latest most recent final failed fail failure failures unsuccessful successful successfully success succeeded
times time timestamp date utc country city impossible travel number count total unique distinct different highest largest
operation operations action actions api call calls performed perform generated generate observed seen shown show shows appear appears
occurred occur happen happened originated originate come came used use uses using take took place there here
were's s
""".split())
_QUALIFIER = re.compile(r"\b(?:between|before|after|within|outside|except|excluding|not|non|never|without|other than|per|each|average|"
                        r"hour|hours|day|days|minute|minutes|second|seconds|week|least|fewest|second|third|fourth)\b", re.I)


_ACTOR_CLASS = re.compile(r"\b(?:by|from|as|did|do|does) (?:(?:all|any|the|an?|this|that|other|new|iam|aws|assumed|federated|root|service|human|"
                          r"console|guest|external|internal|admin|privileged) )*(?:users?|roles?|accounts?|identit(?:y|ies)|principals?|"
                          r"services?|keys?|service accounts?|root|applications?|apps?)\b", re.I)
_COUNT_SKIP = set("unique distinct different failed successful unsuccessful suspicious malicious total new inbox mailbox mail forwarding "
                  "access ip api log audit oauth consent role sign in on aws iam source client of the".split())
_COUNT_NOUN = {"events": "events", "event": "events", "records": "events", "record": "events", "entries": "events", "entry": "events",
               "times": "events", "calls": "events", "call": "events", "ins": "events", "signins": "events", "logins": "events",
               "logons": "events", "attempts": "events", "rules": "rule", "rule": "rule", "keys": "key", "key": "key", "consents": "consent", "grants": "consent",
               "assumptions": "assume", "addresses": "ip", "address": "ip", "users": "actor", "accounts": "actor", "agents": "ua",
               "countries": "country", "cities": "city", "applications": "app", "apps": "app", "roles": "role"}


def _count_noun(low: str):
    """What a count counts: 'events', a class (rule, key, consent, assume), or the field whose
    distinct values are counted (ip, actor, ua, country, city, app, role). None: not modelled."""
    m = _COUNT.search(low)
    words = re.findall(r"[a-z0-9]+", low[m.end():])
    for n, w in enumerate(words[:6]):
        if w == "user" and words[n + 1:n + 2] in (["agents"], ["agent"]):
            continue
        if w in _COUNT_NOUN:
            if _COUNT_NOUN[w] == "events" and {"iam", "oauth", "consent", "role", "ip", "source", "client", "mailbox", "mail", "inbox",
                                               "forwarding", "new", "user", "access"} & set(words[:n]):
                return None             # "IAM events", "mailbox events": a service or a kind of event nothing here selects (2900 for 398)
            return _COUNT_NOUN[w]
        if w not in _COUNT_SKIP and w != "user":
            return None
    return None


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _fits(q, value) -> bool:
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, str(value)) is not None
        except re.error:
            return False
    return True


def _enum(q) -> list:
    f = _fmt(q)
    for key in ("options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            return [str(v) for v in f[key]]
    return []


def _ops_named(text: str, events) -> list:
    """Operations of the log that the question names in so many words. Only a distinctive name counts
    (CreateAccessKey, New-InboxRule, user.session.start, 'Consent to application'): a single lowercase
    word (the Kubernetes verbs get, list, create) is an English word, not a name."""
    out = []
    for op in {e["op"] for e in events if e["op"]}:
        bare = op.rstrip(". ")
        if len(bare) < 4 or re.fullmatch(r"[a-z]+", bare):
            continue
        if re.search(r"(?<![\w.\-/])" + re.escape(bare) + r"(?![\w\-/])", text, re.I if " " in bare else 0):
            out.append(op)
    # A name inside a longer name that is named too ("AssumeRole" in "AssumeRoleWithSAML") is not named.
    return [o for o in out if not any(o != p and o.rstrip(". ") in p for p in out)]


def read_question(q, events) -> dict:
    """What a question asks, or {'field': None, 'why': ...}. See the module text for the rules."""
    text = " ".join(str(q.get("question") or "").split())
    it = {"field": None, "cls": None, "ops": [], "actors": [], "ips": [], "result": None, "ordinal": None, "most": False,
          "suspicious": False, "signin": False, "distinct": None, "why": "", "text": text}
    if not text:
        it["why"] = "no question text"
        return it
    rest = text
    for arn in _ARN.findall(rest):
        it["actors"].append(arn)
        rest = rest.replace(arn, " ")
    for mail in _EMAIL.findall(rest):
        it["actors"].append(mail.rstrip("."))
        rest = rest.replace(mail, " ")
    for ip in _IPV4.findall(rest):
        it["ips"].append(ip)
        rest = rest.replace(ip, " ")
    it["ops"] = _ops_named(rest, events)
    for op in sorted(it["ops"], key=len, reverse=True):
        rest = re.sub(re.escape(op.rstrip(". ")), " ", rest, flags=re.I)
    it["targets"] = []
    named = {}
    for e in events:
        for v in (e["actor_alt"].get("user_name"), e["actor"] if e["src"] != "cloudtrail" else None):
            if v:
                named.setdefault(str(v).lower(), "actor")
    for e in events:
        if e.get("target"):
            named.setdefault(str(e["target"]).lower(), "target")
    for tok in set(re.findall(r"(?<![\w@.\-/:])[A-Za-z0-9][\w.\-]*[\-_.\d][\w.\-]*(?![\w@\-/])", rest)):
        tok = tok.rstrip(".")
        role = named.get(tok.lower())
        if role is None or _IPV4.fullmatch(tok):
            continue
        it["actors" if role == "actor" else "targets"].append(tok)
        rest = re.sub(r"(?<![\w@.\-/:])" + re.escape(tok) + r"(?![\w@\-/])", " ", rest)
    it["rule_names"], it["fwd_targets"] = [], []
    if _CLASS[1][1].search(rest):
        rules = _cached(inbox_rules, events)
        targets = {re.sub(r"^smtp:", "", str(a), flags=re.I).lower() for r in rules for a in (r.get("forward_to") or [])}
        acting = {(e["actor"] or "").lower() for e in events}
        for a in list(it["actors"]):
            if a.lower() in targets and a.lower() not in acting:
                it["actors"].remove(a)          # the address a rule forwards to, not the one who made it
                it["fwd_targets"].append(a.lower())
        for nm in sorted({str(r["name"]).strip() for r in rules if r.get("name")}, key=len, reverse=True):
            if len(nm) < 3:
                continue
            quoted = re.search(r"[\"'“‘`]" + re.escape(nm) + r"[\"'”’`]", rest, re.I)
            plain_words = all(w in VOCAB for w in re.findall(r"[a-z0-9]+", nm.lower()))
            if quoted or (not plain_words and re.search(r"(?<![\w@.])" + re.escape(nm) + r"(?![\w@])", rest, re.I)):
                it["rule_names"].append(nm.lower())
                rest = re.sub(r"[\"'“‘`]?" + re.escape(nm) + r"[\"'”’`]?", " ", rest, flags=re.I)
    art = str(q.get("artifact") or "")
    for name in [p.strip() for p in art.split("->") if p.strip()]:
        rest = rest.replace(name, " ").replace(Path(name).name, " ")
    low = rest.lower()
    if _QUALIFIER.search(low):
        it["why"] = "a qualifier this file does not model: " + _QUALIFIER.search(low).group()
        return it
    words = [w for w in re.findall(r"[a-z0-9]+", low.replace("'s", " ")) if w not in VOCAB]
    if words:
        it["why"] = "words outside the vocabulary: " + ", ".join(sorted(set(words))[:6])
        return it
    for cls, rx in _CLASS:
        if rx.search(low):
            it["cls"] = cls
            break
    it["suspicious"] = bool(_SUSPICIOUS.search(low))
    it["signin"] = bool(_SIGNIN.search(low))
    failed, ok = bool(_FAILED.search(low)), bool(_SUCCESS.search(low))
    it["result"] = "failure" if failed and not ok else "success" if ok and not failed else None
    if failed and ok:
        it["why"] = "both failed and successful"
        return it
    first, last = bool(_FIRST.search(low)), bool(_LAST.search(low))
    if first and last:
        it["why"] = "both first and last"
        return it
    it["ordinal"] = "first" if first else "last" if last else None
    it["most"] = bool(_MOST.search(low))
    kind = str(_fmt(q).get("kind") or "")
    cls = it["cls"]
    asks_user = bool(_F_USER.search(low))
    if _COUNT.search(low):
        field = "count"
        noun = _count_noun(low)
        if noun is None or (noun == "events" and _DISTINCT.search(low)) or (noun in ("rule", "consent", "key", "assume") and noun != cls):
            it["why"] = "a count of something this file does not model"
            return it
        if noun not in ("events", "rule", "consent", "key", "assume"):
            it["distinct"] = noun
    elif _F_UA.search(low):
        field = "ua"
    elif cls == "rule" and _F_FWD.search(low) and not asks_user and not _F_IP.search(low) and not it["fwd_targets"] \
            and not re.search(r"\bnames? of\b|\b(?:which|what) (?:\w+ )?rule\b|\brule(?:'s)? name\b", low):
        field = "rule_forward"
    elif cls == "rule" and _F_FOLDER.search(low):
        field = "rule_folder"
    elif cls == "rule" and _F_WORDS.search(low):
        field = "rule_keywords"
    elif cls == "consent" and _F_SCOPE.search(low):
        field = "scopes"
    elif cls == "consent" and _F_APPID.search(low):
        field = "app_id"
    elif _F_IP.search(low):
        field = "ip"
    elif cls == "assume" and _F_CHAIN.search(low):
        field = "role_chain"
    elif _F_TIME.search(low):
        field = "time"
    elif re.search(r"\bcountry\b", low):
        field = "country"
    elif re.search(r"\bcity\b", low):
        field = "city"
    elif asks_user:
        field = "user"
    elif _F_OP.search(low):
        field = "op"
    elif cls == "rule" and re.search(r"\bnames?\b|\bnamed\b|\bcalled\b|\b(?:which|what) (?:\w+ )?rule\b", low):
        field = "rule_name"
    elif cls == "consent" and re.search(r"\bapp(?:lication)?s?\b", low):
        field = "app"
    elif cls == "key" and re.search(r"\bkeys?\b", low):
        field = "access_key"
    elif cls == "assume" and re.search(r"\broles?\b", low):
        field = "role"
    else:
        it["why"] = "no field this file answers is asked for"
        return it
    if kind == "mitre_attack_id":
        it["why"] = "an ATT&CK id is not read from a log"
        return it
    if field == "count" and not it["actors"] and _ACTOR_CLASS.search(low):
        it["why"] = "a count over a class of actors the question does not name (IAM users, assumed roles, the user)"
        return it
    if kind == "integer" and field != "count":
        it["why"] = "an integer is asked for, and the question is not a count"
        return it
    it["field"] = field
    it["wants_mailbox"] = bool(re.search(r"\b(?:which|what|whose) (?:[\w']+ )?mailbox\b", low))
    it["made"] = bool(re.search(r"\bcreat\w*|\bgenerat\w*|\bnew\b|\badded\b|\bmade\b|\bissued\b", low))
    it["wants_arn"] = bool(re.search(r"\barns?\b", low))
    it["wants_name"] = bool(re.search(r"\bnames?\b|\busername\b", low))
    it["for_user"] = bool(re.search(r"\bfor (?:which|what) (?:\w+ )?(?:user|account)\b|\b(?:created|made) for\b", low))
    it["verb"] = "remove" if re.search(r"\bdelet\w*|\bremov\w*", low) else "modify" if re.search(r"\bmodif\w*|\bchang\w*|\bupdat\w*", low) else None
    return it


# ---- answering -----------------------------------------------------------------------------------------

def pick(key: str, options):
    """labels.pick for a `cloudlogs.` key. While labels.py does not list the lane, the unsure wire
    form itself: the answer is never sent and reads as unsure everywhere."""
    opts, seen = [], set()
    for name, value in options:
        if value is None or name in seen:
            continue
        seen.add(name)
        opts.append((name, value))
    if not opts:
        return None
    opts = opts[:MAX_OPTIONS]
    if labels is not None:
        try:
            return labels.pick(key, opts)
        except ValueError:
            pass
    return UNSURE + json.dumps({"k": key.lower(), "o": [[n, v] for n, v in opts]}, separators=(",", ":"))


def time_formats(e) -> list:
    """[(format name, text)] of an event's time, the log's own text first."""
    out = [("as_logged", e["time_raw"])]
    t = e["time"]
    if t is not None and e["tq"] == "ok":      # a month/day/year time is only offered as logged
        out += [("iso_z_seconds", t.strftime("%Y-%m-%dT%H:%M:%SZ")), ("space_seconds", t.strftime("%Y-%m-%d %H:%M:%S")),
                ("iso_seconds", t.strftime("%Y-%m-%dT%H:%M:%S")), ("space_seconds_utc", t.strftime("%Y-%m-%d %H:%M:%S UTC")),
                ("iso_offset", t.strftime("%Y-%m-%dT%H:%M:%S+00:00")), ("date", t.strftime("%Y-%m-%d")),
                ("epoch", str(int(t.timestamp())))]
    seen, uniq = set(), []
    for n, v in out:
        if v is not None and v not in seen:
            seen.add(v)
            uniq.append((n, v))
    return uniq


def _joins(items, prefix="") -> list:
    items = [str(x) for x in items]
    out = [(prefix + "comma", ",".join(items)), (prefix + "comma_space", ", ".join(items)), (prefix + "space", " ".join(items)),
           (prefix + "arrow", " -> ".join(items)), (prefix + "json", json.dumps(items, separators=(",", ":")))]
    if sorted(items) != items:
        out += [(prefix + "sorted_comma", ",".join(sorted(items))), (prefix + "sorted_space", " ".join(sorted(items)))]
    return out


def _formats(field, item, it) -> list:
    """[(format name, value)] of `field` for one selected item; one entry means one spelling. An item
    is an event, or a helper's row that holds one under 'event'."""
    e = item["event"] if "event" in item else item
    if field == "ip":
        if e["ip"] is None:
            return []
        return [("address", e["ip"])] + ([("as_logged", e["ip_raw"])] if e["ip_raw"] != e["ip"] else [])
    if field == "ua":
        return [("as_logged", e["ua"])] if e["ua"] else []
    if field == "time":
        return time_formats(e) if e["time_raw"] else []
    if field == "user":
        if it.get("for_user") and "for_user" in item:
            return [("for_user", item["for_user"])] if item["for_user"] else []
        if "mailbox" in item:       # a mailbox rule: who made it and whose mailbox it is can differ
            mb, actor = item["mailbox"], e["actor"]
            if it.get("wants_mailbox"):
                if not mb:
                    return []
                return [("mailbox", mb)] if item.get("mailbox_stated") else [("actor_as_mailbox", mb)]
            if mb and actor and mb.lower() != actor.lower():
                return [("actor", actor), ("mailbox", mb)]
            return [("as_logged", actor)] if actor else []
        alt = e["actor_alt"]
        extra = []
        if item.get("for_user") and "key_id" in item:      # an access key: who made it, and whom it is for
            extra = [("key_for_user", item["for_user"])]
        elif item is e and not e["signin"] and e["target"] and "@" in e["target"]:
            extra = [("target", e["target"])]              # "which user was added": the actor or the target
        if e["src"] == "cloudtrail" and alt:
            if it.get("wants_arn"):
                return [("arn", alt["arn"])] if alt.get("arn") else []
            if alt.get("session_issuer"):       # an assumed role: the session's ARN, or the role behind it
                opts = [("arn", alt.get("arn")), ("session_issuer_arn", alt["session_issuer"]),
                        ("role_name", role_name(alt["session_issuer"])), ("principal_id", alt.get("principal_id"))]
            else:
                opts = [("user_name", alt.get("user_name")), ("arn", alt.get("arn")), ("principal_id", alt.get("principal_id"))]
            seen, out = set(), []
            for n, v in opts + extra:
                if v and v not in seen:
                    seen.add(v)
                    out.append((n, v))
            return out
        if not e["actor"]:
            return []
        extra = [(n, v) for n, v in extra if v.lower() != e["actor"].lower()]
        return ([("actor", e["actor"])] + extra) if extra else [("as_logged", e["actor"])]
    if field == "country":
        c = e["country"]
        if not c:
            return []
        if c.upper() in COUNTRY:
            return [("as_logged", c), ("country_name", COUNTRY[c.upper()])]
        if c.lower() in COUNTRY_CODE:
            return [("as_logged", c), ("country_code", COUNTRY_CODE[c.lower()])]
        return [("country_as_logged", c)]      # code or name is not judged, and this file knows no other spelling
    if field == "city":
        return [("as_logged", e["city"])] if e["city"] else []
    if field == "op":
        op = e["op"]
        if not op:
            return []
        return [("as_logged", op)] + ([("no_final_period", op.rstrip(". "))] if op.endswith(".") else [])
    if field == "rule_name":
        if not item.get("name"):
            return []
        if item.get("name_from_identity"):
            return [("identity_tail", item["name"])] + ([("identity", item["name_from_identity"])]
                                                        if item["name_from_identity"] != item["name"] else [])
        return [("as_logged", item["name"])]
    if field == "rule_folder":
        return [("as_logged", item["move_to"])] if item.get("move_to") else []
    if field in ("rule_forward", "rule_keywords", "scopes"):
        vals = item.get({"rule_forward": "forward_to", "rule_keywords": "keywords", "scopes": "scopes"}[field]) or []
        if not vals:
            return []
        if len(vals) == 1:
            v = str(vals[0])
            bare = re.sub(r"^smtp:", "", v, flags=re.I)
            return [("as_logged", v)] + ([("no_smtp_prefix", bare)] if bare != v else [])
        return _joins(vals)
    if field == "app":
        names = item.get("app_names") or {}
        seen, out = set(), []
        for n, v in names.items():
            if v not in seen:
                seen.add(v)
                out.append((n, v))
        return out
    if field == "app_id":
        return list((item.get("app_ids") or {}).items())
    if field == "access_key":
        kid = item.get("key_id")
        if not kid:
            return []
        if item.get("provider") == "gcp" and "/" in kid:      # the key's resource name, or the id at its end
            return [("key_id", kid.rsplit("/", 1)[-1]), ("resource_name", kid)]
        return [("as_logged", kid)]
    if field == "role":
        arn = item.get("role_arn")
        if not arn:
            return []
        if it.get("wants_arn"):
            return [("arn", arn)]
        if it.get("wants_name"):
            return [("role_name", role_name(arn))]
        return [("arn", arn), ("role_name", role_name(arn))]
    return []


def _subject(it, events):
    """(items, tag, heuristic methods or None, why). items are events or helper rows with ['event']."""
    cls = it["cls"]
    pool = events
    lit = []
    if it["ops"]:
        pool = [e for e in pool if e["op"] in it["ops"]]
        lit.append("op")
    if it["actors"]:
        want = {a.lower() for a in it["actors"]}
        pool = [e for e in pool if (e["actor"] or "").lower() in want or want & {str(v).lower() for v in e["actor_alt"].values()}]
        lit.append("actor")
    if it["ips"]:
        pool = [e for e in pool if e["ip"] in it["ips"]]
        lit.append("ip")
    if it.get("targets"):
        want = {t.lower() for t in it["targets"]}
        pool = [e for e in pool if str(e.get("target") or "").lower() in want]
        if it.get("made") and not it["ops"]:
            # "who created X": the calls that make something, not every call that names X
            pool = [e for e in pool if re.match(r"(?:create|new-|add|put|run|register|issue)", (e["op"] or "").lower()) and e["result"] != "failure"]
        lit.append("target")
    if lit and not pool:
        return [], "", None, "no event matches what the question names"
    if lit == ["target"] and cls is None and not it.get("made") and it.get("field") in ("ip", "ua", "user", "country", "city", "op", "count"):
        # "which IP address did X use", "who is X", "what did X do": X made none of these events, it is
        # what they were done to; the caller's address or name is not X's (review, 2026-10-08)
        return [], "", None, "the name the question gives is only the target of events others made, and no making verb is asked"
    tag = "+".join(lit)
    keep = {id(e) for e in pool}
    if cls == "travel":
        return pool, "impossible_travel", "travel", ""
    if cls == "rule":
        rows = [r for r in _cached(inbox_rules, events) if id(r["event"]) in keep]
        if it.get("rule_names"):
            rows = [r for r in rows if str(r.get("name") or "").strip().lower() in it["rule_names"]]
            tag = (tag + "+" if tag else "") + "rule_name"
        if it.get("fwd_targets"):
            rows = [r for r in rows if set(it["fwd_targets"]) <= {re.sub(r"^smtp:", "", str(a), flags=re.I).lower() for a in (r.get("forward_to") or [])}]
            tag = (tag + "+" if tag else "") + "forward_to"
        if (it.get("rule_names") or it.get("fwd_targets")) and not rows:
            return [], "", None, "no rule matches the name or the forwarding address the question gives"
        verb = it.get("verb")
        if verb:
            rows = [r for r in rows if r["kind"] == verb]
        else:
            # mailbox forwarding (Set-Mailbox) is a rule only for a question that speaks of forwarding
            fwd = bool(_F_FWD.search(it["text"]))
            rows = [r for r in rows if r["kind"] != "forwarding" or fwd]
            made = [r for r in rows if r["kind"] in ("create", "forwarding")]
            rows = made if (made or it.get("made")) else [r for r in rows if r["kind"] != "remove"]
        return rows, "inbox_rule" + ("." + tag if tag else ""), None, ""
    if cls == "consent":
        rows = [r for r in _cached(consent_grants, events) if id(r["event"]) in keep]
        if not it["ops"]:       # the consent itself, when the log has it; the grants beside it name the resource
            rows = [r for r in rows if (r["op"] or "").lower().startswith("consent to application")] or rows
        return rows, "consent" + ("." + tag if tag else ""), None, ""
    if cls == "key":
        if not it.get("made"):
            return [], "", None, "an access key the question does not say was created (the log shows keys in use as well)"
        return [r for r in _cached(access_keys, events) if id(r["event"]) in keep], "access_key" + ("." + tag if tag else ""), None, ""
    if cls == "assume":
        return [r for r in _cached(role_assumptions, events) if id(r["event"]) in keep], "assume_role" + ("." + tag if tag else ""), None, ""
    if it["suspicious"] and not it["ops"]:
        return pool, "suspicious_signin" + ("." + tag if tag else ""), "suspicious", ""
    if it["signin"]:
        return [e for e in pool if e["signin"]], "signin" + ("." + tag if tag else ""), None, ""
    if not lit and not (it["field"] == "count" and (_TOTAL.search(it["text"]) or it["distinct"])) and not it["most"] \
            and not (it["field"] == "op" and it["ordinal"]):
        return [], "", None, "the question names no event, account, address or class of events"
    return pool, tag or "all", None, ""


def _ev(item):
    return item["event"] if "event" in item else item


def _cached(fn, events):
    """fn(events), kept while the same list object is asked again (one delivery, many questions)."""
    k = (fn.__name__, id(events))
    hit = _MEMO.get(k)
    if hit is not None and hit[0] is events:
        return hit[1]
    if len(_MEMO) > 64:
        _MEMO.clear()
    out = fn(events)
    _MEMO[k] = (events, out)
    return out


def answer(q, log: Log, explain: list = None):
    """One question's answer: a plain value, an unsure string, or None (see the module text)."""
    def no(why):
        if explain is not None:
            explain.append(why)
        return None

    if not log.events:
        return no("no known log source in the delivery")
    if not log.whole:
        return no("a log file did not parse whole")
    events = log.events
    member = q.get("member")
    if member:
        scopes = log.__dict__.setdefault("_scopes", {})
        if member not in scopes:
            scopes[member] = [e for e in events if e["file"].split(ARROW)[-1].strip() == member
                              or Path(e["file"].split(ARROW)[-1]).name == Path(member).name]
        mine = scopes[member]
        if mine:
            events = mine
        elif len(log.files) > 1:
            return no(f"the member {member} is not a log this file read")
    used = {e["file"] for e in events}
    for f in log.files:
        if f["file"] in used and f["records"] - f["events"] - f["duplicates"] - f.get("repeats", 0) > 0:
            return no(f"{f['file']} mixes records of a known source with records this file does not know: "
                      "what it shows is not the whole log")
    srcs = sorted({e["src"] for e in events})
    it = read_question(q, events)
    field = it["field"]
    if field is None:
        return no(it["why"])
    kind = str(_fmt(q).get("kind") or "")
    items, tag, heur, why = _subject(it, events)
    if why:
        return no(why)
    src = srcs[0] if len(srcs) == 1 else "mixed"
    key = f"{KEY}.{field}/{src}.{tag}"
    enum = _enum(q)
    if field == "count" and any(f["duplicates"] for f in log.files):
        return no("records with the same id came in two files; whether a count takes them once or twice is not proven")
    soft = None
    if tag.split(".")[0] == "signin" and any(_ev(x)["src"] in SOFT_SIGNIN_SOURCES for x in items):
        soft = "signin_ops"

    def out_plain(value):
        value = str(value)
        if soft:
            return out_unsure(key, [(soft, value)])
        if enum and value not in enum:
            return no("the value is not one of the listed options")
        if not _fits(q, value):
            return no("the value does not fit the answer pattern")
        return value

    def out_unsure(k, options):
        options = [(n, str(v)) for n, v in options if v is not None and _fits(q, str(v)) and (not enum or str(v) in enum)]
        if not options:
            return no("no option fits the answer format")
        return pick(k, options)

    # ---- heuristics: unsure, one option per method -------------------------------------------------
    if heur == "travel":
        pairs = _cached(impossible_travel, items)
        if not pairs:
            return no("no impossible-travel pair")
        if field == "count":
            return out_unsure(key, [("pairs", len(pairs)), ("accounts", len({p["actor"] for p in pairs}))])
        if len({p["actor"] for p in pairs}) != 1 and field == "user":
            return no("more than one account travels impossibly")
        p = pairs[0]
        opts = []
        for which, e in (("later", p["b"]), ("earlier", p["a"])) if it["ordinal"] != "first" else (("earlier", p["a"]), ("later", p["b"])):
            for n, v in _formats(field, e, it)[:4]:
                opts.append((f"{which}:{n}", v))
        if field == "user":
            opts = opts[:1]
        return out_unsure(key, opts)
    if heur == "suspicious":
        if field == "count" or it["most"]:
            return no("a count of suspicious events is a judgement")
        cands = _cached(suspicious_signins, items)
        if not cands:
            return no("no heuristic names a suspicious sign-in")
        votes, order, rep = Counter(), [], {}
        for rank, (method, e) in enumerate(cands):
            fm = _formats(field, e, it)
            if not fm:
                continue
            v = fm[0][1]
            votes[v] += 1
            if v not in rep:
                rep[v] = (method, fm)
                order.append(v)
        if not order:
            return no("the suspicious sign-ins carry no such field")
        order.sort(key=lambda v: -votes[v])
        opts = []
        depth = max(len(rep[v][1]) for v in order)
        for d in range(depth):
            for v in order:
                method, fm = rep[v]
                if d < len(fm):
                    opts.append((f"{method}:{fm[d][0]}", fm[d][1]))
        return out_unsure(key, opts)

    # ---- structural selections ---------------------------------------------------------------------
    if it["result"]:
        evs = [_ev(x) for x in items]
        if not all(e["signin"] for e in evs) and it["cls"] is None:
            evs_known = [e for e in evs if e["result"] is not None]
            if len(evs_known) != len(evs):
                return no("some events state no result")
        strict = [x for x in items if _ev(x)["result"] == it["result"]]
        loose = [x for x in items if _ev(x)["result"] in ((it["result"], "interrupted") if it["result"] == "failure" else (it["result"],))]
        if len(strict) != len(loose) or any(_ev(x)["result"] is None for x in items):
            if field != "count":
                return no("interrupted or unstated results make 'failed' ambiguous here")
            return out_unsure(key + "." + it["result"], [("status_strict", len(strict)), ("status_with_interrupted", len(loose))])
        items = strict
        key += "." + it["result"]
    if not items:
        return no("nothing matches (a zero is not proven: the log may spell the thing another way)")
    if field == "count":
        if it["most"] or it["ordinal"]:
            return no("a count with an ordinal")
        if any(_ev(x)["src"] == "k8s_audit" for x in items):
            stages = {_ev(x).get("stage") for x in items}
            if len(stages) > 1:
                done = [x for x in items if _ev(x).get("stage") == "ResponseComplete"]
                return out_unsure(key, [("requests_response_complete", len(done)), ("records", len(items)),
                                        ("audit_ids", len({_ev(x)["id"] for x in items}))])
        if it["distinct"]:
            d = it["distinct"]
            if d == "role":
                if it["cls"] != "assume":
                    return no("roles are counted only among role assumptions")
                vals = [x.get("role_arn") for x in items]
            elif d == "app" and it["cls"] == "consent":
                # the apps consented to are the consent rows' targets, never the event's own app field
                # (the portal the consent was given in): review 2026-10-08, 1 for 12 on a real export
                def shown(x):
                    names = x.get("app_names") or {}
                    return x.get("app") or names.get("target_type_1") or names.get("target_display_name")
                rows = [x for x in items if isinstance(x, dict)]
                by_name = {str(shown(x)).lower() for x in rows} if rows and all(shown(x) for x in rows) else set()
                by_id = {str(x.get("app_id")).lower() for x in rows} if rows and all(x.get("app_id") for x in rows) else set()
                opts = [(nm, len(s)) for nm, s in (("distinct_app_names", by_name), ("distinct_app_ids", by_id)) if s]
                if not opts:
                    return no("no consent names its application")
                return out_unsure(key + ".distinct_app", opts + [("events", len(items))])
            else:
                vals = [_ev(x).get(d) for x in items]
            n = len({str(v).lower() for v in vals if v is not None})
            if d == "actor" and it.get("made") and not it["cls"]:
                return no("users that were created are not the users that made the events")
            if d == "actor" and None not in vals:
                # 'users': the log's actors hold service names beside people, and one address in two casings
                raw = len({str(v) for v in vals})
                people = len({str(v).lower() for v in vals if re.fullmatch(r"[^@\s\\]+@[^@\s\\]+\.[^@\s\\]+", str(v))})
                if len({n, raw, people} - {0}) > 1:
                    return out_unsure(key + ".distinct_actor.kinds", [(nm, c) for nm, c in (("user_principal_names", people), ("every_actor", n),
                                                                                           ("as_logged", raw)) if c])
            if d != "role" and it["signin"] and not it["result"]:
                # "how many users signed in": every attempt, or only the ones that got in
                ok = len({str(_ev(x).get(d)).lower() for x in items if _ev(x)["result"] == "success" and _ev(x).get(d) is not None})
                if ok != n:
                    return out_unsure(key + ".distinct_" + d, [("all_signins", n), ("successful_signins", ok)])
            if d == "actor" and it.get("made") and not it["cls"]:
                return no("users that were created are not the users that made the events")
            if None in vals or (d == "actor" and any(_ev(x)["src"] == "cloudtrail" for x in items)):
                # an event without the field, or AWS identities (one user has many session ARNs)
                if n == 0:
                    return no("no event states the field (a zero is not proven)")
                return out_unsure(key + ".distinct_" + d, [("stated_values", n)])
            return out_plain(n)
        if it["cls"] == "rule":
            names = {r["name"] for r in items}
            if len(names) != len(items) or None in names:
                return out_unsure(key, [("events", len(items)), ("distinct_names", len(names - {None}) or None)])
            if any((r["event"]["op"] or "").lower() == "updateinboxrules" for r in items):
                # Outlook on the web logs one UpdateInboxRules for a new, a changed and a removed rule alike
                return out_unsure(key, [("events", len(items))])
        if it["cls"] == "consent":
            apps = {r["app"] or r["app_id"] for r in items}
            if len(apps) != len(items):
                return out_unsure(key, [("events", len(items)), ("distinct_apps", len(apps))])
        rows = sum(_ev(x).get("copies", 1) for x in items)
        if rows != len(items):
            # an export that repeats records: the records, or the rows of the file
            return out_unsure(key + ".repeated", [("distinct_records", len(items)), ("rows", rows)])
        return out_plain(len(items))
    if field == "role_chain":
        keep = {id(r["event"]) for r in items}
        chains = [c for c in role_chains(events) if any(id(s["event"]) in keep for s in c["steps"])]
        long = [c for c in chains if len(c["roles"]) >= 2]
        if len(long) != 1:
            return no(f"{len(long)} chains of two or more roles")
        c = long[0]
        names, arns = [role_name(r) for r in c["roles"]], c["roles"]
        opts = _joins(names, "names_")[:4] + _joins(arns, "arns_")[:2]
        if c["origin"]:
            opts += [("origin_names_arrow", " -> ".join([role_name(c["origin"])] + names)),
                     ("origin_names_comma", ",".join([role_name(c["origin"])] + names))]
        opts += [("names_json", json.dumps(names, separators=(",", ":"))), ("arns_json", json.dumps(arns, separators=(",", ":")))]
        return out_unsure(key, opts)
    if field == "role" and it["cls"] == "assume" and it["ordinal"]:
        long = [c for c in role_chains(events) if len(c["roles"]) >= 2]
        if len(long) == 1:
            step = long[0]["steps"][0 if it["ordinal"] == "first" else -1]
            return out_unsure(key + ".chain_" + it["ordinal"], [(f"chain_{it['ordinal']}:{n}", v) for n, v in _formats(field, step, it)]
                              + [(f"by_time:{n}", v) for n, v in _formats(field, items[0 if it["ordinal"] == "first" else -1], it)
                                 if items[0 if it["ordinal"] == "first" else -1] is not step])
    # the one item the question pins down
    chosen, how = None, ""
    if it["most"]:
        if field not in ("user", "ip", "ua", "op", "country", "city"):
            return no("'most' of a field this file does not rank")
        ranked, by_rows = Counter(), Counter()
        rep = {}
        for x in items:
            fm = _formats(field, x, it)
            if fm:
                ranked[fm[0][1]] += 1
                by_rows[fm[0][1]] += _ev(x).get("copies", 1)
                rep.setdefault(fm[0][1], x)
        top = ranked.most_common(2)
        if not top or (len(top) == 2 and top[0][1] == top[1][1]):
            return no("no value has strictly the most events")
        top_rows = by_rows.most_common(2)
        if top_rows[0][0] != top[0][0] or (len(top_rows) == 2 and top_rows[0][1] == top_rows[1][1]):
            return no("the file repeats records, and the value with the most records is not the one with the most rows")
        chosen, how = rep[top[0][0]], ".most"
    elif it["ordinal"]:
        if any(_ev(x)["time"] is None or _ev(x)["tq"] != "ok" for x in items):
            return no("an event's time is missing or its day/month order is not proven")
        ordered = sorted(items, key=lambda x: (_ev(x)["time"], _ev(x)["i"]))
        chosen = ordered[0] if it["ordinal"] == "first" else ordered[-1]
        ties = [x for x in ordered if _ev(x)["time"] == _ev(chosen)["time"]]
        if len({json.dumps(_formats(field, x, it)) for x in ties}) != 1:
            return no("two events share the first or last time and differ in the field")
        how = "." + it["ordinal"]
    else:
        per = {}
        for x in items:
            per.setdefault(json.dumps(_formats(field, x, it)), x)
        if len(per) != 1:
            return no(f"{len(per)} different values among {len(items)} matching events, and the question does not say which")
        chosen = next(iter(per.values()))
    fm = _formats(field, chosen, it)
    if not fm:
        return no("the event carries no such field")
    key += how
    if len(fm) == 1 and field != "time" and fm[0][0] not in SOFT:
        return out_plain(fm[0][1])
    if field == "time":
        fitting = [(n, v) for n, v in fm if _fits(q, v)]
        raw_t = str(_ev(chosen)["time_raw"] or "")
        zoned = bool(re.search(r"(?:Z|UTC|GMT|[+-]\d\d:?\d\d)$", raw_t, re.I) or re.fullmatch(r"\d{10}(?:\d{3})?(?:\.\d+)?", raw_t))
        # a time rewritten into another format is proven only when the log states its zone
        if (_fmt(q).get("pattern") or _fmt(q).get("regex")) and len(fitting) == 1 and (fitting[0][0] == "as_logged" or zoned):
            return out_plain(fitting[0][1])
    return out_unsure(key, fm)


def solve_set(questions, files, ctx) -> dict:
    """The runner contract. Everything is None when the delivery holds no log of a known source."""
    out = {}
    ids = [q.get("qid") or q.get("id") for q in questions]
    try:
        log = load(files or {})
    except Exception:
        return {i: None for i in ids}
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    for q, qid in zip(questions, ids):
        try:
            out[qid] = answer(q, log) if log.events else None
        except Exception:       # a fact that cannot be read is no answer
            out[qid] = None
        if partial is not None and out[qid] is not None:
            partial[qid] = out[qid]
    return out


# ---- the command ---------------------------------------------------------------------------------------

def _brief(e) -> str:
    t = e["time"].strftime("%Y-%m-%d %H:%M:%SZ") if e["time"] else (e["time_raw"] or "-")
    bits = [t, e["src"], e["op"] or ("sign-in" if e["signin"] else "-"), e["actor"] or "-", e["ip_raw"] or "-"]
    if e["result"]:
        bits.append(e["result"] + (f"({e['error']})" if e["error"] else ""))
    if e["country"] or e["city"]:
        bits.append("/".join(x for x in (e["city"], e["country"]) if x))
    return " | ".join(bits)


def summary(log: Log, top: int = 8) -> dict:
    """The triage of a Log as plain data (what the command prints)."""
    ev = log.events
    timed = [e for e in ev if e["time"]]
    sig = signins(ev)
    s = {"files": log.files, "notes": log.notes, "sources": log.sources, "events": len(ev), "unrecognised_records": len(log.other),
         "first": min(timed, key=lambda e: e["time"])["time"].isoformat() if timed else None,
         "last": max(timed, key=lambda e: e["time"])["time"].isoformat() if timed else None}
    for f in ("actor", "ip", "op", "ua", "country", "app"):
        s["top_" + f] = counts_by(ev, f).most_common(top)
    s["signins"] = {"total": len(sig), "results": dict(Counter(e["result"] or "unstated" for e in sig)),
                    "failures_by_ip": Counter(e["ip"] for e in sig if e["result"] == "failure" and e["ip"]).most_common(top),
                    "failures_by_actor": Counter(e["actor"] for e in sig if e["result"] == "failure" and e["actor"]).most_common(top)}
    s["suspicious_signins"] = [{"method": m, "event": _brief(e), "ua": e["ua"]} for m, e in suspicious_signins(ev)]
    s["impossible_travel"] = [{"actor": p["actor"], "from": _brief(p["a"]), "to": _brief(p["b"]), "km": p["km"], "hours": p["hours"],
                               "kmh": p["kmh"]} for p in impossible_travel(ev)[:top]]
    s["inbox_rules"] = [{"kind": r["kind"], "name": r["name"], "mailbox": r["mailbox"], "forward_to": r["forward_to"],
                         "move_to": r["move_to"], "delete": r["delete"], "mark_read": r["mark_read"], "keywords": r["keywords"],
                         "event": _brief(r["event"])} for r in inbox_rules(ev)]
    s["consent_grants"] = [{"app": c["app"], "app_names": c["app_names"], "app_id": c["app_id"], "scopes": c["scopes"], "admin": c["admin"],
                            "event": _brief(c["event"])} for c in consent_grants(ev)]
    s["access_keys"] = [{"provider": k["provider"], "key_id": k["key_id"], "for_user": k["for_user"], "event": _brief(k["event"])}
                        for k in access_keys(ev)]
    s["role_chains"] = [{"origin": c["origin"], "roles": c["roles"], "linked_by": c["linked_by"]} for c in role_chains(ev)]
    s["registered_devices"] = [{"name": d["name"], "device_id": d["device_id"], "record": d["record"], "event": _brief(d["event"])}
                               for d in registered_devices(ev)]
    s["device_code_signins"] = Counter(e["ip"] for _how, e in device_code_signins(ev) if e["ip"]).most_common(top)
    s["downloads_by_ip"] = Counter(d["ip"] for d in downloads(ev) if d["ip"]).most_common(top)
    note = notable(ev)
    s["notable"] = [_brief(e) + (f" | {e['target']}" if e["target"] else "") for e in note[:top * 5]]
    s["notable_total"] = len(note)
    return s


def render(s: dict) -> str:
    lines = ["# cloudlogs triage", ""]
    for f in s["files"]:
        src = ", ".join(f"{k} x{v}" for k, v in f["sources"].items()) or "no known source"
        lines.append(f"- {f['file']}: {f['form']}, {f['records']} records, {src}" + ("" if f["whole"] else "  (NOT WHOLE)"))
    lines += [f"- NOTE {n}" for n in s["notes"]]
    lines += ["", f"events: {s['events']}  (records of no known source: {s['unrecognised_records']})",
              f"time range: {s['first']} .. {s['last']}", ""]
    for f, title in (("actor", "actors"), ("ip", "IP addresses"), ("op", "operations"), ("ua", "user agents"), ("country", "countries"),
                     ("app", "apps / services")):
        if s["top_" + f]:
            lines.append(f"## top {title}")
            lines += [f"  {n:6d}  {v}" for v, n in s["top_" + f]]
    sg = s["signins"]
    if sg["total"]:
        lines += ["## sign-ins", f"  total {sg['total']}: " + ", ".join(f"{k} {v}" for k, v in sg["results"].items())]
        lines += [f"  failures from {v}: {n}" for v, n in sg["failures_by_ip"]]
        lines += [f"  failures of {v}: {n}" for v, n in sg["failures_by_actor"]]
    if s["suspicious_signins"]:
        lines.append("## suspicious sign-in candidates (one per heuristic; candidates, not answers)")
        lines += [f"  {c['method']}: {c['event']} | ua={c['ua']}" for c in s["suspicious_signins"]]
    if s["impossible_travel"]:
        lines.append("## impossible travel")
        lines += [f"  {p['actor']}: {p['from']}  =>  {p['to']}  ({p['km']} km in {p['hours']} h)" for p in s["impossible_travel"]]
    if s["inbox_rules"]:
        lines.append("## mailbox rules and forwarding")
        lines += [f"  {r['kind']} name={r['name']!r} forward_to={r['forward_to']} move_to={r['move_to']!r} delete={r['delete']} "
                  f"keywords={r['keywords']} | {r['event']}" for r in s["inbox_rules"]]
    if s["consent_grants"]:
        lines.append("## OAuth consent grants")
        lines += [f"  app={c['app']!r} names={c['app_names']} id={c['app_id']} scopes={' '.join(c['scopes'])} admin={c['admin']} | {c['event']}"
                  for c in s["consent_grants"]]
    if s["access_keys"]:
        lines.append("## access keys created")
        lines += [f"  {k['provider']} {k['key_id']} for {k['for_user']} | {k['event']}" for k in s["access_keys"]]
    if s["role_chains"]:
        lines.append("## role assumption chains")
        lines += [f"  {c['origin']} -> " + " -> ".join(c["roles"]) + (f"  (linked by {c['linked_by']})" if c["linked_by"] else "")
                  for c in s["role_chains"]]
    if s["registered_devices"]:
        lines.append("## registered devices")
        lines += [f"  {d['name']!r} device_id={d['device_id']} ({d['record']}) | {d['event']}" for d in s["registered_devices"]]
    if s["device_code_signins"]:
        lines.append("## device-code sign-ins by IP")
        lines += [f"  {n:6d}  {v}" for v, n in s["device_code_signins"]]
    if s["downloads_by_ip"]:
        lines.append("## file downloads by IP")
        lines += [f"  {n:6d}  {v}" for v, n in s["downloads_by_ip"]]
    if s["registered_devices"] or s["device_code_signins"] or s["downloads_by_ip"]:
        lines.append("  (--pivot joins these per IP and judges each device, rule and download)")
    if s["notable"]:
        lines.append(f"## notable operations ({s['notable_total']})")
        lines += ["  " + n for n in s["notable"]]
    return "\n".join(lines)


def read_paths(paths, big: list = None) -> dict:
    """{name: bytes} of the files named, the members of a plain zip included. With a `big` list (the
    pivot, which is handed whole folders), a file over MAX_BYTES is not read: (name, its first SNIFF
    bytes) is appended to `big` for the caller to judge, and links inside a folder are not followed."""
    files = {}
    for p in paths:
        p = Path(p)
        for f in (sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]):
            if big is not None:
                if p.is_dir() and f.is_symlink():
                    continue
                if f.stat().st_size > MAX_BYTES:
                    with open(f, "rb") as fh:
                        big.append((str(f), fh.read(SNIFF)))
                    continue
            data = f.read_bytes()
            files[f.name if f.name not in files else str(f)] = data
            if data[:4] == b"PK\x03\x04":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for info in z.infolist()[:MAX_FILES]:
                            if not info.is_dir() and info.file_size <= MAX_BYTES and not info.flag_bits & 1:
                                files[f"{f.name}{ARROW}{info.filename}"] = z.read(info)
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    pass
    return files


def _web_evidence():
    """The sibling access-log reader (solvers/toolkits/web_evidence.py), loaded by its path so a copy
    of this file beside it works from any folder. ImportError says why when it cannot be loaded."""
    mod = sys.modules.get("web_evidence")
    if mod is None:
        import importlib.util
        path = HERE / "web_evidence.py"
        if not path.is_file():
            raise ImportError(f"{path.name} is not beside cloudlogs.py")
        spec = importlib.util.spec_from_file_location("web_evidence", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["web_evidence"] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException as ex:
            sys.modules.pop("web_evidence", None)
            raise ImportError(f"web_evidence.py did not load: {type(ex).__name__}: {ex}") from ex
    return mod


def access_logs(files: dict, log: Log) -> dict:
    """The web access logs among `files` that are not cloud logs, read with web_evidence.read_log():
    {files [{file, kind, events}], events, activity (web_evidence.ip_activity)}. The same bytes under
    two names are read once. ImportError when web_evidence cannot be loaded."""
    we = _web_evidence()
    cloud = {f["file"] for f in log.files if f["events"]}
    # by its bytes, not its name: a cloud log under a second name (a member and its unpacked copy) is still one
    out, events, digests = [], [], {hashlib.sha256(files[n]).digest() for n in cloud if isinstance(files.get(n), (bytes, bytearray))}
    for name, data in files.items():
        if not isinstance(data, (bytes, bytearray)) or data[:4] in (b"PK\x03\x04", b"\x7fELF") or data[:2] == b"\x1f\x8b":
            continue
        digest = hashlib.sha256(data).digest()
        if digest in digests:
            continue
        digests.add(digest)
        evs = we.read_log(bytes(data), str(name))
        if evs:
            out.append({"file": str(name), "kind": evs[0]["kind"], "events": len(evs)})
            events += evs
    return {"files": out, "events": len(events), "activity": we.ip_activity(events)}


def read_brief(path) -> str:
    """The text of a challenge brief: a challenge folder's challenge.json (name, description), a JSON
    file of that shape, or any other file as text. OSError / ValueError name what could not be read."""
    p = Path(path)
    if p.is_dir():
        p = p / "challenge.json"
        if not p.is_file():
            raise OSError(f"{path}: no challenge.json in the folder")
    text = p.read_text(encoding="utf-8", errors="replace")
    if p.suffix.lower() == ".json":
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError(f"{p}: not a JSON object")
        return "\n".join(str(doc[k]) for k in ("name", "description") if isinstance(doc.get(k), str))
    return text


def pivot_data(pv: dict, top: int = 8) -> dict:
    """A pivot as plain data (what `--pivot --json` prints): no raw records, times as text."""
    def art(a):
        d = {k: v for k, v in a.items() if k not in ("event", "failed")}
        d["time"] = _iso(a["time"])
        return d

    def acc(r):
        if r is None:
            return None
        return {"requests": r["requests"], "first": _iso(r["first"]), "last": _iso(r["last"]), "statuses": dict(r["statuses"]),
                "methods": dict(r["methods"]), "top_paths": r["paths"].most_common(top),
                "user_agents": r["user_agents"].most_common(3), "forwarded": r["forwarded"], "forwarded_via": dict(r["forwarded_via"])}

    ips = []
    for r in pv["ips"]:
        ips.append({"ip": r["ip"], "attacker": r["attacker"], "events": r["events"], "top_ops": r["ops"].most_common(top),
                    "signins": dict(r["signins"]), "first_signin": _iso(r["first_signin"]), "last_signin": _iso(r["last_signin"]),
                    "device_code_signins": r["device_code_signins"], "accounts": sorted(r["accounts"]),
                    "devices": [art(a) for a in r["devices"]], "rules": [art(a) for a in r["rules"]], "downloads": r["downloads"],
                    "access": acc(r["access"])})
    return {"attacker_rule": ATTACKER_RULE, "decoy_rule": DECOY_RULE,
            "attackers": {k: {"why": v["why"], "first_signin": _iso(v["first_signin"]), "device_code_signins": v["device_code_signins"]}
                          for k, v in pv["attackers"].items()},
            "ips": ips, "artifacts": [art(a) for a in pv["artifacts"]], "access_only": pv["access_only"], "notes": pv["notes"]}


def render_pivot(d: dict) -> str:
    """The pivot for a reader. The brief's template is never echoed (a flag search over this output
    would take it for a flag): only its slot names and, when every slot has one value, the flag."""
    lines = ["# cloudlogs pivot (per client IP)", "", "attacker rule: " + d["attacker_rule"], "decoy rule: " + d["decoy_rule"], ""]
    lines += [f"- {f['file']}: {f['form']}, {f['records']} records, " + (", ".join(f"{k} x{v}" for k, v in f["sources"].items())
              or "no known source") + ("" if f["whole"] else "  (NOT WHOLE)") for f in d.get("files", [])]
    for f in (d.get("access_logs") or {}).get("files", []):
        lines.append(f"- {f['file']}: access log ({f['kind']}), {f['events']} requests")
    lines += [f"- NOTE {n}" for n in d["notes"]]
    lines += ["", "## attacker IPs"]
    lines += [f"  {k}: {'+'.join(v['why'])}; first sign-in {v['first_signin']}; device-code sign-ins {v['device_code_signins']}"
              for k, v in d["attackers"].items()] or ["  none"]

    def art(a):
        extra = ""
        if a["kind"] == "device":
            extra = f" device_id={a['device_id']}"
        elif a["kind"] == "rule":
            extra = f" {a['rule_kind']} forward_to={a['forward_to']} move_to={a['move_to']!r}"
        return f"{a['kind']} {a['name']!r}{extra} | {a['time']} | {a['ip'] or 'no IP'} | {a['verdict'].upper()} ({a['why']}): {a['detail']}"

    for r in d["ips"]:
        lines.append(f"## {r['ip']}" + (f"  ATTACKER ({'+'.join(r['attacker'])})" if r["attacker"] else ""))
        lines.append(f"  events {r['events']}: " + ", ".join(f"{op} x{n}" for op, n in r["top_ops"]))
        if r["signins"]:
            lines.append("  sign-ins: " + ", ".join(f"{k} {v}" for k, v in r["signins"].items())
                         + f"; first {r['first_signin']}, last {r['last_signin']}; device-code {r['device_code_signins']}; "
                         + "accounts " + ", ".join(r["accounts"]))
        lines += ["  " + art(a) for a in r["devices"] + r["rules"]]
        if r["downloads"]:
            lines.append(f"  downloads: {r['downloads']}")
        if r["access"]:
            a = r["access"]
            lines.append(f"  access log: {a['requests']} requests, {a['first']} .. {a['last']}; status "
                         + ", ".join(f"{k} x{v}" for k, v in a["statuses"].items())
                         + (f"; named in X-Forwarded-For by {a['forwarded']} requests of other peers" if a["forwarded"] else ""))
            lines += [f"    {n:5d}  {p}" for p, n in a["top_paths"]]
        elif d.get("access_logs"):
            lines.append("  access log: no request")
    if d["access_only"]:
        lines.append(f"({d['access_only']} more addresses are in the access logs only)")
    lines.append("## devices, rules and downloads under the decoy rule")
    lines += ["  " + art(a) for a in d["artifacts"]] or ["  none"]
    t = d.get("template")
    if t:
        lines.append("## flag template of the brief: slots " + (", ".join(s["slot"] for s in t["slots"]) or "none"))
        lines += [f"  {s['slot']} ({s['field'] or 'unknown'}) = {', '.join(s['values']) or '-'}" for s in t["slots"]]
        lines += [f"  not filled: {w}" for w in t["why"]]
        if t["flag"]:
            lines.append(f"  flag: {t['flag']}")
    lines += [f"- NOTE {n}" for n in d.get("template_notes", [])]
    return "\n".join(lines)


def _option_values(argv, name) -> list:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == name]


def pivot_main(argv, args) -> int:
    """`--pivot`: the per-IP pivot of the files and folders named, the access logs among them joined
    by IP, and the brief's flag template filled when the rules leave one value per slot."""
    if "--top" in argv:     # the pivot lists every IP: a --top value would otherwise be read as a path
        print("cloudlogs.py --pivot: --top limits the triage tables only; the pivot lists every IP, drop --top",
              file=sys.stderr)
        return 2
    named = _option_values(argv, "--attacker-ip")
    briefs, templates = _option_values(argv, "--brief"), _option_values(argv, "--template")
    taken = set(named + briefs + templates)
    args = [a for a in args if a not in taken]
    if not args:
        print("cloudlogs.py --pivot: name the log files or their folder", file=sys.stderr)
        return 2
    big = []
    try:
        files = read_paths(args, big)
    except OSError as e:
        print(f"cloudlogs.py: {e}", file=sys.stderr)
        return 1
    log = load(files)
    for name, head in big:
        if _sniff(head) is not None:
            log.whole = False
            log.notes.append(f"{name}: a cloud log over {MAX_BYTES} bytes, not read; nothing is answered from a log that is not whole")
        else:
            log.notes.append(f"{name}: over {MAX_BYTES} bytes and not a cloud log by its head; not read")
    notes = list(log.notes)
    logs = None
    try:
        logs = access_logs(files, log)
    except ImportError as ex:
        notes.append(f"access logs NOT joined: {ex}")
        print(f"cloudlogs.py: access logs not joined: {ex}", file=sys.stderr)
    try:
        pv = pivot(log.events, named, logs["activity"] if logs and logs["files"] else None)
    except ValueError as ex:
        print(f"cloudlogs.py: {ex}", file=sys.stderr)
        return 2
    d = pivot_data(pv)
    d["files"], d["whole"] = log.files, log.whole
    d["notes"] = notes + d["notes"]
    d["access_logs"] = {"files": logs["files"], "events": logs["events"]} if logs and logs["files"] else None
    tnotes = []
    for b in briefs:
        try:
            found = find_templates(read_brief(b))
        except (OSError, ValueError) as ex:
            tnotes.append(f"brief NOT read: {ex}")
            print(f"cloudlogs.py: brief not read: {ex}", file=sys.stderr)
            continue
        if not found:
            tnotes.append(f"{b}: the brief holds no flag template with <slots>")
        templates += found
    templates = list(dict.fromkeys(templates))
    d["template"] = None
    if len(templates) == 1:
        d["template"] = fill_template(templates[0], pv, log.whole)
    elif templates:
        tnotes.append(f"{len(templates)} different flag templates were given; none is filled")
    d["template_notes"] = tnotes
    print(json.dumps(d, indent=1, default=str) if "--json" in argv else render_pivot(d))
    return 0 if log.events else 3


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if "--pivot" in argv:
        return pivot_main(argv, args)
    if not args:
        print(__doc__.split("\n\n")[0] + "\n\n  .venv/bin/python solvers/toolkits/cloudlogs.py <file>... [--json] [--top N]\n"
              "  .venv/bin/python solvers/toolkits/cloudlogs.py --pivot <file|folder>... [--attacker-ip IP]... [--brief DIR|FILE] "
              "[--template T] [--json]", file=sys.stderr)
        return 2
    top = 8
    if "--top" in argv:
        try:
            top = int(argv[argv.index("--top") + 1])
            args = [a for a in args if a != argv[argv.index("--top") + 1]]
        except (IndexError, ValueError):
            pass
    try:
        files = read_paths(args)
    except OSError as e:
        print(f"cloudlogs.py: {e}", file=sys.stderr)
        return 1
    log = load(files)
    s = summary(log, top)
    s["signal"] = signals([], files)
    print(json.dumps(s, indent=1, default=str) if "--json" in argv else render(s) + f"\n\nsignal: {s['signal']}")
    return 0 if log.events else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
