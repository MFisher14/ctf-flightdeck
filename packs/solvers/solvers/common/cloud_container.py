#!/usr/bin/env python3
"""Toolkit `cloud_container`: cloud control-plane logs, container images, infrastructure files.

  .venv/bin/python solvers/toolkits/cloud_container.py <file | folder>... [--json] [--find PATH]
                                                       [--ask "question text"]

Offline, plain Python, no request. Nothing is ever written to disk: archives and image layers are
read in memory, with limits on members, sizes and paths. Everything read is data; text inside a
log, a layer or a manifest is never followed.

What it reads (each by its bytes, a name only strengthens):

  logs      AWS CloudTrail (`Records[]`, gzip or plain, JSON lines), GCP audit (`protoPayload`),
            Azure Activity (`operationName`, `caller`), Kubernetes audit (`audit.k8s.io` events,
            JSON lines or an EventList), into one event shape (normalize)
  images    `docker save` tars (old and new layout) and OCI image layouts (a tar, or loose members
            of a zip): manifest, config, history, env, entrypoint, cmd, and every layer's file
            list with whiteouts; a path is found in any layer, one deleted later included
  files     Dockerfile, Compose file, Kubernetes manifests (PyYAML safe_load only), Terraform
            state (every attribute, the ones Terraform itself marks sensitive, outputs)

Readers an agent calls by hand: load(files) -> Evidence, load_records, normalize, read_image,
find_path, deleted_files, final_listing, parse_dockerfile, read_compose, read_k8s_manifests,
tf_leaves, tf_sensitive, and the log queries access_keys_used, access_keys_created, assumed_roles,
source_ips_by_principal, first_event, object_reads, pod_execs, secret_reads, privileged_pods,
cluster_role_bindings, sensitive_events, suspects.

solve_set (AGENTS.md, "Uncertain answers") reads the question's words. Every word must be one this
file knows (VOCAB) or a literal found in the evidence (an operation name, a user, an IP, a key id, a
path, an environment variable, a resource address); one unknown word means None. Then:

  plain    a value read from the bytes that exactly one candidate fits, in a form with one
           spelling: an access key id, a source IP, a bucket, an ARN asked for as an ARN, a logged
           userName, a pod, a secret's name, a file's SHA-256 (lowercase hex), an environment
           variable's value, a count, a Terraform attribute the question names
  unsure   labels.pick('cloud_container.<field>/<shape>', [(method, value), ...]) for a fact with
           more than one spelling (a time; a layer: manifest digest, diff id, with and without
           `sha256:`, its number; an entrypoint: JSON or joined; a role: name or ARN; a deleted
           path: with or without the leading slash; a service account), and for every selection
           made by a rule rather than by the question: the 'attacker' (rules in suspects()), a
           'secret' found by its name
  None     everything else: more than one candidate, a question with a qualifier this file does
           not model (before, after, not, second, ...), evidence that was cut or did not parse,
           and any set whose questions carry the marks of one of the five known lanes

The label key's lane is `cloud_container`. Until solvers/common/labels.py lists that lane, pick()
refuses the key and the unsure wire form is written directly ("??" + JSON): never sent, shown as
unsure, and probed only once the lane is registered.
"""
import base64
import gzip
import hashlib
import io
import ipaddress
import json
import re
import sys
import tarfile
import time as _time
import urllib.parse
import zipfile
import zlib
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
try:
    import labels      # noqa: E402
except Exception:      # a copy of this file alone still reads evidence
    labels = None
try:
    import yaml        # noqa: E402  (PyYAML; safe_load only)
except Exception:
    yaml = None

KEY = "cloud_container"
ARROW = " -> "
UNSURE = "??"
MAX_OPTIONS = 12
UTC = timezone.utc

MAX_DOC = 64 * 1024 * 1024       # a log, state or manifest parsed whole is at most this large
MAX_RAW = 256 * 1024 * 1024      # a decompressed stream (a gzip log, an image layer)
MAX_FILE = 64 * 1024 * 1024      # one tar member read into memory
KEEP_FILE = 4 * 1024 * 1024      # a layer file's bytes are kept up to this size (larger: sizes and names only)
MAX_MEMBERS = 50000              # members of one tar
MAX_TOTAL = 512 * 1024 * 1024    # bytes read out of tars in one load
MAX_EVENTS = 400000
MAX_YAML = 4 * 1024 * 1024
MAX_NODES = 300000               # nodes walked in one JSON or YAML tree
MAX_FLATTEN_DEPTH = 400          # deepest a JSON/state tree may nest before failing closed (well under the recursion limit)
MAX_DEPTH = 3                    # archive in archive
SNIFF = 96 * 1024
BUDGET = 4.0                     # seconds load() may take inside solve_set; cut evidence answers nothing


class Cut(Exception):
    """A limit was reached: the evidence is incomplete and nothing is answered from it."""


def _safe(v, limit=200) -> str:
    """A value for a terminal: control characters (escape sequences) are shown, never sent."""
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    s = "".join(c if c.isprintable() else "\\x%02x" % ord(c) if ord(c) < 256 else "?" for c in s)
    return s if len(s) <= limit else s[:limit] + "..."


def _get(d, *path):
    for p in path:
        if isinstance(d, dict):
            d = d.get(p)
        elif isinstance(d, list) and isinstance(p, int) and -len(d) <= p < len(d):
            d = d[p]
        else:
            return None
    return d


def _s(v):
    """A non-empty string, or None (numbers become strings; containers never do)."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def gunzip(data: bytes, limit: int = MAX_RAW) -> bytes:
    """Every member of a gzip stream, at most `limit` bytes (Cut beyond). A truncated or malformed
    stream fails closed with Cut, never a raw zlib.error or ValueError."""
    out, rest = [], data
    total = 0
    while rest[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            chunk = d.decompress(rest, limit - total + 1)
        except zlib.error as e:
            raise Cut("a gzip stream did not decompress") from e
        total += len(chunk)
        if total > limit or d.unconsumed_tail:
            raise Cut("a gzip stream is larger than the limit")
        out.append(chunk)
        if not d.eof:
            raise Cut("a gzip stream ended early")
        rest = d.unused_data
    return b"".join(out)


def _unzstd(data: bytes, limit: int = MAX_RAW) -> bytes:
    import zstandard
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))
    out = reader.read(limit + 1)
    if len(out) > limit:
        raise Cut("a zstd stream is larger than the limit")
    return out


def parse_time(v):
    """An aware datetime for an RFC 3339 time (a missing zone reads as UTC, as these logs write
    it), or for epoch seconds or milliseconds; None for anything else."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / 1000.0 if v > 1e11 else v, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?", str(v).strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    try:
        tz = UTC
        if zone and zone != "Z":
            sign = -1 if zone[0] == "-" else 1
            tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[-2:])))
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), int((frac or "0")[:6].ljust(6, "0")), tz)
    except ValueError:
        return None


def time_options(dt, raw=None, date_first=False) -> list:
    """The spellings of one moment, best first, as labels.pick options (the names are those of
    solvers/common/evidence_core.py: raw, iso_z, iso_offset, iso_space, epoch, epoch_ms)."""
    out = []
    if raw is not None and str(raw).strip():
        out.append(("raw", str(raw).strip()))
    if dt is not None:
        u = dt.astimezone(UTC)
        frac = f".{u.microsecond:06d}".rstrip("0") if u.microsecond else ""
        off = dt.strftime("%z") or "+0000"
        out += [("iso_z", u.strftime("%Y-%m-%dT%H:%M:%S") + frac + "Z"),
                ("iso_offset", dt.strftime("%Y-%m-%dT%H:%M:%S") + (f".{dt.microsecond:06d}".rstrip("0") if dt.microsecond else "")
                 + off[:3] + ":" + off[3:5]),
                ("iso_space", u.strftime("%Y-%m-%d %H:%M:%S")),
                ("epoch", str(int((u - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds()))),
                ("epoch_ms", str(int((u - datetime(1970, 1, 1, tzinfo=UTC)) / timedelta(milliseconds=1))))]
        if date_first:
            out.insert(0, ("date", u.strftime("%Y-%m-%d")))
    return out


# ---- operation dictionaries --------------------------------------------------------------------------
#
# name -> (class label in this event's style, sensitive). The labels are vocabulary for a lane agent
# (docs/toolkits/cloud_container.md); solve_set never answers one plain.

AWS_OPS = {
    "ConsoleLogin": ("console_login", False), "GetCallerIdentity": ("identity_check", False),
    "ListUsers": ("iam_enumeration", False), "ListRoles": ("iam_enumeration", False),
    "ListAttachedUserPolicies": ("iam_enumeration", False), "ListAccessKeys": ("iam_enumeration", False),
    "GetAccountAuthorizationDetails": ("iam_enumeration", False), "ListBuckets": ("bucket_enumeration", False),
    "ListObjects": ("bucket_enumeration", False), "ListObjectsV2": ("bucket_enumeration", False),
    "CreateUser": ("create_user", True), "CreateLoginProfile": ("create_login_profile", True),
    "UpdateLoginProfile": ("update_login_profile", True), "CreateAccessKey": ("create_access_key", True),
    "AttachUserPolicy": ("attach_user_policy", True), "AttachRolePolicy": ("attach_role_policy", True),
    "AttachGroupPolicy": ("attach_group_policy", True), "PutUserPolicy": ("put_user_policy", True),
    "PutRolePolicy": ("put_role_policy", True), "AddUserToGroup": ("add_user_to_group", True),
    "UpdateAssumeRolePolicy": ("update_trust_policy", True), "CreatePolicyVersion": ("create_policy_version", True),
    "AssumeRole": ("assume_role", False), "AssumeRoleWithSAML": ("assume_role", False),
    "AssumeRoleWithWebIdentity": ("assume_role", False), "GetSessionToken": ("session_token", False),
    "GetObject": ("object_read", False), "PutObject": ("object_write", False), "DeleteObject": ("object_delete", False),
    "DeleteObjects": ("object_delete", False), "PutBucketPolicy": ("bucket_policy_change", True),
    "PutBucketAcl": ("bucket_acl_change", True), "DeleteBucketPolicy": ("bucket_policy_change", True),
    "DeletePublicAccessBlock": ("public_access_block_removed", True), "PutPublicAccessBlock": ("public_access_block", False),
    "StopLogging": ("stop_logging", True), "DeleteTrail": ("delete_trail", True), "UpdateTrail": ("update_trail", True),
    "PutEventSelectors": ("update_trail", True), "DeleteFlowLogs": ("delete_flow_logs", True),
    "DeleteDetector": ("disable_guardduty", True), "RunInstances": ("run_instances", False),
    "AuthorizeSecurityGroupIngress": ("security_group_open", True), "CreateKeyPair": ("create_key_pair", False),
    "ModifyInstanceAttribute": ("modify_instance", False), "GetSecretValue": ("secret_read", False),
    "GetParameter": ("parameter_read", False), "GetPasswordData": ("password_data_read", True),
    "CreateFunction20150331": ("create_function", False), "UpdateFunctionCode20150331v2": ("update_function_code", True),
    "Decrypt": ("kms_decrypt", False), "ScheduleKeyDeletion": ("kms_key_deletion", True),
}
READ_OPS = {"getobject", "storage.objects.get"}
WRITE_OPS = {"putobject", "storage.objects.create"}
DELETE_OPS = {"deleteobject", "deleteobjects", "storage.objects.delete"}
K8S_SENSITIVE = ("pod_exec", "secret_read", "clusterrolebinding_create", "privileged_pod")

# A phrase of a question -> the operations it means (API semantics, stated here; applied only to
# operations the log holds).
OP_PHRASES = (
    (re.compile(r"\bconsole (?:log|sign)[\s-]?in\w*|\b(?:log(?:ged|s|ging)?|sign(?:ed|s|ing)?) in(?:to)? (?:to )?the (?:aws )?(?:management )?console"),
     {"consolelogin"}),
    (re.compile(r"\bassum\w*"), {"assumerole", "assumerolewithsaml", "assumerolewithwebidentity"}),
    (re.compile(r"\b(?:stop\w*|disabl\w*|turn\w* off) (?:the )?(?:cloudtrail )?(?:logging|trail)"), {"stoplogging"}),
    (re.compile(r"\battach\w*"), {"attachuserpolicy", "attachrolepolicy", "attachgrouppolicy"}),
    (re.compile(r"\bbucket policy\b"), {"putbucketpolicy"}),
    (re.compile(r"\bcreat\w* (?:an? |the |new |§ )*access keys?\b|\baccess keys? (?:was |were |that was )?creat\w*"), {"createaccesskey"}),
    (re.compile(r"\bcreat\w* (?:an? |the |new |backdoor |rogue )*(?:iam )?users?\b|\busers? (?:was |were |that was )creat\w*"), {"createuser"}),
    (re.compile(r"\b(?:launch\w*|spun up|r[au]n|start\w*) (?:an? |the |new )*(?:ec2 )?instances?"), {"runinstances"}),
)


# ---- logs: records -> events ---------------------------------------------------------------------------

def _unwrap(doc) -> list:
    """The records of one parsed document: CloudTrail {Records}, Azure {value} or {records}, a
    Kubernetes EventList {items}, GCP {entries}, a list, or the one record itself."""
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if isinstance(doc, dict):
        for k in ("Records", "records", "value", "items", "entries", "events", "logEntries"):
            if isinstance(doc.get(k), list) and doc[k] and all(isinstance(r, dict) for r in doc[k][:50]):
                return [r for r in doc[k] if isinstance(r, dict)]
        return [doc]
    return []


_ENTRA_CATEGORY = re.compile(r"signinlogs?$|^auditlogs$|^provisioninglogs$|^riskyusers$|^userriskevents$", re.I)


def _inner(rec):
    """The record itself, or the CloudTrail record inside a row of `aws cloudtrail lookup-events`
    ({"EventId", "EventName", "CloudTrailEvent": "<the record as a JSON string>"})."""
    if isinstance(rec, dict) and isinstance(rec.get("CloudTrailEvent"), str) and "EventName" in rec:
        try:
            inner = json.loads(rec["CloudTrailEvent"])
        except ValueError:
            return rec
        if isinstance(inner, dict) and "eventName" in inner:
            return inner
    return rec


def detect(rec: dict):
    """'cloudtrail', 'gcp_audit', 'azure_activity', 'k8s_audit' or None, from a record's own fields."""
    if not isinstance(rec, dict):
        return None
    rec = _inner(rec)
    if "operation_name" in rec and any(k in rec for k in ("caller", "resource_id", "subscription_id", "event_timestamp")):
        return "azure_activity"
    if "eventName" in rec and "eventSource" in rec and ("userIdentity" in rec or "eventVersion" in rec or "awsRegion" in rec):
        return "cloudtrail"
    if isinstance(rec.get("protoPayload"), dict) and ("methodName" in rec["protoPayload"] or "serviceName" in rec["protoPayload"]):
        return "gcp_audit"
    if "auditID" in rec and "verb" in rec and ("requestURI" in rec or "objectRef" in rec):
        return "k8s_audit"
    if str(rec.get("apiVersion") or "").startswith("audit.k8s.io") and "verb" in rec:
        return "k8s_audit"
    if "operationName" in rec and any(k in rec for k in ("caller", "callerIpAddress", "resourceId", "subscriptionId", "eventTimestamp")):
        # Azure Monitor wraps Entra sign-in and audit records in the same envelope (operationName,
        # callerIpAddress, resourceId): those are identity logs, solvers/toolkits/cloudlogs.py reads them
        if _ENTRA_CATEGORY.search(str(rec.get("category") or "")) or str(rec.get("resourceId") or "").lower().startswith("/tenants/"):
            return None
        return "azure_activity"
    return None


def load_records(data: bytes, name: str = "") -> tuple:
    """(records, problem) of one file: gzip is opened, a JSON document is unwrapped, JSON lines are
    read one by one. problem is None when every byte was read as records."""
    if not isinstance(data, (bytes, bytearray)):
        return [], "not bytes"
    try:
        if data[:2] == b"\x1f\x8b":
            data = gunzip(data, MAX_DOC)
    except Cut as e:
        return [], str(e)
    except (ValueError, zlib.error):
        return [], "gzip did not open"
    if len(data) > MAX_DOC:
        return [], "larger than the limit"
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return [], "not UTF-8"
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return [], "not JSON"
    try:
        return _unwrap(json.loads(stripped)), None
    except ValueError:
        pass
    recs, bad = [], 0
    for line in stripped.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            bad += 1
            continue
        recs.extend(_unwrap(doc))
    if not recs:
        return [], "not JSON"
    return recs, (f"{bad} lines did not parse" if bad else None)


def role_name(arn):
    """The role's name out of a role ARN or an assumed-role ARN (the last path segment of a role)."""
    m = re.match(r"arn:[\w-]+:(?:iam|sts)::\d*:(?:role|assumed-role)/(.+)$", str(arn or ""))
    if not m:
        return None
    parts = m.group(1).split("/")
    return parts[0] if ":assumed-role/" in str(arn) else parts[-1]


def _pod_spec(obj):
    """The pod spec inside a Kubernetes object (a Pod, or a workload's template), or None."""
    for path in (("spec", "jobTemplate", "spec", "template", "spec"), ("spec", "template", "spec"), ("spec",)):
        spec = _get(obj, *path)
        if isinstance(spec, dict) and isinstance(spec.get("containers"), list):
            return spec
    return None


def _containers(spec) -> list:
    out = []
    for k in ("initContainers", "containers", "ephemeralContainers"):
        for c in (spec.get(k) or []) if isinstance(spec, dict) else []:
            if isinstance(c, dict):
                out.append(c)
    return out


def _blank(src, n, fname, rec) -> dict:
    return {"src": src, "n": n, "file": fname, "raw": rec, "time": None, "dt": None, "op": "", "op_short": "", "service": None,
            "actor": None, "actor_logged": False, "actor_arn": None, "actor_type": None, "session_name": None, "account": None,
            "key": None, "ip": None, "ips": [], "ua": None, "region": None, "error": None, "failed": False, "target_user": None,
            "new_key": None, "issued_key": None, "role_arn": None, "session_arn": None, "policy_arn": None, "policy_name": None,
            "bucket": None, "object": None, "mfa": None, "instance_ids": [], "instance_type": None, "ami": None, "trail": None,
            "verb": None, "resource": None, "subresource": None, "ns": None, "name": None, "sa": False, "sa_ns": None,
            "sa_name": None, "images": [], "privileged": False, "command": None, "roleref": None, "subjects": [],
            "stage": None, "audit_id": None, "sensitive": None, "new_user": None, "role_session": None, "new_user_arn": None}


def normalize(rec: dict, n: int = 0, fname: str = "", src: str = None):
    """One record as an event (the keys of _blank), or None for a record of no known source."""
    src = src or detect(rec)
    if src is None:
        return None
    rec = _inner(rec)
    e = _blank(src, n, fname, rec)
    if src == "cloudtrail":
        ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
        rp = rec.get("requestParameters") if isinstance(rec.get("requestParameters"), dict) else {}
        rs = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
        e.update(time=_s(rec.get("eventTime")) or _s(rec.get("@timestamp")), op=_s(rec.get("eventName")) or "", service=_s(rec.get("eventSource")),
                 actor_type=_s(ui.get("type")), actor_arn=_s(ui.get("arn")), account=_s(ui.get("accountId")) or _s(rec.get("recipientAccountId")),
                 key=_s(ui.get("accessKeyId")), ip=_s(rec.get("sourceIPAddress")), ua=_s(rec.get("userAgent")),
                 region=_s(rec.get("awsRegion")), error=_s(rec.get("errorCode")), mfa=_s(_get(rec, "additionalEventData", "MFAUsed")))
        e["audit_id"] = _s(rec.get("eventID"))
        if _s(ui.get("userName")):
            e.update(actor=_s(ui.get("userName")), actor_logged=True)
        elif e["actor_type"] == "AssumedRole":
            e["actor"] = _s(_get(ui, "sessionContext", "sessionIssuer", "userName")) or role_name(e["actor_arn"])
            m = re.search(r":assumed-role/[^/]+/(.+)$", e["actor_arn"] or "")
            e["session_name"] = m.group(1) if m else None
        elif e["actor_type"] == "AWSService":
            e["actor"] = _s(ui.get("invokedBy"))
        e["failed"] = bool(e["error"]) or _s(rs.get("ConsoleLogin")) == "Failure"
        e["target_user"] = _s(rp.get("userName"))
        e["new_key"] = _s(_get(rs, "accessKey", "accessKeyId"))
        if e["new_key"] and not e["target_user"]:
            e["target_user"] = _s(_get(rs, "accessKey", "userName"))     # a key made with no userName is the caller's own
        e["issued_key"] = _s(_get(rs, "credentials", "accessKeyId"))
        e["role_arn"] = _s(rp.get("roleArn")) if e["op"].startswith("AssumeRole") else None
        e["session_arn"] = _s(_get(rs, "assumedRoleUser", "arn"))
        e["role_session"] = _s(rp.get("roleSessionName")) if e["op"].startswith("AssumeRole") else None
        e["policy_arn"] = _s(rp.get("policyArn"))
        e["policy_name"] = _s(rp.get("policyName")) or (e["policy_arn"].rsplit("/", 1)[-1] if e["policy_arn"] else None)
        e["bucket"] = _s(rp.get("bucketName"))
        e["object"] = _s(rp.get("key"))
        e["trail"] = _s(rp.get("name")) if e["op"] in ("StopLogging", "DeleteTrail", "UpdateTrail", "StartLogging") else None
        if e["op"] == "CreateUser":
            e["new_user"] = _s(_get(rs, "user", "userName")) or e["target_user"]
            e["new_user_arn"] = _s(_get(rs, "user", "arn"))
        if e["op"] == "RunInstances":
            e["instance_ids"] = [i for i in (_s(_get(it, "instanceId")) for it in (_get(rs, "instancesSet", "items") or [])
                                             if isinstance(it, dict)) if i]
            e["instance_type"] = _s(rp.get("instanceType"))
            e["ami"] = _s(_get(rp, "instancesSet", "items", 0, "imageId")) or _s(rp.get("imageId"))
        if AWS_OPS.get(e["op"], ("", False))[1]:
            e["sensitive"] = AWS_OPS[e["op"]][0]
    elif src == "gcp_audit":
        pp = rec["protoPayload"]
        e.update(time=_s(rec.get("timestamp")) or _s(rec.get("receiveTimestamp")), op=_s(pp.get("methodName")) or "",
                 service=_s(pp.get("serviceName")), actor=_s(_get(pp, "authenticationInfo", "principalEmail")),
                 ip=_s(_get(pp, "requestMetadata", "callerIp")), ua=_s(_get(pp, "requestMetadata", "callerSuppliedUserAgent")),
                 account=_s(_get(rec, "resource", "labels", "project_id")), name=_s(pp.get("resourceName")))
        e["actor_logged"] = e["actor"] is not None
        code = _get(pp, "status", "code")
        e["error"] = _s(_get(pp, "status", "message")) if code not in (None, 0) else None
        e["failed"] = code not in (None, 0) or str(rec.get("severity") or "").upper() == "ERROR"
        m = re.search(r"buckets/([^/]+)(?:/objects/(.+))?$", e["name"] or "")
        if m:
            e["bucket"], e["object"] = m.group(1), m.group(2)
        e["sa"] = bool(e["actor"] and e["actor"].endswith(".gserviceaccount.com"))
    elif src == "azure_activity":
        op = rec.get("operationName") or rec.get("operation_name")
        op = _s(op.get("value")) if isinstance(op, dict) else _s(op)
        status = rec.get("status")
        status = _s(status.get("value")) if isinstance(status, dict) else _s(status)
        e.update(time=_s(rec.get("eventTimestamp")) or _s(rec.get("event_timestamp")) or _s(rec.get("time")), op=op or "",
                 actor=_s(rec.get("caller")) or _s(_get(rec, "identity", "claims", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")),
                 ip=_s(rec.get("callerIpAddress")) or _s(_get(rec, "httpRequest", "clientIpAddress"))
                 or _s(_get(rec, "http_request", "client_ip_address")),
                 name=_s(rec.get("resourceId")) or _s(rec.get("resource_id")),
                 account=_s(rec.get("subscriptionId")) or _s(rec.get("subscription_id")), region=_s(rec.get("location")))
        e["audit_id"] = _s(rec.get("event_data_id")) or _s(rec.get("eventDataId"))
        e["actor_logged"] = e["actor"] is not None
        e["failed"] = (status or _s(rec.get("resultType")) or "").lower() in ("failed", "failure")
        e["error"] = status if e["failed"] else None
    else:   # k8s_audit
        ref = rec.get("objectRef") if isinstance(rec.get("objectRef"), dict) else {}
        user = _s(_get(rec, "user", "username"))
        code = _get(rec, "responseStatus", "code")
        e.update(time=_s(rec.get("requestReceivedTimestamp")) or _s(rec.get("stageTimestamp")) or _s(rec.get("timestamp")),
                 verb=_s(rec.get("verb")), resource=_s(ref.get("resource")), subresource=_s(ref.get("subresource")),
                 ns=_s(ref.get("namespace")), name=_s(ref.get("name")), actor=user, actor_logged=user is not None,
                 ua=_s(rec.get("userAgent")), stage=_s(rec.get("stage")), audit_id=_s(rec.get("auditID")))
        e["ips"] = [i for i in (_s(x) for x in (rec.get("sourceIPs") or []) if not isinstance(x, (dict, list))) if i]
        e["ip"] = e["ips"][0] if len(e["ips"]) == 1 else None
        e["op"] = " ".join(x for x in (e["verb"], "/".join(x for x in (e["resource"], e["subresource"]) if x)) if x)
        e["failed"] = isinstance(code, int) and code >= 400
        e["error"] = str(code) if e["failed"] else None
        m = re.fullmatch(r"system:serviceaccount:([^:]+):([^:]+)", user or "")
        if m:
            e.update(sa=True, sa_ns=m.group(1), sa_name=m.group(2))
        obj = rec.get("requestObject") if isinstance(rec.get("requestObject"), dict) else {}
        if not e["name"]:
            e["name"] = _s(_get(obj, "metadata", "name"))
        spec = _pod_spec(obj)
        if spec:
            cs = _containers(spec)
            e["images"] = [i for i in (_s(c.get("image")) for c in cs) if i]
            e["privileged"] = any(_get(c, "securityContext", "privileged") is True for c in cs)
        if e["resource"] == "pods" and e["subresource"] == "exec":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(str(rec.get("requestURI") or "")).query)
            e["command"] = qs.get("command") or None
        if e["resource"] in ("clusterrolebindings", "rolebindings"):
            e["roleref"] = _s(_get(obj, "roleRef", "name"))
            e["subjects"] = [n for n in (_s(_get(s, "name")) for s in (obj.get("subjects") or []) if isinstance(s, dict)) if n]
        if e["resource"] == "pods" and e["subresource"] == "exec":
            e["sensitive"] = "pod_exec"
        elif e["resource"] == "secrets" and e["verb"] in ("get", "list", "watch"):
            e["sensitive"] = "secret_read"
        elif e["resource"] == "clusterrolebindings" and e["verb"] == "create":
            e["sensitive"] = "clusterrolebinding_create"
        elif e["privileged"] and e["verb"] == "create":
            e["sensitive"] = "privileged_pod"
    e["dt"] = parse_time(e["time"])
    e["op_short"] = re.split(r"[./]", e["op"])[-1] if src in ("gcp_audit",) else e["op"]
    if e["ip"] and not e["ips"]:
        e["ips"] = [e["ip"]]
    vals = set()
    for k in ("actor", "actor_arn", "session_name", "account", "key", "ua", "region", "target_user", "new_key", "issued_key", "role_arn",
              "session_arn", "policy_arn", "policy_name", "bucket", "object", "trail", "verb", "resource", "ns", "name", "sa_name",
              "roleref", "new_user", "instance_type", "ami", "service"):
        if e[k]:
            vals.add(str(e[k]).lower())
    for k in ("ips", "instance_ids", "images", "subjects"):
        vals.update(str(v).lower() for v in e[k])
    if e["role_arn"] and role_name(e["role_arn"]):
        vals.add(role_name(e["role_arn"]).lower())
    e["vals"] = vals
    e["actor_vals"] = {str(v).lower() for v in [e["actor"], e["actor_arn"], e["session_name"], e["key"], e["sa_name"]] + e["ips"] if v}
    obj = set()
    for k in ("target_user", "new_key", "issued_key", "role_arn", "session_arn", "policy_arn", "policy_name", "bucket", "object",
              "trail", "ns", "name", "roleref", "new_user", "instance_type", "ami"):
        if e[k]:
            obj.add(str(e[k]).lower())
    for k in ("instance_ids", "images", "subjects"):
        obj.update(str(v).lower() for v in e[k])
    if e["role_arn"] and role_name(e["role_arn"]):
        obj.add(role_name(e["role_arn"]).lower())
    e["obj_vals"] = obj
    return e


# ---- logs: the queries -----------------------------------------------------------------------------------

def _is_address(v) -> bool:
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def _is_op(e, ops) -> bool:
    return e["op"].lower() in ops or e["op_short"].lower() in ops


def _distinct(events, key) -> list:
    """The distinct non-empty values of one event key, in first-seen order (a list key is flattened)."""
    out = []
    for e in events:
        v = e.get(key)
        for x in (v if isinstance(v, list) else [v]):
            if x not in (None, "", False) and x not in out:
                out.append(x)
    return out


def access_keys_used(events) -> dict:
    """{access key id: {'events': n, 'actors': [...], 'ips': [...], 'ops': [...]}} of the keys requests were signed with."""
    out = OrderedDict()
    for e in events:
        if e["key"]:
            row = out.setdefault(e["key"], {"events": 0, "actors": [], "ips": [], "ops": []})
            row["events"] += 1
            for k, v in (("actors", e["actor_arn"] or e["actor"]), ("ips", e["ip"]), ("ops", e["op"])):
                if v and v not in row[k]:
                    row[k].append(v)
    return out


def access_keys_created(events) -> list:
    """[{key, for_user, by, by_arn, ip, time}] of every CreateAccessKey that returned a key."""
    return [{"key": e["new_key"], "for_user": e["target_user"] or e["actor"], "by": e["actor"], "by_arn": e["actor_arn"],
             "ip": e["ip"], "time": e["time"]} for e in events if e["new_key"]]


def assumed_roles(events) -> list:
    """[{role_arn, role, session_arn, by, by_arn, ip, time, failed}] of every AssumeRole* call."""
    return [{"role_arn": e["role_arn"], "role": role_name(e["role_arn"]), "session_arn": e["session_arn"], "by": e["actor"],
             "by_arn": e["actor_arn"], "ip": e["ip"], "time": e["time"], "failed": e["failed"]} for e in events if e["role_arn"]]


def source_ips_by_principal(events) -> dict:
    """{principal (its ARN, else its name): [source IP, ...]} in first-seen order."""
    out = OrderedDict()
    for e in events:
        who = e["actor_arn"] or e["actor"]
        if who:
            row = out.setdefault(who, [])
            for ip in e["ips"]:
                if ip not in row:
                    row.append(ip)
    return out


def first_event(events, op=None, last=False):
    """The earliest (or latest) event, of one operation when `op` is given (its name, any case; a
    GCP method also by its last segment). None when there is none or a time does not parse; the
    list of events when several share that time."""
    sel = [e for e in events if op is None or op.lower() in (e["op"].lower(), e["op_short"].lower())]
    if not sel or any(e["dt"] is None for e in sel):
        return None
    t = (max if last else min)(e["dt"] for e in sel)
    edge = [e for e in sel if e["dt"] == t]
    return edge[0] if len(edge) == 1 else edge


def object_reads(events) -> list:
    """[{bucket, object, by, ip, key, time}] of every object read (GetObject, storage.objects.get)."""
    return [{"bucket": e["bucket"], "object": e["object"], "by": e["actor_arn"] or e["actor"], "ip": e["ip"], "key": e["key"],
             "time": e["time"]} for e in events if _is_op(e, READ_OPS) and e["bucket"]]


def pod_execs(events) -> list:
    return [{"pod": e["name"], "ns": e["ns"], "by": e["actor"], "command": e["command"], "ips": e["ips"], "time": e["time"]}
            for e in events if e["sensitive"] == "pod_exec"]


def secret_reads(events) -> list:
    return [{"secret": e["name"], "ns": e["ns"], "verb": e["verb"], "by": e["actor"], "ips": e["ips"], "time": e["time"]}
            for e in events if e["sensitive"] == "secret_read"]


def privileged_pods(events) -> list:
    return [{"pod": e["name"], "ns": e["ns"], "images": e["images"], "by": e["actor"], "time": e["time"]}
            for e in events if e["privileged"] and e["verb"] == "create"]


def cluster_role_bindings(events) -> list:
    return [{"binding": e["name"], "role": e["roleref"], "subjects": e["subjects"], "by": e["actor"], "time": e["time"]}
            for e in events if e["resource"] == "clusterrolebindings" and e["verb"] == "create"]


def sensitive_events(events) -> list:
    return [e for e in events if e["sensitive"]]


def suspects(events) -> dict:
    """{rule: [source IP, ...]}: the stated rules a 'malicious' selection is made by. Each rule names
    source IPs; a rule that does not fire is absent.

      sensitive_ops               the IPs behind an operation the dictionaries mark sensitive
      console_login_without_mfa   a successful ConsoleLogin with MFAUsed 'No'
      success_after_failures      three or more failed requests from an IP, then a successful one
      most_denied                 the IP with strictly the most failed requests (three at least)
    """
    out = OrderedDict()
    hit = _distinct([e for e in events if e["sensitive"]], "ips")
    if hit:
        out["sensitive_ops"] = hit
    hit = _distinct([e for e in events if e["op"] == "ConsoleLogin" and not e["failed"] and (e["mfa"] or "").lower() == "no"], "ips")
    if hit:
        out["console_login_without_mfa"] = hit
    fails, after = Counter(), []
    ordered = sorted((e for e in events if e["dt"] is not None), key=lambda e: e["dt"])
    for e in ordered:
        for ip in e["ips"]:
            if e["failed"]:
                fails[ip] += 1
            elif fails[ip] >= 3 and ip not in after:
                after.append(ip)
    if after:
        out["success_after_failures"] = after
    denied = Counter(ip for e in events if e["failed"] for ip in e["ips"]).most_common(2)
    if denied and denied[0][1] >= 3 and (len(denied) == 1 or denied[0][1] > denied[1][1]):
        out["most_denied"] = [denied[0][0]]
    return out


# ---- tar, in memory -----------------------------------------------------------------------------------

def norm_path(name: str) -> tuple:
    """(path with no leading './' or '/', unsafe): unsafe when a '..' segment is in it. A path is
    only ever a dictionary key here; nothing is written."""
    parts = [p for p in str(name).split("/") if p not in ("", ".")]
    return "/".join(parts), ".." in parts


class Entry:
    __slots__ = ("path", "kind", "size", "mode", "link", "data", "sha256", "unsafe")

    def __init__(self, path, kind, size, mode, link, data, sha256, unsafe):
        self.path, self.kind, self.size, self.mode, self.link, self.data, self.sha256, self.unsafe = \
            path, kind, size, mode, link, data, sha256, unsafe

    def digest(self, algo: str):
        if algo == "sha256":
            return self.sha256
        return hashlib.new(algo, self.data).hexdigest() if self.data is not None else None


class _Meter:
    """The bytes one load() has read out of tars, and its deadline."""

    def __init__(self, deadline=None, limit=MAX_TOTAL):
        self.total, self.deadline, self.limit = 0, deadline, limit

    def take(self, n):
        self.total += n
        if self.total > self.limit:
            raise Cut("more than the limit was read out of archives")
        if self.deadline is not None and _time.monotonic() > self.deadline:
            raise Cut("the time budget ran out")


def is_tar(data: bytes) -> bool:
    return len(data) >= 512 and data[257:262] == b"ustar"


def read_tar(data: bytes, keep: int = KEEP_FILE, meter=None) -> tuple:
    """(OrderedDict path -> Entry, problems) of one uncompressed tar, in memory. A later member of
    the same path replaces an earlier one, as extraction would. File bytes are kept up to `keep`;
    a larger file has its size and SHA-256 only, and one above MAX_FILE its size only."""
    meter = meter or _Meter()
    entries, problems = OrderedDict(), []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as e:
        raise Cut(f"a tar did not open ({type(e).__name__})") from e
    try:
        with tf:
            for n, m in enumerate(tf):
                if n >= MAX_MEMBERS:
                    raise Cut("a tar has more members than the limit")
                path, unsafe = norm_path(m.name)
                if unsafe:
                    problems.append(f"unsafe path {_safe(m.name, 80)}")
                kind = ("file" if m.isreg() else "dir" if m.isdir() else "symlink" if m.issym() else "hardlink" if m.islnk() else "other")
                body, digest = None, None
                if kind == "file":
                    if m.size > MAX_FILE:
                        problems.append(f"{_safe(path, 80)} is larger than the limit and was not read")
                    else:
                        meter.take(m.size)
                        f = tf.extractfile(m)
                        body = f.read(MAX_FILE + 1) if f is not None else b""
                        digest = hashlib.sha256(body).hexdigest()
                        if len(body) > keep:
                            body = None
                if not path:
                    continue
                entries.pop(path, None)
                entries[path] = Entry(path, kind, m.size, m.mode, m.linkname or None, body, digest, unsafe)
    except tarfile.TarError as e:
        raise Cut(f"a tar is malformed ({type(e).__name__})") from e
    return entries, problems


# ---- images ----------------------------------------------------------------------------------------------

WH = ".wh."
OPAQUE = ".wh..wh..opq"


class Layer:
    """One layer: its file list and what it removes. digest names: `declared_digest` is what the
    manifest calls the blob, `declared_diff_id` what the config lists; `blob_sha256` and
    `tar_sha256` are computed here from the stored and the uncompressed bytes."""

    def __init__(self, index, ref):
        self.index, self.ref = index, ref
        self.declared_digest = self.declared_diff_id = self.blob_sha256 = self.tar_sha256 = self.layer_id = None
        self.media = self.created_by = self.created = None
        self.size = 0
        self.entries = OrderedDict()
        self.whiteouts, self.opaque, self.problems = [], [], []

    def digest_options(self) -> list:
        """The spellings of 'this layer's digest', best first; every one is a (method, value) pair."""
        seen, out = set(), []
        for name, v in (("manifest_digest", self.declared_digest), ("diff_id", self.declared_diff_id),
                        ("blob_sha256", self.blob_sha256), ("tar_sha256", self.tar_sha256)):
            for nm, val in ((name, v), (name + "_hex", v.split(":", 1)[-1] if v else None)):
                if val and val not in seen:
                    seen.add(val)
                    out.append((nm, val))
        if self.layer_id and self.layer_id not in seen:
            out.append(("layer_id", self.layer_id))
        return out

    def removes(self, path: str) -> bool:
        return path in self.whiteouts or any(path == d or path.startswith(d + "/") for d in self.whiteouts) \
            or any((path.startswith(d + "/") if d else True) and path not in self.entries for d in self.opaque)


class Image:
    def __init__(self, origin, layout):
        self.origin, self.layout = origin, layout       # layout: 'docker_save' or 'oci'
        self.config, self.config_digest, self.manifest_digest = {}, None, None
        self.tags, self.layers, self.problems = [], [], []

    @property
    def cfg(self) -> dict:
        c = self.config.get("config") or self.config.get("Config") or self.config.get("container_config") or {}
        return c if isinstance(c, dict) else {}

    @property
    def env(self) -> OrderedDict:
        out = OrderedDict()
        for item in self.cfg.get("Env") or []:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
        return out

    @property
    def entrypoint(self):
        v = self.cfg.get("Entrypoint")
        return [str(x) for x in v] if isinstance(v, list) and v else None

    @property
    def cmd(self):
        v = self.cfg.get("Cmd")
        return [str(x) for x in v] if isinstance(v, list) and v else None

    @property
    def history(self) -> list:
        h = self.config.get("history")
        return [x for x in h if isinstance(x, dict)] if isinstance(h, list) else []

    @property
    def cut(self) -> bool:
        return bool(self.problems) or any(L.problems for L in self.layers)


def _blob(store: dict, digest: str):
    alg, _, hexd = str(digest).partition(":")
    return store.get(f"blobs/{alg}/{hexd}")


def read_layer(blob: bytes, index: int, ref: str, meter=None) -> Layer:
    """A layer from its stored bytes (tar, tar+gzip or tar+zstd), read in memory."""
    L = Layer(index, ref)
    L.size = len(blob)
    L.blob_sha256 = "sha256:" + hashlib.sha256(blob).hexdigest()
    try:
        if blob[:2] == b"\x1f\x8b":
            raw = gunzip(blob)
        elif blob[:4] == b"\x28\xb5\x2f\xfd":
            raw = _unzstd(blob)
        else:
            raw = blob
        L.tar_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
        entries, problems = read_tar(raw, meter=meter)
    except Cut as e:             # a resource-limit cut fails the load; a malformed stream is a layer problem
        if _is_limit_cut(e):
            raise
        L.problems.append(f"layer {index} did not open ({e})")
        return L
    except Exception as e:       # a layer that does not open is a problem of the image, never an answer
        L.problems.append(f"layer {index} did not open ({type(e).__name__})")
        return L
    L.problems += [p for p in problems if "larger than the limit" in p]
    for path, en in entries.items():
        base = path.rsplit("/", 1)[-1]
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        if base == OPAQUE:
            L.opaque.append(parent)
        elif base.startswith(WH):
            L.whiteouts.append((parent + "/" if parent else "") + base[len(WH):])
        else:
            L.entries[path] = en
    return L


def read_image(store: dict, origin: str = "", meter=None) -> list:
    """[Image] of a `docker save` tar or an OCI layout given as {path: bytes} (read_tar's entries
    work too). An image whose manifest, config or a layer is missing carries the problem."""
    store = {p: (v.data if isinstance(v, Entry) else v) for p, v in store.items()}
    store = {p: v for p, v in store.items() if isinstance(v, (bytes, bytearray))}
    images = []

    def build(layout, config_bytes, layer_refs, tags, manifest_digest=None):
        im = Image(origin, layout)
        im.tags = [str(t) for t in (tags or []) if isinstance(t, str)]
        im.manifest_digest = manifest_digest
        if config_bytes is None:
            im.problems.append("the config is missing")
        else:
            im.config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
            try:
                cfg = json.loads(config_bytes.decode("utf-8-sig"))
                im.config = cfg if isinstance(cfg, dict) else {}
            except (ValueError, UnicodeDecodeError):
                im.problems.append("the config is not JSON")
        diff_ids = _get(im.config, "rootfs", "diff_ids") or []
        for i, (ref, declared, media) in enumerate(layer_refs):
            blob = store.get(ref)
            if blob is None:
                im.problems.append(f"layer {i} ({_safe(ref, 80)}) is missing")
                L = Layer(i, ref)
            else:
                L = read_layer(blob, i, ref, meter)
            L.declared_digest, L.media = declared, media
            L.declared_diff_id = _s(diff_ids[i]) if i < len(diff_ids) else None
            m = re.fullmatch(r"([0-9a-f]{64})/layer\.tar", ref)
            L.layer_id = m.group(1) if m else None
            im.layers.append(L)
        real = [h for h in im.history if not h.get("empty_layer")]
        if len(real) == len(im.layers):
            for h, L in zip(real, im.layers):
                L.created_by, L.created = _s(h.get("created_by")), _s(h.get("created"))
        images.append(im)

    def blob_ref(path):
        m = re.fullmatch(r"blobs/(\w+)/([0-9a-f]+)", path)
        return f"{m.group(1)}:{m.group(2)}" if m else None

    if "manifest.json" in store:
        try:
            man = json.loads(store["manifest.json"].decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            man = None
        if isinstance(man, list) and man and all(isinstance(x, dict) and "Layers" in x for x in man):
            for x in man:
                layers = x.get("Layers")
                refs = [(str(p), blob_ref(str(p)), None) for p in (layers if isinstance(layers, list) else [])]
                build("docker_save", store.get(str(x.get("Config"))), refs, x.get("RepoTags"))
            return images
    if "index.json" in store and ("oci-layout" in store or any(p.startswith("blobs/") for p in store)):
        def walk(desc, depth, tags):
            raw = _blob(store, desc.get("digest", "")) if isinstance(desc, dict) else None
            if raw is None or depth > 3:
                im = Image(origin, "oci")
                im.problems.append("a manifest blob is missing")
                images.append(im)
                return
            try:
                doc = json.loads(raw.decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError):
                return
            if not isinstance(doc, dict):
                return
            ref = _s(_get(desc, "annotations", "org.opencontainers.image.ref.name")) or _s(_get(desc, "annotations", "io.containerd.image.name"))
            tags = [ref] if ref else tags
            if isinstance(doc.get("manifests"), list):
                for d in doc["manifests"]:
                    walk(d, depth + 1, tags)
            elif isinstance(doc.get("layers"), list):
                refs = []
                for l in doc["layers"]:
                    dg = _s(_get(l, "digest")) or ""
                    alg, _, hexd = dg.partition(":")
                    refs.append((f"blobs/{alg}/{hexd}", dg, _s(_get(l, "mediaType"))))
                build("oci", _blob(store, _get(doc, "config", "digest") or ""), refs, tags, desc.get("digest"))
        try:
            index = json.loads(store["index.json"].decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            index = {}
        for d in (index.get("manifests") or []) if isinstance(index, dict) else []:
            walk(d, 0, [])
    return images


def find_path(image: Image, path: str) -> list:
    """Every layer that touches a path: [{'layer': Layer, 'action': 'add' | 'modify' | 'delete',
    'entry': Entry or None}], bottom layer first. 'delete' is a whiteout of the path, of a
    directory above it, or an opaque directory above it."""
    path, _ = norm_path(path)
    out, present = [], False
    for L in image.layers:
        if path in L.entries:
            out.append({"layer": L, "action": "modify" if present else "add", "entry": L.entries[path]})
            present = True
        elif present and L.removes(path):
            out.append({"layer": L, "action": "delete", "entry": None})
            present = False
    return out


def final_listing(image: Image) -> OrderedDict:
    """path -> (Entry, Layer) of the image as it runs: the layers applied in order."""
    fs = OrderedDict()
    for L in image.layers:
        for p in [p for p in fs if L.removes(p)]:
            del fs[p]
        for p, en in L.entries.items():
            fs.pop(p, None)
            fs[p] = (en, L)
    return fs


def deleted_files(image: Image, include_recreated: bool = False) -> list:
    """Regular files a lower layer holds and the final image does not: [{'path', 'entry' (its last
    content), 'added': Layer, 'deleted': Layer}]. A path a later layer recreates is present in the
    final image and is left out by default; include_recreated=True lists it too (with
    'recreated': True), since its deleted content is still layer history."""
    out, live = [], OrderedDict()
    for L in image.layers:
        for p in [p for p in live if L.removes(p)]:
            en, added = live.pop(p)
            if en.kind == "file" and p not in L.entries:
                out.append({"path": p, "entry": en, "added": added, "deleted": L})
        for p, en in L.entries.items():
            live[p] = (en, live[p][1] if p in live else L)
    final = final_listing(image)       # a path a later layer recreates is present in the final image, not deleted
    if include_recreated:
        return [dict(row, recreated=row["path"] in final) for row in out]
    return [row for row in out if row["path"] not in final]


# ---- Dockerfile, Compose, Kubernetes manifests ------------------------------------------------------------

DOCKER_INSTR = ("FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER",
                "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL")
_SECRET_NAME = re.compile(r"pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|connection[_-]?string|"
                          r"auth", re.I)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>|;)]+")


def looks_like_dockerfile(text: str, name: str = "") -> bool:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    named = base.startswith(("dockerfile", "containerfile")) or base.endswith((".dockerfile", ".containerfile"))
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines or not re.match(r"(?:FROM|ARG)\s+\S", lines[0]):
        return False
    more = sum(1 for l in lines[1:] if re.match(r"(?:RUN|COPY|ADD|CMD|ENTRYPOINT|ENV|WORKDIR|EXPOSE|USER|FROM)\s", l))
    return any(re.match(r"FROM\s+\S", l) for l in lines) and (named or more >= 1)


def _kv_pairs(rest: str) -> list:
    """ENV, ARG and LABEL arguments: 'K=V K2="v 2"' or the old 'K V' form."""
    import shlex
    if not re.match(r"\s*[\w.-]+\s*=", rest):
        k, _, v = rest.strip().partition(" ")
        return [(k, v.strip())] if k else []
    try:
        parts = shlex.split(rest, posix=True)
    except ValueError:
        return []
    return [tuple(p.split("=", 1)) for p in parts if "=" in p]


def parse_dockerfile(text: str) -> dict:
    """{'instructions': [(line number, NAME, argument text)], 'stages': [{'base', 'name', 'env',
    'arg', 'labels', 'entrypoint', 'cmd', 'user', 'workdir', 'expose', 'copies', 'runs'}]}. An
    exec-form ENTRYPOINT or CMD is a list, a shell form a string."""
    if not isinstance(text, str):
        return {"instructions": [], "stages": []}
    instr, buf, start = [], "", 0
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if buf and s.startswith("#"):
            continue
        if not buf:
            start = n
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        m = re.match(r"([A-Za-z]+)\s*(.*)$", buf, re.S)
        if m and m.group(1).upper() in DOCKER_INSTR:
            instr.append((start, m.group(1).upper(), m.group(2).strip()))
        buf = ""
    stages = []

    def form(arg):
        if arg.startswith("["):
            try:
                v = json.loads(arg)
                if isinstance(v, list) and all(isinstance(x, str) for x in v):
                    return v
            except ValueError:
                pass
        return arg

    for _, name, arg in instr:
        if name == "FROM":
            m = re.match(r"(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", arg)
            stages.append({"base": m.group(1) if m else arg, "name": m.group(2) if m else None, "env": OrderedDict(),
                           "arg": OrderedDict(), "labels": OrderedDict(), "entrypoint": None, "cmd": None, "user": None,
                           "workdir": None, "expose": [], "copies": [], "runs": []})
            continue
        if not stages:
            continue
        st = stages[-1]
        if name in ("ENV", "LABEL"):
            st["env" if name == "ENV" else "labels"].update(_kv_pairs(arg))
        elif name == "ARG":
            k, _, v = arg.partition("=")
            st["arg"][k.strip()] = v.strip().strip("\"'") if _ else None
        elif name in ("ENTRYPOINT", "CMD"):
            st[name.lower()] = form(arg)
        elif name in ("USER", "WORKDIR"):
            st[name.lower()] = arg
        elif name == "EXPOSE":
            st["expose"] += arg.split()
        elif name in ("COPY", "ADD"):
            st["copies"].append(arg)
        elif name == "RUN":
            st["runs"].append(arg)
    return {"instructions": instr, "stages": stages}


def _yaml_docs(text: str) -> list:
    """The documents of a YAML text through yaml.safe_load_all; [] when PyYAML is missing, the
    text is too large, it leans on aliases (an expansion bomb), or it does not parse."""
    if yaml is None or len(text) > MAX_YAML or len(re.findall(r"(?<![\w*])\*[A-Za-z_]\w*", text)) > 64:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, (dict, list))]
    except Exception:
        return []


def _env_map(v) -> OrderedDict:
    out = OrderedDict()
    if isinstance(v, dict):
        for k, val in v.items():
            out[str(k)] = None if val is None else str(val)
    elif isinstance(v, list):
        for item in v:
            if isinstance(item, str):
                k, sep, val = item.partition("=")
                out[k] = val if sep else None
            elif isinstance(item, dict) and _s(item.get("name")):
                out[str(item["name"])] = None if item.get("value") is None else str(item["value"])
    return out


def read_compose(doc: dict) -> list:
    """[{service, image, env, ports, volumes, privileged, entrypoint, command, user, cap_add,
    network_mode, pid}] of a Compose document (a dict with `services`)."""
    out = []
    for name, s in (doc.get("services") or {}).items() if isinstance(doc.get("services"), dict) else []:
        if not isinstance(s, dict):
            continue
        out.append({"service": str(name), "image": _s(s.get("image")), "env": _env_map(s.get("environment")),
                    "ports": [str(p) for p in (s.get("ports") if isinstance(s.get("ports"), list) else []) if not isinstance(p, (dict, list))],
                    "volumes": [str(v) for v in (s.get("volumes") if isinstance(s.get("volumes"), list) else []) if not isinstance(v, (dict, list))],
                    "privileged": s.get("privileged") is True, "entrypoint": s.get("entrypoint"), "command": s.get("command"),
                    "user": _s(s.get("user")), "cap_add": [str(c) for c in (s.get("cap_add") if isinstance(s.get("cap_add"), list) else [])],
                    "network_mode": _s(s.get("network_mode")), "pid": _s(s.get("pid"))})
    return out


def read_k8s_manifests(docs) -> list:
    """[{kind, name, ns, containers: [{name, image, env, privileged, command, args}], host_paths,
    service_account, host_network, host_pid, secret: {key: (base64 text, decoded text or None)},
    roleref, subjects}] of Kubernetes objects (a `List` is unwrapped)."""
    out, queue = [], list(docs)
    while queue and len(out) < 5000:
        d = queue.pop(0)
        if not isinstance(d, dict) or "kind" not in d or "apiVersion" not in d:
            continue
        if isinstance(d.get("items"), list) and str(d.get("kind")).endswith("List"):
            queue = [x for x in d["items"] if isinstance(x, dict)] + queue
            continue
        row = {"kind": str(d.get("kind")), "name": _s(_get(d, "metadata", "name")), "ns": _s(_get(d, "metadata", "namespace")),
               "containers": [], "host_paths": [], "service_account": None, "host_network": False, "host_pid": False,
               "secret": OrderedDict(), "roleref": _s(_get(d, "roleRef", "name")),
               "subjects": [n for n in (_s(_get(s, "name")) for s in (d.get("subjects") if isinstance(d.get("subjects"), list) else []) if isinstance(s, dict)) if n]}
        spec = _pod_spec(d)
        if spec:
            for c in _containers(spec):
                row["containers"].append({"name": _s(c.get("name")), "image": _s(c.get("image")), "env": _env_map(c.get("env")),
                                          "privileged": _get(c, "securityContext", "privileged") is True,
                                          "command": c.get("command") if isinstance(c.get("command"), list) else None,
                                          "args": c.get("args") if isinstance(c.get("args"), list) else None})
            row["host_paths"] = [p for p in (_s(_get(v, "hostPath", "path")) for v in (spec.get("volumes") or []) if isinstance(v, dict)) if p]
            row["service_account"] = _s(spec.get("serviceAccountName")) or _s(spec.get("serviceAccount"))
            row["host_network"], row["host_pid"] = spec.get("hostNetwork") is True, spec.get("hostPID") is True
        if row["kind"] == "Secret":
            for k, v in (d.get("data") or {}).items() if isinstance(d.get("data"), dict) else []:
                dec = None
                try:
                    dec = base64.b64decode(str(v), validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    pass
                row["secret"][str(k)] = (str(v), dec)
            for k, v in (d.get("stringData") or {}).items() if isinstance(d.get("stringData"), dict) else []:
                row["secret"][str(k)] = (None, str(v))
        out.append(row)
    return out


# ---- Terraform state ---------------------------------------------------------------------------------------

def looks_like_tfstate(doc) -> bool:
    return isinstance(doc, dict) and "terraform_version" in doc and ("resources" in doc or "modules" in doc) \
        and ("lineage" in doc or "serial" in doc)


def _flatten(obj, prefix, out, budget, depth=0):
    budget[0] -= 1
    if budget[0] < 0:
        raise Cut("a document has more nodes than the limit")
    if depth > MAX_FLATTEN_DEPTH:
        raise Cut("a document is nested deeper than the limit")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out, budget, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten(v, f"{prefix}.{i}" if prefix else str(i), out, budget, depth + 1)
    else:
        out.append((prefix, obj))


def _sens_path(p) -> str:
    """One entry of `sensitive_attributes` as a dotted path: a list of get_attr and index steps."""
    parts = []
    for step in p if isinstance(p, list) else []:
        v = step.get("value") if isinstance(step, dict) else None
        if isinstance(v, dict):
            v = v.get("value")
        if v is not None:
            parts.append(str(v))
    return ".".join(parts)


def tf_leaves(state: dict) -> list:
    """Every attribute of a Terraform state as a row: {address, mode, type, name, path, leaf (the
    attribute's own name), value, sensitive (Terraform marked it), secret_name (its name looks like
    a secret's)}. Outputs are rows with the address output.<name>."""
    rows, budget = [], [MAX_NODES]

    def add(address, mode, rtype, rname, attrs, marked):
        flat = []
        _flatten(attrs, "", flat, budget)
        for path, value in flat:
            leaf = next((p for p in reversed(path.split(".")) if not p.isdigit()), path)
            rows.append({"address": address, "mode": mode, "type": rtype, "name": rname, "path": path, "leaf": leaf,
                         "value": value, "sensitive": any(path == s or path.startswith(s + ".") for s in marked if s),
                         "secret_name": bool(_SECRET_NAME.search(leaf))})

    for r in state.get("resources") or [] if isinstance(state.get("resources"), list) else []:
        if not isinstance(r, dict):
            continue
        mode, rtype, rname = str(r.get("mode") or "managed"), str(r.get("type") or ""), str(r.get("name") or "")
        base = (str(r["module"]) + "." if r.get("module") else "") + ("data." if mode == "data" else "") + f"{rtype}.{rname}"
        insts = [i for i in (r.get("instances") if isinstance(r.get("instances"), list) else []) if isinstance(i, dict)]
        for inst in insts:
            key = inst.get("index_key")
            address = base + ("" if key is None else f"[{json.dumps(key)}]")
            marked = [_sens_path(p) for p in inst.get("sensitive_attributes") or []]
            attrs = inst.get("attributes") if isinstance(inst.get("attributes"), dict) else inst.get("attributes_flat")
            add(address, mode, rtype, rname, attrs if isinstance(attrs, dict) else {}, marked)
    for mod in state.get("modules") or [] if isinstance(state.get("modules"), list) else []:      # state version 3 and older
        for addr, r in (mod.get("resources") or {}).items() if isinstance(mod, dict) and isinstance(mod.get("resources"), dict) else []:
            attrs = _get(r, "primary", "attributes")
            rtype = str(_get(r, "type") or addr.split(".")[0])
            path = [str(x) for x in mod.get("path") or [] if isinstance(x, str)]
            prefix = "".join(f"module.{x}." for x in path[1:]) if path[:1] == ["root"] else ""
            add(prefix + str(addr), "data" if str(addr).startswith("data.") else "managed", rtype, str(addr).split(".")[-1],
                attrs if isinstance(attrs, dict) else {}, [])
    for name, o in (state.get("outputs") or {}).items() if isinstance(state.get("outputs"), dict) else []:
        if isinstance(o, dict) and "value" in o:
            flat = []
            _flatten(o["value"], "", flat, budget)
            for path, value in flat:
                rows.append({"address": f"output.{name}", "mode": "output", "type": "output", "name": str(name),
                             "path": path or "value", "leaf": next((p for p in reversed(path.split(".")) if p and not p.isdigit()), str(name)),
                             "value": value, "sensitive": o.get("sensitive") is True, "secret_name": bool(_SECRET_NAME.search(str(name)))})
    return rows


def tf_sensitive(state: dict, by_name: bool = True) -> list:
    """The rows Terraform marks sensitive, then (by_name) the ones whose name looks like a secret's;
    empty values are left out."""
    rows = [r for r in tf_leaves(state) if r["value"] not in (None, "", [], {})]
    out = [r for r in rows if r["sensitive"]]
    return out + ([r for r in rows if r["secret_name"] and not r["sensitive"]] if by_name else [])


# ---- loading a delivery ---------------------------------------------------------------------------------

class Evidence:
    """Everything load() found. `cut` names the kinds ('logs', 'image', 'tf', 'files') in which
    something did not parse whole; solve_set answers nothing from a cut kind."""

    def __init__(self):
        self.events, self.sources = [], Counter()
        self.images, self.tfstates, self.dockerfiles, self.compose, self.k8s = [], [], [], [], []
        self.cut, self.notes, self.kinds = set(), [], OrderedDict()
        self._index = None

    @property
    def empty(self) -> bool:
        return not (self.events or self.images or self.tfstates or self.dockerfiles or self.compose or self.k8s)

    @property
    def multi_stage(self) -> bool:
        """Kubernetes audit events of one request at several stages: an event count is not a request count."""
        ids = Counter((e["src"], e["audit_id"]) for e in self.events if e["audit_id"])
        return any(n > 1 for n in ids.values())

    @property
    def tf_rows(self) -> list:
        if getattr(self, "_tf", None) is None:
            self._tf = []
            for name, st in self.tfstates:
                try:
                    self._tf += tf_leaves(st)
                except Cut as e:
                    self.cut.add("tf")
                    self.notes.append(f"{name}: {e}")
        return self._tf

    def index(self) -> dict:
        """lower-case literal -> kinds, for the words of a question that are values of the evidence."""
        if self._index is None:
            ix = {}
            for e in self.events:
                for v in e["vals"]:
                    ix.setdefault(v, set()).add("log")
                for v in e["actor_vals"] | e["obj_vals"]:
                    ix.setdefault(v, set()).add("ident")
                for o in (e["op"], e["op_short"] if re.search(r"[A-Z]", e["op_short"]) else ""):
                    if o and " " not in o:
                        ix.setdefault(o.lower(), set()).add("op")
            self._index = ix
        return self._index


def unique_files(files: dict) -> list:
    """[(name, bytes)] once per bytes object; the '<archive> -> <member>' names first."""
    seen, same, out = set(), set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if isinstance(data, (bytes, bytearray)) and id(data) not in seen:
            seen.add(id(data))
            mark = (len(data), hashlib.sha256(data).digest())
            if mark in same:
                continue                # a second copy of a log would double every count
            same.add(mark)
            out.append((key, bytes(data)))
    return out


def _ingest_text(ev: Evidence, name: str, data: bytes):
    short = name.split(ARROW)[-1]
    head = data[:1].strip() or data[:64].strip()[:1]
    if head in (b"{", b"[") or data[:3] == b"\xef\xbb\xbf":
        if len(data) > MAX_DOC:
            if sniff(data, short):
                ev.cut.add("logs")
                ev.notes.append(f"{short}: larger than the limit")
            return
        recs, problem = load_records(data, short)
        if recs:
            if len(recs) == 1 and looks_like_tfstate(recs[0]):
                ev.tfstates.append((short, recs[0]))
                ev.kinds[name] = "tfstate"
                return
            if len(recs) == 1 and isinstance(recs[0].get("services"), dict) and not detect(recs[0]):
                ev.compose += [dict(r, file=short) for r in read_compose(recs[0])]
                ev.kinds[name] = "compose"
                return
            known = [(r, detect(r)) for r in recs]
            hits = [(r, s) for r, s in known if s]
            if hits:
                if len(hits) != len(known) or problem:
                    ev.cut.add("logs")
                    ev.notes.append(f"{short}: {problem or str(len(known) - len(hits)) + ' records of no known source'}")
                if len(ev.events) + len(hits) > MAX_EVENTS:
                    ev.cut.add("logs")
                    ev.notes.append(f"{short}: more events than the limit")
                    return
                for r, s in hits:
                    ev.events.append(normalize(r, len(ev.events), short, s))
                    ev.sources[s] += 1
                ev.kinds[name] = "log (" + ", ".join(sorted({s for _, s in hits})) + ")"
                return
            objs = read_k8s_manifests(recs)
            if objs:
                ev.k8s += [dict(o, file=short) for o in objs]
                ev.kinds[name] = "k8s manifest"
            return
        if problem and sniff(data, short):
            ev.cut.add("logs")
            ev.notes.append(f"{short}: {problem}")
        return
    if len(data) > MAX_YAML or b"\x00" in data[:4096]:
        return
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return
    if looks_like_dockerfile(text, short):
        ev.dockerfiles.append((short, parse_dockerfile(text)))
        ev.kinds[name] = "dockerfile"
        return
    if re.search(r"^(?:apiVersion|kind|services)\s*:", text, re.M):
        docs = _yaml_docs(text)
        objs = read_k8s_manifests(docs)
        if objs:
            ev.k8s += [dict(o, file=short) for o in objs]
            ev.kinds[name] = "k8s manifest"
        for d in docs:
            if isinstance(d, dict) and isinstance(d.get("services"), dict) and "apiVersion" not in d:
                ev.compose += [dict(r, file=short) for r in read_compose(d)]
                ev.kinds[name] = "compose"
        if not docs and re.search(r"^(?:apiVersion|services)\s*:", text, re.M):
            ev.cut.add("files")
            ev.notes.append(f"{short}: YAML did not parse")


def _is_limit_cut(e: Cut) -> bool:
    """True for a Cut raised by a resource limit (size, member count, depth, time budget); False for
    one raised because a stream or archive is malformed."""
    return "limit" in str(e) or "budget" in str(e)


def _ingest(ev: Evidence, name: str, data: bytes, depth: int, meter: _Meter, expanded: bool):
    short = name.split(ARROW)[-1]
    try:
        if data[:2] == b"\x1f\x8b" and depth < MAX_DEPTH:
            try:
                raw = gunzip(data)
            except Cut as e:
                if _is_limit_cut(e):
                    raise
                # A stream that ends early or is damaged: when what does open looks like evidence
                # (JSON, a tar), part of the evidence is missing and nothing is answered from the rest.
                try:
                    head = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, SNIFF)
                except zlib.error:
                    head = b""
                if head.lstrip()[:1] in (b"{", b"[") or head[257:262] == b"ustar" or (head and sniff(head, short)):
                    ev.cut.update(("image", "logs", "tf", "files"))
                    ev.notes.append(f"{short}: a gzip stream that holds evidence did not open whole")
                return
            return _ingest(ev, name, raw, depth + 1, meter, False)
        if data[:4] == b"PK\x03\x04" and not expanded and depth < MAX_DEPTH:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                store = {}
                for n, info in enumerate(zf.infolist()):
                    if n >= MAX_MEMBERS:
                        raise Cut("a zip has more members than the limit")
                    if info.is_dir() or info.flag_bits & 1 or info.file_size > MAX_FILE:
                        continue
                    meter.take(info.file_size)
                    store[norm_path(info.filename)[0]] = zf.read(info)
            ims = read_image(store, short, meter)
            if ims:
                ev.images += ims
                ev.kinds[name] = "image (" + ims[0].layout + ", zipped)"
                return
            for p, body in store.items():
                _ingest(ev, f"{short}{ARROW}{p}", body, depth + 1, meter, False)
            return
        if is_tar(data) and depth < MAX_DEPTH:
            entries, problems = read_tar(data, keep=MAX_FILE, meter=meter)
            if "manifest.json" in entries or "index.json" in entries or "oci-layout" in entries:
                ims = read_image(entries, short, meter)
                if ims:
                    ev.images += ims
                    ev.kinds[name] = f"image ({ims[0].layout}, {sum(len(i.layers) for i in ims)} layers)"
                    if any(i.cut for i in ims) or any("larger than the limit" in p for p in problems):
                        ev.cut.add("image")
                    return
            for p, en in entries.items():
                if en.kind == "file" and en.data is not None:
                    _ingest(ev, f"{short}{ARROW}{p}", en.data, depth + 1, meter, False)
            return
    except Cut as e:
        if not _is_limit_cut(e):
            # A malformed archive (a damaged tar, say) is a note, as it was before read_tar and
            # gunzip raised Cut for it; only a resource-limit cut withholds every answer.
            ev.notes.append(f"{short}: an archive did not open ({e})")
            return
        ev.cut.update(("image", "logs", "tf", "files"))
        ev.notes.append(f"{short}: {e}")
        return
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, ValueError, KeyError, RuntimeError) as e:
        ev.notes.append(f"{short}: an archive did not open ({type(e).__name__})")
        return
    try:
        _ingest_text(ev, name, data)
    except Cut as e:
        ev.cut.update(("logs", "tf", "files"))
        ev.notes.append(f"{short}: {e}")


def load(files: dict, budget: float = None, max_total: int = MAX_TOTAL) -> Evidence:
    """The evidence of {name: bytes} (a delivery and its members, as tools/run.py hands them; or
    read_paths() of files on disk). budget: seconds, after which what is left is cut (solve_set
    gives BUDGET; the command gives none). max_total: bytes read out of archives before a cut."""
    ev = Evidence()
    meter = _Meter(_time.monotonic() + budget if budget else None, max_total)
    names = list(files)
    for name, data in unique_files(files):
        short = name.split(ARROW)[-1]
        expanded = any(k.startswith(short + ARROW) for k in names)      # the runner unpacked this archive already
        _ingest(ev, name, data, 0, meter, expanded)
    # An OCI layout or a docker save tree whose members arrived loose (out of a zip the runner unpacked).
    roots = {}
    for key in names:
        tail = key.split(ARROW)[-1]
        for marker in ("oci-layout", "manifest.json", "index.json"):
            if tail == marker or tail.endswith("/" + marker):
                roots.setdefault((key[:len(key) - len(tail)], tail[:len(tail) - len(marker)]), set()).add(marker)
    for (holder, prefix), marks in roots.items():
        if not ({"oci-layout", "index.json"} <= marks or "manifest.json" in marks):
            continue
        store = {}
        for key in names:
            if key.startswith(holder + prefix) and ARROW not in key[len(holder):] and isinstance(files[key], (bytes, bytearray)):
                store[key[len(holder) + len(prefix):]] = bytes(files[key])
        try:
            ims = read_image(store, (holder + prefix).rstrip("/ ->") or "delivery", meter)
        except Cut as e:
            ev.cut.add("image")
            ev.notes.append(str(e))
            continue
        ims = [i for i in ims if not any(i.config_digest and i.config_digest == j.config_digest for j in ev.images)]
        if ims:
            ev.images += ims
            ev.kinds[holder + prefix] = f"image ({ims[0].layout}, loose members)"
            if any(i.cut for i in ims):
                ev.cut.add("image")
    for im in ev.images:
        if im.cut:
            ev.cut.add("image")
            ev.notes += [f"{im.origin}: {p}" for p in im.problems] + [f"{im.origin}: {p}" for L in im.layers for p in L.problems]
    return ev


# ---- signals -----------------------------------------------------------------------------------------------

_MARKS = {
    "cloudtrail": (b'"eventSource"', b'"eventName"', b'"userIdentity"', b'"awsRegion"', b'"sourceIPAddress"'),
    "gcp_audit": (b'"protoPayload"', b'"methodName"', b'"serviceName"', b'"authenticationInfo"'),
    "azure_activity": (b'"operationName"', b'"callerIpAddress"', b'"resourceId"', b'"subscriptionId"', b'"caller"'),
    "k8s_audit": (b'"auditID"', b'"requestURI"', b'"objectRef"', b'"verb"', b"audit.k8s.io"),
    "tfstate": (b'"terraform_version"', b'"lineage"', b'"serial"', b'"resources"'),
}
_Q_WORDS = re.compile(r"\bcloudtrail\b|\baws\b|\biam\b|\baccess key\b|\bassum\w* (?:the |a |an )?role\b|\bs3\b|\bbucket\b|\barn\b|\bgcp\b|"
                      r"\bazure\b|\bkubernetes\b|\bk8s\b|\bkubectl\b|\bpods?\b|\bservice ?account\b|\bclusterrolebinding\b|"
                      r"\bnamespace\b|\bdocker\w*\b|\bcontainer\w*\b|\bimage layers?\b|\blayers?\b|\bentrypoint\b|\bwhiteout\b|"
                      r"\boci\b|\bterraform\b|\btfstate\b|\bcompose\b|\bhelm\b|\bregistry\b", re.I)


def sniff(data: bytes, name: str = ""):
    """A cheap look at one file: the kind this toolkit reads it as ('cloudtrail', 'gcp_audit',
    'azure_activity', 'k8s_audit', 'tfstate', 'image', 'dockerfile', 'k8s_manifest', 'compose'),
    or None. Only the head is read; a tar's member names are read up to 4000 members."""
    head = data[:SNIFF]
    if head[:2] == b"\x1f\x8b":
        try:
            head = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head, SNIFF)
        except zlib.error:
            return None
    if is_tar(head) or is_tar(data[:1024]):
        if data[:2] == b"\x1f\x8b":
            return None                     # a gzip tar: only load() opens it
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                for n, m in enumerate(tf):
                    p = norm_path(m.name)[0]
                    if p in ("manifest.json", "oci-layout", "index.json"):
                        return "image"
                    if n > 4000:
                        break
        except (tarfile.TarError, OSError, EOFError, ValueError):
            pass
        return None
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped[:1] in (b"{", b"["):
        hits = {s: sum(1 for m in marks if m in head) for s, marks in _MARKS.items()}
        best = max(hits, key=hits.get)
        if hits[best] >= 3:
            if best == "azure_activity" and re.search(rb'"category"\s*:\s*"(?:\w*SignInLogs|AuditLogs|ProvisioningLogs)"', head):
                return None                 # Entra sign-in or audit records in the Azure Monitor envelope: cloudlogs
            return best
        if b'"CloudTrailEvent"' in head and b'"EventName"' in head and b'\\"eventSource\\"' in head:
            return "cloudtrail"             # rows of `aws cloudtrail lookup-events`
        if sum(1 for m in (b'"operation_name"', b'"event_timestamp"', b'"resource_id"', b'"subscription_id"', b'"caller"') if m in head) >= 3:
            return "azure_activity"         # the Azure CLI / SDK spelling of the activity log
        return None
    if b"\x00" in head[:2048]:
        return None
    try:
        text = head.decode("utf-8-sig", "ignore")
    except UnicodeDecodeError:
        return None
    if looks_like_dockerfile(text, name):
        return "dockerfile"
    if re.search(r"^apiVersion\s*:", text, re.M) and re.search(r"^kind\s*:", text, re.M):
        return "k8s_manifest"
    if re.search(r"^services\s*:", text, re.M) and re.search(r"^\s+(?:image|build)\s*:", text, re.M):
        return "compose"
    return None


def _known_lane(questions) -> bool:
    """True when the questions carry the marks of one of the five lanes of Days 1 to 8 (the same
    marks as solvers/common/triage.py lane_signals): those sets are never this toolkit's."""
    for q in questions or []:
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), f.get("syntax"), f.get("pattern")))
        if "ANS-" in text or re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", str(q.get("question") or "")):
            return True
        if re.search(r"-(?:role|attack|steps|adapter|campaign)$", aid) or f.get("kind") == "mitre_attack_id":
            return True
        if re.match(r"d\d\d_", aid) or aid == "message":
            return True
    return False


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like this category. A file this toolkit
    reads gives 0.7; the share of questions that speak of cloud, Kubernetes, containers or
    Terraform gives up to 0.3 (the questions alone: at most 0.3). 0.0 for a set of a known lane."""
    qs = list(questions or [])
    if _known_lane(qs):
        return 0.0
    score, seen = 0.0, 0
    for name, data in unique_files(files or {}):
        seen += 1
        if seen > 300:
            break
        tail = name.split(ARROW)[-1]
        if tail.rsplit("/", 1)[-1] == "oci-layout" or tail.endswith(".tfstate") or sniff(data, tail):
            score = 0.7
            break
    if qs:
        hits = sum(1 for q in qs if _Q_WORDS.search(" ".join(str(q.get(k) or "") for k in ("question", "id", "answer_id"))))
        score += 0.3 * hits / len(qs)
    return round(min(1.0, score), 3)


# ---- reading a question ------------------------------------------------------------------------------------

VOCAB = set("""
a an the of in on at to from for by with as into via through and or it its this that these those their his her they them there here
is are was were be been being did do does done has have had can could would should will what which who whom whose when where how
many much please determine identify find give provide state name names named called list exact exactly full complete value values
one single only any all some both same own
log logs logged logging audit activity trail trails cloudtrail event events record records recorded entry entries evidence file files
dataset delivered delivery set archive export exported capture captured sample
aws amazon gcp google azure microsoft cloud kubernetes k8s cluster kubectl api apiserver server control plane iam sts s3 ec2 eks gke aks
account accounts id ids identifier number user users username identity identities principal principals caller actor
ip ipv4 ipv6 address addresses source client agent agents string
access key keys secret secrets credential credentials password passwords token tokens flag sensitive
role roles assume assumed assumes assuming assumption arn arns session policy policies attach attached attaches attaching permission
permissions admin administrator administratoraccess privilege privileges privileged escalate escalated escalation
bucket buckets object objects download downloaded downloads read reads reading retrieve retrieved exfiltrate exfiltrated exfiltration
stolen stole steal accessed accesses upload uploaded written wrote write public policy
console login logins logon sign signed signin mfa
create created creates creating creation new generate generated issued made make added add adds adding introduced introduce
delete deleted deletes deleting removal remove removed removes removing whiteout whiteouts wiped erased gone later earlier still
stop stopped stops stopping disable disabled disables turned off launch launched started start run ran running instance instances
ami type region regions operation operations action actions call calls method verb error code message request requests requested
first earliest initial last latest most recent final failed fail failure failures unsuccessful successful successfully success
succeeded denied unauthorized unauthorised
attacker attackers attacker's threat adversary adversary's malicious suspicious compromised compromise intruder intruder's rogue backdoor
time timestamp date utc
pod pods exec execed executed execute execution shell command commands container containers containerized namespace namespaces service
serviceaccount clusterrolebinding clusterrole binding bindings subject subjects bound grant granted grants workload workloads deployment deployments daemonset
image images docker dockerfile oci layer layers digest digests hash hashes checksum sha256 history instruction instructions build built
entrypoint entry point cmd default env environment variable variables var vars config configuration configured manifest tag tags tagged
base parent architecture arch os operating system port ports expose exposed exposes listen listens workdir working
directory dir label labels maintainer author path paths filename content contents contain contains contained containing hold holds
held stored store stores inside within present exists existed appear appears appeared saved baked embedded hidden leaked leak
left behind copied copy placed dropped
terraform tfstate state resource resources attribute attributes output outputs version serial lineage managed
compose yaml host hostpath mount mounted mounts volume volumes url urls
used use uses using performed perform made did done originated originate come came observed seen shown show shows happen happened
occur occurred took take place belong belongs belonging tied associated related given
db database data manage manages stage stages times index distinct unique different total overall have having get gets got fetch fetched
pull pulled put puts changed change modified modify set sets bound open opened into onto out up down about against under over
not without no never return returned returns returning
""".split())      # "not", "without", "no", "never" are known only so that _VETO (or the MFA reading) can name them

_VETO = re.compile(r"\b(?:not|no|never|except|excluding|without|other than|besides|between|before|after|prior|following|subsequent\w*|then|"
                   r"until|since|during|second|third|fourth|fifth|\d+(?:st|nd|rd|th)|least|fewest|average|per|each|every|"
                   r"longest|shortest|largest|smallest|biggest|total size|percent\w*|ratio|how long|duration)\b", re.I)
_ALGO = re.compile(r"^sha-?(?:256|1|512)$|^md5$", re.I)
# MFA is a qualifier of a console login (CloudTrail: additionalEventData.MFAUsed). It is read only in
# these wordings; any other use of the word leaves the question unanswered. Before the real-data
# pass of 2026-10-08 "mfa" was plain vocabulary and "how many console logins used MFA" counted
# every console login.
_MFA_NO = re.compile(r"\bwithout (?:using )?(?:an? |any )?mfa\b|\b(?:did|does|do|have|has|had|was|were) not (?:use[ds]?|using|have|protected by) (?:an? |any )?mfa\b|"
                     r"\bnot us(?:e|ing) mfa\b|\bno mfa\b|\bmfa (?:was |is |were )?not (?:used|enabled|present)\b|\bmfa (?:was |is )?(?:disabled|off)\b")
_MFA_YES = re.compile(r"\bwith mfa\b|\bus(?:e|ed|es|ing) mfa\b|\bmfa (?:was |is |were )?(?:used|enabled|present)\b|\bprotected by mfa\b")

FIELDS = (
    ("count", r"\bhow many\b|\b(?:number|count) of (?!the\b|this\b|that\b)"),
    ("time", r"\bwhen\b|\bwhat time\b|\btimestamp\b|\b(?:what|which) date\b|\bdate and time\b|\btime\b|\bdate\b"),
    ("hash", r"\bhashalgo\b|\bhash\b|\bchecksum\b|\bdigests?\b"),
    ("arn", r"\barns?\b"),
    ("ip", r"\bip(?:v4|v6)?\b|\bsource address\b"),
    ("ua", r"\buser agents?\b"),
    ("secretkey", r"\bsecret access key\b|\bsecret key\b"),
    ("key", r"\baccess keys?\b|\bkey ids?\b"),
    ("accountid", r"\baccount (?:id|number|identifier)\b"),
    ("session", r"\bsession names?\b|\bsessions?\b"),
    ("subject", r"\bsubjects?\b"),
    ("role", r"\broles?\b|\bclusterrole\b"),
    ("policy", r"\bpolic(?:y|ies)\b"),
    ("bucket", r"\bbuckets?\b"),
    ("object", r"\bobjects?\b"),
    ("region", r"\bregions?\b"),
    ("op", r"\bapi calls?\b|\boperations?\b|\bevent names?\b|\b(?:which|what) events?\b|\b(?:first|last|earliest|latest) events?\b|\bactions?\b|\bmethod\b|\bverb\b"),
    ("error", r"\berror (?:code|message)\b"),
    ("instance", r"\binstance (?:id|type)s?\b|\binstances?\b|\bami\b"),
    ("trail", r"\btrails?\b"),
    ("pod", r"\bpods?\b"),
    ("sa", r"\bservice ?accounts?\b"),
    ("crb", r"\bclusterrolebindings?\b|\bcluster role bindings?\b|\bbindings?\b"),
    ("namespace", r"\bnamespaces?\b"),
    ("entrypoint", r"\bentry ?point\b"),
    ("cmd", r"\bcmd\b|\bdefault command\b"),
    ("command", r"\bcommands?\b|\binstructions?\b"),
    ("envvar", r"\benv(?:ironment)? var(?:iable)?s?\b|\bvariables?\b"),
    ("layer", r"\blayers?\b"),
    ("hostpath", r"\bhost ?path\b"),
    ("file", r"\bfiles?\b|\bpaths?\b|\bfilename\b"),
    ("credential", r"\bpasswords?\b|\btokens?\b|\bcredentials?\b|\bflag\b|\bsecrets?\b"),
    ("port", r"\bports?\b"),
    ("workdir", r"\bworking dir(?:ectory)?\b|\bworkdir\b"),
    ("base", r"\b(?:base|parent) image\b"),
    ("imageid", r"\bimage (?:ids?|digests?)\b|\bconfig digest\b"),
    ("workload", r"\bdeployments?\b|\bworkloads?\b|\bdaemonsets?\b"),
    ("service", r"\bservices?\b"),
    ("image", r"\bimages?\b"),
    ("container", r"\bcontainers?\b"),
    ("label", r"\bmaintainer\b|\bauthor\b|\blabels?\b"),
    ("tag", r"\b(?:image )?tags?\b"),
    ("arch", r"\barchitecture\b|\barch\b"),
    ("os", r"\boperating system\b|\bos\b"),
    ("url", r"\burls?\b"),
    ("tfversion", r"\bterraform version\b|\bversion of terraform\b|\bversion\b"),
    ("serial", r"\bserial\b"),
    ("lineage", r"\blineage\b"),
    ("resource", r"\bresources?\b"),
    ("content", r"\bcontents?\b|\bcontain\w*\b|\bvalue\b"),
    ("user", r"\bwho\b|\busers?\b|\busername\b|\bprincipals?\b|\bidentit(?:y|ies)\b|\bcaller\b|\bactor\b"),
)
FIELDS = tuple((n, re.compile(rx)) for n, rx in FIELDS)

_W = {
    "create": re.compile(r"\bcreat\w*|\bgenerat\w*|\bnew\b|\bissued\b|\bmade\b"),
    "read": re.compile(r"\bread\w*|\bdownload\w*|\bretriev\w*|\bexfiltrat\w*|\bstole\w*|\bsteal\w*|\baccess(?:ed|es)\b"),
    "write": re.compile(r"\bupload\w*|\bwrit\w*|\bwrote\b"),
    "delete": re.compile(r"\bdelet\w*|\bremov\w*|\bwhiteouts?\b|\bwiped\b|\berased\b|\bgone\b"),
    "add": re.compile(r"\badd\w*|\bintroduc\w*|\bcreat\w*|\bcopied\b|\bcopy\b|\bwrote\b|\bwritten\b|\bplaced\b|\bdropped\b"),
    "first": re.compile(r"\bfirst\b|\bearliest\b|\binitial\b"),
    "last": re.compile(r"\blast\b|\blatest\b|\bmost recent\b|\bfinal\b"),
    "attacker": re.compile(r"\battacker\w*|\bthreat\b|\badversary\b|\bmalicious\b|\bsuspicious\b|\bcompromis\w*|\bintruder\b|\brogue\b|"
                           r"\bbackdoor\b|\bunauthori[sz]ed\b"),
    "failed": re.compile(r"\bfail\w*|\bunsuccessful\b|\bdenied\b|\b(?:with|have|has|had|returned|returning) (?:an? )?errors?\b"),
    "success": re.compile(r"\bsuccess\w*|\bsucceed\w*"),
    "privileged": re.compile(r"\bprivileged\b"),
    "exec": re.compile(r"\bexec\w*|\bshell\b"),
    "name": re.compile(r"\bnames? of\b|\bnamed\b|\bcalled\b|\bfilename\b|\b(?:role|policy|file|image|bucket|user|pod|container|trail|session|secret) names?\b"),
    "env": re.compile(r"\benv\w*\b|\bvariables?\b"),
    "public": re.compile(r"\bpublic\b"),
    "sensitive": re.compile(r"\bsensitive\b"),
    "target": re.compile(r"\b(?:for|to) (?:which|what|whom)\b|\b(?:which|what) (?:iam )?user (?:is|are|was|were|did|does) (?:the |an? )?"
                         r"(?:access key|polic\w+|key)\b|\battach\w* to\b|\bcreated for\b|\bbelongs? to\b|\bowner\b|\bowned\b|"
                         r"\b(?:for|to)$"),
    "newuser": re.compile(r"\b(?:new|created|backdoor|added|rogue) (?:iam )?(?:user|account)\b|\b(?:user|account) (?:was |were |that was )"
                          r"(?:created|added)\b|\bcreat\w* (?:a |an |the )?(?:new |backdoor |rogue )?(?:iam )?(?:user|account)\b|"
                          r"\b(?:user|account) (?:created|added) by\b"),
}


_CONTEXT = (      # an attribute noun, and what must stand before it (or after it) for this file to read it
    (re.compile(r"\b(?:ids?|identifiers?)\b"), re.compile(r"(?:access key|key|account|instance|image|layer|config) $"),
     re.compile(r"^ of (?:the |an? )?(?:\S+ )?(?:access key|key|account|instance|image|layer)\b")),
    (re.compile(r"\bnumbers?\b"), re.compile(r"(?:account|layer|port) $"), re.compile(r"^ of\b")),
    (re.compile(r"\b(?:codes?|messages?)\b"), re.compile(r"error $"), None),
    (re.compile(r"\bstrings?\b"), re.compile(r"agent $"), None),
    (re.compile(r"\baddress(?:es)?\b"), re.compile(r"(?:ip|ipv4|ipv6|source) $"), None),
    (re.compile(r"\btypes?\b"), re.compile(r"instance $"), None),
    (re.compile(r"\bsource\b"), None, re.compile(r"^ (?:ip|ipv4|ipv6|address)")),
    (re.compile(r"\bagents?\b"), re.compile(r"user $"), None),
    (re.compile(r"\bindex\b"), re.compile(r"layer $"), re.compile(r"^ of the layer")),
)
_FILLER = set("is was were are the a an of name names exact full complete please did does do has have had for to in on at from by "
              "it its this that these those".split())
_ANCHOR = re.compile(r"\b(?:which|what)\b|^(?:please )?(?:identify|find|give|provide|state|determine|name|list)\b")


def _context_veto(m: str):
    for rx, before, after in _CONTEXT:
        for hit in rx.finditer(m):
            ok = (before is not None and before.search(m[:hit.start()])) or (after is not None and after.search(m[hit.end():]))
            if not ok:
                return hit.group()
    return None


def _asked_first(m: str, pos: int) -> bool:
    """True when the first known field stands where the question's subject does: at most two other
    content words between 'which', 'what' or an opening imperative and the field ("which deployment
    uses the privileged container" asks for a deployment, not a container)."""
    a = _ANCHOR.search(m)
    if not a or a.end() > pos:
        return True
    between = [w for w in m[a.end():pos].split() if w not in _FILLER]
    return len(between) <= 2


class Reading:
    """What a question was read as: the field asked first, every field named, the literals of the
    evidence it names, its hash algorithms and its flag words; `why` when it cannot be answered."""

    def __init__(self):
        self.text = self.masked = ""
        self.primary, self.fields, self.why, self.primary_pos = None, [], None, 0
        self.ops, self.lits, self.algos = set(), [], []
        self.paths, self.envs, self.labels, self.tf_addr, self.tf_types, self.tf_leafs, self.names = [], [], [], [], [], [], []
        self.flags = set()
        self.marks = []         # one per § of `masked`, in order: the lower-case log literal, or None
        self.shadow = []        # words read as vocabulary that are also names in the logs ("admin", "default")
        self.mfa = None         # True / False: console logins with / without MFA are asked
        self.phrase_ops = set() # operations named by a phrase ("logged in to the console"), not by their own name

    def has(self, *flags) -> bool:
        return any(f in self.flags for f in flags)


def _image_index(ev: Evidence) -> dict:
    """What a question's token may name outside the logs: paths, base names, env names, labels,
    Terraform addresses, types and attribute names, manifest object and container names."""
    ix = getattr(ev, "_image_index", None)
    if ix is not None:
        return ix
    ix = {"paths": {}, "bases": {}, "envs": set(), "labels": set(), "tf_addr": {}, "tf_types": set(), "tf_leafs": set(), "names": set()}
    for im in ev.images:
        for L in im.layers:
            for p in list(L.entries) + L.whiteouts:
                ix["paths"].setdefault(p, None)
                ix["bases"].setdefault(p.rsplit("/", 1)[-1], set()).add(p)
        ix["envs"].update(im.env)
        if isinstance(im.cfg.get("Labels"), dict):
            ix["labels"].update(str(k) for k in im.cfg["Labels"])
    for _, df in ev.dockerfiles:
        for st in df["stages"]:
            ix["envs"].update(st["env"])
            ix["envs"].update(st["arg"])
            ix["labels"].update(st["labels"])
    for s in ev.compose:
        ix["envs"].update(s["env"])
        ix["names"].add(s["service"])
    for o in ev.k8s:
        if o["name"]:
            ix["names"].add(o["name"])
        for c in o["containers"]:
            ix["envs"].update(c["env"])
            if c["name"]:
                ix["names"].add(c["name"])
        ix["envs"].update(o["secret"])
    for r in ev.tf_rows:
        ix["tf_addr"].setdefault(r["address"].lower(), r["address"])
        ix["tf_types"].add(r["type"].lower())
        ix["tf_leafs"].add(r["leaf"].lower())
    ev._image_index = ix
    return ix


def read_question(q, ev: Evidence) -> Reading:
    """Read one question against the evidence (see Reading). Text in a question is matched, never run."""
    rd = Reading()
    text = " ".join(str(q.get("question") or "").split())
    if not text:
        text = re.sub(r"[-_.]+", " ", re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or "")))
    rd.text = text
    if not text:
        rd.why = "no question text"
        return rd
    logs, ix = ev.index(), _image_index(ev)
    masked = []
    for chunk in text.split():
        c = chunk.strip("`'\"()[]{}<>,;!?").rstrip(".:")
        c = re.sub(r"['’][sd]$", "", c)
        low = c.lower()
        if not c:
            continue
        if _ALGO.match(c):
            rd.algos.append(low.replace("-", ""))
            masked.append("hashalgo")
            continue
        if low not in VOCAB:
            kinds = logs.get(low)
            if kinds and "op" in kinds:
                rd.ops.add(low)
                rd.marks.append(None)
                masked.append("§")
                continue
            if kinds:
                rd.lits.append(low)
                rd.marks.append(low)
                masked.append("§")
                continue
            p = norm_path(c)[0]
            if "/" in c and p in ix["paths"]:
                rd.paths.append(p)
                rd.marks.append(None)
                masked.append("§")
                continue
            if c in ix["bases"] and ("." in c or "_" in c or "-" in c):
                rd.paths += sorted(ix["bases"][c])
                rd.marks.append(None)
                masked.append("§")
                continue
            if c in ix["envs"]:
                rd.envs.append(c)
                rd.marks.append(None)
                masked.append("§")
                continue
            if c in ix["labels"]:
                rd.labels.append(c)
                rd.marks.append(None)
                masked.append("§")
                continue
            if low in ix["tf_addr"]:
                rd.tf_addr.append(ix["tf_addr"][low])
                rd.marks.append(None)
                masked.append("§")
                continue
            if low in ix["tf_types"]:
                rd.tf_types.append(low)
                rd.marks.append(None)
                masked.append("§")
                continue
            if low in ix["tf_leafs"]:
                rd.tf_leafs.append(low)
                rd.marks.append(None)
                masked.append("§")
                continue
            if c in ix["names"]:
                rd.names.append(c)
                rd.marks.append(None)
                masked.append("§")
                continue
        if "ident" in (logs.get(low) or ()):
            rd.shadow.append(low)
        words = re.findall(r"[a-z0-9]+", low)
        unknown = [w for w in words if w not in VOCAB]
        if unknown or not words:
            rd.why = f"a word this file does not know, or a literal the evidence does not hold: {_safe(c, 60)}"
            return rd
        masked.append(" ".join(words))
    m = " ".join(masked)
    if _MFA_NO.search(m):
        rd.mfa, m = False, _MFA_NO.sub("nomfa", m)
    if _MFA_YES.search(m):
        if rd.mfa is False:
            rd.why = "MFA is asked both ways"
            return rd
        rd.mfa, m = True, _MFA_YES.sub("withmfa", m)
    rd.masked = m
    if re.search(r"\bmfa\b", m):
        rd.why = "MFA in a wording this file does not model"
        return rd
    v = _VETO.search(m)
    if v:
        rd.why = f"a qualifier this file does not model: {v.group()}"
        return rd
    found = []
    for name, rx in FIELDS:
        hit = rx.search(m)
        if hit:
            found.append((hit.start(), -len(hit.group()), name))
    found.sort()
    rd.fields = [n for _, _, n in found]
    rd.primary = rd.fields[0] if rd.fields else None
    rd.primary_pos = found[0][0] if found else 0
    bad = _context_veto(m)
    if bad in ("id", "ids") and len(set(rd.tf_addr)) == 1 and re.search(r"\bid of (?:the )?(?:resource )?§", m):
        bad = None                      # the id attribute of a named Terraform resource
    if bad:
        rd.why = f"'{bad}' asks for an attribute this file does not read here"
        return rd
    if rd.primary and not _asked_first(m, found[0][0]):
        rd.why = f"the question asks for something before its first known field ('{rd.primary}')"
        return rd
    rd.flags = {name for name, rx in _W.items() if rx.search(m)}
    present = {e["op"].lower() for e in ev.events} | {e["op_short"].lower() for e in ev.events}
    for rx, ops in OP_PHRASES:
        if rx.search(m):
            rd.phrase_ops |= (ops & present) - rd.ops
            rd.ops |= (ops & present)
    if rd.primary is None and (rd.tf_leafs or (len(set(rd.tf_addr)) == 1 and re.search(r"\b(?:id|name|value) of (?:the )?(?:resource )?§", m))):
        rd.primary = "content"
    if rd.primary is None:
        rd.why = "no field this file answers is asked"
    return rd


# ---- facts and how they are answered ---------------------------------------------------------------------

MISS = object()     # "not this handler's question"


class Fact:
    """One established fact and its spellings: options is [(method, value)], best first. forced:
    the fact was selected by a rule of this file, so it is never answered plain. hexlike: a hash,
    upper-cased when the question asks for upper case."""

    def __init__(self, field, shape, options, forced=False, json_value=None, hexlike=False):
        self.field, self.shape, self.forced, self.json_value, self.hexlike = field, shape, forced, json_value, hexlike
        self.options = [(str(n), v) for n, v in options if v is not None and str(v) != ""]

    @property
    def value(self):
        return self.options[0][1] if self.options else None


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


def pick(key: str, options):
    """labels.pick for a `cloud_container.` key. While labels.py does not list the lane, the unsure
    wire form itself: the answer is never sent and reads as unsure everywhere."""
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


def emit(q, fact: Fact):
    """A fact as an answer: plain when one spelling is left and no rule selected it, else unsure."""
    if fact is None or not fact.options:
        return None
    if fact.field == "count" and all(str(v) == "0" for _, v in fact.options):
        return None                     # nothing matched: the question's words selected no event, which proves no zero
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    words = str(f.get("syntax") or "") + " " + str(q.get("question") or "")
    opts = list(fact.options)
    if kind in ("mitre_attack_id", "ordered_tokens"):
        return None
    if kind == "json":
        if fact.json_value is None:
            return None
        opts = [("json", json.dumps(fact.json_value, separators=(",", ":"), ensure_ascii=False))]
    elif kind == "integer":
        opts = [(n, v) for n, v in opts if re.fullmatch(r"-?\d+", str(v))]
    elif kind == "enum":
        allowed = _enum(q)
        if not allowed:
            return None
        opts = [(n, v) for n, v in opts if str(v) in allowed]
    if fact.hexlike and re.search(r"\bupper-?case\b", words, re.I):
        opts = [(n, str(v).upper()) for n, v in opts]
    opts = [(n, v) for n, v in opts if _fits(q, v)]
    if not opts:
        return None
    values = []
    for _, v in opts:
        if v not in values:
            values.append(v)
    if len(values) == 1 and not fact.forced:
        return values[0]
    return pick(f"{KEY}.{fact.field}/{fact.shape}", opts)


def _one(values):
    values = [v for v in values if v not in (None, "")]
    uniq = []
    for v in values:
        if v not in uniq:
            uniq.append(v)
    return uniq[0] if len(uniq) == 1 else None


def _list_fact(field, shape, items, forced=False):
    """A list (an entrypoint, a command): JSON, or its items joined by a space."""
    items = [str(x) for x in items]
    joined = " ".join(items)
    opts = [("joined_space", joined), ("json", json.dumps(items, separators=(",", ":"), ensure_ascii=False))]
    return Fact(field, shape, opts, forced=forced, json_value=items)


# ---- answering from the logs -----------------------------------------------------------------------------

def _scope(rd: Reading, events: list) -> list:
    sel = events
    if rd.ops:
        sel = [e for e in sel if _is_op(e, rd.ops)]
    for lit in rd.lits:
        sel = [e for e in sel if lit in e["vals"]]
    if rd.has("failed") and not rd.has("success"):
        sel = [e for e in sel if e["failed"]]
    if rd.has("success") and not rd.has("failed"):
        sel = [e for e in sel if not e["failed"]]
    return sel


def _edge(sel: list, last: bool):
    if not sel or any(e["dt"] is None for e in sel):
        return None
    t = (max if last else min)(e["dt"] for e in sel)
    return [e for e in sel if e["dt"] == t]


def _identity_fact(sel, src_shape):
    """Who made these events, when it is one identity: the logged user name plain; an assumed role,
    a service account or a service as its spellings."""
    ids = []
    for e in sel:
        who = (e["actor_arn"], e["actor"])
        if (e["actor_arn"] or e["actor"]) and who not in ids:
            ids.append(who)
    if len(ids) != 1:
        return None
    e = next(x for x in sel if (x["actor_arn"], x["actor"]) == ids[0])
    if e["sa"] and e["sa_name"]:
        return Fact("service_account", src_shape, [("name", e["sa_name"]), ("username", e["actor"]), ("namespace_name", f"{e['sa_ns']}/{e['sa_name']}")])
    if e["actor_logged"] and e["actor"]:
        return Fact("user", src_shape, [("user_name", e["actor"])])
    return Fact("identity", src_shape + "." + (e["actor_type"] or "unknown").lower(),
                [("session_name", e["session_name"]), ("role_name", e["actor"]), ("arn", e["actor_arn"])], forced=True)


_USER_ACTIVE = re.compile(r"\b(?:which|what) (?:\S+ ){0,2}(?:users?|principal|identity|caller|actor) "
                          r"(?!did\b|does\b|do\b|has\b|had\b|was\b|were\b|is\b|are\b|name\b|names\b|§)\w+")
_USER_OBJECT = re.compile(r"\b(?:which|what) (?:\S+ ){0,2}(?:users?|principal|identity)(?: names?)? (?:did|does|was|were)\b")


def _log_fact(rd: Reading, sel: list, ev: Evidence, src: str = None):
    """The fact a log question asks for over the events `sel`, None when there is not exactly one,
    MISS when the field is not one the logs answer."""
    p, src = rd.primary, src or (ev.sources.most_common(1)[0][0] if ev.sources else "log")
    k8s = src == "k8s_audit"
    if k8s and rd.has("exec"):
        sel = [e for e in sel if e["sensitive"] == "pod_exec"]
    if k8s and rd.has("privileged"):
        sel = [e for e in sel if e["privileged"]]
    if p == "session" or (p == "role" and "session" in rd.fields and not k8s):
        v = _one(e["role_session"] for e in sel if e["role_arn"])
        return Fact("role_session_name", src, [("as_logged", v)]) if v else None
    if p == "subject" or (p == "crb" and "subject" in rd.fields):
        subs = {tuple(e["subjects"]) for e in sel if e["resource"] in ("clusterrolebindings", "rolebindings") and e["verb"] == "create"}
        if len(subs) != 1 or len(next(iter(subs))) != 1:
            return None
        return Fact("binding_subject", src, [("name", next(iter(subs))[0])])
    if p == "ip":
        v = _one(ip for e in sel for ip in e["ips"])
        return Fact("source_ip", src, [("as_logged", v)]) if v else None
    if p == "ua":
        v = _one(e["ua"] for e in sel)
        return Fact("user_agent", src, [("as_logged", v)]) if v else None
    if p == "key":
        made = [e["new_key"] for e in sel if e["new_key"]]
        used = [e["key"] for e in sel if e["key"]]
        if rd.has("create") or "createaccesskey" in rd.ops:
            v = _one(made)
        elif re.search(r"\bus(?:ed|es|ing|e)\b|\bsigned\b|\bperformed\b|\bmade\b", rd.masked):
            v = _one(used)
        else:
            v = _one(made + used)
        return Fact("access_key_id", src, [("as_logged", v)]) if v else None
    if p in ("role", "arn", "policy") and not k8s:
        want_arn = "arn" in rd.fields
        other = [f for f in rd.fields if f != "arn"]
        if p == "arn" and other and other[0] not in ("role", "policy", "user"):
            return None                 # the ARN of a bucket, a trail, an instance: not an identity's
        sub = p if p != "arn" else (other[0] if other else "user")
        if sub == "role":
            arn = _one(e["role_arn"] for e in sel)
            if not arn:
                return None
            name = role_name(arn)
            if want_arn:
                return Fact("role_arn", src, [("arn", arn)])
            if rd.has("name") and name and arn.endswith(":role/" + name):
                return Fact("role_name", src, [("name", name)])
            return Fact("role", src, [("name", name), ("arn", arn)])
        if sub == "policy":
            arn, name = _one(e["policy_arn"] for e in sel), _one(e["policy_name"] for e in sel)
            if want_arn:
                return Fact("policy_arn", src, [("arn", arn)]) if arn else None
            if not name or (len({e["policy_arn"] for e in sel if e["policy_arn"]}) > 1):
                return None
            if rd.has("name") or not arn:
                return Fact("policy_name", src, [("name", name)])
            return Fact("policy", src, [("name", name), ("arn", arn)])
        if rd.has("newuser", "target") and not _USER_ACTIVE.search(rd.masked):
            return None                 # the ARN of the user created or acted on: not the actor's
        if re.search(r"\b(?:of|for) (?:the )?(?:iam |aws )?(?:users?|principal|identity|account)(?: named| called)? §(?! (?:who|that|which)\b)", rd.masked) \
                or (rd.lits and not rd.ops and not _actions(rd.masked) and re.search(r"\barn (?:of|for) (?:the )?§", rd.masked)):
            # "the ARN of the user X": X's own ARN, as an event X made or the call that created X states it
            own = set()
            for lit in rd.lits:
                for e in ev.events:
                    if e["actor_logged"] and (e["actor"] or "").lower() == lit and e["actor_arn"]:
                        own.add(e["actor_arn"])
                    if (e["new_user"] or "").lower() == lit and e["new_user_arn"]:
                        own.add(e["new_user_arn"])
            return Fact("user_arn", src, [("arn", next(iter(own)))]) if len(own) == 1 else None
        arn = _one(e["actor_arn"] for e in sel)
        return Fact("principal_arn", src, [("arn", arn)]) if arn else None
    if p == "bucket":
        pool = [e for e in sel if e["bucket"]]
        if rd.has("read"):
            pool = [e for e in pool if _is_op(e, READ_OPS)]
        v = _one(e["bucket"] for e in pool)
        return Fact("bucket", src, [("name", v)]) if v else None
    if p == "object" or (p == "file" and any(e["object"] for e in sel)):
        pool = [e for e in sel if e["object"]]
        for flag, ops in (("read", READ_OPS), ("write", WRITE_OPS), ("delete", DELETE_OPS)):
            if rd.has(flag):
                pool = [e for e in pool if _is_op(e, ops)]
        keys = {(e["bucket"], e["object"]) for e in pool}
        if len(keys) != 1:
            return None
        bucket, key = next(iter(keys))
        if "/" not in key:
            return Fact("object_key", src, [("key", key)])
        uri = ("gs_uri", f"gs://{bucket}/{key}") if src == "gcp_audit" else ("s3_uri", f"s3://{bucket}/{key}")
        return Fact("object", src, [("key", key), ("basename", key.rsplit("/", 1)[-1]), uri if bucket else ("uri", None)])
    if p == "accountid":
        if _attr_residual(rd):
            return None                 # "the account ID given access to the bucket": another account than the log's own
        v = _one(e["account"] for e in sel)
        return Fact("account_id", src, [("as_logged", v)]) if v else None
    if p == "region":
        if _attr_residual(rd):
            return None                 # "the region the snapshot was copied to": not the events' own region
        v = _one(e["region"] for e in sel)
        return Fact("region", src, [("as_logged", v)]) if v else None
    if p == "error":
        v = _one(e["error"] for e in sel if e["error"])
        return Fact("error_code", src, [("as_logged", v)]) if v else None
    if p == "trail":
        acts = _actions(rd.masked)
        if "stop" in acts:
            sel = [e for e in sel if e["op"] == "StopLogging"]
        if "delete" in acts:
            sel = [e for e in sel if e["op"] == "DeleteTrail"]
        v = _one(e["trail"] for e in sel)
        if not v:
            return None
        return Fact("trail", src, [("as_logged", v)] + ([("name", v.rsplit("/", 1)[-1])] if "/" in v else []))
    if p == "instance":
        if re.search(r"\binstance type", rd.masked):
            v = _one(e["instance_type"] for e in sel)
        elif re.search(r"\bami\b", rd.masked):
            v = _one(e["ami"] for e in sel)
        else:
            v = _one(i for e in sel for i in e["instance_ids"])
        return Fact("instance", src, [("as_logged", v)]) if v else None
    if p == "op":
        if not (rd.lits or rd.has("first", "last")):
            return None
        if k8s:
            v = _one(e["verb"] for e in sel) if re.search(r"\bverb\b", rd.masked) else None
        else:
            v = _one(e["op"] for e in sel)
            short = _one(e["op_short"] for e in sel)
            if v and short and short != v:
                return Fact("operation", src, [("as_logged", v), ("short", short)])
        return Fact("operation", src, [("as_logged", v)]) if v else None
    if p == "time":
        if not (rd.ops or rd.lits or rd.has("first", "last") or len(sel) == 1):
            return None
        if len({e["dt"] for e in sel}) != 1 or sel[0]["dt"] is None:
            return None
        raws = {e["time"] for e in sel}
        return Fact("time", src, time_options(sel[0]["dt"], sel[0]["time"] if len(raws) == 1 else None,
                                              date_first=bool(re.search(r"\bdate\b", rd.masked) and not re.search(r"\btime\b", rd.masked))))
    if p == "user":
        # Who acted, or whom it was done to: "who created ...", "which user created ..." ask for the
        # actor; "which user did X create", "which user was created", "the new user" for the object.
        m = rd.masked
        actor_q = re.match(r"who\b", m[rd.primary_pos:]) or _USER_ACTIVE.search(m)
        if not actor_q and (_USER_OBJECT.search(m) or rd.has("newuser") or rd.has("target")):
            if re.search(r"\bby$|\bby whom\b", m):
                return None
            if re.search(r"\bkeys?\b|\bpolic\w+|\battach\w*", m) or (rd.has("target") and not rd.has("newuser")):
                v = _one(e["target_user"] for e in sel if e["target_user"])
                return Fact("target_user", src, [("user_name", v)]) if v else None
            if rd.has("create"):
                v = _one(e["new_user"] for e in sel if e["new_user"])
                return Fact("created_user", src, [("user_name", v)]) if v else None
            return None
        if not actor_q and not re.search(r"\bby (?:which|what|whom)\b|\b(?:users?|principal|identity|caller|actor) (?:of|behind|for|in)\b|"
                                         r"\busers? ha(?:s|ve|d) (?:the |an? )?(?:access )?keys?\b|"
                                         r"\b(?:user ?name|identity|principal|caller|actor)\b(?! (?:is|was|are|were) (?:the |an? )?§)", m):
            return None                 # no wording says the one acting is asked ("which user is key X for")
        if "arn" in rd.fields:
            arn = _one(e["actor_arn"] for e in sel)
            return Fact("principal_arn", src, [("arn", arn)]) if arn else None
        return _identity_fact(sel, src)
    if p == "sa":
        pool = [e for e in sel if e["sa"]]
        if not pool:
            return None
        return _identity_fact(pool, src)
    if not k8s:
        return MISS
    if rd.has("exec"):
        sel = [e for e in sel if e["sensitive"] == "pod_exec"]
    if rd.has("privileged"):
        sel = [e for e in sel if e["privileged"]]
    if p == "pod":
        pool = [e for e in sel if e["resource"] == "pods"]
        if rd.has("create") and not rd.has("exec"):
            pool = [e for e in pool if e["verb"] == "create" and not e["subresource"]]
        v = _one(e["name"] for e in pool)
        return Fact("pod", src, [("name", v)]) if v else None
    if p in ("image", "container"):
        if p == "container":
            return None
        v = _one(i for e in sel for i in e["images"])
        return Fact("image", src, [("as_logged", v)]) if v else None
    if p in ("command", "cmd"):
        cmds = [tuple(e["command"]) for e in sel if e["command"]]
        if len(set(cmds)) != 1:
            return None
        return _list_fact("exec_command", src, list(cmds[0]))
    if p == "credential":
        if not re.search(r"\bsecrets?\b", rd.masked):
            return None
        pool = [e for e in sel if e["resource"] == "secrets" and e["name"]]
        if rd.has("read"):
            pool = [e for e in pool if e["verb"] == "get"]
        v = _one(e["name"] for e in pool)
        return Fact("secret_name", src, [("name", v)]) if v else None
    if p == "namespace" and "sa" in rd.fields:
        v = _one(e["sa_ns"] for e in sel if e["sa"])
        return Fact("service_account_namespace", src, [("name", v)]) if v else None
    if p == "namespace":
        if re.search(r"\bsecrets?\b", rd.masked):
            sel = [e for e in sel if e["resource"] == "secrets"]
        elif re.search(r"\bpods?\b", rd.masked):
            sel = [e for e in sel if e["resource"] == "pods"]
        if not (rd.lits or rd.ops or rd.has("exec", "privileged") or re.search(r"\bsecrets?\b|\bpods?\b", rd.masked)):
            return None
        v = _one(e["ns"] for e in sel)
        return Fact("namespace", src, [("name", v)]) if v else None
    if p in ("crb", "role"):
        pool = [e for e in sel if e["resource"] == "clusterrolebindings" and e["verb"] == "create"]
        if p == "role":
            v = _one(e["roleref"] for e in pool)
            return Fact("cluster_role", src, [("name", v)]) if v else None
        v = _one(e["name"] for e in pool)
        return Fact("clusterrolebinding", src, [("name", v)]) if v else None
    return MISS


# What a log question's verbs, literals and noun phrases must be accounted for before any answer.
# An exactly-one answer over events the question did not select is a coincidence, not a fact: a verb
# that narrowed nothing ("who created alice" read as "who is alice"), a literal in the wrong role
# ("which user did svc-backup create" answered with the user created FOR it), or a noun phrase that
# refers to something the file cannot resolve ("the new user", "the role") all give None.

_ACTIONS = tuple((n, re.compile(rx)) for n, rx in (
    ("login", r"\blog(?:ged|s|ging)? (?:in|on)\b|\blogins?\b|\blogons?\b|\bsign(?:ed|s|ing)? in\b|\bsignin\b"),
    ("read", r"\bread\w*|\bdownload\w*|\bretriev\w*|\bexfiltrat\w*|\bstole\w*|\bsteal\w*|\baccess(?:ed|es)\b|\bfetch\w*|\bpull\w*|"
             r"\bgets?\b|\bgot\b"),
    ("write", r"\bupload\w*|\bwrit\w*|\bwrote\b|\bputs?\b"),
    ("delete", r"\bdelet\w*|\bremov\w*|\bwiped\b|\berased\b"),
    ("create", r"\bcreat\w*|\bgenerat\w*|\bissued\b|\badd(?:ed|s|ing)?\b|\bintroduc\w*"),
    ("attach", r"\battach\w*"),
    ("assume", r"\bassum\w*"),
    ("stop", r"\bstop\w*|\bdisabl\w*|\bturned off\b"),
    ("launch", r"\blaunch\w*|\bstart(?:ed|s|ing)?\b|\bran\b|\brun(?:s|ning)?\b"),
    ("exec", r"\bexec\w*|\bshell\b"),
    ("grant", r"\bgrant\w*|\bbound\b"),
    ("change", r"\bchang\w*|\bmodif\w*|\bsets?\b|\bopen(?:ed)?\b|\bescalat\w*"),
    ("public", r"\bpublic\b"),
))
_OP_ACTIONS = {     # what an operation phrase of OP_PHRASES accounts for
    "consolelogin": {"login"}, "assumerole": {"assume"}, "assumerolewithsaml": {"assume"},
    "assumerolewithwebidentity": {"assume"}, "stoplogging": {"stop"}, "attachuserpolicy": {"attach"},
    "attachrolepolicy": {"attach"}, "attachgrouppolicy": {"attach"}, "putbucketpolicy": {"change", "public", "write"},
    "createaccesskey": {"create"}, "createuser": {"create"}, "runinstances": {"launch"},
}
_FIELD_ACTIONS = {  # what a field's own handler filters by
    "bucket": {"read"}, "object": {"read", "write", "delete"}, "file": {"read", "write", "delete"}, "key": {"create"},
    "trail": {"stop", "delete"}, "instance": {"launch"},
}
_REFER = re.compile(r"\b(?:by|did|does|has|had|from) (?:the |an? )(?:newly )?(?:(?:new|created|backdoor|rogue|assumed|compromised|added|"
                    r"attached|stolen|launched|deleted|same|malicious|suspicious|iam|aws) )*"
                    r"(?:users?|roles?|accounts?|keys?|access keys?|identity|principal|instances?|pods?|polic\w+|"
                    r"sessions?)\b(?! §)")
_REFER_CLASS = re.compile(r"\b(?:by|from|as|did|do) (?:(?:all|any|the|other|new|iam|aws|assumed|federated|root|service|human|console) )*"
                          r"(?:users|roles|accounts|identities|principals|services|keys|access keys|service ?accounts|root)\b(?! §)")
_NOUN = r"(?: (?:iam|aws|new))?(?: (?:user|role|account|principal|identity|access key|key|service ?account|ip address|ip|address|pod|" \
        r"bucket|object|file|trail|instance|policy|secret|namespace))?"
_SUBJ_BEFORE = re.compile(r"\b(?:by|did|does|has|had|use[ds]?|using)(?: the)?" + _NOUN + r"$")
_SUBJ_AFTER = re.compile(r"^ (?:use[ds]?|made|makes?|perform\w*|creat\w*|assum\w*|attach\w*|download\w*|reads?|log\w*|launch\w*|"
                         r"stop\w*|delet\w*|access(?:ed|es)|ran|runs?|sign\w*|upload\w*|exec\w*|call\w*|stole|did)\b")
_OBJ_BEFORE = re.compile(r"\b(?:(?:creat\w*|generat\w*|issued|made) for|to|into|on|named|called|creat\w*|assum\w*|attach\w*|read|download\w*|delet\w*|stop\w*|launch\w*|"
                         r"access(?:ed|es)|exec\w*)(?: the| an?)?" + _NOUN + r"$")
_PASSIVE_BEFORE = re.compile(r"\b(?:was|were|is|are|been|being)$")
_PASSIVE_AFTER = re.compile(r"^ (?:was|were|is|are|has been|had been|got) ")
_USERS_CREATED = re.compile(r"\busers? (?:was|were|have been|had been|got) (?:created|added)\b|"
                            r"\b(?:new|created|backdoor|rogue) (?:iam )?users?\b")


_LOGGED_IN = re.compile(r"\b(?:events?|records?|entries|calls?|requests?|activity|it|they) (?:were |was |are |is )?(?:logged|recorded) (?:in|on)\b")


def _actions(m: str) -> set:
    m = _LOGGED_IN.sub(" ", m)          # "the events were logged in <region>" is no login
    return {n for n, rx in _ACTIONS if rx.search(m)}


def _literal_roles(rd: Reading, sel: list):
    """`sel` narrowed by the role each named literal plays in the sentence: the one acting ("did X",
    "by X", "X created") or the one acted on ("created X", "for X", "X was created"). None when the
    events hold the literal in a role the sentence does not give it, or in both roles while the
    sentence gives neither."""
    m, at = rd.masked, -1
    for lit in rd.marks:
        at = m.find("§", at + 1)
        if at < 0:
            return None
        if lit is None or not sel:
            continue
        acts = any(lit in e["actor_vals"] for e in sel)
        objs = any(lit in e["obj_vals"] for e in sel)
        if not acts and not objs:
            continue                    # an attribute (a region, an account, a user agent)
        before, after = m[:at].rstrip(), m[at + 1:]
        role = None
        if _PASSIVE_AFTER.search(after) or (_PASSIVE_BEFORE.search(before) and _SUBJ_AFTER.search(after)):
            role = "object"
        elif _SUBJ_BEFORE.search(before) or _SUBJ_AFTER.search(after):
            role = "subject"
        elif _OBJ_BEFORE.search(before):
            role = "object"
        elif re.search(r"\bfrom$", before) and acts != objs:
            role = "subject" if acts else "object"
        if role is None and rd.primary in ("ip", "ua"):
            role = "subject" if acts else None      # a source address, a user agent: the acting one's
        if role is None:
            if acts and objs:
                return None
            continue
        if (role == "subject" and not acts) or (role == "object" and not objs):
            return None
        sel = [e for e in sel if lit in (e["actor_vals"] if role == "subject" else e["obj_vals"])]
    return sel


def _k8s_scope(rd: Reading, sel: list):
    """Kubernetes audit events narrowed by the question's verb and the resource it names; None for
    a verb this file cannot map onto an audit verb and one named resource."""
    m, acts = rd.masked, _actions(rd.masked)
    if rd.primary in ("command", "cmd"):
        acts -= {"launch"}
    if "exec" in acts:
        acts -= {"exec"}
        return [e for e in sel if e["sensitive"] == "pod_exec"] if not acts else None
    if rd.primary in ("crb", "role", "subject"):
        acts -= {"grant", "create"}     # the handler reads created bindings only
    if not acts:
        return sel
    if not acts <= {"create", "delete", "read"}:
        return None
    res = [r for r, rx in (("secrets", r"\bsecrets?\b"), ("pods", r"\bpods?\b"),
                           ("clusterrolebindings", r"\bclusterrolebindings?\b|\bcluster role bindings?\b|\bbindings?\b"))
           if re.search(rx, m)]
    if len(res) != 1:
        return None
    verbs = set()
    if "create" in acts:
        verbs.add("create")
    if "delete" in acts:
        verbs |= {"delete", "deletecollection"}
    if "read" in acts:
        verbs |= {"get", "list", "watch"}
    return [e for e in sel if e["resource"] == res[0] and not e["subresource"] and e["verb"] in verbs]


def _cloud_unaccounted(rd: Reading) -> set:
    """The action words of a cloud-log question that neither an operation it names nor its field's
    own handler narrows the events by."""
    m, acts = rd.masked, _actions(rd.masked)
    for op in rd.ops:
        if op not in _OP_ACTIONS:
            return set()                # an operation named by its own name: the question's verb is that operation
        acts -= _OP_ACTIONS[op]
    p = rd.primary
    if p == "count":
        p = next((f for f in rd.fields if f != "count"), None)
        if p == "user":
            return acts - ({"create"} if _USERS_CREATED.search(m) else set())
    elif p == "user":
        actor_q = re.match(r"who\b", m[rd.primary_pos:]) or _USER_ACTIVE.search(m)
        return acts - (set() if actor_q else {"create"})
    return acts - _FIELD_ACTIONS.get(p, set())


_COUNT_EVENTS = re.compile(r"\b(?:how many|number of|count of) (?:(?:total|distinct|unique|different|failed|successful|unsuccessful|denied|"
                           r"api|cloudtrail|log|logged|recorded|audit|aws|nomfa|withmfa|§) ){0,3}(?:events?|records?|entries|calls?|requests?)\b")
_COUNT_WORDS = set("""how many number count of events event records record entries entry calls call api requests request times attempts attempt
are there is was were be been in the logs log file files dataset evidence made make makes by from did does do done perform performed performs
come came comes originate originated for to on at a an total overall all logged recorded cloudtrail audit have has had that which with
using used use uses via failed fail fails failure failures unsuccessful denied successful succeeded succeed success successfully
unauthorized unauthorised error errors returned returning nomfa withmfa it they aws happen happened occur occurred took place seen observed
shown show shows""".split())
_COUNT_NOUN = re.compile(r"\b(?:the )?(?:iam |aws |source )?(?:user|users|account|access key|key|ip address|ip|address|role|bucket|trail|policy|"
                         r"instance|pod|namespace|secret|service ?account|region|principal|identity|user agent|operation|event|api call|action)"
                         r"(?: named| called| id)? §")
_OP_WORDS = {   # the words an operation phrase of OP_PHRASES is made of (accounted for when that operation is selected)
    "consolelogin": "console login logins logon logged logs logging signed signs signing sign signin into management",
    "assumerole": "assume assumed assumes assuming assumption role roles", "assumerolewithsaml": "assume assumed assumes assuming role roles",
    "assumerolewithwebidentity": "assume assumed assumes assuming role roles",
    "stoplogging": "stop stopped stops stopping disable disabled disables turned off logging trail cloudtrail",
    "attachuserpolicy": "attach attached attaches attaching policy policies user users",
    "attachrolepolicy": "attach attached attaches attaching policy policies role roles",
    "attachgrouppolicy": "attach attached attaches attaching policy policies",
    "putbucketpolicy": "bucket policy", "createaccesskey": "create created creates creating new access key keys",
    "createuser": "create created creates creating new backdoor rogue iam user users",
    "runinstances": "launch launched run ran running start started new ec2 instance instances",
}


def _count_residual(rd) -> list:
    """The words of an event-count question that nothing accounts for: not the count's own words,
    not a literal with its noun, not the words of an operation phrase that selected events."""
    m = _COUNT_NOUN.sub(" ", rd.masked).replace("§", " ")
    known = set(_COUNT_WORDS)
    for op in rd.phrase_ops:
        known.update(_OP_WORDS.get(op, "").split())
    return [w for w in m.split() if w not in known]


_ATTR_WORDS = set("""what which is was were are the a an of for in on at by from to that this these it its aws amazon gcp azure cloud account accounts
id ids identifier number region regions location project subscription tenant used use uses using logs log file files events event records record
recorded logged evidence dataset cloudtrail audit trail activity made make did does do call calls called api request requests come came happen
happened occur occurred take took place name named there where victim affected""".split())


def _attr_residual(rd) -> list:
    """The words of an account or region question that nothing accounts for. Every event of a log
    carries the log's own account and region, so a selection always has exactly one: a qualifier
    the reader did not understand ("given access to", "shared with", "in the bucket policy",
    "copied to") asks for another account or region than that one. An operation phrase is such a
    qualifier too: "the account ID in the bucket policy" is the policy's principal."""
    m = _COUNT_NOUN.sub(" ", rd.masked).replace("§", " ")
    return [w for w in re.findall(r"[a-z0-9']+", m) if w not in _ATTR_WORDS]


_LOG_FIELDS = {"session", "subject", "ip", "ua", "key", "role", "arn", "policy", "bucket", "object", "accountid", "region", "error", "trail", "instance", "op",
               "time", "user", "sa", "pod", "image", "command", "cmd", "credential", "namespace", "crb", "count", "file", "container"}


_NAME_AFTER = r"(?:by|did|does|from|for|to|as|of|user|role|bucket|pod|namespace|secret|account|named|called|key)"
_NAME_BEFORE = r"(?:use[ds]?|made|makes?|perform\w*|creat\w*|assum\w*|attach\w*|download\w*|reads?|log\w*|launch\w*|stop\w*|" \
               r"delet\w*|access(?:ed|es)|ran|runs?|sign\w*|upload\w*|exec\w*|call\w*|did|was|were|namespace|bucket|user|role|pod|" \
               r"account|secret|service ?account)"


def _shadowed(rd: Reading) -> bool:
    """True when a word of the question that was read as vocabulary is also a name in the logs and
    stands where a name would ("did admin", "the default namespace"): the events it would select
    were not selected."""
    for w in rd.shadow:
        w = re.escape(" ".join(re.findall(r"[a-z0-9]+", w)))
        if re.search(rf"\b{_NAME_AFTER} {w}\b|\b{w} {_NAME_BEFORE}\b", rd.masked):
            return True
    return False


def _log_answer(rd: Reading, ev: Evidence):
    """The logs' answer. Logs of several sources (CloudTrail beside a Kubernetes audit log) are
    asked one source at a time: a source takes part when it holds every literal and an operation
    the question names, and the sources that take part must give one fact."""
    if not ev.events or rd.primary not in _LOG_FIELDS:
        return MISS
    if rd.paths or rd.envs or rd.labels or rd.tf_addr or rd.tf_types or rd.tf_leafs:
        return MISS
    if _shadowed(rd):
        return None                     # "admin" the word or admin the user: not this file's call
    if len(ev.sources) <= 1:
        return _log_answer_one(rd, ev)
    facts = []
    for src in sorted(ev.sources):
        part = Evidence()
        part.events = [e for e in ev.events if e["src"] == src]
        part.sources[src] = len(part.events)
        if any(not any(lit in e["vals"] for e in part.events) for lit in rd.lits):
            continue
        if rd.ops and not any(_is_op(e, rd.ops) for e in part.events):
            continue
        got = _log_answer_one(rd, part)
        if got is MISS:
            continue
        if got is None:
            return None
        facts.append(got)
    if not facts:
        return MISS if not (rd.lits or rd.ops) else None
    if len(facts) > 1:
        return None                     # two logs, each with an answer of its own
    return facts[0]


_K8S_ONLY = {"pod", "image", "container", "command", "cmd", "credential", "namespace", "crb"}


def _log_answer_one(rd: Reading, ev: Evidence):
    src = ev.sources.most_common(1)[0][0]
    if src != "k8s_audit" and rd.primary in _K8S_ONLY:
        return MISS                     # fields only a Kubernetes audit log answers
    sel = _scope(rd, ev.events)
    if rd.mfa is not None:
        # only a console login records MFAUsed; one login that does not say stops the answer
        if src != "cloudtrail" or not ("login" in _actions(rd.masked) or "consolelogin" in rd.ops):
            return None
        sel = [e for e in sel if e["op"] == "ConsoleLogin"]
        if any(e["mfa"] not in ("Yes", "No") for e in sel):
            return None
        sel = [e for e in sel if (e["mfa"] == "Yes") == rd.mfa]
    if _REFER.search(rd.masked) or _REFER_CLASS.search(rd.masked):
        return None                     # "the new user", "the role", "by assumed roles": someone this file cannot point at
    sel = _literal_roles(rd, sel)
    if sel is None:
        return None
    if src == "k8s_audit":
        sel = _k8s_scope(rd, sel)
        if sel is None:
            return None
    elif _cloud_unaccounted(rd):
        return None                     # a verb that narrowed nothing
    if rd.has("first") != rd.has("last") and rd.primary != "count":
        sel = _edge(sel, rd.has("last"))
        if sel is None:
            return None
    if rd.primary == "count":
        nxt = next((f for f in rd.fields if f != "count"), None)
        m = rd.masked
        if rd.has("attacker"):
            return None                 # a count over a rule's selection is never exact
        loose = re.search(r"\b(?:how many|number of|count of) (?:\S+ ){0,3}(?:times|logins?|attempts?)\b", m)
        if re.search(r"\b(?:how many|number of|count of) (?:\S+ ){0,3}(?:event names?|operations?|actions?|methods?|verbs?)\b", m):
            names = len({e["op"] for e in sel})         # the names, or the events that carry them: plain only when equal
            return Fact("count", src + ".operations", [("distinct", str(names)), ("events", str(len(sel)))])
        if _COUNT_EVENTS.search(m) or (loose and rd.ops) or (nxt in (None, "op") and (rd.ops or rd.lits)):
            if ev.multi_stage or len(ev.sources) > 1 and not (rd.ops or rd.lits):
                return None
            if _count_residual(rd):
                return None             # a word that should have narrowed the events and did not ("by IAM users", "have a tag")
            ok = [e for e in sel if not e["failed"]]
            worded = (loose or rd.phrase_ops) and not rd.has("failed", "success") and not re.search(r"\battempt", m)
            if worded and len(ok) != len(sel):
                # "how many times was a role assumed" over calls of which some failed: the calls, or the ones that worked
                return Fact("count", src + ".events.outcome", [("successful", str(len(ok))), ("events", str(len(sel)))], forced=True)
            return Fact("count", src + ".events", [("events", str(len(sel)))])
        if loose:
            return None
        keymap = {"ip": "ips", "key": "key", "bucket": "bucket", "object": "object", "region": "region", "user": None, "pod": None}
        if nxt == "ip":
            vals = _distinct(sel, "ips")
            addrs = [v for v in vals if _is_address(v)]
            if len(addrs) == len(vals):
                return Fact("count", src + ".ip", [("distinct", str(len(vals)))])
            # CloudTrail writes a service's name where a service made the call ("AWS Internal",
            # "rds.amazonaws.com"): the addresses, or every distinct value of the field
            return Fact("count", src + ".ip.with_services", [("addresses", str(len(addrs))), ("source_values", str(len(vals)))], forced=True)
        made = "create" in _actions(m)
        if nxt == "key" and made:
            # Keys created, not the keys that signed the creating calls: every successful
            # CreateAccessKey must show the key it returned.
            calls = [e for e in sel if e["op"] == "CreateAccessKey" and not e["failed"]]
            if any(not e["new_key"] for e in calls):
                return None
            return Fact("count", src + ".created_key", [("distinct", str(len({e["new_key"] for e in calls})))])
        if nxt == "bucket":
            for flag, ops in (("read", READ_OPS), ("write", WRITE_OPS), ("delete", DELETE_OPS)):
                if rd.has(flag):
                    sel = [e for e in sel if _is_op(e, ops)]
        if nxt in ("key", "bucket", "region"):
            narrowed = bool(rd.ops or rd.lits or rd.has("read", "write", "delete", "failed", "success") or nxt == "region")
            return Fact("count", src + "." + nxt, [("distinct" if narrowed else "named_in_requests", str(len(_distinct(sel, keymap[nxt]))))],
                        forced=not narrowed)
        if nxt == "user" and made:
            if not _USERS_CREATED.search(m):
                return None             # "how many users created ...": the creators, or the created? not this file's call
            calls = [e for e in sel if e["op"] == "CreateUser" and not e["failed"]]
            if any(not e["new_user"] for e in calls):
                return None
            return Fact("count", src + ".created_user", [("distinct", str(len({e["new_user"] for e in calls})))])
        if nxt == "user":
            who = [e for e in sel if e["actor_arn"] or e["actor"]]
            if not who or not all(e["actor_logged"] and not e["sa"] for e in who):
                return None             # an assumed role, a service or a service account among them: is it a 'user'?
            return Fact("count", src + ".user", [("distinct", str(len({(e["actor_arn"], e["actor"]) for e in who})))])
        return MISS
    attempted = False
    if (rd.phrase_ops or _actions(rd.masked)) and not rd.has("failed", "success") and rd.primary != "error":
        # an action the question words as done ("which trail was stopped", "who created ..."): the calls that worked
        done = [e for e in sel if not e["failed"]]
        if done:
            sel = done                  # "which trail was stopped": the call that stopped one
        elif sel:
            attempted = True            # every such call failed: what was tried is not what was done
    fact = _log_fact(rd, sel, ev, src)
    if attempted and fact not in (None, MISS):
        fact.options = [("attempted_only:" + n, v) for n, v in fact.options]
        fact.forced = True
    if fact is MISS or fact is not None or not rd.has("attacker"):
        return fact
    # More than one candidate and the question speaks of the attacker: the stated rules of suspects().
    rules = suspects(ev.events)
    if not rules:
        return None
    if rd.primary == "ip":
        groups = OrderedDict()
        for rule, ips in rules.items():
            ips = [ip for ip in ips if any(ip in e["ips"] for e in sel)]
            if len(ips) == 1:
                groups.setdefault(ips[0], []).append(rule)
        opts = [("+".join(names), ip) for ip, names in sorted(groups.items(), key=lambda kv: -len(kv[1]))]
        return Fact("attacker_ip", src, opts, forced=True) if opts else None
    named = {ip for ips in rules.values() for ip in ips}
    if len(named) != 1:
        return None
    ip = next(iter(named))
    fact = _log_fact(rd, [e for e in sel if ip in e["ips"]], ev, src)
    if fact in (None, MISS):
        return None
    fact.options = [("+".join(rules) + ":" + n, v) for n, v in fact.options]
    fact.field, fact.forced = "attacker_" + fact.field, True
    return fact


# ---- answering from images -------------------------------------------------------------------------------

def _path_spellings(path: str, want_name: bool) -> list:
    out = [("absolute", "/" + path), ("relative", path)]
    base = path.rsplit("/", 1)[-1]
    return ([("basename", base)] + out) if want_name and base != path else out + ([("basename", base)] if base != path else [])


def _text_fact(field, shape, data: bytes, forced=False):
    """A file's content as an answer: one line of text; `KEY=value` also as its value."""
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if len(lines) != 1 or len(lines[0]) > 512:
        return None
    line = lines[0]
    m = re.fullmatch(r"(?:export\s+)?[\w.\-]+\s*[=:]\s*[\"']?(.+?)[\"']?", line)
    if m:
        return Fact(field, shape + ".kv", [("value", m.group(1)), ("line", line)], forced=forced)
    return Fact(field, shape, [("line", line)], forced=forced)


_FILE_ID = re.compile(r"\b(?:which|what) (?:\S+ ){0,2}(?:files?|paths?|filename)\b|\b(?:name|path) of the (?:\S+ ){0,2}files?\b")
_ADD_VERB = re.compile(r"\badd\w*|\bintroduc\w*|\bcreat\w*|\bcopied\b|\bwrote\b|\bplaced\b|\bdropped\b")
_DEL_VERB = re.compile(r"\bdelet\w*|\bremov\w*|\bwiped\b|\berased\b|\bwhiteouts?\b")


def _layer_verb(m: str):
    """What the layer asked for did, by the first such verb after the word 'layer': 'add',
    'delete', or None ("which layer added the file that was later deleted" asks for the add)."""
    at = re.search(r"\blayers?\b", m)
    tail = m[at.end():] if at else m
    a, d = _ADD_VERB.search(tail), _DEL_VERB.search(tail)
    if not a and not d:
        a, d = _ADD_VERB.search(m), _DEL_VERB.search(m)
    if a and (not d or a.start() < d.start()):
        return "add"
    return "delete" if d else None


def _layer_fact(rd: Reading, L: Layer, im: Image, shape: str):
    m = rd.masked
    if re.search(r"\bcommands?\b|\binstructions?\b", m):
        if not L.created_by:
            return None
        short = re.sub(r"^/bin/sh -c (?:#\(nop\)\s+)?", "", L.created_by).strip()
        return Fact("layer_command", shape, [("created_by", L.created_by)] + ([("without_shell_prefix", short)] if short != L.created_by else []))
    digests = L.digest_options()
    numbers = [("one_based", str(L.index + 1)), ("zero_based", str(L.index))]
    if "hash" in rd.fields or re.search(r"\bids?\b", m):
        return Fact("layer_digest", shape, digests, hexlike=True) if digests else None
    if re.search(r"\b(?:number|index)\b", m):
        return Fact("layer_number", shape, numbers)
    return Fact("layer", shape, digests + numbers)


def _image_answer(rd: Reading, ev: Evidence):
    if not ev.images:
        return MISS
    p, m = rd.primary, rd.masked
    if rd.lits or rd.ops or rd.tf_addr or rd.tf_types or rd.tf_leafs:
        return MISS
    ims = ev.images
    one = ims[0] if len(ims) == 1 else None
    shape = ims[0].layout

    def across(get):
        vals = [get(i) for i in ims]
        return vals[0] if all(v == vals[0] for v in vals) else None

    if p == "user" and re.search(r"\bauthor\b|\bmaintainer\b", m):
        p = "label"
    if p == "content" and rd.labels:
        p = "label"
    if p == "imageid":
        if not one:
            return None
        opts = [("config_digest", one.config_digest), ("config_digest_hex", (one.config_digest or ":").split(":", 1)[1] or None),
                ("manifest_digest", one.manifest_digest), ("manifest_digest_hex", (one.manifest_digest or ":").split(":", 1)[1] or None)]
        if one.config_digest:
            opts.insert(2, ("config_digest_short", one.config_digest.split(":", 1)[1][:12]))
        return Fact("image_id", shape, opts, hexlike=True)
    if p == "image" and rd.has("name") and re.search(r"\bnames? of the image\b|\bimage names?\b", m):
        tags = across(lambda i: tuple(i.tags))
        if not tags or len(tags) != 1:
            return None
        full = tags[0]
        repo = full.rsplit(":", 1)[0] if ":" in full.rsplit("/", 1)[-1] else full
        return Fact("image_name", shape, [("name_tag", full), ("name", repo), ("short_name", repo.rsplit("/", 1)[-1])])
    if p == "count":
        if re.search(r"\b(?:how many|number of|count of) (?:\S+ ){0,2}layers?\b", m):
            if rd.has("add", "delete", "create") or set(rd.fields) - {"count", "layer", "image", "container"} or rd.paths:
                return None             # the layers that did something: not the image's layer count
            n = across(lambda i: len(i.layers))
            return Fact("count", shape + ".layers", [("layers", str(n))]) if n is not None else None
        return MISS
    if p == "entrypoint" or p == "cmd":
        v = across(lambda i: i.entrypoint if p == "entrypoint" else i.cmd)
        return _list_fact(p, shape, v) if v else None
    if p == "workdir":
        v = across(lambda i: _s(i.cfg.get("WorkingDir")))
        return Fact("workdir", shape, [("as_configured", v)]) if v else None
    if p == "arch":
        v = across(lambda i: _s(i.config.get("architecture")))
        return Fact("architecture", shape, [("as_configured", v)]) if v else None
    if p == "os":
        v = across(lambda i: _s(i.config.get("os")))
        return Fact("os", shape, [("as_configured", v)]) if v else None
    if p == "port":
        ports = across(lambda i: tuple(sorted(i.cfg.get("ExposedPorts") or {})) if isinstance(i.cfg.get("ExposedPorts"), dict) else ())
        if not ports or len(ports) != 1:
            return None
        return Fact("exposed_port", shape, [("number", ports[0].split("/")[0]), ("with_protocol", ports[0])])
    if p == "label":
        if len(rd.labels) == 1:
            v = across(lambda i: _s((i.cfg.get("Labels") or {}).get(rd.labels[0])) if isinstance(i.cfg.get("Labels"), dict) else None)
            return Fact("label", shape, [("value", v)]) if v else None
        if re.search(r"\bmaintainer\b|\bauthor\b", m):
            def who(i):
                labs = i.cfg.get("Labels") if isinstance(i.cfg.get("Labels"), dict) else {}
                return _one([_s(i.config.get("author")), _s(labs.get("maintainer")), _s(labs.get("org.opencontainers.image.authors"))])
            v = across(who)
            return Fact("author", shape, [("as_configured", v)]) if v else None
        return None
    if p == "tag":
        tags = across(lambda i: tuple(i.tags))
        if not tags or len(tags) != 1:
            return None
        full = tags[0]
        tag = full.rsplit(":", 1)[-1] if ":" in full.rsplit("/", 1)[-1] else None
        return Fact("tag", shape, [("tag", tag), ("name_tag", full)] if re.search(r"\btags?\b", m) and not re.search(r"\bimage name\b", m)
                    else [("name_tag", full), ("tag", tag)])
    if p == "envvar" or (p in ("credential", "content") and (rd.envs or rd.has("env"))):
        if len(rd.envs) == 1:
            v = across(lambda i: i.env.get(rd.envs[0]))
            return Fact("env_value", shape, [("value", v)]) if v is not None and v != "" else None
        if rd.envs or not one:
            return None
        hits = [(k, v) for k, v in one.env.items() if _SECRET_NAME.search(k) and v]
        if len(hits) != 1:
            return None
        if p == "envvar" and re.search(r"\b(?:which|what|name of the) (?:\w+ )?(?:env\w*|variable)", m) and not re.search(r"\bvalue\b", m):
            return Fact("secret_env_name", shape, [("secret_named_env", hits[0][0])], forced=True)
        return Fact("secret_env_value", shape, [("secret_named_env:" + hits[0][0], hits[0][1])], forced=True)
    if p == "user":
        if not re.search(r"\b(?:run|runs|running|ran|configured|default)\b", m) or not re.search(r"\bimage|\bcontainer", m):
            return MISS
        v = across(lambda i: _s(i.cfg.get("User")))
        return Fact("image_user", shape, [("as_configured", v)]) if v else None
    if p == "time":
        if not re.search(r"\bimage\b", m) or not re.search(r"\bcreat\w*|\bbuil[dt]\w*", m) or rd.paths:
            return MISS
        raw = across(lambda i: _s(i.config.get("created")))
        return Fact("image_created", shape, time_options(parse_time(raw), raw)) if raw else None
    if not one:
        return None if p in ("layer", "file", "hash", "content", "credential", "command", "url") else MISS
    im = one
    gone = deleted_files(im)
    if rd.paths:
        paths = [x for x in dict.fromkeys(rd.paths)]
        if len(paths) != 1:
            return None
        path = paths[0]
        trail = find_path(im, path)
        adds = [t for t in trail if t["action"] in ("add", "modify")]
        dels = [t for t in trail if t["action"] == "delete"]
        if p in ("layer", "command") or (p == "hash" and "layer" in rd.fields):
            verb = _layer_verb(m)
            pool = dels if verb == "delete" else adds[:1] if verb == "add" or rd.has("first") else adds
            if len(pool) != 1:
                return None
            return _layer_fact(rd, pool[0]["layer"], im, shape)
        versions = [t["entry"] for t in adds if t["entry"].kind == "file"]
        if p == "hash":
            if len(rd.algos) != 1 or not versions:
                return None
            v = _one(en.digest(rd.algos[0]) for en in versions)
            if not v or any(en.digest(rd.algos[0]) is None for en in versions):
                return None
            return Fact("file_" + rd.algos[0], shape, [("hex", v)], hexlike=True)
        if p in ("content", "credential") or (p == "file" and not _FILE_ID.search(m) and "content" in rd.fields):
            if not versions or len({en.sha256 for en in versions}) != 1:
                return None
            return _text_fact("file_content", shape, versions[0].data)
        return None
    if rd.has("delete") and p in ("file", "hash", "content", "credential", "layer", "command"):
        if len(gone) != 1:
            return None
        g = gone[0]
        if p == "file" and _FILE_ID.search(m):
            return Fact("deleted_path", shape, _path_spellings(g["path"], rd.has("name") or bool(re.search(r"\bfilename\b", m))))
        if p == "file" and not ("content" in rd.fields or "credential" in rd.fields):
            return None
        if p == "hash" and "layer" not in rd.fields:
            if len(rd.algos) != 1:
                return None
            v = g["entry"].digest(rd.algos[0])
            return Fact("deleted_file_" + rd.algos[0], shape, [("hex", v)], hexlike=True) if v else None
        if p in ("layer", "command", "hash"):
            return _layer_fact(rd, g["added"] if _layer_verb(m) == "add" else g["deleted"], im, shape)
        return _text_fact("deleted_file_content", shape, g["entry"].data)
    if p == "hash":
        if re.search(r"\blayers?\b", m):
            return None
        if re.search(r"\bconfig\w*\b|\bimage (?:id|digest)\b|\bdigest of the image\b|\bimage\b", m) and not rd.has("delete"):
            opts = [("config_digest", im.config_digest), ("config_digest_hex", (im.config_digest or ":").split(":", 1)[1] or None),
                    ("manifest_digest", im.manifest_digest), ("manifest_digest_hex", (im.manifest_digest or ":").split(":", 1)[1] or None)]
            if re.search(r"\bmanifest\b", m):
                opts = opts[2:] + opts[:2]
            return Fact("image_digest", shape, opts, hexlike=True)
        return None
    if p == "url":
        urls = []
        for h in im.history:
            urls += _URL.findall(str(h.get("created_by") or ""))
        v = _one(urls)
        return Fact("build_url", shape, [("as_written", v)]) if v else None
    if p == "credential":
        # A secret anywhere in the image, found by its name or by having been removed: a rule's selection.
        word = next((w for w in ("password", "token") if re.search(r"\b%ss?\b" % w, m)), None)
        named = lambda text: word is None or word in text.lower() or (word == "password" and "passwd" in text.lower())
        cands = [("secret_named_env:" + k, v) for k, v in im.env.items() if _SECRET_NAME.search(k) and v and named(k)]
        for g in gone:
            f = _text_fact("x", "x", g["entry"].data)
            if f and named(g["path"]):
                cands += [("deleted_file:" + g["path"] + ":" + n, v) for n, v in f.options]
        if word and not cands:
            return MISS
        if len({v for _, v in cands}) == 1 or (len(cands) == 2 and cands[0][0].startswith("deleted_file") and cands[1][0].startswith("deleted_file")):
            return Fact("image_secret", shape, cands, forced=True)
        return None
    return MISS


# ---- answering from Terraform state -----------------------------------------------------------------------

_TF_PRIMARY = {
    "key": (("aws_iam_access_key", "id"),), "secretkey": (("aws_iam_access_key", "secret"),),
    "bucket": (("aws_s3_bucket", "bucket"), ("google_storage_bucket", "name")),
    "region": ((None, "region"),), "arn": ((None, "arn"),),
}


_TF_GENERIC = set("id name names value values type key keys arn user users secret secrets resource resources state version public "
                  "private time policy role tags tag description access region bucket password token".split())


_TF_STOP = set("""what which who whom whose when where why how many much is are was were be been being the a an of in on at to from for by with
as into via and or it its this that these those there here do does did has have had can could would should will stored store held kept
found used set given one any all some both same own not no""".split())


def _tf_answer(rd: Reading, ev: Evidence):
    if not ev.tfstates:
        return MISS
    if rd.lits or rd.ops or rd.paths or rd.envs or rd.labels:
        return MISS
    p, m = rd.primary, rd.masked
    spoken = bool(rd.tf_addr or rd.tf_types or rd.tf_leafs or _KIND_WORDS["tf"].search(m))
    if (ev.events or ev.images) and not spoken and p not in ("tfversion", "serial", "lineage"):
        return MISS
    if p in ("tfversion", "serial", "lineage"):
        key = {"tfversion": "terraform_version", "serial": "serial", "lineage": "lineage"}[p]
        if p == "tfversion" and not re.search(r"\bterraform\b", m):
            return MISS
        v = _one(_s(st.get(key)) for _, st in ev.tfstates)
        return Fact(p, "tfstate", [("as_written", v)]) if v and len(ev.tfstates) == 1 else None
    rows = [r for r in ev.tf_rows if isinstance(r["value"], (str, int, float)) and not isinstance(r["value"], bool) and r["value"] != ""]
    if p == "count":
        if not re.search(r"\b(?:how many|number of|count of) (?:\S+ ){0,2}resources?\b", m) or len(ev.tfstates) != 1:
            return MISS
        res = [r for r in ev.tfstates[0][1].get("resources") or [] if isinstance(r, dict)]
        if rd.tf_types:
            res = [r for r in res if str(r.get("type")).lower() in rd.tf_types]
        managed = [r for r in res if r.get("mode", "managed") == "managed"]
        inst = sum(len(r.get("instances") or []) for r in managed)
        return Fact("count", "tfstate.resources", [("resource_blocks", str(len(res))), ("managed", str(len(managed))), ("instances", str(inst))])
    narrowed = bool(rd.tf_addr or rd.tf_types or rd.tf_leafs)
    if rd.tf_addr:
        rows = [r for r in rows if r["address"] in rd.tf_addr]
    if rd.tf_types:
        rows = [r for r in rows if r["type"].lower() in rd.tf_types]
    if rd.tf_leafs:
        rows = [r for r in rows if r["leaf"].lower() in rd.tf_leafs]
        v = _one(str(r["value"]) for r in rows)
        return Fact("attribute", "tfstate", [("value", v)]) if v else None
    leafs = {r["leaf"].lower() for r in rows}
    if rd.tf_addr and len(set(rd.tf_addr)) == 1:
        # "the id of null_resource.bar": a generic attribute name counts when the resource is named
        generic = [w for w in dict.fromkeys(m.split()) if w in leafs and w in ("id", "arn", "name", "value")]
        if len(generic) == 1 and p not in ("count",):
            v = _one(str(r["value"]) for r in rows if r["leaf"].lower() == generic[0] and r["path"] == r["leaf"])
            return Fact("attribute", "tfstate." + generic[0], [("value", v)]) if v else None
    named = [w for w in dict.fromkeys(m.split()) if w in leafs and w not in _TF_GENERIC and w not in _TF_STOP]
    if len(named) == 1 and p not in ("count", "key", "secretkey", "arn"):
        v = _one(str(r["value"]) for r in rows if r["leaf"].lower() == named[0])
        return Fact("attribute", "tfstate." + named[0], [("value", v)]) if v else None
    if p in _TF_PRIMARY:
        pool = [r for r in rows if any((t is None or r["type"] == t) and r["path"] == leaf for t, leaf in _TF_PRIMARY[p])]
        if p == "arn":
            sub = next((f for f in rd.fields if f in ("role", "policy", "user", "bucket")), None)
            types = {"role": "aws_iam_role", "policy": "aws_iam_policy", "user": "aws_iam_user", "bucket": "aws_s3_bucket"}
            if sub:
                pool = [r for r in pool if r["type"] == types[sub]]
        v = _one(str(r["value"]) for r in pool)
        return Fact("tf_" + p, "tfstate", [("value", v)]) if v else None
    if p == "ip":
        want = "private_ip" if re.search(r"\bprivate\b", m) else "public_ip" if rd.has("public") else None
        pool = [r for r in rows if r["path"] in ((want,) if want else ("public_ip", "private_ip", "ip_address"))]
        v = _one(str(r["value"]) for r in pool)
        return Fact("tf_ip", "tfstate", [("value", v)]) if v else None
    if p in ("user", "role", "policy"):
        if not narrowed and not re.search(r"\bterraform\b|\bstate\b", m) and (ev.events or ev.images):
            return MISS
        t = {"user": "aws_iam_user", "role": "aws_iam_role", "policy": "aws_iam_policy"}[p]
        v = _one(str(r["value"]) for r in rows if r["type"] == t and r["path"] == "name")
        return Fact("tf_" + p, "tfstate", [("name", v)]) if v else None
    if p in ("credential", "content"):
        if rd.has("sensitive"):
            v = _one(str(r["value"]) for r in rows if r["sensitive"])
            return Fact("tf_sensitive", "tfstate", [("value", v)]) if v else None
        word = next((w for w in ("password", "token") if re.search(r"\b%ss?\b" % w, m)), None)
        if word:
            v = _one(str(r["value"]) for r in rows if word in r["leaf"].lower())
            return Fact("tf_" + word, "tfstate", [("value", v)]) if v else None
        if p == "content":
            return MISS
        marked = [r for r in rows if r["sensitive"]]
        pool = marked or [r for r in rows if r["secret_name"]]
        v = _one(str(r["value"]) for r in pool)
        if not v:
            return None
        r = next(x for x in pool if str(x["value"]) == v)
        return Fact("tf_secret", "tfstate", [(("marked_sensitive:" if marked else "secret_named:") + r["address"] + "." + r["path"], v)], forced=True)
    return MISS


# ---- answering from Dockerfiles, Compose files and Kubernetes manifests -----------------------------------

def _files_answer(rd: Reading, ev: Evidence):
    if not (ev.dockerfiles or ev.compose or ev.k8s):
        return MISS
    if rd.lits or rd.ops or rd.paths or rd.tf_addr or rd.tf_types or rd.tf_leafs:
        return MISS
    p, m = rd.primary, rd.masked
    finals = [df["stages"][-1] for _, df in ev.dockerfiles if df["stages"]]
    conts = [(o, c) for o in ev.k8s for c in o["containers"]]
    if rd.names:
        conts = [(o, c) for o, c in conts if o["name"] in rd.names or c["name"] in rd.names]
    services = [s for s in ev.compose if not rd.names or s["service"] in rd.names]
    if rd.has("privileged"):
        conts = [(o, c) for o, c in conts if c["privileged"]]
        services = [s for s in services if s["privileged"]]
    if p == "workload":
        v = _one(o["name"] for o, _ in conts)
        return Fact("workload", "manifest", [("name", v)]) if v else None
    if p == "service":
        v = _one(s["service"] for s in services)
        return Fact("compose_service", "manifest", [("name", v)]) if v and (rd.has("privileged") or len(ev.compose) == 1) else None
    if p == "base":
        if not ev.dockerfiles:
            return None
        bases = [st["base"] for _, df in ev.dockerfiles for st in (df["stages"][-1:] if rd.has("last") else df["stages"])]
        v = _one(bases)
        return Fact("base_image", "dockerfile", [("as_written", v)]) if v else None
    if p in ("entrypoint", "cmd"):
        vals = [st[p] for st in finals if st[p]]
        vals += [s["entrypoint" if p == "entrypoint" else "command"] for s in services if s["entrypoint" if p == "entrypoint" else "command"]]
        vals += [c["command" if p == "entrypoint" else "args"] for _, c in conts if c["command" if p == "entrypoint" else "args"]]
        keys = {json.dumps(v) for v in vals}
        if len(keys) != 1:
            return None
        v = vals[0]
        if isinstance(v, list):
            return _list_fact(p, "manifest", v)
        return Fact(p, "manifest.shell_form", [("as_written", str(v))])
    if p in ("user", "workdir"):
        if p == "user" and not re.search(r"\b(?:run|runs|running|ran|configured|default)\b", m):
            return MISS
        if p == "user" and (ev.k8s or ev.compose) and not re.search(r"\bdockerfile\b", m):
            return None                 # a manifest's runAsUser is not read here; the Dockerfile's USER may not be the answer
        v = _one([st[p] for st in finals if st[p]] + ([s["user"] for s in services if s["user"]] if p == "user" else []))
        return Fact("file_" + p, "manifest", [("as_written", v)]) if v else None
    if p == "port":
        ports = [x for st in finals for x in st["expose"]]
        if len(set(ports)) != 1 or any(s["ports"] for s in services):
            return None
        return Fact("exposed_port", "dockerfile", [("number", ports[0].split("/")[0])] + ([("with_protocol", ports[0])] if "/" in ports[0] else []))
    if p == "envvar" or (p in ("credential", "content") and (rd.envs or rd.has("env"))):
        envs = [st["env"] for st in finals] + [{k: v for k, v in st["arg"].items() if v} for st in finals] + \
               [s["env"] for s in services] + [c["env"] for _, c in conts]
        if len(rd.envs) == 1:
            every = [st for _, df in ev.dockerfiles for st in df["stages"]]
            envs = [st["env"] for st in every] + [{k: v for k, v in st["arg"].items() if v} for st in every] + \
                   [s["env"] for s in services] + [c["env"] for _, c in conts]
            sec = [o["secret"][rd.envs[0]] for o in ev.k8s if rd.envs[0] in o["secret"]]
            vals = [e[rd.envs[0]] for e in envs if e.get(rd.envs[0]) not in (None, "")]
            if sec and not vals:
                if len({s for s in sec}) != 1:
                    return None
                b64, dec = sec[0]
                return Fact("k8s_secret_value", "manifest", [("decoded", dec), ("base64", b64)])
            v = _one(vals)
            return Fact("env_value", "manifest", [("value", v)]) if v and not sec else None
        if rd.envs:
            return None
        hits = {(k, v) for e in envs for k, v in e.items() if _SECRET_NAME.search(k) and v}
        if len(hits) != 1:
            return None
        k, v = next(iter(hits))
        if p == "envvar" and not re.search(r"\bvalue\b", m):
            return Fact("secret_env_name", "manifest", [("secret_named_env", k)], forced=True)
        return Fact("secret_env_value", "manifest", [("secret_named_env:" + k, v)], forced=True)
    if p == "image":
        v = _one([c["image"] for _, c in conts if c["image"]] + [s["image"] for s in services if s["image"]])
        return Fact("manifest_image", "manifest", [("as_written", v)]) if v else None
    if p == "hostpath":
        v = _one([hp for o in ev.k8s for hp in o["host_paths"]] + [vol.split(":")[0] for s in services for vol in s["volumes"] if vol.startswith("/")])
        return Fact("host_path", "manifest", [("as_written", v)]) if v else None
    if p == "sa":
        v = _one(o["service_account"] for o in ev.k8s if o["service_account"])
        return Fact("service_account", "manifest", [("name", v)]) if v else None
    if p == "container" and rd.has("privileged"):
        v = _one(c["name"] for _, c in conts)
        return Fact("privileged_container", "manifest", [("name", v)]) if v else None
    if p == "pod" and rd.has("privileged"):
        if any(o["kind"] != "Pod" for o, _ in conts):
            return None                 # a workload's template: its pods carry generated names
        v = _one(o["name"] for o, _ in conts)
        return Fact("privileged_workload", "manifest", [("name", v)]) if v else None
    if p == "namespace":
        if not (rd.has("privileged") or rd.names):
            return MISS
        v = _one(o["ns"] for o, _ in conts)
        return Fact("namespace", "manifest", [("name", v)]) if v else None
    if p == "url":
        v = _one(u for _, df in ev.dockerfiles for st in df["stages"] for run in st["runs"] + st["copies"] for u in _URL.findall(run))
        return Fact("build_url", "dockerfile", [("as_written", v)]) if v else None
    return MISS


# ---- one question -----------------------------------------------------------------------------------------

_KIND_WORDS = {
    "logs": re.compile(r"\blogs?\b|\bcloudtrail\b|\baudit\b|\bevents?\b|\blogged\b"),
    "image": re.compile(r"\bimages?\b|\blayers?\b|\bdocker\b|\boci\b"),
    "tf": re.compile(r"\bterraform\b|\btfstate\b|\bstate\b"),
    "files": re.compile(r"\bdockerfile\b|\bcompose\b|\bmanifests?\b|\byaml\b|\bimages?\b"),
}

def answer(q, ev: Evidence, explain: list = None):
    """One question's answer: plain, an unsure string, or None. `explain` collects the reason."""
    def no(why):
        if explain is not None:
            explain.append(why)
        return None

    if ev.empty:
        return no("no cloud log, image, state or manifest in the files")
    rd = read_question(q, ev)
    if rd.why:
        return no(rd.why)
    facts = []
    # A question that names a kind of evidence the delivery holds is answered from that kind alone.
    have = {"logs": bool(ev.events), "image": bool(ev.images), "tf": bool(ev.tfstates), "files": bool(ev.dockerfiles or ev.compose or ev.k8s)}
    named = {k for k, rx in _KIND_WORDS.items() if have[k] and rx.search(rd.masked)}
    for kind, handler in (("logs", _log_answer), ("image", _image_answer), ("tf", _tf_answer), ("files", _files_answer)):
        if named and kind not in named:
            continue
        got = handler(rd, ev)
        if got is MISS:
            continue
        if kind in ev.cut:
            return no(f"the {kind} evidence was cut or did not parse whole: " + "; ".join(ev.notes[:3]))
        if got is None:
            return no(f"{kind}: not exactly one candidate for '{rd.primary}'")
        facts.append((kind, got))
    if not facts:
        return no(f"'{rd.primary}' is not a field the evidence present answers")
    if len({f.value for _, f in facts}) != 1:
        return no("two kinds of evidence answer differently: " + ", ".join(f"{k}={_safe(f.value, 40)}" for k, f in facts))
    out = emit(q, facts[0][1])
    if out is None:
        return no("the fact does not fit the answer format")
    if explain is not None:
        explain.append(f"{facts[0][0]}: {facts[0][1].field}/{facts[0][1].shape}" + (" (selected by a rule)" if facts[0][1].forced else ""))
    return out


def solve_set(questions, files, ctx) -> dict:
    """The runner contract. Evidence is read once per set; a question whose artifact names a member
    is answered from that member alone."""
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if _known_lane(questions):
        return out
    try:
        cache = {None: load(files, budget=BUDGET)}
    except Exception:
        return out
    if cache[None].empty:
        return out
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            member, ev = q.get("member"), cache[None]
            if member:
                hit = [k for k in files if k.split(ARROW)[-1] == member or k.split(ARROW)[-1].rsplit("/", 1)[-1] == str(member).rsplit("/", 1)[-1]]
                datas = {id(files[k]) for k in hit}
                if len(datas) == 1:
                    if member not in cache:
                        short = hit[0].split(ARROW)[-1]
                        cache[member] = load({k: v for k, v in files.items() if k in hit or k.startswith(short + ARROW)}, budget=BUDGET)
                    ev = cache[member] if not cache[member].empty else ev
            out[qid] = answer(q, ev)
        except Exception:       # a fact that cannot be read is no answer
            out[qid] = None
    return out


# ---- the command --------------------------------------------------------------------------------------------

def read_paths(paths) -> dict:
    """{name: bytes} of files and folders on disk (a folder is walked; an OCI layout folder becomes
    loose members), each file at most MAX_FILE."""
    out = {}
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(x for x in p.rglob("*") if x.is_file())[:MAX_MEMBERS]:
                if f.stat().st_size <= MAX_RAW:
                    out[f"{p.name}{ARROW}{f.relative_to(p).as_posix()}"] = f.read_bytes()
        elif p.is_file():
            out[p.name] = p.read_bytes()
        else:
            print(f"cloud_container.py: {raw} is not a file or a folder", file=sys.stderr)
    return out


def summary(ev: Evidence) -> dict:
    s = {"kinds": dict(ev.kinds), "cut": sorted(ev.cut), "notes": ev.notes[:20]}
    if ev.events:
        ev_t = sorted((e for e in ev.events if e["dt"]), key=lambda e: e["dt"])
        s["logs"] = {
            "sources": dict(ev.sources), "events": len(ev.events),
            "first": ev_t[0]["time"] if ev_t else None, "last": ev_t[-1]["time"] if ev_t else None,
            "operations": Counter(e["op"] for e in ev.events).most_common(25),
            "source_ips_by_principal": source_ips_by_principal(ev.events),
            "access_keys_used": access_keys_used(ev.events), "access_keys_created": access_keys_created(ev.events),
            "assumed_roles": assumed_roles(ev.events), "object_reads": object_reads(ev.events)[:50],
            "sensitive": [{"time": e["time"], "op": e["op"], "class": e["sensitive"], "by": e["actor_arn"] or e["actor"], "ips": e["ips"],
                           "target": e["target_user"] or e["bucket"] or e["trail"] or e["name"]} for e in sensitive_events(ev.events)][:60],
            "pod_execs": pod_execs(ev.events), "secret_reads": secret_reads(ev.events)[:50],
            "privileged_pods": privileged_pods(ev.events), "cluster_role_bindings": cluster_role_bindings(ev.events),
            "suspects": suspects(ev.events), "failed": sum(1 for e in ev.events if e["failed"])}
    s["images"] = []
    for im in ev.images:
        s["images"].append({
            "origin": im.origin, "layout": im.layout, "tags": im.tags, "config_digest": im.config_digest,
            "manifest_digest": im.manifest_digest, "architecture": im.config.get("architecture"), "os": im.config.get("os"),
            "created": im.config.get("created"), "entrypoint": im.entrypoint, "cmd": im.cmd, "env": dict(im.env),
            "user": im.cfg.get("User"), "workdir": im.cfg.get("WorkingDir"), "labels": im.cfg.get("Labels"),
            "exposed_ports": sorted(im.cfg.get("ExposedPorts") or {}) if isinstance(im.cfg.get("ExposedPorts"), dict) else [],
            "history": [{"created_by": h.get("created_by"), "empty_layer": bool(h.get("empty_layer"))} for h in im.history],
            "layers": [{"number": L.index + 1, "digests": L.digest_options(), "created_by": L.created_by, "files": len(L.entries),
                        "whiteouts": L.whiteouts, "opaque": L.opaque,
                        "paths": [p for p, en in L.entries.items() if en.kind != "dir"][:40]} for L in im.layers],
            "deleted": [{"path": g["path"], "added_in": g["added"].index + 1, "deleted_in": g["deleted"].index + 1,
                         "size": g["entry"].size, "sha256": g["entry"].sha256,
                         "text": (g["entry"].data or b"")[:300].decode("utf-8", "replace")} for g in deleted_files(im)],
            "problems": im.problems + [p for L in im.layers for p in L.problems]})
    s["tfstates"] = [{"file": name, "terraform_version": st.get("terraform_version"), "serial": st.get("serial"), "lineage": st.get("lineage"),
                      "resources": sorted({r["address"] for r in tf_leaves(st) if r["mode"] != "output"}),
                      "sensitive": [{"address": r["address"], "path": r["path"], "value": r["value"],
                                     "why": "marked sensitive" if r["sensitive"] else "name"} for r in tf_sensitive(st)][:80]}
                     for name, st in ev.tfstates]
    s["dockerfiles"] = [{"file": name, "stages": df["stages"]} for name, df in ev.dockerfiles]
    s["compose"] = ev.compose
    s["k8s"] = [{k: v for k, v in o.items()} for o in ev.k8s]
    return s


def render(s: dict) -> str:
    L = ["# cloud_container triage", ""]
    L += [f"- {_safe(n, 100)}: {k}" for n, k in s["kinds"].items()] or ["- nothing this toolkit reads"]
    if s["cut"]:
        L += ["", "CUT (nothing is answered from these kinds): " + ", ".join(s["cut"])]
    L += [f"NOTE {_safe(n)}" for n in s["notes"]]
    lg = s.get("logs")
    if lg:
        L += ["", f"## Logs: {lg['events']} events, " + ", ".join(f"{k} {v}" for k, v in lg["sources"].items()),
              f"first {_safe(lg['first'])}  last {_safe(lg['last'])}  failed {lg['failed']}", "", "operations: "
              + ", ".join(f"{_safe(o, 60)} x{n}" for o, n in lg["operations"])]
        L += ["", "source IPs by principal:"] + [f"  {_safe(p, 120)}: {', '.join(_safe(i, 45) for i in ips)}" for p, ips in lg["source_ips_by_principal"].items()]
        if lg["access_keys_used"]:
            L += ["", "access keys used:"] + [f"  {_safe(k, 40)}: {r['events']} events, by {', '.join(_safe(a, 80) for a in r['actors'])}, "
                                              f"from {', '.join(_safe(i, 45) for i in r['ips'])}" for k, r in lg["access_keys_used"].items()]
        for title, key in (("access keys created", "access_keys_created"), ("assumed roles", "assumed_roles"), ("object reads", "object_reads"),
                           ("sensitive operations", "sensitive"), ("pod execs", "pod_execs"), ("secret reads", "secret_reads"),
                           ("privileged pods", "privileged_pods"), ("cluster role bindings", "cluster_role_bindings")):
            if lg[key]:
                L += ["", title + ":"] + ["  " + _safe(json.dumps(r, ensure_ascii=False, default=str), 400) for r in lg[key]]
        if lg["suspects"]:
            L += ["", "suspect source IPs (rule: IPs):"] + [f"  {r}: {', '.join(_safe(i, 45) for i in ips)}" for r, ips in lg["suspects"].items()]
    for im in s["images"]:
        L += ["", f"## Image {_safe(im['origin'], 100)} ({im['layout']}) tags {_safe(im['tags'])}",
              f"config {im['config_digest']}  manifest {im['manifest_digest']}  {_safe(im['os'])}/{_safe(im['architecture'])}  created {_safe(im['created'])}",
              f"entrypoint {_safe(im['entrypoint'])}  cmd {_safe(im['cmd'])}  user {_safe(im['user'])}  workdir {_safe(im['workdir'])}  ports {_safe(im['exposed_ports'])}",
              "env:"] + [f"  {_safe(k, 80)}={_safe(v)}" for k, v in im["env"].items()]
        L += ["history:"] + [f"  {'-' if h['empty_layer'] else 'L'} {_safe(h['created_by'], 220)}" for h in im["history"]]
        for l in im["layers"]:
            L += [f"layer {l['number']}: {l['files']} entries; " + "; ".join(f"{n} {v}" for n, v in l["digests"][:4])]
            L += [f"    created by: {_safe(l['created_by'], 200)}"] if l["created_by"] else []
            L += [f"    removes: {', '.join(_safe(w, 100) for w in l['whiteouts'] + [d + '/ (opaque)' for d in l['opaque']])}"] if l["whiteouts"] or l["opaque"] else []
            L += ["    " + ", ".join(_safe(p, 100) for p in l["paths"])] if l["paths"] else []
        for g in im["deleted"]:
            L += [f"DELETED {_safe(g['path'], 160)}: added in layer {g['added_in']}, removed in layer {g['deleted_in']}, {g['size']} bytes, "
                  f"sha256 {g['sha256']}", f"    text: {_safe(g['text'], 300)}"]
        L += [f"PROBLEM {_safe(p)}" for p in im["problems"]]
    for t in s["tfstates"]:
        L += ["", f"## Terraform state {_safe(t['file'], 100)}: terraform {_safe(t['terraform_version'])}, serial {_safe(t['serial'])}, lineage {_safe(t['lineage'])}",
              "resources: " + ", ".join(_safe(a, 80) for a in t["resources"])]
        L += [f"  {r['why']}: {_safe(r['address'], 80)}.{_safe(r['path'], 80)} = {_safe(r['value'])}" for r in t["sensitive"]]
    for d in s["dockerfiles"]:
        L += ["", f"## Dockerfile {_safe(d['file'], 100)}"]
        for st in d["stages"]:
            L += [f"  FROM {_safe(st['base'])}" + (f" AS {_safe(st['name'])}" if st["name"] else "") + f"  entrypoint {_safe(st['entrypoint'])}  cmd {_safe(st['cmd'])}"
                  f"  user {_safe(st['user'])}  expose {_safe(st['expose'])}"]
            L += [f"    ENV {_safe(k, 80)}={_safe(v)}" for k, v in st["env"].items()] + [f"    ARG {_safe(k, 80)}={_safe(v)}" for k, v in st["arg"].items()]
            L += [f"    RUN {_safe(r, 200)}" for r in st["runs"]]
    if s["compose"]:
        L += ["", "## Compose services"] + ["  " + _safe(json.dumps(c, ensure_ascii=False, default=str), 400) for c in s["compose"]]
    if s["k8s"]:
        L += ["", "## Kubernetes objects"] + ["  " + _safe(json.dumps(o, ensure_ascii=False, default=str), 500) for o in s["k8s"]]
    return "\n".join(L) + "\n"


def main(argv) -> int:
    args, as_json, find, ask = [], False, None, None
    it = iter(argv)
    for a in it:
        if a == "--json":
            as_json = True
        elif a == "--find":
            find = next(it, None)
        elif a == "--ask":
            ask = next(it, None)
        elif a.startswith("--"):
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 2
        else:
            args.append(a)
    if not args:
        print("usage: cloud_container.py <file | folder>... [--json] [--find PATH] [--ask \"question\"]", file=sys.stderr)
        return 2
    files = read_paths(args)
    if not files:
        return 1
    ev = load(files, max_total=8 * MAX_TOTAL)
    if find is not None:
        for im in ev.images:
            trail = find_path(im, find)
            print(f"{_safe(im.origin, 100)}: {_safe(find, 160)}" + ("" if trail else " is in no layer"))
            for t in trail:
                en = t["entry"]
                print(f"  layer {t['layer'].index + 1} {t['action']}" + (f" {en.kind} {en.size} bytes sha256 {en.sha256}" if en else "")
                      + f"  ({'; '.join(f'{n} {v}' for n, v in t['layer'].digest_options()[:2])})")
                if en is not None and en.data is not None and en.kind == "file":
                    print("    text: " + _safe(en.data[:400].decode("utf-8", "replace"), 400))
        return 0
    if ask is not None:
        why = []
        got = answer({"id": "ask", "question": ask}, ev, why)
        print(f"answer: {_safe(got, 600) if got is not None else 'None'}")
        print("because: " + "; ".join(_safe(w, 300) for w in why))
        return 0
    s = summary(ev)
    print(json.dumps(s, indent=1, ensure_ascii=False, default=str) if as_json else render(s), end="" if not as_json else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
