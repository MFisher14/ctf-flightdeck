"""B-066: the cloud-log pivot (solvers/toolkits/cloudlogs.py --pivot), its two written rules, the flag
template filler, the access-log join (web_evidence.ip_activity) and the route / [intake] table.

  .venv/bin/python -m pytest tests/test_toolkits_cloudlogs_pivot.py

Offline. Every log is built here in the layout of the real exports (the Entra portal's sign-in and
audit-log CSV downloads with their BOM and quoted header, Purview's AuditData CSV, Graph JSON, an nginx
combined log): the column names are Microsoft's, every value is invented. Nothing of a challenge is read.

The scene: one mailbox (dana), her usual address HOME, and an address EVIL that signs in through a
device-code flow, registers a device, makes a forwarding rule and downloads files. A second device and
a second rule, made from HOME a day earlier, are the decoys.
"""
from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

import cloudlogs as cl
import web_evidence as we
from ctf import event, flagfmt, triage
from ctf.engines import manifest as M
from ctf.engines import router
from ctf.intake import engines as E
from ctf.intake import guard as G

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "solvers" / "toolkits" / "cloudlogs.manifest.toml"
BOM = b"\xef\xbb\xbf"

USER = "dana@northwind.example"
HOME, EVIL, OTHER = "198.51.100.7", "203.0.113.9", "192.0.2.44"
DEV_OK, DEV_DECOY = "LAB-RELAY-01", "FRONT-DESK-PC"
ID_OK, ID_DECOY = "11111111-2222-4333-8444-555555555555", "99999999-8888-4777-8666-555555555555"
RULE_OK, RULE_DECOY = "Invoices-Fwd", "Weekly-Digest"

SIGNIN_COLS = ["Date (UTC)", "Request ID", "User agent", "Correlation ID", "User ID", "User", "Username", "User type",
               "Authentication Protocol", "Original transfer method", "Application", "IP address", "Location", "Status",
               "Sign-in error code", "Failure reason", "Client app", "Device ID", "Join Type"]
AUDIT_COLS = (["Date (UTC)", "CorrelationId", "Service", "Category", "Activity", "Result", "ResultReason", "User Agent",
               "ActorType", "ActorDisplayName", "ActorObjectId", "ActorUserPrincipalName", "IPAddress"]
              + [f"Target{t}{c}" for t in (1, 2) for c in
                 ("Type", "DisplayName", "ObjectId", "UserPrincipalName", "ModifiedProperty1Name", "ModifiedProperty1OldValue",
                  "ModifiedProperty1NewValue", "ModifiedProperty2Name", "ModifiedProperty2OldValue", "ModifiedProperty2NewValue")]
              + [f"AdditionalDetail{n}{c}" for n in (1, 2, 3, 4, 5) for c in ("Key", "Value")])
UAL_COLS = ["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData", "AssociatedAdminUnits",
            "AssociatedAdminUnitsNames"]


def _csv(cols, rows, bom=True, quote=True) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL if quote else csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(cols)
    for r in rows:
        w.writerow([r.get(c, "") for c in cols])
    return (BOM if bom else b"") + buf.getvalue().encode("utf-8")


_N = [0]


def _rid() -> str:
    _N[0] += 1
    return f"00000000-0000-4000-8000-{_N[0]:012d}"


def signin(t, ip, status="Success", proto="none", transfer="none", device_id="", code=None) -> dict:
    return {"Date (UTC)": t, "Request ID": _rid(), "User agent": "Mozilla/5.0", "Correlation ID": _rid(), "User ID": "u-1",
            "User": "Dana Field", "Username": USER, "User type": "member", "Authentication Protocol": proto,
            "Original transfer method": transfer, "Application": "Office Web", "IP address": ip, "Location": "Somewhere, XX",
            "Status": status, "Sign-in error code": code if code is not None else ("" if status == "Success" else "50126"),
            "Failure reason": "Other.", "Client app": "Browser", "Device ID": device_id,
            "Join Type": "Azure AD joined" if device_id else ""}


def register(t, ip, name, device_id, result="Success") -> dict:
    return {"Date (UTC)": t, "CorrelationId": _rid(), "Service": "Device Registration Service", "Category": "Device",
            "Activity": "Register device", "Result": result, "ResultReason": "(blank)", "User Agent": "Mozilla/5.0",
            "ActorType": "User", "ActorUserPrincipalName": USER, "IPAddress": ip, "Target1Type": "Device",
            "Target1DisplayName": name, "AdditionalDetail1Key": "AdditionalInfo", "AdditionalDetail1Value": "joined",
            "AdditionalDetail2Key": "Device Profile", "AdditionalDetail2Value": "RegisteredDevice",
            "AdditionalDetail3Key": "Device Trust Type", "AdditionalDetail3Value": "Azure AD join",
            "AdditionalDetail4Key": "Device OS", "AdditionalDetail4Value": "Windows",
            "AdditionalDetail5Key": "Device Id", "AdditionalDetail5Value": device_id}


def companion(t, name, activity="Add registered owner to device") -> dict:
    return {"Date (UTC)": t, "CorrelationId": _rid(), "Service": "Core Directory", "Category": "Device", "Activity": activity,
            "Result": "Success", "ActorType": "Application", "ActorDisplayName": "Device Registration Service",
            "Target1Type": "User", "Target1ObjectId": "u-1", "Target1UserPrincipalName": USER,
            "Target1ModifiedProperty1Name": "Device.ObjectID", "Target1ModifiedProperty1NewValue": '"obj-' + name + '"',
            "Target1ModifiedProperty2Name": "Device.DisplayName", "Target1ModifiedProperty2NewValue": '"' + name + '"',
            "Target2Type": "Device", "Target2ObjectId": "obj-" + name,
            "AdditionalDetail1Key": "User-Agent", "AdditionalDetail1Value": "Microsoft.OData.Client/7.12.5"}


def ual(t, op, ip, **data) -> dict:
    rid = _rid()
    audit = {"CreationTime": t, "Id": rid, "Operation": op, "OrganizationId": "org-1", "RecordType": 1, "UserKey": "k",
             "UserType": 0, "Version": 1, "Workload": data.pop("Workload", "Exchange"), "UserId": USER, **data}
    if ip is not None:
        audit["ClientIP"] = ip
    return {"RecordId": rid, "CreationDate": t + ".0000000Z ", "RecordType": "1", "Operation": op, "UserId": USER,
            "AuditData": json.dumps(audit, separators=(",", ":"))}


def rule(t, ip, name, **params) -> dict:
    ps = [{"Name": "Name", "Value": name}] + [{"Name": k, "Value": v} for k, v in params.items()]
    return ual(t, "New-InboxRule", ip, Parameters=ps, ResultStatus="True", ObjectId="store\\" + name)


def download(t, ip, name, site="https://northwind.example/sites/ops/Shared Documents/") -> dict:
    return ual(t, "FileDownloaded", ip, Workload="SharePoint", ObjectId=site + name, SourceFileName=name)


def scene(*, extra_signins=(), extra_audit=(), extra_ual=(), device_code=True, dc_status="Success") -> dict:
    """{name: bytes} of the base scene: the attacker's device, rule and three downloads, and the decoys."""
    dc = {"transfer": "deviceCodeFlow"} if device_code else {}
    signins = [
        signin("2026-03-01T08:00:10Z", HOME), signin("2026-03-01T09:10:00Z", HOME), signin("2026-03-02T08:01:00Z", HOME),
        signin("2026-03-02T08:02:00Z", HOME, status="Failure"),
        signin("2026-03-02T14:00:05Z", EVIL, status=dc_status, proto="deviceCode" if device_code else "none", **dc),
        signin("2026-03-02T14:03:00Z", EVIL, status=dc_status, device_id=ID_OK, **dc),
        signin("2026-03-02T14:20:00Z", EVIL, status=dc_status, device_id=ID_OK, **dc),
        *extra_signins]
    audit = [
        register("2026-03-01T08:05:00.1251443+00:00", HOME, DEV_DECOY, ID_DECOY),
        companion("2026-03-01T08:04:59.5793697+00:00", DEV_DECOY),
        companion("2026-03-01T08:04:59.5823736+00:00", DEV_DECOY, "Add registered users to device"),
        register("2026-03-02T14:01:00.1251443+00:00", EVIL, DEV_OK, ID_OK),
        companion("2026-03-02T14:00:59.5793697+00:00", DEV_OK),
        {"Date (UTC)": "2026-03-02T09:00:00.0000000+00:00", "CorrelationId": _rid(), "Service": "Core Directory",
         "Category": "UserManagement", "Activity": "Update user", "Result": "Success", "ActorType": "Application",
         "ActorDisplayName": "Some Service", "Target1Type": "User", "Target1UserPrincipalName": USER},
        *extra_audit]
    records = [
        rule("2026-03-01T08:30:00", HOME + ":51224", RULE_DECOY, MoveToFolder="Digest", FromAddressContainsWords="digest;noreply"),
        rule("2026-03-02T14:25:00", EVIL + ":17091", RULE_OK, ForwardTo="drop@elsewhere.example", StopProcessingRules="True"),
        download("2026-03-02T14:10:00", EVIL, "plan.docx"), download("2026-03-02T14:10:30", EVIL, "roster.xlsx"),
        download("2026-03-02T14:11:00", EVIL, "map.jpg"), download("2026-03-02T09:30:00", HOME, "lunch.pdf"),
        ual("2026-03-02T09:00:00", "MailItemsAccessed", HOME), ual("2026-03-02T14:12:00", "MailItemsAccessed", EVIL),
        *extra_ual]
    return {"InteractiveSignIns_2026-03-01_2026-03-02.csv": _csv(SIGNIN_COLS, signins),
            "AuditLogs_2026-03-02.csv": _csv(AUDIT_COLS, audit),
            "UnifiedAuditLog.csv": _csv(UAL_COLS, records, bom=False, quote=False)}


def _pivot(files, named=(), access=None):
    log = cl.load(files)
    return log, cl.pivot(log.events, named, access)


def _verdicts(pv, kind) -> dict:
    return {a["name"]: (a["verdict"], a["why"]) for a in pv["artifacts"] if a["kind"] == kind}


TEMPLATE = "spooky{<device_name>_<rule_name>_<download_count>}"
FLAG = f"spooky{{{DEV_OK}_{RULE_OK}_3}}"


# ---------------------------------------------------------------- reading the exports

def test_the_portal_audit_csv_is_read_as_entra_audit():
    log = cl.load({"AuditLogs.csv": scene()["AuditLogs_2026-03-02.csv"]})
    assert log.sources == {"entra_audit": 6} and log.whole and not log.other
    reg = [e for e in log.events if e["op"] == "Register device"]
    assert [(e["ip"], e["target"], e["actor"], e["result"]) for e in reg] == [
        (HOME, DEV_DECOY, USER, "success"), (EVIL, DEV_OK, USER, "success")]
    assert reg[1]["time"].isoformat() == "2026-03-02T14:01:00.125144+00:00"
    assert cl.signals([], {"a.csv": scene()["AuditLogs_2026-03-02.csv"]}) == 0.7
    # the rows carry no record id: two rows of one correlation are two events, never a duplicate
    assert all(e["id"] is None for e in log.events)


def test_a_csv_without_the_audit_columns_is_not_an_audit_log():
    other = _csv(["Date (UTC)", "Activity", "Owner", "Notes"], [{"Date (UTC)": "2026-03-02T14:01:00Z", "Activity": "Register device"}])
    log = cl.load({"todo.csv": other})
    assert not log.events and len(log.other) == 1
    assert cl.signals([], {"todo.csv": other}) == 0.0


def test_registered_devices_reads_the_csv_rows_and_folds_companions():
    log = cl.load(scene())
    devs = cl.registered_devices(log.events)
    assert [(d["name"], d["device_id"], d["ip"], d["record"], d["companions"]) for d in devs] == [
        (DEV_DECOY, ID_DECOY, HOME, "register", 2), (DEV_OK, ID_OK, EVIL, "register", 1)]
    assert devs[1]["os"] == "Windows" and devs[1]["trust_type"] == "Azure AD join" and devs[1]["object_id"] == "obj-" + DEV_OK


def test_a_device_named_only_by_the_directory_rows_has_no_ip():
    files = scene(extra_audit=[companion("2026-03-02T15:00:00.0000000+00:00", "GHOST-BOX"),
                               companion("2026-03-02T15:00:00.1000000+00:00", "GHOST-BOX", "Add device")])
    log, pv = _pivot(files)
    ghost = [d for d in cl.registered_devices(log.events) if d["name"] == "GHOST-BOX"]
    assert len(ghost) == 1 and ghost[0]["record"] == "companion" and ghost[0]["ip"] is None and ghost[0]["companions"] == 2
    assert _verdicts(pv, "device")["GHOST-BOX"] == ("unattributed", "no_ip")
    assert cl.template_values(pv)["device"] == [DEV_OK]


def test_a_companion_row_joins_the_nearest_registration_of_that_name():
    files = scene(extra_audit=[register("2026-03-02T16:00:00.0000000+00:00", EVIL, DEV_DECOY, "44444444-0000-4000-8000-000000000000"),
                               companion("2026-03-02T15:59:59.0000000+00:00", DEV_DECOY)])
    devs = [d for d in cl.registered_devices(cl.load(files).events) if d["name"] == DEV_DECOY]
    assert [(d["ip"], d["companions"]) for d in devs] == [(HOME, 2), (EVIL, 1)]


def test_registered_devices_reads_graph_json():
    doc = {"value": [{"id": "a1", "category": "Device", "activityDisplayName": "Register device", "result": "success",
                      "activityDateTime": "2026-03-02T14:01:00Z",
                      "initiatedBy": {"user": {"userPrincipalName": USER, "ipAddress": EVIL}},
                      "targetResources": [{"type": "Device", "displayName": DEV_OK, "id": "obj-1", "modifiedProperties": []}],
                      "additionalDetails": [{"key": "Device OS", "value": "Linux"}, {"key": "Device Id", "value": ID_OK}]},
                     {"id": "a2", "category": "Device", "activityDisplayName": "Add registered owner to device", "result": "success",
                      "activityDateTime": "2026-03-02T14:00:59Z", "initiatedBy": {"app": {"displayName": "Device Registration Service"}},
                      "targetResources": [{"type": "User", "userPrincipalName": USER, "modifiedProperties": [
                          {"displayName": "Device.DisplayName", "newValue": '"' + DEV_OK + '"'},
                          {"displayName": "Device.ObjectID", "newValue": '"obj-1"'}]}],
                      "additionalDetails": []}]}
    log = cl.load({"audit.json": json.dumps(doc).encode()})
    devs = cl.registered_devices(log.events)
    assert [(d["name"], d["device_id"], d["ip"], d["os"], d["object_id"], d["companions"]) for d in devs] == [
        (DEV_OK, ID_OK, EVIL, "Linux", "obj-1", 1)]


def test_device_code_signins_names_the_marker():
    log = cl.load(scene())
    got = [(how, e["ip"], e["time"].strftime("%H:%M:%S")) for how, e in cl.device_code_signins(log.events)]
    assert got == [("authentication_protocol", EVIL, "14:00:05"), ("original_transfer_method", EVIL, "14:03:00"),
                   ("original_transfer_method", EVIL, "14:20:00")]
    late = cl.load(scene(extra_signins=[signin("2026-03-02T14:01:30Z", EVIL, transfer="deviceCodeFlow")])).events
    assert [e["time"].strftime("%H:%M:%S") for _how, e in cl.device_code_signins(late)] == ["14:00:05", "14:01:30", "14:03:00", "14:20:00"]
    graph = {"value": [{"id": "s1", "createdDateTime": "2026-03-02T14:00:05Z", "userPrincipalName": USER, "ipAddress": EVIL,
                        "appDisplayName": "x", "status": {"errorCode": 0}, "authenticationProtocol": "deviceCode",
                        "deviceDetail": {"deviceId": ID_OK}},
                       {"id": "s2", "createdDateTime": "2026-03-02T08:00:00Z", "userPrincipalName": USER, "ipAddress": HOME,
                        "appDisplayName": "x", "status": {"errorCode": 0}, "authenticationProtocol": "oAuth2",
                        "originalTransferMethod": "none", "deviceDetail": {"deviceId": ""}}]}
    ev = cl.load({"signins.json": json.dumps(graph).encode()}).events
    assert [(how, e["ip"]) for how, e in cl.device_code_signins(ev)] == [("authentication_protocol", EVIL)]
    assert [cl.signin_device_id(e) for e in cl.signins(ev)] == [None, ID_OK]
    # the marker is the field's value, however an export spells it; another protocol is not one
    for value, want in (("Device Code", "authentication_protocol"), ("device_code", "authentication_protocol"),
                        ("ropc", None), ("deviceCodeFlow", None), ("", None)):
        one = cl.load({"s.csv": _csv(SIGNIN_COLS, [signin("2026-03-02T14:00:05Z", EVIL, proto=value)])}).events[0]
        assert cl.device_code(one) == want, value
    assert cl.device_code(cl.load({"u.csv": _csv(UAL_COLS, [ual("2026-03-02T14:00:05", "UserLoggedIn", EVIL)], bom=False)}).events[0]) is None


def test_downloads_reads_file_object_and_ip():
    log = cl.load(scene())
    got = [(d["file"], d["ip"], d["object"].rsplit("/", 1)[0]) for d in cl.downloads(log.events)]
    synced = cl.load({"u.csv": _csv(UAL_COLS, [ual("2026-03-02T14:10:00", "FileSyncDownloadedFull", EVIL, SourceFileName="s.db"),
                                               ual("2026-03-02T14:10:01", "FileAccessed", EVIL, SourceFileName="seen.txt"),
                                               ual("2026-03-02T14:10:02", "FileUploaded", EVIL, SourceFileName="up.txt")],
                                    bom=False, quote=False)}).events
    assert [(d["file"], d["op"]) for d in cl.downloads(synced)] == [("s.db", "FileSyncDownloadedFull")]
    assert got == [("lunch.pdf", HOME, "https://northwind.example/sites/ops/Shared Documents"),
                   ("plan.docx", EVIL, "https://northwind.example/sites/ops/Shared Documents"),
                   ("roster.xlsx", EVIL, "https://northwind.example/sites/ops/Shared Documents"),
                   ("map.jpg", EVIL, "https://northwind.example/sites/ops/Shared Documents")]


@pytest.mark.parametrize("raw,want", [("203.0.113.9:17091", "203.0.113.9"), ("[2001:DB8::1]:443", "2001:db8::1"),
                                      ("::ffff:203.0.113.9", "203.0.113.9"), ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
                                      (" 203.0.113.9 ", "203.0.113.9"), ("[::ffff:203.0.113.9]:80", "203.0.113.9"),
                                      ("203.0.113.009", None), ("-", None),
                                      ("true", None), ("", None), (None, None)])
def test_ip_key_is_one_spelling_per_address(raw, want):
    # cloudlogs.ip_key and web_evidence.ip_key are two copies (each docstring points here): the access-log join
    # holds only while they agree, so every spelling is checked against both
    assert cl.ip_key(raw) == want
    assert we.ip_key(raw) == want


# ---------------------------------------------------------------- the attacker rule

def test_the_device_code_address_is_the_attacker_and_no_other():
    log, pv = _pivot(scene())
    assert list(pv["attackers"]) == [EVIL]
    a = pv["attackers"][EVIL]
    assert a["why"] == ["device_code"] and a["device_code_signins"] == 3
    assert a["first_signin"].isoformat() == "2026-03-02T14:00:05+00:00"
    rows = {r["ip"]: r for r in pv["ips"]}
    assert pv["ips"][0]["ip"] == EVIL and rows[EVIL]["attacker"] == ["device_code"] and rows[HOME]["attacker"] == []


def test_without_a_device_code_signin_nothing_is_named_and_nothing_attributed():
    log, pv = _pivot(scene(device_code=False))
    assert pv["attackers"] == {}
    assert {a["verdict"] for a in pv["artifacts"]} == {"undecided"} and {a["why"] for a in pv["artifacts"]} == {"no_attacker_ip"}
    assert any("no attacker IP" in n for n in pv["notes"])
    filled = cl.fill_template(TEMPLATE, pv)
    assert filled["flag"] is None and any("no attacker IP" in w for w in filled["why"])
    assert cl.template_values(pv) == {"device": [], "rule": [], "downloads": [], "ip": [], "forward_to": [], "device_id": []}


def test_a_device_code_signin_that_never_succeeded_names_no_attacker():
    log, pv = _pivot(scene(dc_status="Failure"))
    assert pv["attackers"] == {}
    assert any(EVIL in n and "never succeeded" in n for n in pv["notes"])


def test_a_named_address_is_an_attacker_and_a_bad_one_is_refused():
    log, pv = _pivot(scene(device_code=False), named=[EVIL + ":443"])
    assert pv["attackers"][EVIL]["why"] == ["named"]
    assert cl.fill_template(TEMPLATE, pv)["flag"] == FLAG
    log, both = _pivot(scene(), named=[EVIL])
    assert both["attackers"][EVIL]["why"] == ["named", "device_code"]
    with pytest.raises(ValueError, match="not an IP address"):
        cl.pivot(log.events, ["evil.example"])
    log, pv = _pivot(scene(), named=[OTHER])
    assert f"attacker IP {OTHER} appears in no cloud event" in pv["notes"]
    assert [(r["ip"], r["events"]) for r in pv["ips"]] == [(EVIL, 9), (OTHER, 0), (HOME, 8)]     # the attackers' rows first


# ---------------------------------------------------------------- the decoy rule

def test_the_decoys_are_rejected_with_their_reason():
    log, pv = _pivot(scene())
    assert _verdicts(pv, "device") == {DEV_DECOY: ("rejected", "other_ip"), DEV_OK: ("attributed", "ip+device_id")}
    assert _verdicts(pv, "rule") == {RULE_DECOY: ("rejected", "other_ip"), RULE_OK: ("attributed", "ip")}
    assert _verdicts(pv, "download") == {"lunch.pdf": ("rejected", "other_ip"), "plan.docx": ("attributed", "ip"),
                                         "roster.xlsx": ("attributed", "ip"), "map.jpg": ("attributed", "ip")}
    decoy = next(a for a in pv["artifacts"] if a["name"] == DEV_DECOY)
    assert HOME in decoy["detail"] and "not an attacker IP" in decoy["detail"]


def test_an_artifact_older_than_the_first_signin_from_the_attacker_ip_is_rejected():
    # the attacker's address was used a day earlier (a shared exit): what was made then is not the attacker's
    files = scene(extra_audit=[register("2026-03-01T10:00:00.0000000+00:00", EVIL, "OLD-KIOSK", "77777777-0000-4000-8000-000000000000")],
                  extra_ual=[rule("2026-03-02T14:00:04", EVIL, "Early-Rule", ForwardTo="x@elsewhere.example"),
                             download("2026-03-01T10:05:00", EVIL, "old.txt")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "device")["OLD-KIOSK"] == ("rejected", "predates_first_signin")
    assert _verdicts(pv, "rule")["Early-Rule"] == ("rejected", "predates_first_signin")       # one second before 14:00:05
    assert _verdicts(pv, "download")["old.txt"] == ("rejected", "predates_first_signin")
    old = next(a for a in pv["artifacts"] if a["name"] == "OLD-KIOSK")
    assert "2026-03-01 10:00:00Z" in old["detail"] and "2026-03-02 14:00:05Z" in old["detail"]
    assert cl.fill_template(TEMPLATE, pv)["flag"] == FLAG


def test_an_artifact_at_the_moment_of_the_first_signin_is_kept():
    files = scene(extra_ual=[rule("2026-03-02T14:00:05", EVIL, RULE_OK, ForwardTo="drop@elsewhere.example")])
    log, pv = _pivot(files)
    assert [a["verdict"] for a in pv["artifacts"] if a["kind"] == "rule" and a["name"] == RULE_OK] == ["attributed", "attributed"]


def test_a_device_without_an_ip_is_joined_by_its_device_id():
    doc = {"value": [{"id": "g1", "category": "Device", "activityDisplayName": "Register device", "result": "success",
                      "activityDateTime": "2026-03-02T14:02:00Z", "initiatedBy": {"user": {"userPrincipalName": USER}},
                      "targetResources": [{"type": "Device", "displayName": "NO-IP-BOX", "id": "obj-9"}],
                      "additionalDetails": [{"key": "Device Id", "value": ID_OK.upper()}]},
                     {"id": "g2", "category": "Device", "activityDisplayName": "Register device", "result": "success",
                      "activityDateTime": "2026-03-02T14:02:30Z", "initiatedBy": {"user": {"userPrincipalName": USER}},
                      "targetResources": [{"type": "Device", "displayName": "STRAY-BOX", "id": "obj-8"}],
                      "additionalDetails": [{"key": "Device Id", "value": "abcdabcd-0000-4000-8000-000000000000"}]}]}
    files = {k: v for k, v in scene().items() if not k.startswith("AuditLogs")}
    files["audit.json"] = json.dumps(doc).encode()
    log, pv = _pivot(files)
    assert _verdicts(pv, "device") == {"NO-IP-BOX": ("attributed", "device_id"), "STRAY-BOX": ("unattributed", "no_ip")}
    row = next(r for r in pv["ips"] if r["ip"] == EVIL)
    assert [a["name"] for a in row["devices"]] == ["NO-IP-BOX"]


def _graph_device(gid, t, name, device_id, ip=None) -> dict:
    who = {"userPrincipalName": USER, **({"ipAddress": ip} if ip else {})}
    return {"id": gid, "category": "Device", "activityDisplayName": "Register device", "result": "success",
            "activityDateTime": t, "initiatedBy": {"user": who},
            "targetResources": [{"type": "Device", "displayName": name, "id": "obj-" + gid}],
            "additionalDetails": [{"key": "Device Id", "value": device_id}]}


def _with_graph_devices(*devices, extra_signins=()) -> dict:
    files = {k: v for k, v in scene(extra_signins=extra_signins).items() if not k.startswith("AuditLogs")}
    files["audit.json"] = json.dumps({"value": list(devices)}).encode()
    return files


@pytest.mark.parametrize("audit_spelling,signin_spelling", [(str.upper, str.lower), (str.lower, str.upper)])
def test_a_device_id_joins_its_signins_whatever_its_letter_case(audit_spelling, signin_spelling):
    hex_id = "aaaabbbb-cccc-4ddd-8eee-ffff00001111"
    files = _with_graph_devices(_graph_device("h1", "2026-03-02T14:02:00Z", "HEX-BOX", audit_spelling(hex_id)),
                                extra_signins=[signin("2026-03-02T14:05:00Z", EVIL, device_id=signin_spelling(hex_id))])
    log, pv = _pivot(files)
    assert _verdicts(pv, "device")["HEX-BOX"] == ("attributed", "device_id")
    assert next(a for a in pv["artifacts"] if a["name"] == "HEX-BOX")["id_ips"] == [EVIL]


def test_a_device_with_no_ip_whose_device_id_signs_in_from_another_address_is_other_ip():
    files = _with_graph_devices(_graph_device("h2", "2026-03-02T14:02:00Z", "HOME-BOX", "bbbbcccc-0000-4000-8000-000000000001"),
                                extra_signins=[signin("2026-03-02T15:00:00Z", HOME, device_id="bbbbcccc-0000-4000-8000-000000000001")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "device")["HOME-BOX"] == ("rejected", "other_ip")
    box = next(a for a in pv["artifacts"] if a["name"] == "HOME-BOX")
    assert box["ip"] is None and f"made from {HOME}," in box["detail"]


def test_a_rejected_device_is_not_listed_under_the_attacker_ip_its_device_id_signs_in_from():
    # the decoy (registered from HOME a day earlier) later signs in from EVIL: joined by its Device Id, but older
    # than EVIL's first sign-in, so rejected, and EVIL's row does not list it; HOME's row (its own IP) does
    log, pv = _pivot(scene(extra_signins=[signin("2026-03-02T15:00:00Z", EVIL, device_id=ID_DECOY)]))
    assert _verdicts(pv, "device")[DEV_DECOY] == ("rejected", "predates_first_signin")
    rows = {r["ip"]: r for r in pv["ips"]}
    assert [a["name"] for a in rows[EVIL]["devices"]] == [DEV_OK]
    assert [a["name"] for a in rows[HOME]["devices"]] == [DEV_DECOY]


def test_the_device_own_ip_sets_the_time_window_before_its_device_id_ip():
    # two attacker IPs: EVIL2 (named) first signs in at 13:00, EVIL at 14:00:05. A device registered from EVIL at
    # 13:30 whose Device Id later signs in from EVIL2 is judged by EVIL's window (its own record's IP): rejected.
    evil2 = "203.0.113.77"
    did = "cccc0000-0000-4000-8000-000000000002"
    files = scene(extra_signins=[signin("2026-03-02T13:00:00Z", evil2), signin("2026-03-02T15:00:00Z", evil2, device_id=did)],
                  extra_audit=[register("2026-03-02T13:30:00.0000000+00:00", EVIL, "EARLY-BOX", did)])
    log, pv = _pivot(files, named=[evil2])
    early = next(a for a in pv["artifacts"] if a["name"] == "EARLY-BOX")
    assert early["id_ips"] == [evil2] and (early["verdict"], early["why"]) == ("rejected", "predates_first_signin")
    assert f"before the first sign-in from {EVIL} (2026-03-02 14:00:05Z)" in early["detail"]
    # after EVIL's first sign-in the same device is the attacker's, by both joins
    files = scene(extra_signins=[signin("2026-03-02T13:00:00Z", evil2), signin("2026-03-02T15:00:00Z", evil2, device_id=did)],
                  extra_audit=[register("2026-03-02T14:30:00.0000000+00:00", EVIL, "LATE-BOX", did)])
    log, pv = _pivot(files, named=[evil2])
    assert _verdicts(pv, "device")["LATE-BOX"] == ("attributed", "ip+device_id")


@pytest.mark.parametrize("evil2_first,registered,verdict,named_ip,named_start", [
    # EVIL2 signs in first (13:00): a device registered at 13:30 is inside EVIL2's window, though before EVIL's
    ("13:00:00", "13:30:00", ("attributed", "device_id"), "203.0.113.77", "13:00:00"),
    # EVIL signs in first (14:00:05): the window and the detail are EVIL's, though EVIL2 sorts first as a string
    ("15:00:00", "14:30:00", ("attributed", "device_id"), EVIL, "14:00:05"),
    ("15:00:00", "13:59:00", ("rejected", "predates_first_signin"), EVIL, "14:00:05"),
])
def test_a_device_id_seen_from_two_attacker_ips_takes_the_earliest_first_signin(evil2_first, registered, verdict, named_ip,
                                                                                named_start):
    # a device record with no IP whose Device Id signs in from two attacker IPs (EVIL by device code, EVIL2 named) with
    # different first sign-ins: DECOY_RULE opens its window at the earlier of the two, and the detail names that IP
    evil2 = "203.0.113.77"
    did = "dddd0000-0000-4000-8000-000000000003"
    files = _with_graph_devices(_graph_device("m1", f"2026-03-02T{registered}Z", "TWO-IP-BOX", did),
                                extra_signins=[signin(f"2026-03-02T{evil2_first}Z", evil2),
                                               signin("2026-03-02T15:10:00Z", evil2, device_id=did),
                                               signin("2026-03-02T15:20:00Z", EVIL, device_id=did)])
    log, pv = _pivot(files, named=[evil2])
    box = next(a for a in pv["artifacts"] if a["name"] == "TWO-IP-BOX")
    assert box["ip"] is None and box["id_ips"] == [evil2, EVIL]
    assert (box["verdict"], box["why"]) == verdict
    want = f"from {named_ip} " if verdict[0] == "rejected" else f"from attacker IP {named_ip}, "
    assert want in box["detail"] and f"(2026-03-02 {named_start}Z)" in box["detail"], box["detail"]
    assert "earliest first sign-in among them" in cl.DECOY_RULE


@pytest.mark.parametrize("status,code", [("Failure", "50126"), ("Interrupted", "50074")])
def test_a_signin_that_opened_no_session_does_not_start_the_attacker_window(status, code):
    # a password spray from EVIL at 13:00 (failed, or stopped at an MFA prompt), a rule from EVIL at 13:30, the
    # device-code success at 14:00:05: the rule predates every session from EVIL
    files = scene(extra_signins=[signin("2026-03-02T13:00:00Z", EVIL, status=status, code=code)],
                  extra_ual=[rule("2026-03-02T13:30:00", EVIL, "Spray-Rule", ForwardTo="x@elsewhere.example")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "rule")["Spray-Rule"] == ("rejected", "predates_first_signin")
    assert pv["attackers"][EVIL]["first_signin"].isoformat() == "2026-03-02T14:00:05+00:00"
    assert next(r for r in pv["ips"] if r["ip"] == EVIL)["first_signin"].isoformat() == "2026-03-02T13:00:00+00:00"   # the table


def test_a_signin_with_no_stated_result_starts_the_attacker_window():
    files = scene(extra_signins=[signin("2026-03-02T13:00:00Z", EVIL, status="", code="")],
                  extra_ual=[rule("2026-03-02T13:30:00", EVIL, "Quiet-Rule", ForwardTo="x@elsewhere.example")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "rule")["Quiet-Rule"] == ("attributed", "ip")
    assert pv["attackers"][EVIL]["first_signin"].isoformat() == "2026-03-02T13:00:00+00:00"


def test_downloads_are_counted_by_their_full_path_not_their_name():
    files = scene(extra_ual=[download("2026-03-02T14:15:00", EVIL, "plan.docx", site="https://northwind.example/sites/ops/Archive/")])
    log, pv = _pivot(files)
    assert cl.template_values(pv)["downloads"] == ["4"]
    assert cl.fill_template(TEMPLATE, pv)["flag"] == f"spooky{{{DEV_OK}_{RULE_OK}_4}}"


def test_removing_a_rule_is_not_making_one():
    gone = ual("2026-03-02T14:40:00", "Remove-InboxRule", EVIL, Parameters=[{"Name": "Identity", "Value": "dana\\" + RULE_DECOY}])
    log, pv = _pivot(scene(extra_ual=[gone]))
    assert [r["kind"] for r in cl.inbox_rules(log.events)] == ["create", "create", "remove"]
    assert [a["name"] for a in pv["artifacts"] if a["kind"] == "rule"] == [RULE_DECOY, RULE_OK]
    assert cl.template_values(pv)["rule"] == [RULE_OK]


def test_a_failed_registration_is_not_the_attackers_device():
    files = scene(extra_audit=[register("2026-03-02T14:05:00.0000000+00:00", EVIL, "FAILED-BOX", "66666666-0000-4000-8000-000000000000",
                                        result="Failure")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "device")["FAILED-BOX"] == ("rejected", "failed")
    assert cl.template_values(pv)["device"] == [DEV_OK]


def test_a_named_attacker_with_no_signin_skips_the_time_check_and_says_so():
    files = {k: v for k, v in scene().items() if "SignIns" not in k}
    log, pv = _pivot(files, named=[EVIL])
    dev = next(a for a in pv["artifacts"] if a["name"] == DEV_OK)
    assert dev["verdict"] == "attributed" and "time check was not applied" in dev["detail"]
    assert pv["attackers"][EVIL]["first_signin"] is None


def test_a_record_with_no_time_is_not_attributed():
    files = scene(extra_ual=[download("not-a-time", EVIL, "undated.bin")])
    log, pv = _pivot(files)
    assert _verdicts(pv, "download")["undated.bin"] == ("unattributed", "no_time")
    assert cl.template_values(pv)["downloads"] == ["3"]


# ---------------------------------------------------------------- the per-IP rows

def test_the_rows_join_signins_devices_rules_and_downloads_per_ip():
    log, pv = _pivot(scene())
    d = cl.pivot_data(pv)
    rows = {r["ip"]: r for r in d["ips"]}
    evil, home = rows[EVIL], rows[HOME]
    assert evil["signins"] == {"success": 3} and evil["device_code_signins"] == 3 and evil["accounts"] == [USER]
    assert evil["first_signin"] == "2026-03-02 14:00:05Z" and evil["last_signin"] == "2026-03-02 14:20:00Z"
    assert [a["name"] for a in evil["devices"]] == [DEV_OK] and [a["name"] for a in evil["rules"]] == [RULE_OK]
    assert evil["downloads"] == 3 and evil["rules"][0]["forward_to"] == ["drop@elsewhere.example"]
    assert home["signins"] == {"success": 3, "failure": 1} and home["device_code_signins"] == 0
    assert [a["name"] for a in home["devices"]] == [DEV_DECOY] and [a["name"] for a in home["rules"]] == [RULE_DECOY]
    assert home["downloads"] == 1 and home["rules"][0]["move_to"] == "Digest"
    assert dict(evil["top_ops"])["FileDownloaded"] == 3 and dict(evil["top_ops"])["sign-in"] == 3
    assert "event" not in json.dumps(d["artifacts"][0]) and json.loads(json.dumps(d))["attackers"][EVIL]["why"] == ["device_code"]
    assert d["attacker_rule"] == cl.ATTACKER_RULE and d["decoy_rule"] == cl.DECOY_RULE


def test_the_written_rules_say_what_the_code_does():
    assert "device-code" in cl.ATTACKER_RULE and "SUCCESSFUL" in cl.ATTACKER_RULE and "--attacker-ip" in cl.ATTACKER_RULE
    for word in ("other_ip", "predates_first_signin", "failed", "no_ip", "no_time", "no_attacker_ip", "first sign-in",
                 "failed or interrupted does not count", "states no result does"):
        assert word in cl.DECOY_RULE, word
    assert set(cl.NO_SESSION) == {"failure", "interrupted"}


# ---------------------------------------------------------------- the access-log join

def _access_log() -> bytes:
    lines = [
        f'{EVIL} - - [02/Mar/2026:13:58:00 +0000] "GET /login?next=/portal HTTP/1.1" 200 512 "-" "curl/8.1"',
        f'{EVIL} - - [02/Mar/2026:13:59:10 +0000] "POST /devicelogin HTTP/1.1" 302 0 "-" "curl/8.1"',
        f'{HOME} - - [02/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
        f'{OTHER} - - [02/Mar/2026:07:00:00 +0000] "GET /robots.txt HTTP/1.1" 404 10 "-" "bot/1"',
        f'10.0.0.5 - - [02/Mar/2026:14:30:00 +0000] "GET /export HTTP/1.1" 200 9000 "-" "curl/8.1" "{EVIL}, 10.0.0.9"',
        f'10.0.0.5 - - [02/Mar/2026:14:31:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "probe" "0.004"',
        f'10.0.0.6 - - [02/Mar/2026:14:32:00 +0000] "GET /a HTTP/1.1" 200 2 "-" "probe" "{OTHER}, unknown"',
        f'10.0.0.7 - - [02/Mar/2026:14:33:00 +0000] "GET /b HTTP/1.1" 200 2 "-" "probe" "10.0.0.7"',
    ]
    return ("\n".join(lines) + "\n").encode()


def test_parse_access_keeps_a_forwarded_for_list_and_nothing_else():
    evs = we.read_log(_access_log(), "access.log")
    assert len(evs) == 8 and {e["kind"] for e in evs} == {"access_combined"}
    assert evs[4]["extra"]["forwarded_for"] == [EVIL, "10.0.0.9"] and evs[4]["ip"] == "10.0.0.5"
    assert "forwarded_for" not in evs[5]["extra"] and evs[5]["extra"]["rest"] == '"0.004"'      # a request time is no address
    assert all("forwarded_for" not in e["extra"] for e in evs[:4])
    assert "forwarded_for" not in evs[6]["extra"]                 # one item is no address: the field is not a list of them
    assert evs[7]["extra"]["forwarded_for"] == ["10.0.0.7"]


def test_ip_activity_counts_peers_and_forwarded_addresses_apart():
    act = we.ip_activity(we.read_log(_access_log(), "access.log"))
    assert set(act) == {EVIL, HOME, OTHER, "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.9"}
    assert act[OTHER]["forwarded"] == 0                                       # "<address>, unknown" names nobody
    assert act["10.0.0.7"]["requests"] == 1 and act["10.0.0.7"]["forwarded"] == 0      # a peer naming itself is one request
    evil = act[EVIL]
    assert evil["requests"] == 2 and evil["forwarded"] == 1 and dict(evil["forwarded_via"]) == {"10.0.0.5": 1}
    assert evil["first"].isoformat() == "2026-03-02T13:58:00+00:00" and evil["last"].isoformat() == "2026-03-02T13:59:10+00:00"
    assert dict(evil["statuses"]) == {200: 1, 302: 1} and dict(evil["methods"]) == {"GET": 1, "POST": 1}
    assert dict(evil["paths"]) == {"/login": 1, "/devicelogin": 1} and dict(evil["user_agents"]) == {"curl/8.1": 2}
    assert act["10.0.0.9"]["requests"] == 0 and act["10.0.0.9"]["forwarded"] == 1 and act["10.0.0.9"]["first"] is None
    assert act["10.0.0.5"]["requests"] == 2 and act["10.0.0.5"]["forwarded"] == 0


def test_the_pivot_joins_each_ip_to_its_access_log_requests():
    files = {**scene(), "access.log": _access_log()}
    log = cl.load(files)
    logs = cl.access_logs(files, log)
    assert logs["files"] == [{"file": "access.log", "kind": "access_combined", "events": 8}] and logs["events"] == 8
    pv = cl.pivot(log.events, (), logs["activity"])
    rows = {r["ip"]: r for r in cl.pivot_data(pv)["ips"]}
    assert rows[EVIL]["access"]["requests"] == 2 and rows[EVIL]["access"]["forwarded"] == 1
    assert rows[EVIL]["access"]["first"] == "2026-03-02 13:58:00Z" and rows[EVIL]["access"]["top_paths"][0][1] == 1
    assert rows[HOME]["access"]["requests"] == 1
    assert pv["access_only"] == 5                      # OTHER, three proxies and the second forwarded address
    assert not any("no request in the access logs" in n for n in pv["notes"])


def test_an_attacker_absent_from_the_access_log_is_said():
    quiet = f'{HOME} - - [02/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'.encode()
    files = {**scene(), "access.log": quiet}
    log = cl.load(files)
    pv = cl.pivot(log.events, (), cl.access_logs(files, log)["activity"])
    assert f"attacker IP {EVIL}: no request in the access logs" in pv["notes"]
    assert next(r for r in pv["ips"] if r["ip"] == EVIL)["access"] is None


def test_cloud_logs_are_never_read_as_access_logs_even_under_a_second_name():
    # a Kubernetes audit log has a request URI, a verb and a source address: web_evidence reads it as a web log
    k8s = "\n".join(json.dumps({"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": f"id-{i}", "stage": "ResponseComplete",
                                "requestURI": f"/api/v1/namespaces/default/pods/p{i}", "verb": "get", "user": {"username": "dev"},
                                "sourceIPs": [EVIL], "userAgent": "kubectl/1.29", "responseStatus": {"code": 200},
                                "requestReceivedTimestamp": f"2026-03-02T14:00:0{i}Z"}) for i in range(3)).encode()
    assert len(we.read_log(k8s, "audit.jsonl")) == 3
    files = {"audit.jsonl": k8s}
    log = cl.load(files)
    assert log.sources == {"k8s_audit": 3}
    assert cl.access_logs(files, log) == {"files": [], "events": 0, "activity": {}}
    files["copy-of-audit.jsonl"] = bytes(k8s)                                   # the unpacked copy of a zip member
    log = cl.load(files)
    assert [f["file"] for f in log.files] == ["audit.jsonl"]
    assert cl.access_logs(files, log) == {"files": [], "events": 0, "activity": {}}


# ---------------------------------------------------------------- the flag template

def test_find_templates_reads_slots_and_html_entities():
    brief = "Find the device.\n\nFlag format: **`spooky{<device_name>_<rule_name>_<download_count>}`**\nNot one: spooky{plain}"
    assert cl.find_templates(brief) == [TEMPLATE]
    assert cl.find_templates("format EVT{&lt;ip&gt;-&lt;device&gt;}") == ["EVT{<ip>-<device>}"]
    assert cl.find_templates("EVT{&lt;ip&gt;} twice EVT{<ip>} and EVT{<device>}") == ["EVT{<ip>}", "EVT{<device>}"]
    assert cl.find_templates("no template here {<x>} and FLAG{done}") == []


def test_the_template_is_filled_from_the_attributed_artifacts():
    log, pv = _pivot(scene())
    out = cl.fill_template(TEMPLATE, pv)
    assert out == {"slots": [{"slot": "device_name", "field": "device", "values": [DEV_OK]},
                             {"slot": "rule_name", "field": "rule", "values": [RULE_OK]},
                             {"slot": "download_count", "field": "downloads", "values": ["3"]}],
                   "flag": FLAG, "why": []}
    other = cl.fill_template("EVT{<Attacker IP>|<forward_to>|<device-id>}", pv)
    assert other["flag"] == f"EVT{{{EVIL}|drop@elsewhere.example|{ID_OK}}}"


def test_two_attacker_devices_leave_the_template_unfilled():
    files = scene(extra_audit=[register("2026-03-02T14:30:00.0000000+00:00", EVIL, "SECOND-BOX", "55555555-0000-4000-8000-000000000000")])
    log, pv = _pivot(files)
    out = cl.fill_template(TEMPLATE, pv)
    assert out["flag"] is None and out["why"] == [f"<device_name>: 2 values ({DEV_OK}, SECOND-BOX); which one is not judged"]


def test_a_file_downloaded_twice_leaves_the_count_unfilled():
    files = scene(extra_ual=[download("2026-03-02T14:15:00", EVIL, "plan.docx")])
    log, pv = _pivot(files)
    assert cl.template_values(pv)["downloads"] == ["4", "3"]
    out = cl.fill_template(TEMPLATE, pv)
    assert out["flag"] is None and out["why"] == ["<download_count>: 2 values (4, 3); which one is not judged"]


def test_no_attributed_download_is_no_count_never_zero():
    files = scene()
    files["UnifiedAuditLog.csv"] = _csv(UAL_COLS, [rule("2026-03-02T14:25:00", EVIL, RULE_OK, ForwardTo="d@elsewhere.example"),
                                                   download("2026-03-02T09:30:00", HOME, "lunch.pdf")], bom=False, quote=False)
    log, pv = _pivot(files)
    out = cl.fill_template(TEMPLATE, pv)
    assert out["flag"] is None and out["why"] == ["<download_count>: no attributed downloads value"]


def test_an_unknown_or_bare_slot_is_not_filled():
    log, pv = _pivot(scene())
    out = cl.fill_template("spooky{<device>_<rule>_<count>}", pv)
    assert out["flag"] is None and out["why"] == ["<count>: not a slot name this file fills (TEMPLATE_FIELDS)"]
    assert cl.fill_template("spooky{nothing}", pv)["why"] == ["the template has no <slot>"]


def test_a_log_that_is_not_whole_fills_nothing():
    log, pv = _pivot(scene())
    out = cl.fill_template(TEMPLATE, pv, whole=False)
    assert out["flag"] is None and out["why"] == ["a log did not parse whole, so nothing is answered from it"]


# ---------------------------------------------------------------- the command

def _folder(tmp_path, files, brief=TEMPLATE) -> tuple:
    chal = tmp_path / "77-audit"
    logs = chal / "unpacked" / "handout" / "logs"
    logs.mkdir(parents=True)
    for name, data in files.items():
        (logs / name).write_bytes(data)
    (chal / "challenge.json").write_text(json.dumps({"id": 77, "name": "Audit", "category": "forensics", "description":
                                                     f"Name the device, the rule and the count.\n\nFlag format: `{brief}`"}))
    return chal, chal / "unpacked"


def test_cli_pivot_prints_the_flag_once_and_never_the_template(tmp_path, capsys):
    chal, folder = _folder(tmp_path, {**scene(), "access.log": _access_log()})
    ff = flagfmt.for_profile(event.load("spooky"))
    assert cl.main(["--pivot", "--brief", str(chal), str(folder)]) == 0
    out = capsys.readouterr().out
    assert ff.find_flags(out) == [FLAG]
    assert "<device_name>" not in out and "slots device_name, rule_name, download_count" in out
    assert cl.ATTACKER_RULE in out and cl.DECOY_RULE in out
    assert f"## {EVIL}  ATTACKER (device_code)" in out and "access log: 2 requests" in out
    assert f"device '{DEV_DECOY}'" in out and "REJECTED (other_ip)" in out and "ATTRIBUTED (ip+device_id)" in out
    assert cl.main(["--pivot", "--json", "--brief", str(chal), str(folder)]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["template"]["flag"] == FLAG and d["access_logs"]["events"] == 8 and d["whole"] is True
    assert TEMPLATE not in json.dumps(d)


def test_cli_pivot_without_an_attacker_prints_no_flag_and_takes_a_named_one(tmp_path, capsys):
    chal, folder = _folder(tmp_path, scene(device_code=False))
    assert cl.main(["--pivot", "--brief", str(chal), str(folder)]) == 0
    out = capsys.readouterr().out
    assert "spooky{" not in out and "not filled: no attacker IP" in out and "UNDECIDED (no_attacker_ip)" in out
    assert cl.main(["--pivot", "--attacker-ip", EVIL, "--template", TEMPLATE, str(folder)]) == 0
    assert f"flag: {FLAG}" in capsys.readouterr().out
    assert cl.main(["--pivot", "--attacker-ip", "nonsense", str(folder)]) == 2
    assert "not an IP address" in capsys.readouterr().err


def test_cli_pivot_says_when_the_brief_or_the_logs_are_missing(tmp_path, capsys):
    chal, folder = _folder(tmp_path, scene())
    (chal / "challenge.json").unlink()
    assert cl.main(["--pivot", "--brief", str(chal), str(folder)]) == 0
    cap = capsys.readouterr()
    assert "brief NOT read" in cap.out and "no challenge.json" in cap.err and "spooky{" not in cap.out
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("nothing")
    assert cl.main(["--pivot", str(empty)]) == 3
    assert cl.main(["--pivot"]) == 2


def test_cli_pivot_refuses_top_by_name_and_never_reads_its_value_as_a_path(tmp_path, capsys, monkeypatch):
    chal, folder = _folder(tmp_path, scene())
    monkeypatch.chdir(tmp_path)
    (tmp_path / "5").write_bytes(scene()["UnifiedAuditLog.csv"])          # a file named like the --top value
    assert cl.main(["--pivot", "--top", "5", str(folder)]) == 2
    cap = capsys.readouterr()
    assert "--top limits the triage tables only" in cap.err and cap.out == ""
    assert cl.main(["--top", "5", str(folder)]) == 0                        # the triage still takes it
    assert "## registered devices" in capsys.readouterr().out


def test_cli_pivot_two_templates_fill_none(tmp_path, capsys):
    chal, folder = _folder(tmp_path, scene())
    assert cl.main(["--pivot", "--brief", str(chal), "--template", "spooky{<device_name>}", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "2 different flag templates were given; none is filled" in out and "spooky{" not in out
    assert cl.main(["--pivot", "--brief", str(chal), "--template", TEMPLATE, str(folder)]) == 0      # the same one twice is one
    assert f"flag: {FLAG}" in capsys.readouterr().out


def test_cli_pivot_does_not_follow_a_link_out_of_the_folder(tmp_path, capsys):
    chal, folder = _folder(tmp_path, scene())
    outside = tmp_path / "outside.csv"
    outside.write_bytes(_csv(UAL_COLS, [download("2026-03-02T14:16:00", EVIL, "elsewhere.bin")], bom=False, quote=False))
    (folder / "link.csv").symlink_to(outside)
    assert cl.main(["--pivot", "--json", "--brief", str(chal), str(folder)]) == 0
    d = json.loads(capsys.readouterr().out)
    assert "link.csv" not in {f["file"] for f in d["files"]} and d["template"]["flag"] == FLAG
    seen = cl.pivot(cl.load(cl.read_paths([folder])).events)["artifacts"]          # the triage reader does follow it
    assert "elsewhere.bin" in {a["name"] for a in seen}


def test_cli_pivot_does_not_read_an_oversize_file_and_a_cut_cloud_log_stops_the_flag(tmp_path, capsys, monkeypatch):
    chal, folder = _folder(tmp_path, scene())
    monkeypatch.setattr(cl, "MAX_BYTES", 64 * 1024)
    (folder / "disk.img").write_bytes(b"\x00\x01\x02\x03" * 40000)                     # over the cap, not a log
    assert cl.main(["--pivot", "--brief", str(chal), str(folder)]) == 0
    out = capsys.readouterr().out
    assert "disk.img: over 65536 bytes and not a cloud log by its head; not read" in out and f"flag: {FLAG}" in out
    big = scene()["UnifiedAuditLog.csv"]
    (folder / "huge-ual.csv").write_bytes(big + b"x,y,z,w,v,u,t,s\n" * 6000)             # a cloud log over the cap
    assert cl.main(["--pivot", "--brief", str(chal), str(folder)]) == 0
    out = capsys.readouterr().out
    assert "huge-ual.csv: a cloud log over 65536 bytes, not read" in out
    assert "spooky{" not in out and "not filled: a log did not parse whole" in out


def test_cli_pivot_reads_a_zip_and_its_unpacked_copy_once(tmp_path, capsys):
    files = scene()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr("logs/" + name, data)
    chal, folder = _folder(tmp_path, files)
    (folder / "handout.zip").write_bytes(buf.getvalue())
    assert cl.main(["--pivot", "--json", "--brief", str(chal), str(folder)]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["template"]["flag"] == FLAG and sum(f["events"] for f in d["files"]) == 21
    assert next(r for r in d["ips"] if r["ip"] == EVIL)["downloads"] == 3


def test_the_triage_lists_devices_device_code_signins_and_downloads(tmp_path, capsys):
    chal, folder = _folder(tmp_path, scene())
    assert cl.main([str(folder)]) == 0
    out = capsys.readouterr().out
    assert "## registered devices" in out and f"'{DEV_OK}' device_id={ID_OK} (register)" in out
    assert "## device-code sign-ins by IP" in out and f"     3  {EVIL}" in out
    assert "## file downloads by IP" in out and "--pivot joins these per IP" in out


# ---------------------------------------------------------------- route and intake

HEADS = {
    "ual.csv": _csv(UAL_COLS, [download("2026-03-02T14:10:00", EVIL, "a.txt")], bom=False, quote=False),
    "ual-bom.csv": _csv(UAL_COLS, [download("2026-03-02T14:10:00", EVIL, "a.txt")], bom=True, quote=False),
    "ual-quoted.csv": _csv(UAL_COLS, [download("2026-03-02T14:10:00", EVIL, "a.txt")], bom=True, quote=True),
    "classic.csv": _csv(["CreationDate", "UserIds", "Operations", "AuditData"], [], bom=False, quote=False),
    "signins.csv": _csv(SIGNIN_COLS, [signin("2026-03-02T14:00:05Z", EVIL)]),
    "signins-plain.csv": _csv(SIGNIN_COLS, [signin("2026-03-02T14:00:05Z", EVIL)], bom=False, quote=False),
    "audit.csv": _csv(AUDIT_COLS, [register("2026-03-02T14:01:00.0000000+00:00", EVIL, DEV_OK, ID_OK)]),
    "audit-plain.csv": _csv(AUDIT_COLS, [register("2026-03-02T14:01:00.0000000+00:00", EVIL, DEV_OK, ID_OK)], bom=False, quote=False),
}


@pytest.mark.parametrize("name", sorted(HEADS))
def test_intake_picks_cloudlogs_on_each_export_head(tmp_path, name):
    (tmp_path / "export.dat").write_bytes(HEADS[name])            # by its head, whatever the file is called
    m = M.load(MANIFEST)
    plan = E.plan([m], "misc", "", tmp_path, guard=G.Guard("hook", (), "test"))
    assert [(j.engine, j.files) for j in plan.jobs] == [("toolkits.cloudlogs", ())], [(s.engine, s.reason) for s in plan.skipped]
    assert m.intake.run == "folder" and m.intake.select == "files" and "{folder}" in m.intake.args and "--pivot" in m.intake.args


def test_intake_leaves_other_csv_and_text_alone(tmp_path):
    (tmp_path / "people.csv").write_text("name,team,score\nann,red,3\n")
    (tmp_path / "access.log").write_bytes(_access_log())
    (tmp_path / "dates.csv").write_text('"Date (UTC)","Value"\n"2026-03-02","3"\n')
    plan = E.plan([M.load(MANIFEST)], "forensics", "a web server log", tmp_path, guard=G.Guard("hook", (), "test"))
    assert plan.jobs == []


def test_the_router_and_triage_send_entra_and_purview_briefs_to_cloudlogs(tmp_path):
    for brief in ("sanitized Microsoft Entra and Purview-style exports", "the mailbox's Unified Audit Log",
                  "who made the inbox rule?", "Entra ID sign-in logs of the tenant"):
        ids = [h.manifest.id for h in router.route("forensics", brief, None)]
        assert "toolkits.cloudlogs" in ids, brief
        assert "toolkits.cloudlogs" in [r["id"] for r in triage.suggest("forensics", brief)["routes"]], brief
    # "entra" is a whole word: these briefs hold it only inside another word
    for brief in ("a reentrancy bug in the vault contract", "the central directory of the zip"):
        assert "toolkits.cloudlogs" not in [h.manifest.id for h in router.route("forensics", brief, None)], brief
    # the keyword route is for the log lanes: a web challenge that signs in with Azure AD is not a log to read
    assert "toolkits.cloudlogs" in [h.manifest.id for h in router.route("misc", "sign in with azure ad", None)]
    assert "toolkits.cloudlogs" not in [h.manifest.id for h in router.route("web", "sign in with azure ad", None)]
    (tmp_path / "x.csv").write_bytes(HEADS["signins.csv"])
    hits = {h.manifest.id: h for h in router.route("misc", "some files", tmp_path)}
    assert "toolkits.cloudlogs" in hits and "starts with" in hits["toolkits.cloudlogs"].reason


def test_intake_runs_the_pivot_with_no_model_and_finds_the_flag(tmp_path):
    chal, folder = _folder(tmp_path, {**scene(), "access.log": _access_log()})
    guard = G.Guard("hook", (), "test")
    plan = E.plan(M.discover(), "forensics", "identity and mailbox-audit exports", folder, guard=guard)
    job = next(j for j in plan.jobs if j.engine == "toolkits.cloudlogs")
    ctx = E.Context(challenge_dir=chal, folder=folder, out_root=chal / "recon" / "engines", profile=event.load("spooky"),
                    guard=guard, root=REPO, python=sys.executable, challenge_id="77", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (chal / run.errors).read_text()
    assert run.flags == (FLAG,)
    out = (chal / run.output).read_text()
    assert f"## {EVIL}  ATTACKER (device_code)" in out and "access log: 2 requests" in out and "REJECTED (other_ip)" in out


def test_intake_run_without_a_device_code_signin_reports_no_flag(tmp_path):
    chal, folder = _folder(tmp_path, scene(device_code=False))
    guard = G.Guard("hook", (), "test")
    job = next(j for j in E.plan([M.load(MANIFEST)], "forensics", "", folder, guard=guard).jobs)
    ctx = E.Context(challenge_dir=chal, folder=folder, out_root=chal / "recon" / "engines", profile=event.load("spooky"),
                    guard=guard, root=REPO, python=sys.executable, challenge_id="77", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok" and run.flags == ()
    assert "not filled: no attacker IP" in (chal / run.output).read_text()
