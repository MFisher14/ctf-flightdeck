#!/usr/bin/env python3
"""`cloudlogs` on real artifacts (the cache of tests/real/fetch_b.py; SKIPs without it).

  .venv/bin/python tests/real/test_real_cloudlogs.py

Offline, nothing written, no request. The expected values are recomputed here with `csv` and `json`
alone (never with the toolkit's readers), or were read from the records by hand.

- Invictus IR's Unified Audit Log of a simulated BEC (38 MB CSV through Splunk; 9,611 rows that hold
  5,373 distinct records): repeated rows are read once and a count is offered both ways; a mailbox
  rule is found by its name or by the address it forwards to.
- Invictus IR's CloudTrail data set and OTRF's: a class of actors is no selection, a user named like
  the question's own words is a name.
- Elastic beats' and plaso's samples of Entra sign-ins, Okta, the Management Activity API, GCP,
  Azure activity and Kubernetes audit: read, recognised, counted.
"""
import collections
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("cloudlogs")
UAL = "cloudlogs/o365_dataset/auditrecords.7z.d/auditrecords.csv"
AWS = "cloudlogs/aws_dataset"


def ual_truth():
    csv.field_size_limit(1 << 30)
    rows = list(csv.DictReader((rd.CACHE / UAL).open(encoding="utf-8-sig", newline="")))
    recs = []
    for r in rows:
        try:
            recs.append(json.loads(r["AuditData"]))
        except ValueError:
            pass
    return rows, recs


def ask_all(cl, fs, questions):
    return cl.solve_set([{"qid": f"q{i}", "question": t} for i, t in enumerate(questions)], fs, {})


def main() -> int:
    cl = rd.toolkit("cloudlogs")
    if R.need("Invictus Unified Audit Log", UAL):
        fs = rd.files(UAL)
        rows, recs = ual_truth()
        by_op = collections.defaultdict(set)
        op_rows = collections.Counter()
        for a in recs:
            by_op[a.get("Operation")].add(a.get("Id"))
            op_rows[a.get("Operation")] += 1
        R.check("UAL truth: 9,611 rows, 5,373 distinct record ids", len(rows) == 9611 and len({a.get("Id") for a in recs}) == 5373)
        R.check("UAL: signal", R.timed("UAL: signals on 38 MB", lambda: cl.signals([], fs)) >= 0.5)
        log = R.timed("UAL: load of a 38 MB csv", lambda: cl.load(fs), limit=4.0)
        R.check("UAL: every repeated row is read once", len(log.events) == len({a.get("Id") for a in recs}) + (len(rows) - len(recs)),
                f"{len(log.events)} events")
        R.check("UAL: the rows are still accounted for", sum(e.get("copies", 1) for e in log.events) == len(rows))
        qs = ["How many New-InboxRule events are there?", "How many UserLoginFailed events are there?", "How many UserLoggedIn events are there?",
              "How many records are in the log?", "How many failed sign-ins are there?",
              "What is the name of the inbox rule that forwards to korstiaan@financial-technology.com?",
              "Which address does the inbox rule Financial Reporting forward to?",
              "Which user created the inbox rule Financial Reporting?",
              "What IP address created the inbox rule Financial Reporting?",
              "How many New-TransportRule events are there?",
              "What was the first operation in the log?", "What was the last operation in the log?",
              "Which account had the most failed sign-ins?", "How many countries are in the log?", "What is the name of the inbox rule?",
              "When was the inbox rule Financial Reporting created?", "What is the attacker's IP address?"]
        ans = R.timed("UAL: solve_set of 17 questions on 38 MB", lambda: ask_all(cl, fs, qs), limit=4.0)
        for i, op in ((0, "New-InboxRule"), (1, "UserLoginFailed"), (2, "UserLoggedIn")):
            got = rd.options(ans[f"q{i}"])
            R.check(f"UAL: a count of {op} is unsure between the records ({len(by_op[op])}) and the rows ({op_rows[op]}) (was plain {op_rows[op]})",
                    not rd.plain(ans[f"q{i}"]) and str(len(by_op[op])) in got and str(op_rows[op]) in got, ans[f"q{i}"])
        R.check("UAL: the record count is not plain", not rd.plain(ans["q3"]) and "9611" in rd.options(ans["q3"]), ans["q3"])
        R.check("UAL: the failed sign-in count is not plain", not rd.plain(ans["q4"]), ans["q4"])
        R.check("UAL: the rule found by its forwarding address", ans["q5"] == "Financial Reporting", ans["q5"])
        R.check("UAL: the address the named rule forwards to", ans["q6"] == "korstiaan@financial-technology.com", ans["q6"])
        R.check("UAL: who created the named rule", ans["q7"] == "joey@dutchmasterz.onmicrosoft.com", ans["q7"])
        R.check("UAL: the rule's address is unsure between address and address:port", sorted(rd.options(ans["q8"])) == ["80.114.221.214", "80.114.221.214:52378"], ans["q8"])
        R.check("UAL: one New-TransportRule, plain", ans["q9"] == "1" and op_rows["New-TransportRule"] == 1, ans["q9"])
        first = min(recs, key=lambda a: a["CreationTime"])
        last = max(recs, key=lambda a: a["CreationTime"])
        R.check("UAL: first and last operation by CreationTime", (ans["q10"], ans["q11"]) == (first["Operation"], last["Operation"]), (ans["q10"], ans["q11"]))
        fails = collections.Counter(a.get("UserId") for a in recs if a.get("Operation") == "UserLoginFailed")
        fails_once = collections.Counter(u for _, u in {(a.get("Id"), a.get("UserId")) for a in recs if a.get("Operation") == "UserLoginFailed"})
        R.check("UAL: the account with the most failed sign-ins, by rows and by records alike",
                ans["q12"] == fails.most_common(1)[0][0] == fails_once.most_common(1)[0][0], ans["q12"])
        R.check("UAL: no country in the log is no answer (a zero is not offered)", ans["q13"] is None, ans["q13"])
        R.check("UAL: four rules and no name given is None", ans["q14"] is None, ans["q14"])
        R.check("UAL: a time is unsure and holds the logged text", "2021-06-15T10:09:55" in rd.options(ans["q15"]), ans["q15"])
        R.check("UAL: the attacker's address is never plain", not rd.plain(ans["q16"]), ans["q16"])
        rules = cl.inbox_rules(log.events)
        R.check("UAL: the four created inbox rules of the records", sorted(str(r["name"]) for r in rules if r["kind"] == "create")
                == sorted(next(p["Value"] for p in a["Parameters"] if p["Name"] == "Name") or "None"
                          for a in {a["Id"]: a for a in recs if a.get("Operation") == "New-InboxRule"}.values()),
                [r["name"] for r in rules if r["kind"] == "create"])
    if R.need("Invictus CloudTrail", AWS):
        fs = rd.files(AWS)
        recs = [r for p in sorted((rd.CACHE / AWS).glob("*.json")) for r in json.loads(p.read_text())["Records"]]
        ok_assume = [r for r in recs if r["eventName"].startswith("AssumeRole") and not r.get("errorCode")]
        qs = ["How many events are in the logs?", "How many AssumeRole events are there?", "How many events were made by IAM users?",
              "How many events were made by assumed roles?", "How many events did the user make?", "How many roles were assumed?",
              "How many times was a role assumed?", "Who created the user malicious-iam-user?", "How many users were created?",
              "What is the attacker's IP address?", "How many GetSecretValue events are in the logs?", "How many console logins did not use MFA?"]
        ans = R.timed("aws_dataset: solve_set", lambda: ask_all(cl, fs, qs))
        R.check("aws: event count", ans["q0"] == str(len(recs)) == "2900", ans["q0"])
        R.check("aws: AssumeRole events", ans["q1"] == str(sum(1 for r in recs if r["eventName"] == "AssumeRole")), ans["q1"])
        R.check("aws: 'by IAM users' is not every event (was plain 2900; 2,748 are IAM users')", ans["q2"] is None, ans["q2"])
        R.check("aws: 'by assumed roles' is not the AssumeRole calls (was plain 36)", ans["q3"] is None, ans["q3"])
        R.check("aws: 'the user' names nobody", ans["q4"] is None, ans["q4"])
        R.check("aws: roles assumed = distinct roleArn of the successful calls", ans["q5"] == str(len({r["requestParameters"]["roleArn"] for r in ok_assume})), ans["q5"])
        R.check("aws: times a role was assumed = the successful calls", ans["q6"] == str(len(ok_assume)), ans["q6"])
        R.check("aws: who created a user named like the question's words (was the suspicious sign-in rules)",
                "bert-jan" in rd.options(ans["q7"]) and "stratus-red-team-nmfalu-gfjyeaypjt" not in rd.options(ans["q7"]), ans["q7"])
        R.check("aws: 'users created' is not the distinct callers", ans["q8"] is None, ans["q8"])
        R.check("aws: the attacker's address is never plain", not rd.plain(ans["q9"]), ans["q9"])
        R.check("aws: GetSecretValue events", ans["q10"] == "60", ans["q10"])
        R.check("aws: an MFA question is not answered by this toolkit", ans["q11"] is None, ans["q11"])
    sts = "cloudlogs/beats/o365/15-azuread-sts-logon.log"
    if R.need("beats Management Activity sign-ins", sts):
        recs = [json.loads(ln) for ln in (rd.CACHE / sts).read_text().splitlines() if ln.strip()]
        ops = collections.Counter(r["Operation"] for r in recs)
        ans = ask_all(cl, rd.files(sts), ["How many sign-ins are there?", "How many failed sign-ins are there?", "How many records are in the log?",
                                         "How many distinct IP addresses are in the log?", "What is the attacker's IP address?"])
        R.check("o365 sts: sign-ins", ans["q0"] == str(ops["UserLoggedIn"] + ops["UserLoginFailed"]), (ans["q0"], dict(ops)))
        R.check("o365 sts: failed sign-ins", ans["q1"] == str(ops["UserLoginFailed"]), ans["q1"])
        R.check("o365 sts: records", ans["q2"] == str(len(recs)), ans["q2"])
        ips = {str(r.get("ClientIP") or r.get("ActorIpAddress") or "").rsplit(":", 1)[0] if str(r.get("ClientIP") or "").count(":") == 1
               else str(r.get("ClientIP") or r.get("ActorIpAddress") or "") for r in recs}
        R.check("o365 sts: distinct addresses", ans["q3"] == str(len(ips - {""})), (ans["q3"], sorted(ips)))
        R.check("o365 sts: the attacker's address is never plain", not rd.plain(ans["q4"]), ans["q4"])
    want = {"cloudlogs/beats/azure/signinlogs.log": "entra_signin", "cloudlogs/beats/azure/test-non-interactive-user-signin.log": "entra_signin",
            "cloudlogs/beats/azure/auditlogs.log": "entra_audit", "cloudlogs/beats/azure/activitylogs.log": "azure_activity",
            "cloudlogs/beats/okta/okta-system-test.json.log": "okta", "cloudlogs/beats/gcp/audit-log-entries.json.log": "gcp_audit",
            "cloudlogs/beats/o365/01-exchange-admin.log": "m365_ual", "cloudlogs/beats/cloudtrail/console-login-json.log": "cloudtrail",
            "cloudlogs/plaso/microsoft_audit_log.jsonl": "m365_ual", "cloudlogs/falco_k8s_audit/exec_pod.json": "k8s_audit",
            "cloudlogs/plaso/aws_cloudtrail.jsonl": "cloudtrail", "cloudlogs/plaso/azure_activity_log.jsonl": "azure_activity"}
    for rel, src in want.items():
        if not R.need(rel.rsplit("/", 1)[-1], rel):
            continue
        fs = rd.files(rel)
        log = cl.load(fs)
        lines = {json.dumps(json.loads(ln), sort_keys=True) for ln in (rd.CACHE / rel).read_text().splitlines() if ln.strip()}  # beats repeats records too
        R.check(f"{rel.split('/', 1)[1]}: read as {src}, one event per distinct record, signal at the threshold",
                set(log.sources) == {src} and len(log.events) == len(lines)
                and cl.signals([], fs) >= 0.5, f"{log.sources} events={len(log.events)} lines={len(lines)} signal={cl.signals([], fs)}")
    si = "cloudlogs/beats/azure/signinlogs.log"
    if R.need("beats Entra sign-ins", si):
        ans = ask_all(cl, rd.files(si), ["How many sign-ins are there?", "How many failed sign-ins are there?", "How many successful sign-ins are there?"])
        recs = [json.loads(ln) for ln in (rd.CACHE / si).read_text().splitlines() if ln.strip()]
        codes = [str(r["properties"]["status"].get("errorCode")) for r in recs]
        R.check("entra: three sign-ins, one with error code 0", ans["q0"] == "3" == str(len(recs)) and ans["q2"] == str(codes.count("0")), (ans, codes))
        R.check("entra: interrupted sign-ins make 'failed' unsure", rd.unsure(ans["q1"]), ans["q1"])
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
