#!/usr/bin/env python3
"""Review checks of the group-b toolkits (cloud_container, cloudlogs, edr_persistence, nix_host,
sqlite_artifacts): what the adversarial review of 2026-10-08 found on real artifacts, each a
question that narrows, ranks, negates or redirects what the code matched and was answered as if
it did not.

  .venv/bin/python tests/real/test_real_review_b.py

Offline, nothing written, no request. Part 1 builds its evidence in memory and always runs. Part 2
asserts the same defects on the real files of tests/real/fetch_b.py and SKIPs without the cache;
every expected value there was recounted with json, csv or re (see the comment beside it), never
with a toolkit.

The rule each check guards: an answer over events the question did not select is a coincidence. A
rank other than the first, a negation, a port, a direction, a role (process or parent), a
qualifier in front of "events" or behind "account ID" gives None or an unsure answer, never a
plain one.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("review_b")


def ask_all(mod, fs, questions):
    return mod.solve_set([{"qid": f"q{i}", "question": t} for i, t in enumerate(questions)], fs, {})


def never_plain(name, mod, fs, questions):
    ans = ask_all(mod, fs, questions)
    for i, t in enumerate(questions):
        R.check(f"{name}: never plain: {t}", not rd.plain(ans[f"q{i}"]), repr(ans[f"q{i}"])[:140])
    return ans


def plain_is(name, mod, fs, pairs):
    ans = ask_all(mod, fs, [t for t, _ in pairs])
    for i, (t, want) in enumerate(pairs):
        R.check(f"{name}: plain {want!r}: {t}", ans[f"q{i}"] == want, repr(ans[f"q{i}"])[:140])


# ---- part 1: evidence built here -------------------------------------------------------------------

def trail():
    """Ten CloudTrail events of account 111111111111 in us-east-1; a bucket policy lets account
    999999999999 in; svc-backdoor is only ever the target of alice's calls."""
    def ev(n, name, source, user="alice", ip="198.51.100.7", req=None, resp=None):
        return {"eventVersion": "1.08", "eventTime": f"2026-01-05T10:00:{n:02d}Z", "eventSource": source, "eventName": name, "awsRegion": "us-east-1",
                "sourceIPAddress": ip, "userAgent": "aws-cli/2.0", "eventID": f"00000000-0000-0000-0000-{n:012d}", "eventType": "AwsApiCall",
                "recipientAccountId": "111111111111", "requestParameters": req, "responseElements": resp,
                "userIdentity": {"type": "IAMUser", "principalId": "AIDA" + user.upper(), "arn": f"arn:aws:iam::111111111111:user/{user}",
                                 "accountId": "111111111111", "userName": user, "accessKeyId": "AKIAEXAMPLEEXAMPLE00"}}  # secret-scan: allow
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                                                      "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-data/*"}]}
    recs = [ev(1, "ListBuckets", "s3.amazonaws.com"), ev(2, "CreateBucket", "s3.amazonaws.com", req={"bucketName": "corp-data"}),
            ev(3, "PutBucketPolicy", "s3.amazonaws.com", req={"bucketName": "corp-data", "bucketPolicy": policy}),
            ev(4, "CreateUser", "iam.amazonaws.com", req={"userName": "svc-backdoor"},
               resp={"user": {"userName": "svc-backdoor", "arn": "arn:aws:iam::111111111111:user/svc-backdoor", "userId": "AIDASVCBACKDOOR"}}),
            ev(5, "AttachUserPolicy", "iam.amazonaws.com", req={"userName": "svc-backdoor", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
            ev(6, "GetObject", "s3.amazonaws.com", user="bob", ip="203.0.113.9", req={"bucketName": "corp-data", "key": "a.txt"}),
            ev(7, "GetObject", "s3.amazonaws.com", user="bob", ip="203.0.113.9", req={"bucketName": "corp-data", "key": "a.txt"}),
            ev(8, "DescribeInstances", "ec2.amazonaws.com"), ev(9, "DescribeInstances", "ec2.amazonaws.com"),
            ev(10, "GetCallerIdentity", "sts.amazonaws.com", user="bob", ip="203.0.113.9")]
    return {"trail.json": json.dumps({"Records": recs}).encode()}


def sshd_log():
    """Five failures for root from .1; three invalid users from .2; alice fails once from .4 and
    logs in from .3."""
    L, n = [], 0

    def line(msg):
        nonlocal n
        n += 1
        L.append(f"Jan  5 10:{n // 60:02d}:{n % 60:02d} web01 sshd[{2000 + n}]: {msg}")
    for _ in range(5):
        line("Failed password for root from 192.0.2.1 port 40000 ssh2")
    for u in ("oracle", "git", "test"):
        line(f"Invalid user {u} from 192.0.2.2 port 40001")
        line(f"Failed password for invalid user {u} from 192.0.2.2 port 40001 ssh2")
    line("Failed password for alice from 192.0.2.4 port 40002 ssh2")
    line("Accepted password for alice from 192.0.2.3 port 40003 ssh2")
    return {"auth.log": ("\n".join(L) + "\n").encode()}


def sudo_log():
    return {"auth.log": (
        "Jan  5 10:00:01 web01 sudo:      bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id -un\n"
        "Jan  5 10:00:09 web01 sudo:    carol : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/whoami\n").encode()}


def sysmon_xml():
    """cmd.exe is started once and starts two net.exe; a real and a planted svchost.exe each accept
    connections (Initiated=False); tool.exe makes one."""
    out, n = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>'], 0

    def event(eid, data):
        nonlocal n
        n += 1
        body = "\n".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
        out.append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                   '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>\n'
                   f'<EventID Qualifiers="">{eid}</EventID>\n<Version>5</Version>\n<Level>4</Level>\n'
                   f'<TimeCreated SystemTime="2026-01-05 10:00:{n:02d}.000000+00:00"></TimeCreated>\n<EventRecordID>{100 + n}</EventRecordID>\n'
                   '<Channel>Microsoft-Windows-Sysmon/Operational</Channel>\n<Computer>WS01</Computer>\n<Security UserID="S-1-5-18"></Security>\n'
                   f'</System>\n<EventData>{body}\n</EventData>\n</Event>')

    def proc(pid, image, cmd, ppid, parent, user="WS01\\alice"):
        event(1, {"UtcTime": f"2026-01-05 10:00:{n + 1:02d}.000", "ProcessId": pid, "Image": image, "CommandLine": cmd, "User": user,
                  "Hashes": f"SHA256={pid:064X}", "ParentProcessId": ppid, "ParentImage": parent, "ParentCommandLine": parent})

    def conn(image, initiated, src, sport, dst, dport):
        event(3, {"UtcTime": f"2026-01-05 10:00:{n + 1:02d}.000", "ProcessId": 900, "Image": image, "User": "NT AUTHORITY\\SYSTEM", "Protocol": "tcp",
                  "Initiated": initiated, "SourceIp": src, "SourcePort": sport, "DestinationIp": dst, "DestinationPort": dport})
    proc(100, r"C:\Windows\System32\cmd.exe", "cmd.exe", 50, r"C:\Windows\explorer.exe")
    proc(101, r"C:\Windows\System32\net.exe", "net user", 100, r"C:\Windows\System32\cmd.exe")
    proc(102, r"C:\Windows\System32\net.exe", "net share", 100, r"C:\Windows\System32\cmd.exe")
    proc(103, r"C:\ProgramData\svchost.exe", r'"C:\ProgramData\svchost.exe"', 60, r"C:\Windows\System32\inetsrv\w3wp.exe", "IIS APPPOOL\\web")
    proc(104, r"C:\Tools\tool.exe", "tool.exe -c 9.9.9.9", 100, r"C:\Windows\System32\cmd.exe")
    conn(r"C:\Windows\System32\svchost.exe", "False", "198.51.100.20", 50001, "10.0.0.5", 3389)
    conn(r"C:\Windows\System32\svchost.exe", "False", "198.51.100.21", 50002, "10.0.0.5", 3389)
    conn(r"C:\ProgramData\svchost.exe", "False", "198.51.100.30", 50003, "10.0.0.5", 8080)
    conn(r"C:\Tools\tool.exe", "True", "10.0.0.5", 50004, "9.9.9.9", 443)
    out.append("</Events>\n")
    return {"Sysmon.evtx.xml": "\n".join(out).encode()}


def synthetic():
    cc, cl = rd.toolkit("cloud_container"), rd.toolkit("cloudlogs")
    fs = trail()
    plain_is("cloud_container", cc, fs, [("What is the AWS account ID?", "111111111111"), ("Which AWS region was used?", "us-east-1"),
                                         ("How many events are in the logs?", "10")])
    never_plain("cloud_container", cc, fs, [
        "What account ID was given access to the bucket corp-data?",        # was the log's own account; the policy names 999999999999
        "What is the account ID in the bucket policy?",
        "Which account ID was the bucket corp-data shared with?",
        "What is the attacker's account ID?",
        "What region was the snapshot copied to?",
        "What region is the bucket corp-data replicated to?"])
    ans = never_plain("cloudlogs", cl, fs, [
        "How many IAM events are there?",                                   # was every event of the log (2900 for 398 on the real set)
        "Which IP address did svc-backdoor use?",                                # was the caller's: svc-backdoor made no event
        "What user agent did svc-backdoor use?",
        "Who is svc-backdoor?"])
    R.check("cloudlogs: 'how many events are in the logs' is still answered", rd.ask(cl, fs, "How many events are in the logs?") == "10")
    R.check("cloudlogs: a making verb still reads the target's events (the address that created svc-backdoor)",
            rd.ask(cl, fs, "Which IP address created the user svc-backdoor?") == "198.51.100.7", rd.ask(cl, fs, "Which IP address created the user svc-backdoor?"))
    del ans

    N = rd.toolkit("nix_host")
    fs = sshd_log()
    plain_is("nix_host sshd", N, fs, [("Which IP address had the most failed logins?", "192.0.2.1"),
                                      ("Which IP address failed to log in as alice?", "192.0.2.4"),          # was .3, where alice got in
                                      ("Which IP address logged in as alice?", "192.0.2.3"),
                                      ("Which user logged in successfully?", "alice")])
    never_plain("nix_host sshd", N, fs, [
        "Which IP address had the second most failed logins?",              # was the first
        "Which IP address had the fewest failed logins?",
        "Which IP address tried the most invalid users?",                   # was the address with the most failures
        "Which IP address tried the most usernames?",
        "Which user logged in as root?",                                    # was alice
        "Which user failed to log in from 192.0.2.3?",                      # was alice, who got in from there
        "Which user did 192.0.2.1 try to log in as?",
        "Which IP address did not fail to log in?"])
    ans = ask_all(N, fs, ["How many failed password attempts were not for root?", "How many failed password attempts were for root?"])
    R.check("nix_host sshd: a negated count is None (was root's own count, offered)", ans["q0"] is None, ans["q0"])
    R.check("nix_host sshd: the count it negates is still answered", ans["q1"] == "5", ans["q1"])
    fs = sudo_log()
    plain_is("nix_host sudo", N, fs, [("What sudo command did bob run?", "/usr/bin/id -un")])
    ans = ask_all(N, fs, ["What directory did bob run sudo from?", "When did bob run sudo?", "What sudo command did bob not run?",
                          "What TTY did bob run sudo from?"])
    for i, what in enumerate(("its directory", "its time", "a negation", "its terminal")):
        R.check(f"nix_host sudo: {what} is not the command (was '/usr/bin/id -un', plain)", ans[f"q{i}"] is None, ans[f"q{i}"])

    E = rd.toolkit("edr_persistence")
    fs = sysmon_xml()
    plain_is("edr_persistence", E, fs, [("What IP address did tool.exe connect to?", "9.9.9.9"),
                                        ("How many processes were created by cmd.exe?", "3"),                  # was 4: its own start counted
                                        (r"How many network connections did C:\ProgramData\svchost.exe make?", "1"),
                                        ("How many network connection events are there?", "4")])
    never_plain("edr_persistence", E, fs, [
        "How many network connections were made to port 3389?",             # was every connection
        "How many network connections did svchost.exe make?",               # two programs carry the name
        "What IP address did svchost.exe connect to?",                      # accepted connections: the destination is the host itself
        r"What IP address did C:\ProgramData\svchost.exe connect to?",
        "What IP address connected to svchost.exe?",                        # the source is asked
        "Which user did not run tool.exe?",                                 # was the user that ran it, offered
        "How many process creation events are there for cmd.exe?"])         # its start, or the three it started
    got = rd.ask(E, fs, "How many process creation events are there for cmd.exe?")
    R.check("edr_persistence: a program that is process and parent: the count is offered both ways", {"1", "3"} <= set(rd.options(got)), got)


# ---- part 2: the real files -----------------------------------------------------------------------

def real():
    cc, cl, N, E, S = (rd.toolkit(k) for k in ("cloud_container", "cloudlogs", "nix_host", "edr_persistence", "sqlite_artifacts"))
    A = "cloudlogs/aws_dataset"
    if R.need("Invictus CloudTrail", A):
        fs = rd.files(A)
        # PutBucketPolicy on that bucket: Principal arn:aws:iam::193672423079:root; the log's account is 123837392027
        never_plain("aws_dataset", cc, fs, ["What account ID was given access to the bucket stratus-red-team-bdbp-lhfzvgcamn?",
                                            "What is the account ID in the bucket policy?"])
        plain_is("aws_dataset", cc, fs, [("What is the AWS account ID?", "123837392027"), ("Which AWS region was used?", "us-east-1")])
        # 398 of 2,900 events have eventSource iam.amazonaws.com; malicious-iam-user is in no userIdentity
        never_plain("aws_dataset (cloudlogs)", cl, fs, ["How many IAM events are there?", "Which IP address did malicious-iam-user use?"])
    U = "cloudlogs/o365_dataset/auditrecords.7z.d"
    if R.need("Invictus Unified Audit Log", U):
        fs = rd.files(U)
        ans = ask_all(cl, fs, ["How many applications were consented to?", "How many users are in the log?", "How many users created inbox rules?"])
        # 30 'Consent to application.' records: 12 target names, 13 object ids (was 1, plain)
        R.check("ual: consented applications are counted from the consents' targets, unsure", {"12", "13"} <= set(rd.options(ans["q0"])), ans["q0"])
        # 48 UserId values, 44 without case, 18 of them addresses (was 44, plain)
        R.check("ual: 'users in the log' is unsure between people and every actor", {"18", "44"} <= set(rd.options(ans["q1"])), ans["q1"])
        R.check("ual: a count of three people stays plain", ans["q2"] == "3", ans["q2"])
    o = "nix_host/loghub/OpenSSH_2k.log"
    if R.need("loghub OpenSSH", o):
        fs = rd.files(o)
        # failures: 183.62.140.253 286, 187.141.143.180 80; 'Invalid user' lines: 103.99.0.122 35; fztu's one login from 119.137.62.142
        plain_is("openssh", N, fs, [("Which IP address had the most failed logins?", "183.62.140.253"), ("Which IP address logged in as fztu?", "119.137.62.142")])
        never_plain("openssh", N, fs, ["Which IP address had the second most failed logins?", "Which IP address tried the most invalid users?",
                                       "Which IP address failed to log in as fztu?", "Which user logged in as root?",
                                       "How many failed password attempts were not for root?"])
    sd = "nix_host/plaso/syslog_sudo.log"
    if R.need("plaso syslog_sudo.log", sd):
        fs = rd.files(sd)
        plain_is("sudo", N, fs, [("What sudo command did svc-backup run?", "/usr/bin/id -un")])
        never_plain("sudo", N, fs, ["What directory did svc-backup run sudo from?", "When did svc-backup run sudo?", "What sudo command did svc-backup not run?"])
    W = "edr_persistence/ctf2025_webshellz/Sysmon.evtx.xml"
    if R.need("Webshellz Sysmon", W):
        fs = rd.files(W)
        # eight event 3: six to port 3389, all eight but frpc.exe's with Initiated=False; svchost.exe is two files
        never_plain("webshellz", E, fs, ["How many network connections were made to port 3389?", "How many network connections did svchost.exe make?",
                                         "What IP address did svchost.exe connect to?", "What IP address connected to svchost.exe?",
                                         r"What IP address did C:\ProgramData\svchost.exe connect to?", "Which user did not run frpc.exe?"])
        plain_is("webshellz", E, fs, [("What IP address did frpc.exe connect to?", "117.72.105.10"),
                                      (r"How many network connections did C:\ProgramData\svchost.exe make?", "1")])
    NM = "edr_persistence/ctf2024_nightmare/logs-parts1-5.zip.d/Security.evtx.xml"
    if R.need("Nightmare on Hunt Street Security log", NM):
        fs = rd.files(NM)
        # 4688: cmd.exe is the parent of ten and is started once; net.exe is started nine times and starts nine net1.exe
        ans = ask_all(E, fs, ["How many processes were created by cmd.exe?", "How many process creation events are there for net.exe?"])
        R.check("nightmare: processes created by cmd.exe = 10 (was 11)", ans["q0"] == "10", ans["q0"])
        R.check("nightmare: 'for net.exe' is unsure (was 18, plain)", "9" in rd.options(ans["q1"]), ans["q1"])
    h = "sqlite_artifacts/plaso/chrome/History"
    if R.need("Chrome History (2011)", h):
        # the carve has a wall-clock budget: under load it is cut and the count is a one-option pick, never another number
        old = S.CARVE_SECONDS
        try:
            for budget in (old, 0.0):
                S.CARVE_SECONDS = budget
                a = rd.ask(S, rd.files(h), "How many downloads are in the history?")
                R.check(f"chrome 2011: downloads with a carve budget of {budget:g} s: 2, plain or the only option",
                        a == "2" or rd.options(a) == ["2"], a)
        finally:
            S.CARVE_SECONDS = old


def main() -> int:
    synthetic()
    real()
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
