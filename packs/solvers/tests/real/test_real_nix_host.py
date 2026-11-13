#!/usr/bin/env python3
"""`nix_host` on real artifacts (the cache of tests/real/fetch_b.py; SKIPs without it).

  .venv/bin/python tests/real/test_real_nix_host.py

Offline, nothing written, no request. Expected values are recounted here from the raw lines with
`re`, from the databases with `sqlite3`, from the plists with `plistlib` (never with the toolkit's
readers).

- loghub's OpenSSH_2k.log and Linux_2k.log (2,000 lines each of a real sshd log and of a 2005 RHEL
  /var/log/messages), Elastic beats' secure-rhel7.log and auth-ubuntu1204.log.
- beats' auditd logs, wtmp and btmp; plaso's utmp, sudo and cron syslog, bash history, launchd
  plists, TCC.db and quarantine events; beats' `journalctl -o export`; OTRF's auditd record.
"""
import collections
import plistlib
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("nix_host")


def lines(rel):
    return (rd.CACHE / rel).read_text(errors="replace").splitlines()


def ask_all(N, fs, questions):
    return N.solve_set([{"qid": f"q{i}", "question": t} for i, t in enumerate(questions)], fs, {})


def ssh_truth(rel):
    L = lines(rel)
    fp = [ln for ln in L if re.search(r"sshd\[\d+\]: Failed \S+ for ", ln)]
    acc = [re.search(r"Accepted (\S+) for (\S+) from (\S+) port", ln).groups() for ln in L if re.search(r"sshd\[\d+\]: Accepted \S+ for ", ln)]
    inv = [re.search(r"Invalid user .*from (\S+)", ln).group(1) for ln in L if re.search(r"sshd\[\d+\]: Invalid user ", ln)]
    rep = [(int(m.group(1)), m.group(2)) for m in (re.search(r"message repeated (\d+) times: \[ ?(Failed \S+ for .*?)\]", ln) for ln in L) if m]
    src = collections.Counter(re.search(r" from (\S+) port", ln).group(1) for ln in fp)
    users = collections.Counter(re.search(r" for (?:invalid user )?(.*?) from ", ln).group(1) for ln in fp)
    return {"failed_lines": len(fp), "accepted": acc, "invalid_sources": set(inv), "repeats": rep, "sources": src, "users": users}


def main() -> int:
    N = rd.toolkit("nix_host")
    Q = ["Which IP address had the most failed logins?", "How many successful logins are there?", "How many distinct IP addresses had failed logins?",
         "How many different source IP addresses attempted to log in?", "Which user was targeted the most?", "Which user logged in successfully?",
         "Which IP address logged in as drewr?", "How many failed login attempts are there?", "When was the first failed login?",
         "What is the attacker's IP address?"]
    o = "nix_host/loghub/OpenSSH_2k.log"
    if R.need("loghub OpenSSH_2k.log", o):
        t, fs = ssh_truth(o), rd.files(o)
        ans = R.timed("OpenSSH_2k: solve_set on 2,000 lines", lambda: ask_all(N, fs, Q + ["How many failed logins came from 112.95.230.3?",
                                                                                         "How many failed logins were there for root?"]))
        R.check("OpenSSH_2k: the address with the most failed logins", ans["q0"] == t["sources"].most_common(1)[0][0] == "183.62.140.253", ans["q0"])
        R.check("OpenSSH_2k: successful logins", ans["q1"] == str(len(t["accepted"])) == "1", ans["q1"])
        R.check("OpenSSH_2k: distinct addresses with failed logins", ans["q2"] == str(len(t["sources"])) == "24", ans["q2"])
        tried = set(t["sources"]) | {a[2] for a in t["accepted"]} | t["invalid_sources"]
        R.check("OpenSSH_2k: addresses that attempted to log in = failed, accepted or invalid-user sources (was 1: the accepted ones)",
                ans["q3"] == str(len(tried)), (ans["q3"], len(tried)))
        R.check("OpenSSH_2k: the most targeted user", ans["q4"] == t["users"].most_common(1)[0][0] == "root", ans["q4"])
        R.check("OpenSSH_2k: who logged in", ans["q5"] == t["accepted"][0][1] == "fztu", ans["q5"])
        R.check("OpenSSH_2k: 'logged in as drewr' when no drewr is in the log is None (was the one login's address)", ans["q6"] is None, ans["q6"])
        R.check("OpenSSH_2k: 'message repeated' lines make the failed count unsure or None, never plain", not rd.plain(ans["q7"]) and len(t["repeats"]) == 2, ans["q7"])
        R.check("OpenSSH_2k: a time with no year is unsure and holds the stamp", "Dec 10 06:55:48" in rd.options(ans["q8"]), ans["q8"])
        R.check("OpenSSH_2k: twenty-four sources and one success from another address name no attacker", ans["q9"] is None, ans["q9"])
        R.check("OpenSSH_2k: failed logins from one address", ans["q10"] == str(t["sources"]["112.95.230.3"]) == "26", ans["q10"])
        root_lines = t["users"]["root"] + sum(1 for n, m in t["repeats"] if " for root " in m)
        root_all = t["users"]["root"] + sum(n for n, m in t["repeats"] if " for root " in m)
        R.check("OpenSSH_2k: failed logins for root, with and without the repeats", sorted(rd.options(ans["q11"])) == sorted([str(root_lines), str(root_all)]),
                (ans["q11"], root_lines, root_all))
    s = "nix_host/beats/auth/secure-rhel7.log"
    if R.need("beats secure-rhel7.log", s):
        t, fs = ssh_truth(s), rd.files(s)
        ans = ask_all(N, fs, Q)
        R.check("rhel7: most failed logins", ans["q0"] == t["sources"].most_common(1)[0][0], ans["q0"])
        R.check("rhel7: successful logins", ans["q1"] == str(len(t["accepted"])) == "3", ans["q1"])
        R.check("rhel7: distinct failing addresses", ans["q2"] == str(len(t["sources"])) == "3", ans["q2"])
        R.check("rhel7: addresses that attempted to log in (was 2)", ans["q3"] == str(len(set(t["sources"]) | {a[2] for a in t["accepted"]})) == "5", ans["q3"])
        R.check("rhel7: the address drewr logged in from", ans["q6"] == "69.245.39.97" and {a[2] for a in t["accepted"] if a[1] == "drewr"} == {"69.245.39.97"}, ans["q6"])
        R.check("rhel7: failed login attempts", ans["q7"] == str(t["failed_lines"]) == "352", ans["q7"])
        R.check("rhel7: no failing source logged in: no attacker named", ans["q9"] is None, ans["q9"])
    lx = "nix_host/loghub/Linux_2k.log"
    if R.need("loghub Linux_2k.log", lx):
        L, fs = lines(lx), rd.files(lx)
        pam = [ln for ln in L if re.search(r" sshd\(pam_unix\)\[\d+\]: authentication failure;", ln)]
        R.check("Linux_2k: the old PAM tag is seen by signals() (was 0.0)", N.signals([], fs) >= 0.5, N.signals([], fs))
        ans = R.timed("Linux_2k: solve_set", lambda: ask_all(N, fs, ["How many failed SSH logins are there?", "Which IP address had the most failed logins?",
                                                                    "How many different source IP addresses attempted to log in?",
                                                                    "How many failed login attempts are there?"]))
        R.check("Linux_2k: sshd(pam_unix) authentication failures are failed SSH logins (none was read before)", ans["q0"] == str(len(pam)) == "489", ans["q0"])
        named = sum(1 for ln in pam if not re.search(r"rhost=\d+\.\d+\.\d+\.\d+\b", ln))
        R.check("Linux_2k: sources logged by host name: no 'most' and no count of addresses", named > 0 and ans["q1"] is None and ans["q2"] is None, (named, ans["q1"], ans["q2"]))
        R.check("Linux_2k: su, ftp and login fail too, so 'failed login attempts' without SSH is None", ans["q3"] is None, ans["q3"])
    u = "nix_host/beats/auth/auth-ubuntu1204.log"
    if R.need("beats auth-ubuntu1204.log", u):
        L, fs = lines(u), rd.files(u)
        cmds = [ln for ln in L if re.search(r" sudo:\s+\S+ :.* COMMAND=", ln)]
        refused = [ln for ln in cmds if re.search(r"NOT in sudoers|incorrect password|not allowed", ln)]
        new = [re.search(r"new user: name=(\S+), UID=(\d+), GID=(\d+), home=(\S+), shell=(\S+)", ln).groups() for ln in L if "new user: name=" in ln]
        ans = ask_all(N, fs, ["How many sudo commands were run?", "What is the UID of the new user tsg?", "Which user account was created?",
                              "Which user logged in successfully?", "How many successful logins are there?"])
        R.check("ubuntu: sudo commands run = COMMAND lines sudo did not refuse", ans["q0"] == str(len(cmds) - len(refused)) == "184", (ans["q0"], len(cmds), len(refused)))
        R.check("ubuntu: the new user's uid", ans["q1"] == dict((n[0], n[1]) for n in new)["tsg"] == "1001", ans["q1"])
        R.check("ubuntu: two users were created, so 'which' is None", ans["q2"] is None and len(new) == 2, ans["q2"])
        acc = [re.search(r"Accepted \S+ for (\S+) from (\S+)", ln).groups() for ln in L if " Accepted " in ln]
        R.check("ubuntu: who logged in, how often", ans["q3"] == "vagrant" and ans["q4"] == str(len(acc)) == "13", (ans["q3"], ans["q4"]))
    sd = "nix_host/plaso/syslog_sudo.log"
    if R.need("plaso syslog_sudo.log", sd):
        L, fs = lines(sd), rd.files(sd)
        run = [ln for ln in L if "COMMAND=" in ln and not re.search(r"NOT in sudoers|incorrect password|not allowed", ln)]
        ans = ask_all(N, fs, ["What sudo command was run?", "What sudo command did svc-backup run?", "What command did john.doe run with sudo?",
                              "What command did test_user run with sudo?", "How many sudo commands were run?"])
        R.check("sudo: lines with no TTY= are read, so 'the' sudo command is None (was the one line that has a TTY)", ans["q0"] is None and len(run) > 3, (ans["q0"], len(run)))
        R.check("sudo: one user's command", ans["q1"] == "/usr/bin/id -un", ans["q1"])
        R.check("sudo: a user sudo refused ran nothing (was another user's command)", ans["q2"] is None and ans["q3"] is None, (ans["q2"], ans["q3"]))
        R.check("sudo: commands run", ans["q4"] == str(len(run)), (ans["q4"], len(run)))
    h = "nix_host/plaso/bash_history"
    if R.need("plaso bash_history", h):
        stamps = sum(1 for ln in lines(h) if re.fullmatch(r"#\d{9,10}", ln))
        R.check("bash history: a stamped command over four lines is one command (was 7 for 4)",
                rd.ask(N, rd.files(h), "How many commands are in the bash history?") == str(stamps) == "4")
    pl = "nix_host/plaso/launchd.plist"
    if R.need("plaso launchd.plist", pl):
        fs, d = rd.files(pl), plistlib.loads(rd.data(pl))
        ans = ask_all(N, fs, ["What is the Label of the launch agent?", "What is the StartInterval of the plist?", "Which user does the launchd job run as?",
                              "What program does the launchd job run?", "Does the launchd job run at load?"])
        R.check("launchd: Label, StartInterval", (ans["q0"], ans["q1"]) == (d["Label"], str(d["StartInterval"])), (ans["q0"], ans["q1"]))
        R.check("launchd: UserName (was offered the program)", ans["q2"] == d["UserName"] == "nobody", ans["q2"])
        R.check("launchd: Program and the first argument differ: unsure, Program first", rd.options(ans["q3"])[:1] == [d["Program"]] and d["ProgramArguments"][0] in rd.options(ans["q3"]), ans["q3"])
        R.check("launchd: a boolean is unsure by spelling", rd.unsure(ans["q4"]), ans["q4"])
        rows = N.persistence_rows(fs)
        R.check("launchd: the persistence row's command names the program launchd executes", len(rows) == 1 and d["Program"] in str(rows[0]["command"]), rows)
    tc = "nix_host/plaso/TCC-test.db"
    if R.need("plaso TCC-test.db", tc):
        con = sqlite3.connect(f"file:{rd.CACHE / tc}?mode=ro", uri=True)
        cam = [r[0] for r in con.execute("select client from access where service='kTCCServiceCamera'")]
        mic = [r[0] for r in con.execute("select client from access where service='kTCCServiceMicrophone'")]
        con.close()
        ans = ask_all(N, rd.files(tc), ["Which application was granted camera access in TCC?", "Which client has the microphone permission in TCC?",
                                       "Which app was granted Full Disk Access?"])
        R.check("TCC: the camera client", cam == [ans["q0"]], (ans["q0"], cam))
        R.check("TCC: the microphone client", mic == [ans["q1"]], (ans["q1"], mic))
        R.check("TCC: a service with no row is None", ans["q2"] is None, ans["q2"])
    qd = "nix_host/plaso/quarantine.db"
    if R.need("plaso quarantine.db", qd):
        con = sqlite3.connect(f"file:{rd.CACHE / qd}?mode=ro", uri=True)
        n = con.execute("select count(*) from LSQuarantineEvent").fetchone()[0]
        con.close()
        R.check("quarantine: event count", rd.ask(N, rd.files(qd), "How many quarantine events are there?") == str(n), n)
    ut = "nix_host/plaso/utmp"
    if R.need("plaso utmp", ut):
        b = rd.data(ut)
        recs = [b[i:i + 384] for i in range(0, len(b), 384)]
        users = [r[44:76].split(b"\0")[0].decode() for r in recs if int.from_bytes(r[:4], "little") == 7]
        ans = ask_all(N, rd.files(ut), ["How many successful logins are there?", "How many users logged in?", "When was the first login?"])
        R.check("utmp: logins = USER_PROCESS records", ans["q0"] == str(len(users)) == "6", ans["q0"])
        R.check("utmp: distinct users", ans["q1"] == str(len(set(users))) == "1", ans["q1"])
        R.check("utmp: a time is unsure", rd.unsure(ans["q2"]), ans["q2"])
    bt = "nix_host/beats/login/btmp.amd"
    if R.need("beats btmp", bt):
        b = rd.data(bt)
        users = [b[i + 44:i + 76].split(b"\0")[0].decode() for i in range(0, len(b), 384)]
        ans = ask_all(N, rd.files(bt), ["How many failed logins are there?", "How many failed logins were there for root?"])
        R.check("btmp: failed logins, and those of root", (ans["q0"], ans["q1"]) == (str(len(users)), str(users.count("root"))), (ans, users))
    wt = "nix_host/beats/login/wtmp"
    if R.need("beats wtmp", wt):
        R.check("wtmp: the address a user logged in from", rd.ask(N, rd.files(wt), "From which IP address did vagrant log in?") == "10.0.2.2")
    ot = "nix_host/otrf/sh_binary_padding_dd.zip.d"
    if R.need("OTRF auditd record", ot):
        raw = next((rd.CACHE / ot).glob("*.log")).read_text()
        args = re.findall(r'a\d="([^"]*)"', next(ln for ln in raw.splitlines() if ln.startswith("type=EXECVE")))
        R.check("auditd: the EXECVE's command, EXECVE and PROCTITLE agreeing", rd.ask(N, rd.files(ot), "What command was executed?") == " ".join(args), args)
    je = "nix_host/beats/journald/journal1.export"
    if R.need("beats journal export", je):
        n = sum(1 for ln in lines(je) if ln.startswith("__CURSOR="))
        item = N.classify("journal1.export", rd.data(je))
        R.check("journald: `journalctl -o export` is read (was 'text'): one record per __CURSOR", item[0] == "journal" and len(item[1]) == n, (item[0], n))
    for rel in ("nix_host/beats/auditd/audit-rhel7.log", "nix_host/beats/auditd/execve.log", "nix_host/plaso/audit.log", "nix_host/beats/auditbeat/sudo.log"):
        if R.need(rel.rsplit("/", 1)[-1], rel):
            kind, parsed = R.timed(f"{rel.rsplit('/', 1)[-1]}: classify", lambda: N.classify(rel.rsplit("/", 1)[-1], rd.data(rel)))
            serials = {m.group(1) for m in re.finditer(r"msg=audit\((\d+\.\d+:\d+)\)", rd.data(rel).decode("utf-8", "replace"))}
            R.check(f"{rel.rsplit('/', 1)[-1]}: auditd, one event per serial", kind == "audit" and len(parsed) == len(serials), (kind, len(parsed or []), len(serials)))
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
