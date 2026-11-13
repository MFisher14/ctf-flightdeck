#!/usr/bin/env python3
"""`edr_persistence` on real artifacts (the cache of tests/real/fetch_b.py; SKIPs without it).

  .venv/bin/python tests/real/test_real_edr_persistence.py

Offline, nothing written, no request. Expected values are recounted here from the XML or JSON with
the standard library alone, or are the answers the write-ups state.

- Huntress CTF 2024 "Nightmare on Hunt Street" (Security.evtx, exported to XML by fetch_b.py with
  python-evtx; the log's header says 1 chunk and the file holds 16): parts 1 and 2 of the challenge.
- Huntress CTF 2024 "Little Shop of Hashes" (two hosts' logs) and 2025 "Webshellz" (Sysmon.evtx).
- OTRF Security-Datasets (Mordor): NXLog JSON of Sysmon, Security and PowerShell events for run-key,
  scheduled-task, WMI, Startup-folder and logon-script persistence, an Empire launcher, an LSASS dump.
"""
import collections
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("edr_persistence")
NIGHT = "edr_persistence/ctf2024_nightmare/logs-parts1-5.zip.d/Security.evtx.xml"
WEB = "edr_persistence/ctf2025_webshellz/Sysmon.evtx.xml"
SHOP = "edr_persistence/ctf2024_little_shop/little_shop_of_hashes_logs.zip.d"
OTRF = "edr_persistence/otrf/"


def xml_events(rel):
    text = re.sub(r'xmlns="[^"]+"', "", (rd.CACHE / rel).read_text(encoding="utf-8"))
    out = []
    for ev in ET.fromstring(text).iter("Event"):
        out.append((ev.findtext("System/EventID"), {d.get("Name"): (d.text or "") for d in ev.iter("Data")}))
    return out


def jsonl(rel):
    p = next((rd.CACHE / rel).glob("*.json"))
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def ask_all(E, fs, questions):
    return E.solve_set([{"qid": f"q{i}", "question": t} for i, t in enumerate(questions)], fs, {})


def main() -> int:
    E = rd.toolkit("edr_persistence")
    if R.need("Nightmare on Hunt Street", NIGHT):
        fs = rd.files(NIGHT)
        evs = xml_events(NIGHT)
        ids = collections.Counter(e for e, _ in evs)
        R.check("nightmare: the export holds every chunk (1,249 events, not the 97 of the header's one chunk)", len(evs) == 1249, len(evs))
        qs = ["What is the IP address of the host that the attacker used?",                                    # part 1: 10.1.1.42
              "How many times was the compromised account brute-forced? Answer just the integer value.",       # part 2: 32
              "How many failed logons are there?", "How many successful logons are there?", "How many process creation events are there?",
              "Which user account was created?", "Which account was brute-forced?", "What is the source address of the failed logons?",
              "What is the logon type of the failed logons?", "What is the hostname?",
              "What command line created the user susan_admin?",                                               # was plain 'susan_admin'
              "What password was successfully given to the user created?",                                     # part 5: an agent's
              "What is the name of the offensive security tool that was used to gain initial access? Answer in all lowercase.",
              "How many unique enumeration commands were run with net.exe? Answer just the integer value.",
              "Which group was the new user added to?", "When was the user account created?"]
        ans = R.timed("nightmare: solve_set of 16 questions on 1.7 MB of XML", lambda: ask_all(E, fs, qs))
        R.check("nightmare part 1 (write-up: 10.1.1.42)", ans["q0"] == "10.1.1.42", ans["q0"])
        R.check("nightmare part 2 (write-up: 32) is offered, as a pick", rd.options(ans["q1"]) == ["32"], ans["q1"])
        R.check("nightmare: failed logons = the 4625 events", ans["q2"] == str(ids["4625"]) == "32", ans["q2"])
        R.check("nightmare: successful logons = the 4624 events", ans["q3"] == str(ids["4624"]), ans["q3"])
        R.check("nightmare: process creations = the 4688 events", ans["q4"] == str(ids["4688"]), ans["q4"])
        made = [d for e, d in evs if e == "4720"]
        R.check("nightmare: the created account", ans["q5"] == made[0]["TargetUserName"] == "susan_admin" and len(made) == 1, ans["q5"])
        fails = [d for e, d in evs if e == "4625"]
        R.check("nightmare: the brute-forced account", ans["q6"] == "Jsmith" and {d["TargetUserName"] for d in fails} == {"Jsmith"}, ans["q6"])
        R.check("nightmare: the failures' source", ans["q7"] == "10.1.1.42" and {d["IpAddress"] for d in fails} == {"10.1.1.42"}, ans["q7"])
        R.check("nightmare: the failures' logon type", ans["q8"] == "3" and {d["LogonType"] for d in fails} == {"3"}, ans["q8"])
        R.check("nightmare: the host", ans["q9"] == "EC2AMAZ-0TD157D", ans["q9"])
        R.check("nightmare: a command line is not the created user's name", ans["q10"] != "susan_admin" and not rd.plain(ans["q10"]), ans["q10"])
        for i, what in ((11, "part 5, a password in a command line"), (12, "part 3, a tool's name"), (13, "part 4, 'unique enumeration commands'"),
                        (14, "three group adds")):
            R.check(f"nightmare: left to the agent, never plain ({what})", not rd.plain(ans[f"q{i}"]), ans[f"q{i}"])
        R.check("nightmare: a time is unsure", rd.unsure(ans["q15"]), ans["q15"])
        m = E.Model(fs)
        cmds = [p["command_line"] for p in m.procs if "susan_admin" in (p["command_line"] or "")]
        R.check("nightmare part 5 is in the process list for the agent (write-up: SusanIsStrong123)",
                any("SusanIsStrong123" in c for c in cmds), cmds[:2])
    if R.need("Webshellz Sysmon", WEB):
        fs = rd.files(WEB)
        evs = xml_events(WEB)
        ids = collections.Counter(e for e, _ in evs)
        p1 = {d["Image"].lower(): d for e, d in evs if e == "1"}
        frpc = p1[r"c:\programdata\frpc.exe"]
        fake = p1[r"c:\programdata\svchost.exe"]
        qs = ["How many process creation events are there?", "How many network connection events are there?", "What domain was queried?",
              "What is the parent image of frpc.exe?", "What is the command line of frpc.exe?", "What is the process ID of frpc.exe?",
              "What is the parent process ID of frpc.exe?", "What IP address did frpc.exe connect to?", "What destination port did frpc.exe connect to?",
              "What is the SHA256 hash of frpc.exe?", r"What is the parent image of C:\ProgramData\svchost.exe?",
              r"What is the SHA256 hash of C:\ProgramData\svchost.exe?", "What is the SHA256 hash of svchost.exe?",
              "What is the parent process of cmd.exe?", "What is the command line of net.exe?", "Which user ran frpc.exe?",
              "What is the password of the user IIS_USER?", "What is the attacker's IP address?", "What is the hostname?"]
        ans = R.timed("webshellz: solve_set of 19 questions", lambda: ask_all(E, fs, qs))
        net3 = [d for e, d in evs if e == "3" and d["Image"].lower().endswith("frpc.exe")]
        sha = dict(kv.split("=") for kv in frpc["Hashes"].split(","))["SHA256"]
        fake_sha = dict(kv.split("=") for kv in fake["Hashes"].split(","))["SHA256"]
        R.check("webshellz: Sysmon 1 count", ans["q0"] == str(ids["1"]) == "35", ans["q0"])
        R.check("webshellz: Sysmon 3 count", ans["q1"] == str(ids["3"]), ans["q1"])
        R.check("webshellz: the one DNS query", ans["q2"] == next(d["QueryName"] for e, d in evs if e == "22"), ans["q2"])
        R.check("webshellz: frpc.exe's ParentImage", ans["q3"] == frpc["ParentImage"], ans["q3"])
        R.check("webshellz: frpc.exe's command line as recorded (two spaces)", ans["q4"] == frpc["CommandLine"] == "frpc.exe  -c frpc.ini", ans["q4"])
        R.check("webshellz: frpc.exe's pid and parent pid", (ans["q5"], ans["q6"]) == (frpc["ProcessId"], frpc["ParentProcessId"]), (ans["q5"], ans["q6"]))
        R.check("webshellz: where frpc.exe connected", (ans["q7"], ans["q8"]) == (net3[0]["DestinationIp"], net3[0]["DestinationPort"]) and len(net3) == 1,
                (ans["q7"], ans["q8"]))
        R.check("webshellz: a hash is unsure by case and holds both", sorted(rd.options(ans["q9"])) == sorted([sha, sha.lower()]), ans["q9"])
        R.check("webshellz: a program named by its full path (was None): the fake svchost's parent is w3wp.exe",
                ans["q10"] == fake["ParentImage"] == r"C:\Windows\System32\inetsrv\w3wp.exe", ans["q10"])
        R.check("webshellz: the fake svchost's hash by its path", fake_sha in rd.options(ans["q11"]), ans["q11"])
        R.check("webshellz: 'svchost.exe' alone names two programs: None", ans["q12"] is None, ans["q12"])
        R.check("webshellz: three cmd.exe, two net.exe: None", ans["q13"] is None and ans["q14"] is None, (ans["q13"], ans["q14"]))
        R.check("webshellz: the user is unsure by domain", sorted(rd.options(ans["q15"])) == sorted([frpc["User"], frpc["User"].split("\\")[-1]]), ans["q15"])
        R.check("webshellz: a password and 'the attacker' are not answered", ans["q16"] is None and not rd.plain(ans["q17"]), (ans["q16"], ans["q17"]))
        R.check("webshellz: the host", ans["q18"] == "EC2AMAZ-AGR00JO", ans["q18"])
        tree = "\n".join(E.render_tree(E.Model(fs).procs))
        R.check("webshellz: the tree shows the web server as the parent of the shell's children (was a root with no parent)",
                re.search(r"\(w3wp\.exe \[4036\]\)\n\s+svchost\.exe \[3452\]", tree) is not None, tree[:200])
    if R.need("Little Shop of Hashes", SHOP):
        base = rd.CACHE / SHOP
        fs = {str(p.relative_to(base)): p.read_bytes() for p in sorted(base.rglob("*.evtx.xml"))}
        qs = ["What is the name of the service that the attacker ran and stopped, which dumped hashes on the first compromised host?",
              "What lateral movement technique did the threat actor use to move to the other machine?",
              "How many accounts were compromised by the threat actor?", "What is the command line of runasc.exe?"]
        ans = R.timed("little shop: solve_set over six exports of two hosts", lambda: ask_all(E, fs, qs))
        R.check("little shop: the three judgement questions are not answered plain", not any(rd.plain(ans[f"q{i}"]) for i in range(3)), ans)
        allp = [d for rel in fs for e, d in xml_events(f"{SHOP}/{rel}") if e == "4688" and d.get("NewProcessName", "").lower().endswith("runasc.exe")]
        R.check("little shop: runasc.exe's command line (part 3's binary, C:\\Users\\DeeDee\\Documents\\runasc.exe)",
                ans["q3"] is not None and len({d["CommandLine"] for d in allp}) == 1 and ans["q3"] == allp[0]["CommandLine"]
                and allp[0]["NewProcessName"] == r"C:\Users\DeeDee\Documents\runasc.exe", ans["q3"])
    sets = {
        "empire_persistence_registry_modification_run_keys_elevated_user.zip.d":
            (("What is the name of the registry value used for persistence?", "Updater"), ("What is the value name of the run key?", "Updater")),
        "empire_schtasks_creation_standard_user.zip.d":
            (("Who is the author of the scheduled task?", r"THESHIRE\pgustavo"), ("Which user created the scheduled task?", "pgustavo"),
             ("How many scheduled tasks were created?", "1")),
        "covenant_persistwmi.tar.gz.d":
            (("What is the name of the WMI event consumer?", "Evil Persistence"),
             ("What is the WMI filter query?", "select * from Win32_ProcessStartTrace where ProcessName='notepad.exe'"),          # had a leading quote
             ("What command does the WMI consumer run?", "powershell -Sta -Nop -Window Hidden -EncodedCommand <blah>")),          # was "...&lt;blah&gt;
        "cmd_userinitmprlogonscript_batch.zip.d": (("What is the registry value name used for persistence?", "UserInitMprLogonScript"),),
    }
    mech = {"empire_persistence_registry_modification_run_keys_elevated_user.zip.d": ("registry_run_key", "T1547.001"),
            "empire_schtasks_creation_standard_user.zip.d": ("scheduled_task", "T1053.005"), "covenant_persistwmi.tar.gz.d": ("wmi_event_subscription", "T1546.003"),
            "covenant_persiststartup.tar.gz.d": ("startup_folder", "T1547.001"), "cmd_userinitmprlogonscript_batch.zip.d": ("logon_script", "T1037.001")}
    for name, (m_name, tech) in mech.items():
        if not R.need(name.split(".")[0], OTRF + name):
            continue
        fs = rd.files(OTRF + name)
        model = R.timed(f"{name.split('.')[0]}: Model of {sum(map(len, fs.values())) >> 10} KiB", lambda: E.Model(fs))
        R.check(f"{name.split('.')[0]}: one persistence row, {m_name}", [r["mechanism"] for r in model.rows] == [m_name], [r["mechanism"] for r in model.rows])
        qs = ["What persistence mechanism was used?", "What is the MITRE ATT&CK technique ID of the persistence?"] + [t for t, _ in sets.get(name, ())]
        ans = ask_all(E, fs, qs)
        R.check(f"{name.split('.')[0]}: the mechanism and technique are picks that hold {m_name} and {tech}",
                m_name in rd.options(ans["q0"]) and tech in rd.options(ans["q1"]), (ans["q0"], ans["q1"]))
        for i, (t, want) in enumerate(sets.get(name, ())):
            R.check(f"{name.split('.')[0]}: {t} -> {want!r}", ans[f"q{i + 2}"] == want, ans[f"q{i + 2}"])
        R.check(f"{name.split('.')[0]}: signal with its questions reaches the threshold (0.6)", E.signals([{"question": t} for t in qs], fs) >= 0.6)
    s = "empire_schtasks_creation_standard_user.zip.d"
    if R.need("schtasks 4698", OTRF + s):
        fs = rd.files(OTRF + s)
        recs = jsonl(OTRF + s)
        t = [r for r in recs if str(r.get("EventID")) == "4698"]
        row = E.Model(fs).rows[0]
        R.check("schtasks: the 4698's TaskContent is XML-escaped in the export and is read all the same (command, author, daily trigger)",
                len(t) == 1 and t[0]["TaskContent"].startswith("&lt;?xml") and (row["command"] or "").startswith(r"C:\Windows\System32\WindowsPowerShell")
                and row["author"] == r"THESHIRE\pgustavo" and row["trigger"] == "daily", (row["command"], row["author"], row["trigger"]))
    r_ = "empire_persistence_registry_modification_run_keys_elevated_user.zip.d"
    if R.need("run keys count", OTRF + r_):
        fs, recs = rd.files(OTRF + r_), jsonl(OTRF + r_)
        n13 = sum(1 for r in recs if str(r.get("EventID")) == "13" and "Sysmon" in str(r.get("Channel")))
        R.check("run keys: registry value set events = the Sysmon 13 records", rd.ask(E, fs, "How many registry value set events are there?") == str(n13), n13)
        R.check("run keys: a Security and PowerShell export in NXLog JSON is recognised with no question (was 0.2)", E.signals([], fs) >= 0.6, E.signals([], fs))
    v = "empire_launcher_vbs.zip.d"
    if R.need("empire launcher", OTRF + v):
        fs = rd.files(OTRF + v)
        ans = R.timed("empire launcher: solve_set on 5.6 MB", lambda: ask_all(E, fs, ["What URL does the decoded PowerShell command contact?", "What is the decoded command?"]))
        R.check("empire launcher: the -enc command is decoded and its URL offered", rd.options(ans["q0"]) == ["http://10.10.10.5"], ans["q0"])
        R.check("empire launcher: a decoded command with layers is never plain", not rd.plain(ans["q1"]), str(ans["q1"])[:80])
    b = "cmd_bitsadmin_download_psh_script.zip.d"
    if R.need("bitsadmin", OTRF + b):
        fs = rd.files(OTRF + b)
        R.check("bitsadmin: Sysmon 1 and Security 4688 both record each process, so 'process creation events' is None",
                rd.ask(E, fs, "How many process creation events are there?") is None)
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
