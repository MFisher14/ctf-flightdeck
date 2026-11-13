#!/usr/bin/env python3
"""The windows toolkit on real artifacts (solvers/toolkits/windows.py).

  .venv/bin/python tests/real/test_real_windows.py

Offline. SKIPs when `challenges/_realdata/windows/` is absent (tests/real/fetch_a.py fills it). The files:
Huntress CTF 2024 Zimmer Down (NTUSER.DAT), Hidden Streams (Sysmon.evtx), Nightmare on Hunt Street and
Little Shop of Hashes (Security, System, Application logs), Huntress CTF 2025 Trashcan (117 $I files), and
public test corpora (python-evtx, EVTX-ATTACK-SAMPLES, regipy hives, Eric Zimmerman's prefetch files,
LnkParse3 shortcuts, omerbenamram/mft).

What each expectation rests on:
  event logs   a second parser. The toolkit reads through pyevtx-rs when it is installed and through
               python-evtx otherwise; here both read every log and must agree on every record's id,
               number, computer, channel and provider and on its time to 5 microseconds, and every
               plain count is checked against the other parser and against the record chain of the file.
  hives        regipy (its own reader of the same bytes).
  prefetch     the values Eric Zimmerman's own tests assert for these files (Prefetch.Test/TestVersion*.cs).
  shortcuts    LnkParse3.
  $MFT         the number of 1,024-byte entries that begin FILE.
  challenges   the flag the public write-up states.
"""
import copy
import hashlib
import io
import subprocess
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

from _real_a import check, finish, folder, is_plain, manifest, offers, options, q, timed, values

D = folder("windows")
import windows as W     # noqa: E402
sys.path.append(str(Path(__file__).resolve().parent.parent))       # tests/, last: for loadclock only
import loadclock        # noqa: E402  (tests/loadclock.py)


class ParseOnce:
    """SH-10: W.evtx_events, each log parsed once per parser in this run, every later reader handed a copy.

    Without pyevtx-rs every log is read through python-evtx (pure Python), and this script read the same
    logs again and again (read+summary, both parsers, each solve_set, each slack pass): 67 parses, about
    140 s of CPU, which a loaded machine stretched past the item's 280 s limit (SH-10). evtx_events is a
    function of the bytes and the parser: `src` only names the file in each event, and is set on the copy.
    A result cut by a deadline is not kept. `fresh` checks the premise: a real parse equals the copy.
    """

    def __init__(self, real):
        self.real, self.kept, self.parsed, self.reused = real, {}, 0, 0

    def key(self, data):
        return hashlib.sha256(data).digest(), len(data), W.evtx_rs() is not None

    def __call__(self, data, deadline=None, src=""):
        got = self.kept.get(self.key(data))
        if got is None:
            self.parsed += 1
            events, complete = self.real(data, deadline, src)
            if complete or deadline is None:
                self.kept[self.key(data)] = (copy.deepcopy(events), complete)
            return events, complete
        self.reused += 1
        events = copy.deepcopy(got[0])
        for e in events:
            e["src"] = src
        return events, got[1]

    def fresh(self, data, src=""):
        return self.real(data, None, src)

ZIMMER_FLAG = "flag{4b676ccc1070be66b1a15dB601c8d500}"       # Huntress 2024 Zimmer Down
STREAM_FLAG = "flag{bfefb891183032f44fa93d0c7bd40da9}"       # Huntress 2024 Hidden Streams
TRASH_FLAG = "flag{1d2b2b05671ed1ee5812678850d5e329}"        # Huntress 2025 Trashcan
# Eric Zimmerman's Prefetch.Test: (file, hash, uncompressed size, run count, last run, file names)
PREFETCH = (("prefetch-Win10-CHROME.EXE-B3BA7868.pf", 0xB3BA7868, 116042, 20, "2016-01-13T18:06:55.3344577Z", 282),
            ("prefetch-Win7-CALC.EXE-77FDF17F.pf", 0x77FDF17F, 23538, 2, "2016-01-16T20:27:01.19675Z", 37))


def ask(files: dict, *questions):
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=next(iter(files)))
          for i, t in enumerate(questions)]
    size = sum(len(v) for v in files.values())
    got, _ = timed("solve_set " + "+".join(files), lambda: W.solve_set(qs, files, {"partial": {}}), size)
    return [got.get(x["id"]) for x in qs]


def both_parsers(data: bytes):
    """(events through pyevtx-rs or None, events through python-evtx, complete flags)."""
    saved = list(W._EVTX_RS)
    try:
        W._EVTX_RS[:] = []
        fast = W.evtx_events(data) if W.evtx_rs() is not None else None
        W._EVTX_RS[:] = [None]
        slow = W.evtx_events(data)
    finally:
        W._EVTX_RS[:] = saved
    return fast, slow


def main() -> int:
    # SH-10: every toolkit budget (EVTX_UNTIMED's 25 s for a solve's logs, read from time.monotonic) counts
    # CPU seconds, so a loaded machine cannot cut a python-evtx read short and leave a count unanswered.
    # The command-line checks run in a child process on the real clock: their reads have no deadline.
    real = W.evtx_events
    W.evtx_events = once = ParseOnce(real)
    try:
        with loadclock.cpu_clock():
            return _main(once)
    finally:
        W.evtx_events = real


def _main(once) -> int:
    names = [e["name"] for e in manifest("windows")]
    check("every file of the manifest is in the cache", all((D / n).is_file() for n in names), [n for n in names if not (D / n).is_file()][:5])
    have_rs = W.evtx_rs() is not None
    print(f"note pyevtx-rs {'found' if have_rs else 'NOT found: python-evtx only (slow), the two-parser checks are skipped'}")

    # ---- every file is named by its bytes, read and summarised
    kinds = Counter()
    for n in names:
        if n.startswith("trashcan/$R"):
            continue                    # the $R files hold the deleted content (a line of text), not an artifact
        data = (D / n).read_bytes()
        kind = W.sniff(n, data)
        want = "evtx" if n.endswith(".evtx") else "lnk" if n.endswith(".lnk") else "prefetch" if n.endswith(".pf") else \
            "recycle" if n.startswith("trashcan/$I") else "mft" if n.startswith("mft-") else "hive"
        kinds[kind] += 1
        if kind != want:
            check(f"{n}: named {want} by its bytes", False, kind)
            continue
        if kind == "evtx" and not have_rs and len(data) > 2 << 20:
            continue                    # python-evtx alone needs seconds for these: read once, below
        try:
            (a, s), dt = timed(f"read+summary {n}", lambda: (lambda a: (a, W.summary(a)))(W.read(n, data)), len(data))
        except Exception as e:            # noqa: BLE001  a crash on a real file is the finding
            check(f"{n}: read and summarised", False, f"{type(e).__name__}: {e}")
    check(f"all {sum(kinds.values())} artifacts read without an error: {dict(kinds)}", True)

    # ---- event logs: two parsers, one answer
    logs = [n for n in names if n.endswith(".evtx")]
    counts = {}
    for n in logs:
        data = (D / n).read_bytes()
        chain = W.evtx_record_count(data)
        t = time.time()
        fast, (slow, slow_ok) = both_parsers(data)
        ev, ok = fast if fast is not None else (slow, slow_ok)
        counts[n] = Counter(e["id"] for e in ev)
        if fast is None and n == "pyevtx-dns_log_malformed.evtx":
            check(f"{n}: python-evtx stops in this log and the part it read is marked incomplete (nothing is counted from it)", not ok and len(ev) < chain, (len(ev), ok))
            continue
        check(f"{n}: {len(ev)} records, the file's record chain has {chain}", len(ev) == chain and ok, (len(ev), chain, ok))
        if fast is None or n == "pyevtx-dns_log_malformed.evtx":       # python-evtx stops in that log; pyevtx-rs reads all 5
            continue
        key = lambda e: (e["record"], e["id"], e["computer"], e["channel"], e["provider"])     # noqa: E731
        check(f"{n}: both parsers give the same records (id, number, computer, channel, provider)", sorted(map(key, fast[0])) == sorted(map(key, slow)))
        bys = {e["record"]: e for e in slow}
        late = [e["record"] for e in fast[0] if e["time"] is None or bys[e["record"]]["time"] is None or abs(int(e["time"]) - int(bys[e["record"]]["time"])) > 50]
        check(f"{n}: both parsers give the same time to 5 microseconds", not late, late[:5])
        mixed = [(e["record"], k) for e in fast[0] for k, v in e["data"].items() if isinstance(v, str) and (v.startswith("0x0") and len(v) > 3 or v in ("True", "False"))
                 and e.get("renderer") is None and k in ("LogonId", "SubjectLogonId", "TargetLogonId", "Initiated")]
        check(f"{n}: numbers and booleans as Windows writes them (0x3e7, true)", not mixed, mixed[:3])
    small = (D / "little_shop-HOSTB-System.evtx").read_bytes()
    first, mine = W.evtx_events(small, None, "copy.evtx")[0], once.fresh(small, "copy.evtx")[0]
    first[0]["data"]["sh10"] = "changed by a reader"          # a reader that changes its copy changes no other
    again = W.evtx_events(small, None, "copy.evtx")[0]
    check("the parse memo hands back the parser's own result (a fresh parse of HOSTB-System.evtx equals the kept copy, "
          "a new copy each time)", again == mine and len(mine) == 19 and first != mine and once.reused > 0,
          (len(mine), once.parsed, once.reused))
    print(f"note event-log parses so far: {once.parsed} parsed, {once.reused} handed a kept copy")
    sys_events = W.evtx_events((D / "hidden_streams-Sysmon.evtx").read_bytes())[0]
    check("Sysmon.evtx: a record's time keeps its 100 ns (the record header's FILETIME)", sys_events[0]["time"].iso() == "2024-08-28T00:18:19.5094125Z", sys_events[0]["time"].iso())
    for n in ("nightmare-Security.evtx", "pyevtx-security.evtx", "little_shop-HOSTA-Security.evtx", "hidden_streams-Sysmon.evtx"):
        files = {n.split("-", 1)[1]: (D / n).read_bytes()}
        name = next(iter(files))
        top = [i for i, _ in counts[n].most_common(3)]
        a = ask(files, ("integer", f"How many events are in {name}?"), *[("integer", f"How many events with event ID {i} are in {name}?") for i in top])
        check(f"{n}: the total and the three commonest ids are plain and are the other parser's counts",
              a == [str(sum(counts[n].values()))] + [str(counts[n][i]) for i in top], a)

    # ---- Huntress 2024 Nightmare on Hunt Street: the challenge's own five questions
    night = {x: (D / f"nightmare-{x}").read_bytes() for x in ("Security.evtx", "System.evtx", "Application.evtx")}
    a = ask(night, "What is the IP address of the host that the attacker used?",
            ("integer", "How many times was the compromised account brute-forced? Answer just the integer value."),
            "What is the name of the offensive security tool that was used to gain initial access? Answer in all lowercase.",
            ("integer", "How many unique enumeration commands were run with net.exe? Answer just the integer value."),
            "What password was successfully given to the user created?",
            ("integer", "How many events with event ID 4625 are in Security.evtx?"), "What is the source IP address of the failed logons?",
            "In event 4720, what is the TargetUserName?")
    check("nightmare 2: 'brute-forced' is the 4625 count, 32 (the write-up's flag), offered unsure", values(a[1]) == ["32"], a[1])
    check("nightmare: the 4625 count asked by id is plain 32", a[5] == "32", a[5])
    check("nightmare 1: the failed logons' source address is the write-up's 10.1.1.42 (unsure); 'the attacker' alone is not answered",
          values(a[6]) == ["10.1.1.42"] and a[0] is None, (a[0], a[6]))
    check("nightmare 3 and 4: a tool's name and a count of 'enumeration commands' are not answered", a[2] is None and a[3] is None, a[2:4])
    arts = W.artifacts(night)
    pw = list(dict.fromkeys(p["password"] for p in W.findings(arts)["net_user_passwords"]))
    check("nightmare 5: two passwords were tried with net user /add (the write-up's SusanIsStrong123 and a later one): two candidates, no answer",
          pw == ["SusanIsStrong123", "Susan123!"] and a[4] is None, (pw, a[4]))
    check("nightmare: the created account, asked by event id", values(a[7]) == ["susan_admin"], a[7])
    per = W.persistence(arts)
    check("nightmare: the persistence summary has the new local account", any(p["mechanism"] == "local_account" and p["name"] == "susan_admin" for p in per),
          [(p["mechanism"], p["name"]) for p in per])
    app = next(x for x in arts if x.file == "Application.evtx")
    check("nightmare: the cleared Application.evtx owns no record and still holds 61 (12980 to 13040), recovered apart from the log's own",
          app.events == [] and len(app.slack) == 61 and (app.slack[0]["record"], app.slack[-1]["record"]) == (12980, 13040)
          and all(e.get("slack") for e in app.slack), (len(app.events), len(app.slack)))
    b = ask({"Application.evtx": night["Application.evtx"]}, ("integer", "How many events are in Application.evtx?"))
    check("nightmare: a count over a log with recovered records offers both readings, never one plain", values(b[0]) == ["61", "0"], b[0])
    check("nightmare: the other logs have no slack and their counts stay plain", all(not x.slack for x in arts if x.file != "Application.evtx"))

    # ---- Huntress 2024 Hidden Streams
    sysmon = {"Sysmon.evtx": (D / "hidden_streams-Sysmon.evtx").read_bytes()}
    a = ask(sysmon, ("integer", "How many events with event ID 15 are in the log?"), "What is the content of the alternate data stream?",
            "What flag is hidden in the alternate data stream?", "In event 15, what is the TargetFilename?", ("integer", "How many events are in Sysmon.evtx?"))
    check("hidden streams: one event 15, plain; 2,850 records, plain (the file is named Sysmon.evtx)", a[0] == "1" and a[4] == "2850", (a[0], a[4]))
    check("hidden streams: the stream's Contents, base64 read, is the write-up's flag (first option, unsure)", values(a[1])[:1] == [STREAM_FLAG] and len(values(a[1])) == 2, a[1])
    check("hidden streams: the flag question; a NAME{guid} file name is not a flag", values(a[2]) == [STREAM_FLAG], a[2])
    check("hidden streams: the stream's path", offers(a[3], "C:\\Temp:$5GMLW"), a[3])

    # ---- Huntress 2024 Zimmer Down
    hive = {"ntuser.dat": (D / "zimmer_down-ntuser.dat").read_bytes()}
    v = W.Hive(hive["ntuser.dat"])
    enc = {r["name"]: (r["method"], r["decoded"]) for r in W.encoded_names(v)}
    check("zimmer down: RecentDocs holds the .b62 name and base62 reads it as the write-up's flag",
          enc.get("VJGSuERgCoVhl6mJg1x87faFOPIqacI3Eby4oP5MyBYKQy5paDF.b62") == ("base62", ZIMMER_FLAG), list(enc.items())[:4])
    check("zimmer down: the decoy names decode too (base64)", ("base64", "its_a_red_herring lol") in enc.values())
    a = ask(hive, "What is the flag hidden in the registry hive?", ("integer", "How many times was notepad.exe run according to UserAssist?"))
    check("zimmer down: the flag is offered unsure", values(a[0]) == [ZIMMER_FLAG], a[0])
    check("zimmer down: no Amcache rows are invented from a user hive", W.amcache(v) == [])

    # ---- Huntress 2025 Trashcan
    trash = {n.split("/", 1)[1]: (D / n).read_bytes() for n in names if n.startswith("trashcan/")}
    arts, _ = timed("artifacts trashcan", lambda: W.artifacts(trash), 1)
    bins = [x for x in arts if x.kind == "recycle"]
    check("trashcan: all 117 $I files are artifacts (39 different contents: same bytes under another name is another file)", len(bins) == 117, len(bins))
    rec = W.findings(arts)["recycle"]
    check("trashcan: the sizes read as characters in deletion order, runs of three collapsed, are the write-up's flag",
          (rec.get("sizes_by_deletion_time_collapsed") or "").strip() == TRASH_FLAG, rec)
    a = ask(trash, "What flag is hidden in the Recycle Bin?", ("integer", "How many $I files are in the Recycle Bin?"))
    check("trashcan: the flag is offered unsure", values(a[0]) == [TRASH_FLAG], a[0])
    one = W.recycle_i(trash["$I01XCGF.txt"])
    check("trashcan: one $I as RBCmd reads it (size 49, the path, a 1642 deletion time)", one["file_size"] == 49 and one["original_path"] == r"C:\Users\flag\Desktop\flag.txt"
          and one["deleted_time"].iso().startswith("1642-12-14T08:40:03"), one)

    # ---- hives against regipy
    try:
        from regipy.registry import RegistryHive
    except Exception:            # noqa: BLE001
        RegistryHive = None
        print("note regipy not importable: the hive comparison is skipped")
    if RegistryHive is not None:
        def rvals(h, path):
            try:
                return {x.name: x.value for x in h.get_key(path).iter_values()}
            except Exception:            # noqa: BLE001
                return {}
        for n in ("regipy-NTUSER.DAT", "zimmer_down-ntuser.dat", "regipy-NTUSER_BAGMRU.DAT"):
            h, v = RegistryHive(str(D / n)), W.Hive((D / n).read_bytes())
            run = rvals(h, "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            mine = {r["name"]: r["command"] for r in W.run_keys(v) if r["key"].lower().endswith("currentversion\\run")}
            ua = sum(1 for g in h.get_key("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist").iter_subkeys()
                     for x in h.get_key("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + g.name + "\\Count").iter_values()
                     if not W.rot13(x.name).startswith("UEME_CTL"))
            docs = sum(1 for x in h.get_key("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs").iter_values() if x.name.isdigit())
            check(f"{n}: Run values, UserAssist entries and RecentDocs entries as regipy reads them ({len(run)}, {ua}, {docs})",
                  run == mine and ua == len(W.userassist(v)) and docs == sum(1 for r in W.recent_docs(v) if r["key"] == "RecentDocs"))
        for n, host, zone in (("regipy-SYSTEM", "WKS-WIN732BITA", "Eastern Standard Time"), ("regipy-SYSTEM_WIN_10_1709", "DESKTOP-2KGM189", "Pacific Standard Time")):
            h, v = RegistryHive(str(D / n)), W.Hive((D / n).read_bytes())
            cs = "\\ControlSet%03d" % rvals(h, "\\Select").get("Current", 1)
            info = W.system_info(v)
            check(f"{n}: computer name and time zone as regipy reads the current control set", rvals(h, cs + "\\Control\\ComputerName\\ComputerName").get("ComputerName") == host
                  == info.get("computer_name") and info.get("timezone") == zone, info)
            usb = [s.name for s in h.get_key(cs + "\\Enum\\USBSTOR").iter_subkeys()]
            check(f"{n}: the USBSTOR device", [u.get("device") or u.get("name") for u in W.usbstor(v)] == usb, (usb, W.usbstor(v)[:1]))
        h, v = RegistryHive(str(D / "regipy-SAM")), W.Hive((D / "regipy-SAM").read_bytes())
        check("SAM: the three account names", sorted(s.name for s in h.get_key("\\SAM\\Domains\\Account\\Users\\Names").iter_subkeys()) == sorted(u["name"] for u in W.sam_users(v)))
        h, v = RegistryHive(str(D / "regipy-amcache.hve")), W.Hive((D / "regipy-amcache.hve").read_bytes())
        am = W.amcache(v)
        theirs = [{x.name: x.value for x in k.iter_values()}.get("LowerCaseLongPath") for k in h.get_key("\\Root\\InventoryApplicationFile").iter_subkeys()]
        check("Amcache: the 247 InventoryApplicationFile paths regipy reads are all rows, beside the older Root\\File rows; every row has a path",
              len(theirs) == 247 and set(theirs) <= {r["path"] for r in am} and all(r["path"] for r in am), len(am))
    a = ask({"SYSTEM": (D / "regipy-SYSTEM_WIN_10_1709").read_bytes()}, "What is the computer name?", "What is the time zone of the machine?")
    check("SYSTEM: computer name and time zone are answered unsure", values(a[0])[:1] == ["DESKTOP-2KGM189"] and values(a[1])[:1] == ["Pacific Standard Time"], a)
    a = ask({"NTUSER.DAT": (D / "regipy-NTUSER_BAGMRU.DAT").read_bytes()}, ("integer", r"How many values are under HKCU\Software\Microsoft\Windows\CurrentVersion\Run?"))
    check("NTUSER: six values under the Run key (regipy: six), offered unsure because the hive is dirty",
          values(a[0]) == ["6"] and not is_plain(a[0]), a[0])

    # ---- prefetch against Eric Zimmerman's test expectations
    for n, h, size, runs, last, nfiles in PREFETCH:
        p = W.prefetch((D / n).read_bytes())
        check(f"{n}: hash, size, run count, last run and file names as Prefetch.Test asserts",
              (p["hash"], p["file_size"], p["run_count"], p["last_run_time"].iso(), len(p["files"])) == (h, size, runs, last, nfiles),
              (hex(p["hash"]), p["file_size"], p["run_count"], p["last_run_time"].iso(), len(p["files"])))
    vers = {n: W.prefetch((D / n).read_bytes())["version"] for n in names if n.endswith(".pf")}
    check("prefetch: versions 17 (XP, 2003), 23 (Vista, 7), 26 (8.x, 2012 R2) and 30 (10) all read", sorted(set(vers.values())) == [17, 23, 26, 30], vers)
    a = ask({"CHROME.EXE-B3BA7868.pf": (D / "prefetch-Win10-CHROME.EXE-B3BA7868.pf").read_bytes()}, ("integer", "How many times was CHROME.EXE run?"),
            "Determine prefetch.run_count for CHROME.EXE-B3BA7868.pf", "When was CHROME.EXE last run?")
    check("prefetch: the run count is plain 20 in both wordings; the last run is offered with its 100 ns", a[0] == "20" and a[1] == "20"
          and "2016-01-13T18:06:55.3344577Z" in values(a[2]), a)

    # ---- shortcuts against LnkParse3
    try:
        import LnkParse3
    except Exception:            # noqa: BLE001
        LnkParse3 = None
        print("note LnkParse3 not importable: the shortcut comparison is skipped")
    for n in [x for x in names if x.endswith(".lnk")]:
        data = (D / n).read_bytes()
        mine = W.lnk(data)
        if LnkParse3 is None:
            continue
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            j = LnkParse3.lnk_file(io.BytesIO(data)).get_json()
        d, li = j.get("data") or {}, j.get("link_info") or {}
        same = (mine["arguments"] or None) == (d.get("command_line_arguments") or None) and (mine["working_dir"] or None) == (d.get("working_directory") or None) \
            and (mine["relative_path"] or None) == (d.get("relative_path") or None) and (mine["description"] or None) == (d.get("description") or None)
        if li.get("local_base_path"):
            same = same and mine["target_path"] == li["local_base_path"] + (li.get("common_path_suffix") or "")
        check(f"{n}: arguments, working directory, relative path, description and local target as LnkParse3 reads them", same,
              {k: str(mine[k])[:60] for k in ("arguments", "working_dir", "target_path")})
    pad = W.lnk((D / "lnkparse3-padded_cli_arguments.lnk").read_bytes())
    check("padded shortcut: the target is cmd.exe (from the item list: there is no LinkInfo) and the hidden arguments start /c",
          pad["target_path"] == r"C:\Windows\System32\cmd.exe" and pad["arguments"].startswith('/c "set PATH=') and pad["working_dir"].rstrip() == r"C:\Windows\System32"
          and pad["icon_location"] == r"C:\Windows\System32\shell32.dll", {k: str(pad[k])[:50] for k in ("target_path", "arguments", "icon_location")})
    a = ask({"invoice.lnk": (D / "lnkparse3-padded_cli_arguments.lnk").read_bytes()}, "What is the target path of the shortcut?")
    check("padded shortcut: the target is offered unsure", values(a[0])[:1] == [r"C:\Windows\System32\cmd.exe"], a[0])

    # ---- $MFT
    data = (D / "mft-MFT").read_bytes()
    recs, dt = timed("mft_records mft-MFT", lambda: W.mft_records(data), len(data))
    want = sum(1 for i in range(0, len(data), 1024) if data[i:i + 4] == b"FILE")
    check(f"$MFT: {len(recs)} records, one per FILE entry, in {dt:.2f} s; record 0 is $MFT and record 5 the root", len(recs) == want == 13068
          and recs[0]["name"] == "$MFT" and recs[5]["name"] == "." and recs[5]["is_directory"], (len(recs), want))
    one = W.mft_records((D / "mft-entry_single_file").read_bytes())[0]
    check("$MFT: the single-entry sample is test_cfuncs.py, 8,072 bytes, record 26370", (one["name"], one["size"], one["record"]) == ("test_cfuncs.py", 8072, 26370), one)

    # ---- the command line
    r = subprocess.run([sys.executable, str(W.__file__), str(D / "hidden_streams-Sysmon.evtx")], capture_output=True, text=True, timeout=120)
    check("cli: the triage of Sysmon.evtx prints the findings with the stream's flag", r.returncode == 0 and "== findings" in r.stdout and STREAM_FLAG in r.stdout, r.stderr[-300:])
    r = subprocess.run([sys.executable, str(W.__file__), "--ask", "What flag is hidden in the Recycle Bin?", str(D / "trashcan")], capture_output=True, text=True, timeout=120)
    check("cli: --ask on the Recycle Bin folder offers the flag", TRASH_FLAG in r.stdout, r.stdout[-300:] + r.stderr[-300:])
    return finish("test_real_windows")


if __name__ == "__main__":
    sys.exit(main())
