#!/usr/bin/env python3
"""What the adversarial review of the group-a real-artifact package found, one check per fix.

  .venv/bin/python tests/real/test_review_a.py

Offline, a few seconds, no cache needed for the first part (every input is built here from invented values;
the builders are tests/real/test_fixes_a.py's and tests/maldoc_fixtures.py's). The last part reads three real
files when the cache `challenges/_realdata/` is there and is left out, with a note, when it is not.

The review asked each new reader questions that narrow, qualify or negate what it matches, fed it cut and
damaged files, and timed it on large inputs. What it found:

  maldoc   "Does the document NOT contain macros? (yes or no)" was answered `yes`, plain (a wrong plain answer);
           a Markdown list line or a shell pipe made a text file a `csv_dde` document; a real Word 97 file with
           FibBase.fEncrypted set read as not encrypted; a 4 MB .ppt whose stream holds 64 storages that each
           inflate to 64 MB took 5 GB and 17 s.
  windows  a Rust panic in pyevtx-rs (a BaseException) would have ended the whole set;
           every question ran the findings scan (every value of every event), and two logs asked about in turn
           ran it again each time: twelve plain questions over two large logs took 9 s on a path whose timed
           budget is 2.5 s; a log cut inside a chunk was counted as whole, plain; the same log under two names
           was counted twice; a shortcut target read only from the item list (which may hold 8.3 names) could
           be answered plain; `net user NAME * /add` gave `*` as a password and only the first of two commands
           on one line was read; the hex spelling rule rewrote a provider's own string (0x00007FFB...).
  network  the flag, the echo-request count, the DHCP address, the Telnet command and the SSH banner were
           offered for questions about something else (which packet holds the flag, how many pings failed,
           the address assigned to the DNS server, the output of the first command, the attacker's banner).
  email    the look-alike domain was offered for "which domain is NOT a look-alike" and for its registrar; every
           pair of a mail's domain labels was compared (800 domains: 5 s).
  plain    three plain answers to questions that negate or exclude: "the size in bytes of the email without the
           attachment" gave the attachment's size (email), "how many pages does the PDF not have" the page count
           (maldoc), "what is not the SHA-256 of download.html" the hash (network).
"""
import html
import importlib.util
import struct
import sys
import time
import zlib

from _real_a import REPO, check, finish, is_plain, q, values
import fetch_a

import test_fixes_a as F            # the builders: pcap, icmp_echo, tcp, modbus_write, shell_link
sys.path.insert(0, str(REPO / "tests"))
import loadclock                    # noqa: E402  (tests/loadclock.py)
import maldoc_fixtures as TM        # noqa: E402  cfb_write, lnk_bytes, pdf_bytes
import toolkit_fixtures as fx       # noqa: E402

import network as nw                # noqa: E402
import windows as W                 # noqa: E402
import maldoc as M                  # noqa: E402

spec = importlib.util.spec_from_file_location("tk_email_review", REPO / "solvers" / "toolkits" / "email.py")
E = importlib.util.module_from_spec(spec)
sys.modules["tk_email_review"] = E
spec.loader.exec_module(E)

FLAG = "flag{0123456789abcdef0123456789abcdef}"
YN = {"options": ["yes", "no"]}


def ask(mod, files, art, *texts, ctx=None):
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=art,
            **(t[2] if not isinstance(t, str) and len(t) > 2 else {})) for i, t in enumerate(texts)]
    got = mod.solve_set(qs, files, ctx if ctx is not None else {})
    return [got.get(x["id"]) for x in qs]


def event_xml(events) -> bytes:
    """An XML export: [(event id, {name: value})] as Security-Auditing events one second apart."""
    out = ["<Events>"]
    for n, (eid, data) in enumerate(events):
        rows = "".join(f'<Data Name="{k}">{html.escape(v)}</Data>' for k, v in data.items())
        out.append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
                   f"<EventID>{eid}</EventID><TimeCreated SystemTime=\"2026-01-02T03:04:{n % 60:02d}.000000Z\"/><EventRecordID>{n + 1}</EventRecordID>"
                   f"<Channel>Security</Channel><Computer>HOST.example</Computer></System><EventData>{rows}</EventData></Event>")
    return ("".join(out) + "</Events>").encode()


def main() -> int:
    # ---- network: a question about the thing is not a question for it
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(200, 232)) + FLAG.encode()
    cap = F.pcap([F.icmp_echo(i, struct.pack("<QQ", 1700000000 + i, i * 977) + bytes([b]) * 40) for i, b in enumerate(png)])
    a = ask(nw, {"c.pcap": cap}, "c.pcap", "What is the flag?", "What flag is hidden in the ICMP echo request payloads?",
            "Which packet number contains the flag?", "What is the flag's length?", "What is NOT the flag?", "What is the second flag?",
            "What flag is in the HTTP traffic?", "What is the name of the file hidden in the ICMP payloads?", "What is the flag format?",
            ("integer", "How many ICMP echo requests are in the capture?"), ("integer", "How many pings failed?"),
            ("integer", "How many ping requests got no reply?"), ("integer", "How many pings per second were sent?"),
            ("integer", "How many echo requests carry a payload of 0x41?"))
    check("network: the flag is still offered (unsure) to the two questions that ask for it", values(a[0]) == [FLAG] and values(a[1]) == [FLAG] and not is_plain(a[0]), a[:2])
    check("network: which packet, how long, what is not, the second one, the flag in other traffic, the hidden file's name, the format: no answer",
          a[2:9] == [None] * 7, a[2:9])
    check("network: the echo requests are counted for the bare question only (failed, no reply, per second, with a payload: no answer)",
          values(a[9]) == [str(len(png))] and a[10:] == [None] * 4, a[9:])
    bits = [int(b) for byte in FLAG.encode() for b in f"{byte:08b}"]
    cap = F.pcap([F.modbus_write(i, 0, bit) for i, bit in enumerate(bits)])
    a = ask(nw, {"c.pcap": cap}, "c.pcap", "What flag is hidden in the Modbus register writes?", "Which register hides the flag?",
            "What is the Modbus unit ID of the PLC that hides the flag?")
    check("network: Modbus writes that spell the flag answer the flag question, not which register or which unit", values(a[0]) == [FLAG] and a[1:] == [None, None], a)
    banner = F.pcap([F.tcp("192.0.2.20", "192.0.2.10", 22, 40001, 5000, 0x18, b"SSH-2.0-OpenSSH_9.9\r\n")])
    a = ask(nw, {"c.pcap": banner}, "c.pcap", "What is the SSH server banner?", "What SSH banner did the attacker's tool send?", "Which SSH banner was not sent by the server?")
    check("network: the server's SSH banner is not the attacker's tool's", values(a[0]) == ["SSH-2.0-OpenSSH_9.9"] and a[1:] == [None, None], a)

    # ---- maldoc
    slk = b"ID;PWXL;N;E\nNN;NAuto_Open;ER1C1\nC;Y1;X1;K0;EEXEC(\"calc.exe\")\nC;Y2;K0;EHALT()\nE\n"
    a = ask(M, {"sheet.slk": slk}, "sheet.slk", ("enum", "Does the document contain macros? (yes or no)", YN),
            ("enum", "Does the document not contain macros? (yes or no)", YN), ("enum", "Is the document free of macros? (yes or no)", YN),
            ("enum", "Doesn't the document contain macros? (yes or no)", YN))
    check("maldoc: macros that are there answer yes, plain", a[0] == "yes", a[0])
    check("maldoc: the negated question is not answered (it was `yes`, plain)", a[1:] == [None, None, None], a[1:])
    kinds = {name: M.kind_of(body, "notes.txt") for name, body in (
        ("markdown", b"# notes\n- item | other !important\n- two\n"), ("shell", b"#!/bin/sh\n-x foo | grep bar !baz\n"),
        ("batch", b"@echo off\n@call foo | bar !baz!\n"), ("sum", b"a,b\n1,=A1+B1\n2,-3|4!x\n"),
        ("dde", b"name,cmd\nbob,=cmd|' /C calc'!A0\n"), ("dde_path", b"x\n=MSEXCEL|'\\..\\..\\Windows\\System32\\cmd.exe /c calc.exe'!''\n"),
        ("dde_bare", b"x;+rundll32|URL.dll!A1\n"))}
    check("maldoc: a Markdown list, a shell pipe, a batch line and a sum are not DDE spreadsheets; cmd, MSEXCEL and rundll32 formulas are",
          kinds == {"markdown": "", "shell": "", "batch": "", "sum": "", "dde": "csv_dde", "dde_path": "csv_dde", "dde_bare": "csv_dde"}, kinds)
    d = M.parse(b"name,cmd\nbob,=cmd|' /C calc'!A0\nann,-x foo | grep bar !baz\n", "a.csv")
    check("maldoc: only the formula a spreadsheet would run is listed as DDE", d["fields"].get("dde") == ["cmd ' /C calc'"], d["fields"].get("dde"))
    fib = bytearray(b"\xec\xa5\xc1\x00" + b"\x00" * 5000)
    plain_doc = TM.cfb_write({"WordDocument": bytes(fib), "1Table": b"\x00" * 64})
    struct.pack_into("<H", fib, 0x0A, 0x1300)           # fEncrypted | fWhichTblStm | fExtChar
    locked = TM.cfb_write({"WordDocument": bytes(fib), "1Table": b"\x00" * 64})
    check("maldoc: FibBase.fEncrypted makes a Word 97 document encrypted (a real one read as not encrypted)",
          M.parse(locked, "a.doc")["fields"].get("encrypted") is True and M.parse(plain_doc, "a.doc")["fields"].get("encrypted") is False)
    a = ask(M, {"a.doc": locked}, "a.doc", ("enum", "Is the document encrypted? (yes or no)", YN), ("enum", "Does the document contain macros? (yes or no)", YN))
    check("maldoc: ... and nothing is said about the macros of a document that cannot be read", a[0] == "yes" and a[1] is None, a)

    def storage(tag: bytes) -> bytes:
        inner = M.OLE_MAGIC + tag + bytes(300000)
        body = struct.pack("<I", len(inner)) + zlib.compress(inner)
        return struct.pack("<HHI", 0x0010, 0x1011, len(body)) + body
    stream = bytes(40) + storage(b"A") * 3 + storage(b"B") + storage(b"C") + storage(b"D") + bytes(16)
    kept, M.PPT_INFLATE_MAX = M.PPT_INFLATE_MAX, 1 << 20
    try:
        got = M.ppt_storages(stream)
    finally:
        M.PPT_INFLATE_MAX = kept
    check("maldoc: the storages of a PowerPoint stream inflate within one budget, and the same storage is read once (64 storages of a 4 MB file asked for 4 GB)",
          [g[8:9] for g in got] == [b"A", b"B"] and sum(map(len, got)) <= 1 << 20 and len(M.ppt_storages(stream)) == 4, [g[8:9] for g in got])

    # ---- windows
    events = [(4624, {"TargetUserName": f"user{n}", "LogonType": "3", "Note": "SHA256=" + "AB" * 32}) for n in range(600)]
    events[77] = (4688, {"CommandLine": "cmd /c net user backup Winter2026! /add & net user helper Spring2026! /add", "NewProcessName": "C:\\Windows\\System32\\net.exe"})
    events[78] = (4688, {"CommandLine": "net user guest * /add", "NewProcessName": "C:\\Windows\\System32\\net.exe"})
    events[300] = (4104, {"ScriptBlockText": f"Write-Output {FLAG}"})
    xml = event_xml(events)
    arts = W.artifacts({"sec.xml": xml})
    f = W.findings(arts)
    check("windows: every `net user ... /add` of a command line is read, and `*` (ask at the prompt) is not a password",
          [(p["user"], p["password"]) for p in f["net_user_passwords"]] == [("backup", "Winter2026!"), ("helper", "Spring2026!")], f["net_user_passwords"])
    a = ask(W, {"sec.xml": xml}, "sec.xml", "What is the password of the user account that was created?", "What is the password of the new user account backup?",
            "What is the password hash of the new user account backup?", "What is the flag?", "Which event holds the flag?", "How long is the flag?",
            "What is NOT the flag?")
    check("windows: two created accounts are no one password; the named one's is offered; its hash is another question",
          a[0] is None and values(a[1])[:1] == ["Winter2026!"] and not is_plain(a[1]) and a[2] is None, a[:3])
    check("windows: the flag answers the question for it, not which event holds it, how long it is or what it is not",
          values(a[3]) == [FLAG] and not is_plain(a[3]) and a[4:] == [None, None, None], a[3:])
    two_logs = {"sec.xml": xml, "copy/dc.xml": xml.replace(b"HOST.example", b"HOST2.example")}
    before = W._FIND_STOP[1]
    a = ask(W, two_logs, "evidence.zip", *[("integer", f"How many events with event ID 4624 are in {n}?") for n in ("sec.xml", "dc.xml")] * 6)
    check("windows: a question that asks for no flag, password or stream does not read every value of every event (twelve such questions ran the scan twelve times)",
          W._FIND_STOP[1] == before and a == ["597"] * 12, (W._FIND_STOP[1] - before, a[:2]))
    a = ask(W, two_logs, "evidence.zip", *["What is the flag in sec.xml?", "What is the flag in dc.xml?"] * 4)
    check("windows: ... and two groups of files asked about in turn are each scanned once", W._FIND_STOP[1] == before + 2 and [values(x) for x in a] == [[FLAG]] * 8,
          (W._FIND_STOP[1] - before, a[:2]))
    W._FINDINGS.clear()
    W._FIND_STOP[0] = time.monotonic() - 1
    try:
        hits = W._q_special("what is the flag?", arts)
    finally:
        W._FIND_STOP[0] = None
    check("windows: out of time inside the scan is no finding and no answer, and nothing half-read is kept", hits == [] and not W._FINDINGS, hits)
    one = ask(W, {"sec.xml": xml}, "sec.xml", ("integer", "How many events with event ID 4624 are in the log?"))
    two = ask(W, {"sec.xml": xml, "backup/sec-copy.xml": xml}, "evidence.zip", ("integer", "How many events with event ID 4624 are in the log?"))
    check("windows: the same log under a second name is one log (it was counted twice)", one == ["597"] and two == one, (one, two))
    recycle = {f"$I{n:06d}.txt": F.recycle_i(65, 133000000000000000) for n in range(3)}
    check("windows: ... while equal $I files under different names stay separate files", len(W.artifacts(recycle)) == 3)
    chunk = b"ElfChnk\x00" + bytes(0x10000 - 8)
    whole = b"ElfFile\x00" + bytes(0x1000 - 8) + chunk + chunk
    check("windows: a log that ends inside a chunk is cut; one that ends on a chunk is not",
          W.evtx_cut(whole) is False and W.evtx_cut(whole[:-1]) is True and W.evtx_cut(whole[:0x1000 + 0x10000 + 0x100]) is True
          and W.evtx_cut(whole[:0x1000 + 0x10000]) is False and W.evtx_cut(b"ElfFile\x00" + bytes(0x1000 - 8)) is False)
    class PanicException(BaseException):        # what pyo3 raises for a Rust panic: not an Exception
        pass

    class Panics:
        def __init__(self, *a):
            raise PanicException("index out of bounds")
    kept = list(W._EVTX_RS)
    W._EVTX_RS[:] = [type("fake_evtx", (), {"PyEvtxParser": Panics})]
    try:
        got = W._evtx_fast(whole, None, "x", {})
    except BaseException as e:                  # noqa: BLE001
        got = e
    finally:
        W._EVTX_RS[:] = kept
    check("windows: a panic inside the Rust parser is the fallback's turn, not the end of the set", got is None, repr(got))
    link = F.shell_link(["PROGRA~1", "TOOLS~1", "UPDATE~1.EXE"], "C:\\", "/s")
    full = TM.lnk_bytes()
    base = {"syntax": "base file name only, no directory path"}
    a = ask(W, {"a.lnk": link}, "a.lnk", ("exact_text", "What is the target path of the shortcut?", base))
    b = ask(W, {"b.lnk": full}, "b.lnk", ("exact_text", "What is the target path of the shortcut?", base))
    check("windows: a target read only from the item list (8.3 names) is offered, never plain; one from LinkInfo may be plain",
          not is_plain(a[0]) and "UPDATE~1.EXE" in values(a[0]) and b[0] is not None, (a, b))

    # ---- email
    mail = (b"From: IT <it@contoso-corp.example>\r\nTo: bob@contoso-corp.example\r\nReply-To: it@contoso-c0rp.example\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: text/html\r\n\r\n<a href="http://contoso-c0rp.example/login">Pay here</a>')
    a = ask(E, {"m.eml": mail}, "m.eml", "What is the lookalike domain used in the email?", "Which domain is NOT a lookalike domain?",
            "What is the typosquatted domain's registrar?", "Which character differs in the lookalike domain?")
    check("email: the look-alike domain answers the question for it only", values(a[0])[:1] == ["contoso-c0rp.example"] and a[1:] == [None, None, None], a)

    import random
    rnd = random.Random(5)
    links = "".join(f'<a href="http://{"".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))}.example/p">x</a>\n' for _ in range(1500))
    big = mail.replace(b"<a href", links.encode() + b"<a href", 1)
    # Timed in this process's CPU time: a full-suite run on a loaded machine stretched its wall time to
    # 6.7 s while the work stayed the same (SH-08). Comparing every pair again is seconds of CPU.
    t0 = time.process_time()
    a = ask(E, {"m.eml": big}, "m.eml", "What is the lookalike domain used in the email?")
    dt = time.process_time() - t0
    check(f"email: a mail with 1,500 other domains still names the look-alike of its own party, in {dt:.2f} s of CPU (every pair of 800 took 5 s)",
          values(a[0])[:1] == ["contoso-c0rp.example"] and dt < 2.0, (a, dt))

    # ---- a question that negates or excludes is never answered plain (email, maldoc, network; windows and memory account for every word already)
    att = bytes(range(256)) * 3
    import base64
    mail = (b"From: a@x.example\r\nTo: b@y.example\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n"
            b"Content-Type: text/plain\r\n\r\nhello\r\n--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"tool.bin\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(att).replace(b"\n", b"\r\n") + b"--B--\r\n")
    a = ask(E, {"m.eml": mail}, "m.eml", ("integer", "What is the size in bytes of the attachment?"), ("integer", "What is the size in bytes of the email without the attachment?"),
            "What is the SHA-256 of the attachment?", "What is the SHA-256 of the file that is not the attachment?",
            ("integer", "What is the size in bytes of the attachment? Do not include a unit."))
    check("email: the attachment's size and hash are plain; 'without the attachment' and 'not the attachment' are not (they were); a format instruction is not a negation",
          a[0] == "768" and not is_plain(a[1]) and is_plain(a[2]) and not is_plain(a[3]) and a[4] == "768", a)
    pdf = TM.pdf_bytes()
    a = ask(M, {"a.pdf": pdf}, "a.pdf", ("integer", "How many pages does the PDF have?"), ("integer", "How many pages does the PDF not have?"),
            ("integer", "How many pages other than the first does the PDF have?"))
    check("maldoc: a page count is plain for the bare question only", is_plain(a[0]) and not is_plain(a[1]) and not is_plain(a[2]), a)
    body = b"<html>" + b"x" * 500 + b"</html>"
    http = [F.tcp("192.0.2.10", "192.0.2.20", 40001, 80, 1000, 0x02), F.tcp("192.0.2.20", "192.0.2.10", 80, 40001, 5000, 0x12),
            F.tcp("192.0.2.10", "192.0.2.20", 40001, 80, 1001, 0x18, b"GET /download.html HTTP/1.1\r\nHost: files.example\r\n\r\n"),
            F.tcp("192.0.2.20", "192.0.2.10", 80, 40001, 5001, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body),
            F.tcp("192.0.2.20", "192.0.2.10", 80, 40001, 5001 + 38 + len(str(len(body))) + len(body), 0x11),
            F.tcp("192.0.2.10", "192.0.2.20", 40001, 80, 1001 + 52, 0x11)]
    a = ask(nw, {"c.pcap": F.pcap(http)}, "c.pcap", ("integer", "How many packets are in the capture?"), ("integer", "How many packets are not in the capture?"),
            "What is the SHA-256 of download.html?", "What is not the SHA-256 of download.html?")
    import hashlib
    check("network: the packet count and a whole carved file's hash are plain; the negated questions are not",
          a[0] == "6" and not is_plain(a[1]) and a[2] == hashlib.sha256(body).hexdigest() and not is_plain(a[3]), a)

    # ---- the real files, when the cache is there
    root = fetch_a.cache_root()
    if not (root / "windows").is_dir() or not (root / "maldoc").is_dir():
        print("note no real-file cache: the three real-file checks are left out (tests/real/fetch_a.py fills it)")
    else:
        log = (root / "windows" / "nightmare-Security.evtx").read_bytes()
        cnt = ("integer", "How many events with event ID 1102 are in the log?")
        tot = ("integer", "How many events are in the log?")
        # SH-10: the windows toolkit reads an event log under a 25 s budget of time.monotonic (EVTX_UNTIMED);
        # python-evtx needs several CPU seconds for this log, so a loaded machine could cut the read and
        # leave the counts unanswered. The same budget, counted in CPU seconds (tests/loadclock.cpu_clock).
        with loadclock.cpu_clock():
            a = ask(W, {"Security.evtx": log}, "Security.evtx", cnt, tot)
            b = ask(W, {"Security.evtx": log[:int(len(log) * 0.3)]}, "Security.evtx", cnt, tot)
            c = ask(W, {"Security.evtx": log, "old/Security-backup.evtx": log}, "evidence.zip", cnt)
        check("real: a whole log's counts are plain; the same log cut inside a chunk answers no count plain (it said 448 events and one 1102, plain)",
              a == ["1", "1249"] and not is_plain(b[0]) and not is_plain(b[1]), (a, b))
        check("real: the log delivered twice under two names is counted once", c == ["1"], c)
        doc = (root / "maldoc" / "oletools-encrypted.doc").read_bytes()
        a = ask(M, {"encrypted.doc": doc}, "encrypted.doc", ("enum", "Is the document encrypted? (yes or no)", YN))
        check("real: oletools' encrypted.doc is encrypted (it was offered `no`)", a == ["yes"], a)
        ev, _ = W.evtx_events((root / "windows" / "hidden_streams-Sysmon.evtx").read_bytes())
        padded = [v for e in ev for v in e["data"].values() if isinstance(v, str) and W._HEX_PADDED.fullmatch(v) and len(v) in (10, 18)]
        check("real: no value of the Sysmon log is a padded hex number in either spelling rule's reach (the rule rewrites python-evtx's own padding only)",
              W.evtx_rs() is None or not padded, padded[:3])
    return finish("test_review_a")


if __name__ == "__main__":
    sys.exit(main())
