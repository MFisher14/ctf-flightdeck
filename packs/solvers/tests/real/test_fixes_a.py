#!/usr/bin/env python3
"""What the real artifacts taught the group-a toolkits, as small built-here cases (no cache needed).

  .venv/bin/python tests/real/test_fixes_a.py

Offline, a second or two, nothing downloaded and nothing written outside a temporary folder. The
tests/real/test_real_<toolkit>.py files check the same behaviour on the real files and SKIP where the
cache `challenges/_realdata/` is absent; this file keeps each fix under test everywhere. Every case is the
shape a real file had (named in the comment), rebuilt from invented values: RFC 5737 addresses, .example
names, nothing of any real artifact.
"""
import importlib.util
import struct
import sys
import zipfile
import zlib
import io

from _real_a import REPO, check, finish, is_plain, q, values

sys.path.insert(0, str(REPO / "tests"))
import toolkit_fixtures as fx       # noqa: E402

import network as nw                # noqa: E402
import windows as W                 # noqa: E402
import maldoc as M                  # noqa: E402
import memory as MEM                # noqa: E402

spec = importlib.util.spec_from_file_location("tk_email", REPO / "solvers" / "toolkits" / "email.py")
E = importlib.util.module_from_spec(spec)
sys.modules["tk_email"] = E
spec.loader.exec_module(E)

FLAG = "flag{0123456789abcdef0123456789abcdef}"


# ---- builders ----------------------------------------------------------------------------------------------------

def pcap(frames, linktype=1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


def icmp_echo(seq: int, payload: bytes, reply=False) -> bytes:
    body = struct.pack(">BBHHH", 0 if reply else 8, 0, 0, 0x1234, seq) + payload
    return fx._eth(fx._ip4("192.0.2.10", "192.0.2.20", body, proto=1))


def tcp(src, dst, sport, dport, seq, flags, payload=b"") -> bytes:
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload
    return fx._eth(fx._ip4(src, dst, seg, proto=6))


def modbus_write(tid: int, address: int, value: int) -> bytes:
    pdu = struct.pack(">HHHBBHH", tid, 0, 6, 1, 6, address, value)
    return tcp("192.0.2.10", "192.0.2.20", 40000, 502, 1000 + 12 * tid, 0x18, pdu)


def shell_link(target_items, working_dir: str, arguments: str, stated_count=None) -> bytes:
    """A shell link with an item list and no LinkInfo; stated_count overstates the working directory's length."""
    items = b"\x14\x00\x1f\x50" + bytes(16)                                     # root folder
    items += struct.pack("<H", 25) + b"\x2fC:\\" + bytes(19)                     # volume C:\
    for i, name in enumerate(target_items):
        body = bytes([0x36 if i == len(target_items) - 1 else 0x35, 0]) + bytes(10) + name.encode("utf-16-le") + b"\x00\x00"
        items += struct.pack("<H", len(body) + 2) + body
    items += b"\x00\x00"
    head = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046") + struct.pack("<I", 0x01 | 0x10 | 0x20 | 0x80)
    head += bytes(76 - len(head))
    wd = working_dir.encode("utf-16-le")
    out = head + struct.pack("<H", len(items)) + items
    out += struct.pack("<H", stated_count if stated_count is not None else len(working_dir)) + wd
    out += struct.pack("<H", len(arguments)) + arguments.encode("utf-16-le")
    return out + b"\x00\x00\x00\x00"


def recycle_i(size: int, when: int) -> bytes:
    path = "C:\\Users\\a\\Desktop\\note.txt\x00"
    return struct.pack("<QQQI", 2, size, when, len(path)) + path.encode("utf-16-le")


def eprocess(pid, ppid, name, created, tag=True, header=True) -> bytes:
    """A 32-bit EPROCESS in the Windows XP layout with its pool header: tag at +4, object at +0x20."""
    rec = bytearray(0x300)
    if tag:
        rec[4:8] = b"Pro\xe3"
    base = 0x20
    if header:
        rec[base:base + 4] = b"\x03\x00\x1b\x00"
    struct.pack_into("<Q", rec, base + 0x70, created)
    struct.pack_into("<III", rec, base + 0x84, pid, 0x81000000 + pid, 0x82000000 + pid)
    struct.pack_into("<I", rec, base + 0x14C, ppid)
    rec[base + 0x174:base + 0x174 + len(name)] = name.encode()
    return bytes(rec)


def elf32_core(pid, ppid, name, args) -> bytes:
    info = struct.pack("<BBBBIHHiiii", 0, 0, 0, 0, 0, 1000, 1000, pid, ppid, pid, pid) + name.encode().ljust(16, b"\x00") + args.encode().ljust(80, b"\x00")
    note = struct.pack("<III", 5, len(info), 3) + b"CORE\x00\x00\x00\x00" + info
    eh = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", 4, 3, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    ph = struct.pack("<IIIIIIII", 4, 52 + 32, 0, 0, len(note), len(note), 0, 4)
    return eh + ph + note


def main() -> int:
    # ---- network
    # Echo Chamber (2024): `ping -p` writes 16 bytes of time before the pattern byte
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(200, 232)) + FLAG.encode()
    cap = nw.read(pcap([icmp_echo(i, struct.pack("<QQ", 1700000000 + i, i * 977) + bytes([b]) * 40) for i, b in enumerate(png)]))
    check("network: one byte per ping behind the 16-byte time is read; a binary result is a blob, and its one flag a reading",
          cap.hidden("icmp") == {"echo_request:repeated_byte_flag": FLAG} and [(b.kind, b.size) for b in cap.hidden_blobs()] == [("png", len(png))], cap.hidden("icmp"))
    cap = nw.read(pcap([icmp_echo(i, bytes([b]) * 32) for i, b in enumerate(b"hello covert world")]))
    check("network: the plain repeated-byte channel still reads as text", cap.hidden("icmp") == {"echo_request:repeated_byte": "hello covert world"}, cap.hidden("icmp"))
    # a real capture began inside a connection, on a TCP keep-alive byte
    req = b"GET /a.txt HTTP/1.1\r\nHost: files.example\r\n\r\n"
    cap = nw.read(pcap([tcp("192.0.2.10", "192.0.2.20", 40001, 80, 999, 0x10, b"\x00"), tcp("192.0.2.10", "192.0.2.20", 40001, 80, 1000, 0x18, req)]))
    check("network: a keep-alive byte before the first captured request is not part of the stream",
          [(r.method, r.host, r.uri) for r in cap.http()] == [("GET", "files.example", "/a.txt")], [dict(r) for r in cap.http()][:1])
    # Bussing Around (2025): a zip, one bit per register write, its comment stating the password
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("flag.txt", FLAG + "\n")
    bits = [int(b) for byte in buf.getvalue() for b in f"{byte:08b}"]
    cap = nw.read(pcap([modbus_write(i, 0, bit) for i, bit in enumerate(bits)]))
    ser = cap.modbus_series()
    blobs = [b for b in cap.hidden_blobs() if b.channel == "modbus"]
    check("network: the values written to one register, read as bits, are a zip whose member holds the flag",
          len(ser) == 1 and ser[0].reading == "bits_msb" and len(blobs) == 1 and blobs[0].kind == "zip" and blobs[0].flags == [FLAG], [(s.reading, s.writes) for s in ser])
    got = nw.solve_set([q("a", "What flag is hidden in the Modbus register writes?", artifact="c.pcap"), q("b", "What is the flag?", artifact="c.pcap")],
                       {"c.pcap": pcap([modbus_write(i, 0, bit) for i, bit in enumerate(bits)])}, {})
    check("network: the flag is offered unsure for both wordings, never plain", values(got["a"]) == [FLAG] and values(got["b"]) == [FLAG], got)
    # reverse lookups and service discovery are not a DNS tunnel (a Wireshark sample showed them as one)
    def dnsq(name, i):
        query = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0) + fx._name(name) + struct.pack(">HH", 12, 1)
        return fx._eth(fx._ip4("192.0.2.10", "192.0.2.53", fx._udp(53000 + i, 53, query)))
    cap = nw.read(pcap([dnsq(f"{i}.2.0.192.in-addr.arpa", i) for i in range(1, 6)] + [dnsq(f"_ldap._tcp.site{i}._sites.corp.example", i + 10) for i in range(4)]))
    check("network: PTR lookups and _service names are not labels of a tunnel", cap.dns_tunnel() == [] and cap.hidden("dns") == {}, cap.dns_tunnel())

    # ---- windows
    # Trashcan (2025): 117 $I files with 39 different contents; the answer was in how often each occurred
    when = 0x01DB000000000000
    text = "".join(c * 3 for c in FLAG) + "\n\n\n"
    files = {f"$I{i:06d}.txt": recycle_i(ord(c), when + i * 10_000_000) for i, c in enumerate(text)}
    arts = W.artifacts(files)
    rec = W.findings(arts)["recycle"]
    check("windows: files with the same bytes and other names are all artifacts; their sizes in deletion order, runs collapsed, are read",
          len(arts) == len(text) and (rec["sizes_by_deletion_time_collapsed"] or "").strip() == FLAG, (len(arts), rec.get("sizes_by_deletion_time_collapsed")))
    got = W.solve_set([q("a", "What flag is hidden in the Recycle Bin?", artifact="bin.zip")], files, {})
    check("windows: that flag is offered unsure", values(got["a"]) == [FLAG] and not is_plain(got["a"]), got)
    # Zimmer Down (2024): a file name that is base62 text
    n, alphabet = int.from_bytes(FLAG.encode(), "big"), W._B62
    b62 = ""
    while n:
        n, r = divmod(n, 62)
        b62 = alphabet[r] + b62
    check("windows: base62, base64 and hex names decode; a GUID in braces is not a flag", ("base62", FLAG) in W.decodings(b62)
          and ("base64", "its_a_red_herring lol") in W.decodings("aXRzX2FfcmVkX2hlcnJpbmcgbG9s") and W._FLAG_RX.search("SourceHash{DDC95F26-92B1-4546-9678-5DC68DF76BA0}") is None
          and W._FLAG_RX.search(FLAG) is not None)
    # event values as Windows writes them, whichever parser read the log
    ev = W._evtx_finish({"time": W.filetime(133692779540335850), "renderer": "python-evtx",
                         "data": {"LogonId": "0x00000000000003e7", "ProcessGuid": "B56AE52F-6533-66CE-BE00-000000000900",
                                  "Empty": "\n    ", "Text": "0x0 stays"}}, 7, {7: 133692779540335852})
    check("windows: 0x3e7, {guid}, an empty element, and the record header's exact time", ev["data"] == {"LogonId": "0x3e7", "ProcessGuid": "{b56ae52f-6533-66ce-be00-000000000900}",
                                                                                                         "Empty": "", "Text": "0x0 stays"} and int(ev["time"]) == 133692779540335852, ev)
    ev = W._evtx_finish({"time": None, "renderer": "python-evtx", "data": {"StartAddress": "0x00007FFB6C2E0000"}}, 8, {})
    rs = W._evtx_finish({"time": None, "data": {"Address": "0x00000000000003e7"}}, 9, {})
    check("windows: a string that only looks like a padded number (capitals: the provider's own text) and anything pyevtx-rs rendered are kept as written",
          ev["data"] == {"StartAddress": "0x00007FFB6C2E0000"} and rs["data"] == {"Address": "0x00000000000003e7"}, (ev["data"], rs["data"]))
    check("windows: python-evtx's one Data of <string> items becomes one Data each", W._split_strings({"Data0": "<string>sa</string>\n<string> Reason: x</string>\n", "Binary": "00"})
          == {"Data0": "sa", "Data1": " Reason: x", "Binary": "00"})
    # a padded shortcut (LnkParse3's sample): an overstated count, UTF-16 short names, no LinkInfo
    link = shell_link(["Windows", "System32", "cmd.exe"], "C:\\Windows\\System32" + " " * 241, '/c "echo hidden"', stated_count=1693)
    k = W.lnk(link)
    check("windows: the padded shortcut reads as the shell reads it", k["target_path"] == "C:\\Windows\\System32\\cmd.exe" and k["arguments"] == '/c "echo hidden"'
          and k["working_dir"].rstrip() == "C:\\Windows\\System32", {x: str(k[x])[:40] for x in ("target_path", "arguments", "working_dir")})

    # ---- maldoc
    k = M.lnk(link)
    check("maldoc: the same shortcut, the padding noted", k["target"] == "C:\\Windows\\System32\\cmd.exe" and k["arguments"] == '/c "echo hidden"' and k.get("padded") is True
          and k["working_dir"] == "C:\\Windows\\System32", {x: str(k.get(x))[:40] for x in ("target", "arguments", "working_dir")})
    check("maldoc: DDE formulas of a CSV cell and of a 2003 XML attribute, as msodde prints them",
          M.dde_formulas("a,b\n=cmd|'/k calc.exe'!A0,c\n") == ["cmd '/k calc.exe'"] and M.dde_formulas("=cmd|'/c calc.exe'!A1") == ["cmd '/c calc.exe'"]
          and M.dde_formulas("total,=A1+B2\nname|other,x!y\n") == [])
    slk = b"ID;PWXL;N;E\nNN;NAuto_Open;ER1C1\nC;Y1;X1;K0;EEXEC(\"calc.exe\")\nC;Y2;K0;EHALT()\nE\n"
    d = M.parse(slk, "sheet.slk")
    check("maldoc: a SYLK file with an Auto_Open name is an Excel 4 macro", d["kind"] == "slk" and d["fields"].get("has_macros") is True and d["fields"].get("autoexec") == ["Auto_Open"], d["fields"])
    check("maldoc: kinds by the bytes for the text carriers", M.kind_of(b"=cmd|'/c calc'!A0\n", "a.csv") == "csv_dde" and M.kind_of(b"name,total\nx,=A1+2\n", "a.csv") == ""
          and M.kind_of(b'<?xml version="1.0"?>\n<?mso-application progid="Excel.Sheet"?>\n<Workbook/>', "a.xml") == "xml2003")
    inner = M.OLE_MAGIC + bytes(600)
    body = struct.pack("<I", len(inner)) + zlib.compress(inner)
    stream = bytes(40) + struct.pack("<HHI", 0x0010, 0x1011, len(body)) + body + bytes(16)
    check("maldoc: a compressed OLE storage inside a PowerPoint Document stream is found and inflated", M.ppt_storages(stream) == [inner], len(M.ppt_storages(stream)))
    check("maldoc: a name this file gave a payload is not an embedded file's name", M._OWN_NAME.fullmatch("ExternalOleObjectStg1") and M._OWN_NAME.fullmatch("decrypted_package")
          and not M._OWN_NAME.fullmatch("calc.lnk"))

    # ---- email
    ad = E._addrs
    check("email: an address as display name, a comma in an encoded name, a wholly encoded address, a group of two",
          ad(["alice@a.example <bob@b.example>"]) == [("alice@a.example", "bob@b.example")]
          and ad(["=?iso-8859-1?Q?Last=DFName=2C_First?= <c@d.example>"]) == [("Last\u00dfName, First", "c@d.example")]
          and ad(["=?UTF-8?B?bm90aWNlQGJhbmsuZXhhbXBsZQ==?="]) == [("", "notice@bank.example")]
          and ad(['"Brown, Charlie" <c@e.example>, dave@e.example']) == [("Brown, Charlie", "c@e.example"), ("", "dave@e.example")],
          (ad(["alice@a.example <bob@b.example>"]), ad(["=?UTF-8?B?bm90aWNlQGJhbmsuZXhhbXBsZQ==?="])))
    check("email: one non-ASCII letter inside an address is decoded where it stands", ad(["Sec <s@micr=?utf-8?b?0L4=?=soft.example>"]) == [("Sec", "s@micr\u043esoft.example")])
    raw = ("From: Pay <pay@evergatetitle.example>\r\nTo: dangl\u00fce@bank.example\r\nSubject: x\r\nMIME-Version: 1.0\r\n"
           'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<a href="https://evergatetltle.example/pay">Pay here</a>\r\n'
           '--b\r\nContent-Type: application/zip; name="\u0424\u041d\u0421.zip"\r\nContent-Disposition: attachment; filename="\u0424\u041d\u0421.zip"\r\n'
           "Content-Transfer-Encoding: base64\r\n\r\nUEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==\r\n--b--\r\n").encode("utf-8")
    m = E.load(raw, "m.eml")[0]
    check("email: raw UTF-8 in a header and in a file name is read", [a for _, a in E.addresses(m)["to"]] == ["dangl\u00fce@bank.example"]
          and [x["filename"] for x in m.attachments] == ["\u0424\u041d\u0421.zip"], (E.addresses(m)["to"], [x["filename"] for x in m.attachments]))
    la = E.lookalikes(m)
    check("email: a link host one edit from the sender's domain is listed as its look-alike", len(la) == 1 and la[0]["domain"] == "evergatetltle.example"
          and la[0]["resembles"] == "evergatetitle.example" and la[0]["ordered"], la)
    got = E.solve_set([q("a", "What is the lookalike domain used in the email?", artifact="m.eml"), q("b", 'Which URL does the "Pay here" link point to?', artifact="m.eml")], {"m.eml": raw}, {})
    check("email: the look-alike and the target of a link named by its text are offered unsure", values(got["a"])[:1] == ["evergatetltle.example"]
          and values(got["b"])[:1] == ["https://evergatetltle.example/pay"], got)

    # ---- memory
    t0 = 0x01C5796000000000
    img = bytearray(0x20000)
    procs = [(4, 0, "System", 0), (448, 4, "smss.exe", t0), (504, 448, "csrss.exe", t0 + 10_000_000), (592, 504, "lsass.exe", t0 + 20_000_000)]
    for i, (pid, ppid, name, created) in enumerate(procs):
        img[0x1000 + i * 0x400:0x1000 + i * 0x400 + 0x300] = eprocess(pid, ppid, name, created)
    img[0x8000:0x8300] = eprocess(1234, 4, "decoy.exe", t0, tag=False, header=False)        # a name with a PID before it and nothing else
    c = MEM.carve_windows_processes(bytes(img))
    got = sorted((r["pid"], r["ppid"], r["name"]) for r in c["procs"])
    check("memory: a place with a name and a PID but no object header and no pool tag is not a process (a real image had 2,300 of them)",
          got == [(p, pp, nm) for p, pp, nm, _ in procs] and c["head_delta"] == 0x174 and c["pool_tag"], (got, {k: v for k, v in c.items() if k != "procs"}))
    check("memory: the create time beside the PID is found though System has none", c["create_delta"] == -0x14 and [r["create"] is not None for r in sorted(c["procs"], key=lambda r: r["pid"])]
          == [False, True, True, True], c["create_delta"])
    core = MEM.elf_core(elf32_core(11038, 10442, "coredump", "./coredump foo bar 42"))
    check("memory: a 32-bit core's process record is read", (core.get("pid"), core.get("ppid"), core.get("name"), core.get("args"), core.get("bits")) == (11038, 10442, "coredump", "./coredump foo bar 42", 32), core)
    model = MEM.Model()
    model.add_proc(4, "table", name="System", args="Required memory at 0x10 is not valid (process exited?)")
    model.add_proc(8, "table", name="a.exe", args="a.exe -x")
    check("memory: Volatility's remark for an unreadable cell is not a command line", model.procs[4].get("args") is None and model.procs[8].get("args") == "a.exe -x", model.procs)
    import uuid
    g = uuid.UUID("32962337-f0f6-4638-8b39-535cd8dd70e8")
    check("memory: the kernel's debug reference is read from the bytes", MEM.kernel_pdb(bytes(64) + b"RSDS" + g.bytes_le + struct.pack("<I", 2) + b"ntoskrnl.pdb\x00" + bytes(64))
          == [("ntoskrnl.pdb", "32962337F0F646388B39535CD8DD70E8", 2)])
    return finish("test_fixes_a")


if __name__ == "__main__":
    sys.exit(main())
