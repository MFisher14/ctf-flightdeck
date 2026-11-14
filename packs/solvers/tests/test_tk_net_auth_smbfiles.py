#!/usr/bin/env python3
"""Offline tests of the SMB file-transfer reassembly in solvers/toolkits/net_auth.py (wave122): a file
written (SMB2 WRITE) or read (SMB2 READ, or simple SMB1 READ_ANDX) over a share, reassembled from a pcap
by (file-id, offset) and exposed as its bytes / sha256 / size / name.

  .venv/bin/python tests/test_tk_net_auth_smbfiles.py

No network, no token. Every packet is built here from invented hosts (RFC 5737 addresses); nothing is
real traffic. It proves:
  1. A WRITE upload and a READ download are reassembled byte-exact, with the right sha256/size/name.
  2. Never-wrong: a transfer is `complete` ONLY when proven whole (contiguous 0..EndOfFile, sound TCP
     streams, size anchored); a missing chunk, a gap, an overlap, a missing anchor, an ambiguous match
     or an unsound stream all yield None -- and every answer reaches network.decide as an UNSURE pick,
     never a plain value, so it can never sink a batch.
  3. The simple SMB1 READ_ANDX download path (unicode and latin-1 names).
  4. No regression: the SMB2 metadata path (dialect/share/opened-file) is unchanged, and the reader only
     ADDS answers for ids network.py left None.
Prints one line per check and `ok` at the end; exits 1 on the first failure.
"""
import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = str(Path(tempfile.mkdtemp(prefix="test_smbfiles_")) / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import network as nw     # noqa: E402
import net_auth as na    # noqa: E402

FAILED = []


def check(name, cond, extra=""):
    print(("ok  " if cond else "FAIL") + f" {name}" + (f"  {extra}" if extra else ""))
    if not cond:
        FAILED.append(name)


# ---- packet construction (RFC 5737 / RFC 3849-style invented hosts) --------------------------------------

def _ip4(src, dst, payload, proto):
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b) + payload


def _tcp(sport, dport, seq, ack, flags, data=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data


def _eth(payload):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + payload


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + i, 1000 * i, len(f), len(f)) + f
    return out


def netbios(msg):
    return bytes([0x00]) + len(msg).to_bytes(3, "big") + msg


# ---- SMB2 message builders (offsets are from the SMB2 header start) --------------------------------------

def smb2_hdr(cmd, flags, mid):
    h = bytearray(64)
    h[0:4] = b"\xfeSMB"
    struct.pack_into("<H", h, 4, 64)
    struct.pack_into("<H", h, 12, cmd)
    struct.pack_into("<I", h, 16, flags)       # flags bit0 = SERVER_TO_REDIR (response)
    struct.pack_into("<Q", h, 24, mid)
    return bytes(h)


def create_req(name, mid):
    nm = name.encode("utf-16-le")
    body = bytearray(56)
    struct.pack_into("<H", body, 0, 57)
    struct.pack_into("<H", body, 44, 120)
    struct.pack_into("<H", body, 46, len(nm))
    return netbios(smb2_hdr(0x0005, 0x0000, mid) + bytes(body) + nm)


def create_resp(fid, eof, mid):
    body = bytearray(90)
    struct.pack_into("<H", body, 0, 89)
    struct.pack_into("<Q", body, 48, eof)
    body[64:80] = fid
    return netbios(smb2_hdr(0x0005, 0x0001, mid) + bytes(body))


def write_req(fid, off, data, mid):
    body = bytearray(48)
    struct.pack_into("<H", body, 0, 49)
    struct.pack_into("<H", body, 2, 112)       # DataOffset from SMB header
    struct.pack_into("<I", body, 4, len(data))
    struct.pack_into("<Q", body, 8, off)
    body[16:32] = fid
    return netbios(smb2_hdr(0x0009, 0x0000, mid) + bytes(body) + data)


def read_req(fid, off, length, mid):
    body = bytearray(49)
    struct.pack_into("<H", body, 0, 49)
    struct.pack_into("<I", body, 4, length)
    struct.pack_into("<Q", body, 8, off)
    body[16:32] = fid
    return netbios(smb2_hdr(0x0008, 0x0000, mid) + bytes(body))


def read_resp(data, mid):
    body = bytearray(16)
    struct.pack_into("<H", body, 0, 17)
    body[2] = 80                               # DataOffset from SMB header
    struct.pack_into("<I", body, 4, len(data))
    return netbios(smb2_hdr(0x0008, 0x0001, mid) + bytes(body) + data)


def close_req(fid, mid):
    body = bytearray(24)
    struct.pack_into("<H", body, 0, 24)
    body[8:24] = fid
    return netbios(smb2_hdr(0x0006, 0x0000, mid) + bytes(body))


def close_resp(eof, mid, postquery=True):
    body = bytearray(60)
    struct.pack_into("<H", body, 0, 60)
    struct.pack_into("<H", body, 2, 0x0001 if postquery else 0)
    struct.pack_into("<Q", body, 48, eof)
    return netbios(smb2_hdr(0x0006, 0x0001, mid) + bytes(body))


# ---- SMB1 message builders -------------------------------------------------------------------------------

def smb1_hdr(cmd, is_resp, tid, mid, unicode=True):
    h = bytearray(32)
    h[0:4] = b"\xffSMB"
    h[4] = cmd
    h[9] = 0x80 if is_resp else 0x00           # Flags: SMB_FLAGS_REPLY
    struct.pack_into("<H", h, 10, 0x8000 if unicode else 0)
    struct.pack_into("<H", h, 24, tid)
    struct.pack_into("<H", h, 30, mid)
    return bytes(h)


def s1_create_req(name, tid, mid, unicode=True):
    params = bytearray(48)
    params[0] = 0xFF                           # AndXCommand = none
    if unicode:
        nm = name.encode("utf-16-le")
        struct.pack_into("<H", params, 5, len(nm) + 2)
        body = bytes([0x00]) + nm + b"\x00\x00"
    else:
        nm = name.encode("latin-1")
        struct.pack_into("<H", params, 5, len(nm) + 1)
        body = nm + b"\x00"
    msg = smb1_hdr(0xA2, False, tid, mid, unicode) + bytes([24]) + bytes(params) + struct.pack("<H", len(body)) + body
    return netbios(msg)


def s1_create_resp(fid, eof, tid, mid):
    params = bytearray(68)
    params[0] = 0xFF
    struct.pack_into("<H", params, 5, fid)
    struct.pack_into("<Q", params, 55, eof)
    return netbios(smb1_hdr(0xA2, True, tid, mid) + bytes([34]) + bytes(params) + struct.pack("<H", 0))


def s1_read_req(fid, off, length, tid, mid):
    params = bytearray(20)
    params[0] = 0xFF
    struct.pack_into("<H", params, 4, fid)
    struct.pack_into("<I", params, 6, off)
    return netbios(smb1_hdr(0x2E, False, tid, mid) + bytes([10]) + bytes(params) + struct.pack("<H", 0))


def s1_read_resp(data, tid, mid):
    params = bytearray(24)
    params[0] = 0xFF
    struct.pack_into("<H", params, 10, len(data) & 0xFFFF)
    struct.pack_into("<H", params, 12, 59)     # DataOffset from SMB header (hdr32 + wc1 + params24 + bc2)
    struct.pack_into("<H", params, 14, len(data) >> 16)
    return netbios(smb1_hdr(0x2E, True, tid, mid) + bytes([12]) + bytes(params) + struct.pack("<H", len(data)) + data)


# ---- helpers ---------------------------------------------------------------------------------------------

def q(qid, text, kind="exact_text", syntax="exact value only"):
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": "capture.pcap",
            "answer_format": {"kind": kind, "syntax": syntax}}


def unsure_value(ans):
    if not isinstance(ans, str) or not ans.startswith("??"):
        return None
    import json
    return [v for _, v in json.loads(ans[2:])["o"]]


def one_conn(cli, srv, cport, cdata, sdata, frames, server_segments=None):
    frames.append(_eth(_ip4(cli, srv, _tcp(cport, 445, 1000, 0, 0x02), 6)))
    frames.append(_eth(_ip4(srv, cli, _tcp(445, cport, 5000, 1001, 0x12), 6)))
    if server_segments is None:
        frames.append(_eth(_ip4(srv, cli, _tcp(445, cport, 5001, 1001, 0x18, sdata), 6)))
    else:
        for seq, seg in server_segments:
            frames.append(_eth(_ip4(srv, cli, _tcp(445, cport, seq, 1001, 0x18, seg), 6)))
    frames.append(_eth(_ip4(cli, srv, _tcp(cport, 445, 1001, 9000, 0x18, cdata), 6)))


def xfers(frames):
    data = _pcap(frames)
    files = {"capture.pcap": data}
    caps = nw.find_captures(files)
    cap = nw._cap_of(caps[0][0], caps[0][1])
    return na.smb_transfers(cap), files, caps


CLI, SRV = "192.0.2.10", "192.0.2.200"


def main():
    # ===== SMB2 WRITE upload + READ download in one capture ===============================
    WFID, RFID = bytes(range(16)), bytes(range(16, 32))
    upload = b"flag{smb_write_demo}\n"
    u0, u1 = upload[:10], upload[10:]
    download = bytes((i * 7 + 3) % 256 for i in range(300))
    d0, d1 = download[:128], download[128:]

    frames = []
    cA = create_req("reports\\payroll.csv", 1) + write_req(WFID, 0, u0, 2) + write_req(WFID, len(u0), u1, 3) + close_req(WFID, 4)
    sA = create_resp(WFID, 0, 1) + close_resp(len(upload), 4, True)
    one_conn(CLI, SRV, 40001, cA, sA, frames)
    cB = create_req("loot\\secret.bin", 1) + read_req(RFID, 0, 128, 2) + read_req(RFID, 128, len(d1), 3) + close_req(RFID, 4)
    sB = create_resp(RFID, len(download), 1) + read_resp(d0, 2) + read_resp(d1, 3)
    one_conn(CLI, SRV, 40002, cB, sB, frames)
    xf, files, caps = xfers(frames)

    w = [t for t in xf if t["direction"] == "write"]
    r = [t for t in xf if t["direction"] == "read"]
    check("smb2 write reassembled complete", len(w) == 1 and w[0]["complete"])
    check("smb2 write sha256 byte-exact", w and w[0]["sha256"] == hashlib.sha256(upload).hexdigest())
    check("smb2 write size", w and w[0]["size"] == len(upload) and w[0]["data"] == upload)
    check("smb2 write name basename", w and w[0]["name"] == "payroll.csv" and w[0]["path"] == "reports\\payroll.csv")
    check("smb2 read reassembled complete", len(r) == 1 and r[0]["complete"])
    check("smb2 read sha256 byte-exact", r and r[0]["sha256"] == hashlib.sha256(download).hexdigest())
    check("smb2 read size+data", r and r[0]["size"] == len(download) and r[0]["data"] == download)

    # through network.decide: every fact is an UNSURE pick (never plain)
    probes = [
        (q("h", "What is the SHA-256 of the file uploaded over SMB?"), hashlib.sha256(upload).hexdigest()),
        (q("hu", "What is the SHA-256 of the file uploaded over SMB?"), hashlib.sha256(upload).hexdigest().upper()),
        (q("s", "How many bytes is the file downloaded over SMB2?", kind="integer", syntax="integer"), str(len(download))),
        (q("nw", "What file was written to the SMB share?"), "payroll.csv"),
        (q("nr", "Which file was downloaded over SMB2?"), "secret.bin"),
        (q("md", "What is the MD5 of the file read over SMB?"), hashlib.md5(download).hexdigest()),
        (q("c", "What is the content of the file uploaded over SMB?"), upload.strip().decode()),
    ]
    for qq, want in probes:
        ans = nw.decide(qq, files, {}, caps)[0]
        vals = unsure_value(ans)
        plain = isinstance(ans, str) and not ans.startswith("??")
        check(f"decide {qq['id']} unsure+has value", vals is not None and want in vals and not plain, extra=f"{ans!r}"[:90])

    # ===== never-wrong guards (all -> None) ==============================================
    FID = bytes(range(16))
    body = b"flag{guarded}\n"
    b0, b1 = body[:6], body[6:]

    def hashnone(frames, text="sha-256 of the file uploaded over smb?"):
        _, files, caps = xfers(frames)
        return nw.decide(q("g", text), files, {}, caps)[0]

    fr = []
    one_conn(CLI, SRV, 40010, create_req("a\\f.txt", 1) + write_req(FID, 0, b0, 2) + close_req(FID, 4),
             create_resp(FID, 0, 1) + close_resp(len(body), 4, True), fr)
    check("guard: missing chunk -> hash None", hashnone(fr) is None)

    fr = []
    one_conn(CLI, SRV, 40011, create_req("a\\f.txt", 1) + write_req(FID, 0, b0, 2) + write_req(FID, len(b0), b1, 3) + close_req(FID, 4),
             create_resp(FID, 0, 1) + close_resp(len(body), 4, False), fr)        # no POSTQUERY -> no size anchor
    check("guard: no size anchor -> hash None", hashnone(fr) is None)

    fr = []
    one_conn(CLI, SRV, 40012, create_req("a\\f.txt", 1) + write_req(FID, 0, b0, 2) + write_req(FID, len(b0) + 1, b1, 3) + close_req(FID, 4),
             create_resp(FID, 0, 1) + close_resp(len(body), 4, True), fr)         # a 1-byte gap
    check("guard: offset gap -> hash None", hashnone(fr) is None)

    fr = []
    one_conn(CLI, SRV, 40013, create_req("a\\f.txt", 1) + write_req(FID, 0, b0, 2) + write_req(FID, 0, b0, 3) + close_req(FID, 4),
             create_resp(FID, 0, 1) + close_resp(len(body), 4, True), fr)         # the same offset twice
    check("guard: overlap -> hash None", hashnone(fr) is None)

    # two complete uploads: ambiguous without a name, resolved with one
    FID2 = bytes(range(16, 32))
    up2 = b"second-upload-bytes!!"
    fr = []
    one_conn(CLI, SRV, 40014, create_req("a\\one.txt", 1) + write_req(FID, 0, body, 2) + close_req(FID, 4),
             create_resp(FID, 0, 1) + close_resp(len(body), 4, True), fr)
    one_conn(CLI, SRV, 40015, create_req("b\\two.txt", 1) + write_req(FID2, 0, up2, 2) + close_req(FID2, 4),
             create_resp(FID2, 0, 1) + close_resp(len(up2), 4, True), fr)
    _, files, caps = xfers(fr)
    check("guard: two uploads, no name -> None",
          nw.decide(q("g", "what is the sha256 of the file uploaded over smb?"), files, {}, caps)[0] is None)
    a = nw.decide(q("g2", "what is the sha256 of one.txt uploaded over smb?"), files, {}, caps)[0]
    check("guard: named upload resolves", isinstance(a, str) and a.startswith("??") and hashlib.sha256(body).hexdigest() in a)

    # an unsound server stream (a hole in the TCP data) -> read incomplete
    rc = bytes(range(40)) * 4
    sd = create_resp(FID, len(rc), 1) + read_resp(rc, 2)
    half = len(sd) // 2
    fr = []
    one_conn(CLI, SRV, 40016, create_req("a\\r.bin", 1) + read_req(FID, 0, len(rc), 2) + close_req(FID, 4), sd, fr,
             server_segments=[(5001, sd[:half]), (5001 + half + 50, sd[half:])])    # 50-byte sequence hole
    xf2, files, caps = xfers(fr)
    rr = [t for t in (xf2 or []) if t["direction"] == "read"]
    check("guard: unsound stream -> read not complete", (not rr) or (not rr[0]["complete"]))
    check("guard: unsound stream -> hash None",
          nw.decide(q("g", "sha-256 of the file downloaded over smb?"), files, {}, caps)[0] is None)

    # ===== SMB1 READ_ANDX download ========================================================
    TID = 2049
    s1content = bytes((i * 13 + 5) % 256 for i in range(200))
    s0, s1 = s1content[:120], s1content[120:]
    fr = []
    one_conn(CLI, SRV, 40020,
             s1_create_req("docs\\stolen.docx", TID, 1) + s1_read_req(0x4001, 0, 120, TID, 2) + s1_read_req(0x4001, 120, len(s1), TID, 3),
             s1_create_resp(0x4001, len(s1content), TID, 1) + s1_read_resp(s0, TID, 2) + s1_read_resp(s1, TID, 3), fr)
    xf3, files, caps = xfers(fr)
    rr = [t for t in (xf3 or []) if t["direction"] == "read"]
    check("smb1 read complete + proto", rr and rr[0]["complete"] and rr[0]["proto"] == "smb1")
    check("smb1 read sha256 byte-exact", rr and rr[0]["sha256"] == hashlib.sha256(s1content).hexdigest())
    check("smb1 read name (unicode)", rr and rr[0]["name"] == "stolen.docx")
    a = nw.decide(q("h", "What is the SHA-256 of the file downloaded over SMB?"), files, {}, caps)[0]
    check("smb1 decide hash unsure", isinstance(a, str) and a.startswith("??") and hashlib.sha256(s1content).hexdigest() in a)

    fr = []
    one_conn(CLI, SRV, 40021,
             s1_create_req("ascii.txt", TID, 1, unicode=False) + s1_read_req(0x4002, 0, len(s0), TID, 2),
             s1_create_resp(0x4002, len(s0), TID, 1) + s1_read_resp(s0, TID, 2), fr)
    xf4, _, _ = xfers(fr)
    rr = [t for t in (xf4 or []) if t["direction"] == "read"]
    check("smb1 read name (latin-1)", rr and rr[0]["complete"] and rr[0]["name"] == "ascii.txt")

    # ===== no regression: the SMB2 metadata path is unchanged ============================
    # the WRITE/READ capture above also carries CREATE/tree names; the opened-file question still
    # answers a create name (not a transfer), and no SMB traffic -> smb_transfers is None.
    frames = []
    cA = create_req("reports\\payroll.csv", 1) + write_req(WFID, 0, upload, 2) + close_req(WFID, 4)
    sA = create_resp(WFID, 0, 1) + close_resp(len(upload), 4, True)
    one_conn(CLI, SRV, 40030, cA, sA, frames)
    _, files, caps = xfers(frames)
    opened = nw.decide(q("o", "What file was opened over SMB2?"), files, {}, caps)[0]
    ovals = unsure_value(opened)                 # parse the pick: the value's backslash is JSON-escaped in the raw string
    check("metadata: opened-file still answered (unsure)",
          isinstance(opened, str) and opened.startswith("??") and ovals is not None and "reports\\payroll.csv" in ovals)

    # a capture with no SMB traffic at all -> smb_transfers None, and the reader claims nothing
    nosmb = _pcap([_eth(_ip4(CLI, "192.0.2.53", struct.pack(">HHHH", 50000, 53, 8 + 12, 0) + b"\x00" * 12, 17))])
    f2 = {"capture.pcap": nosmb}
    caps2 = nw.find_captures(f2)
    cap2 = nw._cap_of(caps2[0][0], caps2[0][1])
    check("no-smb: smb_transfers None", na.smb_transfers(cap2) is None)
    check("no-smb: smb hash question -> None",
          nw.decide(q("g", "What is the SHA-256 of the file transferred over SMB?"), f2, {}, caps2)[0] is None)

    # the reader never answers a non-SMB question (strict dispatch)
    nf = na.field(nw._Q(q("x", "What is the HTTP user agent?"), files), nw._cap_of(caps[0][0], caps[0][1]), nw.Found, nw._choose)
    check("strict dispatch: non-SMB question -> None", nf is None)

    print("ok" if not FAILED else f"FAILED: {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
