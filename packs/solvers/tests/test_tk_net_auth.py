#!/usr/bin/env python3
"""Offline tests of the never-wrong auth/directory protocol readers (solvers/toolkits/net_auth.py)
that network.py loads by name: SMB2, Kerberos, SNMP and IRC (buildlist rows 12, 14, 10, 11).

  .venv/bin/python tests/test_tk_net_auth.py

No network, no token. Every packet is built here from invented hosts (RFC 5737 addresses,
`.example` names); nothing is real traffic. Two things are proved:
  1. The new readers parse each protocol and offer the fact as an UNSURE pick (never plain).
  2. The fail-safe wiring in network.py: with net_auth absent/raising, solve_set is BYTE-IDENTICAL
     to the pre-hook behaviour (protocol questions answer None, every other answer unchanged); and
     the hook only ever ADDS answers for ids _field left None, so no existing answer can change.
Prints one line per check and `ok` at the end; exits 1 on the first failure.
"""
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = str(Path(tempfile.mkdtemp(prefix="test_net_auth_")) / "challenges")
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


# ---- packet construction (RFC 5737 hosts) ----------------------------------------------------------------

def _ip4(src, dst, payload, proto):
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b)
    return head + payload


def _udp(sport, dport, data):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def _tcp(sport, dport, seq, ack, flags, data=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + data


def _eth(payload):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + payload


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + i, 1000 * i, len(f), len(f)) + f
    return out


# ---- minimal DER / BER encoders (for the Kerberos and SNMP payloads) -------------------------------------

def der(tag, content):
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    lb = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + content


def integer(n):
    return der(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


def seq(b):
    return der(0x30, b)


def ctx(num, content):
    return der(0xA0 | num, content)


def gstr(s):
    return der(0x1B, s.encode())


def principal(names, ntype=1):
    return seq(ctx(0, integer(ntype)) + ctx(1, seq(b"".join(gstr(n) for n in names))))


def enc_oid(s):
    nums = [int(x) for x in s.split(".")]
    out = [nums[0] * 40 + nums[1]]
    for n in nums[2:]:
        if n < 128:
            out.append(n)
        else:
            stack = []
            while n:
                stack.append(n & 0x7F)
                n >>= 7
            stack = stack[::-1]
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            out += stack
    return bytes(out)


# ---- SMB2 message builders -------------------------------------------------------------------------------

def smb2_hdr(cmd, flags, nxt=0):
    h = bytearray(64)
    h[0:4] = b"\xfeSMB"
    struct.pack_into("<H", h, 4, 64)
    struct.pack_into("<H", h, 12, cmd)
    struct.pack_into("<I", h, 16, flags)
    struct.pack_into("<I", h, 20, nxt)
    return bytes(h)


def netbios(msg):
    return bytes([0x00]) + len(msg).to_bytes(3, "big") + msg


def smb2_negotiate_resp(rev):
    body = struct.pack("<HHH", 65, 1, rev) + b"\x00" * 32
    return netbios(smb2_hdr(0x0000, 0x0001) + body)


def smb2_tree_connect(path):
    p = path.encode("utf-16-le")
    body = struct.pack("<HHHH", 9, 0, 72, len(p)) + p
    return netbios(smb2_hdr(0x0003, 0x0000) + body)


def smb2_create(name):
    nm = name.encode("utf-16-le")
    body = bytearray(56)
    struct.pack_into("<H", body, 0, 57)
    struct.pack_into("<H", body, 44, 120)
    struct.pack_into("<H", body, 46, len(nm))
    return netbios(smb2_hdr(0x0005, 0x0000) + bytes(body) + nm)


# ---- a capture carrying all four protocols ---------------------------------------------------------------

def build_pcap():
    f = []
    CLI, SRV = "192.0.2.10", "192.0.2.200"

    # SNMP: v2c GetRequest, community "s3cr3t-community", one sysDescr OID (UDP 161)
    oid = "1.3.6.1.2.1.1.1.0"
    varbind = seq(der(0x06, enc_oid(oid)) + der(0x05, b""))
    pdu = der(0xA0, integer(1) + integer(0) + integer(0) + seq(varbind))
    snmp = seq(integer(1) + der(0x04, b"s3cr3t-community") + pdu)
    f.append(_eth(_ip4(CLI, SRV, _udp(50000, 161, snmp), 17)))

    # Kerberos: AS-REQ (realm EXAMPLE.COM, cname alice, sname krbtgt/EXAMPLE.COM) and AS-REP (etype 23)
    reqbody = ctx(4, seq(ctx(1, principal(["alice"])) + ctx(2, gstr("EXAMPLE.COM"))
                         + ctx(3, principal(["krbtgt", "EXAMPLE.COM"]))))
    as_req = der(0x6A, seq(reqbody))
    as_rep = der(0x6B, seq(ctx(3, gstr("EXAMPLE.COM")) + ctx(4, principal(["alice"]))
                           + ctx(6, seq(ctx(0, integer(23))))))
    f.append(_eth(_ip4(CLI, SRV, _udp(51000, 88, as_req), 17)))
    f.append(_eth(_ip4(SRV, CLI, _udp(88, 51000, as_rep), 17)))

    # IRC: a TCP connection on 6667 with a handshake, NICK/JOIN/PRIVMSG and a server reply
    c_lines = ("NICK wopr\r\nUSER wopr 0 * :War Operation\r\nJOIN #secret-ops\r\n"
               "PRIVMSG #secret-ops :exfil started\r\n").encode()
    s_lines = (":irc.example 001 wopr :Welcome\r\n:irc.example 353 wopr = #secret-ops :wopr\r\n").encode()
    f.append(_eth(_ip4(CLI, SRV, _tcp(40000, 6667, 1000, 0, 0x02), 6)))               # SYN
    f.append(_eth(_ip4(SRV, CLI, _tcp(6667, 40000, 2000, 1001, 0x12), 6)))            # SYN-ACK
    f.append(_eth(_ip4(CLI, SRV, _tcp(40000, 6667, 1001, 2001, 0x18, c_lines), 6)))
    f.append(_eth(_ip4(SRV, CLI, _tcp(6667, 40000, 2001, 1001 + len(c_lines), 0x18, s_lines), 6)))

    # SMB2: a TCP connection on 445; server negotiates 3.1.1, client connects a tree and opens a file
    c_smb = smb2_tree_connect(r"\\fileserver\PAYROLL$") + smb2_create("secret\\accounts.xlsx")
    s_smb = smb2_negotiate_resp(0x0311)
    f.append(_eth(_ip4(CLI, SRV, _tcp(40001, 445, 5000, 0, 0x02), 6)))                # SYN
    f.append(_eth(_ip4(SRV, CLI, _tcp(445, 40001, 6000, 5001, 0x12), 6)))             # SYN-ACK
    f.append(_eth(_ip4(SRV, CLI, _tcp(445, 40001, 6001, 5001, 0x18, s_smb), 6)))
    f.append(_eth(_ip4(CLI, SRV, _tcp(40001, 445, 5001, 6001 + len(s_smb), 0x18, c_smb), 6)))

    # a plain DNS query too, so the existing network.py path is exercised in the same capture
    name = b"\x03cdn\x07example\x03com\x00"
    dq = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
    f.append(_eth(_ip4(CLI, "192.0.2.53", _udp(53002, 53, dq), 17)))
    return _pcap(f)


def q(qid, text, kind="exact_text", syntax="exact value only"):
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": "capture.pcap",
            "answer_format": {"kind": kind, "syntax": syntax}}


def unsure_value(ans):
    """The decoded option list of a `??` pick, or None when the answer is None/plain."""
    if not isinstance(ans, str) or not ans.startswith("??"):
        return None
    import json
    return [v for _, v in json.loads(ans[2:])["o"]]


def main():
    data = build_pcap()
    files = {"capture.pcap": data}
    caps = nw.find_captures(files)
    check("capture reads", bool(caps), extra=f"{len(caps)} capture(s)")
    cap = nw._cap_of(caps[0][0], caps[0][1])

    # --- the library parsers ------------------------------------------------------------------
    smb = na.smb2_facts(cap)
    check("smb2 dialect 3.1.1", smb and smb["dialect"] == "3.1.1", extra=str(smb and smb["dialect"]))
    check("smb2 hex 0x0311", smb and smb["dialect_hex"] == "0x0311")
    check("smb2 share parsed", smb and r"\\fileserver\PAYROLL$" in smb["shares"], extra=str(smb and smb["shares"]))
    check("smb2 file parsed", smb and "secret\\accounts.xlsx" in smb["files"], extra=str(smb and smb["files"]))

    kr = na.kerberos_messages(cap)
    types = {r["msg_type"] for r in kr}
    check("kerberos as_req+as_rep", {"as_req", "as_rep"} <= types, extra=str(types))
    check("kerberos realm", any(r["realm"] == "EXAMPLE.COM" for r in kr))
    check("kerberos cname alice", any(r["cname"] == "alice" for r in kr))
    check("kerberos sname krbtgt", any(r["sname"] == "krbtgt/EXAMPLE.COM" for r in kr),
          extra=str([r["sname"] for r in kr]))
    check("kerberos etype rc4", any(r["etype"] == 23 for r in kr))

    sn = na.snmp_messages(cap)
    check("snmp community", any(r["community"] == "s3cr3t-community" for r in sn))
    check("snmp version v2c", any(r["version"] == "v2c" for r in sn))
    check("snmp oid", any("1.3.6.1.2.1.1.1.0" in r["oids"] for r in sn))

    irc = na.irc_sessions(cap)
    check("irc nick", any("wopr" in s["nicks"] for s in irc))
    check("irc channel", any("#secret-ops" in s["channels"] for s in irc))
    check("irc message", any("exfil started" in body for s in irc for _, body in s["messages"]))

    # --- through network.decide: every new fact is an UNSURE pick, never plain ----------------
    probes = [
        (q("smb-dialect", "What SMB2 dialect was negotiated?"), "3.1.1"),
        (q("smb-share", "What SMB2 share (tree) did the client connect to?"), r"\\fileserver\PAYROLL$"),
        (q("smb-file", "What file was opened over SMB2?"), "secret\\accounts.xlsx"),
        (q("krb-realm", "What Kerberos realm is in the AS-REQ?"), "EXAMPLE.COM"),
        (q("krb-user", "Which user (principal) requested the Kerberos ticket?"), "alice"),
        (q("krb-service", "What service principal name is requested in the Kerberos AS-REQ?"), "krbtgt/EXAMPLE.COM"),
        (q("krb-etype", "What Kerberos encryption type is used in the AS-REP?"), "rc4_hmac"),
        (q("snmp-comm", "What is the SNMP community string?"), "s3cr3t-community"),
        (q("snmp-ver", "What SNMP version is used?"), "v2c"),
        (q("irc-chan", "What IRC channel did the bot join?"), "#secret-ops"),
        (q("irc-nick", "What IRC nickname did the client use?"), "wopr"),
        (q("irc-msg", "What message was sent over IRC to the channel?"), "exfil started"),
    ]
    for qq, want in probes:
        ans = nw.decide(qq, files, {}, caps)[0]
        vals = unsure_value(ans)
        plain = isinstance(ans, str) and not ans.startswith("??")
        check(f"decide {qq['id']} unsure+has value", vals is not None and want in vals and not plain,
              extra=f"{ans!r}")

    # --- FAIL-SAFE: with net_auth absent/raising, the protocol answers are None and NOTHING else
    #     changes (byte-identical to the pre-hook behaviour) -------------------------------------
    dns_q = q("dns-name", "List all the DNS names queried.", kind="ordered_tokens", syntax="comma separated")
    all_qs = [qq for qq, _ in probes] + [dns_q]
    with_hook = {qq["id"]: nw.decide(qq, files, {}, caps)[0] for qq in all_qs}

    # simulate the module being absent / broken at the loader, so the REAL _netauth_field guard
    # (its try/except) is what has to turn that into "no answer".
    def _boom(name):
        raise ImportError("net_auth gone")

    saved = nw._sibling
    nw._sibling = _boom
    try:
        check("fail-safe: _netauth_field swallows a broken module",
              nw._netauth_field(nw._Q(probes[0][0], files), cap) is None)
        off = {qq["id"]: nw.decide(qq, files, {}, caps)[0] for qq in all_qs}
    finally:
        nw._sibling = saved

    proto_ids = {qq["id"] for qq, _ in probes}
    check("fail-safe: protocol ids None when module absent",
          all(off[i] is None for i in proto_ids), extra=str({i: off[i] for i in proto_ids if off[i] is not None}))
    # the hook only ADDS: every id net_auth did not answer is byte-identical with the hook on/off,
    # and every id it DID answer was None without it (so no existing answer was ever changed).
    non_proto = [i for i in with_hook if i not in proto_ids]
    check("fail-safe: non-protocol answers byte-identical",
          all(with_hook[i] == off[i] for i in non_proto),
          extra=str({i: (with_hook[i], off[i]) for i in non_proto if with_hook[i] != off[i]}))
    check("fail-safe: hook never overwrote an existing answer",
          all(off[i] is None for i in proto_ids if with_hook[i] is not None))
    check("DNS still answers with the hook (existing path unchanged)", with_hook["dns-name"] is not None)

    # --- strict dispatch: a non-matching question gets no false match -------------------------
    bogus = nw.decide(q("bogus", "How long did the capture last in seconds?"), files, {}, caps)[0]
    # (answered or None by network.py's own duration reader; net_auth must not have claimed it)
    nf = na.field(nw._Q(q("x", "What is the HTTP user agent?"), files), cap, nw.Found, nw._choose)
    check("net_auth returns None for a non-(smb/krb/snmp/irc) question", nf is None)

    print("ok" if not FAILED else f"FAILED: {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
