#!/usr/bin/env python3
"""Offline tests of the never-wrong VoIP readers (solvers/toolkits/net_voip.py) that network.py
loads by name: SIP (signalling + digest auth) and RTP (media; G.711/G.722 PCM facts).

  .venv/bin/python tests/test_tk_net_voip.py

No network, no token. Every packet is built here from invented hosts (RFC 5737 addresses,
`.example` names) with raw bytes; nothing is real traffic. Three things are proved:
  1. The readers parse SIP (method / From / To / Contact / User-Agent / Call-ID and the digest
     realm / nonce / uri / response / username) and RTP (payload type, SSRC, stream count, and the
     G.711 decoded duration + sample rate), and offer each fact as an UNSURE pick (never plain).
  2. A malformed / partial packet reads as None (a short RTP header, a sequence gap, a truncated SIP
     line, a lone RTP-shaped datagram).
  3. The fail-safe wiring in network.py: with net_voip absent/raising, solve_set is BYTE-IDENTICAL
     to the pre-hook behaviour (VoIP questions answer None, every other answer -- network.py's own
     and net_auth's -- unchanged); the hook only ADDS answers for ids left None.
Prints one line per check and `ok` at the end; exits 1 on the first failure.
"""
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_WORKDIR"] = str(Path(tempfile.mkdtemp(prefix="test_net_voip_")) / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import network as nw      # noqa: E402
import net_voip as nv     # noqa: E402

FAILED = []


def check(name, cond, extra=""):
    print(("ok  " if cond else "FAIL") + f" {name}" + (f"  {extra}" if extra else ""))
    if not cond:
        FAILED.append(name)


# ---- packet construction (RFC 5737 hosts, raw bytes; no scapy) -------------------------------------------

def _ip4(src, dst, payload, proto):
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b)
    return head + payload


def _udp(sport, dport, data):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def _eth(payload):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + payload


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + i, 1000 * i, len(f), len(f)) + f
    return out


def _rtp(pt, seq, ts, ssrc, media):
    return struct.pack(">BBHII", 0x80, pt & 0x7F, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF) + media


# ---- the capture: a SIP REGISTER + 401 digest + authenticated REGISTER, and an RTP G.711 stream ---------
NONCE = "1a2b3c4d5e6f7890abcdef1234567890"
REALM = "asterisk.example"
RESP = "deadbeefcafe1234567890abcdef0011"
SSRC = 0x11223344
CLI, SRV = "192.0.2.10", "192.0.2.200"

REG1 = (
    "REGISTER sip:asterisk.example SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
    'From: "Alice Wonderland" <sip:alice@asterisk.example>;tag=aaa\r\n'
    "To: <sip:alice@asterisk.example>\r\n"
    "Call-ID: call-abc-123@192.0.2.10\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: <sip:alice@192.0.2.10:5060>\r\n"
    "User-Agent: PolyPhone/3.4.1\r\n"
    "Content-Length: 0\r\n\r\n"
)
RESP401 = (
    "SIP/2.0 401 Unauthorized\r\n"
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
    'From: "Alice Wonderland" <sip:alice@asterisk.example>;tag=aaa\r\n'
    "To: <sip:alice@asterisk.example>;tag=bbb\r\n"
    "Call-ID: call-abc-123@192.0.2.10\r\n"
    "CSeq: 1 REGISTER\r\n"
    f'WWW-Authenticate: Digest realm="{REALM}", nonce="{NONCE}", algorithm=MD5\r\n'
    "Content-Length: 0\r\n\r\n"
)
REG2 = (
    "REGISTER sip:asterisk.example SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK2\r\n"
    'From: "Alice Wonderland" <sip:alice@asterisk.example>;tag=aaa\r\n'
    "To: <sip:alice@asterisk.example>\r\n"
    "Call-ID: call-abc-123@192.0.2.10\r\n"
    "CSeq: 2 REGISTER\r\n"
    "Contact: <sip:alice@192.0.2.10:5060>\r\n"
    "User-Agent: PolyPhone/3.4.1\r\n"
    f'Authorization: Digest username="alice", realm="{REALM}", nonce="{NONCE}", '
    f'uri="sip:asterisk.example", response="{RESP}", algorithm=MD5\r\n'
    "Content-Length: 0\r\n\r\n"
)


def build_pcap():
    f = [
        _eth(_ip4(CLI, SRV, _udp(5060, 5060, REG1.encode()), 17)),
        _eth(_ip4(SRV, CLI, _udp(5060, 5060, RESP401.encode()), 17)),
        _eth(_ip4(CLI, SRV, _udp(5060, 5060, REG2.encode()), 17)),
    ]
    # RTP G.711 u-law: 50 packets, 160-byte payloads (20 ms @ 8 kHz), one SSRC, contiguous sequence
    for i in range(50):
        media = bytes((0xD5 + i) & 0xFF for _ in range(160))
        f.append(_eth(_ip4(CLI, SRV, _udp(40000, 40002, _rtp(0, 1000 + i, 320000 + 160 * i, SSRC, media)), 17)))
    # a plain DNS query too, so the existing network.py path is exercised in the same capture
    name = b"\x03cdn\x07example\x03com\x00"
    dq = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
    f.append(_eth(_ip4(CLI, "192.0.2.53", _udp(53002, 53, dq), 17)))
    return _pcap(f)


def q(qid, text, kind="exact_text", syntax="exact value only"):
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": "voip.pcap",
            "answer_format": {"kind": kind, "syntax": syntax}}


def unsure_value(ans):
    if not isinstance(ans, str) or not ans.startswith("??"):
        return None
    return [v for _, v in json.loads(ans[2:])["o"]]


def unsure_key(ans):
    if not isinstance(ans, str) or not ans.startswith("??"):
        return None
    return json.loads(ans[2:])["k"]


def main():
    files = {"voip.pcap": build_pcap()}
    caps = nw.find_captures(files)
    check("capture reads", bool(caps), extra=f"{len(caps)} capture(s)")
    cap = nw._cap_of(caps[0][0], caps[0][1])

    # --- the library parsers ------------------------------------------------------------------
    sip = nv.sip_messages(cap)
    check("sip: 2 REGISTER + 1 response parsed", len([m for m in sip if m["method"] == "REGISTER"]) == 2
          and any(m["kind"] == "response" for m in sip), extra=str([(m["kind"], m["method"], m["status"]) for m in sip]))
    auth = next((m["authorization"] for m in sip if m["authorization"]), None)
    chal = next((m["www_authenticate"] for m in sip if m["www_authenticate"]), None)
    check("sip digest Authorization parsed", auth and auth.get("username") == "alice"
          and auth.get("response") == RESP and auth.get("uri") == "sip:asterisk.example", extra=str(auth))
    check("sip WWW-Authenticate challenge parsed", chal and chal.get("realm") == REALM
          and chal.get("nonce") == NONCE, extra=str(chal))

    streams = nv.rtp_streams(cap)
    check("rtp: one stream, PT 0 (PCMU), 50 packets", len(streams) == 1 and streams[0]["pt"] == 0
          and streams[0]["packets"] == 50, extra=str([(s["pt"], s["packets"], hex(s["ssrc"])) for s in streams]))
    check("rtp ssrc parsed", streams and streams[0]["ssrc"] == SSRC)
    check("rtp G.711 duration == 1.0 s (50*160/8000)", streams and nv.rtp_duration(streams[0]) == 1.0,
          extra=str(streams and nv.rtp_duration(streams[0])))

    # --- through network.decide: every fact is an UNSURE pick, never plain, under its key -----
    probes = [
        (q("sip-method", "What SIP request method did the client send?"), "REGISTER", "network.sip_method/"),
        (q("sip-user", "What username is in the SIP digest Authorization header?"), "alice", "network.sip_auth_username/"),
        (q("sip-realm", "What realm is in the SIP digest authentication?"), REALM, "network.sip_auth_realm/"),
        (q("sip-nonce", "What nonce was used for SIP digest authentication?"), NONCE, "network.sip_auth_nonce/"),
        (q("sip-uri", "What is the digest URI in the SIP Authorization header?"), "sip:asterisk.example", "network.sip_auth_uri/"),
        (q("sip-resp", "What is the SIP digest response hash?"), RESP, "network.sip_auth_response/"),
        (q("sip-ua", "What SIP User-Agent is in the REGISTER?"), "PolyPhone/3.4.1", "network.sip_user_agent/"),
        (q("sip-callid", "What is the SIP Call-ID?"), "call-abc-123@192.0.2.10", "network.sip_call_id/"),
        (q("sip-from", "Who is the caller (SIP From header)?"), "sip:alice@asterisk.example", "network.sip_from/"),
        (q("sip-contact", "What is the SIP Contact URI?"), "sip:alice@192.0.2.10:5060", "network.sip_contact/"),
        (q("rtp-pt", "What RTP payload type is used?"), "0", "network.rtp_payload_type/"),
        (q("rtp-pt2", "What codec does the RTP stream carry?"), "PCMU", "network.rtp_payload_type/"),
        (q("rtp-ssrc", "What is the RTP SSRC?"), "0x11223344", "network.rtp_ssrc/"),
        (q("rtp-dur", "How long is the RTP audio stream in seconds?"), "1.000", "network.rtp_duration/"),
        (q("rtp-rate", "What is the sample rate of the RTP audio?"), "8000", "network.rtp_sample_rate/"),
    ]
    for qq, want, keypre in probes:
        ans = nw.decide(qq, files, {}, caps)[0]
        vals = unsure_value(ans)
        plain = isinstance(ans, str) and not ans.startswith("??")
        key = unsure_key(ans) or ""
        check(f"decide {qq['id']} unsure+value+key", vals is not None and want in vals and not plain
              and key.startswith(keypre), extra=f"key={key} ans={ans!r}")

    # "how many RTP streams" -> a count of 1
    cnt = nw.decide(q("rtp-count", "How many RTP streams are in the capture?"), files, {}, caps)[0]
    check("rtp stream count == 1", "1" in (unsure_value(cnt) or []), extra=repr(cnt))

    # --- MALFORMED / PARTIAL => None ----------------------------------------------------------
    bad = _pcap([
        _eth(_ip4(CLI, SRV, _udp(40000, 40002, b"\x80\x00\x03\xe8\x00\x04"), 17)),   # 6-byte RTP: too short
        _eth(_ip4(CLI, SRV, _udp(5060, 5060, b"REGISTER sip:broke"), 17)),           # truncated SIP: no SIP/2.0
    ])
    bfiles = {"bad.pcap": bad}
    bcaps = nw.find_captures(bfiles)
    check("malformed RTP => None", nw.decide(q("b-pt", "What RTP payload type is used?"), bfiles, {}, bcaps)[0] is None)
    check("malformed SIP => None",
          nw.decide(q("b-user", "What username is in the SIP digest Authorization header?"), bfiles, {}, bcaps)[0] is None)
    lone = nw._cap_of("lone.pcap", _pcap([_eth(_ip4(CLI, SRV, _udp(5000, 5002, b"\x80" + b"\x00" * 11), 17))]))
    check("a single RTP-shaped datagram is not a stream", nv.rtp_streams(lone) == [])
    gap_frames = [_eth(_ip4(CLI, SRV, _udp(41000, 41002, _rtp(8, 100 + i, 160 * i, 0xAA, bytes(160))), 17))
                  for i in (0, 1, 2, 5, 6)]      # a gap at sequence 103, 104
    gs = nv.rtp_streams(nw._cap_of("gap.pcap", _pcap(gap_frames)))
    check("a stream with a sequence gap => duration None (lost packet, not never-wrong)",
          len(gs) == 1 and nv.rtp_duration(gs[0]) is None, extra=str([nv.rtp_duration(s) for s in gs]))

    # --- FAIL-SAFE: with net_voip absent/raising, VoIP ids are None and NOTHING else changes --
    dns_q = q("dns-name", "List all the DNS names queried.", kind="ordered_tokens", syntax="comma separated")
    sip_q = q("sip-m2", "What SIP request method did the client send?")
    rtp_q = q("rtp-s2", "What is the RTP SSRC?")
    all_qs = [sip_q, rtp_q, dns_q]
    with_hook = {qq["id"]: nw.decide(qq, files, {}, caps)[0] for qq in all_qs}

    saved = nw._sibling

    def _boom(name):
        if name == "net_voip":
            raise ImportError("net_voip gone")
        return saved(name)

    nw._sibling = _boom
    try:
        check("fail-safe: _netvoip_field swallows a broken module",
              nw._netvoip_field(nw._Q(sip_q, files), cap) is None)
        off = {qq["id"]: nw.decide(qq, files, {}, caps)[0] for qq in all_qs}
    finally:
        nw._sibling = saved

    check("fail-safe: SIP id None when module absent", off["sip-m2"] is None, extra=repr(off["sip-m2"]))
    check("fail-safe: RTP id None when module absent", off["rtp-s2"] is None, extra=repr(off["rtp-s2"]))
    check("fail-safe: DNS answer byte-identical hook on/off (existing path unchanged)",
          with_hook["dns-name"] == off["dns-name"] and with_hook["dns-name"] is not None,
          extra=f"{with_hook['dns-name']!r} vs {off['dns-name']!r}")
    check("fail-safe: hook only ADDS (VoIP ids were None without it)",
          off["sip-m2"] is None and off["rtp-s2"] is None and with_hook["sip-m2"] is not None and with_hook["rtp-s2"] is not None)

    # --- net_auth still resolves alongside net_voip (decide chains both) -----------------------
    # an SMB2/Kerberos/SNMP/IRC question in a VoIP-free capture is untouched by net_voip
    check("strict dispatch: net_voip returns None for a non-SIP/RTP question",
          nv.field(nw._Q(q("x", "What is the HTTP user agent?"), files), cap, nw.Found, nw._choose) is None)
    check("strict dispatch: net_voip returns None for an RTP question when no RTP in the capture",
          nv.field(nw._Q(q("y", "What is the RTP SSRC?"), files), lone, nw.Found, nw._choose) is None)

    print("ok" if not FAILED else f"FAILED: {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
