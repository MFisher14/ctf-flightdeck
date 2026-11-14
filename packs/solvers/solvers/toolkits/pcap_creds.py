#!/usr/bin/env python3
"""pcap credential-hash extractor (GAP-PCAP-CREDS): the hashcat-format credential MATERIAL a
packet capture carries, read in plain Python, for a lane no shipped solver plays.

  .venv/bin/python solvers/toolkits/pcap_creds.py <capture>...          triage of each capture
  .venv/bin/python solvers/toolkits/pcap_creds.py --json <capture>...   the same as JSON
  .venv/bin/python solvers/toolkits/pcap_creds.py --attempt <dir>       every question: field, answer
  .venv/bin/python solvers/toolkits/pcap_creds.py --selftest            the in-file crafted-pcap checks

Offline: no Game Master request, no token, no subprocess, no network. stdlib only.

What it reads (each from the exact bytes, no dependency, no shelling out):
  - 802.11 (radiotap / bare Dot11) EAPOL 4-way handshake  -> the hashcat 22000 (WPA*) line
  - NTLMSSP CHALLENGE(type 2) + AUTHENTICATE(type 3) over SMB/HTTP/LDAP (raw blob or a
    base64 `NTLM `/`Negotiate ` HTTP token) -> the netntlmv1 (5500) / netntlmv2 (5600) line
  - Kerberos (UDP/TCP 88, ASN.1 DER) AS-REQ PA-ENC-TIMESTAMP, AS-REP enc-part and TGS-REP
    ticket enc-part, etype 23 (RC4-HMAC) -> the krb5pa (7500) / krb5asrep (18200) /
    krb5tgs (13100) line

The never-wrong boundary (AGENTS.md, "Uncertain answers"; recorded here so the solver never
sends a guess):

  - The ASSEMBLED HASHCAT STRING is a deterministic concatenation/encoding of exact captured
    bytes.  Its content is byte-proven; the only axis the judge has not fixed is the rendering
    (hex case, the author's separators).  So it is PLAIN-eligible but emitted through
    `labels.pick(key, renderings)` -- the renderings are spellings of the ONE assembled fact
    (lowercase-hex first, then uppercase-hex) -- which `gm.session()` strips from any direct
    submission and `tools/verify.py` probes one rendering at a time on the untimed base.  Never
    plain until the judge accepts a rendering for the key.
  - The CRACKED password / PSK / plaintext is NEVER derived or submitted here.  A question that
    asks for the password, passphrase, PSK, secret or the cracked value is always None: that is
    not a byte-fact of the capture, it is the output of an offline crack this module does not do.
  - A handshake missing a required message (no M1 ANonce or no M2 MIC for a WPA*02 line, no
    known ESSID), a truncated or malformed NTLMSSP blob, a Kerberos enc-part whose etype is not
    23, two equally-matching facts with nothing in the question to choose between them, or any
    parse that does not reproduce -> None.  Never a padded, defaulted or guessed line.

signals(questions, files) -> 0..1 says how much a delivery and its questions look like pcap
credential material.  solve_set(questions, files, ctx) is the runner contract.

The label prefix is `network` (an established toolkit prefix in solvers/common/labels.py); the
fields here (`wpa_hashcat`, `netntlmv2_hashcat`, `krb5asrep_hashcat`, ...) identify the narrow
credential-material specialty.  `network.py` also reconstructs Net-NTLM material as part of its
broader capture reader; `ownership()` proves the exact complete fact and lets the production matcher
prefer this specialist only when tied readers offer that same value for the same answer ids.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

# The runner puts this folder first on sys.path; import stdlib with the toolkit folder removed so a
# sibling named like a standard module can never stand in for it.
_saved_path = list(sys.path)
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != HERE]
import base64         # noqa: E402
import binascii       # noqa: E402
import hashlib        # noqa: E402
import json           # noqa: E402
import re             # noqa: E402
import struct         # noqa: E402
from collections import OrderedDict   # noqa: E402
sys.path[:] = _saved_path

KEY = "network"                 # the label prefix (solvers/common/labels.py TOOLKIT_PREFIXES)
SENTINEL = "??"
MAX_OPTIONS = 12
MAX_CAPTURE = 256 * 1024 * 1024
MAX_PACKETS = 2_000_000
MAX_TLV_DEPTH = 40
EAPOL_ETHERTYPE = 0x888E


# ============================================================================================
#  the capture reader: pcap and pcapng, to (linktype, packet bytes)
# ============================================================================================

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),   # us, little-endian
    b"\xa1\xb2\xc3\xd4": (">", False),   # us, big-endian
    b"\x4d\x3c\xb2\xa1": ("<", True),    # ns, little-endian
    b"\xa1\xb2\x3c\x4d": (">", True),    # ns, big-endian
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def is_capture(data) -> bool:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 24:
        return False
    head = bytes(data[:4])
    if head in PCAP_MAGICS:
        return True
    return head == PCAPNG_MAGIC and bytes(data[8:12]) in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d")


def find_captures(files) -> list:
    """[(name, bytes)] for every delivery member whose bytes are a pcap or pcapng."""
    out = []
    for name, data in (files or {}).items():
        try:
            if is_capture(data) and len(data) <= MAX_CAPTURE:
                out.append((name, bytes(data)))
        except Exception:
            pass
    return out


def read_packets(data: bytes):
    """Yield (linktype, packet_bytes) for every captured frame, pcap or pcapng.  Bounded; a
    damaged record ends the walk rather than raising."""
    if not isinstance(data, (bytes, bytearray)):
        return
    data = bytes(data)
    head = data[:4]
    if head in PCAP_MAGICS:
        yield from _read_pcap(data)
    elif head == PCAPNG_MAGIC:
        yield from _read_pcapng(data)


def _read_pcap(data: bytes):
    endian, _ns = PCAP_MAGICS[data[:4]]
    if len(data) < 24:
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off, n = 24, 0
    while off + 16 <= len(data) and n < MAX_PACKETS:
        _ts, _us, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > 0x7FFFFFFF or off + incl > len(data):
            break
        yield linktype, data[off:off + incl]
        off += incl
        n += 1


def _read_pcapng(data: bytes):
    off, n = 0, 0
    endian = "<"
    iface_link = {}       # interface id -> linktype, in order of IDB
    iface_count = 0
    while off + 12 <= len(data) and n < MAX_PACKETS:
        btype = struct.unpack(endian + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:        # Section Header Block: byte order from its magic
            if off + 12 > len(data):
                break
            bom = data[off + 8:off + 12]
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                break
            iface_link = {}
            iface_count = 0
            btype = struct.unpack(endian + "I", data[off:off + 4])[0]
        blen = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > len(data) or blen % 4:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:        # Interface Description Block
            if len(body) >= 4:
                lt = struct.unpack(endian + "H", body[0:2])[0]
                iface_link[iface_count] = lt
                iface_count += 1
        elif btype == 0x00000006:      # Enhanced Packet Block
            if len(body) >= 20:
                ifid, _hi, _lo, caplen, _orig = struct.unpack(endian + "IIIII", body[:20])
                pkt = body[20:20 + caplen]
                if len(pkt) == caplen:
                    yield iface_link.get(ifid, 1), pkt
                    n += 1
        elif btype == 0x00000003:      # Simple Packet Block
            if len(body) >= 4:
                yield iface_link.get(0, 1), body[4:]
                n += 1
        elif btype == 0x00000002:      # legacy Packet Block
            if len(body) >= 20:
                _ifid, _drop, _hi, _lo, caplen, _orig = struct.unpack(endian + "HHIIII", body[:20])
                pkt = body[20:20 + caplen]
                if len(pkt) == caplen:
                    yield iface_link.get(_ifid, 1), pkt
                    n += 1
        off += blen


# ============================================================================================
#  link / network / transport dissection (enough for EAPOL, NTLM, Kerberos)
# ============================================================================================

def _l3_from_ethertype(etype, payload):
    """(proto, src_ip, dst_ip, l4payload) or None, following VLAN tags."""
    while etype == 0x8100 and len(payload) >= 4:        # 802.1Q VLAN
        etype = struct.unpack(">H", payload[2:4])[0]
        payload = payload[4:]
    if etype == 0x0800:
        return _ipv4(payload)
    if etype == 0x86DD:
        return _ipv6(payload)
    return None


def _ipv4(b):
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return None
    proto = b[9]
    src = ".".join(str(x) for x in b[12:16])
    dst = ".".join(str(x) for x in b[16:20])
    total = struct.unpack(">H", b[2:4])[0]
    body = b[ihl:total] if 0 < total <= len(b) else b[ihl:]
    return proto, src, dst, body


def _ipv6(b):
    if len(b) < 40:
        return None
    nxt = b[6]
    src = _ip6(b[8:24])
    dst = _ip6(b[24:40])
    off = 40
    EXT = {0, 43, 44, 51, 60}        # hop-by-hop, routing, fragment, AH, dest-opts
    while nxt in EXT and off + 8 <= len(b):
        if nxt == 44:                # fragment header: 8 bytes fixed
            new, hlen = b[off], 8
        elif nxt == 51:              # AH: length in 4-byte units + 2
            new, hlen = b[off], (b[off + 1] + 2) * 4
        else:
            new, hlen = b[off], (b[off + 1] + 1) * 8
        nxt = new
        off += hlen
    return nxt, src, dst, b[off:]


def _ip6(raw):
    return ":".join("%x" % struct.unpack(">H", raw[i:i + 2])[0] for i in range(0, 16, 2))


def _l4(proto, body):
    """(kind, sport, dport, payload) for TCP(6)/UDP(17); kind is 'tcp'/'udp'.  None otherwise."""
    if proto == 6 and len(body) >= 20:                 # TCP
        sport, dport = struct.unpack(">HH", body[0:4])
        doff = (body[12] >> 4) * 4
        if doff < 20 or len(body) < doff:
            return None
        return "tcp", sport, dport, body[doff:]
    if proto == 17 and len(body) >= 8:                 # UDP
        sport, dport = struct.unpack(">HH", body[0:4])
        ln = struct.unpack(">H", body[4:6])[0]
        payload = body[8:ln] if 8 <= ln <= len(body) else body[8:]
        return "udp", sport, dport, payload
    return None


def _decode_frame(linktype, frame):
    """A normalized view of one frame: either an ('dot11', ...) record for 802.11, or a
    ('l4', kind, src, dst, sport, dport, payload) record for an IP transport payload."""
    if linktype in (105, 127, 119, 120):               # 802.11 family
        if linktype in (127, 119):                     # radiotap / AVS: skip the header
            if linktype == 127 and len(frame) >= 4:
                rtlen = struct.unpack("<H", frame[2:4])[0]
                frame = frame[rtlen:] if 0 < rtlen <= len(frame) else frame
            elif linktype == 119 and len(frame) >= 8:
                frame = frame[struct.unpack(">I", frame[4:8])[0]:]
        return ("dot11", frame)
    if linktype in (1,):                               # Ethernet
        if len(frame) < 14:
            return None
        et = struct.unpack(">H", frame[12:14])[0]
        l3 = _l3_from_ethertype(et, frame[14:])
    elif linktype in (12, 14, 101, 228):               # raw IP
        ver = frame[0] >> 4 if frame else 0
        l3 = _ipv4(frame) if ver == 4 else (_ipv6(frame) if ver == 6 else None)
    elif linktype == 229:
        l3 = _ipv6(frame)
    elif linktype == 0:                                # BSD null/loopback: 4-byte family
        if len(frame) < 4:
            return None
        fam = struct.unpack("<I", frame[0:4])[0]
        l3 = _ipv4(frame[4:]) if fam == 2 else (_ipv6(frame[4:]) if fam in (24, 28, 30) else None)
    elif linktype == 113:                              # Linux cooked v1
        if len(frame) < 16:
            return None
        l3 = _l3_from_ethertype(struct.unpack(">H", frame[14:16])[0], frame[16:])
    elif linktype == 276:                              # Linux cooked v2
        if len(frame) < 20:
            return None
        l3 = _l3_from_ethertype(struct.unpack(">H", frame[0:2])[0], frame[20:])
    else:
        return None
    if not l3:
        return None
    proto, src, dst, body = l3
    tr = _l4(proto, body)
    if not tr:
        return None
    kind, sport, dport, payload = tr
    return ("l4", kind, src, dst, sport, dport, payload)


# ============================================================================================
#  802.11 EAPOL -> hashcat 22000
# ============================================================================================

def _mac(raw):
    return "".join("%02x" % x for x in raw[:6])


def _mac_colon(raw):
    return ":".join("%02x" % x for x in raw[:6])


class EapolMsg:
    __slots__ = ("bssid", "sta", "nonce", "mic", "replay", "eapol", "msg", "keyinfo")

    def __init__(self, bssid, sta, nonce, mic, replay, eapol, msg, keyinfo):
        self.bssid, self.sta, self.nonce, self.mic = bssid, sta, nonce, mic
        self.replay, self.eapol, self.msg, self.keyinfo = replay, eapol, msg, keyinfo


def _iter_dot11(frames):
    """From the decoded 802.11 frames, yield SSIDs by BSSID and EAPOL key messages."""
    ssids = {}            # bssid (12 hex) -> ssid bytes
    eapols = []           # EapolMsg
    for frame in frames:
        if len(frame) < 10:
            continue
        fc = frame[0]
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF
        to_ds = bool(frame[1] & 0x01)
        from_ds = bool(frame[1] & 0x02)
        if ftype == 0:        # management: beacon(8)/probe-resp(5)/assoc(0)/reassoc(2)
            if len(frame) < 24:
                continue
            addr3 = frame[16:22]           # BSSID
            if subtype in (8, 5):          # beacon / probe response: 12-byte fixed params
                body = frame[36:]
            elif subtype in (0, 2):        # (re)assoc request
                body = frame[28:] if subtype == 0 else frame[34:]
            else:
                continue
            ssid = _tag(body, 0)
            if ssid is not None and 0 < len(ssid) <= 32 and all(32 <= c < 127 for c in ssid):
                ssids.setdefault(_mac(addr3), ssid)
            continue
        if ftype != 2:        # only data frames carry EAPOL
            continue
        hdr = 24
        if to_ds and from_ds:
            hdr += 6          # addr4 (WDS): unusual, skip EAPOL extraction
            continue
        if subtype & 0x08:    # QoS data: +2 QoS control
            hdr += 2
        addr1, addr2, addr3 = frame[4:10], frame[10:16], frame[16:22]
        body = frame[hdr:]
        # LLC/SNAP for EAPOL: AA AA 03 00 00 00 88 8E
        if len(body) >= 8 and body[0:3] == b"\xaa\xaa\x03" and body[3:6] == b"\x00\x00\x00":
            et = struct.unpack(">H", body[6:8])[0]
            if et != EAPOL_ETHERTYPE:
                continue
            eapol = body[8:]
        else:
            continue
        rec = _parse_eapol(eapol)
        if rec is None:
            continue
        nonce, mic, replay, msg, keyinfo, eapol_frame = rec
        if from_ds:                        # AP -> STA
            bssid, sta = addr2, addr1
        else:                              # STA -> AP (to_ds) or ad-hoc
            bssid, sta = addr1, addr2
        eapols.append(EapolMsg(_mac(bssid), _mac(sta), nonce, mic, replay, eapol_frame, msg, keyinfo))
    return ssids, eapols


def _tag(body, want):
    """The value bytes of the first 802.11 information element with id `want`."""
    i = 0
    while i + 2 <= len(body):
        tid, tlen = body[i], body[i + 1]
        if i + 2 + tlen > len(body):
            break
        if tid == want:
            return body[i + 2:i + 2 + tlen]
        i += 2 + tlen
    return None


def _parse_eapol(b):
    """(nonce, mic, replay, msg_number, keyinfo, eapol_frame_with_mic_zeroed) or None."""
    if len(b) < 99 or b[1] != 3:          # 802.1X type 3 = EAPOL-Key
        return None
    body_len = struct.unpack(">H", b[2:4])[0]
    total = 4 + body_len
    if body_len < 95 or total > len(b):
        return None
    frame = b[:total]
    keyinfo = struct.unpack(">H", frame[5:7])[0]
    replay = frame[9:17]
    nonce = frame[17:49]
    mic = frame[81:97]
    kdl = struct.unpack(">H", frame[97:99])[0]
    if 99 + kdl != total:
        return None
    pairwise = bool(keyinfo & 0x0008)
    ack = bool(keyinfo & 0x0080)
    mic_set = bool(keyinfo & 0x0100)
    secure = bool(keyinfo & 0x0200)
    install = bool(keyinfo & 0x0040)
    if not pairwise:
        return None
    if ack and not mic_set:
        msg = 1
    elif mic_set and not ack and not secure:
        msg = 2
    elif mic_set and ack and install:
        msg = 3
    elif mic_set and not ack and secure:
        msg = 4
    else:
        msg = 0
    zeroed = bytearray(frame)
    zeroed[81:97] = b"\x00" * 16          # the MIC field is zeroed in the 22000 EAPOL field
    return nonce, mic, replay, msg, keyinfo, bytes(zeroed)


def _wpa_handshakes(ssids, eapols):
    """[dict] one per (bssid, sta) pair that has an M1 ANonce and an M2 MIC and a known ESSID."""
    by_pair = OrderedDict()
    for e in eapols:
        by_pair.setdefault((e.bssid, e.sta), []).append(e)
    out = []
    for (bssid, sta), msgs in by_pair.items():
        m1 = next((m for m in msgs if m.msg == 1), None)
        m2 = next((m for m in msgs if m.msg == 2), None)
        if m1 is None or m2 is None:
            continue
        essid = ssids.get(bssid)
        if essid is None:                 # ESSID is required for a 22000 line; never guessed
            continue
        if m2.mic == b"\x00" * 16:        # no MIC to authenticate
            continue
        mp = 0x00                         # M1+M2, EAPOL from M2
        if m1.replay != m2.replay:        # replay counter not matched -> nc bit
            mp |= 0x10
        out.append({
            "field": "wpa_hashcat", "shape": "hc22000", "mode": 22000,
            "bssid": bssid, "sta": sta, "essid": essid,
            "mic": m2.mic.hex(), "anonce": m1.nonce.hex(),
            "eapol": m2.eapol.hex(), "mp": "%02x" % mp,
        })
    return out


def _render_wpa(h, upper):
    def hx(s):
        return s.upper() if upper else s
    essid = hx(h["essid"].hex())
    return "WPA*02*%s*%s*%s*%s*%s*%s*%s" % (
        hx(h["mic"]), hx(h["bssid"]), hx(h["sta"]), essid,
        hx(h["anonce"]), hx(h["eapol"]), hx(h["mp"]))


# ============================================================================================
#  NTLMSSP -> netntlmv1 (5500) / netntlmv2 (5600)
# ============================================================================================

NTLMSSP_SIG = b"NTLMSSP\x00"
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001


def _secbuf(blob, base, pos):
    if pos + 8 > len(blob):
        return None
    ln, _maxln, off = struct.unpack("<HHI", blob[pos:pos + 8])
    s, e = base + off, base + off + ln
    if ln == 0 or e > len(blob):
        return b"" if ln == 0 else None
    return blob[s:e]


def _decode_str(raw, unicode_flag):
    if raw is None:
        return None
    try:
        if unicode_flag:
            return raw.decode("utf-16-le")
        return raw.decode("latin-1")
    except Exception:
        return None


def _find_ntlmssp(payload):
    """Yield (msgtype, blob, base_in_payload) for every NTLMSSP message in a transport payload,
    both raw (SMB/LDAP) and inside a base64 `NTLM `/`Negotiate ` HTTP token."""
    start = 0
    while True:
        i = payload.find(NTLMSSP_SIG, start)
        if i < 0:
            break
        if i + 12 <= len(payload):
            mtype = struct.unpack("<I", payload[i + 8:i + 12])[0]
            if mtype in (1, 2, 3):
                yield mtype, payload, i
        start = i + 8
    for m in re.finditer(rb"(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]{16,})", payload):
        try:
            raw = base64.b64decode(m.group(1), validate=False)
        except Exception:
            continue
        if raw[:8] == NTLMSSP_SIG and len(raw) >= 12:
            mtype = struct.unpack("<I", raw[8:12])[0]
            if mtype in (1, 2, 3):
                yield mtype, raw, 0


def _parse_type2(blob, base):
    if base + 32 > len(blob):
        return None
    return blob[base + 24:base + 32]          # ServerChallenge, 8 bytes


def _parse_type3(blob, base):
    if base + 60 > len(blob):
        return None
    flags = struct.unpack("<I", blob[base + 60:base + 64])[0] if base + 64 <= len(blob) else 0
    uni = bool(flags & NTLMSSP_NEGOTIATE_UNICODE)
    lm = _secbuf(blob, base, base + 12)
    nt = _secbuf(blob, base, base + 20)
    dom = _decode_str(_secbuf(blob, base, base + 28), uni)
    usr = _decode_str(_secbuf(blob, base, base + 36), uni)
    if nt is None or usr is None:
        return None
    return {"lm": lm, "nt": nt, "domain": dom or "", "user": usr}


def _stream_key(src, dst, sport, dport):
    return frozenset(((src, sport), (dst, dport)))


def _ntlm_creds(frames):
    """[dict] one per CHALLENGE+AUTHENTICATE pair, as netntlmv1 or netntlmv2 fields."""
    pend = {}             # stream -> last server challenge seen (type 2)
    out = []
    for rec in frames:
        if rec[0] != "l4":
            continue
        _, _kind, src, dst, sport, dport, payload = rec
        if NTLMSSP_SIG not in payload and b"NTLM" not in payload and b"Negotiate" not in payload:
            continue
        sk = _stream_key(src, dst, sport, dport)
        for mtype, blob, base in _find_ntlmssp(payload):
            if mtype == 2:
                ch = _parse_type2(blob, base)
                if ch is not None:
                    pend[sk] = ch
            elif mtype == 3:
                t3 = _parse_type3(blob, base)
                ch = pend.get(sk)
                if t3 is None or ch is None:
                    continue
                nt = t3["nt"]
                if len(nt) == 24 and t3["lm"] is not None and len(t3["lm"]) == 24:
                    out.append({
                        "field": "netntlmv1_hashcat", "shape": "mode5500", "mode": 5500,
                        "user": t3["user"], "domain": t3["domain"],
                        "lm": t3["lm"].hex(), "nt": nt.hex(), "challenge": ch.hex(),
                    })
                elif len(nt) > 24:
                    out.append({
                        "field": "netntlmv2_hashcat", "shape": "mode5600", "mode": 5600,
                        "user": t3["user"], "domain": t3["domain"],
                        "challenge": ch.hex(), "ntproof": nt[:16].hex(), "blob": nt[16:].hex(),
                    })
    return out


def _render_ntlmv1(h, upper):
    def hx(s):
        return s.upper() if upper else s
    return "%s::%s:%s:%s:%s" % (h["user"], h["domain"], hx(h["lm"]), hx(h["nt"]), hx(h["challenge"]))


def _render_ntlmv2(h, upper):
    def hx(s):
        return s.upper() if upper else s
    return "%s::%s:%s:%s:%s" % (h["user"], h["domain"], hx(h["challenge"]), hx(h["ntproof"]), hx(h["blob"]))


# ============================================================================================
#  Kerberos (ASN.1 DER) -> krb5pa (7500) / krb5asrep (18200) / krb5tgs (13100)
# ============================================================================================

class TLV:
    __slots__ = ("cls", "constructed", "num", "value", "children", "raw")

    def __init__(self, cls, constructed, num, value, children, raw):
        self.cls, self.constructed, self.num = cls, constructed, num
        self.value, self.children, self.raw = value, children, raw


def _der(b, off=0, depth=0):
    """Parse one DER TLV at `off`.  Returns (TLV, end) or None.  Bounded in depth."""
    if depth > MAX_TLV_DEPTH or off + 2 > len(b):
        return None
    t = b[off]
    cls = (t & 0xC0) >> 6
    constructed = bool(t & 0x20)
    num = t & 0x1F
    p = off + 1
    if num == 0x1F:                               # long-form tag number
        num = 0
        while p < len(b):
            num = (num << 7) | (b[p] & 0x7F)
            more = b[p] & 0x80
            p += 1
            if not more:
                break
    if p >= len(b):
        return None
    first = b[p]
    p += 1
    if first < 0x80:
        length = first
    else:
        nbytes = first & 0x7F
        if nbytes == 0 or p + nbytes > len(b):
            return None
        length = int.from_bytes(b[p:p + nbytes], "big")
        p += nbytes
    end = p + length
    if end > len(b):
        return None
    value = b[p:end]
    children = []
    if constructed:
        q = p
        while q < end:
            res = _der(b, q, depth + 1)
            if res is None:
                break
            child, q = res
            children.append(child)
    return TLV(cls, constructed, num, value, children, b[off:end]), end


def _ctx(tlv, num):
    """The first context [num] child's single inner element (DER wraps context tags)."""
    for c in tlv.children:
        if c.cls == 2 and c.num == num:
            return c.children[0] if c.children else c
    return None


def _ctx_raw(tlv, num):
    for c in tlv.children:
        if c.cls == 2 and c.num == num:
            return c
    return None


def _int(tlv):
    return int.from_bytes(tlv.value, "big") if tlv is not None and tlv.value else None


def _gstr(tlv):
    try:
        return tlv.value.decode("latin-1") if tlv is not None else None
    except Exception:
        return None


def _principal(tlv):
    """PrincipalName -> name-string joined with '/'."""
    if tlv is None:
        return None
    seq = tlv if tlv.constructed else None
    if seq is None:
        return None
    names = _ctx(seq, 1)
    if names is None or not names.constructed:
        return None
    parts = [_gstr(c) for c in names.children]
    parts = [p for p in parts if p]
    return "/".join(parts) if parts else None


def _encrypted_data(tlv):
    """EncryptedData SEQUENCE -> (etype, cipher bytes) or None."""
    if tlv is None or not tlv.constructed:
        return None
    etype = _int(_ctx(tlv, 0))
    cipher_ctx = _ctx(tlv, 2)
    if etype is None or cipher_ctx is None:
        return None
    return etype, cipher_ctx.value


def _kerberos_messages(frames):
    """Yield parsed top-level Kerberos TLVs (application 10/11/12/13) from UDP/TCP 88."""
    for rec in frames:
        if rec[0] != "l4":
            continue
        _, kind, _src, _dst, sport, dport, payload = rec
        if 88 not in (sport, dport):
            continue
        candidates = [payload]
        if kind == "tcp" and len(payload) >= 4:
            ln = struct.unpack(">I", payload[0:4])[0]
            if 0 < ln <= len(payload) - 4:
                candidates = [payload[4:4 + ln]]
        for data in candidates:
            if not data or data[0] & 0xC0 != 0x40:        # must be an APPLICATION tag
                continue
            res = _der(data, 0)
            if res is None:
                continue
            tlv, _end = res
            if tlv.cls == 1 and tlv.num in (10, 11, 12, 13):
                yield tlv.num, tlv


def _kdc_rep_body(app_tlv):
    """The inner KDC-REP SEQUENCE of an AS-REP/TGS-REP application wrapper."""
    if app_tlv.children and app_tlv.children[0].constructed:
        return app_tlv.children[0]
    return None


def _kerberos_hashes(frames):
    out = []
    for num, tlv in _kerberos_messages(frames):
        try:
            if num == 11:                 # AS-REP
                out += _from_as_rep(tlv)
            elif num == 13:               # TGS-REP
                out += _from_tgs_rep(tlv)
            elif num == 10:               # AS-REQ (PA-ENC-TIMESTAMP)
                out += _from_as_req(tlv)
        except Exception:
            continue
    return out


def _from_as_rep(app):
    body = _kdc_rep_body(app)
    if body is None:
        return []
    realm = _gstr(_ctx(body, 3))
    user = _principal(_ctx(body, 4))
    enc = _encrypted_data(_ctx(body, 6))
    if not realm or not user or enc is None:
        return []
    etype, cipher = enc
    if etype != 23 or len(cipher) < 16:
        return []
    return [{
        "field": "krb5asrep_hashcat", "shape": "mode18200", "mode": 18200,
        "user": user, "realm": realm,
        "checksum": cipher[:16].hex(), "edata": cipher[16:].hex(),
    }]


def _from_tgs_rep(app):
    body = _kdc_rep_body(app)
    if body is None:
        return []
    realm = _gstr(_ctx(body, 3))
    user = _principal(_ctx(body, 4))
    ticket = _ctx(body, 5)                 # Ticket, APPLICATION 1
    if ticket is None:
        return []
    tseq = ticket.children[0] if (ticket.cls == 1 and ticket.num == 1 and ticket.children) else ticket
    sname = _principal(_ctx(tseq, 2))
    trealm = _gstr(_ctx(tseq, 1))
    enc = _encrypted_data(_ctx(tseq, 3))
    if enc is None or not sname:
        return []
    etype, cipher = enc
    if etype != 23 or len(cipher) < 16:
        return []
    return [{
        "field": "krb5tgs_hashcat", "shape": "mode13100", "mode": 13100,
        "user": user or "", "realm": realm or trealm or "", "spn": sname,
        "checksum": cipher[:16].hex(), "edata": cipher[16:].hex(),
    }]


def _from_as_req(app):
    kdc_req = app.children[0] if app.children and app.children[0].constructed else None
    if kdc_req is None:
        return []
    padata = _ctx(kdc_req, 3)
    body = _ctx(kdc_req, 4)
    if padata is None or body is None:
        return []
    user = _principal(_ctx(body, 1))
    realm = _gstr(_ctx(body, 2))
    cipher = None
    seqof = padata if padata.constructed else None
    for pa in (seqof.children if seqof else []):
        if not pa.constructed:
            continue
        ptype = _int(_ctx(pa, 1))
        pval = _ctx(pa, 2)
        if ptype == 2 and pval is not None:          # PA-ENC-TIMESTAMP
            res = _der(pval.value, 0)
            if res is None:
                continue
            enc = _encrypted_data(res[0])
            if enc and enc[0] == 23 and len(enc[1]) >= 1:
                cipher = enc[1]
                break
    if cipher is None or not user or not realm:
        return []
    return [{
        "field": "krb5pa_hashcat", "shape": "mode7500", "mode": 7500,
        "user": user, "realm": realm, "cipher": cipher.hex(),
    }]


def _render_krb5asrep(h, upper):
    def hx(s):
        return s.upper() if upper else s
    return "$krb5asrep$23$%s@%s:%s$%s" % (h["user"], h["realm"], hx(h["checksum"]), hx(h["edata"]))


def _render_krb5tgs(h, upper):
    def hx(s):
        return s.upper() if upper else s
    return "$krb5tgs$23$*%s$%s$%s*$%s$%s" % (h["user"], h["realm"], h["spn"], hx(h["checksum"]), hx(h["edata"]))


def _render_krb5pa(h, upper):
    def hx(s):
        return s.upper() if upper else s
    # etype 23 ignores the salt field; it is not in the AS-REQ bytes, so it is left empty.
    return "$krb5pa$23$%s$%s$$%s" % (h["user"], h["realm"], hx(h["cipher"]))


# ============================================================================================
#  the whole read, and the renderers map
# ============================================================================================

_RENDER = {
    "wpa_hashcat": _render_wpa,
    "netntlmv1_hashcat": _render_ntlmv1,
    "netntlmv2_hashcat": _render_ntlmv2,
    "krb5pa_hashcat": _render_krb5pa,
    "krb5asrep_hashcat": _render_krb5asrep,
    "krb5tgs_hashcat": _render_krb5tgs,
}


def extract(capture_bytes) -> list:
    """Every credential-material fact in one capture, as a list of field dicts."""
    dot11, l4 = [], []
    for linktype, frame in read_packets(capture_bytes):
        dec = _decode_frame(linktype, frame)
        if dec is None:
            continue
        if dec[0] == "dot11":
            dot11.append(dec[1])
        else:
            l4.append(dec)
    out = []
    if dot11:
        ssids, eapols = _iter_dot11(dot11)
        out += _wpa_handshakes(ssids, eapols)
    if l4:
        out += _ntlm_creds(l4)
        out += _kerberos_hashes(l4)
    return out


def renderings(h) -> list:
    """The ordered (name, value) renderings of one assembled hashcat fact: lowercase first."""
    fn = _RENDER[h["field"]]
    lower = fn(h, False)
    upper = fn(h, True)
    opts = [("hashcat_lower", lower)]
    if upper != lower:
        opts.append(("hashcat_upper", upper))
    return opts


# ============================================================================================
#  question routing
# ============================================================================================

_SELECTORS = [
    ("wpa_hashcat", re.compile(
        r"\b(eapol|pmkid|wpa2?|802\.11|wifi|wi-fi|wireless|4-?way|four-?way|handshake|"
        r"hccapx|22000|m22000)\b", re.I)),
    ("netntlmv2_hashcat", re.compile(r"\b(net-?ntlmv2|ntlmv2|ntlm\s*v2|5600)\b", re.I)),
    ("netntlmv1_hashcat", re.compile(r"\b(net-?ntlmv1|ntlmv1|ntlm\s*v1|5500)\b", re.I)),
    ("krb5tgs_hashcat", re.compile(r"\b(tgs-?rep|tgs|kerberoast|13100|service ticket)\b", re.I)),
    ("krb5asrep_hashcat", re.compile(r"\b(as-?rep|asrep-?roast|asreproast|18200)\b", re.I)),
    ("krb5pa_hashcat", re.compile(r"\b(as-?req|pa-?enc-?timestamp|pre-?auth|7500|krb5pa)\b", re.I)),
]
_NTLM_ANY = re.compile(r"\bntlm\b", re.I)
_KRB_ANY = re.compile(r"\b(kerberos|krb5|\.kirbi|ccache)\b", re.I)
_HASHCAT_ANY = re.compile(r"\b(hashcat|hash of the|hash for the|crackable hash|hash string|the hash)\b", re.I)
# A question that asks for the SECRET itself is never answered from a capture (not a byte-fact).
_SECRET = re.compile(
    r"\b(password|passphrase|psk|pre-?shared key|plaintext|cracked|the secret|"
    r"the key is|wifi key|wireless key|recovered password)\b", re.I)


def _qtext(q):
    return " ".join(str(q.get(k, "")) for k in ("question", "prompt", "text", "answer_format", "qid", "id"))


def _fields_for(text, found_fields):
    """Which credential field(s) a question is asking for, by its words.  Empty when unclear."""
    wanted = []
    for field, rx in _SELECTORS:
        if rx.search(text):
            wanted.append(field)
    if not wanted and _NTLM_ANY.search(text):
        # NTLM without a version word: answer only if the capture has exactly one NTLM kind.
        kinds = {f for f in found_fields if f.startswith("netntlm")}
        if len(kinds) == 1:
            wanted = list(kinds)
    if not wanted and _KRB_ANY.search(text):
        kinds = {f for f in found_fields if f.startswith("krb5")}
        if len(kinds) == 1:
            wanted = list(kinds)
    if not wanted and _HASHCAT_ANY.search(text):
        kinds = set(found_fields)
        if len(kinds) == 1:
            wanted = list(kinds)
    # de-dup, keep order
    seen, ordered = set(), []
    for f in wanted:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def _select(hashes, field, text):
    """The single matching hash of `field`, disambiguated by a user/essid/spn the question names;
    None when zero or more than one match (never a guess)."""
    cands = [h for h in hashes if h["field"] == field]
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    low = text.lower()
    narrowed = []
    for h in cands:
        for k in ("user", "essid", "spn", "domain", "bssid", "sta"):
            v = h.get(k)
            if isinstance(v, bytes):
                try:
                    v = v.decode("latin-1")
                except Exception:
                    continue
            if v and str(v).lower() in low:
                narrowed.append(h)
                break
    if len(narrowed) == 1:
        return narrowed[0]
    return None


def _fact_for(q, hashes):
    """The one complete captured credential-material fact selected by ``q``, else None.

    This is also the ownership boundary: it depends on a successful packet parse and every field
    required to render the line, not merely on a capture magic or a credential word in the prompt.
    """
    text = _qtext(q)
    if _SECRET.search(text):
        return None                       # the cracked secret is never a byte-fact: None
    found_fields = [h["field"] for h in hashes]
    fields = _fields_for(text, found_fields)
    if len(fields) != 1:                  # unclear, or asks for two kinds at once
        return None
    return _select(hashes, fields[0], text)


def _answer_for(q, hashes):
    h = _fact_for(q, hashes)
    if h is None:
        return None
    opts = renderings(h)
    return _pick("%s.%s/%s" % (KEY, h["field"], h["shape"]), opts)


# ============================================================================================
#  labels bridge (never sends an unproven name as plain; matches network.py's pattern)
# ============================================================================================

def _common(name):
    path = ROOT / "solvers" / "common" / f"{name}.py"
    mod = sys.modules.get(name)
    if mod is not None and Path(getattr(mod, "__file__", "") or ".").resolve() == path:
        return mod
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    held = sys.modules.get(name)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        if held is not None:
            sys.modules[name] = held
        raise
    return mod


def _pick(key, options):
    """labels.pick; the same wire form written here as a fallback so the answer is never plain
    until a rendering is judged (labels strips every `??` value from a submission)."""
    options = [(n, v) for n, v in options if v is not None and v != ""][:MAX_OPTIONS]
    if not options:
        return None
    try:
        return _common("labels").pick(key, options)
    except Exception:
        body = {"k": key, "o": [[n, v] for n, v in options]}
        return SENTINEL + json.dumps(body, separators=(",", ":"))


# ============================================================================================
#  the runner contract
# ============================================================================================

def signals(questions, files) -> float:
    """0..1: how much a delivery and its questions look like pcap credential material.  A capture
    among the files is worth 0.4; the share of questions that name a credential-material word adds
    up to 0.6.  Without a capture only the strong words count, up to 0.3."""
    try:
        caps = bool(find_captures(files or {}))
    except Exception:
        caps = False
    qs = list(questions or [])
    texts = [_qtext(q) for q in qs]
    strong = sum(1 for t in texts if any(rx.search(t) for _f, rx in _SELECTORS)
                 or _NTLM_ANY.search(t) or _KRB_ANY.search(t) or _HASHCAT_ANY.search(t))
    share = (strong / len(texts)) if texts else 0.0
    if caps:
        return round(0.4 + 0.6 * share, 3)
    return round(0.3 * share, 3)


_cache = OrderedDict()            # (length, SHA-256 of all bytes) -> extracted hashes


def _extract_cached(name, data):
    # Full-content identity: a reused Python id or two same-length captures with matching ends must
    # never borrow credential material from a different middle.  SHA-256 is only an internal cache
    # identity (not an answer/protocol hash) and is recomputed from the exact delivery bytes.
    raw = bytes(data)
    k = (len(raw), hashlib.sha256(raw).digest())
    hit = _cache.get(k)
    if hit is None:
        hit = _cache[k] = extract(raw)
        while len(_cache) > 8:
            _cache.popitem(last=False)
    return hit


def _all_hashes(files) -> list:
    hashes = []
    for name, data in find_captures(files or {}):
        try:
            hashes += _extract_cached(name, data)
        except Exception:
            pass
    return hashes


def ownership(questions, files) -> dict:
    """{qid: [exact rendering values]} for complete credential facts owned by this specialist.

    The matcher hashes these values and uses them only to resolve an equal-coverage collision where
    every tied reader answers the same ids with an overlapping value.  An incomplete handshake,
    secret/cracking question, ambiguity, malformed capture or unrelated packet question claims
    nothing, so ordinary network routing and exact-tie refusal remain unchanged.
    """
    hashes = _all_hashes(files)
    out = {}
    for q in questions or []:
        try:
            fact = _fact_for(q, hashes) if hashes else None
            values = [value for _method, value in renderings(fact)] if fact is not None else []
        except Exception:
            values = []
        if values:
            qid = q.get("qid") or q.get("id") or q.get("answer_id")
            if qid is not None:
                out[qid] = values
    return out


def solve_set(questions, files, ctx) -> dict:
    out = {}
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    hashes = _all_hashes(files)
    for q in questions or []:
        qid = q.get("qid") or q.get("id")
        try:
            ans = _answer_for(q, hashes) if hashes else None
        except Exception:
            ans = None
        out[qid] = ans
        if partial is not None and ans is not None:
            partial[qid] = ans
    return out


def covers(questions) -> list:
    """The ids this toolkit would answer (plain or unsure) given a capture in the delivery.  Used
    by the runner only; it never gates a clock (CONTRACT line)."""
    return []


# ============================================================================================
#  the command and the in-file selftest
# ============================================================================================

def _triage(name, data) -> dict:
    hashes = _extract_cached(name, data)
    rows = []
    for h in hashes:
        rows.append({"field": h["field"], "mode": h["mode"],
                     "rendering": renderings(h)[0][1]})
    return {"capture": name, "credential_material": rows}


def main(argv) -> int:
    flags = {a for a in argv if a.startswith("--")}
    if "--selftest" in flags:
        return 0 if _selftest() else 1
    if "--attempt" in flags:
        i = argv.index("--attempt")
        if i + 1 >= len(argv):
            print("pcap_creds.py: --attempt needs a folder", file=sys.stderr)
            return 2
        tools = str(ROOT / "tools")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        import run
        folder = Path(argv[i + 1]).resolve()
        att, blobs, _ = run.load_offline(folder.name, str(folder))
        for n, qs, files, ctx in run.split_sets(att, blobs, [], []):
            print("## set %s: signals %s" % (n, signals(qs, files)))
            ans = solve_set(qs, files, ctx)
            for q in qs:
                qid = q.get("qid") or q.get("id")
                print("- %s: %s" % (qid, _clip(ans.get(qid))))
        return 0
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    code = 0
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print("pcap_creds.py: %s: %s" % (p, e), file=sys.stderr)
            code = 1
            continue
        if not is_capture(data):
            print("pcap_creds.py: %s: not a pcap/pcapng" % p, file=sys.stderr)
            code = 1
            continue
        t = _triage(Path(p).name, data)
        if "--json" in flags:
            print(json.dumps(t, indent=1))
        else:
            print("# %s" % t["capture"])
            if not t["credential_material"]:
                print("  (no credential material)")
            for r in t["credential_material"]:
                print("  %s (mode %s): %s" % (r["field"], r["mode"], _clip(r["rendering"], 160)))
    return code


def _clip(s, n=200):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n - 3] + "..."


# -- the crafted-pcap selftest (also driven by tests/test_GAP_PCAP_CREDS.py) -----------------

def _pcap_wrap(linktype, packets) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for pkt in packets:
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


def build_eapol_pcap(essid=b"HuntNet", bssid=b"\x00\x11\x22\x33\x44\x55",
                     sta=b"\xaa\xbb\xcc\xdd\xee\xff", drop_m2=False):
    """A minimal radiotap+Dot11 capture: beacon (ESSID), M1 (ANonce), M2 (SNonce+MIC)."""
    anonce = bytes(range(32))
    snonce = bytes(range(32, 64))
    mic = bytes.fromhex("00112233445566778899aabbccddeeff")
    replay1 = (1).to_bytes(8, "big")

    def radiotap():
        return struct.pack("<BBH I", 0, 0, 8, 0)      # version, pad, len=8, present=0

    def dot11_data(from_ds, src, dst, bssid_, payload):
        fc = struct.pack("<BB", 0x08, 0x02 if from_ds else 0x01)   # data, FromDS/ToDS
        dur = b"\x00\x00"
        if from_ds:
            a1, a2, a3 = dst, src, bssid_
        else:
            a1, a2, a3 = bssid_, src, bssid_
        seq = b"\x00\x00"
        snap = b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", EAPOL_ETHERTYPE)
        return radiotap() + fc + dur + a1 + a2 + a3 + seq + snap + payload

    def eapol_key(keyinfo, nonce, mic_bytes, replay):
        body = bytearray()
        body += b"\x02"                                 # descriptor type: RSN
        body += struct.pack(">H", keyinfo)
        body += struct.pack(">H", 16)                   # key length
        body += replay
        body += nonce
        body += b"\x00" * 16                            # key IV
        body += b"\x00" * 8                             # key RSC
        body += b"\x00" * 8                             # key ID
        body += mic_bytes
        body += struct.pack(">H", 0)                    # key data length
        hdr = struct.pack(">BBH", 2, 3, len(body))      # 802.1X v2, type 3, length
        return hdr + bytes(body)

    def beacon():
        fc = struct.pack("<BB", 0x80, 0x00)
        dur = b"\x00\x00"
        da = b"\xff\xff\xff\xff\xff\xff"
        seq = b"\x00\x00"
        fixed = b"\x00" * 8 + b"\x64\x00" + b"\x01\x04"
        ssid_ie = b"\x00" + bytes([len(essid)]) + essid
        return radiotap() + fc + dur + da + bssid + bssid + seq + fixed + ssid_ie

    m1_ki = 0x008a           # pairwise(0x08) + ACK(0x80) + key type bits
    m2_ki = 0x010a           # pairwise(0x08) + MIC(0x100)
    m1 = dot11_data(True, bssid, sta, bssid, eapol_key(m1_ki, anonce, b"\x00" * 16, replay1))
    m2 = dot11_data(False, sta, bssid, bssid, eapol_key(m2_ki, snonce, mic, replay1))
    pkts = [beacon(), m1] + ([] if drop_m2 else [m2])
    expect = None
    if not drop_m2:
        eapol_m2 = eapol_key(m2_ki, snonce, b"\x00" * 16, replay1)   # MIC zeroed in the field
        expect = "WPA*02*%s*%s*%s*%s*%s*%s*00" % (
            mic.hex(), bssid.hex(), sta.hex(), essid.hex(), anonce.hex(), eapol_m2.hex())
    return _pcap_wrap(127, pkts), expect


def _eth_ipv4(proto, src, dst, sport, dport, payload, tcp=True):
    if tcp:
        l4 = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18, 8192, 0, 0) + payload
    else:
        l4 = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    sip = bytes(int(x) for x in src.split("."))
    dip = bytes(int(x) for x in dst.split("."))
    total = 20 + len(l4)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, proto, 0) + sip + dip
    eth = b"\x11\x22\x33\x44\x55\x66" + b"\x66\x55\x44\x33\x22\x11" + struct.pack(">H", 0x0800)
    return eth + ip + l4


def build_ntlmv2_pcap():
    """SMB-style raw NTLMSSP: a type-2 CHALLENGE then a type-3 AUTHENTICATE (NTLMv2)."""
    challenge = bytes.fromhex("1122334455667788")
    t2 = bytearray(NTLMSSP_SIG + struct.pack("<I", 2))
    t2 += struct.pack("<HHI", 0, 0, 0)               # target name sec-buf
    t2 += struct.pack("<I", 0x00000001)              # flags: unicode
    t2 += challenge                                  # server challenge (offset 24)
    t2 += b"\x00" * 8                                # reserved

    user = "Administrator".encode("utf-16-le")
    domain = "CORP".encode("utf-16-le")
    ntproof = bytes.fromhex("aabbccddeeff00112233445566778899")
    blob = bytes.fromhex("01010000000000000a0b0c0d0e0f1011") + b"\x00" * 8 + bytes.fromhex("deadbeef")
    nt = ntproof + blob

    base_hdr = 64
    lm_off = base_hdr
    nt_off = lm_off + 0
    dom_off = nt_off + len(nt)
    usr_off = dom_off + len(domain)
    ws_off = usr_off + len(user)
    t3 = bytearray(NTLMSSP_SIG + struct.pack("<I", 3))
    t3 += struct.pack("<HHI", 0, 0, lm_off)                        # LM response (empty)
    t3 += struct.pack("<HHI", len(nt), len(nt), nt_off)            # NT response
    t3 += struct.pack("<HHI", len(domain), len(domain), dom_off)   # domain
    t3 += struct.pack("<HHI", len(user), len(user), usr_off)       # user
    t3 += struct.pack("<HHI", 0, 0, ws_off)                        # workstation
    t3 += struct.pack("<HHI", 0, 0, ws_off)                        # session key
    t3 += struct.pack("<I", 0x00000001)                            # flags: unicode
    assert len(t3) == base_hdr, len(t3)
    t3 += nt + domain + user

    pkts = [
        _eth_ipv4(6, "10.0.0.2", "10.0.0.5", 445, 50000, bytes(t2), tcp=True),
        _eth_ipv4(6, "10.0.0.5", "10.0.0.2", 50000, 445, bytes(t3), tcp=True),
    ]
    expect = "%s::%s:%s:%s:%s" % ("Administrator", "CORP", challenge.hex(), ntproof.hex(), blob.hex())
    return _pcap_wrap(1, pkts), expect


def build_kerberos_asrep_pcap():
    """A Kerberos AS-REP (etype 23) over UDP/88, hand-built DER."""
    def tlv(tag, body):
        return bytes([tag]) + _der_len(len(body)) + body

    def ctx(n, inner):
        return tlv(0xA0 | n, inner)

    def integer(v):
        b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
        return tlv(0x02, b)

    def gstr(s):
        return tlv(0x1B, s.encode())

    def seq(body):
        return tlv(0x30, body)

    realm = "CORP.LOCAL"
    user = "svc_web"
    cipher = bytes.fromhex("00112233445566778899aabbccddeeff") + bytes(range(40))  # 16-byte sum + edata

    name_string = seq(gstr(user))
    cname = seq(ctx(0, integer(1)) + ctx(1, name_string))
    encdata = seq(ctx(0, integer(23)) + ctx(2, tlv(0x04, cipher)))
    ticket_inner = seq(ctx(0, integer(5)) + ctx(1, gstr(realm))
                       + ctx(2, seq(ctx(0, integer(2)) + ctx(1, seq(gstr("krbtgt") + gstr(realm)))))
                       + ctx(3, seq(ctx(0, integer(23)) + ctx(2, tlv(0x04, bytes(20))))))
    ticket = tlv(0x61, ticket_inner)
    kdc_rep = seq(
        ctx(0, integer(5))
        + ctx(1, integer(11))
        + ctx(3, gstr(realm))
        + ctx(4, cname)
        + ctx(5, ticket)
        + ctx(6, encdata))
    as_rep = tlv(0x6B, kdc_rep)

    pkt = _eth_ipv4(17, "10.0.0.9", "10.0.0.1", 88, 40000, as_rep, tcp=False)
    expect = "$krb5asrep$23$%s@%s:%s$%s" % (user, realm, cipher[:16].hex(), cipher[16:].hex())
    return _pcap_wrap(1, [pkt]), expect


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        print("%s %s" % ("PASS" if cond else "FAIL", name))
        ok = ok and cond

    # WPA / EAPOL 22000
    cap, expect = build_eapol_pcap()
    hs = extract(cap)
    wpa = [h for h in hs if h["field"] == "wpa_hashcat"]
    check("eapol: one WPA handshake extracted", len(wpa) == 1)
    if wpa:
        check("eapol: rendering equals expected 22000 line", renderings(wpa[0])[0][1] == expect)
    q = {"qid": "q1", "question": "Provide the hashcat 22000 hash of the captured WPA handshake."}
    ans = solve_set([q], {"wifi.pcap": cap}, {})["q1"]
    check("eapol: answered as an unsure pick (never plain)", _is_unsure_for(ans, expect))

    # missing M2 -> None
    cap2, _ = build_eapol_pcap(drop_m2=True)
    hs2 = extract(cap2)
    check("eapol: no M2 -> nothing extracted", not [h for h in hs2 if h["field"] == "wpa_hashcat"])
    ans2 = solve_set([q], {"wifi.pcap": cap2}, {})["q1"]
    check("eapol: no M2 -> None", ans2 is None)

    # NTLMv2 5600
    capn, expectn = build_ntlmv2_pcap()
    hsn = extract(capn)
    v2 = [h for h in hsn if h["field"] == "netntlmv2_hashcat"]
    check("ntlmv2: one net-NTLMv2 extracted", len(v2) == 1)
    if v2:
        check("ntlmv2: rendering equals expected 5600 line", renderings(v2[0])[0][1] == expectn)
    qn = {"qid": "n1", "question": "Give the Net-NTLMv2 hash for the authentication, in hashcat format."}
    ansn = solve_set([qn], {"smb.pcap": capn}, {})["n1"]
    check("ntlmv2: answered as an unsure pick", _is_unsure_for(ansn, expectn))

    # Kerberos AS-REP 18200
    capk, expectk = build_kerberos_asrep_pcap()
    hsk = extract(capk)
    asrep = [h for h in hsk if h["field"] == "krb5asrep_hashcat"]
    check("kerberos: one AS-REP (etype 23) extracted", len(asrep) == 1)
    if asrep:
        check("kerberos: rendering equals expected 18200 line", renderings(asrep[0])[0][1] == expectk)
    qk = {"qid": "k1", "question": "What is the hashcat krb5asrep hash from the AS-REP?"}
    ansk = solve_set([qk], {"krb.pcap": capk}, {})["k1"]
    check("kerberos: answered as an unsure pick", _is_unsure_for(ansk, expectk))

    # the cracked secret is never a byte-fact: None
    qp = {"qid": "p1", "question": "What is the WiFi password / PSK recovered from the handshake?"}
    ansp = solve_set([qp], {"wifi.pcap": cap}, {})["p1"]
    check("secret: password question -> None (never derived or submitted)", ansp is None)

    return ok


def _is_unsure_for(ans, expect):
    """True iff `ans` is an unsure pick (never plain) whose first rendering is `expect`."""
    if not isinstance(ans, str) or not ans.startswith(SENTINEL):
        return False
    try:
        body = json.loads(ans[len(SENTINEL):])
        opts = body.get("o") or []
        return bool(opts) and opts[0][1] == expect
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
