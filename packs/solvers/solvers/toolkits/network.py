#!/usr/bin/env python3
"""Network forensics toolkit (backlog row 83, toolkit key "network"): packet captures read in
plain Python, for a lane no shipped solver plays.

  .venv/bin/python solvers/toolkits/network.py <capture>...            triage of each capture
  .venv/bin/python solvers/toolkits/network.py --json <capture>        the same as JSON
  .venv/bin/python solvers/toolkits/network.py --all <capture>         no row limit per section
  .venv/bin/python solvers/toolkits/network.py --carve DIR <capture>   write the carved objects to DIR
  .venv/bin/python solvers/toolkits/network.py --attempt <attempt dir> every question: field, candidates, answer
  .venv/bin/python solvers/toolkits/network.py --tshark <capture> -- -q -z conv,tcp     tshark in the sandbox

Offline: no Game Master request, no token. Nothing here starts a process except --tshark and the
tshark_* functions, which go through tools/sandbox.py (down means not read, never a native run)
and are never called by solve_set. The timed path is this file's own reader; only an exact matching
TCP/TLS ClientHello + shipped TLS key log lazily loads the bounded in-process common TLS reader.

Readers (each takes a Capture, the bytes of one, or a path):
  read(x)             pcap (micro and nanosecond, both byte orders) and pcapng (sections, interfaces
                      with their own link type and time resolution, enhanced/simple/old packet
                      blocks, packet comments, name-resolution blocks, decryption-secrets blocks);
                      Ethernet with VLAN tags, Linux cooked v1 and v2, null/loop, raw IP, IPv4, IPv6
                      with extension headers, TCP, UDP, ICMP, ICMPv6, ARP, three USB link types
  times, protocols, conversations, endpoints, streams, conns, banners
  dns, dhcp           queries and answers (UDP and TCP, name compression), DHCP host names
  http                requests paired with responses (Content-Length, chunked, gzip/deflate/br)
  tls, certs          ClientHello SNI, ALPN, JA3, JA4; ServerHello JA3S; the certificates sent
  credentials         FTP, POP3, IMAP, SMTP AUTH, Telnet, HTTP Basic and form posts
  ntlm, http_digest   NTLMSSP Type 1/2/3 and HTTP Digest auth metadata (user, domain, workstation, target
                      name, server challenge, negotiated flags, AV pairs), the NetNTLM hash as a candidate
  ftp, smtp, telnet, tftp
  objects             carved files with their hashes: HTTP bodies and uploads, FTP data, SMTP
                      attachments, TFTP
  icmp_payloads, dns_tunnel, hidden    covert-channel material and its plain decodings
  beacons             periodic connections, queries and requests with their interval
  syn_scan, open_ports
  usb_keystrokes      HID boot-keyboard reports to text
  modbus              Modbus/TCP requests and responses
  field, bitstream    one value per packet (ip_id, ttl, tcp_urg, ...) and bits to bytes
  tshark, tshark_fields, tshark_objects   the sandbox's tshark, off the timed path
  find_keylog, tls_decrypt, tls_decrypt_bundle   TLS/QUIC decrypt with a key log shipped in the
                      delivery (an SSLKEYLOG member or a pcapng decryption-secrets block), via the
                      sandbox's tshark (tls.keylog_file); off the timed path, never in solve_set
  solve_set native TLS   TLS 1.2/1.3 over TCP plus an exact matching shipped key-log entry; strict
                      HTTP/1.x only, fail-closed, no process. HTTP/2 is detection-only; no QUIC.

signals(questions, files) -> 0..1 says how strongly a delivery and its questions look like network
forensics. solve_set(questions, files, ctx) is the runner contract. It never guesses (AGENTS.md,
"Uncertain answers"). Nothing of this category has been judged, so:

  - plain: the number of packets in the capture, the hash or size of a carved file the question
    names and whose transfer is whole, and whatever solvers/common/triage.py proves of a delivered
    file the question names;
  - labels.pick('network.<field>/<shape>', [(method, value), ...]) for a fact the capture
    establishes: the value is the only one of its kind in the capture (or among the packets of the
    address, port or name the question gives), or the first, last or most frequent one when the
    question asks for that. The method names how it was read and written (`raw`, `iso_z_seconds`,
    `colon_lower`), so one accepted method answers the same question on the next variant;
  - None for everything else: two candidates and no word to choose by, two readings that differ
    (queries against distinct names, first record against earliest time), a capture that was cut
    by the packet limit, a question that is not about the capture.

`network` is not a lane solvers/common/labels.py knows yet (its LANE_DIRS has five). Until it is
added there, an unsure answer is written in the same wire form by this file: gm.session() drops it
from any submission, and tools/verify.py finds nothing to probe in it.
"""
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

# The runner puts this folder first on sys.path; a sibling toolkit named like a standard module
# (email.py, struct.py) must not be imported in its place.
_saved_path = list(sys.path)
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != HERE]
import base64            # noqa: E402
import binascii          # noqa: E402
import bisect            # noqa: E402
import datetime          # noqa: E402
import email             # noqa: E402
import email.policy      # noqa: E402
import hashlib           # noqa: E402
import json              # noqa: E402
import re                # noqa: E402
import socket            # noqa: E402
import struct            # noqa: E402
import urllib.parse      # noqa: E402
import zlib              # noqa: E402
from collections import Counter, OrderedDict, defaultdict   # noqa: E402
sys.path[:] = _saved_path

KEY = "network"
MAX_PACKETS = 400_000           # solve_set reads at most this many packets; more is "truncated": no answer
MAX_RECORD = 16 * 1024 * 1024   # a packet record longer than this means the file is damaged
MAX_GUNZIP = 256 * 1024 * 1024
MAX_OPTIONS = 12
SENTINEL = "??"
ARROW = " -> "


class Rec(dict):
    """A record: a dict whose keys also read as attributes (missing ones are None)."""
    __getattr__ = dict.get

    def __setattr__(self, k, v):
        self[k] = v


# ---- the file --------------------------------------------------------------------------------------

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
              b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPES = {0: "null", 1: "ethernet", 12: "raw", 14: "raw", 101: "raw", 105: "ieee802_11", 108: "loop",
             113: "linux_sll", 127: "ieee802_11_radiotap", 189: "usb_linux", 220: "usb_linux_mmapped",
             228: "ipv4", 229: "ipv6", 249: "usbpcap", 276: "linux_sll2"}
USB_LINKS = (189, 220, 249)


def is_capture(data) -> bool:
    return isinstance(data, (bytes, bytearray)) and (bytes(data[:4]) in PCAP_MAGIC or (
        bytes(data[:4]) == PCAPNG_MAGIC and bytes(data[8:12]) in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d")))


def gunzip_capture(data):
    """The capture inside a gzip file (capture.pcap.gz), or None."""
    if not isinstance(data, (bytes, bytearray)) or bytes(data[:2]) != b"\x1f\x8b":
        return None
    try:
        d = zlib.decompressobj(47)
        head = d.decompress(bytes(data[:4096]), 64)
        if not is_capture(head + b"\x00" * 12 if len(head) < 12 else head):
            return None
        out = zlib.decompressobj(47).decompress(bytes(data), MAX_GUNZIP)
        return out if is_capture(out) else None
    except zlib.error:
        return None


class Pkt:
    """One packet. ts is nanoseconds since the epoch (None in a pcapng simple packet block)."""
    __slots__ = ("i", "ts", "link", "raw", "wire", "smac", "dmac", "etype", "vlan", "src", "dst", "proto", "ttl",
                 "ipid", "tos", "frag", "sport", "dport", "flags", "seq", "ack", "win", "urg", "payload", "itype",
                 "icode", "iid", "iseq", "arp", "usb", "comment")

    def __init__(self, i, ts, link, raw, wire):
        self.i, self.ts, self.link, self.raw, self.wire = i, ts, link, raw, wire
        self.smac = self.dmac = self.etype = self.vlan = self.src = self.dst = self.proto = self.ttl = None
        self.ipid = self.tos = self.sport = self.dport = self.flags = self.seq = self.ack = self.win = None
        self.urg = self.itype = self.icode = self.iid = self.iseq = self.arp = self.usb = self.comment = None
        self.frag = 0
        self.payload = b""

    def __repr__(self):
        return (f"<Pkt {self.i} {self.src}:{self.sport} > {self.dst}:{self.dport} proto={self.proto} "
                f"len={len(self.payload)}>")


def mac(b, sep=":", upper=False) -> str:
    s = sep.join(f"{x:02x}" for x in b)
    return s.upper() if upper else s


def _l4(p, raw, o, end):
    proto = p.proto
    if proto == 6:
        if end - o < 20:
            return
        p.sport, p.dport, p.seq, p.ack = struct.unpack_from("!HHII", raw, o)
        doff = (raw[o + 12] >> 4) * 4
        p.flags = raw[o + 13]
        p.win, _, p.urg = struct.unpack_from("!HHH", raw, o + 14)
        p.payload = raw[o + doff:end] if doff >= 20 else b""
    elif proto == 17:
        if end - o < 8:
            return
        p.sport, p.dport = struct.unpack_from("!HH", raw, o)
        p.payload = raw[o + 8:end]
    elif proto in (1, 58):
        if end - o < 4:
            return
        p.itype, p.icode = raw[o], raw[o + 1]
        if end - o >= 8:
            p.iid, p.iseq = struct.unpack_from("!HH", raw, o + 4)
        p.payload = raw[o + 8:end]
    else:
        p.payload = raw[o:end]


def _ip4(p, raw, o):
    if len(raw) < o + 20 or raw[o] >> 4 != 4:
        return
    ihl = (raw[o] & 15) * 4
    if ihl < 20:
        return
    tot = (raw[o + 2] << 8) | raw[o + 3]
    p.tos, p.ipid, p.ttl, p.proto = raw[o + 1], (raw[o + 4] << 8) | raw[o + 5], raw[o + 8], raw[o + 9]
    fo = (raw[o + 6] << 8) | raw[o + 7]
    p.src, p.dst = socket.inet_ntoa(raw[o + 12:o + 16]), socket.inet_ntoa(raw[o + 16:o + 20])
    end = o + tot if tot and o + tot <= len(raw) else len(raw)
    if fo & 0x1FFF:
        p.frag = 2              # a later fragment: no transport header in it
        p.payload = raw[o + ihl:end]
        return
    if fo & 0x2000:
        p.frag = 1
    _l4(p, raw, o + ihl, end)


def _ip6(p, raw, o):
    if len(raw) < o + 40 or raw[o] >> 4 != 6:
        return
    plen, nxt, p.ttl = (raw[o + 4] << 8) | raw[o + 5], raw[o + 6], raw[o + 7]
    p.tos = ((raw[o] & 15) << 4) | (raw[o + 1] >> 4)
    p.src = socket.inet_ntop(socket.AF_INET6, raw[o + 8:o + 24])
    p.dst = socket.inet_ntop(socket.AF_INET6, raw[o + 24:o + 40])
    end = o + 40 + plen if plen and o + 40 + plen <= len(raw) else len(raw)
    o += 40
    for _ in range(8):
        if nxt in (0, 43, 60) and o + 8 <= end:
            nxt, o = raw[o], o + (raw[o + 1] + 1) * 8
        elif nxt == 51 and o + 8 <= end:
            nxt, o = raw[o], o + (raw[o + 1] + 2) * 4
        elif nxt == 44 and o + 8 <= end:
            off = ((raw[o + 2] << 8) | raw[o + 3]) >> 3
            more = raw[o + 3] & 1
            nxt, o = raw[o], o + 8
            if off:
                p.frag, p.proto, p.payload = 2, nxt, raw[o:end]
                return
            if more:
                p.frag = 1
        else:
            break
    p.proto = nxt
    _l4(p, raw, o, end)


def _usb(p, link, raw):
    try:
        if link in (189, 220):
            hdr = 64 if link == 220 else 48
            if len(raw) < hdr:
                return
            etype, xfer, ep, dev, bus = raw[8], raw[9], raw[10], raw[11], struct.unpack_from("<H", raw, 12)[0]
            p.usb = Rec(bus=bus, device=dev, endpoint=ep & 0x7F, incoming=bool(ep & 0x80), transfer=xfer,
                        event=chr(etype), data=raw[hdr:])
        else:
            hlen = struct.unpack_from("<H", raw, 0)[0]
            if hlen < 27 or len(raw) < hlen:
                return
            info, bus, dev, ep, xfer = raw[16], *struct.unpack_from("<HH", raw, 17), raw[21], raw[22]
            # USBPcap numbers transfers 0 isochronous, 1 interrupt, 2 control, 3 bulk, as usbmon does
            p.usb = Rec(bus=bus, device=dev, endpoint=ep & 0x7F, incoming=bool(ep & 0x80), transfer=xfer,
                        event="C" if info & 1 else "S", data=raw[hlen:])
    except (struct.error, IndexError):
        return


def _decode(p, link, raw):
    o, et = 0, None
    n = len(raw)
    if link == 1:
        if n < 14:
            return
        p.dmac, p.smac = raw[0:6], raw[6:12]
        et, o = (raw[12] << 8) | raw[13], 14
        while et in (0x8100, 0x88A8, 0x9100) and n >= o + 4:
            p.vlan = ((raw[o] << 8) | raw[o + 1]) & 0x0FFF
            et, o = (raw[o + 2] << 8) | raw[o + 3], o + 4
    elif link == 113:
        if n < 16:
            return
        if raw[4] == 0 and raw[5] == 6:
            p.smac = raw[6:12]
        et, o = (raw[14] << 8) | raw[15], 16
    elif link == 276:
        if n < 20:
            return
        if raw[11] == 6:
            p.smac = raw[12:18]
        et, o = (raw[0] << 8) | raw[1], 20
    elif link in (0, 108):
        if n < 4:
            return
        fam = int.from_bytes(raw[:4], "big" if link == 108 else "little")
        if fam > 0xFFFF:
            fam = int.from_bytes(raw[:4], "little" if link == 108 else "big")
        et, o = (0x0800 if fam == 2 else 0x86DD if fam in (10, 24, 28, 30) else None), 4
    elif link in (12, 14, 101, 228, 229):
        if not n:
            return
        et = 0x0800 if raw[0] >> 4 == 4 else 0x86DD if raw[0] >> 4 == 6 else None
    elif link in USB_LINKS:
        _usb(p, link, raw)
        return
    else:
        return
    p.etype = et
    if et == 0x0800:
        _ip4(p, raw, o)
    elif et == 0x86DD:
        _ip6(p, raw, o)
    elif et == 0x0806 and n >= o + 28:
        op = (raw[o + 6] << 8) | raw[o + 7]
        p.arp = Rec(op=op, sha=raw[o + 8:o + 14], spa=socket.inet_ntoa(raw[o + 14:o + 18]),
                    tha=raw[o + 18:o + 24], tpa=socket.inet_ntoa(raw[o + 24:o + 28]))


def _opts(body, off, e):
    out, end = [], len(body)
    while off + 4 <= end:
        code, ln = struct.unpack_from(e + "HH", body, off)
        off += 4
        if code == 0 or off + ln > end:
            break
        out.append((code, body[off:off + ln]))
        off += (ln + 3) & ~3
    return out


def _txt(b) -> str:
    return bytes(b).decode("utf-8", "replace").rstrip("\x00")


def _memo(fn):
    def wrap(self):
        c = self._cache
        if fn.__name__ not in c:
            c[fn.__name__] = fn(self)
        return c[fn.__name__]
    wrap.__name__, wrap.__doc__ = fn.__name__, fn.__doc__
    return wrap


class Capture:
    """A parsed capture. `packets` holds every record; the analyses are computed on first use."""

    def __init__(self, data: bytes, name: str = "", limit=None):
        self.name, self.size = name, len(data)
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.format = None          # 'pcap' or 'pcapng'
        self.packets = []
        self.linktypes = Counter()
        self.damaged = None         # why reading stopped early (a cut record); None for a whole file
        self.truncated = False      # True when `limit` stopped the read: facts about "the capture" are not known
        self.comments = []          # [(packet index or None, text)] of pcapng comments
        self.secrets = []           # [(type, bytes)] of pcapng decryption-secrets blocks (a TLS key log)
        self.names = []             # [(address, name)] of pcapng name-resolution blocks
        self.meta = {}              # section and interface options: hardware, os, application, interface names
        self._cache = {}
        data = bytes(data)
        if data[:4] in PCAP_MAGIC:
            self._pcap(data, limit)
        elif data[:4] == PCAPNG_MAGIC:
            self._pcapng(data, limit)
        else:
            raise ValueError("not a pcap or pcapng file")

    def _add(self, ts, link, raw, wire):
        p = Pkt(len(self.packets), ts, link, raw, wire)
        try:
            _decode(p, link, raw)
        except (struct.error, IndexError, OSError, ValueError):
            pass
        self.packets.append(p)
        self.linktypes[link] += 1
        return p

    def _pcap(self, data, limit):
        self.format = "pcap"
        e, mult = PCAP_MAGIC[data[:4]]
        if len(data) < 24:
            self.damaged = "the file header is cut"
            return
        vmaj, vmin, _, _, snap, link = struct.unpack_from(e + "HHiIII", data, 4)
        link &= 0x0FFFFFFF
        self.meta.update(version=f"{vmaj}.{vmin}", snaplen=snap, linktype=link, nanosecond=mult == 1)
        off, n = 24, len(data)
        unpack = struct.Struct(e + "IIII").unpack_from
        while off < n:
            if limit is not None and len(self.packets) >= limit:
                self.truncated = True
                return
            if off + 16 > n:
                self.damaged = f"record header cut at byte {off}"
                return
            sec, frac, cap, wire = unpack(data, off)
            if cap > MAX_RECORD:
                self.damaged = f"record of {cap} bytes at byte {off}"
                return
            if off + 16 + cap > n:
                self.damaged = f"record cut at byte {off}"
                return
            self._add(sec * 1_000_000_000 + frac * mult, link, data[off + 16:off + 16 + cap], wire)
            off += 16 + cap

    def _pcapng(self, data, limit):
        self.format = "pcapng"
        off, n, e, ifaces = 0, len(data), "<", []
        while off + 12 <= n:
            if data[off:off + 4] == PCAPNG_MAGIC:
                bom = data[off + 8:off + 12]
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
                if e is None:
                    self.damaged = f"section header without a byte-order mark at byte {off}"
                    return
                ifaces = []
            btype, blen = struct.unpack_from(e + "II", data, off)
            if blen < 12 or blen % 4 or off + blen > n:
                self.damaged = f"block cut at byte {off}"
                return
            body = data[off + 8:off + blen - 4]
            off += blen
            if btype == 0x0A0D0D0A:
                for code, v in _opts(body, 16, e):
                    key = {1: "comment", 2: "hardware", 3: "os", 4: "application"}.get(code)
                    if key == "comment":
                        self.comments.append((None, _txt(v)))
                    elif key:
                        self.meta[key] = _txt(v)
            elif btype == 1 and len(body) >= 8:
                link, _, snap = struct.unpack_from(e + "HHI", body, 0)
                mult, div, tsoff = 1000, 1, 0
                for code, v in _opts(body, 8, e):
                    if code == 9 and v:
                        if v[0] & 0x80:
                            mult, div = 1_000_000_000, 1 << (v[0] & 0x7F)
                        elif v[0] <= 9:
                            mult, div = 10 ** (9 - v[0]), 1
                        else:
                            mult, div = 1, 10 ** (v[0] - 9)
                    elif code == 14 and len(v) >= 8:
                        tsoff = struct.unpack_from(e + "q", v, 0)[0]
                    elif code in (2, 3, 12):
                        self.meta.setdefault("interfaces", []).append(
                            ({2: "name", 3: "description", 12: "os"}[code], _txt(v)))
                ifaces.append((link, snap, mult, div, tsoff))
            elif btype in (6, 2, 3):
                if limit is not None and len(self.packets) >= limit:
                    self.truncated = True
                    return
                try:
                    if btype == 6:
                        ifid, hi, lo, cap, wire = struct.unpack_from(e + "IIIII", body, 0)
                        start = 20
                    elif btype == 2:
                        ifid, _, hi, lo, cap, wire = struct.unpack_from(e + "HHIIII", body, 0)
                        start = 20
                    else:
                        ifid, wire = 0, struct.unpack_from(e + "I", body, 0)[0]
                        start, hi, lo = 4, None, None
                        snap = ifaces[0][1] if ifaces else 0
                        cap = min(wire, snap or wire, len(body) - 4)
                    link, _, mult, div, tsoff = ifaces[ifid]
                except (struct.error, IndexError):
                    self.damaged = f"packet block before {off} cannot be read"
                    return
                ts = None if hi is None else ((hi << 32) | lo) * mult // div + tsoff * 1_000_000_000
                p = self._add(ts, link, body[start:start + cap], wire)
                if btype == 6:
                    for code, v in _opts(body, start + ((cap + 3) & ~3), e):
                        if code == 1:
                            p.comment = _txt(v)
                            self.comments.append((p.i, p.comment))
            elif btype == 0x0A and len(body) >= 8:
                stype, slen = struct.unpack_from(e + "II", body, 0)
                self.secrets.append((stype, body[8:8 + slen]))
            elif btype == 4:
                o = 0
                while o + 4 <= len(body):
                    rtype, rlen = struct.unpack_from(e + "HH", body, o)
                    o += 4
                    if rtype == 0 or o + rlen > len(body):
                        break
                    v = body[o:o + rlen]
                    o += (rlen + 3) & ~3
                    try:
                        if rtype == 1 and rlen > 4:
                            addr, rest = socket.inet_ntoa(v[:4]), v[4:]
                        elif rtype == 2 and rlen > 16:
                            addr, rest = socket.inet_ntop(socket.AF_INET6, v[:16]), v[16:]
                        else:
                            continue
                    except (OSError, ValueError):
                        continue
                    for nm in rest.split(b"\x00"):
                        if nm:
                            self.names.append((addr, _txt(nm)))
        if off != n and self.damaged is None:
            self.damaged = f"{n - off} bytes after the last block"

    # ---- the frame of the capture ---------------------------------------------------------------

    @_memo
    def times(self):
        """first/last: the first and last record's time; earliest/latest: by value. Nanoseconds."""
        ts = [p.ts for p in self.packets if p.ts is not None]
        if not ts:
            return Rec(first=None, last=None, earliest=None, latest=None, duration=None, ordered=True)
        return Rec(first=ts[0], last=ts[-1], earliest=min(ts), latest=max(ts), duration=max(ts) - min(ts),
                   ordered=all(a <= b for a, b in zip(ts, ts[1:])))

    @_memo
    def protocols(self):
        c = Counter()
        l3 = {0x0800: "ipv4", 0x86DD: "ipv6", 0x0806: "arp"}
        l4 = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 2: "igmp", 47: "gre", 50: "esp", 132: "sctp"}
        for p in self.packets:
            if p.usb is not None:
                c["usb"] += 1
            elif p.etype in l3:
                c[l3[p.etype]] += 1
                if p.proto is not None:
                    c[l4.get(p.proto, f"ip-proto-{p.proto}")] += 1
            else:
                c["other"] += 1
        return c

    @_memo
    def conversations(self):
        """[Rec(a, b, proto, aport, bport, packets, bytes, a_to_b, b_to_a, first, last)], most packets
        first. a is the sender of the conversation's first packet."""
        conv = OrderedDict()
        for p in self.packets:
            if p.src is None:
                continue
            k = (p.src, p.sport, p.dst, p.dport, p.proto)
            r = (p.dst, p.dport, p.src, p.sport, p.proto)
            c = conv.get(k) or conv.get(r)
            if c is None:
                c = conv[k] = Rec(a=p.src, aport=p.sport, b=p.dst, bport=p.dport, proto=p.proto, packets=0,
                                  bytes=0, a_to_b=0, b_to_a=0, first=p.ts, last=p.ts)
            c.packets += 1
            c.bytes += p.wire
            if p.src == c.a and p.sport == c.aport:
                c.a_to_b += 1
            else:
                c.b_to_a += 1
            c.last = p.ts
        return sorted(conv.values(), key=lambda c: -c.packets)

    @_memo
    def endpoints(self):
        """{address: Rec(sent, received, bytes_sent, bytes_received, macs)}"""
        out = OrderedDict()
        for p in self.packets:
            if p.src is None:
                continue
            s = out.setdefault(p.src, Rec(sent=0, received=0, bytes_sent=0, bytes_received=0, macs=[]))
            d = out.setdefault(p.dst, Rec(sent=0, received=0, bytes_sent=0, bytes_received=0, macs=[]))
            s.sent += 1
            s.bytes_sent += p.wire
            d.received += 1
            d.bytes_received += p.wire
            if p.smac is not None and p.smac not in s.macs:
                s.macs.append(p.smac)
        return out

    def macs_of(self, ip) -> list:
        """The hardware addresses seen as the sender of ip's packets, and in ARP for it."""
        out = []
        for p in self.packets:
            m = p.smac if p.src == ip else p.arp.sha if p.arp is not None and p.arp.spa == ip else None
            if m is not None and m not in out:
                out.append(m)
        return out

    # ---- TCP -------------------------------------------------------------------------------------

    @_memo
    def streams(self):
        """{(src, sport, dst, dport, generation): Rec(data, marks, gaps, syn, fin, first, ...)}: one
        direction of one TCP connection, its payload in sequence order, retransmissions dropped.
        marks is [(offset, time)] per segment; gaps counts the holes (bytes never captured)."""
        segs, info, gen, last_syn = defaultdict(list), OrderedDict(), defaultdict(int), {}
        for p in self.packets:
            if p.proto != 6 or p.sport is None or p.frag == 2:
                continue
            four = (p.src, p.sport, p.dst, p.dport)
            pair = four if four <= (p.dst, p.dport, p.src, p.sport) else (p.dst, p.dport, p.src, p.sport)
            if p.flags & 2 and not p.flags & 16:
                if four in last_syn and last_syn[four] != p.seq:
                    gen[pair] += 1          # the same ports in a new connection
                last_syn[four] = p.seq
            k = four + (gen[pair],)
            st = info.get(k)
            if st is None:
                st = info[k] = Rec(src=p.src, sport=p.sport, dst=p.dst, dport=p.dport, gen=gen[pair], first=p.ts,
                                   last=p.ts, syn=None, synack=False, fin=False, rst=False, packets=0, isn=None)
            st.packets += 1
            st.last = p.ts
            if p.flags & 2 and st.isn is None:
                st.isn = p.seq
                st.syn = True
                st.synack = bool(p.flags & 16)
            if p.flags & 1:
                if not st.fin:
                    st.fin_seq = (p.seq + len(p.payload or b"")) & 0xFFFFFFFF
                st.fin = True
            if p.flags & 4:
                st.rst = True
            if p.payload:
                segs[k].append((p.seq, p.ts, p.payload))
        for k, st in info.items():
            s = segs.get(k, [])
            if st.isn is not None:
                base = (st.isn + 1) & 0xFFFFFFFF
            elif s:
                base = s[0][0]
            else:
                base = 0
            rel = []
            for seq, ts, d in s:
                r = (seq - base) & 0xFFFFFFFF
                rel.append((r - (1 << 32) if r >= 1 << 31 else r, ts if ts is not None else 0, d))
            if rel and st.isn is None:
                low = min(r for r, _, _ in rel)
                rel = [(r - low, ts, d) for r, ts, d in rel]
            if st.isn is None and len(s) > 1 and s[0][2] == b"\x00" and s[1][0] == (s[0][0] + 1) & 0xFFFFFFFF:
                # a capture that starts inside a connection, on a TCP keep-alive: one zero byte at the
                # sequence number before the next real one (seen in a real capture: "\x00GET /...")
                rel = [(r - 1, ts, d) for r, ts, d in rel if r > 0 or d != b"\x00"]
                st.keepalive = True
            rel.sort(key=lambda x: (x[0], x[1]))
            buf, marks, gaps, pos, conflicts = bytearray(), [], 0, 0, 0
            for r, ts, d in rel:
                if r < 0:
                    d, r = d[-r:], 0
                if r > pos:
                    gaps += 1
                    pos = r
                if len(d) == 1 and r == pos - 1 and pos:
                    continue                    # a keep-alive probe: one byte at the last sequence number
                if r < pos and d:
                    # bytes sent twice: the same bytes are a retransmission, other bytes are two
                    # readings of the stream (which one the receiver kept is not in the capture)
                    held = pos - len(buf)       # the bytes of the holes before here
                    n = min(pos, r + len(d)) - r
                    if r - held < 0 or bytes(buf[r - held:r - held + n]) != d[:n]:
                        conflicts += 1
                if r + len(d) <= pos:
                    continue
                d = d[pos - r:]
                marks.append((len(buf), ts))
                buf += d
                pos += len(d)
            st.data, st.marks, st.gaps, st.conflicts = bytes(buf), marks, gaps, conflicts
            # whole: every byte from the SYN to the FIN is here once (nothing lost before the first
            # captured segment, between two, or between the last one and the FIN)
            st.whole = bool(st.isn is not None and st.fin and not gaps and not conflicts
                            and ((st.fin_seq - base) & 0xFFFFFFFF) == pos)
            st.sound = not gaps and not conflicts
            st.key = k
        return info

    def stream_time(self, st, offset):
        """When the byte at `offset` of a stream's data was captured."""
        if not st.marks:
            return st.first
        i = bisect.bisect_right([m[0] for m in st.marks], offset) - 1
        return st.marks[max(i, 0)][1]

    @_memo
    def conns(self):
        """[Rec(client, cport, server, sport, c, s, ts, handshake)]: TCP connections, the two
        directions paired. c is the client's stream (it sent the SYN; without one, the side talking
        to the lower port), s the server's; either can be None."""
        st = self.streams()
        out, seen = [], set()
        for k, a in st.items():
            if k in seen:
                continue
            rk = (k[2], k[3], k[0], k[1], k[4])
            b = st.get(rk)
            seen.update((k, rk))
            if b is None:
                a_client = not a.synack if a.syn else not (a.sport < 1024 <= a.dport)
            elif a.syn and not a.synack:
                a_client = True
            elif b.syn and not b.synack:
                a_client = False
            elif (a.dport < 1024) != (a.sport < 1024):
                a_client = a.dport < 1024
            else:
                a_client = (a.first or 0) <= (b.first or 0)
            c, s = (a, b) if a_client else (b, a)
            one = c or s
            out.append(Rec(client=one.src if c else one.dst, cport=one.sport if c else one.dport,
                           server=one.dst if c else one.src, sport=one.dport if c else one.sport, c=c, s=s,
                           ts=min(x.first for x in (a, b) if x is not None and x.first is not None) if (
                               a.first is not None or (b is not None and b.first is not None)) else None,
                           handshake=bool(c and c.syn and s and s.synack)))
        return out

    @_memo
    def banners(self):
        """[Rec(server, port, banner)]: the first printable line of a server that spoke first (SSH, FTP,
        SMTP, POP3, IMAP, ...)."""
        out = []
        for c in self.conns():
            if c.s is not None and c.s.data:
                line = c.s.data[:200].split(b"\n")[0].rstrip(b"\r")
                if line and all(32 <= x < 127 for x in line) and not line.startswith(b"HTTP/") and re.match(rb"[A-Za-z0-9+*-]", line) \
                        and (c.c is None or not c.c.marks or c.s.marks[0][1] <= c.c.marks[0][1] or line.startswith(b"SSH-")):
                    out.append(Rec(server=c.server, port=c.sport, client=c.client, banner=line.decode(), ts=c.ts))
        return out

    # ---- DNS and DHCP ----------------------------------------------------------------------------

    @_memo
    def dns(self):
        """[Rec(ts, src, dst, sport, dport, id, qr, rcode, qname, qtype, answers, proto)]; answers is
        [(name, type, value)]. proto is dns, mdns or llmnr. A retransmitted message appears once."""
        out, seen = [], set()

        def take(p_ts, src, dst, sport, dport, payload, proto):
            m = parse_dns(payload)
            if m is None:
                return
            sig = (src, sport, dst, dport, m.id, m.qr, m.qname, m.qtype, tuple(m.answers))
            if sig in seen:
                return
            seen.add(sig)
            m.update(ts=p_ts, src=src, dst=dst, sport=sport, dport=dport, proto=proto)
            out.append(m)

        for p in self.packets:
            if p.proto == 17 and p.payload and p.frag != 2:
                port = p.dport if p.dport in (53, 5353, 5355) else p.sport if p.sport in (53, 5353, 5355) else None
                if port:
                    take(p.ts, p.src, p.dst, p.sport, p.dport, p.payload, {53: "dns", 5353: "mdns", 5355: "llmnr"}[port])
        for st in self.streams().values():
            if 53 in (st.sport, st.dport) and st.data:
                o, d = 0, st.data
                while o + 2 <= len(d):
                    ln = (d[o] << 8) | d[o + 1]
                    if ln < 12 or o + 2 + ln > len(d):
                        break
                    take(self.stream_time(st, o), st.src, st.dst, st.sport, st.dport, d[o + 2:o + 2 + ln], "dns")
                    o += 2 + ln
        out.sort(key=lambda m: m.ts if m.ts is not None else 0)
        return out

    @_memo
    def dhcp(self):
        """[Rec(ts, mac, type, hostname, requested_ip, vendor, your_ip, client_ip)] of DHCP messages."""
        out = []
        for p in self.packets:
            d = p.payload
            if p.proto != 17 or not {p.sport, p.dport} & {67, 68} or len(d) < 240 or d[236:240] != b"\x63\x82\x53\x63":
                continue
            r = Rec(ts=p.ts, src=p.src, dst=p.dst, op=d[0], mac=d[28:34], client_ip=socket.inet_ntoa(d[12:16]),
                    your_ip=socket.inet_ntoa(d[16:20]))
            o = 240
            while o + 2 <= len(d) and d[o] != 255:
                if d[o] == 0:
                    o += 1
                    continue
                code, ln = d[o], d[o + 1]
                v = d[o + 2:o + 2 + ln]
                o += 2 + ln
                if code == 12:
                    r.hostname = _txt(v)
                elif code == 50 and ln == 4:
                    r.requested_ip = socket.inet_ntoa(v)
                elif code == 53 and ln == 1:
                    r.type = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak",
                              7: "release", 8: "inform"}.get(v[0], str(v[0]))
                elif code == 60:
                    r.vendor = _txt(v)
                elif code == 81 and ln > 3:
                    r.fqdn = _txt(v[3:])
            out.append(r)
        return out

    # ---- HTTP ------------------------------------------------------------------------------------

    @_memo
    def http(self):
        """[Rec(ts, src, dst, sport, dport, method, uri, url, host, user_agent, headers, body, status,
        resp_headers, resp_body, resp_raw, resp_complete, resp_encoded, content_type, server, filename)]:
        every request, with its response when one was captured. resp_body has the content coding
        removed (None when it could not be), resp_raw is the body as sent."""
        out = []
        for c in self.conns():
            cd = c.c.data if c.c is not None else b""
            sd = c.s.data if c.s is not None else b""
            if not (_REQ.match(cd) or _RESP.match(sd)):
                continue
            reqs = _http_messages(cd, _REQ) if cd else []
            resps = _http_messages(sd, _RESP, heads=[r.first[0] == "HEAD" for r in reqs]) if sd else []
            for i in range(max(len(reqs), len(resps))):
                q = reqs[i] if i < len(reqs) else None
                a = resps[i] if i < len(resps) else None
                r = Rec(src=c.client, sport=c.cport, dst=c.server, dport=c.sport,
                        ts=self.stream_time(c.c, q.offset) if q else self.stream_time(c.s, a.offset))
                if q:
                    host = q.h.get("host")
                    uri = q.first[1]
                    r.update(method=q.first[0], uri=uri, version=q.first[2], host=host, headers=q.headers,
                             user_agent=q.h.get("user-agent"), body=q.body, referer=q.h.get("referer"),
                             cookie=q.h.get("cookie"), authorization=q.h.get("authorization"),
                             req_content_type=q.h.get("content-type"),
                             url=uri if "://" in uri else (f"http://{host}{uri}" if host and uri.startswith("/") else None))
                if q:
                    r.req_complete = bool(q.complete and c.c.sound)
                if a:
                    complete = a.complete
                    if complete is None:        # delimited by the close of the connection
                        complete = bool(c.s.whole and i == len(resps) - 1)
                    if not c.s.sound:
                        complete = False
                    # A response is named by the request at the same place in the connection. That
                    # pairing holds only when both directions are here from their SYN with no hole:
                    # one lost request gives every later body the name of another file.
                    if c.c is None or c.c.isn is None or not c.c.sound or c.s.isn is None or q is None:
                        complete = False
                    enc = (a.h.get("content-encoding") or "").lower().strip()
                    body = _decode_content(a.body, enc) if enc and enc != "identity" else a.body
                    r.update(status=int(a.first[1]), resp_headers=a.headers, resp_raw=a.body, resp_body=body,
                             resp_complete=complete, resp_encoded=bool(enc and enc != "identity"),
                             content_type=a.h.get("content-type"), server=a.h.get("server"),
                             resp_ts=self.stream_time(c.s, a.offset),
                             disposition=_disposition_name(a.h.get("content-disposition")))
                if q:
                    path = urllib.parse.unquote(q.first[1].split("?")[0].split("#")[0])
                    r.filename = path.rstrip("/").rsplit("/", 1)[-1] or None
                out.append(r)
        out.sort(key=lambda r: r.ts if r.ts is not None else 0)
        return out

    # ---- TLS -------------------------------------------------------------------------------------

    @_memo
    def tls(self):
        """[Rec(ts, src, dst, sport, dport, sni, alpn, version, ja3, ja3_string, ja4, ciphers,
        extensions, ja3s, ja3s_string, server_version, cipher, certs)]: one per connection whose
        client stream starts with a ClientHello (or whose server stream starts with a ServerHello)."""
        out = []
        for c in self.conns():
            cd = c.c.data if c.c is not None else b""
            sd = c.s.data if c.s is not None else b""
            ch = sh = None
            certs = []
            if cd[:1] == b"\x16" and cd[1:2] == b"\x03":
                for t, body in _tls_handshakes(cd):
                    if t == 1:
                        ch = _client_hello(body)
                        break
            if sd[:1] == b"\x16" and sd[1:2] == b"\x03":
                for t, body in _tls_handshakes(sd):
                    if t == 2 and sh is None:
                        sh = _server_hello(body)
                    elif t == 11 and len(body) >= 3:
                        o, end = 3, min(len(body), 3 + int.from_bytes(body[:3], "big"))
                        while o + 3 <= end:
                            ln = int.from_bytes(body[o:o + 3], "big")
                            certs.append(body[o + 3:o + 3 + ln])
                            o += 3 + ln
            if ch is None and sh is None:
                continue
            r = Rec(ts=c.ts, src=c.client, sport=c.cport, dst=c.server, dport=c.sport, certs=certs)
            r.update(ch or {})
            r.update(sh or {})
            out.append(r)
        out.sort(key=lambda r: r.ts if r.ts is not None else 0)
        return out

    @_memo
    def certs(self):
        """[Rec(server, port, position, sha1, sha256, subject, issuer, serial, not_before, not_after,
        names)] for every certificate a server sent in the clear (TLS 1.2 and older)."""
        out = []
        for t in self.tls():
            for i, der in enumerate(t.certs or []):
                r = Rec(server=t.dst, port=t.dport, position=i, size=len(der),
                        sha1=hashlib.sha1(der).hexdigest(), sha256=hashlib.sha256(der).hexdigest(), der=der)
                try:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(der)
                    r.update(subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                             serial=f"{cert.serial_number:x}",
                             not_before=cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                             not_after=cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
                    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    r.common_name = cn[0].value if cn else None
                    try:
                        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                        r.names = [str(n.value) for n in san]
                    except x509.ExtensionNotFound:
                        r.names = []
                except Exception:
                    pass
                out.append(r)
        return out

    # ---- line protocols and credentials --------------------------------------------------------------

    @_memo
    def ftp(self):
        """[Rec(server, port, client, user, password, ok, commands, replies, transfers, ts)] per FTP
        control connection; transfers is [Rec(command, name, data, complete)]."""
        out = []
        conns = self.conns()
        used = set()
        for c in conns:
            cd = c.c.data if c.c is not None else b""
            sd = c.s.data if c.s is not None else b""
            if not (sd[:3] in (b"220", b"120") and re.search(rb"(?mi)^(USER|PASS|RETR|STOR|PASV|EPSV|PORT|QUIT|SYST|FEAT|AUTH) ?", cd)) \
                    or re.search(rb"(?mi)^(EHLO|HELO|MAIL FROM)", cd):
                continue
            cmds = _lines(cd)
            replies = [(o, ln) for o, ln in _lines(sd) if re.match(rb"\d{3} ", ln) and not ln.startswith(b"1")]
            passive = []
            for _, ln in replies:
                m = re.match(rb"227 .*?(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", ln)
                if m:
                    g = [int(x) for x in m.groups()]
                    passive.append((".".join(map(str, g[:4])), g[4] * 256 + g[5]))
                m = re.match(rb"229 .*?\(\|\|\|(\d+)\|\)", ln)
                if m:
                    passive.append((c.server, int(m.group(1))))
            r = Rec(proto="ftp", server=c.server, port=c.sport, client=c.client, ts=c.ts, src=c.client, dst=c.server,
                    sport=c.cport, dport=c.sport, commands=[ln.decode("latin-1") for _, ln in cmds],
                    replies=[ln.decode("latin-1") for _, ln in replies], logins=[], transfers=[])
            user, endpoint, pi = None, None, 0
            binary, rest = False, 0     # RFC 959: the type is ASCII until TYPE I; REST moves the start
            for i, (o, ln) in enumerate(cmds):
                verb, _, arg = ln.partition(b" ")
                verb = verb.upper()
                arg = arg.decode("utf-8", "replace")
                rep = replies[i + 1][1] if i + 1 < len(replies) else None
                if verb == b"USER":
                    user = arg
                elif verb == b"PASS":
                    ok = None if rep is None else rep.startswith(b"230") if rep[:1] in b"235" else None
                    r.logins.append(Rec(proto="ftp", user=user, password=arg, ok=ok, src=c.client, dst=c.server,
                                        sport=c.cport, dport=c.sport, ts=self.stream_time(c.c, o)))
                elif verb == b"TYPE":
                    binary = arg.strip().upper()[:1] in ("I", "L")
                elif verb == b"REST":
                    rest = int(arg.strip()) if arg.strip().isdigit() else -1
                elif verb in (b"PASV", b"EPSV"):
                    endpoint, pi = (("passive",) + passive[pi] if pi < len(passive) else None), pi + 1
                elif verb == b"PORT":
                    g = [int(x) for x in re.findall(r"\d+", arg)]
                    endpoint = ("active", ".".join(map(str, g[:4])), g[4] * 256 + g[5]) if len(g) == 6 else None
                elif verb == b"EPRT":
                    m = re.match(r"\|\d\|([^|]+)\|(\d+)\|", arg)
                    endpoint = ("active", m.group(1), int(m.group(2))) if m else None
                elif verb in (b"RETR", b"STOR", b"APPE", b"LIST", b"NLST", b"MLSD"):
                    t = Rec(command=verb.decode(), name=arg or None, data=None, complete=False, ascii=not binary,
                            offset=rest, ts=self.stream_time(c.c, o), src=c.client, dst=c.server)
                    if endpoint is not None:
                        for j, dc in enumerate(conns):
                            if j in used or dc is c or dc.sport != endpoint[2]:
                                continue
                            if endpoint[0] == "passive" and dc.server not in (endpoint[1], c.server):
                                continue
                            if endpoint[0] == "active" and dc.server not in (endpoint[1], c.client):
                                continue
                            sender = c.client if verb in (b"STOR", b"APPE") else c.server
                            st = next((x for x in (dc.c, dc.s) if x is not None and x.src == sender), None)
                            used.add(j)
                            t.data = st.data if st is not None else b""
                            # a file resumed at an offset (REST) or added to another (APPE) is a
                            # piece of a file, however whole its own connection is
                            t.complete = bool(st is not None and st.whole and rest == 0 and verb != b"APPE")
                            break
                        endpoint = None
                    rest = 0
                    r.transfers.append(t)
            if r.logins:
                r.user, r.password, r.ok = r.logins[-1].user, r.logins[-1].password, r.logins[-1].ok
            out.append(r)
        return out

    @_memo
    def smtp(self):
        """[Rec(server, client, mail_from, rcpt_to, subject, from_, to, date, body, attachments, raw,
        auth)] per message sent over SMTP; attachments is [Rec(name, data, content_type)]."""
        out = []
        for c in self.conns():
            cd = c.c.data if c.c is not None else b""
            if not re.match(rb"(?i)(EHLO|HELO) ", cd):
                continue
            pos = 0
            while True:
                m = re.compile(rb"(?im)^DATA\r\n").search(cd, pos)
                if not m:
                    break
                end = cd.find(b"\r\n.\r\n", m.end())
                raw = cd[m.end():end + 2 if end >= 0 else len(cd)].replace(b"\r\n..", b"\r\n.")
                head = cd[pos:m.start()]
                r = Rec(proto="smtp", server=c.server, client=c.client, src=c.client, dst=c.server, sport=c.cport,
                        dport=c.sport, ts=self.stream_time(c.c, m.start()), raw=raw, complete=end >= 0 and bool(c.c.sound),
                        mail_from=(re.findall(rb"(?im)^MAIL FROM:\s*<?([^>\r\n ]*)", head) or [b""])[-1].decode("latin-1"),
                        rcpt_to=[x.decode("latin-1") for x in re.findall(rb"(?im)^RCPT TO:\s*<?([^>\r\n ]*)", head)],
                        attachments=[])
                try:
                    msg = email.message_from_bytes(raw, policy=email.policy.default)
                    r.update(subject=_hdr(msg, "subject"), from_=_hdr(msg, "from"), to=_hdr(msg, "to"),
                             date=_hdr(msg, "date"), message_id=_hdr(msg, "message-id"))
                    body = msg.get_body(preferencelist=("plain", "html"))
                    r.body = body.get_content() if body is not None else None
                    for part in msg.iter_attachments():
                        data = part.get_payload(decode=True)
                        if data is None:
                            data = part.get_content()
                            data = data if isinstance(data, bytes) else str(data).encode()
                        # only base64 carries a file byte for byte: a text encoding (7bit, 8bit,
                        # quoted-printable) is the mail's rendering of it, line ends and all
                        r.attachments.append(Rec(name=part.get_filename(), data=data, content_type=part.get_content_type(),
                                                 cte=str(part.get("Content-Transfer-Encoding") or "7bit").strip().lower()))
                except Exception:
                    pass
                out.append(r)
                if end < 0:
                    break
                pos = end + 5
        return out

    @_memo
    def telnet(self):
        """[Rec(server, port, client, user, password, typed, shown)] per Telnet connection: what the
        client typed (line by line, backspaces applied) and what the server showed."""
        out = []
        for c in self.conns():
            cd = c.c.data if c.c is not None else b""
            sd = c.s.data if c.s is not None else b""
            if not sd or not (b"\xff" in sd[:64] or c.sport == 23):
                continue
            shown = _telnet_text(sd)
            if not re.search(rb"(?i)(login|username)\s*:", shown) and c.sport != 23:
                continue
            typed = _telnet_text(cd)
            lines = [ln.decode("utf-8", "replace") for ln in _edit_lines(typed)]
            r = Rec(proto="telnet", server=c.server, port=c.sport, client=c.client, src=c.client, dst=c.server,
                    sport=c.cport, dport=c.sport, ts=c.ts, typed=lines, shown=shown.decode("utf-8", "replace"))
            lo = re.search(rb"(?i)(login|username)\s*:", shown)
            pw = re.search(rb"(?i)password\s*:", shown)
            if lo and pw and lo.start() < pw.start() and len(lines) >= 2:
                r.user, r.password = lines[0], lines[1]
                r.ok = None
            out.append(r)
        return out

    @_memo
    def credentials(self):
        """[Rec(proto, user, password, ok, src, dst, dport, ts)] of every credential sent in clear:
        ftp, pop3, imap, smtp (AUTH PLAIN and LOGIN), telnet, http_basic, http_form. ok is True or
        False where the server's reply says so, else None."""
        out = []
        for f in self.ftp():
            out.extend(f.logins)
        for t in self.telnet():
            if t.password is not None:
                out.append(Rec(proto="telnet", user=t.user, password=t.password, ok=None, src=t.client, dst=t.server,
                               sport=t.sport, dport=t.dport, ts=t.ts))
        for c in self.conns():
            cd = c.c.data if c.c is not None else b""
            sd = c.s.data if c.s is not None else b""
            base = dict(src=c.client, dst=c.server, sport=c.cport, dport=c.sport)
            if sd.startswith(b"+OK") and cd:
                cmds = _lines(cd)
                reps = [ln for _, ln in _lines(sd) if ln.startswith((b"+OK", b"-ERR"))]
                user = None
                for i, (o, ln) in enumerate(cmds):
                    verb, _, arg = ln.partition(b" ")
                    if verb.upper() == b"USER":
                        user = arg.decode("utf-8", "replace")
                    elif verb.upper() == b"PASS":
                        rep = reps[i + 1] if i + 1 < len(reps) else None
                        out.append(Rec(proto="pop3", user=user, password=arg.decode("utf-8", "replace"),
                                       ok=None if rep is None else rep.startswith(b"+OK"),
                                       ts=self.stream_time(c.c, o), **base))
            elif sd.startswith(b"* OK") and cd:
                for o, ln in _lines(cd):
                    m = re.match(rb'(\S+) LOGIN ("(?:[^"\\]|\\.)*"|\S+) ("(?:[^"\\]|\\.)*"|\S+)$', ln, re.I)
                    if m:
                        tag = m.group(1)
                        ok = True if re.search(rb"(?m)^" + re.escape(tag) + rb" OK", sd) else \
                            False if re.search(rb"(?m)^" + re.escape(tag) + rb" (NO|BAD)", sd) else None
                        out.append(Rec(proto="imap", user=_unq(m.group(2)), password=_unq(m.group(3)), ok=ok,
                                       ts=self.stream_time(c.c, o), **base))
            elif re.match(rb"(?i)(EHLO|HELO) ", cd):
                cmds = _lines(cd)
                ok = True if re.search(rb"(?m)^235 ", sd) else False if re.search(rb"(?m)^535 ", sd) else None
                for i, (o, ln) in enumerate(cmds):
                    m = re.match(rb"(?i)AUTH PLAIN ?(\S*)$", ln)
                    if m:
                        blob = m.group(1) or (cmds[i + 1][1] if i + 1 < len(cmds) else b"")
                        parts = (_b64(blob) or b"").split(b"\x00")
                        if len(parts) == 3:
                            out.append(Rec(proto="smtp", user=parts[1].decode("utf-8", "replace"),
                                           password=parts[2].decode("utf-8", "replace"), ok=ok,
                                           ts=self.stream_time(c.c, o), **base))
                    m = re.match(rb"(?i)AUTH LOGIN ?(\S*)$", ln)
                    if m:
                        rest = ([m.group(1)] if m.group(1) else []) + [x for _, x in cmds[i + 1:i + 3]]
                        if len(rest) >= 2:
                            u, pw = _b64(rest[0]), _b64(rest[1])
                            if u is not None and pw is not None:
                                out.append(Rec(proto="smtp", user=u.decode("utf-8", "replace"),
                                               password=pw.decode("utf-8", "replace"), ok=ok,
                                               ts=self.stream_time(c.c, o), **base))
        for r in self.http():
            base = dict(src=r.src, dst=r.dst, sport=r.sport, dport=r.dport, ts=r.ts, host=r.host, uri=r.uri)
            ok = None if r.status is None else False if r.status in (401, 403, 407) else None
            for h in (r.authorization, dict((k.lower(), v) for k, v in (r.headers or [])).get("proxy-authorization")):
                m = re.match(r"(?i)basic\s+(\S+)", h or "")
                raw = _b64(m.group(1).encode()) if m else None
                if raw is not None and b":" in raw:
                    u, _, pw = raw.partition(b":")
                    out.append(Rec(proto="http_basic", user=u.decode("utf-8", "replace"),
                                   password=pw.decode("utf-8", "replace"), ok=ok, **base))
            fields = _form_fields(r)
            pw = next((v for k, v in fields if _PASS_KEY.match(k)), None)
            if pw is not None:
                out.append(Rec(proto="http_form", user=next((v for k, v in fields if _USER_KEY.match(k)), None),
                               password=pw, ok=None, **base))
        out.sort(key=lambda r: r.ts if r.ts is not None else 0)
        return out

    @_memo
    def _ntlm_blobs(self):
        """[Rec(src, dst, sport, dport, ts, order, pair, msg)] of every NTLMSSP message in the
        capture, found in the reassembled TCP streams: the binary signature (SMB2 SESSION_SETUP,
        LDAP, RPC) and the base64-wrapped form (HTTP/SMTP/IMAP/POP3 `Authorization: NTLM ...`).
        `pair` is the connection's sorted endpoints, so a 401 challenge and its answer group."""
        out, seen, order = [], set(), 0

        def take(st, off, raw):
            nonlocal order
            i = bytes(raw).find(NTLM_SIG)
            if i < 0:
                return
            m = parse_ntlmssp(raw[i:])
            if m is None:
                return
            pair = tuple(sorted(((st.src, st.sport), (st.dst, st.dport))))
            sig = (pair, m.type, bytes(m.raw)[:96])
            if sig in seen:
                return
            seen.add(sig)
            out.append(Rec(src=st.src, dst=st.dst, sport=st.sport, dport=st.dport,
                           ts=self.stream_time(st, off), order=order, pair=pair, msg=m))
            order += 1

        for st in self.streams().values():
            d = st.data
            if not d:
                continue
            start = d.find(NTLM_SIG)
            while start >= 0:                       # binary-embedded (SMB2, LDAP, RPC, raw)
                take(st, start, d[start:])
                start = d.find(NTLM_SIG, start + 8)
            if b"TlRMTVNT" in d:                    # base64-wrapped (HTTP, SMTP, IMAP, POP3 SASL)
                for mm in NTLM_B64_RE.finditer(d):
                    raw = _b64(mm.group())
                    if raw:
                        take(st, mm.start(), raw)
        out.sort(key=lambda b: (b.ts if b.ts is not None else 0, b.order))
        return out

    @_memo
    def ntlm(self):
        """[Rec(proto='ntlmssp', src, dst, sport, dport, ts, user, domain, workstation, target_name,
        flags, challenge (8 bytes), av, lm_response, nt_response, netntlm)] -- one per NTLM exchange
        in the capture. An exchange is a TCP connection's Negotiate/Challenge/Authenticate messages:
        the Authenticate (Type 3) carries the user, domain and workstation and, with the connection's
        Challenge (Type 2), the NetNTLM response; the Challenge carries target_name and the 8-byte
        server challenge. `netntlm` is [(format, hash string)] for hashcat/john (empty without a
        response). Every field is read from the bytes; nothing is guessed or cracked."""
        by_pair = OrderedDict()
        for b in self._ntlm_blobs():
            by_pair.setdefault(b.pair, []).append(b)
        out = []
        for msgs in by_pair.values():
            t1s = [b for b in msgs if b.msg.type == 1]
            t2s = [b for b in msgs if b.msg.type == 2]
            t3s = [b for b in msgs if b.msg.type == 3]

            def challenge_before(order):
                prior = [b for b in t2s if b.order <= order] or t2s
                return prior[-1] if prior else None

            if t3s:
                for b in t3s:
                    m = b.msg
                    t2 = challenge_before(b.order)
                    t1 = t1s[0] if t1s else None
                    ch = t2.msg.challenge if t2 else None
                    out.append(Rec(proto="ntlmssp", src=b.src, dst=b.dst, sport=b.sport, dport=b.dport, ts=b.ts,
                                   user=m.user, domain=m.domain, workstation=m.workstation,
                                   target_name=t2.msg.target_name if t2 else None, flags=m.flags, challenge=ch,
                                   av=(t2.msg.av if t2 else OrderedDict()), lm_response=m.lm_response,
                                   nt_response=m.nt_response, netntlm=_netntlm_strings(m.user, m.domain, ch, m.lm_response, m.nt_response),
                                   negotiate=t1 is not None, authenticate=True))
            else:                               # a Negotiate and/or Challenge with no captured Authenticate
                b = (t2s or t1s)[0]
                t1, t2 = (t1s[0] if t1s else None), (t2s[0] if t2s else None)
                out.append(Rec(proto="ntlmssp", src=b.src, dst=b.dst, sport=b.sport, dport=b.dport, ts=b.ts,
                               user=None, domain=(t1.msg.domain if t1 else None),
                               workstation=(t1.msg.workstation if t1 else None),
                               target_name=(t2.msg.target_name if t2 else None), flags=b.msg.flags,
                               challenge=(t2.msg.challenge if t2 else None), av=(t2.msg.av if t2 else OrderedDict()),
                               lm_response=None, nt_response=None, netntlm=[], negotiate=t1 is not None, authenticate=False))
        out.sort(key=lambda r: r.ts if r.ts is not None else 0)
        return out

    @_memo
    def http_digest(self):
        """[Rec(proto='http_digest', src, dst, sport, dport, ts, method, uri, username, realm, nonce,
        response, algorithm, qop, nc, cnonce, opaque)] of every HTTP `Authorization: Digest` request.
        realm/nonce fall back to the server's `WWW-Authenticate: Digest` challenge when the request
        omits them. Every field is the exact header value."""
        out = []
        for r in self.http():
            server = {}
            for k, v in (r.resp_headers or []):
                if k.lower() in ("www-authenticate", "proxy-authenticate") and re.match(r"(?i)\s*digest\b", v or ""):
                    server = _auth_params(v)
                    break
            auth = r.authorization or next((v for k, v in (r.headers or []) if k.lower() == "proxy-authorization"), None)
            if not (auth and re.match(r"(?i)\s*digest\b", auth)):
                continue
            p = _auth_params(auth)
            out.append(Rec(proto="http_digest", src=r.src, dst=r.dst, sport=r.sport, dport=r.dport, ts=r.ts,
                           method=r.method, uri=p.get("uri") or r.uri, username=p.get("username"),
                           realm=p.get("realm") or server.get("realm"), nonce=p.get("nonce") or server.get("nonce"),
                           response=p.get("response"), algorithm=(p.get("algorithm") or server.get("algorithm")),
                           qop=p.get("qop"), nc=p.get("nc"), cnonce=p.get("cnonce"), opaque=p.get("opaque")))
        return out

    @_memo
    def tftp(self):
        """[Rec(op, name, mode, client, server, data, complete)] of TFTP transfers."""
        out = []
        # only the packets a transfer can consist of (a request to port 69, a DATA block), so that
        # a capture with many requests costs requests x blocks and not requests x packets
        cand = [q for q in self.packets if q.proto == 17 and q.payload and (q.dport == 69 or q.payload[:2] == b"\x00\x03")]
        for i, p in enumerate(cand):
            d = p.payload
            if p.dport != 69 or len(d) < 4 or d[:2] not in (b"\x00\x01", b"\x00\x02"):
                continue
            parts = d[2:].split(b"\x00")
            r = Rec(op="read" if d[1] == 1 else "write", name=_txt(parts[0]), mode=_txt(parts[1]) if len(parts) > 1 else None,
                    client=p.src, server=p.dst, src=p.src, dst=p.dst, sport=p.sport, dport=69, ts=p.ts)
            # RFC 2347 options (blksize) change the block length, and with it what a short last
            # block is: such a transfer is carved but never called whole
            options = any(x for x in parts[2:])
            blocks, last = {}, None
            for q in cand[i + 1:]:
                e = q.payload
                if q.dport == 69 and q.src == p.src and q.sport == p.sport:
                    break               # the same client port asks again: a new transfer
                if len(e) < 4 or e[:2] != b"\x00\x03":
                    continue
                if r.op == "read" and not (q.src == p.dst and q.dst == p.src and q.dport == p.sport):
                    continue
                if r.op == "write" and not (q.src == p.src and q.dst == p.dst and q.sport == p.sport):
                    continue
                n = (e[2] << 8) | e[3]
                blocks.setdefault(n, e[4:])
                if len(e) - 4 < 512:
                    last = n
                    break
            r.data = b"".join(blocks[k] for k in sorted(blocks))
            r.complete = last is not None and sorted(blocks) == list(range(1, last + 1)) and not options
            r.options = options
            out.append(r)
        return out

    # ---- carved files ----------------------------------------------------------------------------

    @_memo
    def objects(self):
        """[Rec(source, name, data, size, sha256, sha1, md5, complete, encoded, content_type, src, dst,
        ts, status)] of every file that crossed the capture: source is http_response, http_request,
        http_upload (a multipart part with a file name), ftp_retr, ftp_stor, smtp_attachment, tftp.
        complete is False when bytes are missing; encoded marks an HTTP body whose content coding was
        removed (data is the decoded file)."""
        out = []

        def add(source, name, data, complete, **kw):
            if data:
                out.append(Rec(source=source, name=name, data=data, size=len(data), complete=bool(complete),
                               sha256=hashlib.sha256(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
                               md5=hashlib.md5(data).hexdigest(), **kw))

        for r in self.http():
            if r.status is not None and r.resp_raw:
                data = r.resp_body
                add("http_response", r.disposition or r.filename, data if data is not None else r.resp_raw,
                    r.resp_complete and data is not None, encoded=bool(r.resp_encoded), content_type=r.content_type,
                    src=r.dst, dst=r.src, ts=r.resp_ts, status=r.status, uri=r.uri, host=r.host,
                    uri_name=r.filename, disposition=r.disposition)
            if r.body:
                ct = r.req_content_type or ""
                parts = _multipart(ct, r.body) if ct.lower().startswith("multipart/") else []
                for name, data, ptype in parts:
                    add("http_upload", name, data, r.req_complete, encoded=False, content_type=ptype, src=r.src, dst=r.dst,
                        ts=r.ts, uri=r.uri, host=r.host)
                if not parts:
                    add("http_request", r.filename, r.body, r.req_complete, encoded=False, content_type=ct or None, src=r.src,
                        dst=r.dst, ts=r.ts, uri=r.uri, host=r.host)
        for f in self.ftp():
            for t in f.transfers:
                if t.command in ("RETR", "STOR", "APPE") and t.data:
                    name = (t.name or "").replace("\\", "/").rsplit("/", 1)[-1] or None
                    add("ftp_" + ("retr" if t.command == "RETR" else "stor"), name, t.data, t.complete, encoded=bool(t.ascii),
                        src=f.server if t.command == "RETR" else f.client,
                        dst=f.client if t.command == "RETR" else f.server, ts=t.ts)
        for m in self.smtp():
            for a in m.attachments:
                add("smtp_attachment", a.name, a.data, m.complete, encoded=a.get("cte") != "base64", content_type=a.content_type,
                    src=m.client, dst=m.server, ts=m.ts)
        for t in self.tftp():
            add("tftp", t.name.replace("\\", "/").rsplit("/", 1)[-1], t.data, t.complete,
                encoded=(t.mode or "").lower() != "octet",
                src=t.server if t.op == "read" else t.client, dst=t.client if t.op == "read" else t.server, ts=t.ts)
        return out

    # ---- covert channels --------------------------------------------------------------------------

    @_memo
    def icmp_payloads(self):
        """[Rec(ts, src, dst, type, code, id, seq, data, standard)] of ICMP echo requests and replies;
        standard marks the payload an ordinary ping writes."""
        out, seen = [], set()
        for p in self.packets:
            if (p.proto == 1 and p.itype in (0, 8)) or (p.proto == 58 and p.itype in (128, 129)):
                sig = (p.src, p.dst, p.itype, p.iid, p.iseq, p.payload)
                if sig in seen:
                    continue
                seen.add(sig)
                out.append(Rec(ts=p.ts, src=p.src, dst=p.dst, type=p.itype, code=p.icode, id=p.iid, seq=p.iseq,
                               data=p.payload, request=p.itype in (8, 128), standard=_standard_ping(p.payload),
                               ttl=p.ttl, ipid=p.ipid))
        return out

    @_memo
    def dns_tunnel(self):
        """[Rec(parent, names, labels, joined, decoded)] for every parent domain queried under three
        or more different names: the labels in front of the parent, in the order first asked, joined,
        and that text's plain decodings ({method: bytes} for hex, base32, base64, base64url).
        Sequence-numbered names (<data>.<NN>.<zone>, dns_sequences) come first, one Rec per source and
        zone with kind "sequence", src, seq and missing: their data labels sorted by number, repeats
        dropped and the numbers stripped. Those names are left out of the per-parent groups (kind
        "labels") so a shuffled, numbered stream is never also read in the order asked."""
        queries = [m for m in self.dns() if not m.qr and m.proto == "dns" and m.qname]
        seqs = dns_sequences((m.src, m.qname) for m in queries)
        claimed = {(s.src, q) for s in seqs for q in s.members}
        first = [Rec(kind="sequence", parent=s.zone, src=s.src, names=s.names, labels=s.labels, joined=s.joined,
                     decoded=s.decoded, per_label=s.per_label, seq=s.seq, missing=s.missing, layout=s.layout)
                 for s in seqs]
        groups = OrderedDict()
        for m in queries:
            if (m.src, m.qname.rstrip(".")) in claimed:
                continue
            labels = m.qname.rstrip(".").split(".")
            if m.qname.rstrip(".").lower().endswith((".arpa", ".local")) or any(x.startswith("_") for x in labels):
                continue            # reverse lookups, mDNS and _service._proto names: many names, no channel
            for keep in (2, 3):
                if len(labels) > keep:
                    parent = ".".join(labels[-keep:]).lower()
                    g = groups.setdefault(parent, OrderedDict())
                    g.setdefault(".".join(labels[:-keep]), m.ts)
        out = []
        for parent, g in groups.items():
            if len(g) < 3:
                continue
            labels = list(g)
            joined = "".join(x.replace(".", "") for x in labels)
            out.append(Rec(kind="labels", parent=parent, names=len(g), labels=labels, joined=joined,
                           decoded=decodings(joined.encode()),
                           per_label=_per_piece([x.replace(".", "").encode() for x in labels])))
        # a parent of three labels that only repeats its two-label parent's names adds nothing
        return first + [r for r in out if not any(o is not r and o.parent.endswith("." + r.parent) and o.names == r.names
                                          and len(o.parent) > len(r.parent) and len(set(x.rsplit(".", 1)[-1] for x in r.labels)) == 1
                                          for o in out)]

    def hidden(self, channel="icmp") -> dict:
        """{'<arrangement>:<method>': text} of the printable readings of a covert channel: 'icmp' (echo
        payloads that are not an ordinary ping's) or 'dns' (query labels and TXT answers). An
        arrangement is one way of putting the pieces together (echo_request, echo_reply,
        labels@<parent domain>, sequence@<zone><-<source> for a numbered stream in number order, txt); two arrangements are different facts. A method is how one
        arrangement is written: joined (as sent), joined_hex / joined_base64 / ... (joined, then
        decoded), each_hex / ... (every piece decoded, then joined), repeated_byte (one byte per
        payload that repeats it). Decoded readings come first."""
        return self._hidden(channel)[0]

    def hidden_blobs(self):
        """[Rec(channel, key, kind, size, sha256, flags, data, ...)]: the readings of a covert channel
        that are not text (a file sent a byte or a chunk at a time), each described by describe_blob,
        and the files the Modbus writes spell (modbus_series)."""
        out = []
        for ch in ("icmp", "dns"):
            for key, data in self._hidden(ch)[1].items():
                out.append(describe_blob(data, channel=ch, key=key))
        for m in self.modbus_series():
            if m.blob is not None:
                out.append(describe_blob(m.blob, channel="modbus", key=f"fn{m.function}@{m.address}:{m.reading}"))
        return out

    def _hidden(self, channel="icmp"):
        cache = self.__dict__.setdefault("_hidden_cache", {})
        if channel not in cache:
            cache[channel] = self._hidden_read(channel)
        return cache[channel]

    def _hidden_read(self, channel):
        out, raw = OrderedDict(), OrderedDict()

        def put(arr, pieces):
            got = []
            blob = b"".join(pieces)
            skip = _uniform_tail(pieces)
            if len(pieces) >= 2 and skip is not None:
                got.append(("repeated_byte", bytes(x[skip] for x in pieces)))     # one byte of news per payload
            else:
                got += [("joined_" + meth, dec) for meth, dec in decodings(blob).items()]
                got += [("each_" + meth, dec) for meth, dec in _per_piece(pieces).items() if len(pieces) > 1]
                got.append(("joined", blob))
            for meth, data in got:
                if data and _printable(data):
                    out[f"{arr}:{meth}"] = data.decode("utf-8", "replace").strip("\x00")
                elif data and (meth == "repeated_byte" or _magic(data)):
                    # not text: a file, a byte or a chunk at a time. The file is a finding
                    # (hidden_blobs); the one flag-shaped text in it is a reading of the channel.
                    raw[f"{arr}:{meth}"] = data
                    flags = _flags_in(data)
                    if len(flags) == 1:
                        out[f"{arr}:{meth}_flag"] = flags[0]

        if channel == "icmp":
            recs = [r for r in self.icmp_payloads() if not r.standard and r.data]
            req = [r.data for r in recs if r.request]
            if req:
                put("echo_request", req)
            elif recs:
                put("echo_reply", [r.data for r in recs])
        else:
            for t in self.dns_tunnel():
                arr = (f"sequence@{t.parent}<-{t.src}" if t.kind == "sequence" else "labels@" + t.parent)
                put(arr, [x.replace(".", "").encode() for x in t.labels])
            txt = list(dict.fromkeys(v for m in self.dns() if m.qr for _, t, v in m.answers if t == "TXT"
                                     and not re.match(r"(?i)v=(?:spf1|dkim1|dmarc1)\b|[a-z0-9-]+-(?:site|domain)-verification=|MS=ms\d", v)))
            if txt:
                put("txt", [v.encode() for v in txt])
        return out, raw

    # ---- behaviour -------------------------------------------------------------------------------

    @_memo
    def beacons(self):
        """[Rec(kind, key, events, median, low, high, jitter, periodic)] for every repeated event with
        four or more occurrences: a TCP connection opened (syn), a DNS name asked (dns), an HTTP
        request made (http), a UDP or ICMP message to one place (udp, icmp). Seconds; periodic is
        True when no interval is more than a tenth from the median."""
        ev, syns = defaultdict(list), set()
        for p in self.packets:
            if p.ts is None or p.src is None:
                continue
            if p.proto == 6 and p.flags is not None and p.flags & 2 and not p.flags & 16:
                if (p.src, p.sport, p.dst, p.dport, p.seq) not in syns:
                    syns.add((p.src, p.sport, p.dst, p.dport, p.seq))
                    ev[("syn", p.src, p.dst, p.dport)].append(p.ts)
            elif p.proto == 17 and p.dport not in (53, 5353, 5355, 67, 68, 137, 138, 1900):
                ev[("udp", p.src, p.dst, p.dport)].append(p.ts)
            elif p.proto in (1, 58) and p.itype in (8, 128):
                ev[("icmp", p.src, p.dst, None)].append(p.ts)
        for m in self.dns():
            if not m.qr and m.proto == "dns" and m.ts is not None:
                ev[("dns", m.src, m.qname.lower(), m.qtype)].append(m.ts)
        for r in self.http():
            if r.method and r.ts is not None:
                ev[("http", r.src, r.host, r.uri.split("?")[0])].append(r.ts)
        out = []
        for k, ts in ev.items():
            ts = sorted(set(ts))
            if len(ts) < 4:
                continue
            gaps = sorted((b - a) / 1e9 for a, b in zip(ts, ts[1:]))
            med = gaps[len(gaps) // 2] if len(gaps) % 2 else (gaps[len(gaps) // 2 - 1] + gaps[len(gaps) // 2]) / 2
            if med <= 0:
                continue
            jit = max(abs(g - med) for g in gaps) / med
            out.append(Rec(kind=k[0], key=k[1:], src=k[1], dst=k[2], events=len(ts), median=med, low=gaps[0],
                           high=gaps[-1], jitter=jit, periodic=jit <= 0.1 and med >= 0.5))
        out.sort(key=lambda b: (not b.periodic, -b.events))
        return out

    @_memo
    def syn_scan(self):
        """[Rec(src, dst, ports, open)]: a source that sent SYNs to twenty or more ports of one host;
        open lists the ports that answered SYN-ACK."""
        tried, opened = defaultdict(set), defaultdict(set)
        for st in self.streams().values():
            if st.syn and not st.synack:
                tried[(st.src, st.dst)].add(st.dport)
            elif st.syn and st.synack:
                opened[(st.dst, st.src)].add(st.sport)
        return [Rec(src=s, dst=d, ports=sorted(ports), open=sorted(opened.get((s, d), ())))
                for (s, d), ports in tried.items() if len(ports) >= 20]

    @_memo
    def open_ports(self):
        """{address: sorted ports} that answered a SYN with a SYN-ACK."""
        out = defaultdict(set)
        for st in self.streams().values():
            if st.syn and st.synack:
                out[st.src].add(st.sport)
        return {k: sorted(v) for k, v in out.items()}

    # ---- USB, Modbus, fields ----------------------------------------------------------------------

    @_memo
    def usb_keystrokes(self):
        """[Rec(bus, device, endpoint, reports, text, raw)] per device that sent 8-byte HID
        boot-keyboard reports: text has backspaces applied, raw keeps them as '<BS>'."""
        dev = OrderedDict()
        for p in self.packets:
            u = p.usb
            if u is None or not u.incoming or u.transfer != 1 or len(u.data) != 8 or u.event == "S":
                continue
            dev.setdefault((u.bus, u.device, u.endpoint), []).append(u.data)
        out = []
        for (bus, d, ep), reps in dev.items():
            if any(r[1] for r in reps) or not any(any(r[2:]) for r in reps):
                continue            # byte 1 is reserved in a keyboard report; a mouse or tablet is not one
            text, raw, prev, caps = [], [], set(), False
            for r in reps:
                shift = bool(r[0] & 0x22)
                chord = "C-" if r[0] & 0x11 else "A-" if r[0] & 0x04 else "M-" if r[0] & 0x88 else ""
                keys = [k for k in r[2:] if k > 3]
                for k in keys:
                    if k in prev:
                        continue
                    if k == 57:
                        caps = not caps
                        continue
                    ch = _hid(k, shift, caps)
                    if ch is None:
                        continue
                    if chord:                   # Ctrl+C types nothing (seen in a real capture: "...lol\nc")
                        raw.append(f"<{chord}{ch.strip() or 'space'}>")
                        continue
                    if ch == "\b":
                        raw.append("<BS>")
                        del text[-1:]
                    else:
                        raw.append(ch)
                        text.append(ch)
                prev = set(keys)
            out.append(Rec(bus=bus, device=d, endpoint=ep, reports=len(reps), text="".join(text), raw="".join(raw)))
        return [r for r in out if r.raw]

    @_memo
    def modbus(self):
        """[Rec(ts, src, dst, transaction, unit, function, request, address, count, registers)] of
        Modbus/TCP messages (port 502): register and coil reads and writes."""
        out = []
        for p in self.packets:
            d = p.payload
            if p.proto != 6 or 502 not in (p.sport, p.dport) or len(d) < 8 or d[2:4] != b"\x00\x00":
                continue
            tid, _, ln, unit, fn = struct.unpack_from("!HHHBB", d, 0)
            body = d[8:6 + ln]
            r = Rec(ts=p.ts, src=p.src, dst=p.dst, sport=p.sport, dport=p.dport, transaction=tid, unit=unit,
                    function=fn, request=p.dport == 502, registers=[])
            try:
                if fn in (5, 6) and len(body) >= 4:
                    r.address, v = struct.unpack_from("!HH", body, 0)
                    r.registers = [v]
                elif fn in (15, 16) and r.request and len(body) >= 5:
                    r.address, r.count, n = struct.unpack_from("!HHB", body, 0)
                    r.registers = list(struct.unpack_from(f"!{n // 2}H", body, 5)) if fn == 16 else list(body[5:5 + n])
                elif fn in (1, 2, 3, 4) and r.request and len(body) >= 4:
                    r.address, r.count = struct.unpack_from("!HH", body, 0)
                elif fn in (3, 4) and len(body) >= 1:
                    r.registers = list(struct.unpack_from(f"!{body[0] // 2}H", body, 1))
                elif fn in (1, 2) and len(body) >= 1:
                    r.registers = list(body[1:1 + body[0]])
            except struct.error:
                pass
            out.append(r)
        return out

    @_memo
    def flags(self):
        """OrderedDict {flag-shaped text: where it was read}: covert-channel readings and the files
        they spell, typed keys, Modbus writes, TCP streams, UDP payloads and carved files."""
        out = OrderedDict()

        def add(where, data):
            for x in _flags_in(data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8", "replace")):
                out.setdefault(x, where)
        for ch in ("icmp", "dns"):
            for k, v in self._hidden(ch)[0].items():
                add(f"hidden {ch} {k}", v)
        for b in self.hidden_blobs():
            for x in b.flags:
                out.setdefault(x, f"hidden {b.channel} {b.key} ({b.kind})")
        for k in self.usb_keystrokes():
            add("usb keystrokes", k.text)
        for m in self.modbus_series():
            if m.text:
                add(f"modbus fn{m.function}@{m.address}", m.text)
        budget = 64 << 20
        for st in self.streams().values():
            if st.data and budget > 0:
                budget -= len(st.data)
                add(f"tcp {st.src}:{st.sport} > {st.dst}:{st.dport}", st.data)
        for p in self.packets:
            if p.proto == 17 and p.payload and budget > 0:
                budget -= len(p.payload)
                add(f"udp {p.src}:{p.sport} > {p.dst}:{p.dport}", p.payload)
        for o in self.objects():
            if o.data and len(o.data) <= 8 << 20:
                add(f"carved {o.source} {o.name}", o.data)
        return out

    @_memo
    def modbus_series(self):
        """[Rec(src, dst, unit, function, address, writes, written, reading, text, blob)]: the values
        written to ONE coil or register, in order (functions 5, 6, 15, 16; requests only). reading
        says how the values spell something: 'bytes' (every value under 256), 'bits_msb' or
        'bits_lsb' (every value 0 or 1, or a coil's 0 / 0xFF00), else None. text is the printable
        result; blob the bytes when they begin like a file (describe_blob names it)."""
        groups = OrderedDict()
        for m in self.modbus():
            if m.request and m.function in (5, 6, 15, 16) and m.registers and m.get("address") is not None:
                groups.setdefault((m.src, m.dst, m.unit, m.function, m.address), []).extend(m.registers)
        out = []
        for (src, dst, unit, fn, addr), vals in groups.items():
            r = Rec(src=src, dst=dst, unit=unit, function=fn, address=addr, writes=len(vals), written=vals,
                    reading=None, text=None, blob=None)
            tries = []
            if len(vals) >= 16 and set(vals) <= {0, 1, 0xFF00}:
                bits = [1 if v else 0 for v in vals]
                tries += [("bits_msb", bitstream(bits)), ("bits_lsb", bitstream(bits, msb_first=False))]
            elif len(vals) >= 4 and all(0 <= v < 256 for v in vals):
                tries.append(("bytes", bytes(vals)))
            for name, data in tries:
                if _magic(data):
                    r.reading, r.blob = name, data
                    break
                if _printable(data) and len(set(data)) > 2:
                    r.reading, r.text = name, data.decode("utf-8", "replace").strip("\x00")
                    break
            out.append(r)
        return out


# ---- what a carved blob is ----------------------------------------------------------------------------

_MAGICS = ((b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"PK\x03\x04", "zip"),
           (b"%PDF-", "pdf"), (b"\x1f\x8b\x08", "gzip"), (b"\x7fELF", "elf"), (b"MZ", "pe"), (b"7z\xbc\xaf\x27\x1c", "7z"),
           (b"Rar!\x1a\x07", "rar"), (b"BM", "bmp"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"RIFF", "riff"),
           (b"SQLite format 3\x00", "sqlite"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"))
_FLAG_RX = re.compile(r"[A-Za-z0-9_]{2,16}\{(?![0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})[^{}\s]{1,200}\}")   # not NAME{a-guid}
_PASSWORD_RX = re.compile(r"\bpass(?:word|phrase)?\b(?:\s+is)?\s*[:=]?\s*([^\s'\"]{3,64})", re.I)


def _magic(data: bytes):
    """The file type a blob's first bytes state, or None. Two-byte magics (MZ, BM) need a longer blob."""
    for m, kind in _MAGICS:
        if data[:len(m)] == m and (len(m) > 2 or len(data) >= 64):
            return kind
    return None


def _flags_in(data: bytes) -> list:
    """The distinct flag-shaped texts (name{...}) in a blob, in order. A CSS rule (btn{color:red})
    matches the broad shape but is never a flag: flagfmt.shape_reportable drops it (R-16)."""
    hits = (m.group() for m in _FLAG_RX.finditer(bytes(data).decode("latin-1")))
    return list(dict.fromkeys(h for h in hits if flagfmt.shape_reportable(h)))


def _uniform_tail(pieces):
    """How many leading bytes come before the one byte every payload repeats: 0, or the 16 or 8
    bytes of the time `ping -p` writes first. None when the payloads are not of that kind."""
    for k in (0, 16, 8):
        if all(len(x) > k + 1 and len(set(x[k:])) == 1 for x in pieces):
            return k
    return None


def describe_blob(data: bytes, **more) -> Rec:
    """Rec(kind, size, sha256, md5, flags, data) of a carved blob, and for a zip: members
    [(name, size, encrypted)], comment, and opened {name: bytes} for the members that open with no
    password or with the one the zip's own comment states (data of the capture, read in memory;
    nothing is run and no other password is tried)."""
    r = Rec(kind=_magic(data) or "data", size=len(data), sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(), flags=_flags_in(data), data=data, members=[], comment="", opened={},
            password=None, **more)
    if r.kind == "zip":
        import io
        import zipfile
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            r.comment = zf.comment.decode("utf-8", "replace")
            r.members = [(i.filename, i.file_size, bool(i.flag_bits & 1)) for i in zf.infolist()]
            stated = _PASSWORD_RX.search(r.comment)
            pw = stated.group(1).rstrip(".,;") if stated else None
            for i in zf.infolist()[:16]:
                if i.is_dir() or i.file_size > 1 << 20:
                    continue
                try:
                    if not i.flag_bits & 1:
                        r.opened[i.filename] = zf.read(i)
                    elif pw:
                        r.opened[i.filename] = zf.read(i, pwd=pw.encode())
                        r.password = pw
                except Exception:              # AES, a wrong password, a damaged member: not opened
                    continue
        except Exception:
            pass
        if r.opened:
            # the members' own text, not the container's bytes: in a stored zip a member's name runs
            # straight into its content ("flag.txtflag{...}" is not a second flag)
            r.flags = []
        for body in r.opened.values():
            r.flags += [f for f in _flags_in(body) if f not in r.flags]
    return r


# ---- parsers used above ----------------------------------------------------------------------------

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 65: "HTTPS", 255: "ANY", 10: "NULL"}


def _dns_name(d, o):
    labels, jumps, end = [], 0, None
    while True:
        if o >= len(d):
            raise ValueError
        ln = d[o]
        if ln == 0:
            o += 1
            break
        if ln & 0xC0 == 0xC0:
            if o + 1 >= len(d) or jumps > 20:
                raise ValueError
            if end is None:
                end = o + 2
            o = ((ln & 0x3F) << 8) | d[o + 1]
            jumps += 1
            continue
        if ln > 63 or o + 1 + ln > len(d):
            raise ValueError
        labels.append("".join(chr(b) if 0x21 <= b <= 0x7e and b not in (46, 92)
                              else f"\\{b:03d}" for b in d[o + 1:o + 1 + ln]))
        o += 1 + ln
    return ".".join(labels), (end if end is not None else o)


def parse_dns(d):
    """Rec(id, qr, opcode, rcode, qname, qtype, questions, answers) of one DNS message, or None."""
    try:
        tid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", d, 0)
        if qd > 8 or an > 200 or (flags >> 11) & 15 > 5:
            return None
        o, qs = 12, []
        for _ in range(qd):
            name, o = _dns_name(d, o)
            qtype, qclass = struct.unpack_from("!HH", d, o)
            o += 4
            qs.append((name, DNS_TYPES.get(qtype, str(qtype))))
        answers = []
        for i in range(an + ns + ar):
            name, o = _dns_name(d, o)
            rtype, _, _, rlen = struct.unpack_from("!HHIH", d, o)
            o += 10
            rd = d[o:o + rlen]
            if len(rd) < rlen:
                return None
            t = DNS_TYPES.get(rtype, str(rtype))
            if rtype == 1 and rlen == 4:
                v = socket.inet_ntoa(rd)
            elif rtype == 28 and rlen == 16:
                v = socket.inet_ntop(socket.AF_INET6, rd)
            elif rtype in (2, 5, 12):
                v = _dns_name(d, o)[0]
            elif rtype == 15:
                v = _dns_name(d, o + 2)[0]
            elif rtype == 33:
                v = _dns_name(d, o + 6)[0] + ":" + str(struct.unpack_from("!H", d, o + 4)[0])
            elif rtype == 16:
                parts, x = [], 0
                while x < rlen:
                    parts.append(rd[x + 1:x + 1 + rd[x]])
                    x += 1 + rd[x]
                v = b"".join(parts).decode("utf-8", "replace")
            else:
                v = rd.hex()
            o += rlen
            if i < an and rtype != 41:
                answers.append((name, t, v))
        if not qs and not answers:
            return None
        return Rec(id=tid, qr=flags >> 15, opcode=(flags >> 11) & 15, rcode=flags & 15, questions=qs,
                   qname=qs[0][0] if qs else None, qtype=qs[0][1] if qs else None, answers=answers)
    except (struct.error, ValueError, IndexError, OSError):
        return None


_METHODS = rb"GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|PROPPATCH|MKCOL|MOVE|COPY|LOCK|UNLOCK"
_REQ = re.compile(rb"(" + _METHODS + rb") (\S+) HTTP/(1\.[01])\r?\n")
_RESP = re.compile(rb"HTTP/(1\.[01]) (\d{3})[^\r\n]*\r?\n")
_USER_KEY = re.compile(r"(?i)^(user(_?name)?|login|log|e?mail|uname|usr|account|j_username|user_?id|userid|id)$")
_PASS_KEY = re.compile(r"(?i)^(pass(word|wd)?|pwd|pw|passwd|j_password|secret|passphrase)$")


def _http_messages(data, rx, heads=()):
    out, pos = [], 0
    while pos < len(data):
        m = rx.match(data, pos)
        if not m:
            break
        hend = data.find(b"\r\n\r\n", m.end() - 2)
        if hend < 0:
            break
        headers = []
        for ln in data[m.end():hend].split(b"\r\n"):
            k, sep, v = ln.partition(b":")
            if sep:
                headers.append((k.decode("latin-1").strip(), v.decode("latin-1").strip()))
        h = {}
        for k, v in headers:
            h.setdefault(k.lower(), v)
        first = tuple(g.decode("latin-1") for g in m.groups())
        start = hend + 4
        complete = True
        te, cl = h.get("transfer-encoding", "").lower(), h.get("content-length", "")
        is_resp = rx is _RESP
        status = int(first[1]) if is_resp else None
        if is_resp and status < 200 and status != 101:
            pos = start             # 100 Continue, 103 Early Hints: not the answer to a request
            continue
        if is_resp and (status in (101, 204, 304) or (len(out) < len(heads) and heads[len(out)])):
            body, end = b"", start
        elif "chunked" in te:
            body, end, complete = _dechunk(data, start)
        elif cl.isdigit():
            body = data[start:start + int(cl)]
            complete, end = len(body) == int(cl), start + len(body)
            if len({v for k, v in headers if k.lower() == "content-length"}) > 1:
                complete = False    # two lengths: where the body ends is not one reading
        elif is_resp:
            body, end, complete = data[start:], len(data), None
        else:
            body, end = b"", start
        # ``end`` is the first byte after this message. Existing readers do not
        # need it, but sibling evidence readers can now prove that the whole
        # reassembled direction was consumed instead of silently ignoring a
        # malformed or unparsed suffix.
        out.append(Rec(first=first, headers=headers, h=h, body=body, complete=complete,
                       offset=pos, end=end))
        pos = end
    return out


def _dechunk(data, o):
    out = bytearray()
    while True:
        e = data.find(b"\r\n", o)
        if e < 0:
            return bytes(out), len(data), False
        try:
            n = int(data[o:e].split(b";")[0].strip() or b"x", 16)
        except ValueError:
            return bytes(out), o, False
        o = e + 2
        if n == 0:
            t = data.find(b"\r\n\r\n", o - 2)
            return bytes(out), (t + 4 if t >= 0 else len(data)), True
        chunk = data[o:o + n]
        out += chunk
        if len(chunk) < n:
            return bytes(out), len(data), False
        o += n + 2


def _decode_content(body, enc):
    try:
        for e in reversed([x.strip() for x in enc.split(",")]):
            if e in ("gzip", "x-gzip"):
                body = zlib.decompress(body, 47)
            elif e == "deflate":
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    body = zlib.decompress(body, -15)
            elif e == "br":
                import brotli
                body = brotli.decompress(body)
            elif e == "zstd":
                import zstandard
                body = zstandard.ZstdDecompressor().decompressobj().decompress(body)
            elif e not in ("identity", ""):
                return None
        return body
    except Exception:
        return None


def _disposition_name(v):
    if not v:
        return None
    m = re.search(r"filename\*\s*=\s*[\w-]*''([^;]+)", v)
    if m:
        return urllib.parse.unquote(m.group(1)).rsplit("/", 1)[-1]
    m = re.search(r'filename\s*=\s*"((?:[^"\\]|\\.)*)"|filename\s*=\s*([^;\s]+)', v)
    if m:
        return (m.group(1) if m.group(1) is not None else m.group(2)).replace("\\", "/").rsplit("/", 1)[-1]
    return None


def _multipart(content_type, body):
    """[(file name, bytes, content type)] of the parts of a multipart body that carry a file name."""
    try:
        msg = email.message_from_bytes(b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body,
                                       policy=email.policy.HTTP)
        out = []
        for part in msg.iter_parts():
            name = part.get_filename()
            if name:
                data = part.get_payload(decode=True)
                out.append((name.replace("\\", "/").rsplit("/", 1)[-1], data if data is not None else b"",
                            part.get_content_type()))
        return out
    except Exception:
        return []


def _form_fields(r):
    """[(key, value)] of a request's form: a urlencoded or JSON body."""
    body = r.body or b""
    ct = (r.req_content_type or "").lower()
    try:
        if "json" in ct or body[:1] == b"{":
            obj = json.loads(body.decode("utf-8"))
            return [(str(k), str(v)) for k, v in obj.items() if isinstance(v, (str, int, float))] if isinstance(obj, dict) else []
        if "x-www-form-urlencoded" in ct or (body and b"=" in body and not ct and _printable(body)):
            return urllib.parse.parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    except (ValueError, UnicodeDecodeError):
        pass
    return []


def _hdr(msg, name):
    v = msg.get(name)
    return str(v) if v is not None else None


def _lines(data):
    """[(offset, line)] of a CRLF (or LF) line protocol, empty lines dropped."""
    out, o = [], 0
    for ln in data.split(b"\n"):
        s = ln.rstrip(b"\r")
        if s:
            out.append((o, s))
        o += len(ln) + 1
    return out


def _unq(b):
    s = b.decode("utf-8", "replace")
    return re.sub(r"\\(.)", r"\1", s[1:-1]) if len(s) >= 2 and s[0] == s[-1] == '"' else s


def _b64(b):
    try:
        return base64.b64decode(bytes(b).strip(), validate=True)
    except (binascii.Error, ValueError):
        return None


# ---- NTLM(SSP), NetNTLM and HTTP Digest (row 5 of the reference build list) ----------------------------
#
# NTLMSSP messages (MS-NLMP) travel inside SMB2 SESSION_SETUP (GSS-API/SPNEGO), HTTP/SMTP/IMAP/POP3/LDAP
# `Authorization: NTLM <base64>` headers, and raw. Every field read here is a deterministic byte value, so
# it is answered as an unsure pick (plain once the judge accepts its label) -- never guessed. The one thing
# that is never plain is the NetNTLM hash string: its exact format (hashcat 5500/5600, john) is unjudged, so
# it is a labels.candidates value (row 346). Nothing is cracked; the challenge/response are copied verbatim.

NTLM_SIG = b"NTLMSSP\x00"
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
# MsvAv* AV-pair ids of a Type 2 (Challenge) message's target info (all UTF-16LE text but the numeric ones).
_NTLM_AV = {1: "netbios_computer", 2: "netbios_domain", 3: "dns_computer", 4: "dns_domain", 5: "dns_tree",
            6: "av_flags", 7: "timestamp", 8: "single_host", 9: "target_name", 10: "channel_bindings"}
_NTLM_AV_TEXT = ("netbios_computer", "netbios_domain", "dns_computer", "dns_domain", "dns_tree", "target_name")
# base64 of "NTLMSS" (the stable 8-char prefix of any base64-wrapped NTLMSSP message), for a line protocol.
NTLM_B64_RE = re.compile(rb"TlRMTVNT[A-Za-z0-9+/]*={0,2}")


def _ntlm_text(raw, unicode_):
    """A Domain/User/Workstation/TargetName field as text; None when the buffer is absent."""
    if raw is None:
        return None
    try:
        s = bytes(raw).decode("utf-16-le" if unicode_ else "latin-1")
    except (UnicodeDecodeError, ValueError):
        s = bytes(raw).decode("latin-1", "replace")
    return s.rstrip("\x00")


def _ntlm_av_pairs(ti):
    """The target-info AV pairs of a Type 2 message as an ordered {name: value}."""
    out = OrderedDict()
    if not ti:
        return out
    ti = bytes(ti)
    o = 0
    while o + 4 <= len(ti):
        avid, avlen = struct.unpack_from("<HH", ti, o)
        o += 4
        if avid == 0 or o + avlen > len(ti):        # MsvAvEOL, or a length past the buffer
            break
        val = ti[o:o + avlen]
        o += avlen
        name = _NTLM_AV.get(avid)
        if name in _NTLM_AV_TEXT:
            out[name] = val.decode("utf-16-le", "replace").rstrip("\x00")
        elif name == "timestamp" and avlen == 8:
            out[name] = struct.unpack_from("<Q", val, 0)[0]
        elif name == "av_flags" and avlen >= 4:
            out[name] = struct.unpack_from("<I", val, 0)[0]
    return out


def parse_ntlmssp(blob):
    """One NTLMSSP message (MS-NLMP) at the start of `blob`, or None. Returns a Rec with `type`
    (1 Negotiate, 2 Challenge, 3 Authenticate), `flags`, and the fields that type carries: Type 1
    domain/workstation (OEM); Type 2 target_name, challenge (8 bytes), av; Type 3 user, domain,
    workstation, lm_response, nt_response. Every field is derived from the exact bytes."""
    if not isinstance(blob, (bytes, bytearray)):
        return None
    blob = bytes(blob)
    if blob[:8] != NTLM_SIG or len(blob) < 12:
        return None
    mtype = struct.unpack_from("<I", blob, 8)[0]
    if mtype not in (1, 2, 3):
        return None
    if (mtype == 1 and len(blob) < 16) or (mtype == 2 and len(blob) < 24):
        return None

    def sb(off):
        """The bytes of the security buffer whose (len, maxlen, offset) is at `off`, or None."""
        if off + 8 > len(blob):
            return None
        ln, _maxln, boff = struct.unpack_from("<HHI", blob, off)
        if ln == 0 or boff < 0 or boff + ln > len(blob):
            return None
        return blob[boff:boff + ln]

    r = Rec(type=mtype, signature="NTLMSSP", raw=blob)
    if mtype == 1:
        flags = struct.unpack_from("<I", blob, 12)[0]
        r.update(flags=flags,
                 domain=_ntlm_text(sb(16), False) if flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED else None,
                 workstation=_ntlm_text(sb(24), False) if flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED else None)
    elif mtype == 2:
        flags = struct.unpack_from("<I", blob, 20)[0]
        uni = bool(flags & NTLMSSP_NEGOTIATE_UNICODE)
        r.update(flags=flags, target_name=_ntlm_text(sb(12), uni),
                 challenge=blob[24:32] if len(blob) >= 32 else None, av=_ntlm_av_pairs(sb(40)))
    else:
        flags = struct.unpack_from("<I", blob, 60)[0] if len(blob) >= 64 else 0
        uni = bool(flags & NTLMSSP_NEGOTIATE_UNICODE) if len(blob) >= 64 else True
        r.update(flags=flags, lm_response=sb(12), nt_response=sb(20),
                 domain=_ntlm_text(sb(28), uni), user=_ntlm_text(sb(36), uni),
                 workstation=_ntlm_text(sb(44), uni))
    return r


def _netntlm_strings(user, domain, challenge, lm, nt):
    """[(format name, hash string)] for a captured NTLM response, hashcat/john order. NetNTLMv1 when
    the NT response is 24 bytes (-m 5500), NetNTLMv2 when it is longer (-m 5600). Empty when there is
    no NT response, user or 8-byte challenge: nothing to write. The format is the HYPOTHESIS (the name),
    the string the value -- it is never plain, only a candidate, because the judge's chosen format is
    not known. The response bytes are copied, never cracked."""
    if not user or not isinstance(challenge, (bytes, bytearray)) or len(challenge) != 8 or not nt:
        return []
    dom = domain or ""
    ch = bytes(challenge).hex()
    nt = bytes(nt)
    out = []
    if len(nt) == 24:
        lm = bytes(lm) if lm else b""
        lmh = lm.hex() if len(lm) == 24 else nt.hex()       # some clients send no distinct LM response
        out.append(("netntlmv1", f"{user}::{dom}:{lmh}:{nt.hex()}:{ch}"))
        if len(lm) == 24 and lm != nt:
            out.append(("netntlmv1_lmdup", f"{user}::{dom}:{nt.hex()}:{nt.hex()}:{ch}"))
    elif len(nt) > 24:
        proof, rest = nt[:16].hex(), nt[16:].hex()
        out.append(("netntlmv2", f"{user}::{dom}:{ch}:{proof}:{rest}"))
    return out


def _auth_params(value):
    """The `key=value` (or key="value") parameters of an HTTP auth header after its scheme word."""
    v = re.sub(r"(?is)^\s*[\w-]+\s+", "", str(value or ""), count=1)
    out = {}
    for m in re.finditer(r'([\w-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]*))', v):
        if m.group(1).lower() not in out:
            out[m.group(1).lower()] = (m.group(2) if m.group(2) is not None else (m.group(3) or "")).strip()
    return out


def _telnet_text(d):
    """A Telnet stream with its option negotiation taken out."""
    out, i, n = bytearray(), 0, len(d)
    while i < n:
        b = d[i]
        if b != 0xFF:
            out.append(b)
            i += 1
        elif i + 1 < n and d[i + 1] == 0xFF:
            out.append(0xFF)
            i += 2
        elif i + 1 < n and d[i + 1] == 0xFA:
            e = d.find(b"\xff\xf0", i + 2)
            i = e + 2 if e >= 0 else n
        elif i + 1 < n and d[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE):
            i += 3
        else:
            i += 2
    return bytes(out)


def _edit_lines(typed):
    out = []
    for ln in re.split(rb"\r\n|\r\x00|\r|\n", typed):
        cur = bytearray()
        for b in ln:
            if b in (8, 127):
                del cur[-1:]
            elif b:
                cur.append(b)
        out.append(bytes(cur))
    while out and not out[-1]:
        out.pop()
    return out


def _grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _tls_handshakes(data):
    """[(type, body)] of the handshake messages sent in the clear at the start of a TLS stream."""
    buf, o = bytearray(), 0
    while o + 5 <= len(data):
        ctype, major, ln = data[o], data[o + 1], (data[o + 3] << 8) | data[o + 4]
        if major != 3 or ctype not in (20, 21, 22, 23) or ln > 18432:
            break
        if ctype != 22:
            break               # after the change of cipher the handshake is no longer readable
        buf += data[o + 5:o + 5 + ln]
        o += 5 + ln
    out, o = [], 0
    while o + 4 <= len(buf):
        ln = int.from_bytes(buf[o + 1:o + 4], "big")
        if o + 4 + ln > len(buf):
            break
        out.append((buf[o], bytes(buf[o + 4:o + 4 + ln])))
        o += 4 + ln
    return out


def _exts(b, o):
    out = []
    if o + 2 > len(b):
        return out
    end = min(len(b), o + 2 + ((b[o] << 8) | b[o + 1]))
    o += 2
    while o + 4 <= end:
        t, ln = struct.unpack_from("!HH", b, o)
        out.append((t, b[o + 4:o + 4 + ln]))
        o += 4 + ln
    return out


def _u16s(b):
    return [(b[i] << 8) | b[i + 1] for i in range(0, len(b) - 1, 2)]


def _client_hello(b):
    """SNI, ALPN, JA3 and JA4 of a ClientHello body, or None."""
    try:
        ver = (b[0] << 8) | b[1]
        o = 34
        o += 1 + b[o]
        n = (b[o] << 8) | b[o + 1]
        ciphers = _u16s(b[o + 2:o + 2 + n])
        o += 2 + n
        o += 1 + b[o]
        exts = _exts(b, o)
    except IndexError:
        return None
    sni, alpn, groups, points, versions, sigalgs = None, [], [], [], [], []
    for t, v in exts:
        try:
            if t == 0 and len(v) >= 5:
                sni = v[5:5 + ((v[3] << 8) | v[4])].decode("latin-1")
            elif t == 16:
                x = 2
                while x < len(v):
                    alpn.append(v[x + 1:x + 1 + v[x]].decode("latin-1"))
                    x += 1 + v[x]
            elif t == 10:
                groups = _u16s(v[2:])
            elif t == 11:
                points = list(v[1:1 + v[0]])
            elif t == 43:
                versions = _u16s(v[1:1 + v[0]])
            elif t == 13:
                sigalgs = _u16s(v[2:])
        except IndexError:
            pass
    cs = [c for c in ciphers if not _grease(c)]
    ex = [t for t, _ in exts if not _grease(t)]
    ja3s = ",".join([str(ver), "-".join(map(str, cs)), "-".join(map(str, ex)),
                     "-".join(str(g) for g in groups if not _grease(g)), "-".join(map(str, points))])
    best = max([v for v in versions if not _grease(v)] or [ver])
    vtxt = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}.get(best, "00")
    a = alpn[0] if alpn else ""
    atxt = (a[0] + a[-1]) if a and a[0].isalnum() and a[-1].isalnum() else (a.encode("latin-1").hex()[0] + a.encode("latin-1").hex()[-1]) if a else "00"
    part_b = hashlib.sha256(",".join(sorted(f"{c:04x}" for c in cs)).encode()).hexdigest()[:12] if cs else "0" * 12
    rest = ",".join(sorted(f"{t:04x}" for t in ex if t not in (0x0000, 0x0010)))
    sig = ",".join(f"{s:04x}" for s in sigalgs)
    part_c = hashlib.sha256((rest + ("_" + sig if sig else "")).encode()).hexdigest()[:12] if ex else "0" * 12
    ja4 = f"t{vtxt}{'d' if sni else 'i'}{min(len(cs), 99):02d}{min(len(ex), 99):02d}{atxt}_{part_b}_{part_c}"
    return dict(version=ver, client_random=b[2:34].hex(), sni=sni, alpn=alpn, ciphers=ciphers,
                extensions=[t for t, _ in exts], groups=groups,
                supported_versions=versions, ja3_string=ja3s, ja3=hashlib.md5(ja3s.encode()).hexdigest(), ja4=ja4)


def _server_hello(b):
    try:
        ver = (b[0] << 8) | b[1]
        o = 34
        o += 1 + b[o]
        cipher = (b[o] << 8) | b[o + 1]
        exts = _exts(b, o + 3)
    except IndexError:
        return None
    s = f"{ver},{cipher},{'-'.join(str(t) for t, _ in exts if not _grease(t))}"
    sel = next((_u16s(v)[0] for t, v in exts if t == 43 and len(v) >= 2), ver)
    return dict(server_version=sel, cipher=cipher, ja3s_string=s, ja3s=hashlib.md5(s.encode()).hexdigest())


def _printable(b) -> bool:
    try:
        s = bytes(b).decode("utf-8")
    except UnicodeDecodeError:
        return False
    s = s.strip("\x00")
    return bool(s) and all(c.isprintable() or c in "\r\n\t" for c in s)


def decodings(blob: bytes) -> dict:
    """{method: bytes} for the strict decodings a text has: hex, base32, base64, base64url. Only a
    text made of that alphabet alone decodes; nothing is repaired but missing padding."""
    out = OrderedDict()
    s = bytes(blob).strip()
    if not s:
        return out
    if len(s) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", s):
        out["hex"] = bytes.fromhex(s.decode())
    if re.fullmatch(rb"[A-Z2-7]+=*", s.upper()) and len(s) >= 8:
        t = s.upper().rstrip(b"=")
        try:
            out["base32"] = base64.b32decode(t + b"=" * (-len(t) % 8))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(rb"[A-Za-z0-9+/]+=*", s) and len(s) >= 4:
        t = s.rstrip(b"=")
        if len(t) % 4 != 1:
            try:
                out["base64"] = base64.b64decode(t + b"=" * (-len(t) % 4), validate=True)
            except (binascii.Error, ValueError):
                pass
    if re.fullmatch(rb"[A-Za-z0-9_-]+=*", s) and (b"-" in s or b"_" in s):
        t = s.rstrip(b"=")
        if len(t) % 4 != 1:
            try:
                out["base64url"] = base64.urlsafe_b64decode(t + b"=" * (-len(t) % 4))
            except (binascii.Error, ValueError):
                pass
    return out


def _per_piece(pieces) -> dict:
    """{method: bytes}: every piece decoded by itself with one method, then joined."""
    out = OrderedDict()
    each = [decodings(p) for p in pieces]
    for meth in ("hex", "base32", "base64", "base64url"):
        if each and all(meth in d for d in each):
            out[meth] = b"".join(d[meth] for d in each)
    return out


# ---- sequence-aware DNS exfil (B-079) ------------------------------------------------------------------
# One shared reassembly for every reader of a DNS label channel (Capture.dns_tunnel here and
# covert_channels.dns_exfil): an exfil client that numbers its chunks writes <data>.<NN>.<zone> (or
# <NN>.<data>.<zone>) and may send them out of order, more than once, with cover traffic around them.

_SEQ_LABEL = re.compile(r"[0-9]{1,6}")
_SEQ_DATA_LABEL = re.compile(r"[A-Za-z0-9_+=-]+")


def dns_seq_readings(qname):
    """Every (layout, seq, data, zone) reading of one query name that carries a numeric sequence label,
    preferred first; [] when it carries none. layout "data.seq": <data labels...>.<NN>.<zone of two or
    more labels>, one reading for each all-digit label after at least one data label, the earliest
    first (3132.3334.01.evil.com, a hex chunk of ASCII digits in two labels, reads as number 3334 in
    zone 01.evil.com and as number 1 in zone evil.com); "seq.data": <NN>.<one data label>.<zone>. A
    name can fit both (05.313233.zone; 05.ab.07.x.example): data.seq comes first, except when the
    first two labels are both all digits and the first is the shorter (it is then the likelier
    counter). dns_sequences picks among the readings by what the source's other names fit. Reverse
    lookups, .local names and _service names never carry a sequence."""
    name = (qname or "").rstrip(".")
    labels = name.split(".")
    low = name.lower()
    if len(labels) < 4 or low.endswith((".arpa", ".local")) or any(x.startswith("_") or not x for x in labels):
        return []
    out = []
    for i in range(1, len(labels) - 2):             # the zone after the number keeps two labels or more
        if not _SEQ_DATA_LABEL.fullmatch(labels[i - 1]):
            break                                   # every label in front of the number is data
        if _SEQ_LABEL.fullmatch(labels[i]):
            out.append(("data.seq", int(labels[i]), "".join(labels[:i]), ".".join(labels[i + 1:]).lower()))
    if _SEQ_LABEL.fullmatch(labels[0]) and _SEQ_DATA_LABEL.fullmatch(labels[1]):
        seq_first = ("seq.data", int(labels[0]), labels[1], ".".join(labels[2:]).lower())
        if out and _SEQ_LABEL.fullmatch(labels[1]) and len(labels[0]) < len(labels[1]):
            out.insert(0, seq_first)
        else:
            out.append(seq_first)
    return out


def dns_seq_parse(qname):
    """The preferred (layout, seq, data, zone) reading of one query name (dns_seq_readings), or None."""
    got = dns_seq_readings(qname)
    return got[0] if got else None


def dns_sequences(queries, min_parts: int = 2):
    """[Rec(src, zone, layout, names, seq, labels, joined, decoded, per_label, missing, repeats,
    conflicts, qnames, members)] for every (source, zone, layout) whose queries carry two or more distinct
    sequence numbers (min_parts or more), largest first. queries is an iterable of (src, qname) of DNS
    queries in the order asked (src may be None). A name that fits both layouts (dns_seq_readings) takes
    the layout and zone that most of the source's unambiguous names fit; on a tie, the one most of the
    source's readings of every name fit (a stream whose names are all ambiguous still shares one zone);
    then its own preferred reading.
    Within a stream the data labels are sorted by their number, an exact repeat is dropped
    (repeats counts it), a number asked again with other data keeps the first asked (conflicts lists
    the rest) and the sequence labels are stripped before the join (qnames: the name kept for each
    number, in order; members: every name the stream took, repeats included); missing names the numbers absent
    between the lowest and the highest. A stream whose numbers are mostly gaps (more missing than
    present), or whose data label never changes, is not a stream. decoded is the joined text's strict decodings (decodings())."""
    parsed, fits, any_fits = [], {}, {}
    for src, qname in queries:
        got = dns_seq_readings(qname)
        if not got:
            continue
        parsed.append((src, qname, got))
        if len(got) == 1:
            layout, _seq, _data, zone = got[0]
            fits[(src, zone, layout)] = fits.get((src, zone, layout), 0) + 1
        for key in {(src, r[3], r[0]) for r in got}:
            any_fits[key] = any_fits.get(key, 0) + 1
    groups = OrderedDict()
    for src, qname, got in parsed:
        # max keeps the first (preferred) reading on a tie
        pick = max(got, key=lambda r: (fits.get((src, r[3], r[0]), 0), any_fits.get((src, r[3], r[0]), 0)))
        layout, seq, data, zone = pick
        g = groups.setdefault((src, zone, layout), OrderedDict())
        g.setdefault(seq, []).append((data, qname.rstrip(".")))
    out = []
    for (src, zone, layout), g in groups.items():
        if len(g) < max(2, min_parts):
            continue
        nums = sorted(g)
        missing = [n for n in range(nums[0], nums[-1] + 1) if n not in g]
        if len(missing) > len(nums):
            continue
        labels, repeats, conflicts, qnames = [], 0, [], []
        for n in nums:
            first = g[n][0][0]
            labels.append(first)
            qnames.append(g[n][0][1])
            for data, qn in g[n][1:]:
                if data == first:
                    repeats += 1
                else:
                    conflicts.append(qn)
        if len(set(labels)) == 1:
            continue        # one name with a counter in it (0..3.pool.ntp.org): no data moves
        joined = "".join(labels)
        out.append(Rec(src=src, zone=zone, layout=layout, names=len(nums), seq=nums, labels=labels,
                       joined=joined, decoded=decodings(joined.encode()),
                       per_label=_per_piece([x.encode() for x in labels]), missing=missing,
                       repeats=repeats, conflicts=conflicts, qnames=qnames,
                       members=[qn for n in nums for _d, qn in g[n]]))
    out.sort(key=lambda r: -r.names)
    return out


def _standard_ping(d: bytes) -> bool:
    if not d:
        return True
    if d.startswith(b"abcdefghijklmnopqrstuvwabcdefghi"[:len(d)]) and len(d) <= 32:
        return True
    return len(d) <= 248 and any(len(d) > k and d[k:] == bytes(range(k, len(d))) for k in (8, 16))


_HID = {40: "\n", 42: "\b", 43: "\t", 44: " ", 45: "-_", 46: "=+", 47: "[{", 48: "]}", 49: "\\|", 50: "#~", 51: ";:",
        52: "'\"", 53: "`~", 54: ",<", 55: ".>", 56: "/?", 84: "/", 85: "*", 86: "-", 87: "+", 88: "\n", 99: "."}
_HID_DIGITS = "1234567890"
_HID_SHIFT = "!@#$%^&*()"


def _hid(k, shift, caps):
    if 4 <= k <= 29:
        ch = chr(ord("a") + k - 4)
        return ch.upper() if shift != caps else ch
    if 30 <= k <= 39:
        return _HID_SHIFT[k - 30] if shift else _HID_DIGITS[k - 30]
    if 89 <= k <= 98:
        return "1234567890"[k - 89]
    v = _HID.get(k)
    if v is None:
        return None
    return v if len(v) == 1 else v[1 if shift else 0]


# ---- readers by hand ---------------------------------------------------------------------------------

def read(x, name: str = "", limit=None) -> Capture:
    """A Capture from a Capture, the bytes of a pcap or pcapng file (gzip around it is removed), or a
    path. limit stops the read after that many packets (cap.truncated)."""
    if isinstance(x, Capture):
        return x
    if isinstance(x, (str, Path)):
        name, x = name or Path(x).name, Path(x).read_bytes()
    x = bytes(x)
    inner = gunzip_capture(x)
    return Capture(inner if inner is not None else x, name, limit)


def _reader(method):
    def fn(x):
        return getattr(read(x), method)()
    fn.__name__ = method
    fn.__doc__ = getattr(Capture, method).__doc__
    return fn


for _m in ("times", "protocols", "conversations", "endpoints", "streams", "conns", "banners", "dns", "dhcp", "http", "tls",
           "certs", "ftp", "smtp", "telnet", "credentials", "ntlm", "http_digest", "tftp", "objects", "icmp_payloads",
           "dns_tunnel", "beacons", "syn_scan", "open_ports", "usb_keystrokes", "modbus"):
    globals()[_m] = _reader(_m)


def hidden(x, channel="icmp") -> dict:
    return read(x).hidden(channel)


FIELDS = {"ip_id": lambda p: p.ipid, "ttl": lambda p: p.ttl, "tos": lambda p: p.tos, "tcp_urg": lambda p: p.urg,
          "tcp_win": lambda p: p.win, "tcp_seq": lambda p: p.seq, "tcp_ack": lambda p: p.ack, "tcp_flags": lambda p: p.flags,
          "sport": lambda p: p.sport, "dport": lambda p: p.dport, "icmp_id": lambda p: p.iid, "icmp_seq": lambda p: p.iseq,
          "icmp_code": lambda p: p.icode, "length": lambda p: p.wire, "payload_length": lambda p: len(p.payload),
          "first_byte": lambda p: p.payload[0] if p.payload else None,
          "last_byte": lambda p: p.payload[-1] if p.payload else None,
          "time_gap_ms": None}


def field(x, name: str, where=None) -> list:
    """One value per packet, in capture order: ip_id, ttl, tos, tcp_urg, tcp_win, tcp_seq, tcp_ack,
    tcp_flags, sport, dport, icmp_id, icmp_seq, icmp_code, length, payload_length, first_byte,
    last_byte, or time_gap_ms (the gap to the packet before, among the chosen ones). `where` is a
    test on the packet (lambda p: p.dst == '10.0.0.9'); packets without the field are left out."""
    pk = [p for p in read(x).packets if where is None or where(p)]
    if name == "time_gap_ms":
        ts = [p.ts for p in pk if p.ts is not None]
        return [round((b - a) / 1e6) for a, b in zip(ts, ts[1:])]
    fn = FIELDS[name]
    return [v for v in (fn(p) for p in pk) if v is not None]


def bitstream(values, bits: int = 1, msb_first: bool = True) -> bytes:
    """Bytes from one small number per packet: the low `bits` bits of every value, joined."""
    acc = "".join(format(int(v) & ((1 << bits) - 1), f"0{bits}b") for v in values)
    acc = acc[:len(acc) - len(acc) % 8]
    out = bytes(int(acc[i:i + 8], 2) for i in range(0, len(acc), 8))
    return out if msb_first else bytes(int(f"{b:08b}"[::-1], 2) for b in out)


def as_text(values) -> str:
    """One character per value (a field that carries a byte in each packet); '' unless printable."""
    try:
        b = bytes(int(v) & 0xFF for v in values)
    except (TypeError, ValueError):
        return ""
    return b.decode("utf-8", "replace") if _printable(b) else ""


# ---- tshark, in the sandbox, off the timed path ---------------------------------------------------------

def _sandbox():
    tools = str(ROOT / "tools")
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import sandbox
    return sandbox


def tshark(data, args=(), timeout: float = 60.0, name: str = "capture.pcap", keep_files: bool = False) -> Rec:
    """Run the sandbox's tshark on a capture: tshark -r <capture> ARGS. Rec(ok, stdout, stderr, files,
    note). A sandbox that is down gives ok=False and the reason; nothing is ever run natively.
    Never call this from solve_set: it is a docker exec (0.3 s and up)."""
    if isinstance(data, (str, Path)):
        name, data = Path(data).name, Path(data).read_bytes()
    try:
        sb = _sandbox()
    except Exception as e:
        return Rec(ok=False, stdout="", stderr="", files={}, note=f"tools/sandbox.py cannot be loaded ({type(e).__name__}): not read")
    try:
        r = sb.run("tshark", ["-r", "{in}", *[str(a) for a in args]], inputs=[(name, bytes(data))], timeout=timeout)
    except sb.SandboxDown as e:
        return Rec(ok=False, stdout="", stderr="", files={}, note=f"sandbox down: {e}: not read")
    return Rec(ok=r.code == 0, code=r.code, stdout=r.stdout.decode("utf-8", "replace"), stderr=r.stderr.decode("utf-8", "replace"),
               files=dict(r.files) if keep_files else {}, note=r.note or "")


def tshark_fields(data, fields, display_filter: str = "", timeout: float = 60.0):
    """[[value, ...], ...]: tshark -T fields for the named fields, one row per packet that passes the
    display filter; None when the sandbox is down or tshark failed."""
    args = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|"]
    for f in fields:
        args += ["-e", f]
    if display_filter:
        args += ["-Y", display_filter]
    r = tshark(data, args, timeout)
    if not r.ok:
        return None
    return [ln.split("\t") for ln in r.stdout.splitlines()]


def tshark_objects(data, proto: str = "http", timeout: float = 120.0):
    """{name: bytes} of tshark --export-objects (http, smb, tftp, imf, dicom, ftp-data); None when the
    sandbox is down."""
    r = tshark(data, ["-q", "--export-objects", f"{proto},{{out}}/objects"], timeout, keep_files=True)
    if not r.ok:
        return None
    return {k.split("/", 1)[-1]: v for k, v in r.files.items() if k.startswith("objects/")}


# ---- sandbox TLS/QUIC hand tool (C5); the separate native TCP/TLS gate below is on solve_set --------------
# When the delivery carries the session keys (an SSLKEYLOGFILE member, or a pcapng Decryption Secrets
# block), tshark can inspect HTTPS/QUIC by hand. Never called by solve_set: tls_decrypt remains a
# docker exec, like tshark. Production solve_set uses the bounded TCP/TLS-only reader below instead.

_KEYLOG_LABEL = (rb"CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|"
                 rb"CLIENT_TRAFFIC_SECRET_0|SERVER_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|"
                 rb"EARLY_EXPORTER_SECRET|EXPORTER_SECRET|RSA|RSA_SESSION_ID|"
                 rb"QUIC_CLIENT_[A-Z0-9_]+|QUIC_SERVER_[A-Z0-9_]+|(?:CLIENT|SERVER)_[A-Z0-9_]+_SECRET")
_KEYLOG_LINE = re.compile(rb"(?m)^(?:" + _KEYLOG_LABEL + rb")[ \t]+[0-9a-fA-F]{16,}(?:[ \t]+[0-9a-fA-F]{16,})?[ \t]*$")
_DSB_TLS_KEYLOG = 0x544C534B        # pcapng Decryption Secrets Block, secrets type "TLSK"


def _looks_like_keylog(data) -> bool:
    return (isinstance(data, (bytes, bytearray)) and 0 < len(data) <= 64 * 1024 * 1024
            and _KEYLOG_LINE.search(bytes(data[:8192])) is not None)


_NATIVE_TLS_KEYLOG_LINE = re.compile(
    rb"(?m)^(CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|"
    rb"CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0)[ \t]+"
    rb"([0-9a-fA-F]{64})[ \t]+([0-9a-fA-F]+)[ \t]*$")


def _native_tls_keylog_randoms(data):
    """ClientHello.random values in exact TLS 1.2/1.3 NSS entries; QUIC/generic labels do not gate."""
    if not isinstance(data, (bytes, bytearray)) or not (0 < len(data) <= 64 * 1024 * 1024):
        return set()
    out = set()
    for match in _NATIVE_TLS_KEYLOG_LINE.finditer(bytes(data)):
        label, client_random, secret = match.groups()
        if ((label == b"CLIENT_RANDOM" and len(secret) == 96)
                or (label != b"CLIENT_RANDOM" and len(secret) in (64, 96))):
            out.add(client_random.lower().decode("ascii"))
    return out


def _keylog_in_capture(cap_data):
    """The NSS key log inside a pcapng's Decryption Secrets Blocks (secrets type TLS Key Log, or any
    block whose bytes read as a key log), joined, or None. Reads bytes only."""
    if not is_capture(cap_data):
        return None
    try:
        cap = Capture(bytes(cap_data), limit=MAX_PACKETS)
    except ValueError:
        return None
    chunks = [bytes(b) for t, b in cap.secrets if t == _DSB_TLS_KEYLOG or _looks_like_keylog(b)]
    return b"\n".join(chunks) if chunks else None


def find_keylog(files) -> list:
    """[(source, keylog bytes)] of TLS/QUIC key material shipped in a delivery: a member whose lines
    are NSS key-log entries (CLIENT_RANDOM ..., *_TRAFFIC_SECRET_0 ..., QUIC_*), and the decryption
    secrets of any pcapng among the files. Deterministic; reads bytes only, starts nothing."""
    out = []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)):
            continue
        name = key.split(ARROW)[-1]
        cap = data if is_capture(data) else gunzip_capture(data)
        if cap is not None:
            k = _keylog_in_capture(cap)
            if k:
                out.append((name + " (pcapng decryption secrets)", k))
            continue
        if _looks_like_keylog(data):
            out.append((name, bytes(data)))
    return out


def _tshark_keylog(cap_data, keylog_data, args, timeout: float = 120.0, keep_files: bool = False,
                   cap_name: str = "capture.pcap", key_name: str = "sslkeylog.txt") -> Rec:
    """tshark -r <capture> -o tls.keylog_file:<keylog> ARGS, through the sandbox (two inputs). The
    key log reaches the container as a second input file; nothing is ever run natively."""
    if isinstance(cap_data, (str, Path)):
        cap_name, cap_data = Path(cap_data).name, Path(cap_data).read_bytes()
    try:
        sb = _sandbox()
    except Exception as e:
        return Rec(ok=False, stdout="", stderr="", files={}, note=f"tools/sandbox.py cannot be loaded ({type(e).__name__}): not read")
    full = ["-r", "{in0}", "-o", "tls.keylog_file:{in1}", *[str(a) for a in args]]
    try:
        r = sb.run("tshark", full, inputs=[(cap_name, bytes(cap_data)), (key_name, bytes(keylog_data))], timeout=timeout)
    except sb.SandboxDown as e:
        return Rec(ok=False, stdout="", stderr="", files={}, note=f"sandbox down: {e}: not read")
    return Rec(ok=r.code == 0, code=r.code, stdout=r.stdout.decode("utf-8", "replace"),
               stderr=r.stderr.decode("utf-8", "replace"), files=dict(r.files) if keep_files else {}, note=r.note or "")


def tls_decrypt(cap_data, keylog_data, timeout: float = 120.0) -> Rec:
    """Decrypt a TLS/QUIC capture with a key log shipped in the delivery, through the sandbox's
    tshark (tls.keylog_file). Returns Rec(ok, decrypted, http, objects, note):
      http     [Rec(frame, method, host, uri, status, url)] of the requests read once decrypted,
      objects  [Rec(name, size, sha256, md5, data)] of --export-objects http.
    `decrypted` is True when any application data came back: the key log was right and the plaintext
    parsed, which is the self-check that makes these facts plain-eligible. ok/decrypted False when
    the sandbox is down or nothing decrypted. Off the timed path -- a docker exec; not for solve_set."""
    http = []
    r = _tshark_keylog(cap_data, keylog_data, [
        "-Y", "http || http2 || http3", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "http.request.method", "-e", "http.host",
        "-e", "http.request.uri", "-e", "http.response.code", "-e", "http.request.full_uri"], timeout)
    if r.ok:
        for ln in r.stdout.splitlines():
            if not ln.strip():
                continue
            c = (ln.split("\t") + [""] * 6)[:6]
            http.append(Rec(frame=c[0] or None, method=c[1] or None, host=c[2] or None,
                            uri=c[3] or None, status=c[4] or None, url=c[5] or None))
    objects = []
    ro = _tshark_keylog(cap_data, keylog_data, ["-q", "--export-objects", "http,{out}/objects"], timeout, keep_files=True)
    if ro.ok:
        for k, v in sorted(ro.files.items()):
            if k.startswith("objects/"):
                objects.append(Rec(name=k.split("/", 1)[-1], size=len(v),
                                   sha256=hashlib.sha256(v).hexdigest(), md5=hashlib.md5(v).hexdigest(), data=v))
    decrypted = bool(http) or bool(objects)
    note = ""
    if not r.ok and not ro.ok:
        note = r.note or ro.note or "tshark did not run"
    elif not decrypted:
        note = "no application data decrypted (the key log does not match this capture)"
    return Rec(ok=bool(r.ok or ro.ok), decrypted=decrypted, http=http, objects=objects, note=note)


def tls_decrypt_bundle(files, timeout: float = 120.0) -> list:
    """Find each capture in a delivery and, when a key log ships with it (a member, or a pcapng
    decryption-secrets block inside it), decrypt it. Returns [Rec(capture, keylog_source, decrypted,
    http, objects, note)], one per capture; [] when there is no capture. A capture with no key
    material gets decrypted=False and a 'no key log in the delivery' note -- the caller DEFERS
    (detect only), unchanged from before. The key log being IN the delivery is what makes the
    recovered facts deterministic and plain-eligible. Off the timed path."""
    out = []
    caps = find_captures(files)
    bundle = find_keylog(files)
    for cname, cdata in caps:
        local = _keylog_in_capture(cdata)
        # a key log inside this capture wins; else any key-log member of the bundle
        extern = next((b for src, b in bundle if "pcapng decryption secrets" not in src), None)
        keylog = local or extern
        if keylog is None:
            out.append(Rec(capture=cname, keylog_source=None, decrypted=False, http=[], objects=[],
                           note="no key log in the delivery: encrypted TLS is not decrypted (detect and defer)"))
            continue
        r = tls_decrypt(cdata, keylog, timeout)
        r.capture = cname
        r.keylog_source = "pcapng decryption secrets" if local else "bundle member"
        out.append(r)
    return out


# ---- signals -------------------------------------------------------------------------------------------

_STRONG = re.compile(r"\bpcap(?:ng)?\b|\bpacket capture\b|\bwireshark\b|\btshark\b|\bnetwork capture\b|\btraffic capture\b", re.I)
_NET = re.compile(r"\bpackets?\b|\bcapture\b|\bdns\b|\bhttp\b|\btls\b|\bsni\b|\bja3s?\b|\bja4\b|\buser.agent\b|\bbeacon"
                  r"|\btcp\b|\budp\b|\bicmp\b|\bftp\b|\bsmtp\b|\btelnet\b|\bip address\b|\bport\b|\btraffic\b|\bhandshake\b"
                  r"|\bmac address\b|\bquer(?:y|ied|ies)\b|\bexfiltrat|\bc2\b", re.I)


def find_captures(files: dict) -> list:
    """[(name, capture bytes)] of the captures among a delivery's files, once per file; a gzip around
    one is removed."""
    out, seen = [], set()
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        if is_capture(data):
            out.append((key, bytes(data)))
        else:
            inner = gunzip_capture(data)
            if inner is not None:
                out.append((key, inner))
    return out


def _qtext(q) -> str:
    f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return " ".join(str(x or "") for x in (q.get("question"), q.get("artifact"), f.get("syntax"),
                                           re.sub(r"[-_./]+", " ", str(q.get("answer_id") or q.get("id") or ""))))


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like network forensics. A capture among
    the files is 0.7, and the share of questions that speak of the network adds up to 0.3. Without
    a capture only questions that name one count, up to 0.3."""
    try:
        caps = bool(find_captures(files or {}))
    except Exception:
        caps = False
    qs = list(questions or [])
    texts = [_qtext(q) for q in qs]
    if caps:
        share = sum(1 for t in texts if _NET.search(t) or _STRONG.search(t)) / len(texts) if texts else 0.0
        return round(0.7 + 0.3 * share, 3)
    if not texts:
        return 0.0
    return round(0.3 * sum(1 for t in texts if _STRONG.search(t)) / len(texts), 3)


# ---- the runner contract ---------------------------------------------------------------------------------

_cap_cache = OrderedDict()      # (id of the bytes, length) -> Capture, for a Mastery that asks one file many times


def _cap_of(name, data) -> Capture:
    k = (id(data), len(data), data[:64], data[-64:])
    c = _cap_cache.get(k)
    if c is None:
        c = _cap_cache[k] = Capture(data, name.split(ARROW)[-1], limit=MAX_PACKETS)
        while len(_cap_cache) > 8:
            _cap_cache.popitem(last=False)
    return c


def _common(name):
    """solvers/common/<name>.py, by its path: the module already loaded from there, else loaded now."""
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


def _native_tls_ready(files, caps):
    """Exact cheap gate for the in-process TLS reader. Ordinary captures stop before import/decrypt:
    the delivery must contain a syntactically valid key-log member or a TLSK pcapng DSB, and a
    capture must expose a TLS handshake. QUIC/key-log evidence alone does not qualify."""
    external_randoms = set()
    local_randoms = {}
    for key, data in (files or {}).items():
        if not isinstance(data, (bytes, bytearray)):
            continue
        if not is_capture(data):
            external_randoms.update(_native_tls_keylog_randoms(data))
    little = struct.pack("<I", _DSB_TLS_KEYLOG)
    big = struct.pack(">I", _DSB_TLS_KEYLOG)
    for name, data in caps:
        if data[:4] != PCAPNG_MAGIC or little not in data and big not in data:
            continue
        try:
            cap = _cap_of(name, data)
        except Exception:
            continue
        randoms = set()
        for stype, blob in cap.secrets:
            if stype == _DSB_TLS_KEYLOG:
                randoms.update(_native_tls_keylog_randoms(blob))
        if randoms:
            local_randoms[name] = randoms
    if not external_randoms and not local_randoms:
        return False
    for name, data in caps:
        available = external_randoms | local_randoms.get(name, set())
        if not available:
            continue
        try:
            cap = _cap_of(name, data)
            hellos = {str(row.client_random).lower() for row in cap.tls() if row.client_random}
            if not cap.truncated and hellos & available:
                return True
        except Exception:
            continue
    return False


def _native_tls_answers(questions, files, caps):
    if not _native_tls_ready(files, caps):
        return None
    try:
        tls = _common("tls_keylog")
        # Use the already-normalised capture bytes (including a gzip-wrapped capture) plus every
        # exact key-log member. Nothing else in the delivery is handed to the specialist.
        native_files = {name: data for name, data in caps}
        for key, data in (files or {}).items():
            if (isinstance(data, (bytes, bytearray)) and not is_capture(data)
                    and _native_tls_keylog_randoms(data)):
                native_files[key] = bytes(data)
        return tls.solve_set(questions, native_files, {})
    except Exception:
        return None


def _pick(key, options):
    """labels.pick; the same wire form written here while labels.py does not know the lane `network`."""
    options = [(n, v) for n, v in options if v is not None and v != ""][:MAX_OPTIONS]
    if not options:
        return None
    try:
        return _common("labels").pick(key, options)
    except Exception:
        pass                    # ValueError: the lane is not registered, so nothing is known about the key
    return SENTINEL + json.dumps({"k": key.lower(), "o": [[n, v] for n, v in options]}, separators=(",", ":"))


def _candidates(key, options):
    """labels.candidates (row 346): a few DIFFERENT values, best first, each named by its
    hypothesis; never plain before the judge accepts a name. The same wire form (key marked
    #candidates) is written here if labels.py cannot place the lane."""
    options = [(n, v) for n, v in options if v is not None and v != ""][:MAX_OPTIONS]
    if not options:
        return None
    try:
        return _common("labels").candidates(key, options)
    except Exception:
        pass
    ck = key.lower()
    if not ck.endswith("#candidates"):
        ck += "#candidates"
    return SENTINEL + json.dumps({"k": ck, "o": [[n, v] for n, v in options]}, separators=(",", ":"))


def _triage():
    try:
        return _common("triage")
    except Exception:
        return None


_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])", re.I)
_FILE_EXT = re.compile(r"\.(?:pcap|pcapng|cap|gz|zip|7z|txt|json|csv|log)$", re.I)
_ALGO = re.compile(r"\b(sha-?256|sha-?1|md5|sha-?512|sha-?384|crc-?32|ssdeep|imphash)\b", re.I)
_PROTO_WORDS = (("ftp", r"\bftp\b"), ("smtp", r"\bsmtp\b"), ("telnet", r"\btelnet\b"),
                ("pop3", r"\bpop3?\b"), ("imap", r"\bimap\b"), ("http", r"\bhttps?\b|\bweb\b|\bform\b|\bbasic auth"),
                ("tftp", r"\btftp\b"), ("dns", r"\bdns\b"), ("tls", r"\btls\b|\bssl\b|\bhttps\b"), ("ssh", r"\bssh\b"),
                ("icmp", r"\bicmp\b|\bping\b"))


class _Q:
    """One question, read: its words, the selector it asks by, the addresses, ports and names it gives."""

    def __init__(self, q, files):
        self.q = q
        self.text = " ".join(str(q.get("question") or "").split())
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        self.fmt = f
        self.kind = str(f.get("kind") or "")
        self.syntax = str(f.get("syntax") or "")
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        self.low = self.text.lower()
        self.words = (self.text + " | " + re.sub(r"[-_./]+", " ", aid)).lower()
        self.upper = re.search(r"\bupper-?case\b", self.text + " " + self.syntax, re.I) is not None
        low = self.low
        self.unique = re.search(r"\b(unique|distinct|different)\b", low) is not None
        if re.search(r"\bhow many\b|\bnumber of\b|\bcount of\b|\btotal number\b", low):
            self.sel = "count"
        elif self.kind in ("ordered_tokens", "json") or re.search(r"\blist (?:all|every|each|the)\b|\ball (?:of )?the\b|\bin order\b", low):
            self.sel = "all"
        elif re.search(r"\bmost (?:frequent|common|often|queried|requested|visited|contacted|popular|used)\w*|\btop\b|\bhighest number\b", low):
            self.sel = "most"
        elif re.search(r"\b(?:first|earliest|initial(?:ly)?)\b", low):
            self.sel = "first"
        elif re.search(r"\b(?:last|latest|final|most recent)\b", low):
            self.sel = "last"
        else:
            self.sel = "only"
        self.ips = []
        for m in _IPV4.finditer(self.text):
            before = self.low[max(0, m.start() - 40):m.start()]
            role = "dst" if re.search(r"\b(?:to|towards|toward|destination|dst|against|at|on)\s+(?:the\s+)?(?:(?:host|server|ip|address|machine)\s+){0,2}$", before) \
                else "src" if re.search(r"\b(?:from|source|src|by)\s+(?:the\s+)?(?:(?:host|client|ip|address|machine)\s+){0,2}$", before) else "any"
            if (m.group(), role) not in self.ips:
                self.ips.append((m.group(), role))
        self.ports = [int(x) for x in re.findall(r"\bport\s+(\d{1,5})\b", low)]
        delivered = {k.split(ARROW)[-1].rsplit("/", 1)[-1].lower() for k in files}
        self.names = [m.group().lower() for m in _DOMAIN.finditer(self.text)
                      if m.group().lower() not in delivered and not _FILE_EXT.search(m.group())]
        self.file_names = [m.group().lower() for m in re.finditer(r"(?<![\w./@-])[\w-][\w.-]*\.[A-Za-z][A-Za-z0-9]{1,5}(?![\w-])", self.text)
                           if m.group().lower() not in delivered and not _IPV4.fullmatch(m.group())
                           and not re.search(r"\.(?:com|net|org|io|example|local|test|invalid|corp|lan|ru|cn|info|biz|xyz|top|gov|edu|uk|de)$", m.group(), re.I)]
        self.protos = [name for name, rx in _PROTO_WORDS if re.search(rx, low)]
        self.cred_protos = [p for p in self.protos if p in ("ftp", "smtp", "telnet", "pop3", "imap", "http")]
        self.success = re.search(r"\bsuccess|\bvalid\b|\bcorrect\b|\bworked\b|\bauthenticated\b|\bgranted\b|\baccepted\b", low) is not None

    def has(self, rx) -> bool:
        return re.search(rx, self.words) is not None

    def asks(self, rx) -> bool:
        return re.search(rx, self.low) is not None

    def shape(self, *extra) -> str:
        parts = [self.sel] + (["unique"] if self.sel == "count" and self.unique else [])
        parts += ["ip"] * bool(self.ips) + ["port"] * bool(self.ports) + [e for e in extra if e]
        return "+".join(parts)

    def fits(self, value) -> bool:
        rx = self.fmt.get("pattern") or self.fmt.get("regex")
        if isinstance(rx, str) and rx.strip():
            try:
                return re.fullmatch(rx, str(value)) is not None
            except re.error:
                return False
        if self.kind == "integer":
            return re.fullmatch(r"-?\d+", str(value)) is not None
        return True

    def filter(self, recs) -> list:
        out = list(recs)
        for ip, role in self.ips:
            if role == "dst":
                out = [r for r in out if r.get("dst") == ip]
            elif role == "src":
                out = [r for r in out if r.get("src") == ip]
            else:
                out = [r for r in out if ip in (r.get("src"), r.get("dst"))]
        for port in self.ports:
            out = [r for r in out if port in (r.get("sport"), r.get("dport"))]
        return out


class Found(Rec):
    """What a question's field gave: field, shape, options [(method, value)], plain (a value to
    answer as it is), candidate ([(hypothesis, value)] for a labels.candidates answer, row 346;
    never plain before the judge accepts a hypothesis), candidates (the distinct values seen, for
    a reader), why (when no answer)."""


_DESCRIBED_DOMAIN = (r"\b(?:under|to|for|of|beneath|below|within)\s+(?:the|that|this|an?)\s+(?:[\w-]+\s+){0,3}(?:domains?|zone)\b"
                     r"|\bsub-?domains? of (?:the|that|this)\b")


def _choose(Q, values, field, extra_shape="", formats=None, method="raw") -> Found:
    """Apply the question's selector to the values of a field, in the order they occurred."""
    values = [v for v in values if v not in (None, "")]
    counts = Counter(values)
    distinct = list(counts)
    out = Found(field=field, shape=Q.shape(extra_shape), options=[], candidates=[(v, counts[v]) for v in distinct][:40])
    if not values:
        out.why = "the capture holds no such value" + (" for the address, port or name the question gives" if Q.ips or Q.ports else "")
        return out
    fmt = formats or (lambda v: [(method, v)])
    if Q.sel == "count":
        if Q.unique or len(values) == len(distinct):
            out.options = [("distinct" if Q.unique else "count", str(len(distinct)))]
        else:
            out.why = f"{len(values)} occurrences of {len(distinct)} distinct values, and the question does not say which is counted"
    elif Q.sel == "all":
        ordered = distinct
        if re.search(r"\bsorted\b|\balphabetical", Q.low):
            ordered = sorted(distinct)
        elif Q.kind != "ordered_tokens" and not re.search(r"\bin order\b|\bchronolog", Q.low) and sorted(distinct) != distinct:
            out.why = "several values, and their order (first seen or sorted) is not asked for"
            return out
        items = [str(v) for v in ordered]
        out.options = [("comma", ",".join(items)), ("comma_space", ", ".join(items)),
                       ("json", json.dumps(items, separators=(",", ":"))), ("space", " ".join(items)),
                       ("arrow", ">".join(items))]
    elif Q.sel == "most":
        top = counts.most_common(2)
        if len(top) == 1 or top[0][1] > top[1][1]:
            out.options = fmt(top[0][0])
        else:
            out.why = f"two values share the highest count ({top[0][1]})"
    elif Q.sel == "first":
        out.options = fmt(values[0])
    elif Q.sel == "last":
        out.options = fmt(values[-1])
    elif len(distinct) == 1:
        out.options = fmt(distinct[0])
    else:
        out.why = f"{len(distinct)} different values and no word in the question to choose by"
    return out


def _iso(ns, frac_digits=0, sep="T", tail="Z") -> str:
    sec, frac = divmod(ns, 1_000_000_000)
    s = datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime(f"%Y-%m-%d{sep}%H:%M:%S")
    if frac_digits:
        s += "." + f"{frac:09d}"[:frac_digits]
    return s + tail


def time_options(ns, epoch_first=False) -> list:
    """[(method, text)] for one instant: ISO 8601 in UTC and Unix seconds, to the second and finer."""
    sec, frac = divmod(ns, 1_000_000_000)
    iso = [("iso_z_seconds", _iso(ns))]
    if frac:
        iso += [("iso_z_micros", _iso(ns, 6)), ("iso_z_millis", _iso(ns, 3))]
        if frac % 1000:
            iso.append(("iso_z_nanos", _iso(ns, 9)))
    iso += [("iso_space_seconds", _iso(ns, 0, " ", "")), ("iso_offset_seconds", _iso(ns, 0, "T", "+00:00"))]
    if frac:
        iso.append(("iso_space_micros", _iso(ns, 6, " ", "")))
    ep = [("epoch_seconds", str(sec))] + ([("epoch_micros", f"{sec}.{frac // 1000:06d}")] if frac else [])
    return (ep + iso) if epoch_first else (iso + ep)


def _mac_formats(b):
    return [("colon_lower", mac(b)), ("colon_upper", mac(b, ":", True)), ("dash_upper", mac(b, "-", True)),
            ("dash_lower", mac(b, "-")), ("plain_lower", mac(b, ""))]


def _hash_algo(Q):
    algos = {m.group().lower().replace("-", "") for m in _ALGO.finditer(Q.text)}
    return next(iter(algos)) if len(algos) == 1 and next(iter(algos)) in ("sha256", "sha1", "md5") else None


def _plain_object(o) -> bool:
    """A carved file whose bytes are the named file's and nothing else: the body of a 200 response
    (a 206 is a range of it, a 3xx or 4xx body is the server's page about it), an uploaded part, an
    FTP or TFTP transfer, a mail attachment; whole, and with no coding removed on the way. The body
    of a posted form carries its URI's name and is not that file."""
    if not o.complete or o.encoded:
        return False
    if o.source == "http_response":
        return o.status == 200
    return o.source in ("http_upload", "ftp_retr", "ftp_stor", "smtp_attachment", "tftp")


_OF_FILE = (r"\b(?:of|for|is|was|does|did)\s+(?:the\s+)?(?:(?:carved|downloaded|uploaded|transferred|transmitted|extracted|"
            r"attached|exfiltrated|retrieved|delivered|served)\s+)?(?:(?:file|attachment|executable|binary|document|payload|"
            r"object|image|archive|script)\s+)?(?:(?:named|called)\s+)?[`'\"\u2018\u201c]?")


def _asked_of(Q, objs) -> bool:
    """True when the question asks its digest or size OF the named file itself ('the SHA-256 of
    tool.exe', 'how many bytes is the file tool.exe'). A name anywhere else in the sentence ('the
    archive containing tool.exe', 'the file dropped by tool.exe') is about another file."""
    names = {o.name.lower() for o in objs if o.name}
    return len(names) == 1 and re.search(_OF_FILE + re.escape(next(iter(names))) + r"(?![\w-])", Q.low) is not None \
        and len(re.findall(r"(?<![\w.-])" + re.escape(next(iter(names))) + r"(?![\w-])", Q.low)) == 1 \
        and not re.search(r"\b(?:contain(?:s|ing|ed)?|inside|within|after|before|dropped by|created by|written by|"
                          r"extracted from|embedded|decoded|decrypted|decompressed|unpacked|parent|child|response to|"
                          r"request for|first \d+|last \d+|header|without|excluding|part)\b", Q.low)


def _objects_for(Q, cap):
    """(objects the question is about, True when it names them by file name)."""
    objs = cap.objects()
    # A name is a file's only when it reads as one (`tool.exe`): /file, /download or /payload are
    # ordinary words of a question, and matching them would choose one of several files by chance.
    named = [o for o in objs if o.name and re.fullmatch(r"[\w.-]*\w\.[A-Za-z0-9]{1,8}", o.name)
             and re.search(r"(?<![\w.-])" + re.escape(o.name.lower()) + r"(?![\w-])", Q.low)]
    if named:
        return named, True
    if Q.file_names:
        return [], False        # the question names a file, and no carved file has that name
    src = {"http": ("http_response", "http_request", "http_upload"), "ftp": ("ftp_retr", "ftp_stor"),
           "smtp": ("smtp_attachment",), "tftp": ("tftp",)}
    kinds = [k for pr in Q.protos for k in src.get(pr, ())]
    if Q.asks(r"\be-?mail\b|\battachment\b|\battached\b") and "smtp" not in Q.protos:
        kinds += src["smtp"]
    if kinds:
        objs = [o for o in objs if o.source in kinds]
    if Q.asks(r"\bupload|\bexfiltrat|\bposted\b|\bsent out\b|\bstolen\b"):
        up = [o for o in objs if o.source in ("http_request", "http_upload", "ftp_stor", "smtp_attachment")]
        objs = up or objs
    elif Q.asks(r"\bdownload|\bretriev|\bfetched\b|\bdropped\b|\bserved\b"):
        down = [o for o in objs if o.source in ("http_response", "ftp_retr", "tftp")]
        objs = down or objs
    return Q.filter(objs), False


def _server_ips(Q, cap, proto):
    if proto == "http":
        return [r.dst for r in cap.http() if r.method]
    if proto == "dns":
        return [m.dst for m in cap.dns() if not m.qr and m.proto == "dns"]
    if proto == "ftp":
        return [f.server for f in cap.ftp()]
    if proto == "smtp":
        return [m.server for m in cap.smtp()] or [b.server for b in cap.banners() if b.port in (25, 587) and b.banner.startswith("220")]
    if proto == "telnet":
        return [t.server for t in cap.telnet()]
    if proto == "tls":
        return [t.dst for t in cap.tls()]
    if proto == "ssh":
        return [b.server for b in cap.banners() if b.banner.startswith("SSH-")]
    return []


# A question that asks for the number of packets in the capture and for nothing else: every word of
# it is one of these. Any other word ('send', 'contain', 'dropped', 'after') may narrow the count.
_WHOLE_COUNT = re.compile(
    r"(?:\W*\b(?:how|many|what|is|are|was|were|the|a|an|total|number|count|of|packets?|frames?|in|inside|within|there|does|do|did|"
    r"this|capture|captured|pcap|pcapng|cap|file|trace|recording|recorded|contain|contains|hold|holds|have|has|"
    r"altogether|overall|all|delivered|evidence|network|provided|given|whole|entire|"
    r"answer|give|enter|report|as|integer|decimal|digits|only)\b)+\W*")


# ... and the same for 'how many ICMP echo requests are in the capture'
_ECHO_COUNT = re.compile(_WHOLE_COUNT.pattern.replace("how|many|", "how|many|icmp|icmpv6|echo|ping|pings|requests?|sent|seen|"))


def _only_the_count(Q, cap, rx=_WHOLE_COUNT) -> bool:
    low = Q.low
    for name in {cap.name or "", (cap.name or "").rsplit("/", 1)[-1]}:
        if name:
            low = low.replace(name.lower(), " ")
    return rx.fullmatch(low) is not None


# A question that asks FOR the flag, not about it: 'which packet holds the flag', 'how long is the
# flag', 'what is not the flag', 'the second flag', 'the flag's format' ask something else.
_ABOUT_FLAG = re.compile(
    r"\bnot\b|n't\b|\bhow (?:many|long|was|is|were|did)\b|\blength\b|\bnumber\b|\bsecond\b|\bthird\b|\bother\b|\bbefore\b|\bafter\b|"
    r"\bwhich (?!(?:flag|message|text|secret|data|string|word|phrase)\b)\w+|\bwhere\b|\bwhen\b|\bwho\b|\bwhy\b|\bflag'?s\b|\bformat of\b|\bwhat format\b|\bflag format\s*\??$|"
    r"\b(?:name|size|hash|md5|sha-?\d+|offset|password|address|port|protocol|encoding|cipher|algorithm|timestamp|unit|register|coil)\s+(?:of|for|is|was|that|which|id)\b|"
    r"\b(?:what|which) (?:is the |was the )?(?:file ?name|name|size|hash|md5|sha-?\d+|offset|password|address|ip|port|protocol|encoding|cipher|algorithm|"
    r"timestamp|time|unit|register|coil|packet|frame|stream|host|key)\b")
# where a flag was read, and the protocol words of a question that mean another place
_FLAG_PLACES = (("icmp", r"hidden icmp"), ("dns", r"hidden dns|udp \S+:53 |udp \S+ > \S+:53\b"), ("http", r"carved http|tcp "), ("ftp", r"carved ftp|tcp "),
                ("smtp", r"carved smtp|tcp "), ("telnet", r"tcp "), ("tftp", r"carved tftp|udp "), ("tls", r"tcp "), ("ssh", r"tcp "))


# A question that negates or excludes ("the file that is NOT the attachment", "the size without the
# attachment", "other than", "except") asks for something this file's reading of it does not prove:
# never plain. A format instruction ("do not include the 0x prefix", "without quotes") is not one.
_FORMAT_NEG = re.compile(r"(?i)\b(?:do not|don't|not|without|no|excluding)\s+(?:\w+\s+){0,3}?(?:0x|prefix(?:es)?|quotes?|quotation marks?|units?|spaces?|"
                         r"extensions?|braces|brackets|dashes|hyphens|colons|separators?|padding|zeros?|punctuation|whitespace|newlines?|"
                         r"trailing \w+|leading \w+|scheme|defang\w*)\b")
_NEGATION = re.compile(r"(?i)\bnot\b|n't\b|\bwithout\b|\bexcluding\b|\bexcept\b|\bother than\b|\bnever\b|\bneither\b|\bminus\b|\bapart from\b")


def _negates(text) -> bool:
    return _NEGATION.search(_FORMAT_NEG.sub(" ", str(text or ""))) is not None


def _asks_for_flag(Q) -> bool:
    return Q.has(r"\bflag\b") and _ABOUT_FLAG.search(Q.low) is None


def _count_block(Q, cap, noun) -> Found:
    """A 'how many ...' question, by the thing counted (the words after 'how many')."""
    has = Q.has
    queries = [m for m in cap.dns() if not m.qr and m.proto == "dns"]
    if re.match(r"(?:icmp(?:v6)? )?(?:echo|ping) requests\b|pings\b", noun):
        n = sum(1 for p in cap.packets if (p.proto == 1 and p.itype == 8) or (p.proto == 58 and p.itype == 128))
        f = Found(field="packet_count", shape="count+echo_request", options=[], candidates=[("echo requests", n)])
        if Q.ips or Q.ports or not _only_the_count(Q, cap, _ECHO_COUNT):
            # every word must be one this reading accounts for: 'failed', 'per second', 'no reply',
            # 'before the first reply', 'carry 0x41' each count something else
            f.why = "a count of some of the echo requests: which ones is not a single reading"
        elif n:
            f.options = [("icmp_type_8_packets", str(n))]
        else:
            f.why = "no ICMP echo requests"
        return f
    if re.match(r"(?:(?:tcp|udp|icmp|arp|ipv6|total|captured|network)\s+)*(?:packets|frames)\b", noun):
        f = Found(field="packet_count", shape="count", options=[], candidates=[("all", len(cap.packets))] + sorted(cap.protocols().items()))
        proto = next((p for p in ("tcp", "udp", "icmp", "arp", "ipv6") if has(r"\b" + p + r"\b")), None)
        other = has(r"\bdns\b|\bhttp\b|\btls\b|\bssl\b|\bftp\b|\bsmtp\b|\bsyn\b|\back\b|\brst\b|\bfin\b|\bretransmi|\bmalformed\b|\bfragment|"
                    r"\bbroadcast\b|\bthat\b|\bwhich\b|\bwhose\b|\bwith\b|\bwhere\b|\blarger\b|\bsmaller\b|\bbetween\b|"
                    r"\bsent\b|\breceived\b|\bto\b|\bfrom\b|\bport\b|\bexcept\b|\bexcluding\b|\bother than\b|\bunique\b|\bdistinct\b")
        if other or Q.ips or Q.ports:
            f.why = "a count of some of the packets: which ones is not a single reading"
        elif proto:
            f.shape = "count+" + proto
            n = cap.protocols().get(proto, 0)
            f.options = [("packets", str(n))] if n else []
            f.why = None if n else f"no {proto} packets"
        elif not _only_the_count(Q, cap):
            f.why = "a count of packets with words this file does not read: which packets is not proven"
        elif cap.damaged is None:
            f.plain = str(len(cap.packets))
        else:
            f.shape = "count+damaged"       # the file is cut: the whole records are one reading of it
            f.options = [("whole_records", str(len(cap.packets)))]
        return f
    if re.match(r"(?:ip|ipv4|ipv6|hosts?|endpoints?|addresses|machines|devices|systems)\b", noun):
        eps = list(cap.endpoints())
        f = Found(field="address_count", shape=Q.shape(), options=[], candidates=[(k, v.sent + v.received) for k, v in cap.endpoints().items()][:40])
        if eps and all(":" not in e for e in eps) and not Q.ips and not Q.names and not has(
                r"\bsource\b|\bdestination\b|\binternal\b|\bexternal\b|\bprivate\b|\bpublic\b|\bto\b|\bfrom\b|\bthat\b|\bwhich\b|\bquer|\brequest|\bconnect|\bscan"):
            f.options = [("distinct_addresses", str(len(eps)))]
        else:
            f.why = "the count depends on which addresses are meant"
        return f
    if re.match(r"(?:dns )?(?:quer|lookups?\b|requests? for\b)|(?:domains?|domain names|host ?names|names|subdomains)\b", noun):
        sub = Q.filter(queries)
        if not Q.names and has(_DESCRIBED_DOMAIN):
            # Day 14 look-ahead (new-lane finding F5): a count of the queries "under the exfiltration domain"
            # is one domain's count, and the question describes that domain without naming it. Every DNS
            # query of the capture was counted and offered (10 where 7 went to the domain). Which domain is
            # meant is not read here: no option.
            return Found(field="dns_query", shape=Q.shape(), options=[], candidates=[],
                         why="a count of the queries under a domain the question describes and does not name")
        if re.match(r"(?:domains?|domain names|host ?names|names|subdomains)\b", noun):
            Q.unique = True         # a count of names is a count of different names
            if re.match(r"subdomains\b", noun) and Q.names:
                sub = [m for m in sub if m.qname and any(m.qname.lower().rstrip(".").endswith("." + n) for n in Q.names)]
        return _choose(Q, [m.qname.lower().rstrip(".") for m in sub if m.qname], "dns_query")
    if re.match(r"(?:http |get |post |web )?requests?\b", noun):
        reqs = [r for r in Q.filter(cap.http()) if r.method and (not noun.startswith("post") or r.method == "POST")
                and (not noun.startswith("get") or r.method == "GET")]
        return _choose(Q, [(r.url or r.uri) if Q.unique else (r.ts, r.src, r.sport, r.uri) for r in reqs], "http_request")
    if re.match(r"(?:urls?|uris?)\b", noun):
        Q.unique = True
        return _choose(Q, [r.url or r.uri for r in Q.filter(cap.http()) if r.method], "http_url")
    if re.match(r"user.?agents?\b", noun):
        Q.unique = True
        return _choose(Q, [r.user_agent for r in Q.filter(cap.http()) if r.method], "http_user_agent")
    if re.match(r"(?:open |listening )ports?\b", noun) or (re.match(r"ports?\b", noun) and has(r"\bopen\b|\blistening\b")):
        return _open_ports(Q, cap)
    if re.match(r"(?:files?|objects?|attachments?)\b", noun):
        objs, _ = _objects_for(Q, cap)
        f = Found(field="object_count", shape=Q.shape(*Q.protos), options=[], candidates=[(f"{o.source} {o.name} {o.size}", 1) for o in objs][:40])
        shas = {o.sha256 for o in objs}
        if objs and len(shas) == len(objs) and all(o.complete for o in objs) and all(o.source != "http_response" or o.status == 200 for o in objs) \
                and not any(o.source == "http_request" for o in objs):
            f.options = [("carved_objects", str(len(objs)))]
        else:
            f.why = "the count depends on what counts as a file (error pages, posted forms, repeats, cut transfers)"
        return f
    if re.match(r"(?:failed |successful |unsuccessful |invalid )?(?:log-?ins?|log-?ons?|authentications?|passwords?|credentials?|attempts?)\b", noun) \
            or re.match(r"(?:failed|successful|unsuccessful)\b", noun):
        creds = _creds_for(Q, cap, success=False)
        f = Found(field="login_count", shape=Q.shape(*Q.cred_protos), options=[], candidates=[(f"{c.proto} {c.user}:{c.password} ok={c.ok}", 1) for c in creds][:40])
        failed, good = has(r"\bfailed\b|\bunsuccessful\b|\binvalid\b|\bwrong\b"), has(r"\bsuccessful\b|\bsucceeded\b|\bvalid\b")
        if not creds:
            f.why = "no credentials in the clear"
        elif failed or good:
            if all(c.ok is not None for c in creds):
                f.shape += "+failed" if failed else "+ok"
                f.options = [("server_replies", str(sum(1 for c in creds if c.ok is (not failed))))]
            else:
                f.why = "the server's reply to a login is not readable for every attempt"
        else:
            f.options = [("logins_sent", str(len(creds)))]
        return f
    if re.match(r"(?:tcp )?(?:connections|sessions|streams|conversations)\b", noun):
        conns = Q.filter([Rec(src=c.client, dst=c.server, sport=c.cport, dport=c.sport, hs=c.handshake) for c in cap.conns()])
        f = Found(field="tcp_connection_count", shape=Q.shape(), options=[], candidates=[("all", len(conns)), ("with handshake", sum(1 for c in conns if c.hs))])
        if conns and all(c.hs for c in conns) and not has(r"\budp\b"):
            f.options = [("tcp_handshakes", str(len(conns)))]
        else:
            f.why = "connections with and without a full handshake: which are counted is not said"
        return f
    if re.match(r"(?:e-?mails?|messages|mails)\b", noun) and cap.smtp():
        return Found(field="smtp_message_count", shape=Q.shape(), options=[("smtp_data", str(len(Q.filter(cap.smtp()))))], candidates=[])
    return Found(field="count", shape=Q.shape(), options=[], candidates=[], why=f"a count of '{noun[:30]}': not a thing this file counts")


def _auth_field(Q, cap) -> Found:
    """NTLM(SSP) / NetNTLM / HTTP Digest metadata for a question that named the mechanism. Every
    returned fact is read from the bytes: deterministic strings/ids come back as unsure picks
    (plain once the judge accepts the label), the NetNTLM hash as a candidate (format unjudged),
    and anything the capture does not establish as None."""
    has = Q.has
    ex = Q.filter(cap.ntlm())
    digest = bool(cap.http_digest()) and (has(r"\bdigest\b") or not cap.ntlm())

    # -- the NetNTLM hash string: a labels.candidates value, never plain (its format is unjudged)
    if has(r"\bnet-?ntlm\b|\bntlmv[12]\b|\bntproof|\bnt proof\b") or (has(r"\bhash\b|\bhashcat\b|\bcrack\w*\b")
            and has(r"\bntlm\b|\bntlmssp\b|\bresponse\b")):
        pairs = [(fmt, s) for e in ex for fmt, s in (e.netntlm or [])]
        f = Found(field="netntlm_hash", shape=Q.shape(), options=[], candidate=[],
                  candidates=[(f"{fmt}: {_clip(s, 70)}", 1) for fmt, s in pairs])
        if not pairs:
            f.why = "no NTLM Authenticate message with an NT response (and its challenge) in the capture"
        elif len({s for _, s in pairs}) == 1:
            f.candidate = pairs[:1]
        elif Q.sel in ("first", "last", "only") and len({e.nt_response for e in ex if e.nt_response}) == 1:
            f.candidate = list(dict.fromkeys((fmt, s) for fmt, s in pairs))
        else:
            f.why = f"{len({s for _, s in pairs})} NTLM responses in the capture; the question names none"
        return f

    # -- HTTP Digest fields
    if digest:
        ds = Q.filter(cap.http_digest())
        pick = {"username": "username", "realm": "realm", "nonce": "nonce", "response": "response",
                "algorithm": "algorithm", "qop": "qop", "cnonce": "cnonce", "opaque": "opaque", "nc": "nc"}
        # cnonce and nc are tested BEFORE the generic "nonce": a question that says "client
        # nonce" or "nonce count" also contains the word "nonce", so the plain-nonce branch
        # would otherwise file it under http_digest_nonce and answer the server nonce -- a wrong
        # answer that would go PLAIN once that key is judged (never-wrong: a specific field is
        # matched before the generic word whose token it contains).
        attr = ("cnonce" if has(r"\bcnonce\b|\bclient nonce\b") else "nc" if has(r"\bnonce count\b|\bnc\b")
                else "username" if has(r"\buser ?name\b|\buser\b|\baccount\b") else "realm" if has(r"\brealm\b")
                else "nonce" if has(r"\bnonce\b") else "response" if has(r"\bresponse\b|\bdigest value\b|\bhash\b")
                else "algorithm" if has(r"\balgorithm\b") else "qop" if has(r"\bqop\b|\bquality of protection\b")
                else "opaque" if has(r"\bopaque\b") else None)
        if attr is None:
            return Found(field="http_digest", shape=Q.shape(), options=[], candidates=[], why="not a Digest field this reader derives")
        meth = {"response": "hex_lower", "nonce": "raw", "cnonce": "raw", "opaque": "raw"}.get(attr, "raw")
        return _choose(Q, [d.get(pick[attr]) for d in ds], f"http_digest_{attr}", method=meth)

    f0 = Found(field="ntlm", shape=Q.shape(), options=[], candidates=[(f"{e.user}@{e.domain} ws={e.workstation} "
               f"target={e.target_name} flags={e.flags:#010x} ch={(e.challenge or b'').hex()}", 1) for e in ex if e.flags is not None])
    if not ex:
        f0.why = "no NTLMSSP messages in the capture"
        return f0

    # -- the AV pairs of the Type 2 Challenge (NetBIOS / DNS computer and domain names), before the
    #    plain "domain"/"computer" branches, which these words would otherwise capture.
    av_name = ("netbios_domain" if has(r"\bnet-?bios\b") and has(r"\bdomain\b")
               else "netbios_computer" if has(r"\bnet-?bios\b") and has(r"\b(?:computer|machine|host|server)\b")
               else "dns_domain" if has(r"\bdns\b") and has(r"\bdomain\b")
               else "dns_computer" if has(r"\bdns\b") and has(r"\b(?:computer|machine|host|server|fqdn)\b")
               else "dns_tree" if has(r"\bdns\b") and has(r"\btree\b") else None)
    if av_name is not None:
        return _choose(Q, [e.av.get(av_name) for e in ex if e.av], f"ntlm_av_{av_name}")

    if has(r"\btarget name\b") or (has(r"\btarget\b") and has(r"\bntlm\b|\bchallenge\b|\btype ?2\b|\bserver\b")):
        return _choose(Q, [e.target_name for e in ex], "ntlm_target_name")
    if has(r"\bchallenge\b") or (has(r"\bserver\b") and has(r"\bnonce\b")):
        return _choose(Q, [e.challenge.hex() for e in ex if e.challenge], "ntlm_challenge",
                       formats=lambda v: [("hex_lower", v), ("hex_upper", v.upper())])
    if has(r"\bflags?\b|\bnegotiat\w*\b"):
        return _choose(Q, [e.flags for e in ex if e.flags is not None], "ntlm_flags",
                       formats=lambda v: [("hex_prefixed", f"0x{v:08x}"), ("hex", f"{v:08x}"), ("decimal", str(v))])
    if has(r"\bworkstation\b") or (has(r"\b(?:client|source)\b") and has(r"\b(?:machine|computer|host ?name|name)\b")):
        return _choose(Q, [e.workstation for e in ex if e.workstation], "ntlm_workstation")
    if has(r"\bdomain\b"):
        return _choose(Q, [e.domain for e in ex if e.domain is not None and e.domain != ""], "ntlm_domain")
    if has(r"\buser ?name\b|\buser\b|\baccount\b|\blogon\b|\blogged in as\b|\bidentity\b"):
        return _choose(Q, [e.user for e in ex if e.user], "ntlm_username")
    f0.why = "an NTLM question whose field this reader does not derive"
    return f0


def _creds_for(Q, cap, success=True) -> list:
    creds = cap.credentials()
    if Q.cred_protos:
        creds = [c for c in creds if c.proto.split("_")[0] in Q.cred_protos]
    creds = Q.filter(creds)
    okd = [c for c in creds if c.ok]
    return okd if success and Q.success and okd else creds


def _open_ports(Q, cap) -> Found:
    op = cap.open_ports()
    hosts = [ip for ip, _ in Q.ips] or list(op)
    f = Found(field="open_ports", shape=Q.shape(), options=[], candidates=[(f"{h}: {op.get(h)}", 1) for h in hosts])
    if len(hosts) != 1 or not op.get(hosts[0]):
        f.why = f"{len(hosts)} hosts answered a SYN; the question names none of them"
        return f
    ports = [str(p) for p in op[hosts[0]]]
    if Q.sel == "count":
        f.options = [("syn_ack_ports", str(len(ports)))]
    elif len(ports) == 1:
        f.options = [("syn_ack_port", ports[0])]
    else:
        f.options = [("comma", ",".join(ports)), ("comma_space", ", ".join(ports)), ("json", "[" + ",".join(ports) + "]"),
                     ("space", " ".join(ports))]
    return f


def _address_block(Q, cap) -> Found:
    """A question that asks for an IP address."""
    has = Q.has
    queries = [m for m in cap.dns() if not m.qr and m.proto == "dns"]
    answers = [m for m in cap.dns() if m.qr and m.proto == "dns"]

    def none(why):
        return Found(field="address", shape=Q.shape(), options=[], why=why,
                     candidates=[(k, v.sent + v.received) for k, v in cap.endpoints().items()][:40])

    if has(r"\bresolv\w*\b|\ba record\b|\baaaa\b|\bdns (?:answer|response)\b|\b(?:of|for|behind) (?:the )?(?:domain|host ?name)\b|\bpoints? to\b"):
        want = "AAAA" if has(r"\bipv6\b|\baaaa\b") else "A"
        sub = answers
        if Q.names:
            sub = [m for m in sub if m.qname and m.qname.lower().rstrip(".") in Q.names]
        return _choose(Q, [v for m in sub for _, t, v in m.answers if t == want], "dns_address", want.lower() + "+name" * bool(Q.names))
    if has(r"\bscan"):
        sc = cap.syn_scan()
        want_target = has(r"\btarget\b|\bvictim\b|\bscanned\b") and not has(r"\bscanner\b|\bperformed\b|\bsource\b|\battacker\b|\bconducted\b|\blaunched\b")
        vals = list(dict.fromkeys(s.dst if want_target else s.src for s in sc))
        f = Found(field="scan_target_address" if want_target else "scanner_address", shape=Q.shape(), options=[],
                  candidates=[(f"{s.src} -> {s.dst} {len(s.ports)} ports", 1) for s in sc])
        if len(vals) == 1:
            f.options = [("syn_scan_target" if want_target else "syn_scan_source", vals[0])]
        else:
            f.why = f"{len(vals)} sources sent SYNs to twenty or more ports of one host"
        return f
    if has(r"\btop talker\b|\bmost (?:packets|traffic|data|bytes)\b|\bbusiest\b"):
        eps = cap.endpoints()
        f = Found(field="top_talker", shape=Q.shape(), options=[], candidates=[(k, v.sent) for k, v in eps.items()][:40])
        by_p = sorted(eps, key=lambda k: -eps[k].sent)[:2]
        by_b = sorted(eps, key=lambda k: -eps[k].bytes_sent)[:2]
        if by_p and by_p[0] == by_b[0] and (len(by_p) == 1 or eps[by_p[0]].sent > eps[by_p[1]].sent):
            f.options = [("most_packets_and_bytes_sent", by_p[0])]
        else:
            f.why = "the sender of most packets is not the sender of most bytes"
        return f
    if has(r"\bbeacon|\bcheck.?ins?\b|\bcall.?backs?\b|\bheart ?beat\b|\bperiodic"):
        per = [b for b in cap.beacons() if b.periodic and b.kind in ("syn", "udp", "icmp")]
        dsts = list(dict.fromkeys(b.dst for b in per))
        f = Found(field="beacon_destination", shape=Q.shape(), options=[],
                  candidates=[(f"{b.kind} {b.key} every {b.median:.3f} s x{b.events}", 1) for b in per][:20])
        if len(dsts) == 1:
            f.options = [("periodic_destination", dsts[0])]
        else:
            f.why = f"{len(dsts)} destinations are contacted periodically"
        return f
    acks = [d for d in cap.dhcp() if d.type == "ack" and d.your_ip != "0.0.0.0"]
    if (has(r"\bdhcp\b") and has(r"\bassigned\b|\boffered\b|\bleased?\b|\breceived?\b|\bgiven\b")) or \
            (acks and has(r"\bassigned\b|\bleased?\b") and has(r"\bip\b|\baddress\b") and not has(
                r"\bmac\b|\bhardware\b|\bdns\b|\brouter\b|\bgateway\b|\bserver\b|\bmask\b|\bby\b|\bseconds?\b|\bminutes?\b|\bhours?\b|\bnot\b|"
                r"\bbefore\b|\bafter\b|\bsecond\b|\bprevious")):
        return _choose(Q, [d.your_ip for d in acks], "dhcp_address", method="dhcp_ack_yiaddr")
    server = has(r"\bservers?\b|\bresolver\b|\bdestination\b|\bhost(?:ing|ed|s)\b|\bserv(?:ed|ing)\b|\bconnected to\b")
    client = has(r"\bclients?\b|\bsource\b|\bquer(?:ied|ying)\b|\brequest(?:ed|ing)\b|\bdownloaded\b|\buploaded\b|\blogged in\b|\bsent\b|\bmade\b|\binitiated\b|\bvisited\b|\bbrowsed\b|\bused\b")
    if server == client:
        return none("which address is meant (a server or a client) is the author's, not the bytes'")
    for pr in Q.protos:
        if server and pr in ("http", "dns", "ftp", "smtp", "telnet", "tls", "ssh"):
            return _choose(Q, _server_ips(Q, cap, pr), "server_address", pr)
        if client and pr in ("http", "dns", "ftp", "tls", "telnet", "smtp"):
            if pr == "http":
                src = [r.src for r in cap.http() if r.method and (not Q.names or (r.host or "").lower().split(":")[0] in Q.names)]
            elif pr == "dns":
                src = [m.src for m in queries if not Q.names or (m.qname or "").lower().rstrip(".") in Q.names]
            else:
                src = {"ftp": [f.client for f in cap.ftp()], "tls": [t.src for t in cap.tls() if not Q.names or (t.sni or "").lower() in Q.names],
                       "telnet": [t.client for t in cap.telnet()], "smtp": [m.client for m in cap.smtp()]}[pr]
            return _choose(Q, src, "client_address", pr + "+name" * bool(Q.names))
    if client and Q.names:
        src = [m.src for m in queries if (m.qname or "").lower().rstrip(".") in Q.names]
        return _choose(Q, src, "client_address", "dns+name")
    return none("which address is meant is the author's, not the bytes'")


def _field(Q, cap) -> Found:
    """The field a question asks for and what the capture gives for it; None when it asks for none
    this file knows. The kind of answer asked for (a time, a digest, a count, an address, a port)
    is read first, so that a question about one thing is never answered with another."""
    has, asks = Q.has, Q.asks
    T = cap.times()
    known = {(m.qname or "").lower().rstrip(".") for m in cap.dns()} | {(r.host or "").lower().split(":")[0] for r in cap.http()} \
        | {(t.sni or "").lower() for t in cap.tls()}
    Q.names = [n for n in Q.names if n in known or any(k.endswith("." + n) for k in known)]
    queries = [m for m in cap.dns() if not m.qr and m.proto == "dns"]
    answers = [m for m in cap.dns() if m.qr and m.proto == "dns"]

    # -- what a keyboard typed
    if asks(r"\bkeystrokes?\b|\btyped\b|\bkeyboard\b|\bkey ?press") and any(lt in USB_LINKS for lt in cap.linktypes):
        ks = cap.usb_keystrokes()
        f = Found(field="usb_keystrokes", shape=Q.shape(), options=[], candidates=[(k.text, k.reports) for k in ks])
        if len(ks) == 1:
            f.options = [("hid_boot_edited", ks[0].text.strip("\n"))]
            flags = _flags_in(ks[0].text.encode("utf-8", "replace"))
            if _asks_for_flag(Q) and len(flags) == 1:
                f.options.insert(0, ("hid_boot_flag", flags[0]))
        else:
            f.why = f"{len(ks)} keyboards in the capture"
        return f

    # -- a time
    if has(r"\bduration\b|\bhow long\b|\btime ?span\b|\belapsed\b"):
        f = Found(field="capture_duration", shape="span", options=[], candidates=[])
        if not has(r"\bcapture\b|\bpcap|\btraffic\b|\btrace\b|\brecording\b") or has(r"\bsession\b|\bconnection\b|\bdownload\b|\battack\b|\bscan\b"):
            f.why = "the length of an event, not of the capture: read it by hand"
        elif T.duration is None or not T.ordered:
            f.why = "no time on the packets, or they are not in time order"
        else:
            d = T.duration
            whole = [("seconds_int", str(d // 1_000_000_000)), ("seconds_round", str(round(d / 1e9)))]
            fine = [("seconds_micros", f"{d / 1e9:.6f}"), ("seconds_3dp", f"{d / 1e9:.3f}")]
            f.options = whole[:1] + fine if d % 1_000_000_000 == 0 else fine + whole
        return f
    if asks(r"\bwhen\b|\btimestamps?\b|\b(?:what|which) (?:date|time)\b|\bat what time\b|\bdate and time\b|\btime of\b|\b(?:start|end) time\b"):
        m = re.search(r"\b(first|last|earliest|latest|final)\b[^.?]{0,30}\b(?:packet|frame)\b|\b(?:capture|recording|trace) (start|begin|end|stop)"
                      r"|\b(start|end) (?:time )?of the (?:capture|recording|trace)\b"
                      r"|\b(?:capture|recording|trace)(?:'s)? (start|end) time\b", Q.low)
        f = Found(field="capture_time", shape="", options=[], candidates=[])
        if not m or has(r"\bdns\b|\bhttp\b|\btls\b|\bftp\b|\bsyn\b|\bicmp\b|\bto\b|\bfrom\b") or Q.ips:
            f.why = "the time of an event: read it by hand"
            return f
        first = next(g for g in m.groups() if g) in ("first", "earliest", "start", "begin")
        f.shape = "first" if first else "last"
        ts = (T.first, T.earliest) if first else (T.last, T.latest)
        if ts[0] is None or ts[0] != ts[1]:
            f.why = "no time on the packets, or the first/last record is not the earliest/latest"
        else:
            f.options = time_options(ts[0], epoch_first=has(r"\bepoch\b|\bunix\b"))
        return f

    # -- a digest or a size of a carved file
    if _ALGO.search(Q.text) and not has(r"\bja3s?\b|\bja4\b"):
        algo = _hash_algo(Q)
        f = Found(field="object_hash", shape=Q.shape(algo or "", *Q.protos), options=[], candidates=[])
        if algo is None:
            f.why = "a digest this file does not write, or two of them"
            return f
        if has(r"\bcertificate\b|\bcert\b"):
            vals = [c[algo] for c in cap.certs() if c.position == 0 and c[algo]]
            return _choose(Q, [v.upper() if Q.upper else v for v in vals], "certificate_fingerprint", algo, method="leaf_der_" + algo)
        objs, named = _objects_for(Q, cap)
        f.candidates = [(f"{o.source} {o.name} {o[algo]}", 1) for o in objs][:40]
        digests = list(dict.fromkeys(o[algo] for o in objs))
        if len(digests) != 1:
            f.why = "the question names a file that was not carved from the capture" if Q.file_names and not objs else \
                f"{len(digests)} different files could be meant"
            return f
        value = digests[0].upper() if Q.upper else digests[0]
        if not all(o.complete for o in objs):
            f.why = "the transfer is not whole in the capture"
        elif named and all(_plain_object(o) for o in objs) and _asked_of(Q, objs):
            f.plain = value
        else:
            f.options = [("carved_" + objs[0].source, value)]
        return f
    if asks(r"\b(?:size|length)\b.*\bbytes\b|\bhow many bytes\b|\bhow large\b|\bfile size\b|\bsize of the\b"):
        objs, named = _objects_for(Q, cap)
        f = Found(field="object_size", shape=Q.shape(*Q.protos), options=[], candidates=[(f"{o.source} {o.name} {o.size}", 1) for o in objs][:40])
        sizes = list(dict.fromkeys((o.size, o.sha256) for o in objs))
        if not has(r"\bfile\b|\bdownload|\bupload|\battachment\b|\bpayload\b|\bobject\b|\btransferr?ed\b|\bexecutable\b|\bdocument\b|\bimage\b|\barchive\b") and not named:
            f.why = "the size of something that is not a carved file"
        elif len(sizes) != 1:
            f.why = f"{len(sizes)} different files could be meant"
        elif not all(o.complete for o in objs):
            f.why = "the transfer is not whole in the capture"
        elif named and all(_plain_object(o) for o in objs) and _asked_of(Q, objs):
            f.plain = str(sizes[0][0])
        else:
            f.options = [("carved_" + objs[0].source, str(sizes[0][0]))]
        return f

    # -- a count
    if Q.sel == "count":
        m = re.search(r"\b(?:how many|(?:total )?number of|count of)\s+((?:(?:unique|distinct|different|total|separate|individual)\s+)*)([a-z0-9][a-z0-9 .'/-]{0,60})", Q.low)
        return _count_block(Q, cap, m.group(2) if m else "")

    # -- a hardware address
    if has(r"\bmac(?: address(?:es)?)?\b|\bhardware address\b|\bethernet address\b|\bphysical address\b"):
        f = Found(field="mac_of_address", shape=Q.shape(), options=[], candidates=[])
        if not Q.ips and has(r"\bdhcp\b") and has(r"\bclient\b|\brequest") and not has(r"\bserver\b|\brelay\b|\bsent to\b|\bdestination\b|\bnot\b|\brouter\b|\bgateway\b"):
            macs = list(dict.fromkeys(bytes(d.mac) for d in cap.dhcp() if d.op == 1))
            f.shape, f.candidates = "dhcp_client", [(mac(m), 1) for m in macs]
            if len(macs) == 1:
                f.options = _mac_formats(macs[0])
            else:
                f.why = f"{len(macs)} DHCP clients in the capture"
            return f
        if len(Q.ips) != 1:
            f.why = "the question gives no single address to look the hardware address up for"
            return f
        macs = cap.macs_of(Q.ips[0][0])
        f.candidates = [(mac(m), 1) for m in macs]
        if len(macs) == 1:
            f.options = _mac_formats(macs[0])
        else:
            f.why = f"{len(macs)} hardware addresses sent packets as {Q.ips[0][0]}"
        return f

    # -- an address or a port
    if asks(r"\b(?:what|which|whose)\b[^?.]{0,60}\bip(?:v4|v6)?\b|\bip(?:v4|v6)?(?: address(?:es)?)?\s+(?:of|for|that|which|did|does|was|is|were|has|had)\b"
            r"|\b(?:what|which) (?:address|host|machine|system|endpoint)\b|\bip(?:v4|v6)? address\b") \
            and not asks(r"\b(?:what|which) (?:domain|host ?name|name|url|uri|user.?agent|file|password|user ?name|port|protocol)\b"):
        return _address_block(Q, cap)
    if has(r"\bopen ports?\b|\bports? (?:are|were|is|was) open\b|\blistening ports?\b"):
        return _open_ports(Q, cap)
    if asks(r"\b(?:which|what) (?:tcp |udp |destination |server |remote |network )?port\b|\bport number\b|\bon (?:which|what) port\b"):
        for pr in Q.protos:
            if pr in ("http", "ftp", "smtp", "telnet", "tls", "ssh"):
                ports = {"http": [r.dport for r in cap.http() if r.method], "ftp": [f.port for f in cap.ftp()],
                         "smtp": [m.dport for m in cap.smtp()], "telnet": [t.port for t in cap.telnet()],
                         "tls": [t.dport for t in cap.tls()],
                         "ssh": [b.port for b in cap.banners() if b.banner.startswith("SSH-")]}[pr]
                return _choose(Q, [str(p) for p in ports], "server_port", pr)
        if has(r"\bbeacon|\bcheck.?ins?\b|\bcall.?backs?\b"):
            per = [b for b in cap.beacons() if b.periodic and b.kind in ("syn", "udp")]
            return _choose(Q, [str(b.key[2]) for b in per], "beacon_port", method="periodic_destination_port")
        return Found(field="port", shape=Q.shape(), options=[], candidates=[], why="no protocol in the question to find the port of")

    # -- TLS
    if has(r"\bja3s\b"):
        full = asks(r"\bstring\b|\bfull\b")
        return _choose(Q, [t.ja3s_string if full else t.ja3s for t in Q.filter(cap.tls())], "tls_ja3s", method="ja3s_string" if full else "ja3s_md5")
    if has(r"\bja3\b"):
        full = asks(r"\bstring\b|\bfull\b")
        return _choose(Q, [t.ja3_string if full else t.ja3 for t in Q.filter(cap.tls())], "tls_ja3", method="ja3_string" if full else "ja3_md5")
    if has(r"\bja4\b"):
        return _choose(Q, [t.ja4 for t in Q.filter(cap.tls())], "tls_ja4", method="ja4")
    if has(r"\bsni\b|server name indication") or (has(r"\bserver name\b|\bhost ?name\b|\bdomain\b") and has(r"\btls\b|\bssl\b|client ?hello|\bhttps\b")):
        return _choose(Q, [t.sni for t in Q.filter(cap.tls())], "tls_sni")
    if has(r"\bcertificate\b") and has(r"\bcommon name\b|\bcn\b|\bsubject\b|\bissuer\b|\bserial\b"):
        leaf = [c for c in cap.certs() if c.position == 0]
        if has(r"\bissuer\b"):
            return _choose(Q, [c.issuer for c in leaf], "certificate_issuer", method="rfc4514")
        if has(r"\bserial\b"):
            return _choose(Q, [c.serial for c in leaf], "certificate_serial",
                           formats=lambda v: [("hex_lower", v), ("hex_upper", v.upper()), ("decimal", str(int(v, 16)))])
        if has(r"\bcommon name\b|\bcn\b"):
            return _choose(Q, [c.common_name for c in leaf], "certificate_common_name")
        return _choose(Q, [c.subject for c in leaf], "certificate_subject", method="rfc4514")

    # -- HTTP headers
    if has(r"\buser.?agents?\b"):
        return _choose(Q, [r.user_agent for r in Q.filter(cap.http()) if r.method], "http_user_agent")
    if has(r"\bstatus code\b|\bresponse code\b|\bhttp status\b"):
        return _choose(Q, [str(r.status) for r in Q.filter(cap.http()) if r.status is not None], "http_status")
    if has(r"\bssh\b") and has(r"\bbanner\b|\bversion string\b|\bidentification string\b|\bsoftware version\b"):
        ssh = [b for b in cap.banners() if b.banner.startswith("SSH-")]
        if (has(r"\bclient\b|\battacker|\btool\b|\bscanner\b|\bsent\b|\bsend\b") and not has(r"\bserver\b")) or has(r"\bnot\b"):
            return Found(field="ssh_banner", shape="client", options=[], candidates=[], why="the client's SSH banner is not read")
        return _choose(Q, [b.banner for b in Q.filter(ssh)], "ssh_banner", method="server_first_line")
    if has(r"\bserver header\b|\bserver software\b|\bweb server (?:software|version|banner)\b"):
        return _choose(Q, [r.server for r in Q.filter(cap.http()) if r.status is not None], "http_server")
    if has(r"\bhttp method\b|\brequest method\b|\bwhich method\b|\bwhat method\b"):
        return _choose(Q, [r.method for r in Q.filter(cap.http()) if r.method], "http_method")
    if has(r"\breferr?er\b"):
        return _choose(Q, [r.referer for r in Q.filter(cap.http()) if r.method], "http_referer")
    if has(r"\bcookies?\b"):
        return _choose(Q, [r.cookie for r in Q.filter(cap.http()) if r.method], "http_cookie")

    # -- NTLM(SSP) / NetNTLM / HTTP Digest authentication metadata (row 5). Only a question that
    # names the mechanism reaches here, so inside it a bare word ("domain", "flags", "challenge",
    # "response") is read in that context and never steals a cleartext-credential question.
    if has(r"\bntlmssp\b|\bnet-?ntlm\b|\bntlmv[12]\b") or (has(r"\bntlm\b|\bdigest\b") and (cap.ntlm() or cap.http_digest())):
        return _auth_field(Q, cap)

    # -- credentials
    if has(r"\bpasswords?\b|\bcredentials?\b|\buser ?names?\b|\blogin name\b|\baccount name\b|\blogged in as\b|\b(?:which|what) (?:user|account)\b"):
        sub = _creds_for(Q, cap)
        extra = "+".join(Q.cred_protos + (["ok"] if Q.success else []))
        if has(r"\bcredentials?\b"):
            return _choose(Q, [(c.user, c.password) for c in sub if c.user is not None], "credentials", extra,
                           formats=lambda v: [("user_colon_password", f"{v[0]}:{v[1]}"), ("user_slash_password", f"{v[0]}/{v[1]}")])
        if has(r"\bpasswords?\b") and not asks(r"\b(?:which|what) (?:user|account|user ?name)\b"):
            return _choose(Q, [c.password for c in sub], "password", extra)
        return _choose(Q, [c.user for c in sub], "username", extra)

    # -- what Modbus writes spell
    if has(r"\bmodbus\b|\bregisters?\b|\bcoils?\b|\bplc\b|\bhmi\b") and \
            has(r"\bmessage\b|\bhidden\b|\bsecret\b|\bflag\b|\bspell|\bencoded\b|\bcovert\b|\bexfil|\bsmuggl"):
        series = cap.modbus_series()
        texts = [(m, m.text) for m in series if m.text]
        blobs = [b for b in cap.hidden_blobs() if b.channel == "modbus"]
        f = Found(field="hidden_modbus", shape=Q.shape(), options=[],
                  candidates=[(f"fn{m.function}@{m.address} {m.reading}: {m.text[:80]}", m.writes) for m, _ in texts]
                  + [(f"{b.key}: {b.kind} {b.size} bytes, flags {b.flags}", 1) for b in blobs])
        flags = list(dict.fromkeys([x for b in blobs for x in b.flags] + [x for _, t in texts for x in _flags_in(t.encode())]))
        if has(r"\bflag\b") and not _asks_for_flag(Q):
            f.why = "the question asks about the flag (where, which, how long), not for it"
        elif has(r"\bflag\b") and len(flags) == 1:
            f.options = [("modbus_writes_flag", flags[0])]
        elif len(texts) == 1 and not blobs and not _ABOUT_FLAG.search(Q.low):
            f.options = [("modbus_" + texts[0][0].reading, texts[0][1])]
        else:
            f.why = "no one text in the values written to one register or coil" if not flags else \
                f"{len(flags)} flag-shaped texts in the Modbus writes"
        return f

    # -- covert channels, before plain DNS
    if has(r"\bicmp\b|\bping\b") and has(r"\bpayload|\bdata\b|\bmessage\b|\bhidden\b|\bsecret\b|\bexfil|\btunnel|\bflag\b|\bcovert\b|\bsmuggl"):
        return _hidden_found(Q, cap, "icmp")
    if has(r"\bdns\b") and has(r"\btunnel|\bexfil|\bcovert\b|\bencoded\b|\bhidden\b|\bsecret\b|\bsmuggl|\bflag\b|\bmessage\b"):
        return _hidden_found(Q, cap, "dns")

    # -- what was typed in a Telnet session, after the login
    if cap.telnet() and has(r"\bcommands?\b") and has(r"\bran\b|\brun\b|\btyped?\b|\bexecuted?\b|\bentered\b|\bissued\b") \
            and not has(r"\bftp\b|\bsmtp\b|\bhttp\b|\boutput\b|\bresult\b|\bresponse\b|\breturned\b|\bprinted\b|\bnot\b|\bfailed\b|\bserver ran\b"):
        cmds = [ln for t in cap.telnet() for ln in t.typed[(2 if t.get("user") is not None else 0):] if ln.strip()]
        return _choose(Q, cmds, "telnet_command", method="typed_line")
    # -- mail
    if cap.smtp() and has(r"\bsubject\b"):
        return _choose(Q, [m.subject for m in Q.filter(cap.smtp())], "smtp_subject")
    if cap.smtp() and has(r"\bsender\b|\bmail from\b|\bfrom address\b|\bsent the e-?mail\b|\bwho sent\b"):
        return _choose(Q, [m.mail_from for m in Q.filter(cap.smtp())], "smtp_mail_from")
    if cap.smtp() and has(r"\brecipients?\b|\brcpt\b|\bsent to\b|\breceived the e-?mail\b"):
        return _choose(Q, [x for m in Q.filter(cap.smtp()) for x in m.rcpt_to], "smtp_rcpt_to")

    # -- file names
    if has(r"\bfile ?names?\b|\bname of the (?:file|attachment|payload|executable|script|document|archive|binary)\b"
           r"|\b(?:which|what) (?:file|attachment|executable|script|document|archive|binary)\b"):
        objs, _ = _objects_for(Q, cap)
        names = []
        for o in objs:
            if o.source == "http_response" and (o.status != 200 or (o.disposition and o.uri_name and o.disposition != o.uri_name)):
                continue        # an error page is not a file; a name sent two ways is two readings
            if o.source == "http_request":
                continue        # a posted form is not a named file
            names.append(o.name)
        if not objs and (not Q.protos or "ftp" in Q.protos):
            names = [t.name.replace("\\", "/").rsplit("/", 1)[-1] for f in Q.filter(cap.ftp()) for t in f.transfers
                     if t.command in ("RETR", "STOR", "APPE") and t.name]
        return _choose(Q, names, "object_name", "+".join(Q.protos))

    # -- HTTP requests
    http_ctx = has(r"\bhttp\b|\bweb\b|\brequest|\bvisit|\bbrows|\bget\b|\bpost\b|\bdownload|\bupload")
    if has(r"\buris?\b|\burls?\b|\bendpoint\b|\bresource\b") or (has(r"\bpath\b") and http_ctx):
        reqs = [r for r in Q.filter(cap.http()) if r.method]
        if Q.names:
            reqs = [r for r in reqs if r.host and (r.host.lower().split(":")[0] in Q.names or any(r.host.lower().endswith("." + n) for n in Q.names))]
        if asks(r"\bpost\b"):
            reqs = [r for r in reqs if r.method == "POST"]
        want_url = has(r"\burls?\b")
        if Q.sel == "all":
            return _choose(Q, [(r.url or r.uri) if want_url else r.uri for r in reqs], "http_url" if want_url else "http_uri", "name" * bool(Q.names))
        return _choose(Q, [(r.uri, r.url) for r in reqs], "http_url" if want_url else "http_uri", "name" * bool(Q.names),
                       formats=lambda v: ([("url", v[1]), ("uri", v[0])] if want_url else [("uri", v[0]), ("url", v[1])])
                       + ([("path", v[0].split("?")[0])] if "?" in v[0] else []))
    if has(r"\bhost header\b|\bhttp host\b|\bwebsite\b|\bweb site\b") or (has(r"\bhosts?\b|\bhost ?names?\b|\bdomains?\b|\bsites?\b") and http_ctx and not has(r"\bdns\b|\bquer")):
        return _choose(Q, [r.host for r in Q.filter(cap.http()) if r.method], "http_host")

    # -- DNS
    if Q.ips and has(r"\bresolv\w* to\b|\bpoints? to\b") and has(r"\bdomain\b|\bhost ?name\b|\bname\b"):
        ips = {ip for ip, _ in Q.ips}
        return _choose(Q, [m.qname.lower().rstrip(".") for m in answers if any(t in ("A", "AAAA") and v in ips for _, t, v in m.answers)],
                       "dns_name_of_address", "ip")
    if has(r"\btxt\b") and has(r"\bdns\b|\brecord\b"):
        return _choose(Q, [v for m in Q.filter(answers) for _, t, v in m.answers if t == "TXT"], "dns_txt")
    if has(r"\bdns\b|\bquer(?:y|ied|ies)\b|\blook(?:ed)? ?up\b|\blookups?\b|\bdomains?\b|\bfqdn\b"):
        sub = Q.filter(queries)
        qt = next((t for t in ("TXT", "MX", "AAAA", "CNAME", "PTR", "NS", "SRV") if has(r"\b" + t.lower() + r"\b")), None)
        if qt:
            sub = [m for m in sub if m.qtype == qt]
        if has(r"\bquery type\b|\brecord type\b") and not qt:      # a type the question names is a filter, not what is asked
            return _choose(Q, [m.qtype for m in sub], "dns_query_type")
        if not has(r"\bdomains?\b|\bhost ?names?\b|\bnames?\b|\bfqdn\b|\bquer(?:y|ied|ies)\b|\blook(?:ed)? ?up\b|\blookups?\b|\bsites?\b"):
            return Found(field="dns", shape=Q.shape(), options=[], candidates=[], why="a DNS question this file does not read")
        return _choose(Q, [m.qname.lower().rstrip(".") for m in sub if m.qname], "dns_query", (qt or "").lower())

    # -- host names and beacons
    if has(r"\bhost ?name\b|\bcomputer name\b|\bdevice name\b|\bmachine name\b"):
        return _choose(Q, [d.hostname for d in cap.dhcp() if d.hostname], "dhcp_hostname", method="dhcp_option_12")
    if has(r"\bbeacon|\bcheck.?ins?\b|\bcall.?backs?\b|\bheart ?beat\b|\bpolling\b|\binterval\b|\bhow often\b|\bperiod\b"):
        per = [b for b in cap.beacons() if b.periodic]
        if Q.ips:
            ips = {ip for ip, _ in Q.ips}
            per = [b for b in per if ips & {b.src, b.dst}]
        f = Found(field="beacon_interval", shape=Q.shape(), options=[],
                  candidates=[(f"{b.kind} {b.key} every {b.median:.3f} s x{b.events}", 1) for b in per][:20])
        if not has(r"\binterval\b|\bseconds?\b|\bminutes?\b|\bhow often\b|\bfrequen|\bperiod|\bevery\b"):
            f.why = "a question about the beacon that is not its interval"
            return f
        periods = sorted({round(b.median) for b in per})
        if len(periods) != 1:
            f.why = f"{len(periods)} different periods among the periodic events"
            return f
        med = sorted(b.median for b in per)[len(per) // 2]
        sec = periods[0]
        f.options = [("seconds_int", str(sec)), ("seconds_1dp", f"{med:.1f}"), ("seconds_unit", f"{sec}s")]
        if sec % 60 == 0 and sec and has(r"\bminutes?\b"):
            f.options.insert(0, ("minutes_int", str(sec // 60)))
        return f
    # -- a flag, and no channel named: the one flag-shaped text anywhere in what the capture carries
    if has(r"\bflag\b") and not has(r"\btcp flags?\b|\bflags? (?:field|bits?|set)\b|\bsyn\b|\back\b|\bfin\b|\brst\b|\bdf\b"):
        fl = cap.flags()
        f = Found(field="flag", shape="only", options=[], candidates=[(f"{k} ({v})", 1) for k, v in fl.items()][:20])
        named = [rx for name, rx in _FLAG_PLACES if name in Q.protos]
        if not _asks_for_flag(Q):
            f.why = "the question asks about the flag (where, which, how long), not for it"
        elif len(fl) == 1 and named and not any(re.match(rx, next(iter(fl.values()))) for rx in named):
            f.why = "the one flag-shaped text is not in the traffic the question names"
        elif len(fl) == 1:
            f.options = [("only_flag_shaped_text", next(iter(fl)))]
        else:
            f.why = "no flag-shaped text in the capture's payloads" if not fl else f"{len(fl)} flag-shaped texts in the capture"
        return f
    return None


def _hidden_found(Q, cap, channel) -> Found:
    """A covert channel's message: the readings of ONE arrangement of the pieces are ways of writing
    one fact (decoded first, then as sent); two arrangements are two facts, and then only the answer
    format's own pattern, or the one flag-shaped text among them, can choose."""
    readings = cap.hidden(channel)
    if _ABOUT_FLAG.search(Q.low):
        # a question about the hidden thing (its name, its hash, which packet, the second one, what
        # is not hidden) is not read here
        readings = OrderedDict()
    f = Found(field=f"hidden_{channel}", shape=Q.shape(), options=[], candidates=[(f"{k}: {v[:80]}", 1) for k, v in readings.items()])
    rx = Q.fmt.get("pattern") or Q.fmt.get("regex")
    fit = OrderedDict((k, v) for k, v in readings.items() if Q.fits(v)) if isinstance(rx, str) and rx.strip() else readings
    arrangements = list(dict.fromkeys(k.split(":")[0] for k in fit))
    if len(arrangements) == 1:
        f.options = [(k.split(":", 1)[1], v) for k, v in fit.items()]
        return f
    if Q.has(r"\bflag\b"):
        flags = OrderedDict()
        for k, v in readings.items():
            for m in flagfmt.TEXT.finditer(v):
                flags.setdefault(m.group(), k)
        if len(flags) == 1:
            val, k = next(iter(flags.items()))
            f.options = [(k.split(":", 1)[1] + "_flag", val)]
            return f
    f.why = "the capture holds no such channel, or the question asks about the hidden thing and not for it" if not readings else \
        f"{len(arrangements)} arrangements of the channel's pieces, and nothing in the question chooses one"
    return f


def _capture_for(q, files, caps):
    """The capture a question is about: the member it names, a capture named in its text, or the only one."""
    if not caps:
        return None
    member = str(q.get("member") or "")
    text = str(q.get("question") or "") + " " + str(q.get("artifact") or "")
    for want in (member, None):
        hits = []
        for name, data in caps:
            tail = name.split(ARROW)[-1]
            base = tail.rsplit("/", 1)[-1]
            if (want and base == want.rsplit("/", 1)[-1]) or (want is None and re.search(r"(?<![\w.-])" + re.escape(base) + r"(?![\w-])", text)):
                hits.append((name, data))
        if len(hits) == 1:
            return hits[0]
    return caps[0] if len(caps) == 1 else None


def _sibling(name):
    """A sibling toolkit module solvers/toolkits/<name>.py, loaded by path (the runner strips HERE
    from sys.path, so a plain import of a module named like a stdlib one would miss)."""
    path = HERE / f"{name}.py"
    mod = sys.modules.get("toolkits_" + name)
    if mod is not None and Path(getattr(mod, "__file__", "") or ".").resolve() == path:
        return mod
    import importlib.util
    spec = importlib.util.spec_from_file_location("toolkits_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["toolkits_" + name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop("toolkits_" + name, None)
        raise
    return mod


def _netauth_field(Q, cap):
    """The never-wrong readers for SMB2, Kerberos, SNMP and IRC in solvers/toolkits/net_auth.py
    (reference-technique-buildlist.md rows 12, 14, 10, 11). Consulted ONLY for a question _field
    returned None for, so it never changes an answer _field made; every value it offers is an
    unsure option list, never plain. Any import or parse failure is no answer -- the behaviour
    before this hook (the module absent or raising falls straight back to `return None, None`)."""
    try:
        return _sibling("net_auth").field(Q, cap, Found, _choose)
    except Exception:
        return None


def _netvoip_field(Q, cap):
    """The never-wrong SIP and RTP readers in solvers/toolkits/net_voip.py. Consulted ONLY for a
    question _field and net_auth returned no answer for, so it never changes an answer already made;
    every value it offers is an unsure option list, never plain. Any import or parse failure is no
    answer (the behaviour before this hook)."""
    try:
        return _sibling("net_voip").field(Q, cap, Found, _choose)
    except Exception:
        return None


def _netdb_field(Q, cap):
    """The never-wrong MQTT, Redis, MySQL, PostgreSQL, LDAP-bind and syslog readers in
    solvers/toolkits/net_dbproto.py. Consulted ONLY after _field, net_auth and net_voip gave no answer;
    unsure options only, never plain; any failure is no answer."""
    try:
        return _sibling("net_dbproto").field(Q, cap, Found, _choose)
    except Exception:
        return None


def _extra_field(Q, cap, name):
    """Consult the sibling never-wrong readers (net_auth, then net_voip) for a question network.py's
    own _field did not answer. Returns (answer, Found, name) for the first reader whose Found
    resolves to a non-None (unsure) answer; else (None, Found, name) for the first reader that
    recognised the question but read no value (so explain keeps its `why`); else None. Each reader
    offers unsure picks only, so this never makes an answer network.py already made, nor a plain one."""
    first = None
    for consult in (_netauth_field, _netvoip_field, _netdb_field):
        nf = consult(Q, cap)
        if nf is None:
            continue
        ans, rf, rn = _resolve(Q, nf, name)
        if ans is not None:
            return ans, rf, rn
        if first is None:
            first = (None, rf, rn)
    return first


def decide(q, files, ctx=None, caps=None):
    """(answer, Found or None, capture name) for one question. The answer is a plain value, an
    unsure '??' string, or None."""
    caps = find_captures(files) if caps is None else caps
    if not caps:
        return None, None, None
    tri = _triage()
    if tri is not None:
        try:
            generic = tri.answer(q, files, ctx or {})
        except Exception:
            generic = None
        if generic is not None:
            return generic, Found(field="delivered_file", shape="named", plain=generic, options=[], candidates=[]), None
    chosen = _capture_for(q, files, caps)
    if chosen is None:
        return None, Found(field=None, why=f"{len(caps)} captures in the delivery and the question names none", options=[], candidates=[]), None
    name, data = chosen
    cap = _cap_of(name, data)
    Q = _Q(q, files)
    if cap.truncated:
        return None, Found(field=None, why=f"the capture has more than {MAX_PACKETS} packets: read it by hand (read(path))",
                           options=[], candidates=[]), name
    f = _field(Q, cap)
    if f is None:
        # network.py's own readers do not know this question: consult the sibling never-wrong
        # readers (net_auth: SMB2/Kerberos/SNMP/IRC; net_voip: SIP/RTP). None (module absent/
        # raising, or not one of those) keeps the old `return None, None` exactly.
        got = _extra_field(Q, cap, name)
        return got if got is not None else (None, None, name)
    ans, rf, rn = _resolve(Q, f, name)
    if ans is None:
        # network.py recognised the question but read no value for it (a Found with only a `why`):
        # give the sibling readers a turn. This fills ONLY where network.py answers None, so it can
        # never change an answer network.py made, and the siblings offer unsure picks only.
        got = _extra_field(Q, cap, name)
        if got is not None and got[0] is not None:
            return got
    return ans, rf, rn


def _resolve(Q, f, name):
    """Turn a Found into (answer, Found, capture name): a plain value, a labels.candidates answer,
    an unsure pick over the fitting options, or None. The post-_field half of decide, so the same
    resolution applies to network.py's own Found and to net_auth's."""
    if f.plain is not None and _negates(Q.text):
        f.options, f.plain = [("as_read", f.plain)], None       # "what is NOT the SHA-256 of x": the fact is there, the question is not for it
    if f.plain is not None:
        return (f.plain if Q.fits(f.plain) else None), f, name
    if f.candidate:
        # a labels.candidates answer (row 346): different values, each named by its hypothesis,
        # never plain before the judge accepts one. Kept in offered order (best first); two
        # hypotheses with the same value are one candidate.
        seen, cand = set(), []
        for n, v in f.candidate:
            if v not in (None, "") and Q.fits(v) and v not in seen:
                seen.add(v)
                cand.append((n, v))
        if not cand:
            if not f.why:
                f.why = "no candidate value fits the answer format"
            return None, f, name
        return _candidates(f"{KEY}.{f.field}/{f.shape}", cand), f, name
    opts = [(n, v) for n, v in (f.options or []) if v not in (None, "") and Q.fits(v)]
    seen, uniq = set(), []
    for n, v in opts:               # two methods that write the same text are one option
        if v not in seen:
            seen.add(v)
            uniq.append((n, v))
    if not uniq:
        if f.options and not f.why:
            f.why = "no way of writing the value fits the answer format"
        return None, f, name
    return _pick(f"{KEY}.{f.field}/{f.shape}", uniq), f, name


def solve_set(questions, files, ctx) -> dict:
    out = {}
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    try:
        caps = find_captures(files)
    except Exception:
        caps = []
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            ans = decide(q, files, ctx, caps)[0] if caps else None
        except Exception:           # a fact that cannot be read is no answer
            ans = None
        out[qid] = ans
        if partial is not None and ans is not None:
            partial[qid] = ans
    if caps and any(value is None for value in out.values()):
        native = _native_tls_answers(questions, files, caps)
        if isinstance(native, dict):
            for q in questions:
                qid = q.get("qid") or q.get("id")
                if out.get(qid) is None and native.get(qid) is not None:
                    out[qid] = native[qid]        # fill only a gap; native TLS never replaces a fact
                    if partial is not None:
                        partial[qid] = native[qid]
    return out


def explain(questions, files, ctx=None) -> list:
    """[Rec(answer_id, question, capture, field, shape, answer, options, candidates, why)] for a
    reader: what each question was taken to ask and what the capture holds for it."""
    rows = []
    caps = find_captures(files)
    for q in questions:
        try:
            ans, f, name = decide(q, files, ctx, caps)
        except Exception as e:
            ans, f, name = None, Found(field=None, why=f"{type(e).__name__}: {e}", options=[], candidates=[]), None
        f = f or Found(field=None, why="not a question this toolkit reads" if caps else "no capture in the delivery", options=[], candidates=[])
        rows.append(Rec(answer_id=q.get("answer_id") or q.get("id"), question=q.get("question"), capture=name, field=f.field,
                        shape=f.shape, answer=ans, options=f.options, candidates=f.candidates, why=f.why))
    return rows


# ---- the command ---------------------------------------------------------------------------------------

def _when(ns) -> str:
    return "-" if ns is None else _iso(ns, 6)


def _clip(s, n=100) -> str:
    s = "" if s is None else str(s).replace("\r", "\\r").replace("\n", "\\n")
    return s if len(s) <= n else s[:n - 3] + "..."


def summary(cap: Capture, rows: int = 15) -> dict:
    """The triage of one capture as plain data (what the command prints)."""
    T = cap.times()
    lim = None if rows is None else rows

    def cut(seq):
        seq = list(seq)
        return seq if lim is None else seq[:lim]

    return {
        "file": cap.name, "format": cap.format, "size": cap.size, "sha256": cap.sha256, "packets": len(cap.packets),
        "linktypes": {LINKTYPES.get(k, str(k)): v for k, v in cap.linktypes.items()}, "damaged": cap.damaged,
        "truncated": cap.truncated, "first": _when(T.first), "last": _when(T.last),
        "duration_seconds": None if T.duration is None else T.duration / 1e9, "time_ordered": T.ordered, "meta": cap.meta,
        "comments": cut(cap.comments), "secrets": [(t, len(b)) for t, b in cap.secrets], "names": cut(cap.names),
        "protocols": dict(cap.protocols().most_common()),
        "endpoints": cut((ip, e.sent, e.received, [mac(m) for m in e.macs][:3]) for ip, e in
                         sorted(cap.endpoints().items(), key=lambda kv: -(kv[1].sent + kv[1].received))),
        "conversations": cut((c.a, c.aport, c.b, c.bport, c.proto, c.packets, c.bytes) for c in cap.conversations()),
        "banners": cut((b.server, b.port, b.banner) for b in cap.banners()),
        "dns_queries": cut((n, t, c) for (n, t), c in Counter((m.qname, m.qtype) for m in cap.dns() if not m.qr).items()),
        "dns_answers": cut(dict.fromkeys((m.qname, t, v) for m in cap.dns() if m.qr for _, t, v in m.answers)),
        "dhcp": cut(dict.fromkeys((mac(d.mac), d.type, d.hostname, d.requested_ip or d.your_ip) for d in cap.dhcp())),
        "http": cut((_when(r.ts), r.src, r.method, r.host, r.uri, r.status, r.user_agent) for r in cap.http()),
        "user_agents": cut(Counter(r.user_agent for r in cap.http() if r.user_agent).most_common()),
        "tls": cut((_when(t.ts), t.src, t.dst, t.dport, t.sni, t.ja3, t.ja3s, t.ja4) for t in cap.tls()),
        "certs": cut((c.server, c.position, c.subject, c.issuer, c.sha256) for c in cap.certs()),
        "credentials": cut((c.proto, c.user, c.password, c.ok, c.src, c.dst, c.dport) for c in cap.credentials()),
        "ntlm": cut((e.src, e.dst, e.dport, e.user, e.domain, e.workstation, e.target_name,
                     (f"0x{e.flags:08x}" if e.flags is not None else None), (e.challenge or b"").hex() or None,
                     dict(e.av), [fmt for fmt, _ in (e.netntlm or [])]) for e in cap.ntlm()),
        "http_digest": cut((d.src, d.dst, d.dport, d.method, d.uri, d.username, d.realm, d.nonce, d.response,
                            d.algorithm, d.qop) for d in cap.http_digest()),
        "ftp": cut((f.server, f.port, f.commands) for f in cap.ftp()),
        "smtp": cut((m.mail_from, m.rcpt_to, m.subject, [a.name for a in m.attachments]) for m in cap.smtp()),
        "telnet": cut((t.server, t.user, t.password, t.typed[:20]) for t in cap.telnet()),
        "objects": cut((o.source, o.name, o.size, o.sha256, o.md5, o.complete, o.content_type) for o in cap.objects()),
        "icmp": cut((r.src, r.dst, r.type, r.seq, r.data[:48].hex(), r.standard) for r in cap.icmp_payloads()),
        "hidden_icmp": cap.hidden("icmp"), "hidden_dns": cap.hidden("dns"),
        "dns_tunnel": cut((t.parent if t.kind != "sequence" else f"{t.parent} <- {t.src} seq {t.seq[0]}-{t.seq[-1]}",
                           t.names, _clip(t.joined, 120)) for t in cap.dns_tunnel()),
        "beacons": cut((b.kind, list(b.key), b.events, round(b.median, 3), round(b.jitter, 3), b.periodic) for b in cap.beacons()),
        "syn_scan": cut((s.src, s.dst, len(s.ports), s.open) for s in cap.syn_scan()),
        "open_ports": cap.open_ports(),
        "usb_keystrokes": [(k.bus, k.device, k.endpoint, k.text, k.raw) for k in cap.usb_keystrokes()],
        "modbus": cut((m.src, m.dst, m.function, m.address, m.registers) for m in cap.modbus()),
        "modbus_series": cut((m.src, m.dst, m.function, m.address, m.writes, len(set(m.written)), m.reading or "",
                              m.text if m.text else "") for m in cap.modbus_series()),
        "flags": cut(cap.flags().items()),
        "hidden_blobs": cut((b.channel, b.key, b.kind, b.size, b.sha256, b.flags, b.members, b.comment,
                             {k: _clip(v.decode("utf-8", "replace"), 80) for k, v in b.opened.items()})
                            for b in cap.hidden_blobs()),
    }


COLUMNS = {"comments": "packet, text", "names": "address, name", "endpoints": "address, sent, received, hardware addresses",
           "conversations": "a, port, b, port, ip protocol, packets, bytes", "banners": "server, port, first line",
           "dns_queries": "name, type, times asked", "dns_answers": "name, type, value", "dhcp": "hardware address, message, host name, address",
           "http": "time, client, method, host, uri, status, user agent", "user_agents": "user agent, requests",
           "tls": "time, client, server, port, sni, ja3, ja3s, ja4", "certs": "server, position, subject, issuer, sha256",
           "credentials": "protocol, user, password, accepted, client, server, port",
           "ntlm": "client, server, port, user, domain, workstation, target, flags, challenge, av pairs, netntlm formats",
           "http_digest": "client, server, port, method, uri, user, realm, nonce, response, algorithm, qop",
           "ftp": "server, port, commands",
           "smtp": "mail from, rcpt to, subject, attachments", "telnet": "server, user, password, typed lines",
           "objects": "source, name, bytes, sha256, md5, whole, content type", "icmp": "from, to, type, seq, payload hex, ordinary ping",
           "dns_tunnel": "parent, names, labels joined", "beacons": "kind, key, events, median seconds, jitter, periodic",
           "syn_scan": "source, target, ports tried, ports open", "usb_keystrokes": "bus, device, endpoint, text, raw",
           "modbus": "from, to, function, address, registers",
           "modbus_series": "from, to, function, address, writes, distinct values, reading, text",
           "flags": "flag-shaped text, where",
           "hidden_blobs": "channel, reading, kind, bytes, sha256, flag-shaped texts, zip members, zip comment, opened members"}


def render(s: dict) -> str:
    out = [f"# {s['file']}: {s['format']}, {s['packets']} packets, {s['size']} bytes, sha256 {s['sha256']}",
           f"link {s['linktypes']}  first {s['first']}  last {s['last']}  duration {s['duration_seconds']} s"
           + ("" if s["time_ordered"] else "  (NOT in time order)")]
    if s["damaged"]:
        out.append(f"NOTE damaged: {s['damaged']}")
    if s["truncated"]:
        out.append("NOTE truncated by the packet limit")
    if s["meta"]:
        out.append(f"meta {s['meta']}")
    if s["secrets"]:
        out.append(f"NOTE decryption secrets in the file (a TLS key log): {s['secrets']}; decrypt in process with "
                   f"tls_decrypt(...) / the --tls-decrypt command (sandbox tshark), or tshark -o tls.keylog_file")
    for key in ("protocols", "open_ports", "hidden_icmp", "hidden_dns"):
        if s[key]:
            out.append(f"## {key}")
            out += [f"  {k}: {_clip(v, 200)}" for k, v in s[key].items()]
    for key in ("comments", "names", "endpoints", "conversations", "banners", "dns_queries", "dns_answers", "dhcp", "http",
                "user_agents", "tls", "certs", "credentials", "ntlm", "http_digest", "ftp", "smtp", "telnet", "objects",
                "icmp", "dns_tunnel", "beacons", "syn_scan", "usb_keystrokes", "modbus", "modbus_series", "hidden_blobs", "flags"):
        if s.get(key):
            out.append(f"## {key}" + (f"   ({COLUMNS[key]})" if key in COLUMNS else ""))
            out += ["  " + "  ".join(_clip(x, 110) for x in row) for row in s[key]]
    return "\n".join(out)


def _safe_name(name, i) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "object"))[:80].lstrip(".") or "object"
    return f"{i:03d}-{base}"


def main(argv) -> int:
    flags = {a for a in argv if a.startswith("--") and a != "--"}
    if "--tshark" in flags:
        rest = argv[argv.index("--") + 1:] if "--" in argv else []
        paths = [a for a in (argv[:argv.index("--")] if "--" in argv else argv) if not a.startswith("--")]
        if len(paths) != 1:
            print("usage: network.py --tshark <capture> -- <tshark arguments>", file=sys.stderr)
            return 2
        r = tshark(paths[0], rest)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        if r.note:
            print(f"NOTE {r.note}", file=sys.stderr)
        return 0 if r.ok else 1
    if "--tls-decrypt" in flags:
        paths = [a for a in argv if not a.startswith("--")]
        if not paths:
            print("usage: network.py --tls-decrypt <capture> [keylog] [more files...]  "
                  "(the capture and its key log, among the delivery's files)", file=sys.stderr)
            return 2
        files = {}
        for p in paths:
            try:
                files[Path(p).name] = Path(p).read_bytes()
            except OSError as e:
                print(f"network.py: {p}: {e}", file=sys.stderr)
                return 1
        rows = tls_decrypt_bundle(files)
        if not rows:
            print("no capture among the files", file=sys.stderr)
            return 1
        any_decrypted = False
        for r in rows:
            print(f"# {r.capture}: decrypted={r.decrypted} keylog={r.keylog_source or '-'}" + (f"  NOTE {r.note}" if r.note else ""))
            any_decrypted = any_decrypted or r.decrypted
            for h in r.http:
                print(f"  HTTP {h.method or ''} {(h.host or '')}{h.uri or ''}" + (f" -> {h.status}" if h.status else ""))
            for o in r.objects:
                print(f"  OBJECT {o.name} {o.size} bytes sha256 {o.sha256}")
        return 0 if any_decrypted else 1
    args, carve, attempt, i = [], None, None, 0
    while i < len(argv):
        a = argv[i]
        if a in ("--carve", "--attempt"):
            if i + 1 >= len(argv):
                print(f"network.py: {a} needs a folder", file=sys.stderr)
                return 2
            carve, attempt = (argv[i + 1], attempt) if a == "--carve" else (carve, argv[i + 1])
            i += 1
        elif not a.startswith("--"):
            args.append(a)
        i += 1
    if attempt:
        tools = str(ROOT / "tools")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        import run
        folder = Path(attempt).resolve()
        att, blobs, _ = run.load_offline(folder.name, str(folder))
        for n, qs, files, ctx in run.split_sets(att, blobs, [], []):
            print(f"## set {n}: signals {signals(qs, files)}; captures {[c[0] for c in find_captures(files)]}")
            for r in explain(qs, files, ctx):
                print(f"- {r.answer_id}: {_clip(r.question, 140)}")
                print(f"    field {r.field or '-'}/{r.shape or '-'}  answer {_clip(r.answer, 160) if r.answer is not None else 'None'}"
                      + (f"  why: {r.why}" if r.why else ""))
                if r.candidates:
                    print("    candidates: " + "; ".join(f"{_clip(v, 60)} x{c}" for v, c in r.candidates[:12]))
        return 0
    if not args:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    code = 0
    for path in args:
        try:
            cap = read(path)
        except (OSError, ValueError) as e:
            print(f"network.py: {path}: {e}", file=sys.stderr)
            code = 1
            continue
        s = summary(cap, None if "--all" in flags else 15)
        if "--json" in flags:
            print(json.dumps(s, indent=1, ensure_ascii=False, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
        else:
            print(render(s))
        if carve:
            out = Path(carve)
            out.mkdir(parents=True, exist_ok=True)
            for n, o in enumerate(cap.objects()):
                (out / _safe_name(o.name, n)).write_bytes(o.data)
                print(f"CARVED {out / _safe_name(o.name, n)} {o.size} bytes sha256 {o.sha256} source {o.source}"
                      + ("" if o.complete else " INCOMPLETE"))
            for n, b in enumerate(cap.hidden_blobs()):
                name = _safe_name(f"hidden-{b.channel}.{b.kind}", n)
                (out / name).write_bytes(b.data)
                print(f"CARVED {out / name} {b.size} bytes sha256 {b.sha256} source hidden {b.channel} {b.key}")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
