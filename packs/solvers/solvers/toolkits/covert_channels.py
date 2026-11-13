#!/usr/bin/env python3
"""General covert-channel decoder (toolkit key "network"): recover data smuggled in packet fields.

Covert channels are a recurring CTF forensics/networking/ICS theme (CSCTF 2025 alone had an NTP
RefID channel, DNS TXT exfil, and FFT tones). This engine reads the usual arrangements OFFLINE and
returns, per channel, a RANKED LIST OF CANDIDATE decoded strings for a human to read
(`labels.show(...)`). It never probes a judge and never submits; you reason to the one flag.

Channels covered:
  (a) ntp_refid   - the 4 reference-identifier bytes (NTP header bytes 12-15) across a series -> ASCII
  (b) dns_exfil   - data smuggled in QNAME labels or TXT answers across queries -> concatenated/decoded;
                    numbered <data>.<NN>.<zone> streams per source in number order (qname_sequence)
  (c) icmp_echo   - bytes hidden in ICMP echo-request/reply payloads across a series
  (d) timing_bits - an inter-packet-timing bit channel: threshold the gaps -> bits -> bytes
  (e) header_field- IP id low byte, TCP sequence low byte, or TTL carried one byte per packet

Input (any channel function and `scan`) is EITHER
  - a .pcap/.pcapng path, its bytes, or a network.Capture (read via solvers/toolkits/network.py), OR
  - a provided list of packets: dicts (flexible keys: proto/src/dst/sport/dport/payload/ttl/ip_id/
    seq/icmp_type/iid/iseq/qname/txt/refid/ts) or scapy packets or network Pkt objects.
This dual input is what lets the tests build synthetic packet lists with no real pcap.

CLI:
  .venv/bin/python solvers/toolkits/covert_channels.py <capture>...          every channel, ranked
  .venv/bin/python solvers/toolkits/covert_channels.py --json <capture>      the same as JSON
  .venv/bin/python solvers/toolkits/covert_channels.py --channel dns <cap>   one channel only
  .venv/bin/python solvers/toolkits/covert_channels.py --auto <capture>...   intake's read: the DNS
      channel of a DNS-dominated capture only (numbered QNAME streams first, with source and zone);
      any other capture is reported as not DNS-dominated and nothing else is printed

Numbered DNS exfil (B-079): <data>.<NN>.<zone> queries are grouped by source and zone, sorted by NN,
repeats dropped and the NN labels stripped before the decode (network.dns_sequences, shared with
network.Capture.dns_tunnel); arrangement `qname_sequence`, ranked ahead of the as-asked join.

Keys are `network.covert_<channel>/<arrangement>` (labels.py TOOLKIT_PREFIXES knows `network`); each
result's `candidates` is a labels unsure value whose options are the decoded strings, best first, a
flag-bearing reading ranked ahead of the rest. Never a guess, never an auto-submit.
"""
import json
import re
import sys
from collections import Counter
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
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
import labels          # noqa: E402
import network         # noqa: E402  (packet reading plumbing: read, parse_dns, decodings, _printable)

KEY = "network"
FLAG_RE = flagfmt.BYTES
# proto numbers we key on
TCP, UDP, ICMP, ICMPV6 = 6, 17, 1, 58
NTP_PORT, DNS_PORTS = 123, (53, 5353, 5355)
_MIN_TIMING = 16        # bits (gaps) needed before a timing reading is worth offering
DNS_SHARE = 0.5         # --auto reads a capture only when DNS messages are more than this share of it
AUTO_PACKET_LIMIT = 200_000     # --auto reads at most this many packets of one capture (and says so)
_PROTO_WORDS = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "icmpv6": ICMPV6, "icmp6": ICMPV6,
                "ntp": UDP, "dns": UDP}
_DEFAULT_PORT = {"ntp": NTP_PORT, "dns": 53}


# ---------------------------------------------------------------------------- normalized packets

class _P(dict):
    """A normalized packet view: attribute access, missing fields read as None."""
    __getattr__ = dict.get

    def __setattr__(self, k, v):
        self[k] = v


def _as_bytes(x) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        # a hex string if it looks like one, else the raw latin-1 bytes
        s = x.strip()
        if len(s) % 2 == 0 and s and re.fullmatch(r"[0-9a-fA-F]+", s):
            try:
                return bytes.fromhex(s)
            except ValueError:
                pass
        return x.encode("latin-1", "replace")
    if isinstance(x, (list, tuple)):
        return bytes(int(b) & 0xFF for b in x)
    return bytes(x)


def _int(x):
    if isinstance(x, bool):
        return int(x)
    if x is None:
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _from_dict(d: dict) -> _P:
    p = _P()
    proto = d.get("proto")
    word = proto.lower() if isinstance(proto, str) else None
    if word in _PROTO_WORDS:
        p.proto = _PROTO_WORDS[word]
    else:
        p.proto = _int(proto)
    p.src, p.dst = d.get("src"), d.get("dst")
    p.sport = _int(d.get("sport"))
    p.dport = _int(d.get("dport"))
    if word in _DEFAULT_PORT and p.sport is None and p.dport is None:
        p.dport = _DEFAULT_PORT[word]
    p.payload = _as_bytes(d.get("payload", d.get("data", b"")))
    p.ttl = _int(d.get("ttl", d.get("hlim")))
    p.ipid = _int(d.get("ip_id", d.get("ipid", d.get("id"))))
    p.seq = _int(d.get("seq", d.get("tcp_seq")))
    p.itype = _int(d.get("itype", d.get("icmp_type", d.get("type"))))
    p.iid = _int(d.get("iid", d.get("icmp_id")))
    p.iseq = _int(d.get("iseq", d.get("icmp_seq")))
    p.qname = d.get("qname")
    txt = d.get("txt")
    p.txt = [txt] if isinstance(txt, str) else list(txt) if txt else []
    refid = d.get("refid")
    p.refid = _as_bytes(refid) if refid is not None else None
    qr = d.get("qr")
    p.qr = None if qr is None else int(bool(qr))
    ts = d.get("ts", d.get("time"))
    p.ts = float(ts) if ts is not None else None
    # infer proto from the fields present when it was not given
    if p.proto is None:
        if p.qname is not None or p.txt or p.dport in DNS_PORTS or p.sport in DNS_PORTS:
            p.proto = UDP
        elif p.itype is not None or p.iid is not None:
            p.proto = ICMP
        elif p.seq is not None:
            p.proto = TCP
    return p


def _from_pkt(p) -> _P:
    """From a network.Pkt (ts is nanoseconds there)."""
    out = _P()
    out.proto, out.src, out.dst = p.proto, p.src, p.dst
    out.sport, out.dport = p.sport, p.dport
    out.payload = bytes(p.payload or b"")
    out.ttl, out.ipid, out.seq = p.ttl, p.ipid, p.seq
    out.itype, out.iid, out.iseq = p.itype, p.iid, p.iseq
    out.qname, out.txt, out.refid, out.qr = None, [], None, None
    out.ts = None if p.ts is None else p.ts / 1e9
    return out


def _from_scapy(pk) -> _P:
    """Best-effort from a scapy packet (used only if scapy objects are passed in)."""
    d = {}
    try:
        if pk.haslayer("IP"):
            ip = pk["IP"]
            d.update(src=ip.src, dst=ip.dst, ttl=int(ip.ttl), ip_id=int(ip.id), proto=int(ip.proto))
        elif pk.haslayer("IPv6"):
            ip6 = pk["IPv6"]
            d.update(src=ip6.src, dst=ip6.dst, ttl=int(ip6.hlim))
        if pk.haslayer("TCP"):
            t = pk["TCP"]
            d.update(proto=TCP, sport=int(t.sport), dport=int(t.dport), seq=int(t.seq))
        elif pk.haslayer("UDP"):
            u = pk["UDP"]
            d.update(proto=UDP, sport=int(u.sport), dport=int(u.dport))
        elif pk.haslayer("ICMP"):
            ic = pk["ICMP"]
            d.update(proto=ICMP, itype=int(ic.type), iid=int(getattr(ic, "id", 0)), iseq=int(getattr(ic, "seq", 0)))
        pay = bytes(pk.lastlayer().payload) if hasattr(pk, "lastlayer") else b""
        if not pay and hasattr(pk, "load"):
            pay = bytes(pk.load)
        d["payload"] = pay
        if hasattr(pk, "time"):
            d["ts"] = float(pk.time)
    except Exception:
        pass
    return _from_dict(d)


def _to_rec(x) -> _P:
    if isinstance(x, _P):
        return x
    if isinstance(x, dict):
        return _from_dict(x)
    if hasattr(x, "haslayer"):
        return _from_scapy(x)
    return _from_pkt(x)


def _normalize(source):
    """A list of normalized packets from a pcap path/bytes/Capture or a provided packet list."""
    if isinstance(source, (list, tuple)):
        return [_to_rec(x) for x in source]
    cap = network.read(source)
    return [_from_pkt(p) for p in cap.packets]


# ---------------------------------------------------------------------------- candidate ranking

def _printable(b) -> bool:
    return network._printable(b)


def _text(blob: bytes) -> str:
    return bytes(blob).decode("utf-8", "replace").strip("\x00")


def _has_flag(value) -> bool:
    data = value if isinstance(value, (bytes, bytearray)) else str(value).encode("latin-1", "replace")
    return bool(FLAG_RE.search(data))


def _candidate_pairs(blob: bytes, decoded_first: bool = False, more=()):
    """Ranked (hypothesis, decoded-string) pairs for one recovered blob, best evidence first. A
    reading that contains a flag is pulled to the front; plain ASCII beats the strict base decodings
    unless decoded_first (a reassembled exfil stream, whose text as sent is the encoding, not the
    data); a raw-hex fallback is always last so there is something to show. more: extra
    (name, bytes) readings (each piece decoded by itself), offered after the whole-blob ones."""
    blob = bytes(blob)
    pairs, seen = [], set()

    def add(name, value):
        if value and value not in seen:
            seen.add(value)
            pairs.append((name, value))

    if _printable(blob):
        add("ascii", _text(blob))
    for meth, dec in list(network.decodings(blob).items()) + list(more):
        if dec and (_printable(dec) or _has_flag(dec)):
            add(meth, _text(dec))
    # flag anywhere in the raw bytes, even if the whole blob is not printable
    m = FLAG_RE.search(blob)
    if m:
        add("ascii_flag", m.group().decode("latin-1"))
    add("raw_hex", blob.hex())

    def score(pair):
        name, value = pair
        has_flag = 0 if _has_flag(value) else 1
        is_hex = 2 if name == "raw_hex" else 0
        as_sent = 1 if decoded_first and name == "ascii" else 0
        return (has_flag, is_hex, as_sent)

    pairs.sort(key=score)
    return pairs


def _result(channel: str, arrangement: str, blob: bytes, *, decoded_first: bool = False, more=(),
            **extra) -> _P:
    """Wrap one recovered blob as a channel result with a labels candidate list."""
    key = f"{KEY}.covert_{channel}/{arrangement}"
    pairs = _candidate_pairs(blob, decoded_first=decoded_first, more=more)
    cand = labels.candidates(key, pairs) if pairs else None
    r = _P(channel=channel, arrangement=arrangement, key=key, blob_hex=bytes(blob).hex(),
           candidates=cand, ranked=[v for _, v in pairs],
           shown=labels.show(cand) if cand is not None else "")
    r.update(extra)
    return r


# ---------------------------------------------------------------------------- (a) NTP RefID

def _ntp(pkts):
    """NTP packets carry a 32-bit reference identifier at header bytes 12-15; a covert channel writes
    ASCII there across a series. Concatenate the ref-id bytes in capture order."""
    refids = []
    for p in pkts:
        if p.refid is not None:
            refids.append(p.refid[:4].ljust(4, b"\x00")[:4])
        elif p.proto == UDP and (p.sport == NTP_PORT or p.dport == NTP_PORT) and len(p.payload) >= 16:
            refids.append(p.payload[12:16])
    if not refids:
        return None
    blob = b"".join(refids)
    return _result("ntp", "refid", blob, pieces=[r.hex() for r in refids], count=len(refids))


def ntp_refid(source):
    return _ntp(_normalize(source))


# ---------------------------------------------------------------------------- (b) DNS exfil

def _dns_message(p):
    """(qr, qname, [txt values]) for a DNS packet, from explicit fields or by parsing the payload."""
    if p.qname is not None or p.txt:
        return p.qr, p.qname, list(p.txt)
    if p.proto == UDP and p.payload and (p.dport in DNS_PORTS or p.sport in DNS_PORTS):
        m = network.parse_dns(p.payload)
        if m is not None:
            txt = [v for _n, t, v in m.answers if t == "TXT"]
            return m.qr, m.qname, txt
    return None


def dns_share(pkts):
    """(DNS messages, packets) of a normalized packet list: how much of a capture is DNS."""
    return sum(1 for p in pkts if _dns_message(p) is not None), len(pkts)


def dns_dominated(pkts) -> bool:
    """True when DNS messages are more than half the packets (DNS_SHARE): the captures intake's
    --auto run reads. A capture of anything else is not read for a DNS channel there."""
    n, total = dns_share(pkts)
    return n >= 2 and n > total * DNS_SHARE


def _sequence_results(streams):
    """One `qname_sequence` result per numbered stream (network.dns_sequences): the data labels in
    number order, numbers stripped, decoded readings ranked over the text as sent."""
    out = []
    for s in streams:
        more = [("each_" + meth, dec) for meth, dec in s.per_label.items()]
        out.append(_result("dns", "qname_sequence", s.joined.encode("latin-1", "replace"), decoded_first=True,
                           more=more, src=s.src, zone=s.zone, layout=s.layout, sequence=s.seq,
                           missing=s.missing, repeats=s.repeats, conflicts=s.conflicts, pieces=s.labels,
                           qnames=s.qnames))
    return out


def _dns(pkts):
    msgs = []
    for p in pkts:
        m = _dns_message(p)
        if m is not None:
            msgs.append((p.src,) + tuple(m))
    if not msgs:
        return None
    out = []

    # Numbered QNAME streams first (B-079): <data>.<NN>.<zone> per source and zone, put in number
    # order whatever order they were asked in; the shared reassembly is network.dns_sequences.
    streams = network.dns_sequences((src, qname) for src, qr, qname, _t in msgs if qname and qr in (None, 0))
    out += _sequence_results(streams)
    claimed = {(s.src, q) for s in streams for q in s.members}

    # QNAME channel: the leading labels of each query, data smuggled in the subdomain (names of a
    # numbered stream are read above, not again here in the order asked).
    names, seen = [], set()
    for src, qr, qname, _txt in msgs:
        if qname and (src, qname.rstrip(".")) in claimed:
            continue
        if qname and qr in (None, 0) and qname not in seen:
            seen.add(qname)
            names.append(qname.rstrip("."))
    if names:
        split = [n.split(".") for n in names]
        # the shared parent domain = the most common trailing two labels
        tails = Counter(tuple(lbls[-2:]) for lbls in split if len(lbls) >= 2)
        parent = tails.most_common(1)[0][0] if tails else ()
        subs = []
        for lbls in split:
            lead = lbls[:-len(parent)] if parent and tuple(lbls[-len(parent):]) == parent else lbls
            subs.append("".join(lead))
        blob_sub = "".join(subs).encode("latin-1", "replace")
        if blob_sub:
            out.append(_result("dns", "qname", blob_sub, pieces=subs, names=len(names),
                               parent=".".join(parent)))
        firsts = "".join(lbls[0] for lbls in split if lbls)
        fb = firsts.encode("latin-1", "replace")
        if fb and fb != blob_sub:
            out.append(_result("dns", "qname_first_label", fb, pieces=[l[0] for l in split if l]))

    # TXT channel: concatenated TXT answers across the series.
    txts, tseen = [], set()
    for _src, _qr, _qname, txt in msgs:
        for t in txt:
            if t not in tseen:
                tseen.add(t)
                txts.append(t)
    if txts:
        blob_txt = "".join(txts).encode("latin-1", "replace")
        out.append(_result("dns", "txt", blob_txt, pieces=txts, answers=len(txts)))
    return out or None


def dns_exfil(source):
    return _dns(_normalize(source))


# ---------------------------------------------------------------------------- (c) ICMP echo payloads

def _std_ping(data: bytes) -> bool:
    try:
        return network._standard_ping(data)
    except Exception:
        return False


def _icmp(pkts):
    req, rep = [], []
    seen = set()
    for p in pkts:
        if p.proto not in (ICMP, ICMPV6) or p.itype is None:
            continue
        is_req = p.itype in (8, 128)
        is_rep = p.itype in (0, 129)
        if not (is_req or is_rep) or not p.payload:
            continue
        sig = (p.src, p.dst, p.itype, p.iid, p.iseq, p.payload)
        if sig in seen:
            continue
        seen.add(sig)
        (req if is_req else rep).append(p.payload)
    out = []
    for name, group in (("echo_request", req), ("echo_reply", rep)):
        if not group:
            continue
        covert = [d for d in group if not _std_ping(d)] or group
        blob = b"".join(covert)
        out.append(_result("icmp", name, blob, pieces=[d.hex() for d in covert], count=len(covert)))
        # one covert byte per packet (first byte of each payload) is a common arrangement
        firsts = bytes(d[0] for d in covert if d)
        if firsts and firsts != blob:
            out.append(_result("icmp", name + "_first_byte", firsts, count=len(covert)))
    return out or None


def icmp_echo(source):
    return _icmp(_normalize(source))


# ---------------------------------------------------------------------------- (d) inter-packet timing

def _bits_to_bytes(bits, msb_first=True) -> bytes:
    bits = bits[:len(bits) - len(bits) % 8]
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if not msb_first:
            chunk = chunk[::-1]
        out.append(int("".join(str(b) for b in chunk), 2))
    return bytes(out)


def _timing(pkts, threshold=None):
    ts = [p.ts for p in pkts if p.ts is not None]
    if len(ts) < _MIN_TIMING + 1:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if len(gaps) < _MIN_TIMING:
        return None
    ordered = sorted(gaps)
    mid = ordered[len(ordered) // 2]
    mean = sum(gaps) / len(gaps)
    thresholds = [("median", mid), ("mean", mean)]
    if threshold is not None:
        thresholds.insert(0, ("given", float(threshold)))
    out = []
    for tname, thr in thresholds:
        for polarity, long_is_one in (("long=1", True), ("long=0", False)):
            bits = [1 if (g > thr) == long_is_one else 0 for g in gaps]
            for order, msb in (("msb", True), ("lsb", False)):
                blob = _bits_to_bytes(bits, msb_first=msb)
                if not blob:
                    continue
                pairs = _candidate_pairs(blob)
                # only offer a timing reading that actually decodes to text or a flag
                best = pairs[0] if pairs else None
                if best and best[0] != "raw_hex":
                    out.append(_result("timing", f"{tname}/{polarity}/{order}", blob,
                                       threshold=thr, gaps=len(gaps)))
    if not out:
        return None
    out.sort(key=lambda r: 0 if (r.ranked and _has_flag(r.ranked[0])) else 1)
    return out


def timing_bits(source, threshold=None):
    return _timing(_normalize(source), threshold=threshold)


# ---------------------------------------------------------------------------- (e) header-field channels

def _header(pkts):
    out = []

    def collect(getter):
        vals = []
        for p in pkts:
            v = getter(p)
            if v is not None:
                vals.append(v)
        return vals

    ipids = collect(lambda p: p.ipid)
    if ipids:
        low = bytes(v & 0xFF for v in ipids)
        out.append(_result("header", "ip_id_low_byte", low, count=len(ipids)))
        full = b"".join(int(v & 0xFFFF).to_bytes(2, "big") for v in ipids)
        out.append(_result("header", "ip_id_be16", full, count=len(ipids)))

    seqs = collect(lambda p: p.seq if p.proto == TCP else None)
    if seqs:
        low = bytes(v & 0xFF for v in seqs)
        out.append(_result("header", "tcp_seq_low_byte", low, count=len(seqs)))
        high = bytes((v >> 24) & 0xFF for v in seqs)
        if high != low:
            out.append(_result("header", "tcp_seq_high_byte", high, count=len(seqs)))

    ttls = collect(lambda p: p.ttl)
    if ttls:
        raw = bytes(v & 0xFF for v in ttls)
        out.append(_result("header", "ttl_raw", raw, count=len(ttls)))
    return out or None


def header_field(source):
    return _header(_normalize(source))


# ---------------------------------------------------------------------------- aggregate scan

_CHANNELS = {"ntp": _ntp, "dns": _dns, "icmp": _icmp, "timing": _timing, "header": _header}


def scan(source, channels=None) -> dict:
    """Run every covert channel over one source and return {channel: result-or-list}, only the
    channels that recovered something. Normalizes the packets once."""
    pkts = _normalize(source)
    want = channels or list(_CHANNELS)
    out = {}
    for name in want:
        try:
            res = _CHANNELS[name](pkts)
        except Exception as e:                       # a malformed series must not sink the others
            res = None
            out.setdefault("_errors", {})[name] = f"{type(e).__name__}: {e}"
        if res:
            out[name] = res
    return out


# ---------------------------------------------------------------------------- reporting / CLI

def _iter_results(res):
    return res if isinstance(res, list) else [res]


def _to_jsonable(r):
    d = {k: v for k, v in r.items() if k != "candidates"}
    d["candidates"] = r.get("candidates") if isinstance(r.get("candidates"), str) else None
    return d


def report(scanned: dict) -> str:
    lines = []
    for name in _CHANNELS:
        if name not in scanned:
            continue
        for r in _iter_results(scanned[name]):
            lines.append(f"# {r['channel']}:{r['arrangement']}  ({r['key']})")
            if r.get("arrangement") == "qname_sequence":
                lines += _sequence_lines(r)
            for i, v in enumerate(r.get("ranked") or []):
                tag = "flag" if _has_flag(v) else f"#{i + 1}"
                show = v if len(v) <= 160 else v[:157] + "..."
                lines.append(f"    [{tag}] {show}")
            if not r.get("ranked"):
                lines.append("    (no printable reading; raw bytes only)")
    if scanned.get("_errors"):
        for name, err in scanned["_errors"].items():
            lines.append(f"! {name}: {err}")
    if not lines:
        lines.append("no covert channel recovered a reading")
    return "\n".join(lines)


def _sequence_lines(r) -> list:
    """The source host, zone and order of one numbered stream, for a human to check the reassembly."""
    seq = r.get("sequence") or []
    lines = [f"    source {r.get('src') or '?'} -> zone {r.get('zone')}  ({r.get('layout')}, "
             f"{len(seq)} parts numbered {seq[0]}-{seq[-1]})" if seq else f"    source {r.get('src')}"]
    if r.get("missing"):
        lines.append(f"    missing numbers: {r['missing']}")
    if r.get("repeats") or r.get("conflicts"):
        lines.append(f"    repeats dropped: {r.get('repeats', 0)}; other data under a number kept out: "
                     f"{r.get('conflicts') or []}")
    lines.append("    pieces in number order: " + " ".join(r.get("pieces") or []))
    if not any(_has_flag(v) for v in r.get("ranked") or []):
        lines.append("    assembly: no reading is in the event flag format; the brief may say how the payload "
                     "and its source host make the flag")
    return lines


def auto(data) -> dict:
    """The intake read of one capture (--auto): {"dns_messages", "packets", "truncated",
    "dns_dominated", "scanned"}. scanned is {"dns": results} for a DNS-dominated capture
    (dns_dominated) and {} for any other: nothing is read or reported for it. Raises ValueError for
    bytes that are not a capture."""
    cap = network.read(data, limit=AUTO_PACKET_LIMIT)
    pkts = [_from_pkt(p) for p in cap.packets]
    n, total = dns_share(pkts)
    out = {"dns_messages": n, "packets": total, "truncated": bool(cap.truncated),
           "dns_dominated": dns_dominated(pkts), "scanned": {}}
    if out["dns_dominated"]:
        res = _dns(pkts)
        if res:
            out["scanned"] = {"dns": res}
    return out


def _main_auto(args, as_json) -> int:
    """--auto over each capture; exit 1 when one could not be read (named on stderr), else 0."""
    blocks, failed = [], False
    for p in args:
        try:
            got = auto(Path(p).read_bytes())
        except (OSError, ValueError) as e:
            print(f"covert_channels.py: {p}: {e}", file=sys.stderr)
            failed = True
            continue
        n, total, scanned = got["dns_messages"], got["packets"], got["scanned"]
        cut_note = f" (first {AUTO_PACKET_LIMIT} packets only)" if got["truncated"] else ""
        if as_json:
            blk = {"file": p, "dns_messages": n, "packets": total, "truncated": got["truncated"],
                   "dns_dominated": got["dns_dominated"]}
            for name, res in scanned.items():
                blk[name] = [_to_jsonable(r) for r in _iter_results(res)]
            blocks.append(blk)
            continue
        print(f"=== {p} ===")
        if not got["dns_dominated"]:
            print(f"not DNS-dominated: {n} of {total} packets are DNS{cut_note}; nothing reported "
                  "(run without --auto for every channel)")
            continue
        print(f"DNS-dominated: {n} of {total} packets are DNS{cut_note}")
        print(report(scanned))
    if as_json:
        print(json.dumps(blocks, indent=1, ensure_ascii=False))
    return 1 if failed else 0


def main(argv) -> int:
    as_json = "--json" in argv
    if "--auto" in argv:
        args = [a for a in argv if not a.startswith("--")]
        if not args:
            print("usage: covert_channels.py --auto <capture>... [--json]", file=sys.stderr)
            return 2
        return _main_auto(args, as_json)
    channels = None
    args = [a for a in argv if not a.startswith("--")]
    if "--channel" in argv:
        i = argv.index("--channel")
        if i + 1 < len(argv):
            channels = [argv[i + 1]]
            args = [a for a in args if a != argv[i + 1]]
    if not args:
        print("usage: covert_channels.py <capture>... [--json] [--channel ntp|dns|icmp|timing|header]",
              file=sys.stderr)
        print("       offline covert-channel decoder; ranked CANDIDATE readings, never a guess/submit",
              file=sys.stderr)
        return 2
    blocks = []
    for p in args:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"covert_channels.py: {p}: {e}", file=sys.stderr)
            continue
        try:
            scanned = scan(data, channels=channels)
        except ValueError as e:
            print(f"covert_channels.py: {p}: {e}", file=sys.stderr)
            continue
        if as_json:
            blk = {"file": p}
            for name, res in scanned.items():
                if name == "_errors":
                    blk["_errors"] = res
                else:
                    blk[name] = [_to_jsonable(r) for r in _iter_results(res)]
            blocks.append(blk)
        else:
            print(f"=== {p} ===")
            print(report(scanned))
    if as_json:
        print(json.dumps(blocks, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
