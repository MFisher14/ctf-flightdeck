"""net_voip.py -- never-wrong readers for the VoIP protocols that solvers/toolkits/network.py does
not parse: SIP (signalling) and RTP (media). A passive, read-only pcap reader: no network, no
exploitation, nothing is run.

Why this file exists (network pcap readers have ZERO SIP/RTP support): the network toolkit
reassembles TCP streams and parses DNS/HTTP/TLS/FTP/SMTP/NTLM, and net_auth.py adds SMB2/Kerberos/
SNMP/IRC, but neither reads VoIP. SIP method / From / To / Contact / User-Agent / Call-ID and the
digest-authentication fields (realm / nonce / uri / response / username), and RTP payload type /
SSRC / stream reassembly with a G.711 (u-law / a-law) or G.722 PCM-decode duration and sample rate,
are classic network-forensics asks on a pcap lane the opener plays through lane_match.

How it is wired (fail-safe, zero regress by construction): network.py's decide() consults
net_voip.field() ONLY for a question its own _field() and net_auth.field() returned no answer for, so
this file can never change an answer that was already made. If this module is absent, fails to
import, or raises, the hook catches it and network.py behaves exactly as before. It is a library --
it has no signals() / solve_set() of its own and is not a registry toolkit; network.py loads it by
name.

Never-wrong: no network label has ever been judged and every SIP / RTP field rendering is an
author-chosen name, so every value this file offers is an UNSURE labels.pick option list (network.py
turns Found.options into a probed `??` pick), never a plain answer -- so it can never sink an
all-or-nothing batch. The dispatch is strict: a branch claims a question only when the question
names SIP / RTP / VoIP AND the capture actually carries it; otherwise None, and network.py falls
through unchanged. A malformed or partial packet is read as no value (None). Parsers are
bounds-checked and raise nothing to the caller.

PCM facts, NOT a transcription: for a clean G.711 / G.722 RTP stream the duration and the codec
sample rate are derived from the bytes (a byte-count decode cross-checked against the RTP
timestamps); no audio is reconstructed, played or transcribed.
"""
import re
from collections import Counter, OrderedDict

# ---- SIP (UDP/TCP 5060/5061; a CRLF text protocol like HTTP) ---------------------------------------------

SIP_PORTS = {5060, 5061}
SIP_METHODS = ("REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "SUBSCRIBE", "NOTIFY",
               "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE", "PRACK")
# RFC 3261 single-letter compact header forms
_COMPACT = {"f": "from", "t": "to", "m": "contact", "i": "call-id", "v": "via", "c": "content-type",
            "l": "content-length", "s": "subject", "k": "supported", "e": "content-encoding"}
_START_RE = re.compile(
    rb"(?:\A|\n)((?:" + b"|".join(m.encode() for m in SIP_METHODS) + rb")\s+\S+\s+SIP/2\.\d"
    rb"|SIP/2\.\d\s+\d{3}(?:\s|\r))")


def parse_digest(value):
    """The parameters of a Digest Authorization / WWW-Authenticate header value, lower-cased keys,
    or None when the value is not a Digest challenge/credential. Quoted and bare values both."""
    if not value:
        return None
    v = value.strip()
    head = v.split(None, 1)
    if not head or head[0].lower() != "digest":
        return None
    rest = head[1] if len(head) > 1 else ""
    params = {}
    for m in re.finditer(r'([A-Za-z0-9_-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s"]+))', rest):
        key = m.group(1).lower()
        val = (re.sub(r'\\(.)', r'\1', m.group(2)) if m.group(2) is not None
               else (m.group(3) or ""))
        if key not in params:
            params[key] = val
    return params or None


def parse_sip(data):
    """One SIP message at offset 0 of `data` (its header section ends at the first blank line, so a
    trailing SDP body or a following message is ignored). Returns a dict or None when the first line
    is not a SIP request-line or status-line."""
    if not data or len(data) < 12:
        return None
    nl = data.find(b"\n")
    if nl < 0:
        return None
    try:
        first = data[:nl].rstrip(b"\r").decode("ascii")
    except Exception:
        return None
    toks = first.split(" ")
    kind = method = status = None
    if len(toks) >= 3 and toks[0] in SIP_METHODS and toks[-1].startswith("SIP/2."):
        kind, method = "request", toks[0]
    elif len(toks) >= 2 and toks[0].startswith("SIP/2.") and toks[1].isdigit() and len(toks[1]) == 3:
        kind, status = "response", int(toks[1])
    else:
        return None
    text = data.decode("utf-8", "replace")
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in text:
            head = text.split(sep, 1)[0]
            break
    else:
        head = text
    lines = head.replace("\r\n", "\n").split("\n")[1:]
    headers = []
    for ln in lines:
        if ln[:1] in (" ", "\t") and headers:          # an unfolded continuation line
            headers[-1] = (headers[-1][0], headers[-1][1] + " " + ln.strip())
        elif ":" in ln:
            name, val = ln.split(":", 1)
            headers.append((name.strip().lower(), val.strip()))
    hd = OrderedDict()
    for name, val in headers:
        name = _COMPACT.get(name, name)
        hd.setdefault(name, []).append(val)

    def one(n):
        return hd[n][0] if n in hd and hd[n] else None

    rec = {"kind": kind, "method": method, "status": status, "from": one("from"), "to": one("to"),
           "contact": one("contact"), "user_agent": one("user-agent"), "call_id": one("call-id"),
           "cseq": one("cseq"), "authorization": None, "www_authenticate": None}
    for h in ("authorization", "proxy-authorization"):
        if h in hd:
            d = parse_digest(hd[h][0])
            if d:
                rec["authorization"] = d
                break
    for h in ("www-authenticate", "proxy-authenticate"):
        if h in hd:
            d = parse_digest(hd[h][0])
            if d:
                rec["www_authenticate"] = d
                break
    return rec


def _sip_in_stream(data):
    """Every SIP message in one blob (a UDP payload holds one; a reassembled TCP stream may hold
    several concatenated)."""
    out = []
    m = _START_RE.search(data)
    if m is None:
        return out
    pos = m.start(1)
    while pos < len(data):
        # Stream framing counts body octets, including any SIP-looking body lines.
        end = re.search(rb"\r?\n\r?\n", data[pos:])
        if end is None:
            break
        body_start = pos + end.end()
        head = data[pos:body_start]
        try:
            rec = parse_sip(head)
        except Exception:
            rec = None
        if rec is None:
            break
        unfolded = re.sub(rb"\r?\n[ \t]+", b" ", head)
        lengths = []
        for line in unfolded.split(b"\n")[1:]:
            name, sep, value = line.partition(b":")
            if sep and name.strip().lower() in (b"content-length", b"l"):
                lengths.append(value.strip())
        if not lengths:
            # A partial capture can still yield its first header, but without a
            # length there is no safe boundary at which to resume scanning.
            out.append(rec)
            break
        if len(lengths) != 1 or not lengths[0].isdigit():
            break
        length = lengths[0].lstrip(b"0") or b"0"
        if len(length) > len(str(len(data) - body_start)):
            break
        body_length = int(length)
        if body_length > len(data) - body_start:
            break
        out.append(rec)
        pos = body_start + body_length
        # RFC 3261 permits leading CRLFs between stream messages.
        while data[pos:pos + 1] in (b"\r", b"\n"):
            pos += 1
    return out


def sip_messages(cap):
    """[dict] one per SIP message seen, each with src/dst/sport/dport. UDP datagrams on any port
    whose payload parses as SIP, and reassembled TCP streams on 5060/5061 or that parse as SIP."""
    out = []
    for p in cap.packets:
        if p.proto != 17 or not p.payload or p.frag == 2:
            continue
        try:
            rec = parse_sip(p.payload)
        except Exception:
            rec = None
        if rec is not None:
            rec = dict(rec, src=p.src, dst=p.dst, sport=p.sport, dport=p.dport)
            out.append(rec)
    try:
        streams = cap.streams()
    except Exception:
        streams = {}
    for st in streams.values():
        data = st.data or b""
        if not data:
            continue
        on_port = bool({st.sport, st.dport} & SIP_PORTS)
        if not on_port and b"SIP/2." not in data[:512]:
            continue
        for rec in _sip_in_stream(data):
            out.append(dict(rec, src=st.src, dst=st.dst, sport=st.sport, dport=st.dport))
    return out


# ---- RTP (UDP; RFC 3550/3551) ----------------------------------------------------------------------------

RTCP_PT = set(range(72, 77))            # RTCP SR/RR/SDES/BYE/APP, carried as RTP PT 72..76
# static RTP clock rates (RFC 3551, table 4/5); the clock that drives the RTP timestamp
_RTP_CLOCK = {0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000, 10: 44100,
              11: 44100, 12: 8000, 13: 8000, 14: 90000, 15: 8000, 16: 11025, 17: 22050, 18: 8000}
_RTP_NAME = {0: "PCMU", 3: "GSM", 4: "G723", 5: "DVI4", 6: "DVI4", 7: "LPC", 8: "PCMA", 9: "G722",
             10: "L16", 11: "L16", 12: "QCELP", 13: "CN", 14: "MPA", 15: "G728", 18: "G729"}
# payload types this file decodes to PCM facts, and the OUTPUT (decoded) sample rate.  All three are
# 64 kbit/s, so decoded seconds == total payload bytes / 8000 regardless of the output rate.
_CODEC_RATE = {0: 8000, 8: 8000, 9: 16000}


def _rtp_header(payload):
    """(payload_type, seq, timestamp, ssrc, media_offset) for one RTP packet, or None when the
    bytes are not a well-formed RTP header (version != 2, too short, padding/extension/CSRC do not
    fit)."""
    n = len(payload)
    if n < 12 or payload[0] >> 6 != 2:          # version must be 2
        return None
    cc = payload[0] & 0x0F
    pt = payload[1] & 0x7F
    if pt in RTCP_PT:
        return None
    seq = (payload[2] << 8) | payload[3]
    ts = int.from_bytes(payload[4:8], "big")
    ssrc = int.from_bytes(payload[8:12], "big")
    o = 12 + cc * 4
    if o > n:
        return None
    if payload[0] & 0x10:                       # extension header present
        if o + 4 > n:
            return None
        extlen = (payload[o + 2] << 8) | payload[o + 3]
        o += 4 + extlen * 4
        if o > n:
            return None
    pad = 0
    if payload[0] & 0x20:                        # padding: the last byte is the pad length
        if n == 0:
            return None
        pad = payload[-1]
        if pad == 0:
            return None
    media_end = n - pad
    if media_end < o:
        return None
    return pt, seq, ts, ssrc, payload[o:media_end]


def rtp_streams(cap):
    """[dict(ssrc, pt, src, dst, sport, dport, packets, seqs, timestamps, media_lens)] one per RTP
    stream: UDP packets of version 2 grouped by (src, sport, dst, dport, ssrc) with a constant
    payload type. Only groups of 2+ packets are kept (a single 0x80 byte is not an RTP stream)."""
    groups = OrderedDict()
    for p in cap.packets:
        if p.proto != 17 or not p.payload or p.frag == 2:
            continue
        try:
            h = _rtp_header(p.payload)
        except Exception:
            h = None
        if h is None:
            continue
        pt, seq, ts, ssrc, media = h
        key = (p.src, p.sport, p.dst, p.dport, ssrc)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"ssrc": ssrc, "src": p.src, "dst": p.dst, "sport": p.sport,
                               "dport": p.dport, "pts": [], "seqs": [], "timestamps": [], "media_lens": []}
        g["pts"].append(pt)
        g["seqs"].append(seq)
        g["timestamps"].append(ts)
        g["media_lens"].append(len(media))
    out = []
    for g in groups.values():
        if len(g["seqs"]) < 2:
            continue
        ptc = Counter(g["pts"])
        if len(ptc) != 1:                   # a constant payload type within a stream, or it is not one
            continue
        pt = next(iter(ptc))
        out.append({"ssrc": g["ssrc"], "pt": pt, "src": g["src"], "dst": g["dst"], "sport": g["sport"],
                    "dport": g["dport"], "packets": len(g["seqs"]), "seqs": g["seqs"],
                    "timestamps": g["timestamps"], "media_lens": g["media_lens"]})
    return out


def rtp_duration(stream):
    """The decoded-PCM duration in seconds of a clean G.711 / G.722 stream, cross-checked between a
    byte count and the RTP timestamps, or None when the payload type is not decoded here, the stream
    lost a packet, or the two readings disagree (so the duration is not unambiguous)."""
    pt = stream["pt"]
    if pt not in _CODEC_RATE:
        return None
    pairs = sorted(zip(stream["seqs"], stream["media_lens"], stream["timestamps"]))
    if not pairs:
        return None
    seqs = [s for s, _, _ in pairs]
    # sequence numbers must be contiguous (allowing one 16-bit wrap): a gap means a lost packet, so a
    # byte count would understate the real duration -- not never-wrong.
    gaps = [i for i in range(1, len(seqs)) if seqs[i] - seqs[i - 1] != 1]
    if gaps:
        if (len(gaps) != 1 or ((seqs[0] - seqs[-1]) & 0xFFFF) != 1
                or seqs[gaps[0]] == seqs[gaps[0] - 1]):
            return None
        split = gaps[0]
        pairs = pairs[split:] + pairs[:split]
    byte_total = sum(ml for _, ml, _ in pairs)
    first_ts, last_ts = pairs[0][2], pairs[-1][2]
    span = (last_ts - first_ts) & 0xFFFFFFFF
    ts_total = span + pairs[-1][1]          # + the samples of the last packet (G.711/G.722: 1 byte = 1 tick)
    if byte_total <= 0 or byte_total != ts_total:
        return None
    return byte_total / 8000.0              # 64 kbit/s: decoded seconds = bytes / 8000 for PCMU/PCMA/G722


# ---- cache -----------------------------------------------------------------------------------------------

_CACHE = OrderedDict()


def _facts(cap):
    key = (id(cap), getattr(cap, "sha256", None), getattr(cap, "size", None))
    hit = _CACHE.get(key)
    if hit is None:
        hit = _CACHE[key] = {"sip": sip_messages(cap), "rtp": rtp_streams(cap)}
        while len(_CACHE) > 8:
            _CACHE.popitem(last=False)
    return hit


# ---- renderings ------------------------------------------------------------------------------------------

def _addr_formats(raw):
    """Renderings of ONE SIP address header: the raw value, its sip(s) URI, the user@host and the
    user part (as http_url offers url / uri / path -- projections of one value)."""
    raw = (raw or "").strip()
    opts = [("raw", raw)]
    m = re.search(r"<([^>]+)>", raw) or re.search(r"(sips?:[^\s;>]+)", raw)
    uri = m.group(1) if m else None
    if uri:
        opts.append(("uri", uri))
        m2 = re.match(r"sips?:(.+)$", uri)
        addr = m2.group(1) if m2 else uri
        if addr != uri:
            opts.append(("addr", addr))
        if "@" in addr:
            opts.append(("user", addr.split("@", 1)[0]))
    seen, out = set(), []
    for n, v in opts:
        if v and v not in seen:
            seen.add(v)
            out.append((n, v))
    return out


def _ssrc_formats(s):
    return [("hex0x_lower", f"0x{s:08x}"), ("hex0x_upper", f"0x{s:08X}"), ("hex_lower", f"{s:08x}"),
            ("hex_upper", f"{s:08X}"), ("decimal", str(s))]


def _duration_formats(d):
    return [("seconds_3dp", f"{d:.3f}"), ("seconds_2dp", f"{d:.2f}"), ("seconds_1dp", f"{d:.1f}"),
            ("milliseconds_int", str(round(d * 1000))), ("seconds_round", str(round(d)))]


def _pt_formats(pt):
    opts = [("number", str(pt))]
    if pt in _RTP_NAME:
        opts.append(("codec", _RTP_NAME[pt]))
    return opts


def _rate_formats(hz):
    opts = [("hz_int", str(hz)), ("hz_unit", f"{hz} Hz")]
    if hz % 1000 == 0:
        opts.append(("khz", f"{hz // 1000} kHz"))
    return opts


# ---- the dispatcher network.py calls ---------------------------------------------------------------------

def field(Q, cap, Found, choose):
    """Return a Found for a SIP or RTP question, or None when the question is not one of these
    (network.py then falls through exactly as before). Reached ONLY for a question network.py's own
    _field and net_auth.field returned no answer for, so it never changes an existing answer. Every
    value is offered as an unsure option list; nothing here is ever plain."""
    f = _facts(cap)

    # -- SIP ---------------------------------------------------------------------------------------
    if Q.has(r"\bsip\b|\bvoip\b|\bsession initiation protocol\b"):
        sip = f["sip"]
        if not sip:
            return None
        reqs = [m for m in sip if m["kind"] == "request"]
        auths = [m["authorization"] for m in sip if m["authorization"]]
        chals = [m["www_authenticate"] for m in sip if m["www_authenticate"]]
        digests = auths + chals

        # digest-authentication fields first (most specific words)
        if Q.asks(r"\bresponse\b") and (Q.asks(r"\bdigest\b|\bauth\w*\b|\bhash\b") or auths):
            return choose(Q, [a.get("response") for a in auths if a.get("response")], "sip_auth_response", "sip")
        if Q.asks(r"\bnonce\b"):
            return choose(Q, [d.get("nonce") for d in digests if d.get("nonce")], "sip_auth_nonce", "sip")
        if Q.asks(r"\brealm\b"):
            return choose(Q, [d.get("realm") for d in digests if d.get("realm")], "sip_auth_realm", "sip")
        if (Q.asks(r"\buri\b") and Q.asks(r"\bdigest\b|\bauthoriz\w*\b|\bcredential\b")
                and not Q.asks(r"\bcontact\b|\brequest[- ]?uri\b")):
            return choose(Q, [a.get("uri") for a in auths if a.get("uri")], "sip_auth_uri", "sip")
        if Q.asks(r"\balgorithm\b") and (Q.asks(r"\bdigest\b|\bauth\w*\b") or auths):
            return choose(Q, [a.get("algorithm") for a in digests if a.get("algorithm")], "sip_auth_algorithm", "sip")
        if Q.asks(r"\bmethod\b|\brequest type\b|\brequest line\b|\bwhich (?:sip )?(?:request|method)\b"):
            return choose(Q, [m["method"] for m in reqs if m["method"]], "sip_method", "sip")
        if Q.asks(r"\bcall[- ]?id\b"):
            return choose(Q, [m["call_id"] for m in sip if m["call_id"]], "sip_call_id", "sip")
        if Q.asks(r"\buser[- ]?agent\b"):
            return choose(Q, [m["user_agent"] for m in sip if m["user_agent"]], "sip_user_agent", "sip")
        if Q.asks(r"\bcontact\b"):
            return choose(Q, [m["contact"] for m in sip if m["contact"]], "sip_contact", "sip",
                          formats=_addr_formats)
        # digest username, before a bare From-user ask
        if Q.asks(r"\buser(?: ?name)?\b|\baccount\b|\bauthenticat\w*\b") and (Q.asks(r"\bdigest\b|\bauth\w*\b|\bcredential|\bregist\w*\b") or auths):
            vals = [a.get("username") for a in auths if a.get("username")]
            if vals:
                return choose(Q, vals, "sip_auth_username", "sip")
        if Q.asks(r"\bto (?:header|uri|field|address|user|number)\b|\bcallee\b|\bcalled (?:party|number)\b|\brecipient\b"):
            return choose(Q, [m["to"] for m in sip if m["to"]], "sip_to", "sip", formats=_addr_formats)
        if Q.asks(r"\bfrom (?:header|uri|field|address|user|number)\b|\bcaller\b|\bcalling (?:party|number)\b|\bfrom\b"):
            return choose(Q, [m["from"] for m in sip if m["from"]], "sip_from", "sip", formats=_addr_formats)
        return None

    # -- RTP ---------------------------------------------------------------------------------------
    if Q.has(r"\brtp\b|\breal[- ]?time (?:transport )?protocol\b") or (Q.has(r"\bssrc\b") and f["rtp"]):
        streams = f["rtp"]
        if not streams:
            return None
        sel = Q.filter(streams) if (Q.ips or Q.ports) else streams

        if Q.asks(r"\bssrc\b|\bsynchron\w* source\b"):
            if Q.sel == "count":
                return choose(Q, [s["ssrc"] for s in sel], "rtp_ssrc", "rtp")
            return choose(Q, [s["ssrc"] for s in sel], "rtp_ssrc", "rtp", formats=_ssrc_formats)
        if Q.asks(r"\bpayload type\b|\bpayload-type\b|\bcodec\b|\bencoding\b") or (Q.has(r"\bpt\b") and Q.asks(r"\btype\b")):
            return choose(Q, [s["pt"] for s in sel], "rtp_payload_type", "rtp", formats=_pt_formats)
        if Q.asks(r"\bsample ?rate\b|\bsampling rate\b|\bclock rate\b|\bsamples? per second\b") or Q.has(r"\bhz\b"):
            vals = [_CODEC_RATE[s["pt"]] for s in sel if s["pt"] in _CODEC_RATE]
            return choose(Q, vals, "rtp_sample_rate", "rtp", formats=_rate_formats)
        if Q.asks(r"\bduration\b|\bhow long\b|\blength\b|\bseconds\b"):
            vals = [d for d in (rtp_duration(s) for s in sel) if d is not None]
            return choose(Q, vals, "rtp_duration", "rtp", formats=_duration_formats)
        if Q.asks(r"\bstreams?\b|\bflows?\b|\bcalls?\b|\bconversations?\b|\bchannels?\b") or Q.sel == "count":
            # "how many RTP streams": one value per stream (distinct SSRCs), count by the selector
            return choose(Q, [s["ssrc"] for s in sel], "rtp_ssrc", "rtp")
        return None

    return None
