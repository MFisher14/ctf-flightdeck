"""net_auth.py -- never-wrong readers for the authentication / directory network protocols that
solvers/toolkits/network.py does not parse: SMB2, Kerberos, SNMP and IRC.

Why this file exists (reference-technique-buildlist.md rows 12, 14, 10, 11; forecast-days-25-31.md
section 5): the network toolkit reassembles TCP streams and parses DNS/HTTP/TLS/FTP/SMTP/NTLM, but
has NO reader for the SMB2 session/tree/file metadata + dialect (row 12, HIGH, NOBODY), the Kerberos
identity fields (row 14, med-high, NOBODY), the SNMP community string + varbinds (row 10, med,
NOBODY) or the IRC chat / C2 messages (row 11, med, NOBODY). Those are classic network-forensics
asks on a pcap lane the opener plays through lane_match.

How it is wired (fail-safe, zero regress by construction): network.py's decide() consults
net_auth.field() ONLY for a question its own _field() returned None for, so this file can never
change an answer network.py already made. If this module is absent, fails to import, or raises, the
hook catches it and network.py behaves exactly as before. It is a library -- it has no signals() /
solve_set() of its own and is not a registry toolkit; network.py loads it by name.

Never-wrong: no network label has ever been judged, so every value this file offers is an UNSURE
labels.pick option list (network.py's decide() turns Found.options into a probed `??` pick), never a
plain answer -- so it can never sink a batch. The dispatch is strict: a branch claims a question
only when the question names its protocol AND the capture actually carries it; otherwise None, and
network.py falls through unchanged. Parsers are bounds-checked and raise nothing to the caller.

Deliberately left as a None gap (too author-chosen / fragile to be never-wrong): the hashcat
AS-REP / TGS-REP hash string ($krb5asrep$ / $krb5tgs$ ...). Its exact rendering (etype tag, the
checksum/cipher split, the field separators) is an unjudged author choice and the cipher-part byte
offsets are brittle; net_auth surfaces the Kerberos etype and message type instead, and leaves the
full crack string to the lane agent.
"""
import hashlib
from collections import OrderedDict

# ---- generic DER / BER TLV -------------------------------------------------------------------------------


def _tlv(data, o, end):
    """One definite-length ASN.1 TLV at offset o, within [o, end).
    Returns (tag, value_start, value_end, next_offset) or None when it does not fit."""
    if o < 0 or o + 2 > end:
        return None
    tag = data[o]
    p = o + 1
    first = data[p]
    p += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or p + n > end:      # indefinite / over-long length: not DER we read
            return None
        length = int.from_bytes(data[p:p + n], "big")
        p += n
    else:
        length = first
    vend = p + length
    if vend > end:
        return None
    return tag, p, vend, vend


def _int(data, o, end):
    t = _tlv(data, o, end)
    if not t or t[0] != 0x02:
        return None
    return int.from_bytes(data[t[1]:t[2]], "big", signed=True)


def _oid_str(b):
    """Dotted OID from the contents of an OBJECT IDENTIFIER."""
    if not b or b[-1] & 0x80:
        return None
    parts = []
    val = 0
    for x in b:
        val = (val << 7) | (x & 0x7F)
        if not (x & 0x80):
            try:
                if not parts:
                    first = min(val // 40, 2)
                    parts.extend((str(first), str(val - first * 40)))
                else:
                    parts.append(str(val))
            except ValueError:           # integer-to-decimal conversion resource limit
                return None
            val = 0
    return ".".join(parts)


def _printable(b):
    return bool(b) and all(32 <= x < 127 for x in b)


# ---- SNMP (UDP 161/162; BER) -----------------------------------------------------------------------------

SNMP_PORTS = {161, 162}
_SNMP_VER = {0: "v1", 1: "v2c", 3: "v3"}
_SNMP_PDU = {0: "get_request", 1: "get_next_request", 2: "get_response", 3: "set_request",
             4: "trap", 5: "get_bulk_request", 6: "inform_request", 7: "snmpv2_trap", 8: "report"}


def parse_snmp(data):
    """A single SNMP message. {version, community, pdu, oids:[...]} or None.
    v3 messages carry no plaintext community, so only the version is returned for them."""
    n = len(data)
    outer = _tlv(data, 0, n)
    if not outer or outer[0] != 0x30:
        return None
    vo, ve = outer[1], outer[2]
    vt = _tlv(data, vo, ve)
    if not vt or vt[0] != 0x02:
        return None
    ver = int.from_bytes(data[vt[1]:vt[2]], "big")
    if ver not in _SNMP_VER:
        return None
    rec = {"version": _SNMP_VER[ver], "community": None, "pdu": None, "oids": []}
    if ver == 3:
        return rec
    ct = _tlv(data, vt[3], ve)
    if not ct or ct[0] != 0x04:
        return None
    comm = data[ct[1]:ct[2]]
    if not _printable(comm):
        return None                     # a binary "community" is not an SNMP message we trust
    rec["community"] = comm.decode("ascii")
    pt = _tlv(data, ct[3], ve)
    if not pt or not (0xA0 <= pt[0] <= 0xA8):
        return None
    rec["pdu"] = _SNMP_PDU.get(pt[0] - 0xA0)
    # PDU: request-id INT, error-status INT, error-index INT, varbind-list SEQUENCE OF SEQUENCE{OID, value}
    p, pend = pt[1], pt[2]
    for _ in range(3):                   # skip request-id, error-status, error-index (or trap fields)
        it = _tlv(data, p, pend)
        if not it:
            break
        p = it[3]
    while True:
        vb = _tlv(data, p, pend)
        if not vb:
            break
        if vb[0] == 0x30:                # the varbind-list
            q = vb[1]
            while True:
                one = _tlv(data, q, vb[2])
                if not one or one[0] != 0x30:
                    break
                ot = _tlv(data, one[1], one[2])
                if ot and ot[0] == 0x06:
                    oid = _oid_str(data[ot[1]:ot[2]])
                    if oid is None:
                        return None
                    rec["oids"].append(oid)
                q = one[3]
            break
        p = vb[3]
    return rec


def snmp_messages(cap):
    """[dict] one per SNMP datagram (UDP 161/162, both directions)."""
    out = []
    for p in cap.packets:
        if p.proto != 17 or not p.payload:
            continue
        if p.sport not in SNMP_PORTS and p.dport not in SNMP_PORTS:
            continue
        rec = None
        try:
            rec = parse_snmp(p.payload)
        except Exception:
            rec = None
        if rec is not None:
            rec = dict(rec, src=p.src, dst=p.dst)
            out.append(rec)
    return out


# ---- IRC (TCP; a CRLF line protocol) ---------------------------------------------------------------------

IRC_PORTS = {6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697, 7000, 7070}
_IRC_VERBS = ("PASS", "NICK", "USER", "JOIN", "PART", "PRIVMSG", "NOTICE", "MODE", "QUIT",
              "PING", "PONG", "TOPIC", "WHO", "NAMES", "KICK", "OPER", "CAP", "NICKSERV")


def _irc_lines(data):
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return []
    return [ln for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if ln]


def _irc_verb(line):
    toks = line.split(" ")
    i = 1 if toks and toks[0].startswith(":") else 0
    if i >= len(toks):
        return None, toks, i
    return toks[i].upper(), toks, i


def _irc_shaped(lines):
    hits = 0
    for ln in lines:
        v, _, _ = _irc_verb(ln)
        if v in _IRC_VERBS or (v is not None and v.isdigit() and len(v) == 3):
            hits += 1
            if hits >= 2:
                return True
    return False


def irc_sessions(cap):
    """[dict(nicks, channels, messages, realnames, server, client)] one per IRC TCP connection."""
    out = []
    for c in cap.conns():
        on_port = c.cport in IRC_PORTS or c.sport in IRC_PORTS
        cdata = c.c.data if c.c else b""
        sdata = c.s.data if c.s else b""
        clines = _irc_lines(cdata)
        slines = _irc_lines(sdata)
        if not (on_port and (clines or slines)) and not (_irc_shaped(clines) or _irc_shaped(slines)):
            continue
        if not (_irc_shaped(clines) or _irc_shaped(slines) or (on_port and (clines or slines))):
            continue
        nicks, chans, msgs, reals = [], [], [], []
        for ln in clines + slines:
            v, toks, i = _irc_verb(ln)
            if v == "NICK" and i + 1 < len(toks):
                nicks.append(toks[i + 1].lstrip(":"))
            elif v == "USER" and i + 1 < len(toks):
                reals.append(toks[i + 1].lstrip(":"))
            elif v == "JOIN" and i + 1 < len(toks):
                for ch in toks[i + 1].lstrip(":").split(","):
                    if ch:
                        chans.append(ch)
            elif v in ("PRIVMSG", "NOTICE") and i + 2 < len(toks):
                target = toks[i + 1]
                if target.startswith(("#", "&")):
                    chans.append(target)
                body = " ".join(toks[i + 2:])
                if body.startswith(":"):
                    body = body[1:]
                msgs.append((target, body))
        if not (nicks or chans or msgs):
            continue
        out.append({"nicks": nicks, "channels": chans, "messages": msgs, "realnames": reals,
                    "server": c.server, "client": c.client})
    return out


# ---- SMB2 (TCP 445/139; NetBIOS session service framing) -------------------------------------------------

SMB_PORTS = {445, 139}
_SMB2_MAGIC = b"\xfeSMB"
_SMB2_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
_CMD_NEGOTIATE, _CMD_TREE_CONNECT, _CMD_CREATE = 0x0000, 0x0003, 0x0005


def _u16(b, o):
    return b[o] | (b[o + 1] << 8)


def _u32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def _smb2_pdus(stream):
    """Yield (smb_start, body_start) for each SMB2 PDU in one reassembled TCP stream, walking the
    NetBIOS session-service length prefix and each message's NextCommand chain."""
    n = len(stream)
    o = 0
    while o + 4 <= n:
        if stream[o] != 0x00:                       # not a NetBIOS session message
            break
        length = (stream[o + 1] << 16) | (stream[o + 2] << 8) | stream[o + 3]
        msg_start = o + 4
        msg_end = msg_start + length
        if length <= 0 or msg_end > n:
            break
        s = msg_start
        while s + 64 <= msg_end and stream[s:s + 4] == _SMB2_MAGIC:
            yield s, s + 64
            nxt = _u32(stream, s + 20)
            if nxt == 0:
                break
            s += nxt
        o = msg_end


def smb2_facts(cap):
    """{dialect, dialect_hex, shares:[...], files:[...]}: the one negotiated dialect and the tree /
    file names seen across the capture's SMB2 connections. None when no SMB2 traffic is present."""
    dialects, shares, files = [], [], []
    seen = False
    for c in cap.conns():
        if not (c.cport in SMB_PORTS or c.sport in SMB_PORTS):
            continue
        for st in (c.c, c.s):
            if st is None or _SMB2_MAGIC not in (st.data or b""):
                continue
            data = st.data
            for s, body in _smb2_pdus(data):
                seen = True
                cmd = _u16(data, s + 12)
                flags = _u32(data, s + 16)
                is_resp = bool(flags & 0x00000001)
                if cmd == _CMD_NEGOTIATE and is_resp and body + 6 <= len(data):
                    rev = _u16(data, body + 4)
                    if rev in _SMB2_DIALECTS:
                        dialects.append(rev)
                elif cmd == _CMD_TREE_CONNECT and not is_resp and body + 8 <= len(data):
                    poff, plen = _u16(data, body + 4), _u16(data, body + 6)
                    if plen and 0 <= s + poff and s + poff + plen <= len(data):
                        try:
                            shares.append(data[s + poff:s + poff + plen].decode("utf-16-le"))
                        except Exception:
                            pass
                elif cmd == _CMD_CREATE and not is_resp and body + 48 <= len(data):
                    noff, nlen = _u16(data, body + 44), _u16(data, body + 46)
                    if nlen and s + noff + nlen <= len(data):
                        try:
                            files.append(data[s + noff:s + noff + nlen].decode("utf-16-le"))
                        except Exception:
                            pass
    if not seen:
        return None
    dmap = {}
    for rev in dialects:
        dmap.setdefault(rev, 0)
        dmap[rev] += 1
    dialect = dialect_hex = None
    if len(dmap) == 1:
        rev = next(iter(dmap))
        dialect, dialect_hex = _SMB2_DIALECTS[rev], f"0x{rev:04x}"
    return {"dialect": dialect, "dialect_hex": dialect_hex,
            "shares": list(dict.fromkeys(shares)), "files": list(dict.fromkeys(files))}


# ---- SMB file-transfer reassembly (SMB2 WRITE/READ; simple SMB1 READ_ANDX) -------------------------------
#
# smb2_facts above reads the SMB2 session/tree/file METADATA; this reassembles the file PAYLOAD that
# a client wrote (SMB2 WRITE, cmd 0x0009) or read (SMB2 READ, cmd 0x0008) over the share, keyed by the
# 16-byte SMB2 FileId (the 2-byte SMB1 FID) and concatenated in offset order. Passive: it reads only the
# bytes the capture already holds and derives the file's size, sha256/sha1/md5 and name.
#
# Never-wrong by construction. A transfer is `complete` ONLY when the capture proves it whole: every byte
# of [0, EndOfFile) is present exactly once (chunks contiguous from offset 0, no gap and no overlap), the
# TCP streams that carried the data and the size anchor were sound (no gap, no retransmission conflict),
# and the final size is ANCHORED -- a SMB2 CLOSE response with POSTQUERY_ATTRIB (a write) or a CREATE /
# CLOSE EndOfFile (a read). A transfer short of that proof exposes only its name (unsure) and is never
# hashed or sized. Even a complete transfer's facts are offered by field() as UNSURE labels.pick options
# (no network label has ever been judged), so nothing here can ever reach the judge as a plain answer.

_CMD_WRITE, _CMD_READ, _CMD_CLOSE = 0x0009, 0x0008, 0x0006
_FILEID_SENTINEL = b"\xff" * 16          # SMB2 "related operation" file-id: not a real handle, never guessed
_SMB1_MAGIC = b"\xffSMB"
# SMB1 commands whose parameter block begins with AndXCommand/AndXReserved/AndXOffset
_SMB1_ANDX = {0x2D, 0x2E, 0x2F, 0x73, 0x74, 0x75, 0xA2, 0xA4}
_SMB1_NT_CREATE, _SMB1_READ, _SMB1_WRITE, _SMB1_CLOSE = 0xA2, 0x2E, 0x2F, 0x04


def _u64(b, o):
    return int.from_bytes(b[o:o + 8], "little")


def _basename(path):
    if not path:
        return path
    return path.replace("\\", "/").rsplit("/", 1)[-1] or path


def _smb2_pdu_list(streams):
    """[(is_resp, cmd, message_id, smb_start, body_start, stream_bytes, stream_sound)] for every SMB2
    PDU across the two directions of one connection. is_resp comes from SMB2_FLAGS_SERVER_TO_REDIR, so
    requests and responses are told apart by the header, not by which stream carried them."""
    out = []
    for st in streams:
        data = st.data
        snd = bool(st.sound)
        for s, body in _smb2_pdus(data):
            if s + 32 > len(data):
                continue
            out.append((bool(_u32(data, s + 16) & 0x1), _u16(data, s + 12),
                        _u64(data, s + 24), s, body, data, snd))
    return out


def _smb2_transfers_conn(ci, streams):
    """Reassemble the SMB2 WRITE/READ payloads of one connection into transfer records."""
    pdus = _smb2_pdu_list(streams)
    names, create_eof, close_eof, eof_sound = {}, {}, {}, {}
    create_mid, read_mid, close_mid = {}, {}, {}
    chunks = {}

    def ch(fid, direction):
        return chunks.setdefault(fid, {"write": [], "read": []})[direction]

    for is_resp, cmd, mid, s, body, data, snd in pdus:          # pass 1: requests
        if is_resp:
            continue
        n = len(data)
        if cmd == _CMD_CREATE and body + 48 <= n:
            noff, nlen = _u16(data, body + 44), _u16(data, body + 46)
            if nlen and 0 <= s + noff and s + noff + nlen <= n:
                try:
                    nm = data[s + noff:s + noff + nlen].decode("utf-16-le")
                except Exception:
                    nm = None
                if nm:
                    create_mid[mid] = nm
        elif cmd == _CMD_WRITE and body + 32 <= n:
            doff, length = _u16(data, body + 2), _u32(data, body + 4)
            offset, fid = _u64(data, body + 8), bytes(data[body + 16:body + 32])
            if fid != _FILEID_SENTINEL and length and s + doff >= s + 64 and s + doff + length <= n:
                ch(fid, "write").append((offset, bytes(data[s + doff:s + doff + length]), snd))
        elif cmd == _CMD_READ and body + 32 <= n:
            length, offset = _u32(data, body + 4), _u64(data, body + 8)
            fid = bytes(data[body + 16:body + 32])
            if fid != _FILEID_SENTINEL:
                read_mid[mid] = (fid, offset)
        elif cmd == _CMD_CLOSE and body + 24 <= n:
            fid = bytes(data[body + 8:body + 24])
            if fid != _FILEID_SENTINEL:
                close_mid[mid] = fid

    for is_resp, cmd, mid, s, body, data, snd in pdus:          # pass 2: responses
        if not is_resp:
            continue
        n = len(data)
        if cmd == _CMD_CREATE and body + 80 <= n and _u16(data, body) == 89:
            fid = bytes(data[body + 64:body + 80])
            if mid in create_mid:
                names[fid] = create_mid[mid]
            if fid not in create_eof:
                create_eof[fid] = _u64(data, body + 48)
                eof_sound.setdefault(fid, snd)
        elif cmd == _CMD_READ and body + 8 <= n and _u16(data, body) == 17:
            doff, dlen = data[body + 2], _u32(data, body + 4)
            rm = read_mid.get(mid)
            if rm and dlen and s + doff >= s + 64 and s + doff + dlen <= n:
                fid, offset = rm
                ch(fid, "read").append((offset, bytes(data[s + doff:s + doff + dlen]), snd))
        elif cmd == _CMD_CLOSE and body + 56 <= n and _u16(data, body) == 60:
            if _u16(data, body + 2) & 0x0001:            # POSTQUERY_ATTRIB: the size fields are valid
                fid = close_mid.get(mid)
                if fid is not None:
                    close_eof[fid] = _u64(data, body + 48)
                    eof_sound[fid] = snd

    out = []
    for fid, dirs in chunks.items():
        for direction, items in (("write", dirs["write"]), ("read", dirs["read"])):
            if not items:
                continue
            anchor = close_eof.get(fid) if direction == "write" else (
                close_eof.get(fid) if fid in close_eof else create_eof.get(fid))
            out.append(_assemble(ci, direction, items, names.get(fid), anchor, eof_sound.get(fid, True), "smb2"))
    return out


def _smb1_messages(stream):
    """Yield (msg_start, msg_end) for each SMB1 message (one per NetBIOS session message)."""
    n = len(stream)
    o = 0
    while o + 4 <= n:
        if stream[o] != 0x00:
            break
        length = (stream[o + 1] << 16) | (stream[o + 2] << 8) | stream[o + 3]
        msg_start, msg_end = o + 4, o + 4 + length
        if length <= 0 or msg_end > n:
            break
        if stream[msg_start:msg_start + 4] == _SMB1_MAGIC and msg_start + 33 <= n:
            yield msg_start, msg_end
        o = msg_end


def _smb1_commands(data, s, msg_end):
    """Yield (cmd, params_offset, wordcount, bytes_offset, bytecount) for each command in the message's
    AndX chain. The AndX offsets are followed, bounded; a data offset inside a command is absolute from
    the SMB header start, so a command is read without following the chain."""
    end = min(msg_end, len(data))
    cmd = data[s + 4]
    off = s + 32                                      # the WordCount byte of the primary command
    for _ in range(16):
        if off < s + 32 or off + 1 > end:
            break
        wc = data[off]
        poff, pend = off + 1, off + 1 + wc * 2
        if pend + 2 > end:
            break
        bc = data[pend] | (data[pend + 1] << 8)
        yield cmd, poff, wc, pend + 2, bc
        if cmd in _SMB1_ANDX and wc >= 2:
            andx_cmd, andx_off = data[poff], data[poff + 2] | (data[poff + 3] << 8)
            if andx_cmd == 0xFF or andx_off == 0 or s + andx_off <= off:
                break
            cmd, off = andx_cmd, s + andx_off
        else:
            break


def _smb1_name(data, boff, bc, namelen, unicode):
    """The NT_CREATE_ANDX request's file name out of its byte block."""
    region = bytes(data[boff:boff + bc])
    if namelen <= 0 or namelen > len(region):
        return None
    if unicode:
        start = 1 if (len(region) > namelen and region[0] == 0 and namelen % 2 == 0) else 0
        raw = region[start:start + namelen]
        try:
            nm = raw.decode("utf-16-le")
        except Exception:
            return None
    else:
        try:
            nm = region[:namelen].decode("latin-1")
        except Exception:
            return None
    nm = nm.split("\x00", 1)[0]
    return nm or None


def _smb1_transfers_conn(ci, streams):
    """Reassemble simple SMB1 READ_ANDX downloads (and record WRITE_ANDX uploads as name-only, SMB1
    carries no post-write size anchor) of one connection."""
    names, create_eof, eof_sound = {}, {}, {}
    create_mid, read_mid = {}, {}
    chunks = {}

    def ch(key, direction):
        return chunks.setdefault(key, {"write": [], "read": []})[direction]

    pdus = []
    for st in streams:
        data, snd = st.data, bool(st.sound)
        for s, msg_end in _smb1_messages(data):
            is_resp = bool(data[s + 9] & 0x80)
            unicode = bool((data[s + 10] | (data[s + 11] << 8)) & 0x8000)
            tid, mid = data[s + 24] | (data[s + 25] << 8), data[s + 30] | (data[s + 31] << 8)
            pdus.append((is_resp, unicode, tid, mid, s, msg_end, data, snd))

    for is_resp, unicode, tid, mid, s, msg_end, data, snd in pdus:
        if is_resp:
            continue
        for cmd, poff, wc, boff, bc in _smb1_commands(data, s, msg_end):
            n = len(data)
            if cmd == _SMB1_NT_CREATE and wc >= 24 and poff + 7 <= n:
                nm = _smb1_name(data, boff, bc, _u16(data, poff + 5), unicode)
                if nm:
                    create_mid[mid] = nm
            elif cmd == _SMB1_READ and wc >= 10 and poff + 10 <= n:
                fid = _u16(data, poff + 4)
                offv = _u32(data, poff + 6) | ((_u32(data, poff + 20) << 32) if wc >= 12 and poff + 24 <= n else 0)
                read_mid[mid] = ((tid, fid), offv)
            elif cmd == _SMB1_WRITE and wc >= 12 and poff + 24 <= n:
                fid = _u16(data, poff + 4)
                offv = _u32(data, poff + 6) | ((_u32(data, poff + 24) << 32) if wc >= 14 and poff + 28 <= n else 0)
                length = _u16(data, poff + 20) | (_u16(data, poff + 18) << 16)
                doff = _u16(data, poff + 22)
                if length and s + doff >= s + 32 and s + doff + length <= n:
                    ch((tid, fid), "write").append((offv, bytes(data[s + doff:s + doff + length]), snd))

    for is_resp, unicode, tid, mid, s, msg_end, data, snd in pdus:
        if not is_resp:
            continue
        for cmd, poff, wc, boff, bc in _smb1_commands(data, s, msg_end):
            n = len(data)
            if cmd == _SMB1_NT_CREATE and wc >= 34 and poff + 63 <= n:
                key = (tid, _u16(data, poff + 5))
                if mid in create_mid:
                    names[key] = create_mid[mid]
                create_eof[key] = _u64(data, poff + 55)
                eof_sound.setdefault(key, snd)
            elif cmd == _SMB1_READ and wc >= 12 and poff + 16 <= n:
                dlen = _u16(data, poff + 10) | (_u16(data, poff + 14) << 16)
                doff = _u16(data, poff + 12)
                rm = read_mid.get(mid)
                if rm and dlen and s + doff >= s + 32 and s + doff + dlen <= n:
                    key, offset = rm
                    ch(key, "read").append((offset, bytes(data[s + doff:s + doff + dlen]), snd))

    out = []
    for key, dirs in chunks.items():
        for direction, items in (("write", dirs["write"]), ("read", dirs["read"])):
            if not items:
                continue
            anchor = create_eof.get(key) if direction == "read" else None     # SMB1 has no post-write size
            out.append(_assemble(ci, direction, items, names.get(key), anchor, eof_sound.get(key, True), "smb1"))
    return out


def _assemble(ci, direction, items, name, anchor, anchor_sound, proto):
    """One transfer record. `complete` iff the chunks cover [0, anchor) exactly once over sound streams."""
    all_sound = anchor_sound and all(snd for _, _, snd in items)
    pos, buf, contiguous = 0, bytearray(), True
    for off, b, _ in sorted(items, key=lambda x: (x[0], len(x[1]))):
        if off != pos:                     # a gap (off > pos) or an overlap (off < pos): not whole
            contiguous = False
            break
        buf += b
        pos += len(b)
    complete = bool(contiguous and all_sound and isinstance(anchor, int) and anchor > 0 and pos == anchor)
    data = bytes(buf) if complete else None
    return {
        "conn": ci, "proto": proto, "direction": direction,
        "name": _basename(name), "path": name,
        "complete": complete,
        "size": len(data) if complete else None,
        "declared_size": anchor if isinstance(anchor, int) else None,
        "bytes_seen": pos if contiguous else None,
        "sha256": hashlib.sha256(data).hexdigest() if complete else None,
        "sha1": hashlib.sha1(data).hexdigest() if complete else None,
        "md5": hashlib.md5(data).hexdigest() if complete else None,
        "data": data,
    }


def smb_transfers(cap):
    """[transfer record] for files written or read over SMB2/SMB1 across the capture's connections, or
    None when the capture carries no SMB2/SMB1 traffic. See the section header for the record shape and
    the completeness proof. Bounds-checked throughout; nothing it offers is ever a plain answer."""
    seen, out = False, []
    for ci, c in enumerate(cap.conns()):
        if not (c.cport in SMB_PORTS or c.sport in SMB_PORTS):
            continue
        streams = [st for st in (c.c, c.s) if st is not None and st.data]
        if any(_SMB2_MAGIC in st.data for st in streams):
            seen = True
            out += _smb2_transfers_conn(ci, streams)
        if any(_SMB1_MAGIC in st.data for st in streams):
            seen = True
            out += _smb1_transfers_conn(ci, streams)
    if not seen:
        return None
    return [t for t in out if t.get("path") or t.get("complete")]


# ---- Kerberos (TCP/UDP 88; DER) --------------------------------------------------------------------------

KRB_PORTS = {88, 464}
# application tags: AS-REQ 10, AS-REP 11, TGS-REQ 12, TGS-REP 13, KRB-ERROR 30
_KRB_APP = {0x6A: "as_req", 0x6B: "as_rep", 0x6C: "tgs_req", 0x6D: "tgs_rep", 0x7E: "krb_error"}
_KRB_ETYPE = {1: "des_cbc_crc", 3: "des_cbc_md5", 17: "aes128_cts_hmac_sha1", 18: "aes256_cts_hmac_sha1",
              23: "rc4_hmac", 24: "rc4_hmac_exp"}


def _der_children(data, vo, ve):
    out, p = [], vo
    while p < ve:
        t = _tlv(data, p, ve)
        if not t:
            break
        out.append(t)
        p = t[3]
    return out


def _ctx(children, num):
    """The one explicitly-tagged [num] child (context-class constructed), or None."""
    want = 0xA0 | num
    for t in children:
        if t[0] == want:
            return t
    return None


def _principal(data, vo, ve):
    """PrincipalName ::= SEQ { [0] name-type INT, [1] name-string SEQ OF GeneralString } -> 'a/b'."""
    seq = _tlv(data, vo, ve)
    if not seq or seq[0] != 0x30:
        return None
    kids = _der_children(data, seq[1], seq[2])
    names = _ctx(kids, 1)
    if not names:
        return None
    inner = _tlv(data, names[1], names[2])
    if not inner or inner[0] != 0x30:
        return None
    parts = []
    for g in _der_children(data, inner[1], inner[2]):
        if g[0] == 0x1B:                      # GeneralString
            parts.append(data[g[1]:g[2]].decode("utf-8", "replace"))
    return "/".join(parts) if parts else None


def _gstr(data, t):
    if not t:
        return None
    inner = _tlv(data, t[1], t[2])
    if inner and inner[0] == 0x1B:
        return data[inner[1]:inner[2]].decode("utf-8", "replace")
    return None


def _etype_of(data, encpart_t):
    """EncryptedData ::= SEQ { [0] etype INT, [1] kvno INT opt, [2] cipher OCTET STRING } -> etype."""
    if not encpart_t:
        return None
    seq = _tlv(data, encpart_t[1], encpart_t[2])
    if not seq or seq[0] != 0x30:
        return None
    et = _ctx(_der_children(data, seq[1], seq[2]), 0)
    if not et:
        return None
    return _int(data, et[1], et[2])


def parse_kerberos(data):
    """One Kerberos message at offset 0. {msg_type, realm, cname, sname, etype} or None."""
    n = len(data)
    t = _tlv(data, 0, n)
    if not t or t[0] not in _KRB_APP:
        return None
    msg = _KRB_APP[t[0]]
    rec = {"msg_type": msg, "realm": None, "cname": None, "sname": None, "etype": None}
    seq = _tlv(data, t[1], t[2])
    if not seq or seq[0] != 0x30:
        return rec
    kids = _der_children(data, seq[1], seq[2])
    if msg in ("as_req", "tgs_req"):
        body = _ctx(kids, 4)
        if body:
            bseq = _tlv(data, body[1], body[2])
            if bseq and bseq[0] == 0x30:
                bk = _der_children(data, bseq[1], bseq[2])
                cn = _ctx(bk, 1)
                if cn:
                    rec["cname"] = _principal(data, cn[1], cn[2])
                rec["realm"] = _gstr(data, _ctx(bk, 2))
                sn = _ctx(bk, 3)
                if sn:
                    rec["sname"] = _principal(data, sn[1], sn[2])
    elif msg in ("as_rep", "tgs_rep"):
        rec["realm"] = _gstr(data, _ctx(kids, 3))
        cn = _ctx(kids, 4)
        if cn:
            rec["cname"] = _principal(data, cn[1], cn[2])
        rec["etype"] = _etype_of(data, _ctx(kids, 6))
    return rec


def kerberos_messages(cap):
    """[dict] one per Kerberos message (UDP datagrams, and TCP streams with the 4-byte length
    prefix), on ports 88/464."""
    out = []
    for p in cap.packets:
        if p.proto != 17 or not p.payload:
            continue
        if p.sport not in KRB_PORTS and p.dport not in KRB_PORTS:
            continue
        try:
            rec = parse_kerberos(p.payload)
        except Exception:
            rec = None
        if rec:
            out.append(dict(rec, src=p.src, dst=p.dst))
    for c in cap.conns():
        if not (c.cport in KRB_PORTS or c.sport in KRB_PORTS):
            continue
        for st in (c.c, c.s):
            if st is None or not st.data:
                continue
            data, o, n = st.data, 0, len(st.data)
            while o + 4 <= n:
                mlen = int.from_bytes(data[o:o + 4], "big")
                if mlen <= 0 or o + 4 + mlen > n:
                    break
                try:
                    rec = parse_kerberos(data[o + 4:o + 4 + mlen])
                except Exception:
                    rec = None
                if rec:
                    out.append(dict(rec, src=st.src, dst=st.dst))
                o += 4 + mlen
    return out


# ---- cache (parsing is cheap but solve_set calls per question) -------------------------------------------

_CACHE = OrderedDict()


def _facts(cap):
    key = (id(cap), getattr(cap, "sha256", None), getattr(cap, "size", None))
    hit = _CACHE.get(key)
    if hit is None:
        hit = _CACHE[key] = {
            "snmp": snmp_messages(cap),
            "irc": irc_sessions(cap),
            "smb2": smb2_facts(cap),
            "smb_files": smb_transfers(cap),
            "kerberos": kerberos_messages(cap),
        }
        while len(_CACHE) > 8:
            _CACHE.popitem(last=False)
    return hit


# ---- the dispatcher network.py calls ---------------------------------------------------------------------

def _found(Found, field, Q, values, choose, method="raw", extra=""):
    return choose(Q, values, field, extra, method=method)


# ---- SMB file-transfer question readers (unsure picks only) ----------------------------------------------

def _smb_algo(Q):
    """The ONE hash algorithm the question names, or None (never guess which one)."""
    t = Q.low + " " + Q.syntax.lower()
    algos = set()
    if Q.asks(r"\bsha-?256\b") or "sha-256" in t or "sha256" in t:
        algos.add("sha256")
    if Q.asks(r"\bsha-?1\b") or "sha-1" in t or "sha1" in t:
        algos.add("sha1")
    if Q.asks(r"\bmd-?5\b") or "md5" in t:
        algos.add("md5")
    return next(iter(algos)) if len(algos) == 1 else None


def _smb_want(Q, xfers):
    """The transfers the question is about: narrowed by a named file and by read/write verbs."""
    ts = [t for t in xfers if (t.get("path") or t.get("complete"))]
    read_v = Q.asks(r"\bdownload|\bread\b|\breads\b|\bretriev|\breceiv|\bpull|\bfetch")
    write_v = Q.asks(r"\bupload|\bwrote\b|\bwritten\b|\bwrite\b|\bwrites\b|\bexfil|\bpush|\bstor|\bsav(?:e|ed|ing)\b")
    if read_v and not write_v:
        ts = [t for t in ts if t["direction"] == "read"]
    elif write_v and not read_v:
        ts = [t for t in ts if t["direction"] == "write"]
    names = list(Q.file_names)
    if names:
        def match(t):
            nm = (t.get("name") or "").lower()
            pth = (t.get("path") or "").lower().replace("\\", "/")
            return nm in names or any(n == nm or n == pth or pth.endswith("/" + n) for n in names)
        ts = [t for t in ts if match(t)]
    return ts


def _smb_hash(Q, xfers, algo, Found):
    want = [t for t in _smb_want(Q, xfers) if t.get("complete") and t.get(algo)]
    fr = Found(field="smb_file_" + algo, shape=Q.shape("smb"), options=[], candidates=[])
    hashes = list(dict.fromkeys(t[algo] for t in want))
    if len(hashes) != 1:
        fr.why = ("no complete SMB file transfer is reassembled for the question" if not hashes
                  else f"{len(hashes)} complete SMB transfers match and the question names none")
        return fr
    fr.options = [(algo + "_lower", hashes[0]), (algo + "_upper", hashes[0].upper())]
    return fr


def _smb_size(Q, xfers, Found):
    want = [t for t in _smb_want(Q, xfers) if t.get("complete") and t.get("size") is not None]
    if not want:
        return None
    sizes = list(dict.fromkeys(t["size"] for t in want))
    fr = Found(field="smb_file_size", shape=Q.shape("smb"), options=[], candidates=[])
    if len(sizes) == 1:
        fr.options = [("bytes", str(sizes[0]))]
    else:
        fr.why = f"{len(sizes)} complete SMB transfers match; the question names none"
    return fr


def _smb_content(Q, xfers, Found):
    want = [t for t in _smb_want(Q, xfers) if t.get("complete") and t.get("data") is not None]
    if not want:
        return None
    datas = list(dict.fromkeys(t["data"] for t in want))
    fr = Found(field="smb_file_content", shape=Q.shape("smb"), options=[], candidates=[])
    if len(datas) != 1:
        fr.why = f"{len(datas)} complete SMB transfers match; the question names none"
        return fr
    d = datas[0]
    if not d or len(d) > 512:
        fr.why = "the reassembled file is empty or larger than a short answer (512 bytes)"
        return fr
    try:
        text = d.decode("utf-8")
    except Exception:
        fr.why = "the reassembled file is not UTF-8 text"
        return fr
    if any(not (32 <= ord(ch) < 127 or ch in "\r\n\t") for ch in text):
        fr.why = "the reassembled file is not printable text"
        return fr
    fr.options = [("text_stripped", text.strip()), ("text", text)]
    return fr


def _smb_name(Q, xfers, Found, choose):
    want = [t for t in _smb_want(Q, xfers) if t.get("path")]
    if not want:
        return None
    distinct = list(dict.fromkeys(t["path"] for t in want))
    if len(distinct) == 1 and Q.sel in ("only", "first", "last", "most"):
        p = distinct[0]
        fr = Found(field="smb_transfer_name", shape=Q.shape("smb"), options=[], candidates=[])
        fr.options = [("basename", _basename(p)), ("path_backslash", p), ("path_slash", p.replace("\\", "/"))]
        return fr
    return choose(Q, [_basename(t["path"]) for t in want], "smb_transfer_name", "smb", method="raw")


def field(Q, cap, Found, choose):
    """Return a Found for an SMB2 / Kerberos / SNMP / IRC question, or None when the question is not
    one of these (network.py then falls through exactly as before). Reached ONLY for a question
    network.py's own _field returned None for, so it never changes an existing answer. Every value
    is offered as an unsure option list; nothing here is ever plain."""
    f = _facts(cap)

    # -- SMB2 --------------------------------------------------------------------------------------
    if Q.has(r"\bsmb\d?\b|\bsmb[ -]?2\b|\bsmb[ -]?3\b|\bserver message block\b"):
        smb = f["smb2"]
        xfers = f["smb_files"] or []
        if smb is None and not xfers:
            return None
        # a file written or read over SMB -- its hash, size, content or name (all unsure, never plain)
        if xfers:
            algo = _smb_algo(Q)
            if algo and Q.asks(r"\bhash\b|\bdigest\b|\bchecksum\b|\bfingerprint\b|\bsha-?\d|\bmd-?5\b"):
                return _smb_hash(Q, xfers, algo, Found)
            if Q.asks(r"\bsize\b|\bbytes?\b|\blength\b|\bhow (?:big|large)\b"):
                r = _smb_size(Q, xfers, Found)
                if r is not None:
                    return r
            if Q.asks(r"\bcontent|\bpayload\b|\bplain-?text\b|\bthe data\b|\bbody\b|\bstring\b|\btext of\b"
                      r"|\bwas written\b|\bwritten to\b|\bflag\b|\bsecret\b") and not Q.asks(r"\bshare\b|\btree\b"):
                r = _smb_content(Q, xfers, Found)
                if r is not None:
                    return r
            if Q.asks(r"\b(?:file|filename|name|path)\b") and Q.asks(
                    r"\bdownload|\bupload|\btransfer|\bexfil|\bretriev|\bwrote\b|\bwritten\b|\bwrite\b"
                    r"|\bread\b|\breads\b|\bcopi|\bcopy\b|\breceiv|\bstor|\bpull|\bpush"):
                r = _smb_name(Q, xfers, Found, choose)
                if r is not None:
                    return r
        if smb is None:
            return None
        if Q.asks(r"\bdialect\b|\bnegotiat|\bprotocol version\b|\bsmb version\b|\bwhich version\b"):
            fr = Found(field="smb2_dialect", shape=Q.shape("smb2"), options=[], candidates=[])
            if smb["dialect"] is None:
                fr.why = "no single SMB2 dialect was negotiated in the capture"
                return fr
            fr.options = [("dialect", smb["dialect"]), ("dialect_full", "SMB " + smb["dialect"]),
                          ("hex", smb["dialect_hex"])]
            return fr
        if Q.asks(r"\bshare\b|\btree\b|\bunc\b|\bconnect(?:ed|ion)?\b|\bmount"):
            return _found(Found, "smb2_share", Q, smb["shares"], choose, extra="smb2")
        if Q.asks(r"\bfile\b|\bfilename\b|\bopen(?:ed)?\b|\bcreate|\bpath\b|\baccess(?:ed)?\b|\brequest(?:ed)?\b"):
            return _found(Found, "smb2_file", Q, smb["files"], choose, extra="smb2")
        return None

    # -- Kerberos ----------------------------------------------------------------------------------
    if Q.has(r"\bkerberos\b|\bkrb5?\b|\bas[ -]?req\b|\bas[ -]?rep\b|\btgs[ -]?req\b|\btgs[ -]?rep\b|\bticket[- ]?granting\b"):
        kr = f["kerberos"]
        if not kr:
            return None
        if Q.asks(r"\brealm\b") or (Q.asks(r"\bdomain\b") and not Q.asks(r"\bdns\b")):
            vals = [r["realm"] for r in kr if r["realm"]]
            return _found(Found, "kerberos_realm", Q, vals, choose, extra="krb")
        if Q.asks(r"\bservice\b|\bspn\b|\bsname\b|\bservice principal\b"):
            vals = [r["sname"] for r in kr if r["sname"]]
            return _found(Found, "kerberos_sname", Q, vals, choose, extra="krb")
        if Q.asks(r"\buser(?:name)?\b|\bprincipal\b|\bclient\b|\baccount\b|\bcname\b|\brequest(?:ed|ing)? (?:a )?ticket\b"):
            vals = [r["cname"] for r in kr if r["cname"]]
            return _found(Found, "kerberos_cname", Q, vals, choose, extra="krb")
        if Q.asks(r"\betype\b|\bencryption type\b|\bencryption algorithm\b|\bcipher\b"):
            vals = [_KRB_ETYPE.get(r["etype"], str(r["etype"])) for r in kr if r["etype"] is not None]
            nums = [str(r["etype"]) for r in kr if r["etype"] is not None]
            fr = _found(Found, "kerberos_etype", Q, vals, choose, extra="krb")
            if fr is not None and nums and len(set(nums)) == 1 and fr.options:
                fr.options.append(("etype_number", nums[0]))
            return fr
        if Q.asks(r"\bmessage type\b|\bmsg[ -]?type\b|\bwhat (?:kind|type) of (?:kerberos )?message\b"):
            vals = list(dict.fromkeys(r["msg_type"] for r in kr))
            return _found(Found, "kerberos_msg_type", Q, vals, choose, extra="krb")
        return None

    # -- SNMP --------------------------------------------------------------------------------------
    if Q.has(r"\bsnmp\b|\bsimple network management\b|\bcommunity string\b"):
        sn = f["snmp"]
        if not sn:
            return None
        if Q.asks(r"\bcommunity\b"):
            vals = [r["community"] for r in sn if r["community"]]
            return _found(Found, "snmp_community", Q, vals, choose, extra="snmp")
        if Q.asks(r"\bversion\b"):
            vals = [r["version"] for r in sn]
            return _found(Found, "snmp_version", Q, vals, choose, extra="snmp")
        if Q.asks(r"\boid\b|\bobject identifier\b|\bvarbind\b"):
            vals = [o for r in sn for o in r["oids"]]
            return _found(Found, "snmp_oid", Q, vals, choose, extra="snmp")
        return None

    # -- IRC ---------------------------------------------------------------------------------------
    if Q.has(r"\birc\b|\binternet relay chat\b") or (Q.has(r"\bchannel\b|\bnick(?:name)?\b") and Q.has(r"\bchat\b|\bc2\b|\bcommand and control\b")):
        irc = f["irc"]
        if not irc:
            return None
        # message first: "what message was sent to the channel" names both, and the fact asked for
        # is the message, not the channel.
        if Q.asks(r"\bmessage\b|\bsaid\b|\bprivmsg\b|\bsent\b|\bwrote\b|\btyped\b|\border(?:ed|s)?\b"):
            vals = [body for s in irc for _, body in s["messages"]]
            return _found(Found, "irc_message", Q, vals, choose, extra="irc")
        if Q.asks(r"\bchannel\b|\bjoin"):
            vals = [ch for s in irc for ch in s["channels"]]
            return _found(Found, "irc_channel", Q, vals, choose, extra="irc")
        if Q.asks(r"\bnick(?:name)?\b|\buser(?:name)?\b|\bhandle\b"):
            vals = [nk for s in irc for nk in s["nicks"]]
            return _found(Found, "irc_nick", Q, vals, choose, extra="irc")
        return None

    return None
