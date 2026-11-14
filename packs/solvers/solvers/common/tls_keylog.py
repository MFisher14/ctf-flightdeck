#!/usr/bin/env python3
"""In-process TCP/TLS record decryption when the session keys ship in the same delivery
(toolkit key `network`, native path). Pure Python, standard library plus the .venv
`cryptography` AEAD primitives when importable (as asn1_reader uses them); a bounded
pure-Python AES-GCM otherwise. Offline, fail-closed, bounded: no Game Master request, no
token, no sandbox, nothing run, nothing fetched. Usable inside solve_set (no docker exec).

  .venv/bin/python solvers/common/tls_keylog.py <pcap/pcapng> [sslkeylog] [more files...]
  .venv/bin/python solvers/common/tls_keylog.py --json <pcap> [keylog...]
  .venv/bin/python solvers/common/tls_keylog.py --attempt <attempt dir>

Why this exists. solvers/toolkits/network.py cheap-gates this module from `solve_set` only when a
TCP ClientHello.random has a matching TLS 1.2/1.3 NSS key-log entry in the same delivery (a member
or pcapng TLSK block). This closes the staple forensics shape "a pcap plus the session keys are in
the bundle -- read the HTTPS." The key log being IN the delivery is what makes the read
DETERMINISTIC and SELF-VALIDATING: an AEAD tag (GCM / Poly1305) or a CBC+HMAC MAC must verify AND
the inner record must parse as well-formed TLS application-data / HTTP before any byte is believed.

Pipeline over a capture:
  1. parse pcap (micro/nano, both byte orders) and pcapng (SHB/IDB/EPB/SPB/old packet block, and
     Decryption Secrets Blocks that carry a TLS key log); Ethernet, raw IPv4/IPv6, Linux SLL,
     null/loop link layers; IPv4/IPv6 + TCP;
  2. bounded in-order TCP stream reassembly, one byte stream per direction of each connection;
  3. collect key material shipped in the SAME delivery: an SSLKEYLOG member (CLIENT_RANDOM,
     CLIENT_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0, SERVER_* lines) or a pcapng DSB;
  4. match each ClientHello.random to its key-log entry; derive keys -- TLS 1.2 PRF key_block from
     the master secret, TLS 1.3 HKDF-Expand-Label traffic-key schedule from the traffic secrets;
  5. decrypt records (AES-128/256-GCM, ChaCha20-Poly1305, CBC+HMAC), each tag/MAC verified;
  6. parse decrypted application-data as HTTP/1.x into cleartext facts: request method/host/path,
     response status, Content-Type, and separate encoded-wire/decoded sha256+size of a COMPLETE
     body. HTTP/2 is detected only; no HPACK/frame reconstruction is claimed. QUIC is not read.

Never-wrong (AGENTS.md, "Uncertain answers"):
  - NO key log present, a tag/MAC that fails to verify, or application-data that does not parse as
    HTTP  =>  None for every id. Never a partial or guessed read.
  - a transferred file's sha256 (lowercase hex, a digest of exact bytes) and size in bytes, when the
    question names that object and it is present once and COMPLETE  =>  PLAIN (triage.py's precedent).
  - method / host / path / status / Content-Type recovered from the bytes  =>  an unsure
    labels.pick/labels.candidates rendering under the `network` key prefix (the author's spelling is
    not judged; an author SELECTION among several requests/headers is a candidate list), never plain.
  - everything else (a tie with no rule, a scan cut by the limit, a question not about the HTTP) => None.

Text is data. A credential, token or flag found in the plaintext is reported in the facts and never
submitted; a flag id is answered None. An instruction in the plaintext changes nothing.
"""
import hashlib
import hmac
import json
import re
import struct
import sys
import zlib
from collections import OrderedDict
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
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
try:
    import labels                      # noqa: E402
except Exception:                      # noqa: BLE001 - usable without the ledger (unsure, never sent)
    labels = None

KEY = "network"
ARROW = " -> "
SENTINEL = "??"

# ---- bounds (fail-closed; nothing here is governed by a clock) -------------------------------------
MAX_PACKETS = 400_000
MAX_CAPTURE = 512 * 1024 * 1024
MAX_RECORD = 16 * 1024 * 1024
MAX_STREAM = 64 * 1024 * 1024          # bytes kept for one direction of one connection
MAX_CONNS = 256
MAX_RECORDS = 200_000                  # TLS records decrypted over the whole capture
MAX_KEYLOG = 64 * 1024 * 1024
MAX_HTTP_MSGS = 20_000
MAX_OPTIONS = 12
MAX_CONTENT_LAYERS = 8
MAX_DECODED_BODY = 64 * 1024 * 1024


# =====================================================================================================
# cryptography primitives: the .venv library when importable, a bounded pure-Python AES-GCM otherwise
# =====================================================================================================

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM, ChaCha20Poly1305 as _ChaChaPoly
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _algs, modes as _modes
    _HAVE_CRYPTO = True
except Exception:                      # noqa: BLE001
    _HAVE_CRYPTO = False


def _aes_gcm_decrypt(key, nonce, ct_and_tag, aad):
    """AES-GCM decrypt; returns the plaintext or raises on a tag mismatch (self-validation)."""
    if _HAVE_CRYPTO:
        return _AESGCM(key).decrypt(nonce, ct_and_tag, aad)        # raises InvalidTag on failure
    return _PyAESGCM(key).decrypt(nonce, ct_and_tag, aad)


def _chacha_poly_decrypt(key, nonce, ct_and_tag, aad):
    if _HAVE_CRYPTO:
        return _ChaChaPoly(key).decrypt(nonce, ct_and_tag, aad)
    raise _NoCipher("ChaCha20-Poly1305 needs the cryptography library (fail-closed)")


def _aes_cbc_decrypt(key, iv, ct):
    if _HAVE_CRYPTO:
        dec = _Cipher(_algs.AES(key), _modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()
    return _py_aes_cbc_decrypt(key, iv, ct)


class _NoCipher(Exception):
    pass


# --- a compact, correct pure-Python AES (encrypt block) + GCM, used only without cryptography --------

_SBOX = []
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _init_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        xf = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xf ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r & 0xFF


class _PyAES:
    def __init__(self, key):
        global _SBOX
        if not _SBOX:
            _SBOX = _init_sbox()
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self._expand(key)

    def _expand(self, key):
        nk = len(key) // 4
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        i = nk
        total = 4 * (self.rounds + 1)
        while i < total:
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
            i += 1
        self.w = w

    def encrypt_block(self, block):
        s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_round_key(s, 0)
        for rnd in range(1, self.rounds):
            self._sub_bytes(s)
            self._shift_rows(s)
            self._mix_columns(s)
            self._add_round_key(s, rnd)
        self._sub_bytes(s)
        self._shift_rows(s)
        self._add_round_key(s, self.rounds)
        return bytes(s[r][c] for c in range(4) for r in range(4))

    def _add_round_key(self, s, rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= self.w[rnd * 4 + c][r]

    def _sub_bytes(self, s):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]

    def _shift_rows(self, s):
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]

    def _mix_columns(self, s):
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        blk = blk + b"\x00" * (16 - len(blk))
        y ^= int.from_bytes(blk, "big")
        y = _gf_mul(y, h)
    return y


def _gf_mul(x, y):
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        if y & 1:
            y = (y >> 1) ^ (0xE1 << 120)
        else:
            y >>= 1
    return z & ((1 << 128) - 1)


class _PyAESGCM:
    def __init__(self, key):
        self.aes = _PyAES(key)

    def decrypt(self, nonce, ct_and_tag, aad):
        if len(ct_and_tag) < 16:
            raise _NoCipher("ciphertext shorter than the GCM tag")
        ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
        h = int.from_bytes(self.aes.encrypt_block(b"\x00" * 16), "big")
        if len(nonce) == 12:
            j0 = nonce + b"\x00\x00\x00\x01"
        else:
            j0 = (_ghash(h, nonce + b"\x00" * ((16 - len(nonce) % 16) % 16)
                         + struct.pack(">QQ", 0, len(nonce) * 8))).to_bytes(16, "big")
        aad = aad or b""
        s = _ghash(h, aad + b"\x00" * ((16 - len(aad) % 16) % 16) + ct + b"\x00" * ((16 - len(ct) % 16) % 16)
                   + struct.pack(">QQ", len(aad) * 8, len(ct) * 8))
        j0i = int.from_bytes(j0, "big")
        exp = (s ^ int.from_bytes(self.aes.encrypt_block(j0i.to_bytes(16, "big")), "big")).to_bytes(16, "big")
        if not hmac.compare_digest(exp, tag):
            raise _NoCipher("GCM tag mismatch")
        out = bytearray()
        ctr = (j0i + 1) & ((1 << 32) - 1) | (j0i & ~((1 << 32) - 1))
        for i in range(0, len(ct), 16):
            ks = self.aes.encrypt_block(ctr.to_bytes(16, "big"))
            chunk = ct[i:i + 16]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            ctr = (ctr & ~((1 << 32) - 1)) | ((ctr + 1) & ((1 << 32) - 1))
        return bytes(out)


def _py_aes_cbc_decrypt(key, iv, ct):
    aes = _PyAES(key)
    # CBC decrypt needs block decryption; derive it from encrypt via the inverse cipher is heavy.
    raise _NoCipher("AES-CBC pure-Python path is not provided; cryptography is required (fail-closed)")


# =====================================================================================================
# capture parsing (pcap and pcapng) -> packets, then IPv4/IPv6 + TCP
# =====================================================================================================

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
              b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINK_ETH, LINK_NULL, LINK_RAW, LINK_LOOP, LINK_SLL, LINK_SLL2, LINK_RAW2, LINK_IPV4, LINK_IPV6 = \
    1, 0, 101, 108, 113, 276, 12, 228, 229
_DSB_TLS_KEYLOG = 0x544C534B           # pcapng Decryption Secrets Block, secrets type "TLSK"


def is_capture(data) -> bool:
    return isinstance(data, (bytes, bytearray)) and (
        bytes(data[:4]) in PCAP_MAGIC
        or (bytes(data[:4]) == PCAPNG_MAGIC and bytes(data[8:12]) in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d")))


class Packet:
    __slots__ = ("linktype", "data")

    def __init__(self, linktype, data):
        self.linktype = linktype
        self.data = data


class Capture:
    """Packets and the pcapng decryption secrets of one capture. Bounded; reads bytes only."""

    def __init__(self, data: bytes):
        self.packets = []
        self.secrets = []           # [(secrets_type, bytes)]
        self.truncated = False
        data = bytes(data)
        if len(data) > MAX_CAPTURE:
            data = data[:MAX_CAPTURE]
            self.truncated = True
        if data[:4] in PCAP_MAGIC:
            self._read_pcap(data)
        elif data[:4] == PCAPNG_MAGIC:
            self._read_pcapng(data)
        else:
            raise ValueError("not a pcap/pcapng")

    def _read_pcap(self, data):
        endian, _ = PCAP_MAGIC[data[:4]]
        if len(data) < 24:
            self.truncated = True
            return
        linktype = struct.unpack(endian + "I", data[20:24])[0]
        i = 24
        n = len(data)
        while i + 16 <= n and len(self.packets) < MAX_PACKETS:
            _, _, caplen, origlen = struct.unpack(endian + "IIII", data[i:i + 16])
            i += 16
            if caplen > MAX_RECORD or i + caplen > n:
                self.truncated = True
                break
            if caplen < origlen:
                self.truncated = True
            self.packets.append(Packet(linktype, data[i:i + caplen]))
            i += caplen
        if i != n or len(self.packets) >= MAX_PACKETS and i < n:
            self.truncated = True

    def _read_pcapng(self, data):
        i = 0
        n = len(data)
        iface_links = []
        default_link = LINK_ETH
        endian = "<"
        while i + 12 <= n and len(self.packets) < MAX_PACKETS:
            btype = struct.unpack(endian + "I", data[i:i + 4])[0]
            if btype == 0x0A0D0D0A:          # Section Header Block: read the byte order
                bom = data[i + 8:i + 12]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    self.truncated = True
                    break
                btype = struct.unpack(endian + "I", data[i:i + 4])[0]
                iface_links = []              # interface ids are scoped to one section
            blen = struct.unpack(endian + "I", data[i + 4:i + 8])[0]
            if blen < 12 or i + blen > n:
                self.truncated = True
                break
            body = data[i:i + blen]
            if struct.unpack(endian + "I", body[-4:])[0] != blen:
                self.truncated = True
                break
            if btype == 0x00000001:          # Interface Description Block
                if blen < 20:
                    self.truncated = True
                    break
                lt = struct.unpack(endian + "H", body[8:10])[0]
                iface_links.append(lt)
            elif btype == 0x00000006:        # Enhanced Packet Block
                if blen < 32:
                    self.truncated = True
                    break
                ifid, _, _, caplen, _ = struct.unpack(endian + "IIIII", body[8:28])
                origlen = struct.unpack(endian + "I", body[24:28])[0]
                lt = iface_links[ifid] if ifid < len(iface_links) else default_link
                if caplen < origlen:
                    self.truncated = True
                if 0 < caplen <= MAX_RECORD and 28 + caplen <= blen - 4:
                    self.packets.append(Packet(lt, body[28:28 + caplen]))
                elif caplen:
                    self.truncated = True
            elif btype == 0x00000003:        # Simple Packet Block
                if blen < 16:
                    self.truncated = True
                    break
                caplen = struct.unpack(endian + "I", body[8:12])[0]
                lt = iface_links[0] if iface_links else default_link
                available = blen - 16
                kept = min(caplen, available)
                if kept < caplen:
                    self.truncated = True
                if 0 < kept <= MAX_RECORD:
                    self.packets.append(Packet(lt, body[12:12 + kept]))
            elif btype == 0x00000002:        # old Packet Block
                if blen < 32:
                    self.truncated = True
                    break
                ifid = struct.unpack(endian + "H", body[8:10])[0]
                caplen = struct.unpack(endian + "I", body[20:24])[0]
                origlen = struct.unpack(endian + "I", body[24:28])[0]
                lt = iface_links[ifid] if ifid < len(iface_links) else default_link
                if caplen < origlen:
                    self.truncated = True
                if 0 < caplen <= MAX_RECORD and 28 + caplen <= blen - 4:
                    self.packets.append(Packet(lt, body[28:28 + caplen]))
                elif caplen:
                    self.truncated = True
            elif btype == 0x0000000A:        # Decryption Secrets Block
                if blen >= 20:
                    stype, slen = struct.unpack(endian + "II", body[8:16])
                    if 16 + slen <= blen - 4:
                        self.secrets.append((stype, body[16:16 + slen]))
                    else:
                        self.truncated = True
            i += blen
        if i != n or len(self.packets) >= MAX_PACKETS and i < n:
            self.truncated = True
        self._endian = endian


def _l3_from_link(pkt: Packet):
    """(ethertype, l3 bytes) from one packet's link layer; (None, None) when unhandled."""
    d = pkt.data
    lt = pkt.linktype
    if lt == LINK_ETH:
        if len(d) < 14:
            return None, None
        et = struct.unpack(">H", d[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and off + 4 <= len(d):      # VLAN tags
            et = struct.unpack(">H", d[off + 2:off + 4])[0]
            off += 4
        return et, d[off:]
    if lt in (LINK_RAW, LINK_RAW2, LINK_IPV4):
        if d[:1] and (d[0] >> 4) == 4:
            return 0x0800, d
        if d[:1] and (d[0] >> 4) == 6:
            return 0x86DD, d
        return None, None
    if lt == LINK_IPV6:
        return 0x86DD, d
    if lt in (LINK_NULL, LINK_LOOP):
        if len(d) < 4:
            return None, None
        fam = struct.unpack("<I", d[:4])[0]
        if fam in (2,):
            return 0x0800, d[4:]
        if fam in (24, 28, 30):
            return 0x86DD, d[4:]
        fam2 = struct.unpack(">I", d[:4])[0]
        if fam2 == 2:
            return 0x0800, d[4:]
        if fam2 in (24, 28, 30):
            return 0x86DD, d[4:]
        return None, None
    if lt == LINK_SLL:
        if len(d) < 16:
            return None, None
        return struct.unpack(">H", d[14:16])[0], d[16:]
    if lt == LINK_SLL2:
        if len(d) < 20:
            return None, None
        return struct.unpack(">H", d[:2])[0], d[20:]
    # unknown link: try to sniff an IP header
    if d[:1] and (d[0] >> 4) == 4:
        return 0x0800, d
    if d[:1] and (d[0] >> 4) == 6:
        return 0x86DD, d
    return None, None


class _Seg:
    __slots__ = ("seq", "payload", "syn")

    def __init__(self, seq, payload, syn):
        self.seq = seq
        self.payload = payload
        self.syn = syn


def _tcp_segments(cap: Capture):
    """{(src,sport,dst,dport): [ _Seg ]} for every TCP segment carrying payload or a SYN."""
    flows = OrderedDict()
    for pkt in cap.packets:
        et, l3 = _l3_from_link(pkt)
        if l3 is None:
            continue
        if et == 0x0800:
            if len(l3) < 20 or (l3[0] >> 4) != 4:
                continue
            ihl = (l3[0] & 0x0F) * 4
            if ihl < 20 or len(l3) < ihl:
                continue
            proto = l3[9]
            total = struct.unpack(">H", l3[2:4])[0]
            if 20 <= total <= len(l3):
                l3 = l3[:total]
            src = ".".join(str(b) for b in l3[12:16])
            dst = ".".join(str(b) for b in l3[16:20])
            l4 = l3[ihl:]
        elif et == 0x86DD:
            if len(l3) < 40 or (l3[0] >> 4) != 6:
                continue
            proto = l3[6]
            payload_len = struct.unpack(">H", l3[4:6])[0]
            src = l3[8:24].hex()
            dst = l3[24:40].hex()
            l4 = l3[40:40 + payload_len] if payload_len else l3[40:]
            # one layer of common extension headers
            hops = 0
            while proto in (0, 43, 44, 60) and len(l4) >= 8 and hops < 8:
                nxt = l4[0]
                ext = (l4[1] + 1) * 8
                l4 = l4[ext:]
                proto = nxt
                hops += 1
        else:
            continue
        if proto != 6 or len(l4) < 20:
            continue
        sport, dport = struct.unpack(">HH", l4[:4])
        seq = struct.unpack(">I", l4[4:8])[0]
        off = (l4[12] >> 4) * 4
        if off < 20 or len(l4) < off:
            continue
        flags = l4[13]
        payload = l4[off:]
        syn = bool(flags & 0x02)
        if not payload and not syn:
            continue
        k = (src, sport, dst, dport)
        flows.setdefault(k, []).append(_Seg(seq, payload, syn))
        if len(flows) > MAX_CONNS * 2:
            break
    return flows


def _reassemble(segs):
    """One direction's exact bytes, or None for a gap/conflicting overlap/resource cut.

    Exact retransmissions are harmless. Missing TCP bytes and two different bytes at one sequence
    position withdraw the connection; retaining a complete-looking prefix could otherwise turn a
    packet-loss/truncated capture into a falsely complete HTTP exchange.
    """
    base = None
    for s in segs:
        if s.syn:
            base = (s.seq + 1) & 0xFFFFFFFF
            break
    data_segs = [s for s in segs if s.payload]
    if not data_segs:
        return b""
    if base is None:
        base = min(s.seq for s in data_segs)
    out = bytearray()
    for s in sorted(data_segs, key=lambda x: ((x.seq - base) & 0xFFFFFFFF)):
        off = (s.seq - base) & 0xFFFFFFFF
        if off > len(out):                       # a sequence gap, including a wrap-looking offset
            return None
        overlap = min(len(s.payload), len(out) - off)
        if overlap and bytes(out[off:off + overlap]) != s.payload[:overlap]:
            return None                          # contradictory retransmission
        tail = s.payload[overlap:]
        if len(out) + len(tail) > MAX_STREAM:
            return None
        out += tail
    return bytes(out)


def _connections(cap: Capture):
    """Pair the two directions of each TCP connection.
    [ {a,b: (ip,port), astream, bstream} ] where astream is a->b bytes."""
    flows = _tcp_segments(cap)
    seen = set()
    conns = []
    for k, segs in flows.items():
        if k in seen:
            continue
        src, sport, dst, dport = k
        rk = (dst, dport, src, sport)
        seen.add(k)
        seen.add(rk)
        fwd = _reassemble(segs)
        rev = _reassemble(flows.get(rk, []))
        if fwd is None or rev is None:
            continue
        conns.append({"a": (src, sport), "b": (dst, dport), "ab": fwd, "ba": rev})
        if len(conns) >= MAX_CONNS:
            break
    return conns


# =====================================================================================================
# TLS record / handshake parsing
# =====================================================================================================

def _tls_records(stream: bytes):
    """Yield (content_type, legacy_version, body_bytes) for each TLS record in a byte stream.
    A malformed/truncated suffix invalidates the WHOLE stream: positions are validated before the
    first record is yielded, so callers can never retain a verified prefix as a partial reading."""
    i = 0
    n = len(stream)
    positions = []
    while i + 5 <= n:
        ctype = stream[i]
        ver = struct.unpack(">H", stream[i + 1:i + 3])[0]
        length = struct.unpack(">H", stream[i + 3:i + 5])[0]
        if ctype not in (20, 21, 22, 23) or ver >> 8 != 0x03 or length > 16384 + 2048:
            return
        if i + 5 + length > n:
            return
        positions.append((ctype, ver, i + 5, i + 5 + length))
        i += 5 + length
        if len(positions) > MAX_RECORDS:
            return
    if i != n:                              # one to four trailing bytes are a truncated header
        return
    for ctype, ver, start, end in positions:
        yield ctype, ver, stream[start:end]


def _handshake_messages(stream: bytes):
    """Yield (hs_type, body) of the cleartext handshake records (type 22) at the start of a stream,
    coalescing records. Stops at the first non-handshake record (e.g. ChangeCipherSpec)."""
    buf = bytearray()
    for ctype, _ver, body in _tls_records(stream):
        if ctype != 22:
            break
        buf += body
    i = 0
    n = len(buf)
    while i + 4 <= n:
        htype = buf[i]
        hlen = int.from_bytes(buf[i + 1:i + 4], "big")
        if i + 4 + hlen > n:
            break
        yield htype, bytes(buf[i + 4:i + 4 + hlen])
        i += 4 + hlen


def _parse_client_hello(body: bytes):
    if len(body) < 2 + 32:
        return None
    return body[2:34]                   # client_random (full 32 bytes)


def _parse_server_hello(body: bytes):
    """(server_random, cipher_suite) from a ServerHello body, or None."""
    if len(body) < 2 + 32 + 1:
        return None
    random = body[2:34]
    i = 34
    sid_len = body[i]
    i += 1 + sid_len
    if i + 2 > len(body):
        return None
    suite = struct.unpack(">H", body[i:i + 2])[0]
    return random, suite


# =====================================================================================================
# cipher-suite table and key schedules
# =====================================================================================================

# suite -> (aead|cbc, key_len, prf_hash_name, [mac_name, mac_len])
_SUITES = {
    # TLS 1.3
    0x1301: ("gcm", 16, "sha256"), 0x1302: ("gcm", 32, "sha384"), 0x1303: ("chacha", 32, "sha256"),
    # TLS 1.2 AES-GCM
    0xC02F: ("gcm", 16, "sha256"), 0xC02B: ("gcm", 16, "sha256"), 0x009C: ("gcm", 16, "sha256"),
    0xC030: ("gcm", 32, "sha384"), 0xC02C: ("gcm", 32, "sha384"), 0x009D: ("gcm", 32, "sha384"),
    # TLS 1.2 ChaCha20-Poly1305
    0xCCA8: ("chacha", 32, "sha256"), 0xCCA9: ("chacha", 32, "sha256"), 0xCCAA: ("chacha", 32, "sha256"),
    # TLS 1.2 AES-CBC + HMAC
    0xC013: ("cbc", 16, "sha256", "sha1", 20), 0xC014: ("cbc", 32, "sha256", "sha1", 20),
    0xC027: ("cbc", 16, "sha256", "sha256", 32), 0xC028: ("cbc", 32, "sha384", "sha384", 48),
    0x002F: ("cbc", 16, "sha256", "sha1", 20), 0x0035: ("cbc", 32, "sha256", "sha1", 20),
    0x003C: ("cbc", 16, "sha256", "sha256", 32), 0x003D: ("cbc", 32, "sha256", "sha256", 32),
}


def _p_hash(secret, seed, length, hashname):
    out = bytearray()
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, hashname).digest()
        out += hmac.new(secret, a + seed, hashname).digest()
    return bytes(out[:length])


def _tls12_key_block(master, client_random, server_random, length, hashname):
    return _p_hash(master, b"key expansion" + server_random + client_random, length, hashname)


def _hkdf_expand(secret, info, length, hashname):
    hlen = hashlib.new(hashname).digest_size
    out = bytearray()
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashname).digest()
        out += t
        i += 1
    return bytes(out[:length])


def _hkdf_expand_label(secret, label, context, length, hashname):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    return _hkdf_expand(secret, info, length, hashname)


# =====================================================================================================
# the decryptor
# =====================================================================================================

_KEYLOG_LABELS = ("CLIENT_RANDOM", "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                  "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
                  "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET")
_KEYLOG_RE = re.compile(
    r"(?m)^(" + "|".join(_KEYLOG_LABELS) + r")[ \t]+([0-9a-fA-F]{16,})[ \t]+([0-9a-fA-F]{16,})[ \t]*$")


def _looks_like_keylog(data) -> bool:
    if not isinstance(data, (bytes, bytearray)) or not (0 < len(data) <= MAX_KEYLOG):
        return False
    try:
        head = bytes(data).decode("latin-1")
    except Exception:                  # noqa: BLE001
        return False
    return _KEYLOG_RE.search(head) is not None


def _parse_keylog_details(data):
    """(entries, conflicting client-randoms) from one NSS key-log byte string."""
    out = {}
    conflicts = set()
    try:
        text = bytes(data).decode("latin-1")
    except Exception:                  # noqa: BLE001
        return out, conflicts
    for m in _KEYLOG_RE.finditer(text):
        label, cr_hex, secret_hex = m.group(1), m.group(2), m.group(3)
        try:
            cr = bytes.fromhex(cr_hex)
            secret = bytes.fromhex(secret_hex)
        except ValueError:
            continue
        if len(cr) != 32:                       # the second NSS column is always ClientHello.random
            continue
        prior = out.setdefault(cr, {}).get(label)
        if prior is not None and prior != secret:
            conflicts.add(cr)                    # two secrets for one epoch: no deterministic read
        else:
            out[cr][label] = secret
    for cr in conflicts:
        out.pop(cr, None)
    return out, conflicts


def parse_keylog(data) -> dict:
    """{ client_random(32 bytes): {label: secret bytes} } from unambiguous NSS key-log text."""
    return _parse_keylog_details(data)[0]


def collect_keylog(files: dict):
    """(keylog dict, source label) from SSLKEYLOG members and pcapng DSBs. Identical duplicates
    merge; conflicting secrets for one client-random/epoch remove that whole session."""
    merged = {}
    conflicts = set()
    sources = []

    def merge(kl, bad, label):
        for cr in bad:
            conflicts.add(cr)
            merged.pop(cr, None)
        if not kl:
            return
        sources.append(label)
        for cr, values in kl.items():
            if cr in conflicts:
                continue
            slot = merged.setdefault(cr, {})
            if any(name in slot and slot[name] != secret for name, secret in values.items()):
                conflicts.add(cr)
                merged.pop(cr, None)
                continue
            slot.update(values)

    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)):
            continue
        if _looks_like_keylog(data):
            kl, bad = _parse_keylog_details(data)
            merge(kl, bad, key.split(ARROW)[-1])
    for key in sorted(files):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or not is_capture(data):
            continue
        try:
            cap = Capture(data)
        except ValueError:
            continue
        for stype, blob in cap.secrets:
            if stype == _DSB_TLS_KEYLOG:
                kl, bad = _parse_keylog_details(blob)
                merge(kl, bad, key.split(ARROW)[-1] + " (pcapng decryption secrets)")
    source = sources[0] if len(sources) == 1 else ("multiple matching key-log sources" if sources else None)
    return merged, source


class _Decryptor:
    """Per-connection TLS decryption with the key material matched by ClientHello.random."""

    def __init__(self, keylog, client_random, server_random, suite):
        self.keylog = keylog.get(client_random, {})
        self.client_random = client_random
        self.server_random = server_random
        self.suite = suite
        self.spec = _SUITES.get(suite)
        self.is_tls13 = ("CLIENT_TRAFFIC_SECRET_0" in self.keylog or "SERVER_TRAFFIC_SECRET_0" in self.keylog)
        self.ok = self.spec is not None and bool(self.keylog)

    # -- TLS 1.2 ------------------------------------------------------------------------------------
    def _tls12_keys(self):
        master = self.keylog.get("CLIENT_RANDOM")
        if not master:
            return None
        kind, klen, prf = self.spec[0], self.spec[1], self.spec[2]
        if kind == "gcm":
            block = _tls12_key_block(master, self.client_random, self.server_random, 2 * klen + 8, prf)
            cwk, swk = block[:klen], block[klen:2 * klen]
            civ, siv = block[2 * klen:2 * klen + 4], block[2 * klen + 4:2 * klen + 8]
            return {"kind": "gcm", "client": (cwk, civ), "server": (swk, siv)}
        if kind == "chacha":
            block = _tls12_key_block(master, self.client_random, self.server_random, 2 * klen + 2 * 12, prf)
            cwk, swk = block[:klen], block[klen:2 * klen]
            civ = block[2 * klen:2 * klen + 12]
            siv = block[2 * klen + 12:2 * klen + 24]
            return {"kind": "chacha", "client": (cwk, civ), "server": (swk, siv)}
        if kind == "cbc":
            mac, maclen = self.spec[3], self.spec[4]
            block = _tls12_key_block(master, self.client_random, self.server_random, 2 * maclen + 2 * klen, prf)
            cmk, smk = block[:maclen], block[maclen:2 * maclen]
            cwk = block[2 * maclen:2 * maclen + klen]
            swk = block[2 * maclen + klen:2 * maclen + 2 * klen]
            return {"kind": "cbc", "mac": mac, "maclen": maclen,
                    "client": (cwk, cmk), "server": (swk, smk)}
        return None

    def decrypt_stream_tls12(self, stream, from_client):
        keys = self._tls12_keys()
        if not keys:
            return None
        plains = []
        encrypted = False
        seq = 0
        for ctype, ver, body in _tls_records(stream):
            if ctype == 20:                     # ChangeCipherSpec: the next records are encrypted
                if encrypted:
                    return None                  # a second clear CCS would make the epoch ambiguous
                encrypted = True
                seq = 0
                continue
            if not encrypted:
                continue
            cur = seq
            seq += 1
            try:
                pt = self._tls12_record(keys, body, cur, ctype, ver, from_client)
            except Exception:                   # noqa: BLE001 - a verify failure is a non-answer
                pt = None
            if pt is None:
                return None                     # never concatenate around a failed encrypted record
            if ctype == 23:
                plains.append(pt)
            if sum(len(p) for p in plains) > MAX_STREAM:
                return None
        return b"".join(plains) if plains else None

    def _tls12_record(self, keys, body, seq, ctype, ver, from_client):
        wk, extra = keys["client"] if from_client else keys["server"]
        if keys["kind"] == "gcm":
            if len(body) < 8 + 16:
                return None
            explicit, ct = body[:8], body[8:]
            nonce = extra + explicit
            plen = len(ct) - 16
            aad = struct.pack(">Q", seq) + bytes([ctype]) + struct.pack(">H", ver) + struct.pack(">H", plen)
            return _aes_gcm_decrypt(wk, nonce, ct, aad)
        if keys["kind"] == "chacha":
            if len(body) < 16:
                return None
            nonce = bytes(a ^ b for a, b in zip(extra, b"\x00\x00\x00\x00" + struct.pack(">Q", seq)))
            plen = len(body) - 16
            aad = struct.pack(">Q", seq) + bytes([ctype]) + struct.pack(">H", ver) + struct.pack(">H", plen)
            return _chacha_poly_decrypt(wk, nonce, body, aad)
        if keys["kind"] == "cbc":
            return self._tls12_cbc(keys, wk, extra, body, seq, ctype, ver, from_client)
        return None

    def _tls12_cbc(self, keys, wk, mk, body, seq, ctype, ver, from_client):
        bs = 16
        maclen = keys["maclen"]
        if len(body) < bs + maclen + 1 or len(body) % bs:
            return None
        iv, ct = body[:bs], body[bs:]
        try:
            dec = _aes_cbc_decrypt(wk, iv, ct)
        except _NoCipher:
            return None
        pad = dec[-1]
        if pad + 1 > len(dec):
            return None
        if any(b != pad for b in dec[-(pad + 1):]):
            return None
        content = dec[:-(pad + 1)]
        if len(content) < maclen:
            return None
        plain, mac = content[:-maclen], content[-maclen:]
        aad = struct.pack(">Q", seq) + bytes([ctype]) + struct.pack(">H", ver) + struct.pack(">H", len(plain))
        exp = hmac.new(mk, aad + plain, keys["mac"]).digest()
        if not hmac.compare_digest(exp, mac):       # MAC verify = self-validation
            return None
        return plain

    # -- TLS 1.3 ------------------------------------------------------------------------------------
    def _tls13_traffic_keys(self, secret):
        kind, klen, prf = self.spec[0], self.spec[1], self.spec[2]
        key = _hkdf_expand_label(secret, b"key", b"", klen, prf)
        iv = _hkdf_expand_label(secret, b"iv", b"", 12, prf)
        return kind, key, iv

    def decrypt_stream_tls13(self, stream, from_client):
        app = self.keylog.get("CLIENT_TRAFFIC_SECRET_0" if from_client else "SERVER_TRAFFIC_SECRET_0")
        hs = self.keylog.get("CLIENT_HANDSHAKE_TRAFFIC_SECRET" if from_client else "SERVER_HANDSHAKE_TRAFFIC_SECRET")
        app_keys = self._tls13_traffic_keys(app) if app else None
        hs_keys = self._tls13_traffic_keys(hs) if hs else None
        app_seq = hs_seq = 0
        app_plains = []
        for ctype, _ver, body in _tls_records(stream):
            if ctype != 23:                     # cleartext handshake / middlebox CCS: skip
                continue
            done = False
            if app_keys is not None:
                inner = self._tls13_record(app_keys, body, app_seq)
                if inner is not None:
                    app_seq += 1
                    itype, payload = inner
                    if itype == 23:
                        app_plains.append(payload)
                    done = True
            if not done and hs_keys is not None:
                inner = self._tls13_record(hs_keys, body, hs_seq)
                if inner is not None:
                    hs_seq += 1
                    done = True
            if not done:
                return None                     # wrong key, corrupt record, or unsupported epoch
            if sum(len(p) for p in app_plains) > MAX_STREAM:
                return None
        return b"".join(app_plains) if app_plains else None

    def _tls13_record(self, keys, body, seq):
        kind, key, iv = keys
        if len(body) < 16:
            return None
        nonce = bytes(a ^ b for a, b in zip(iv, b"\x00\x00\x00\x00" + struct.pack(">Q", seq)))
        aad = bytes([23]) + b"\x03\x03" + struct.pack(">H", len(body))
        try:
            if kind == "gcm":
                plain = _aes_gcm_decrypt(key, nonce, body, aad)
            elif kind == "chacha":
                plain = _chacha_poly_decrypt(key, nonce, body, aad)
            else:
                return None
        except Exception:                        # noqa: BLE001 - tag mismatch = non-answer
            return None
        j = len(plain) - 1
        while j >= 0 and plain[j] == 0:
            j -= 1
        if j < 0:
            return None
        return plain[j], plain[:j]               # (real content type, inner plaintext)


# =====================================================================================================
# HTTP parsing of the decrypted application streams
# =====================================================================================================

_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SINGLETON_HEADERS = {"host", "content-type", "content-disposition"}


def _header_end(stream, start):
    # The start-line parser already consumed its newline.  With zero fields the header section is
    # therefore one empty CRLF/LF, not another full CRLFCRLF delimiter.
    if stream.startswith(b"\r\n", start):
        return start, 2
    if stream.startswith(b"\n", start):
        return start, 1
    crlf = stream.find(b"\r\n\r\n", start)
    lf = stream.find(b"\n\n", start)
    if crlf == -1 and lf == -1:
        return None
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return crlf, 4
    return lf, 2


def _parse_headers(blob: bytes):
    """(normalised dict, {name:[values]}), or None. Duplicate values are retained. Identical
    singleton/framing duplicates are accepted; conflicting CL/TE/CE/Host-style readings fail."""
    values = OrderedDict()
    if not blob:
        return {}, {}
    for raw in blob.split(b"\n"):
        line = raw[:-1] if raw.endswith(b"\r") else raw
        if not line or b":" not in line:
            return None
        key, value = line.split(b":", 1)
        value = value.strip(b" \t")
        if not _HEADER_NAME.fullmatch(key) or any(ch < 32 and ch != 9 or ch == 127 for ch in value):
            return None
        name = key.decode("ascii").lower()
        values.setdefault(name, []).append(value.decode("latin-1"))

    headers = {}
    for name, vals in values.items():
        if name == "content-length":
            tokens = [part.strip() for value in vals for part in value.split(",")]
            if not tokens or any(re.fullmatch(r"[0-9]+", token) is None for token in tokens):
                return None
            numbers = [int(token) for token in tokens]
            if len(set(numbers)) != 1 or numbers[0] > MAX_STREAM:
                return None
            headers[name] = str(numbers[0])
        elif name in ("transfer-encoding", "content-encoding"):
            split_values = [[part.strip().lower() for part in value.split(",")] for value in vals]
            if any(any(not part for part in parts) for parts in split_values):
                return None
            sequences = [tuple(parts) for parts in split_values]
            if not sequences or any(not seq for seq in sequences) or len(set(sequences)) != 1:
                return None
            headers[name] = ", ".join(sequences[0])
        elif name in _SINGLETON_HEADERS:
            normal = [value.strip() for value in vals]
            if len(set(normal)) != 1:
                return None
            headers[name] = normal[0]
        else:
            headers[name] = ", ".join(vals)
    if "transfer-encoding" in headers and "content-length" in headers:
        return None                              # two body boundaries: smuggling ambiguity
    if "transfer-encoding" in headers and headers["transfer-encoding"] != "chunked":
        return None                              # unsupported transfer codings cannot frame exactly
    codings = [part.strip() for part in headers.get("content-encoding", "").split(",") if part.strip()]
    if len(codings) > MAX_CONTENT_LAYERS:
        return None
    return headers, dict(values)


def _read_body(stream, start, headers, *, request=False, method=None, status=None):
    """(wire body, complete, first byte after message, has-representation)."""
    no_body = (not request and (method == "HEAD" or status == 101 or status in (204, 304)
                               or status is not None and 100 <= status < 200))
    if no_body:
        return b"", True, start, False
    if headers.get("transfer-encoding") == "chunked":
        body, complete, end = _read_chunked(stream, start)
        return body, complete, end, True
    if "content-length" in headers:
        length = int(headers["content-length"])
        end = start + length
        if end > len(stream):
            return stream[start:], False, len(stream), True
        return stream[start:end], True, end, True
    if request:
        return b"", True, start, False           # request with no framing has no message body
    return stream[start:], False, len(stream), True  # close-delimited completeness is not proven


def _parse_http_requests(stream: bytes):
    """(requests, http2_seen, valid). Every decrypted byte must be framed as HTTP/1.x."""
    if stream.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return [], True, True                    # detected only; HPACK/frame reconstruction is absent
    out, i, n = [], 0, len(stream)
    line_re = re.compile(rb"^([A-Z]{3,16}) ([^\r\n ]+) HTTP/1\.[01]\r?\n")
    while i < n and len(out) < MAX_HTTP_MSGS:
        match = line_re.match(stream[i:i + 8192])
        if not match:
            return [], False, False
        if any(byte < 0x21 or byte == 0x7F for byte in match.group(2)):
            return [], False, False              # no control/whitespace ambiguity in request-target
        boundary = _header_end(stream, i + match.end())
        if boundary is None:
            return [], False, False
        end, sep = boundary
        parsed = _parse_headers(stream[i + match.end():end])
        if parsed is None:
            return [], False, False
        headers, header_values = parsed
        method = match.group(1).decode("ascii")
        path = match.group(2).decode("latin-1")
        body, complete, consumed, _has_body = _read_body(stream, end + sep, headers, request=True,
                                                         method=method)
        if not complete or consumed <= i:
            return [], False, False
        out.append({"method": method, "path": path, "host": headers.get("host"), "headers": headers,
                    "header_values": header_values, "body": body, "complete": True})
        i = consumed
    return (out, False, i == n and len(out) <= MAX_HTTP_MSGS) if out else ([], False, False)


def _parse_http_responses(stream: bytes, requests):
    """(final responses, valid). Interim 100/102/103 do not consume a request slot; each final
    response is bound to the next request and carries both wire and decoded representation bytes."""
    out, i, n, req_index = [], 0, len(stream), 0
    pending_interim = False
    status_re = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})([^\r\n]*)\r?\n")
    while i < n and len(out) < MAX_HTTP_MSGS:
        match = status_re.match(stream[i:i + 8192])
        if not match:
            return [], False
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in match.group(2)):
            return [], False
        boundary = _header_end(stream, i + match.end())
        if boundary is None:
            return [], False
        end, sep = boundary
        parsed = _parse_headers(stream[i + match.end():end])
        if parsed is None or req_index >= len(requests):
            return [], False
        headers, header_values = parsed
        status = int(match.group(1))
        if not 100 <= status <= 599:
            return [], False
        method = requests[req_index]["method"]
        wire, complete, consumed, has_representation = _read_body(
            stream, end + sep, headers, method=method, status=status)
        if not complete or consumed <= i:
            return [], False
        i = consumed
        if 100 <= status < 200 and status != 101:
            pending_interim = True
            continue                              # 100 Continue / 103 Early Hints: not a final pair
        pending_interim = False
        decoded, codings, decoded_complete = _decode_content(wire, headers)
        out.append({"status": status, "content_type": headers.get("content-type"),
                    "wire_body": wire, "body": decoded, "complete": True,
                    "decoded_complete": decoded_complete, "content_encoding": codings,
                    "has_representation": has_representation, "name": _content_disposition_name(headers),
                    "headers": headers, "header_values": header_values, "request_index": req_index})
        req_index += 1
    valid = i == n and not pending_interim and req_index == len(requests) and len(out) <= MAX_HTTP_MSGS
    return (out, True) if valid else ([], False)


def _read_chunked(stream, start):
    out = bytearray()
    i, n = start, len(stream)
    while i < n:
        nl = stream.find(b"\n", i)
        if nl == -1:
            return bytes(out), False, n
        raw_line = stream[i:nl]
        line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
        size_text = line.split(b";", 1)[0].strip()
        if not size_text or re.fullmatch(rb"[0-9A-Fa-f]+", size_text) is None:
            return bytes(out), False, n
        size = int(size_text, 16)
        i = nl + 1
        if size == 0:
            # Trailer section, including the immediate empty trailer, must terminate completely.
            while True:
                nl = stream.find(b"\n", i)
                if nl == -1:
                    return bytes(out), False, n
                raw = stream[i:nl]
                trailer = raw[:-1] if raw.endswith(b"\r") else raw
                i = nl + 1
                if not trailer:
                    return bytes(out), True, i
                parsed = _parse_headers(trailer)
                if parsed is None or any(name in parsed[0] for name in
                                         ("content-length", "transfer-encoding", "content-encoding")):
                    return bytes(out), False, n
        if size > MAX_STREAM - len(out) or i + size > n:
            return bytes(out), False, n
        out += stream[i:i + size]
        i += size
        if stream[i:i + 2] == b"\r\n":
            i += 2
        elif stream[i:i + 1] == b"\n":
            i += 1
        else:
            return bytes(out), False, n
    return bytes(out), False, n


def _zlib_decode_complete(data, wbits):
    """One zlib/gzip/raw-deflate stream, capped and with no trailing or unconsumed bytes."""
    dec = zlib.decompressobj(wbits)
    out = dec.decompress(data, MAX_DECODED_BODY + 1)
    if len(out) > MAX_DECODED_BODY or dec.unconsumed_tail:
        return None
    out += dec.flush(MAX_DECODED_BODY + 1 - len(out))
    if len(out) > MAX_DECODED_BODY or not dec.eof or dec.unused_data or dec.unconsumed_tail:
        return None
    return out


def _decode_one_content(data, coding):
    try:
        if coding in ("gzip", "x-gzip"):
            return _zlib_decode_complete(data, 31)
        if coding == "deflate":
            wrapped = _zlib_decode_complete(data, zlib.MAX_WBITS)
            return wrapped if wrapped is not None else _zlib_decode_complete(data, -zlib.MAX_WBITS)
        if coding == "br":
            import brotli
            dec = brotli.Decompressor()
            out = bytearray()
            for start in range(0, len(data), 4096):
                part = dec.process(data[start:start + 4096])
                if len(out) + len(part) > MAX_DECODED_BODY:
                    return None
                out += part
            if hasattr(dec, "is_finished") and not dec.is_finished():
                return None
            return bytes(out)
        if coding == "zstd":
            import zstandard
            declared = zstandard.frame_content_size(data)
            if declared < 0 or declared > MAX_DECODED_BODY:
                return None                         # unknown/oversized output cannot be bounded in advance
            dec = zstandard.ZstdDecompressor().decompressobj()
            out = dec.decompress(data)
            out += dec.flush()
            if (len(out) != declared or not getattr(dec, "eof", False)
                    or getattr(dec, "unused_data", b"") or getattr(dec, "unconsumed_tail", b"")):
                return None
            return out
        if coding in ("identity", ""):
            return data
    except Exception:                           # noqa: BLE001 - malformed/unsupported coding is no object
        return None
    return None


def _decode_content(wire, headers):
    """(decoded bytes or None, codings in wire order, complete). RFC content codings are removed
    in reverse order; every layer must consume one complete stream and stay under the output cap."""
    codings = [part.strip().lower() for part in headers.get("content-encoding", "").split(",") if part.strip()]
    body = wire
    for coding in reversed(codings):
        body = _decode_one_content(body, coding)
        if body is None or len(body) > MAX_DECODED_BODY:
            return None, codings, False
    return body, codings, True


def _content_disposition_name(headers):
    cd = headers.get("content-disposition")
    if not cd:
        return None
    m = re.search(r'filename\*?=(?:"([^"]+)"|([^;]+))', cd)
    if m:
        return (m.group(1) or m.group(2)).strip().split("/")[-1]
    return None


def _object_name(req_path, resp_name):
    if resp_name:
        return resp_name
    if req_path:
        p = req_path.split("?", 1)[0].rstrip("/")
        base = p.split("/")[-1]
        if base:
            return base
    return None


# =====================================================================================================
# facts()
# =====================================================================================================

def facts(files: dict) -> dict:
    """Decrypt every TLS flow whose keys ship in the delivery and return the cleartext facts.
    Fail-closed: no key log, or nothing that verifies and parses, gives decrypted=False and empty
    lists. Never a partial read -- one failed tag/MAC, TCP gap/conflict, capture cut, ambiguous key
    or incomplete HTTP direction withdraws the entire connection."""
    result = {"decrypted": False, "keylog_source": None, "flows": [],
              "requests": [], "responses": [], "objects": [], "secrets_in_plaintext": [], "note": ""}
    if not isinstance(files, dict):
        return result
    keylog, source = collect_keylog(files)
    result["keylog_source"] = source
    captures = [(k.split(ARROW)[-1], bytes(v)) for k, v in files.items()
                if isinstance(v, (bytes, bytearray)) and is_capture(v)]
    if not captures:
        result["note"] = "no pcap/pcapng in the delivery"
        return result
    if not keylog:
        result["note"] = "no TLS key log in the delivery: encrypted TLS is not decrypted (detect and defer)"
        return result
    http2_seen = False
    for cname, cdata in captures:
        try:
            cap = Capture(cdata)
        except ValueError:
            continue
        if cap.truncated:
            continue                              # no facts from a resource-cut or damaged capture
        for conn in _connections(cap):
            flow = _decrypt_connection(conn, keylog, cname)
            if flow is None:
                continue
            http2_seen = http2_seen or flow.get("http2", False)
            if flow["requests"] or flow["responses"]:
                result["decrypted"] = True
                result["flows"].append(flow["summary"])
                result["requests"].extend(flow["requests"])
                result["responses"].extend(flow["responses"])
                result["objects"].extend(flow["objects"])
                result["secrets_in_plaintext"].extend(flow["secrets"])
    if http2_seen and not result["decrypted"]:
        result["note"] = "an HTTP/2 flow was decrypted but its HPACK frames are not parsed here"
    return result


def _decrypt_connection(conn, keylog, cname):
    ab, ba = conn["ab"], conn["ba"]
    # which direction carries the ClientHello?
    cr = None
    client_is_a = None
    for direction, stream in (("a", ab), ("b", ba)):
        for htype, body in _handshake_messages(stream):
            if htype == 1:
                cr = _parse_client_hello(body)
                client_is_a = (direction == "a")
                break
        if cr is not None:
            break
    if cr is None or cr not in keylog:
        return None
    client_stream = ab if client_is_a else ba
    server_stream = ba if client_is_a else ab
    sh = None
    for htype, body in _handshake_messages(server_stream):
        if htype == 2:
            sh = _parse_server_hello(body)
            break
    if sh is None:
        return None
    server_random, suite = sh
    dec = _Decryptor(keylog, cr, server_random, suite)
    if not dec.ok:
        return None
    if dec.is_tls13:
        client_plain = dec.decrypt_stream_tls13(client_stream, from_client=True)
        server_plain = dec.decrypt_stream_tls13(server_stream, from_client=False)
        version = "TLS 1.3"
    else:
        client_plain = dec.decrypt_stream_tls12(client_stream, from_client=True)
        server_plain = dec.decrypt_stream_tls12(server_stream, from_client=False)
        version = "TLS 1.2"
    if client_plain is None or server_plain is None:
        return None
    requests, http2, requests_valid = _parse_http_requests(client_plain)
    if http2:
        summary = {"capture": cname, "version": version,
                   "client": f"{(conn['a'] if client_is_a else conn['b'])[0]}:{(conn['a'] if client_is_a else conn['b'])[1]}",
                   "server": f"{(conn['b'] if client_is_a else conn['a'])[0]}:{(conn['b'] if client_is_a else conn['a'])[1]}",
                   "suite": f"0x{suite:04X}", "requests": 0, "responses": 0}
        return {"summary": summary, "requests": [], "responses": [], "objects": [],
                "secrets": [], "http2": True}
    if not requests_valid:
        return None
    responses, responses_valid = _parse_http_responses(server_plain, requests)
    if not responses_valid:
        return None
    objects, secrets = [], []
    for resp in responses:
        req = requests[resp["request_index"]]
        if resp.get("status") == 200 and resp.get("complete") and resp.get("has_representation"):
            wire = resp.get("wire_body")
            decoded = resp.get("body") if resp.get("decoded_complete") else None
            name = _object_name(req["path"], resp.get("name"))
            obj = {"name": name, "wire_size": len(wire),
                   "wire_sha256": hashlib.sha256(wire).hexdigest(),
                   "decoded_size": len(decoded) if decoded is not None else None,
                   "decoded_sha256": hashlib.sha256(decoded).hexdigest() if decoded is not None else None,
                   "content_encoding": list(resp.get("content_encoding") or []),
                   "content_type": resp.get("content_type")}
            if decoded is not None:              # backward-compatible names mean the decoded object
                obj.update(size=len(decoded), sha256=hashlib.sha256(decoded).hexdigest())
            objects.append(obj)
    for blob in (client_plain or b"", server_plain or b""):
        secrets.extend(_find_secrets(blob))
    ca, cp = (conn["a"] if client_is_a else conn["b"])
    sa, sp = (conn["b"] if client_is_a else conn["a"])
    summary = {"capture": cname, "version": version, "client": f"{ca}:{cp}", "server": f"{sa}:{sp}",
               "suite": f"0x{suite:04X}", "requests": len(requests), "responses": len(responses)}
    return {"summary": summary, "requests": requests, "responses": responses,
            "objects": objects, "secrets": secrets, "http2": http2}


_SECRET_RE = re.compile(
    rb"(?i)(authorization|x-api-key|api[_-]?key|password|passwd|secret|token|session)[\"':= ]+([^\s\"'&]{4,200})")
_FLAG_RE = flagfmt.BYTES


def _find_secrets(blob: bytes):
    out = []
    for m in _SECRET_RE.finditer(blob[:MAX_STREAM]):
        out.append({"kind": m.group(1).decode("latin-1").lower(),
                    "value": m.group(2).decode("latin-1")[:200], "note": "text is data: reported, never submitted"})
        if len(out) > 100:
            break
    for m in _FLAG_RE.finditer(blob[:MAX_STREAM]):
        out.append({"kind": "flag_shaped", "value": m.group(0).decode("latin-1"),
                    "note": "text is data: reported, never submitted"})
        if len(out) > 200:
            break
    return out


# =====================================================================================================
# solve_set() -- the never-wrong runner contract
# =====================================================================================================

_FIELD_WORDS = {
    "method": ("method", "verb", "http method"),
    "host": ("host", "hostname", "domain", "sni", "virtual host"),
    "path": ("path", "uri", "url", "endpoint", "resource", "request", "get", "page", "route"),
    "status": ("status", "status code", "response code", "http code", "code"),
    "content_type": ("content-type", "content type", "mime", "media type"),
    "sha256": ("sha256", "sha-256", "sha 256", "hash", "digest", "checksum"),
    "size": ("size", "bytes", "length", "file size", "byte count"),
    "flag": ("flag",),
    "password": ("password", "credential", "secret", "token", "api key", "api-key"),
}


def _qtext(q) -> str:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return " ".join(str(x or "") for x in (
        q.get("question"), q.get("artifact"), q.get("member"), fmt.get("syntax"),
        re.sub(r"[-_./]+", " ", str(q.get("answer_id") or q.get("id") or "")))).lower()


def _field_of(text):
    best = None
    best_pos = len(text) + 1
    for field, words in _FIELD_WORDS.items():
        for w in words:
            match = re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text)
            if match is not None and match.start() < best_pos:
                best, best_pos = field, match.start()
    return best


def _pick(key, options):
    if labels is not None:
        try:
            return labels.pick(key, options)
        except Exception:                        # noqa: BLE001
            pass
    return _wire_unsure(key, options)


def _candidates(key, options):
    if labels is not None:
        try:
            return labels.candidates(key, options)
        except Exception:                        # noqa: BLE001
            pass
    return _wire_unsure(key + "#candidates", options)


def _wire_unsure(key, options):
    pairs = []
    for o in options:
        if isinstance(o, (list, tuple)) and len(o) == 2:
            pairs.append([o[0], o[1]])
        else:
            pairs.append([o, o])
    if not pairs:
        return None
    return SENTINEL + json.dumps({"k": key.lower(), "o": pairs[:MAX_OPTIONS]}, separators=(",", ":"))


def _named_object(text, objects):
    """The unique, complete transferred object the question names, or None.

    Never-wrong: a question that names a file (a filename-like token absent from the
    transferred objects) is answered from NO object -- never from an unrelated sole object,
    which would be a wrong PLAIN digest/size. The sole-object fallback stands only when the
    question names no missing file. Version-number tokens (a numeric extension, "1.1", "2.5")
    are not filenames, so they neither match nor block the fallback (no false None)."""
    file_tokens = [t for t in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.[A-Za-z0-9]{1,8}", text)
                   if not t.rsplit(".", 1)[-1].isdigit()]
    present = {o["name"].lower() for o in objects if o.get("name")}
    for nm in file_tokens:
        matches = [o for o in objects if o.get("name") and o["name"].lower() == nm.lower()]
        if len(matches) == 1:
            return matches[0]
    if any(nm.lower() not in present for nm in file_tokens):
        return None                              # a named file is absent: never guess another object
    if len(objects) == 1:
        return objects[0]
    return None


def solve_set(questions, files, ctx=None) -> dict:
    out = {}
    try:
        f = facts(files)
    except Exception:                            # noqa: BLE001 - a read that fails is a non-answer
        f = {"decrypted": False, "requests": [], "responses": [], "objects": []}
    partial = None
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        partial = ctx["partial"]
    for q in questions:
        qid = q.get("qid") or q.get("id")
        ans = None
        if f.get("decrypted"):
            try:
                ans = _answer(q, f)
            except Exception:                    # noqa: BLE001
                ans = None
        out[qid] = ans
        if partial is not None and ans is not None:
            partial[qid] = ans
    return out


def _answer(q, f):
    text = _qtext(q)
    field = _field_of(text)
    if field is None:
        return None
    requests = f.get("requests") or []
    responses = f.get("responses") or []
    objects = f.get("objects") or []

    if field == "flag":
        return None                              # a flag is text-is-data: reported, never submitted

    if field == "password":
        return None                              # a secret found in plaintext is reported, never answered

    if field in ("sha256", "size"):
        obj = _named_object(text, objects)
        if obj is None:
            return None
        wire_ask = re.search(r"\b(?:wire|on[- ]the[- ]wire|compressed|(?:content[- ]|transfer[- ])?encoded|"
                             r"as sent|before (?:content )?decod(?:e|ed|ing)|"
                             r"before decompress(?:ion|ed|ing)?)\b", text) is not None
        decoded_ask = re.search(r"\b(?:decoded|decompressed|after (?:content )?decod(?:e|ed|ing)|"
                                r"after decompress(?:ion|ed|ing)?)\b", text) is not None
        if wire_ask and decoded_ask:
            return None
        prefix = "wire_" if wire_ask else "decoded_"
        if field == "sha256":
            fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
            val = obj.get(prefix + "sha256")
            if val is None:
                return None
            syn = (fmt.get("syntax") or "").lower()
            if "upper" in syn or (q.get("question") or "").lower().find("uppercase") != -1:
                val = val.upper()
            return val                           # PLAIN: a digest of exact bytes (triage precedent)
        return obj.get(prefix + "size")          # PLAIN: the exact byte count, at the named layer

    if field == "method":
        vals = [r["method"] for r in requests if r.get("method")]
        return _one_or_candidates("network.tls_http_method/decrypted", vals)
    if field == "host":
        vals = [r["host"] for r in requests if r.get("host")]
        return _one_or_candidates("network.tls_http_host/decrypted", vals)
    if field == "path":
        vals = [r["path"] for r in requests if r.get("path")]
        return _path_answer(vals)
    if field == "status":
        vals = [str(r["status"]) for r in responses if r.get("status")]
        return _one_or_candidates("network.tls_http_status/decrypted", vals)
    if field == "content_type":
        vals = [r["content_type"] for r in responses if r.get("content_type")]
        return _one_or_candidates("network.tls_http_content_type/decrypted", vals)
    return None


def _one_or_candidates(key, vals):
    """Unsure under the network prefix: one value -> a pick rendering; several distinct -> a
    candidate list (an author selection); none -> None. Never plain (no judged name)."""
    seen = list(dict.fromkeys(vals))
    if not seen:
        return None
    if len(seen) == 1:
        return _pick(key + "/single", [("raw", seen[0])])
    return _candidates(key + "/which", [(f"value_{i + 1}", v) for i, v in enumerate(seen[:MAX_OPTIONS])])


def _path_answer(vals):
    seen = list(dict.fromkeys(vals))
    if not seen:
        return None
    if len(seen) == 1:
        p = seen[0]
        opts = [("raw", p)]
        if "?" in p:
            opts.append(("path_only", p.split("?", 1)[0]))
        return _pick("network.tls_http_path/single", opts)
    return _candidates("network.tls_http_path/which", [(f"request_{i + 1}", v) for i, v in enumerate(seen[:MAX_OPTIONS])])


# =====================================================================================================
# CLI
# =====================================================================================================

def _load_attempt(attempt_dir):
    """{name: bytes} for a saved attempt dir (artifact/ members), best-effort."""
    files = {}
    d = Path(attempt_dir)
    art = d / "artifact"
    search = [art] if art.is_dir() else [d]
    for base in search:
        for p in sorted(base.rglob("*")):
            if p.is_file():
                try:
                    files[str(p.relative_to(base))] = p.read_bytes()
                except OSError:
                    pass
    return files


def main(argv) -> int:
    want_json = "--json" in argv
    args = [a for a in argv if a != "--json"]
    if args and args[0] == "--attempt":
        if len(args) < 2:
            print("usage: tls_keylog.py --attempt <attempt dir>", file=sys.stderr)
            return 2
        files = _load_attempt(args[1])
    else:
        files = {}
        for p in args:
            try:
                files[Path(p).name] = Path(p).read_bytes()
            except OSError as e:
                print(f"tls_keylog.py: {p}: {e}", file=sys.stderr)
                return 1
    if not files:
        print("usage: tls_keylog.py <pcap/pcapng> [sslkeylog] [more files...]", file=sys.stderr)
        return 2
    f = facts(files)
    if want_json:
        printable = dict(f)
        printable["objects"] = f["objects"]
        print(json.dumps(printable, indent=2))
        return 0 if f["decrypted"] else 1
    print(f"# key log: {f['keylog_source'] or '-'}   decrypted: {f['decrypted']}" + (f"   NOTE {f['note']}" if f["note"] else ""))
    for fl in f["flows"]:
        print(f"## flow {fl['client']} -> {fl['server']}  {fl['version']} {fl['suite']}  "
              f"{fl['requests']} request(s), {fl['responses']} response(s)")
    for r in f["requests"]:
        print(f"  > {r.get('method')} {r.get('path')}  Host: {r.get('host')}")
    for r in f["responses"]:
        print(f"  < {r.get('status')}  {r.get('content_type')}")
    for o in f["objects"]:
        print(f"  object name={o.get('name')} size={o['size']} sha256={o['sha256']} type={o.get('content_type')}")
    for s in f["secrets_in_plaintext"]:
        print(f"  NOTE text-is-data {s['kind']}: {s['value']} (reported, never submitted)")
    return 0 if f["decrypted"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
