#!/usr/bin/env python3
"""RF, RFID and hardware-capture toolkit (backlog row 89, toolkit key "rf"). Offline, small, stdlib
(numpy only speeds the IQ envelope up when it is there). No Game Master request, no token.

  .venv/bin/python solvers/toolkits/rf.py <file>... [--json]      a triage of each file

What it reads (every reader is a plain function an agent can call by hand):

  Flipper Zero text files   flipper_parse, sub_info (.sub: frequency, preset, protocol, bit, key, TE,
                            RAW_Data timings), nfc_info (.nfc: device type, UID, ATQA, SAK, MIFARE
                            Classic blocks, NTAG/Ultralight pages), rfid_info (.rfid: key type, data,
                            EM4100 / H10301 ids), ir_info (.ir: parsed and raw signals)
  MIFARE Classic            mfc_parse (a 320/1024/4096-byte dump) and mfc_model (blocks from any
                            source): UID, BCC, SAK, ATQA, sectors, key A, access bits (checked against
                            their inverted copy and decoded per block), key B, value blocks
  NDEF                      ndef_tlv (the TLV area of a tag), ndef_parse (records: text, URI with the
                            prefix table, MIME, smart poster, external)
  raw timings to bits       te_estimate, split_packets, pwm_bits, manchester_bits, bits_to_bytes,
                            readings (every reading of a capture, named)
  IQ and audio              iq_info / iq_pulses (.cu8 .cs8 .cs16 .cf32: samples, OOK envelope, pulse
                            runs), wav_info (channels, rate, frames)
  magstripe                 magstripe_text (track 1 / 2 strings), magstripe_bits (5- and 7-bit tracks
                            from a bit string, parity and LRC checked), luhn
  125 kHz ids               em4100_bytes, em4100_bits (64 bits, row and column parity), wiegand
                            (26/34/35/37 bits)
  firmware text             ihex_parse (Intel HEX), srec_parse (Motorola S-records)
  bus captures              can_parse (candump), logic_csv with uart_decode, i2c_decode, spi_decode

signals(questions, files) -> 0..1 says how strongly a delivery and its questions look like this
category (for tools/lane_match.py style scoring). solve_set(questions, files, ctx) is the runner
contract. It never guesses (AGENTS.md, "Uncertain answers"), and nothing is judged for this
category yet, so:

  - plain: only a fact proven from the bytes in the one form the question allows: an integer the
    question asks for as a number (a count, a value block's value, a bit length), or the single
    spelling of a fact that the answer_format's own regular expression or its list of choices
    accepts, or the form the question's words fix (case, separator and 0x prefix of a hex value;
    "in Hz")
  - labels.pick('rf.<field>/<shape>', [(method, value), ...]) for a proven fact whose spelling is
    not judged (hex case and separators, units, the label of a modulation), best first
  - None for everything else: a question no rule reads, a field the file does not hold, two files
    that disagree, a block with unknown bytes, an access-bit set whose inverted copy does not match,
    and a bit decoding of a raw capture (its polarity is a choice, not a fact) unless exactly one
    reading is printable text.

A key with the lane `rf` is remembered by solvers/common/labels.py only once its LANE_DIRS knows
`rf`; until then the unsure string is still written in the wire form (gm.session() strips it, and
tools/verify.py lists the id as open instead of probing it).
"""
import csv
import io
import json
import math
import re
import struct
import sys
import wave
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
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
try:
    import labels
except Exception:           # the toolkit still reads files without it
    labels = None

KEY = "rf"
ARROW = " -> "
MAX_TEXT = 8 * 1024 * 1024          # bytes of one text file parsed
MAX_IQ = 16 * 1024 * 1024           # bytes of one IQ file inspected
MAX_TIMINGS = 400_000               # timings of one capture decoded
IQ_EXT = {".cu8": "cu8", ".cs8": "cs8", ".cs16": "cs16", ".cf32": "cf32", ".cfile": "cf32"}


# ---- small helpers ---------------------------------------------------------------------------------

def _text(data, limit=MAX_TEXT):
    """The bytes as text when they are text (UTF-8 or UTF-16 with a BOM), else None."""
    if isinstance(data, str):
        return data
    if data is None or len(data) > limit:
        return None
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _hexbytes(value):
    """'04 A1 b2' / '04:A1:B2' / '04a1b2' -> bytes; None when it is not hex (a '??' byte included)."""
    s = re.sub(r"[\s:,-]", "", str(value or ""))
    s = s[2:] if s[:2].lower() == "0x" else s
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", s):
        return None
    return bytes.fromhex(s)


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def printable(b: bytes, least=4) -> bool:
    return len(b) >= least and all(32 <= x < 127 or x in (9, 10, 13) for x in b) and any(x > 32 for x in b)


def luhn(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


# ---- Flipper Zero text files ------------------------------------------------------------------------

FLIPPER_KINDS = (("subghz", "sub"), ("sub-ghz", "sub"), ("nfc", "nfc"), ("rfid", "rfid"), ("ibutton", "ibutton"),
                 ("ir ", "ir"), ("infrared", "ir"), ("badusb", "badusb"))


def flipper_parse(data):
    """{'filetype', 'kind' (sub, nfc, rfid, ir, ibutton, other), 'version', 'fields': [(key, value)]}
    of a Flipper text file; None when the first line is not `Filetype:`. Comment lines are kept as
    ('#', text): in an .ir file a bare '#' separates the signals."""
    text = _text(data)
    if text is None:
        return None
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    if not lines:
        return None
    m = re.match(r"Filetype:\s*(.+)$", lines[0], re.I)
    if not m:
        return None
    fields = []
    for ln in lines:
        if ln.startswith("#"):
            fields.append(("#", ln[1:].strip()))
        elif ":" in ln:
            k, v = ln.split(":", 1)
            fields.append((k.strip(), v.strip()))
    low = m.group(1).lower() + " "
    kind = next((k for word, k in FLIPPER_KINDS if word in low), "other")
    # A last line with no line end may be cut short: its key is `tail`, and facts() never answers
    # that field plain.
    tail = fields[-1][0].lower() if fields and len(lines) > 1 and not text.endswith(("\n", "\r")) else None
    return {"filetype": m.group(1).strip(), "kind": kind, "version": _int(_get(fields, "Version")), "fields": fields, "tail": tail}


def _get(fields, key):
    """The value of a key; None when the file has none, or states two different ones."""
    key = key.lower()
    vals = {v for k, v in fields if k.lower() == key}
    return next(iter(vals)) if len(vals) == 1 else None


def _getall(fields, key):
    key = key.lower()
    return [v for k, v in fields if k.lower() == key]


def modulation_of(preset: str):
    """The modulation family a Flipper preset name states: 'ook', '2fsk', 'gfsk', 'msk'; else None."""
    p = re.sub(r"^furihalsubghzpreset", "", str(preset or "").strip().lower())
    for word, name in (("ook", "ook"), ("am", "ook"), ("2fsk", "2fsk"), ("gfsk", "gfsk"), ("msk", "msk"), ("fm", "2fsk")):
        if re.match(word + r"(?=\d|dev|async|_|$)", p):
            return name
    return None


def sub_info(data):
    """A .sub file: frequency (Hz), preset, modulation, protocol, bit, key (bytes), te, timings (the
    RAW_Data of every line, in order: positive is carrier on, negative is off, microseconds)."""
    f = data if isinstance(data, dict) else flipper_parse(data)
    if not f or f["kind"] != "sub":
        return None
    fields = f["fields"]
    timings, cut = [], False
    for line in _getall(fields, "RAW_Data"):
        for tok in line.split():
            v = _int(tok)
            if v is None:
                timings = None
                break
            timings.append(v)
        if timings is None:
            break
        if len(timings) > MAX_TIMINGS:
            cut = True                  # not all of it was read: no count of it is a fact
            break
    preset = _get(fields, "Preset")
    return {"filetype": f["filetype"], "raw": "raw" in f["filetype"].lower() or (_get(fields, "Protocol") or "").upper() == "RAW",
            "frequency": _int(_get(fields, "Frequency")), "preset": preset, "modulation": modulation_of(preset),
            "protocol": _get(fields, "Protocol"), "bit": _int(_get(fields, "Bit")), "key": _hexbytes(_get(fields, "Key")),
            "te": _int(_get(fields, "TE")), "timings": timings or [], "timings_cut": cut, "lat": _get(fields, "Latitute") or _get(fields, "Latitude"),
            "lon": _get(fields, "Longitude")}


_NOT_ULC_TYPE = re.compile(r"ntag\s*-?\s*\d|ev1|ultralight\s*(11|21)\b|mf0ul\d|ntag\s*i2c", re.I)


def _is_ultralight_c(device_type, subtype, pages_total, pages):
    """Whether a .nfc describes a MIFARE Ultralight C (48 pages, AUTH0/AUTH1 at 0x2A/0x2B)."""
    named = " ".join(t for t in (device_type, subtype) if t)
    if re.search(r"ultralight\s*-?\s*c\b", named, re.I):
        return True
    specific = subtype or device_type or ""
    if _NOT_ULC_TYPE.search(specific):
        return False
    count = pages_total if pages_total else (max(pages) + 1 if pages else 0)
    return count == 48


def nfc_info(data):
    """A .nfc file: device_type, uid, atqa, sak (bytes), mifare_type, blocks {n: [int or None] * 16}
    ('??' is None), pages {n: bytes}, and `mfc` (mfc_model of the blocks) for a MIFARE Classic."""
    f = data if isinstance(data, dict) else flipper_parse(data)
    if not f or f["kind"] != "nfc":
        return None
    fields = f["fields"]
    blocks, pages, twice = {}, {}, set()
    for k, v in fields:
        m = re.fullmatch(r"(Block|Page)\s+(\d+)", k, re.I)
        if not m:
            continue
        toks = v.split()
        idx = int(m.group(2))
        if m.group(1).lower() == "block":
            if len(toks) == 16 and all(re.fullmatch(r"[0-9A-Fa-f]{2}|\?\?", t) for t in toks):
                row = [None if t == "??" else int(t, 16) for t in toks]
                if idx in blocks and blocks[idx] != row:
                    twice.add(("b", idx))
                blocks[idx] = row
        else:
            b = _hexbytes(v)
            if b is not None and len(b) == 4:       # a page is four bytes; a shorter line was cut
                if idx in pages and pages[idx] != b:
                    twice.add(("p", idx))
                pages[idx] = b
    for which, idx in twice:            # a block or page listed twice with different bytes is unknown
        if which == "b":
            blocks[idx] = [None] * 16
        else:
            pages.pop(idx, None)
    out = {"filetype": f["filetype"], "version": f["version"], "device_type": _get(fields, "Device type"),
           "uid": _hexbytes(_get(fields, "UID")), "atqa": _hexbytes(_get(fields, "ATQA")), "sak": _hexbytes(_get(fields, "SAK")),
           "mifare_type": _get(fields, "Mifare Classic type"), "blocks": blocks, "pages": pages,
           "pages_total": _int(_get(fields, "Pages total")), "mfc": mfc_model(blocks) if blocks else None, "ndef": []}
    if pages and all(i in pages for i in range(4, max(pages) + 1)) and max(pages) >= 4:
        out["ndef"] = ndef_tlv(b"".join(pages[i] for i in range(4, max(pages) + 1)))
    elif out["mfc"]:
        out["ndef"] = out["mfc"]["ndef"]
    # MIFARE Ultralight C protection config: AUTH0 (0x2A), AUTH1 (0x2B) and the write-only 3DES key
    # pages (0x2C-0x2F, which read back as zero on a real card). Only for a card that IS an UL-C: the
    # type line names it, or the tag has exactly 48 pages and its type is not an NTAG/EV1 model. Page
    # presence alone is not enough: on an NTAG213/215/216 pages 0x2A/0x2B are CFG/PWD, not AUTH0/1.
    if _is_ultralight_c(out["device_type"], _get(fields, "NTAG/Ultralight type"), out["pages_total"], pages):
        key_pages = [pages.get(i) for i in range(0x2C, 0x30)]
        have_key = all(p is not None for p in key_pages)
        out["ultralight_c"] = {
            "auth0": pages[0x2A][0] if 0x2A in pages else None,
            "auth1": pages[0x2B][0] if 0x2B in pages else None,
            "key_pages_present": have_key,
            "key_pages": b"".join(key_pages).hex() if have_key else None,
            "key_pages_zeroed": have_key and set(b"".join(key_pages)) <= {0},
        }
    return out


def em4100_bytes(b: bytes):
    """The ids a 5-byte EM4100 code is printed as: version/customer byte, the 32-bit id, the 10-digit
    and 8-digit decimal forms and the 3,5 'facility,card' form (third byte, last two bytes)."""
    if len(b) != 5:
        return None
    return {"customer": b[0], "id32": int.from_bytes(b[1:], "big"), "dez10": f"{int.from_bytes(b[1:], 'big'):010d}",
            "dez8": f"{int.from_bytes(b[2:], 'big'):08d}", "facility_code": b[2], "card_number": int.from_bytes(b[3:], "big"),
            "dez3_5": f"{b[2]:03d},{int.from_bytes(b[3:], 'big'):05d}"}


def rfid_info(data):
    """A .rfid file: key_type, data (bytes), and the decoded ids for EM4100 (5 bytes) and H10301
    (3 bytes: facility code, 16-bit card number)."""
    f = data if isinstance(data, dict) else flipper_parse(data)
    if not f or f["kind"] != "rfid":
        return None
    kt, b = _get(f["fields"], "Key type"), _hexbytes(_get(f["fields"], "Data"))
    out = {"filetype": f["filetype"], "key_type": kt, "data": b, "em4100": None, "facility_code": None, "card_number": None}
    low = (kt or "").lower()
    if b and low.startswith("em4100") and len(b) == 5:
        out["em4100"] = em4100_bytes(b)
    if b and low == "h10301" and len(b) == 3:
        out["facility_code"], out["card_number"] = b[0], int.from_bytes(b[1:], "big")
    return out


def ir_info(data):
    """An .ir file: signals [{name, type, protocol, address, command (bytes) | frequency, duty_cycle,
    data (timings)}]."""
    f = data if isinstance(data, dict) else flipper_parse(data)
    if not f or f["kind"] != "ir":
        return None
    signals, cur = [], None
    for k, v in f["fields"]:
        kl = k.lower()
        if kl == "name":
            cur = {"name": v}
            signals.append(cur)
        elif cur is None or kl == "#":
            continue
        elif kl in ("address", "command"):
            cur[kl] = _hexbytes(v)
        elif kl == "frequency":
            cur[kl] = _int(v)
        elif kl == "data":
            cur[kl] = [x for x in (_int(t) for t in v.split()) if x is not None]
        elif kl in ("type", "protocol", "duty_cycle"):
            cur[kl] = v
    return {"filetype": f["filetype"], "signals": signals}


def nec_decode(durations):
    """NEC infrared frames in a raw signal (alternating mark and space times in microseconds, as a
    Flipper .ir `data:` line gives them; a leading silence is skipped): [{protocol 'NEC' or 'NECext',
    address, command (ints), repeat}]. A frame is a 9 ms mark, a 4.5 ms space and 32 bits sent as a
    560 us mark and a 560 us (0) or 1690 us (1) space, least significant bit first: address, its
    complement, command, its complement, then a closing mark and silence (a frame that goes on,
    such as the 42-bit NEC42, is not read). With an address byte that is not complemented the frame is
    NECext with a 16-bit address and a 16-bit command, as the Flipper firmware reports it.
    A 9 ms mark with a 2.25 ms space is a repeat of the frame before it."""
    d = [abs(x) for x in durations]
    if d and d[0] > 20000:
        d = d[1:]
    out, i, last = [], 0, None

    def near(v, want, tol=0.25):
        return abs(v - want) <= want * tol
    while i + 2 < len(d):
        if not near(d[i], 9000):
            i += 2
            continue
        if near(d[i + 1], 2250) and near(d[i + 2], 560, 0.4):
            if last:
                out.append(dict(last, repeat=True))
            i += 4
            continue
        if not near(d[i + 1], 4500):
            i += 2
            continue
        bits, j = [], i + 2
        while len(bits) < 32 and j + 1 < len(d) and near(d[j], 560, 0.4):
            if near(d[j + 1], 560, 0.4):
                bits.append(0)
            elif near(d[j + 1], 1690, 0.3):
                bits.append(1)
            else:
                break
            j += 2
        if len(bits) == 32 and j < len(d) and near(d[j], 560, 0.4) and (j + 1 >= len(d) or d[j + 1] > 3000):
            b = [sum(bits[k * 8 + n] << n for n in range(8)) for k in range(4)]
            if b[0] ^ b[1] == 0xFF and b[2] ^ b[3] == 0xFF:
                last = {"protocol": "NEC", "address": b[0], "command": b[2], "repeat": False}
            else:
                last = {"protocol": "NECext", "address": b[0] | b[1] << 8, "command": b[2] | b[3] << 8, "repeat": False}
            out.append(last)
            i = j + 2
        else:
            i += 2
    return out


# ---- MIFARE Classic ---------------------------------------------------------------------------------

MFC_SIZES = {320: ("mini", 5), 1024: ("1k", 16), 4096: ("4k", 40)}
# What the three access bits of a block mean (NXP MF1S50 data sheet): data blocks, then the trailer.
MFC_DATA_ACCESS = {
    (0, 0, 0): "read AB, write AB, increment AB, decrement AB (transport)", (0, 1, 0): "read AB only",
    (1, 0, 0): "read AB, write B", (1, 1, 0): "read AB, write B, increment B, decrement AB (value block)",
    (0, 0, 1): "read AB, decrement AB (value block, no recharge)", (0, 1, 1): "read B, write B",
    (1, 0, 1): "read B only", (1, 1, 1): "no access"}
MFC_TRAILER_ACCESS = {
    (0, 0, 0): "key A: write A; access bits: read A; key B: read A, write A", (0, 1, 0): "access bits: read A; key B: read A; nothing writable",
    (1, 0, 0): "key A: write B; access bits: read AB; key B: write B", (1, 1, 0): "access bits: read AB; nothing writable",
    (0, 0, 1): "key A: write A; access bits: read A, write A; key B: read A, write A (transport)",
    (0, 1, 1): "key A: write B; access bits: read AB, write B; key B: write B",
    (1, 0, 1): "access bits: read AB, write B", (1, 1, 1): "access bits: read AB; nothing writable"}


def mfc_sector_blocks(sector: int):
    """(first block, block count) of a sector: 4 blocks each for sectors 0 to 31, 16 each above."""
    return (sector * 4, 4) if sector < 32 else (128 + (sector - 32) * 16, 16)


def mfc_access(acc: bytes):
    """The access conditions of a trailer's bytes 6 to 8: [(c1, c2, c3)] for the four block groups
    (the fourth is the trailer), or None when the bits do not match their inverted copy."""
    if len(acc) != 3:
        return None
    b6, b7, b8 = acc
    out = []
    for i in range(4):
        c1, c2, c3 = (b7 >> (4 + i)) & 1, (b8 >> i) & 1, (b8 >> (4 + i)) & 1
        if ((b6 >> i) & 1, (b6 >> (4 + i)) & 1, (b7 >> i) & 1) != (c1 ^ 1, c2 ^ 1, c3 ^ 1):
            return None
        out.append((c1, c2, c3))
    return out


def mfc_value(block):
    """The value of a value block (signed 32-bit, little-endian) and its address byte when the block
    holds the value, its inverse, the value again and the address four times as a/~a/a/~a; else None."""
    if block is None or len(block) != 16 or any(x is None for x in block):
        return None
    b = bytes(block)
    v, nv, v2 = struct.unpack_from("<iIi", b, 0)
    if v != v2 or nv != (~v & 0xFFFFFFFF):
        return None
    if not (b[12] == b[14] and b[13] == b[15] and b[12] ^ b[13] == 0xFF):
        return None
    return {"value": v, "address": b[12]}


def _whole(seq):
    return seq is not None and all(x is not None for x in seq)


def mfc_model(blocks: dict):
    """A MIFARE Classic card from {block number: 16 values (int, or None for an unknown byte)}:
    uid (the first four bytes when their BCC holds), bcc_ok, sak, atqa (as stored in block 0),
    sectors [{sector, first, blocks, trailer, key_a, access, access_ok, conditions, gpb, key_b}],
    values {block: {value, address}}, ndef (messages found in the data blocks from sector 1 on)."""
    if not blocks:
        return None
    top = max(blocks)
    b0 = blocks.get(0)
    out = {"block_count": top + 1 if len(blocks) == top + 1 else None, "uid": None, "bcc": None, "bcc_ok": None, "sak": None, "atqa": None, "manufacturer_block": None,
           "sectors": [], "values": {}, "ndef": []}
    if _whole(b0):
        b = bytes(b0)
        out["manufacturer_block"] = b
        out["bcc"], out["bcc_ok"] = b[4], (b[0] ^ b[1] ^ b[2] ^ b[3]) == b[4]
        if out["bcc_ok"]:
            out["uid"], out["sak"], out["atqa"] = b[:4], b[5:6], b[6:8]
    s = 0
    data_area, area_ok = [], True
    while True:
        first, n = mfc_sector_blocks(s)
        if first + n - 1 > top:
            break
        rows = [blocks.get(first + i) for i in range(n)]
        tr = rows[-1]
        sec = {"sector": s, "first": first, "blocks": rows, "trailer": first + n - 1, "key_a": None, "access": None,
               "access_ok": None, "conditions": None, "gpb": None, "key_b": None}
        if tr is not None and len(tr) == 16:
            if _whole(tr[:6]):
                sec["key_a"] = bytes(tr[:6])
            if _whole(tr[6:9]):
                sec["access"] = bytes(tr[6:9])
                sec["conditions"] = mfc_access(sec["access"])
                sec["access_ok"] = sec["conditions"] is not None
            if tr[9] is not None:
                sec["gpb"] = tr[9]
            if _whole(tr[10:]):
                sec["key_b"] = bytes(tr[10:])
        for i in range(n - 1):
            if first + i == 0:
                continue
            v = mfc_value(rows[i])
            if v:
                out["values"][first + i] = v
            if s >= 1 and area_ok:
                if _whole(rows[i]):
                    data_area.append(bytes(rows[i]))
                else:
                    area_ok = False
        out["sectors"].append(sec)
        s += 1
    out["sector_count"] = len(out["sectors"]) if out["block_count"] else None      # a partial listing is no count
    if data_area:
        out["ndef"] = ndef_tlv(b"".join(data_area))
    return out


def mfc_parse(data: bytes):
    """A binary MIFARE Classic dump (320, 1024 or 4096 bytes: Mini, 1K, 4K) as mfc_model, with
    'type'. None for any other size. `plausible` says the card's own checks hold (BCC, and the
    access bits of at least half the sectors); a blob of the right size alone is not a card."""
    if not isinstance(data, (bytes, bytearray)) or len(data) not in MFC_SIZES:
        return None
    blocks = {i: list(data[i * 16:i * 16 + 16]) for i in range(len(data) // 16)}
    m = mfc_model(blocks)
    m["type"] = MFC_SIZES[len(data)][0]
    good = sum(1 for s in m["sectors"] if s["access_ok"])
    m["plausible"] = bool(m["bcc_ok"]) and good * 2 >= len(m["sectors"]) and len(set(data)) > 2
    return m


# ---- NDEF ---------------------------------------------------------------------------------------------

URI_PREFIX = ("", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@",
              "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:",
              "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
              "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:")
TNF = ("empty", "well_known", "mime", "absolute_uri", "external", "unknown", "unchanged", "reserved")


def ndef_parse(data: bytes, depth=0):
    """The records of one NDEF message: [{tnf, tnf_name, type, id, payload, and for a text record
    lang, text; for a URI record uri; for a smart poster records}]. ValueError when the bytes are
    not one well-formed message (first record MB, last ME, lengths inside the data, no chunks)."""
    out, i = [], 0
    if not data:
        raise ValueError("empty message")
    while i < len(data):
        hdr = data[i]
        mb, me, cf, sr, il, tnf = hdr >> 7 & 1, hdr >> 6 & 1, hdr >> 5 & 1, hdr >> 4 & 1, hdr >> 3 & 1, hdr & 7
        if cf:
            raise ValueError("chunked record")
        if bool(mb) != (not out):
            raise ValueError("message-begin flag out of place")
        need = 2 + (1 if sr else 4) + (1 if il else 0)
        if i + need > len(data):
            raise ValueError("record header cut")
        tlen = data[i + 1]
        plen = data[i + 2] if sr else struct.unpack_from(">I", data, i + 2)[0]
        j = i + 2 + (1 if sr else 4)
        ilen = data[j] if il else 0
        j += 1 if il else 0
        if j + tlen + ilen + plen > len(data):
            raise ValueError("record longer than the message")
        rtype, rid = data[j:j + tlen], data[j + tlen:j + tlen + ilen]
        payload = data[j + tlen + ilen:j + tlen + ilen + plen]
        rec = {"tnf": tnf, "tnf_name": TNF[tnf], "type": rtype.decode("latin-1"), "id": rid.decode("latin-1"), "payload": payload}
        if tnf == 1 and rtype == b"T" and payload:
            n = payload[0] & 0x3F
            if 1 + n <= len(payload):
                rec["lang"] = payload[1:1 + n].decode("ascii", "replace")
                try:
                    rec["text"] = payload[1 + n:].decode("utf-16" if payload[0] & 0x80 else "utf-8")
                except UnicodeDecodeError:
                    pass
        elif tnf == 1 and rtype == b"U" and payload and payload[0] < len(URI_PREFIX):
            try:
                rec["uri"] = URI_PREFIX[payload[0]] + payload[1:].decode("utf-8")
            except UnicodeDecodeError:
                pass
        elif tnf == 3:
            rec["uri"] = rtype.decode("latin-1")
        elif tnf == 1 and rtype == b"Sp" and depth < 3:
            try:
                rec["records"] = ndef_parse(payload, depth + 1)
            except ValueError:
                pass
        elif tnf == 2:
            try:
                t = payload.decode("utf-8")
                if t.isprintable() or "\n" in t:
                    rec["text_payload"] = t
            except UnicodeDecodeError:
                pass
        out.append(rec)
        i = j + tlen + ilen + plen
        if me:
            if i != len(data):
                raise ValueError("bytes after the message-end record")
            return out
    raise ValueError("no message-end record")


def ndef_tlv(area: bytes):
    """The NDEF messages in a tag's TLV area (Type 2 tag from page 4; MIFARE Classic data blocks):
    [records] per NDEF TLV (0x03) that parses. Stops at the terminator (0xFE) or the first byte
    that is no TLV; an area that does not start with a TLV gives []."""
    out, i = [], 0
    while i < len(area):
        t = area[i]
        if t == 0x00:
            i += 1
            continue
        if t == 0xFE or t not in (0x01, 0x02, 0x03, 0xFD):
            break
        if i + 1 >= len(area):
            break
        n = area[i + 1]
        i += 2
        if n == 0xFF:
            if i + 2 > len(area):
                break
            n = struct.unpack_from(">H", area, i)[0]
            i += 2
        if i + n > len(area):
            break
        if t == 0x03 and n:
            try:
                out.append(ndef_parse(area[i:i + n]))
            except ValueError:
                pass
        i += n
    return out


def ndef_flat(messages):
    """Every record of the messages, smart-poster members included, in order."""
    out = []

    def walk(recs):
        for r in recs:
            out.append(r)
            walk(r.get("records") or [])
    for m in messages or []:
        walk(m)
    return out


# ---- raw timings to bits ------------------------------------------------------------------------------

def te_estimate(timings):
    """The short unit of a capture: the median of the durations within 1.5 times the 10th-percentile
    duration (so one glitch does not set it). None for fewer than 8 timings."""
    d = sorted(abs(t) for t in timings if t)
    if len(d) < 8:
        return None
    base = d[len(d) // 10]
    near = [x for x in d if base <= x <= base * 1.5]
    return near[len(near) // 2] if near else base


def split_packets(timings, gap=None, te=None):
    """Timings cut at every silence (a negative duration) of at least `gap` (default 8 TE). The
    silence itself is dropped; packets shorter than 8 timings are dropped too."""
    te = te or te_estimate(timings)
    if not te:
        return []
    gap = gap or te * 8
    out, cur = [], []
    for t in timings:
        if t < 0 and -t >= gap:
            if len(cur) >= 8:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if len(cur) >= 8:
        out.append(cur)
    if gap == te * 8 and sum(len(x) for x in out) * 2 < len(timings):
        alt = _split_by_gap_groups(timings)     # short pulses and long gaps: 8 TE cuts between the bits
        if sum(len(x) for x in alt) > sum(len(x) for x in out):
            return alt
    return out


def _split_by_gap_groups(timings):
    """Packets of a pulse-distance capture, where every gap is many pulse widths long: the off
    times are grouped (a group ends where the next gap is 1.5 times longer), and with three groups
    or more the capture is cut at the gaps of the longest groups that hold under a tenth of the
    gaps between them. [] when the gaps do not fall into such groups."""
    gaps = sorted(-t for t in timings if t < 0)
    if len(gaps) < 16:
        return []
    groups = [[gaps[0]]]
    for g in gaps[1:]:
        if g >= groups[-1][-1] * 1.5:
            groups.append([g])
        else:
            groups[-1].append(g)
    if len(groups) < 3:
        return []
    cut, held = None, 0
    for grp in reversed(groups[2:]):
        if (held + len(grp)) * 10 > len(gaps):
            break
        held += len(grp)
        cut = grp[0]
    if cut is None:
        return []
    out, cur = [], []
    for t in timings:
        if t < 0 and -t >= cut:
            if len(cur) >= 8:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if len(cur) >= 8:
        out.append(cur)
    return out


def pwm_bits(packet, te=None):
    """Pulse-width bits of one packet: each (on, off) pair is a bit, '1' when the on time is the
    longer one ('long_high=1', the Princeton / PT2262 reading). None when a pair has equal halves.
    A leading off time is ignored. The last on time has lost its off time to the silence after the
    packet, so it is read by its own length: '1' at two TE or more. (A protocol that ends with a
    short sync pulse therefore shows one extra '0' at the end.)"""
    p = list(packet)
    while p and p[0] < 0:
        p.pop(0)
    te = te or te_estimate(p)
    bits = []
    for i in range(0, len(p) - 1, 2):
        hi, lo = p[i], -p[i + 1]
        if hi <= 0 or lo <= 0:
            return None
        if max(hi, lo) < 1.5 * min(hi, lo):
            return None
        bits.append("1" if hi > lo else "0")
    if len(p) % 2 and bits and te:
        if p[-1] <= 0:
            return None
        bits.append("1" if p[-1] >= 2 * te else "0")
    return "".join(bits) or None


def ppm_bits(packet):
    """Pulse-distance bits of one packet: every on time has one width (the longest under 1.5 times
    the shortest) and the off times fall in two groups at least 1.5 apart; a bit is '1' for the
    long gap (the Nexus / Prologue sensor reading). The last pulse has lost its gap to the silence
    and carries no bit. None when the packet is not of this form (under 8 gaps, or a third gap
    length such as a sync inside it)."""
    p = list(packet)
    while p and p[0] < 0:
        p.pop(0)
    his, los = [t for t in p if t > 0], [-t for t in p if t < 0]
    if len(los) < 8 or len(his) < 8 or max(his) >= 1.5 * min(his):
        return None
    lo, hi = min(los), max(los)
    if hi < 1.5 * lo:
        return None
    mid = (lo + hi) / 2
    short = [g for g in los if g < mid]
    long_ = [g for g in los if g >= mid]
    if not short or not long_ or max(short) >= 1.5 * min(short) or max(long_) >= 1.5 * min(long_):
        return None
    return "".join("1" if g >= mid else "0" for g in los)


def pwm_gap_first_bits(packet):
    """Pulse-width bits of a packet that opens with a start pulse and then sends each bit as
    (off, on): '1' when the off time is the longer one (the CAME / Nice FLO reading: long gap and
    short pulse is 1). None when a pair has equal halves or fewer than 8 pairs follow the start."""
    p = list(packet)
    while p and p[0] < 0:
        p.pop(0)
    p = p[1:]
    bits = []
    for i in range(0, len(p) - 1, 2):
        lo, hi = -p[i], p[i + 1]
        if hi <= 0 or lo <= 0 or max(hi, lo) < 1.5 * min(hi, lo):
            return None
        bits.append("1" if lo > hi else "0")
    return "".join(bits) if len(bits) >= 8 else None


def _halves(packet, te):
    """The packet as half-bit levels ('1' carrier on): each duration is one or two TE; else None."""
    out = []
    for t in packet:
        n = abs(t) / te
        k = 1 if 0.5 <= n < 1.5 else 2 if 1.5 <= n < 2.6 else 0
        if not k:
            return None
        out.append(("1" if t > 0 else "0") * k)
    return "".join(out)


def manchester_bits(packet, te=None):
    """Manchester readings of one packet: {'ieee' (low-to-high is 1, IEEE 802.3), 'thomas'
    (high-to-low is 1, G. E. Thomas)}. The half-bit stream is aligned at whichever offset pairs
    every half with its opposite; {} when neither does (it is not Manchester at this TE)."""
    te = te or te_estimate(packet)
    if not te:
        return {}
    h = _halves(packet, te)
    if not h:
        return {}
    for off in (0, 1):
        s = h[off:]
        s = s[:len(s) - len(s) % 2]
        pairs = [s[i:i + 2] for i in range(0, len(s), 2)]
        if len(pairs) >= 4 and all(p in ("01", "10") for p in pairs):
            ieee = "".join("1" if p == "01" else "0" for p in pairs)
            return {"ieee": ieee, "thomas": "".join("0" if c == "1" else "1" for c in ieee)}
    return {}


def bits_to_bytes(bits: str, msb_first=True) -> bytes:
    """Whole bytes of a bit string (a ragged tail is dropped)."""
    out = bytearray()
    for i in range(0, len(bits) - len(bits) % 8, 8):
        chunk = bits[i:i + 8]
        out.append(int(chunk if msb_first else chunk[::-1], 2))
    return bytes(out)


def readings(timings, te=None):
    """Every reading of a capture's first packets, named: {name: [bit string per packet]} for
    pwm_long_high, pwm_short_high (the inverse), ppm_long_gap, ppm_short_gap (pulses of one width,
    the gap is the bit), pwm_gap_first_long_gap and its inverse (a start pulse, then off-on pairs;
    tried only where the on-off pairing fails), manchester_ieee, manchester_thomas. A reading that
    fails on a packet is left out for that packet. A packet of constant-width pulses is read by
    its gaps only: its on-off pairs would all read as one bit value."""
    te = te or te_estimate(timings)
    out = {}
    inv = lambda b: "".join("0" if c == "1" else "1" for c in b)      # noqa: E731
    for pkt in split_packets(timings, te=te)[:64]:
        d = ppm_bits(pkt)
        if d:
            out.setdefault("ppm_long_gap", []).append(d)
            out.setdefault("ppm_short_gap", []).append(inv(d))
            continue
        b = pwm_bits(pkt, te)
        if b:
            out.setdefault("pwm_long_high", []).append(b)
            out.setdefault("pwm_short_high", []).append("".join("0" if c == "1" else "1" for c in b))
        else:
            g = pwm_gap_first_bits(pkt)
            if g:
                out.setdefault("pwm_gap_first_long_gap", []).append(g)
                out.setdefault("pwm_gap_first_short_gap", []).append(inv(g))
        for name, mb in manchester_bits(pkt, te).items():
            out.setdefault("manchester_" + name, []).append(mb)
    return out


def text_readings(timings):
    """{text: [reading names]} for every reading whose first packet is printable ASCII (MSB or LSB
    first). A message is a fact only when exactly one text comes out."""
    out = {}
    for name, packets in readings(timings).items():
        for order, msb in (("msb", True), ("lsb", False)):
            b = bits_to_bytes(packets[0], msb)
            if printable(b):
                out.setdefault(b.decode("ascii"), []).append(f"{name}_{order}")
    return out


# ---- IQ and audio --------------------------------------------------------------------------------------

def iq_format(name: str):
    return IQ_EXT.get(Path(str(name).split(ARROW)[-1]).suffix.lower())


def name_hints(name: str):
    """Centre frequency (Hz) and sample rate (Hz) an rtl_433-style file name states
    (g001_433.92M_250k.cu8); each None when the name has none. A name is a hint, not bytes."""
    base = Path(str(name).split(ARROW)[-1]).name
    mult = {"k": 1e3, "M": 1e6, "G": 1e9}
    freq = re.search(r"(?<![\d.])(\d+(?:\.\d+)?)([MG])(?:Hz)?(?=[_.\-]|$)", base)
    rate = re.search(r"(?<![\d.])(\d+(?:\.\d+)?)(k|M)(?:sps|Hz)?(?=[_.\-]|$)", base[freq.end():] if freq else base)
    return (int(round(float(freq.group(1)) * mult[freq.group(2)])) if freq else None,
            int(round(float(rate.group(1)) * mult[rate.group(2)])) if rate else None)


def _magnitudes(data: bytes, fmt: str):
    try:
        import numpy as np
    except Exception:
        np = None
    if np is not None:
        if fmt == "cu8":
            a = np.frombuffer(data[:len(data) // 2 * 2], dtype=np.uint8).astype(np.float32) - 127.5
        elif fmt == "cs8":
            a = np.frombuffer(data[:len(data) // 2 * 2], dtype=np.int8).astype(np.float32)
        elif fmt == "cs16":
            a = np.frombuffer(data[:len(data) // 4 * 4], dtype="<i2").astype(np.float32)
        else:
            a = np.frombuffer(data[:len(data) // 8 * 8], dtype="<f4")
        return np.hypot(a[0::2], a[1::2]).tolist()
    if fmt == "cu8":
        vals = [x - 127.5 for x in data[:len(data) // 2 * 2]]
    elif fmt == "cs8":
        vals = list(struct.unpack(f"{len(data) // 2 * 2}b", data[:len(data) // 2 * 2]))
    elif fmt == "cs16":
        vals = list(struct.unpack(f"<{len(data) // 4 * 2}h", data[:len(data) // 4 * 4]))
    else:
        vals = list(struct.unpack(f"<{len(data) // 8 * 2}f", data[:len(data) // 8 * 8]))
    return [math.hypot(vals[i], vals[i + 1]) for i in range(0, len(vals) - 1, 2)]


def runs(levels):
    """Run lengths of a 0/1 sequence as timings: +n for a run of ones, -n for zeros."""
    out, prev, n = [], None, 0
    for v in levels:
        if v == prev:
            n += 1
        else:
            if prev is not None:
                out.append(n if prev else -n)
            prev, n = v, 1
    if prev is not None:
        out.append(n if prev else -n)
    return out


def _threshold(mag):
    """(floor, peak, threshold) of an envelope: the 5th and 99.5th percentile and their middle;
    the threshold is None when the peak is under twice the floor (no bursts)."""
    srt = sorted(mag)
    floor, peak = srt[len(srt) // 20], srt[min(len(srt) - 1, len(srt) * 199 // 200)]
    if peak < floor * 2 + 1e-9 or peak - floor < 1e-9:
        return floor, peak, None
    return floor, peak, (floor + peak) / 2


def iq_pulses(data: bytes, fmt: str, smooth=4):
    """The OOK envelope of an IQ capture as timings in samples (+ carrier on, - off), the threshold
    used and the magnitude range. The threshold is halfway between the floor (5th percentile) and
    the peak (99.5th percentile) of the smoothed magnitude; a capture whose peak is under twice its
    floor has no bursts ([]). It depends on that threshold: read it as an inspection, not as a
    proven count."""
    if smooth <= 0:
        return None
    mag = _magnitudes(data[:MAX_IQ], fmt)
    if len(mag) < smooth * 2:
        return {"timings": [], "threshold": None, "floor": None, "peak": None}
    acc, sm = sum(mag[:smooth]), []
    for i in range(smooth, len(mag)):
        sm.append(acc / smooth)
        acc += mag[i] - mag[i - smooth]
    sm.append(acc / smooth)
    floor, peak, thr = _threshold(sm)
    if thr is None:
        return {"timings": [], "threshold": None, "floor": floor, "peak": peak}
    t = runs(1 if v > thr else 0 for v in sm)
    while t and t[0] < 0:
        t.pop(0)
    return {"timings": t, "threshold": thr, "floor": floor, "peak": peak}


def iq_info(data: bytes, fmt: str, name: str = ""):
    """Samples (complex pairs), the bytes per sample pair, the name's frequency and rate hints, and
    the envelope's pulse runs (iq_pulses)."""
    width = {"cu8": 2, "cs8": 2, "cs16": 4, "cf32": 8}.get(fmt)
    if width is None:
        return None
    freq, rate = name_hints(name)
    p = iq_pulses(data, fmt)
    return {"format": fmt, "samples": len(data) // width, "whole": len(data) % width == 0, "name_frequency": freq,
            "name_rate": rate, "pulses": sum(1 for t in p["timings"] if t > 0), **p}


def wav_info(data: bytes, envelope=True):
    """A RIFF/WAVE file's header facts: channels, sample_rate, sample_width (bytes), frames,
    duration (seconds), and for PCM the envelope's pulse runs of the first channel. None when the
    bytes are not a WAV the wave module reads."""
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    try:
        with wave.open(io.BytesIO(data), "rb") as w:
            ch, sw, rate, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            raw = w.readframes(min(n, 400_000)) if envelope else b""
            w.rewind()
            whole = len(data) <= MAX_IQ * 4 and len(w.readframes(n)) == n * ch * sw
    except (wave.Error, EOFError, struct.error, RuntimeError):
        return None
    out = {"channels": ch, "sample_rate": rate, "sample_width": sw, "bits_per_sample": sw * 8, "frames": n, "whole": whole,
           "duration": n / rate if rate else None, "timings": []}
    if sw in (1, 2) and ch in (1, 2) and raw:
        if sw == 1:
            vals = [x - 128 for x in raw]
        else:
            vals = list(struct.unpack(f"<{len(raw) // 2}h", raw[:len(raw) // 2 * 2]))
        if ch == 2:
            mag = [math.hypot(vals[i], vals[i + 1]) for i in range(0, len(vals) - 1, 2)]
        else:
            mag = [abs(v) for v in vals]
        if mag:
            thr = _threshold(mag)[2]
            if thr is not None:
                out["timings"] = runs(1 if v > thr else 0 for v in mag)
    return out


# ---- audio FSK modems ---------------------------------------------------------------------------------

# name: (baud, mark Hz, space Hz). Bell 202 is what `minimodem 1200` reads; Bell 103 is `minimodem 300`.
AFSK_MODES = {"bell202_1200": (1200, 1200.0, 2200.0), "bell103_300": (300, 1270.0, 1070.0),
              "bell103_answer_300": (300, 2225.0, 2025.0), "v23_1200": (1200, 1300.0, 2100.0)}
MAX_AFSK = 6_000_000                # samples demodulated (about two minutes at 48 kHz)


def wav_samples(data: bytes, limit=MAX_AFSK):
    """(first channel as a numpy float array, sample rate) of a PCM WAV, or (None, None): no numpy,
    not PCM of 8, 16, 24 or 32 bits, or not a WAV."""
    try:
        import numpy as np
        with wave.open(io.BytesIO(data), "rb") as w:
            ch, sw, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            raw = w.readframes(min(w.getnframes(), limit))
    except Exception:
        return None, None
    if sw == 1:
        a = np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0
    elif sw == 2:
        a = np.frombuffer(raw[:len(raw) // 2 * 2], dtype="<i2").astype(np.float32)
    elif sw == 3:
        b = np.frombuffer(raw[:len(raw) // 3 * 3], dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        a = ((b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)) - ((b[:, 2] & 0x80) << 17)).astype(np.float32)
    elif sw == 4:
        a = np.frombuffer(raw[:len(raw) // 4 * 4], dtype="<i4").astype(np.float32)
    else:
        return None, None
    if ch > 1:
        a = a[:len(a) // ch * ch].reshape(-1, ch)[:, 0]
    return a, rate


def afsk_decode(samples, rate, baud, mark, space):
    """Asynchronous 8N1 bytes of a two-tone FSK recording (mark is the idle tone and bit 1):
    {bytes, framing_errors, frames}. Each window of one bit length gets the energy of the mark and
    of the space tone; a start bit is a mark-to-space edge with carrier, the eight data bits are
    read LSB first at mid-bit, and a frame whose stop bit is not mark is a framing error (its byte
    is dropped). None without numpy, with under 20 bit lengths of samples, or with a tone above
    the rate's reach."""
    try:
        import numpy as np
    except Exception:
        return None
    n = int(round(rate / baud)) if baud else 0
    if rate <= 0 or n < 4 or len(samples) < n * 20 or max(mark, space) * 2.2 > rate:
        return None
    t = np.arange(len(samples), dtype=np.float64) / rate

    def energy(f):
        c = np.cumsum(np.concatenate(([0], samples * np.exp(-2j * np.pi * f * t))))
        return np.abs(c[n:] - c[:-n])
    m, sp = energy(mark), energy(space)
    level = m + sp
    carrier = level > 0.25 * float(np.percentile(level, 95))
    bit = m > sp                        # bit[j] is the tone of samples j .. j+n
    edges = np.flatnonzero(bit[:-1] & ~bit[1:] & carrier[1:])
    out, errors, frames = bytearray(), 0, 0
    step, last, nxt = rate / baud, len(bit) - 1, 0
    for e in edges.tolist():
        if e < nxt:
            continue
        # the window at e is half mark, half space: the start bit begins n/2 later, and the window
        # that starts there covers it whole. Bit b of the frame is read from the window b bits on.
        idx = [int(round(e + n / 2 + step * b)) for b in range(10)]
        if idx[-1] > last:
            break
        if bit[idx[0]] or not carrier[idx[0]]:
            continue                    # a glitch, not a start bit
        frames += 1
        if not bit[idx[9]]:
            errors += 1
            continue
        v = 0
        for b in range(8):
            v |= int(bit[idx[1 + b]]) << b
        out.append(v)
        nxt = idx[9] - n // 2           # the next start edge may come as soon as the stop bit ends
    return {"bytes": bytes(out), "framing_errors": errors, "frames": frames}


_AFSK_SEEN = {}


def afsk_text(data: bytes):
    """{mode: text} for every modem in AFSK_MODES whose decode of this WAV is text: at least 8
    bytes, nine in ten printable ASCII (or CR, LF, tab), and framing errors under a tenth of the
    frames. Non-printable bytes are dropped from the text."""
    import hashlib
    key = hashlib.sha256(data).digest()
    if key in _AFSK_SEEN:               # signals, solve_set and the triage all ask about the same bytes
        return dict(_AFSK_SEEN[key])
    samples, rate = wav_samples(data)
    out = {}
    if len(_AFSK_SEEN) >= 8:
        _AFSK_SEEN.clear()
    _AFSK_SEEN[key] = out
    if samples is None:
        return out
    probe = int(rate * 10)
    for mode, (baud, mark, space) in AFSK_MODES.items():
        if len(samples) > probe * 3:    # a long recording: a mode is run whole only when a 10 s window shows bytes
            mid = len(samples) // 2
            seen = [afsk_decode(samples[a:a + probe], rate, baud, mark, space) for a in (0, mid - probe // 2, len(samples) - probe)]
            if not any(r and len(r["bytes"]) >= 8 and r["framing_errors"] * 4 <= r["frames"] for r in seen):
                continue
        r = afsk_decode(samples, rate, baud, mark, space)
        if not r or len(r["bytes"]) < 8 or r["framing_errors"] * 10 > r["frames"]:
            continue
        good = bytes(c for c in r["bytes"] if 32 <= c < 127 or c in (9, 10, 13))
        if len(good) * 10 >= len(r["bytes"]) * 9:
            out[mode] = good.decode("ascii").replace("\r\n", "\n").replace("\r", "\n").strip()
    return out


# ---- magstripe ----------------------------------------------------------------------------------------

TRACK1 = re.compile(r"%([A-Z])(\d{8,19})\^([^^?]{2,26})\^(\d{4}|\^)(\d{3}|\^)([^?^]*)\?")
TRACK2 = re.compile(r";(\d{8,19})=(\d{4}|=)(\d{3}|=)(\d*)\?")


def magstripe_text(text):
    """Tracks found in text: [{track, pan, name (track 1), expiry (YYMM), service_code,
    discretionary, luhn}]."""
    text = _text(text) if not isinstance(text, str) else text
    if not text:
        return []
    out = []
    for m in TRACK1.finditer(text):
        out.append({"track": 1, "raw": m.group(0), "format_code": m.group(1), "pan": m.group(2), "name": m.group(3).strip(),
                    "expiry": None if m.group(4) == "^" else m.group(4), "service_code": None if m.group(5) == "^" else m.group(5),
                    "discretionary": m.group(6), "luhn": luhn(m.group(2))})
    for m in TRACK2.finditer(text):
        out.append({"track": 2, "raw": m.group(0), "pan": m.group(1), "expiry": None if m.group(2) == "=" else m.group(2),
                    "service_code": None if m.group(3) == "=" else m.group(3), "discretionary": m.group(4), "luhn": luhn(m.group(1))})
    return out


def _track_from(bits, width, base, start, end):
    """One direction: characters of `width` bits (LSB first, odd parity last) from the start
    sentinel to the end sentinel, then the LRC. (text, lrc_ok) or None."""
    n = width - 1

    def char(i):
        chunk = bits[i:i + width]
        if len(chunk) < width or chunk.count("1") % 2 != 1:
            return None
        return int(chunk[:n][::-1], 2)
    s_bits = format(start, f"0{n}b")[::-1]
    s_bits += "0" if s_bits.count("1") % 2 else "1"
    i = bits.find(s_bits)
    while i >= 0:
        vals, j = [], i
        while True:
            v = char(j)
            if v is None:
                vals = None
                break
            vals.append(v)
            j += width
            if v == end and len(vals) > 1:
                break
        if vals:
            lrc_ok = None
            chunk = bits[j:j + width]
            if len(chunk) == width:
                x = 0
                for v in vals:
                    x ^= v
                lrc_ok = int(chunk[:n][::-1], 2) == x and chunk.count("1") % 2 == 1
            return "".join(chr(v + base) for v in vals), lrc_ok
        i = bits.find(s_bits, i + 1)
    return None


def magstripe_bits(bits: str):
    """Tracks decoded from a bit string, read forwards and backwards: [{encoding ('5bit' is track 2
    and 3 BCD, '7bit' is track 1 alpha), direction, text, lrc_ok}]. Every character's odd parity
    must hold from the start sentinel to the end sentinel."""
    bits = re.sub(r"[^01]", "", bits)
    out = []
    for direction, b in (("forward", bits), ("reverse", bits[::-1])):
        for enc, width, base, start, end in (("5bit", 5, 0x30, 0x0B, 0x0F), ("7bit", 7, 0x20, 0x05, 0x1F)):
            got = _track_from(b, width, base, start, end)
            if got and len(got[0]) >= 4:
                out.append({"encoding": enc, "direction": direction, "text": got[0], "lrc_ok": got[1]})
    return out


# ---- 125 kHz ids -----------------------------------------------------------------------------------------

def em4100_bits(bits: str):
    """The 5 data bytes of an EM4100 frame in a bit string of 64 or more bits (any rotation): nine
    header ones, ten rows of four data bits with even row parity, four column parity bits, a stop
    zero. None unless exactly one rotation checks out."""
    bits = re.sub(r"[^01]", "", bits)
    if len(bits) < 64:
        return None
    found = set()
    ring = bits if len(bits) > 64 else bits + bits
    for off in range(len(ring) - 63):
        f = ring[off:off + 64]
        if f[:9] != "1" * 9 or f[63] != "0":
            continue
        rows = [f[9 + r * 5:14 + r * 5] for r in range(10)]
        if any(r.count("1") % 2 for r in rows):
            continue
        cols = f[59:63]
        if any((sum(int(r[c]) for r in rows) + int(cols[c])) % 2 for c in range(4)):
            continue
        nib = [int(r[:4], 2) for r in rows]
        found.add(bytes(nib[i] << 4 | nib[i + 1] for i in range(0, 10, 2)))
    return next(iter(found)) if len(found) == 1 else None


WIEGAND = {26: ("H10301", 1, 8, 9, 16, (0, 1, 13), (25, 13, 25)), 34: ("H10306", 1, 16, 17, 16, (0, 1, 17), (33, 17, 33)),
           37: ("H10304", 1, 16, 17, 19, (0, 1, 19), (36, 18, 36)), 35: ("Corporate 1000", 2, 12, 14, 20, None, None)}


def wiegand(bits: str):
    """A Wiegand credential by its length: {format, facility_code, card_number, parity_ok} for 26
    (H10301), 34 (H10306) and 37 (H10304) bits, with the leading even and trailing odd parity
    checked; 35 bits (Corporate 1000) gives the fields with parity_ok None. None for other lengths."""
    bits = re.sub(r"[^01]", "", bits)
    spec = WIEGAND.get(len(bits))
    if not spec:
        return None
    name, fs, fl, cs, cl, even, odd = spec
    ok = None
    if even:
        ok = (bits[even[1]:even[2]].count("1") + int(bits[even[0]])) % 2 == 0 \
            and (bits[odd[1]:odd[2]].count("1") + int(bits[odd[0]])) % 2 == 1
    return {"format": name, "bits": len(bits), "facility_code": int(bits[fs:fs + fl], 2), "card_number": int(bits[cs:cs + cl], 2),
            "parity_ok": ok}


# ---- firmware text: Intel HEX and S-records ----------------------------------------------------------------

def _image(mem: dict):
    """(lowest address, the bytes from there with gaps filled 0xFF, number of data bytes)."""
    if not mem:
        return None, b"", 0
    lo, hi = min(mem), max(mem)
    if hi - lo > 16 * 1024 * 1024:
        return lo, b"", len(mem)
    return lo, bytes(mem.get(a, 0xFF) for a in range(lo, hi + 1)), len(mem)


def ihex_parse(text):
    """Intel HEX: {records, data_records, bad_checksums, eof, start_address, base_address, data_size
    (bytes in data records), image (from base_address, gaps 0xFF), contiguous}. None when a line is
    not a record."""
    text = _text(text) if not isinstance(text, str) else text
    if not text:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    mem, upper, bad, start, eof, ndata = {}, 0, 0, None, False, 0
    for ln in lines:
        if not re.fullmatch(r":(?:[0-9A-Fa-f]{2}){5,}", ln):
            return None
        b = bytes.fromhex(ln[1:])
        n, addr, typ = b[0], b[1] << 8 | b[2], b[3]
        if len(b) != n + 5:
            return None
        if sum(b) & 0xFF:
            bad += 1
        d = b[4:4 + n]
        if typ == 0:
            ndata += 1
            for i, x in enumerate(d):
                mem[upper + addr + i] = x
        elif typ == 1:
            eof = True
        elif typ == 2 and n == 2:
            upper = int.from_bytes(d, "big") << 4
        elif typ == 4 and n == 2:
            upper = int.from_bytes(d, "big") << 16
        elif typ == 3 and n == 4:
            start = (int.from_bytes(d[:2], "big") << 4) + int.from_bytes(d[2:], "big")
        elif typ == 5 and n == 4:
            start = int.from_bytes(d, "big")
    lo, image, size = _image(mem)
    return {"format": "ihex", "records": len(lines), "data_records": ndata, "bad_checksums": bad, "eof": eof,
            "start_address": start, "base_address": lo, "data_size": size, "image": image, "contiguous": size == len(image)}


def srec_parse(text):
    """Motorola S-records: the same facts as ihex_parse, plus `header` (the S0 text). None when a
    line is not a record."""
    text = _text(text) if not isinstance(text, str) else text
    if not text:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    mem, bad, start, header, ndata, eof = {}, 0, None, None, 0, False
    alen = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}
    for ln in lines:
        m = re.fullmatch(r"S([0-35-9])((?:[0-9A-Fa-f]{2}){3,})", ln)
        if not m:
            return None
        b = bytes.fromhex(m.group(2))
        if b[0] != len(b) - 1:
            return None
        if (sum(b) & 0xFF) != 0xFF:
            bad += 1
        a = alen[m.group(1)]
        if len(b) < 1 + a + 1:
            return None
        addr, d = int.from_bytes(b[1:1 + a], "big"), b[1 + a:-1]
        if m.group(1) == "0":
            header = d.decode("latin-1").rstrip("\x00")
        elif m.group(1) in "123":
            ndata += 1
            for i, x in enumerate(d):
                mem[addr + i] = x
        elif m.group(1) in "789":
            start, eof = addr, True
    lo, image, size = _image(mem)
    return {"format": "srec", "records": len(lines), "data_records": ndata, "bad_checksums": bad, "eof": eof, "header": header,
            "start_address": start, "base_address": lo, "data_size": size, "image": image, "contiguous": size == len(image)}


# ---- bus captures -------------------------------------------------------------------------------------------

CAN_LOG = re.compile(r"\((\d+(?:\.\d+)?)\)\s+(\S+)\s+([0-9A-Fa-f]{3,8})#(#?[0-9A-Fa-f]*|R\d?)\s*$")
CAN_CONSOLE = re.compile(r"\s*(?:\((\d+(?:\.\d+)?)\)\s+)?(\S+)\s+([0-9A-Fa-f]{3,8})\s+\[(\d+)\]((?:\s+[0-9A-Fa-f]{2})*)\s*$")


CAN_ASC = re.compile(r"\s*(\d+\.\d+)\s+(\d+)\s+([0-9A-Fa-f]{1,8})(x?)\s+(?:Rx|Tx)\s+d\s+([0-9A-Fa-f]{1,2})((?:\s+[0-9A-Fa-f]{2})*)(?:\s+\S.*)?$")


def can_asc_parse(text):
    """A Vector ASC log (`date`, `base hex|dec`, then `<time> <channel> <id>[x] Rx|Tx d <dlc> <bytes>`):
    the same table as can_parse plus 'other' (event lines that are no data frame: status,
    statistics, error and remote frames, CAN FD, J1939TP) and 'base'. None unless the header names
    a base and three data frames or more are read."""
    head = re.search(r"^\s*base\s+(hex|dec)\b", text[:2000], re.M | re.I)
    if not head:
        return None
    base = 16 if head.group(1).lower() == "hex" else 10
    frames, other = [], 0
    for ln in text.splitlines():
        m = CAN_ASC.match(ln)
        if not m:
            other += bool(re.match(r"\s*\d+\.\d+\s+\S", ln))
            continue
        try:
            ident, dlc = int(m.group(3), base), int(m.group(5), base)
            data = bytes(int(x, base) for x in m.group(6).split())
        except ValueError:
            other += 1
            continue
        if len(data) != min(dlc, 8):
            other += 1
            continue
        frames.append({"ts": float(m.group(1)), "iface": m.group(2), "id": ident, "data": data, "extended": bool(m.group(4))})
    if len(frames) < 3:
        return None
    ids = {}
    for f in frames:
        ids[f["id"]] = ids.get(f["id"], 0) + 1
    return {"frames": frames, "ids": ids, "lines": len(frames) + other, "other": other, "format": "asc", "base": base}


def can_parse(text):
    """candump output, log form `(ts) can0 123#DEADBEEF` or console form `can0  123   [4]  DE AD BE
    EF`: {frames: [{ts, iface, id, data}], ids: {id: count}}. None unless at least three lines and
    nine in ten of the non-empty ones are frames."""
    text = _text(text) if not isinstance(text, str) else text
    if not text:
        return None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    frames = []
    for ln in lines:
        m = CAN_LOG.match(ln.strip())
        if m:
            payload = m.group(4)        # DEADBEEF, R (remote request), or #<flags><data> for CAN FD
            body = "" if payload.startswith("R") else payload[2:] if payload.startswith("#") else payload
            if len(body) % 2:
                continue
            data = bytes.fromhex(body)
            frames.append({"ts": float(m.group(1)), "iface": m.group(2), "id": int(m.group(3), 16), "data": data})
            continue
        m = CAN_CONSOLE.match(ln)
        if m:
            data = bytes.fromhex(m.group(5).replace(" ", ""))
            if len(data) == int(m.group(4)):
                frames.append({"ts": float(m.group(1)) if m.group(1) else None, "iface": m.group(2), "id": int(m.group(3), 16),
                               "data": data})
    if len(frames) < 3 or len(frames) * 10 < len(lines) * 9:
        return None
    ids = {}
    for f in frames:
        ids[f["id"]] = ids.get(f["id"], 0) + 1
    return {"frames": frames, "ids": ids, "lines": len(lines)}


def logic_csv(text):
    """A sampled logic capture as CSV with a header: {'columns': {lowercase name: [values]},
    'time': [seconds] or None}. A time column is one named time, t, timestamp or seconds (with an
    optional unit in brackets). None when there is no header or a cell is not a number."""
    text = _text(text) if not isinstance(text, str) else text
    if not text or "," not in text[:4096] and ";" not in text[:4096] and "\t" not in text[:4096]:
        return None
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = [r for r in csv.reader(io.StringIO(text), dialect) if r and any(c.strip() for c in r)]
    if len(rows) < 4:
        return None
    head = [re.sub(r"\s*[\[(].*?[\])]", "", c).strip().lower() for c in rows[0]]
    if not all(h and not re.fullmatch(r"[-+0-9.eE]+", h) for h in head):
        return None
    cols = {h: [] for h in head}
    if len(cols) != len(head):
        return None
    for r in rows[1:]:
        if len(r) != len(head):
            return None
        for h, c in zip(head, r):
            try:
                cols[h].append(float(c))
            except ValueError:
                return None
    tname = next((h for h in head if h in ("time", "t", "timestamp", "seconds", "time_s", "time_us", "time_ms")), None)
    scale = 1.0
    if tname is not None:
        original = rows[0][head.index(tname)]
        m = re.search(r"[\[(]\s*([^\])]+?)\s*[\])]", original)
        token = (m.group(1) if m else tname.rsplit("_", 1)[-1]).strip().lower()
        scale = {"us": 1e-6, "µs": 1e-6, "ms": 1e-3, "ns": 1e-9}.get(token, 1.0)
    time = [v * scale for v in cols.pop(tname)] if tname is not None else None
    return {"columns": cols, "time": time}


def _column(cols, *names):
    return next((cols[n] for n in names if n in cols), None)


BAUDS = (300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 28800, 38400, 57600, 115200, 230400, 460800, 921600, 1000000)


def uart_decode(levels, time=None, baud=None, inverted=False):
    """8N1, LSB first, idle high (idle low with inverted=True) from sampled levels. `time` gives the
    seconds of each sample (else the sample index is the clock and the bit time is in samples).
    The bit time is the shortest run between two edges unless `baud` is given. Returns {bytes,
    framing_errors, bit_time, baud (snapped to a standard rate within 8 percent, else None)}."""
    lv = [1 if (v > 0.5) != inverted else 0 for v in levels]
    t = list(time) if time is not None else list(range(len(lv)))
    if len(lv) < 20 or len(t) != len(lv):
        return None
    edges = [i for i in range(1, len(lv)) if lv[i] != lv[i - 1]]
    if len(edges) < 2:
        return None
    bit = 1.0 / baud if baud and time is not None else min(t[b] - t[a] for a, b in zip(edges, edges[1:]))
    if bit <= 0:
        return None
    import bisect

    def at(when):
        i = bisect.bisect_right(t, when) - 1
        return lv[max(0, min(i, len(lv) - 1))]
    out, errors, i, end = bytearray(), 0, 0, t[-1]
    while i < len(edges):
        e = edges[i]
        if lv[e] != 0:
            i += 1
            continue
        t0 = t[e]
        if t0 + 9.5 * bit > end + bit:
            break
        val = 0
        for k in range(8):
            val |= at(t0 + (1.5 + k) * bit) << k
        if at(t0 + 9.5 * bit) != 1:
            errors += 1
        else:
            out.append(val)
        stop = t0 + 9.5 * bit
        while i < len(edges) and t[edges[i]] <= stop:
            i += 1
    rate = None
    if time is not None:
        raw = 1.0 / bit
        rate = next((b for b in BAUDS if abs(raw - b) <= 0.08 * b), None)
    return {"bytes": bytes(out), "framing_errors": errors, "bit_time": bit, "baud": rate}


def i2c_decode(scl, sda):
    """I2C transactions from sampled SCL and SDA: [{address (7 bits), rw ('r'/'w'), data, acks}].
    A start is SDA falling while SCL is high, a stop SDA rising while SCL is high, a bit is SDA at
    SCL's rising edge."""
    out, cur, bits = [], None, []
    if not scl or not sda:
        return []
    ps, pd = (1 if scl[0] > 0.5 else 0), (1 if sda[0] > 0.5 else 0)
    for a, b in zip(scl[1:], sda[1:]):
        s, d = (1 if a > 0.5 else 0), (1 if b > 0.5 else 0)
        if s and ps and pd and not d:
            cur, bits = {"address": None, "rw": None, "data": bytearray(), "acks": []}, []
            out.append(cur)
        elif s and ps and not pd and d:
            cur, bits = None, []
        elif s and not ps and cur is not None:
            bits.append(d)
            if len(bits) == 9:
                val = int("".join(map(str, bits[:8])), 2)
                if cur["address"] is None:
                    cur["address"], cur["rw"] = val >> 1, "r" if val & 1 else "w"
                else:
                    cur["data"].append(val)
                cur["acks"].append(bits[8] == 0)
                bits = []
        ps, pd = s, d
    for tr in out:
        tr["data"] = bytes(tr["data"])
    return [tr for tr in out if tr["address"] is not None]


def spi_decode(clk, mosi=None, miso=None, cs=None):
    """SPI mode 0 bytes (sampled on the rising clock edge, MSB first, while CS is low when a CS
    column is given): {'mosi': bytes, 'miso': bytes}."""
    acc = {"mosi": [], "miso": []}
    out = {"mosi": bytearray(), "miso": bytearray()}
    if not clk or any(col is not None and len(col) != len(clk) for col in (mosi, miso, cs)):
        return {k: bytes(v) for k, v in out.items()}
    pc = 1 if clk[0] > 0.5 else 0
    for i in range(1, len(clk)):
        c = 1 if clk[i] > 0.5 else 0
        if cs is not None and cs[i] > 0.5:
            acc = {"mosi": [], "miso": []}
        elif c and not pc:
            for name, col in (("mosi", mosi), ("miso", miso)):
                if col is None:
                    continue
                acc[name].append("1" if col[i] > 0.5 else "0")
                if len(acc[name]) == 8:
                    out[name].append(int("".join(acc[name]), 2))
                    acc[name] = []
        pc = c
    return {k: bytes(v) for k, v in out.items()}


def spi_transactions(clk, mosi=None, miso=None, cs=None, *, max_transactions=100000):
    """SPI mode-0 bytes split at chip-select boundaries.

    ``spi_decode`` intentionally returns one flat stream for the legacy fact reader.  Flash-command
    reconstruction needs the CS framing as well, so this companion returns
    ``[{mosi: bytes, miso: bytes, complete: bool}, ...]``.  It is still a sampled-logic decoder:
    no bus/device access occurs, partial trailing bytes are discarded, and output is capped.
    """
    try:
        count = len(clk)
    except TypeError:
        return []
    if count < 2 or any(col is not None and len(col) != count for col in (mosi, miso, cs)):
        return []
    if not isinstance(max_transactions, int) or not 1 <= max_transactions <= 100000:
        return []
    active = cs is None or cs[0] <= 0.5
    current = {"mosi_bits": [], "miso_bits": []}
    result = []
    previous_clock = 1 if clk[0] > 0.5 else 0

    def finish(complete=True):
        nonlocal current
        if current["mosi_bits"] or current["miso_bits"]:
            result.append({
                "mosi": bytes(int("".join(current["mosi_bits"][i:i + 8]), 2)
                              for i in range(0, len(current["mosi_bits"]) - 7, 8)),
                "miso": bytes(int("".join(current["miso_bits"][i:i + 8]), 2)
                              for i in range(0, len(current["miso_bits"]) - 7, 8)),
                "complete": bool(complete and len(current["mosi_bits"]) % 8 == 0
                                 and len(current["miso_bits"]) % 8 == 0),
            })
        current = {"mosi_bits": [], "miso_bits": []}

    for i in range(1, count):
        selected = cs is None or cs[i] <= 0.5
        if not active and selected:
            active = True
            current = {"mosi_bits": [], "miso_bits": []}
        elif active and not selected:
            finish(True)
            if len(result) >= max_transactions:
                return result
            active = False
        clock = 1 if clk[i] > 0.5 else 0
        if active and clock and not previous_clock:
            if mosi is not None:
                current["mosi_bits"].append("1" if mosi[i] > 0.5 else "0")
            if miso is not None:
                current["miso_bits"].append("1" if miso[i] > 0.5 else "0")
        previous_clock = clock
    if active:
        finish(cs is None)
    return result[:max_transactions]


def logic_info(text):
    """What a logic CSV decodes to, by its column names: {'uart': ..., 'i2c': [...], 'spi': {...}}
    for the buses whose columns are there; None when it is no logic capture."""
    lc = logic_csv(text)
    if not lc:
        return None
    cols, out = lc["columns"], {}
    for c in cols.values():
        if any(v not in (0.0, 1.0) for v in c[:2000]):
            return None
    scl, sda = _column(cols, "scl", "i2c_scl"), _column(cols, "sda", "i2c_sda")
    if scl and sda:
        out["i2c"] = i2c_decode(scl, sda)
    clk = _column(cols, "clk", "sck", "sclk", "clock")
    mosi, miso = _column(cols, "mosi", "sdo", "copi"), _column(cols, "miso", "sdi", "cipo")
    if clk and (mosi or miso):
        out["spi"] = spi_decode(clk, mosi, miso, _column(cols, "cs", "ss", "ncs", "csn", "enable"))
    line = _column(cols, "uart", "tx", "rx", "txd", "rxd", "serial", "uart_tx", "uart_rx")
    if line:
        u = uart_decode(line, lc["time"])
        if u:
            out["uart"] = u
    return out or None


# ---- what a file is, and its facts -----------------------------------------------------------------------------

def classify(name: str, data: bytes):
    """(shape, parsed) of one file: sub, nfc, rfid, ir, ibutton (Flipper files), mfc (a MIFARE
    Classic dump whose checks hold), iq, wav, magstripe, ihex, srec, can, logic; (None, None) for
    anything else."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None, None
    fmt = iq_format(name)
    if fmt:
        return "iq", fmt
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        w = wav_info(bytes(data), envelope=False)
        return ("wav", w) if w else (None, None)
    if len(data) in MFC_SIZES and b"\x00" in data:
        m = mfc_parse(bytes(data))
        if m and m["plausible"]:
            return "mfc", m
    if len(data) > MAX_TEXT:
        return None, None
    head = bytes(data[:64]).lstrip(b"\xef\xbb\xbf \t\r\n")
    if head[:9].lower() == b"filetype:":
        f = flipper_parse(bytes(data))
        if f and f["kind"] in ("sub", "nfc", "rfid", "ir", "ibutton"):
            return f["kind"], f
        return None, None
    text = _text(bytes(data))
    if text is None:
        return None, None
    first = text.lstrip()[:1]
    if first == ":":
        h = ihex_parse(text)
        if h and h["eof"]:
            return "ihex", h
    if first == "S":
        s = srec_parse(text)
        if s and s["data_records"]:
            return "srec", s
    if first in "( " or re.match(r"\s*\S+\s+[0-9A-Fa-f]{3,8}\s+\[", text):
        c = can_parse(text)
        if c:
            return "can", c
    if re.match(r"\s*date\b[^\n]*\n\s*base\s+(?:hex|dec)\b", text[:400], re.I):
        c = can_asc_parse(text)
        if c:
            return "can", c
    tracks = magstripe_text(text) if ("%" in text or ";" in text) and len(text) < 65536 else []
    if tracks:
        return "magstripe", tracks
    if re.match(r"[^\n]*\b(?:scl|sda|mosi|miso|sck|sclk|uart|tx|rx|txd|rxd)\b", text[:300], re.I):
        lg = logic_info(text)
        if lg:
            return "logic", lg
    return None, None


FLAG_RX = flagfmt.TEXT


class Fact:
    """One proven fact in every spelling offered: options [(method, value)], best first. kind is
    'int' (one decimal spelling), 'hex' (bytes; case, separator and prefix are the methods),
    'freq' (Hz, kHz, MHz), 'text' (as read; its case is the method) or 'label' (names of one fact)."""
    __slots__ = ("kind", "options", "shape", "soft")

    def __init__(self, kind, options, shape, soft=False):
        self.soft = soft                # True: a reading, not a judged fact; never answered plain
        seen, opts = set(), []
        for n, v in options:
            if v is None or v in seen:
                continue
            seen.add(v)
            opts.append((n, v))
        self.kind, self.options, self.shape = kind, opts, shape


def hex_options(b: bytes):
    lo, sp = b.hex(), " ".join(f"{x:02x}" for x in b)
    return [("lower", lo), ("upper", lo.upper()), ("upper_spaced", sp.upper()), ("lower_spaced", sp),
            ("upper_colon", sp.upper().replace(" ", ":")), ("lower_colon", sp.replace(" ", ":")),
            ("0x_lower", "0x" + lo), ("0x_upper", "0x" + lo.upper())]


def _snake(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s).lower()).strip("_")


def _f_int(v, shape):
    return None if v is None else Fact("int", [("decimal", str(v))], shape)


def _f_hex(b, shape):
    return None if not b else Fact("hex", hex_options(bytes(b)), shape)


def _f_padded(b, shape):
    """Bytes a Flipper file pads with zero bytes (an .ir address or command is written as four):
    the bytes without the padding first, then as written. Which one is meant is not judged."""
    if not b:
        return None
    short = bytes(b).rstrip(b"\x00") or bytes(b)[:1]
    if short == bytes(b):
        return _f_hex(b, shape)
    return Fact("hex", [("short_" + n, v) for n, v in hex_options(short)] + hex_options(bytes(b)), shape)


def _f_text(s, shape):
    if s is None or not str(s).strip():
        return None
    s = str(s).strip()
    return Fact("text", [("as_read", s), ("lower", s.lower()), ("snake", _snake(s)), ("upper", s.upper())], shape)


def _f_freq(hz, shape):
    if not hz:
        return None
    mhz = hz / 1e6
    short = f"{mhz:.6f}".rstrip("0").rstrip(".")
    return Fact("freq", [("hz", str(hz)), ("mhz", short), ("mhz_2dp", f"{mhz:.2f}"), ("mhz_3dp", f"{mhz:.3f}"),
                         ("mhz_unit", f"{short} MHz"), ("mhz_unit_tight", f"{short}MHz"),
                         ("khz", f"{hz / 1e3:.3f}".rstrip("0").rstrip("."))], shape)


MODULATION_NAMES = {"ook": ["ook", "ask", "am", "on_off_keying", "ask_ook"], "2fsk": ["2fsk", "fsk", "2_fsk", "fm", "frequency_shift_keying"],
                    "gfsk": ["gfsk", "fsk"], "msk": ["msk"]}


def _ndef_facts(messages, shape, out):
    flat = ndef_flat(messages)
    if not messages:
        return
    out["ndef_count"] = _f_int(len(messages[0]) if len(messages) == 1 else None, shape)
    uris = [r["uri"] for r in flat if "uri" in r]
    texts = [r for r in flat if "text" in r]
    if len(set(uris)) == 1:
        out["ndef_uri"] = Fact("text", [("as_read", uris[0])], shape)
    if len({r["text"] for r in texts}) == 1:
        out["ndef_text"] = Fact("text", [("as_read", texts[0]["text"])], shape)
        if len({r["lang"] for r in texts}) == 1:
            out["ndef_lang"] = Fact("text", [("as_read", texts[0]["lang"])], shape)
    top = messages[0] if len(messages) == 1 else []
    many = len(top) > 1                 # "record 1" of several: counted from 1 here, which is not judged
    for i, r in enumerate(top, 1):
        if "uri" in r:
            out[f"ndef_uri:{i}"] = Fact("text", [("as_read", r["uri"])], shape, soft=many)
        if "text" in r:
            out[f"ndef_text:{i}"] = Fact("text", [("as_read", r["text"])], shape, soft=many)
        out[f"ndef_type:{i}"] = Fact("text", [("as_read", r["type"])], shape, soft=many) if r["type"] else None
    if len(top) == 1 and top[0]["type"]:
        out["ndef_type"] = Fact("text", [("as_read", top[0]["type"])], shape)


def _f_access(sec, shape, alone=True):
    """A trailer's access bytes: the three access bytes, then the four with the user byte (many
    tools print FF078069). Two readings, so a stated hex form alone never makes it plain; where the
    user byte is unknown or differs between the sectors the three bytes are offered, never plain."""
    opts = hex_options(sec["access"])
    if sec.get("gpb") is not None:
        opts += [("gpb_" + n, v) for n, v in hex_options(sec["access"] + bytes([sec["gpb"]]))]
        return Fact("hex", opts, shape)
    return Fact("hex", opts, shape, soft=True)


def _mfc_facts(m, shape, out):
    out["sector_count"] = _f_int(m["sector_count"], shape)
    out["block_count"] = _f_int(m["block_count"], shape)
    out.setdefault("uid", _f_hex(m["uid"], shape))
    out.setdefault("sak", _f_hex(m["sak"], shape))
    if m["atqa"] and "atqa" not in out:        # block 0 stores it low byte first; the number is read high byte first
        out["atqa"] = Fact("hex", [("be_" + n, v) for n, v in hex_options(m["atqa"][::-1])]
                           + [("stored_" + n, v) for n, v in hex_options(m["atqa"])], shape)
    if m["bcc_ok"]:
        out["bcc"] = _f_hex(bytes([m["bcc"]]), shape)
    for s in m["sectors"]:
        n = s["sector"]
        out[f"key_a:{n}"] = _f_hex(s["key_a"], shape)
        out[f"key_b:{n}"] = _f_hex(s["key_b"], shape)
        if s["access_ok"]:
            out[f"access:{n}"] = _f_access(s, shape)
        for i, row in enumerate(s["blocks"]):
            if _whole(row):
                out[f"block:{s['first'] + i}"] = _f_hex(bytes(row), shape)
    for blk, v in m["values"].items():
        out[f"value:{blk}"] = _f_int(v["value"], shape)
    if len(m["values"]) == 1:
        (blk, v), = m["values"].items()
        out["value"], out["value_block"] = _f_int(v["value"], shape), _f_int(blk, shape)
    out["value_block_count"] = _f_int(len(m["values"]), shape)
    for which in ("key_a", "key_b", "access"):
        keys = {s[which] if which != "access" or s["access_ok"] else None for s in m["sectors"]}
        if len(keys) == 1 and None not in keys:
            out[which] = _f_hex(next(iter(keys)), shape)
            if which == "access":
                out[which] = _f_access(m["sectors"][0], shape) if len({s["gpb"] for s in m["sectors"]}) == 1 else \
                    _f_access({"access": m["sectors"][0]["access"], "gpb": None}, shape, alone=False)
    _ndef_facts(m["ndef"], shape, out)


def facts(name: str, data: bytes) -> dict:
    """{field: Fact} of one file, {} when it is none of this toolkit's. Fields with an index are
    'key_a:3' (sector), 'block:5', 'value:6', 'page:4', 'ndef_uri:1' (record, from 1); a field of
    one of several IR signals is 'address@<name>'."""
    shape, p = classify(name, data)
    out = {}
    if shape is None:
        return out
    if shape == "sub":
        s = sub_info(p)
        out["frequency"] = _f_freq(s["frequency"], shape)
        out["preset"] = _f_text(s["preset"], shape)
        out["protocol"] = _f_text(s["protocol"], shape)
        if s["modulation"]:
            out["modulation"] = Fact("label", [(n, n) for n in MODULATION_NAMES[s["modulation"]]], f"sub.{s['modulation']}")
        out["bit"] = _f_int(s["bit"], shape)
        out["te"] = _f_int(s["te"], shape)
        if s["key"]:
            k = s["key"]
            opts = []
            if s["bit"] and 0 < s["bit"] <= len(k) * 8 and not int.from_bytes(k, "big") >> s["bit"]:
                short = k[len(k) - (s["bit"] + 7) // 8:]
                opts += [("bits_" + n, v) for n, v in hex_options(short)]
            out["key"] = Fact("hex", opts + hex_options(k), shape)
        if s["timings"]:
            if not s["timings_cut"]:
                out["timing_count"] = _f_int(len(s["timings"]), shape)
                out["pulse_count"] = _f_int(sum(1 for t in s["timings"] if t > 0), shape)
            texts = text_readings(s["timings"])
            if len(texts) == 1:         # named by its reading, and never plain: a decoding is not a judged fact
                (txt, how), = texts.items()
                out["message"] = Fact("text", [(how[0], txt)], shape + ".raw", soft=True)
    elif shape == "nfc":
        n = nfc_info(p)
        out["device_type"] = _f_text(n["device_type"], shape)
        out["uid"], out["sak"] = _f_hex(n["uid"], shape), _f_hex(n["sak"], shape)
        if n["atqa"]:                   # Flipper's file versions differ in the byte order: as written, then swapped
            a = n["atqa"]
            out["atqa"] = Fact("hex", hex_options(a) + ([("swapped_" + x, v) for x, v in hex_options(a[::-1])] if a[::-1] != a else []), shape)
        if n["uid"]:
            out["uid_length"] = _f_int(len(n["uid"]), shape)
        out["mifare_type"] = _f_text(n["mifare_type"], shape)
        if n["mfc"]:
            m = dict(n["mfc"])
            if n["uid"] and m["uid"] and m["uid"] != n["uid"][:4] and len(n["uid"]) == 4:
                out["uid"] = None                   # the header and block 0 disagree: no proven UID
            _mfc_facts(m, shape, out)
        if n["pages"]:
            if n["pages_total"] in (None, len(n["pages"])):         # the header and the listing agree
                out["page_count"] = _f_int(len(n["pages"]), shape)
            for i, b in n["pages"].items():
                out[f"page:{i}"] = _f_hex(b, shape)
            _ndef_facts(n["ndef"], shape, out)
    elif shape == "mfc":
        out["card_type"] = Fact("label", [(x, x) for x in {"mini": ["mifare_classic_mini", "mini"], "1k": ["mifare_classic_1k", "1k", "1K"],
                                                             "4k": ["mifare_classic_4k", "4k", "4K"]}[p["type"]]], f"mfc.{p['type']}")
        _mfc_facts(p, shape, out)
    elif shape == "rfid":
        r = rfid_info(p)
        out["key_type"] = _f_text(r["key_type"], shape)
        out["data"] = out["key"] = _f_hex(r["data"], shape)
        if r["em4100"]:
            e = r["em4100"]
            out["card_id"] = Fact("text", [("dez10", e["dez10"]), ("decimal", str(e["id32"])), ("dez8", e["dez8"]),
                                           ("dez3_5", e["dez3_5"])], "rfid.em4100")
            out["customer"] = _f_int(e["customer"], "rfid.em4100")
        elif r["card_number"] is not None:
            out["facility_code"], out["card_number"] = _f_int(r["facility_code"], "rfid.h10301"), _f_int(r["card_number"], "rfid.h10301")
    elif shape == "ir":
        sig = ir_info(p)["signals"]
        out["signal_count"] = _f_int(len(sig), shape)
        names = [s.get("name", "") for s in sig]
        for s in sig:
            tag = "" if len(sig) == 1 else "@" + s.get("name", "").strip().lower()
            if len(sig) > 1 and (not s.get("name") or names.count(s["name"]) > 1):
                continue
            out["protocol" + tag] = _f_text(s.get("protocol"), shape)
            out["address" + tag] = _f_padded(s.get("address"), shape)
            out["command" + tag] = _f_padded(s.get("command"), shape)
            out["frequency" + tag] = _f_int(s.get("frequency"), shape)
            out["signal_type" + tag] = _f_text(s.get("type"), shape)
            if len(sig) == 1:
                out["name"] = _f_text(s.get("name"), shape)
    elif shape == "iq":
        width = {"cu8": 2, "cs8": 2, "cs16": 4, "cf32": 8}[p]
        if len(data) % width == 0:
            n = len(data) // width          # a sample is an I/Q pair; the other count is offered, never plain
            out["sample_count"] = Fact("int", [("pairs", str(n)), ("values", str(2 * n))], f"iq.{p}", soft=True)
    elif shape == "wav":
        out["channels"], out["sample_rate"] = _f_int(p["channels"], shape), _f_int(p["sample_rate"], shape)
        if p.get("whole") and p["channels"] == 1:       # the data is all there, and a frame is one sample
            out["sample_count"] = _f_int(p["frames"], shape)
        out["bits_per_sample"] = _f_int(p["bits_per_sample"], shape)
        texts = afsk_text(data) if len(data) <= MAX_IQ * 4 else {}
        if len(set(texts.values())) == 1:           # a demodulation is a reading: never plain
            mode, txt = next(iter(texts.items()))
            flags = set(FLAG_RX.findall(txt))
            opts = ([("flag_" + mode, next(iter(flags)))] if len(flags) == 1 else []) + [(mode, txt)]
            out["message"] = Fact("text", opts, "wav.afsk", soft=True)
    elif shape == "magstripe":
        for field in ("pan", "name", "expiry", "service_code", "discretionary"):
            vals = {t[field] for t in p if t.get(field)}
            if len(vals) != 1:
                continue
            v = next(iter(vals))
            if field == "expiry":
                out[field] = Fact("text", [("yymm", v), ("mm_yy", f"{v[2:]}/{v[:2]}"), ("mmyy", v[2:] + v[:2]),
                                           ("iso", f"20{v[:2]}-{v[2:]}"), ("mm_yyyy", f"{v[2:]}/20{v[:2]}")], shape)
            elif field == "name":
                out[field] = Fact("text", [("as_read", v)], shape)
            else:
                out[field] = Fact("int" if field != "discretionary" else "text", [("as_read", v)], shape)
        if "pan" in out:
            pan = out["pan"].options[0][1]
            out["card_number"] = out["pan"]
            out["luhn"] = Fact("label", [(x, x) for x in (("valid", "true", "yes", "pass") if luhn(pan) else ("invalid", "false", "no", "fail"))],
                               "magstripe." + ("valid" if luhn(pan) else "invalid"))
        out["track_count"] = Fact("int", [("decimal", str(len(p)))], shape, soft=True)     # track 3 is not read here
    elif shape in ("ihex", "srec"):
        if not p["bad_checksums"]:
            out["record_count"] = _f_int(p["records"], shape)
            out["data_record_count"] = _f_int(p["data_records"], shape)
            out["data_size"] = _f_int(p["data_size"], shape)
            for field in ("start_address", "base_address"):
                v = p[field]
                if v is not None:
                    out[field] = Fact("hex", [("0x_lower_8", f"0x{v:08x}"), ("0x_lower", f"0x{v:x}"), ("lower_8", f"{v:08x}"),
                                              ("upper_8", f"{v:08X}"), ("0x_upper_8", f"0x{v:08X}"), ("0x_lower_4", f"0x{v:04x}"),
                                              ("lower", f"{v:x}"), ("upper", f"{v:X}"), ("0x_upper", f"0x{v:X}"),
                                              ("lower_4", f"{v:04x}"), ("upper_4", f"{v:04X}"), ("0x_upper_4", f"0x{v:04X}"),
                                              ("decimal", str(v))], shape)
            if shape == "srec" and p["header"]:
                out["header"] = Fact("text", [("as_read", p["header"])], shape)
    elif shape == "can":
        if len(p["frames"]) == p.get("lines"):          # a line that is no frame leaves the counts unproven
            out["frame_count"] = _f_int(len(p["frames"]), shape)
            out["id_count"] = _f_int(len(p["ids"]), shape)
    elif shape == "logic":
        u = p.get("uart")
        if u and not u["framing_errors"] and printable(u["bytes"]):
            out["message"] = Fact("text", [("as_read", u["bytes"].decode("ascii").strip("\r\n"))], "logic.uart")
            out["baud"] = _f_int(u["baud"], "logic.uart")
        i2c = p.get("i2c") or []
        if i2c and len({t["address"] for t in i2c}) == 1:
            a = i2c[0]["address"]
            out["address"] = Fact("hex", [("0x_lower", f"0x{a:02x}"), ("lower", f"{a:02x}"), ("upper", f"{a:02X}"),
                                          ("0x_upper", f"0x{a:02X}"), ("decimal", str(a))], "logic.i2c")
    out = {k: v for k, v in out.items() if v is not None and v.options}
    tail = p.get("tail") if isinstance(p, dict) and shape in TAIL_FIELDS else None
    if tail:
        names = TAIL_FIELDS[shape].get(re.sub(r"\s+\d+$", "", tail), ())
        last = "@" + sig[-1].get("name", "").strip().lower() if shape == "ir" and sig else ""
        for k, v in out.items():
            base, _, tag = k.partition("@")
            if base.split(":")[0] in names and (shape != "ir" or len(sig) == 1 or "@" + tag == last):
                v.soft = True
    return out


# Which facts hang on which line of a Flipper file (lowercase key, an index removed).
TAIL_FIELDS = {
    "sub": {"frequency": ("frequency",), "preset": ("preset", "modulation"), "protocol": ("protocol",), "bit": ("bit", "key"), "key": ("key",),
            "te": ("te",), "raw_data": ("timing_count", "pulse_count", "message")},
    "nfc": {"uid": ("uid", "uid_length"), "atqa": ("atqa",), "sak": ("sak",), "device type": ("device_type",),
            "mifare classic type": ("mifare_type",), "pages total": ("page_count",)},
    "rfid": {"key type": ("key_type", "card_id", "customer", "facility_code", "card_number"),
             "data": ("data", "key", "card_id", "customer", "facility_code", "card_number")},
    "ir": {k: (k if k != "type" else "signal_type",) for k in ("name", "protocol", "address", "command", "frequency", "type")},
}


# ---- reading a question -------------------------------------------------------------------------------------------

_N = r"#?\s*(\d{1,3})\b"
# (field, pattern over the lowercased question + answer id; a group named n is the index).
# First match wins, so the narrow ones come first. A field the file does not hold is None.
RULES = [
    ("key_a", r"\bkey[\s_]*a\b(?:.*?\bsector\s*" + _N.replace("(", "(?P<n>", 1) + r")?"),
    ("key_b", r"\bkey[\s_]*b\b(?:.*?\bsector\s*" + _N.replace("(", "(?P<n>", 1) + r")?"),
    ("access", r"\baccess[\s_]*(?:bits?|bytes?|conditions?)\b(?:.*?\bsector\s*" + _N.replace("(", "(?P<n>", 1) + r")?"),
    ("value_block_count", r"\bhow many value blocks?\b|\bnumber of value blocks?\b|\bvalue block count\b"),
    ("value_block", r"\bwhich block\b.*\bvalue block\b|\bblock number of the value block\b|\bvalue block (?:number|index)\b"),
    ("value", r"\bvalue\b.*?\bblock\s*" + _N.replace("(", "(?P<n>", 1) + r"|\bvalue block\b|\b(?:balance|credit)\b"),
    ("sector_count", r"\bhow many sectors\b|\bnumber of sectors\b|\bsector count\b"),
    ("block_count", r"\bhow many blocks\b|\bnumber of blocks\b|\bblock count\b"),
    ("page_count", r"\bhow many pages\b|\bnumber of pages\b|\bpage count\b|\bpages total\b"),
    ("block", r"\bblock\s*" + _N.replace("(", "(?P<n>", 1)),
    ("page", r"\bpage\s*" + _N.replace("(", "(?P<n>", 1)),
    ("ndef_count", r"\bhow many (?:ndef )?records\b.*\bndef\b|\bhow many ndef records\b|\bndef record count\b|\bnumber of ndef records\b"),
    ("ndef_lang", r"\bndef\b.*\blanguage\b|\blanguage code\b"),
    ("ndef_uri", r"\b(?:uri|url|link)\b(?:.*?\brecord\s*" + _N.replace("(", "(?P<n>", 1) + r")?"),
    ("ndef_type", r"\brecord type\b|\bndef type\b|\btype of the (?:ndef )?record\b"),
    ("ndef_text", r"\bndef\b.*\b(?:text|message|payload)\b|\btext record\b"),
    ("uid_length", r"\buid\b.*\b(?:length|how many bytes|size|long)\b|\b(?:length|size|how many bytes|how long)\b.*\buid\b"),
    ("uid", r"\buid\b|\bunique id(?:entifier)?\b"),
    ("atqa", r"\batqa\b"), ("sak", r"\bsak\b"), ("bcc", r"\bbcc\b|\bblock check character\b"),
    ("mifare_type", r"\bmifare(?: classic)? type\b"),
    ("device_type", r"\b(?:device|card|tag) type\b|\btype of (?:the )?(?:card|tag|device)\b"),
    ("key_type", r"\bkey type\b"),
    ("facility_code", r"\b(?:facility|site) code\b"),
    ("customer", r"\bcustomer (?:id|code)\b|\bversion (?:byte|number)\b"),
    ("pan", r"\bpan\b|\bprimary account number\b|\baccount number\b"),
    ("card_id", r"\b(?:card|tag|badge|fob) id\b|\bid of the (?:card|tag|badge|fob)\b"),
    ("card_number", r"\b(?:card|badge) number\b"),
    ("name", r"\bcard\s?holder\b|\bname on the card\b|\b(?:button|signal) name\b|\bname of the (?:button|signal)\b"),
    ("expiry", r"\bexpir\w*\b"), ("service_code", r"\bservice code\b"), ("luhn", r"\bluhn\b"),
    ("discretionary", r"\bdiscretionary\b"),
    ("track_count", r"\bhow many tracks\b|\bnumber of tracks\b"),
    ("modulation", r"\bmodulation\b"),
    ("preset", r"\bpreset\b"),
    ("sample_rate", r"\bsampl(?:e|ing) rate\b"),
    ("sample_count", r"\bhow many (?:iq )?(?:samples|frames)\b(?!.*\bcan\b)|\bnumber of (?:iq )?samples\b|\bsample count\b"),
    ("channels", r"\bhow many channels\b|\bnumber of channels\b|\bchannel count\b"),
    ("bits_per_sample", r"\bbits per sample\b|\bbit depth\b"),
    ("frequency", r"\b(?:carrier |centre |center |transmit )?frequency\b(?! deviation| shift| hopping)"),
    ("signal_count", r"\bhow many (?:signals|buttons)\b|\bnumber of (?:signals|buttons)\b"),
    ("signal_type", r"\bsignal type\b"),
    ("protocol", r"\bprotocol\b"),
    ("bit", r"\bbit (?:length|count)\b|\bhow many bits\b|\bnumber of bits\b|\bkey length in bits\b"),
    ("te", r"\bte\b|\btiming element\b|\bbase pulse (?:length|width)\b"),
    ("timing_count", r"\bhow many (?:timings|durations)\b|\bnumber of (?:timings|durations)\b"),
    ("pulse_count", r"\bhow many pulses\b|\bnumber of pulses\b|\bpulse count\b"),
    ("command", r"\bcommand\b"),
    ("address", r"\baddress\b"),
    ("start_address", r"\bentry point\b|\b(?:start|entry|execution) address\b"),
    ("base_address", r"\b(?:base|load|lowest) address\b"),
    ("data_record_count", r"\bhow many data records\b|\bnumber of data records\b"),
    ("record_count", r"\bhow many records\b|\bnumber of records\b|\brecord count\b"),
    ("data_size", r"\bhow many (?:data )?bytes\b.*\b(?:image|firmware|data|payload)\b|\b(?:image|firmware|payload) size\b"),
    ("header", r"\bheader (?:text|string|record)\b|\bs0\b"),
    ("id_count", r"\bhow many (?:distinct|unique|different) (?:can |arbitration )?(?:ids|identifiers)\b"),
    ("frame_count", r"\bhow many (?:can )?(?:frames|messages)\b|\bnumber of (?:can )?(?:frames|messages)\b"),
    ("baud", r"\bbaud\b"),
    ("message", r"\b(?:decoded|transmitted|hidden|secret) (?:message|text|string|payload)\b|\bmessage\b|\bflag\b"),
    ("key", r"\bkey\b(?! type)"),
    ("data", r"\b(?:card|tag|key) data\b"),
]
RULES = [(f, re.compile(rx)) for f, rx in RULES]


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _words(q) -> str:
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    return " ".join((str(q.get("question") or "") + " | " + re.sub(r"[-_./]+", " ", aid)).lower().split())


_NOT_OURS = re.compile(r"\b(?:sha-?\d+|md5|hash|digest|checksum|crc\d*|entropy|file size|size of the file|in bytes)\b")
_COUNT_NOT = re.compile(r"\b(?:that|which|whose|with|without|where|use[sd]?|using|default|valid|invalid|contain\w*|non-?zero|"
                        r"empty|blank|unknown|differ\w*|except|excluding|other than|more|less|than|at least|only|same|"
                        r"readable|writable|locked|unlocked|named|matching)\b")


def wanted(q):
    """(field, index or None) the question asks for by its words and its answer id, or None. A
    question about a hash or a file size is not this toolkit's (solvers/common/triage.py proves
    those), and a count with a condition ("how many sectors use the default key") is not the plain
    count."""
    words = _words(q)
    if _NOT_OURS.search(words) and not re.search(r"\buid\b", words):
        return None
    if re.search(r"\b(?:start|entry|execution) address\b|\bentry point\b", words):
        return "start_address", None
    if re.search(r"\b(?:base|load|lowest) address\b", words):
        return "base_address", None
    for field, rx in RULES:
        m = rx.search(words)
        if not m:
            continue
        n = m.groupdict().get("n")
        if n is None and field in ("key_a", "key_b", "access", "value", "ndef_uri", "ndef_text", "ndef_type"):
            unit = "record" if field.startswith("ndef") else "block" if field == "value" else "sector"
            m2 = re.search(r"\b" + unit + r"\s*" + _N, words)
            n = m2.group(1) if m2 else None
        if field.endswith("_count") and _COUNT_NOT.search(str(q.get("question") or "").lower()):
            return None
        return field, (int(n) if n is not None else None)
    return None


def _fits(q, value: str) -> bool:
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, value) is not None
        except re.error:
            return False
    return True


def enum_options(q) -> list:
    """The answers a question lists as its only choices (solvers/common/triage.py's reading)."""
    f = _fmt(q)
    for key in ("options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            return [str(v) for v in f[key]][:50]
    m = re.search(r"\bone of[:\s]+(.+)$", str(f.get("syntax") or ""), re.I)
    if m:
        return [v.strip(" .`'\"") for v in re.split(r",|\bor\b", m.group(1)) if v.strip(" .`'\"")][:50]
    return []


def _has_pattern(q) -> bool:
    f = _fmt(q)
    return isinstance(f.get("pattern") or f.get("regex"), str) and bool((f.get("pattern") or f.get("regex")).strip())


def _narrow(fact: Fact, text: str):
    """(options the question's words leave, True when the words fix the form completely)."""
    opts = fact.options
    if fact.kind == "hex":
        case = "upper" if re.search(r"\bupper-?\s?case\b|\bcapital", text) else "lower" if re.search(r"\blower-?\s?case\b", text) else None
        sep = "colon" if re.search(r"\bcolons?\b", text) else \
            "none" if re.search(r"\b(?:no|without)\s+(?:spaces?|separators?|delimiters?)\b|\bcontiguous\b|\bunseparated\b", text) else \
            "spaced" if re.search(r"\bspace-?\s?separated\b|\bseparated by (?:single )?spaces?\b|\bwith spaces\b", text) else None
        pre = False if re.search(r"\b(?:no|without|omit\w*)\s+(?:the\s+|a\s+)?(?:leading\s+)?0x\b", text) else \
            True if re.search(r"\b0x", text) else None
        if case:
            # a value with no letter is the same in either case, and is kept under the one name it has
            opts = [o for o in opts if case in o[0] or o[0] == "decimal" or o[1].lower() == o[1].upper()]
        if sep:
            opts = [o for o in opts if ("_" + sep in o[0]) or (sep == "none" and "spaced" not in o[0] and "colon" not in o[0])]
        if pre is not None:
            opts = [o for o in opts if ("0x" in o[0]) == pre]
        opts = [o for o in opts if o[0] != "decimal"] if (case or sep or pre) else opts
        return opts, bool(case and sep and pre is not None)
    if fact.kind == "freq":
        if re.search(r"\b(?:in|as)\s+(?:hz|hertz)\b|\bhertz\b", text) and not re.search(r"\b[mk]hz\b|\bmega|\bkilo", text):
            return [o for o in opts if o[0] == "hz"], True
        if re.search(r"\bmhz\b|\bmegahertz\b", text):
            return [o for o in opts if o[0].startswith("mhz")], False
        if re.search(r"\bkhz\b|\bkilohertz\b", text):
            return [o for o in opts if o[0] == "khz"], False
    return opts, False


def _pick(key: str, options):
    """labels.pick, or the same wire form when labels.py does not know the `rf` lane yet (the value
    is then never sent and never probed: gm.session() strips it, labels.parse reads no options)."""
    if labels is not None:
        try:
            return labels.pick(key, options)
        except ValueError:
            pass
    opts = [[n, v] for n, v in options if n and v is not None][:12]
    return ("??" + json.dumps({"k": key, "o": opts}, separators=(",", ":"))) if opts else None


COUNTING = {"bit", "data_size", "uid_length", "channels", "bits_per_sample"}
# Words a plain count question is made of. Any other word (a condition, a number, a part of the
# file) and the count of the whole file is not known to be what is asked.
_COUNT_WORDS = set("""how many number of the a an is are was were there in on at this that these those it its file dump
    card tag capture log recording image firmware contain contains contained hold holds have has does do did total count
    overall altogether all what whats s give state report as integer decimal digits answer sectors blocks pages records
    ndef value tracks signals buttons samples frames can messages timings durations pulses data distinct unique different
    ids identifiers iq arbitration stored saved present listed recorded captured found appear appears bits bit key long bytes uid length
    size payload mifare classic flipper nfc rfid sub ghz subghz ir infrared remote hex intel srec wav audio candump bus
    per sample depth channels channel and please""".split())
_UNITS = re.compile(r"\b(?:[kmg]hz|kilohertz|megahertz|ms|milliseconds?|percent\w*|dollars?|euros?|cents?|ki?b|mi?b|"
                    r"kilobytes?|megabytes?|words|nibbles|hexadecimal|binary|octal)\b|\b(?:in|as)\s+hex\b|%")
# A question about a part or a property of the value, not the value.
_PART = re.compile(r"\b(?:domain|host(?:name)?|path|scheme|port|tld|subdomain|query|parameter|how many|length|how long|"
                   r"nibble|reversed?|xor|sum|last|first|second|third|middle)\b|\bbytes?\s+#?\d|"
                   r"\bdigits?\s+of\b|(?<!card )(?<!badge )(?<!account )(?<!block )(?<!version )\bnumber of\b")


def _count_is_plain(q) -> bool:
    text = str(q.get("question") or "").lower()
    text = re.sub(r"[\w./-]+\.[a-z][a-z0-9]{0,5}\b", " ", text)      # file names
    return all(w in _COUNT_WORDS for w in re.findall(r"[a-z0-9_]+", text))


def decide(q, field: str, fact: Fact):
    """The answer for one proven fact: plain, unsure, or None (see the module text)."""
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    if kind in ("mitre_attack_id", "ordered_tokens", "json"):
        return None
    text = (str(q.get("question") or "") + " " + str(f.get("syntax") or "")).lower()
    asked = str(q.get("question") or "").lower()
    base = field.split(":")[0].split("@")[0]
    counting = base.endswith("_count") or base in COUNTING
    if counting and not fact.soft and not _count_is_plain(q):
        return None                     # a count with a condition, a part or a number in it
    if not counting and _PART.search(asked):
        return None
    if base in ("block", "value") and re.search(r"\bsector\b", asked):
        return None                     # a block counted inside a sector is not the card's block of that number
    if fact.kind == "int" and _UNITS.search(text):
        return None                     # another unit or base than the one read
    opts, fixed = _narrow(fact, text)
    opts = [(n, v) for n, v in opts if _fits(q, v)]
    listed = enum_options(q)
    if listed:
        opts = [(n, v) for n, v in opts if v in listed]
    if not opts:
        return None
    values = [v for _, v in opts]
    if fact.soft:
        return _pick(f"{KEY}.{field}/{fact.shape}", opts)
    if (_has_pattern(q) or listed) and len(values) == 1:
        return values[0]
    if fixed and len(values) == 1:
        return values[0]
    if fact.kind == "int" and len(values) == 1 and (kind == "integer" or re.search(
            r"\bhow many\b|\bnumber of\b|\binteger\b|\bdecimal\b|\bdigits\b|\bcount\b", text)):
        return values[0]
    return _pick(f"{KEY}.{field}/{fact.shape}", opts)


def _lookup(table: dict, field: str, n, words: str):
    if n is not None:
        return table.get(f"{field}:{n}")
    if field in table:
        return table[field]
    tagged = [k for k in table if k.startswith(field + "@") and re.search(r"(?<![\w])" + re.escape(k.split("@", 1)[1]) + r"(?![\w])", words)]
    return table[tagged[0]] if len(tagged) == 1 else None


# What a capture does NOT hold, another device's value, or arithmetic on a value, is not the field as read.
# An unsure offer on such a question would get the field's names rejected for its key (labels: one key, one fate).
NEGATED = re.compile(r"\bnot\b|n't\b|\bexcept\b|\bexcluding\b|\bother\b|\banother\b|\bneither\b|\bnever\b|\binstead\b"
                     r"|\b(?:twice|double|half|sum of|minus|plus|times|divided|multiplied)\b", re.I)


def answer(q, tables: dict):
    """One question's answer from {file name: {field: Fact}}."""
    want = wanted(q)
    if not want or not tables:
        return None
    if NEGATED.search(" ".join(str(q.get("question") or "").split())):
        return None
    field, n = want
    words = _words(q)
    names = list(tables)
    member = q.get("member")
    if member:
        names = [k for k in names if k.split(ARROW)[-1] in (member, Path(member).name) or Path(k.split(ARROW)[-1]).name == Path(member).name]
    else:
        text = str(q.get("question") or "")
        named = [k for k in names if re.search(r"(?<![\w.-])" + re.escape(Path(k.split(ARROW)[-1]).name) + r"(?![\w-])", text)]
        names = named or names
    found = [f for f in (_lookup(tables[k], field, n, words) for k in names) if f is not None]
    if not found:
        return None
    first = found[0]
    if any(f.options != first.options or f.shape != first.shape for f in found[1:]):
        return None                     # two files answer differently and the question names neither
    return decide(q, field, first)


def tables_of(files: dict) -> dict:
    """{file name: {field: Fact}} for every distinct file of a delivery this toolkit reads."""
    out, seen = {}, []
    for name, data in files.items():
        if not isinstance(data, (bytes, bytearray)) or any(data is s for s in seen):
            continue
        seen.append(data)
        try:
            t = facts(name, bytes(data))
        except Exception:
            t = {}
        if t:
            out[name] = t
    return out


def solve_set(questions, files, ctx) -> dict:
    out = {}
    try:
        tables = tables_of(files)
    except Exception:
        tables = {}
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            out[qid] = answer(q, tables)
        except Exception:           # a fact that cannot be read is no answer
            out[qid] = None
        if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
            ctx["partial"][qid] = out[qid]
    return out


# ---- the category signal --------------------------------------------------------------------------------------------

STRONG_WORDS = re.compile(r"\b(?:mifare|flipper|sub-?ghz|nfc|rfid|ndef|em4100|em410x|hid prox|wiegand|magstripe|mag-?stripe|"
                          r"manchester|key ?fob|proxmark|ntag\d*|rtl[-_ ]?sdr|rtl_433|iq (?:capture|samples|recording)|ook|"
                          r"2?fsk|atqa|can bus|intel hex|s-?record|uart|i2c|spi bus|infrared)\b", re.I)
SHAPE_SCORE = {"sub": 0.95, "nfc": 0.95, "rfid": 0.95, "ir": 0.9, "ibutton": 0.9, "mfc": 0.9, "magstripe": 0.7, "can": 0.6,
               "iq": 0.6, "ihex": 0.5, "srec": 0.5, "logic": 0.5, "wav": 0.1}
EXT_SCORE = {".sub": 0.6, ".nfc": 0.6, ".rfid": 0.6, ".mfd": 0.6, ".ir": 0.3, ".srec": 0.3, ".s19": 0.3}


def signals(questions, files) -> float:
    """0..1: how strongly the delivery and its questions look like an RF / RFID / hardware-capture
    challenge. Cheap: the first bytes and the size of each file, and the words of the questions;
    a WAV of 8 MB or less is also put through the FSK modems (about 0.1 s for 5 s of audio)."""
    best, seen = 0.0, []
    for name, data in (files or {}).items():
        if not isinstance(data, (bytes, bytearray)) or any(data is s for s in seen):
            continue
        seen.append(data)
        tail = name.split(ARROW)[-1]
        best = max(best, EXT_SCORE.get(Path(tail).suffix.lower(), 0.0))
        try:
            shape, _ = classify(name, bytes(data)) if len(data) <= MAX_TEXT or iq_format(name) else (None, None)
        except Exception:
            shape = None
        best = max(best, SHAPE_SCORE.get(shape, 0.0))
        if shape == "wav" and afsk_text(bytes(data)):
            best = max(best, 0.8)       # a recording a modem reads as text is this toolkit's, whatever the question says
    hits = set()
    for q in questions or []:
        f = _fmt(q)
        text = " ".join(str(x or "") for x in (q.get("question"), f.get("syntax"), q.get("answer_id"), q.get("artifact")))
        hits.update(m.group().lower() for m in STRONG_WORDS.finditer(text))
    word = 0.0 if not hits else 0.35 if len(hits) == 1 else 0.5
    if best and word:
        return round(min(1.0, best + 0.05), 2)
    return round(max(best, word), 2)


# ---- the command -------------------------------------------------------------------------------------------------------

def _show_bits(timings, lines, unit="us"):
    te = te_estimate(timings)
    lines.append(f"  timings: {len(timings)} ({sum(1 for t in timings if t > 0)} pulses), TE about {te} {unit}, "
                 f"{len(split_packets(timings, te=te))} packet(s)")
    for name, packets in readings(timings, te).items():
        b = packets[0]
        lines.append(f"  {name}: {len(packets)} packet(s), first {len(b)} bits {b[:96]}{'...' if len(b) > 96 else ''}")
        by = bits_to_bytes(b)
        if by:
            lines.append(f"    hex {by.hex()}" + (f"  ascii {by.decode('ascii')!r}" if printable(by) else ""))
        em = em4100_bits(b)
        if em:
            lines.append(f"    EM4100 frame: {em.hex()} {em4100_bytes(em)}")
        w = wiegand(b)
        if w:
            lines.append(f"    Wiegand: {w}")
        for t in magstripe_bits(b):
            lines.append(f"    magstripe {t}")


def triage(name: str, data: bytes) -> str:
    """A reader's triage of one file."""
    shape, p = classify(name, data)
    lines = [f"== {name}  ({len(data)} bytes)  shape: {shape or 'not an RF/hardware file this toolkit knows'}"]
    if shape == "sub":
        s = sub_info(p)
        lines.append(f"  {s['filetype']}: frequency {s['frequency']} Hz, preset {s['preset']} (modulation {s['modulation']}), "
                     f"protocol {s['protocol']}, bit {s['bit']}, key {s['key'].hex() if s['key'] else None}, TE {s['te']}")
        if s["timings"]:
            _show_bits(s["timings"], lines)
            for text, names in text_readings(s["timings"]).items():
                lines.append(f"  printable reading {text!r} via {', '.join(names)}")
    elif shape == "nfc":
        n = nfc_info(p)
        lines.append(f"  {n['device_type']}: UID {n['uid'].hex() if n['uid'] else None}, ATQA {n['atqa'].hex() if n['atqa'] else None}, "
                     f"SAK {n['sak'].hex() if n['sak'] else None}, type {n['mifare_type']}, {len(n['blocks'])} blocks, {len(n['pages'])} pages")
        if n["mfc"]:
            lines += _mfc_lines(n["mfc"])
        lines += _ndef_lines(n["ndef"])
    elif shape == "mfc":
        lines.append(f"  MIFARE Classic {p['type']} dump")
        lines += _mfc_lines(p) + _ndef_lines(p["ndef"])
    elif shape == "rfid":
        r = rfid_info(p)
        lines.append(f"  key type {r['key_type']}, data {r['data'].hex() if r['data'] else None}")
        if r["em4100"]:
            lines.append(f"  EM4100: {r['em4100']}")
        if r["card_number"] is not None:
            lines.append(f"  H10301: facility code {r['facility_code']}, card number {r['card_number']}")
    elif shape == "ir":
        for s in ir_info(p)["signals"]:
            if s.get("type") == "raw":
                lines.append(f"  {s.get('name')}: raw, {s.get('frequency')} Hz, duty {s.get('duty_cycle')}, {len(s.get('data') or [])} timings")
                nec = [m for m in nec_decode(s.get("data") or []) if not m["repeat"]]
                seen = sorted({(m["protocol"], m["address"], m["command"]) for m in nec})
                if seen:
                    lines.append("    read as NEC timing (a reading, not answered): " + ", ".join(
                        f"{pr} address 0x{a:02x} command 0x{c:02x}" for pr, a, c in seen[:8]) + (" ..." if len(seen) > 8 else ""))
            else:
                lines.append(f"  {s.get('name')}: {s.get('protocol')} address {(s.get('address') or b'').hex()} command {(s.get('command') or b'').hex()}")
    elif shape == "iq":
        i = iq_info(data, p, name)
        lines.append(f"  {p}: {i['samples']} samples, name says frequency {i['name_frequency']} Hz, rate {i['name_rate']} Hz; "
                     f"envelope floor {i['floor']}, peak {i['peak']}, {i['pulses']} pulse(s) (threshold-dependent)")
        if len(i["timings"]) >= 8:
            _show_bits(i["timings"], lines, "samples")
    elif shape == "wav":
        p = wav_info(data)
        lines.append(f"  WAV: {p['channels']} channel(s), {p['sample_rate']} Hz, {p['bits_per_sample']} bits, {p['frames']} frames, "
                     f"{p['duration']:.3f} s")
        texts = afsk_text(data) if len(data) <= MAX_IQ * 4 else {}
        for mode, txt in texts.items():
            lines.append(f"  FSK modem {mode} (baud, mark, space {AFSK_MODES[mode]}) decodes to text: {txt[:600]!r}")
        if not texts and len(p["timings"]) >= 8:
            _show_bits(p["timings"], lines, "samples")
    elif shape == "magstripe":
        for t in p:
            lines.append(f"  track {t['track']}: PAN {t['pan']} (Luhn {'ok' if t['luhn'] else 'FAILS'}), name {t.get('name')}, "
                         f"expiry {t['expiry']} (YYMM), service code {t['service_code']}, discretionary {t['discretionary']!r}")
    elif shape in ("ihex", "srec"):
        lines.append(f"  {shape}: {p['records']} records ({p['data_records']} data), {p['bad_checksums']} bad checksum(s), base "
                     f"{p['base_address']:#x}, {p['data_size']} data bytes, start {p['start_address']}, contiguous {p['contiguous']}"
                     + (f", header {p['header']!r}" if p.get("header") else ""))
        found = re.findall(rb"[\x20-\x7e]{6,}", p["image"])[:12]
        if found:
            lines.append("  strings: " + ", ".join(repr(s.decode()) for s in found))
    elif shape == "can":
        if p.get("format") == "asc":
            lines.append(f"  Vector ASC, base {p['base']}; {p['other']} other event line(s) are no data frame"
                         + (" (so no count is answered)" if p["other"] else ""))
        lines.append(f"  candump: {len(p['frames'])} frames, {len(p['ids'])} ids: "
                     + ", ".join(f"{i:03X}x{c}" for i, c in sorted(p["ids"].items())[:20]))
        for i in sorted(p["ids"]):
            blob = b"".join(f["data"] for f in p["frames"] if f["id"] == i)
            if printable(blob):
                lines.append(f"  id {i:03X} payloads as text: {blob.decode('ascii')!r}")
    elif shape == "logic":
        u = p.get("uart")
        if u:
            lines.append(f"  UART 8N1: baud {u['baud']}, {len(u['bytes'])} bytes, {u['framing_errors']} framing error(s): {u['bytes']!r}")
        for t in (p.get("i2c") or [])[:20]:
            lines.append(f"  I2C {t['rw']} 0x{t['address']:02x}: {t['data'].hex()}  acks {''.join('A' if a else 'N' for a in t['acks'])}")
        if p.get("spi"):
            lines.append(f"  SPI mosi {p['spi']['mosi'].hex()} miso {p['spi']['miso'].hex()}")
    else:
        text = _text(data)
        if text and re.fullmatch(r"[01\s]{26,}", text):
            b = re.sub(r"\s", "", text)
            lines.append(f"  a bit string of {len(b)} bits: EM4100 {em4100_bits(b)}, Wiegand {wiegand(b)}, magstripe {magstripe_bits(b)}")
        elif text and re.fullmatch(r"[-\d\s,]{40,}", text):
            t = [int(x) for x in re.findall(r"-?\d+", text)]
            _show_bits(t, lines)
    table = facts(name, data) if shape else {}
    if table:
        lines.append("  facts solve_set can answer: " + ", ".join(sorted(table)[:60]) + (" ..." if len(table) > 60 else ""))
    return "\n".join(lines)


def _mfc_lines(m) -> list:
    out = [f"  block 0: UID {m['uid'].hex() if m['uid'] else None} (BCC {'ok' if m['bcc_ok'] else 'FAILS or unknown'}), "
           f"SAK {m['sak'].hex() if m['sak'] else None}, ATQA bytes {m['atqa'].hex() if m['atqa'] else None}; {len(m['sectors'])} sectors"]
    for s in m["sectors"]:
        cond = ""
        if s["conditions"]:
            cond = " | data " + "/".join("".join(map(str, c)) for c in s["conditions"][:3]) + " trailer " + "".join(map(str, s["conditions"][3]))
            cond += f" ({MFC_TRAILER_ACCESS[s['conditions'][3]]})"
        out.append(f"  sector {s['sector']:2d} (blocks {s['first']}-{s['trailer']}): key A {s['key_a'].hex() if s['key_a'] else '??'}, "
                   f"access {s['access'].hex() if s['access'] else '??'}{'' if s['access_ok'] else ' INVALID' if s['access'] else ''}, "
                   f"key B {s['key_b'].hex() if s['key_b'] else '??'}{cond}")
        for i, row in enumerate(s["blocks"][:-1]):
            if _whole(row) and any(row) and s["first"] + i:
                b = bytes(row)
                out.append(f"    block {s['first'] + i}: {b.hex()}" + (f"  {b.decode('ascii')!r}" if printable(b.rstrip(b'\x00')) else ""))
    for blk, v in m["values"].items():
        out.append(f"  value block {blk}: value {v['value']}, address {v['address']}")
    return out


def _ndef_lines(messages) -> list:
    out = []
    for r in ndef_flat(messages):
        what = r.get("uri") or r.get("text") or r.get("text_payload") or r["payload"].hex()
        out.append(f"  NDEF {r['tnf_name']} type {r['type']!r}" + (f" lang {r['lang']}" if "lang" in r else "") + f": {what!r}")
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if not argv:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    rc = 0
    for arg in argv:
        p = Path(arg)
        if not p.is_file():
            print(f"rf.py: {arg} is not a file", file=sys.stderr)
            rc = 1
            continue
        data = p.read_bytes()
        if as_json:
            shape, _ = classify(p.name, data)
            print(json.dumps({"file": str(p), "shape": shape, "signal": signals([], {p.name: data}),
                              "facts": {k: v.options for k, v in facts(p.name, data).items()}}, ensure_ascii=False))
        else:
            print(triage(p.name, data))
    return rc


if __name__ == "__main__":
    sys.exit(main())
