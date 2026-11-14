#!/usr/bin/env python3
"""Toolkit financial: an OFFLINE, STATIC reader for payment / banking message formats
(CSCTF 2026 "Total Warfare" financial-infrastructure coverage; built 2026-11-03).

It parses the BYTES of three payment grammars as a grammar and reads out the structure and the
field values — it never instantiates, connects to a switch, or replays anything (the repo's
never-execute discipline). In a jeopardy event the decoded content is where the flag hides, so any
text matching the CSCTF flag format is HIGHLIGHTED prominently in the report.

  iso8583   ISO 8583 financial transaction message: the MTI (message type indicator), the primary
            and (when present) secondary bitmap, and each present data element decoded by the
            standard 1987 / 1993 field definitions (fixed, LLVAR, LLLVAR; numeric/BCD, alpha,
            binary, track). Handles the fully-ASCII, binary-bitmap+ASCII-field, and fully-packed
            (BCD) encodings, auto-detecting which; an optional 2-byte message-length indicator
            (MLI) is stripped.
  emv       EMV / chip-card BER-TLV (as in a tag 55 ICC-data field, a READ RECORD response, a GPO
            response, APDU logs): the full TLV tree decoded against an EMV tag dictionary (4F AID,
            50 label, 5A PAN, 57 track-2 equivalent, 9F26 application cryptogram, 82 AIP, 95 TVR,
            9A date, 9F02 amount, ...), with light value decoding (BCD amounts/dates, PAN, track-2).
  swift     SWIFT FIN / MT message: the {1:}{2:}{3:}{4:...-}{5:} block structure and, for the text
            block, the :TAG: fields named by an MT dictionary (MT103 single customer credit
            transfer: :20: reference, :32A: value date/ccy/amount, :50x: ordering customer,
            :59x: beneficiary, :71A: details of charges, :70: remittance info, ...).

INPUT: accepts BOTH a raw protocol-payload file (the message bytes, or a hex / ASCII-hex dump of
them — auto-detected, or forced with --hex) AND a .pcap / .pcapng, from which TCP/UDP payloads are
pulled with scapy (per packet and per reassembled flow) and dissected. scapy is optional; without
it, only raw / hex files are read.

SCOPE: offline parser of a provided artifact only. It does not touch the network, scan, or submit.
No real card / account / patient data lives in this file or its test — everything is synthetic and
spec-derived. (BER length handling follows the same rules as solvers/toolkits/asn1_reader.py's DER
walk; the EMV tag layer is implemented here because EMV multi-byte tags are not X.509 DER.)

    .venv/bin/python solvers/toolkits/financial.py <file>... [--json] [--hex]
        [--iso8583|--emv|--swift] [--iso-encoding auto|ascii|bin-bitmap|packed]
        [--iso-spec 1987|1993] [--strip-mli] [--no-pcap]
"""
import argparse
import binascii
import json
import re
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

KEY = "financial"
MAX_FILE = 64 * 1024 * 1024
MAX_PCAP_PKTS = 200000
MAX_PAYLOADS = 20000
MAX_TLV_ITEMS = 100000
MAX_TLV_DEPTH = 40

# The CSCTF flag format (identical to solvers/toolkits/web.py). The decoded content IS where the
# flag hides, so every decoded string is scanned and any hit is highlighted.
FLAG_RE = flagfmt.TEXT


# ============================================================================ flag highlighting

def find_flags(*texts) -> list:
    """Unique flag-format hits across the given strings/bytes, in first-seen order. Bytes (TLV values,
    raw messages, fixed-width fields) are scanned without a word boundary before the flag
    (flagfmt.PACKED_TEXT, R-16); text keeps the boundary."""
    out, seen = [], set()
    for t in texts:
        if t is None:
            continue
        rx = FLAG_RE
        if isinstance(t, (bytes, bytearray)):
            t, rx = bytes(t).decode("latin-1", "replace"), flagfmt.PACKED_TEXT
        for m in rx.finditer(str(t)):
            v = m.group(0)
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def _hilite(s: str, tty: bool) -> str:
    """Wrap any flag-format substring in a prominent marker (ANSI bold-red on a tty)."""
    if not s:
        return s

    def repl(m):
        v = m.group(0)
        return (f"\x1b[1;31m{v}\x1b[0m" if tty else f">>>{v}<<<")
    return FLAG_RE.sub(repl, s)


# ============================================================================ small byte helpers

def _is_hexdump(data: bytes) -> bool:
    """True if `data` is plausibly an ASCII hex dump (only hex digits + whitespace, even nibbles)."""
    try:
        s = data.decode("ascii")
    except UnicodeDecodeError:
        return False
    compact = re.sub(r"\s+", "", s)
    return len(compact) >= 4 and len(compact) % 2 == 0 and bool(re.fullmatch(r"[0-9A-Fa-f]+", compact))


def _unhex(data: bytes) -> bytes:
    return binascii.unhexlify(re.sub(rb"\s+", b"", data))


def _bcd_digits(b: bytes) -> str:
    """The BCD / packed-decimal digits of `b` as a string (each nibble a hex digit)."""
    return b.hex().upper()


def _luhn_ok(digits: str) -> bool:
    """Luhn (mod-10) check on a PAN digit string; False if non-digit or empty."""
    if not digits or not digits.isdigit():
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _printable_ascii(b: bytes):
    """`b` decoded as ASCII if it is wholly printable (plus tab/newline), else None."""
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    if s and all(32 <= ord(c) < 127 or c in "\t\r\n" for c in s):
        return s
    return None


# ============================================================================ ISO 8583

# MTI position meanings (ISO 8583 message type indicator, 4 digits).
_MTI_VERSION = {"0": "ISO 8583:1987", "1": "ISO 8583:1993", "2": "ISO 8583:2003",
                "8": "National use", "9": "Private use"}
_MTI_CLASS = {"1": "Authorization", "2": "Financial", "3": "File actions", "4": "Reversal/chargeback",
              "5": "Reconciliation", "6": "Administrative", "7": "Fee collection",
              "8": "Network management", "9": "Reserved"}
_MTI_FUNCTION = {"0": "Request", "1": "Request response", "2": "Advice", "3": "Advice response",
                 "4": "Notification", "5": "Notification acknowledgement", "6": "Instruction",
                 "7": "Instruction acknowledgement"}
_MTI_ORIGIN = {"0": "Acquirer", "1": "Acquirer repeat", "2": "Issuer", "3": "Issuer repeat",
               "4": "Other", "5": "Other repeat"}

# length-type sentinels
F, L2, L3 = "FIXED", "LLVAR", "LLLVAR"

# ISO 8583:1987 data-element definitions: de -> (name, fmt, lentype, length).
# fmt: n=numeric, a=alpha, an=alphanumeric, ans=alphanumeric+special, b=binary (length in BITS for
# FIXED b), z=track, "x+n"=sign+numeric. length = max chars (n/a/an/ans/z), or bits (FIXED b).
FIELDS_1987 = {
    1: ("Bitmap, secondary", "b", F, 64),
    2: ("Primary account number (PAN)", "n", L2, 19),
    3: ("Processing code", "n", F, 6),
    4: ("Amount, transaction", "n", F, 12),
    5: ("Amount, settlement", "n", F, 12),
    6: ("Amount, cardholder billing", "n", F, 12),
    7: ("Transmission date & time (MMDDhhmmss)", "n", F, 10),
    8: ("Amount, cardholder billing fee", "n", F, 8),
    9: ("Conversion rate, settlement", "n", F, 8),
    10: ("Conversion rate, cardholder billing", "n", F, 8),
    11: ("System trace audit number (STAN)", "n", F, 6),
    12: ("Time, local transaction (hhmmss)", "n", F, 6),
    13: ("Date, local transaction (MMDD)", "n", F, 4),
    14: ("Date, expiration (YYMM)", "n", F, 4),
    15: ("Date, settlement", "n", F, 4),
    16: ("Date, conversion", "n", F, 4),
    17: ("Date, capture", "n", F, 4),
    18: ("Merchant type (MCC)", "n", F, 4),
    19: ("Acquiring institution country code", "n", F, 3),
    20: ("PAN extended, country code", "n", F, 3),
    21: ("Forwarding institution country code", "n", F, 3),
    22: ("Point of service entry mode", "n", F, 3),
    23: ("Card sequence number", "n", F, 3),
    24: ("Network international identifier (NII)", "n", F, 3),
    25: ("Point of service condition code", "n", F, 2),
    26: ("Point of service capture code", "n", F, 2),
    27: ("Authorizing identification response length", "n", F, 1),
    28: ("Amount, transaction fee", "x+n", F, 8),
    29: ("Amount, settlement fee", "x+n", F, 8),
    30: ("Amount, transaction processing fee", "x+n", F, 8),
    31: ("Amount, settlement processing fee", "x+n", F, 8),
    32: ("Acquiring institution identification code", "n", L2, 11),
    33: ("Forwarding institution identification code", "n", L2, 11),
    34: ("PAN extended", "ns", L2, 28),
    35: ("Track 2 data", "z", L2, 37),
    36: ("Track 3 data", "z", L3, 104),
    37: ("Retrieval reference number", "an", F, 12),
    38: ("Authorization identification response", "an", F, 6),
    39: ("Response code", "an", F, 2),
    40: ("Service restriction code", "an", F, 3),
    41: ("Card acceptor terminal identification", "ans", F, 8),
    42: ("Card acceptor identification code", "ans", F, 15),
    43: ("Card acceptor name/location", "ans", F, 40),
    44: ("Additional response data", "an", L2, 25),
    45: ("Track 1 data", "an", L2, 76),
    46: ("Additional data - ISO", "an", L3, 999),
    47: ("Additional data - national", "an", L3, 999),
    48: ("Additional data - private", "an", L3, 999),
    49: ("Currency code, transaction", "an", F, 3),
    50: ("Currency code, settlement", "an", F, 3),
    51: ("Currency code, cardholder billing", "an", F, 3),
    52: ("Personal identification number (PIN) data", "b", F, 64),
    53: ("Security related control information", "n", F, 16),
    54: ("Additional amounts", "an", L3, 120),
    55: ("ICC data - EMV having multiple tags", "b", L3, 999),
    56: ("Reserved ISO", "n", L3, 999),
    57: ("Reserved national", "n", L3, 999),
    58: ("Reserved national", "n", L3, 999),
    59: ("Reserved national", "n", L3, 999),
    60: ("Reserved national", "an", L3, 999),
    61: ("Reserved private", "an", L3, 999),
    62: ("Reserved private", "an", L3, 999),
    63: ("Reserved private", "an", L3, 999),
    64: ("Message authentication code (MAC)", "b", F, 64),
    65: ("Bitmap, tertiary", "b", F, 1),
    66: ("Settlement code", "n", F, 1),
    67: ("Extended payment code", "n", F, 2),
    68: ("Receiving institution country code", "n", F, 3),
    69: ("Settlement institution country code", "n", F, 3),
    70: ("Network management information code", "n", F, 3),
    71: ("Message number", "n", F, 4),
    72: ("Message number, last", "n", F, 4),
    73: ("Date, action (YYMMDD)", "n", F, 6),
    74: ("Credits, number", "n", F, 10),
    75: ("Credits, reversal number", "n", F, 10),
    76: ("Debits, number", "n", F, 10),
    77: ("Debits, reversal number", "n", F, 10),
    78: ("Transfer, number", "n", F, 10),
    79: ("Transfer, reversal number", "n", F, 10),
    80: ("Inquiries, number", "n", F, 10),
    81: ("Authorizations, number", "n", F, 10),
    82: ("Credits, processing fee amount", "n", F, 12),
    83: ("Credits, transaction fee amount", "n", F, 12),
    84: ("Debits, processing fee amount", "n", F, 12),
    85: ("Debits, transaction fee amount", "n", F, 12),
    86: ("Credits, amount", "n", F, 16),
    87: ("Credits, reversal amount", "n", F, 16),
    88: ("Debits, amount", "n", F, 16),
    89: ("Debits, reversal amount", "n", F, 16),
    90: ("Original data elements", "n", F, 42),
    91: ("File update code", "an", F, 1),
    92: ("File security code", "an", F, 2),
    93: ("Response indicator", "an", F, 5),
    94: ("Service indicator", "an", F, 7),
    95: ("Replacement amounts", "an", F, 42),
    96: ("Message security code", "b", F, 64),
    97: ("Amount, net settlement", "x+n", F, 16),
    98: ("Payee", "ans", F, 25),
    99: ("Settlement institution identification code", "n", L2, 11),
    100: ("Receiving institution identification code", "n", L2, 11),
    101: ("File name", "ans", L2, 17),
    102: ("Account identification 1", "ans", L2, 28),
    103: ("Account identification 2", "ans", L2, 28),
    104: ("Transaction description", "ans", L3, 100),
    105: ("Reserved for ISO use", "ans", L3, 999),
    106: ("Reserved for ISO use", "ans", L3, 999),
    107: ("Reserved for ISO use", "ans", L3, 999),
    108: ("Reserved for ISO use", "ans", L3, 999),
    109: ("Reserved for ISO use", "ans", L3, 999),
    110: ("Reserved for ISO use", "ans", L3, 999),
    111: ("Reserved for ISO use", "ans", L3, 999),
    112: ("Reserved for national use", "ans", L3, 999),
    113: ("Reserved for national use", "ans", L3, 999),
    114: ("Reserved for national use", "ans", L3, 999),
    115: ("Reserved for national use", "ans", L3, 999),
    116: ("Reserved for national use", "ans", L3, 999),
    117: ("Reserved for national use", "ans", L3, 999),
    118: ("Reserved for national use", "ans", L3, 999),
    119: ("Reserved for national use", "ans", L3, 999),
    120: ("Reserved for private use", "ans", L3, 999),
    121: ("Reserved for private use", "ans", L3, 999),
    122: ("Reserved for private use", "ans", L3, 999),
    123: ("Reserved for private use", "ans", L3, 999),
    124: ("Reserved for private use", "ans", L3, 999),
    125: ("Reserved for private use", "ans", L3, 999),
    126: ("Reserved for private use", "ans", L3, 999),
    127: ("Reserved for private use", "ans", L3, 999),
    128: ("Message authentication code (MAC)", "b", F, 64),
}

# ISO 8583:1993 differs from 1987 mainly in a handful of elements; the common data elements are the
# same. The concrete, well-known deltas (DE 72 and DE 96 become LLLVAR) are overridden here.
FIELDS_1993 = dict(FIELDS_1987)
FIELDS_1993[72] = ("Data record", "ans", L3, 999)
FIELDS_1993[96] = ("Message security code", "ans", L3, 999)


class ISOError(ValueError):
    pass


def _mti_decode(mti: str) -> dict:
    d = {"raw": mti}
    if len(mti) == 4 and mti.isdigit():
        d["version"] = _MTI_VERSION.get(mti[0], f"reserved ({mti[0]})")
        d["class"] = _MTI_CLASS.get(mti[1], f"reserved ({mti[1]})")
        d["function"] = _MTI_FUNCTION.get(mti[2], f"reserved ({mti[2]})")
        d["origin"] = _MTI_ORIGIN.get(mti[3], f"reserved ({mti[3]})")
    return d


def _bitmap_present(primary: bytes, secondary: bytes):
    """Present DATA element numbers (ascending) from the bitmaps, plus indicator flags.
    Field 1 (secondary indicator) and field 65 (tertiary indicator) are not data elements."""
    present = []
    for k in range(64):
        if primary[k // 8] & (0x80 >> (k % 8)):
            present.append(k + 1)                 # DE 1..64
    has_secondary = 1 in present
    present = [de for de in present if de != 1]
    has_tertiary = False
    if secondary:
        for k in range(64):
            if secondary[k // 8] & (0x80 >> (k % 8)):
                de = 65 + k                       # DE 65..128
                if de == 65:
                    has_tertiary = True
                else:
                    present.append(de)
    return sorted(present), has_secondary, has_tertiary


def _read_field(data, i, de, defn, field_mode):
    """Read one data element at offset i. Returns (field_dict, new_i). Raises ISOError on overrun."""
    name, fmt, lentype, length = defn
    n = len(data)

    def take(count):
        if i + count > n or count < 0:
            raise ISOError(f"DE{de}: want {count} bytes at {i}, only {n - i} left")
        return data[i:i + count]

    # ---- determine the declared length L and where the value starts
    if lentype == F:
        L = length
        vstart = i
    else:
        if field_mode == "bcd":
            nlen = 1 if lentype == L2 else 2
            lraw = take(nlen)
            if any(nib > 9 for b in lraw for nib in (b >> 4, b & 0x0F)):
                raise ISOError(f"DE{de}: non-BCD {lentype} length prefix")
            L = int(_bcd_digits(lraw))
            vstart = i + nlen
        else:
            nlen = 2 if lentype == L2 else 3
            lraw = take(nlen)
            try:
                L = int(lraw.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                raise ISOError(f"DE{de}: non-numeric {lentype} length prefix {lraw!r}")
            vstart = i + nlen
        if L > length:
            raise ISOError(f"DE{de}: declared length {L} exceeds max {length}")

    j = vstart
    # ---- read the value bytes and decode to a display string
    if field_mode == "bcd":
        if fmt == "n":
            nbytes = (L + 1) // 2
            raw = data[j:j + nbytes]
            if len(raw) != nbytes:
                raise ISOError(f"DE{de}: short numeric value")
            digits = _bcd_digits(raw)
            value = digits[-L:] if L else ""
            j += nbytes
        elif fmt == "b":
            nbytes = (length // 8) if lentype == F else L
            raw = data[j:j + nbytes]
            if len(raw) != nbytes:
                raise ISOError(f"DE{de}: short binary value")
            value = raw.hex().upper()
            j += nbytes
        elif fmt == "x+n":
            nbytes = 1 + (length + 1) // 2
            raw = data[j:j + nbytes]
            if len(raw) != nbytes:
                raise ISOError(f"DE{de}: short x+n value")
            value = raw[:1].decode("latin-1") + _bcd_digits(raw[1:])[-length:]
            j += nbytes
        else:                                     # a/an/ans/ns/z: ASCII bytes, L (or length) chars
            cnt = length if lentype == F else L
            raw = data[j:j + cnt]
            if len(raw) != cnt:
                raise ISOError(f"DE{de}: short value")
            value = raw.decode("latin-1")
            j += cnt
    else:                                         # ASCII field mode
        if fmt == "b":
            cnt = (length // 4) if lentype == F else (L * 2)   # hex chars
        elif fmt == "x+n":
            cnt = length + 1
        else:
            cnt = length if lentype == F else L
        raw = data[j:j + cnt]
        if len(raw) != cnt:
            raise ISOError(f"DE{de}: want {cnt} chars at {j}, only {len(raw)}")
        value = raw.decode("latin-1")
        j += cnt

    field = {"de": de, "name": name, "format": fmt, "lentype": lentype,
             "declared_len": L, "value": value}
    note = _iso_field_note(de, fmt, value)
    if note:
        field["note"] = note
    return field, j


def _iso_field_note(de, fmt, value):
    """A light semantic note for a few well-known elements (never a guess, just a read)."""
    if de == 2 and value:                 # PAN -> Luhn
        digits = value.rstrip("Ff")
        if digits.isdigit():
            return f"PAN; Luhn {'valid' if _luhn_ok(digits) else 'INVALID'}"
    if de in (35, 36) and value:          # track data
        t = _parse_track2(value)
        if t:
            bits = [f"PAN={t['pan']}"]
            if t.get("expiry"):
                bits.append(f"expiry(YYMM)={t['expiry']}")
            if t.get("service_code"):
                bits.append(f"service={t['service_code']}")
            return "track2: " + " ".join(bits)
    if de == 3 and len(value) == 6:
        return f"processing: txn={value[0:2]} from={value[2:4]} to={value[4:6]}"
    if de == 39:
        return "response code"
    return None


def _parse_track2(value):
    """Parse a track-2 string 'PAN=YYMMsss...' (or with 'D' separator). None if no separator."""
    s = value.strip().rstrip("Ff")
    sep = "=" if "=" in s else ("D" if "D" in s.upper() else None)
    if not sep:
        return None
    idx = s.upper().find(sep)
    pan = s[:idx]
    rest = s[idx + 1:]
    out = {"pan": pan}
    if len(rest) >= 4 and rest[:4].isdigit():
        out["expiry"] = rest[:4]
    if len(rest) >= 7 and rest[4:7].isdigit():
        out["service_code"] = rest[4:7]
    if pan.isdigit():
        out["luhn"] = _luhn_ok(pan)
    return out


# ISO encoding combos tried by auto-detect, in priority order:
# (name, mti_mode, bitmap_mode, field_mode)
_ISO_COMBOS = [
    ("ascii", "ascii", "hex", "ascii"),            # fully ASCII (hex-ASCII bitmap)
    ("bin-bitmap", "ascii", "binary", "ascii"),    # ASCII MTI + binary bitmap + ASCII fields
    ("packed", "bcd", "binary", "bcd"),            # fully packed (BCD)
    ("ascii-mti-packed", "ascii", "binary", "bcd"),
]
_ISO_ENCODING_ALIASES = {
    "ascii": "ascii", "bin-bitmap": "bin-bitmap", "packed": "packed",
    "ascii-mti-packed": "ascii-mti-packed",
}


def _decode_iso(data: bytes, mti_mode, bitmap_mode, field_mode, spec):
    """Decode one ISO 8583 message in an explicit encoding. Returns a result dict; raises ISOError."""
    fields_def = FIELDS_1993 if str(spec) == "1993" else FIELDS_1987
    n = len(data)
    i = 0
    # ---- MTI
    if mti_mode == "bcd":
        if n < 2:
            raise ISOError("truncated before MTI")
        if any(nib > 9 for b in data[0:2] for nib in (b >> 4, b & 0x0F)):
            raise ISOError("MTI is not valid BCD")
        mti = _bcd_digits(data[0:2])
        i = 2
    else:
        if n < 4:
            raise ISOError("truncated before MTI")
        mti = data[0:4].decode("latin-1")
        if not mti.isdigit():
            raise ISOError(f"MTI not 4 ASCII digits: {mti!r}")
        i = 4

    # ---- primary bitmap
    if bitmap_mode == "hex":
        if i + 16 > n:
            raise ISOError("truncated before hex bitmap")
        hexmap = data[i:i + 16]
        if not re.fullmatch(rb"[0-9A-Fa-f]{16}", hexmap):
            raise ISOError("primary bitmap is not 16 hex chars")
        primary = bytes.fromhex(hexmap.decode("ascii"))
        i += 16
        bm_render = [hexmap.decode("ascii").upper()]
    else:
        if i + 8 > n:
            raise ISOError("truncated before bitmap")
        primary = data[i:i + 8]
        i += 8
        bm_render = [primary.hex().upper()]

    secondary = b""
    if primary[0] & 0x80:                           # bit 1 -> secondary bitmap present
        if bitmap_mode == "hex":
            if i + 16 > n:
                raise ISOError("truncated before secondary hex bitmap")
            hexmap = data[i:i + 16]
            if not re.fullmatch(rb"[0-9A-Fa-f]{16}", hexmap):
                raise ISOError("secondary bitmap is not 16 hex chars")
            secondary = bytes.fromhex(hexmap.decode("ascii"))
            i += 16
            bm_render.append(hexmap.decode("ascii").upper())
        else:
            if i + 8 > n:
                raise ISOError("truncated before secondary bitmap")
            secondary = data[i:i + 8]
            i += 8
            bm_render.append(secondary.hex().upper())

    present, has_sec, has_ter = _bitmap_present(primary, secondary)

    # ---- data elements
    fields = []
    for de in present:
        defn = fields_def.get(de)
        if defn is None:
            raise ISOError(f"DE{de} has no definition in the {spec} map")
        field, i = _read_field(data, i, de, defn, field_mode)
        fields.append(field)

    trailing = data[i:]
    result = {
        "type": "iso8583",
        "encoding": {"mti": mti_mode, "bitmap": bitmap_mode, "field": field_mode, "spec": str(spec)},
        "mti": _mti_decode(mti),
        "bitmaps": bm_render,
        "has_secondary_bitmap": has_sec,
        "has_tertiary_bitmap": has_ter,
        "present_fields": present,
        "fields": fields,
        "consumed": i,
        "trailing_hex": trailing.hex() if trailing else "",
    }
    return result


def parse_iso8583(data: bytes, encoding="auto", spec="1987", strip_mli=False):
    """Decode an ISO 8583 message. encoding 'auto' tries the common encodings and keeps the one
    that consumes the message most completely. Returns a result dict, or None if nothing parses."""
    if strip_mli:
        data = _maybe_strip_mli(data)
    if encoding != "auto" and encoding in _ISO_ENCODING_ALIASES:
        combo = next(c for c in _ISO_COMBOS if c[0] == _ISO_ENCODING_ALIASES[encoding])
        try:
            res = _decode_iso(data, combo[1], combo[2], combo[3], spec)
        except ISOError:
            # try again with the MLI stripped, in case it was present
            stripped = _maybe_strip_mli(data)
            if stripped is not data:
                try:
                    res = _decode_iso(stripped, combo[1], combo[2], combo[3], spec)
                except ISOError:
                    return None
            else:
                return None
        _attach_iso_flags(res)
        return res

    best = None
    for candidate in (data, _maybe_strip_mli(data)):
        for name, mti_mode, bm_mode, fld_mode in _ISO_COMBOS:
            try:
                res = _decode_iso(candidate, mti_mode, bm_mode, fld_mode, spec)
            except ISOError:
                continue
            leftover = len(candidate) - res["consumed"]
            score = (leftover == 0, len(res["fields"]), -leftover)
            if best is None or score > best[0]:
                best = (score, res)
        if best is not None and best[0][0]:        # a clean full-consume on the un-stripped buffer wins
            break
    if best is None:
        return None
    res = best[1]
    _attach_iso_flags(res)
    return res


def _maybe_strip_mli(data: bytes) -> bytes:
    """Strip a 2-byte big-endian message-length indicator if it exactly frames the rest."""
    if len(data) >= 2:
        n = int.from_bytes(data[:2], "big")
        if n == len(data) - 2 and n > 0:
            return data[2:]
    return data


def _attach_iso_flags(res):
    texts = [f.get("value", "") for f in res.get("fields", [])]
    texts += [f.get("note", "") for f in res.get("fields", [])]
    res["flags"] = find_flags(*texts)


# ============================================================================ EMV BER-TLV

# EMV / chip-card tag dictionary (common tags; EMV Books 1-4 + common proprietary templates).
EMV_TAGS = {
    "4F": "Application Identifier (AID) - card",
    "50": "Application Label",
    "57": "Track 2 Equivalent Data",
    "5A": "Application Primary Account Number (PAN)",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date (YYMMDD)",
    "5F25": "Application Effective Date (YYMMDD)",
    "5F28": "Issuer Country Code",
    "5F2A": "Transaction Currency Code",
    "5F2D": "Language Preference",
    "5F30": "Service Code",
    "5F34": "Application PAN Sequence Number",
    "5F36": "Transaction Currency Exponent",
    "5F50": "Issuer URL",
    "5F53": "International Bank Account Number (IBAN)",
    "5F54": "Bank Identifier Code (BIC)",
    "5F55": "Issuer Country Code (alpha2)",
    "5F56": "Issuer Country Code (alpha3)",
    "61": "Application Template",
    "6F": "File Control Information (FCI) Template",
    "70": "Record Template (READ RECORD response)",
    "71": "Issuer Script Template 1",
    "72": "Issuer Script Template 2",
    "73": "Directory Discretionary Template",
    "77": "Response Message Template Format 2",
    "80": "Response Message Template Format 1",
    "81": "Amount, Authorised (Binary)",
    "82": "Application Interchange Profile (AIP)",
    "83": "Command Template",
    "84": "Dedicated File (DF) Name",
    "86": "Issuer Script Command",
    "87": "Application Priority Indicator",
    "88": "Short File Identifier (SFI)",
    "89": "Authorisation Code",
    "8A": "Authorisation Response Code (ARC)",
    "8C": "Card Risk Management Data Object List 1 (CDOL1)",
    "8D": "Card Risk Management Data Object List 2 (CDOL2)",
    "8E": "Cardholder Verification Method (CVM) List",
    "8F": "Certification Authority Public Key Index",
    "90": "Issuer Public Key Certificate",
    "91": "Issuer Authentication Data",
    "92": "Issuer Public Key Remainder",
    "93": "Signed Static Application Data",
    "94": "Application File Locator (AFL)",
    "95": "Terminal Verification Results (TVR)",
    "97": "Transaction Certificate Data Object List (TDOL)",
    "98": "Transaction Certificate (TC) Hash Value",
    "99": "Transaction PIN Data",
    "9A": "Transaction Date (YYMMDD)",
    "9B": "Transaction Status Information (TSI)",
    "9C": "Transaction Type",
    "9D": "Directory Definition File (DDF) Name",
    "A5": "FCI Proprietary Template",
    "9F01": "Acquirer Identifier",
    "9F02": "Amount, Authorised (Numeric)",
    "9F03": "Amount, Other (Numeric)",
    "9F04": "Amount, Other (Binary)",
    "9F05": "Application Discretionary Data",
    "9F06": "Application Identifier (AID) - terminal",
    "9F07": "Application Usage Control",
    "9F08": "Application Version Number (card)",
    "9F09": "Application Version Number (terminal)",
    "9F0B": "Cardholder Name Extended",
    "9F0D": "Issuer Action Code - Default",
    "9F0E": "Issuer Action Code - Denial",
    "9F0F": "Issuer Action Code - Online",
    "9F10": "Issuer Application Data (IAD)",
    "9F11": "Issuer Code Table Index",
    "9F12": "Application Preferred Name",
    "9F13": "Last Online ATC Register",
    "9F14": "Lower Consecutive Offline Limit",
    "9F15": "Merchant Category Code",
    "9F16": "Merchant Identifier",
    "9F17": "PIN Try Counter",
    "9F18": "Issuer Script Identifier",
    "9F1A": "Terminal Country Code",
    "9F1B": "Terminal Floor Limit",
    "9F1C": "Terminal Identification",
    "9F1D": "Terminal Risk Management Data",
    "9F1E": "Interface Device (IFD) Serial Number",
    "9F1F": "Track 1 Discretionary Data",
    "9F20": "Track 2 Discretionary Data",
    "9F21": "Transaction Time (HHMMSS)",
    "9F22": "Certification Authority Public Key Index (terminal)",
    "9F23": "Upper Consecutive Offline Limit",
    "9F26": "Application Cryptogram (ARQC/TC/AAC)",
    "9F27": "Cryptogram Information Data (CID)",
    "9F2A": "Kernel Identifier",
    "9F2D": "ICC PIN Encipherment Public Key Certificate",
    "9F2E": "ICC PIN Encipherment Public Key Exponent",
    "9F2F": "ICC PIN Encipherment Public Key Remainder",
    "9F32": "Issuer Public Key Exponent",
    "9F33": "Terminal Capabilities",
    "9F34": "Cardholder Verification Method (CVM) Results",
    "9F35": "Terminal Type",
    "9F36": "Application Transaction Counter (ATC)",
    "9F37": "Unpredictable Number (UN)",
    "9F38": "Processing Options Data Object List (PDOL)",
    "9F39": "Point-of-Service (POS) Entry Mode",
    "9F3A": "Amount, Reference Currency",
    "9F3B": "Application Reference Currency",
    "9F3C": "Transaction Reference Currency Code",
    "9F3D": "Transaction Reference Currency Exponent",
    "9F40": "Additional Terminal Capabilities",
    "9F41": "Transaction Sequence Counter",
    "9F42": "Application Currency Code",
    "9F43": "Application Reference Currency Exponent",
    "9F44": "Application Currency Exponent",
    "9F45": "Data Authentication Code",
    "9F46": "ICC Public Key Certificate",
    "9F47": "ICC Public Key Exponent",
    "9F48": "ICC Public Key Remainder",
    "9F49": "Dynamic Data Authentication Data Object List (DDOL)",
    "9F4A": "Static Data Authentication Tag List",
    "9F4B": "Signed Dynamic Application Data",
    "9F4C": "ICC Dynamic Number",
    "9F4D": "Log Entry",
    "9F4E": "Merchant Name and Location",
    "9F4F": "Log Format",
    "9F5B": "Issuer Script Results",
    "9F6B": "Track 2 Data (Card)",
    "9F6E": "Form Factor Indicator / Third Party Data",
    "BF0C": "FCI Issuer Discretionary Data",
}
# constructed templates (value is itself a sequence of TLVs)
EMV_CONSTRUCTED = {"61", "6F", "70", "71", "72", "73", "77", "A5", "BF0C"}
# tags whose value is BCD numeric (EMV format "n", packed decimal) — shown as the decimal digits.
_EMV_NUMERIC = {"9F02", "9F03", "5F2A", "9F1A", "9F15", "5F28", "9C",
                "9F41", "9F21", "9A", "5F24", "5F25", "9F42", "9F3C"}
# tags whose value is a BIG-ENDIAN BINARY integer (EMV format "b" amounts / counters). These are NOT
# BCD: tag 81 = 0x00000100 is 256, not 100. Decode as int.from_bytes(.., "big"), never hex-as-decimal.
_EMV_BINARY_INT = {"81", "9F04", "9F36", "9F13"}
_EMV_DATE = {"9A", "5F24", "5F25"}
_EMV_TIME = {"9F21"}
_EMV_ASCII = {"50", "5F20", "9F12", "5F50", "5F2D", "5F53", "5F54", "5F55", "5F56",
              "9F0B", "9F1E", "9F4E", "9F1C"}


class TLVError(ValueError):
    pass


def _parse_tag(data, i):
    """BER tag at offset i -> (tag_hex, constructed, cls, new_i)."""
    n = len(data)
    if i >= n:
        raise TLVError("tag past end")
    b0 = data[i]
    cls = (b0 >> 6) & 0x03
    constructed = bool(b0 & 0x20)
    tag_bytes = [b0]
    i += 1
    if (b0 & 0x1F) == 0x1F:                     # multi-byte tag
        while True:
            if i >= n:
                raise TLVError("tag runs past end")
            bn = data[i]
            tag_bytes.append(bn)
            i += 1
            if not (bn & 0x80):
                break
            if len(tag_bytes) > 4:
                raise TLVError("tag too long")
    return bytes(tag_bytes).hex().upper(), constructed, cls, i


def _parse_len(data, i):
    """BER length at offset i -> (length, new_i). Same rules as asn1_reader._der_len (no indefinite)."""
    n = len(data)
    if i >= n:
        raise TLVError("length past end")
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    nbytes = b & 0x7F
    if nbytes == 0 or nbytes > 4 or i + nbytes > n:
        raise TLVError("bad / indefinite length")
    return int.from_bytes(data[i:i + nbytes], "big"), i + nbytes


def _tlv_walk(data, start, end, depth, budget):
    """Parse the TLVs in data[start:end]. Returns (nodes, consumed_end)."""
    if depth > MAX_TLV_DEPTH:
        raise TLVError("too deep")
    nodes = []
    i = start
    while i < end:
        if budget[0] <= 0:
            raise TLVError("too many items")
        if data[i] in (0x00, 0xFF):             # EMV inter-TLV padding
            i += 1
            continue
        budget[0] -= 1
        tag, constructed, cls, i = _parse_tag(data, i)
        length, i = _parse_len(data, i)
        if i + length > end:
            raise TLVError(f"value of tag {tag} runs past end")
        vstart, vend = i, i + length
        node = {"tag": tag, "constructed": constructed, "class": cls, "length": length}
        if constructed:
            children, _ = _tlv_walk(data, vstart, vend, depth + 1, budget)
            node["children"] = children
        else:
            node["value"] = data[vstart:vend]
        nodes.append(node)
        i = vend
    return nodes, i


def _emv_decode_value(tag, value: bytes):
    """A light decoded rendering of a primitive EMV value (never a guess, just a read)."""
    out = {}
    out["hex"] = value.hex().upper()
    if tag == "5A":                                       # PAN (BCD, trailing F pad)
        digits = value.hex().upper().rstrip("F")
        out["pan"] = digits
        if digits.isdigit():
            out["luhn"] = _luhn_ok(digits)
    elif tag in ("57", "9F6B"):                           # track 2 equivalent (nibble coded)
        t = _decode_track2_nibbles(value)
        if t:
            out["track2"] = t
            parsed = _parse_track2(t)
            if parsed:
                out["track2_parsed"] = parsed
    elif tag in _EMV_DATE:
        d = value.hex().upper()
        if len(d) == 6 and d.isdigit():
            out["date"] = f"20{d[0:2]}-{d[2:4]}-{d[4:6]}"
    elif tag in _EMV_TIME:
        t = value.hex().upper()
        if len(t) == 6 and t.isdigit():
            out["time"] = f"{t[0:2]}:{t[2:4]}:{t[4:6]}"
    elif tag in _EMV_BINARY_INT:                          # EMV format "b": big-endian integer
        if value and len(value) <= 9:
            out["numeric"] = str(int.from_bytes(value, "big"))
    elif tag in _EMV_NUMERIC:                             # EMV format "n": packed BCD decimal digits
        d = value.hex().upper()
        if d.isdigit():
            out["numeric"] = str(int(d)) if d.strip("0") else "0"
    if tag in _EMV_ASCII or (tag not in ("5A", "57", "9F6B") and _printable_ascii(value)):
        a = _printable_ascii(value)
        if a:
            out["ascii"] = a
    return out


def _decode_track2_nibbles(b: bytes) -> str:
    """Decode nibble-coded track-2 equivalent data: 0-9 digits, D -> '=' separator, F -> end."""
    s = []
    for byte in b:
        for nib in (byte >> 4, byte & 0x0F):
            if nib <= 9:
                s.append(str(nib))
            elif nib == 0x0D:
                s.append("=")
            elif nib == 0x0F:
                return "".join(s)
            else:
                s.append("?")
    return "".join(s)


def _annotate_tlv(nodes):
    """Add the tag name and decoded value to each node (recursively), and collect flag hits."""
    flags = []
    for node in nodes:
        node["name"] = EMV_TAGS.get(node["tag"], "unknown tag")
        if node.get("constructed"):
            flags += _annotate_tlv(node["children"])
        else:
            dec = _emv_decode_value(node["tag"], node["value"])
            node["decoded"] = dec
            flags += find_flags(dec.get("ascii"), dec.get("track2"),
                                node["value"])
    return flags


# top-level template tags that make an all-printable buffer confidently EMV
_EMV_ROOT_TEMPLATES = {"6F", "70", "77", "80", "A5", "61", "72", "71", "BF0C"}


def parse_emv(data: bytes):
    """Parse an EMV BER-TLV blob into a decoded tree. Returns a result dict, or None if it does not
    look like EMV TLV (parse failed, poor coverage, or too little confidence it is EMV)."""
    if not data:
        return None
    try:
        nodes, consumed = _tlv_walk(data, 0, len(data), 0, [MAX_TLV_ITEMS])
    except TLVError:
        return None
    if not nodes:
        return None
    if consumed / len(data) < 0.98:              # EMV blobs are framed exactly; near-full only
        return None
    named = _count_named_tags(nodes)
    root_template = nodes[0]["tag"] in _EMV_ROOT_TEMPLATES
    if not (root_template or named >= 2):        # confidence gate
        return None
    # a wholly printable-ASCII buffer that merely BER-parses is almost never EMV (EMV is binary):
    # accept it only when it starts with a real EMV template tag.
    if _printable_ascii(data) is not None and not root_template:
        return None
    flags = _annotate_tlv(nodes)
    return {"type": "emv", "tlvs": nodes, "consumed": consumed,
            "total": len(data), "flags": flags}


def _count_named_tags(nodes) -> int:
    total = 0
    for node in nodes:
        if node["tag"] in EMV_TAGS:
            total += 1
        if node.get("children"):
            total += _count_named_tags(node["children"])
    return total


# ============================================================================ SWIFT MT

# SWIFT MT103 (single customer credit transfer) and common FIN text-block tag names.
SWIFT_TAGS = {
    "20": "Sender's Reference",
    "13C": "Time Indication",
    "23B": "Bank Operation Code",
    "23E": "Instruction Code",
    "26T": "Transaction Type Code",
    "32A": "Value Date / Currency / Interbank Settled Amount",
    "32B": "Currency / Amount",
    "33B": "Currency / Instructed Amount",
    "36": "Exchange Rate",
    "50A": "Ordering Customer (Option A)",
    "50F": "Ordering Customer (Option F)",
    "50K": "Ordering Customer (Option K)",
    "51A": "Sending Institution",
    "52A": "Ordering Institution (Option A)",
    "52D": "Ordering Institution (Option D)",
    "53A": "Sender's Correspondent (Option A)",
    "53B": "Sender's Correspondent (Option B)",
    "53D": "Sender's Correspondent (Option D)",
    "54A": "Receiver's Correspondent (Option A)",
    "55A": "Third Reimbursement Institution",
    "56A": "Intermediary Institution (Option A)",
    "56D": "Intermediary Institution (Option D)",
    "57A": "Account With Institution (Option A)",
    "57C": "Account With Institution (Option C)",
    "57D": "Account With Institution (Option D)",
    "59": "Beneficiary Customer",
    "59A": "Beneficiary Customer (Option A)",
    "59F": "Beneficiary Customer (Option F)",
    "70": "Remittance Information",
    "71A": "Details of Charges (BEN/OUR/SHA)",
    "71F": "Sender's Charges",
    "71G": "Receiver's Charges",
    "72": "Sender to Receiver Information",
    "77B": "Regulatory Reporting",
    "77T": "Envelope Contents",
}
_SWIFT_TAG_RE = re.compile(r"^:(\d{2}[A-Z]?):", re.M)


def _split_swift_blocks(text):
    """Top-level SWIFT blocks as [(id, value)], brace-nesting aware (blocks 3/5 nest)."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "{":
            depth, j = 1, i + 1
            while j < n and depth > 0:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            inner = text[i + 1:j - 1]
            if ":" in inner:
                bid, val = inner.split(":", 1)
                out.append((bid.strip(), val))
            i = j
        else:
            i += 1
    return out


def _parse_block1(val):
    """Basic header: F/A/L app id, 2-digit service id, 12-char LT address, 4 session, 6 sequence."""
    d = {"raw": val}
    if len(val) >= 3:
        d["app_id"] = val[0]
        d["service_id"] = val[1:3]
    if len(val) >= 15:
        d["lt_address"] = val[3:15]
        d["bic"] = val[3:11]
    if len(val) >= 19:
        d["session_number"] = val[15:19]
    if len(val) >= 25:
        d["sequence_number"] = val[19:25]
    return d


def _parse_block2(val):
    """Application header: input (I<MT><receiver><prio>...) or output (O<MT>...)."""
    d = {"raw": val}
    if not val:
        return d
    d["direction"] = "input" if val[0] == "I" else ("output" if val[0] == "O" else val[0])
    if len(val) >= 4:
        d["message_type"] = val[1:4]
    if val[0] == "I" and len(val) >= 16:
        d["receiver_address"] = val[4:16]
        d["receiver_bic"] = val[4:12]
        if len(val) >= 17:
            d["priority"] = val[16]
    elif val[0] == "O":
        # Output header: O | MT(3) | input time(4) | MIR(28) | output date(6) | output time(4) | prio(1).
        # The MIR (Message Input Reference) is 28 chars = input date(6) + input LT address(12) +
        # session(4) + input sequence(6); output date/time follow it, not at offset 28.
        if len(val) >= 8:
            d["input_time"] = val[4:8]
        if len(val) >= 36:
            d["message_input_reference"] = val[8:36]
            d["input_date"] = val[8:14]
            d["sender_lt_address"] = val[14:26]
            d["sender_bic"] = val[14:22]
        if len(val) >= 42:
            d["output_date"] = val[36:42]
        if len(val) >= 46:
            d["output_time"] = val[42:46]
        if len(val) >= 47:
            d["priority"] = val[46]
    return d


def _parse_block4_fields(val):
    """Text block -> [(tag, name, value)]; values may span multiple lines up to the next :TAG:."""
    body = val
    # the text block ends with '-' (from the '-}' terminator)
    if body.rstrip().endswith("-"):
        body = body.rstrip()[:-1]
    fields = []
    matches = list(_SWIFT_TAG_RE.finditer(body))
    for idx, m in enumerate(matches):
        tag = m.group(1)
        vstart = m.end()
        vend = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        value = body[vstart:vend].strip("\r\n")
        fields.append({"tag": tag, "name": SWIFT_TAGS.get(tag, "unknown field"),
                       "value": value, "decoded": _swift_field_decode(tag, value)})
    return fields


def _swift_field_decode(tag, value):
    """Light structured read of a few MT103 fields (32A amount, 71A charge code)."""
    if tag == "32A":
        m = re.match(r"^(\d{6})([A-Z]{3})([0-9,]+)$", value.strip())
        if m:
            d, ccy, amt = m.groups()
            return {"value_date": f"20{d[0:2]}-{d[2:4]}-{d[4:6]}", "currency": ccy,
                    "amount": amt.replace(",", ".")}
    if tag == "33B":
        m = re.match(r"^([A-Z]{3})([0-9,]+)$", value.strip())
        if m:
            return {"currency": m.group(1), "amount": m.group(2).replace(",", ".")}
    if tag == "71A":
        return {"charge_bearer": value.strip()}
    return None


def parse_swift(data: bytes):
    """Parse a SWIFT FIN / MT message. Returns a result dict, or None if no block structure found."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")
    blocks_raw = _split_swift_blocks(text)
    has_blocks = bool(blocks_raw)
    has_tags = bool(_SWIFT_TAG_RE.search(text))
    if not has_blocks and not has_tags:
        return None

    blocks = {}
    mt = None
    flags = []
    for bid, val in blocks_raw:
        if bid == "1":
            blocks["1"] = _parse_block1(val)
        elif bid == "2":
            b2 = _parse_block2(val)
            blocks["2"] = b2
            mt = b2.get("message_type") or mt
        elif bid == "3":
            blocks["3"] = {"raw": val, "subfields": _split_swift_blocks(val)}
        elif bid == "4":
            fields = _parse_block4_fields(val)
            blocks["4"] = {"raw": val, "fields": fields}
            for f in fields:
                flags += find_flags(f["value"])
        elif bid == "5":
            blocks["5"] = {"raw": val, "subfields": _split_swift_blocks(val)}
        else:
            blocks[bid] = {"raw": val}

    # a bare text block (no {4:} wrapper) still yields fields
    if "4" not in blocks and has_tags:
        fields = _parse_block4_fields(text)
        if fields:
            blocks["4"] = {"raw": text, "fields": fields}
            for f in fields:
                flags += find_flags(f["value"])

    if not blocks:
        return None
    flags += find_flags(text) if not flags else []
    return {"type": "swift", "message_type": mt, "blocks": blocks,
            "flags": list(dict.fromkeys(flags))}


# ============================================================================ pcap input (scapy)

def _looks_pcap(data: bytes) -> bool:
    magic = data[:4]
    return magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                     b"\x0a\x0d\x0d\x0a")           # last is pcapng


def pcap_payloads(path):
    """[(label, payload_bytes)] of TCP/UDP payloads in a pcap/pcapng: each packet's payload, plus
    each reassembled per-flow stream. Uses scapy; returns [] if scapy is missing or the read fails."""
    try:
        import logging
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import PcapReader, Raw, TCP, UDP          # noqa: N811
    except Exception:
        return []
    out = []
    flows = {}
    try:
        with PcapReader(str(path)) as rd:
            for idx, pkt in enumerate(rd):
                if idx >= MAX_PCAP_PKTS or len(out) >= MAX_PAYLOADS:
                    break
                if not pkt.haslayer(Raw):
                    continue
                load = bytes(pkt[Raw].load)
                if not load:
                    continue
                proto, sport, dport = "ip", 0, 0
                if pkt.haslayer(TCP):
                    proto, sport, dport = "tcp", int(pkt[TCP].sport), int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    proto, sport, dport = "udp", int(pkt[UDP].sport), int(pkt[UDP].dport)
                out.append((f"pkt{idx} {proto} {sport}->{dport}", load))
                flows.setdefault((proto, sport, dport), bytearray()).extend(load)
    except Exception:
        return out
    for (proto, sport, dport), buf in flows.items():
        if len(buf) > 0 and bytes(buf) not in (p for _, p in out):
            out.append((f"flow {proto} {sport}->{dport} (reassembled)", bytes(buf)))
    return out


# ============================================================================ analysis dispatch

def analyze_bytes(data: bytes, force=None, iso_encoding="auto", iso_spec="1987", strip_mli=False,
                  allow_hex=True):
    """Return [result, ...] for a raw payload: every parser (or only the forced one) that fits.
    If the payload is an ASCII hex dump it is also tried after un-hexing."""
    def want(kind):
        return force is None or force == kind

    def parse_all(buf):
        found = []
        if want("swift"):
            try:
                r = parse_swift(buf)
            except Exception:
                r = None
            if r:
                found.append(r)
        if want("emv"):
            try:
                r = parse_emv(buf)
            except Exception:
                r = None
            if r:
                found.append(r)
        if want("iso8583"):
            try:
                r = parse_iso8583(buf, encoding=iso_encoding, spec=iso_spec, strip_mli=strip_mli)
            except Exception:
                r = None
            # When not explicitly forced, only accept an ISO decode that consumes the whole buffer,
            # so an EMV/SWIFT payload is not also reported as a junk partial ISO message.
            if r and (force == "iso8583" or r.get("trailing_hex", "") == ""):
                found.append(r)
        return found

    results = parse_all(data)
    # Hex is a FALLBACK: only when the raw bytes decode as nothing do we try the buffer as an
    # ASCII hex dump of a binary payload (so an all-numeric ASCII message is not also re-read as hex).
    if not results and allow_hex and _is_hexdump(data):
        try:
            results = parse_all(_unhex(data))
        except (binascii.Error, ValueError):
            results = []

    seen, uniq = set(), []
    for r in results:
        key = (r["type"], json.dumps(_jsonable(r), sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return uniq


def analyze_file(path, **kw):
    """Return [(source_label, result), ...] for one file (raw payload or pcap)."""
    data = Path(path).read_bytes()
    if len(data) > MAX_FILE:
        data = data[:MAX_FILE]
    out = []
    use_pcap = kw.pop("use_pcap", True)
    if use_pcap and _looks_pcap(data):
        payloads = pcap_payloads(path)
        if not payloads:
            return [("(pcap: scapy unavailable or no payloads)", None)]
        for label, payload in payloads:
            for r in analyze_bytes(payload, **kw):
                out.append((label, r))
        return out
    for r in analyze_bytes(data, **kw):
        out.append(("(raw payload)", r))
    if not out:
        out.append(("(raw payload)", None))
    return out


# ============================================================================ JSON rendering

def _jsonable(obj):
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).hex().upper()
    return obj


# ============================================================================ text report

def _report_iso(res, lines, tty):
    enc = res["encoding"]
    lines.append(f"  encoding: mti={enc['mti']} bitmap={enc['bitmap']} field={enc['field']} spec={enc['spec']}")
    mti = res["mti"]
    lines.append(f"  MTI {mti['raw']}"
                 + (f"  [{mti.get('version')} | {mti.get('class')} | {mti.get('function')} | {mti.get('origin')}]"
                    if "version" in mti else ""))
    for n, bm in enumerate(res["bitmaps"]):
        lines.append(f"  bitmap{n + 1}: {bm}")
    lines.append(f"  present data elements: {res['present_fields']}")
    for f in res["fields"]:
        val = _hilite(str(f["value"]), tty)
        head = f"    DE{f['de']:<3} {f['name']}"
        meta = f"[{f['format']}/{f['lentype']}" + (f" len={f['declared_len']}" if f["lentype"] != F else "") + "]"
        lines.append(f"{head} {meta}")
        lines.append(f"        = {val}")
        if f.get("note"):
            lines.append(f"        ({_hilite(f['note'], tty)})")
    if res.get("trailing_hex"):
        lines.append(f"  trailing bytes: {res['trailing_hex']}")


def _report_emv(res, lines, tty):
    lines.append(f"  TLV coverage: {res['consumed']}/{res['total']} bytes")

    def walk(nodes, indent):
        for node in nodes:
            pad = "    " + "  " * indent
            name = node.get("name", "")
            if node.get("constructed"):
                lines.append(f"{pad}{node['tag']} {name} (constructed, len={node['length']})")
                walk(node["children"], indent + 1)
            else:
                dec = node.get("decoded", {})
                extra = []
                for k in ("ascii", "pan", "track2", "numeric", "date", "time"):
                    if dec.get(k):
                        extra.append(f"{k}={_hilite(str(dec[k]), tty)}")
                if "luhn" in dec:
                    extra.append(f"luhn={'valid' if dec['luhn'] else 'INVALID'}")
                lines.append(f"{pad}{node['tag']} {name} (len={node['length']})")
                lines.append(f"{pad}    hex = {_hilite(dec.get('hex', ''), tty)}")
                if extra:
                    lines.append(f"{pad}    {'  '.join(extra)}")
    walk(res["tlvs"], 0)


def _report_swift(res, lines, tty):
    if res.get("message_type"):
        lines.append(f"  message type: MT{res['message_type']}")
    b = res["blocks"]
    if "1" in b:
        d = b["1"]
        lines.append(f"  {{1:}} basic header: app={d.get('app_id')} service={d.get('service_id')} "
                     f"LT={d.get('lt_address')} (BIC {d.get('bic')}) "
                     f"session={d.get('session_number')} seq={d.get('sequence_number')}")
    if "2" in b:
        d = b["2"]
        lines.append(f"  {{2:}} application header: {d.get('direction')} MT{d.get('message_type')} "
                     + (f"receiver={d.get('receiver_address')} (BIC {d.get('receiver_bic')}) prio={d.get('priority')}"
                        if d.get("direction") == "input" else f"out_date={d.get('output_date')} out_time={d.get('output_time')}"))
    if "3" in b:
        subs = b["3"].get("subfields", [])
        lines.append("  {3:} user header: " + " ".join(f"{{{k}:{v}}}" for k, v in subs) if subs else "  {3:} user header")
    if "4" in b:
        lines.append("  {4:} text block:")
        for f in b["4"]["fields"]:
            lines.append(f"    :{f['tag']}: {f['name']}")
            for ln in str(f["value"]).splitlines() or [""]:
                lines.append(f"        {_hilite(ln, tty)}")
            if f.get("decoded"):
                parts = "  ".join(f"{k}={v}" for k, v in f["decoded"].items())
                lines.append(f"        -> {_hilite(parts, tty)}")
    if "5" in b:
        subs = b["5"].get("subfields", [])
        lines.append("  {5:} trailer: " + " ".join(f"{{{k}:{v}}}" for k, v in subs) if subs else "  {5:} trailer")


def report(entries, tty=False) -> str:
    """Human-readable report for [(source_label, result), ...]."""
    lines = []
    all_flags = []
    for label, res in entries:
        if res is None:
            lines.append(f"# {label}: no ISO 8583 / EMV / SWIFT structure recognized")
            lines.append("")
            continue
        lines.append(f"# {label}  [{res['type']}]")
        if res["type"] == "iso8583":
            _report_iso(res, lines, tty)
        elif res["type"] == "emv":
            _report_emv(res, lines, tty)
        elif res["type"] == "swift":
            _report_swift(res, lines, tty)
        if res.get("flags"):
            all_flags += res["flags"]
            lines.append("  " + ("\x1b[1;31m" if tty else "") + f"*** FLAG(S): {res['flags']}" + ("\x1b[0m" if tty else ""))
        lines.append("")
    if all_flags:
        uniq = list(dict.fromkeys(all_flags))
        banner = "=" * 60
        lines.insert(0, "")
        lines.insert(0, ("\x1b[1;31m" if tty else "") + f"  FLAGS FOUND: {uniq}" + ("\x1b[0m" if tty else ""))
        lines.insert(0, banner)
    return "\n".join(lines)


# ============================================================================ CLI

def main(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="financial.py",
        description="Offline decoder for ISO 8583 / EMV BER-TLV / SWIFT MT payment messages. "
                    "Accepts a raw payload file, an ASCII-hex dump, or a .pcap/.pcapng (scapy).")
    ap.add_argument("files", nargs="+", help="raw payload / hex dump / pcap file(s)")
    ap.add_argument("--json", action="store_true", help="emit a JSON decode instead of the report")
    ap.add_argument("--hex", action="store_true", help="force: treat the file as an ASCII hex dump")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--iso8583", action="store_const", const="iso8583", dest="force")
    grp.add_argument("--emv", action="store_const", const="emv", dest="force")
    grp.add_argument("--swift", action="store_const", const="swift", dest="force")
    ap.add_argument("--iso-encoding", default="auto",
                    choices=["auto", "ascii", "bin-bitmap", "packed", "ascii-mti-packed"],
                    help="ISO 8583 wire encoding (default auto-detect)")
    ap.add_argument("--iso-spec", default="1987", choices=["1987", "1993"],
                    help="ISO 8583 field-definition map (default 1987)")
    ap.add_argument("--strip-mli", action="store_true",
                    help="strip a leading 2-byte big-endian message-length indicator")
    ap.add_argument("--no-pcap", action="store_true", help="never treat input as a pcap")
    args = ap.parse_args(argv)

    kw = dict(force=args.force, iso_encoding=args.iso_encoding, iso_spec=args.iso_spec,
              strip_mli=args.strip_mli, use_pcap=not args.no_pcap)

    all_entries = []
    for path in args.files:
        try:
            if args.hex:
                raw = Path(path).read_bytes()
                try:
                    payload = _unhex(raw)
                except (binascii.Error, ValueError):
                    print(f"financial.py: {path}: not a valid hex dump", file=sys.stderr)
                    continue
                entries = [("(hex payload)", r) for r in analyze_bytes(
                    payload, force=args.force, iso_encoding=args.iso_encoding,
                    iso_spec=args.iso_spec, strip_mli=args.strip_mli, allow_hex=False)]
                if not entries:
                    entries = [("(hex payload)", None)]
            else:
                entries = analyze_file(path, **kw)
        except OSError as e:
            print(f"financial.py: {path}: {e}", file=sys.stderr)
            continue
        all_entries.append((path, entries))

    if args.json:
        payload = []
        for path, entries in all_entries:
            payload.append({"file": path,
                            "results": [{"source": lbl, "decode": _jsonable(res) if res else None}
                                        for lbl, res in entries]})
        print(json.dumps(payload, indent=1))
        return 0

    tty = sys.stdout.isatty()
    for path, entries in all_entries:
        print(f"==== {path} ====")
        print(report(entries, tty=tty))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
