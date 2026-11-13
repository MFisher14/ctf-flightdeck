#!/usr/bin/env python3
"""JPEG-domain steganography: jsteg DCT-coefficient LSB extraction (wave 3, ticket #10). Offline,
pure Python (standard library only). Nothing is executed; bytes in, a verdict out.

The offline stego battery can read LSBs in the spatial domain of a PNG or BMP (carve_stego, zsteg),
but not in the DCT domain of a JPEG, where jsteg hides: jsteg replaces the least significant bit of
every quantised DCT coefficient that is not 0 and not 1, in decode order, and reads them back the
same way. zsteg and zxing cannot do this and there is no pure-Python reader for it in the tree.

This module decodes a BASELINE (sequential Huffman) JPEG far enough to recover those coefficients
(SOF0/SOF1 only; a progressive JPEG, SOF2, is declined), pulls the jsteg bitstream, and hands the
carved bytes to stego_containers.validate_container. The never-wrong rule holds: the carved bytes
are PLAIN only when they prove themselves -- a stored length+CRC, or a complete file structure
(magic + sizer). Printable-but-unproven bytes are an unsure candidate; an ambiguous or failed
decode is None. The flag is never used or submitted.

  extract_jsteg(data) -> bytes | None     the raw jsteg bitstream of a baseline JPEG as bytes (MSB
                                          first), capped at MAX_BYTES; None when it is not a
                                          baseline JPEG this reader decodes.
  survey(data) -> dict                    JPEG-domain survey (research ticket #9): DCT coefficients per
                                          component x rule (jsteg, non-zero, AC-only, F5-unpermuted,
                                          every) x bit order, PLUS bit planes 0-7 of the decoded pixels;
                                          same proof rule as read(); CLI flag --survey.
  read(data) -> dict                   {plain, method, channel: 'jsteg', candidates, notes}:
                                          plain only on self-validation, else candidates/None.

No `solve_set`, no `signals`: a hand tool, like stego_tools.py and carve_stego's sandbox side.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (str(HERE),):
    if _p not in sys.path:
        sys.path.append(_p)

import stego_containers as sc      # noqa: E402  (shared self-validating-container test)
import carve_stego as cs           # noqa: E402

MAX_BYTES = 1 << 18        # jsteg bitstream bytes recovered before stopping (bounded)
MAX_BLOCKS = 1 << 20       # a ceiling on decoded 8x8 blocks, so a malformed header cannot spin


# ---- a byte-stuffing bit reader over the entropy-coded segment -------------------------------------

class _BitReader:
    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos
        self.acc = 0
        self.nbits = 0
        self.marker = None      # set to the marker byte when FFxx (xx != 00, FF) is reached
        self.done = False

    def _next_byte(self):
        d = self.data
        n = len(d)
        while True:
            if self.pos >= n:
                self.done = True
                return None
            b = d[self.pos]
            self.pos += 1
            if b != 0xFF:
                return b
            if self.pos >= n:
                self.done = True
                return None
            nb = d[self.pos]
            if nb == 0x00:
                self.pos += 1
                return 0xFF         # stuffed literal
            if nb == 0xFF:
                continue            # fill byte, skip
            self.marker = nb        # a real marker: stop feeding bits
            self.pos += 1
            return None

    def read_bit(self):
        if self.nbits == 0:
            if self.marker is not None or self.done:
                return None
            b = self._next_byte()
            if b is None:
                return None
            self.acc = b
            self.nbits = 8
        self.nbits -= 1
        return (self.acc >> self.nbits) & 1

    def read_bits(self, n: int):
        v = 0
        for _ in range(n):
            bit = self.read_bit()
            if bit is None:
                return None
            v = (v << 1) | bit
        return v

    def sync_restart(self) -> bool:
        """Byte-align and step over the next RSTn marker (D0-D7). True when one was consumed."""
        self.nbits = 0
        self.acc = 0
        if self.marker is not None:
            m = self.marker
            self.marker = None
            return 0xD0 <= m <= 0xD7
        d, n = self.data, len(self.data)
        while self.pos + 1 < n:
            if d[self.pos] == 0xFF:
                nb = d[self.pos + 1]
                if 0xD0 <= nb <= 0xD7:
                    self.pos += 2
                    return True
                if nb != 0x00:
                    return False
            self.pos += 1
        return False


def _huff_decode(reader: _BitReader, table: dict):
    code = 0
    for length in range(1, 17):
        bit = reader.read_bit()
        if bit is None:
            return None
        code = (code << 1) | bit
        v = table.get((length, code))
        if v is not None:
            return v
    return None


def _build_table(counts, values) -> dict:
    table, code, vi = {}, 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            if vi >= len(values):
                return table
            table[(length, code)] = values[vi]
            vi += 1
            code += 1
        code <<= 1
    return table


def _extend(v: int, s: int) -> int:
    return v - ((1 << s) - 1) if v < (1 << (s - 1)) else v


# ---- the baseline JPEG parse + decode --------------------------------------------------------------

class _Unsupported(Exception):
    pass


def _parse(data: bytes):
    """Read the markers up to and including SOS; return (frame, scan, sos_data_offset) or raise
    _Unsupported. frame: {w, h, comps: [{id,h,v,tq}]}. scan: {comps: [{id,td,ta}], dri}."""
    if data[:2] != b"\xff\xd8":
        raise _Unsupported("not a JPEG (no SOI)")
    dc_tables, ac_tables = {}, {}
    frame = None
    dri = 0
    i, n = 2, len(data)
    while i + 2 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m in (0x01,) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xD9:                       # EOI before SOS
            raise _Unsupported("no scan")
        if i + 4 > n:
            raise _Unsupported("truncated")
        ln = struct.unpack_from(">H", data, i + 2)[0]
        seg = data[i + 4:i + 2 + ln]
        if m in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            raise _Unsupported("not a baseline/extended-sequential Huffman JPEG (SOF%d)" % (m - 0xC0))
        if m in (0xC0, 0xC1):               # SOF0 baseline, SOF1 extended sequential
            _prec, h, w, nf = struct.unpack_from(">BHHB", seg, 0)
            comps = []
            off = 6
            for _ in range(nf):
                cid, hv, tq = struct.unpack_from(">BBB", seg, off)
                comps.append({"id": cid, "h": hv >> 4, "v": hv & 0xF, "tq": tq})
                off += 3
            frame = {"w": w, "h": h, "comps": comps}
        elif m == 0xC4:                     # DHT
            off = 0
            while off + 17 <= len(seg):
                tc_th = seg[off]
                tc, th = tc_th >> 4, tc_th & 0xF
                counts = list(seg[off + 1:off + 17])
                total = sum(counts)
                values = list(seg[off + 17:off + 17 + total])
                (ac_tables if tc else dc_tables)[th] = _build_table(counts, values)
                off += 17 + total
        elif m == 0xDD:                     # DRI
            dri = struct.unpack_from(">H", seg, 0)[0]
        elif m == 0xDA:                     # SOS
            ns = seg[0]
            scomps = []
            off = 1
            for _ in range(ns):
                cs_id, tdta = struct.unpack_from(">BB", seg, off)
                scomps.append({"id": cs_id, "td": tdta >> 4, "ta": tdta & 0xF})
                off += 2
            if frame is None:
                raise _Unsupported("SOS before SOF")
            return (frame, {"comps": scomps, "dri": dri, "dc": dc_tables, "ac": ac_tables},
                    i + 2 + ln)
        i += 2 + ln
    raise _Unsupported("no scan")


def _decode_coeffs(data: bytes, limit_bits: int, comp_out=None):
    """Yield DCT coefficients of a baseline JPEG in decode order (block by block, index 0..63), up
    to about `limit_bits` coefficients worth, as a flat list of ints. Raises _Unsupported on a shape
    this reader does not decode; returns [] on a mid-stream decode failure (what decoded so far).
    `comp_out`, when a list, receives the frame-component index (0 = Y, 1 = Cb, 2 = Cr) of each
    decoded block, in order, so a caller can split the flat list into 64-coefficient blocks."""
    frame, scan, data_off = _parse(data)
    comps = frame["comps"]
    by_id = {c["id"]: c for c in comps}
    hmax = max(c["h"] for c in comps)
    vmax = max(c["v"] for c in comps)
    mcu_x = (frame["w"] + 8 * hmax - 1) // (8 * hmax)
    mcu_y = (frame["h"] + 8 * vmax - 1) // (8 * vmax)
    total_mcu = mcu_x * mcu_y
    scomps = []
    for s in scan["comps"]:
        c = by_id.get(s["id"])
        if c is None:
            raise _Unsupported("scan names an unknown component")
        dct = scan["dc"].get(s["td"])
        act = scan["ac"].get(s["ta"])
        if dct is None or act is None:
            raise _Unsupported("a Huffman table the scan uses is missing")
        scomps.append((c, dct, act))
    reader = _BitReader(data, data_off)
    pred = {c["id"]: 0 for c in comps}
    dri = scan["dri"]
    coeffs = []
    blocks = 0
    for mcu in range(total_mcu):
        if dri and mcu and mcu % dri == 0:
            if not reader.sync_restart():
                break
            for k in pred:
                pred[k] = 0
        for comp, dct, act in scomps:
            for _bv in range(comp["v"]):
                for _bh in range(comp["h"]):
                    block, dc = _decode_one(reader, dct, act, pred[comp["id"]])
                    if block is None:
                        return coeffs
                    pred[comp["id"]] = dc
                    coeffs.extend(block)
                    if comp_out is not None:
                        comp_out.append(comps.index(comp))
                    blocks += 1
                    if blocks >= MAX_BLOCKS or len(coeffs) >= limit_bits:
                        return coeffs
    return coeffs


def _decode_one(reader: _BitReader, dct: dict, act: dict, pred: int):
    block = [0] * 64
    s = _huff_decode(reader, dct)
    if s is None:
        return None, None
    diff = 0
    if s:
        v = reader.read_bits(s)
        if v is None:
            return None, None
        diff = _extend(v, s)
    dc = pred + diff
    block[0] = dc
    k = 1
    while k < 64:
        rs = _huff_decode(reader, act)
        if rs is None:
            return None, None
        r, sb = rs >> 4, rs & 0xF
        if sb == 0:
            if r == 15:
                k += 16
                continue
            break                       # end of block
        k += r
        if k > 63:
            break
        v = reader.read_bits(sb)
        if v is None:
            return None, None
        block[k] = _extend(v, sb)
        k += 1
    return block, dc


# ---- jsteg bitstream -------------------------------------------------------------------------------

def extract_jsteg(data, max_bytes: int = MAX_BYTES):
    """The jsteg payload of a baseline JPEG as bytes (MSB first): the LSB of every coefficient that
    is not 0 and not 1, in decode order. None when it is not a baseline JPEG this reader decodes."""
    if not data or data[:2] != b"\xff\xd8":
        return None
    try:
        # each usable coefficient yields one bit; ask for enough coefficients to fill max_bytes,
        # with slack because 0/1 coefficients are skipped.
        coeffs = _decode_coeffs(bytes(data), limit_bits=max_bytes * 8 * 4 + 64)
    except _Unsupported:
        return None
    except Exception:
        return None
    bits = bytearray()
    for c in coeffs:
        if c != 0 and c != 1:
            bits.append(c & 1)
            if len(bits) >= max_bytes * 8:
                break
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def read(data):
    """Ticket #10. Extract the jsteg bitstream and validate it. Returns:

      {plain, method, channel: 'jsteg', candidates, notes}

    plain is set only when the carved bytes self-validate (length+CRC, or a complete file magic);
    a printable-but-unproven start is an unsure candidate; a clean JPEG or a failed decode is None."""
    result = {"plain": None, "method": "", "channel": "jsteg", "candidates": [], "notes": []}
    blob = extract_jsteg(data)
    if blob is None:
        result["notes"].append("not a baseline JPEG this reader decodes (or not a JPEG)")
        return result
    if not blob:
        result["notes"].append("no usable DCT coefficients (no jsteg capacity)")
        return result
    f = sc.validate_container(blob)
    if f.plain is not None:
        result["plain"] = f.plain
        result["method"] = f"jsteg; {f.method}"
        result["notes"].append(f"self-validated jsteg payload, {len(f.plain)} bytes ({f.method}), "
                               f"kind={cs.sniff(f.plain)}")
    elif f.candidates:
        for name, value in f.candidates:
            result["candidates"].append((f"jsteg_{name}", value))
        result["notes"].append("jsteg bytes carved but unproven (no length/CRC/magic): unsure")
    else:
        result["notes"].append("jsteg bytes carried no self-validating container: None")
    return result


# ---- the survey: every coefficient reading per component, and the decoded pixels' bit planes --------
#
# Research ticket #9's gap: the zsteg-style extractor reads PNG/BMP only. survey() reads a JPEG in
# both of its domains and applies the SAME proof rule as read(): a reading is PLAIN only when
# stego_containers.validate_container proves it (stored length + CRC-32, or a checksum-verified file
# structure; a chance match is ~2^-32 per reading). Everything else is an unsure candidate or None.
# Not covered, said out loud: F5 with its password-keyed permutation and matrix encoding, OutGuess,
# JPHide (steghide has its own tool row), and progressive JPEGs (SOF2) for the coefficient domain.

SURVEY_BYTES = 1 << 16          # bytes of each coefficient stream tried (bounded work per reading)
SURVEY_COMPS = (("all", None), ("Y", 0), ("Cb", 1), ("Cr", 2))
SURVEY_MAX_CANDIDATES = 12


def _rule_jsteg(c, k):       # jsteg: not 0 and not 1, DC included
    return c != 0 and c != 1, c & 1


def _rule_nonzero(c, k):     # every non-zero coefficient (the "keeps the ones" jsteg variant)
    return c != 0, c & 1


def _rule_ac_jsteg(c, k):    # jsteg rule, AC only
    return k != 0 and c != 0 and c != 1, c & 1


def _rule_ac_nonzero(c, k):  # every non-zero AC coefficient, plain parity
    return k != 0 and c != 0, c & 1


def _rule_f5(c, k):          # F5's un-permuted LSB of a non-zero AC: negative values are inverted
    return k != 0 and c != 0, (c & 1) if c > 0 else 1 - (c & 1)


def _rule_every(c, k):       # the LSB of every coefficient, zeros and DC included
    return True, c & 1


SURVEY_RULES = (("jsteg", _rule_jsteg), ("nonzero", _rule_nonzero), ("ac_jsteg", _rule_ac_jsteg),
                ("ac_nonzero", _rule_ac_nonzero), ("f5_nopermute", _rule_f5), ("every", _rule_every))


MIN_PROVEN = 8          # a proof shorter than this, or made of fewer than MIN_DISTINCT byte values, is
MIN_DISTINCT = 4        # not trusted as PLAIN: a flat image's constant planes match tiny CRC layouts


def _provable(payload):
    """A CRC/checksum proof is strong only for a payload with some substance: a 1-byte or constant
    'payload' read out of a flat image's constant bit plane is a structural coincidence, not a message."""
    return len(payload) >= MIN_PROVEN and len(set(payload)) >= MIN_DISTINCT


def _pack(bits, msb_first=True):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if not msb_first:
            chunk = chunk[::-1]
        byte = 0
        for b in chunk:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def _stream(coeffs, tags, comp, rule, limit_bytes):
    """The bits `rule` picks from component `comp` (None: all) in decode order, capped."""
    bits = bytearray()
    cap = limit_bytes * 8
    nblocks = len(coeffs) // 64
    for b in range(min(nblocks, len(tags))):
        if comp is not None and tags[b] != comp:
            continue
        base = b * 64
        for k in range(64):
            take, bit = rule(coeffs[base + k], k)
            if take:
                bits.append(bit)
                if len(bits) >= cap:
                    return bits
    return bits


def _judge_stream(bits, tag, plains, cands, readings):
    for msb in (True, False):
        blob = _pack(bits, msb)
        if len(blob) < 8:
            continue
        f = sc.validate_container(blob)
        label = f"{tag} {'msb' if msb else 'lsb'}-first"
        if f.plain is not None and _provable(f.plain):
            plains.setdefault(bytes(f.plain), []).append(f"{label}; {f.method}")
            readings.append(f"PLAIN {label}: {len(f.plain)} bytes ({f.method})")
        elif f.plain is not None:
            readings.append(f"degenerate {label}: {len(f.plain)}-byte checksum match not trusted (unsure)")
            cands.append((f"jpeg_{tag.replace(' ', '_')}_{'msb' if msb else 'lsb'}_short_crc", bytes(f.plain)))
        elif f.candidates:
            for name, value in f.candidates:
                cands.append((f"jpeg_{tag.replace(' ', '_')}_{'msb' if msb else 'lsb'}_{name}", value))
            readings.append(f"unsure {label}: {[n for n, _ in f.candidates]}")


def coefficient_survey(data):
    """Every component x rule x bit-order reading of a baseline JPEG's DCT coefficients, judged by
    validate_container. -> (plains {bytes: [methods]}, candidates [(name, value)], readings, notes)."""
    plains, cands, readings, notes = {}, [], [], []
    if not data or data[:2] != b"\xff\xd8":
        return plains, cands, readings, ["not a JPEG"]
    tags = []
    try:
        coeffs = _decode_coeffs(bytes(data), limit_bits=SURVEY_BYTES * 8 * 8, comp_out=tags)
    except _Unsupported as e:
        return plains, cands, readings, [f"coefficient domain not read: {e}"]
    except Exception as e:                                  # a hostile file: say so, read nothing
        return plains, cands, readings, [f"coefficient domain not read: {type(e).__name__}"]
    if len(coeffs) < 64:
        return plains, cands, readings, ["no decodable DCT blocks"]
    for cname, comp in SURVEY_COMPS:
        if comp is not None and comp not in tags:
            continue
        for rname, rule in SURVEY_RULES:
            bits = _stream(coeffs, tags, comp, rule, SURVEY_BYTES)
            _judge_stream(bits, f"dct {cname} {rname}", plains, cands, readings)
    notes.append(f"coefficient domain: {len(coeffs) // 64} blocks, {len(set(tags))} component(s) read")
    return plains, cands, readings, notes


def pixel_survey(data, deadline=None):
    """The decoded pixels' bit planes of a JPEG (Pillow decodes; nothing is executed): every bit plane
    0..7 of each colour channel set, row and column order, both bit orders. PLAIN only through
    validate_container; a byte-proven plane payload (carve_stego._plane_judge) is an unsure candidate
    (a lossy image's pixels were never a stored payload channel, so never plain on structure)."""
    import time
    plains, cands, readings, notes = {}, [], [], []
    im = cs._pillow(bytes(data))
    if im is None:
        return plains, cands, readings, ["pixel domain not decoded (Pillow missing or the image did not load)"]
    if im.width * im.height > cs.MAX_PIXELS:
        return plains, cands, readings, ["pixel domain skipped: image too large"]
    if im.mode not in ("L", "RGB"):
        im = im.convert("RGB" if len(im.getbands()) > 1 else "L")
    px = {"width": im.width, "height": im.height, "mode": im.mode, "channels": len(im.getbands()),
          "depth": 8, "data": im.tobytes(), "palette": None}
    sets = [im.mode] + ([im.mode[::-1]] + list(im.mode) if len(im.mode) == 3 else [])
    seen = set()
    for bit in range(8):
        for order in ("xy", "yx"):
            for chans in sets:
                if deadline and time.monotonic() > deadline:
                    notes.append("pixel domain: out of time")
                    return plains, cands, readings, notes
                for msb in (True, False):
                    blob = cs.lsb_extract(px, chans, bit, order, msb, max_bytes=SURVEY_BYTES)
                    tag = f"pixel bit{bit} {chans} {order} {'msb' if msb else 'lsb'}-first"
                    f = sc.validate_container(blob)
                    if f.plain is not None:
                        if _provable(f.plain):
                            plains.setdefault(bytes(f.plain), []).append(f"{tag}; {f.method}")
                            readings.append(f"PLAIN {tag}: {len(f.plain)} bytes ({f.method})")
                        else:
                            readings.append(f"degenerate {tag}: {len(f.plain)}-byte checksum match not trusted")
                        continue
                    got = cs._plane_judge(blob)
                    if got and got[2] not in seen:
                        seen.add(got[2])
                        cands.append((f"jpeg_pixel_bit{bit}_{chans}_{order}", got[2]))
                        readings.append(f"unsure {tag}: byte-proven {got[0]} {got[1] or ''}")
    notes.append(f"pixel domain: {im.width}x{im.height} {im.mode}, planes 0-7 read")
    return plains, cands, readings, notes


def survey(data, deadline=None):
    """JPEG-domain extraction, both domains. Returns the read() shape plus `readings`:

      {plain, method, channel: 'jpeg-survey', candidates, readings, notes}

    plain is set only when exactly ONE distinct payload self-validated across every reading (two
    different proven payloads are refused as ambiguous, never picked); unproven readings are unsure
    candidates (capped, de-duplicated); a clean photo gives plain None and no candidates."""
    result = {"plain": None, "method": "", "channel": "jpeg-survey", "candidates": [], "readings": [],
              "notes": []}
    if not data or data[:2] != b"\xff\xd8":
        result["notes"].append("not a JPEG: nothing read")
        return result
    plains, cands, readings, notes = coefficient_survey(data)
    p2, c2, r2, n2 = pixel_survey(data, deadline)
    for k, v in p2.items():
        plains.setdefault(k, []).extend(v)
    cands += c2
    if not plains:      # Day-26: F5 matrix encoding + extra LSB orders; only when nothing proved yet (moves no answer)
        try:
            import f5_stego as _f5
            _x = _f5.survey(data, deadline)
            if _x["plain"] is not None:
                plains[_x["plain"]] = [_x["method"]]
            cands += _x["candidates"]
            r2 = r2 + _x["readings"]
            n2 = n2 + _x["notes"]
        except Exception:
            pass
    if not plains:      # B-245: library coefficient orders, sign/DC/DQT channels; only when nothing proved yet
        try:
            import jpeg_stego_f8 as _f8
            _y = _f8.survey(data, deadline=deadline)
            for k, v in _y["proven"].items():
                plains.setdefault(k, []).extend(v)
            cands += _y["candidates"]
            r2 = r2 + _y["readings"]
            n2 = n2 + _y["notes"]
        except Exception as e:                      # said, not swallowed: the F8 readings did not run
            n2 = n2 + [f"jpeg-f8 readings not run: {type(e).__name__}: {e}"]
    result["readings"] = readings + r2
    result["notes"] += notes + n2
    if len(plains) == 1:
        payload, methods = next(iter(plains.items()))
        result["plain"] = payload
        result["method"] = methods[0]
        result["notes"].append(f"self-validated payload, {len(payload)} bytes, found by {len(methods)} "
                               f"reading(s), kind={cs.sniff(payload)}")
        return result
    if len(plains) > 1:
        result["notes"].append(f"ambiguous: {len(plains)} distinct proven payloads: none is plain")
        cands = [(f"jpeg_proven_{i}", k) for i, k in enumerate(plains)] + cands
    seen, out = set(), []
    for name, value in cands:
        key = value if isinstance(value, (str, bytes)) else repr(value)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, value))
    result["candidates"] = out[:SURVEY_MAX_CANDIDATES]
    if len(out) > SURVEY_MAX_CANDIDATES:
        result["notes"].append(f"{len(out) - SURVEY_MAX_CANDIDATES} more unsure candidate(s) not listed")
    return result


def main(argv) -> int:
    import hashlib
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    for path in argv:
        if path.startswith("--"):
            continue
        data = Path(path).read_bytes()
        r = survey(data) if "--survey" in argv else read(data)
        print(f"== {path} ({len(data)} bytes)")
        if r["plain"] is not None:
            print(f"   PLAIN  {r['method']}  {len(r['plain'])} bytes "
                  f"sha256={hashlib.sha256(r['plain']).hexdigest()[:16]}")
        for name, value in r["candidates"][:12]:
            shown = value if isinstance(value, str) else f"{len(value)} bytes"
            print(f"   unsure {name}: {shown}")
        for note in r["notes"]:
            print(f"   note   {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
