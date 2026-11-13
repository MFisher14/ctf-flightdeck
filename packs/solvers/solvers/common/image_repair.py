#!/usr/bin/env python3
"""Structural dimension repair for JPEG and GIF carriers, each validated by a clean decode.

This mirrors the contract of `solvers/toolkits/carve_stego.py::png_fix_dimensions` (which recovers a
corrupted PNG IHDR width/height by making the IHDR CRC match) for two more carriers that have NO
dimension checksum: JPEG and GIF. Where PNG gets a free self-check from the IHDR CRC, JPEG and GIF
are validated instead by a full offline decode of the pixel stream:

  * JPEG: a strict baseline (SOF0) Huffman walk of the entropy-coded scan. The scan does not depend
    on the stored width/height at all -- it is a flat sequence of MCUs whose structure is fixed by
    the sampling factors in SOF -- so decoding to the EOI marker yields the EXACT total MCU count T.
    A stored width pins mcus-per-line, and T/mpl then pins the MCU rows; a stored height pins the
    rows and T/rows pins the columns. The recovered dimension is reported at MCU-block granularity
    (a whole number of 8*Hmax / 8*Vmax pixel blocks -- the decoded extent of the image), which is the
    exact pixel size for an MCU-aligned image (the usual CTF case: a dimension field zeroed on an
    otherwise intact JPEG) and is an upper bound within one MCU block otherwise (the `mcu_granularity`
    field says so, and a caller must not submit a sub-MCU pixel count as PLAIN unless alignment is
    independently known). Progressive (SOF2) scans are NOT walked here and return None.

  * GIF: a full LZW decode of the first image block. A conformant stream emits exactly one color index
    per pixel, so for a well-formed image the decoded length N equals width*height. But N is only an
    UPPER BOUND on the true pixel count: there is no dimension checksum, and a non-minimal / overshooting
    stream (the norm for adversarial stego carriers) decodes cleanly to EOI yet emits MORE indices than
    there are pixels. So a stored image width gives a CANDIDATE height = N/width (and vice versa) that is
    reported NOT exact (`exact=False`, bound `(1, recovered)`), never a PLAIN count. Only a repair that
    reads both frame axes from the file and validates iw*ih==N -- the logical-screen-descriptor-only
    case -- yields proven-exact frame dimensions. A corrupted/zeroed logical-screen descriptor is
    restored to the minimal canvas that contains the frame.

NEVER-WRONG (the whole point of the module). A repair is returned ONLY when it is proven unique:

  * the patched bytes decode cleanly end-to-end (every entropy byte / every LZW code consumed, the
    stream terminating exactly at EOI / the LZW end code, with no leftover and no error), AND
  * the recovered dimension pair is the ONLY one consistent with that clean decode.

If NO dimension pair decodes cleanly, or MORE THAN ONE does (e.g. BOTH axes unknown, where the decode
pins only the product width*height and every factor pair is equally clean), or the decode is partial /
ambiguous, the answer is None. This module never guesses and never "picks one"; it only produces a
structural fix it can prove. It submits nothing and judges nothing -- the caller feeds `fixed_bytes`
to the existing image/stego readers (carried by an agent or a lane `day_patch.py`).

  fix_jpeg(data) -> {"width", "height", "fixed_bytes", ...} | None
  fix_gif(data)  -> {"width", "height", "fixed_bytes", ...} | None

Pure offline byte math: the standard library only (struct). No Game Master request, no token, nothing
executed, nothing written. Nothing imported from, and nothing edited in, any shipped solver.
"""
import struct

__all__ = ["fix_jpeg", "fix_gif", "fix_magic"]

MAX_DIM = 1 << 16          # JPEG/GIF both store dimensions in 16 bits
MCU_CAP = 8 * 1000 * 1000  # a sane ceiling on MCUs / LZW output, so a hostile file cannot spin

PNG_SIG = b"\x89PNG\r\n\x1a\n"


# ====================================================================================================
# JPEG
# ====================================================================================================

class _StopScan(Exception):
    """Raised by the bit reader when the entropy stream ends (EOI, another marker, or data end)."""
    def __init__(self, eoi: bool, marker=None):
        self.eoi = eoi
        self.marker = marker


class _Corrupt(Exception):
    """A Huffman code that is not in the table, or a restart marker out of place."""


class _BitReader:
    """MSB-first bit reader over a JPEG entropy segment, honouring 0xFF00 byte-stuffing and stopping
    on a real marker. It never interprets 0xFFD9 (EOI) as data: 0xFF in the stream is always a stuff
    byte (0xFF00) or a marker, so the reader's view of the bytes is unambiguous."""

    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos
        self.cur = 0
        self.nbits = 0

    def _nextbyte(self) -> int:
        d = self.data
        if self.pos >= len(d):
            raise _StopScan(False)
        b = d[self.pos]
        if b == 0xFF:
            if self.pos + 1 >= len(d):
                raise _StopScan(False)
            nxt = d[self.pos + 1]
            if nxt == 0x00:
                self.pos += 2
                return 0xFF
            if nxt == 0xD9:
                raise _StopScan(True, 0xD9)
            raise _StopScan(False, nxt)   # restart marker mid-byte, or any other marker: end of run
        self.pos += 1
        return b

    def bit(self) -> int:
        if self.nbits == 0:
            self.cur = self._nextbyte()
            self.nbits = 8
        self.nbits -= 1
        return (self.cur >> self.nbits) & 1

    def bits(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bit()
        return v

    def align(self):
        self.nbits = 0


def _build_huff(counts, symbols):
    """Map (code length, code) -> symbol for one Huffman table."""
    table = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            table[(length, code)] = symbols[k]
            k += 1
            code += 1
        code <<= 1
    return table


def _huff_decode(br: _BitReader, table) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | br.bit()
        sym = table.get((length, code))
        if sym is not None:
            return sym
    raise _Corrupt


def _decode_block(br: _BitReader, dc, ac):
    """Consume the bits of one 8x8 block (values discarded -- only bit consumption matters)."""
    s = _huff_decode(br, dc)
    if s:
        br.bits(s)
    k = 1
    while k <= 63:
        rs = _huff_decode(br, ac)
        r = rs >> 4
        sz = rs & 0x0F
        if sz == 0:
            if r != 15:
                break          # EOB
            k += 16
        else:
            k += r
            br.bits(sz)
            k += 1


def _parse_jpeg(data: bytes):
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None
    i, n = 2, len(data)
    huff = {}
    dri = 0
    sof = None
    sof_off = None
    progressive = False
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD8 or m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xD9:
            break
        if i + 4 > n:
            break
        ln = struct.unpack_from(">H", data, i + 2)[0]
        if ln < 2 or i + 2 + ln > n:
            break
        seg = data[i + 4:i + 2 + ln]
        if m in (0xC0, 0xC1, 0xC2):
            if len(seg) < 6:
                return None
            precision = seg[0]
            height, width = struct.unpack_from(">HH", seg, 1)
            ncomp = seg[5]
            if precision != 8 or len(seg) < 6 + 3 * ncomp or ncomp < 1:
                return None
            comps = {}
            for c in range(ncomp):
                cid = seg[6 + 3 * c]
                hv = seg[7 + 3 * c]
                comps[cid] = (hv >> 4, hv & 0x0F)
            sof = {"precision": precision, "height": height, "width": width, "comps": comps}
            sof_off = i
            progressive = (m == 0xC2)
        elif m == 0xC4:
            pos = 0
            while pos + 17 <= len(seg):
                tc_th = seg[pos]
                counts = seg[pos + 1:pos + 17]
                total = sum(counts)
                symbols = seg[pos + 17:pos + 17 + total]
                if len(symbols) < total:
                    break
                huff[(tc_th >> 4, tc_th & 0x0F)] = _build_huff(counts, symbols)
                pos += 17 + total
        elif m == 0xDD and len(seg) >= 2:
            dri = struct.unpack_from(">H", seg, 0)[0]
        elif m == 0xDA:
            ns = seg[0]
            if len(seg) < 1 + 2 * ns:
                return None
            scan = []
            for c in range(ns):
                cs = seg[1 + 2 * c]
                td_ta = seg[2 + 2 * c]
                scan.append((cs, td_ta >> 4, td_ta & 0x0F))
            return {"sof": sof, "sof_off": sof_off, "huff": huff, "dri": dri,
                    "scan": scan, "scan_start": i + 2 + ln, "progressive": progressive}
        i += 2 + ln
    return None


def _jpeg_blockspec(info):
    """(blockspec, step_x, step_y) or None. blockspec is [(dc_table, ac_table, blocks_per_mcu)]."""
    sof = info["sof"]
    if sof is None or info["progressive"]:
        return None
    comps = sof["comps"]
    scan = info["scan"]
    hmax = max(h for h, _ in comps.values())
    vmax = max(v for _, v in comps.values())
    spec = []
    interleaved = len(scan) > 1
    for (cs, td, ta) in scan:
        if cs not in comps:
            return None
        h, v = comps[cs]
        dc = info["huff"].get((0, td))
        ac = info["huff"].get((1, ta))
        if dc is None or ac is None:
            return None
        spec.append((dc, ac, (h * v) if interleaved else 1))
    if interleaved:
        step_x, step_y = 8 * hmax, 8 * vmax
    else:
        # non-interleaved single-component scan: one block per data unit (8x8); for grayscale
        # (h=v=1) this is the whole-image block grid.
        step_x = step_y = 8
    return spec, step_x, step_y


def _jpeg_total_mcus(data: bytes, info, spec):
    """Walk the entropy stream MCU by MCU to EOI. Returns (T, clean): T complete MCUs, clean True iff
    the walk ended exactly at EOI on an MCU boundary. The walk is independent of the stored
    width/height, so T is the true total MCU count of the image."""
    br = _BitReader(data, info["scan_start"])
    dri = info["dri"]
    mcu = 0
    d = data
    try:
        while True:
            if dri and mcu > 0 and mcu % dri == 0:
                br.align()
                p = br.pos
                if p + 1 >= len(d) or d[p] != 0xFF:
                    return mcu, False
                nxt = d[p + 1]
                if nxt == 0xD9:
                    return mcu, True
                if 0xD0 <= nxt <= 0xD7:
                    br.pos = p + 2
                    br.nbits = 0
                else:
                    return mcu, False
            # EOI directly ahead at an MCU boundary (0xFFD9 can only be the real marker)?
            p = br.pos
            if p + 1 < len(d) and d[p] == 0xFF and d[p + 1] == 0xD9:
                return mcu, True
            for (dc, ac, cnt) in spec:
                for _ in range(cnt):
                    _decode_block(br, dc, ac)
            mcu += 1
            if mcu > MCU_CAP:
                return mcu, False
    except _StopScan as e:
        # EOI reached while trying to decode the (mcu+1)-th MCU off the fill bits: the image had
        # exactly `mcu` MCUs and the end is clean.
        return mcu, bool(e.eoi)
    except (_Corrupt, IndexError):
        return mcu, False


def _patch_jpeg(data: bytes, sof_off: int, width: int, height: int) -> bytes:
    out = bytearray(data)
    struct.pack_into(">H", out, sof_off + 4 + 1, height)   # SOF body: precision(1), height(2), width(2)
    struct.pack_into(">H", out, sof_off + 4 + 3, width)
    return bytes(out)


def _pillow_ok(data: bytes, width: int, height: int) -> bool:
    """Optional independent confirmation. True when Pillow is absent (we then rely on our own decoder);
    True when Pillow opens the bytes at the given size; False only when Pillow raises."""
    try:
        from PIL import Image
        import io
    except Exception:
        return True
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
        return (im.width, im.height) == (width, height)
    except Exception:
        return False


def fix_jpeg(data):
    """Recover a JPEG's SOF width/height by brute dimensions validated by a clean baseline decode.

    Returns a dict or None. The dict has:
      "width", "height"   the dimensions patched into the SOF (bytes that decode cleanly);
      "fixed_bytes"       the repaired JPEG;
      "mcu_granularity"   (step_x, step_y), the MCU block size in pixels;
      "exact"             bool -- whether the recovered pixel dimensions are PROVABLY exact. This is
                          ALWAYS False for a JPEG whose axis was recovered here: a JPEG's entropy data
                          encodes only whole MCUs, so a recovered axis is pinned only to its MCU-block
                          extent and the true pixel size may be up to one block smaller (the image's
                          last MCU row/column may be cropped). A caller must NOT submit a recovered
                          JPEG pixel dimension as a PLAIN answer; it is the decoded extent, not a
                          proven count.
      "bounds"            {"width": (lo, hi), "height": (lo, hi)} -- the proven inclusive pixel range of
                          each axis (lo==hi on an axis that was not recovered);
      "total_mcus", "repaired": [...]
    None when the SOF cannot be parsed, the scan is progressive, the entropy stream does not decode
    cleanly, or the MCU grid is not uniquely determined (notably when BOTH axes are unknown -- the
    decode pins only the product width*height, so every factor pair is equally clean)."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    info = _parse_jpeg(data)
    if info is None or info["sof"] is None:
        return None
    if info["progressive"]:
        return None                      # not validated here
    bs = _jpeg_blockspec(info)
    if bs is None:
        return None
    spec, step_x, step_y = bs
    total, clean = _jpeg_total_mcus(data, info, spec)
    if not clean or total < 1:
        return None

    sof = info["sof"]
    w0, h0 = sof["width"], sof["height"]
    w_bad = (w0 == 0 or w0 > MAX_DIM)
    h_bad = (h0 == 0 or h0 > MAX_DIM)

    def grid_ok(mpl, rows):
        return mpl >= 1 and rows >= 1 and mpl * rows == total and mpl * step_x <= MAX_DIM and rows * step_y <= MAX_DIM

    candidates = []   # (width, height)
    if not w_bad and not h_bad:
        mpl = (w0 + step_x - 1) // step_x
        rows = (h0 + step_y - 1) // step_y
        if grid_ok(mpl, rows):
            return None                  # nothing to fix: the stored dimensions already decode cleanly
        # dimensions present but inconsistent with the data; which axis is wrong is unprovable
        return None
    elif w_bad and not h_bad:
        rows = (h0 + step_y - 1) // step_y
        if rows >= 1 and total % rows == 0:
            mpl = total // rows
            if grid_ok(mpl, rows):
                candidates.append((mpl * step_x, h0))
    elif h_bad and not w_bad:
        mpl = (w0 + step_x - 1) // step_x
        if mpl >= 1 and total % mpl == 0:
            rows = total // mpl
            if grid_ok(mpl, rows):
                candidates.append((w0, rows * step_y))
    else:
        # both axes unknown: the decode pins only mpl*rows == total. Every factor pair is an equally
        # clean decode, so a unique answer exists only for total == 1.
        seen = set()
        a = 1
        while a * a <= total:
            if total % a == 0:
                for mpl, rows in ((a, total // a), (total // a, a)):
                    if grid_ok(mpl, rows):
                        seen.add((mpl * step_x, rows * step_y))
            a += 1
        candidates = list(seen)

    if len(candidates) != 1:
        return None
    width, height = candidates[0]
    fixed = _patch_jpeg(data, info["sof_off"], width, height)
    # self-check: the patched bytes re-decode cleanly to exactly this MCU grid
    info2 = _parse_jpeg(fixed)
    if info2 is None:
        return None
    t2, clean2 = _jpeg_total_mcus(fixed, info2, spec)
    if not clean2 or t2 != total:
        return None
    if not _pillow_ok(fixed, width, height):
        return None
    repaired = [k for k, bad in (("width", w_bad), ("height", h_bad)) if bad]
    bounds = {"width": (width, width), "height": (height, height)}
    if "width" in repaired:
        bounds["width"] = (max(1, width - step_x + 1), width)
    if "height" in repaired:
        bounds["height"] = (max(1, height - step_y + 1), height)
    return {"width": width, "height": height, "fixed_bytes": fixed,
            "mcu_granularity": (step_x, step_y), "exact": False, "bounds": bounds,
            "total_mcus": total, "repaired": repaired}


# ====================================================================================================
# GIF
# ====================================================================================================

def _gif_lzw_count(comp: bytes, mcs: int):
    """Full LZW decode of one GIF image's code stream. Returns (output_index_count, clean): clean True
    iff the stream terminated on the end-of-information code with no invalid code. Only index COUNTS
    are tracked (table entries are stored as (length, first_symbol)), which is all a dimension check
    needs."""
    if not (2 <= mcs <= 11):
        return 0, False
    clear = 1 << mcs
    end = clear + 1
    size = mcs + 1
    table = {i: (1, i) for i in range(clear)}
    next_code = end + 1
    bitbuf = 0
    bitcnt = 0
    i = 0
    n = len(comp)
    out_len = 0
    prev = None
    steps = 0
    while True:
        steps += 1
        if steps > MCU_CAP:
            return out_len, False
        while bitcnt < size:
            if i >= n:
                return out_len, False          # ran out before the end code: not clean
            bitbuf |= comp[i] << bitcnt
            bitcnt += 8
            i += 1
        code = bitbuf & ((1 << size) - 1)
        bitbuf >>= size
        bitcnt -= size
        if code == clear:
            size = mcs + 1
            next_code = end + 1
            prev = None
            for k in [k for k in table if k > end]:
                del table[k]
            continue
        if code == end:
            return out_len, True
        if prev is None:
            if code not in table:
                return out_len, False
            entry = table[code]
        else:
            if code in table:
                entry = table[code]
            elif code == next_code:
                entry = (prev[0] + 1, prev[1])
            else:
                return out_len, False
            table[next_code] = (prev[0] + 1, prev[1])
            next_code += 1
            if next_code == (1 << size) and size < 12:
                size += 1
        out_len += entry[0]
        if out_len > MCU_CAP:
            return out_len, False
        prev = entry


def _gif_structure(data: bytes):
    """Parse a GIF far enough to recover and patch dimensions. Returns a dict with the logical-screen
    offsets/values and every image block's descriptor offset, dimensions and decoded pixel count, or
    None when it is not a GIF / is truncated."""
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    sw, sh = struct.unpack_from("<HH", data, 6)
    packed = data[10]
    i = 13
    if packed & 0x80:
        i += 3 * (2 << (packed & 7))
    images = []
    n = len(data)
    try:
        while i < n:
            b = data[i]
            if b == 0x3B:                      # trailer
                break
            if b == 0x21:                      # extension
                i += 2
                while i < n:
                    ln = data[i]
                    i += 1 + ln
                    if ln == 0:
                        break
                continue
            if b == 0x2C:                      # image descriptor
                if i + 10 > n:
                    return None
                left, top, iw, ih = struct.unpack_from("<HHHH", data, i + 1)
                ipacked = data[i + 9]
                desc_off = i
                i += 10
                if ipacked & 0x80:
                    i += 3 * (2 << (ipacked & 7))
                if i >= n:
                    return None
                mcs = data[i]
                i += 1
                parts = []
                while i < n:
                    ln = data[i]
                    i += 1
                    if ln == 0:
                        break
                    parts.append(data[i:i + ln])
                    i += ln
                comp = b"".join(parts)
                count, clean = _gif_lzw_count(comp, mcs)
                images.append({"desc_off": desc_off, "left": left, "top": top,
                               "width": iw, "height": ih, "pixels": count, "clean": clean})
                continue
            return None                        # unknown block: give up rather than guess
    except IndexError:
        return None
    return {"sw": sw, "sh": sh, "screen_packed": packed, "images": images}


def _pillow_gif_ok(data: bytes, width: int, height: int) -> bool:
    try:
        from PIL import Image
        import io
    except Exception:
        return True
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
        return True
    except Exception:
        return False


def fix_gif(data):
    """Recover a GIF's image-descriptor dimensions and/or repair a corrupted logical-screen descriptor,
    validated by a full LZW decode (which yields exactly width*height color indices).

    Returns {"width", "height", "fixed_bytes", "screen": (sw, sh), "pixels", "exact", "bounds",
    "repaired": [...]} or None. `width`/`height` are the first image block's (frame) dimensions.
    `exact` is True ONLY for a logical-screen-descriptor-only repair, where both frame axes were read
    from the file and validated iw*ih==N (the file's own byte-read dimensions). When an image axis was
    RECOVERED as N/known_axis, `exact` is False and that axis's bound is `(1, recovered)`: N (the LZW
    index count) is only an upper bound on the true pixel count -- there is no dimension checksum, and a
    non-minimal / overshooting stream decodes cleanly yet overcounts -- so a recovered GIF axis must
    never be submitted as a PLAIN answer. None when it is not a GIF, is truncated, has more than one
    image block (ambiguous), does not decode cleanly, or the dimensions are not uniquely determined
    (e.g. BOTH frame axes unknown, where the LZW count pins only the product)."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    st = _gif_structure(data)
    if st is None or len(st["images"]) != 1:
        return None                            # single-image GIF only; multi-frame extent is not proven
    img = st["images"][0]
    if not img["clean"] or img["pixels"] < 1:
        return None
    N = img["pixels"]
    iw, ih = img["width"], img["height"]
    w_bad = (iw == 0 or iw > MAX_DIM)
    h_bad = (ih == 0 or ih > MAX_DIM)

    repaired = []
    if not w_bad and not h_bad:
        if iw * ih != N:
            return None                        # both present but inconsistent: which is wrong is unprovable
        fw, fh = iw, ih
    elif w_bad and not h_bad:
        if N % ih != 0 or N // ih > MAX_DIM:
            return None
        fw, fh = N // ih, ih
        repaired.append("image_width")
    elif h_bad and not w_bad:
        if N % iw != 0 or N // iw > MAX_DIM:
            return None
        fw, fh = iw, N // iw
        repaired.append("image_height")
    else:
        # both frame axes unknown: LZW pins only fw*fh == N -> unique only for N == 1.
        pairs = set()
        a = 1
        while a * a <= N:
            if N % a == 0:
                for fw, fh in ((a, N // a), (N // a, a)):
                    if 1 <= fw <= MAX_DIM and 1 <= fh <= MAX_DIM:
                        pairs.add((fw, fh))
            a += 1
        if len(pairs) != 1:
            return None
        fw, fh = next(iter(pairs))
        repaired.extend(["image_width", "image_height"])

    # logical-screen descriptor: it must contain the frame. Repair it when zeroed/too small.
    need_sw = img["left"] + fw
    need_sh = img["top"] + fh
    sw, sh = st["sw"], st["sh"]
    new_sw = sw if sw >= need_sw and sw != 0 else need_sw
    new_sh = sh if sh >= need_sh and sh != 0 else need_sh
    if new_sw != sw:
        repaired.append("screen_width")
    if new_sh != sh:
        repaired.append("screen_height")

    if not repaired:
        return None                            # nothing was wrong

    out = bytearray(data)
    struct.pack_into("<HH", out, 6, new_sw, new_sh)                 # logical screen descriptor
    struct.pack_into("<HH", out, img["desc_off"] + 5, fw, fh)       # image descriptor: sep,left,top,w,h
    fixed = bytes(out)

    # self-check: re-parse and re-decode the patched bytes
    st2 = _gif_structure(fixed)
    if st2 is None or len(st2["images"]) != 1:
        return None
    im2 = st2["images"][0]
    if not im2["clean"] or im2["pixels"] != fw * fh or im2["width"] != fw or im2["height"] != fh:
        return None
    if st2["sw"] < need_sw or st2["sh"] < need_sh:
        return None
    if not _pillow_gif_ok(fixed, fw, fh):
        return None
    # A recovered IMAGE axis (image_width/image_height) is derived as N/known_axis, where N is the
    # LZW index count. N is only an UPPER BOUND on the true pixel count: a non-minimal or overshooting
    # LZW stream -- the norm for the adversarial stego carriers this module targets -- decodes cleanly
    # to EOI yet emits MORE indices than the image has pixels (a final multi-pixel code or redundant
    # literals that a spec decoder truncates). There is no checksum to pin N to the pixel count, so a
    # recovered axis is NOT a proven exact count and must never be submitted PLAIN: exact=False, and
    # the axis's bound widens to (1, recovered) (truth <= recovered), the JPEG upper-bound treatment.
    # exact=True is kept only for the screen-descriptor-only repair, where BOTH frame axes were read
    # from the file and validated iw*ih==N -- those are the file's own byte-read dimensions.
    image_axis_recovered = ("image_width" in repaired) or ("image_height" in repaired)
    bounds = {"width": (fw, fw), "height": (fh, fh)}
    if "image_width" in repaired:
        bounds["width"] = (1, fw)
    if "image_height" in repaired:
        bounds["height"] = (1, fh)
    return {"width": fw, "height": fh, "fixed_bytes": fixed, "screen": (new_sw, new_sh),
            "pixels": N, "exact": not image_axis_recovered, "bounds": bounds,
            "repaired": repaired}


# ====================================================================================================
# Magic / signature repair (no dimension involved)
# ====================================================================================================
#
# The dimension repairs above assume the file already parses as its format. These CTF carriers break
# one layer earlier: the file's MAGIC is damaged, so no decoder will even open it. Three habits recur
# (2024 "Magical Bytes 1/2", and the generic "junk before the PNG signature"):
#
#   * junk bytes PREPENDED before an otherwise intact signature (carve the real start);
#   * a signature whose bytes had their NIBBLES swapped per byte -- the 2024 "Magical Bytes 2" trick,
#     where GIF's "GIF89a" (47 49 46 38 39 61) shipped as 74 94 64 83 93 16 ("`74 94 64 83`" in the
#     writeup), optionally ALSO behind a junk prefix ("dd skip=13 then fix the magic");
#   * the two combined.
#
# NEVER-WRONG, same contract as above: a corrected file is returned ONLY when the patched bytes parse
# cleanly as the claimed format (PNG: signature + an IHDR chunk whose CRC is valid; GIF: a full
# structural + LZW parse; JPEG: SOI + a real SOFn). A 6-byte exact signature match (direct or
# nibble-swapped) plus that structural re-validation makes a false positive effectively impossible.
# If zero corrections validate, or more than one distinct corrected file validates (ambiguous), the
# answer is None -- this never guesses which repair was meant.

_JUNK_CAP = 4096     # how far in to look for a prepended signature (a sane ceiling, not a guess)

# (signature, kind). Order matters only for reporting; uniqueness is enforced on the bytes.
_MAGICS = (
    (PNG_SIG, "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF89a", "gif"),
    (b"GIF87a", "gif"),
)


def _nibswap(b: int) -> int:
    """Swap the two nibbles of a byte: 0x47 <-> 0x74."""
    return ((b & 0x0F) << 4) | ((b >> 4) & 0x0F)


def _png_ihdr_ok(d: bytes) -> bool:
    """A PNG signature followed by a length-13 IHDR chunk whose stored CRC is valid."""
    if not d.startswith(PNG_SIG) or len(d) < 8 + 4 + 4 + 13 + 4:
        return False
    if d[8:12] != b"\x00\x00\x00\x0d" or d[12:16] != b"IHDR":
        return False
    import zlib
    body = d[12:16 + 13]                                 # "IHDR" + 13-byte payload
    stored = struct.unpack_from(">I", d, 16 + 13)[0]
    return (zlib.crc32(body) & 0xFFFFFFFF) == stored


def _magic_valid(kind: str, d: bytes) -> bool:
    if kind == "png":
        return _png_ihdr_ok(d)
    if kind == "gif":
        st = _gif_structure(d)
        return st is not None and len(st["images"]) >= 1
    if kind == "jpeg":
        info = _parse_jpeg(d)
        return info is not None and info["sof"] is not None
    return False


def _already_valid_image(data: bytes) -> bool:
    for sig, kind in _MAGICS:
        if data.startswith(sig) and _magic_valid(kind, data):
            return True
    return False


def fix_magic(data):
    """Repair a damaged image signature: a prepended junk prefix, a per-byte nibble-swapped magic, or
    both. Returns a dict or None.

    The dict has:
      "kind"              "png" | "jpeg" | "gif";
      "method"            "strip_prefix"  (junk bytes before an intact signature),
                          "nibble_swap"   (magic nibbles swapped, no junk),
                          "strip_and_nibble_swap" (junk prefix AND nibble-swapped magic);
      "junk_prefix_len"   bytes dropped from the front (0 for a pure nibble-swap);
      "orig_magic"        hex of the corrupted magic bytes that were rewritten (None for strip_prefix);
      "fixed_bytes"       the corrected file, which PARSES as `kind`.

    None when: the input already opens as an image (nothing to fix); nothing validates; or more than
    one distinct corrected file validates (ambiguous -- never guess). The correction is proven by a
    structural re-parse of `fixed_bytes` (PNG IHDR CRC / GIF LZW / JPEG SOF), so a returned fix is
    never a false positive. The repaired bytes are then handed to the normal image/stego readers (and,
    for a cropped dimension, to fix_jpeg/fix_gif)."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if len(data) < 8:
        return None
    if _already_valid_image(data):
        return None                                      # opens already -- no magic repair needed

    cands = {}                                           # fixed_bytes -> dict (dedupe on the result)
    for sig, kind in _MAGICS:
        n = len(sig)
        limit = min(len(data) - n, _JUNK_CAP)
        if limit < 0:
            continue
        swapped = bytes(_nibswap(b) for b in sig)        # what a nibble-swapped signature looks like
        for k in range(limit + 1):
            window = data[k:k + n]
            fixed = None
            method = None
            if window == sig:
                fixed = data[k:]
                method = "strip_prefix" if k else None   # k==0 & equal would mean already valid (handled)
                orig = None
            elif window == swapped and window != sig:
                fixed = sig + data[k + n:]
                method = "strip_and_nibble_swap" if k else "nibble_swap"
                orig = window.hex()
            if fixed is None or method is None:
                continue
            if _magic_valid(kind, fixed):
                cands.setdefault(fixed, {"kind": kind, "method": method,
                                         "junk_prefix_len": k, "orig_magic": orig,
                                         "fixed_bytes": fixed})
            break                                        # first (smallest-k) hit for this signature only

    if len(cands) != 1:
        return None                                      # nothing validated, or ambiguous -> never guess
    return next(iter(cands.values()))


def _main(argv) -> int:
    import sys
    if argv and argv[0] in ("-h", "--help"):
        print("usage: image_repair.py <image> [...]")
        return 0
    if not argv:
        print("image_repair.py: expected at least one image", file=sys.stderr)
        return 2
    try:
        for path in argv:
            with open(path, "rb") as fh:
                raw = fh.read()
            m = fix_magic(raw)
            if m:
                print(f"{path}: magic repair kind={m['kind']} method={m['method']} "
                      f"junk={m['junk_prefix_len']}")
                raw = m["fixed_bytes"]
            r = fix_jpeg(raw) or fix_gif(raw)
            if r:
                print(f"{path}: width={r['width']} height={r['height']} repaired={r.get('repaired')}")
            elif not m:
                print(f"{path}: no proven repair")
    except Exception as exc:
        print(f"image_repair.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
