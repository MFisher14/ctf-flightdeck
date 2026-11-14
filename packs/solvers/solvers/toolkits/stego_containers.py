#!/usr/bin/env python3
"""Self-validating steganography containers (wave 3, tickets #9 and C6). Offline except where it
calls stego_tools (steghide/stegseek), which run only inside tools/sandbox.py, off the clock.

The never-wrong rule here is one line: a value is PLAIN only when the extraction proves itself
with a stored length and CRC/checksum, or with a complete file structure whose sizer verifies a
payload checksum (gzip, zip; CHECKSUM_KINDS). A structure that only walks a self-declared length or
a trailing marker with no content checksum (png/jpeg/gif/pdf/7z/elf/pe/riff), anything that only
*looks* like text, or any extraction with no self-check, is unsure or None -- a forged or decoy
header that merely begins with the magic must never be claimed PLAIN (new-code audit v2, H12).
The flag is never used or submitted; a found payload is a fact to hand back, nothing more.

Readers an agent calls by hand (bytes in, a Finding out; nothing is executed or written):

  validate_container(blob)        the heart of it: is `blob` the start of a self-validating
                                  container? A matching CRC-32 (len+crc header, or a trailing crc)
                                  or a structurally complete file (carve_stego.judge_blob) -> PLAIN;
                                  a length-prefixed / NUL-ended printable start -> UNSURE; else None.
  read_image(image_bytes)         ticket #9: pull the usual LSB planes of a PNG, BMP, GIF (palette
                                  indices) or WebP
                                  (carve_stego.lsb_extract), run each through validate_container, and
                                  return the ONE self-validated payload as plain (two distinct
                                  self-validated payloads is ambiguous -> no plain), the text starts
                                  as unsure candidates, None when nothing validates.
  steghide_channel(data, ...)     ticket C6: steghide/stegseek carry a CRC-32 over the payload, so a
                                  successful extract is self-proving. PLAIN only under the empty
                                  passphrase or a word the QUESTION supplied; a locked cover no
                                  supplied word opens is the ARCHIVE-PASSWORD STOP (never guessed,
                                  never brute-forced beyond the question's own list).
  classify_steghide(ok, payload, passphrase, in_wordlist)   the C6 decision as a pure function, so
                                  the never-wrong logic is testable with no sandbox.

A Finding carries: .plain (bytes when self-validated, else None), .candidates [(name, value)] for an
established-but-unproven reading (feed to labels.pick / render_candidates), .need_password / .note /
.method / .channel / .validated. `Finding.pick(field, shape)` wraps the candidates as the lane's
unsure wire string (carve_stego.pick) when an agent wants it.

This module defines no `solve_set` and no `signals`: it is a hand tool, like stego_tools.py. It is
never on a timed path (steghide refuses one itself; the pure Python here reads bytes only).
"""
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.append(_p)

import carve_stego as cs       # noqa: E402

MAX_PAYLOAD = 1 << 20          # the largest container payload read or validated (bounded)
MIN_PAYLOAD = 1               # a stored length below this is not a container
LSB_CAP = 1 << 18             # bytes pulled from one LSB plane before giving up on it
MAX_CONFIGS = 10              # LSB channel/order/bit combinations tried per image

# The embedded-file kinds whose carve_stego sizer verifies a PAYLOAD checksum, so a structure match
# actually proves the content and is PLAIN-eligible: gzip inflates its whole deflate stream (zlib
# checks the gzip CRC-32 and raises on a mismatch) and a zip carries a CRC-32 per member. Every other
# container sizer (png/jpeg/gif/pdf/7z/elf/pe/riff) walks a self-declared length or a trailing marker
# with NO content checksum, so a forged/garbage/decoy header that merely begins with the magic passes
# it. A structure-only match is therefore established-but-unproven (unsure), never PLAIN
# (new-code never-wrong audit v2, H12).
CHECKSUM_KINDS = frozenset({"gzip", "zip"})


def _crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


class Finding:
    """One channel's verdict (see the module text)."""

    def __init__(self, plain=None, candidates=None, method="", channel="", validated=False,
                 need_password=False, note="", kind=None):
        self.plain = plain                      # bytes, self-validated; else None
        self.candidates = list(candidates or [])  # [(name, value)] established but unproven
        self.method = method
        self.channel = channel
        self.validated = validated
        self.need_password = need_password
        self.note = note
        self.kind = kind

    def __bool__(self):
        return self.plain is not None or bool(self.candidates) or self.need_password

    def __repr__(self):
        p = f"{len(self.plain)}B" if isinstance(self.plain, (bytes, bytearray)) else self.plain
        return (f"Finding(plain={p}, candidates={len(self.candidates)}, validated={self.validated}, "
                f"need_password={self.need_password}, method={self.method!r})")

    def pick(self, field: str, shape: str):
        """The candidates as the toolkit's unsure wire string (carve_stego.pick), or None."""
        if not self.candidates:
            return None
        return cs.pick(field, shape, self.candidates)


# ---- the self-validating container test ------------------------------------------------------------

def _try_len_crc(blob: bytes, be: bool):
    """[len:u32][crc32:u32][payload] with the two 32-bit fields in the given byte order."""
    if len(blob) < 8:
        return None
    fmt = ">I" if be else "<I"
    length = struct.unpack_from(fmt, blob, 0)[0]
    crc = struct.unpack_from(fmt, blob, 4)[0]
    if not (MIN_PAYLOAD <= length <= MAX_PAYLOAD) or 8 + length > len(blob):
        return None
    payload = blob[8:8 + length]
    if _crc32(payload) == crc:
        return payload
    return None


def _try_len_payload_crc(blob: bytes, be: bool):
    """[len:u32][payload][crc32:u32] (the length up front, the CRC after the payload)."""
    if len(blob) < 8:
        return None
    fmt = ">I" if be else "<I"
    length = struct.unpack_from(fmt, blob, 0)[0]
    if not (MIN_PAYLOAD <= length <= MAX_PAYLOAD) or 4 + length + 4 > len(blob):
        return None
    payload = blob[4:4 + length]
    crc = struct.unpack_from(fmt, blob, 4 + length)[0]
    if _crc32(payload) == crc:
        return payload
    return None


def _crc_payloads(blob: bytes):
    """Every payload a CRC-carrying layout validates, as a set (self-proving; order-agnostic)."""
    out = {}
    for be in (True, False):
        for fn, name in ((_try_len_crc, "len+crc"), (_try_len_payload_crc, "len+payload+crc")):
            p = fn(blob, be)
            if p is not None:
                out.setdefault(bytes(p), f"{name} ({'be' if be else 'le'})")
    return out


def validate_container(blob):
    """Is `blob` the start of a self-validating stego container? Returns a Finding:

      - plain, validated=True, method 'len+crc...' when a stored CRC-32 validates the payload, OR
        method 'magic:<kind>' when carve_stego.judge_blob reads a complete checksum-verified file out
        of it (gzip, zip; CHECKSUM_KINDS);
      - candidates [('carved_file', <bytes>)], validated=False, for a complete file structure of a
        kind whose sizer carries no payload checksum (png/jpeg/gif/pdf/7z/elf/pe/riff: unsure, since
        a forged or decoy header passes the structural walk -- H12);
      - candidates [('decoded_text', <text>)], validated=False, when only a length-prefixed or
        NUL-ended printable start is there (established but unproven: unsure);
      - None (falsy Finding) when nothing is readable.

    Never raises. A CRC match on random bytes is ~2^-32 per layout, so a match is a proof."""
    if not blob:
        return Finding(note="empty")
    crc_hits = _crc_payloads(blob)
    if len(crc_hits) == 1:
        payload, method = next(iter(crc_hits.items()))
        return Finding(plain=payload, method=method, channel="container", validated=True,
                       note=f"self-validating: {method}, {len(payload)} bytes", kind=cs.sniff(payload))
    if len(crc_hits) > 1:
        # two distinct CRC-valid readings is not possible by chance; refuse to pick one.
        return Finding(note=f"ambiguous: {len(crc_hits)} distinct CRC-valid payloads", channel="container")
    # no CRC header: a complete embedded file structure is self-proving ONLY when its sizer verifies
    # a payload checksum (gzip, zip; CHECKSUM_KINDS). A structure-only walk (png/jpeg/gif/pdf/7z/elf/
    # pe/riff: a self-declared length or a trailing marker, no content checksum) does not prove the
    # bytes -- a forged/garbage/decoy header that just begins with the magic passes it -- so it is an
    # established-but-unproven reading (unsure candidate), never PLAIN (new-code audit v2, H12).
    judged = None
    try:
        judged = cs.judge_blob(blob)
    except Exception:
        judged = None
    if judged and judged[0] == "file":
        _, kind, payload = judged
        if kind in CHECKSUM_KINDS:
            return Finding(plain=payload, method=f"magic:{kind}", channel="container", validated=True,
                           note=f"self-validating file structure: {kind}, {len(payload)} bytes", kind=kind)
        return Finding(candidates=[("carved_file", payload)], method=f"magic:{kind}", channel="container",
                       validated=False, kind=kind,
                       note=f"a complete {kind} file structure but no payload checksum to prove it: unsure "
                            f"(a forged or decoy header would pass this walk; H12)")
    if judged and judged[0] == "text":
        text = judged[2]
        return Finding(candidates=[("decoded_text", text)], method="text", channel="container",
                       validated=False, note="a printable start, no length/CRC to prove it", kind="text")
    return Finding(note="no self-validating container")


# ---- ticket #9: the LSB container reader -----------------------------------------------------------

def _pixels(image_bytes):
    kind = cs.sniff(image_bytes)
    if kind == "png":
        return cs.png_pixels(image_bytes)
    if kind == "bmp":
        return cs.bmp_pixels(image_bytes)
    if kind == "gif":
        # a GIF's palette INDICES are the samples (mode 'P', one byte/pixel): a palette-LSB tool
        # writes the index's low bit. The same self-validating container test then applies.
        return cs.gif_pixels(image_bytes)
    if kind == "webp":
        # a lossless WebP keeps the bytes a tool wrote; a lossy one is re-quantised, so its planes
        # validate only by chance, which the CRC/checksum self-proof below rejects.
        return cs.webp_pixels(image_bytes)
    return None


def _configs(px: dict):
    """A small, standard set of LSB readings (bit 0 only; headers live at the start). The usual
    channel orders a tool writes and a few single channels, deduped and capped."""
    mode = px.get("mode") or ""
    color = mode.replace("A", "") or mode
    cfgs = []

    def add(ch, order, msb):
        if ch and (ch, order, msb) not in cfgs:
            cfgs.append((ch, order, msb))

    add(color, "xy", True)
    add(color, "xy", False)
    add(color, "yx", True)
    if len(color) >= 2:
        add(color[::-1], "xy", True)
    for c in color:
        add(c, "xy", True)
    if "A" in mode:
        add(mode, "xy", True)
    return cfgs[:MAX_CONFIGS]


def _capacity_bytes(px: dict, channels: str) -> int:
    w, h = px.get("width") or 0, px.get("height") or 0
    return max(0, (w * h * max(1, len(channels))) // 8)


def _declared_lengths(header: bytes):
    """Candidate payload lengths a length field at offset 0 (len+crc / len+payload+crc) would ask
    for, both byte orders: enough to size one full read."""
    out = []
    if len(header) >= 4:
        for fmt in (">I", "<I"):
            n = struct.unpack_from(fmt, header, 0)[0]
            if MIN_PAYLOAD <= n <= MAX_PAYLOAD:
                out.append(n)
    return out


def read_image(image_bytes):
    """Ticket #9. Read the usual LSB planes of a PNG, BMP, GIF or WebP and return the ONE self-validating
    payload as plain. Returns a dict:

      {plain: bytes|None, method: str, channel: 'lsb', candidates: [(name, value)], notes: [...]}

    plain is set only when exactly one distinct self-validated payload (CRC or file magic) was
    found across every plane tried; two distinct ones is ambiguous (plain None). Printable but
    unproven readings are returned as candidates (unsure). Never raises."""
    result = {"plain": None, "method": "", "channel": "lsb", "candidates": [], "notes": []}
    px = _pixels(image_bytes)
    if not px:
        result["notes"].append("not a PNG, BMP, GIF or WebP this reader pulls pixels from")
        return result
    plains = {}                 # payload bytes -> method
    cand_seen = set()
    for channels, order, msb in _configs(px):
        cap = min(MAX_PAYLOAD, LSB_CAP, _capacity_bytes(px, channels) + 16)
        if cap < 8:
            continue
        try:
            header = cs.lsb_extract(px, channels, 0, order, msb, max_bytes=16)
        except Exception:
            continue
        need = 4096
        for n in _declared_lengths(header):
            need = max(need, n + 12)
        need = min(need, cap)
        try:
            blob = cs.lsb_extract(px, channels, 0, order, msb, max_bytes=need)
        except Exception:
            continue
        f = validate_container(blob)
        tag = f"bit0 {channels} {order} {'msb' if msb else 'lsb'}-first"
        if f.plain is not None:
            plains.setdefault(bytes(f.plain), f"{tag}: {f.method}")
        elif f.candidates:
            for name, value in f.candidates:
                key = (name, value if isinstance(value, str) else bytes(value))
                if key not in cand_seen:
                    cand_seen.add(key)
                    result["candidates"].append((f"{name} ({tag})", value))
    if len(plains) == 1:
        payload, method = next(iter(plains.items()))
        result["plain"] = payload
        result["method"] = method
        result["notes"].append(f"self-validated LSB payload, {len(payload)} bytes ({method})")
    elif len(plains) > 1:
        result["notes"].append(f"ambiguous: {len(plains)} distinct self-validated payloads; no plain answer")
    elif not result["candidates"]:
        result["notes"].append("no self-validating LSB container found")
    return result


# ---- ticket C6: the CRC-validated steghide / stegseek channel --------------------------------------

def classify_steghide(ok: bool, payload, passphrase, in_wordlist: bool) -> Finding:
    """The C6 decision, as a pure function (no sandbox), so the never-wrong rule is testable.

    steghide embeds a CRC-32 over the payload and refuses to extract on a mismatch, so a successful
    extract is self-proving. It is PLAIN eligible only when the passphrase was the empty one or a
    word the QUESTION supplied (in_wordlist); a payload opened by any other guessed passphrase would
    not be never-wrong (it is a guess at the passphrase), so it stays unsure."""
    if not ok or payload is None:
        return Finding(note="steghide: nothing extracted under this passphrase (not a reading of the passphrase)")
    empty = passphrase in ("", None)
    if empty or in_wordlist:
        how = "empty passphrase" if empty else "a passphrase the question supplied"
        return Finding(plain=bytes(payload), method=f"steghide (CRC-32 validated, {how})", channel="steghide",
                       validated=True, kind=cs.sniff(bytes(payload)),
                       note=f"steghide CRC-32 validated the {len(payload)}-byte payload ({how}): plain-eligible")
    return Finding(candidates=[("steghide_payload", bytes(payload))], channel="steghide", validated=True,
                   note="steghide CRC-32 validated the payload, but under a passphrase not from the "
                        "question's list: unsure (the passphrase is a guess)")


def steghide_channel(data: bytes, *, passphrases=(), words=None):
    """Ticket C6, end to end (off the clock only). Try the empty passphrase, then each passphrase
    the question states, then stegseek over the question's word list, all through stego_tools (the
    sandbox). Return a Finding:

      - plain when a CRC-validated extract came out under the empty passphrase or a supplied word;
      - need_password=True (the ARCHIVE-PASSWORD STOP) when the cover was read whole but nothing
        supplied opened it and steghide reported an embedded/encrypted payload is present;
      - a not-read note when the sandbox is down or the cover was not read.

    Never guesses a passphrase and never brute-forces beyond the question's own supplied list."""
    try:
        import stego_tools as st
    except Exception as e:
        return Finding(note=f"steghide: stego_tools unavailable ({type(e).__name__}): not read", channel="steghide")

    tried = [""] + [p for p in (passphrases or []) if p not in ("", None)]
    read_cover = False
    saw_embedded = False
    for p in tried:
        info = st.steghide_info(data, p)
        if info.note.startswith(("sandbox down", "on a timed path")):
            return Finding(note=info.note, channel="steghide")
        if getattr(info, "ok", False):
            read_cover = True
        d = getattr(info, "data", None) or {}
        if d.get("embedded") is not None:
            saw_embedded = True
            ex = st.steghide_extract(data, p)
            got = getattr(ex, "data", None)
            if getattr(ex, "ok", False) and got is not None:
                return classify_steghide(True, got, p, in_wordlist=True)
    # the question's word list, if any (stegseek; its own CRC check, bounded to the supplied list)
    if words is not None:
        seek = st.stegseek(data, words)
        if seek.note.startswith(("sandbox down", "on a timed path")):
            return Finding(note=seek.note, channel="steghide")
        got = getattr(seek, "files", {}).get("payload") if hasattr(seek, "files") else None
        if getattr(seek, "ok", False) and got is not None:
            return classify_steghide(True, got, (getattr(seek, "data", None) or {}).get("passphrase"),
                                     in_wordlist=True)
    if read_cover and (saw_embedded or passphrases or words is not None):
        # a passphrase was expected (the challenge named one, or supplied a word list, or steghide saw
        # an embedded header) and nothing we may try opened it. The real passphrase is the player's.
        return Finding(need_password=True, channel="steghide",
                       note="steghide: a passphrase is expected but none the question supplied (nor the "
                            "empty one) opened it: ARCHIVE PASSWORD NEEDED (ask the player; never brute-forced)")
    if read_cover:
        return Finding(note="steghide: the cover was read, nothing opened with the empty passphrase "
                            "(steghide cannot tell a wrong passphrase from an empty cover): no finding",
                       channel="steghide")
    return Finding(note="steghide: the cover was not read (not a cover it reads, or the sandbox is down)",
                   channel="steghide")


# ---- command ---------------------------------------------------------------------------------------

def main(argv) -> int:
    import hashlib
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    for path in argv:
        if path.startswith("--"):
            continue
        data = Path(path).read_bytes()
        r = read_image(data)
        print(f"== {path} ({len(data)} bytes, {cs.sniff(data)})")
        if r["plain"] is not None:
            print(f"   PLAIN  {r['method']}  {len(r['plain'])} bytes "
                  f"sha256={hashlib.sha256(r['plain']).hexdigest()[:16]} kind={cs.sniff(r['plain'])}")
        for name, value in r["candidates"][:12]:
            shown = value if isinstance(value, str) else f"{len(value)} bytes"
            print(f"   unsure {name}: {shown[:120] if isinstance(shown, str) else shown}")
        for note in r["notes"]:
            print(f"   note   {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
