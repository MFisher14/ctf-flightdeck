"""APK container structural reader (new file, loaded by name by codec_search.py).

Covers the mobile gap "APK Signing Block structured ID-value payload + ZIP structural
anomalies" (docs build backlog): a code the APK hides in a place the flat scans never
reach. codec_search already scans every member's bytes and the archive's own raw bytes
(the signing block, the EOCD comment) for a code that stands there as it is
(`apk-string:archive`). So the only thing LEFT for this reader is a code that is NOT a
contiguous plaintext (or UTF-16LE) run in the bytes:

  * inside a NON-standard APK Signing Block ID-value, under base64 / hex / zlib / gzip /
    raw-deflate (a plain code in the block is already `apk-string:archive`);
  * inside a ZIP entry the central directory HIDES (a local file header the CD does not
    reference) or MISDESCRIBES (the CD declares a smaller compressed size than the local
    header), when that entry's data is DEFLATED or encoded -- `zipfile` reads only the
    central directory, so `read_members` never inflates such an entry and the flat raw
    scan sees only its still-compressed bytes.

Where it runs. `codec_search.container_revise` calls `read(blob)` in `_solve` AFTER the
usual reading (`dynamic_member_hit` / `solve_members` / `stated_revise` / the look-ahead
readers), and ONLY when that reading gave NO code. So nothing here can change an answer
the shipped solver already makes; every saved attempt of Days 1 to 24 is answered by the
shipped solver with a code, so this module is never reached on the regression set and
adds no time to a saved solve. It is reached only on a package whose code none of the
other readers could find -- and, because the firing condition is "no code was found
anywhere", a code this reader returns was provably NOT a plaintext run in the archive, so
it never duplicates the `apk-string:archive` reading.

The exactness proof (never-wrong). A value / entry yields a code only when its parsed
structure decodes to EXACTLY one `ANS-[0-9A-F]{16}`; the whole package yields a code only
when all the non-standard block IDs and all the hidden / misdescribed entries together
hold exactly one distinct code. Two different codes give nothing (one NOTE naming them):
nothing proves which the judge asks, as everywhere else in the lane. The chance that a
wrong structure or a spurious decode of signature / compressed bytes yields exactly
`ANS-` and sixteen uppercase hex digits is negligible (the same principle
`dynamic_members.py` uses with a payload magic), so a reader that fires has READ the code,
not guessed it; one that does not fire returns nothing rather than a maybe. Every answer
is a one-option pick under a route of its own (`apk-sigblock:<id>...`,
`apk-zip-hidden:<name>...`), unsure until the judge accepts the route's name; `_solve`'s
second-code look still runs behind it, so a decoy code elsewhere makes it unsure.

Bounded by sizes and counts, never by a clock, so the base, the gate's replay and a clock
agree on the same package. Fails closed on anything it cannot parse exactly: a ZIP64
record, a data-descriptor entry whose local header carries no size, a truncated or
inconsistent signing block, an archive larger than the cap. Not built (left to None, no
guess): a signed / keyed block value (no cheap magic-proved test), a code split across
two block IDs or two hidden entries, and any decode past one layer.
"""

import binascii
import base64
import gzip
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import puzzle_asset_codec as base  # noqa: E402  the ANSWER regex (ANS- and 16 uppercase hex)

# One exact code, with a word boundary so a code glued to other letters is never cut out of the glue.
_ANS_RAW = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")
_ANS_WIDE = re.compile(rb"A\x00N\x00S\x00-\x00(?:[0-9A-F]\x00){16}")

# ZIP record signatures.
_LFH = b"PK\x03\x04"        # local file header
_CDH = b"PK\x01\x02"        # central directory file header
_EOCD = b"PK\x05\x06"       # end of central directory
_EOCD64 = b"PK\x06\x06"     # ZIP64 end of central directory
_EOCD64_LOC = b"PK\x06\x07" # ZIP64 end of central directory locator

# APK Signing Block trailer.
_SIG_MAGIC = b"APK Sig Block 42"

# Block IDs the Android signing scheme defines: these carry signatures / padding, never a
# hidden payload, so they are skipped. Anything else is a candidate carrier.
_STANDARD_SIG_IDS = {
    0x7109871A,   # APK Signature Scheme v2 block
    0xF05368C0,   # APK Signature Scheme v3 block
    0x1B93AD61,   # APK Signature Scheme v3.1 block
    0x42726577,   # verity padding block
    0x2B09189E,   # source stamp v1
    0x6DFF800D,   # source stamp v2
    0x504B4453,   # Google Play dependency metadata
    0x2146444E,   # Google Play "frosting" metadata
}

MAX_BLOB = 64 << 20          # an archive larger than this is not read (fail closed)
MAX_SIG_BLOCK = 16 << 20     # a signing block larger than this is not parsed
MAX_SIG_PAIRS = 256          # ID-value pairs read from a signing block
MAX_VALUE = 4 << 20          # bytes of a block value / entry that a decode may touch
MAX_LOCAL = 8192             # local file headers scanned
MAX_ENTRY = 8 << 20          # bytes of a hidden entry that is inflated


def _one(found: set):
    """The single exact code in a set of exact codes, or None for zero / two or more."""
    return next(iter(found)) if len(found) == 1 else None


def _raw_codes(data: bytes) -> set:
    """Every exact code that stands as a contiguous run (ASCII or UTF-16LE) in `data`."""
    out = {m.group(0).decode() for m in _ANS_RAW.finditer(data)}
    out |= {m.group(0).decode("utf-16le") for m in _ANS_WIDE.finditer(data)}
    return out


def _b64_decode(data: bytes):
    """base64 / base64url of the whole value, or None. Strict: the alphabet and the length must fit."""
    t = bytes(data).strip()
    if not 4 <= len(t) <= MAX_VALUE or len(t) % 4 != 0:
        return None
    for alt, name in ((False, "base64"), (True, "base64url")):
        alphabet = (re.fullmatch(rb"[A-Za-z0-9\-_]*={0,2}", t) if alt
                    else re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", t))
        if not alphabet:
            continue
        try:
            return base64.b64decode(t, altchars=b"-_" if alt else None, validate=True), name
        except (binascii.Error, ValueError):
            continue
    return None


def _hex_decode(data: bytes):
    """hex of the whole value, or None."""
    t = bytes(data).strip()
    if not 8 <= len(t) <= MAX_VALUE or len(t) % 2 != 0 or not re.fullmatch(rb"[0-9A-Fa-f]+", t):
        return None
    try:
        return binascii.unhexlify(t), "hex"
    except (binascii.Error, ValueError):
        return None


def _zlib_decode(data: bytes):
    """zlib / gzip / raw-deflate of the whole value, or None. Bounded output."""
    if not data or len(data) > MAX_VALUE:
        return None
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(bytes(data))[:MAX_ENTRY], "gzip"
        except (OSError, EOFError, zlib.error):
            return None
    if data[0] == 0x78:                     # a zlib stream almost always starts 0x78
        try:
            return zlib.decompressobj().decompress(bytes(data), MAX_ENTRY), "zlib"
        except zlib.error:
            return None
    try:                                     # headerless raw deflate
        return zlib.decompressobj(-15).decompress(bytes(data), MAX_ENTRY), "deflate"
    except zlib.error:
        return None


def _decoded_codes(data: bytes) -> dict:
    """{code: how} for a code that appears after ONE decode layer of the whole value.

    Only base64 / hex / zlib / gzip / raw-deflate of the entire value, each gated on the
    alphabet / header; the gate that makes it never-wrong is the exact-code match on the
    result, not the decode itself."""
    out = {}
    if not data or len(data) > MAX_VALUE:
        return out
    for dec in (_b64_decode, _hex_decode, _zlib_decode):
        got = dec(data)
        if not got:
            continue
        blob, how = got
        for code in _raw_codes(blob):
            out.setdefault(code, how)
    return out


def _scan_value(data: bytes, base_route: str) -> dict:
    """{code: route} for the codes a single value / entry carries.

    A plain run keeps `base_route`; a UTF-16LE run gets `:utf16`; a code behind one decode
    layer gets `:<how>`. (A plain run only reaches here on a package the flat scans could
    not reach, e.g. a signing block past the 8 MiB the package scan reads.)"""
    out = {}
    raw = {m.group(0).decode() for m in _ANS_RAW.finditer(data)}
    wide = {m.group(0).decode("utf-16le") for m in _ANS_WIDE.finditer(data)}
    for code in raw:
        out.setdefault(code, base_route)
    for code in wide:
        out.setdefault(code, base_route + ":utf16")
    for code, how in _decoded_codes(data).items():
        out.setdefault(code, base_route + ":" + how)
    return out


def _find_eocd(blob: bytes):
    """(cd_offset, cd_size) from the End Of Central Directory record, or None.

    ZIP64 is not read (fail closed): the lane's fixtures are small 32-bit ZIPs."""
    if _EOCD64 in blob or _EOCD64_LOC in blob:
        return None
    start = max(0, len(blob) - (22 + 0xFFFF))
    idx = blob.rfind(_EOCD, start)
    if idx < 0 or idx + 22 > len(blob):
        return None
    cd_size, cd_offset = struct.unpack_from("<II", blob, idx + 12)
    comment_len = struct.unpack_from("<H", blob, idx + 20)[0]
    if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:   # ZIP64 sentinels
        return None
    if cd_offset > len(blob) or cd_offset + cd_size > len(blob):
        return None
    if idx + 22 + comment_len != len(blob):               # a trailer past the comment: not a clean EOCD
        return None
    return cd_offset, cd_size


def _central_directory(blob: bytes, cd_offset: int, cd_size: int):
    """[{name, lh_offset, method, comp_size}] from the central directory, or None on a malformed one."""
    entries = []
    pos = cd_offset
    end = cd_offset + cd_size
    while pos + 46 <= end and len(entries) <= MAX_LOCAL:
        if blob[pos:pos + 4] != _CDH:
            break
        (method, csize, _usize, nlen, elen, clen) = struct.unpack_from("<4xH8xIIHHH", blob, pos + 6)
        # ^ from offset+6: skip version-needed(2)+flags(2); method(2); skip time(2)+date(2)+crc(4);
        #   comp(4) uncomp(4) namelen(2) extralen(2) commentlen(2) ...
        name_at = pos + 46
        if name_at + nlen > end:
            return None
        name = blob[name_at:name_at + nlen]
        lh_offset = struct.unpack_from("<I", blob, pos + 42)[0]
        entries.append({"name": name, "lh_offset": lh_offset, "method": method, "comp_size": csize})
        pos = name_at + nlen + elen + clen
    return entries


def _read_sig_block(blob: bytes, cd_offset: int, notes: list) -> dict:
    """{code: route} for the codes the NON-standard APK Signing Block IDs carry.

    The block sits just before the central directory: its 16-byte magic ends at cd_offset,
    the trailing uint64 size is the 8 bytes before the magic, and the matching leading size
    sits 8 bytes before the payload. Fails closed on any inconsistency."""
    found = {}
    if cd_offset < 32:
        return found
    if blob[cd_offset - 16:cd_offset] != _SIG_MAGIC:
        return found
    size = struct.unpack_from("<Q", blob, cd_offset - 24)[0]
    if size <= 24 or size > MAX_SIG_BLOCK or size + 8 > cd_offset:
        notes.append("signing block present but its size field is out of range; not parsed")
        return found
    block_start = cd_offset - 8 - size
    if struct.unpack_from("<Q", blob, block_start)[0] != size:
        notes.append("signing block present but its two size fields disagree; not parsed")
        return found
    region = blob[block_start + 8:cd_offset - 24]     # the ID-value pairs, between the two size fields
    pos = 0
    pairs = 0
    while pos + 12 <= len(region) and pairs < MAX_SIG_PAIRS:
        plen = struct.unpack_from("<Q", region, pos)[0]
        if plen < 4 or pos + 8 + plen > len(region):
            break
        block_id = struct.unpack_from("<I", region, pos + 8)[0]
        value = region[pos + 12:pos + 8 + plen]
        pos += 8 + plen
        pairs += 1
        if block_id in _STANDARD_SIG_IDS or len(value) > MAX_VALUE:
            continue
        for code, route in _scan_value(value, "apk-sigblock:%08x" % block_id).items():
            found.setdefault(code, route)
    return found


def _read_hidden_entries(blob: bytes, cd_offset: int, cd: list, notes: list) -> dict:
    """{code: route} for the codes in ZIP local entries the central directory hides or misdescribes.

    A local file header the CD does not reference at that offset is a HIDDEN entry; a CD
    entry whose declared compressed size is SMALLER than the local header's own is
    MISDESCRIBED (the CD truncates what the real entry inflates to). For each such entry the
    data is inflated from the LOCAL header (stored or deflate) and read for exactly one code.
    An entry whose local header carries a data descriptor (no size in the header) is skipped
    (fail closed)."""
    found = {}
    cd_offsets = {e["lh_offset"] for e in cd}
    cd_by_offset = {e["lh_offset"]: e for e in cd}
    scanned = 0
    pos = blob.find(_LFH, 0)
    while 0 <= pos < cd_offset and scanned < MAX_LOCAL:
        scanned += 1
        header = _parse_local_header(blob, pos, cd_offset)
        nxt = blob.find(_LFH, pos + 4)
        if header is None:
            if nxt < 0:
                break
            pos = nxt
            continue
        hidden = pos not in cd_offsets
        cd_entry = cd_by_offset.get(pos)
        # misdescribed: the CD declares a smaller compressed size than the local header
        misdescribed = (cd_entry is not None and header["comp_size"] > 0
                        and cd_entry["comp_size"] > 0 and header["comp_size"] > cd_entry["comp_size"])
        if hidden or misdescribed:
            data = _entry_data(blob, header)
            if data is not None:
                label = header["name"].decode("latin-1", "replace")[:48] or "unnamed"
                tag = "hidden" if hidden else "mismatch"
                for code, route in _scan_value(data, "apk-zip-%s:%s" % (tag, label)).items():
                    found.setdefault(code, route)
        # advance past this entry's declared data when we can, else to the next LFH signature
        step = header["data_at"] + header["comp_size"] if header["comp_size"] > 0 else -1
        if step > pos and step <= cd_offset:
            nxt2 = blob.find(_LFH, step)
            pos = nxt2 if 0 <= nxt2 < cd_offset else (nxt if nxt > pos else -1)
        else:
            pos = nxt if nxt > pos else -1
    return found


def _parse_local_header(blob: bytes, pos: int, limit: int):
    """A parsed local file header at `pos`, or None if it is malformed or uses a data descriptor."""
    if pos + 30 > limit or blob[pos:pos + 4] != _LFH:
        return None
    (flags, method, csize, _usize, nlen, elen) = struct.unpack_from("<2xHH8xIIHH", blob, pos + 4)
    # ^ from offset+4: skip version(2); flags(2) method(2); skip time(2)+date(2)+crc(4); comp(4) uncomp(4) namelen(2) extralen(2)
    if flags & 0x0008:                       # data descriptor: sizes are 0 here, not trustworthy
        return None
    if method not in (0, 8):                 # only stored / classic deflate
        return None
    name_at = pos + 30
    data_at = name_at + nlen + elen
    if data_at > limit or name_at + nlen > limit:
        return None
    name = blob[name_at:name_at + nlen]
    return {"name": name, "method": method, "comp_size": csize, "data_at": data_at}


def _entry_data(blob: bytes, header: dict):
    """The uncompressed bytes of a local entry (stored or deflate), bounded, or None."""
    csize = header["comp_size"]
    if csize <= 0 or csize > MAX_ENTRY:
        return None
    raw = blob[header["data_at"]:header["data_at"] + csize]
    if len(raw) != csize:
        return None
    if header["method"] == 0:
        return raw
    try:
        return zlib.decompressobj(-15).decompress(raw, MAX_ENTRY)
    except zlib.error:
        return None


def read(blob):
    """(result, notes) for the codes an APK hides at the container level, else (None, notes).

    result is {"code": str, "route": str} when the signing block's non-standard IDs and the
    hidden / misdescribed ZIP entries together hold EXACTLY one distinct code; None for zero,
    or for two or more different codes (nothing proves which is asked). notes are stderr lines."""
    notes = []
    if not isinstance(blob, (bytes, bytearray)):
        return None, notes
    blob = bytes(blob)
    if not blob.startswith(_LFH) or len(blob) > MAX_BLOB:
        return None, notes
    eocd = _find_eocd(blob)
    if eocd is None:
        return None, notes
    cd_offset, cd_size = eocd
    cd = _central_directory(blob, cd_offset, cd_size)
    if cd is None:
        notes.append("central directory is malformed; the container reader stands down")
        return None, notes

    found = {}
    for code, route in _read_sig_block(blob, cd_offset, notes).items():
        found.setdefault(code, route)
    for code, route in _read_hidden_entries(blob, cd_offset, cd, notes).items():
        found.setdefault(code, route)

    if not found:
        return None, notes
    code = _one(set(found))
    if code is None:
        pairs = ", ".join("%s (%s)" % (c, found[c]) for c in sorted(found))[:300]
        notes.append("the container holds %d different codes, nothing proves which is asked: %s"
                     % (len(found), pairs))
        return None, notes
    route = found[code]
    notes.append("a code is hidden in the APK container (%s): %s; unsure until the judge accepts the route"
                 % (route, code))
    return {"code": code, "route": route}, notes
