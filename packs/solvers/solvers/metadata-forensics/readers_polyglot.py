#!/usr/bin/env python3
"""Metadata Forensics Day-24 look-ahead pack: POLYGLOT / APPENDED-OVERLAY deception.

properties_strict.py loads this file by name (MORE_FILES, last, after readers_lookahead22.py) and calls
register(M) with itself. NOTHING here answers plain: every name is registered unconfirmed (confirmed=False),
so the strict wrapper offers it through labels.pick (UNSURE) until the judge has accepted a form for the
key, and one probe on the untimed base (or a no-deadline attempt) settles it. A wrong unsure value can never
sink a batch (gm.session strips every `??`), which is the never-wrong guarantee this pack relies on.

WHY THIS FILE (the Day-24 prediction). The day theme trends toward DECEPTION (Day 23 "Page Me Maybe" was a
decoy day: a `.wav` that was really Ogg/Opus; a forged-order zip). The two deception shapes the lane has NO
dedicated reader for -- and so would STOP on, an agent's morning day_patch costing time -- are:

  (1) A POLYGLOT: one file that is simultaneously two valid formats (a PNG that is also a ZIP, a JPEG with a
      ZIP appended, a GIF/PDF carrier). Classic stego/CTF carrier. A question of the form "what is the true
      type of X / what second format is hidden in X / how many container formats are present" has no reader
      today.
  (2) APPENDED OVERLAY DATA: bytes after the host container's logical end (the data a carrier hides after the
      IEND / trailer / %%EOF / EOCD). "At what offset does the appended data begin / how many trailing bytes
      / the sha256 of the hidden blob" has no reader today outside pe.overlay_*.

Both are DECOY-BY-MAGIC: the file is read by its TRUE structure, never by its extension. The shipped
`deception_guard.py` already made true_magic / is_decoy / select_member reusable; this pack turns the SAME
invariants into REGISTERED PROPERTY READERS so a Day-24 polyglot question routes somewhere and fails closed
(unsure), instead of reaching no reader (STOP).

NEVER-WRONG DISCIPLINE (the hard rule of this lane):
  * The host container's LOGICAL END is computed by walking its real structure (PNG chunks to IEND, GIF
    blocks to the 0x3B trailer, JPEG markers to EOI, PDF to the last %%EOF, ZIP to its EOCD). If the walk is
    the least bit ambiguous or the structure is malformed, we raise Unknown -> None. We NEVER estimate an
    end, so overlay.offset / size / digests are either exact or absent, never a guess.
  * The embedded/second-format scan uses only LONG, distinctive magics (>= 4 bytes) so random bytes do not
    masquerade as a container; a 2-byte magic (gzip, MZ) is used only at offset 0, never mid-file.
  * is_polyglot is True only on positive evidence (a bounded overlay that itself has a known magic, or a
    strong embedded magic at a non-zero offset); False only when the host is boundable and no such evidence
    exists; Unknown (-> None) otherwise. It never claims "not a polyglot" about a file it cannot bound.
  * Everything unconfirmed. The author's label/rendering for "overlay"/"polyglot"/"true format" has never
    been judged, so a probe on the base decides it.

The extractor contract (fn(name, data) -> value), as readers_lookahead22.py documents it:
  * raise M.Unknown  when the file is NOT this reader's subject (so the answer is None, never a wrong-type
    'none' -- a claim about a container we are not reading).
  * return None       only when the file IS the subject but the field is genuinely absent (a boundable host
    with zero trailing bytes has no overlay offset): the wrapper then offers the unsure `none`.
  * return the value  otherwise: the wrapper offers it through labels.pick, unsure.
"""
import hashlib
import struct

M = None   # properties_strict, set by register()

# New namespaces this pack introduces (none clashes with an existing registered name; the test pins it).
NEW_NAMESPACES = ("polyglot", "overlay", "appended", "trailing", "carved")


def U(msg):
    raise M.Unknown(msg)


# --------------------------------------------------------------------------- true magic (self-contained)
# A canonical container tag read from leading bytes only. Kept independent of deception_guard so neither
# file can break the other; the two agree on every shape the battery checks. Ordered most-specific first.

def _is_mp4(d):
    return len(d) >= 12 and d[4:8] == b"ftyp"


def _is_tar(d):
    return len(d) >= 262 and d[257:262] == b"ustar"


def _is_class(d):
    return d[:4] == b"\xca\xfe\xba\xbe" and len(d) >= 8 and d[4:8] >= b"\x00\x00\x00\x2d"


_LEADING = (
    ("sqlite", lambda d: d[:16] == b"SQLite format 3\x00"),
    ("png", lambda d: d[:8] == b"\x89PNG\r\n\x1a\n"),
    ("gif", lambda d: d[:6] in (b"GIF87a", b"GIF89a")),
    ("pdf", lambda d: d[:5] == b"%PDF-"),
    ("class", _is_class),
    ("macho_fat", lambda d: d[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and not _is_class(d)),
    ("macho", lambda d: d[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")),
    ("elf", lambda d: d[:4] == b"\x7fELF"),
    ("flac", lambda d: d[:4] == b"fLaC"),
    ("ogg", lambda d: d[:4] == b"OggS"),
    ("riff", lambda d: d[:4] == b"RIFF"),
    ("sevenzip", lambda d: d[:6] == b"7z\xbc\xaf\x27\x1c"),
    ("rar", lambda d: d[:7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01")),
    ("xz", lambda d: d[:6] == b"\xfd7zXZ\x00"),
    ("zip", lambda d: d[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    ("dex", lambda d: d[:4] == b"dex\n"),
    ("jpeg", lambda d: d[:3] == b"\xff\xd8\xff"),
    ("mp3", lambda d: d[:3] == b"ID3"),
    ("bzip2", lambda d: d[:3] == b"BZh"),
    ("mp4", _is_mp4),
    ("tar", _is_tar),
    ("gzip", lambda d: d[:2] == b"\x1f\x8b"),
    ("pe", lambda d: d[:2] == b"MZ"),
)

_RIFF_SUB = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}

# Strong magics (>= 4 bytes) safe to search for at a NON-zero offset. A short magic is never scanned
# mid-file. Each (tag, signature) is matched literally; the shortest useful distinctive prefix is used.
_EMBED = (
    ("zip", b"PK\x03\x04"),
    ("zip_eocd", b"PK\x05\x06"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("gif", b"GIF89a"),
    ("gif", b"GIF87a"),
    ("pdf", b"%PDF-"),
    ("rar", b"Rar!\x1a\x07"),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c"),
    ("xz", b"\xfd7zXZ\x00"),
    ("flac", b"fLaC"),
    ("ogg", b"OggS"),
    ("elf", b"\x7fELF"),
    ("class", b"\xca\xfe\xba\xbe"),
    ("dex", b"dex\n"),
    ("riff", b"RIFF"),
)

# What a file EXTENSION claims (only unambiguous suffixes; anything else claims nothing).
_EXT_CLAIM = {
    "wav": "wav", "flac": "flac", "ogg": "ogg", "opus": "ogg", "oga": "ogg", "mp3": "mp3",
    "mp4": "mp4", "m4a": "mp4", "mov": "mp4", "png": "png", "gif": "gif", "jpg": "jpeg", "jpeg": "jpeg",
    "pdf": "pdf", "zip": "zip", "jar": "zip", "apk": "zip", "gz": "gzip", "bz2": "bzip2", "xz": "xz",
    "7z": "sevenzip", "rar": "rar", "elf": "elf", "so": "elf", "class": "class", "dex": "dex",
    "sqlite": "sqlite", "sqlite3": "sqlite", "db": "sqlite", "webp": "webp", "avi": "avi", "tar": "tar",
}


def true_magic(data):
    """The canonical container tag read from LEADING BYTES, or None when no magic matches. A RIFF is
    refined to wav/avi/webp. Extension-independent on purpose: the one basis is the bytes."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2:
        return None
    d = bytes(data)
    for tag, pred in _LEADING:
        try:
            if pred(d):
                return _RIFF_SUB.get(d[8:12], "riff") if tag == "riff" else tag
        except Exception:
            continue
    return None


def _declared(name):
    if not isinstance(name, str) or "." not in name.strip("."):
        return None
    return _EXT_CLAIM.get(name.rsplit(".", 1)[-1].lower())


def _base(name):
    """The bare file name (what the delivered member is called), robust to paths given with either slash."""
    s = name if isinstance(name, str) else ""
    return s.replace("\\", "/").rsplit("/", 1)[-1]


# --------------------------------------------------------------------------- logical end of a host format
# Each returns the byte offset ONE PAST the end of the host container's real structure, so d[end:] is the
# appended overlay. Raises Unknown on any malformation or ambiguity: we never estimate an end.

def _png_end(d):
    if d[:8] != b"\x89PNG\r\n\x1a\n":
        U("not a PNG")
    pos = 8
    n = len(d)
    seen_iend = False
    while pos + 8 <= n:
        (ln,) = struct.unpack_from(">I", d, pos)
        ctype = d[pos + 4:pos + 8]
        nxt = pos + 12 + ln            # 4 len + 4 type + ln data + 4 crc
        if nxt > n:
            U("a PNG chunk runs past the file")
        if ctype == b"IEND":
            seen_iend = True
            pos = nxt
            break
        pos = nxt
    if not seen_iend:
        U("no IEND chunk: the PNG structure does not terminate")
    return pos


def _gif_end(d):
    if d[:6] not in (b"GIF87a", b"GIF89a"):
        U("not a GIF")
    n = len(d)
    pos = 13                                   # header(6) + logical screen descriptor(7)
    if pos > n:
        U("a GIF cut before its screen descriptor")
    packed = d[10]
    if packed & 0x80:                          # global colour table
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    while pos < n:
        b = d[pos]
        if b == 0x3B:                          # trailer
            return pos + 1
        if b == 0x21:                          # extension introducer
            pos += 2                           # 0x21 + label
            pos = _gif_skip_subblocks(d, pos)
        elif b == 0x2C:                        # image descriptor
            if pos + 10 > n:
                U("a GIF image descriptor runs past the file")
            ipacked = d[pos + 9]
            pos += 10
            if ipacked & 0x80:                 # local colour table
                pos += 3 * (2 ** ((ipacked & 0x07) + 1))
            pos += 1                           # LZW minimum code size
            pos = _gif_skip_subblocks(d, pos)
        else:
            U(f"an unexpected GIF block byte 0x{b:02x}")
    U("no GIF trailer (0x3B): the structure does not terminate")


def _gif_skip_subblocks(d, pos):
    n = len(d)
    while pos < n:
        sz = d[pos]
        pos += 1
        if sz == 0:                            # block terminator
            return pos
        pos += sz
        if pos > n:
            U("a GIF data sub-block runs past the file")
    U("a GIF sub-block list does not terminate")


_JPEG_STANDALONE = {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7}


def _jpeg_end(d):
    if d[:2] != b"\xff\xd8":
        U("not a JPEG")
    n = len(d)
    pos = 2
    while pos + 1 < n:
        if d[pos] != 0xFF:
            U("a JPEG marker does not begin with 0xFF")
        # skip fill bytes 0xFF
        while pos < n and d[pos] == 0xFF:
            pos += 1
        if pos >= n:
            U("a JPEG marker is cut")
        marker = d[pos]
        pos += 1
        if marker == 0xD9:                     # EOI
            return pos
        if marker in _JPEG_STANDALONE:
            continue
        if pos + 2 > n:
            U("a JPEG segment length is cut")
        (seg,) = struct.unpack_from(">H", d, pos)
        if seg < 2:
            U("a JPEG segment length under 2")
        pos += seg
        if pos > n:
            U("a JPEG segment runs past the file")
        if marker == 0xDA:                     # SOS: entropy-coded data follows until the next real marker
            while pos + 1 < n:
                if d[pos] == 0xFF:
                    nb = d[pos + 1]
                    if nb == 0x00 or 0xD0 <= nb <= 0xD7 or nb == 0xFF:
                        pos += 1                # stuffed 0xFF00, a restart marker, or a fill byte
                        continue
                    break                       # a real marker boundary
                pos += 1
            else:
                U("JPEG entropy data does not reach a terminating marker")
    U("no EOI (0xFFD9): the JPEG structure does not terminate")


def _pdf_end(d):
    if d[:5] != b"%PDF-":
        U("not a PDF")
    at = d.rfind(b"%%EOF")
    if at < 0:
        U("no %%EOF: the PDF structure does not terminate")
    pos = at + 5
    n = len(d)
    # a single trailing EOL is part of the PDF, per the spec; anything after it is overlay
    if pos < n and d[pos:pos + 2] == b"\r\n":
        pos += 2
    elif pos < n and d[pos:pos + 1] in (b"\r", b"\n"):
        pos += 1
    return pos


def _zip_end(d):
    if d[:4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        U("not a ZIP (no local-file/EOCD signature at offset 0)")
    # find the End Of Central Directory record (it is near the end; its comment length bounds the search)
    n = len(d)
    lo = max(0, n - (22 + 65535))
    at = d.rfind(b"PK\x05\x06", lo)
    if at < 0 or at + 22 > n:
        U("no readable EOCD record")
    (comment_len,) = struct.unpack_from("<H", d, at + 20)
    end = at + 22 + comment_len
    if end > n:
        U("the EOCD comment length runs past the file")
    return end


_HOST_END = {"png": _png_end, "gif": _gif_end, "jpeg": _jpeg_end, "pdf": _pdf_end, "zip": _zip_end}


def _host_and_end(d):
    """(leading tag, logical end) for a host format whose end we can bound EXACTLY, else Unknown. The tag
    is true_magic's leading tag; only png/gif/jpeg/pdf/zip are boundable (others raise Unknown here)."""
    tag = true_magic(d)
    if tag is None:
        U("no known magic at offset 0: not a host container this reader bounds")
    fn = _HOST_END.get(tag)
    if fn is None:
        U(f"a {tag} host: this reader does not bound its logical end (pe/elf/macho overlays are other packs')")
    return tag, fn(bytes(d))


def _overlay(d):
    """(host tag, overlay bytes) where overlay is everything after the host's logical end (possibly b'')."""
    tag, end = _host_and_end(d)
    return tag, bytes(d)[end:]


def _embedded_hits(d):
    """[(tag, offset)] of every STRONG magic found at offset > 0, first occurrence of each (tag, sig),
    in offset order. Only used as positive evidence of a second format; never to bound anything."""
    hits = []
    for tag, sig in _EMBED:
        at = d.find(sig, 1)
        if at > 0:
            hits.append((tag, at))
    hits.sort(key=lambda x: x[1])
    # collapse zip/zip_eocd to one "zip" tag
    return [(("zip" if t == "zip_eocd" else t), off) for t, off in hits]


# --------------------------------------------------------------------------- extractors (all unsure)

def _true_format(name, d):
    tag = true_magic(d)
    if tag is None:
        U("no known magic at offset 0")
    return tag


def _declared_format(name, d):
    # a fact about the file NAME; None (absent) when the extension claims nothing
    return _declared(_base(name))


def _is_decoy(name, d):
    """True when the extension claims one container but the true magic is another (the Day-23 decoy trick).
    None when the extension claims nothing or the magic is unknown: no basis to decide (never a false bool)."""
    claimed = _declared(_base(name))
    actual = true_magic(d)
    if claimed is None or actual is None:
        return None
    if claimed == actual:
        return False
    # a jar/apk IS a zip; opus/oga ARE ogg (already mapped): those are not a conflict
    if {claimed, actual} <= {"zip"}:
        return False
    # a riff subtype vs a bare riff claim is not a conflict
    if claimed in _RIFF_SUB.values() and actual in _RIFF_SUB.values():
        return claimed != actual
    return True


def _matches(name, d):
    dec = _is_decoy(name, d)
    return None if dec is None else (not dec)


def _overlay_present(name, d):
    _, ov = _overlay(d)            # raises Unknown if the host is not boundable
    return len(ov) > 0


def _overlay_offset(name, d):
    _, end = _host_and_end(d)
    return end if end < len(d) else None    # no trailing bytes -> the field is absent


def _overlay_size(name, d):
    _, ov = _overlay(d)
    return len(ov)                 # 0 is a true count when the host ends at EOF


def _overlay_digest(algo):
    def fn(name, d):
        _, ov = _overlay(d)
        if not ov:
            return None            # no overlay -> no digest (absent)
        return hashlib.new(algo, ov).hexdigest()
    return fn


def _overlay_magic_hex(name, d):
    _, ov = _overlay(d)
    if not ov:
        return None
    return ov[:8].hex()


def _overlay_format(name, d):
    _, ov = _overlay(d)
    if not ov:
        return None
    tag = true_magic(ov)
    return tag                     # None (absent) when the overlay has no known magic


def _second_format(name, d):
    """The hidden/second container format: the overlay's magic if the host is boundable and the overlay has
    one, else the first strong embedded magic at a non-zero offset. None when no second format shows."""
    try:
        _, ov = _overlay(d)
        if ov:
            tag = true_magic(ov)
            if tag is not None:
                return tag
    except Exception:
        pass
    hits = _embedded_hits(bytes(d))
    lead = true_magic(d)
    for tag, _off in hits:
        if tag != lead:
            return tag
    return None


def _all_formats(name, d):
    """Every distinct container format present, leading first then embedded, in offset order. A list of >=1
    tag, or None when offset 0 has no known magic (not this reader's file)."""
    lead = true_magic(d)
    if lead is None:
        U("no known magic at offset 0")
    out = [lead]
    try:
        _, ov = _overlay(d)
        if ov:
            t = true_magic(ov)
            if t is not None and t not in out:
                out.append(t)
    except Exception:
        pass
    for tag, _off in _embedded_hits(bytes(d)):
        if tag not in out:
            out.append(tag)
    return out


def _format_count(name, d):
    fmts = _all_formats(name, d)
    return len(fmts) if fmts else None


def _is_polyglot(name, d):
    """True on positive evidence of a 2nd format (a bounded overlay with its own magic, or a strong embedded
    magic at offset > 0); False when the host is boundable and no such evidence; Unknown -> None otherwise.
    Never claims 'not a polyglot' about a file whose end it cannot bound."""
    lead = true_magic(d)
    if lead is None:
        U("no known magic at offset 0")
    db = bytes(d)
    hits = [h for h in _embedded_hits(db) if h[0] != lead]
    bounded = False
    try:
        _, ov = _overlay(d)
        bounded = True
        if ov and true_magic(ov) is not None:
            return True
    except Exception:
        bounded = False
    if hits:
        return True
    if bounded:
        return False
    return None                    # cannot bound the host and no embedded 2nd magic: honestly unknown


# --------------------------------------------------------------------------- registration

def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added. Every name
    is unconfirmed, so a name clash is restored to the earlier pack's reader (the existing one wins)."""
    global M
    M = module
    before = dict(M.REG)

    # (1) decoy-by-magic: the true type vs what the extension claims
    M.prop("polyglot.true_format", "polyglot.actual_format", "polyglot.detected_format",
           "polyglot.real_format", "polyglot.content_format", "polyglot.container_format", fmt="label")(_true_format)
    M.prop("polyglot.declared_format", "polyglot.extension_format", "polyglot.claimed_format",
           "polyglot.declared_type", fmt="label")(_declared_format)
    M.prop("polyglot.is_decoy", "polyglot.extension_is_deceptive", "polyglot.extension_mismatch",
           "polyglot.content_mismatches_extension", "polyglot.mislabeled", fmt="bool")(_is_decoy)
    M.prop("polyglot.extension_matches_content", "polyglot.extension_matches",
           "polyglot.extension_is_honest", fmt="bool")(_matches)

    # (2) polyglot structure
    M.prop("polyglot.is_polyglot", "polyglot.polyglot", "polyglot.is_multiformat", fmt="bool")(_is_polyglot)
    M.prop("polyglot.format_count", "polyglot.container_count", "polyglot.signature_count",
           "polyglot.format_number", fmt="integer")(_format_count)
    M.prop("polyglot.formats", "polyglot.embedded_formats", "polyglot.format_list",
           "polyglot.container_formats", "polyglot.signatures", "polyglot.all_formats", fmt="list")(_all_formats)
    M.prop("polyglot.second_format", "polyglot.hidden_format", "polyglot.secondary_format",
           "polyglot.appended_format", "polyglot.trailing_format", fmt="label")(_second_format)

    # (3) appended-overlay (data after the host container's exact logical end)
    M.prop("overlay.present", "overlay.has_appended_data", "overlay.appended_data_present",
           "appended.present", "appended.data_present", "trailing.present",
           "trailing.data_present", "carved.present", fmt="bool")(_overlay_present)
    M.prop("overlay.offset", "overlay.start_offset", "overlay.start", "overlay.file_offset",
           "appended.offset", "trailing.offset", "carved.offset", fmt="integer")(_overlay_offset)
    M.prop("overlay.size_bytes", "overlay.length_bytes", "overlay.size", "overlay.byte_count",
           "appended.size_bytes", "trailing.size_bytes", "carved.size_bytes", fmt="integer")(_overlay_size)
    M.prop("overlay.sha256", "appended.sha256", "trailing.sha256", "carved.sha256",
           fmt="hex")(_overlay_digest("sha256"))
    M.prop("overlay.md5", "appended.md5", "trailing.md5", "carved.md5", fmt="hex")(_overlay_digest("md5"))
    M.prop("overlay.sha1", "appended.sha1", "trailing.sha1", "carved.sha1", fmt="hex")(_overlay_digest("sha1"))
    # The overlay's leading bytes as hex. Registered WITHOUT a trailing `_hex`/width/form word
    # (row 178's guard in test_metadata_readers forbids one, since typed() would strip it and could
    # shadow another reader): the fmt is already "hex", so the value is hex either way, and a
    # question that spells the name with a trailing `_hex` still resolves through guess()'s
    # typed-name routing / synonym(). Every option stays unsure.
    M.prop("overlay.magic_prefix", "overlay.magic", "overlay.header",
           "appended.magic", "trailing.magic", fmt="hex")(_overlay_magic_hex)
    M.prop("overlay.format", "overlay.appended_format", "overlay.trailing_format",
           "appended.format", "trailing.format", "carved.format", fmt="label")(_overlay_format)

    # Clash guard: a name registered before this pack keeps its earlier reader (the existing one wins).
    for k, old in before.items():
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old

    # New namespaces, so dotted()/synonym()/content detection treat them as namespaces.
    for ns in NEW_NAMESPACES:
        M.NAMESPACES.add(ns)
        if hasattr(M, "PACK_NAMESPACES"):
            M.PACK_NAMESPACES.add(ns)
        if hasattr(M, "CONTENT_TOKENS"):
            M.CONTENT_TOKENS.add(ns)
        if hasattr(M, "RELATED"):
            M.RELATED.setdefault(ns, (ns,))

    # Only the extractors of this file are forecasts (tied_readers).
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), 0


if __name__ == "__main__":   # a quick manual look, no network
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 0) + b"IEND" + bytes(4)
    carrier = png + b"PK\x03\x04" + bytes(30)
    print("true_magic(png) ->", true_magic(png))
    print("png end ->", _png_end(carrier), "of", len(carrier))
    print("overlay magic ->", true_magic(_overlay(carrier)[1]))
