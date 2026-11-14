#!/usr/bin/env python3
"""Metadata Forensics look-ahead pack of the Day 22 prep (`docs/retro/day-21-predictions-metadata.md`
"Left for the player or for another group", and the Low Metadata rows of `docs/backlog-status.md`).

properties_strict.py loads this file by name (MORE_FILES, after readers_objects.py and readers_apk.py)
and calls register(M) with itself. NOTHING here answers plain: every name is registered unconfirmed
(confirmed=False), so the strict wrapper offers it through labels.pick (UNSURE) until the judge has
accepted a format for its key, and one probe on the untimed base settles it.

The never-guess contract of an extractor fn(name, data) -> value:
  * raise M.Unknown  when the file is NOT this reader's container (a RAR CRC asked of a PNG): the
    answer is then None, never a wrong-type 'none'. A wrong-type 'none' ("the field is absent") is
    a claim about a container we are not even reading, so it is forbidden here.
  * return None       only when the file IS the container but the field is genuinely absent (an
    Outlook .msg with no subject stream): the wrapper then offers the unsure `none`.
  * return the value   otherwise: the wrapper offers it through labels.pick, unsure.

Why this is safe to add (proved by tests/test_day22_look_metadata.py and preflight --regress):
  * Every name registered here resolved to NOTHING before this pack (lookup/synonym/guess/collection
    all gave None), so turning it into an unsure reader can only move a question from None -> unsure,
    never change an answer another reader already gives. A name an earlier pack registered is restored
    to that pack's reader by the clash guard at the end of register(), so no existing reader is replaced.
  * It is loaded by name and registers new names only; no shipped reader, no tool, no judged key moves.

What is here (all unsure):
  mbox        message_count          the messages of an mbox (its 'From ' separator lines).
  msg         subject, message_id,   an Outlook .msg (OLE compound file with __substg1.0_ streams):
              sender_email,          the message's own top-level property streams, decoded.
              message_class
  pe          subsystem_name         the IMAGE_OPTIONAL_HEADER.Subsystem of a PE, as its short name.
  go          build_version,         a Go binary's embedded build info (the "\xff Go buildinf:" blob,
              main_module_path,       inline string format, Go 1.18+): the toolchain version and the
              main_module_version     main module's path and version.
  rar         main_header_crc_hex,   the stored CRC of a RAR archive's main/volume header (RAR4 CRC16,
              archive_header_crc_hex  RAR5 CRC32).
  ar          member_sizes_bytes,    the per-member fields of a Unix 'ar' archive header (the member
              member_uids,            names and count are an earlier pack's; these four are new).
              member_gids, member_modes
  ttc         font_count,            a TrueType/OpenType collection ('ttcf'): the font count and the
              major_version,          collection header version.
              minor_version

Deferred (and why), for a later group or the player:
  * synthesis words largest/smallest/size/descending: the synthesis handler is a plain-answer path
    keyed on the question text (readers_synthesis.py), not a property reader; an unsure order there
    needs the solve loop, not this pack.
  * directory-only zip names / ole.stream_names in another order: a reader with those words is held
    for the player's yes in the lane rules (a guard forbids a second zip-directory-name reader).
  * TIFF/HEIF embedded ICC, HEVC VUI, AV1/VP9 extras, Matroska stream duration, OOXML signer, VBA
    interior, date forms, bigobj COFF, padded fat slices (row 228, the player's yes): high-risk byte
    parsing or an existing judged/guard surface; staged, not built here.
"""
import io
import re
import struct

M = None   # properties_strict, set by register()

# New namespaces this pack introduces (none clashes with an existing registered name; the test checks it).
NEW_NAMESPACES = ("mbox", "msg", "go", "ttc")


def U(msg):
    raise M.Unknown(msg)


# ------------------------------------------------------------------ mbox

UTF8_BOM = b"\xef\xbb\xbf"
MBOX_FROM = re.compile(rb"(?:\A|(?<=\n))From \S")


def _mbox_count(name, d):
    """The number of messages in an mbox. Unknown when the file is not an mbox (it must begin with a
    'From ' separator line, as every mbox does); the count itself is never None (an mbox has >= 1)."""
    body = d[3:] if d[:3] == UTF8_BOM else d
    if body[:5] != b"From ":
        U("not an mbox: it does not begin with a 'From ' separator line")
    return len(MBOX_FROM.findall(body))


# ------------------------------------------------------------------ Outlook .msg (the message itself)
# The message's own properties live in top-level __substg1.0_<TAG> streams of the OLE compound file.
# TAG is <property-id><type>: 001F unicode (utf-16-le), 001E 8-bit (we read as latin-1, the MAPI default
# code page being unknown here). We read ONLY top-level streams, never a __attach / __recip storage's.

MSG_PROPS = {
    "subject": ("0037", "Subject"),            # PR_SUBJECT
    "message_id": ("1035", "InternetMessageId"),   # PR_INTERNET_MESSAGE_ID
    "sender_email": ("0C1F", "SenderEmailAddress"),   # PR_SENDER_EMAIL_ADDRESS
    "message_class": ("001A", "MessageClass"),   # PR_MESSAGE_CLASS
}


def _msg_ole(d: bytes):
    """An olefile for a .msg, or Unknown. A compound file with no __substg1.0_ top-level stream is not a
    .msg (it may be an MSI, a .doc, ...): Unknown, so the answer is None and never a wrong-type 'none'."""
    if d[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        U("not an OLE compound file, so not an Outlook .msg")
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(d))
    except Exception:
        U("the file does not read as a compound file")
    tops = {e[0] for e in ole.listdir(streams=True) if len(e) == 1}
    if not any(n.lower().startswith("__substg1.0_") for n in tops):
        ole.close()
        U("a compound file with no top-level __substg1.0_ stream, so not an Outlook .msg")
    return ole


def _msg_reader(field: str):
    prop_id, _ = MSG_PROPS[field]

    def fn(name, d):
        ole = _msg_ole(d)
        try:
            for suffix, codec in (("001F", "utf-16-le"), ("001E", "latin-1")):
                stream = f"__substg1.0_{prop_id}{suffix}"
                if ole.exists(stream):
                    raw = ole.openstream(stream).read()
                    text = raw.decode(codec, "replace").rstrip("\x00")
                    return text or None   # an empty property stream: the field is present but blank
            return None   # the message has no such property: the unsure `none`
        finally:
            ole.close()
    return fn


# ------------------------------------------------------------------ PE subsystem name
# The Subsystem WORD is at offset 68 of the optional header in both PE32 and PE32+ (it precedes the
# fields whose width differs between the two). We parse the header directly, so no pefile is loaded.

PE_SUBSYSTEM = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
    8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}


def _pe_optional_header_offset(d: bytes):
    """The file offset of the optional header of a PE, or Unknown when the file is not a PE."""
    if d[:2] != b"MZ" or len(d) < 0x40:
        U("not a PE: no MZ signature")
    (e_lfanew,) = struct.unpack_from("<I", d, 0x3C)
    if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        U("not a PE: no PE signature at e_lfanew")
    return e_lfanew + 24   # after the 4-byte signature and the 20-byte COFF file header


def _pe_subsystem_name(name, d):
    off = _pe_optional_header_offset(d)
    if off + 70 > len(d):
        U("the PE optional header is cut before its Subsystem field")
    magic = struct.unpack_from("<H", d, off)[0]
    if magic not in (0x10B, 0x20B):   # PE32, PE32+ (a ROM image 0x107 has no Subsystem here)
        U(f"an optional header magic 0x{magic:x} this reader does not read")
    (subsystem,) = struct.unpack_from("<H", d, off + 68)
    return PE_SUBSYSTEM.get(subsystem) or f"SUBSYSTEM_{subsystem}"


# ------------------------------------------------------------------ Go build info
# The "\xff Go buildinf:" blob, inline-string format (Go 1.18+): flags bit 0x2 set. The pointer format
# (older) needs the section table to resolve two addresses and is out of scope: Unknown, not a guess.

GO_MAGIC = b"\xff Go buildinf:"


def _uvarint(buf: bytes, i: int):
    """(value, next index) of an unsigned LEB128 varint at buf[i:], or (None, i) when it does not fit."""
    shift = result = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 63:
            return None, i
    return None, i


def _go_decode_string(buf: bytes, i: int):
    """(text bytes, next index) of a uvarint-length-prefixed string, or (None, i)."""
    length, j = _uvarint(buf, i)
    if length is None or j + length > len(buf):
        return None, i
    return buf[j:j + length], j + length


def _go_buildinfo(d: bytes):
    """(version string, module info string) of a Go binary's inline build info, or Unknown. The module
    string carries a 16/16-byte framing that Go's debug/buildinfo strips; we strip it the same way."""
    at = d.find(GO_MAGIC)
    if at < 0 or at + 32 > len(d):
        U("no '\\xff Go buildinf:' blob (not a Go binary, or an unreadable one)")
    flags = d[at + 15]
    if not (flags & 0x2):
        U("the Go build info uses the pointer format, which needs the section table (not read here)")
    vers, j = _go_decode_string(d, at + 32)
    if vers is None:
        U("the Go build info version string does not decode")
    mod, _ = _go_decode_string(d, j)
    if mod is None:
        mod = b""
    if len(mod) >= 33 and mod[len(mod) - 17:len(mod) - 16] == b"\n":
        mod = mod[16:len(mod) - 16]
    return vers.decode("utf-8", "replace"), mod.decode("utf-8", "replace")


def _go_build_version(name, d):
    return _go_buildinfo(d)[0] or None


def _go_mod_field(which: str):
    """The main module's path (the 'path' line) or version (the 'mod' line's 3rd field)."""
    def fn(name, d):
        _, mod = _go_buildinfo(d)
        for line in mod.split("\n"):
            parts = line.split("\t")
            if which == "path" and parts[0] == "path" and len(parts) >= 2:
                return parts[1] or None
            if which == "version" and parts[0] == "mod" and len(parts) >= 3:
                return parts[2] or None
        return None   # the build info is present but names no main module path/version: the unsure `none`
    return fn


# ------------------------------------------------------------------ RAR header CRC

RAR4_SIG = b"Rar!\x1a\x07\x00"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"


def _rar_header_crc(name, d):
    """The stored CRC of a RAR archive's main (volume) header: RAR4's 16-bit block CRC, or RAR5's 32-bit
    header CRC, as a lowercase hex string of the stored width. Unknown when the file is not a RAR archive."""
    if d[:8] == RAR5_SIG:
        # RAR5: after the signature, every block begins with a CRC32 (4 bytes, little-endian), then a
        # vint header size, then the header. The first block is the main archive header.
        if len(d) < 12:
            U("a RAR5 archive cut before its first block CRC")
        (crc,) = struct.unpack_from("<I", d, 8)
        return f"{crc:08x}"
    if d[:7] == RAR4_SIG:
        # RAR4: the 7-byte marker block, then the archive (main) header block whose first 2 bytes are
        # its HEAD_CRC (little-endian). The marker block is exactly 7 bytes, so the main header is at 7.
        if len(d) < 9:
            U("a RAR4 archive cut before its main header CRC")
        (crc,) = struct.unpack_from("<H", d, 7)
        return f"{crc:04x}"
    U("not a RAR archive")


# ------------------------------------------------------------------ Unix 'ar' archive member fields
# The member names and count are an earlier pack's reader; these four numeric fields are new. Each ar
# header is 60 bytes: name[16] mtime[12] uid[6] gid[6] mode[8] size[10] magic[2]="`\n". All ASCII decimal
# (mode is octal). The GNU long-name table ("//") and symbol table ("/") are skipped for a member list.

AR_MAGIC = b"!<arch>\n"


def _ar_members(d: bytes):
    """[(name, mtime, uid, gid, mode, size)] of the real members of an ar archive, or Unknown when the
    file is not an ar archive or a header is malformed. The '/' symbol table and '//' name table are
    skipped (they are not members); long names are read from '//' and '#1/<n>' (BSD) extensions."""
    if d[:8] != AR_MAGIC:
        U("not a Unix 'ar' archive")
    out = []
    longnames = b""
    pos = 8
    while pos + 60 <= len(d):
        hdr = d[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            U("an ar member header with no '`\\n' terminator")
        raw_name = hdr[0:16].rstrip()
        size_field = hdr[48:58].strip()
        try:
            size = int(size_field)
            mtime = int(hdr[16:28].strip() or b"0")
            uid = int(hdr[28:34].strip() or b"0")
            gid = int(hdr[34:40].strip() or b"0")
            mode = int(hdr[40:48].strip() or b"0", 8)
        except ValueError:
            U("an ar member header field that is not a number")
        pos += 60
        data_end = pos + size
        if data_end > len(d):
            U("an ar member whose data runs past the file")
        name = raw_name.decode("latin-1")
        if raw_name == b"//":   # the GNU long-name table
            longnames = d[pos:data_end]
        elif raw_name in (b"/", b"__.SYMDEF", b"__.SYMDEF SORTED"):
            pass   # the symbol table: not a member
        else:
            if name.startswith("/") and name[1:].isdigit() and longnames:   # GNU long name: offset into //
                off = int(name[1:])
                end = longnames.find(b"\n", off)
                name = longnames[off:end if end >= 0 else len(longnames)].rstrip(b"/").decode("latin-1")
            elif name.endswith("/"):   # GNU short name
                name = name[:-1]
            elif name.startswith("#1/") and name[3:].isdigit():   # BSD long name: <n> bytes of data are the name
                n = int(name[3:])
                name = d[pos:pos + n].rstrip(b"\x00").decode("latin-1")
            out.append((name, mtime, uid, gid, mode, size))
        pos = data_end + (data_end & 1)   # members are 2-byte aligned
    if not out:
        return None   # an ar archive with no real member: the field is absent (the unsure `none`)
    return out


def _ar_field(index: int):
    """An intlist reader of one numeric member field across every member, in file order."""
    def fn(name, d):
        members = _ar_members(d)
        return None if members is None else [m[index] for m in members]
    return fn


# ------------------------------------------------------------------ TrueType / OpenType collection ('ttcf')

def _ttc_header(d: bytes):
    """(majorVersion, minorVersion, numFonts) of a font collection, or Unknown when the file is not one."""
    if d[:4] != b"ttcf" or len(d) < 12:
        U("not a TrueType/OpenType collection ('ttcf')")
    major, minor, num_fonts = struct.unpack_from(">HHI", d, 4)
    if num_fonts == 0 or 12 + num_fonts * 4 > len(d):
        U("a ttcf header whose font-offset table does not fit")
    return major, minor, num_fonts


def _ttc_reader(index: int):
    def fn(name, d):
        return _ttc_header(d)[index]
    return fn


# ------------------------------------------------------------------ registration

def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added.
    Every name is registered unconfirmed. A name an earlier pack already registered is restored to
    that pack's reader by the clash guard, so no shipped reader is ever replaced."""
    global M
    M = module
    before = dict(M.REG)

    M.prop("mbox.message_count", fmt="integer")(_mbox_count)

    for field in MSG_PROPS:
        M.prop(f"msg.{field}", fmt="text")(_msg_reader(field))

    M.prop("pe.subsystem_name", fmt="label")(_pe_subsystem_name)

    M.prop("go.build_version", fmt="text")(_go_build_version)
    M.prop("go.main_module_path", fmt="text")(_go_mod_field("path"))
    M.prop("go.main_module_version", fmt="text")(_go_mod_field("version"))

    M.prop("rar.main_header_crc", "rar.archive_header_crc", fmt="hex")(_rar_header_crc)

    for col, field in ((5, "sizes_bytes"), (2, "uids"), (3, "gids"), (4, "modes")):
        M.prop(f"ar.member_{field}", fmt="intlist")(_ar_field(col))

    M.prop("ttc.font_count", fmt="integer")(_ttc_reader(2))
    M.prop("ttc.major_version", fmt="integer")(_ttc_reader(0))
    M.prop("ttc.minor_version", fmt="integer")(_ttc_reader(1))

    # Clash guard: a name registered before this pack keeps its earlier reader (the existing one wins).
    for k, old in before.items():
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old

    # New namespaces, so dotted()/synonym()/content detection treat them as namespaces. Only added when
    # no registered name already used the prefix (none does; the test pins it).
    for ns in NEW_NAMESPACES:
        M.NAMESPACES.add(ns)
        if hasattr(M, "PACK_NAMESPACES"):
            M.PACK_NAMESPACES.add(ns)
        if hasattr(M, "CONTENT_TOKENS"):
            M.CONTENT_TOKENS.add(ns)
        if hasattr(M, "RELATED"):
            M.RELATED.setdefault(ns, (ns,))

    # Only the extractors of this file are forecasts (tied_readers): a name whose reader this pack added.
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), 0
