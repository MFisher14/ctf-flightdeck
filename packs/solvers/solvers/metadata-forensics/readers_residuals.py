#!/usr/bin/env python3
"""Metadata Forensics residual readers (B-248): the rule-file and coverage-matrix rows left open after the Huntress
look-aheads, each read from the bytes and walked by the structure's own size fields.

properties_strict.py loads this file by name, LAST in MORE_FILES, and calls register(M). NOTHING here answers
plain: every name is registered unconfirmed, so the strict wrapper offers it through labels.pick (UNSURE) until the
judge has accepted a format for its key. Only names nothing reads are registered (`free()`): a name an earlier pack
or a keyword family already answers keeps that reader, except the one family capture below, which is the bug.

  png       text_chunk_keywords      The Day 13 adaptability drill: `png.text_chunk_keywords` asked as a JSON array was
            (text_keyword_list, ...)  read by the `png_text_<keyword>` family as the tEXt chunk called `keywords` (None,
                                      a STOP). Registered by exact name here (lookup() takes REG before FAMILIES), it
                                      is the tEXt keywords in file order, the reader of `png.text_keywords`. When the
                                      family's reading is also possible in this file (a tEXt chunk whose keyword IS
                                      the asked word), or zTXt/iTXt text is present, it is Unknown: two readings.
  tiff/heic/avif  icc_profile_*      The embedded ICC profile of a TIFF (tag 34675) or a HEIF/AVIF primary item (colr
                                      'prof'/'rICC'), through readers_docs' icc.* readers (which now find it).
  coff      is_bigobj, bigobj_version, bigobj_class_id, time_date_stamp_utc
                                      A bigobj object's own header fields (readers_objects reads its machine, sections,
                                      stamp and names), and a COFF/PE file header's TimeDateStamp as a date (`_utc`).
  ar        member_<field> scalar    `ar.member_size_bytes`, `_uid`, `_gid`, `_mode`, `_mtime`, `_name` of an archive
                                      with ONE real member. Two or more members: Unknown (a scalar names none of them).

The extractor contract is the wrapper's: fn(name, data) -> the value; None where the file is of the type and the
field is absent; M.Unknown where it is not of the type or the bytes do not settle the fact.
"""
M = None
NEW_FNS = []
ADDED = []          # the names this pack registered (the test reads it)

# The names the png_text_<keyword> family captures that mean the LIST of tEXt keywords, and the family's own
# reading of each (the tEXt keyword it would look up): both readings are checked against the file.
PNG_KEYWORD_LISTS = {
    "png.text_chunk_keywords": "keywords",
    "png.text_chunk_keyword_list": "keyword_list",
    "png.text_keyword_list": "keyword_list",
    "png.text_chunk_keyword_names": "keyword_names",
    "png.text_keyword_names": "keyword_names",
}


def U(msg):
    raise M.Unknown(msg)


def free(names):
    """The names no reader is registered under (a family match does not count: the family capture is the bug)."""
    return [n for n in names if M.canon(n) not in M.REG]


def reg(names, fmt, fn, bits=None, unit=None, forecast=True):
    """Register `fn` under every free name. `forecast` (the default) marks it TIE_FREE like every new extractor
    of a look-ahead pack; an EXISTING reader registered under a further name (forecast=False) keeps its standing."""
    names = free(names)
    if names:
        M.prop(*names, fmt=fmt, bits=bits, unit=unit)(fn)
        if forecast:
            NEW_FNS.append(fn)
        ADDED.extend(names)


def _pack(filename):
    mod = getattr(M, "MORE_MODULES", {}).get(filename)
    if mod is None:
        raise M.PackMissing(f"metadata reader pack {filename}", M.HERE / filename,
                            "readers_residuals.py reads through it and it is not loaded")
    return mod


# ------------------------------------------------------------------ png: the tEXt keyword list under the family's names

def _png_keyword_list(family_word):
    def fn(n, d):
        if d[:8] != b"\x89PNG\r\n\x1a\n":
            U("not a PNG")
        keys = M._png_texts(d, family_word)   # Unknown when a tEXt chunk carries the family's keyword, or zTXt/iTXt
        if keys is None:
            U("the PNG's chunks do not walk")
        return keys or None
    return fn


# ------------------------------------------------------------------ embedded ICC under the container's namespace

ICC_WORDS = (("icc_profile_description", "icc.profile_description"), ("icc_description", "icc.profile_description"),
             ("icc_profile_version", "icc.profile_version"), ("icc_color_space", "icc.color_space"),
             ("icc_profile_size_bytes", "icc.embedded_size_bytes"), ("icc_device_class", "icc.device_class"),
             ("icc_copyright", "icc.copyright"))
ICC_NAMESPACES = ("tiff", "heic", "heif", "avif")


# ------------------------------------------------------------------ coff: bigobj fields and the stamp as a date

def _bigobj(d):
    h = _pack("readers_objects.py").bigobj_object(d)
    if h is None:
        U("not a bigobj COFF object")
    return h


def _is_bigobj(n, d):
    ro = _pack("readers_objects.py")
    if ro.bigobj_object(d) is not None:
        return True
    if ro.coff_object(d) is not None or ro.pe_header(d) is not None:
        return False
    U("not a COFF object or a PE image")


def _bigobj_class_id(n, d):
    import uuid
    return uuid.UUID(bytes_le=_bigobj(d)["class_id"]).hex   # the 32 digits in written (8-4-4-4-12) order


def _coff_stamp_date(n, d):
    ro = _pack("readers_objects.py")
    h = ro.any_object(d) or ro.pe_header(d)
    if h is None:
        U("not a COFF object or a PE image")
    return h["stamp"] or None   # a zero stamp (a reproducible build) is no date: absent


# ------------------------------------------------------------------ ar: one member's field as a scalar

AR_FIELDS = {"name": (0, "text"), "mtime": (1, "unixtime"), "uid": (2, "integer"), "gid": (3, "integer"),
             "mode": (4, "octal"), "size_bytes": (5, "integer")}
AR_NAMES = {"name": ("ar.member_name", "ar.member_file_name"), "mtime": ("ar.member_mtime", "ar.member_modification_time"),
            "uid": ("ar.member_uid", "ar.member_owner_id"), "gid": ("ar.member_gid", "ar.member_group_id"),
            "mode": ("ar.member_mode", "ar.member_file_mode"), "size_bytes": ("ar.member_size_bytes", "ar.member_size")}


def _ar_scalar(index):
    def fn(n, d):
        members = _pack("readers_lookahead22.py")._ar_members(d)   # Unknown when not an ar archive
        if members is None:
            return None   # an archive with no real member: the field is absent
        if len(members) != 1:
            U(f"the archive has {len(members)} members; a scalar member field names none of them")
        return members[0][index]
    return fn


# ------------------------------------------------------------------ registration

def register(module):
    global M
    M = module
    before, families = len(M.REG), len(M.FAMILIES)
    NEW_FNS.clear()
    ADDED.clear()

    for name, word in PNG_KEYWORD_LISTS.items():
        reg([name], "list", _png_keyword_list(word))

    for ns in ICC_NAMESPACES:
        for word, target in ICC_WORDS:
            p = M.REG[M.canon(target)]
            reg([f"{ns}.{word}"], p.fmt, p.fn, forecast=False)

    reg(["coff.is_bigobj", "coff.bigobj", "coff.bigobj_format"], "bool", _is_bigobj)
    reg(["coff.bigobj_version", "coff.bigobj_header_version"], "integer", lambda n, d: _bigobj(d)["version"])
    reg(["coff.bigobj_class_id", "coff.bigobj_class_id_guid", "coff.class_id"], "uuid", _bigobj_class_id)
    reg(["coff.bigobj_flags"], "number", lambda n, d: _bigobj(d)["flags"])
    reg(["coff.time_date_stamp_utc", "coff.timestamp_utc", "coff.time_date_stamp_date", "coff.timestamp_date"],
        "unixtime", _coff_stamp_date)

    for field, names in AR_NAMES.items():
        index, fmt = AR_FIELDS[field]
        reg(list(names), fmt, _ar_scalar(index))

    M.TIE_FREE.update(NEW_FNS)
    return len(M.REG) - before, len(M.FAMILIES) - families
