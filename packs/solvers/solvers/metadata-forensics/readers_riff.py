#!/usr/bin/env python3
"""Metadata Forensics reader pack (B-162): the RIFF container itself, whatever its form.

properties_strict.py loads this file by name after the other packs and calls register(M). The lane read
the forms it knew (wav.*, avi.*, webp.*) and nothing under the container's own name: `riff.sample_rate`
or `riff.chunk_ids` of a WAVE file was an UNKNOWN PROPERTY, and a RIFF form no pack knows (RMID, ACON,
CDDA, ...) had no reader at all. Here, namespace riff (riff_file is read as it):

  the container  riff.form_type (the four characters after the size; a padded one such as `AVI ` is
                 offered as stored first, then trimmed), riff.size_bytes (the header's stated size),
                 riff.file_size_matches (the stated size plus 8 is the file's size), riff.trailing_bytes
                 (bytes after the stated end), riff.chunk_ids and riff.chunk_count (the top-level chunks
                 in stored order), riff.list_types (the list type of each top-level LIST), riff.info_tags
                 and riff.info_<tag> (the INFO list's text, e.g. riff.info_inam), riff.chunk_<id>_size_bytes
  the form       riff.<field> of a WAVE, AVI or WebP file is the form's own reader of that field
                 (riff.sample_rate is wav.sample_rate on a WAVE file): the nearest reader, resolved the way
                 properties_strict resolves any name (lookup, synonym, guess) under the form's namespace,
                 and never for a form that has no namespace

Every reader is registered unconfirmed: every answer is unsure until the judge accepts a name for it. The
extractor contract is properties_strict's: the value, None when the file is no RIFF file or has no such
field, or M.Unknown when it is one and the bytes do not settle the fact (a chunk that runs past the end,
more chunks than are walked, two INFO values under one tag).
"""
import re
import struct

M = None          # properties_strict, set by register()
NS = "riff"
ALIASES = {"riff_file": "riff", "resource_interchange_file_format": "riff"}
FORMS = {"WAVE": "wav", "AVI ": "avi", "WEBP": "webp"}   # a form -> the namespace whose readers read it
MAX_CHUNKS = 1 << 14
INFO_ID = re.compile(r"[A-Z][A-Z0-9 ]{3}")


def U(msg):
    raise M.Unknown(msg)


def _chunks(d: bytes):
    """[(id, body offset, size)] of the top-level chunks, or None when the file is no RIFF file."""
    if d[:4] != b"RIFF" or len(d) < 12:
        return None
    stated = struct.unpack_from("<I", d, 4)[0]
    end = min(len(d), 8 + stated)
    out, at = [], 12
    while at + 8 <= end:
        if len(out) >= MAX_CHUNKS:
            U("more chunks than are walked")
        cid, size = struct.unpack_from("<4sI", d, at)
        if at + 8 + size > end:
            U(f"the chunk {cid.decode('latin-1')!r} runs past the end of the RIFF data")
        out.append((cid.decode("latin-1"), at + 8, size))
        at += 8 + size + (size & 1)
    return out


def _form(d: bytes):
    return d[8:12].decode("latin-1") if d[:4] == b"RIFF" and len(d) >= 12 else None


def _form_type(n, d):
    f = _form(d)
    if f is None:
        return None
    if f != f.rstrip():
        raise M.Ambiguous([("raw", f), ("trimmed", f.rstrip())])
    return f


def _lists(d: bytes):
    c = _chunks(d)
    return None if c is None else [(d[at:at + 4].decode("latin-1"), at, size) for cid, at, size in c if cid == "LIST" and size >= 4]


def _info(d: bytes):
    """{tag: text} of the top-level INFO list(s); Unknown for a tag given twice."""
    lists = _lists(d)
    if lists is None:
        return None
    out = {}
    for kind, at, size in lists:
        if kind != "INFO":
            continue
        i, end = at + 4, at + size
        while i + 8 <= end:
            tag, ln = struct.unpack_from("<4sI", d, i)
            if i + 8 + ln > end:
                U("an INFO entry runs past its list")
            tag = tag.decode("latin-1")
            if tag in out:
                U(f"the INFO tag {tag} is given twice")
            out[tag] = d[i + 8:i + 8 + ln].split(b"\x00", 1)[0].decode("latin-1")
            i += 8 + ln + (ln & 1)
    return out


def _delegate(n, d, rest):
    """riff.<rest> of a WAVE, AVI or WebP file: its form's own reader of <rest>, its options as they are."""
    f = _form(d)
    if f is None:
        return None
    ns = FORMS.get(f)
    if ns is None:
        U(f"no reader namespace reads the RIFF form {f!r}")
    key = f"{ns}_{rest}"
    p = M.lookup(key) or M.synonym(key)[0] or M.guess(key)[0]
    if p is None:
        U(f"no {ns} reader reads {rest}")
    options, absent = M.options_for(p, n, d)
    if absent:
        return None
    kept = [(name, v) for name, v in options if name in M.FORM_NAMES and isinstance(v, str)]
    if not kept:
        U(f"{p.name}'s forms are not ones this container name can offer")
    return kept


def _register():
    prop = M.prop
    prop("riff.form_type", "riff.form", "riff.riff_type", "riff.form_fourcc", "riff.type", fmt="text")(_form_type)
    prop("riff.size_bytes", "riff.riff_size_bytes", "riff.stated_size_bytes", "riff.chunk_size_bytes", "riff.header_size_bytes",
         fmt="integer")(lambda n, d: struct.unpack_from("<I", d, 4)[0] if _form(d) is not None else None)
    prop("riff.file_size_matches", "riff.size_matches_file", fmt="bool")(
        lambda n, d: struct.unpack_from("<I", d, 4)[0] + 8 == len(d) if _form(d) is not None else None)
    prop("riff.trailing_bytes", "riff.bytes_after_riff", "riff.trailing_data_bytes", fmt="integer")(
        lambda n, d: max(0, len(d) - 8 - struct.unpack_from("<I", d, 4)[0]) if _form(d) is not None else None)
    prop("riff.chunk_ids", "riff.chunk_types", "riff.top_level_chunk_ids", "riff.chunk_fourccs", fmt="list")(
        lambda n, d: (lambda c: None if c is None else [x[0] for x in c] or None)(_chunks(d)))
    prop("riff.chunk_count", "riff.top_level_chunk_count", fmt="integer")(
        lambda n, d: (lambda c: None if c is None else len(c))(_chunks(d)))
    prop("riff.list_types", "riff.list_chunk_types", fmt="list")(
        lambda n, d: (lambda c: None if c is None else [x[0] for x in c] or None)(_lists(d)))
    prop("riff.info_tags", "riff.info_chunk_ids", "riff.info_keys", fmt="list")(
        lambda n, d: (lambda i: None if i is None else list(i) or None)(_info(d)))

    def info_field(n, d, tag):
        info = _info(d)
        return None if info is None else info.get(tag.upper()) or None
    M.family(r"riff_info_([a-z0-9]{4})", "text")(info_field)

    def chunk_size(n, d, cid):
        c = _chunks(d)
        if c is None:
            return None
        hits = [size for x, _, size in c if x.strip().lower() == cid]
        if len(hits) > 1:
            U(f"{len(hits)} top-level chunks are named {cid}")
        return hits[0] if hits else None
    M.family(r"riff_chunk_([a-z0-9]{3,4})_size(?:_bytes)?", "integer")(chunk_size)
    # not riff_file_* (an alias of this namespace: guess() reads it as riff.*) nor the two families above
    M.family(r"riff_(?!info_|chunk_|file_)(.+)", "forms")(_delegate)


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    before, families = dict(M.REG), len(M.FAMILIES)
    _register()
    for k, old in before.items():   # a name registered before keeps its reader
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    M.NAMESPACES.add(NS)
    M.PACK_NAMESPACES.add(NS)
    M.CONTENT_TOKENS.add(NS)
    M.RELATED.setdefault(NS, (NS,))
    for form_ns in FORMS.values():   # a WAVE, AVI or WebP file's facts page lists the container's facts too
        M.RELATED[form_ns] = tuple(dict.fromkeys(M.RELATED.get(form_ns, (form_ns,)) + (NS,)))
    M.MORE_TYPES.append((NS, lambda d: _form(d) is not None))
    M.NS_ALIAS.update(ALIASES)
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), len(M.FAMILIES) - families
