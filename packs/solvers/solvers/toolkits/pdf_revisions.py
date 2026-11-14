#!/usr/bin/env python3
"""PDF incremental-revision splitter and redaction opener (GAP-PDF-REVISIONS; ctf-solver-gap-analysis.md A-mid; B-073).

A PDF grows by APPENDING: every incremental update writes new objects, a fresh cross-reference
section and a new trailer, then `startxref <offset>` and `%%EOF`. The earlier document is still
there, byte for byte, as the prefix `data[0 : that %%EOF]`. A redaction, a "final" overlay or a
replaced page therefore hides the *prior state* in plain sight. carve_stego only `rfind()`s the
LAST `%%EOF` (trailing bytes), the Metadata lane only counts `%%EOF` markers, and maldoc checks a
single trailer -- none of them carves each PRIOR revision as its own standalone document and reads
the object N as it stood at revision k. This module does, in pure Python (no new dependency):

  revisions(data)            -> [{index, end_offset, root, size, objects, prev, valid}]  (oldest first)
  revision_count(data)       -> int        number of %%EOF revision boundaries (bounded)
  object_at(data, num, rev)  -> bytes|None  indirect object `num` as it stood at revision `rev`
                                            (1-based), resolved through that revision's /Prev chain

It walks every `startxref`/`%%EOF` boundary and the `/Prev` xref chain, handling BOTH classic xref
tables and xref streams (PDF 1.5+). Everything is bounded (MAX_REVISIONS, MAX_OBJECTS, MAX_SCAN)
and fail-closed: a broken or ambiguous chain, an unparsable revision or a `/Prev` that does not
resolve yields None / an empty table for the affected ids, never a partial guess. Nothing in the
PDF is ever rendered, decompressed-and-executed, or run; only structure is read.

Never-wrong contract (AGENTS.md "Uncertain answers"), per output:
  - `revision_count` and each revision's byte slice are a DETERMINISTIC structural read -> a count
    is PLAIN-eligible (a bare integer, no author-chosen name); a reconstructed revision validated
    by a parsable xref + trailer is plain bytes the caller may hash.
  - an object's VALUE at a revision is plain only when that object parses to a complete, consistent
    cross-reference at that revision (the chain resolves and the entry is an in-use `n` object);
  - an author-named SELECTION ("which revision is the original", a label for a change) is
    labels.candidates -- UNSURE, probed on the untimed base / a no-deadline attempt, never plain;
  - a broken/ambiguous chain, an unparsable revision, or a linearized file whose /Prev does not
    resolve is None for the affected ids.

The opener (B-073) reads what a "redacted" PDF still holds, on the same cross-reference walk:

  open_pdf(data)               -> report: every revision's page text (Tj/TJ through each font's
                                  ToUnicode map), each line marked when something hides it (an opaque
                                  rectangle or image painted over it, ink the colour of what is behind
                                  it, render mode 3, an annotation over it); text only an earlier
                                  revision shows; text in streams no page uses; every Info and XMP field
  metadata_key_crypto(report)  -> a metadata value of 16, 24 or 32 bytes (raw, hex or base64) tried as
                                  an AES key (ECB, CBC) on the blobs found in the PDF; a plaintext counts
                                  only when the event's flag format matches in it

Hidden text is a lead to read (positions are estimates: no glyph widths are read), a decrypted
plaintext is reported only on a flag-format match, and neither is ever a solve_set answer.

  .venv/bin/python solvers/toolkits/pdf_revisions.py <file.pdf>... [--json] [--extract DIR] [--selftest]
                   [--text] [--streams DIR] [--flag-regex RX] [--no-open]

`--extract` writes each reconstructed revision as `<file>.rev<k>.pdf`. `--selftest` runs the
in-file test (a 3-revision incremental PDF) and exits non-zero on failure. The opener runs unless
`--no-open`: `--text` also prints every page's text, `--streams DIR` writes every stream each revision
wrote (decoded where its filters are known), `--flag-regex` replaces the active event's flag format
for the crypto hook. Exit 3: the crypto hook had a key and a blob to try and could not run (the
reason is printed).
"""
import base64
import binascii
import html
import importlib.util
import json
import re
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.append(_p)

try:
    import labels  # noqa: E402
except Exception:  # noqa: BLE001 - never-guess holds even when the unsure contract is unavailable
    labels = None

KEY = "pdf_revisions"
# `pdf_revisions` is not (yet) a registered label prefix (solvers/common/labels.TOOLKIT_PREFIXES),
# so until it is wired into the registry its UNSURE answers ride under the carving family's prefix,
# which already owns PDF carving.  A plain answer needs no prefix; an unsure key that cannot be
# formed falls back to None (fail-closed) -- never a guess.
LABEL_PREFIX = "carve_stego"

MAX_REVISIONS = 256          # %%EOF boundaries / xref hops considered
MAX_OBJECTS = 200_000        # cross-reference entries held at once
MAX_SCAN = 64 * 1024 * 1024  # bytes of one file searched

_EOF = b"%%EOF"
_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_STARTXREF = re.compile(rb"startxref\s+(\d+)")
_REVISION_END = re.compile(rb"(?:\A|[\r\n])[ \t]*startxref\s+\d+[ \t\r\n]+%%EOF[ \t]*(?=[\r\n]|\Z)")
_XREF_KW = re.compile(rb"xref\b")
_TRAILER_KW = re.compile(rb"\s*trailer\b")
_SUBSEC = re.compile(rb"\s*(\d+)\s+(\d+)\s*")
_ENTRY = re.compile(rb"\s*(\d{10})\s(\d{5})\s([nf])")
_WS = re.compile(rb"\s*")
_STREAM_KW = re.compile(rb"\s*stream(?:\r\n|[\r\n])")
_STREAM_END = re.compile(rb"\s*endstream\s+endobj\b")


# ---------------------------------------------------------------------------- structural readers


def _is_pdf(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and data[:1024].find(b"%PDF-") >= 0


def _eof_offsets(data: bytes) -> list:
    """End offsets of startxref/%%EOF revision footers, never bare markers in content."""
    offs = []
    cap = min(len(data), MAX_SCAN)
    for match in _REVISION_END.finditer(data, 0, cap):
        end = match.end()
        if data[end:end + 2] == b"\r\n":
            end += 2
        elif data[end:end + 1] in (b"\r", b"\n"):
            end += 1
        offs.append(end)
        if len(offs) >= MAX_REVISIONS:
            break
    return offs


def _last_startxref(blob: bytes):
    """The offset named by the LAST `startxref` in `blob` (the revision's own top xref)."""
    k = blob.rfind(b"startxref")
    if k < 0:
        return None
    m = _STARTXREF.match(blob, k)
    if not m:
        m = _STARTXREF.search(blob, k)
    # Offsets cannot name a byte in our bounded input with more than 20 digits;
    # reject before int() can hit Python's decimal-conversion limit.
    return int(m.group(1)) if m and len(m.group(1)) <= 20 else None


def _balanced_dict(data: bytes, pos: int):
    """The bytes of the `<< ... >>` dictionary at/after `pos`, with nesting. None if unbalanced."""
    i = data.find(b"<<", pos)
    if i < 0:
        return None
    depth = 0
    j = i
    n = len(data)
    while j < n - 1:
        two = data[j:j + 2]
        if two == b"<<":
            depth += 1
            j += 2
        elif two == b">>":
            depth -= 1
            j += 2
            if depth == 0:
                return data[i:j]
        else:
            j += 1
        if j - i > 1_000_000:          # a dictionary this large is not one we trust
            return None
    return None


def _trailer_fields(dict_bytes: bytes) -> dict:
    """/Size, /Prev, /XRefStm (ints), /Root and /Info (an `N G R` string) and /Encrypt (True when
    the key is there) read from a trailer dict."""
    out = {"Size": None, "Prev": None, "XRefStm": None, "Root": None, "Info": None, "Encrypt": None}
    if not dict_bytes:
        return out
    for name in ("Size", "Prev", "XRefStm"):
        m = re.search(rb"/" + name.encode() + rb"\s+(\d+)", dict_bytes)
        if m:
            out[name] = int(m.group(1))
    for name in ("Root", "Info"):
        m = re.search(rb"/" + name.encode() + rb"\s+(\d{1,20})\s+(\d{1,20})\s+R", dict_bytes)
        if m:
            out[name] = f"{int(m.group(1))} {int(m.group(2))} R"
    if re.search(rb"/Encrypt(?![A-Za-z0-9])", dict_bytes):
        out["Encrypt"] = True
    return out


def _classic(data: bytes, off: int):
    """Parse a classic `xref` table at `off`. Returns ({num: (offset, gen, type)}, trailer) or None."""
    m = _XREF_KW.match(data, off)
    if not m:
        m = _XREF_KW.search(data, off, off + 32)
        if not m:
            return None
    cur = m.end()
    entries = {}
    while True:
        mt = _TRAILER_KW.match(data, cur)
        if mt:
            cur = mt.end()
            break
        ms = _SUBSEC.match(data, cur)
        if not ms:
            return None
        start, count = int(ms.group(1)), int(ms.group(2))
        cur = ms.end()
        if count < 0 or count > MAX_OBJECTS or len(entries) + count > MAX_OBJECTS:
            return None
        for k in range(count):
            me = _ENTRY.match(data, cur)
            if not me:
                return None
            num = start + k
            entries[num] = (int(me.group(1)), int(me.group(2)), me.group(3).decode())
            cur = me.end()
    trailer = _trailer_fields(_balanced_dict(data, cur))
    return entries, trailer


def _decode_stream(dict_bytes: bytes, raw: bytes):
    """Best-effort decode of an xref-stream body: Flate, optionally PNG-predicted. None on failure."""
    filt = re.search(rb"/Filter\s*/(\w+)", dict_bytes)
    body = raw
    if filt and filt.group(1) in (b"FlateDecode", b"Fl"):
        try:
            decoder = zlib.decompressobj()
            body = decoder.decompress(raw, MAX_SCAN + 1)
            if not decoder.eof or len(body) > MAX_SCAN:
                return None
        except zlib.error:
            return None
    elif filt:
        return None  # ASCIIHex/ASCII85/LZW not needed for a cross-reference walk; fail closed
    pr = re.search(rb"/Predictor\s+(\d+)", dict_bytes)
    cols = re.search(rb"/Columns\s+(\d+)", dict_bytes)
    if pr and int(pr.group(1)) >= 10:
        columns = int(cols.group(1)) if cols else 1
        body = _png_unpredict(body, columns)
    return body


def _png_unpredict(body: bytes, columns: int):
    """Undo PNG-up/sub/etc. row predictors on an xref stream (1 tag byte per row)."""
    stride = columns
    row_len = stride + 1
    if row_len <= 1 or len(body) % row_len:
        return body
    out = bytearray()
    prev = bytearray(stride)
    for r in range(0, len(body), row_len):
        tag = body[r]
        row = bytearray(body[r + 1:r + row_len])
        if tag == 2:  # Up
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif tag == 1:  # Sub
            for i in range(stride):
                left = row[i - 1] if i >= 1 else 0
                row[i] = (row[i] + left) & 0xFF
        elif tag != 0:
            return body  # Average/Paeth: not attempted, fail closed to raw
        out += row
        prev = row
    return bytes(out)


def _xref_stream(data: bytes, off: int):
    """Parse an xref STREAM object at `off`. Returns ({num: (offset, gen, type)}, trailer) or None."""
    m = _OBJ.match(data, _WS.match(data, off).end())
    if not m:
        m = _OBJ.search(data, off, off + 64)
        if not m:
            return None
    dict_bytes = _balanced_dict(data, m.end())
    if not dict_bytes or b"/XRef" not in dict_bytes:
        return None
    mw = re.search(rb"/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]", dict_bytes)
    if not mw:
        return None
    w = (int(mw.group(1)), int(mw.group(2)), int(mw.group(3)))
    width = sum(w)
    if width <= 0 or width > 32:
        return None
    size_m = re.search(rb"/Size\s+(\d+)", dict_bytes)
    size = int(size_m.group(1)) if size_m else None
    idx_m = re.search(rb"/Index\s*\[([\d\s]+)\]", dict_bytes)
    index = [int(x) for x in idx_m.group(1).split()] if idx_m else ([0, size] if size is not None else None)
    if not index or len(index) % 2:
        return None
    dictionary_end = data.find(b"<<", m.end()) + len(dict_bytes)
    sm = re.compile(rb"\s*stream(?:\r\n|[\r\n])").match(data, dictionary_end)
    if not sm:
        return None
    s0 = sm.end()
    length_m = re.search(rb"/Length\s+(\d+)(?:\s+(\d+)\s+R\b)?", dict_bytes)
    if not length_m or length_m.group(2) is not None:
        return None
    length = int(length_m.group(1))
    e0 = s0 + length
    if e0 > len(data) or not re.match(rb"\s*endstream\b", data[e0:]):
        return None
    body = _decode_stream(dict_bytes, data[s0:e0])
    if body is None:
        return None
    entries = {}
    pos = 0

    def field(buf, n):
        return int.from_bytes(buf, "big") if n else 0

    for s in range(0, len(index), 2):
        start, count = index[s], index[s + 1]
        if count < 0 or len(entries) + count > MAX_OBJECTS:
            return None
        for k in range(count):
            if pos + width > len(body):
                return None
            row = body[pos:pos + width]
            pos += width
            f1 = field(row[:w[0]], w[0]) if w[0] else 1   # default type 1 when W[0] == 0
            f2 = field(row[w[0]:w[0] + w[1]], w[1])
            f3 = field(row[w[0] + w[1]:], w[2])
            num = start + k
            if f1 == 1:
                entries[num] = (f2, f3, "n")
            elif f1 == 2:
                entries[num] = (f2, f3, "c")  # compressed: object f3 in stream f2 (offset unresolved here)
            else:
                entries[num] = (0, f3, "f")
    trailer = _trailer_fields(dict_bytes)
    return entries, trailer


def _parse_xref_at(data: bytes, off):
    """Dispatch to the classic or stream parser for the xref at `off`. None on any failure."""
    if off is None or off < 0 or off >= len(data):
        return None
    try:
        head = data[off:off + 24].lstrip()
        if head.startswith(b"xref"):
            return _classic(data, off)
        return _xref_stream(data, off)
    except Exception:  # noqa: BLE001 - a cross-reference that cannot be parsed is no answer
        return None


def _walk_chain(blob: bytes, start_off):
    """The merged object table as of the revision whose top xref is at `start_off`: newest wins,
    following /Prev (and a hybrid /XRefStm). None if ANY link in the chain is broken (fail-closed)."""
    if start_off is None:
        return None
    entries = {}
    seen = set()
    cur = start_off
    hops = 0
    while cur is not None:
        if cur in seen:
            return None                 # a cyclic chain never resolves
        seen.add(cur)
        hops += 1
        if hops > MAX_REVISIONS:
            return None
        parsed = _parse_xref_at(blob, cur)
        if parsed is None:
            return None                 # a /Prev that does not resolve -> the whole read is None
        ents, trailer = parsed
        for num, e in ents.items():
            entries.setdefault(num, e)  # we walk newest -> oldest, so the first seen wins
        if len(entries) > MAX_OBJECTS:
            return None
        xr = trailer.get("XRefStm")
        if xr is not None:
            hyb = _parse_xref_at(blob, xr)
            if hyb:
                for num, e in hyb[0].items():
                    entries.setdefault(num, e)
        cur = trailer.get("Prev")
    return entries


def _read_indirect(blob: bytes, off: int, num: int, table=None):
    """The bytes `N G obj ... endobj` of object `num` at `off`. None if it is not there."""
    if off < 0 or off >= len(blob):
        return None
    p = _WS.match(blob, off).end()
    m = _OBJ.match(blob, p)
    if not m or len(m.group(1)) > 20 or int(m.group(1)) != num:
        m = re.compile(rb"\b%d\s+\d+\s+obj\b" % num).search(blob, max(0, off - 8), min(len(blob), off + 64))
        if not m:
            return None
    # A stream's bytes may contain any token, including endobj/endstream. Its
    # declared Length, not the first matching byte string, determines its end.
    start = _WS.match(blob, m.end()).end()
    if blob[start:start + 2] == b"<<":
        dictionary = _balanced_dict(blob, start)
        sm = _STREAM_KW.match(blob, start + len(dictionary)) if dictionary else None
        if sm:
            s0 = sm.end()
            lm = re.search(rb"/Length\s+(\d+)(?:\s+(\d+)\s+R\b)?", dictionary)
            if not lm or len(lm.group(1)) > 20:
                return None
            length = int(lm.group(1))
            if lm.group(2) is not None:
                if table is None or len(lm.group(2)) > 20:
                    return None
                entry = table.get(length)
                if not entry or entry[2] != "n" or entry[1] != int(lm.group(2)):
                    return None
                value = _read_indirect(blob, entry[0], length)
                value = re.fullmatch(rb"\d+\s+\d+\s+obj\s+(\d{1,20})\s+endobj", value or b"")
                if not value:
                    return None
                length = int(value.group(1))
            end = s0 + length
            tail = _STREAM_END.match(blob, end) if end <= len(blob) else None
            return blob[m.start():tail.end()] if tail else None
    e = blob.find(b"endobj", m.end())
    if e < 0:
        return None
    return blob[m.start():e + len(b"endobj")]


def revisions(data: bytes) -> list:
    """Each incremental revision as a record, oldest first. `objects` is THIS revision's own xref
    section ({num: (offset, gen, type)}); `valid` is True when its top xref and trailer parsed."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    out = []
    for idx, end in enumerate(_eof_offsets(data), start=1):
        sl = data[:end]
        start_off = _last_startxref(sl)
        parsed = _parse_xref_at(sl, start_off)
        if parsed is None:
            out.append({"index": idx, "end_offset": end, "root": None, "size": None,
                        "objects": {}, "prev": None, "valid": False})
            continue
        ents, trailer = parsed
        out.append({"index": idx, "end_offset": end, "root": trailer.get("Root"),
                    "size": trailer.get("Size"), "objects": ents, "prev": trailer.get("Prev"),
                    "valid": bool(trailer.get("Root") or trailer.get("Size"))})
    return out


def revision_count(data: bytes) -> int:
    """The number of `%%EOF` revision boundaries (bounded by MAX_REVISIONS). Deterministic."""
    if not isinstance(data, (bytes, bytearray)):
        return 0
    return len(_eof_offsets(bytes(data)))


def chain_resolves(data: bytes) -> bool:
    """True when every revision's top xref parses AND each revision's /Prev links to the previous
    revision's xref offset -- the condition under which a count may be answered PLAIN."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    data = bytes(data)
    eofs = _eof_offsets(data)
    if not eofs:
        return False
    prev_start = None
    for end in eofs:
        sl = data[:end]
        start_off = _last_startxref(sl)
        parsed = _parse_xref_at(sl, start_off)
        if parsed is None or not (parsed[1].get("Root") or parsed[1].get("Size")):
            return False
        trailer_prev = parsed[1].get("Prev")
        if prev_start is None:
            if trailer_prev is not None:
                return False            # earliest revision must not chain further back
        elif trailer_prev != prev_start:
            return False                # a /Prev that does not point at the previous revision
        prev_start = start_off
    return True


def object_at(data: bytes, obj_num: int, revision: int):
    """Indirect object `obj_num` as it stood at `revision` (1-based, 1 = earliest). None when the
    revision is out of range, the chain is broken, or the object is free/absent at that revision."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    eofs = _eof_offsets(data)
    if not isinstance(revision, int) or revision < 1 or revision > len(eofs):
        return None
    sl = data[:eofs[revision - 1]]
    table = _walk_chain(sl, _last_startxref(sl))
    if table is None:
        return None
    ent = table.get(obj_num)
    if not ent or ent[2] != "n":
        return None
    return _read_indirect(sl, ent[0], obj_num, table)


def reconstruct(data: bytes, revision: int):
    """The standalone byte slice of `revision` (data[0 : its %%EOF]), or None out of range."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    eofs = _eof_offsets(bytes(data))
    if not isinstance(revision, int) or revision < 1 or revision > len(eofs):
        return None
    return bytes(data)[:eofs[revision - 1]]


# ---------------------------------------------------------------------------- runner contract

_OWN_WORDS = re.compile(r"\b(revision|revisions|incremental|/prev|prev|startxref|rollback|"
                        r"prior[\s-]?state|prior|previous[\s-]?version|earlier[\s-]?version|"
                        r"before[\s-]?redaction|original[\s-]?version|update|updates)\b", re.I)
_COUNT_WORDS = re.compile(r"\b(how many|number of|count of|count)\b", re.I)
_REV_NOUN = re.compile(r"\b(revision|revisions|version|versions)\b", re.I)
_UPDATE_NOUN = re.compile(r"\b(incremental\s+update|incremental\s+updates|update|updates)\b", re.I)
# `save(s)` and `generation(s)` name quantities DIFFERENT from a revision count that merely coincide
# on a clean file: a "save" may or may not count the original write (total saves = revisions = n vs
# incremental saves = updates = n - 1), and a PDF "generation" is an object generation number, not a
# document version. Neither pins one proven number, so neither is ever answered PLAIN (never-guess).
_SAVE_NOUN = re.compile(r"\b(save|saves|saved|resave|resaves|resaved)\b", re.I)
_GEN_NOUN = re.compile(r"\b(generation|generations)\b", re.I)
_SELECTION = re.compile(r"\b(which|original|first|label|name|named|redaction|what did|changed)\b", re.I)
# ids another lane owns: never ours (carve_stego / maldoc convention)
_FOREIGN_ID = re.compile(r"(^d\d\d_)|(-role$)|(-attack$)|(^ans-)", re.I)
_FOREIGN_Q = re.compile(r"\b(determine .+ for |message\b)", re.I)


def _q_text(q) -> str:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                           fmt.get("syntax")))


def _is_integer_q(q) -> bool:
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    kind = str(fmt.get("kind") or "").lower()
    syntax = str(fmt.get("syntax") or "").lower()
    if kind in ("integer", "int", "number"):
        return True
    return bool(re.search(r"\b(integer|decimal|number|count)\b", syntax))


def _pdf_for(q, pdfs: dict):
    """The PDF a question is about: the member it names, else the only PDF, else None if they differ."""
    if not pdfs:
        return None
    hay = (str(q.get("member") or "") + " " + str(q.get("artifact") or "") + " " + _q_text(q)).lower()
    named = [name for name in pdfs if name and name.lower() in hay]
    if len(named) == 1:
        return pdfs[named[0]]
    if len(pdfs) == 1:
        return next(iter(pdfs.values()))
    # several PDFs, none named: answer only if every one agrees on the count
    counts = {revision_count(b) for b in pdfs.values()}
    if len(counts) == 1:
        return next(iter(pdfs.values()))
    return None


def _selection_unsure(key_shape: str, options):
    """A labels.candidates unsure answer for an author-named selection; None if unavailable."""
    if labels is None or not options:
        return None
    try:
        return labels.candidates(f"{LABEL_PREFIX}.{key_shape}", options)
    except Exception:  # noqa: BLE001 - fail closed to None, never a guess
        return None


def _count_unsure(n: int):
    """An ambiguous count ('how many saves', a revisions+updates mix): the quantities coincide on
    this file but are DIFFERENT facts, so neither is proven. Offer them as evidence-ranked
    labels.candidates (revisions = n, incremental updates = n - 1) -- UNSURE, never a plain guess,
    and under a key of its OWN, apart from the author-named selection pick (one key never carries two
    different quantities). None when the contract is unavailable or nothing distinct is left."""
    opts, seen = [], set()
    for name, val in (("revisions", n), ("incremental_updates", n - 1)):
        if val is not None and val >= 0 and val not in seen:
            seen.add(val)
            opts.append((name, str(val)))          # candidate values must be DISTINCT
    return _selection_unsure("pdf_count_interpretation/xref+prev", opts)


def _answer_one(q, pdfs: dict):
    text = _q_text(q)
    qid = q.get("answer_id") or q.get("qid") or q.get("id") or ""
    if _FOREIGN_ID.search(str(qid)) or _FOREIGN_Q.search(text.lower()):
        return None                              # a known lane owns it
    if not _OWN_WORDS.search(text):
        return None                              # not a revision question
    data = _pdf_for(q, pdfs)
    if data is None or not _is_pdf(data):
        return None
    n = revision_count(data)
    if n < 1:
        return None

    # (A) a count, only when the whole /Prev chain resolves consistently. Each count noun names a
    # DIFFERENT quantity that merely coincides here: revisions/versions = n, incremental updates =
    # n - 1, while 'saves' (total vs incremental) and 'generations' (object generation numbers) do
    # not map to one proven number. A PLAIN integer is emitted ONLY when the noun pins exactly one
    # proven quantity; a 'saves' noun or a revisions+updates mix is ambiguous -> labels.candidates of
    # the distinct interpretations (unsure); a 'generations'-only or unpinned noun -> None.
    if _COUNT_WORDS.search(text) and _is_integer_q(q):
        if not chain_resolves(data):
            return None                          # broken / ambiguous chain -> None, never a guess
        wants_rev = bool(_REV_NOUN.search(text))
        wants_upd = bool(_UPDATE_NOUN.search(text))
        wants_save = bool(_SAVE_NOUN.search(text))
        wants_gen = bool(_GEN_NOUN.search(text))
        proven = int(wants_rev) + int(wants_upd)
        if proven == 1 and not wants_save and not wants_gen:
            return n if wants_rev else n - 1     # exactly one proven, unambiguous quantity -> PLAIN
        if wants_save or (wants_rev and wants_upd):
            return _count_unsure(n)              # 'saves' / a mixed proven noun -> unsure candidates
        return None                              # 'generations' alone, or no pinning noun -> None

    # (B) UNSURE: an author-named selection of a revision ("which is the original", a label).
    if _SELECTION.search(text) and chain_resolves(data):
        revs = revisions(data)
        # evidence-ranked DIFFERENT hypotheses for "the original / prior" revision index
        opts = [("earliest", revs[0]["index"]), ("latest_before_final", revs[-2]["index"] if n >= 2 else None)]
        opts = [(name, str(val)) for name, val in opts if val is not None]
        return _selection_unsure("pdf_original_revision/xref+prev", opts)

    return None


def signals(questions, files) -> float:
    """0..1: how much a delivery + its questions look like a multi-revision PDF. 0 on a non-PDF or
    a single-revision PDF, so it never competes on an ordinary document."""
    pdfs = {n: b for n, b in (files or {}).items() if _is_pdf(b) and revision_count(b) >= 2}
    if not pdfs:
        return 0.0
    score = 0.5
    hits = 0
    for q in questions or []:
        if _OWN_WORDS.search(_q_text(q)):
            hits += 1
    score += min(0.4, 0.15 * hits)
    return round(min(1.0, score), 2)


def solve_set(questions, files, ctx) -> dict:
    """Runner contract. Never guesses: a plain count only when the chain resolves and the noun pins
    the number; an author-named selection unsure; everything else None."""
    files = files or {}
    pdfs = {n: bytes(b) for n, b in files.items() if isinstance(b, (bytes, bytearray)) and _is_pdf(b)}
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        try:
            out[qid] = _answer_one(q, pdfs)
        except Exception:  # noqa: BLE001 - a fact that cannot be read is no answer
            out[qid] = None
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


# ---------------------------------------------------------------------------- opener (B-073)
#
# The cross-reference walk above stays the only file-structure reader: objects come from each
# revision's own xref table through _read_indirect, and their values from maldoc's object reader
# (_pdf_value, _pdf_decode, _pdf_str). New here are the content-stream operator loop, the ToUnicode
# reader and the XMP field reader. Positions are estimates (no glyph widths are read: a run is half
# an em per character wide), so "hidden" is a lead to read, never an answer.

OPEN_CPU_BUDGET = 10.0             # CPU seconds of one open_pdf
CRYPTO_CPU_BUDGET = 6.0            # CPU seconds of one metadata_key_crypto
MAX_PAGES = 2000
MAX_RUNS = 20_000                  # text-showing operators kept per page
MAX_REGIONS = 20_000               # painted rectangles and images kept per page
MAX_FIELDS = 2000                  # metadata fields, annotations, listed streams
MAX_CMAP = 200_000                 # ToUnicode entries of one font
MAX_XMP = 1024 * 1024
MAX_BLOB = 4 * 1024 * 1024         # one stream kept as a ciphertext candidate
MAX_BLOB_TOTAL = 64 * 1024 * 1024
MAX_BLOBS = 400
MAX_SPANS = 20_000                 # runs of neighbouring text lines looked at for a wrapped blob
MAX_KEYS = 64
MAX_TRIALS = 20_000
MAX_HITS = 8
KEY_SIZES = (16, 24, 32)

_IDENT = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
_WHITE = (1.0, 1.0, 1.0)
_BLACK = (0.0, 0.0, 0.0)
_OPERATOR = re.compile(rb"[^\x00\t\n\x0c\r ()<>\[\]{}/%]+")
_INLINE_END = re.compile(rb"[\x00\t\n\x0c\r ]EI(?=[\x00\t\n\x0c\r ]|\Z)")
_CONTENT_LOOK = re.compile(rb"\bBT\b[\s\S]{0,65536}?[)>\]]\s*(?:T[jJ]|['\"])(?![A-Za-z0-9])")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{22,}={0,2}")
_IMAGE_CODECS = ("DCTDecode", "DCT", "JPXDecode", "CCITTFaxDecode", "CCF", "JBIG2Decode")
_QUIET_ANNOTS = ("Link", "Highlight", "Underline", "StrikeOut", "Squiggly", "Popup", "Text", "Caret",
                 "FileAttachment", "Sound")
_FILL_OPS = ("f", "F", "f*", "B", "B*", "b", "b*")
_UNPRINTABLE = bytes(c for c in range(256) if not (32 <= c < 127 or c in (9, 10, 13)))
_GLYPHS = {
    "space": " ", "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
    "seven": "7", "eight": "8", "nine": "9", "period": ".", "comma": ",", "hyphen": "-", "minus": "-",
    "underscore": "_", "braceleft": "{", "braceright": "}", "bracketleft": "[", "bracketright": "]",
    "parenleft": "(", "parenright": ")", "slash": "/", "backslash": "\\", "colon": ":", "semicolon": ";",
    "equal": "=", "plus": "+", "asterisk": "*", "exclam": "!", "question": "?", "at": "@",
    "numbersign": "#", "dollar": "$", "percent": "%", "ampersand": "&", "quotesingle": "'",
    "quotedbl": '"', "less": "<", "greater": ">", "bar": "|", "asciitilde": "~", "asciicircum": "^",
    "grave": "`", "quoteright": "’", "quoteleft": "‘",
}


class OpenerError(RuntimeError):
    """The opener or its crypto hook cannot run, with the reason (a module that does not import, no
    flag format, no AES)."""


class _Budget(Exception):
    pass


def _maldoc():
    """maldoc's PDF object reader (the value parser, the filter decoder, the string decoder)."""
    try:
        import maldoc
    except Exception as e:  # noqa: BLE001 - whatever stops the import, the opener has no object reader
        raise OpenerError(f"solvers/toolkits/maldoc.py did not import ({type(e).__name__}: {e}); "
                          "the PDF opener reads objects with it") from e
    return maldoc


def _common(name: str):
    """solvers/common/<name>.py, loaded by path: solvers/toolkits has a module of the same name
    (the question side), and which one a bare import finds depends on sys.path. The aliases are the
    ones those toolkit modules use, so the library is loaded once."""
    alias = {"malconfig": "malconfig_readers", "modern_crypto": "modern_crypto_lib"}[name]
    if alias in sys.modules:
        return sys.modules[alias]
    try:
        spec = importlib.util.spec_from_file_location(alias, COMMON / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[alias] = mod
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001 - whatever stops the load, the hook has no AES and no ECB check
        sys.modules.pop(alias, None)
        raise OpenerError(f"solvers/common/{name}.py did not load ({type(e).__name__}: {e}); the crypto hook "
                          "decrypts and checks for ECB with it") from e
    return mod


def _ticker(clock, budget):
    limit = clock() + budget

    def tick(stage):
        if clock() > limit:
            raise _Budget(f"cpu budget of {budget:g} s spent while {stage}")
    return tick


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _mul(m, n):
    """The matrix that applies m, then n."""
    return (m[0] * n[0] + m[1] * n[2], m[0] * n[1] + m[1] * n[3],
            m[2] * n[0] + m[3] * n[2], m[2] * n[1] + m[3] * n[3],
            m[4] * n[0] + m[5] * n[2] + n[4], m[4] * n[1] + m[5] * n[3] + n[5])


def _pt(m, x, y):
    return (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])


def _bbox(points):
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    return (min(xs), min(ys), max(xs), max(ys))


def _unit_square(ctm):
    return _bbox([_pt(ctm, x, y) for x in (0.0, 1.0) for y in (0.0, 1.0)])


def _loose_indirect(blob: bytes, off: int, num: int):
    """`N G obj << ... >> stream ... endstream` where the declared /Length is wrong: the stream is
    taken to end at the first `endstream`. Only for the opener, which says so in its notes."""
    m = re.compile(rb"\b%d\s+\d+\s+obj\b" % num).search(blob, max(0, off - 8), min(len(blob), off + 64))
    if not m:
        return None
    start = _WS.match(blob, m.end()).end()
    dictionary = _balanced_dict(blob, start) if blob[start:start + 2] == b"<<" else None
    sm = _STREAM_KW.match(blob, start + len(dictionary)) if dictionary else None
    e = blob.find(b"endstream", sm.end()) if sm else -1
    return blob[m.start():e + len(b"endstream")] if e >= 0 else None


class _Doc:
    """One revision's objects: its byte slice and merged cross-reference table. A value is
    (object, raw stream bytes or None); an object that does not read is (None, None) and a note."""

    def __init__(self, sl: bytes, table: dict):
        self.sl, self.table = sl, table
        self.md = _maldoc()
        self.notes = []
        self._objs, self._members = {}, {}

    def note(self, text: str) -> None:
        if text not in self.notes and len(self.notes) < 100:
            self.notes.append(text)

    def at(self, off: int, num: int):
        """The object written at byte `off`, whatever the table says of `num` now."""
        raw, loose = _read_indirect(self.sl, off, num, self.table), False
        if raw is None:
            raw, loose = _loose_indirect(self.sl, off, num), True
            if raw is None:
                return (None, None)
        try:
            val, end = self.md._pdf_value(raw, _OBJ.match(raw).end())
        except (ValueError, IndexError, RecursionError):
            self.note(f"object {num}: its value does not parse")
            return (None, None)
        sm = _STREAM_KW.match(raw, end) if isinstance(val, dict) else None
        if not sm:
            return (val, None)
        s0, e0 = sm.end(), raw.rfind(b"endstream")
        if e0 < s0:
            return (val, None)
        length = self.get(val.get("Length"))
        if not loose and _is_num(length) and 0 <= length <= e0 - s0:
            return (val, raw[s0:s0 + int(length)])
        body = raw[s0:e0]
        body = body[:-2] if body.endswith(b"\r\n") else body[:-1] if body[-1:] in (b"\r", b"\n") else body
        if loose:
            self.note(f"object {num}: /Length does not fit the stream; read up to endstream")
        return (val, body)

    def obj(self, num):
        if num in self._objs:
            return self._objs[num]
        self._objs[num] = (None, None)        # a reference cycle (through /Length, an object stream) is absent
        ent, out = self.table.get(num), (None, None)
        if ent and ent[2] == "n":
            out = self.at(ent[0], num)
        elif ent and ent[2] == "c":
            out = (self._member(ent[0], num), None)
        self._objs[num] = out
        return out

    def _member(self, stm: int, num: int):
        """Object `num` out of object stream `stm` (PDF 1.5 compressed objects)."""
        if stm not in self._members:
            members = self._members[stm] = {}
            d = self.obj(stm)[0]
            body = self.decoded(stm)
            n, first = (self.get(d.get("N")), self.get(d.get("First"))) if isinstance(d, dict) else (None, None)
            if body is None or not _is_num(n) or not _is_num(first) or not 0 <= first <= len(body) \
                    or not 0 <= n <= MAX_OBJECTS:
                self.note(f"object stream {stm}: not readable, so the objects in it are missing")
            else:
                head = body[:int(first)].split()[:2 * int(n)]
                for k in range(0, len(head) - 1, 2):
                    try:
                        members[int(head[k])] = self.md._pdf_value(body, int(first) + int(head[k + 1]))[0]
                    except (ValueError, IndexError, RecursionError):
                        self.note(f"object stream {stm}: an object in it does not parse")
        return self._members[stm].get(num)

    def get(self, v, hops: int = 0):
        """`v` with indirect references followed; None when one leads nowhere."""
        while isinstance(v, self.md.PdfRef) and hops < 16:
            v, hops = self.obj(v[0])[0], hops + 1
        return None if isinstance(v, self.md.PdfRef) else v

    def filters(self, d: dict) -> list:
        f = self.get(d.get("Filter"))
        return [str(self.get(x)) for x in (f if isinstance(f, list) else [] if f is None else [f])]

    def decode(self, d: dict, raw: bytes):
        """A stream through its filters: (bytes, fully decoded?). An image codec is left encoded."""
        parms = self.get(d.get("DecodeParms", d.get("DP")))
        parms = self.get(parms[0]) if isinstance(parms, list) and parms else parms
        body, ok = self.md._pdf_decode({"Filter": self.filters(d)}, raw)
        predictor = self.get(parms.get("Predictor")) if isinstance(parms, dict) else None
        if ok and _is_num(predictor) and predictor >= 10:
            cols = self.get(parms.get("Columns", 1))
            plain = _png_unpredict(body, int(cols)) if _is_num(cols) else body
            if plain is body:                  # _png_unpredict hands its input back when it gives up
                return body, False
            body = plain
        elif ok and _is_num(predictor) and predictor > 1:
            return body, False                 # the TIFF predictor is not undone
        return body, ok

    def decoded(self, num: int):
        """Object `num`'s stream fully decoded, or None (no stream, a filter not undone)."""
        d, raw = self.obj(num)
        if not isinstance(d, dict) or raw is None:
            return None
        body, ok = self.decode(d, raw)
        if not ok:
            self.note(f"object {num}: stream not decoded (filters: {', '.join(self.filters(d)) or 'none'})")
            return None
        return body


# ---- fonts: the bytes of a shown string -> text

def _u16(b: bytes) -> str:
    return chr(b[0]) if len(b) == 1 else b.decode("utf-16-be", "replace")


def _tounicode(md, body: bytes):
    """A ToUnicode CMap: ({code bytes: text}, the code widths, longest first)."""
    cmap, widths = {}, set()

    def values(chunk):
        out, i = [], 0
        while True:
            try:
                v, i = md._pdf_value(chunk, i)
            except (ValueError, IndexError, RecursionError):
                return out
            out.append(v)

    for m in re.finditer(rb"begincodespacerange(.*?)endcodespacerange", body, re.S):
        widths.update(len(v) for v in values(m.group(1)) if isinstance(v, bytes))
    for m in re.finditer(rb"beginbfchar(.*?)endbfchar", body, re.S):
        vals = values(m.group(1))
        for k in range(0, len(vals) - 1, 2):
            if isinstance(vals[k], bytes) and vals[k] and isinstance(vals[k + 1], bytes) and vals[k + 1]:
                cmap[vals[k]] = _u16(vals[k + 1])
    for m in re.finditer(rb"beginbfrange(.*?)endbfrange", body, re.S):
        vals = values(m.group(1))
        for k in range(0, len(vals) - 2, 3):
            lo, hi, dst = vals[k:k + 3]
            if not (isinstance(lo, bytes) and isinstance(hi, bytes) and lo and len(lo) == len(hi)):
                continue
            a, b = int.from_bytes(lo, "big"), int.from_bytes(hi, "big")
            if not 0 <= b - a <= 0xFFFF or len(cmap) > MAX_CMAP:
                continue
            for j in range(b - a + 1):
                code = (a + j).to_bytes(len(lo), "big")
                if isinstance(dst, list):
                    if j < len(dst) and isinstance(dst[j], bytes) and dst[j]:
                        cmap[code] = _u16(dst[j])
                elif isinstance(dst, bytes) and dst:
                    last = int.from_bytes(dst, "big") + j
                    if last < 1 << (8 * len(dst)):
                        cmap[code] = _u16(last.to_bytes(len(dst), "big"))
    widths.update(len(k) for k in cmap)
    return cmap, tuple(sorted((w for w in widths if 1 <= w <= 4), reverse=True))


def _glyph(name: str) -> str:
    if len(name) == 1:
        return name
    if name in _GLYPHS:
        return _GLYPHS[name]
    m = re.fullmatch(r"uni([0-9A-Fa-f]{4})", name) or re.fullmatch(r"u([0-9A-Fa-f]{4,6})", name)
    if m and int(m.group(1), 16) < 0x110000:
        return chr(int(m.group(1), 16))
    return "�"


class _Font:
    """How one font's string bytes read as text: its ToUnicode map first; a simple font's /Encoding
    and /Differences otherwise; a composite font with no ToUnicode map is not readable."""

    def __init__(self, doc: _Doc, d: dict, used: set):
        self.cmap, self.widths, self.diff = {}, (1,), {}
        self.composite = doc.get(d.get("Subtype")) == "Type0"
        tu = d.get("ToUnicode")
        if isinstance(tu, doc.md.PdfRef):
            used.add(tu[0])
            body = doc.decoded(tu[0])
            if body is not None:
                self.cmap, widths = _tounicode(doc.md, body)
                self.widths = widths or ((2,) if self.composite else (1,))
        enc = doc.get(d.get("Encoding"))
        base = doc.get(enc.get("BaseEncoding")) if isinstance(enc, dict) else enc
        self.codec = {"WinAnsiEncoding": "cp1252", "MacRomanEncoding": "mac_roman"}.get(str(base), "latin-1")
        code = None
        for v in (doc.get(enc.get("Differences")) if isinstance(enc, dict) else None) or []:
            if _is_num(v):
                code = int(v)
            elif isinstance(v, doc.md.PdfName) and code is not None:
                self.diff[code] = _glyph(str(v))
                code += 1
        self.readable = bool(self.cmap) or not self.composite

    def _byte(self, b: int) -> str:
        return self.diff[b] if b in self.diff else bytes([b]).decode(self.codec, "replace")

    def decode(self, s: bytes) -> str:
        if not self.cmap:
            return "�" * max(1, len(s) // 2) if self.composite else "".join(self._byte(b) for b in s)
        out, i = [], 0
        while i < len(s):
            for w in self.widths:
                if s[i:i + w] in self.cmap:
                    out.append(self.cmap[s[i:i + w]])
                    i += w
                    break
            else:
                w = self.widths[-1]
                out.append(self._byte(s[i]) if w == 1 and not self.composite else "�")
                i += w
        return "".join(out)


# ---- content streams: what is shown and what is painted, in paint order

def _colour(nums):
    """An RGB triple for 1 (gray), 3 (RGB) or 4 (CMYK) numeric operands; None for anything else
    (a pattern, a colour space this reader does not know)."""
    if not nums or not all(_is_num(v) for v in nums):
        return None
    if len(nums) == 1:
        return (float(nums[0]),) * 3
    if len(nums) == 3:
        return tuple(float(v) for v in nums)
    if len(nums) == 4:
        c, m, y, k = (float(v) for v in nums)
        return ((1 - c) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    return None


def _same_colour(a, b) -> bool:
    return a is not None and b is not None and all(abs(x - y) <= 0.02 for x, y in zip(a, b))


def _operations(md, buf: bytes, tick):
    """(operator, operands) for every operator of a content stream, in order. An inline image's
    data (ID ... EI) is stepped over."""
    i, n, operands, count = 0, len(buf), [], 0
    while True:
        i = md._pdf_skip(buf, i)
        if i >= n:
            return
        count += 1
        if not count % 256:
            tick("reading a content stream")
        if buf[i] in b"/([<+-.0123456789":
            try:
                v, i = md._pdf_value(buf, i)
            except (ValueError, IndexError, RecursionError):
                i += 1                           # a byte that starts no object: step over it
                continue
            operands.append(v)
            del operands[:-64]
            continue
        m = _OPERATOR.match(buf, i)
        if not m:
            i += 1                               # a stray delimiter
            continue
        op, i = m.group().decode("latin-1"), m.end()
        if op in ("true", "false", "null"):
            operands.append({"true": True, "false": False, "null": None}[op])
            continue
        if op == "ID":
            e = _INLINE_END.search(buf, i)
            i = e.end() if e else n
        yield op, operands
        operands = []


class _Canvas:
    """One page as the opener sees it: text runs and painted regions, each with its paint order."""

    def __init__(self, doc: _Doc, tick, fonts: dict, used: set, names: dict):
        self.doc, self.tick, self.fonts, self.used, self.names = doc, tick, fonts, used, names
        self.runs, self.regions, self.seq = [], [], 0

    def font(self, table, name):
        """The font a page's /Font resources name; for a stream with no resources of its own, the
        first font any page gave that name."""
        ref = table.get(str(name)) if isinstance(table, dict) else None
        d = self.doc.get(ref)
        if not isinstance(d, dict):
            return self.names.get(str(name))
        key = ref[0] if isinstance(ref, self.doc.md.PdfRef) else id(d)
        if key not in self.fonts:
            self.fonts[key] = _Font(self.doc, d, self.used)
        self.names.setdefault(str(name), self.fonts[key])
        return self.fonts[key]

    def paint(self, box, colour, kind: str) -> None:
        self.seq += 1
        if len(self.regions) < MAX_REGIONS:
            self.regions.append((self.seq, box, colour, kind))

    def show(self, run: dict) -> None:
        self.seq += 1
        if len(self.runs) < MAX_RUNS:
            run["seq"] = self.seq
            self.runs.append(run)


def _interpret(canvas: _Canvas, content: bytes, resources, ctm, depth: int = 0, inside=frozenset()):
    """Run a content stream's operators against the canvas. Tracks the transform, the fill and stroke
    colours, the fill opacity and the text state; knows rectangles (`re`, or four straight lines),
    images and form XObjects. Clipping is not tracked."""
    doc, md = canvas.doc, canvas.doc.md
    res = doc.get(resources)
    res = res if isinstance(res, dict) else {}
    fonts, xobjects, gstates = (doc.get(res.get(k)) for k in ("Font", "XObject", "ExtGState"))
    st = {"ctm": ctm, "fill": _BLACK, "stroke": _BLACK, "alpha": 1.0, "font": None, "fname": "", "size": 0.0,
          "lead": 0.0, "mode": 0}
    stack, rects, sub, straight = [], [], [], True
    tm = tlm = _IDENT
    flow = False                 # the pen is where the last shown string left it

    def nums(ops, k):
        vals = ops[-k:]
        if len(vals) != k or not all(_is_num(v) for v in vals):
            raise ValueError("operands")
        return [float(v) for v in vals]

    def close_subpath():
        nonlocal sub, straight
        pts = sub[:-1] if len(sub) == 5 and sub[0] == sub[-1] else sub
        if straight and len(pts) == 4:
            box = _bbox(pts)
            if all(min(abs(p[0] - box[0]), abs(p[0] - box[2])) < 0.01
                   and min(abs(p[1] - box[1]), abs(p[1] - box[3])) < 0.01 for p in pts):
                rects.append(box)                # four straight lines around an upright rectangle
        sub, straight = [], True

    def show(pieces):
        nonlocal tm, flow
        font, size = st["font"], st["size"] or 1.0
        text, raw, adv = [], bytearray(), 0.0
        for p in pieces:
            if isinstance(p, bytes):
                t = font.decode(p) if font is not None else p.decode("latin-1")
                text.append(t)
                raw += p
                adv += len(t) * 0.5 * size       # no glyph widths are read: half an em per character
            elif _is_num(p):
                adv -= p / 1000.0 * size
                if p <= -180 and text and not text[-1].endswith(" "):
                    text.append(" ")             # a kern this wide is a word gap
        shown = "".join(text)
        if shown:
            trm, w = _mul(tm, st["ctm"]), max(adv, 0.0)
            box = _bbox([_pt(trm, x, y) for x in (0.0, w) for y in (-0.2 * size, 0.8 * size)])
            x, y = _pt(trm, 0.0, 0.0)
            canvas.show({"text": shown, "raw": bytes(raw), "x": x, "y": y, "bbox": box, "font": st["fname"],
                         "colour": st["stroke"] if st["mode"] == 1 else st["fill"], "mode": st["mode"],
                         "flow": flow, "readable": font is None or font.readable})
        tm, flow = _mul((1.0, 0.0, 0.0, 1.0, adv, 0.0), tm), True

    def newline(tx, ty):
        nonlocal tm, tlm, flow
        tlm = _mul((1.0, 0.0, 0.0, 1.0, tx, ty), tlm)
        tm, flow = tlm, False

    for op, ops in _operations(md, content, canvas.tick):
        try:
            if op == "q":
                if len(stack) < 256:
                    stack.append(dict(st))
            elif op == "Q":
                st = stack.pop() if stack else st
            elif op == "cm":
                st["ctm"] = _mul(tuple(nums(ops, 6)), st["ctm"])
            elif op == "re":
                x, y, w, h = nums(ops, 4)
                rects.append(_bbox([_pt(st["ctm"], px, py) for px in (x, x + w) for py in (y, y + h)]))
            elif op == "m":
                close_subpath()
                sub.append(_pt(st["ctm"], *nums(ops, 2)))
            elif op == "l":
                sub.append(_pt(st["ctm"], *nums(ops, 2)))
            elif op in ("c", "v", "y"):
                straight = False
            elif op in _FILL_OPS:
                close_subpath()
                opaque = st["alpha"] >= 0.99
                for box in rects:
                    canvas.paint(box, st["fill"] if opaque else None, "rect" if opaque else "tint")
                rects = []
            elif op in ("S", "s", "n"):
                rects, sub, straight = [], [], True
            elif op in ("g", "rg", "k", "sc", "scn"):
                st["fill"] = _colour(ops)
            elif op in ("G", "RG", "K", "SC", "SCN"):
                st["stroke"] = _colour(ops)
            elif op == "cs":
                st["fill"] = _BLACK
            elif op == "CS":
                st["stroke"] = _BLACK
            elif op == "gs":
                g = doc.get(gstates.get(str(ops[-1]))) if isinstance(gstates, dict) else None
                ca = doc.get(g.get("ca")) if isinstance(g, dict) else None
                if _is_num(ca):
                    st["alpha"] = float(ca)
            elif op == "BT":
                tm = tlm = _IDENT
                flow = False
            elif op == "ET":
                flow = False
            elif op == "Tf":
                st["fname"], st["size"] = str(ops[-2]), nums(ops, 1)[0]
                st["font"] = canvas.font(fonts, ops[-2])
            elif op == "TL":
                st["lead"] = nums(ops, 1)[0]
            elif op == "Tr":
                st["mode"] = int(nums(ops, 1)[0])
            elif op == "Td":
                newline(*nums(ops, 2))
            elif op == "TD":
                tx, ty = nums(ops, 2)
                st["lead"] = -ty
                newline(tx, ty)
            elif op == "Tm":
                tm = tlm = tuple(nums(ops, 6))
                flow = False
            elif op == "T*":
                newline(0.0, -st["lead"])
            elif op == "Tj":
                show(ops[-1:])
            elif op == "TJ":
                show(ops[-1] if isinstance(ops[-1], list) else ops[-1:])
            elif op in ("'", '"'):
                newline(0.0, -st["lead"])
                show(ops[-1:])
            elif op == "ID":
                canvas.paint(_unit_square(st["ctm"]), None, "image")
            elif op == "Do":
                ref = xobjects.get(str(ops[-1])) if isinstance(xobjects, dict) else None
                d = doc.get(ref)
                if not isinstance(d, dict) or not isinstance(ref, md.PdfRef):
                    continue
                if doc.get(d.get("Subtype")) != "Form":
                    canvas.paint(_unit_square(st["ctm"]), None, "image")
                    continue
                body = doc.decoded(ref[0]) if ref[0] not in inside and depth < 6 else None
                if body is not None:
                    canvas.used.add(ref[0])
                    mat = doc.get(d.get("Matrix"))
                    mat = tuple(float(v) for v in mat) if isinstance(mat, list) and len(mat) == 6 \
                        and all(_is_num(v) for v in mat) else _IDENT
                    _interpret(canvas, body, d.get("Resources", resources), _mul(mat, st["ctm"]),
                               depth + 1, inside | {ref[0]})
        except (IndexError, TypeError, ValueError, AttributeError):
            continue                             # an operator with the wrong operands does nothing


def _coverage(run: dict, box) -> float:
    """How much of a text run a painted box covers, 0..1: the box must span the run's mid-height and
    be at least half as tall as the run (an underline or a strike-through covers nothing)."""
    bx0, by0, bx1, by1 = run["bbox"]
    rx0, ry0, rx1, ry1 = box
    mid = (by0 + by1) / 2
    if not ry0 - 0.01 <= mid <= ry1 + 0.01 or ry1 - ry0 < 0.5 * (by1 - by0):
        return 0.0
    if bx1 - bx0 <= 0:
        return 1.0 if rx0 - 0.01 <= bx0 <= rx1 + 0.01 else 0.0
    return max(0.0, min(1.0, (min(bx1, rx1) - max(bx0, rx0)) / (bx1 - bx0)))


def _hidden_reasons(run: dict, regions: list, annots: list) -> list:
    """Why a reader of the rendered page would not see this run; [] when nothing hides it.

      invisible-render-mode        text render mode 3 or 7: drawn with no ink
      covered-by-rect / -image     an opaque rectangle or an image is painted over it afterwards
      partly-covered-by-...        the same, over less than half of the run's estimated width
      same-colour-as-rect / -page  drawn in the colour of what lies behind it (a bare page is white)
      under-annotation:<Subtype>   inside an annotation's rectangle (Redact, Square, FreeText, ...)
    """
    reasons, behind = [], None
    if run["mode"] in (3, 7):
        reasons.append("invisible-render-mode")
    for seq, box, colour, kind in regions:
        cover = _coverage(run, box)
        if cover <= 0:
            continue
        if seq < run["seq"]:
            if cover >= 0.5 and (behind is None or seq > behind[0]):
                behind = (seq, colour, kind)
        elif kind != "tint":
            name = ("covered-by-" if cover >= 0.5 else "partly-covered-by-") + kind
            if name not in reasons:
                reasons.append(name)
    reasons = [r for r in reasons if not (r.startswith("partly-") and r[len("partly-"):] in reasons)]
    if run["mode"] not in (3, 7) and _same_colour(behind[1] if behind else _WHITE, run["colour"]):
        reasons.append("same-colour-as-" + (behind[2] if behind else "page"))
    for a in annots:
        name = "under-annotation:" + a["subtype"]
        if a["rect"] and a["subtype"] not in _QUIET_ANNOTS and name not in reasons \
                and _coverage(run, a["rect"]) >= 0.5:
            reasons.append(name)
    return reasons


def _lines(runs: list) -> list:
    """Runs joined into lines: neighbours on one baseline with the same hidden reasons. Strings shown
    back to back join as they are; a run placed by a new position joins after a space."""
    lines = []
    for r in runs:
        height = r["bbox"][3] - r["bbox"][1]
        last = lines[-1] if lines else None
        if last and abs(last["y"] - r["y"]) <= 0.3 * max(height, 1.0) and last["hidden"] == r["hidden"]:
            last["text"] += ("" if r["flow"] else " ") + r["text"]
            last["raw"] += r["raw"]
            last["readable"] = last["readable"] and r["readable"]
            continue
        lines.append({"text": r["text"], "x": round(r["x"], 2), "y": round(r["y"], 2), "font": r["font"],
                      "hidden": r["hidden"], "raw": r["raw"], "readable": r["readable"]})
    for ln in lines:
        if ln.pop("readable"):
            del ln["raw"]                        # the shown bytes stay only where no font map read them
    return lines


# ---- one revision

def _page_list(doc: _Doc, root: int) -> list:
    """(object number, page dict, inherited /Resources) for each page under the catalog, in order."""
    out, seen = [], set()

    def walk(ref, res, depth):
        if not isinstance(ref, doc.md.PdfRef) or ref[0] in seen or depth > 32 or len(out) >= MAX_PAGES:
            return
        seen.add(ref[0])
        node = doc.obj(ref[0])[0]
        if not isinstance(node, dict):
            return
        res = node.get("Resources", res)
        kids = doc.get(node.get("Kids"))
        if isinstance(kids, list) and doc.get(node.get("Type")) != "Page":
            for kid in kids:
                walk(kid, res, depth + 1)
        else:
            out.append((ref[0], node, res))

    catalog = doc.obj(root)[0]
    if isinstance(catalog, dict):
        walk(catalog.get("Pages"), None, 0)
    return out


def _page_content(doc: _Doc, page: dict, used: set) -> bytes:
    """The page's content streams joined in order (one stream, as the format defines)."""
    contents = page.get("Contents")
    if isinstance(contents, doc.md.PdfRef) and doc.obj(contents[0])[1] is not None:
        refs = [contents]
    else:
        refs = doc.get(contents)
    parts = []
    for ref in refs if isinstance(refs, list) else []:
        if isinstance(ref, doc.md.PdfRef):
            used.add(ref[0])
            body = doc.decoded(ref[0])
            if body is not None:
                parts.append(body)
    return b"\n".join(parts)


def _annotations(doc: _Doc, page: dict) -> list:
    out = []
    annots = doc.get(page.get("Annots"))
    for ref in annots if isinstance(annots, list) else []:
        a = doc.get(ref)
        if not isinstance(a, dict) or len(out) >= MAX_FIELDS:
            continue
        rect = doc.get(a.get("Rect"))
        rect = [doc.get(v) for v in rect] if isinstance(rect, list) else []
        box = _bbox([(rect[0], rect[1]), (rect[2], rect[3])]) if len(rect) == 4 and all(map(_is_num, rect)) else None
        item = {"subtype": str(doc.get(a.get("Subtype")) or "?"), "rect": box}
        for key in ("Contents", "T", "Subj", "OverlayText"):
            text = doc.md._pdf_str(doc.get(a.get(key)))
            if text:
                item[key.lower()] = text
        out.append(item)
    return out


_XML_TAG = re.compile(r"<(/?)([A-Za-z_][\w.-]*(?::[\w.-]+)?)((?:\s[^<>]*?)?)(/?)>")
_XML_ATTR = re.compile(r"([A-Za-z_][\w.-]*:[\w.-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def xmp_fields(packet: bytes) -> list:
    """(key, value) for every field of an XMP packet: each element's own text, under the nearest
    element that is not rdf:* (so dc:description/rdf:Alt/rdf:li reads as dc:description), and every
    attribute but the namespace declarations. Read with a tag scanner, not an XML parser: the packet
    is untrusted, and no entity is expanded but the predefined and numeric ones."""
    text = bytes(packet[:MAX_XMP]).decode("utf-8", "replace")
    text = re.sub(r"<!--.*?-->|<\?.*?\?>", "", text, flags=re.S)
    text = re.sub(r"<!\[CDATA\[(.*?)\]\]>", lambda m: html.escape(m.group(1)), text, flags=re.S)
    out, stack, pos = [], [], 0
    for m in _XML_TAG.finditer(text):
        between, pos = text[pos:m.start()].strip(), m.end()
        if between and stack:
            key = next((n for n in reversed(stack) if not n.startswith("rdf:")), stack[-1])
            out.append((key, html.unescape(between)))
        closing, name, attrs, selfclose = m.groups()
        if closing:
            if name in stack:
                while stack.pop() != name:
                    pass
            continue
        for a in _XML_ATTR.finditer(attrs):
            value = a.group(2) if a.group(2) is not None else a.group(3)
            if not a.group(1).startswith("xmlns:") and a.group(1) not in ("xml:lang", "rdf:parseType") \
                    and value.strip():
                out.append((a.group(1), html.unescape(value)))
        if not selfclose:
            stack.append(name)
        if len(out) >= MAX_FIELDS:
            break
    return out


def _add_field(report: dict, source: str, key: str, value: str, raw: bytes, revision, obj) -> None:
    for f in report["metadata"]:
        if (f["source"], f["key"], f["value"]) == (source, key, value):
            if revision not in f["revisions"]:
                f["revisions"].append(revision)
            return
    if len(report["metadata"]) < MAX_FIELDS:
        report["metadata"].append({"source": source, "key": key, "value": value, "revisions": [revision],
                                   "obj": obj, "key_forms": [form for form, _b in key_forms(value, raw)],
                                   "_raw": raw})


def _open_view(report: dict, index, sl: bytes, table: dict, trailer: dict, own: dict, tick, sink, older=()):
    """Read one revision (or the linear scan) into the report. `own` is the part of the table this
    revision wrote; `older` the (number, offset) pairs of objects a scan found replaced."""
    doc = _Doc(sl, table)
    md = doc.md
    view = {"index": index, "pages": []}
    report["revisions"].append(view)
    used, fonts, names = set(), {}, {}
    encrypted = bool(trailer.get("Encrypt"))
    if encrypted and not report["encrypted"]:
        report["encrypted"] = True
        report["notes"].append("the PDF is encrypted (/Encrypt): strings and streams are ciphertext here, so "
                               "page text, Info values and stream blobs are not reported. Decrypt it first "
                               "(the user password is often empty: maldoc.pdf_pypdf(data)['decrypted']), "
                               "then run again")
    root = int(trailer["Root"].split()[0]) if trailer.get("Root") else None
    pages = _page_list(doc, root) if root is not None and not encrypted else []
    if not pages and not encrypted:
        report["notes"].append(f"revision {index}: no page tree read (root: {trailer.get('Root')})")
    for number, (num, page, res) in enumerate(pages, start=1):
        tick("reading pages")
        canvas = _Canvas(doc, tick, fonts, used, names)
        _interpret(canvas, _page_content(doc, page, used), res, _IDENT)
        annots = _annotations(doc, page)
        # Each run is checked against every painted region and annotation (up to MAX_RUNS x
        # MAX_REGIONS), so the budget is looked at once per run. When it runs out here the page's
        # text is still kept, its unchecked runs with no reason, and a note says how many.
        spent = None
        for k, run in enumerate(canvas.runs):
            try:
                tick("checking what hides each text run")
            except _Budget as e:
                spent = e
                for rest in canvas.runs[k:]:
                    rest["hidden"] = []
                report["notes"].append(f"revision {index} page {number}: {len(canvas.runs) - k} of "
                                       f"{len(canvas.runs)} text runs were not checked for what hides "
                                       "them (cpu budget)")
                break
            run["hidden"] = _hidden_reasons(run, canvas.regions, annots)
        view["pages"].append({"page": number, "obj": num, "lines": _lines(canvas.runs),
                              "annotations": [dict(a, rect=list(a["rect"]) if a["rect"] else None) for a in annots]})
        if spent is not None:
            raise spent

    info_num = int(trailer["Info"].split()[0]) if trailer.get("Info") else None
    info = doc.obj(info_num)[0] if info_num is not None and not encrypted else None
    for key, value in (info.items() if isinstance(info, dict) else ()):
        value = doc.get(value)
        text = md._pdf_str(value) if isinstance(value, bytes) else \
            str(value) if isinstance(value, md.PdfName) or _is_num(value) else None
        if text is not None:
            _add_field(report, "info", key, text, value if isinstance(value, bytes) else text.encode(), index, info_num)

    def listed(num, d, raw, replaced=False):
        typ, sub = doc.get(d.get("Type")), doc.get(d.get("Subtype"))
        if typ in ("XRef", "ObjStm"):
            return
        filters = doc.filters(d)
        body, ok = doc.decode(d, raw)
        if typ == "Metadata" or sub == "XML" or (ok and b"<x:xmpmeta" in body[:4096]):
            kind = "xmp"
            for key, value in (xmp_fields(body) if ok else ()):
                _add_field(report, "xmp", key, value, value.encode(), index, num)
        elif num in used and not replaced:
            kind = "page content or font map"
        elif "Length1" in d or typ == "CMap" or sub in ("Type1C", "CIDFontType0C", "OpenType") \
                or (ok and (body[:64].lstrip().startswith(b"/CIDInit") or body[36:40] == b"acsp")):
            kind = "font or colour profile"
        elif sub == "Image":
            kind = "image"
        elif ok and not encrypted and (sub == "Form" or _CONTENT_LOOK.search(body)):
            kind = "content no page uses"
            canvas = _Canvas(doc, tick, fonts, set(), names)
            _interpret(canvas, body, d.get("Resources"), _IDENT)
            for run in canvas.runs:
                run["hidden"] = []
            text = [ln["text"] for ln in _lines(canvas.runs)]
            if text:
                report["orphans"].append({"revision": index, "obj": num, "lines": text})
        else:
            kind = "data"
        if len(report["streams"]) < MAX_FIELDS:
            report["streams"].append({"revision": index, "obj": num, "kind": kind, "filters": filters,
                                      "bytes": len(body), "decoded": ok})
        if kind in ("image", "data") and ok and not encrypted and 16 <= len(body) <= MAX_BLOB \
                and not any(f in _IMAGE_CODECS for f in filters) \
                and report["_blob_bytes"] + len(body) <= MAX_BLOB_TOTAL:
            report["_blob_bytes"] += len(body)
            report["_blobs"].append({"source": f"revision {index} object {num} ({kind} stream)", "data": body,
                                     "kind": kind})
        if sink is not None:
            sink(index, num, kind, body, ok)

    for num in sorted(own):
        tick("listing streams")
        d, raw = doc.obj(num)
        if isinstance(d, dict) and raw is not None:
            listed(num, d, raw)
    for num, off in older:
        tick("listing streams")
        d, raw = doc.at(off, num)
        if isinstance(d, dict) and raw is not None:
            listed(num, d, raw, replaced=True)
    report["notes"] += [f"revision {index}: {note}" for note in doc.notes]


def _trailer_of(sl: bytes, start) -> dict:
    """Root, Info and Encrypt as the newest trailer along the /Prev chain states each."""
    out, seen, cur = {"Root": None, "Info": None, "Encrypt": None}, set(), start
    while cur is not None and cur not in seen and len(seen) < MAX_REVISIONS:
        seen.add(cur)
        parsed = _parse_xref_at(sl, cur)
        if parsed is None:
            break
        for key in out:
            out[key] = out[key] or parsed[1].get(key)
        cur = parsed[1].get("Prev")
    return out


def _scan(data: bytes):
    """Every `N G obj` in the file, read with no cross-reference: ({num: (offset, gen, 'n')} where
    the last one written wins, [(num, offset)] of the ones it replaced, the trailer keys by pattern)."""
    table, older = {}, []
    for m in _OBJ.finditer(data, 0, min(len(data), MAX_SCAN)):
        if len(m.group(1)) > 10 or len(m.group(2)) > 5 or len(table) >= MAX_OBJECTS:
            continue
        num = int(m.group(1))
        if num in table and len(older) < MAX_OBJECTS:
            older.append((num, table[num][0]))
        table[num] = (m.start(), int(m.group(2)), "n")
    trailer = {"Root": None, "Info": None,
               "Encrypt": bool(re.search(rb"/Encrypt\s*(?:\d+\s+\d+\s+R|<<)", data))}
    for key in ("Root", "Info"):
        found = re.findall(rb"/" + key.encode() + rb"\s+(\d{1,10})\s+(\d{1,5})\s+R", data)
        if found:
            trailer[key] = f"{int(found[-1][0])} {int(found[-1][1])} R"
    return table, older, trailer


def open_pdf(data: bytes, *, cpu_budget: float = OPEN_CPU_BUDGET, clock=time.process_time, stream_sink=None) -> dict:
    """Everything the opener reads from a PDF, as one report:

      revisions     [{index, pages: [{page, obj, lines: [{text, x, y, font, hidden: [reason, ...]}],
                    annotations}]}], oldest first; index is the revision number, or "scan" when the
                    final state has no readable cross-reference and its objects were found by a
                    linear scan of the file (the notes say so)
      hidden        the lines something hides (_hidden_reasons names the reasons), with the
                    revisions each is in
      earlier_only  lines an earlier revision shows and the final one does not
      orphans       text in content streams no page uses
      metadata      [{source: info|xmp, key, value, revisions, obj, key_forms}]: every Info and XMP
                    field; key_forms says how the value is 16, 24 or 32 bytes (see key_forms)
      streams       [{revision, obj, kind, filters, bytes, decoded}]: every stream each revision wrote
      notes         what could not be read, and why
      truncated     None, or the stage at which the CPU budget ran out (the rest is what was read)

    A line whose font has no map to text (a composite font without ToUnicode) keeps the shown bytes
    as `raw`. Never raises on a damaged file; OpenerError only when the object reader itself is
    missing. `stream_sink(revision, obj, kind, bytes, decoded)` receives each stream as it is listed."""
    report = {"is_pdf": _is_pdf(data), "encrypted": False, "revisions": [], "hidden": [], "earlier_only": [],
              "orphans": [], "metadata": [], "streams": [], "notes": [], "truncated": None,
              "_blobs": [], "_blob_bytes": 0}
    if not report["is_pdf"]:
        return report
    data = bytes(data)
    _maldoc()
    tick = _ticker(clock, cpu_budget)
    eofs = _eof_offsets(data)
    if len(data) > MAX_SCAN:
        report["notes"].append(f"the file is larger than {MAX_SCAN} bytes: only that much was read")
    try:
        final_read, previous = False, 0
        for index, end in enumerate(eofs, start=1):
            tick("reading revisions")
            sl = data[:end]
            start = _last_startxref(sl)
            table = _walk_chain(sl, start)
            final_read = table is not None
            if table is None:
                report["notes"].append(f"revision {index}: its cross-reference chain does not read")
            else:
                own = {num: e for num, e in table.items() if e[2] == "n" and e[0] >= previous}
                _open_view(report, index, sl, table, _trailer_of(sl, start), own, tick, stream_sink)
                previous = end
        if not final_read:
            table, older, trailer = _scan(data)
            report["notes"].append("the final state has no readable cross-reference: its objects were found "
                                   "by a linear scan of the file (the last `N G obj` of each number wins)")
            _open_view(report, "scan", data, table, trailer, table, tick, stream_sink, older)
    except _Budget as e:
        report["truncated"] = str(e)
    tail = data[eofs[-1]:].strip() if eofs else b""
    if 16 <= len(tail) <= MAX_BLOB:
        report["_blobs"].append({"source": "bytes after the last %%EOF", "data": tail, "kind": "data"})

    views = report["revisions"]
    final = {ln["text"].strip() for p in views[-1]["pages"] for ln in p["lines"]} if views else set()
    seen_hidden, seen_early = {}, set()
    for view in views:
        for page in view["pages"]:
            for ln in page["lines"]:
                key = (page["page"], ln["text"], tuple(ln["hidden"]))
                if ln["hidden"] and key in seen_hidden:
                    seen_hidden[key]["revisions"].append(view["index"])
                elif ln["hidden"]:
                    seen_hidden[key] = {"page": page["page"], "text": ln["text"], "reasons": ln["hidden"],
                                        "revisions": [view["index"]]}
                    report["hidden"].append(seen_hidden[key])
                text = ln["text"].strip()
                if view is not views[-1] and not report["truncated"] and text and text not in final \
                        and text not in seen_early:
                    seen_early.add(text)
                    report["earlier_only"].append({"revision": view["index"], "page": page["page"], "text": text})
    return report


# ---- the metadata-key crypto hook

def _b64(text: str):
    s = "".join(text.split())
    if len(s) < 4 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        return None
    s = s.replace("-", "+").replace("_", "/").rstrip("=")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True) if len(s) % 4 != 1 else None
    except (binascii.Error, ValueError):
        return None


def key_forms(text: str, raw: bytes = b"", sizes=KEY_SIZES) -> list:
    """(form, key bytes) for each way a metadata value is a key of one of `sizes` bytes: `raw` (the
    value's own bytes, as stored or as UTF-8 / Latin-1 text, also with outer blanks removed), `hex`
    (0x, blanks, colons and dashes ignored) and `base64` (standard or URL-safe, padded or not)."""
    out, seen = [], set()

    def add(form, key):
        if len(key) in sizes and key not in seen:
            seen.add(key)
            out.append((form, key))

    stored = [raw] if raw else []
    for codec in ("utf-8", "latin-1"):
        try:
            stored.append(text.encode(codec))
        except UnicodeEncodeError:
            pass
    for b in stored:
        add("raw", b)
        add("raw", b.strip())
    digits = re.sub(r"[\s:-]", "", re.sub(r"^\s*0[xX]", "", text))
    if digits and len(digits) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", digits):
        add("hex", bytes.fromhex(digits))
    decoded = _b64(text)
    if decoded is not None:
        add("base64", decoded)
    return out


def _text_blobs(text: str) -> list:
    """(form, bytes) for each AES-sized blob a piece of text spells: the whole text with its blanks
    removed, and every base64 or hex run inside it, decoded; kept when 16 bytes or more and a multiple
    of 16."""
    out, seen = [], set()
    packed = "".join(text.split())
    for piece in [packed] + _B64_RUN.findall(packed) + _B64_RUN.findall(text):
        forms = [("base64", _b64(piece))]
        if len(piece) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", piece):
            forms.append(("hex", bytes.fromhex(piece)))
        for form, blob in forms:
            if blob and len(blob) % 16 == 0 and blob not in seen:
                seen.add(blob)
                out.append((form, blob))
    return out


def _blob_candidates(report: dict):
    out, seen, pages_seen, spans, cut = [], {}, set(), 0, None

    def add(rank, source, form, blob):
        if blob not in seen:
            seen[blob] = len(out)
            out.append({"source": source, "form": form, "data": blob, "rank": rank})
        elif rank < out[seen[blob]]["rank"]:     # met again where it is likelier: hidden beats shown
            out[seen[blob]].update(source=source, form=form, rank=rank)

    def text(rank, source, value):
        for form, blob in _text_blobs(value):
            add(rank, source, form, blob)

    for view in report["revisions"]:
        for page in view["pages"]:
            lines, where = page["lines"], f"revision {view['index']} page {page['page']}"
            same = tuple((ln["text"], bool(ln["hidden"])) for ln in lines)
            if same not in pages_seen:           # a page a later revision left alone is read once
                pages_seen.add(same)
                for a in range(len(lines)):
                    for b in range(a, min(len(lines), a + 16)):
                        if spans >= MAX_SPANS:
                            cut = f"only the first {MAX_SPANS} runs of text lines were looked at for blobs"
                            break
                        spans += 1
                        span = lines[a:b + 1]
                        hidden = all(ln["hidden"] for ln in span)
                        label = f"{where} {'hidden ' if hidden else ''}text, line{'s' if b > a else ''} " \
                                f"{a + 1}{'-' + str(b + 1) if b > a else ''}"
                        text(0 if hidden else 2, label, "\n".join(ln["text"] for ln in span))
            for a in page["annotations"]:
                for key in ("contents", "overlaytext"):
                    if a.get(key):
                        text(3, f"{where} annotation {a['subtype']} {key}", a[key])
    for item in report["earlier_only"]:
        text(1, f"revision {item['revision']} page {item['page']} text (gone from the final revision)", item["text"])
    for item in report["orphans"]:
        text(1, f"revision {item['revision']} object {item['obj']} (content no page uses)", "\n".join(item["lines"]))
    for f in report["metadata"]:
        text(3, f"{f['source']}:{f['key']}", f["value"])
    for item in report["_blobs"]:
        if item["kind"] == "data" and len(item["data"]) <= 65536:
            text(4, item["source"], item["data"].decode("latin-1"))
        if item["kind"] == "data" and len(item["data"]) % 16 == 0:
            add(4, item["source"], "raw", item["data"])
    out.sort(key=lambda c: c["rank"])
    if len(out) > MAX_BLOBS:
        cut = f"only the {MAX_BLOBS} likeliest of {len(out)} blobs were tried"
    return out[:MAX_BLOBS], cut


def blob_candidates(report: dict) -> list:
    """[{source, form, data, rank}]: the ciphertext candidates of an open_pdf report, likeliest first:
    hidden text (rank 0), text only an earlier revision or an unused stream holds (1), page text (2),
    metadata values and annotation text (3), data streams and bytes after the last %%EOF (4). Text is
    taken line by line and as runs of up to 16 neighbouring lines, so a blob wrapped over several
    lines is found whole; every candidate is 16 bytes or more and a multiple of 16."""
    return _blob_candidates(report)[0]


def _rich_repeats(blob: bytes) -> int:
    """16-byte blocks that repeat an earlier one and look like cipher output (ten or more distinct
    byte values): a flat bitmap repeats its blocks too, but with few values in each."""
    seen, repeats = set(), 0
    for i in range(0, len(blob) - len(blob) % 16, 16):
        block = blob[i:i + 16]
        if block in seen:
            repeats += len(set(block)) >= 10
        seen.add(block)
    return repeats


def _flag_finder(flag_format):
    """(find(bytes) -> [flag, ...], strict) for a ctf.flagfmt.FlagFormat, a regex (source or compiled)
    or None (the active event's format). `strict` is False when the format has no known prefix: a
    match alone then proves little, and the caller asks for more."""
    if flag_format is None:
        try:
            from ctf import flagfmt
        except ModuleNotFoundError:              # run as a plain script: the checkout root on sys.path
            sys.path.append(str(HERE.parent.parent))
            from ctf import flagfmt
        try:
            flag_format = flagfmt.current()
        except ValueError as e:                  # ctf.event.EventError
            raise OpenerError(f"no flag format to accept a plaintext with ({e}); set CTF_EVENT or pass "
                              "--flag-regex") from e
    if hasattr(flag_format, "find_flags"):
        def find(plain):
            found = list(flag_format.find_flags(plain))
            if getattr(flag_format, "proof_regex", None) is not None:
                found += [p for p in flag_format.find_proofs(plain) if p not in found]
            return found
        return find, bool(getattr(flag_format, "known", True))
    source = getattr(flag_format, "pattern", flag_format)
    rx = re.compile(source.encode("latin-1") if isinstance(source, str) else source,
                    getattr(flag_format, "flags", 0) & (re.I | re.S | re.M | re.X))
    return (lambda plain: [m.group(0).decode("latin-1") for m in rx.finditer(plain)]), True


def _printable(b: bytes) -> float:
    return len(b.translate(None, _UNPRINTABLE)) / len(b) if b else 0.0


def metadata_key_crypto(report: dict, flag_format=None, *, cpu_budget: float = CRYPTO_CPU_BUDGET,
                        max_trials: int = MAX_TRIALS, clock=time.process_time) -> dict:
    """Try every key-sized metadata value of an open_pdf report as an AES key on every blob found in
    the PDF: AES-ECB, and AES-CBC with the blob's first block, zeros, the key's first 16 bytes or
    another 16-byte metadata value as the IV. A plaintext is accepted only when the flag format
    matches in it (and, for a format with no known prefix, when it is also PKCS#7-padded or printable).
    Under CBC an IV is named only when the flag lies in the first block and so proves it; a flag past
    the first block is reported with the IV not determined and that block left out of the plaintext.

    `flag_format`: a ctf.flagfmt.FlagFormat, a regex, or None for the active event's format.
    Returns {status, reason, keys, blobs, trials, hits, ecb_suspects, truncated}. status: `hit`;
    `no-hit` (tried, nothing matched); `nothing-to-try` (no key-sized value, or no AES-sized blob:
    `reason` says which). hits: [{mode, key_field, key_form, key_hex, blob_source, blob_form,
    blob_bytes, iv, padding_ok, flags, plaintext}], one per key, mode and set of flags (the padded
    plaintext, then the likelier blob, then the longer one). ecb_suspects: the blobs and image streams with repeated cipher-like 16-byte blocks
    (modern_crypto.ecb_duplicates), key or no key; they are tried first. `truncated` names the limit
    that stopped the trials early. Raises OpenerError, with the reason, when there is something to
    try and no flag format or no AES implementation to try it with."""
    out = {"status": "nothing-to-try", "reason": None, "keys": [], "blobs": 0, "trials": 0, "hits": [],
           "ecb_suspects": [], "truncated": None}
    malconfig, modern_crypto = _common("malconfig"), _common("modern_crypto")

    keys, ivs, seen = [], [], set()
    for f in report["metadata"]:
        for form, key in key_forms(f["value"], f.get("_raw", b"")):
            if key not in seen and len(keys) < MAX_KEYS:
                seen.add(key)
                keys.append({"field": f"{f['source']}:{f['key']}", "form": form, "key": key})
                if len(key) == 16:
                    ivs.append((f"{f['source']}:{f['key']} ({form})", key))
    blobs, cut = _blob_candidates(report)
    for item in blobs + [b for b in report["_blobs"] if not any(c["data"] is b["data"] for c in blobs)]:
        dup = modern_crypto.ecb_duplicates(item["data"])
        rich = _rich_repeats(item["data"]) if dup["repeats"] else 0
        if rich and len(out["ecb_suspects"]) < 50:
            out["ecb_suspects"].append({"source": item["source"], "bytes": len(item["data"]),
                                        "blocks": dup["blocks"], "repeats": rich})
            if "rank" not in item:               # an image or unaligned stream: tried because its blocks repeat
                blobs.append({"source": item["source"], "form": "raw", "data": item["data"], "rank": 4})
    suspects = {s["source"] for s in out["ecb_suspects"]}
    blobs.sort(key=lambda c: (c["rank"], c["source"] not in suspects))
    out["keys"] = [{"field": k["field"], "form": k["form"], "bits": 8 * len(k["key"])} for k in keys]
    out["blobs"] = len(blobs)
    if not keys or not blobs:
        out["truncated"] = cut
        out["reason"] ="no metadata value is 16, 24 or 32 bytes (raw, hex or base64)" if not keys else \
            "no blob in the PDF is 16 bytes or more and a multiple of 16 (text as base64 or hex, data streams)"
        return out
    if malconfig.AES is None:
        raise OpenerError("no AES implementation: pycryptodome is not installed in this interpreter "
                          "(requirements.in pins it)")
    find, strict = _flag_finder(flag_format)
    limit = clock() + cpu_budget
    out["status"] = "no-hit"

    def accepted(plain):
        """(flags, PKCS#7 padded?) of a plaintext; no flags unless the format's rule holds."""
        flags, padded = find(plain), malconfig.unpad(plain) is not None
        return (flags if strict or padded or _printable(plain) >= 0.9 else []), padded

    def found(key, blob, mode, iv, plain, flags, padded):
        return {"mode": f"AES-{8 * len(key['key'])}-{mode}", "key_field": key["field"], "key_form": key["form"],
                "key_hex": key["key"].hex(), "blob_source": blob["source"], "blob_form": blob["form"],
                "blob_bytes": len(blob["data"]), "iv": iv, "padding_ok": padded,
                "flags": list(dict.fromkeys(flags)), "_rank": blob["rank"], "_clean": _printable(plain),
                "plaintext": (malconfig.unpad(plain) if padded else plain).decode("utf-8", "replace")[:4000]}

    def keep(new):
        """One hit per mode, key and set of flags: the padded plaintext, then the likelier blob,
        then the longer one."""
        def better(h):
            return (h["padding_ok"], -h["_rank"], h["blob_bytes"])

        for k, old in enumerate(out["hits"]):
            if (old["mode"], old["key_hex"], old["flags"]) == (new["mode"], new["key_hex"], new["flags"]):
                if better(new) > better(old):
                    out["hits"][k] = new
                return
        out["hits"].append(new)

    def finish(stop=None):
        said = [s for s in (cut, f"stopped at {stop} after {out['trials']} AES trials" if stop else None) if s]
        out["truncated"] = "; ".join(said) or None
        out["status"] = "hit" if out["hits"] else "no-hit"
        return out

    for blob in blobs:
        ct = blob["data"][:len(blob["data"]) // 16 * 16]
        for key in keys:
            stop = f"{MAX_HITS} hits" if len(out["hits"]) >= MAX_HITS else \
                f"the trial limit of {max_trials}" if out["trials"] + 2 > max_trials else \
                f"the cpu budget of {cpu_budget:g} s" if clock() > limit else None
            if stop:
                return finish(stop)
            out["trials"] += 2
            plain = malconfig.aes_ecb(key["key"], ct)
            flags, padded = accepted(plain)
            as_ecb = found(key, blob, "ECB", None, plain, flags, padded) if flags else None
            # CBC: the IV only changes the first block, so every IV is read off one decryption. An IV
            # is named only when a flag needs it (the flag lies in the first block); a flag past the
            # first block proves the key and the mode, not the IV, and that block is left out.
            zero, as_cbc = malconfig.aes_cbc(key["key"], bytes(16), ct), None
            rest, padded = accepted(zero[16:]) if len(ct) >= 32 else ([], False)
            for name, iv in [("zero", bytes(16)), ("the key's first 16 bytes", key["key"][:16])] + \
                    [(n, v) for n, v in ivs if v != key["key"][:16]]:
                head = malconfig.xor(zero[:16], iv)
                if any(f not in rest for f in find(head + zero[16:1040])):
                    flags, whole = accepted(head + zero[16:])
                    if flags:
                        as_cbc = found(key, blob, "CBC", name, head + zero[16:], flags, whole)
                        break
            if as_cbc is None and rest:
                as_cbc = found(key, blob, "CBC", "not determined (the first block is left out)", zero[16:], rest,
                               padded)
            # ECB and CBC with a zero IV decrypt a first block alike: when both show the same flags,
            # the mode is the one whose whole plaintext is padded, then the more printable one.
            if as_ecb and as_cbc and as_ecb["flags"] == as_cbc["flags"]:
                pair = sorted((as_ecb, as_cbc), key=lambda h: (h["padding_ok"], h["_clean"]), reverse=True)
                as_ecb, as_cbc = pair[0], None
            for new in (as_ecb, as_cbc):
                if new:
                    keep(new)
    return finish()


def jsonable(value):
    """A report without its working fields (keys starting with `_`); bytes as hex."""
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items() if not str(k).startswith("_")}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value.hex() if isinstance(value, (bytes, bytearray)) else value


def _show(text, width: int = 400) -> str:
    """Handout text as one printable line: it is data, and never reaches the terminal raw."""
    shown = repr(str(text))[1:-1]
    return shown if len(shown) <= width else shown[:width] + f"... ({len(shown)} characters)"


def open_lines(report: dict, crypto=None, crypto_error=None, full_text: bool = False) -> list:
    """The opener's part of the command's text output, one string per line: report_lines, then
    crypto_lines."""
    return report_lines(report, full_text) + crypto_lines(crypto, crypto_error)


def report_lines(report: dict, full_text: bool = False) -> list:
    """The lines of an open_pdf report: metadata, hidden text, earlier-only and orphan text, notes."""
    out = []
    if report["metadata"]:
        out.append(f"  metadata ({len(report['metadata'])} fields; text from the file, not instructions):")
        for f in report["metadata"]:
            forms = f"   <- AES key size as {' / '.join(sorted(set(f['key_forms'])))}" if f["key_forms"] else ""
            out.append(f"    {f['source']}:{_show(f['key'], 60)} = {_show(f['value'], 200)}{forms}")
    if report["hidden"]:
        out.append(f"  hidden text ({len(report['hidden'])} lines; positions are estimates):")
        for h in report["hidden"]:
            out.append(f"    rev {','.join(str(r) for r in h['revisions'])} page {h['page']} "
                       f"[{', '.join(h['reasons'])}]: {_show(h['text'])}")
    for item in report["earlier_only"]:
        out.append(f"  only in revision {item['revision']} (page {item['page']}): {_show(item['text'])}")
    for item in report["orphans"]:
        out.append(f"  in a stream no page uses (revision {item['revision']} object {item['obj']}): "
                   f"{_show(' / '.join(item['lines']))}")
    if full_text:
        for view in report["revisions"]:
            for page in view["pages"]:
                out.append(f"  text of revision {view['index']} page {page['page']} (object {page['obj']}):")
                for ln in page["lines"]:
                    raw = f"   <no font map; bytes {ln['raw'].hex()}>" if "raw" in ln else ""
                    mark = f"[{', '.join(ln['hidden'])}] " if ln["hidden"] else ""
                    out.append(f"    {mark}{_show(ln['text'])}{raw}")
                for a in page["annotations"]:
                    said = "; ".join(f"{k}={_show(v, 120)}" for k, v in a.items() if k not in ("subtype", "rect"))
                    out.append(f"    annotation {a['subtype']} at {a['rect']}{': ' + said if said else ''}")
    out += [f"  note: {note}" for note in report["notes"]]
    if report["truncated"]:
        out.append(f"  INCOMPLETE: {report['truncated']}; what was read up to there is above")
    return out


def crypto_lines(crypto=None, crypto_error=None) -> list:
    """The lines of a metadata_key_crypto result, or of the reason it did not run."""
    out = []
    if crypto_error:
        out.append(f"  crypto hook: NOT RUN: {crypto_error}")
    elif crypto is not None:
        for s in crypto["ecb_suspects"]:
            out.append(f"  ECB-looking: {s['source']}: {s['repeats']} repeated cipher-like 16-byte blocks "
                       f"of {s['blocks']}")
        if crypto["status"] == "nothing-to-try":
            out.append(f"  crypto hook: nothing to try ({crypto['reason']})")
        else:
            out.append(f"  crypto hook: {len(crypto['keys'])} key(s) x {crypto['blobs']} blob(s), "
                       f"{crypto['trials']} AES trials: {'HIT' if crypto['hits'] else 'no flag-format match'}")
        if crypto["truncated"]:
            out.append(f"  crypto hook INCOMPLETE: {crypto['truncated']}")
        for h in crypto["hits"]:
            out.append(f"    {h['mode']}, key {h['key_field']} ({h['key_form']}, hex {h['key_hex']})"
                       f"{', iv ' + h['iv'] if h['iv'] else ''}, on {h['blob_source']} "
                       f"({h['blob_form']}, {h['blob_bytes']} bytes), PKCS#7 padding "
                       f"{'valid' if h['padding_ok'] else 'not valid'}")
            out += [f"    flag-format match: {flag}" for flag in h["flags"]]
            out.append(f"    plaintext: {_show(h['plaintext'], 1200)}")
    return out


# ---------------------------------------------------------------------------- selftest + CLI


def _build_incremental_pdf() -> bytes:
    """A 3-revision incremental PDF with classic xref tables, built offset-exact.
    rev1: a page whose content stream says SECRET. rev2: overlays a redaction rectangle.
    rev3: adds a second page."""
    def obj(n, body):
        return b"%d 0 obj\n" % n + body + b"\nendobj\n"

    def xref_table(entries, size, root, prev=None):
        # entries: {num: (offset, gen, type)} for THIS section only; always include a subsection
        lines = []
        for num in sorted(entries):
            o, g, t = entries[num]
            lines.append(b"%010d %05d %s \n" % (o, g, t.encode()))
        # emit each contiguous run as its own subsection
        body = bytearray(b"xref\n")
        nums = sorted(entries)
        i = 0
        while i < len(nums):
            j = i
            while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
                j += 1
            run = nums[i:j + 1]
            body += b"%d %d\n" % (run[0], len(run))
            for num in run:
                o, g, t = entries[num]
                body += b"%010d %05d %s \n" % (o, g, t.encode())
            i = j + 1
        tr = b"trailer\n<< /Size %d /Root %s" % (size, root)
        if prev is not None:
            tr += b" /Prev %d" % prev
        tr += b" >>\n"
        return bytes(body) + tr

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    off = {}

    def add(n, body):
        off[n] = len(out)
        out.extend(obj(n, body))

    def stream(content):                # /Length is the content's own: _read_indirect ends a stream by it
        return b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"

    content1 = stream(b"BT /F1 24 Tf 20 100 Td (SECRET) Tj ET")
    add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>")
    add(4, content1)
    sx1 = len(out)
    out.extend(xref_table({0: (0, 65535, "f"), 1: (off[1], 0, "n"), 2: (off[2], 0, "n"),
                           3: (off[3], 0, "n"), 4: (off[4], 0, "n")}, 5, b"1 0 R"))
    out.extend(b"startxref\n%d\n" % sx1 + b"%%EOF\n")

    # revision 2: a redaction rectangle (obj 5) and a replaced page (obj 3) pointing at both streams
    content5 = stream(b"0 g 10 90 80 24 re f")
    add(5, content5)
    add(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents [4 0 R 5 0 R] >>")
    sx2 = len(out)
    out.extend(xref_table({3: (off[3], 0, "n"), 5: (off[5], 0, "n")}, 6, b"1 0 R", prev=sx1))
    out.extend(b"startxref\n%d\n" % sx2 + b"%%EOF\n")

    # revision 3: a new page (obj 6 + its content obj 7) and a replaced /Pages (obj 2)
    content7 = stream(b"BT /F1 18 Tf 20 100 Td (page two) Tj ET")
    add(6, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 7 0 R >>")
    add(7, content7)
    add(2, b"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>")
    sx3 = len(out)
    out.extend(xref_table({2: (off[2], 0, "n"), 6: (off[6], 0, "n"), 7: (off[7], 0, "n")},
                          8, b"1 0 R", prev=sx2))
    out.extend(b"startxref\n%d\n" % sx3 + b"%%EOF\n")
    return bytes(out)


def _selftest() -> int:
    fails = []

    def check(label, ok):
        print(("ok   " if ok else "FAIL ") + label)
        if not ok:
            fails.append(label)

    pdf = _build_incremental_pdf()
    check("revision_count == 3", revision_count(pdf) == 3)
    check("chain resolves", chain_resolves(pdf) is True)
    revs = revisions(pdf)
    check("three revision records, oldest first", [r["index"] for r in revs] == [1, 2, 3])
    check("each revision slice parses to a valid trailer (Root present)",
          all(r["valid"] and r["root"] == "1 0 R" for r in revs))
    check("each revision slice starts with %PDF and ends at its %%EOF",
          all(reconstruct(pdf, i).startswith(b"%PDF-") and reconstruct(pdf, i).rstrip().endswith(b"%%EOF")
              for i in (1, 2, 3)))

    o4r1 = object_at(pdf, 4, 1)
    check("object_at(text obj 4, revision 1) recovers SECRET", o4r1 is not None and b"SECRET" in o4r1)
    check("object 5 (the redaction) is absent at revision 1", object_at(pdf, 5, 1) is None)
    check("object 5 (the redaction) is present at revision 2", (object_at(pdf, 5, 2) or b"").find(b"re f") >= 0)
    check("object_at(obj 4) is byte-identical at revision 3 (text unchanged, prior state intact)",
          object_at(pdf, 4, 3) == o4r1)
    check("object_at out-of-range revision is None", object_at(pdf, 4, 9) is None and object_at(pdf, 4, 0) is None)

    opened = open_pdf(pdf)
    check("opener: SECRET is plain text in revision 1 and under the rectangle from revision 2 on",
          [ln["hidden"] for ln in opened["revisions"][0]["pages"][0]["lines"]] == [[]]
          and [(h["text"], h["reasons"], h["revisions"]) for h in opened["hidden"]]
          == [("SECRET", ["covered-by-rect"], [2, 3])])

    one = _build_incremental_pdf()
    one = one[:one.find(b"%%EOF") + len(b"%%EOF") + 1]  # truncate to the first revision only
    check("a file with one %%EOF -> revision_count == 1", revision_count(one) == 1)

    # a truncated /Prev chain -> None, no crash: corrupt the last trailer's /Prev target
    broken = bytearray(pdf)
    last_prev = broken.rfind(b"/Prev ")
    m = re.compile(rb"/Prev (\d+)").search(bytes(broken), last_prev)
    broken[m.start(1):m.end(1)] = b"9" * (m.end(1) - m.start(1))   # point /Prev into the void
    broken = bytes(broken)
    check("truncated /Prev chain -> object_at None, no crash", object_at(broken, 4, 3) is None)
    check("truncated /Prev chain -> chain_resolves False", chain_resolves(broken) is False)
    check("truncated /Prev chain -> revision_count still structural, no crash", revision_count(broken) == 3)

    check("garbage bytes -> empty / None, no crash",
          revisions(b"not a pdf at all") == [] and revision_count(b"x") == 0 and object_at(b"x", 1, 1) is None)
    check("bounded: a storm of %%EOF markers is capped at MAX_REVISIONS",
          revision_count(b"%PDF-1.4\n" + _EOF * (MAX_REVISIONS + 500)) <= MAX_REVISIONS)

    print(("FAILED: " + ", ".join(fails)) if fails else "selftest OK")
    return 1 if fails else 0


def main(argv) -> int:
    if "--selftest" in argv:
        return _selftest()
    usage = ("usage: pdf_revisions.py <file.pdf>... [--json] [--extract DIR] [--text] [--streams DIR] "
             "[--flag-regex RX] [--open-budget S] [--crypto-budget S] [--no-open] [--selftest]")
    valued = {"--extract": None, "--streams": None, "--flag-regex": None, "--open-budget": None,
              "--crypto-budget": None}
    switches, paths, i = set(), [], 0
    while i < len(argv):
        arg = argv[i]
        if arg in valued:
            if i + 1 >= len(argv):
                print(f"pdf_revisions.py: {arg} needs a value\n{usage}", file=sys.stderr)
                return 2
            valued[arg], i = argv[i + 1], i + 1
        elif arg in ("--json", "--text", "--no-open"):
            switches.add(arg)
        elif arg.startswith("--"):
            print(f"pdf_revisions.py: unknown option {arg}\n{usage}", file=sys.stderr)
            return 2
        else:
            paths.append(arg)
        i += 1
    if not paths:
        print(usage, file=sys.stderr)
        return 2
    flag_format = None
    if valued["--flag-regex"] is not None:
        try:
            flag_format = re.compile(valued["--flag-regex"].encode("utf-8"))
        except re.error as e:
            print(f"pdf_revisions.py: --flag-regex is not a regular expression ({e})", file=sys.stderr)
            return 2
    budgets = {}                      # CPU seconds of the opener and of the hook (intake passes smaller ones)
    for opt, default in (("--open-budget", OPEN_CPU_BUDGET), ("--crypto-budget", CRYPTO_CPU_BUDGET)):
        try:
            budgets[opt] = default if valued[opt] is None else float(valued[opt])
        except ValueError:
            budgets[opt] = None
        if budgets[opt] is None or not 0 < budgets[opt] < float("inf"):
            print(f"pdf_revisions.py: {opt} takes a positive number of CPU seconds, not {valued[opt]!r}",
                  file=sys.stderr)
            return 2
    extract = Path(valued["--extract"]) if valued["--extract"] else None
    streams = Path(valued["--streams"]) if valued["--streams"] else None
    as_json, status, rows = "--json" in switches, 0, []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"pdf_revisions.py: {p}: {e}", file=sys.stderr)
            continue
        revs = revisions(data)
        row = {"file": p, "is_pdf": _is_pdf(data), "revision_count": revision_count(data),
               "chain_resolves": chain_resolves(data),
               "revisions": [{"index": r["index"], "end_offset": r["end_offset"], "root": r["root"],
                              "size": r["size"], "objects": len(r["objects"]), "prev": r["prev"],
                              "valid": r["valid"]} for r in revs]}
        rows.append(row)
        if extract:
            extract.mkdir(parents=True, exist_ok=True)
            for r in revs:
                sl = reconstruct(data, r["index"])
                if sl is not None:
                    (extract / f"{Path(p).name}.rev{r['index']}.pdf").write_bytes(sl)
        if not as_json:
            print(f"# {row['file']}  pdf={row['is_pdf']}  revisions={row['revision_count']}  "
                  f"chain_resolves={row['chain_resolves']}")
            for r in row["revisions"]:
                print(f"    rev {r['index']}: end={r['end_offset']} root={r['root']} size={r['size']} "
                      f"objects={r['objects']} prev={r['prev']} valid={r['valid']}")
            # flushed: intake kills a run at its wall-clock timeout, and what was printed must survive it
            print("  a count is plain-eligible only when chain_resolves; a revision slice is plain bytes "
                  "the caller may hash; an author-named selection is unsure; a broken chain is None.", flush=True)
        if "--no-open" in switches or not row["is_pdf"]:
            continue

        def sink(index, num, kind, body, decoded, name=Path(p).name):
            streams.mkdir(parents=True, exist_ok=True)
            (streams / f"{name}.rev{index}.obj{num}.{'bin' if decoded else 'undecoded'}").write_bytes(body)

        report = crypto = error = None
        try:
            report = open_pdf(data, stream_sink=sink if streams else None, cpu_budget=budgets["--open-budget"])
            if not as_json:                    # the opener's findings are out before the hook starts
                said = report_lines(report, "--text" in switches)
                if said:
                    print("\n".join(said), flush=True)
            crypto = metadata_key_crypto(report, flag_format, cpu_budget=budgets["--crypto-budget"])
        except OpenerError as e:               # loud: the reason is printed and the exit code is 3
            error, status = str(e), 3
            print(f"pdf_revisions.py: {p}: {error}", file=sys.stderr)
        if as_json:
            row["open"] = jsonable(report) if report is not None else None
            row["crypto"] = jsonable(crypto) if crypto is not None else {"status": "not-run", "reason": error}
        elif report is None:
            print(f"  opener: NOT RUN: {error}", flush=True)
        else:
            said = crypto_lines(crypto, error)
            if said:
                print("\n".join(said), flush=True)
    if as_json:
        print(json.dumps(rows, indent=1))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
