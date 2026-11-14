#!/usr/bin/env python3
"""magic_records.py -- a magic-agnostic XOR+CRC record reader for the Binary lane (B-225).

  .venv/bin/python solvers/binary/magic_records.py SAMPLE [MAGIC]   the CRC-valid records of a sample

The Huntress Binary lane re-shipped the same reader almost every morning: hcfg.py reads the HCFG record,
fields_d31.py the HGAU gauntlet record, d30.py the HGRF capsule graph. All three are the same shape -- a
4-byte magic, then `version u8 | xor key u8 | length u16 | crc32 u32 | payload`, the payload XOR the key
decoding to a CRC-verified UTF-8 JSON object -- differing only in the four magic bytes, the scan direction
(HCFG forward, HGAU/HGRF backward from the member's end) and which JSON member the question names. This
module reads that shape for ANY printable 4-byte magic, both byte orders, both scan directions, over the
whole member, never by a magic someone saw first. Everything it emits is CRC-32-gated: it never guesses.

What it carries that overlay_records.records (B-216) does not: it reads the WHOLE member, not only the
overlay; it scans backward as well as forward; and it carries the field-word -> record-root mapper that the
day modules each hand-wrote (fields_d31's `gauntlet.config.*` -> top-level `config`, d30's `graph.config.*`
-> top-level `config`). overlay_records answers overlay/trailer facts; this answers the record's config.

Public surface:

  records(data, magic=None, *, backward=False, others=False, endian=None) -> [Record]
      every CRC-valid record, by offset. `magic` pins the 4 bytes; None reads every printable 4-byte
      magic that frames one. `backward` walks from the end (as HGAU/HGRF do). `others` also tries the
      post-XOR transforms hcfg.py reads (reversed, utf16le, zlib, gzip, base64), each CRC-gated. `endian`
      pins "<" or ">"; None tries both.
  unique_record(data, magic=None, **kw) -> Record | None
      the one record whose decoded payload is distinct, else None (zero, or two that differ: never a guess).
  resolve(record_json, path, root_word=None) -> (found: bool, value)
      the field-word -> record-root mapper: a dotted/underscored path whose leading token names the record
      root (absent from the JSON, or == root_word) is resolved against the root, and any token that is not a
      direct key is expanded on `_` into a sub-path (so `gauntlet.trace_branch` reads `trace.branch`).
  container_offset(data, magic) -> {form: offset}
      the file offset where the magic's record begins in each stored form (raw, base64 at three alignments,
      hex, utf16le): the generalization of field_catalog's hcfg_offset to any magic, offered as unsure picks.
  stated_magic(text) / stated_path(text) -> bytes|None / str|None
      the magic and the dotted JSON path a question states (generalizes d30's question parsing); MAGIC_TABLE
      maps a stated capsule word to a magic.
  nested_records(data, magic=None, **kw) -> [(how, Record)]
      records found inside the nested containers generic.layers/_children unwraps (zip, base64, zlib, gzip,
      utf-16, hex, ...), each CRC-gated by records(): a container the sample wraps one or more layers deep.
  solve_set(questions, files, ctx) -> {qid: answer}
      a conservative reader: crc32_hex and xor_key_hex plain (stated renderings), config members as unsure
      labels.pick (never a wrong plain), container-offset forms as unsure picks. Compose with
      ctf.lookahead.computed.wrap for the computed tier behind it (CONTRACTS section 35).

Nothing here executes a sample; every read is a struct/bytes read and a CRC check.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import struct
import sys
import zlib
from collections import namedtuple
from pathlib import Path

import overlay_records as _ovr     # B-216 sibling: its decode leaves are reused so there is one copy (CRC core below)

HDR = 12                        # magic[4] + version u8 + key u8 + length u16 + crc u32
LEN_MAX = 1 << 24               # a record length field over this is not read (a 16 MB cap; lane payloads < 1 KB)
TAG = re.compile(rb"[A-Za-z0-9_]{4}")
# overlapping tag starts: a lookahead matches a 4-byte tag at every byte, so a magic at any alignment is
# found (finditer alone skips overlapping matches). Scanned in C, not a per-byte Python loop.
_TAG_START = re.compile(rb"(?=([A-Za-z0-9_]{4}))")
DISCOVER_MAX = 1 << 20          # candidate tag offsets read when no magic is pinned (bounds a big member)
_MAGIC_WORD = re.compile(r"\b([A-Z][A-Z0-9]{3})\b")     # a 4-char magic stated in a question (HGRF, HGAU, HCFG)
# a dotted JSON path a question states: `graph.config.sleep`, `config.url`, `gauntlet.trace_branch`
_PATH = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\b")

# A stated capsule word -> its magic (d30 named the HGRF graph; the lane's others follow the same rule).
MAGIC_TABLE = {
    "hcfg": b"HCFG", "hgau": b"HGAU", "hgrf": b"HGRF",
}
# 4-char upper-case English/format words a question carries that are NOT record magics, so `JSON` in
# "the decoded HGAU JSON object" is not taken for the magic (HGAU, which stands before it, is).
_MAGIC_STOPWORDS = frozenset({b"JSON", b"TRUE", b"NULL", b"NONE", b"UTF8", b"BYTE", b"FILE", b"HASH"})

Record = namedtuple("Record", "offset magic version key length crc endian decoding plain json")


def _xor(blob: bytes, key: int) -> bytes:
    # overlay_records' cached XOR table (B-216), so the two readers share one copy and cannot drift
    return blob.translate(_ovr._xor_table(key))


def _transforms(xored: bytes, key: int):
    """(decoding, bytes) readings of the de-XORed payload besides the plain one, cheapest first. Each is a
    way hcfg.py reads a payload; the caller keeps one only when its CRC-32 matches, so none is ever a guess."""
    yield "reversed", xored[::-1]
    if len(xored) % 2 == 0:
        try:
            yield "utf16le", xored.decode("utf-16-le").encode("utf-8")
        except UnicodeError:
            pass
    if xored[:1] == b"\x78" or xored[:2] == b"\x1f\x8b":
        got = _ovr._inflate(xored, gz=xored[:2] == b"\x1f\x8b")
        if got is not None:
            yield "zlib", got
    if xored and len(xored) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", xored):
        try:
            dec = base64.b64decode(xored, validate=True)
            if base64.b64encode(dec) == xored:
                yield "base64", dec
        except (binascii.Error, ValueError):
            pass


def _read_at(data: bytes, o: int, magic: bytes, endian: str, others: bool):
    """A CRC-valid Record whose magic starts at `o` under `endian`, or None. The de-XORed payload is the
    reading unless `others` lets a post-transform of it match the CRC instead."""
    if o < 0 or o + HDR > len(data) or data[o:o + 4] != magic:
        return None
    version, key = data[o + 4], data[o + 5]
    length, crc = struct.unpack_from(endian + "HI", data, o + 6)
    if not length or length > LEN_MAX or o + HDR + length > len(data):
        return None
    enc = bytes(data[o + HDR:o + HDR + length])
    xored = _xor(enc, key)
    if zlib.crc32(xored) & 0xFFFFFFFF == crc:
        return Record(o, magic, version, key, length, crc, endian, "xor", xored, _ovr._json_object(xored))
    if others:
        for how, plain in _transforms(xored, key):
            if zlib.crc32(plain) & 0xFFFFFFFF == crc:
                return Record(o, magic, version, key, length, crc, endian, how, plain, _ovr._json_object(plain))
    return None


def _magic_at(data: bytes, o: int) -> bytes | None:
    """The 4 bytes at `o` when they are a printable tag, else None."""
    chunk = data[o:o + 4]
    return bytes(chunk) if len(chunk) == 4 and TAG.fullmatch(chunk) else None


def records(data, magic=None, *, backward=False, others=False, endian=None) -> list:
    """Every CRC-valid record of `data` (see the module docstring), by offset. Little-endian before big at
    one offset; within an endian, by offset ascending, or descending when `backward`."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    if magic is not None:
        magic = bytes(magic)
        if len(magic) != 4:
            raise ValueError("a record magic is 4 bytes")
    endians = (endian,) if endian in ("<", ">") else ("<", ">")

    offsets = []
    if magic is not None:
        o = data.find(magic)
        while o >= 0:
            offsets.append(o)
            o = data.find(magic, o + 1)
    else:
        # any printable 4-byte tag that begins a header whose fixed-size part fits; overlapping starts,
        # bounded so a large member cannot spend the scan on tags that never frame a record
        limit = len(data) - HDR
        for n, m in enumerate(_TAG_START.finditer(data)):
            if n >= DISCOVER_MAX:
                break
            if m.start() <= limit:
                offsets.append(m.start())
    if backward:
        offsets = offsets[::-1]

    out, seen = [], set()
    for o in offsets:
        tag = magic if magic is not None else _magic_at(data, o)
        if tag is None:
            continue
        for e in endians:
            rec = _read_at(data, o, tag, e, others)
            if rec is not None and (rec.offset, rec.endian) not in seen:
                seen.add((rec.offset, rec.endian))
                out.append(rec)
    return out


def unique_record(data, magic=None, **kw):
    """The record whose decoded payload is the single distinct one among every CRC-valid record, or None.
    Two records with the same decoded bytes are one; two that differ, or none, is None (never a guess)."""
    recs = records(data, magic, **kw)
    distinct = {r.plain for r in recs}
    return recs[0] if len(distinct) == 1 and recs else None


# ---------------------------------------------------------------------------- field-word -> record-root

_MISSING = object()


def _descend(obj, token):
    """obj[token], or, when token is not a direct key, obj walked along token.split('_'); _MISSING on a miss."""
    if isinstance(obj, dict):
        if token in obj:
            return obj[token]
        if "_" in token:
            cur = obj
            for part in token.split("_"):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return _MISSING
            return cur
    return _MISSING


def resolve(record_json, path, root_word=None):
    """Resolve a stated field path against a record's JSON, mapping a field word to the record root.

    `path` is dotted (`gauntlet.config.sleep`) or a single token (`config`). Its leading token names the
    record root -- and is dropped -- when it equals `root_word`, or when it is not a key of the root (the
    case fields_d31/d30 hand-wrote: the question says `gauntlet.config.x` but the JSON has no `gauntlet`
    key, only `config`). Every remaining token is a direct key, or, failing that, is expanded on `_` into a
    sub-path (so `trace_branch` reads `trace.branch`). Returns (found, value); (False, None) on any miss."""
    if not isinstance(record_json, dict) or not isinstance(path, str) or not path:
        return False, None
    tokens = path.split(".")
    first = tokens[0]
    if tokens and (first == root_word or (first not in record_json and _descend(record_json, first) is _MISSING)):
        tokens = tokens[1:]
    if not tokens:
        return False, None              # the whole path named only the root word
    obj = record_json
    for tok in tokens:
        obj = _descend(obj, tok)
        if obj is _MISSING:
            return False, None
    return True, obj


# ---------------------------------------------------------------------------- container offset, any magic

def _b64_seeds(magic: bytes):
    """The base64 text the magic's first bytes become at each of the three byte alignments, so the magic is
    found inside a base64 stream however it is aligned (field_catalog's b64_file_offset, any magic)."""
    seeds = {}
    for pad in range(3):
        enc = base64.b64encode(b"\x00" * pad + magic)
        # drop the leading chars the pad bytes produced and the trailing '=' so the seed is the magic's run
        lead = (pad * 8 + 5) // 6
        seeds[pad] = enc[lead:].rstrip(b"=")
    return seeds


def container_offset(data, magic) -> dict:
    """{form: offset} -- where the magic's record begins in `data` in each stored form. `raw` is reported
    only when the magic there frames a CRC-valid record (records()); the encoded forms are reported at the
    first place the magic's encoded run stands (a candidate the opener probes: never judged here, so the
    caller offers each as an unsure labels.pick, the row-177 'container-offset field for every prefix' gap).
    """
    data = bytes(data)
    magic = bytes(magic)
    if len(magic) != 4:
        raise ValueError("a record magic is 4 bytes")
    out = {}
    recs = records(data, magic)
    if recs:
        out["raw"] = recs[0].offset
    # a 4-byte magic (enforced above) always yields base64 seeds of 5-6 chars (test_b64_seeds_lengths),
    # so each alignment's seed is searched unconditionally -- no length guard, which would be dead code.
    for pad, seed in sorted(_b64_seeds(magic).items()):
        at = data.find(seed)
        if at >= 0:
            out.setdefault("base64", at)
    hexseed = magic.hex().encode()
    at = data.find(hexseed)
    if at < 0:
        at = data.find(magic.hex().upper().encode())
    if at >= 0:
        out["hex"] = at
    wide = magic.decode("latin-1").encode("utf-16-le")
    at = data.find(wide)
    if at >= 0:
        out["utf16le"] = at
    return out


# ---------------------------------------------------------------------------- stated magic / path

def stated_magic(text):
    """The record magic a question states: a 4-char upper-case token (HGRF, HGAU), or a MAGIC_TABLE word,
    or None. The first magic word in the text wins (the question names its own record before any aside)."""
    if not isinstance(text, str):
        return None
    for m in _MAGIC_WORD.finditer(text):
        word = m.group(1).encode("ascii")
        if word not in _MAGIC_STOPWORDS:
            return word
    for word, magic in MAGIC_TABLE.items():
        if re.search(rf"\b{word}\b", text, re.I):
            return magic
    return None


def stated_path(text):
    """The dotted JSON path a question states (`...property graph.config.sleep`), or None."""
    if not isinstance(text, str):
        return None
    m = _PATH.search(text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------- nested search (generic._children)

_GENERIC = []


def _generic():
    """This folder's generic.py, loaded by path under the name binary_generic, defensively: a missing or
    broken module leaves nested_records reading the member itself only, with a stderr note, never a silent
    fall-through to nothing. Never `import generic`: by that bare name Python returns whichever generic.py
    was imported first, and solvers/script-analysis has one too (evidence.py keeps the same rule)."""
    if not _GENERIC:
        import importlib.util
        path = Path(__file__).resolve().parent / "generic.py"
        name = "binary_generic"
        mod = sys.modules.get(name)
        if mod is not None and callable(getattr(mod, "layers", None)):
            _GENERIC.append(mod)
            return _GENERIC[0]
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            _GENERIC.append(mod)
        except (Exception, SystemExit) as e:    # noqa: BLE001 -- generic is a large optional dependency
            sys.modules.pop(name, None)
            print(f"[magic_records] generic.py unavailable ({type(e).__name__}: {e}); nested search is the "
                  f"member itself only", file=sys.stderr)
            _GENERIC.append(None)
    return _GENERIC[0]


def nested_records(data, magic=None, **kw) -> list:
    """[(how, Record)] -- the CRC-valid records inside every nested container generic.layers unwraps (a zip
    or jar member, a base64/zlib/gzip/utf-16/hex run, and those nested), plus the member itself (`raw`). The
    CRC-32 gate is records()'s own, so a layer that merely looks like data yields nothing. One (how, offset)
    is reported once."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    gen = _generic()
    try:
        layers = gen.layers(data) if gen is not None else [("raw", data)]
    except Exception as e:          # noqa: BLE001
        print(f"[magic_records] generic.layers raised {type(e).__name__}: {e}; the member itself only",
              file=sys.stderr)
        layers = [("raw", data)]
    out, seen = [], set()
    for how, blob in layers:
        for rec in records(blob, magic, **kw):
            key = (how, rec.offset, rec.endian, rec.plain)
            if key not in seen:
                seen.add(key)
                out.append((how, rec))
    return out


# ---------------------------------------------------------------------------- a conservative reader

def _qid(q):
    return q.get("qid") or q.get("id") or q.get("answer_id") if isinstance(q, dict) else None


def _labels():
    """The Phase-0 unsure-answer contract module (solvers/common/labels.py). It is required, not an
    optional pack: a config member must be offered as an unsure labels.pick, never a possibly-wrong
    plain. A genuine failure to load it raises with a named reason (rule 6: no silent fallback), which
    solve_set turns into a skipped id -- never a wrong answer."""
    common = str(Path(__file__).resolve().parent.parent / "common")
    if common not in sys.path:
        sys.path.append(common)
    try:
        import labels
    except ImportError as e:
        raise RuntimeError(
            f"solvers/common/labels.py (the Phase-0 unsure-answer contract) is unavailable: {e}; "
            f"a config member cannot be offered as an unsure pick") from e
    return labels


def answer_field(field: str, rec, text: str = "", root_word=None):
    """One answer from a record, or None. crc32_hex and xor_key_hex are the stated renderings, PLAIN. A
    config member (or the stated path) is an unsure labels.pick -- never a wrong plain. `field` is the id
    after the prefix/area (`analysis_config_url` -> `config_url`). If the labels contract module cannot
    load, this raises (rule 6): the member is never degraded to a possibly-wrong plain answer."""
    if rec is None:
        return None
    if field.endswith("crc32_hex"):
        return f"0x{rec.crc:08x}"
    if field.endswith("xor_key_hex"):
        return f"0x{rec.key:02x}"
    path = None
    if field.startswith("config_"):
        path = "config." + field[len("config_"):]
    else:
        stated = stated_path(text)
        if stated is not None:
            path = stated
    if path is None:
        return None
    ok, value = resolve(rec.json or {}, path, root_word=root_word)
    if not ok or value is None:
        return None
    rendered = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    labels = _labels()      # raises loudly if the contract module is missing, not a wrong plain
    return labels.pick(f"binary.magic_config/{path}", [("record_member", rendered)])


def solve_set(questions, files, ctx=None) -> dict:
    """{qid: answer} over `files` (name -> bytes). For each prefix the members carry, the one CRC-valid
    record of the magic the question states (or any magic, when none is stated) answers crc32_hex/xor_key_hex
    plain and config members as unsure picks. Never raises on a bad question or member; a reader that raises
    costs only its own id. Wrap with ctf.lookahead.computed.wrap for the computed tier behind it."""
    out = {}
    if not isinstance(files, dict):
        return out
    bodies = [bytes(b) for b in files.values() if isinstance(b, (bytes, bytearray))]
    for q in questions or []:
        qid = _qid(q)
        if not isinstance(qid, str) or "_" not in qid:
            continue
        field = qid.split("_", 1)[1]
        for area in ("analysis_", "artifact_", "structural_"):
            if field.startswith(area):
                field = field[len(area):]
                break
        text = q.get("question") or q.get("text") or "" if isinstance(q, dict) else ""
        magic = stated_magic(text)
        try:
            rec = None
            # the stated magic first, then any printable magic (discovery), so a word mistaken for a magic
            # or a record under a magic no one stated is still read; backward (HGAU/HGRF) before forward.
            for want in (magic, None) if magic is not None else (None,):
                for body in bodies:
                    got = unique_record(body, want, backward=True) or unique_record(body, want)
                    if got is not None and got.json is not None:
                        rec = got
                        break
                if rec is not None:
                    break
            got = answer_field(field, rec, text)
        except Exception as e:      # noqa: BLE001
            print(f"[magic_records] {qid}: reading the record raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if got is not None:
            out[qid] = got
    return out


def _main(argv) -> int:
    if not argv:
        print("usage: magic_records.py SAMPLE [MAGIC]", file=sys.stderr)
        return 2
    data = Path(argv[0]).read_bytes()
    magic = argv[1].encode() if len(argv) > 1 else None
    recs = records(data, magic, backward=True, others=True) or records(data, magic, others=True)
    if not recs:
        print("no CRC-valid record")
        return 0
    for r in recs:
        keys = sorted(r.json)[:8] if r.json else None
        print(f"  @{r.offset} magic={r.magic.decode('latin-1')} v{r.version} key=0x{r.key:02x} "
              f"len={r.length} crc=0x{r.crc:08x} {r.endian} {r.decoding}"
              + (f" json keys={keys}" if keys else ""))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
