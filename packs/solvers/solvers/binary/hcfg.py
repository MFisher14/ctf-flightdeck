#!/usr/bin/env python3
"""HCFG: the config container the lane's samples carry (seen in the C++, .NET, Go and Rust samples).

Usage:
  python3 solvers/binary/hcfg.py <sample> [...]

Layout, little-endian, stored verbatim in the sample's data:

  "HCFG" | version u8 | xor key u8 | length u16 | crc32 u32 | payload[length]

payload XOR key is a UTF-8 JSON object, and crc32 is the zlib CRC-32 of that
decoded JSON. If no container with a valid header is found, fall back to
hunting for a single-byte-XOR JSON object that opens with a "campaign" key.

find() reads that layout and nothing else, which is what the day modules rely
on. containers() lists every container of a file instead of the first, and with
others=True it also reads a payload that is not JSON under the single-byte XOR:

  rolling_up, rolling_down   XOR with key + i, key - i
  add, sub                   key added to, subtracted from each byte
  repeating,                 a repeating key of 2 to 64 bytes, XOR-ed (repeating) or added (repeating_add:
  repeating_add              payload = plain + key; a SUBTRACTED key K is the added key -K, so it reads
                             here too, with key_bytes the negation); one reader (_long_repeating /
                             _long_search): keys of up to 13 bytes are the bytes that turn the payload's
                             start into OPENING (always read), longer ones a budgeted column search seeded
                             from that crib (B-246 folded the old 2..8-byte XOR loop into it)
  reversed, utf16le,         the single-byte XOR as before, over the JSON reversed, as
  zlib, base64               UTF-16LE, zlib- or gzip-compressed, in base64
  rotate_r<R>, deflate_raw,  B-246 (crc_transforms.py): a bit rotation with a key, and raw deflate, bz2,
  bz2, lzma, lz4f, rle_*,    xz/lzma, an LZ4 frame, RLE and PackBits (and `<name>_outer`: compressed
  packbits                   outside the XOR)

and, for the first RC4_HEADERS headers of a file whose payload nothing above opened, beside RC4: the pure-
Python LZ decoders (lzss, lznt1, aplib, raw/sized LZ4), ChaCha20 / Salsa20 under a key and nonce from the
bytes around the record, and PRNG keystreams (LCGs, glibc, java.util.Random, xorshift32, MT19937, Python's
random) under seeds from the header and around the record (crc_transforms.costly_reading).

Such a reading is kept only when the CRC-32 the header stores is that of the
decoded JSON (for UTF-16LE: of the JSON text or of its UTF-16 bytes), so it is
as established as the plain one. Its "how" names it; a gzip payload reads as
"zlib".

With `others`, every CRC-32-validated final payload -- the direct de-XORed bytes or
one of the transformations above -- is also handed to nonjson_hcfg.decode, which
reads a self-describing non-JSON serialisation (CBOR, MessagePack, BSON, key=value
lines, flat XML). Such a hit carries the decoded map under "json", "how" retains
the transformation, and a marker "nonjson" names the serialisation. The CRC is the
proof the bytes are the author's, so the container is as established as a JSON one,
but no non-JSON member spelling has been judged: generic.config_answer offers each
member as an unsure pick, while the XOR key, CRC-32 and version stay plain. See
nonjson_hcfg.py.
"""
import base64
import binascii
import copy
import importlib.util
import json
import itertools
import struct
import sys
import time
import zlib
from pathlib import Path


def _sibling(stem: str):
    """solvers/binary/<stem>.py under a private name: hcfg is also loaded by path (malconfig), with its folder
    off sys.path. A sibling that cannot load is an error here, never a reading silently missing."""
    name = f"_hcfg_{stem}"
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{stem}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod          # registered first: a dataclass looks its module up
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return mod


crc_transforms = _sibling("crc_transforms")     # B-246: the widened CRC-gated transform families

MAGIC = b"HCFG"
PROBE = b'{"campaign"'
OPENING = b'{"campaign":"'   # how every config of the lane has opened so far
INFLATE_LIMIT = 1 << 20      # bytes a compressed payload (64 KB at most) may decode to
OTHER_LIMIT = 64             # headers of one file whose payload is tried the other ways (a sample has had three)
HEADERLESS_LIMIT = 16        # places the probe stands at that headerless() reads (no saved sample has one)
_OPENS = b"{ \t\n\r"         # what a JSON object can start with: its brace, or the white space json.loads skips
_BYTES = bytes(range(256))
# PROBE XOR-ed with any single byte keeps the XOR of each pair of neighbours.
_PROBE_DELTA = bytes(a ^ b for a, b in zip(PROBE, PROBE[1:]))
_XOR = {}


def _xor(blob: bytes, key: int) -> bytes:
    table = _XOR.get(key)
    if table is None:
        table = _XOR[key] = bytes(i ^ key for i in range(256))
    return blob.translate(table)


def _parse(plain: bytes):
    try:
        obj = json.loads(plain.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _object_end(plain: bytes) -> int:
    """Length of the JSON object that starts at plain[0], or 0."""
    depth, in_str, esc = 0, False, False
    for i, c in enumerate(plain):
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:
                esc = True
            elif c == 0x22:
                in_str = False
        elif c == 0x22:
            in_str = True
        elif c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                return i + 1
    return 0


def _xor_stream(blob: bytes, stream: bytes) -> bytes:
    """`blob` XOR-ed with `stream`, repeated to its length."""
    n = len(blob)
    stream = (stream * (n // len(stream) + 1))[:n]
    return (int.from_bytes(blob, "little") ^ int.from_bytes(stream, "little")).to_bytes(n, "little")


# Day 26 coverage build: a repeating-XOR key LONGER than the 2..8 bytes above (a 16-byte Vigenere key). The header is
# cleartext, so the CRC-32 of the decoded JSON is the oracle: the key's first 13 bytes (fewer when it is shorter) come
# from the OPENING crib, every other key column is the key byte that turns that column of the payload into text,
# best English/JSON score first, and a decode is yielded ONLY when its CRC-32 equals the header's AND it parses as a
# JSON object. No CRC match, no reading: nothing here can emit a decode the author did not write.
#
# B-246: this is now the ONE repeating-key reader. The old 2..8-byte XOR loop of _other_readings is folded in: a key
# of REPEAT_MIN..len(OPENING) bytes is fully determined by the crib, so it costs one CRC-32 per length and is read
# for every tried header, outside the budget ("crib" sizes); longer keys are the budgeted search ("long" sizes).
# The same reader takes two combinations of key and payload (REPEAT_OPS): XOR, and add (payload = plain + key), the
# oracle-audit row 4 "multi-byte add/sub": a subtracted key K is the added key -K (mod 256 per byte), the same
# candidates under the same CRC-32, so a "sub" pass would only repeat the add pass (_op_tables still has "sub").
REPEAT_MIN = 2
REPEAT_OPS = ("xor", "add")
LONG_KEY_MIN, LONG_KEY_MAX = 9, 64
LONG_PAYLOAD_MAX = 1 << 14      # payloads of the lane are under 1 KB; a decoder's compare constant claims up to 64 KB
LONG_TIME = 0.3                # seconds one payload may take over every key length (monotonic clock, no signal)
LONG_PER_L, LONG_EVALS = 4000, 30000   # CRC checks per key length, and per payload
LONG_TOP = 4                    # candidate key bytes kept per unknown column
LONG_COSTLY = 0.02             # seconds a search must take to count against LONG_HEADERS
LONG_HEADERS = 4                # payloads per _headers pass that reach the search (as RC4_HEADERS)
LONG_TOTAL, LONG_IDLE = 1.5, 5.0   # seconds all searches together may take; renewed after this many idle seconds
_LONG_STATE = {"spent": 0.0, "last": 0.0, "headers": 0, "skipped": False, "counted": set()}
_LONG_MEMO = {}
DEADLINE = None                 # a runner may set a time.monotonic() value that ends the search sooner
_TEXT = bytes([9, 10, 13] + list(range(32, 127)))
_SCORE = bytearray(256)
for _c in b"abcdefghijklmnopqrstuvwxyz":
    _SCORE[_c] = 3
for _c in b"0123456789":
    _SCORE[_c] = 2
for _c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    _SCORE[_c] = 1
for _c in b'"_-.:/,{}':
    _SCORE[_c] = 1
_SCORE[0x20] = 4
_SCORE = bytes(_SCORE)


_CORPUS = (
    '{"campaign":"BR26-relay","family":"stage","c2_url":"https://updates.example.net/api/v2/beacon","domain":"cdn.example.org",'
    '"mutex":"Global_RelayMutex7","sleep":30,"interval":60,"jitter":10,"version":"1.4.2","user_agent":"Mozilla/5.0 '
    '(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36","note":"the quick '
    'brown fox jumps over the lazy dog and the operator keeps the beacon alive until the stage is ready","port":443,'
    '"proxy":"http://127.0.0.1:8080","path":"/var/lib/service/config.json","name":"service","key":"abcdef0123456789",'
    '"url":"http://localhost/index.html","host":"server01.internal.example.com","id":"deadbeef","token":"none","enabled":true,'
    '"tags":["alpha","bravo","delta","echo"],"stage":"two","payload":"loader","target":"workstation","region":"north"}'
)
_BIGRAM = None


def _bigram():
    """log-probability table [prev * 256 + next] of a small config-text corpus, add-k smoothed over the text
    bytes; every byte outside the text set scores the floor."""
    global _BIGRAM
    if _BIGRAM is None:
        import math
        counts, uni = {}, {}
        raw = _CORPUS.encode()
        for a_, b_ in zip(raw, raw[1:]):
            counts[(a_, b_)] = counts.get((a_, b_), 0) + 1
            uni[a_] = uni.get(a_, 0) + 1
        table = [math.log(1e-6)] * 65536
        for a_ in _TEXT:
            total = uni.get(a_, 0) + 0.2 * len(_TEXT)
            for b_ in _TEXT:
                table[a_ * 256 + b_] = math.log((counts.get((a_, b_), 0) + 0.2) / total)
        _BIGRAM = table
    return _BIGRAM


_OP_TABLES = {}


def _op_tables(op: str):
    """[k] -> the 256-byte table that turns a payload byte into its plain byte under key byte k for `op`: XOR,
    add (payload = plain + k, so plain = payload - k) or sub (payload = plain - k)."""
    t = _OP_TABLES.get(op)
    if t is None:
        if op == "xor":
            t = [bytes(i ^ k for i in range(256)) for k in range(256)]
        elif op == "add":
            t = [bytes((i - k) & 0xFF for i in range(256)) for k in range(256)]
        elif op == "sub":
            t = [bytes((i + k) & 0xFF for i in range(256)) for k in range(256)]
        else:
            raise ValueError(f"no repeating-key combination {op!r}")
        _OP_TABLES[op] = t
    return t


def _crib_key(enc: bytes, size: int, op: str) -> dict:
    """{column: key byte} that the OPENING crib fixes for a key of `size` bytes under `op`."""
    m = min(size, len(OPENING))
    if op == "xor":
        return {j: enc[j] ^ OPENING[j] for j in range(m)}
    if op == "add":
        return {j: (enc[j] - OPENING[j]) & 0xFF for j in range(m)}
    return {j: (OPENING[j] - enc[j]) & 0xFF for j in range(m)}


def _repeat_decode(enc: bytes, key: bytes, op: str) -> bytes:
    """`enc` under the repeating `key` combined by `op`."""
    if op == "xor":
        return _xor_stream(enc, key)
    tables = _op_tables(op)
    out = bytearray(len(enc))
    size = len(key)
    for j, k in enumerate(key):
        out[j::size] = enc[j::size].translate(tables[k])
    return bytes(out)


def _icm(enc: bytes, size: int, allowed, fixed, end: float, op: str = "xor"):
    """One key byte per column: start from the best unigram score, then sweep the columns choosing, for each, the
    byte that maximises the bigram score of its plaintext given the neighbours' current bytes, until stable.
    Returns the per-column candidate lists ranked by the final conditional score (top LONG_TOP)."""
    n = len(enc)
    big = _bigram()
    tables = _op_tables(op)
    key = [allowed[j][0] for j in range(size)]
    plain = bytearray(tables[key[i % size]][enc[i]] for i in range(n))

    def col_score(j, k):
        tot = 0.0
        t = tables[k]
        for i in range(j, n, size):
            c = t[enc[i]]
            if i:
                tot += big[plain[i - 1] * 256 + c]
            if i + 1 < n:
                tot += big[c * 256 + plain[i + 1]]
        return tot

    for _ in range(6):
        changed = False
        for j in range(size):
            if j in fixed or len(allowed[j]) < 2:
                continue
            if time.monotonic() > end:
                return None
            best = max(allowed[j], key=lambda k: col_score(j, k))
            if best != key[j]:
                key[j] = best
                changed = True
                t = tables[best]
                for i in range(j, n, size):
                    plain[i] = t[enc[i]]
        if not changed or time.monotonic() > end:
            break
    ranked = []
    for j in range(size):
        if j in fixed or len(allowed[j]) < 2:
            ranked.append(list(allowed[j][:1]))
        else:
            if time.monotonic() > end:
                return None
            r = sorted(allowed[j], key=lambda k: (-col_score(j, k), k))
            ranked.append(r[:LONG_TOP])
    return ranked


CRIB_PAYLOAD_MAX = 1 << 16      # a crib-whole key is one CRC-32 a length: read up to the 64 KB a u16 length states


def _long_repeating(enc: bytes, crc: int, op: str = "xor", sizes: str = "long"):
    """The repeating-key reading of one payload under `op` (REPEAT_OPS). sizes="crib": the keys of REPEAT_MIN..
    len(OPENING) bytes the crib determines, one CRC-32 each, unbudgeted (every tried header). sizes="long": the
    longer keys, under three intrinsic guards (no runner wiring needed): at most LONG_HEADERS payloads per
    `_headers` pass reach the search, all calls together spend at most LONG_TOTAL seconds (a budget that renews
    after LONG_IDLE seconds without a search, i.e. for the next solve), and a payload already searched in this
    process is answered from a memo. Yields what `_long_search` yields."""
    n = len(enc)
    if sizes == "crib":
        if len(OPENING) < n <= CRIB_PAYLOAD_MAX:
            yield from _long_search(enc, crc, float("inf"), op, REPEAT_MIN, len(OPENING))
        return
    if n < 2 * LONG_KEY_MIN or n > LONG_PAYLOAD_MAX:
        return
    memo_key = (enc, crc, op)
    if memo_key in _LONG_MEMO:
        got = _LONG_MEMO[memo_key]
        if got:
            yield got
        return
    now = time.monotonic()
    st = _LONG_STATE
    if now - st["last"] > LONG_IDLE:
        st["spent"] = 0.0
    # B-246 review: the cap counts payloads, not searches: the XOR and the add search of one payload are one header
    counted = st.setdefault("counted", set())
    payload = (enc, crc)
    if (st["headers"] >= LONG_HEADERS and payload not in counted) or st["spent"] >= LONG_TOTAL:
        st["skipped"] = True            # REVIEW FIX: a later pass may search this payload; this reading is not final
        return
    hit = None
    try:
        for hit in _long_search(enc, crc, min(now + LONG_TIME, now + LONG_TOTAL - st["spent"]), op,
                                max(LONG_KEY_MIN, len(OPENING) + 1), LONG_KEY_MAX):
            break
    finally:
        done = time.monotonic()
        st["spent"] += done - now
        if done - now > LONG_COSTLY and payload not in counted:   # only a search that cost something counts
            counted.add(payload)
            st["headers"] += 1
        st["last"] = done
    if len(_LONG_MEMO) > 256:
        _LONG_MEMO.clear()
        _CONTAINERS.clear()             # REVIEW FIX: a kept reading may rest on a memo entry a new reading lacks
        st["skipped"] = True            # ... and so may the reading in progress
    _LONG_MEMO[memo_key] = hit
    if hit:
        yield hit


def _long_search(enc: bytes, crc: int, end: float, op: str = "xor", lo: int = LONG_KEY_MIN, hi: int = LONG_KEY_MAX):
    """(decoded bytes, key) for a payload combined by `op` with a repeating key of lo..hi bytes, only when the
    header's CRC-32 matches. A key the OPENING crib determines whole (size <= len(OPENING)) is one CRC-32 check
    and needs only that (a non-JSON payload is hcfg's call, as in the old short loop); a longer key's decode must
    also be a JSON object. Bounded by `end`, LONG_EVALS and DEADLINE; never raises on odd input."""
    n = len(enc)
    if n <= len(OPENING) or n > CRIB_PAYLOAD_MAX:
        return
    if DEADLINE is not None:
        end = min(end, DEADLINE)
    tables = _op_tables(op)
    evals = 0
    for size in range(lo, hi + 1):
        whole = size <= len(OPENING)
        if not whole and (n < 2 * size or n > LONG_PAYLOAD_MAX):
            break
        if time.monotonic() > end or evals >= LONG_EVALS:
            return
        known = _crib_key(enc, size, op)
        if whole:
            key = bytes(known[j] for j in range(size))
            plain = _repeat_decode(enc, key, op)
            evals += 1
            if zlib.crc32(plain) & 0xFFFFFFFF == crc:
                yield plain, key
                return
            continue
        if any(enc[j::size].translate(tables[k]).translate(None, _TEXT) for j, k in known.items()):
            continue                     # the crib's columns do not decode to text: not this length
        allowed = []
        for j in range(size):
            if j in known:
                allowed.append([known[j]])
                continue
            col = enc[j::size]
            ok = [k for k in range(256) if not col.translate(tables[k]).translate(None, _TEXT)]
            if not ok:
                break
            ok.sort(key=lambda k: (-sum(map(_SCORE.__getitem__, col.translate(tables[k]))), k))
            allowed.append(ok)
        else:
            cands = _icm(enc, size, allowed, known, end, op)
            if cands is None:
                return
            options = [(j, a) for j, c in enumerate(cands) for a in range(1, len(c))]
            spent = 0
            # Perf (Day 27 speed build): the same candidates, tried in the same order under the same bounds. A
            # candidate key is the column-wise first choice with at most three columns changed, so it is built
            # from that base key, and the payload's integer is taken once: plain is _xor_stream(enc, cand) exactly.
            base = bytearray(c[0] for c in cands)
            reps = n // size + 1
            enc_int = int.from_bytes(enc, "little")
            for depth in range(min(3, len(options)) + 1):
                for combo in itertools.combinations(options, depth):
                    if len({j for j, _ in combo}) != depth:
                        continue
                    if spent >= LONG_PER_L or evals >= LONG_EVALS or time.monotonic() > end:
                        break
                    spent += 1
                    evals += 1
                    key = bytearray(base)
                    for j, a in combo:
                        key[j] = cands[j][a]
                    cand = bytes(key)
                    if op == "xor":
                        plain = (enc_int ^ int.from_bytes((cand * reps)[:n], "little")).to_bytes(n, "little")
                    else:
                        plain = _repeat_decode(enc, cand, op)
                    if zlib.crc32(plain) & 0xFFFFFFFF == crc and _parse(plain) is not None:
                        yield plain, cand
                        return
                else:
                    continue
                break


_REPEAT_HOW = {"xor": "repeating", "add": "repeating_add", "sub": "repeating_sub"}   # "sub": see REPEAT_OPS


def _other_readings(enc: bytes, key: int, crc: int, x: bytes):
    """(how, decoded JSON bytes, repeating key or None) for each other way the payload `enc`
    reads under the header's key byte and its CRC-32; `x` is enc XOR key. A reading is only
    yielded when the CRC checks; the costlier ones are computed only when the payload starts as
    that reading would (zlib and gzip their magic; the B-246 decoders are prefiltered on their
    first two output bytes)."""
    def checks(blob: bytes) -> bool:
        return zlib.crc32(blob) & 0xFFFFFFFF == crc

    # The header byte completely specifies rolling/add/sub, and the stored CRC is an oracle over
    # the FINAL decoded bytes.  Do not require a JSON opening brace here: B2 routes CRC-proven
    # key/value, wire and XML payloads through the same transformation boundary.
    up = _BYTES[key:] + _BYTES[:key]
    for how, stream in (("rolling_up", up), ("rolling_down", up[:1] + up[:0:-1])):
        decoded = _xor_stream(enc, stream)
        if checks(decoded):
            yield how, decoded, None
    # B-246: the old 2..8-byte XOR loop, folded into the one repeating-key reader: every key the crib fixes
    # whole (2..13 bytes), for XOR and add
    for op in REPEAT_OPS:
        for plain, repeating in _long_repeating(enc, crc, op, "crib"):
            yield _REPEAT_HOW[op], plain, repeating
    for how, shift in (("add", -key), ("sub", key)):
        plain = enc.translate(bytes((i + shift) & 0xFF for i in range(256)))
        if checks(plain):
            yield how, plain, None
    if checks(x[::-1]):
        yield "reversed", x[::-1], None
    if len(x) % 2 == 0:
        try:
            plain = x.decode("utf-16-le").encode("utf-8")
        except UnicodeError:
            plain = b""
        if plain and (checks(plain) or checks(x)):   # the CRC-32 of the text, or of its UTF-16 bytes
            yield "utf16le", plain, None
    if x[:1] == b"\x78" or x[:2] == b"\x1f\x8b":
        try:
            plain = zlib.decompressobj(47).decompress(x, INFLATE_LIMIT)
        except zlib.error:
            plain = b""
        if plain and checks(plain):
            yield "zlib", plain, None
    if x and len(x) % 4 == 0:   # canonical Base64; CRC decides the payload, not a JSON-specific seed
        try:
            plain = base64.b64decode(x, validate=True)
        except (binascii.Error, ValueError):
            plain = b""
        if plain and base64.b64encode(plain) == x and checks(plain):
            yield "base64", plain, None
    # B-246: a bit rotation with a key, and the cheap decompressors (crc_transforms.cheap_readings)
    yield from crc_transforms.cheap_readings(enc, key, crc, OPENING)
    # Day 26: a repeating key of 14 to 64 bytes (XOR, then add), last of all, so every reading above
    # keeps its place
    for op in REPEAT_OPS:
        for plain, repeating in _long_repeating(enc, crc, op):
            yield _REPEAT_HOW[op], plain, repeating


# The Day 19 look-ahead, B7 (row 232): a payload RC4-encrypted under a string the sample itself carries near the
# record (the key an author declares beside the array). Only for the first RC4_HEADERS headers of a file whose
# payload no other reading opened; the keys are the printable runs of RC4_KEY_MIN to RC4_KEY_MAX characters in
# the RC4_NEAR bytes on each side of the record, at most RC4_KEYS of them; kept only when the CRC-32 the
# header stores is that of the decrypted JSON. `key_bytes` is the string.
RC4_HEADERS, RC4_NEAR, RC4_KEYS, RC4_KEY_MIN, RC4_KEY_MAX = 4, 1 << 14, 256, 4, 64
RC4_MAX_VERSION, RC4_MAX_LEN = 8, 1 << 14     # the lane's headers have said version 1 or 2, payloads under 1 KB
_RC4_KEY = None


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4 of `data` under `key`: Cryptodome's ARC4 (about 2 us a key), else the same cipher in Python."""
    try:
        from Cryptodome.Cipher import ARC4
        return ARC4.new(key).encrypt(data)
    except ImportError:
        pass
    S, j = list(range(256)), 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _rc4_reading(data, o: int, enc: bytes, crc: int):
    """(decrypted JSON bytes, the object, the key) of the payload at header offset `o` under one nearby string, or
    None."""
    global _RC4_KEY
    if _RC4_KEY is None:
        import re
        _RC4_KEY = re.compile(rb"[\x21-\x7e][\x20-\x7e]{%d,%d}(?=\x00)" % (RC4_KEY_MIN - 1, RC4_KEY_MAX - 1))
    if len(enc) < 16 or len(enc) > RC4_MAX_LEN or not 1 <= data[o + 4] <= RC4_MAX_VERSION:
        return None                     # a decoder's own compare constant (`== "HCFG"`) is followed by code, not a header
    lo, hi = max(0, o - RC4_NEAR), min(len(data), o + 12 + len(enc) + RC4_NEAR)
    keys, seen = [], set()
    for m in _RC4_KEY.finditer(bytes(data[lo:hi])):
        if lo + m.start() < o + 12 + len(enc) and lo + m.end() > o:
            continue                    # the record's own bytes are no key
        k = m.group()
        if k not in seen:
            seen.add(k)
            keys.append(k)
            if len(keys) >= RC4_KEYS:
                break
    for k in keys:
        head = _rc4(k, enc[:2])
        if head[:1] not in (b"{", b" ", b"\t", b"\n", b"\r"):
            continue
        plain = _rc4(k, enc)
        if zlib.crc32(plain) & 0xFFFFFFFF == crc:
            obj = _parse(plain)
            if obj is not None:
                return plain, obj, k
    return None


# A payload whose CRC-32 checks but is not JSON may be a self-describing non-JSON serialisation
# (CBOR, MessagePack, BSON, key=value lines or a flat XML document): nonjson_hcfg.decode reads it.
# Loaded defensively, so that a missing or broken module leaves hcfg reading exactly as before.
_NONJSON = []


def _nonjson_reading(plain: bytes):
    """(format, {name: value}) for a CRC-valid payload that is not JSON but is an unambiguous
    non-JSON mapping (nonjson_hcfg.decode), or None. Never raises."""
    if not _NONJSON:
        try:
            import nonjson_hcfg
            _NONJSON.append(nonjson_hcfg)
        except Exception:
            _NONJSON.append(None)
    mod = _NONJSON[0]
    if mod is None:
        return None
    try:
        return mod.decode(plain)
    except Exception:
        return None


def _whole(data) -> bytes:
    """`data` as something with find(): a memoryview is copied, bytes and bytearray are not."""
    return data if isinstance(data, (bytes, bytearray)) else bytes(data)


def _headers(data: bytes, others: bool = False):
    """One hit per header in `data` whose payload decodes to a JSON object, in file order
    (containers() says what a hit holds). A generator: find() stops at the first it wants."""
    tried = 0
    _LONG_STATE["headers"] = 0
    _LONG_STATE["counted"] = set()      # the payloads counted against LONG_HEADERS in this pass
    o = data.find(MAGIC)
    while o >= 0:
        if o + 12 < len(data):
            version, key = data[o + 4], data[o + 5]
            length, crc = struct.unpack_from("<HI", data, o + 6)
            # A payload that does not open a JSON object under the key is not copied (a file of
            # 20,000 headers that each claim 64 KB cost 0.4 s), unless the other ways are still tried.
            if data[o + 12] ^ key in _OPENS or (others and tried < OTHER_LIMIT):
                enc = bytes(data[o + 12:o + 12 + length])
            else:
                enc = b""
            if length and len(enc) == length:
                plain = _xor(enc, key)
                hit = {"offset": o, "version": version, "key": key, "crc32": crc, "json": _parse(plain),
                       "plain": plain, "how": "xor"}
                hit["crc_ok"] = zlib.crc32(plain) & 0xFFFFFFFF == crc
                if hit["json"] is None and others and tried < OTHER_LIMIT:
                    tried += 1
                    for how, decoded, repeating in _other_readings(enc, key, crc, plain):
                        obj = _parse(decoded)
                        nonjson = None if obj is not None else _nonjson_reading(decoded)
                        if obj is not None or nonjson is not None:
                            # B2: the transform has already passed the header's CRC-32 over its FINAL
                            # decoded bytes.  Give those same proven bytes to the non-JSON readers, not
                            # only to json.loads.  `how` retains the transformation and `nonjson`
                            # retains the serialization, so config_answer's unjudged-format guard stays
                            # in force and provenance is not collapsed.
                            hit.update(json=obj if obj is not None else nonjson[1], plain=decoded,
                                       how=how, crc_ok=True)
                            if nonjson is not None:
                                hit["nonjson"] = nonjson[0]
                            if repeating:
                                hit["key_bytes"] = repeating
                            break
                    if hit["json"] is None and tried <= RC4_HEADERS:
                        got = _rc4_reading(data, o, enc, crc)
                        if got:
                            hit.update(json=got[1], plain=got[0], how="rc4", crc_ok=True, key_bytes=got[2])
                    if (hit["json"] is None and tried <= RC4_HEADERS and not hit["crc_ok"]
                            and 16 <= len(enc) <= RC4_MAX_LEN and 1 <= version <= RC4_MAX_VERSION):
                        # B-246: the costly CRC-gated families (pure-Python LZ decoders, ChaCha20/Salsa20 and
                        # PRNG keystreams keyed from the bytes around the record), under the RC4 pass's bounds
                        got, cut = crc_transforms.costly_reading(data, o, enc, key, crc, DEADLINE)
                        if cut:
                            _LONG_STATE["skipped"] = True      # out of time: this reading is not final
                        if got:
                            obj = _parse(got["plain"])
                            nonjson = None if obj is not None else _nonjson_reading(got["plain"])
                            if obj is not None or nonjson is not None:
                                hit.update(got, json=obj if obj is not None else nonjson[1], crc_ok=True)
                                if nonjson is not None:
                                    hit["nonjson"] = nonjson[0]
                    if hit["json"] is None and hit["crc_ok"]:
                        # The stored CRC-32 matches the de-XOR'd payload, but it is not JSON: read a
                        # self-describing non-JSON serialisation. The CRC proves the bytes are the
                        # author's; the map is attached under "json" with a "nonjson" marker so
                        # config_answer offers every member unsure (the serialisation is unjudged).
                        # `how` stays "xor": the payload was de-XOR'd with the header's key byte, so
                        # the XOR key, the CRC-32 and the version are answered plain as for JSON.
                        got = _nonjson_reading(plain)
                        if got is not None:
                            hit.update(json=got[1], nonjson=got[0])
                if hit["json"] is not None:
                    yield hit
        o = data.find(MAGIC, o + 1)


_CONTAINERS = []          # [(bytes object, others, settings, hits)], the last few (containers)
CONTAINERS_KEPT = 8
_GLOBALS = globals()


def _same_settings(a, b) -> bool:
    """True when the two settings tuples hold the SAME objects (identity, a is b), not merely
    objects with equal id(): a freed global's id() can be reused by a new object, so an id-equal
    key could serve a stale reading. The held objects cannot pass that way."""
    return len(a) == len(b) and all(x is y for x, y in zip(a, b))


def _copy_hit(hit: dict) -> dict:
    """A hit as a fresh object, as a new reading would give it: its own dict and its own decoded JSON."""
    c = dict(hit)
    if isinstance(c.get("json"), (dict, list)):
        c["json"] = copy.deepcopy(c["json"])
    return c


def containers(data: bytes, others: bool = False) -> list:
    """Every container in `data` whose payload decodes to a JSON object, in file order, each
    once: {"offset","version","key","crc32","crc_ok","json","plain","how"}. `crc_ok` says
    whether the stored CRC-32 is that of the decoded JSON. `how` is "xor" for the lane's
    layout; with `others` a payload that is not JSON under it is tried the other ways
    (module docstring), and a "repeating" reading carries its key under "key_bytes".

    Two headers with the same key byte, CRC-32 and decoded JSON are one container. When one
    of them is in the lane's layout that reading is the one listed, wherever it stands, so
    what the key byte means does not depend on the order of two copies.

    Perf (Day 27 speed build): one prefix's members are read here by the config chooser, the catalog's place
    search and the header views, each the same immutable bytes object; its hits are kept for the last few objects
    (held, so an identity cannot pass to another object) and every call gets fresh copies, equal to what a new
    reading gives (a long-key search a second reading met would answer from _LONG_MEMO, changing nothing). A kept
    reading is served only under the same settings: the identity of every global of this module (a limit, a table,
    a function, DEADLINE) is part of its key, so a constant patched in between, or a runner's deadline, reads anew."""
    if type(data) is bytes:
        settings = tuple(_GLOBALS.values())     # REVIEW FIX: hold the objects (a is b), not id()
        for held, flag, sig, hits in _CONTAINERS:
            if held is data and flag == others and _same_settings(sig, settings):
                return [_copy_hit(h) for h in hits]
    _LONG_STATE["skipped"] = False
    out = _containers(data, others)
    if type(data) is bytes and not _LONG_STATE.get("skipped"):     # REVIEW FIX: keep only a final reading
        _CONTAINERS.append((data, others, settings, [_copy_hit(h) for h in out]))
        del _CONTAINERS[:-CONTAINERS_KEPT]
    return out


def _containers(data: bytes, others: bool = False) -> list:
    """containers() itself (see containers)."""
    out, seen = [], {}
    for hit in _headers(_whole(data), others):
        ident = (hit["key"], hit["crc32"], hit["plain"])
        at = seen.get(ident)
        if at is None:
            seen[ident] = len(out)
            out.append(hit)
        elif hit["how"] == "xor" and out[at]["how"] != "xor":
            out[at] = hit
    return out


def probe_offsets(data: bytes):
    """Every offset where PROBE stands under some single-byte XOR key, in file order.

    One pass for all 256 keys: XOR-ing the file with itself shifted by one byte removes the
    key. Looking for the probe under each key in turn cost about 67 ms per megabyte."""
    n = len(data)
    if n < len(PROBE):
        return
    whole = int.from_bytes(data, "little")
    delta = (whole ^ (whole >> 8)).to_bytes(n, "little")
    at = delta.find(_PROBE_DELTA, 0, n - 1)
    while at >= 0:
        yield at
        at = delta.find(_PROBE_DELTA, at + 1, n - 1)


def headerless(data: bytes):
    """The first single-byte-XOR JSON object that opens with PROBE, without a header, or None.
    Only the first HEADERLESS_LIMIT places where the probe stands are read: each that opens
    no JSON object costs a scan of 64 KB (about 1.5 ms), and a file can hold thousands."""
    data = _whole(data)
    for n, at in enumerate(probe_offsets(data)):
        if n >= HEADERLESS_LIMIT:
            break
        key = data[at] ^ PROBE[0]
        plain = _xor(bytes(data[at:at + 0x10000]), key)
        end = _object_end(plain)
        obj = _parse(plain[:end]) if end else None
        if obj is not None:
            return {"offset": at, "version": None, "key": key, "crc32": zlib.crc32(plain[:end]) & 0xFFFFFFFF,
                    "crc_ok": False, "json": obj, "plain": plain[:end], "how": "xor"}
    return None


def find(data: bytes):
    """Return {"offset","version","key","crc32","crc_ok","json","plain","how"} for the sample's config, or
    None: the first container whose CRC-32 checks, else the first whose payload parses, else headerless().
    It returns at the first CRC-valid container; what stands after it in the file is not read."""
    data = _whole(data)
    first = None
    for hit in _headers(data):
        if hit["crc_ok"]:
            return hit
        first = first or hit
    return first or headerless(data)


def answer(field: str, cfg):
    """Answer one `analysis_*` field that comes from the container, or None if it is not a config field.

    config_crc32_hex -> 0x-prefixed CRC-32, xor_key_hex -> 0x-prefixed key byte,
    config_<name> -> that JSON member. Absent values are the literal "none".
    """
    if field == "analysis_xor_key_hex":
        return "none" if cfg is None else f"0x{cfg['key']:02x}"
    if not field.startswith("analysis_config_"):
        return None
    name = field[len("analysis_config_"):]
    if cfg is None:
        return "none"
    if name == "crc32_hex":
        return f"0x{cfg['crc32']:08x}"
    if cfg.get("nonjson"):
        # A non-JSON payload (CBOR/MessagePack/BSON/key=value/XML): its members are never a plain
        # answer here. generic.config_answer offers each as an unsure labels.pick under a key that
        # names the serialisation, because no non-JSON spelling of a member has been judged.
        return None
    if name not in cfg["json"] or cfg["json"][name] is None:
        return "none"
    v = cfg["json"][name]
    return v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))


def _main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: hcfg.py <sample> [...]")
        return 0
    if not argv:
        print("hcfg.py: expected at least one sample", file=sys.stderr)
        return 2
    try:
        for path in argv:
            with open(path, "rb") as fh:
                cfg = find(fh.read())
            if not cfg:
                print(f"{path}: no config container")
                continue
            print(f"{path}: offset=0x{cfg['offset']:x} version={cfg['version']} key=0x{cfg['key']:02x} "
                  f"crc32=0x{cfg['crc32']:08x} crc_ok={cfg['crc_ok']}")
            for k, v in cfg["json"].items():
                print(f"  {k} = {v}")
    except Exception as exc:
        print(f"hcfg.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
