#!/usr/bin/env python3
"""FlatBuffers and Cap'n Proto readers with no schema (B-251 long tail).

Neither format carries its schema, and both carry enough structure to be walked without one.

FlatBuffers: a table names its fields only by slot, so the schema-less walk is a HEURISTIC: every
present slot is read as an offset when its target is a well-formed string, table or vector, else as
a little-endian scalar of the slot's width (a byte vector, the weakest reading, also states the
slot as a scalar: `or_scalar`). `Table` is the exact reader a caller with a schema uses
(lt_model_meta reads TFLite through it).

    Table(buf, pos, reach=None)   .has(i) .scalar(i, fmt, default) .string(i) .table(i) .tables(i)
                           .strings(i) .scalars(i, fmt) .vector(i) -> (start, count)
    Reach(limit)           a budget of bytes a Table reads through offsets: given one, a Table charges
                           its vtable, every string, scalar vector and offset vector it reads, and hands
                           the budget to the tables it reaches (FormatError once it is spent)
    root_table(buf, reach=None)   (Table, file identifier or None, size-prefixed?)
    walk_flatbuffer(buf)   {"file_identifier", "root": tree, "heuristic": True}

Cap'n Proto: pointers are typed (struct, list with element size, far, capability), so the walk is
exact: the stream framing (segment table), the packed encoding, far and double-far pointers,
composite lists. A byte list ending in NUL that is UTF-8 is shown as text.

    unpack(data)           the packed encoding undone
    read_capnp(data)       {"packed", "messages": [{"segments": n, "root": tree}]}
    detect / inspect / solve   the engine entry points (_lt_common)

Bounds: MAX_DEPTH, MAX_NODES tree nodes per message, and a traversal budget of the message's own
size: in words for Cap'n Proto, and for the FlatBuffers walk in the bytes of the strings and byte
vectors it reaches, each reference charged (BYTES_FACTOR times the buffer, so a few shared targets
pass and offsets that all name one large vector do not). A byte vector goes to the flag scan once,
whatever number of offsets name it. An amplification through zero-sized or shared targets ends in a
FormatError. The packed encoding unpacks to MAX_UNPACKED_BYTES at most.
"""
from __future__ import annotations

import struct
import sys

from _lt_common import FormatError, NotThisFormat, cli, need, solve_files, text_or_hex

ENGINE = "toolkits.lt_flat_capnp"
MAX_DEPTH = 64
MAX_NODES = 200_000
MAX_SEGMENTS = 512
MAX_UNPACKED_BYTES = 64 << 20      # what the packed encoding may unpack to
BYTES_FACTOR = 4                   # the FlatBuffers walk reaches this many times the buffer's bytes at most
KNOWN_ELSEWHERE = (b"TFL3",)        # FlatBuffers files another engine reads with their schema


# ------------------------------------------------------------------ FlatBuffers

def _u(buf, o, fmt):
    size = struct.calcsize(fmt)
    need(0 <= o and o + size <= len(buf), f"a {size}-byte read at offset {o} is outside the buffer")
    return struct.unpack_from(fmt, buf, o)[0]


class Reach:
    """The bytes a schema reader may still read through a buffer's offsets. Offsets can name one target
    many times (a shared string, a vector every table points at, overlapping vectors), so what a reader
    copies is bounded by this budget, not by the buffer's size."""

    def __init__(self, limit: int):
        self.limit = self.left = limit

    def spend(self, n: int):
        self.left -= n
        need(self.left >= 0, f"the offsets reach more than {self.limit} bytes of tables, strings and vectors "
                             "(shared or overlapping targets: an amplification)")


class Table:
    """One FlatBuffers table at absolute position `pos`: its vtable checked, its fields read by slot.
    With `reach`, every read through an offset is charged to it (see Reach)."""

    def __init__(self, buf, pos: int, reach: Reach | None = None):
        self.buf, self.pos, self.reach = buf, pos, reach
        vt = pos - _u(buf, pos, "<i")
        need(0 <= vt <= len(buf) - 4, f"the table at {pos} points to a vtable outside the buffer")
        vsize, self.size = _u(buf, vt, "<H"), _u(buf, vt + 2, "<H")
        need(vsize >= 4 and vsize % 2 == 0 and vt + vsize <= len(buf), f"the vtable at {vt} has the size {vsize}")
        self._spend(vsize)
        need(self.size >= 4 and pos + self.size <= len(buf), f"the table at {pos} has the inline size {self.size}")
        self.slots = struct.unpack_from(f"<{(vsize - 4) // 2}H", buf, vt + 4)
        need(all(s == 0 or 4 <= s < self.size for s in self.slots), f"the vtable at {vt} has a field outside its table")

    def _spend(self, n: int):
        if self.reach is not None:
            self.reach.spend(n)

    def has(self, i: int) -> bool:
        return i < len(self.slots) and self.slots[i] != 0

    def _at(self, i):
        return self.pos + self.slots[i] if self.has(i) else None

    def scalar(self, i, fmt, default=0):
        p = self._at(i)
        return default if p is None else _u(self.buf, p, fmt)

    def _target(self, i):
        p = self._at(i)
        if p is None:
            return None
        t = p + _u(self.buf, p, "<I")
        need(p < t <= len(self.buf) - 4, f"field {i} of the table at {self.pos} points outside the buffer")
        return t

    def vector(self, i):
        """(start of the elements, count) or None."""
        t = self._target(i)
        return None if t is None else (t + 4, _u(self.buf, t, "<I"))

    def string(self, i):
        v = self.vector(i)
        if v is None:
            return None
        need(v[1] <= len(self.buf) - v[0], f"a string of {v[1]} bytes at {v[0]} runs past the buffer")
        self._spend(v[1])
        return bytes(self.buf[v[0]:v[0] + v[1]])

    def table(self, i):
        t = self._target(i)
        return None if t is None else Table(self.buf, t, self.reach)

    def scalars(self, i, fmt):
        v = self.vector(i)
        if v is None:
            return []
        size = struct.calcsize(fmt)
        need(v[1] * size <= len(self.buf) - v[0], f"a vector of {v[1]} elements at {v[0]} runs past the buffer")
        self._spend(v[1] * size)
        return list(struct.unpack_from(f"<{v[1]}{fmt[-1]}", self.buf, v[0]))

    def _offsets(self, i):
        v = self.vector(i)
        if v is None:
            return []
        need(v[1] * 4 <= len(self.buf) - v[0], f"a vector of {v[1]} offsets at {v[0]} runs past the buffer")
        self._spend(4 * v[1])
        out = []
        for k in range(v[1]):
            p = v[0] + 4 * k
            t = p + _u(self.buf, p, "<I")
            need(p < t <= len(self.buf) - 4, f"element {k} of a vector at {v[0]} points outside the buffer")
            out.append(t)
        return out

    def tables(self, i):
        return [Table(self.buf, t, self.reach) for t in self._offsets(i)]

    def strings(self, i):
        out = []
        for t in self._offsets(i):
            n = _u(self.buf, t, "<I")
            need(n <= len(self.buf) - t - 4, f"a string of {n} bytes at {t} runs past the buffer")
            self._spend(n)
            out.append(bytes(self.buf[t + 4:t + 4 + n]))
        return out


def root_table(buf, reach: Reach | None = None):
    """(root Table, file identifier or None, size_prefixed). FormatError when there is no valid root.
    With `reach`, the root and every table read from it charge that budget."""
    need(len(buf) >= 8, "shorter than a FlatBuffers header")
    for base in (0, 4):
        if base == 4 and _u(buf, 0, "<I") + 4 != len(buf):
            break
        try:
            root = _u(buf, base, "<I")
            need(root >= 4, "the root offset is inside the header")
            table = Table(buf, base + root, reach)
        except FormatError as e:
            err = e
            continue
        ident = bytes(buf[base + 4:base + 8])
        has_ident = root >= 8 and ident.isascii() and all(33 <= c < 127 for c in ident)
        return table, (ident if has_ident else None), base == 4
    raise FormatError(f"no FlatBuffers root table: {err}")


def _string_at(buf, t):
    """The string at vector position t when the bytes there are a NUL-terminated UTF-8 text, else None."""
    if t + 4 > len(buf):
        return None
    n = struct.unpack_from("<I", buf, t)[0]
    if n == 0 or t + 4 + n >= len(buf) or buf[t + 4 + n] != 0:
        return None
    try:
        s = bytes(buf[t + 4:t + 4 + n]).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(c >= " " or c in "\t\r\n" for c in s) else None


def walk_flatbuffer(buf, blobs=None) -> dict:
    """The heuristic tree of a buffer. Offsets only point forward, so the walk cannot loop; shared
    targets are bounded by the node budget and by a budget of the bytes the references reach."""
    table, ident, prefixed = root_table(buf)
    budget = [MAX_NODES]
    reach = [BYTES_FACTOR * len(buf) + 1024]
    scanned = set()                       # byte vectors already handed to the flag scan, by position

    def spend(n):
        reach[0] -= n
        need(reach[0] >= 0, "the offsets reach more string and vector bytes than the buffer could hold "
                            "(shared or overlapping targets: an amplification)")

    def node(t: Table, depth):
        need(depth <= MAX_DEPTH, "the tables nest deeper than this reader follows")
        budget[0] -= 1
        need(budget[0] > 0, f"more than {MAX_NODES} nodes")
        present = sorted((s, i) for i, s in enumerate(t.slots) if s)
        out = {}
        for k, (off, i) in enumerate(present):
            width = (present[k + 1][0] if k + 1 < len(present) else t.size) - off
            out[f"field_{i}"] = field(t, i, t.pos + off, min(width, 8), depth)
        return out

    def target(p, depth):
        t = p + struct.unpack_from("<I", buf, p)[0]
        if not (p < t <= len(buf) - 4) or t % 4:      # strings, vectors and tables are 4-aligned
            return None
        budget[0] -= 1
        need(budget[0] > 0, f"more than {MAX_NODES} nodes")
        s = _string_at(buf, t)
        if s is not None:
            spend(len(s))
            return s
        try:
            return node(Table(buf, t), depth + 1)
        except FormatError:
            pass
        n = struct.unpack_from("<I", buf, t)[0]
        if n and 4 * n <= len(buf) - t - 4 and n <= budget[0]:          # a vector of offsets
            items = []
            for k in range(n):
                got = target(t + 4 + 4 * k, depth + 1) if depth < MAX_DEPTH else None
                if got is None:
                    items = None
                    break
                items.append(got)
            if items is not None:
                return items
        if n and n <= len(buf) - t - 4:                                 # a vector of bytes
            spend(n)
            raw = bytes(buf[t + 4:t + 4 + n])
            if blobs is not None and t not in scanned:
                scanned.add(t)
                blobs.append(raw)
            return {"bytes": text_or_hex(raw, 256), "length": n, "or_scalar": struct.unpack_from("<I", buf, p)[0]}
        return None

    def field(t, i, p, width, depth):
        if width >= 4 and p % 4 == 0:
            got = target(p, depth)
            if got is not None:
                return got
        w = 8 if width >= 8 else 4 if width >= 4 else 2 if width >= 2 else 1
        return int.from_bytes(buf[p:p + w], "little")

    return {"format": "flatbuffers", "file_identifier": ident.decode("ascii") if ident else None,
            "size_prefixed": prefixed, "heuristic": True, "root": node(table, 0)}


# ------------------------------------------------------------------ Cap'n Proto

def unpack(data: bytes, max_words: int | None = None) -> bytes:
    """Undo the packed encoding: a tag byte per word (bit i set: byte i follows), 0x00 followed by a
    count of further zero words, 0xFF followed by a count of words that follow unpacked. With
    max_words, stop once that many words are out (to look at the head of a stream)."""
    out, o, n = bytearray(), 0, len(data)
    while o < n and (max_words is None or len(out) < 8 * max_words):
        tag = data[o]
        o += 1
        word = bytearray(8)
        for i in range(8):
            if tag >> i & 1:
                need(o < n, "the packed data ends inside a word")
                word[i] = data[o]
                o += 1
        out += word
        if tag == 0:
            need(o < n, "the packed data ends before a zero-run count")
            out += bytes(8 * data[o])
            o += 1
        elif tag == 0xFF:
            need(o < n, "the packed data ends before a literal-run count")
            k = 8 * data[o]
            need(o + 1 + k <= n, "the packed data ends inside a literal run")
            out += data[o + 1:o + 1 + k]
            o += 1 + k
        need(len(out) <= MAX_UNPACKED_BYTES, f"the packed data unpacks to more than {MAX_UNPACKED_BYTES} bytes")
    return bytes(out)


def frames(data: bytes):
    """[[segment bytes]] of every message in a stream; FormatError unless the framing uses every byte."""
    out, o = [], 0
    while o < len(data):
        need(o + 8 <= len(data), "a segment table is cut short")
        count = struct.unpack_from("<I", data, o)[0] + 1
        need(count <= MAX_SEGMENTS, f"a segment table states {count} segments")
        head = (4 + 4 * count + 7) & ~7
        need(o + head <= len(data), "a segment table is cut short")
        sizes = struct.unpack_from(f"<{count}I", data, o + 4)
        o += head
        segs = []
        for words in sizes:
            need(8 * words <= len(data) - o, f"a segment of {words} words runs past the end of the data")
            segs.append(data[o:o + 8 * words])
            o += 8 * words
        need(sum(sizes) > 0, "a message with no words")
        out.append(segs)
    need(out, "no message")
    return out


def _s30(v):
    return v - (1 << 30) if v & (1 << 29) else v


class _Message:
    def __init__(self, segs, blobs):
        self.segs, self.blobs = segs, blobs
        self.budget = sum(len(s) for s in segs) // 8 * 4 + 64
        self.nodes = MAX_NODES

    def word(self, seg, off):
        need(0 <= seg < len(self.segs), f"a pointer names segment {seg} of {len(self.segs)}")
        need(0 <= off and 8 * off + 8 <= len(self.segs[seg]), f"word {off} is outside segment {seg}")
        return struct.unpack_from("<Q", self.segs[seg], 8 * off)[0]

    def spend(self, words):
        """Charge one node and `words` words: the words bound shared and overlapping targets, the node
        count bounds what costs no words (a list of zero-sized structs)."""
        self.budget -= words
        self.nodes -= 1
        need(self.budget >= 0 and self.nodes >= 0, "the pointers reach more words than the message holds "
             "(an amplification) or more nodes than this reader builds")

    def pointer(self, seg, off, depth):
        need(depth <= MAX_DEPTH, "the pointers nest deeper than this reader follows")
        w = self.word(seg, off)
        if w == 0:
            return None
        kind = w & 3
        if kind == 3:
            return {"capability": w >> 32}
        if kind == 2:
            pad, tseg, double = (w >> 3) & 0x1FFFFFFF, w >> 32, w >> 2 & 1
            if not double:
                p = self.word(tseg, pad)
                need(p & 3 in (0, 1), "a far pointer's landing pad is not a struct or list pointer")
                return self.near(tseg, pad + 1 + _s30(p >> 2 & 0x3FFFFFFF), p, depth)
            far, tag = self.word(tseg, pad), self.word(tseg, pad + 1)
            need(far & 7 == 2 and tag & 3 in (0, 1) and tag >> 2 & 0x3FFFFFFF == 0,
                 "a double-far landing pad is not a far pointer and a tag")
            return self.near(far >> 32, (far >> 3) & 0x1FFFFFFF, tag, depth)
        return self.near(seg, off + 1 + _s30(w >> 2 & 0x3FFFFFFF), w, depth)

    def near(self, seg, start, w, depth):
        if w & 3 == 0:
            return self.struct(seg, start, w >> 32 & 0xFFFF, w >> 48, depth)
        size, count = w >> 32 & 7, w >> 35
        return self.list(seg, start, size, count, depth)

    def struct(self, seg, start, dwords, pwords, depth):
        self.spend(dwords + pwords)
        need(0 <= seg < len(self.segs) and 0 <= start and 8 * (start + dwords + pwords) <= len(self.segs[seg]),
             f"a struct at word {start} of segment {seg} runs past it")
        data = bytes(self.segs[seg][8 * start:8 * (start + dwords)])
        return {"data_hex": data.hex(),
                "pointers": [self.pointer(seg, start + dwords + i, depth + 1) for i in range(pwords)]}

    def list(self, seg, start, size, count, depth):
        need(0 <= seg < len(self.segs) and start >= 0, f"a list at word {start} of segment {seg} is outside it")
        s = self.segs[seg]
        if size == 7:                                    # composite: a tag word, then `count` words of structs
            tag = self.word(seg, start)
            need(tag & 3 == 0, "a composite list's tag is not a struct pointer")
            n, dw, pw = tag >> 2 & 0x3FFFFFFF, tag >> 32 & 0xFFFF, tag >> 48
            need(n * (dw + pw) <= count and 8 * (start + 1 + count) <= len(s), "a composite list runs past its words")
            self.spend(count + 1)
            return [self.struct(seg, start + 1 + k * (dw + pw), dw, pw, depth + 1) for k in range(n)]
        if size == 0:
            self.spend(1)
            return {"void": count}
        if size == 6:
            need(8 * (start + count) <= len(s), "a pointer list runs past its segment")
            self.spend(count)
            return [self.pointer(seg, start + k, depth + 1) for k in range(count)]
        bits = {1: 1, 2: 8, 3: 16, 4: 32, 5: 64}[size] * count
        need(8 * start + (bits + 7) // 8 <= len(s), "a list runs past its segment")
        self.spend((bits + 63) // 64)
        raw = bytes(s[8 * start:8 * start + (bits + 7) // 8])
        if size == 1:
            return {"bits": [raw[i // 8] >> (i % 8) & 1 for i in range(count)]}
        if size == 2:
            if count and raw[-1] == 0:
                try:
                    text = raw[:-1].decode("utf-8")
                    if "\x00" not in text:
                        return text
                except UnicodeDecodeError:
                    pass
            self.blobs.append(raw)
            return {"data": text_or_hex(raw, 256), "length": count}
        return list(struct.unpack(f"<{count}{ {3: 'H', 4: 'I', 5: 'Q'}[size]}", raw))


def read_capnp(data: bytes, blobs=None) -> dict:
    """Every message of a stream, read first as the plain framing and, when that does not fit, packed."""
    blobs = [] if blobs is None else blobs
    packed = False
    try:
        msgs = frames(data)
    except FormatError as plain:
        try:
            msgs = frames(unpack(data))
            packed = True
        except FormatError as e:
            raise NotThisFormat(f"no Cap'n Proto framing fits the data (plain: {plain}; packed: {e})") from None
    out = []
    for segs in msgs:
        m = _Message(segs, blobs)
        root = m.word(0, 0)
        if root & 3 not in (0, 2) or root == 0:
            raise NotThisFormat("the first word of a message is not a struct pointer")
        out.append({"segments": len(segs), "words": sum(len(s) for s in segs) // 8, "root": m.pointer(0, 0, 0)})
    return {"format": "capnp", "packed": packed, "messages": out}


def _capnp_head(head: bytes) -> bool:
    for cand in (head, None):
        if cand is None:
            try:
                cand = unpack(head, max_words=80)
            except FormatError:
                cand = b""
        if len(cand) < 16:
            continue
        count = struct.unpack_from("<I", cand, 0)[0] + 1
        if count > 64 or 4 + 4 * count > len(cand):
            continue
        sizes = struct.unpack_from(f"<{count}I", cand, 4)
        at = (4 + 4 * count + 7) & ~7
        if not all(0 < s <= 1 << 26 for s in sizes) or at + 8 > len(cand):
            continue
        root = struct.unpack_from("<Q", cand, at)[0]
        if root & 3 == 0 and root >> 32 and 0 <= _s30(root >> 2 & 0x3FFFFFFF) < sizes[0]:
            return True
    return False


def _flat_head(head: bytes) -> bool:
    if len(head) < 12:
        return False
    for base in (0, 4):
        root = struct.unpack_from("<I", head, base)[0] + base
        if head[base + 4:base + 8] in KNOWN_ELSEWHERE or root < base + 4 or root + 4 > len(head):
            continue
        vt = root - struct.unpack_from("<i", head, root)[0]
        if 0 <= vt <= len(head) - 4:
            vsize, tsize = struct.unpack_from("<HH", head, vt)
            if 4 <= vsize <= 2048 and vsize % 2 == 0 and tsize >= 4 and vt + vsize <= len(head):
                slots = struct.unpack_from(f"<{(vsize - 4) // 2}H", head, vt + 4)
                if slots and any(slots) and all(s == 0 or 4 <= s < tsize for s in slots):
                    return True
    return False


def detect(head: bytes, name: str = "") -> bool:
    return _flat_head(head) or _capnp_head(head)


def inspect(data: bytes, name: str = "", opts=None):
    blobs = []
    if _flat_head(data[:8192]):
        try:
            root_table(data)
        except FormatError as e:           # the head looked like a table and the whole buffer has no root
            if not _capnp_head(data[:8192]):
                raise NotThisFormat(str(e)) from None
        else:
            facts = walk_flatbuffer(data, blobs)
            return facts, [("bytes", b"\n".join(blobs))] if blobs else []
    facts = read_capnp(data, blobs)
    return facts, [("data", b"\n".join(blobs))] if blobs else []


def solve(challenge_dir, profile=None, **opts):
    """Walk every FlatBuffers buffer and Cap'n Proto message in the handout and scan its text for a flag."""
    return solve_files(ENGINE, "FlatBuffers/Cap'n Proto", challenge_dir, profile, detect, inspect, opts)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:], __doc__, detect, inspect))
