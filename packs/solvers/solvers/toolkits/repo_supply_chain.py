#!/usr/bin/env python3
"""Toolkit `repo_supply_chain`: version-control forensics, package and extension readers, secrets.

  .venv/bin/python solvers/toolkits/repo_supply_chain.py <file or folder>... [--json] [--grep TEXT]

Offline and read-only: no Game Master request, no token, no network, and NO external program.
In particular no `git` binary ever runs on a delivered repository: hooks, config, filters and
alternates are bytes this module reads, never code it runs. Archives are opened in memory, so a member named
`../../x` is only a name. On Python builds lacking SQLite's in-memory deserialize API, a wc.db/Fossil reader
uses one private OS-temporary file opened immutable/read-only and unlinked as soon as its read-only backup into
memory completes; no repository path is written.

What it reads (every reader is a function an agent can call by hand, see docs/toolkits/repo_supply_chain.md):

  git        loose objects, packfiles (OFS and REF deltas, no .idx needed), a bare pack, a bundle,
             refs, packed-refs, HEAD, reflog, stash, the index (v2 to v4), SHA-1 and SHA-256 object
             formats; the commit table, the diff by path between commits, every blob searched,
             the objects no ref reaches and the dangling ones, the files in the git directory
             that git did not write (GitRepo.nonstandard)
  mercurial  revlog v1 (inline or .i/.d, zlib, deltas, generaldelta): changelog, manifest, filelogs
  svn        a dump file (svnadmin dump, full texts), revprops of an FSFS repository, a working
             copy's wc.db
  darcs      _darcs/patches (gzip text): patch info, hunks, file operations
  fossil     the repository database (SQLite): artifacts, deltas, check-in manifests
  packages   npm tgz, wheel, sdist, .vsix, .crx (v2 and v3), .jar, .nupkg, .gem, composer.json,
             GitHub Actions workflows (yaml.safe_load): what runs at install or load time, the
             entry points, the URLs, a wheel's RECORD checked hash by hash
  secrets    AWS key ids, GitHub, Slack, Telegram, npm, PyPI, Google and Stripe tokens, JWTs,
             private-key blocks, flag{...}; each with its path and the commit that brought it.
             A found secret is an answer and nothing else: it is never used, sent or tested.

signals(questions, files) says in 0..1 how much a delivery looks like this category (cheap: names
and magic bytes). solve_set is the runner contract and never guesses (AGENTS.md, "Uncertain
answers"). Nothing of this category is judged yet, and which fact a question means is read from
its words, so no answer is plain before a verdict: every answer is
labels.pick('repo_supply_chain.<field>/<shape>', forms), which tools/verify.py probes on the
untimed base, one request per key. Once the judge has accepted a form for a key, labels.pick
returns that form plain on the next question and the next variant. An answer is offered only
when exactly one fact in the whole delivery fits the question and the history is complete.
Everything else is None: two commits that fit, an object that is missing, a count with a
condition, a question that names another branch, an ordinal or another object (a tree, a file's
hash), a question this file does not recognise. (Review of 2026-10-08: with plain answers, 9 of
38 plausible git questions and 16 of 36 package and secret questions were answered plain and
wrong, e.g. the branch count for "How many commits are on the dev branch?".)

Checked against the real tools on 2026-10-08 (on repositories and packages built for the check,
never on a delivered one): git 2.x (loose and packed objects with OFS deltas, SHA-1 and SHA-256,
index v2 and v4, a bundle, fsck's unreachable and dangling lists, log -S), Mercurial (five store
formats, zstd included), npm pack, gem build, and the RECORD of sixty installed wheels. Written
from the format documentation alone, and so never answered plain: darcs, Fossil, an SVN dump.
"""
import base64
import binascii
import bz2
import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
KEY = "repo_supply_chain"
ARROW = " -> "

MAX_MEMBER = 64 * 1024 * 1024       # bytes one inflated member or object may have
MAX_TOTAL = 384 * 1024 * 1024       # bytes kept over one delivery
MAX_FILES = 40000                   # members listed over one delivery
MAX_OBJECTS = 400000                # objects read from one repository
MAX_DELTA_CHAIN = 4096
SEARCH_CAP = 8 * 1024 * 1024        # bytes of one blob searched for secrets
SECRET_BUDGET = 24 * 1024 * 1024    # bytes searched for secrets over one delivery (about half a second)


def _labels():
    """solvers/common/labels.py, with this toolkit's key prefix known to it. labels.py names five
    lanes; a sixth prefix is registered here at run time (seed: solvers/toolkits/conventions.json,
    ledger: <challenges>/_ledger/repo_supply_chain.jsonl), in the one `labels` module of the
    process, so tools/verify.py parses, probes and learns these keys like any other."""
    if str(COMMON) not in sys.path:
        sys.path.insert(0, str(COMMON))
    import labels
    labels.LANE_DIRS.setdefault(KEY, "toolkits")
    return labels


def pick(key: str, options):
    """labels.pick for a key of this toolkit; when labels cannot be loaded, the same wire form
    built here, so the answer is still unsure and can never be sent as plain."""
    opts = [o for o in options if o is not None and (not isinstance(o, tuple) or o[1] is not None)]
    if not opts:
        return None
    try:
        return _labels().pick(key, opts)
    except Exception:
        pairs = [[o[0], o[1]] if isinstance(o, tuple) else [str(o), o] for o in opts][:12]
        return "??" + json.dumps({"k": key, "o": pairs}, separators=(",", ":"))


try:
    _labels()               # at import, so a "??" answer of this toolkit parses wherever the solver is loaded
except Exception:           # labels.py missing or broken: pick() falls back to the bare wire form
    pass


class Incomplete(Exception):
    """Something a fact depends on could not be read (a missing object, a cap, a broken stream)."""


# ---- bounded decompression ---------------------------------------------------------------------------

def _inflate_at(buf, pos: int, limit: int = MAX_MEMBER):
    """(data, bytes consumed) of the zlib stream that starts at buf[pos]. ValueError when it is
    broken, truncated or larger than limit (the stream is still walked to its end in that case, so
    the caller knows where the next one starts: data is then None)."""
    d = zlib.decompressobj()
    out, n, start, keep = [], 0, pos, True
    view = memoryview(buf)
    while not d.eof:
        chunk = view[pos:pos + 65536]
        if not len(chunk):
            raise ValueError("truncated zlib stream")
        pos += len(chunk)
        data = bytes(chunk)
        while True:
            try:
                piece = d.decompress(data, 1 << 20)
            except zlib.error as e:
                raise ValueError(f"zlib: {e}")
            n += len(piece)
            if n > limit:
                keep = False
                out = []
            elif keep:
                out.append(piece)
            data = d.unconsumed_tail
            if not data or d.eof:
                break
        if n > 64 * limit:
            raise ValueError("zlib stream far over the size cap")
    pos -= len(d.unused_data)
    return (b"".join(out) if keep else None), pos - start


def inflate(data: bytes, limit: int = MAX_MEMBER, wbits: int = 15) -> bytes:
    """A whole zlib (wbits 15), gzip (31) or either (47) stream, at most limit bytes; ValueError otherwise."""
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, limit + 1)
    except zlib.error as e:
        raise ValueError(f"zlib: {e}")
    if len(out) > limit:
        raise ValueError("over the size cap")
    if not d.eof:
        raise ValueError("truncated or incomplete stream")
    return out


def _unpack_stream(data: bytes):
    """The bytes inside a gzip, bzip2, xz or zstd stream, or None when data is none of them."""
    try:
        if data[:2] == b"\x1f\x8b":
            return inflate(data, MAX_MEMBER, 31)
        if data[:3] == b"BZh":
            dec = bz2.BZ2Decompressor()
            out = dec.decompress(data, MAX_MEMBER + 1)
            if len(out) > MAX_MEMBER or not dec.eof:    # over the cap or truncated: not a complete member
                return None
            return out
        if data[:6] == b"\xfd7zXZ\x00":
            dec = lzma.LZMADecompressor()
            out = dec.decompress(data, MAX_MEMBER + 1)
            if len(out) > MAX_MEMBER or not dec.eof:
                return None
            return out
        if data[:4] == b"\x28\xb5\x2f\xfd":
            import zstandard
            return zstandard.ZstdDecompressor().decompressobj().decompress(data)[:MAX_MEMBER]
    except Exception:
        return None
    return None


def _is_tar(data: bytes) -> bool:
    if len(data) < 512:
        return False
    if data[257:262] == b"ustar":
        return True
    # A pre-POSIX tar has no magic: the header's own checksum says whether it is one.
    try:
        want = int(data[148:156].strip(b"\x00 ") or b"0", 8)
    except ValueError:
        return False
    head = data[:148] + b" " * 8 + data[156:512]
    return want != 0 and want == sum(head) and data[0:1] not in (b"\x00",)


def crx_parts(data: bytes) -> dict:
    """A .crx file's header: {version, zip (bytes), id (the 32 letters a-p, or None), public_keys}."""
    if data[:4] != b"Cr24" or len(data) < 12:
        raise ValueError("not a crx")
    version = struct.unpack_from("<I", data, 4)[0]
    out = {"version": version, "id": None, "public_keys": []}
    if version == 2:
        if len(data) < 16:
            raise ValueError("truncated crx2 header")
        klen, slen = struct.unpack_from("<II", data, 8)
        key = data[16:16 + klen]
        out["public_keys"] = [key]
        out["id"] = _crx_id(hashlib.sha256(key).digest()[:16])
        out["zip"] = data[16 + klen + slen:]
    elif version == 3:
        hlen = struct.unpack_from("<I", data, 8)[0]
        header = data[12:12 + hlen]
        out["zip"] = data[12 + hlen:]
        for field, wire, value in _protobuf(header):
            if field in (2, 3) and wire == 2:            # sha256_with_rsa / sha256_with_ecdsa: AsymmetricKeyProof
                for f2, w2, v2 in _protobuf(value):
                    if f2 == 1 and w2 == 2:
                        out["public_keys"].append(v2)
            if field == 10000 and wire == 2:             # signed_header_data: SignedData{crx_id = 1}
                for f2, w2, v2 in _protobuf(value):
                    if f2 == 1 and w2 == 2 and len(v2) == 16:
                        out["id"] = _crx_id(v2)
    else:
        raise ValueError(f"crx version {version}")
    return out


def _crx_id(raw16: bytes) -> str:
    return "".join(chr(ord("a") + int(c, 16)) for c in raw16.hex())


def _protobuf(data: bytes):
    """(field number, wire type, value) of one protobuf message; stops quietly at the first byte it cannot read."""
    pos, n = 0, len(data)

    def varint():
        nonlocal pos
        shift = value = 0
        while pos < n:
            b = data[pos]
            pos += 1
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                break
        raise ValueError
    try:
        while pos < n:
            tag = varint()
            field, wire = tag >> 3, tag & 7
            if wire == 0:
                yield field, wire, varint()
            elif wire == 2:
                size = varint()
                if pos + size > n:
                    return
                yield field, wire, data[pos:pos + size]
                pos += size
            elif wire == 1:
                yield field, wire, data[pos:pos + 8]
                pos += 8
            elif wire == 5:
                yield field, wire, data[pos:pos + 4]
                pos += 4
            else:
                return
    except ValueError:
        return


# ---- the files of a delivery, opened all the way down --------------------------------------------------

def _unique(files: dict) -> list:
    """[(key, bytes)] once per bytes object, the '<archive> -> <member>' name first (tools/run.py's
    expand files a member under that name and, the first time, under its bare name too)."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)):
            continue
        # Python keeps one object for b"" and for every one-byte value, so identity cannot tell two
        # empty members apart (a real wheel has several empty __init__.py and RECORD lists each one):
        # those are told apart by the member's own name instead.
        mark = id(data) if len(data) > 1 else (key.split(ARROW)[-1], bytes(data))
        if mark in seen:
            continue
        seen.add(mark)
        out.append((key, data))
    return out


def expand(files: dict, notes: list = None) -> dict:
    """files plus what tools/run.py's expand leaves packed: tar (plain, gzip, bzip2, xz, zstd: an npm
    tgz, an sdist, a .gem and its data.tar.gz), single compressed streams, a .crx's zip, and any zip
    not opened yet. New members are filed as '<file> -> <member>'. In memory only."""
    notes = notes if notes is not None else []
    out = {k: v for k, v in files.items() if isinstance(v, (bytes, bytearray))}
    opened = {k.split(ARROW)[0] for k in out if ARROW in k}
    queue = [(k, v, 0) for k, v in _unique(out)]
    total = sum(len(v) for _, v, _ in queue)
    while queue:
        key, data, depth = queue.pop(0)
        if depth > 6:
            continue
        tail = key.split(ARROW)[-1]
        if tail in opened:
            continue
        found = []
        try:
            if data[:4] == b"Cr24":
                found = _zip_members(crx_parts(bytes(data))["zip"], notes, tail)
            elif data[:4] == b"PK\x03\x04":
                found = _zip_members(bytes(data), notes, tail)
            else:
                raw = bytes(data) if _is_tar(data) else _unpack_stream(bytes(data))
                if raw is None:
                    continue
                if _is_tar(raw):
                    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                        for m in tf:
                            if m.isfile() and m.size <= MAX_MEMBER:
                                f = tf.extractfile(m)
                                if f is not None:
                                    found.append((m.name, f.read()))
                            elif m.issym() or m.islnk():
                                notes.append(f"{tail}: link member {m.name} -> {m.linkname} (not followed)")
                else:
                    found.append((re.sub(r"\.(gz|bz2|xz|zst|tgz)$", "", Path(tail).name, flags=re.I) or "stream", raw))
        except Exception as e:
            notes.append(f"{tail}: not opened ({type(e).__name__}: {str(e)[:80]})")
            continue
        if found:
            opened.add(tail)
        for member, body in found:
            k = f"{tail}{ARROW}{member}"
            if k in out:
                continue
            total += len(body)
            if len(out) >= MAX_FILES or total > MAX_TOTAL:
                notes.append("the delivery is larger than this toolkit reads: members were left out")
                return out
            out[k] = body
            queue.append((k, body, depth + 1))
    return out


def _zip_members(data: bytes, notes: list, tail: str) -> list:
    found = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER:
                continue
            if info.flag_bits & 1:
                notes.append(f"{tail}: encrypted member {info.filename} (not opened here)")
                continue
            try:
                found.append((info.filename, zf.read(info)))
            except Exception as e:
                notes.append(f"{tail}: member {info.filename} not read ({type(e).__name__})")
    return found


def listing(files: dict) -> list:
    """[(container, path, bytes)] once per file: 'evidence.zip -> repo/.git/HEAD' is
    ('evidence.zip', 'repo/.git/HEAD', ...); a file with no archive around it has container ''."""
    out = []
    for key, data in _unique(files):
        container, _, path = key.rpartition(ARROW)
        out.append((container, path.replace("\\", "/"), bytes(data) if isinstance(data, bytearray) else data))
    return out


def from_paths(paths) -> dict:
    """{name: bytes} of files and folders on disk (a folder is walked, hidden entries included;
    symbolic links are not followed), for the command and for an agent."""
    out = {}
    for p in map(Path, paths):
        if p.is_dir():
            base = p.resolve()
            for f in sorted(base.rglob("*")):
                if f.is_file() and not f.is_symlink() and len(out) < MAX_FILES:
                    try:
                        if f.stat().st_size <= MAX_MEMBER:
                            out[f"{base.name}/{f.relative_to(base).as_posix()}"] = f.read_bytes()
                    except OSError:
                        pass
        elif p.is_file():
            out[p.name] = p.read_bytes()
    return out


# ---- git ---------------------------------------------------------------------------------------------

_GIT_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_IDENT = re.compile(r"^(.*?)\s*<([^>]*)>\s*(-?\d+)?\s*([+-]\d{4})?\s*$")


def apply_git_delta(base: bytes, delta: bytes) -> bytes:
    """A git pack delta applied to its base."""
    pos = 0

    def size():
        nonlocal pos
        value = shift = 0
        while True:
            b = delta[pos]
            pos += 1
            value |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return value
    try:
        src, dst = size(), size()
        if src != len(base):
            raise ValueError("delta: base size mismatch")
        if dst > MAX_MEMBER:
            raise ValueError("delta: result over the size cap")
        out = bytearray()
        n = len(delta)
        while pos < n:
            op = delta[pos]
            pos += 1
            if op & 0x80:
                off = length = 0
                for i in range(4):
                    if op & (1 << i):
                        off |= delta[pos] << (8 * i)
                        pos += 1
                for i in range(3):
                    if op & (0x10 << i):
                        length |= delta[pos] << (8 * i)
                        pos += 1
                length = length or 0x10000
                if off + length > len(base):
                    raise ValueError("delta: copy past the base")
                out += base[off:off + length]
            elif op:
                out += delta[pos:pos + op]
                pos += op
            else:
                raise ValueError("delta: opcode 0")
    except IndexError as e:
        raise ValueError("delta: truncated instruction") from e
    if len(out) != dst:
        raise ValueError("delta: result size mismatch")
    return bytes(out)


def parse_ident(text: str) -> dict:
    """'Name <email> 1700000000 +0100' as {name, email, time (int or None), tz}."""
    m = _IDENT.match(text)
    if not m:
        return {"name": text.strip(), "email": None, "time": None, "tz": None}
    return {"name": m.group(1).strip(), "email": m.group(2).strip(), "time": int(m.group(3)) if m.group(3) else None,
            "tz": m.group(4)}


class SnapshotHistory:
    """What every history that stores whole files answers the same way. A reader gives ids()
    (every commit, oldest first), parents(id), snapshot(id) -> {path: blob id}, blob(blob id),
    meta(id) and id_forms(id); the questions below are asked of those."""

    kind = "?"
    verified = False        # True only for a reader compared with the real tool's output
    complete = True
    label = ""

    def _blob_has(self, bid, needle: bytes) -> bool:
        cache = self.__dict__.setdefault("_has", {})
        key = (bid, needle)
        if key not in cache:
            body = self.blob(bid)
            if body is None:
                raise Incomplete(f"blob {bid} is not in the delivery")
            cache[key] = needle in body
        return cache[key]

    def has(self, cid, needle: bytes) -> bool:
        """True when a file of the commit holds the bytes."""
        cache = self.__dict__.setdefault("_chas", {})
        key = (cid, needle)
        if key not in cache:
            cache[key] = any(self._blob_has(b, needle) for b in set(self.snapshot(cid).values()))
        return cache[key]

    def adding(self, needle: bytes) -> list:
        """The commits that hold the bytes in a file while none of their parents does."""
        return [c for c in self.ids() if self.has(c, needle) and not any(self.has(p, needle) for p in self.parents(c))]

    def removing(self, needle: bytes) -> list:
        """The commits that do not hold the bytes while one of their parents does."""
        return [c for c in self.ids() if self.parents(c) and not self.has(c, needle)
                and any(self.has(p, needle) for p in self.parents(c))]

    def changes(self, cid) -> dict:
        """{path: (old blob id or None, new blob id or None)} of a commit against its first parent."""
        ps = self.parents(cid)
        a = self.snapshot(ps[0]) if ps else {}
        b = self.snapshot(cid)
        return {p: (a.get(p), b.get(p)) for p in sorted(set(a) | set(b)) if a.get(p) != b.get(p)}

    def deleted(self) -> list:
        """[(commit id, path)]: a path every parent has and the commit has not. A file that moved
        (the same or a similar content appears under a new path in that commit) is in renamed(),
        not here."""
        return [(c, p) for c, p, new, _ in self._gone() if new is None]

    def renamed(self) -> list:
        """[(commit id, old path, new path)]: the same content under a new path, or content at
        least 60% alike (git calls a file renamed from 50%)."""
        return [(c, p, new) for c, p, new, _ in self._gone() if new is not None]

    def deletions_in_doubt(self) -> list:
        """[(commit id, path)] of deleted() whose content is 40 to 60% like a file new in the same
        commit: deleted by this reading, renamed by another tool's. No answer rests on them."""
        return [(c, p) for c, p, new, doubt in self._gone() if doubt]

    def _alike(self, a, b) -> float:
        if a == b:
            return 1.0
        x, y = self.blob(a), self.blob(b)
        if x is None or y is None:
            return 0.0
        if x == y:
            return 1.0
        if not x or not y or max(len(x), len(y)) > (1 << 20) or min(len(x), len(y)) * 4 < max(len(x), len(y)):
            return 0.0
        import difflib
        return difflib.SequenceMatcher(None, x.splitlines(), y.splitlines(), autojunk=False).ratio()

    def _gone(self) -> list:
        if "_gone_rows" not in self.__dict__:
            rows = []
            for c in self.ids():
                ps = self.parents(c)
                if not ps:
                    continue
                now = self.snapshot(c)
                before = [self.snapshot(p) for p in ps]
                fresh = [(path, bid) for path, bid in now.items() if path not in before[0]][:200]
                for path, bid in before[0].items():
                    if path not in now and all(path in b for b in before[1:]):
                        best = max(((self._alike(bid, nb), np) for np, nb in fresh), default=(0.0, None))
                        rows.append((c, path, best[1] if best[0] >= 0.6 else None, 0.4 <= best[0] < 0.6))
            self.__dict__["_gone_rows"] = rows
        return self.__dict__["_gone_rows"]

    def by_message(self, needle: str) -> list:
        return [c for c in self.ids() if needle.lower() in (self.meta(c).get("message") or "").lower()]

    def find_commit(self, prefix: str) -> list:
        prefix = prefix.lower()
        return [c for c in self.ids() if any(str(v).lower().startswith(prefix) for _, v in self.id_forms(c)[:1])]

    def table(self) -> list:
        return [self.meta(c) for c in self.ids()]


class _Pack:
    """One packfile read front to back: no .idx is needed, and none is trusted."""

    def __init__(self, data: bytes, name: str, hl: int):
        self.name, self.data, self.hl = name, data, hl
        self.entries = {}       # offset -> (type number, base (offset or hex id or None), payload)
        self.problems = []
        self.complete = True
        if data[:4] != b"PACK" or len(data) < 12:
            raise ValueError("not a packfile")
        version, count = struct.unpack_from(">II", data, 4)
        if version not in (2, 3):
            raise ValueError(f"pack version {version}")
        if count > MAX_OBJECTS:
            self.complete = False
            self.problems.append(f"{name}: {count} objects, over the cap")
            return
        pos = 12
        for _ in range(count):
            start = pos
            try:
                b = data[pos]
                pos += 1
                typ, shift = (b >> 4) & 7, 4
                while b & 0x80:
                    b = data[pos]
                    pos += 1
                    shift += 7
                base = None
                if typ == 6:
                    b = data[pos]
                    pos += 1
                    off = b & 0x7F
                    while b & 0x80:
                        b = data[pos]
                        pos += 1
                        off = ((off + 1) << 7) | (b & 0x7F)
                    base = start - off
                elif typ == 7:
                    base = data[pos:pos + hl].hex()
                    pos += hl
                elif typ not in _GIT_TYPES:
                    raise ValueError(f"object type {typ}")
                payload, used = _inflate_at(data, pos)
                pos += used
            except (IndexError, ValueError) as e:
                self.complete = False
                self.problems.append(f"{name}: unreadable from offset {start} ({e}); {count - len(self.entries)} object(s) not read")
                return
            if payload is None:
                self.complete = False
                self.problems.append(f"{name}: the object at offset {start} is over the size cap")
                continue
            self.entries[start] = (typ, base, payload)


_GIT_TOP_FILES = frozenset("""HEAD ORIG_HEAD FETCH_HEAD MERGE_HEAD MERGE_MSG MERGE_MODE MERGE_RR MERGE_AUTOSTASH
    CHERRY_PICK_HEAD REVERT_HEAD REBASE_HEAD AUTO_MERGE BISECT_HEAD BISECT_LOG BISECT_START BISECT_TERMS BISECT_NAMES
    BISECT_EXPECTED_REV BISECT_ANCESTORS_OK BISECT_RUN BISECT_FIRST_PARENT COMMIT_EDITMSG SQUASH_MSG TAG_EDITMSG
    NOTES_EDITMSG EDIT_DESCRIPTION ADD_EDIT.patch config config.worktree description index packed-refs shallow commondir
    gitdir gc.log gc.pid gitk.cache pack""".split())
_GIT_TOP_DIRS = ("branches/", "modules/", "worktrees/", "rebase-merge/", "rebase-apply/", "lfs/", "rr-cache/", "svn/",
                 "sequencer/", "reftable/", "remotes/", "fsmonitor--daemon/", "filter-repo/")
_GIT_DESCRIPTION = b"Unnamed repository; edit this file 'description' to name the repository."
_GIT_OBJECT_FILE = re.compile(r"objects/(?:pack/(?:pack-[0-9a-f]+\.(?:pack|idx|rev|bitmap|keep|mtimes|promisor)|multi-pack-index[^/]*|tmp_[^/]+)"
                              r"|info/(?:packs|alternates|http-alternates|commit-graph|commit-graphs/[^/]+)"
                              r"|[0-9a-f]{2}/tmp_obj_[^/]+)")
_GIT_INFO_FILES = frozenset(("info/exclude", "info/attributes", "info/refs", "info/grafts", "info/sparse-checkout"))
_GIT_REFLOG_LINE = re.compile(rb"[0-9a-f]{40,64} [0-9a-f]{40,64} [^\n]*")


def _git_nonstandard(path: str, data: bytes, hexlen: int):
    """Why a file of a git directory is not one git writes (a short reason), or None for one that is."""
    top = path.split("/", 1)[0]
    if "/" not in path:
        if path == "description" and data.strip() not in (b"", _GIT_DESCRIPTION):
            return "the description file was edited"
        if path in _GIT_TOP_FILES or path.startswith(("sharedindex.", "index.")) or path.endswith(".lock"):
            return None
        return "not a file git writes"
    if path.startswith(_GIT_TOP_DIRS):
        return None
    if top == "objects":
        m = re.fullmatch(r"objects/([0-9a-f]{2})/([0-9a-f]+)", path)
        if (m and len(m.group(1) + m.group(2)) == hexlen) or _GIT_OBJECT_FILE.fullmatch(path):
            return None
        return "under objects/ but not an object, a pack or an index of one"
    if top == "refs":
        text = data.strip()
        if re.fullmatch(rb"[0-9a-f]{40,64}", text) or text.startswith(b"ref:") or path.endswith(".lock"):
            return None
        return "a ref file that holds no object id"
    if top == "logs":
        lines = [ln for ln in data.split(b"\n") if ln.strip()]
        if all(_GIT_REFLOG_LINE.match(ln) for ln in lines):
            return None
        return "a reflog file with lines that are no reflog entries"
    if top == "hooks":
        return None if path.endswith(".sample") else "a hook that is not a sample (a real git would run it; here it is only read)"
    if top == "info":
        return None if path in _GIT_INFO_FILES else "not a file git writes"
    return "not a file git writes"


class GitRepo(SnapshotHistory):
    """A git repository read from its bytes: `tree` is {path inside the git directory: bytes}
    ('HEAD', 'objects/ab/cd...', 'objects/pack/pack-x.pack', 'refs/heads/main', 'logs/HEAD', 'index').

    problems lists what could not be read; complete is False when an answer that needs every
    object (exactly one commit added it, the only dangling blob) can no longer be proven."""

    kind = "git"
    verified = True         # compared with the real git's output: tests/test_tk_repo_supply_chain.py, test_against_real_git
    container = ""          # set by find_git: the archive the repository came out of ('' = none)
    root = ""               # set by find_git: the git directory's path with its '/' ('' = the top), or a lone pack's path

    def __init__(self, tree: dict, label: str = "", worktree: dict = None, extra_refs: dict = None):
        self.t, self.label, self.worktree = tree, label, worktree or {}
        self.problems, self.complete = [], True
        cfg = tree.get("config", b"")
        self.hashname = "sha256" if re.search(rb"objectformat\s*=\s*sha256", cfg, re.I) else "sha1"
        self.hl = 32 if self.hashname == "sha256" else 20
        self.objects = {}           # hex id -> (type name, bytes)
        self._flat, self._has = {}, {}
        self._extra_refs = dict(extra_refs or {})
        self._load()

    # -- objects

    def _hash(self, typ: str, body: bytes) -> str:
        return hashlib.new(self.hashname, f"{typ} {len(body)}".encode() + b"\x00" + body).hexdigest()

    def _load(self):
        hexlen = self.hl * 2
        for path, raw in self.t.items():
            m = re.fullmatch(r"objects/([0-9a-f]{2})/([0-9a-f]+)", path)
            if not m or len(m.group(1) + m.group(2)) != hexlen:
                continue
            name = m.group(1) + m.group(2)
            try:
                data = inflate(raw)
                head, sep, body = data.partition(b"\x00")
                typ, size = head.decode("ascii").split(" ")
                if not sep or typ not in _GIT_TYPES.values() or int(size) != len(body):
                    raise ValueError("bad object header")
            except (ValueError, UnicodeDecodeError) as e:
                self.complete = False
                self.problems.append(f"loose object {name}: unreadable ({str(e)[:60]})")
                continue
            actual = self._hash(typ, body)
            if actual != name:
                self.problems.append(f"loose object {name}: its content hashes to {actual} (filed under the wrong name)")
            self.objects[name] = (typ, body)
            if len(self.objects) > MAX_OBJECTS:
                self.complete = False
                self.problems.append("more loose objects than the cap")
                break
        packs = []
        for path, raw in sorted(self.t.items()):
            if raw[:4] == b"PACK" and (path.endswith(".pack") or path == "pack"):
                try:
                    packs.append(_Pack(raw, path, self.hl))
                except ValueError as e:
                    self.complete = False
                    self.problems.append(f"{path}: {e}")
        # Resolve every pack entry. A REF delta's base may sit in another pack or among the loose
        # objects (a thin pack), so go round until nothing more resolves.
        done = {}                   # (pack index, offset) -> (type name, bytes)
        pending = [(i, off) for i, p in enumerate(packs) for off in p.entries]
        progress = True
        while pending and progress:
            progress, left = False, []
            for i, off in pending:
                got = self._resolve(packs, i, off, done)
                if got is None:
                    left.append((i, off))
                    continue
                progress = True
                self.objects.setdefault(self._hash(*got), got)
            pending = left
        for p in packs:
            self.problems += p.problems
            self.complete = self.complete and p.complete
        if pending:
            self.complete = False
            self.problems.append(f"{len(pending)} delta object(s) whose base is not in the delivery (a thin pack or a broken one)")
        # Every object another one points to must be here, or "exactly one commit" cannot be proven.
        missing = set()
        for oid, (typ, _) in self.objects.items():
            if typ == "commit":
                c = self.commit(oid)
                missing.update(o for o in [c["tree"]] + c["parents"] if o not in self.objects)
            elif typ == "tree":
                try:
                    missing.update(o for mode, _, o in self.tree_entries(oid) if mode != "160000" and o not in self.objects)
                except Incomplete:
                    missing.add(oid)
            elif typ == "tag":
                missing.update(o for o in [self.tag(oid)["object"]] if o not in self.objects)
        missing.update(o for o in self.refs().values() if o not in self.objects)
        if missing:
            self.complete = False
            self.problems.append(f"{len(missing)} object(s) are pointed to but not in the delivery "
                                 f"(a shallow or partial copy): {', '.join(sorted(str(m)[:12] for m in missing)[:5])}")

    def _resolve(self, packs, i, off, done):
        chain = []
        cur = (i, off)
        base = None
        while True:
            if cur in done:
                base = done[cur]
                break
            entry = packs[cur[0]].entries.get(cur[1])
            if entry is None or len(chain) > MAX_DELTA_CHAIN:
                return None
            typ, ref, payload = entry
            if typ in _GIT_TYPES:
                base = (_GIT_TYPES[typ], payload)
                done[cur] = base
                break
            chain.append((cur, payload))
            if typ == 6:
                cur = (cur[0], ref)
            else:
                if ref not in self.objects:
                    return None
                base = self.objects[ref]
                break
        typ, body = base
        for key, delta in reversed(chain):
            try:
                body = apply_git_delta(body, delta)
            except (ValueError, IndexError) as e:
                self.problems.append(f"{packs[key[0]].name}: delta at offset {key[1]} does not apply ({e})")
                self.complete = False
                packs[key[0]].entries.pop(key[1], None)
                return None
            done[key] = (typ, body)
        return typ, body

    def get(self, oid: str):
        """(type, bytes) of an object, or None."""
        return self.objects.get(oid)

    def resolve_prefix(self, prefix: str) -> list:
        prefix = prefix.lower()
        return sorted(o for o in self.objects if o.startswith(prefix))

    def blob(self, oid: str):
        got = self.objects.get(oid)
        return got[1] if got and got[0] == "blob" else None

    # -- files git did not put there (B-070)

    def nonstandard(self) -> list:
        """[{path, size, why}] of the files in the git directory that a git of its own does not
        write: a note dropped beside HEAD, a file under objects/ that is no object, a hook that is
        not a sample, a ref file holding no object id, a reflog file with lines that are no reflog
        entries, an edited `description`. Sorted by path. This is where an author parks a hint or a
        fragment: the git directory is in no commit, so no history shows it."""
        out = []
        for path in sorted(self.t):
            why = _git_nonstandard(path, self.t[path], self.hl * 2)
            if why:
                out.append({"path": path, "size": len(self.t[path]), "why": why})
        return out

    # -- refs, reflog, stash, index

    def refs(self) -> dict:
        """{ref name: object id}: refs/**, packed-refs, a bundle's refs; a symbolic ref is followed."""
        raw = dict(self._extra_refs)
        for line in self.t.get("packed-refs", b"").decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 2 and not line.startswith(("#", "^")) and re.fullmatch(r"[0-9a-f]{40,64}", parts[0]):
                raw[parts[1]] = parts[0]
        for path, data in self.t.items():
            if path.startswith("refs/") and not path.endswith(".lock"):
                raw[path] = data.decode("utf-8", "replace").strip()
        out = {}
        for name in raw:
            value, hops = raw[name], 0
            while value.startswith("ref:") and hops < 8:
                value, hops = raw.get(value[4:].strip(), ""), hops + 1
            if re.fullmatch(r"[0-9a-f]{40,64}", value):
                out[name] = value
        return out

    def head(self) -> dict:
        """{'ref': 'refs/heads/main' or None, 'id': the commit or None}."""
        text = self.t.get("HEAD", b"").decode("utf-8", "replace").strip()
        if text.startswith("ref:"):
            name = text[4:].strip()
            return {"ref": name, "id": self.refs().get(name)}
        if not text and self._extra_refs.get("HEAD"):          # a bundle lists HEAD among its refs
            tip = self._extra_refs["HEAD"]
            named = sorted(n for n, v in self._extra_refs.items() if v == tip and n.startswith("refs/heads/"))
            return {"ref": named[0] if len(named) == 1 else None, "id": tip}
        return {"ref": None, "id": text if re.fullmatch(r"[0-9a-f]{40,64}", text) else None}

    def pseudo_heads(self) -> dict:
        out = {}
        for name in ("ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_HEAD", "AUTO_MERGE"):
            for m in re.finditer(r"^([0-9a-f]{40,64})\b", self.t.get(name, b"").decode("utf-8", "replace"), re.M):
                out.setdefault(name, []).append(m.group(1))
        return out

    def reflog(self) -> list:
        """Every line of logs/**: {ref, old, new, name, email, time, tz, message}, in file order."""
        out = []
        for path in sorted(self.t):
            if not path.startswith("logs/"):
                continue
            for line in self.t[path].decode("utf-8", "replace").splitlines():
                head, _, message = line.partition("\t")
                m = re.match(r"([0-9a-f]{40,64}) ([0-9a-f]{40,64}) (.*)$", head)
                if m:
                    out.append({"ref": path[5:], "old": m.group(1), "new": m.group(2), **parse_ident(m.group(3)), "message": message})
        return out

    def stashes(self) -> list:
        """The stash entries, newest first: {index, id, message, parents, files (changed against the base)}."""
        ids = [e["new"] for e in self.reflog() if e["ref"] == "refs/stash"]
        tip = self.refs().get("refs/stash")
        if tip and tip not in ids:
            ids.append(tip)
        out = []
        for n, oid in enumerate(reversed(ids)):
            c = self.commit(oid)
            if c is None:
                out.append({"index": n, "id": oid, "message": None, "parents": [], "files": None})
                continue
            try:
                files = self.diff(c["parents"][0] if c["parents"] else None, oid)
            except Incomplete:
                files = None
            out.append({"index": n, "id": oid, "message": c["message"], "parents": c["parents"], "files": files})
        return out

    def index(self) -> list:
        """The entries of the index file: {path, id, mode, size, mtime, stage}. [] when there is none."""
        data = self.t.get("index", b"")
        if data[:4] != b"DIRC" or len(data) < 12:
            return []
        version, count = struct.unpack_from(">II", data, 4)
        if version not in (2, 3, 4) or count > MAX_OBJECTS:
            self.problems.append(f"index: version {version} with {count} entries is not read")
            return []
        pos, out, prev = 12, [], b""
        try:
            for _ in range(count):
                start = pos
                _, _, mtime, _, _, _, mode, _, _, size = struct.unpack_from(">10I", data, pos)
                pos += 40
                oid = data[pos:pos + self.hl].hex()
                pos += self.hl
                flags = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                if version >= 3 and flags & 0x4000:
                    pos += 2
                if version == 4:
                    b = data[pos]
                    pos += 1
                    strip = b & 0x7F
                    while b & 0x80:
                        b = data[pos]
                        pos += 1
                        strip = ((strip + 1) << 7) | (b & 0x7F)
                    end = data.index(b"\x00", pos)
                    path = prev[:len(prev) - strip] + data[pos:end]
                    pos = end + 1
                else:
                    end = data.index(b"\x00", pos)
                    path = data[pos:end]
                    pos = start + ((end - start + 8) // 8) * 8
                prev = path
                out.append({"path": path.decode("utf-8", "replace"), "id": oid, "mode": f"{mode:o}", "size": size,
                            "mtime": mtime, "stage": (flags >> 12) & 3})
        except (struct.error, ValueError, IndexError):
            self.problems.append(f"index: unreadable after {len(out)} of {count} entries")
        return out

    # -- commits, trees, tags

    def commit(self, oid: str):
        """A commit as {id, tree, parents, author, email, time, tz, committer, committer_email,
        committer_time, committer_tz, message, signed}; None when oid is not a commit here."""
        got = self.objects.get(oid)
        if not got or got[0] != "commit":
            return None
        head, _, message = got[1].partition(b"\n\n")
        c = {"id": oid, "tree": None, "parents": [], "author": None, "email": None, "time": None, "tz": None,
             "committer": None, "committer_email": None, "committer_time": None, "committer_tz": None,
             "signed": False, "encoding": None}
        for line in head.decode("utf-8", "replace").split("\n"):
            key, _, value = line.partition(" ")
            if key == "tree":
                c["tree"] = value.strip()
            elif key == "parent":
                c["parents"].append(value.strip())
            elif key == "author":
                i = parse_ident(value)
                c.update(author=i["name"], email=i["email"], time=i["time"], tz=i["tz"])
            elif key == "committer":
                i = parse_ident(value)
                c.update(committer=i["name"], committer_email=i["email"], committer_time=i["time"], committer_tz=i["tz"])
            elif key in ("gpgsig", "gpgsig-sha256"):
                c["signed"] = True
            elif key == "encoding":
                c["encoding"] = value.strip()
        try:
            c["message"] = message.decode(c["encoding"] or "utf-8", "replace")
        except LookupError:
            c["message"] = message.decode("utf-8", "replace")
        return c

    def tag(self, oid: str):
        got = self.objects.get(oid)
        if not got or got[0] != "tag":
            return None
        head, _, message = got[1].partition(b"\n\n")
        t = {"id": oid, "object": None, "type": None, "tag": None, "tagger": None, "email": None, "time": None, "tz": None,
             "message": message.decode("utf-8", "replace")}
        for line in head.decode("utf-8", "replace").split("\n"):
            key, _, value = line.partition(" ")
            if key in ("object", "type", "tag"):
                t[key] = value.strip()
            elif key == "tagger":
                i = parse_ident(value)
                t.update(tagger=i["name"], email=i["email"], time=i["time"], tz=i["tz"])
        return t

    def tree_entries(self, oid: str) -> list:
        """[(mode, name, id)] of one tree object; Incomplete when it is missing or broken."""
        got = self.objects.get(oid)
        if not got or got[0] != "tree":
            raise Incomplete(f"tree {oid} is not in the delivery")
        data, pos, out = got[1], 0, []
        while pos < len(data):
            sp = data.find(b" ", pos)
            nul = data.find(b"\x00", sp)
            if sp < 0 or nul < 0 or nul + 1 + self.hl > len(data):
                raise Incomplete(f"tree {oid} is broken")
            out.append((data[pos:sp].decode("ascii", "replace"), data[sp + 1:nul].decode("utf-8", "replace"),
                        data[nul + 1:nul + 1 + self.hl].hex()))
            pos = nul + 1 + self.hl
        return out

    def flat(self, tree: str, depth: int = 0) -> dict:
        """{path: (mode, blob id)} of a tree, every level; submodule links (mode 160000) included."""
        if tree in self._flat:
            return self._flat[tree]
        if depth > 200:
            raise Incomplete("a tree nested deeper than 200 folders is not read")
        out = {}
        for mode, name, oid in self.tree_entries(tree):
            if mode in ("40000", "040000"):
                for sub, value in self.flat(oid, depth + 1).items():
                    out[f"{name}/{sub}"] = value
            else:
                out[name] = (mode, oid)
        self._flat[tree] = out
        return out

    def snapshot(self, commit_id: str) -> dict:
        """{path: blob id} of a commit; Incomplete when the commit or one of its trees is missing."""
        c = self.commit(commit_id)
        if c is None or not c["tree"]:
            raise Incomplete(f"commit {commit_id} is not in the delivery")
        return {p: oid for p, (mode, oid) in self.flat(c["tree"]).items() if mode != "160000"}

    def diff(self, old, new) -> dict:
        """{path: (old blob id or None, new blob id or None)} between two commits (old None: against nothing)."""
        a = self.snapshot(old) if old else {}
        b = self.snapshot(new) if new else {}
        return {p: (a.get(p), b.get(p)) for p in sorted(set(a) | set(b)) if a.get(p) != b.get(p)}

    def ids(self) -> list:
        """Every commit object, reachable or not, oldest first."""
        rows = [self.commit(o) for o, (t, _) in self.objects.items() if t == "commit"]
        return [c["id"] for c in sorted(rows, key=lambda c: (c["committer_time"] or c["time"] or 0, c["id"]))]

    def parents(self, cid: str) -> list:
        c = self.commit(cid)
        return c["parents"] if c else []

    def meta(self, cid: str) -> dict:
        c = self.commit(cid) or {}
        return {"id": cid, "author": c.get("author"), "email": c.get("email"), "time": c.get("time"), "tz": c.get("tz"),
                "committer": c.get("committer"), "committer_email": c.get("committer_email"),
                "committer_time": c.get("committer_time"), "message": c.get("message")}

    def id_forms(self, oid: str) -> list:
        """The ways a git object id is written: the full id, then the 7-character one when it is unique here."""
        forms = [("full", oid)]
        if len(self.resolve_prefix(oid[:7])) == 1:
            forms.append(("short7", oid[:7]))
        return forms

    # -- reachability

    def _closure(self, roots) -> set:
        seen, stack = set(), [r for r in roots if r in self.objects]
        while stack:
            oid = stack.pop()
            if oid in seen:
                continue
            seen.add(oid)
            typ, body = self.objects[oid]
            nxt = []
            if typ == "commit":
                c = self.commit(oid)
                nxt = [c["tree"]] + c["parents"]
            elif typ == "tree":
                try:
                    nxt = [o for mode, _, o in self.tree_entries(oid) if mode != "160000"]
                except Incomplete:
                    nxt = []
            elif typ == "tag":
                nxt = [self.tag(oid)["object"]]
            stack.extend(o for o in nxt if o and o in self.objects and o not in seen)
        return seen

    def reach(self) -> dict:
        """How each object is reached:
          refs         from a ref (branches, tags, remotes, refs/stash) or HEAD
          reflog       only from a reflog line or ORIG_HEAD, FETCH_HEAD and the like
          index        only from the index
          unreachable  from none of them (git fsck --unreachable)
        and `dangling`: the unreachable objects no other unreachable object points to (git fsck's
        'dangling' lines); `no_ref`: everything no ref reaches (git fsck --unreachable --no-reflogs,
        but for the index)."""
        if getattr(self, "_reach", None) is None:
            head = self.head()["id"]
            a = self._closure(list(self.refs().values()) + ([head] if head else []))
            log = [x for e in self.reflog() for x in (e["old"], e["new"])] + [x for v in self.pseudo_heads().values() for x in v]
            b = self._closure(log) - a
            i = self._closure([e["id"] for e in self.index()]) - a - b
            lost = set(self.objects) - a - b - i
            pointed = self._pointed(lost)
            no_ref = set(self.objects) - a - i
            self._reach = {"refs": a, "reflog": b, "index": i, "unreachable": lost, "dangling": lost - pointed,
                           "no_ref": no_ref, "dangling_no_reflog": no_ref - self._pointed(no_ref)}
        return self._reach

    def _pointed(self, group) -> set:
        """Every object that an object of the group points to."""
        pointed = set()
        for oid in group:
            typ, _ = self.objects[oid]
            if typ == "commit":
                c = self.commit(oid)
                pointed.update([c["tree"]] + c["parents"])
            elif typ == "tree":
                try:
                    pointed.update(o for _, _, o in self.tree_entries(oid))
                except Incomplete:
                    pass
            elif typ == "tag":
                pointed.add(self.tag(oid)["object"])
        return pointed

    def lost(self, typ: str, dangling: bool):
        """The objects of one type that a question about 'the dangling ...' (git fsck's dangling
        lines) or 'the unreachable ...' can mean. With a reflog there are two readings of each
        (git fsck, and git fsck --no-reflogs); an empty reading cannot be what a question means, so
        the answer is the set the non-empty readings agree on, or None when they differ."""
        r = self.reach()
        names = ("dangling", "dangling_no_reflog") if dangling else ("unreachable", "no_ref")
        sets = [frozenset(o for o in r[n] if self.objects[o][0] == typ) for n in names]
        sets = {s for s in sets if s}
        return sorted(next(iter(sets))) if len(sets) == 1 else None

    def where(self, oid: str) -> str:
        r = self.reach()
        return next((k for k in ("refs", "reflog", "index") if oid in r[k]), "unreachable")

    def branches_with(self, cid: str) -> list:
        """The local branches whose history holds the commit."""
        return sorted(name[len("refs/heads/"):] for name, tip in self.refs().items()
                      if name.startswith("refs/heads/") and cid in self._closure_commits(tip))

    def _closure_commits(self, tip: str) -> set:
        seen, stack = set(), [tip]
        while stack:
            oid = stack.pop()
            if oid in seen or self.commit(oid) is None:
                continue
            seen.add(oid)
            stack.extend(self.commit(oid)["parents"])
        return seen

    def all_blobs(self):
        """(blob id, bytes) of every blob object, wherever it hangs."""
        for oid, (typ, body) in self.objects.items():
            if typ == "blob":
                yield oid, body

    def blob_paths(self) -> dict:
        """{blob id: [(commit id, path), ...]} for every blob a commit's tree holds (the oldest commit first)."""
        if getattr(self, "_paths", None) is None:
            out = {}
            for cid in self.ids():
                try:
                    snap = self.snapshot(cid)
                except Incomplete:
                    continue
                for path, oid in snap.items():
                    rows = out.setdefault(oid, [])
                    if not any(p == path for _, p in rows):
                        rows.append((cid, path))
            self._paths = out
        return self._paths


def read_bundle(data: bytes):
    """(refs, pack bytes) of a git bundle (v2 or v3); ValueError when data is not one."""
    m = re.match(rb"# v([23]) git bundle\n", data)
    if not m:
        raise ValueError("not a git bundle")
    end = data.find(b"\n\n", m.end() - 1)
    if end < 0:
        raise ValueError("bundle header without an end")
    refs = {}
    for line in data[m.end():end].decode("utf-8", "replace").splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{40,64}", parts[0]):
            refs[parts[1].strip()] = parts[0]
    return refs, data[end + 2:]


def _roots(entries, rx) -> dict:
    """{(container, root): {path under root: bytes}} for every path a marker pattern matches."""
    marks = {}
    for container, path, _ in entries:
        m = rx.match(path)
        if m:
            marks.setdefault((container, m.group("root")), 0)
            marks[(container, m.group("root"))] += 1
    out = {}
    for (container, root) in marks:
        out[(container, root)] = {p[len(root):]: d for c, p, d in entries if c == container and p.startswith(root)}
    return out


_GIT_MARK = re.compile(r"^(?P<root>(?:.*/)?)(?:objects/[0-9a-f]{2}/[0-9a-f]{38,62}|objects/pack/[^/]+\.pack)$")
_GIT_HEAD = re.compile(r"^(?P<root>(?:.*/)?)HEAD$")
_HG_MARK = re.compile(r"^(?P<root>(?:.*/)?\.hg/)(?:store/)?00changelog\.i$")
_DARCS_MARK = re.compile(r"^(?P<root>(?:.*/)?_darcs/)(?:patches/[^/]+|hashed_inventory|inventory)$")


def find_git(entries) -> list:
    """Every git repository among the files: a git directory (with or without a work tree around
    it), a bare repository, a lone packfile, a bundle."""
    trees = _roots(entries, _GIT_MARK)
    for key, tree in _roots(entries, _GIT_HEAD).items():
        head = tree.get("HEAD", b"")[:80]
        if key not in trees and (head.startswith(b"ref: refs/") or re.fullmatch(rb"[0-9a-f]{40,64}\s*", head)) \
                and any(p.startswith("refs/") or p == "packed-refs" for p in tree):
            trees[key] = tree
    out, inside = [], set()
    for (container, root), tree in sorted(trees.items()):
        work = {}
        if root.endswith(".git/"):
            parent = root[:-5]
            work = {p[len(parent):]: d for c, p, d in entries if c == container and p.startswith(parent) and not p.startswith(root)}
        label = (container + ARROW if container else "") + (root or "./")
        out.append(GitRepo(tree, label.rstrip("/") or ".", work))
        out[-1].container, out[-1].root = container, root
        inside.update(id(d) for d in tree.values())
    for container, path, data in entries:
        if id(data) in inside:
            continue
        name = (container + ARROW if container else "") + path
        before = len(out)
        try:
            if data[:4] == b"PACK":
                out.append(GitRepo({"pack": data}, name))
            elif data[:6] == b"# v2 g" or data[:6] == b"# v3 g":
                refs, pack = read_bundle(data)
                out.append(GitRepo({"pack": pack}, name, extra_refs=refs))
        except ValueError:
            pass
        for repo in out[before:]:
            repo.container, repo.root = container, path
    return out


# ---- mercurial ---------------------------------------------------------------------------------------

def _hg_chunk(c: bytes) -> bytes:
    if not c or c[:1] == b"\x00":
        return c
    if c[:1] == b"x":
        return inflate(c)
    if c[:1] == b"u":
        return c[1:]
    if c[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(c)
    raise ValueError(f"revlog chunk of unknown kind {c[:1]!r}")


def _hg_patch(base: bytes, delta: bytes) -> bytes:
    out, last, pos = [], 0, 0
    while pos < len(delta):
        start, end, size = struct.unpack_from(">III", delta, pos)
        pos += 12
        if start < last or end < start or pos + size > len(delta):
            raise ValueError("revlog delta out of order")
        out += [base[last:start], delta[pos:pos + size]]
        pos += size
        last = end
    out.append(base[last:])
    return b"".join(out)


def read_revlog(index: bytes, data: bytes = None) -> list:
    """The revisions of a Mercurial revlog (version 1): [{rev, node, p1, p2 (revision numbers, -1
    for none), linkrev, text, ok (the node is the hash of the text)}]. `data` is the .d file of a
    revlog that is not inline. ValueError for another version or a broken file."""
    if len(index) < 64:
        return []
    header = struct.unpack_from(">I", index, 0)[0]
    version, flags = header & 0xFFFF, header >> 16
    if version != 1:
        raise ValueError(f"revlog version {version} is not read")
    inline, general = bool(flags & 1), bool(flags & 2)
    rows, texts, pos = [], [], 0
    null = b"\x00" * 20
    while pos + 64 <= len(index):
        off_flags, clen, _, base, link, p1, p2 = struct.unpack_from(">Qiiiiii", index, pos)
        node = index[pos + 32:pos + 52]
        offset = 0 if not rows else off_flags >> 16
        pos += 64
        if clen < 0:
            raise ValueError("revlog entry with a negative length")
        if inline:
            chunk = index[pos:pos + clen]
            pos += clen
        else:
            chunk = (data or b"")[offset:offset + clen]
        if len(chunk) != clen:
            raise ValueError("revlog data is shorter than its index says")
        rev = len(rows)
        body = _hg_chunk(chunk)
        if base == rev or base < 0:
            text = body
        else:
            src = base if general else rev - 1
            if not 0 <= src < rev:
                raise ValueError("revlog delta against a later revision")
            text = _hg_patch(texts[src], body)
        if len(text) > MAX_MEMBER:
            raise ValueError("revlog text over the size cap")
        texts.append(text)
        n1 = rows[p1]["node"] if 0 <= p1 < rev else null
        n2 = rows[p2]["node"] if 0 <= p2 < rev else null
        ok = hashlib.sha1(min(n1, n2) + max(n1, n2) + text).digest() == node
        rows.append({"rev": rev, "node": node, "p1": p1, "p2": p2, "linkrev": link, "text": text, "ok": ok})
        if len(rows) > MAX_OBJECTS:
            raise ValueError("revlog with more revisions than the cap")
    return rows


class HgRepo(SnapshotHistory):
    """A Mercurial repository from the bytes under its .hg folder."""

    kind = "mercurial"
    verified = True         # compared with the real hg's output (five store formats) on 2026-10-08, see the quick reference

    def __init__(self, tree: dict, label: str = ""):
        self.t, self.label, self.problems, self.complete = tree, label, [], True
        self._commits, self._manifests, self._files = {}, {}, {}
        self._order = []
        store = "store/" if "store/00changelog.i" in tree else ""

        def log(name):
            idx = tree.get(name + ".i")
            if idx is None:
                return []
            try:
                rows = read_revlog(idx, tree.get(name + ".d"))
            except (ValueError, struct.error, IndexError, ImportError) as e:
                self.complete = False
                self.problems.append(f"{name}.i: {str(e)[:80]}")
                return []
            bad = [r["rev"] for r in rows if not r["ok"]]
            if bad:
                self.problems.append(f"{name}.i: revision(s) {bad[:5]} do not hash to their node")
            return rows
        change = log(store + "00changelog")
        for r in change:
            head, _, message = r["text"].partition(b"\n\n")
            lines = head.decode("utf-8", "replace").split("\n")
            if len(lines) < 3:
                self.complete = False
                self.problems.append(f"changeset {r['rev']}: unreadable")
                continue
            when = lines[2].split(" ", 2)
            ident = parse_ident(lines[1])
            try:
                stamp, offset = int(float(when[0])), int(when[1])
            except (ValueError, IndexError):
                stamp, offset = None, 0
            tz = "%s%02d%02d" % ("-" if offset > 0 else "+", abs(offset) // 3600, abs(offset) % 3600 // 60)
            extra = when[2] if len(when) > 2 else ""
            cid = r["node"].hex()
            self._order.append(cid)
            self._commits[cid] = {"id": cid, "rev": r["rev"], "manifest": lines[0].strip(),
                                  "parents": [change[p]["node"].hex() for p in (r["p1"], r["p2"]) if 0 <= p < len(change)],
                                  "author": ident["name"] if ident["email"] is not None else lines[1].strip(),
                                  "email": ident["email"] if ident["email"] is not None else
                                  (lines[1].strip() if re.fullmatch(r"\S+@\S+", lines[1].strip()) else None),
                                  "time": stamp, "tz": tz, "message": message.decode("utf-8", "replace"),
                                  "files": lines[3:], "branch": (re.search(r"branch:([^\x00]*)", extra) or [None, "default"])[1]}
        for r in log(store + "00manifest"):
            self._manifests[r["node"].hex()] = r["text"]
        for path in sorted(tree):
            if path.startswith(store + "data/") and path.endswith(".i"):
                for r in log(path[:-2]):
                    text = r["text"]
                    if text.startswith(b"\x01\n"):
                        end = text.find(b"\x01\n", 2)
                        text = text[end + 2:] if end >= 0 else text
                    self._files[r["node"].hex()] = text

    def ids(self):
        return list(self._order)

    def parents(self, cid):
        return self._commits[cid]["parents"]

    def meta(self, cid):
        c = self._commits[cid]
        return {k: c.get(k) for k in ("id", "author", "email", "time", "tz", "message", "rev", "branch")}

    def id_forms(self, cid):
        return [("full", cid), ("short12", cid[:12]), ("rev", str(self._commits[cid]["rev"]))]

    def snapshot(self, cid):
        text = self._manifests.get(self._commits[cid]["manifest"])
        if text is None:
            if set(self._commits[cid]["manifest"]) == {"0"}:
                return {}
            raise Incomplete(f"manifest of changeset {cid[:12]} is not in the delivery")
        out = {}
        for line in text.split(b"\n"):
            path, sep, node = line.partition(b"\x00")
            if sep:
                out[path.decode("utf-8", "replace")] = node[:40].decode("ascii", "replace")
        return out

    def blob(self, bid):
        return self._files.get(bid)

    def all_blobs(self):
        return self._files.items()


# ---- subversion --------------------------------------------------------------------------------------

def _svn_props(data: bytes) -> dict:
    """The K/V property block of a dump record or a revprops file."""
    out, pos = {}, 0
    while True:
        m = re.compile(rb"K (\d+)\n").match(data, pos)
        if not m:
            return out
        klen = int(m.group(1))
        key = data[m.end():m.end() + klen]
        m2 = re.compile(rb"V (\d+)\n").match(data, m.end() + klen + 1)
        if not m2:
            return out
        vlen = int(m2.group(1))
        out[key.decode("utf-8", "replace")] = data[m2.end():m2.end() + vlen].decode("utf-8", "replace")
        pos = m2.end() + vlen + 1


def _epoch(text: str):
    """Seconds since 1970 of an ISO-8601 time taken as UTC unless it says otherwise; None when it is not one."""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d))?(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?", text or "")
    if not m:
        return None
    import calendar
    try:
        t = calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                             int(m.group(6) or 0)))
    except (ValueError, OverflowError):
        return None
    z = m.group(7)
    if z and z != "Z":
        sign = -1 if z[0] == "-" else 1
        t -= sign * (int(z[1:3]) * 3600 + int(z[-2:]) * 60)
    return t


class SvnDump(SnapshotHistory):
    """A Subversion dump file (svnadmin dump). Full texts are read; a delta dump (--deltas) is
    listed but its file contents are not rebuilt, and the history is then not complete."""

    kind = "svn"

    def __init__(self, data: bytes, label: str = ""):
        self.label, self.problems, self.complete = label, [], True
        self._revs, self._snaps, self._blobs = {}, {}, {}
        self.uuid = None
        pos, rev, snap, n = 0, None, {}, len(data)

        def close():
            if rev is not None:
                self._snaps[rev] = dict(snap)
        while pos < n:
            if data[pos:pos + 1] == b"\n":
                pos += 1
                continue
            end = data.find(b"\n\n", pos)
            if end < 0:
                break
            head = {}
            for line in data[pos:end].decode("utf-8", "replace").split("\n"):
                k, sep, v = line.partition(": ")
                if sep:
                    head[k] = v
            pos = end + 2
            try:
                size = int(head.get("Content-length", 0))
                plen = int(head.get("Prop-content-length", 0))
            except ValueError:
                self.complete = False
                self.problems.append("dump record with an unreadable length")
                break
            body = data[pos:pos + size]
            pos += size
            if "UUID" in head:
                self.uuid = head["UUID"]
            if "Revision-number" in head:
                close()
                rev = int(head["Revision-number"])
                props = _svn_props(body[:plen])
                self._revs[rev] = {"id": str(rev), "author": props.get("svn:author"), "date": props.get("svn:date"),
                                   "message": props.get("svn:log"), "nodes": []}
            elif "Node-path" in head and rev is not None:
                path, action, kind = head["Node-path"], head.get("Node-action"), head.get("Node-kind")
                self._revs[rev]["nodes"].append({"path": path, "action": action, "kind": kind})
                if action in ("delete", "replace"):
                    for p in [p for p in snap if p == path or p.startswith(path + "/")]:
                        del snap[p]
                if action == "delete":
                    continue
                source = None
                if "Node-copyfrom-path" in head:
                    try:
                        source = (self._snaps[int(head["Node-copyfrom-rev"])], head["Node-copyfrom-path"])
                    except (KeyError, ValueError):
                        self.complete = False
                        self.problems.append(f"r{rev}: copy of {path} from a revision that is not in the dump")
                if kind == "dir" and source:
                    for p, b in source[0].items():
                        if p.startswith(source[1] + "/"):
                            snap[path + p[len(source[1]):]] = b
                if kind == "file":
                    if "Text-content-length" in head:
                        if head.get("Text-delta") == "true":
                            self.complete = False
                            if not any("delta" in p for p in self.problems):
                                self.problems.append("a delta dump: file contents are not rebuilt")
                            snap[path] = None
                        else:
                            bid = f"r{rev}:{path}"
                            self._blobs[bid] = body[plen:plen + int(head["Text-content-length"])]
                            snap[path] = bid
                    elif source and source[1] in source[0]:
                        snap[path] = source[0][source[1]]
        close()

    def ids(self):
        return [str(r) for r in sorted(self._revs) if r > 0 or self._revs[r]["nodes"]]

    def parents(self, cid):
        prev = [r for r in self._revs if r < int(cid) and (r > 0 or self._revs[r]["nodes"])]
        return [str(max(prev))] if prev else []

    def meta(self, cid):
        r = self._revs[int(cid)]
        author = r["author"]
        return {"id": cid, "author": author, "email": author if author and re.fullmatch(r"\S+@\S+\.\S+", author) else None,
                "time": _epoch(r["date"]), "tz": "+0000", "message": r["message"], "date": r["date"]}

    def id_forms(self, cid):
        return [("number", cid), ("r_number", "r" + cid)]

    def snapshot(self, cid):
        snap = self._snaps.get(int(cid))
        if snap is None or any(v is None for v in snap.values()):
            raise Incomplete(f"r{cid}: a file content is not in the dump")
        return snap

    def blob(self, bid):
        return self._blobs.get(bid)

    def all_blobs(self):
        return self._blobs.items()


def _sqlite(data: bytes):
    """A read-only SQLite connection over bounded bytes; the schema is untrusted.

    Python builds with ``Connection.deserialize`` stay entirely in memory.
    Python 3.9 builds without it use one mode-0600 OS-temporary file, open it
    immutable/read-only, and unlink it after its read-only backup into memory
    completes. No
    repository path, hook, extension, or target-selected filename is used.
    """
    import sqlite3
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("SQLite input is not bytes")
    data = bytes(data)
    if not data.startswith(b"SQLite format 3\x00") or len(data) > MAX_MEMBER:
        raise ValueError("invalid or oversized SQLite input")
    probe = sqlite3.connect(":memory:")
    if hasattr(probe, "deserialize"):
        con = probe
        con.deserialize(data)
    else:
        probe.close()
        fd, temp_path = tempfile.mkstemp(prefix="huntress-sqlite-", suffix=".db")
        source = None
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
            uri = Path(temp_path).resolve().as_uri() + "?mode=ro&immutable=1"
            source = sqlite3.connect(uri, uri=True)
            try:
                source.execute("PRAGMA trusted_schema=OFF")
                source.execute("PRAGMA query_only=ON")
            except sqlite3.Error:
                pass
            # SQLite may defer opening/reading the file until the first query,
            # so unlinking it immediately after ``connect`` breaks on macOS.
            # Copy pages through SQLite's backup API into a private in-memory
            # connection, then close the read-only source before unlinking.
            con = sqlite3.connect(":memory:")
            source.backup(con)
        finally:
            if source is not None:
                try:
                    source.close()
                except sqlite3.Error:
                    pass
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    try:
        con.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.Error:
        pass
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA cell_size_check=ON")
    except sqlite3.Error:
        pass
    return con


def svn_working_copy(db: bytes) -> list:
    """The NODES rows of a working copy's .svn/wc.db: {path, kind, revision, author, date, checksum, presence}."""
    con = _sqlite(db)
    try:
        rows = con.execute("SELECT local_relpath, kind, revision, changed_author, changed_date, checksum, presence "
                           "FROM NODES ORDER BY local_relpath, op_depth").fetchall()
    finally:
        con.close()
    return [{"path": r[0], "kind": r[1], "revision": r[2], "author": r[3],
             "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r[4] / 1e6)) if isinstance(r[4], int) and r[4] > 0 else None,
             "checksum": r[5], "presence": r[6]} for r in rows]


# ---- darcs -------------------------------------------------------------------------------------------

_DARCS_INFO = re.compile(rb"\[(?P<name>[^\n]*)\n(?P<author>[^\n]*?)\*(?P<inv>[*-])(?P<date>[^\n\]]*)(?P<log>(?:\n [^\n]*)*)\n?\]")


def _darcs_name(raw: bytes) -> str:
    text = re.sub(rb"\\(\d{1,3})\\", lambda m: bytes([int(m.group(1)) & 0xFF]), raw).decode("utf-8", "replace")
    return text[2:] if text.startswith("./") else text


def read_darcs_patch(text: bytes) -> list:
    """The patches in one darcs patch file (already gunzipped): [{name, author, email, date, log,
    inverted, info_hash, added {path: bytes}, removed {path: bytes}, addfile, rmfile, moves}]."""
    out = []
    marks = list(_DARCS_INFO.finditer(text))
    for i, m in enumerate(marks):
        body = text[m.end():marks[i + 1].start() if i + 1 < len(marks) else len(text)].lstrip(b" ")
        log = [line[1:] for line in m.group("log").split(b"\n")[1:]]
        author = m.group("author").decode("utf-8", "replace")
        ident = parse_ident(author)
        email = ident["email"] if ident["email"] is not None else (author.strip() if re.fullmatch(r"\S+@\S+", author.strip()) else None)
        p = {"name": m.group("name").decode("utf-8", "replace"), "author": author, "email": email,
             "date": m.group("date").decode("ascii", "replace").strip(), "inverted": m.group("inv") == b"-",
             "log": b"\n".join(l for l in log if not l.startswith(b"Ignore-this:")).decode("utf-8", "replace"),
             "info_hash": hashlib.sha1(m.group("name") + m.group("author") + m.group("date") + b"".join(log)
                                       + (b"t" if m.group("inv") == b"-" else b"f")).hexdigest(),
             "added": {}, "removed": {}, "addfile": [], "rmfile": [], "moves": []}
        cur = side = None
        for line in body.split(b"\n"):
            if line.startswith(b"hunk "):
                parts = line.split(b" ")
                cur, side = _darcs_name(parts[1]) if len(parts) > 1 else None, None
            elif line.startswith((b"addfile ", b"rmfile ")):
                p[line.split(b" ")[0].decode()].append(_darcs_name(line.split(b" ", 1)[1].strip()))
                cur = side = None
            elif line.startswith(b"move "):
                parts = line.split(b" ")
                if len(parts) >= 3:
                    p["moves"].append((_darcs_name(parts[1]), _darcs_name(parts[2])))
                cur = side = None
            elif line.startswith(b"binary "):
                cur, side = _darcs_name(line.split(b" ", 1)[1].strip()), None
            elif cur is not None and line in (b"oldhex", b"newhex"):
                side = "removed" if line == b"oldhex" else "added"
            elif cur is not None and side and line.startswith(b"*"):
                try:
                    p[side][cur] = p[side].get(cur, b"") + binascii.unhexlify(line[1:].strip())
                except (binascii.Error, ValueError):
                    pass
            elif cur is not None and side is None and line[:1] in (b"+", b"-"):
                key = "added" if line[:1] == b"+" else "removed"
                p[key][cur] = p[key].get(cur, b"") + line[1:] + b"\n"
            elif line.startswith((b"adddir ", b"rmdir ", b"replace ", b"changepref ", b"merger ", b"conflictor ", b"}", b"{")):
                cur = side = None
        out.append(p)
    return out


class DarcsRepo:
    """A darcs repository from the bytes under _darcs: its patches are diffs, so a string is
    'added' by the patch whose + lines (or new binary content) hold it."""

    kind = "darcs"
    verified = False

    def __init__(self, tree: dict, label: str = ""):
        self.label, self.problems, self.complete = label, [], True
        self._patches = {}
        for path in sorted(tree):
            if not path.startswith("patches/") or path.endswith(("pending", "pending.tentative", "unrevert")):
                continue
            raw = tree[path]
            text = _unpack_stream(raw) if raw[:2] == b"\x1f\x8b" else raw
            if text is None:
                self.complete = False
                self.problems.append(f"{path}: not unpacked")
                continue
            for p in read_darcs_patch(text):
                p["file"] = Path(path).name
                self._patches.setdefault(p["info_hash"], p)
        self.pending = tree.get("patches/pending", b"")

    def ids(self):
        return sorted(self._patches, key=lambda h: (self._patches[h]["date"], h))

    def parents(self, cid):
        return []

    def meta(self, cid):
        p = self._patches[cid]
        when = None
        if re.fullmatch(r"\d{14}", p["date"]):
            d = p["date"]
            when = _epoch(f"{d[:4]}-{d[4:6]}-{d[6:8]}T{d[8:10]}:{d[10:12]}:{d[12:14]}Z")
        return {"id": cid, "author": parse_ident(p["author"])["name"] if "<" in p["author"] else p["author"],
                "email": p["email"], "time": when, "tz": "+0000", "message": p["name"] + ("\n" + p["log"] if p["log"] else ""),
                "name": p["name"], "date": p["date"]}

    def id_forms(self, cid):
        p = self._patches[cid]
        forms = [("patch_hash", cid), ("name", p["name"])]
        m = re.fullmatch(r"(?:\d+-)?([0-9a-f]{40,64})(?:\.gz)?", p.get("file") or "")
        if m:
            forms.append(("file_hash", m.group(1)))
        return forms

    def adding(self, needle: bytes) -> list:
        return [c for c in self.ids() if any(needle in v for v in self._patches[c]["added"].values())]

    def removing(self, needle: bytes) -> list:
        return [c for c in self.ids() if any(needle in v for v in self._patches[c]["removed"].values())]

    def deleted(self) -> list:
        return [(c, p) for c in self.ids() for p in self._patches[c]["rmfile"]]

    def renamed(self) -> list:
        return [(c, a, b) for c in self.ids() for a, b in self._patches[c]["moves"]]

    def by_message(self, needle: str) -> list:
        return [c for c in self.ids() if needle.lower() in self.meta(c)["message"].lower()]

    def find_commit(self, prefix: str) -> list:
        return [c for c in self.ids() if c.startswith(prefix.lower())]

    def table(self) -> list:
        return [self.meta(c) for c in self.ids()]

    def all_blobs(self):
        for c in self.ids():
            p = self._patches[c]
            for side in ("added", "removed"):
                for path, body in p[side].items():
                    yield f"{c[:12]}:{side}:{path}", body

    def blob_origin(self, bid):
        cid = next((c for c in self._patches if c.startswith(bid.split(":")[0])), None)
        return [(cid, bid.split(":", 2)[2] + (" (removed lines)" if ":removed:" in bid else ""))]


# ---- fossil ------------------------------------------------------------------------------------------

_FOSSIL_DIGITS = {c: i for i, c in enumerate(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~")}


def apply_fossil_delta(src: bytes, delta: bytes) -> bytes:
    """A Fossil delta applied to its source."""
    pos, n = 0, len(delta)

    def num():
        nonlocal pos
        value, start = 0, pos
        while pos < n and delta[pos] in _FOSSIL_DIGITS:
            value = value * 64 + _FOSSIL_DIGITS[delta[pos]]
            pos += 1
        if pos == start:
            raise ValueError("fossil delta: a number was expected")
        return value
    total = num()
    if delta[pos:pos + 1] != b"\n" or total > MAX_MEMBER:
        raise ValueError("fossil delta: bad header")
    pos += 1
    out = bytearray()
    while pos < n:
        count = num()
        op = delta[pos:pos + 1]
        pos += 1
        if op == b"@":
            offset = num()
            if delta[pos:pos + 1] != b"," or offset + count > len(src):
                raise ValueError("fossil delta: bad copy")
            pos += 1
            out += src[offset:offset + count]
        elif op == b":":
            if pos + count > n:
                raise ValueError("fossil delta: literal past the end")
            out += delta[pos:pos + count]
            pos += count
        elif op == b";":
            if len(out) != total:
                raise ValueError("fossil delta: size mismatch")
            return bytes(out)
        else:
            raise ValueError("fossil delta: unknown command")
    raise ValueError("fossil delta: no end")


def _defossil(text: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"s": " ", "n": "\n", "t": "\t", "r": "\r", "0": "\x00"}.get(m.group(1), m.group(1)), text)


class FossilRepo(SnapshotHistory):
    """A Fossil repository database: every artifact, and the check-ins among them."""

    kind = "fossil"

    def __init__(self, db: bytes, label: str = ""):
        self.label, self.problems, self.complete = label, [], True
        self._raw, self._src, self._uuid, self._content, self._commits = {}, {}, {}, {}, {}
        con = _sqlite(db)
        try:
            for rid, uuid, size, content in con.execute("SELECT rid, uuid, size, content FROM blob"):
                self._uuid[rid] = uuid
                if size is not None and size >= 0 and content is not None:
                    self._raw[rid] = bytes(content)
            for rid, srcid in con.execute("SELECT rid, srcid FROM delta"):
                self._src[rid] = srcid
        finally:
            con.close()
        for rid in list(self._raw):
            try:
                self._text(rid)
            except (ValueError, KeyError, RecursionError) as e:
                self.complete = False
                self.problems.append(f"artifact {str(self._uuid.get(rid))[:12]}: not rebuilt ({str(e)[:60]})")
        self.artifacts = {self._uuid[rid]: body for rid, body in self._content.items()}
        for uuid, body in self.artifacts.items():
            m = self._manifest(body)
            if m:
                m["id"] = uuid
                self._commits[uuid] = m

    def _text(self, rid) -> bytes:
        if rid in self._content:
            return self._content[rid]
        chain, cur = [], rid
        while cur not in self._content:
            raw = self._raw[cur]
            body = inflate(raw[4:]) if len(raw) > 4 else b""
            if cur in self._src:
                chain.append((cur, body))
                cur = self._src[cur]
                if len(chain) > MAX_DELTA_CHAIN:
                    raise ValueError("delta chain too long")
            else:
                self._content[cur] = body
        body = self._content[cur]
        for key, delta in reversed(chain):
            body = apply_fossil_delta(body, delta)
            self._content[key] = body
        return self._content[rid]

    @staticmethod
    def _manifest(body: bytes):
        if not re.search(rb"(?:^|\n)Z [0-9a-f]{32}\n$", body[-40:]) or b"\x00" in body[:4096]:
            return None
        cards = {}
        for line in body.decode("utf-8", "replace").split("\n"):
            if len(line) > 1 and line[1] == " " and line[0].isupper():
                cards.setdefault(line[0], []).append(line[2:])
        if not all(k in cards for k in "CDU") or any(k in cards for k in "AEGHIJKLW"):
            return None
        files = {}
        for card in cards.get("F", []):
            parts = card.split(" ")
            files[_defossil(parts[0])] = parts[1] if len(parts) > 1 else None
        user = _defossil(cards["U"][0])
        return {"parents": cards.get("P", [""])[0].split(), "author": user,
                "email": user if re.fullmatch(r"\S+@\S+\.\S+", user) else None, "date": cards["D"][0],
                "time": _epoch(cards["D"][0]), "tz": "+0000", "message": _defossil(cards["C"][0]), "files": files,
                "baseline": cards.get("B", [None])[0]}

    def ids(self):
        return sorted(self._commits, key=lambda c: (self._commits[c]["date"], c))

    def parents(self, cid):
        return [p for p in self._commits[cid]["parents"] if p in self._commits]

    def meta(self, cid):
        c = self._commits[cid]
        return {k: c.get(k) for k in ("id", "author", "email", "time", "tz", "message", "date")}

    def id_forms(self, cid):
        return [("full", cid), ("short10", cid[:10])]

    def snapshot(self, cid):
        c = self._commits[cid]
        files = {}
        if c["baseline"]:
            base = self._commits.get(c["baseline"])
            if base is None:
                raise Incomplete(f"baseline manifest {c['baseline'][:12]} is not in the repository")
            files.update(base["files"])
        for path, uuid in c["files"].items():
            if uuid is None:
                files.pop(path, None)
            else:
                files[path] = uuid
        return files

    def blob(self, bid):
        return self.artifacts.get(bid)

    def all_blobs(self):
        return [(u, b) for u, b in self.artifacts.items() if u not in self._commits]


def find_histories(files: dict, notes: list = None) -> list:
    """Every version-control history among the files (already opened by expand): git, Mercurial,
    darcs, an SVN dump, a Fossil repository."""
    notes = notes if notes is not None else []
    entries = listing(files)
    out = list(find_git(entries))
    for (container, root), tree in sorted(_roots(entries, _HG_MARK).items()):
        out.append(HgRepo(tree, (container + ARROW if container else "") + root.rstrip("/")))
    for (container, root), tree in sorted(_roots(entries, _DARCS_MARK).items()):
        out.append(DarcsRepo(tree, (container + ARROW if container else "") + root.rstrip("/")))
    for container, path, data in entries:
        name = (container + ARROW if container else "") + path
        try:
            if data[:27] == b"SVN-fs-dump-format-version:":
                out.append(SvnDump(data, name))
            elif data[:16] == b"SQLite format 3\x00" and b"CREATE TABLE blob(" in data and b"CREATE TABLE delta(" in data:
                out.append(FossilRepo(data, name))
        except Exception as e:
            notes.append(f"{name}: not read as a repository ({type(e).__name__}: {str(e)[:80]})")
    return out


# ---- secrets -----------------------------------------------------------------------------------------
#
# A found secret is evidence and an answer. Nothing here uses, sends, validates or tests one.

# (kind, the literals one of which must be present before the pattern is tried, pattern, group,
# matched on the lowercased bytes). The literals keep a large delivery cheap: bytes.find is far
# faster than any pattern, and most files hold none of them.
_SECRET_RX = [(kind, lits, re.compile(rx) if rx is not None else flagfmt.BYTES, group, low)
              for kind, lits, rx, group, low in (
    ("aws_access_key_id", (b"AKIA", b"ASIA", b"AGPA", b"AIDA", b"AROA", b"AIPA", b"ANPA", b"ANVA"),
     rb"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Z0-9])", 0, False),
    ("aws_secret_access_key", (b"secret",), rb"secret_?access_?key[\"'\s:=]{1,6}([a-z0-9/+]{40})(?![a-z0-9/+=])", 1, True),
    ("github_token", (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"),
     rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})", 0, False),
    ("slack_token", (b"xox",), rb"(?<![A-Za-z0-9])xox[abeoprs]-[A-Za-z0-9-]{10,250}", 0, False),
    ("slack_webhook", (b"hooks.slack.com",), rb"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,200}", 0, False),
    ("discord_webhook", (b"/api/webhooks/",), rb"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", 0, False),
    ("jwt", (b"eyJ",), rb"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", 0, False),
    ("private_key", (b"PRIVATE KEY",),
     rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", 0, False),
    ("telegram_bot_token", (b":AA",), rb"(?<![0-9A-Za-z_-])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])", 0, False),
    ("google_api_key", (b"AIza",), rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])", 0, False),
    ("stripe_key", (b"_live_", b"_test_"), rb"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}", 0, False),
    ("npm_token", (b"npm_",), rb"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])", 0, False),
    ("pypi_token", (b"pypi-AgE",), rb"(?<![A-Za-z0-9_])pypi-AgE[A-Za-z0-9_-]{50,}", 0, False),
    ("huggingface_token", (b"hf_",), rb"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9])", 0, False),
    ("anthropic_api_key", (b"sk-ant-",), rb"(?<![A-Za-z0-9_])sk-ant-[A-Za-z0-9_-]{20,}", 0, False),
    ("openai_api_key", (b"sk-",), rb"(?<![A-Za-z0-9_])sk-(?:proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})(?![A-Za-z0-9])", 0, False),
    ("url_credentials", (b"://",), rb"(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{1,15}://[^/\s:@\"'<>]{1,80}:[^/\s:@\"'<>]{1,120}@[a-z0-9.-]{1,200}", 0, True),
    ("flag", (), None, 0, False),       # the event's flag format (ctf.flagfmt), on the bytes as delivered
    ("assigned_password", (b"pass", b"pwd"), rb"(?:pass(?:word|wd)?|pwd)[a-z0-9_]{0,24}[\"']?\s*[:=]\s*[\"']([^\"'\n]{4,120})[\"']", 1, True),
    ("assigned_secret", (b"secret",), rb"secret[a-z0-9_]{0,24}[\"']?\s*[:=]\s*[\"']([^\"'\n]{4,200})[\"']", 1, True),
    ("assigned_api_key", (b"api",), rb"api[_-]?key[a-z0-9_]{0,24}[\"']?\s*[:=]\s*[\"']([^\"'\n]{4,200})[\"']", 1, True),
    ("assigned_token", (b"token",), rb"token[a-z0-9_]{0,24}[\"']?\s*[:=]\s*[\"']([^\"'\n]{4,400})[\"']", 1, True),
)]
SECRET_KINDS = [k for k, _, _, _, _ in _SECRET_RX]
# The kinds whose pattern alone proves what the value is; an assigned_* value is only "a quoted
# string after a name that says secret", so it never answers a question that names a kind.
STRICT_KINDS = [k for k in SECRET_KINDS if not k.startswith("assigned_") and k != "url_credentials"]


def scan_secrets(data: bytes) -> list:
    """[(kind, value, offset)] of the secret patterns in the bytes (the first SEARCH_CAP of them)."""
    data = bytes(data[:SEARCH_CAP])
    low = None
    out, seen = [], set()
    for kind, lits, rx, group, on_low in _SECRET_RX:
        if on_low and low is None:
            low = data.lower()
        hay = low if on_low else data
        if lits and not any(lit in hay for lit in lits):
            continue
        for m in rx.finditer(hay):
            a, b = m.span(group)
            value = data[a:b].decode("utf-8", "replace")        # the bytes as delivered, whatever was matched on
            if (kind, value) not in seen:
                seen.add((kind, value))
                out.append((kind, value, a))
    strict = {v for k, v, _ in out if not k.startswith("assigned_")}
    return [(k, v, o) for k, v, o in out if not (k.startswith("assigned_") and v in strict)]


def jwt_parts(token: str) -> dict:
    """The header and the payload of a JWT, decoded and never verified."""
    out = {}
    for name, part in zip(("header", "payload"), token.split(".")[:2]):
        try:
            out[name] = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        except (ValueError, binascii.Error):
            out[name] = None
    return out


def _origin(h, bid) -> list:
    """[{commit, path, state}] for a blob of a history: where it first appears, or that nothing holds it."""
    if isinstance(h, DarcsRepo):
        return [{"commit": c, "path": p, "state": "patch"} for c, p in h.blob_origin(bid)]
    if isinstance(h, GitRepo):
        rows = h.blob_paths().get(bid)
        if rows:
            return [{"commit": c, "path": p, "state": h.where(c)} for c, p in rows]
        return [{"commit": None, "path": None, "state": ("dangling" if bid in h.reach()["dangling"] else h.where(bid)) + " blob " + bid}]
    cache = h.__dict__.setdefault("_origin", None)
    if cache is None:
        cache = h.__dict__["_origin"] = {}
        for c in h.ids():
            try:
                for path, b in h.snapshot(c).items():
                    rows = cache.setdefault(b, [])
                    if not any(p == path for _, p in rows):
                        rows.append((c, path))
            except Incomplete:
                pass
    rows = cache.get(bid)
    if rows:
        return [{"commit": c, "path": p, "state": "history"} for c, p in rows]
    return [{"commit": None, "path": None, "state": f"artifact {bid} outside every check-in"}]


def find_secrets(files: dict, histories: list) -> list:
    """Every secret in the delivered files, in every blob of every history (dangling ones too) and
    in the commit messages: [{kind, value, where: [{repo, commit, path, state}]}], one row per
    distinct (kind, value)."""
    rows = {}
    budget = [SECRET_BUDGET]

    def add(kind, value, where):
        rows.setdefault((kind, value), []).append(where)

    def worth(data) -> bool:
        """Text of any size and small files are searched; a large binary (an executable, an image)
        is not what this toolkit reads, and the whole search stays inside a byte budget."""
        if len(data) > (1 << 20) and b"\x00" in data[:4096]:
            return False
        budget[0] -= min(len(data), SEARCH_CAP)
        return budget[0] >= 0
    internal = set()
    for h in histories:
        if isinstance(h, GitRepo):
            internal.update(id(d) for p, d in h.t.items() if p.startswith("objects/") or p == "index")
        for bid, body in h.all_blobs():
            if not worth(body):
                continue
            found = scan_secrets(body)
            if found:
                origin = _origin(h, bid)
                for kind, value, _ in found:
                    for o in origin:
                        add(kind, value, {"repo": h.label, **o})
        for c in h.ids():
            for kind, value, _ in scan_secrets((h.meta(c).get("message") or "").encode("utf-8", "replace")):
                add(kind, value, {"repo": h.label, "commit": c, "path": None, "state": "commit message"})
    for container, path, data in listing(files):
        if id(data) in internal or data[:4] in (b"PK\x03\x04", b"PACK", b"Cr24") or data[:2] == b"\x1f\x8b" or not worth(data):
            continue
        for kind, value, _ in scan_secrets(data):
            add(kind, value, {"repo": None, "commit": None, "path": (container + ARROW if container else "") + path, "state": "file"})
    return [{"kind": k, "value": v, "where": w} for (k, v), w in rows.items()]


# ---- packages, extensions, workflows -------------------------------------------------------------------

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>()\]\[{}`\\|^]{3,400}", re.I)
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
NPM_LIFECYCLE = NPM_INSTALL_HOOKS + ("prepare", "prepublish", "prepublishOnly", "prepack", "postpack", "preuninstall",
                                     "uninstall", "postuninstall", "pretest", "test", "posttest", "prestart", "start",
                                     "poststart", "dependencies")
_RUNNERS = re.compile(r"(?:^|[;&|]\s*|\s)(?:node|nodejs|sh|bash|zsh|python3?|ruby|perl|pwsh|powershell(?:\.exe)?|deno run|bun)\s+"
                      r"(?:-[A-Za-z-]+\s+)*[\"']?([A-Za-z0-9_./\\-]+\.[A-Za-z0-9]{1,5})[\"']?")


def urls_in(text) -> list:
    """The URLs in a text or in bytes, in order, once each, with trailing punctuation cut."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text[:SEARCH_CAP]).decode("utf-8", "replace")
    out = []
    for m in _URL.finditer(text or ""):
        u = m.group().rstrip(".,;:!?)'\"")
        if u not in out:
            out.append(u)
    return out


def host_of(url: str) -> str:
    m = re.match(r"[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)", url, re.I)
    return m.group(1).lower() if m else ""


def _json(data):
    try:
        return json.loads(bytes(data).decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None


def _hook(when, where, command, install=True, **more) -> dict:
    return {"when": when, "where": where, "command": command, "install_time": install, "urls": urls_in(command), **more}


def _follow(hook: dict, members: dict):
    """The file a hook's command runs, when it names one that is in the package: its URLs join the hook's."""
    for m in _RUNNERS.finditer(hook["command"] or ""):
        rel = m.group(1).replace("\\", "/").lstrip("./")
        if rel in members:
            hook.setdefault("files", []).append(rel)
            for u in urls_in(members[rel]):
                if u not in hook["urls"]:
                    hook["urls"].append(u)


def read_package_json(data: bytes, members: dict = None, where: str = "package.json") -> dict:
    """An npm (or VS Code extension) manifest: name, version, the lifecycle scripts, bin, the entry file."""
    doc = _json(data)
    if not isinstance(doc, dict):
        raise ValueError("package.json is not a JSON object")
    members = members or {}
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    hooks = []
    for name, command in scripts.items():
        if isinstance(command, str):
            h = _hook(name, where, command, install=name in NPM_INSTALL_HOOKS)
            _follow(h, members)
            hooks.append(h)
    if "binding.gyp" in members and not any(h["when"] in ("install", "preinstall") for h in hooks):
        hooks.append(_hook("install", "binding.gyp", "node-gyp rebuild", implicit=True))
    entry = doc.get("main") if isinstance(doc.get("main"), str) else None
    bins = doc.get("bin")
    bins = {str(doc.get("name")): bins} if isinstance(bins, str) else (bins if isinstance(bins, dict) else {})
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if isinstance(doc.get(key), dict):
            deps.update({k: v for k, v in doc[key].items() if isinstance(v, str)})
    odd = {k: v for k, v in deps.items() if re.match(r"(?:https?:|git[+:]|github:|file:|[\w.-]+/[\w.-]+(?:#|$))", v)}
    return {"kind": "npm", "name": doc.get("name"), "version": doc.get("version"), "hooks": hooks, "entry": entry,
            "bin": bins, "dependencies": deps, "dependencies_not_from_registry": odd,
            "extra": {k: doc.get(k) for k in ("publisher", "activationEvents", "engines", "repository", "homepage", "author")
                      if doc.get(k) is not None}}


def check_record(members: dict, record_path: str) -> dict:
    """A wheel's RECORD against the files beside it: {rows, mismatched: [{path, algorithm, recorded,
    actual, actual_hex, recorded_size, actual_size}], missing: [path], unlisted: [path]}."""
    import csv
    out = {"rows": 0, "mismatched": [], "missing": [], "unlisted": []}
    listed = set()
    if record_path not in members:
        raise Incomplete(f"RECORD member is missing: {record_path}")
    text = members[record_path].decode("utf-8", "replace")
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0]:
            continue
        path, digest, size = (row + ["", ""])[:3]
        listed.add(path)
        out["rows"] += 1
        if path not in members:
            out["missing"].append(path)
            continue
        if not digest:
            continue
        algo, _, want = digest.partition("=")
        try:
            raw = hashlib.new(algo, members[path]).digest()
        except (ValueError, TypeError):
            continue
        actual = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        size_ok = not size.strip().isdigit() or int(size) == len(members[path])
        if actual != want.rstrip("=") or not size_ok:
            try:
                want_hex = base64.urlsafe_b64decode(want + "=" * (-len(want) % 4)).hex()
            except (ValueError, binascii.Error):
                want_hex = None
            out["mismatched"].append({"path": path, "algorithm": algo, "recorded": want, "recorded_hex": want_hex,
                                      "actual": actual, "actual_hex": raw.hex(),
                                      "recorded_size": int(size) if size.strip().isdigit() else None,
                                      "actual_size": len(members[path]), "hash_differs": actual != want.rstrip("=")})
    base = record_path.rsplit("/", 1)[0] + "/"
    out["unlisted"] = sorted(p for p in members if p not in listed and p not in (base + "RECORD.jws", base + "RECORD.p7s"))
    return out


_HASH_KEYS = ("hash", "sha256", "sha1", "sha512", "md5", "digest", "checksum", "integrity")
_PATH_KEYS = ("path", "file", "filename", "name")
_HEX_ALGO = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def hash_manifest_rows(doc, depth: int = 0):
    """[(path, hex digest)] of the first list in a JSON value whose entries each name a file and a
    hex digest (a Splunk app's splunkbase.manifest: app.files[{path, hash}]); None when there is none.
    At least three entries: one pair proves no manifest."""
    if depth > 4:
        return None
    if isinstance(doc, list) and len(doc) >= 3 and all(isinstance(e, dict) for e in doc):
        rows = []
        for e in doc:
            path = next((e[k] for k in _PATH_KEYS if isinstance(e.get(k), str) and e[k]), None)
            digest = next((e[k] for k in _HASH_KEYS if isinstance(e.get(k), str) and re.fullmatch(r"[0-9a-fA-F]+", e[k])
                           and len(e[k]) in _HEX_ALGO), None)
            if path is None or digest is None:
                rows = None
                break
            rows.append((path.replace("\\", "/").lstrip("./"), digest.lower()))
        if rows:
            return rows
    if isinstance(doc, dict) and len(doc) >= 3 and all(isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HEX_ALGO
                                                        for v in doc.values()):
        return [(k.replace("\\", "/").lstrip("./"), v.lower()) for k, v in doc.items()]       # {path: digest}
    for v in (doc.values() if isinstance(doc, dict) else doc if isinstance(doc, list) else []):
        if isinstance(v, (dict, list)):
            got = hash_manifest_rows(v, depth + 1)
            if got:
                return got
    return None


def check_hash_manifest(members: dict, manifest_path: str, rows: list) -> dict:
    """A JSON hash manifest against the files beside it, in check_record's form. `members` are the
    files under the manifest's own folder, by their path from it."""
    out = {"rows": 0, "mismatched": [], "missing": [], "unlisted": [], "manifest": manifest_path}
    listed = set()
    for path, want in rows:
        listed.add(path)
        out["rows"] += 1
        if path not in members:
            out["missing"].append(path)
            continue
        algo = _HEX_ALGO[len(want)]
        actual = hashlib.new(algo, members[path]).hexdigest()
        if actual != want:
            out["mismatched"].append({"path": path, "algorithm": algo, "recorded": want, "recorded_hex": want, "actual": actual,
                                      "actual_hex": actual, "recorded_size": None, "actual_size": len(members[path]), "hash_differs": True})
    out["unlisted"] = sorted(p for p in members if p not in listed and p != manifest_path)
    return out


def pth_lines(data: bytes) -> list:
    """The lines of a .pth file that Python's site module executes at every start (they begin with `import`)."""
    return [line.strip() for line in bytes(data).decode("utf-8", "replace").splitlines()
            if re.match(r"import[ \t]", line)]


def read_setup_py(source: bytes) -> dict:
    """setup.py read as a syntax tree and never run: the setup() arguments that are literals, the
    cmdclass keys, and every call that runs a command, fetches a URL or evaluates text."""
    import ast
    text = bytes(source).decode("utf-8", "replace")
    out = {"args": {}, "cmdclass": [], "calls": [], "urls": urls_in(text), "parsed": True}
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        out["parsed"] = False
        return out

    def dotted(node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    def literal(node):
        try:
            return ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
    risky = re.compile(r"^(?:os\.(?:system|popen|exec\w*|spawn\w*|startfile)|subprocess\.\w+|commands\.\w+|exec|eval|compile|"
                       r"__import__|urllib(?:2|\.request)?\.(?:urlopen|urlretrieve|Request)|urlopen|urlretrieve|"
                       r"requests\.(?:get|post|put|request)|socket\.\w+|base64\.\w*decode|codecs\.decode|marshal\.loads|"
                       r"pickle\.loads|ctypes\.\w+|pty\.spawn|shutil\.\w+|builtins\.(?:exec|eval))$")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        if name and name.split(".")[-1] == "setup":
            for kw in node.keywords:
                if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                    out["cmdclass"] = [literal(k) for k in kw.value.keys if k is not None and literal(k) is not None]
                elif kw.arg:
                    value = literal(kw.value)
                    if value is not None:
                        out["args"][kw.arg] = value
        elif name and risky.match(name):
            first = literal(node.args[0]) if node.args else None
            if isinstance(first, (list, tuple)) and all(isinstance(x, str) for x in first):
                first = " ".join(first)
            if isinstance(first, bytes):
                first = first.decode("utf-8", "replace")
            out["calls"].append({"call": name, "arg": first if isinstance(first, str) else None, "line": node.lineno})
    return out


def read_manifest_mf(data: bytes) -> dict:
    """The main section of a jar's META-INF/MANIFEST.MF (continuation lines joined)."""
    text = bytes(data).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n ", "", text)
    out = {}
    for line in text.split("\n\n", 1)[0].split("\n"):
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def read_gem_spec(data: bytes) -> dict:
    """A gem's metadata (YAML with Ruby tags, loaded as plain data): name, version, extensions, executables, files."""
    import yaml

    class Loose(yaml.SafeLoader):
        pass

    def anything(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)
    Loose.add_multi_constructor("!ruby/", anything)
    Loose.add_multi_constructor("!", anything)
    try:
        doc = yaml.load(bytes(data[:4 * 1024 * 1024]).decode("utf-8", "replace"), Loader=Loose)
    except yaml.YAMLError as e:
        raise ValueError(f"invalid gem metadata YAML: {e}")
    if not isinstance(doc, dict):
        raise ValueError("gem metadata is not a mapping")
    version = doc.get("version")
    version = version.get("version") if isinstance(version, dict) else version
    return {"name": doc.get("name"), "version": str(version) if version is not None else None,
            "extensions": [x for x in doc.get("extensions") or [] if isinstance(x, str)],
            "executables": [x for x in doc.get("executables") or [] if isinstance(x, str)],
            "files": [x for x in doc.get("files") or [] if isinstance(x, str)], "homepage": doc.get("homepage"),
            "authors": doc.get("authors"), "email": doc.get("email"), "post_install_message": doc.get("post_install_message"),
            "metadata": doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}}


def read_workflow(data: bytes, where: str = "") -> dict:
    """A GitHub Actions workflow (yaml.safe_load): triggers, jobs, every `run` command and `uses` action, and what stands out."""
    import yaml
    try:
        doc = yaml.safe_load(bytes(data[:2 * 1024 * 1024]).decode("utf-8", "replace"))
    except yaml.YAMLError as e:
        raise ValueError(f"invalid workflow YAML: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise ValueError("not a workflow")
    on = doc.get("on", doc.get(True))           # YAML 1.1 reads the key `on` as the boolean true
    triggers = [on] if isinstance(on, str) else list(on) if isinstance(on, (list, dict)) else []
    hooks, uses, notes, secrets = [], [], [], []
    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue
        if "self-hosted" in str(job.get("runs-on")):
            notes.append(f"job {job_id} runs on a self-hosted runner")
        if isinstance(job.get("uses"), str):
            uses.append(job["uses"])
        for n, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("uses"), str):
                uses.append(step["uses"])
            if isinstance(step.get("run"), str):
                h = _hook(f"workflow:{job_id}", where, step["run"], install=False, step=step.get("name") or n)
                hooks.append(h)
                if re.search(r"\$\{\{\s*github\.(?:event|head_ref)", step["run"]):
                    notes.append(f"job {job_id} step {h['step']}: an event value is pasted into the shell (script injection)")
                if re.search(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", step["run"]):
                    notes.append(f"job {job_id} step {h['step']}: a download piped into a shell")
            secrets += re.findall(r"secrets\.([A-Za-z0-9_]+)", json.dumps(step, default=str))
    for t in ("pull_request_target", "workflow_run", "issue_comment"):
        if t in [str(x) for x in triggers]:
            notes.append(f"trigger {t}: runs with the base repository's secrets")
    for u in uses:
        if not u.startswith(("./", "docker://")) and not re.search(r"@[0-9a-f]{40}$", u):
            notes.append(f"action {u} is not pinned to a commit")
    return {"kind": "github_workflow", "name": doc.get("name"), "version": None, "triggers": [str(t) for t in triggers],
            "hooks": hooks, "uses": uses, "secrets_used": sorted(set(secrets)), "notes": notes}


def _tar_members(raw: bytes) -> dict:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf:
            if m.isfile() and m.size <= MAX_MEMBER:
                f = tf.extractfile(m)
                if f is not None:
                    out[m.name] = f.read()
    return out


def _rx_tag(text: str, tag: str):
    m = re.search(rf"<{tag}\b[^>]*>([^<]*)</{tag}>", text)
    import html
    return html.unescape(m.group(1).strip()) if m else None


def find_packages(files: dict, histories=(), notes: list = None) -> list:
    """Every package, extension and workflow among the files (already opened by expand), and in the
    HEAD commit of every git repository that came without its work tree. One dict per package:
    {kind, file, root, name, version, hooks: [{when, where, command, install_time, urls, files}],
    entry, and the kind's own fields}."""
    notes = notes if notes is not None else []
    groups = {}
    for container, path, data in listing(files):
        groups.setdefault(container, {})[path] = data
    for h in histories:
        if isinstance(h, GitRepo) and not h.worktree and h.head()["id"]:
            try:
                snap = h.snapshot(h.head()["id"])
            except Incomplete:
                continue
            groups[h.label + "@HEAD"] = {p: h.blob(b) for p, b in snap.items() if h.blob(b) is not None}
    raw_of = {}
    for key, data in _unique(files):
        raw_of.setdefault(key.split(ARROW)[-1], data)
    out = []

    def sub(members, root):
        return {p[len(root):]: d for p, d in members.items() if p.startswith(root)}

    def emit(pkg, container, root):
        pkg.update(file=container or "(loose files)", root=root)
        pkg.setdefault("hooks", [])
        pkg.setdefault("notes", [])
        out.append(pkg)

    for container, members in sorted(groups.items()):
        is_git_internal = any(re.search(r"(?:^|/)objects/[0-9a-f]{2}/[0-9a-f]{38}", p) for p in list(members)[:50])
        raw = raw_of.get(container, b"")
        for path in sorted(members):
            data, base, root = members[path], path.rsplit("/", 1)[-1], path[:len(path) - len(path.rsplit("/", 1)[-1])]
            try:
                if "/node_modules/" in "/" + path and base == "package.json":
                    continue
                if base.lower().endswith((".manifest", ".json")) and base not in ("package.json", "composer.json", "manifest.json") \
                        and 64 < len(data) < 8 << 20 and (b'"hash"' in data or b'"sha256"' in data or b'"digest"' in data
                                                          or b'"checksum"' in data or b'"sha1"' in data or b'"md5"' in data):
                    rows = hash_manifest_rows(_json(data))
                    inside = sub(members, root)
                    # it is the manifest of these files only when most of what it lists is there
                    if rows and sum(1 for pth, _ in rows if pth in inside) * 2 >= len(rows):
                        doc = _json(data)
                        app = doc.get("app") if isinstance(doc, dict) and isinstance(doc.get("app"), dict) else {}
                        emit({"kind": "hash_manifest", "name": root.rstrip("/").rsplit("/", 1)[-1] or None,
                              "version": app.get("version") if isinstance(app.get("version"), str) else None,
                              "manifest": path, "record": check_hash_manifest(inside, base, rows), "hooks": []}, container, root)
                        continue
                if base == "package.json" or (base == "composer.json" and isinstance(_json(data), dict)):
                    if base == "composer.json":
                        doc = _json(data)
                        scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
                        hooks = []
                        for name, cmd in scripts.items():
                            for one in cmd if isinstance(cmd, list) else [cmd]:
                                if isinstance(one, str):
                                    hooks.append(_hook(name, path, one, install=name in ("pre-install-cmd", "post-install-cmd",
                                                                                         "post-update-cmd", "post-autoload-dump")))
                        emit({"kind": "composer", "name": doc.get("name"), "version": doc.get("version"), "hooks": hooks}, container, root)
                        continue
                    pkg = read_package_json(data, sub(members, root), path)
                    if (root + "../extension.vsixmanifest").replace("extension/../", "") in members or "extension.vsixmanifest" in members:
                        pkg["kind"] = "vsix"
                        man = members.get("extension.vsixmanifest", b"").decode("utf-8", "replace")
                        m = re.search(r"<Identity\b([^>]*)>", man)
                        if m:
                            pkg["identity"] = dict(re.findall(r"(\w+)=\"([^\"]*)\"", m.group(1)))
                        if pkg.get("entry"):
                            pkg["hooks"].append(_hook("activation", path, pkg["entry"], install=False, entry=True))
                    emit(pkg, container, root)
                elif base == "RECORD" and root.rstrip("/").endswith(".dist-info"):
                    top = root[:len(root) - len(root.rstrip("/").rsplit("/", 1)[-1]) - 1]
                    inside = sub(members, top)
                    info = root[len(top):]
                    meta = inside.get(info + "METADATA", b"").decode("utf-8", "replace")
                    hooks = []
                    for p in sorted(inside):
                        if p.endswith(".pth"):
                            for line in pth_lines(inside[p]):
                                hooks.append(_hook("pth", p, line, install=False, runs="at every Python start"))
                    entry = {}
                    if info + "entry_points.txt" in inside:
                        import configparser
                        cp = configparser.ConfigParser(interpolation=None, delimiters=("=",))
                        cp.optionxform = str
                        try:
                            cp.read_string(inside[info + "entry_points.txt"].decode("utf-8", "replace"))
                            entry = {s: dict(cp[s]) for s in cp.sections()}
                        except configparser.Error:
                            pass
                    emit({"kind": "wheel", "name": (re.search(r"^Name: (.+)$", meta, re.M) or [None, None])[1],
                          "version": (re.search(r"^Version: (.+)$", meta, re.M) or [None, None])[1],
                          "hooks": hooks, "entry_points": entry, "record": check_record(inside, info + "RECORD"),
                          "pth": sorted(p for p in inside if p.endswith(".pth"))}, container, top)
                elif base == "setup.py":
                    info = read_setup_py(data)
                    pk = members.get(root + "PKG-INFO", b"").decode("utf-8", "replace")
                    hooks = [_hook("setup.py", path, c["arg"] or c["call"], call=c["call"], line=c["line"]) for c in info["calls"]]
                    for cmd in info["cmdclass"]:
                        hooks.append(_hook(f"cmdclass:{cmd}", path, str(cmd), custom_command=True))
                    emit({"kind": "sdist", "name": info["args"].get("name") or (re.search(r"^Name: (.+)$", pk, re.M) or [None, None])[1],
                          "version": info["args"].get("version") or (re.search(r"^Version: (.+)$", pk, re.M) or [None, None])[1],
                          "hooks": hooks, "entry_points": info["args"].get("entry_points"), "setup": info,
                          "urls": info["urls"]}, container, root)
                elif base == "manifest.json" and isinstance(_json(data), dict) and "manifest_version" in _json(data):
                    doc = _json(data)
                    inside = sub(members, root)
                    hooks = []
                    bg = doc.get("background") if isinstance(doc.get("background"), dict) else {}
                    scripts = ([bg["service_worker"]] if isinstance(bg.get("service_worker"), str) else []) + \
                        [s for s in bg.get("scripts") or [] if isinstance(s, str)]
                    for s in scripts:
                        hooks.append(_hook("background", path, s, install=False))
                    for cs in doc.get("content_scripts") or []:
                        for s in (cs.get("js") or []) if isinstance(cs, dict) else []:
                            hooks.append(_hook("content_script", path, s, install=False, matches=cs.get("matches")))
                    for h in hooks:
                        rel = h["command"].lstrip("./")
                        if rel in inside:
                            h["files"] = [rel]
                            h["urls"] = urls_in(inside[rel])
                    ext_id = None
                    if raw[:4] == b"Cr24":
                        ext_id = crx_parts(bytes(raw))["id"]
                    if not ext_id and isinstance(doc.get("key"), str):
                        try:
                            ext_id = _crx_id(hashlib.sha256(base64.b64decode(doc["key"])).digest()[:16])
                        except (ValueError, binascii.Error):
                            pass
                    # A store extension names itself by a message key (`__MSG_extName__`): the name is that
                    # message of the default locale. Both are kept; `name` is the resolved one when it resolves.
                    name = doc.get("name")
                    m = re.fullmatch(r"__MSG_(\w+)__", name) if isinstance(name, str) else None
                    if m:
                        loc = _json(inside.get(f"_locales/{doc.get('default_locale') or 'en'}/messages.json", b"")) or {}
                        hit = next((v for k, v in loc.items() if k.lower() == m.group(1).lower()), None) if isinstance(loc, dict) else None
                        if isinstance(hit, dict) and isinstance(hit.get("message"), str) and hit["message"].strip():
                            name = hit["message"].strip()
                    emit({"kind": "crx" if raw[:4] == b"Cr24" else "browser_extension", "name": name, "name_in_manifest": doc.get("name"),
                          "version": doc.get("version"), "hooks": hooks, "extension_id": ext_id,
                          "manifest_version": doc.get("manifest_version"), "permissions": doc.get("permissions") or [],
                          "host_permissions": doc.get("host_permissions") or [], "update_url": doc.get("update_url"),
                          "externally_connectable": doc.get("externally_connectable")}, container, root)
                elif path == "META-INF/MANIFEST.MF" and "AndroidManifest.xml" not in members:
                    mf = read_manifest_mf(data)
                    hooks = [_hook(k.lower().replace("-", "_"), path, mf[k], install=False)
                             for k in ("Premain-Class", "Agent-Class", "Launcher-Agent-Class") if mf.get(k)]
                    props = {}
                    for p, d in members.items():
                        if p.startswith("META-INF/maven/") and p.endswith("pom.properties"):
                            props = dict(re.findall(r"^(\w+)=(.*)$", d.decode("utf-8", "replace"), re.M))
                    emit({"kind": "jar", "name": props.get("artifactId") or mf.get("Implementation-Title"),
                          "version": props.get("version") or mf.get("Implementation-Version"), "hooks": hooks,
                          "entry": mf.get("Main-Class"), "manifest": mf, "group": props.get("groupId"),
                          "classes": sum(1 for p in members if p.endswith(".class")),
                          "services": {p[len("META-INF/services/"):]: d.decode("utf-8", "replace").split()
                                       for p, d in members.items() if p.startswith("META-INF/services/")}}, container, "")
                elif base.endswith(".nuspec") and "/" not in path:
                    text = data.decode("utf-8-sig", "replace")
                    hooks = []
                    import html
                    for p in sorted(members):
                        low = p.lower()
                        if re.fullmatch(r"tools/(?:install|init|uninstall)\.ps1", low):
                            hooks.append(_hook(low.rsplit("/", 1)[-1][:-4], p, p, install=low != "tools/uninstall.ps1",
                                               urls=urls_in(members[p]), files=[p]))
                        elif low.endswith((".targets", ".props")):
                            for m in re.finditer(r"<Exec\b[^>]*\bCommand\s*=\s*\"([^\"]*)\"", members[p].decode("utf-8", "replace")):
                                hooks.append(_hook("msbuild_exec", p, html.unescape(m.group(1)), install=False, runs="at build"))
                    emit({"kind": "nupkg", "name": _rx_tag(text, "id"), "version": _rx_tag(text, "version"), "hooks": hooks,
                          "authors": _rx_tag(text, "authors"), "project_url": _rx_tag(text, "projectUrl")}, container, "")
                elif path == "metadata.gz" and "data.tar.gz" in members:
                    spec = read_gem_spec(_unpack_stream(bytes(data)) or b"")
                    inner = _tar_members(_unpack_stream(bytes(members["data.tar.gz"])) or b"")
                    hooks = []
                    for ext in spec["extensions"]:
                        hooks.append(_hook("extension", ext, ext, urls=urls_in(inner.get(ext, b"")), files=[ext] if ext in inner else []))
                    sums = {}
                    if "checksums.yaml.gz" in members:
                        import yaml
                        doc = yaml.safe_load((_unpack_stream(bytes(members["checksums.yaml.gz"])) or b"").decode("utf-8", "replace")) or {}
                        for algo, table in doc.items() if isinstance(doc, dict) else []:
                            for name, want in (table or {}).items() if isinstance(table, dict) else []:
                                try:
                                    got = hashlib.new(str(algo).lower(), members[name]).hexdigest()
                                except (ValueError, KeyError, TypeError):
                                    continue
                                if got != str(want):
                                    sums.setdefault("mismatched", []).append({"path": name, "algorithm": str(algo), "recorded": str(want), "actual": got})
                    emit({"kind": "gem", **{k: spec[k] for k in ("name", "version", "executables", "homepage", "post_install_message")},
                          "hooks": hooks, "checksums": sums, "members": sorted(inner)}, container, "")
                elif (re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", path)
                      # or a workflow handed over without its folder: a YAML file with top-level `on` and `jobs`
                      or (base.lower().endswith((".yml", ".yaml")) and len(data) < 1 << 20
                          and re.search(rb"(?m)^(?:on|\"on\"|'on'|true):", data) and re.search(rb"(?m)^jobs:", data))) \
                        and not is_git_internal:
                    emit(read_workflow(data, path), container, root)
                elif base in ("requirements.txt", "pip.conf", ".npmrc", ".pypirc", ".yarnrc", "pip.ini") and len(data) < 1 << 20:
                    text = data.decode("utf-8", "replace")
                    idx = re.findall(r"(?:--(?:extra-)?index-url|--find-links|-i|-f|registry|index-url|extra-index-url|repository)\s*[= ]\s*(\S+)", text)
                    direct = [u for u in urls_in(text) if u not in idx]
                    if idx or direct:
                        emit({"kind": "package_config", "name": base, "version": None, "index_urls": idx, "urls": direct}, container, root)
            except Exception as e:
                notes.append(f"{container or '.'}: {path} not read as a package ({type(e).__name__}: {str(e)[:80]})")
    return out


# ---- git extras: what would run if the real git were pointed at this repository --------------------------

_CONFIG_RUNS = re.compile(r"^\s*(fsmonitor|sshcommand|hookspath|pager|editor|askpass|gitproxy|textconv|command|"
                          r"clean|smudge|process|uploadpack|receivepack|helper|program|driver)\s*=\s*(.+)$", re.I | re.M)


def git_config_facts(repo: GitRepo) -> dict:
    """{'remotes': {name: url}, 'user': {...}, 'runs': [(key, value)], 'hooks': [name]} read from the
    git directory's config and hooks folder. `runs` and `hooks` are what a real git could execute
    here (core.fsmonitor, core.sshCommand, filters, aliases with `!`, live hooks): the reason no
    git binary is run on a delivered repository."""
    text = repo.t.get("config", b"").decode("utf-8", "replace")
    remotes, user, section = {}, {}, ""
    for line in text.splitlines():
        m = re.match(r"\s*\[\s*([A-Za-z0-9.-]+)(?:\s+\"([^\"]*)\")?\s*\]", line)
        if m:
            section = m.group(1).lower() + ("." + m.group(2) if m.group(2) else "")
            continue
        k, sep, v = line.partition("=")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if section.startswith("remote.") and k == "url":
            remotes[section[7:]] = v
        elif section == "user":
            user[k] = v
    runs = [(m.group(1), m.group(2).strip()) for m in _CONFIG_RUNS.finditer(text)]
    runs += [("alias", m.group(1).strip()) for m in re.finditer(r"^\s*\w+\s*=\s*(!.+)$", text, re.M)]
    hooks = sorted(p[6:] for p in repo.t if p.startswith("hooks/") and not p.endswith(".sample"))
    return {"remotes": remotes, "user": user, "runs": runs, "hooks": hooks}


# ---- one delivery, read once ---------------------------------------------------------------------------

class Analysis:
    """A delivery opened all the way down and read lazily: histories, packages, secrets."""

    def __init__(self, files: dict):
        self.notes = []
        self.files = expand(files, self.notes)
        self._h = self._p = self._s = None

    @property
    def histories(self) -> list:
        if self._h is None:
            self._h = find_histories(self.files, self.notes)
        return self._h

    @property
    def packages(self) -> list:
        if self._p is None:
            self._p = find_packages(self.files, self.histories, self.notes)
        return self._p

    @property
    def secrets(self) -> list:
        if self._s is None:
            self._s = find_secrets(self.files, self.histories)
        return self._s

    @property
    def complete(self) -> bool:
        return all(h.complete for h in self.histories) and not any("larger than this toolkit reads" in n for n in self.notes)


# ---- signals -------------------------------------------------------------------------------------------

_SIG_VCS = re.compile(r"(?:^|/)(?:\.git/(?:HEAD|objects/|refs/|packed-refs)|objects/[0-9a-f]{2}/[0-9a-f]{38}|objects/pack/pack-|"
                      r"\.hg/(?:store/)?00changelog\.i|_darcs/|\.svn/wc\.db|db/revprops/|\.fslckout|_FOSSIL_)")
_SIG_PKG = re.compile(r"(?:\.dist-info/RECORD|(?:^|/)\.github/workflows/[^/]+\.ya?ml|(?:^|/)extension\.vsixmanifest|\.nuspec|"
                      r"\.(?:tgz|whl|vsix|crx|nupkg|gem|bundle|fossil)|(?:^|/)package/package\.json|(?:^|/)splunkbase\.manifest)$", re.I)
_SIG_WEAK = re.compile(r"(?:(?:^|/)(?:package\.json|setup\.py|composer\.json|manifest\.json|PKG-INFO)|\.pth|\.jar|\.tar\.gz)$", re.I)
_SIG_WORDS = re.compile(r"\b(?:commits?|committed|committer|git|repositor(?:y|ies)|repo|branch(?:es)?|stash(?:es|ed)?|reflog|dangling|"
                        r"unreachable|changesets?|mercurial|darcs|fossil|subversion|svn|check-?ins?|postinstall|preinstall|"
                        r"lifecycle|install[- ]script|install[- ]hook|npm|wheel|pypi|sdist|setup\.py|pth|dist-info|nupkg|nuget|"
                        r"gemspec|rubygems|vsix|crx|extension id|supply[- ]chain|dependency confusion|typosquat\w*|workflows?|"
                        r"github actions?|leaked|access key|api[ _-]?keys?|private key|credentials?)\b", re.I)


def signals(questions, files) -> float:
    """0..1: how much the delivery and its questions look like repository or supply-chain work.
    Cheap (names, the first bytes of each file, the question words): nothing is unpacked."""
    strong = weak = False
    for key, data in files.items():
        if not isinstance(data, (bytes, bytearray)):
            continue
        tail = key.split(ARROW)[-1].replace("\\", "/")
        head = bytes(data[:28])
        if _SIG_VCS.search(tail) or _SIG_PKG.search(tail) or head[:4] in (b"PACK", b"Cr24") \
                or head.startswith((b"# v2 git bundle", b"# v3 git bundle", b"SVN-fs-dump-format-version:")):
            strong = True
            break
        if _SIG_WEAK.search(tail):
            weak = True
    hits = 0
    for q in questions or []:
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"))).replace("_", " ").replace("-", " ")
        hits += bool(_SIG_WORDS.search(text))
    share = hits / len(questions) if questions else 0.0
    score = (0.6 if strong else 0.2 if weak else 0.0) + 0.4 * share
    try:
        if str(COMMON) not in sys.path:
            sys.path.insert(0, str(COMMON))
        import triage
        if triage.lane_signals(questions or [], files):
            score *= 0.25           # one of the five known lanes claims it by its own marks
    except Exception:
        pass
    return round(min(1.0, score), 3)


# ---- the runner contract -------------------------------------------------------------------------------

_QUOTED = re.compile(r"`([^`\n]{2,300})`|\"([^\"\n]{2,300})\"|“([^”\n]{2,300})”|(?<![A-Za-z0-9])'([^'\n]{2,300})'(?![A-Za-z0-9])")
_NO_ANSWER_KINDS = ("mitre_attack_id", "json", "ordered_tokens")


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _fits(q, value) -> bool:
    """False for a value the question's own answer format refuses (its regular expression, an
    integer kind, an enum's accepted values, a no-directory-path or lowercase-hex syntax)."""
    f = _fmt(q)
    value = str(value)
    if not value or "\x00" in value:
        return False
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            if re.fullmatch(rx, value) is None:
                return False
        except re.error:
            return False
    kind = str(f.get("kind") or "")
    if kind == "integer" and not re.fullmatch(r"-?\d+", value):
        return False
    for key in ("accepted_values", "options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            return value in [str(v) for v in f[key]]
    syntax = str(f.get("syntax") or "").lower()
    if re.search(r"no directory|base filename|basename only|file name only", syntax) and "/" in value:
        return False
    if re.search(r"\b0x\b|0x prefix", syntax) and not value.startswith("0x"):
        return False
    m = re.search(r"\b(\d{1,3}) (?:lowercase |uppercase )?hex", syntax)
    if m:
        # "flag{32 lowercase hex characters}": the count is of what stands inside the wrapper the syntax
        # itself writes (the drill on a real 2024 flag was refused by the bare rule)
        wrap = re.search(r"([a-z0-9_]{1,16})\{\s*%s" % re.escape(m.group(0)), syntax)
        body = r"[0-9a-fA-F]{%d}" % int(m.group(1))
        if not re.fullmatch((re.escape(wrap.group(1)) + r"\{" + body + r"\}") if wrap else body, value, re.I if wrap else 0):
            return False
    return True


def _settle(q, key: str, forms, soft: bool = False, prefer=()):
    """One fact, written every way it may be meant (best first), always through labels.pick: nothing
    of this category is judged yet, and which fact a question means is read from its words, so even
    a single form is an unsure answer until the judge has accepted that form for the key (then
    labels.pick itself returns it plain). `soft` is kept for the callers and changes nothing."""
    seen, kept = set(), []
    for name, value in forms:
        if value is None or str(value) in seen or not _fits(q, value):
            continue
        seen.add(str(value))
        kept.append((name, str(value)))
    if not kept:
        return None
    wanted = [f for f in kept if f[0] in prefer]
    if wanted:
        kept = wanted
    return pick(f"{KEY}.{key}", kept)


def _path_forms(path: str) -> list:
    return [("path", path), ("basename", path.rsplit("/", 1)[-1])]


def _url_answer(a, key: str, url: str):
    """A URL read out of a command or a script: always unsure. Where a URL ends in source text is a
    reading (a query string built by concatenation, a trailing slash), so the forms are offered."""
    forms = [("url", url), ("no_query", re.split(r"[?#]", url)[0]), ("no_trailing_slash", re.split(r"[?#]", url)[0].rstrip("/")),
             ("origin", re.match(r"[a-z][a-z0-9+.-]*://[^/?#]+", url, re.I).group() if re.match(r"[a-z][a-z0-9+.-]*://[^/?#]+", url, re.I) else None)]
    return _settle(a.q, key, forms, soft=True)


def _date_forms(t, tz) -> list:
    if t is None:
        return []
    m = re.fullmatch(r"([+-])(\d\d)(\d\d)", tz or "+0000")
    off = (1 if not m or m.group(1) == "+" else -1) * (int(m.group(2)) * 60 + int(m.group(3))) if m else 0
    tz = tz if m else "+0000"
    loc, utc = time.gmtime(t + off * 60), time.gmtime(t)
    colon = tz[:3] + ":" + tz[3:]
    return [("iso_offset", time.strftime("%Y-%m-%dT%H:%M:%S", loc) + colon),
            ("iso_utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", utc)),
            ("git_iso", time.strftime("%Y-%m-%d %H:%M:%S ", loc) + tz),
            ("epoch", str(t)),
            ("date", time.strftime("%Y-%m-%d", loc)),
            ("date_utc", time.strftime("%Y-%m-%d", utc)),
            ("git_default", time.strftime("%a %b ", loc) + str(loc.tm_mday) + time.strftime(" %H:%M:%S %Y ", loc) + tz),
            ("iso_utc_space", time.strftime("%Y-%m-%d %H:%M:%S", utc))]


def _secret_kinds(words: str):
    """(kinds the question names, True when it names a vendor or a format and not just 'a secret')."""
    table = (
        (r"\baws\b.*\bsecret\b|\bsecret access key\b", ["aws_secret_access_key"]),
        (r"\baws\b|\baccess key id\b|\bakia\b", ["aws_access_key_id"]),
        (r"\bgithub\b|\bpersonal access token\b|\bpat\b", ["github_token"]),
        (r"\bslack\b.*\bwebhook\b", ["slack_webhook"]), (r"\bslack\b", ["slack_token", "slack_webhook"]),
        (r"\bdiscord\b", ["discord_webhook"]), (r"\btelegram\b|\bbot token\b", ["telegram_bot_token"]),
        (r"\bjwt\b|\bjson web token\b", ["jwt"]), (r"\bgoogle\b|\bgcp\b", ["google_api_key"]), (r"\bstripe\b", ["stripe_key"]),
        (r"\bnpm\b.*\btoken\b", ["npm_token"]), (r"\bpypi\b", ["pypi_token"]), (r"\bhugging ?face\b", ["huggingface_token"]),
        (r"\banthropic\b", ["anthropic_api_key"]), (r"\bopenai\b", ["openai_api_key"]), (r"\bflag\b", ["flag"]),
    )
    for rx, kinds in table:
        if re.search(rx, words):
            return kinds, True
    if re.search(r"\bpassword\b|\bpasswd\b", words):
        return ["assigned_password", "url_credentials"], False
    if re.search(r"\bsecrets?\b|\btokens?\b|\bcredentials?\b|\bapi ?keys?\b|\baccess keys?\b|\bleak", words):
        return [k for k in STRICT_KINDS if k not in ("flag", "private_key")], False
    return [], False


class _Asked:
    """One question, read once."""

    def __init__(self, q):
        self.q = q
        self.text = " ".join(str(q.get("question") or "").split())
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
        f = _fmt(q)
        self.kind = str(f.get("kind") or "")
        self.syntax = str(f.get("syntax") or "")
        self.words = re.sub(r"\s+", " ", (self.text + " " + re.sub(r"[-_./]+", " ", aid)).lower())
        self.hints = (self.words + " " + self.syntax.lower())
        self.quoted = [next(g for g in m.groups() if g) for m in _QUOTED.finditer(self.text)]

    def w(self, rx: str) -> bool:
        return re.search(rx, self.words) is not None

    def h(self, rx: str) -> bool:
        return re.search(rx, self.hints) is not None


def _id_answer(a: _Asked, h, cid, field="commit_id"):
    forms = h.id_forms(cid)
    m = re.search(r"\bfirst (\d{1,2}) (?:hex(?:adecimal)? )?(?:characters|chars|digits)\b", a.hints)
    if m and forms and forms[0][0] == "full" and 4 <= int(m.group(1)) <= len(forms[0][1]):
        n = int(m.group(1))
        if isinstance(h, GitRepo) and len(h.resolve_prefix(cid[:n])) != 1:
            return None
        forms = [(f"first{n}", cid[:n])]
    prefer = ()
    if a.h(r"\bfull\b|\bcomplete\b|\b40[- ]?(?:char|hex|lowercase|digit)|\bsha-?1\b.*\b40\b"):
        prefer = ("full",)
    elif a.h(r"\bshort\b|\babbreviat|\b7[- ]?(?:char|hex|digit)|\bseven[- ]char"):
        prefer = ("short7", "short12", "short10")
    return _settle(a.q, f"{field}/{h.kind}", forms, soft=not h.verified, prefer=prefer)


_COUNT_WORDS = frozenset("""how many number of the a an total count what is are was were there in does do did have has it its this
    repository repo git project history evidence archive bundle delivered delivery altogether overall all exist exists
    commit commits branch branches local remote tracking tag tags stash stashes stashed entries entry dangling unreachable orphan
    orphaned lost object objects blob blobs tree trees author authors contributor contributors committer committers distinct
    unique different patch patches changeset changesets revision revisions check ins checkin checkins darcs fossil mercurial hg svn
    subversion recorded""".split())
_COUNT_KINDS = (r"commits?|patch(?:es)?|changesets?|revisions?|checkins?|check", r"branch(?:es)?", r"tags?", r"stash(?:es|ed)?", r"authors?|contributors?|committers?")


def _bare_count(a: _Asked) -> bool:
    """True when the question is nothing but a count of one kind of thing in the repository. Any
    other word ('on the dev branch', 'have tags', 'lines', a name) makes it a count this toolkit
    does not compute, and the count of the whole repository would be another fact."""
    words = re.findall(r"[a-z0-9]+", (a.text or a.words).lower())
    if not words or any(w not in _COUNT_WORDS for w in words):
        return False
    return sum(1 for rx in _COUNT_KINDS if any(re.fullmatch(rx, w) for w in words)) <= 1


def _one(items):
    """The only member of a collection of distinct things, or None."""
    items = list(dict.fromkeys(items))
    return items[0] if len(items) == 1 else None


def _targets(a: _Asked, A: Analysis):
    """The commits the question is about: ('all', None) when it names none, else (why, [(history, id)])."""
    hs = A.histories
    out = []
    for tok in re.findall(r"(?<![0-9a-zA-Z])[0-9a-f]{7,64}(?![0-9a-zA-Z])", a.text):
        hit = [(h, c) for h in hs for c in h.find_commit(tok)]
        if len(hit) == 1:
            return "named", hit
    needle = a.quoted[0] if len(a.quoted) == 1 else None
    removal = a.w(r"\bremov|\bdelet|\bscrub|\bpurg|\beras|\bdropp|\brevert|\bclean(?:ed|s)? up")
    adding = a.w(r"\badd(?:ed|s|ing)?\b|\bintroduc|\bfirst (?:appear|contain|includ|commit|show|seen)|\bleak|\binsert|\bcreat|"
                 r"\bcommitted\b|\bbrought\b|\bexpos|\bhardcod|\bhard-cod|\bembed|\bplant")
    # which commit is meant must be plain: one direction, and no word that picks among several
    vague = (removal and a.w(r"\badd(?:ed|s|ing)?\b|\bintroduc|\binsert")) or \
        a.w(r"\b(?:last|latest|second|third|previous|next|before|after|other|another|except|touch\w*|modif\w*|chang\w*|edit\w*)\b")
    if needle and a.w(r"\bmessage\b|\bsubject\b") and not a.w(r"\bfile\b"):
        return "message", [(h, c) for h in hs for c in h.by_message(needle)]
    if needle and (vague or not (removal or adding)):
        return "vague", []
    if needle:
        raw = needle.encode("utf-8")
        for h in hs:
            if a.w(r"\bfile\b|\bfilename\b|\bpath\b") and isinstance(h, SnapshotHistory):
                # the quoted text may be a file's name: the commits where that path appears or goes
                paths = set()
                for c in h.ids():
                    paths.update(p for p in h.snapshot(c) if p == needle or p.rsplit("/", 1)[-1] == needle)
                if len(paths) == 1:
                    path = next(iter(paths))
                    if removal:
                        out += [(h, c) for c, p in h.deleted() if p == path]
                    else:
                        out += [(h, c) for c in h.ids() if path in h.snapshot(c) and not any(path in h.snapshot(p) for p in h.parents(c))]
                    continue
            out += [(h, c) for c in (h.removing(raw) if removal else h.adding(raw))]
        return ("removed" if removal else "added"), out
    kinds, _ = _secret_kinds(a.words)
    if kinds and a.w(r"\bsecret|\btoken|\bcredential|\bkey\b|\bpassword|\bleak|\bjwt\b|\bwebhook|\bflag\b"):
        values = list(dict.fromkeys(s["value"] for s in A.secrets if s["kind"] in kinds))
        # A secret written in a commit message is in that commit and no other, whatever the verb
        # ("holds", "contains", "mentions"); one in a file needs the question to say added or removed.
        in_message = [(h, w["commit"]) for s in A.secrets if s["kind"] in kinds for w in s["where"]
                      if w.get("state") == "commit message" and w.get("commit") for h in hs if h.label == w.get("repo")]
        if not values or vague or (not (removal or adding) and not in_message):
            return "secret", []
        if removal and in_message:
            return "secret", []
        for h in hs:
            for v in values:
                raw = v.encode("utf-8")
                if removal or adding or not in_message:
                    out += [(h, c) for c in (h.removing(raw) if removal else h.adding(raw))]
        return "secret", list(dict.fromkeys(out + in_message))
    gits = [h for h in hs if isinstance(h, GitRepo)]
    # from here on the commit is chosen by a word (first, latest, stash, dangling) or not at all: a
    # question that also names a branch or tag, an ordinal, or a condition means another commit
    if _names_other_ref(a, gits) or a.w(r"\b(?:second|third|fourth|penultimate|previous|prior|preceding|next|before|after|other|another|except)\b") \
            or a.w(r"\b(?:commit|changeset|revision|check-?in|patch)(?:s|ted)? (?:made |authored |created |pushed )?(?:that|which|whose|where|to|on|by|from|"
                   r"with|touching|adding|containing|modifying|changing|removing|deleting)\b") \
            or (a.w(r"\b(?:first|initial|root|earliest|oldest)\b") and a.w(r"\b(?:latest|last|most recent|newest|tip)\b")):
        return "vague", []
    if a.w(r"\bstash"):
        return "stash", [(h, s["id"]) for h in gits for s in h.stashes()]
    if a.w(r"\bdangling\b|\bunreachable\b|\borphan(?:ed)?\b|\blost\b|\bhidden\b|\bdetached\b") and a.w(r"\bcommit"):
        for h in gits:
            found = h.lost("commit", a.w(r"\bdangling\b"))
            if found is None:
                return "unreachable", []
            out += [(h, o) for o in found]
        return "unreachable", out
    if a.w(r"\b(?:first|initial|root|earliest|oldest)\b") and a.w(r"\bcommit|\bchangeset|\brevision|\bcheck-?in|\bpatch\b"):
        return "first", [(h, c) for h in hs if isinstance(h, SnapshotHistory) for c in h.ids() if not h.parents(c)]
    if a.w(r"\b(?:latest|last|most recent|newest|head|tip|current)\b") and a.w(r"\bcommit|\bchangeset|\brevision|\bcheck-?in"):
        return "head", [(h, h.head()["id"]) for h in gits if h.head()["id"] and h.commit(h.head()["id"])]
    return "all", None


def _names_other_ref(a: _Asked, gits) -> bool:
    """True when the question's text holds the short name of a branch or tag that is not the
    checked-out branch ('the last commit on dev', 'the tip of release-1')."""
    for h in gits:
        cur = h.head().get("ref") or ""
        for ref in h.refs():
            if ref == cur or not ref.startswith(("refs/heads/", "refs/tags/", "refs/remotes/")):
                continue
            short = ref.split("/", 2)[2]
            for name in {short, short.rsplit("/", 1)[-1]} - {"HEAD", ""}:
                if re.search(r"(?<![\w./-])" + re.escape(name) + r"(?![\w/-])", a.text):
                    return True
    return False


_OTHER_OBJECT = r"\btrees?\b|\bblobs?\b|\bsize\b|\bbytes?\b|\blength\b|\bmd5\b|\bcrc|\bchecksum\b|\blines?\b|\bcontents?\b"


def _answer_history(a: _Asked, A: Analysis):
    hs = A.histories
    if not hs or not A.complete:
        return None
    why, targets = _targets(a, A)
    count = a.w(r"\bhow many\b|\bnumber of\b|\bcount\b|\btotal\b") or a.kind == "integer"
    gits = [h for h in hs if isinstance(h, GitRepo)]
    one_git = gits[0] if len(gits) == 1 and len(hs) == 1 else None
    # counts of the whole repository
    if count and a.w(r"\b(?:that|which|whose|with|where|named|by|since|before|after|contain\w*|touch\w*|modif\w*|made|authored|"
                     r"other than|except|without|between|per|each)\b"):
        return None             # a filtered count is another fact than the ones counted here
    if count and not _bare_count(a):
        return None
    if count and one_git is not None and why in ("all", "stash", "unreachable"):
        h, r = one_git, one_git.reach()
        refs = h.refs()
        if a.w(r"\bstash"):
            return _settle(a.q, "count/stashes", [("stashes", len(h.stashes()))])
        if a.w(r"\bbranch"):
            local = sum(1 for n in refs if n.startswith("refs/heads/"))
            remote = sum(1 for n in refs if n.startswith("refs/remotes/") and not n.endswith("/HEAD"))
            if a.w(r"\bremote"):
                return _settle(a.q, "count/remote_branches", [("remote", remote)])
            return _settle(a.q, "count/branches", [("local", local)] + ([("local_and_remote", local + remote)] if remote else []))
        if a.w(r"\btags?\b"):
            return _settle(a.q, "count/tags", [("tags", sum(1 for n in refs if n.startswith("refs/tags/")))])
        typ = "commit" if a.w(r"\bcommit") else "blob" if a.w(r"\bblob|\bfile") else "tree" if a.w(r"\btree") else None
        if a.w(r"\bdangling\b|\bunreachable\b|\borphan|\blost\b"):
            def n(name):
                return sum(1 for o in r[name] if typ is None or h.objects[o][0] == typ)
            order = ("dangling", "unreachable", "no_ref") if a.w(r"\bdangling\b") else ("unreachable", "no_ref", "dangling")
            return _settle(a.q, f"count/unreachable_{typ or 'objects'}", [(k, n(k)) for k in order])
        if a.w(r"\bcommit"):
            every = [o for o, (t, _) in h.objects.items() if t == "commit"]
            head = h.head()["id"]
            forms = [("reachable_from_refs", sum(1 for o in every if o in r["refs"])), ("all_commit_objects", len(every))]
            if head:
                forms.insert(0, ("reachable_from_head", len(h._closure_commits(head))))
            return _settle(a.q, "count/commits", forms)
        if a.w(r"\bauthor|\bcontributor|\bcommitter"):
            emails = {h.commit(o)["email"] for o, (t, _) in h.objects.items() if t == "commit"}
            names = {h.commit(o)["author"] for o, (t, _) in h.objects.items() if t == "commit"}
            return _settle(a.q, "count/authors", [("emails", len(emails)), ("names", len(names))])
        return None
    if count and len(hs) == 1 and one_git is None and why == "all" \
            and a.w(r"\bcommits?\b|\bpatch(?:es)?\b|\bcheck-?ins?\b|\bchangesets?\b|\brevisions?\b"):
        h = hs[0]
        ids = list(h.ids())
        forms = [("all", len(ids))]
        # Fossil opens every repository with an empty check-in, and a Subversion dump with revision 0
        empty = [c for c in ids if not (h.meta(c).get("message") or "").strip() or (h.meta(c).get("message") or "").strip() == "initial empty check-in"]
        if 0 < len(empty) < len(ids) and h.kind in ("fossil", "svn"):
            forms.append(("without_empty_first", len(ids) - len(empty)))
        return _settle(a.q, f"count/commits.{h.kind}", forms, soft=True)
    if count:
        return None
    # facts of the whole repository that name no commit
    if why == "all":
        if a.w(r"\bdangling\b|\bunreachable\b|\borphan(?:ed)?\b|\blost\b") and a.w(r"\bblob|\bobject|\bfile|\bcontent") and one_git is not None:
            h = one_git
            found = h.lost("blob", a.w(r"\bdangling\b"))
            if not found or len(found) != 1:
                return None
            oid = found[0]
            if a.w(r"\bhash\b|\bsha\b|\bid\b|\boid\b|\bidentifier\b") and not a.w(r"\bcontent|\bcontain|\btext\b|\binside\b"):
                return _id_answer(a, h, oid, "blob_id")
            if a.w(r"\bcontent|\bcontain|\btext\b|\binside\b|\bsay|\bhold"):
                try:
                    text = h.blob(oid).decode("utf-8")
                except UnicodeDecodeError:
                    return None
                body = text.strip()
                if not body or "\n" in body or len(body) > 400:
                    return None
                return _settle(a.q, "blob_content/dangling", [("stripped", body)], soft=body != text.rstrip("\n"))
            return None
        if a.w(r"\bdelet|\bremov") and a.w(r"\bfile|\bfilename|\bpath\b"):
            rows = [(h, c, p) for h in hs for c, p in h.deleted()]
            path = _one(p for _, _, p in rows)
            if path is None or any(isinstance(h, SnapshotHistory) and h.deletions_in_doubt() for h in hs):
                return None
            if a.w(r"\bcommit|\bchangeset|\brevision|\bpatch\b") and a.w(r"\bhash\b|\bsha\b|\bid\b|\bwhich commit|\bwhat commit"):
                hit = _one((h, c) for h, c, _ in rows)
                return _id_answer(a, hit[0], hit[1]) if hit else None
            if a.w(r"\bemail"):
                hit = _one((h, c) for h, c, _ in rows)
                return _settle(a.q, "author_email/deleted_file", [("email", hit[0].meta(hit[1]).get("email"))],
                               soft=not hit[0].verified) if hit else None
            if a.w(r"\bname\b|\bfilename\b|\bwhich file|\bwhat file|\bpath\b|\bfile was|\bfile that"):
                prefer = ("basename",) if a.h(r"no directory|base ?(?:file)?name") else ("path",) if a.h(r"\bfull path|\brelative path|\bwith (?:its )?(?:directory|path)") else ()
                return _settle(a.q, "path/deleted_file", _path_forms(path), soft=not all(h.verified for h, _, _ in rows), prefer=prefer)
            return None
        if one_git is not None:
            h = one_git
            if a.w(r"\bremote\b|\borigin\b|\bupstream\b") and a.w(r"\burl\b|\baddress\b") \
                    and not a.w(r"\bissues?\b|\btracker\b|\bhomepage\b|\bwiki\b|\bdocs?\b|\bdocumentation\b|\bwebsite\b|\bemail\b"):
                return _settle(a.q, "remote_url/git", [("url", _one(git_config_facts(h)["remotes"].values()))], soft=True)
            if a.w(r"\bcurrent branch|\bchecked[- ]out branch|\bhead point|\bactive branch") and not a.w(r"\bremote\b|\borigin\b|\bupstream\b"):
                ref = h.head()["ref"]
                return _settle(a.q, "branch/head", [("name", ref[len("refs/heads/"):])]) if ref and ref.startswith("refs/heads/") else None
            if a.w(r"\bemail") and a.w(r"\bauthor|\bcommitter|\bwho\b|\bdeveloper\b") \
                    and not a.w(r"\bfiles?\b|\bconfig|\bappears?\b|\bcontain|\bhard-?cod|\bsource\b|\bcode\b|\bcontact\b"):
                rows = [h.commit(c) for c in h.ids()]
                who = [("committer_email",)] if a.w(r"\bcommitter") else [("email",)] if a.w(r"\bauthor") else [("email",), ("committer_email",)]
                return _settle(a.q, "author_email/git", [("email", _one(c[k[0]] for c in rows for k in who))])
        return None
    # a fact of the one commit the question points at
    hit = _one(targets)
    if hit is None:
        return None
    h, cid = hit
    soft = not h.verified
    m = h.meta(cid)
    # the commit is known, but the question may be after one of its objects (a tree, a file's hash)
    other = a.w(_OTHER_OBJECT) or (len(cid) != 64 and a.w(r"\bsha-?(?:256|384|512)\b")) or \
        (isinstance(h, SnapshotHistory) and why in ("first", "head", "named", "stash", "unreachable")
         and any(t.rsplit("/", 1)[-1] in {p.rsplit("/", 1)[-1] for p in h.snapshot(cid)}
                 for t in re.findall(r"[\w./-]*\w\.\w+|[\w.-]+/[\w./-]+", a.text)))
    if a.w(r"\bemail"):
        field = "committer_email" if a.w(r"\bcommitter") and m.get("committer_email") else "email"
        return _settle(a.q, f"author_email/{h.kind}", [("email", m.get(field))], soft=soft)
    if a.w(r"\bauthor(?:ed)?\b|\bcommitter\b|\bwho\b|\busername\b|\buser\b"):
        field = "committer" if a.w(r"\bcommitter") and m.get("committer") else "author"
        forms = [("name", m.get(field))]
        if m.get("email") and m.get(field):
            forms += [("email", m["email"]), ("name_email", f"{m[field]} <{m['email']}>")]
        return _settle(a.q, f"author/{h.kind}", forms, soft=soft)
    if a.w(r"\bmessage\b|\bsubject\b|\bcomment\b|\bsummary\b|\btitle\b") and why != "message":
        text = (m.get("message") or "").strip()
        if not text:
            return None
        return _settle(a.q, f"message/{h.kind}", [("subject", text.split("\n")[0].strip()), ("full", text)], soft=soft)
    if a.w(r"\bdate\b|\btime\b|\btimestamp\b|\bwhen\b"):
        prefer = ()
        if a.h(r"\bepoch\b|\bunix\b") or a.kind == "integer":
            prefer = ("epoch",)
        elif a.h(r"yyyy-mm-dd(?![t ]?hh)") or (a.w(r"\bdate\b") and not a.w(r"\btime\b|\btimestamp\b|\bwhen\b")):
            prefer = ("date_utc",) if a.h(r"\butc\b") else ("date", "date_utc")
        elif a.h(r"\butc\b"):
            prefer = ("iso_utc", "iso_utc_space")
        key_time = m.get("committer_time") if a.w(r"\bcommitter") and m.get("committer_time") else m.get("time")
        return _settle(a.q, f"date/{h.kind}", _date_forms(key_time, m.get("tz")), soft=True, prefer=prefer)
    if a.w(r"\bbranch") and isinstance(h, GitRepo):
        return _settle(a.q, "branch/git", [("name", _one(h.branches_with(cid)))])
    if other:
        return None
    if a.w(r"\bparent") and isinstance(h, SnapshotHistory):
        parent = _one(h.parents(cid))
        return _id_answer(a, h, parent, "parent_id") if parent else None
    if a.w(r"\bwhich file|\bwhat file|\bfilename\b|\bfile name\b|\bpath\b") and isinstance(h, SnapshotHistory) and why not in ("added", "removed"):
        path = _one(h.changes(cid))
        return _settle(a.q, f"path/changed_{h.kind}", _path_forms(path), soft=soft) if path else None
    if a.w(r"\bcommit|\bchangeset|\brevision|\bpatch\b|\bcheck-?in|\bhash\b|\bsha\b") or why == "stash":
        return _id_answer(a, h, cid)
    return None


def _answer_secret(a: _Asked, A: Analysis):
    kinds, named = _secret_kinds(a.words)
    if not kinds or not A.complete:
        return None
    found = [s for s in A.secrets if s["kind"] in kinds]
    if "assigned_password" in kinds:
        found = [s for s in found if s["kind"] == "assigned_password"] or found
    # a question that names a file is about the secrets found in that file
    in_named = [s for s in found if any(w.get("path") and re.search(r"(?<![\w./-])" + re.escape(w["path"].split(ARROW)[-1].rsplit("/", 1)[-1])
                                                                   + r"(?![\w-])", a.text) for w in s["where"])]
    found = in_named or found
    value = _one(s["value"] for s in found)
    if value is None:
        return None
    row = next(s for s in found if s["value"] == value)
    if row["kind"] == "jwt" and a.w(r"\balgorithm\b|\balg\b|\bsubject\b|\bissuer\b|\baudience\b|\bclaim\b"):
        parts = jwt_parts(value)
        for rx, part, claim in ((r"\balgorithm\b|\balg\b", "header", "alg"), (r"\bsubject\b", "payload", "sub"),
                                (r"\bissuer\b", "payload", "iss"), (r"\baudience\b", "payload", "aud")):
            if a.w(rx):
                got = (parts.get(part) or {}).get(claim)
                return _settle(a.q, f"jwt/{claim}", [("value", got)]) if isinstance(got, str) else None
        return None
    if a.w(r"\bwhich file|\bwhat file|\bfilename\b|\bfile name\b|\bpath\b|\bin which\b.*\bfile"):
        path = _one(w["path"] for w in row["where"] if w.get("path"))
        return _settle(a.q, "path/secret", _path_forms(path.split(ARROW)[-1])) if path else None
    if row["kind"] == "private_key" or "\n" in value:
        return None
    if a.w(r"\bregion\b|\bnext to\b|\bvariable\b|\bname of\b|\bowner\b|\baccount\b|\busername\b|\bexpir|\bscopes?\b|\bpermission|"
           r"\blength\b|\bprefix\b|\btype\b|\bkind\b|\blines?\b|\bport\b|\bhow many\b|\bnumber of\b|\bnot\b|\brotated to\b") or a.kind == "integer":
        return None             # a fact about the secret, not its value
    if row["kind"] == "url_credentials":
        m = re.match(r"[^:]+://[^:]+:([^@]+)@", value)
        return _settle(a.q, "secret/url_password", [("password", m.group(1))], soft=True) if m else None
    return _settle(a.q, f"secret/{row['kind'] if named else 'unnamed'}", [("value", value)],
                   soft=not named or row["kind"].startswith("assigned_"))


_PKG_WORDS = (("npm", r"\bnpm\b|\bnode(?:\.js)?\b|\bpackage\.json\b|\btarball\b"), ("wheel", r"\bwheel\b|\bwhl\b|\bdist-info\b"),
              ("sdist", r"\bsdist\b|\bsetup\.py\b|\bsource distribution\b"), ("vsix", r"\bvsix\b|\bvs ?code\b|\bvisual studio code\b"),
              ("crx", r"\bcrx\b|\bchrome\b|\bbrowser extension\b"), ("browser_extension", r"\bchrome\b|\bbrowser extension\b|\bmanifest\.json\b"),
              ("jar", r"\bjar\b|\bjava\b|\bmanifest\.mf\b"), ("nupkg", r"\bnupkg\b|\bnuget\b|\bnuspec\b"),
              ("gem", r"\bgem\b|\brubygems?\b|\bgemspec\b"), ("composer", r"\bcomposer\b|\bphp\b"),
              ("github_workflow", r"\bworkflow|\bgithub actions?\b|\bci\b|\bpipeline\b"))


def _answer_package(a: _Asked, A: Analysis):
    pkgs = A.packages
    if not pkgs:
        return None
    named = [k for k, rx in _PKG_WORDS if a.w(rx)]
    scoped = [p for p in pkgs if p["kind"] in named] if named else [p for p in pkgs if p["kind"] != "package_config"]
    member = a.q.get("member")
    if member and any(p["file"].split(ARROW)[-1].endswith(Path(member).name) for p in scoped):
        scoped = [p for p in scoped if p["file"].split(ARROW)[-1].endswith(Path(member).name)]
    wants_url = a.w(r"\burls?\b|\bendpoint\b|\bc2\b|\blink\b|\bdownload(?:s|ed)? from\b")
    wants_host = a.w(r"\bdomain\b|\bhost(?:name)?\b|\bserver\b") and not wants_url
    path_prefer = ("basename",) if a.h(r"no directory|base ?(?:file)?name") else ("path",) if a.h(r"\bfull path|\brelative path") else ()
    # a wheel's RECORD
    manifests = [p for p in pkgs if p["kind"] == "hash_manifest"]
    if manifests and not a.w(r"\brecord\b|\bwheel\b|\bwhl\b") \
            and a.w(r"\btamper|\bmismatch|\bmodif|\baltered\b|\bintegrity\b|\bbackdoor|\bmanifest\b|\bnot match|\bfails? (?:the )?(?:hash|check)"):
        if len(manifests) != 1:
            return None
        rec = manifests[0]["record"]
        if a.w(r"\bunlisted\b|\bnot listed\b|\bmissing from\b|\bnot in\b|\bextra\b|\badded file\b"):
            path = _one(rec["unlisted"])
            return _settle(a.q, "path/manifest_unlisted", _path_forms(path), prefer=path_prefer) if path else None
        if a.w(r"\bhow many\b|\bnumber of\b") or a.kind == "integer":
            if a.w(r"\bsize\b|\bbytes?\b|\blines?\b|\blength\b|\bentries\b|\blisted\b"):
                return None
            return _settle(a.q, "count/manifest_mismatched", [("mismatched", len(rec["mismatched"]))])
        if len(rec["mismatched"]) != 1:
            return None
        r = rec["mismatched"][0]
        if a.w(r"\bhash\b|\bdigest\b|\bsha-?256\b|\bchecksum\b") and not a.w(r"\bwhich file|\bwhat file|\bfilename\b|\bname of the file"):
            if a.w(r"\brecorded\b|\blisted\b|\bclaimed\b|\bexpected\b|\bstated\b|\bdeclared\b|\boriginal\b"):
                return _settle(a.q, "manifest_hash/recorded", [("hex", r["recorded"])])
            if a.w(r"\bactual\b|\breal\b|\bcomputed\b|\bcurrent\b|\btrue\b|\bcorrect\b|\bon disk\b"):
                return _settle(a.q, "manifest_hash/actual", [("hex", r["actual"])])
            return None
        return _settle(a.q, "path/manifest_mismatch", _path_forms(r["path"]), prefer=path_prefer)
    if a.w(r"\brecord\b") or (a.w(r"\bwheel\b|\bwhl\b") and a.w(r"\btamper|\bmismatch|\bmodif|\baltered\b|\bintegrity\b")):
        rows = [(p, r) for p in scoped if p["kind"] == "wheel" for r in p["record"]["mismatched"]]
        if a.w(r"\bunlisted\b|\bnot listed\b|\bmissing from\b|\bnot in\b|\bextra\b|\badded file\b"):
            path = _one(u for p in scoped if p["kind"] == "wheel" for u in p["record"]["unlisted"])
            return _settle(a.q, "path/record_unlisted", _path_forms(path), prefer=path_prefer) if path else None
        if a.w(r"\bhow many\b|\bnumber of\b") or a.kind == "integer":
            if not a.w(r"\bmismatch|\bnot match|\bfail|\btamper|\bmodif|\baltered\b|\bdiffer|\bwrong\b|\binvalid\b") \
                    or a.w(r"\bsize\b|\bbytes?\b|\blines?\b|\blength\b|\bentries\b|\blisted\b"):
                return None         # a size, a line count, the rows of RECORD: other facts
            return _settle(a.q, "count/record_mismatched", [("mismatched", len(rows))]) if any(p["kind"] == "wheel" for p in scoped) else None
        if len(rows) != 1:
            return None
        r = rows[0][1]
        if a.w(r"\bhash\b|\bdigest\b|\bsha-?256\b|\bchecksum\b") and not a.w(r"\bwhich file|\bwhat file|\bfilename\b|\bname of the file"):
            prefer = ("hex",) if a.h(r"\bhex") else ("record_b64",) if a.h(r"base64|urlsafe|as recorded|as written") else ()
            if a.w(r"\brecorded\b|\blisted\b|\bclaimed\b|\bexpected\b|\bstated\b|\bdeclared\b|\boriginal\b"):
                return _settle(a.q, "record_hash/recorded", [("record_b64", r["recorded"]), ("hex", r["recorded_hex"])], prefer=prefer)
            if a.w(r"\bactual\b|\breal\b|\bcomputed\b|\bcurrent\b|\btrue\b|\bcorrect\b|\bon disk\b"):
                return _settle(a.q, "record_hash/actual", [("hex", r["actual_hex"]), ("record_b64", r["actual"])], prefer=prefer)
            return None
        return _settle(a.q, "path/record_mismatch", _path_forms(r["path"]), prefer=path_prefer)
    hooks = [(p, h) for p in scoped for h in p.get("hooks", [])]
    # .pth
    if a.w(r"\bpth\b"):
        pth = [(p, h) for p, h in hooks if h["when"] == "pth"]
        if wants_url or wants_host:
            url = _one(u for _, h in pth for u in h["urls"])
            if not url:
                return None
            return _url_answer(a, "url/pth", url) if wants_url else _settle(a.q, "host/pth", [("host", host_of(url))])
        # "which .pth file", "what pth file" too: the kind stands between the question word and "file"
        if a.w(r"\b(?:which|what) (?:\.?pth )?file|\bfilename\b|\bname\b|\bpath\b") and not a.w(r"\bmodule\b|\btarget\b|\bimport|\bline\b|\bexecut"):
            path = _one(f for p in scoped for f in p.get("pth", []))
            return _settle(a.q, "path/pth", _path_forms(path), prefer=path_prefer) if path else None
        line = _one(h["command"] for _, h in pth)
        if line and a.w(r"\bimport|\bexecut|\brun|\bcode\b|\bline\b|\bcommand\b|\bpayload\b|\bmodule\b"):
            m = re.fullmatch(r"import\s+([A-Za-z_][\w.]*)\s*", line)
            forms = [("module", m.group(1)), ("line", line)] if m and a.w(r"\bmodule\b") else [("line", line)] + ([("module", m.group(1))] if m else [])
            return _settle(a.q, "pth/line", forms, soft=True)
        return None
    # what runs at install time
    asks_hook = a.w(r"\bpost-?install|\bpre-?install|\binstall(?:ation)?[- ](?:script|hook|command|time)|\blifecycle\b|\bsetup\.py\b|"
                    r"\bextconf\b|\binstall\.ps1\b|\binit\.ps1\b|\b(?:on|during|at|upon|after|before) install|\bwhen (?:it is )?installed\b|"
                    r"\binstall(?:s|ed)?\b.*\b(?:run|execut)|\b(?:run|execut)\w*\b.*\binstall")
    if asks_hook:
        if a.w(r"\bpost-?install"):
            sel = [(p, h) for p, h in hooks if h["when"] in ("postinstall", "post-install-cmd")]
        elif a.w(r"\bpre-?install"):
            sel = [(p, h) for p, h in hooks if h["when"] in ("preinstall", "pre-install-cmd")]
        elif a.w(r"\bsetup\.py\b"):
            sel = [(p, h) for p, h in hooks if h["when"] == "setup.py"]
        else:
            sel = [(p, h) for p, h in hooks if h.get("install_time") and not h.get("implicit") and not h.get("custom_command")]
        if not sel:
            return None
        soft = any(h["when"] == "setup.py" for _, h in sel)
        if wants_url or wants_host:
            url = _one(u for _, h in sel for u in h["urls"])
            if not url:
                return None
            if a.w(r"\bport\b|\bregistry\b|\bip\b"):
                return None
            if wants_host:
                return _settle(a.q, "host/install_hook", [("host", host_of(url))], soft=soft)
            return _url_answer(a, "url/install_hook", url)
        if a.w(r"\bwhich (?:lifecycle )?(?:script|hook)\b|\bname of the (?:lifecycle )?(?:script|hook)\b|\bwhich lifecycle\b|\bhook name\b|\bscript name\b"):
            return _settle(a.q, "hook_name/install", [("name", _one(h["when"] for _, h in sel))], soft=soft)
        if a.w(r"\bwhich file|\bwhat file|\bfilename\b|\bfile name\b|\bscript file\b"):
            path = _one(f for _, h in sel for f in h.get("files", []))
            return _settle(a.q, "path/install_hook_file", _path_forms(path), prefer=path_prefer) if path else None
        if a.w(r"\bexfiltrat|\bsteal|\bstole|\bsend|\bsent\b|\bupload|\benvironment variable|\bport\b|\bentry ?point|\bafter\b.*\bdownload|"
               r"\bthen\b|\bnext\b|\bsecond\b|\bwrit|\bread|\bargument|\bbefore install"):
            return None         # what the script goes on to do is not the manifest's command
        if a.w(r"\bcommand\b|\brun|\bexecut|\bscript\b|\bwhat does\b|\bpayload\b"):
            cmd = _one(h["command"] for _, h in sel)
            return _settle(a.q, "command/install_hook", [("command", cmd.strip())], soft=soft or "\n" in cmd.strip()) if cmd else None
        return None
    # a workflow
    if "github_workflow" in named:
        flows = [p for p in scoped if p["kind"] == "github_workflow"]
        runs = [h for p in flows for h in p["hooks"]]
        if wants_url or wants_host:
            url = _one(u for h in runs for u in h["urls"])
            if not url:
                return None
            return _url_answer(a, "url/workflow", url) if wants_url else _settle(a.q, "host/workflow", [("host", host_of(url))])
        if a.w(r"\baction\b|\buses\b"):
            uses = _one(u for p in flows for u in p["uses"])
            return _settle(a.q, "action/workflow", [("ref", uses), ("name", uses.split("@")[0])]) if uses else None
        if a.w(r"\btrigger|\bevent\b"):
            return _settle(a.q, "trigger/workflow", [("event", _one(t for p in flows for t in p["triggers"]))])
        if a.w(r"\bsecret"):
            name = _one(s for p in flows for s in p["secrets_used"])
            return _settle(a.q, "secret_name/workflow", [("name", name), ("expression", f"secrets.{name}")]) if name else None
        if a.w(r"\bcommand\b|\brun\b|\bexecut"):
            cmd = _one(h["command"] for h in runs)
            return _settle(a.q, "command/workflow", [("command", cmd.strip())], soft="\n" in cmd.strip()) if cmd else None
        return None
    # facts of the one package
    if not a.w(r"\bpackage\b|\bextension\b|\bmodule\b|\blibrary\b|\bdependency\b|\badd-?on\b|\bplugin\b") and not named:
        return None
    real = [p for p in scoped if p["kind"] not in ("github_workflow", "package_config")]
    if len(real) != 1:
        return None
    p = real[0]
    if a.w(r"\bextension id\b|\bextension identifier\b|\bcrx id\b") and p.get("extension_id"):
        return _settle(a.q, "extension_id/crx", [("id", p["extension_id"])])
    if a.w(r"\bmain[- ]class\b") and p["kind"] == "jar":
        return _settle(a.q, "entry/jar_main_class", [("main_class", p.get("entry"))])
    things = r"(?:package|wheel|extension|gem|jar|module|library|tarball|crate|add-?on|plugin|distribution)"
    if a.w(r"\bversion of (?:the |this )?(?:[\w.@/-]+ ){0,2}" + things + r"\b|\b" + things + r"(?:'s)? version\b|"
           r"\bversion (?:number )?(?:is|does|has) (?:the |this )?(?:[\w.@/-]+ ){0,2}" + things + r"\b") \
            and not a.w(r"\bmanifest|\bpython\b|\bnode\b|\bdepend|\brequire|\bengine|\bminimum\b|\bprotocol\b|\bformat\b|"
                                       r"\bschema\b|\bapi\b|\btls\b|\bclass\b|\bbytecode\b|\bcompiler\b|\bruntime\b|\bjava\b|\bjdk\b|\block ?file|"
                                       r"\bfix(?:ed|es)?\b|\bbug\b|\bfirst\b|\blast\b|\bprevious\b|\bnext\b|\blatest\b|\bwhich version\b|"
                                       r"\bwheel version\b|\bspec\b|\bgenerator\b|\btamper|\bimitat|\btyposquat"):
        return _settle(a.q, f"version/{p['kind']}", [("version", p.get("version"))])
    if a.w(r"\bpackage name\b|\bname of the (?:\w+ )?(?:package|extension|module|gem)\b|\b(?:package|extension|gem)'s name\b") \
            and not a.w(r"\bauthors?\b|\bmaintainer|\bimitat|\bimpersonat|\btyposquat|\bmimic|\bdepend|\brequire|\bscript\b|\bconsole\b|\bvariable\b|"
                        r"\bfunction\b|\bfiles?\b|\bclass\b|\bpublisher\b|\boriginal\b|\blegitimate\b|\breal\b|\bthat\b|\bwhich\b"):
        return _settle(a.q, f"name/{p['kind']}", [("name", p.get("name"))])
    if a.w(r"\bentry (?:point|file)\b|\bmain file\b|\bmain script\b|\bentrypoint\b"):
        if p["kind"] in ("npm", "vsix") and p.get("entry"):
            return _settle(a.q, f"entry/{p['kind']}", _path_forms(p["entry"].lstrip("./")) + [("as_written", p["entry"])], prefer=path_prefer)
        if p["kind"] == "jar":
            return _settle(a.q, "entry/jar_main_class", [("main_class", p.get("entry"))])
        scripts = (p.get("entry_points") or {}).get("console_scripts") if isinstance(p.get("entry_points"), dict) else None
        if isinstance(scripts, dict) and len(scripts) == 1:
            name, target = next(iter(scripts.items()))
            return _settle(a.q, "entry/console_script", [("target", target), ("name", name), ("line", f"{name} = {target}")], soft=True)
    return None


def foreign(q) -> bool:
    """True for a question that carries the marks of one of the five known lanes (a dNN_ answer id,
    a -role/-attack/-steps id, `message`, an ANS- answer, Determine <type>.<property> for <file>):
    those lanes have their own solvers, and this one must never win them by a stray word."""
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    f = _fmt(q)
    text = " ".join(str(x or "") for x in (q.get("question"), f.get("syntax"), f.get("pattern")))
    return bool(re.match(r"d\d\d[_-]", aid) or aid in ("message", "answer") or "ANS-" in text
                or re.search(r"-(?:role|attack|steps|adapter|campaign|scenario|syntax|obfuscation|carrier|stage-count)$", aid)
                or re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", str(q.get("question") or "")))


def answer(q, A: Analysis):
    """One question's answer under the never-guess contract, or None."""
    a = _Asked(q)
    if a.kind in _NO_ANSWER_KINDS or foreign(q):
        return None
    pkg = a.w(r"\bpost-?install|\bpre-?install|\blifecycle\b|\bsetup\.py\b|\bpth\b|\brecord\b|\bwheel\b|\bwhl\b|\bnpm\b|\bpackage\b|"
              r"\bextension\b|\bworkflow|\bgithub actions?\b|\bnupkg\b|\bnuget\b|\bgem\b|\bjar\b|\bvsix\b|\bcrx\b|\binstall") \
        or (any(p["kind"] == "hash_manifest" for p in A.packages)       # an app with its own hash manifest
            and a.w(r"\bmanifest\b|\btamper|\bbackdoor|\bintegrity\b|\bmodif|\baltered\b|\bmismatch"))
    vcs =a.w(r"\bcommit|\bgit\b|\breposit|\brepo\b|\bbranch|\bstash|\breflog\b|\bdangling\b|\bunreachable\b|\borphan|\bchangeset|"
              r"\brevision|\bmercurial\b|\bhg\b|\bdarcs\b|\bfossil\b|\bsubversion\b|\bsvn\b|\bpatch\b|\bcheck-?in|\bauthor|"
              r"\bcommitter\b|\bhistory\b|\bdelet|\bremov|\btags?\b|\bremote\b|\borigin\b|\bhead\b|\bstaged\b")
    asks_commit = a.w(r"\b(?:which|what|whose) (?:commit|changeset|revision|patch|check-?in)\b|\bcommit (?:hash|id|sha|identifier|that|which)\b|"
                      r"\b(?:hash|id|sha|identifier) of the (?:commit|changeset|revision|patch|check-?in)\b|\bauthor|\bcommitter\b|\bbranch|"
                      r"\bwho\b|\bwhen\b|\bdate\b|\bemail\b|\bmessage\b|\bchangeset\b|\brevision\b|\bcheck-?in\b|\bpatch\b")
    secretish = bool(_secret_kinds(a.words)[0])
    if pkg and A.packages:
        got = _answer_package(a, A)
        if got is not None:
            return got
    if secretish and not asks_commit and (A.secrets or A.histories):
        got = _answer_secret(a, A)
        if got is not None:
            return got
    if (vcs or (secretish and asks_commit)) and A.histories:
        try:
            return _answer_history(a, A)
        except Incomplete:
            return None
    return None


def solve_set(questions, files, ctx) -> dict:
    """The runner contract: {qid: a plain proven answer, a labels.pick value, or None}."""
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if not any(isinstance(v, (bytes, bytearray)) for v in files.values()):
        return out
    A = None
    for q in questions:
        try:
            if foreign(q):
                continue
            if A is None:
                A = Analysis(files)
                if not A.histories and not A.packages:
                    return out
            out[q.get("qid") or q.get("id")] = answer(q, A)
        except Exception:               # a fact that cannot be read is no answer
            out[q.get("qid") or q.get("id")] = None
    return out


# ---- the triage an agent reads -------------------------------------------------------------------------

def _preview(body: bytes, n: int = 100) -> str:
    try:
        text = body[:4 * n].decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(body)} bytes, binary: {body[:16].hex()}>"
    return json.dumps(text[:n])[1:-1] + ("..." if len(body) > n else "")


def _when(t, tz) -> str:
    forms = dict(_date_forms(t, tz))
    return forms.get("iso_offset", "-")


_SHAPE = re.compile(r"[0-9a-fA-F]{6,}|[A-Za-z0-9+/_=-]{16,}|\d+")


def unusual_messages(commits, least: int = 12, most: int = 8) -> list:
    """The commits whose message has a shape no other commit's has, in a history where at least
    `least` commits share one shape (hex, base64 and numbers count as one token). The two real
    challenges this was tried on each hide one commit among 400 generated ones; the odd one out
    is where a person looks first. Nothing is answered from this: it is a line for the reader."""
    if len(commits) < least:
        return []
    shapes = {}
    for c in commits:
        subject = (c.get("message") or "").strip().split("\n")[0]
        shapes.setdefault(_SHAPE.sub("#", subject), []).append(c)
    if max(len(v) for v in shapes.values()) < least:
        return []
    return [v[0] for v in shapes.values() if len(v) == 1][:most]


def describe(files: dict) -> dict:
    """The whole triage as a JSON-ready dict: {histories, packages, secrets, notes}."""
    A = Analysis(files)
    hist = []
    for h in A.histories:
        row = {"kind": h.kind, "label": h.label, "complete": h.complete, "problems": list(h.problems), "commits": []}
        try:
            for c in h.ids():
                m = h.meta(c)
                entry = {"id": c, "forms": dict(h.id_forms(c)), "author": m.get("author"), "email": m.get("email"),
                         "when": _when(m.get("time"), m.get("tz")), "message": (m.get("message") or "").strip(),
                         "parents": h.parents(c)}
                if isinstance(h, GitRepo):
                    entry["reached_from"] = h.where(c)
                    cm = h.commit(c)
                    if cm["committer_email"] != cm["email"] or cm["committer"] != cm["author"]:
                        entry["committer"] = f"{cm['committer']} <{cm['committer_email']}>"
                if isinstance(h, SnapshotHistory):
                    try:
                        ch = h.changes(c)
                        entry["changes"] = {p: ("added" if o is None else "deleted" if n is None else "modified") for p, (o, n) in ch.items()}
                    except Incomplete as e:
                        entry["changes"] = f"not readable: {e}"
                else:
                    p = h._patches[c]
                    entry["changes"] = {**{f: "addfile" for f in p["addfile"]}, **{f: "rmfile" for f in p["rmfile"]},
                                        **{f: "hunk" for f in list(p["added"]) + list(p["removed"]) if f not in p["addfile"] + p["rmfile"]}}
                row["commits"].append(entry)
            row["deleted_files"] = [{"commit": c, "path": p} for c, p in h.deleted()]
            row["renamed_files"] = [{"commit": c, "from": x, "to": y} for c, x, y in h.renamed()]
        except Incomplete as e:
            row["problems"].append(str(e))
        if isinstance(h, GitRepo):
            r = h.reach()
            row.update(object_format=h.hashname, objects=len(h.objects), head=h.head(), refs=h.refs(),
                       pseudo_heads=h.pseudo_heads(), config=git_config_facts(h),
                       reflog=[{k: e[k] for k in ("ref", "old", "new", "email", "message")} for e in h.reflog()],
                       stashes=h.stashes(), index=[{k: e[k] for k in ("path", "id", "stage")} for e in h.index()],
                       tags=[h.tag(o) for o, (t, _) in h.objects.items() if t == "tag"],
                       nonstandard_files=h.nonstandard(),
                       not_reached_by_a_ref=[{"id": o, "type": h.objects[o][0], "reached_from": h.where(o),
                                              "dangling": o in r["dangling"],
                                              "preview": _preview(h.objects[o][1]) if h.objects[o][0] == "blob" else None}
                                             for o in sorted(r["no_ref"])])
            if h.worktree:
                try:
                    head = h.snapshot(h.head()["id"]) if h.head()["id"] else {}
                    row["work_tree"] = {"missing_from_disk": sorted(p for p in head if p not in h.worktree),
                                        "not_in_head": sorted(p for p in h.worktree if p not in head)[:200],
                                        "modified": sorted(p for p in head if p in h.worktree
                                                           and h._hash("blob", h.worktree[p]) != head[p])}
                except Incomplete:
                    pass
        hist.append(row)
    other = []
    for container, path, data in listing(A.files):
        name = (container + ARROW if container else "") + path
        try:
            if path.endswith(".svn/wc.db") and data[:16] == b"SQLite format 3\x00":
                other.append({"kind": "svn working copy", "file": name, "nodes": svn_working_copy(data)})
            elif re.search(r"(?:^|/)db/revprops/\d+/\d+$", path) and data[:2] == b"K ":
                other.append({"kind": "svn revision properties", "file": name, "revision": path.rsplit("/", 1)[-1],
                              "props": _svn_props(data)})
        except Exception as e:
            A.notes.append(f"{name}: not read ({type(e).__name__}: {str(e)[:80]})")
    return {"made_by": "solvers/toolkits/repo_supply_chain.py", "histories": hist, "packages": A.packages,
            "secrets": A.secrets, "other": other, "notes": A.notes}


def grep(files: dict, text: str) -> list:
    """Where a text occurs: every delivered file, every blob of every history, and for each history
    the commits that added and removed it. [{repo, where, added_by, removed_by}]."""
    A = Analysis(files)
    raw = text.encode("utf-8")
    out = []
    for h in A.histories:
        row = {"repo": h.label, "kind": h.kind, "blobs": [], "added_by": [], "removed_by": [], "messages": h.by_message(text)}
        for bid, body in h.all_blobs():
            if raw in body:
                row["blobs"].append({"blob": bid, "origin": _origin(h, bid)})
        try:
            row["added_by"], row["removed_by"] = h.adding(raw), h.removing(raw)
        except Incomplete as e:
            row["problem"] = str(e)
        out.append(row)
    internal = {id(d) for h in A.histories if isinstance(h, GitRepo) for d in h.t.values()}
    hits = [(c + ARROW if c else "") + p for c, p, d in listing(A.files) if id(d) not in internal and raw in d]
    if hits:
        out.append({"repo": None, "files": hits})
    return out


def report(d: dict) -> str:
    """describe()'s dict as text for a reader."""
    lines = []
    for h in d["histories"]:
        lines += ["", f"== {h['kind']} history: {h['label']}" + ("" if h["complete"] else "   [NOT COMPLETE: exactly-one answers are off]")]
        for p in h["problems"]:
            lines.append(f"   PROBLEM {p}")
        if h["kind"] == "git":
            head = h["head"]
            lines.append(f"   objects={h['objects']} ({h['object_format']})  HEAD={head['ref'] or 'detached'} {str(head['id'])[:12]}")
            for name, oid in sorted(h["refs"].items()):
                lines.append(f"   ref {name} {oid[:12]}")
            for name, ids in h["pseudo_heads"].items():
                lines.append(f"   {name} {' '.join(i[:12] for i in ids)}")
            cfg = h["config"]
            for name, url in cfg["remotes"].items():
                lines.append(f"   remote {name} {url}")
            if cfg["user"]:
                lines.append(f"   config user {cfg['user']}")
            for k, v in cfg["runs"]:
                lines.append(f"   WOULD RUN under a real git: config {k} = {v}")
            for name in cfg["hooks"]:
                lines.append(f"   WOULD RUN under a real git: hooks/{name}")
        lines.append(f"   commits ({len(h['commits'])}), oldest first:")
        for c in h["commits"][:200]:
            subject = c["message"].split("\n")[0][:70]
            lines.append(f"   {str(c['id'])[:12]} {c['when']} {c['author'] or '-'} <{c['email'] or '-'}>"
                         + (f" [{c['reached_from']}]" if c.get("reached_from") not in (None, "refs") else "") + f"  {subject}")
            if c.get("committer"):
                lines.append(f"       committer {c['committer']}")
            if isinstance(c.get("changes"), dict):
                for p, what in list(c["changes"].items())[:12]:
                    lines.append(f"       {what:9} {p}")
                if len(c["changes"]) > 12:
                    lines.append(f"       ... {len(c['changes']) - 12} more")
        if len(h["commits"]) > 200:
            lines.append(f"   ... {len(h['commits']) - 200} more commits not shown (--json has every one; --grep TEXT finds a string)")
        for c in unusual_messages(h["commits"]):
            lines.append(f"   UNUSUAL MESSAGE {str(c['id'])[:12]} {c['when']}  {c['message'].strip()[:200]!r}")
        for row in h.get("deleted_files", [])[:200]:
            lines.append(f"   DELETED {row['path']} in {str(row['commit'])[:12]}")
        if len(h.get("deleted_files", [])) > 200:
            lines.append(f"   ... {len(h['deleted_files']) - 200} more deleted paths")
        for row in h.get("renamed_files", []):
            lines.append(f"   RENAMED {row['from']} -> {row['to']} in {str(row['commit'])[:12]}")
        if h["kind"] == "git":
            for s in h["stashes"]:
                lines.append(f"   STASH stash@{{{s['index']}}} {s['id'][:12]} {(s['message'] or '').strip()[:70]}"
                             + (f"  files: {', '.join(list(s['files'])[:6])}" if s.get("files") else ""))
            for e in h["reflog"][-40:]:
                lines.append(f"   reflog {e['ref']}: {e['old'][:8]} -> {e['new'][:8]} {e['message'][:70]}")
            for o in h["not_reached_by_a_ref"][:80]:
                lines.append(f"   NO REF reaches {o['type']} {o['id'][:12]} (reached from: {o['reached_from']}"
                             + (", dangling" if o["dangling"] else "") + ")" + (f"  {o['preview']}" if o["preview"] else ""))
            for row in h.get("nonstandard_files", [])[:80]:
                lines.append(f"   NOT GIT'S OWN FILE {row['path']} ({row['size']} bytes): {row['why']}")
            wt = h.get("work_tree")
            if wt:
                for k in ("missing_from_disk", "modified", "not_in_head"):
                    if wt[k]:
                        lines.append(f"   work tree {k.replace('_', ' ')}: {', '.join(wt[k][:12])}")
    for p in d["packages"]:
        lines += ["", f"== {p['kind']} package: {p.get('name')} {p.get('version') or ''}  in {p['file']}" + (f" [{p['root']}]" if p.get("root") else "")]
        for h in p.get("hooks", []):
            lines.append(f"   {'RUNS AT INSTALL' if h.get('install_time') else 'RUNS'} [{h['when']}] {h['where']}: {str(h['command'])[:200]}")
            for f in h.get("files", []):
                lines.append(f"       runs file {f}")
            for u in h.get("urls", []):
                lines.append(f"       url {u}")
        rec = p.get("record")
        if rec:
            what = "MANIFEST" if p["kind"] == "hash_manifest" else "RECORD"
            lines.append(f"   {what} {p.get('manifest') or ''} rows={rec['rows']} mismatched={len(rec['mismatched'])} missing={len(rec['missing'])} "
                         f"unlisted={len(rec['unlisted'])}".replace("  ", " "))
            for r in rec["mismatched"]:
                lines.append(f"   {what} MISMATCH {r['path']}: recorded {r['recorded']} actual {r['actual']} ({r['algorithm']} hex {r['actual_hex']})")
            for u in rec["missing"][:20]:
                lines.append(f"   LISTED IN {what}, NOT THERE {u}")
            for u in rec["unlisted"][:20]:
                lines.append(f"   NOT IN {what} {u}")
            if len(rec["unlisted"]) > 20:
                lines.append(f"   ... {len(rec['unlisted']) - 20} more files the {what.lower()} does not list")
        for k in ("entry", "bin", "entry_points", "extension_id", "permissions", "host_permissions", "update_url", "triggers",
                  "uses", "secrets_used", "dependencies_not_from_registry", "index_urls", "urls", "identity", "checksums", "pth"):
            if p.get(k):
                lines.append(f"   {k}: {json.dumps(p[k], default=str)[:300]}")
        for n in p.get("notes", []):
            lines.append(f"   NOTE {n}")
    if d["secrets"]:
        lines += ["", "== secrets (answers only: never used, sent or tested)"]
        for s in d["secrets"]:
            lines.append(f"   {s['kind']}: {s['value'] if len(s['value']) < 200 else s['value'][:60] + '...'}")
            for w in s["where"][:6]:
                lines.append(f"       {w.get('repo') or ''} {('commit ' + str(w['commit'])[:12]) if w.get('commit') else ''} {w.get('path') or ''} [{w['state']}]")
            if s["kind"] == "jwt":
                lines.append(f"       decoded: {json.dumps(jwt_parts(s['value']), default=str)[:300]}")
    for o in d.get("other", []):
        lines += ["", f"== {o['kind']}: {o['file']}"]
        for node in o.get("nodes", [])[:200]:
            lines.append(f"   r{node['revision']} {node['kind']} {node['path'] or '.'} {node['author'] or '-'} {node['date'] or '-'} [{node['presence']}]")
        for k, v in (o.get("props") or {}).items():
            lines.append(f"   r{o['revision']} {k}: {str(v)[:200]}")
    for n in d["notes"]:
        lines.append(f"NOTE {n}")
    if not d["histories"] and not d["packages"] and not d["secrets"] and not d.get("other"):
        lines.append("nothing here is a repository, a package or a secret this toolkit knows")
    return "\n".join(lines).lstrip("\n") + "\n"


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    needle = None
    if "--grep" in argv:
        i = argv.index("--grep")
        if i + 1 >= len(argv):
            print("usage: repo_supply_chain.py <file or folder>... [--json] [--grep TEXT]", file=sys.stderr)
            return 2
        needle = argv[i + 1]
        args.remove(needle)
    if not args:
        print("usage: repo_supply_chain.py <file or folder>... [--json] [--grep TEXT]", file=sys.stderr)
        return 2
    missing = [a for a in args if not Path(a).exists()]
    if missing:
        print(f"repo_supply_chain.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    files = from_paths(args)
    if needle is not None:
        print(json.dumps(grep(files, needle), indent=1, default=str))
        return 0
    d = describe(files)
    print(json.dumps(d, indent=1, default=str) if "--json" in argv else report(d), end="" if "--json" not in argv else "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
