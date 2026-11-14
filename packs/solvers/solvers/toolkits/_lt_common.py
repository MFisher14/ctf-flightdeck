"""Shared plumbing of the long-tail format engines (B-251). Not an engine: an underscore file.

Every `lt_*` engine is a bounded, offline reader of one format family. Each exposes

    detect(head, name) -> bool        a structural test on the first HEAD bytes (never the name alone)
    inspect(data, name, opts) -> (facts, blobs)
                                      facts: a JSON-able dict; blobs: [(label, bytes)] decoded payloads
    solve(challenge_dir, profile=None, **opts) -> SolverResult

and this module turns the first two into the third (`solve_files`) and into a by-hand CLI (`cli`).

The errors mean one thing each, and none of them is ever swallowed into a quiet "nothing found":

    FormatError   the bytes are not a well-formed instance of the format (the message says where)
    NotThisFormat a FormatError of a format with no magic: the head passed the cheap test and the whole
                  file shows it never was this format; a folder walk passes over it
    NeedsTool     the file is this format but a decoder that is not installed is required: `.tool` is a
                  needs_tool name ("py:argon2", "dislocker|bdeinfo"), `.why` what it is needed for
    NeedsKey      the file is this format and only a key or passphrase the caller did not give opens it

A reader that can read the rest of a file without a missing decoder does so and lists what it could not
decode under the facts key `needs_tool` (["py:brotli: a brob box is brotli-compressed"]): `solve_files`
carries every such line into the result's notes, and a file that gave no flag and has one counts as
blocked, not as read (a missing decoder never ends in a quiet "no flag in the decoded content").

Every decompression goes through `bounded_decompress`, which stops at a stated output size: a part that
holds more is a TooLarge, a FormatError (a bomb is refused, not inflated).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:      # appended, never first: run by hand, a reader still finds the ctf package
    sys.path.append(str(ROOT))     # (ctf.formats.detect_longtail holds the structural tests the readers share)

HEAD = 8192
MAX_FILE_BYTES = 256 << 20
MAX_FILES = 4096
MAX_EVIDENCE = 24


class FormatError(ValueError):
    """Not a well-formed instance of the format."""


class NotThisFormat(FormatError):
    """The cheap test on the head matched and the full structure says the file never was this format
    (a format with no magic): not a malformed instance, so a walk passes over it without a note."""


class TooLarge(FormatError):
    """bounded_decompress: the data holds more than the stated limit (nothing past it was inflated). A
    FormatError, so a reader that does not look for it refuses the file; a reader whose limit is a
    per-file budget catches it to stop decoding instead."""


class NeedsTool(RuntimeError):
    def __init__(self, tool: str, why: str):
        super().__init__(f"needs_tool {tool}: {why}")
        self.tool, self.why = tool, why


class NeedsKey(RuntimeError):
    """Only a key or passphrase that was not supplied opens this."""


def need(cond, msg):
    if not cond:
        raise FormatError(msg)


def decoder_errors() -> tuple:
    """What the pinned decompressors raise on corrupt data (anything else they raise is a bug, not a
    malformed file, and is not caught)."""
    import lzma
    import zlib
    errs = [zlib.error, lzma.LZMAError, OSError, EOFError, ValueError]
    for mod, attr in (("cramjam", "DecompressionError"), ("brotli", "error"), ("zstandard", "ZstdError")):
        try:
            errs.append(getattr(__import__(mod), attr))
        except (ImportError, AttributeError):
            pass
    return tuple(errs)


class _Over(Exception):
    """The decompressed output passed its limit."""


def _streams(make, body: bytes, limit: int) -> bytes:
    """Every concatenated stream of `body` through a fresh stdlib decompressor each (zlib, bz2, lzma),
    never asking for more than limit + 1 bytes in all."""
    out, size, data = [], 0, body
    while True:
        d = make()
        chunk = d.decompress(data, limit + 1 - size)
        size += len(chunk)
        out.append(chunk)
        if size > limit:
            raise _Over
        if not d.eof:
            raise EOFError("the compressed stream ends before its end marker")
        data = d.unused_data
        if not data:
            return b"".join(out)


def _uvarint(d: bytes):
    n = shift = 0
    for i, b in enumerate(d[:10]):
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n
        shift += 7
    raise EOFError("the snappy length prefix does not end")


def _module(name: str, why: str):
    try:
        return __import__(name)
    except ImportError:
        raise NeedsTool(f"py:{name}", why) from None


WBITS = {"deflate": -15, "zlib": 15, "gzip": 47}       # gzip: a zlib or a gzip header, as Parquet writes


def bounded_decompress(codec: str, body: bytes, limit: int, what: str, why: str = "") -> bytes:
    """`body` decompressed under `codec` (deflate, zlib, gzip, bzip2, xz, brotli, zstd, snappy: a raw
    block, lz4: a raw block of exactly `limit` bytes), producing at most `limit` bytes. TooLarge (a
    FormatError) when the data holds more than `limit` bytes (nothing past the limit is inflated),
    FormatError when it is corrupt;
    NeedsTool naming the decoder when it is not installed (`why` says what needed it)."""
    why = why or f"{what} is compressed with {codec}"
    try:
        if codec in WBITS:
            import zlib
            d = zlib.decompressobj(WBITS[codec])
            out = d.decompress(body, limit + 1)
            if len(out) > limit:
                raise _Over
            if not d.eof:
                raise EOFError("the compressed stream ends before its end marker")
            return out
        if codec == "bzip2":
            import bz2
            return _streams(bz2.BZ2Decompressor, body, limit)
        if codec == "xz":
            import lzma
            return _streams(lzma.LZMADecompressor, body, limit)
        if codec == "brotli":
            d = _module("brotli", why).Decompressor()
            out, size, data = [], 0, body
            while True:      # the limit of one call is approximate (the library rounds up): ask in small steps
                chunk = d.process(data, output_buffer_limit=min(1 << 20, limit + 1 - size))
                data = b""
                size += len(chunk)
                out.append(chunk)
                if size > limit:
                    raise _Over
                if d.is_finished():
                    return b"".join(out)
                if not chunk:
                    raise EOFError("the brotli stream ends before its last block")
        if codec == "zstd":
            zstandard = _module("zstandard", why)
            if zstandard.frame_content_size(body) > limit:    # the size the frame states for itself
                raise _Over
            d, out, size, view = zstandard.ZstdDecompressor().decompressobj(), [], 0, memoryview(body)
            for i in range(0, len(view), 256):                # small steps: one step cannot pass the limit by much
                chunk = d.decompress(view[i:i + 256])
                size += len(chunk)
                out.append(chunk)
                if size > limit:
                    raise _Over
                if d.eof:
                    break
            if not d.eof:
                raise EOFError("the zstd frame ends before its last block")
            return b"".join(out)
        if codec == "snappy":
            cramjam = _module("cramjam", why)
            if _uvarint(body) > limit:
                raise _Over
            return bytes(cramjam.snappy.decompress_raw(body))
        if codec == "lz4":
            return bytes(_module("cramjam", why).lz4.decompress_block(body, output_len=limit))
    except NeedsTool:
        raise
    except _Over:
        raise TooLarge(f"{what} decompresses to more than {limit} bytes: not inflated further") from None
    except decoder_errors() as e:
        raise FormatError(f"{what}: the {codec} data does not decompress ({type(e).__name__}: {e})") from None
    raise FormatError(f"the codec {codec!r} is not one this reader decodes")


def text_or_hex(b: bytes, limit: int = 4096):
    """How a byte string is shown in facts: its text when it is clean UTF-8 without control bytes,
    else `hex:<digits>`; cut at `limit` bytes with the full length stated."""
    cut = bytes(b[:limit])
    try:
        s = cut.decode("utf-8")
        clean = all(c >= " " or c in "\t\r\n" for c in s)
    except UnicodeDecodeError:
        s, clean = "", False
    out = s if clean else "hex:" + cut.hex()
    return out if len(b) <= limit else out + f"...(+{len(b) - limit} bytes)"


def strings_of(obj, path="$"):
    """(json path, text) of every string in a facts tree, keys included."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}", str(k)
            yield from strings_of(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from strings_of(v, f"{path}[{i}]")


def walk(root: Path):
    """The regular files under root, sorted, symlinks never followed. (files, over): `over` is True when
    more than MAX_FILES were there and the rest were left out (the caller must say so)."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if len(out) >= MAX_FILES:
            return out, True
        out.append(p)
    return out, False


def solve_files(engine: str, noun: str, challenge_dir, profile, detect, inspect, opts=None):
    """Run one reader over a challenge folder and return its SolverResult.

    solved: exactly one distinct flag of the event format was decoded; candidate: several; unsure: files of
    the format were read (or were malformed) and hold no flag: the evidence lists what was read; blocked:
    files of the format are there and none was read whole, each for a named missing tool or key; none: no
    file of the format. A part of a file that a missing decoder left undecoded (the facts key
    `needs_tool`) is always named in the notes, whatever the status."""
    from ctf import flagfmt
    from ctf.result import Evidence, SolverResult

    root = Path(challenge_dir)
    if not root.is_dir():
        return SolverResult("blocked", engine=engine, notes=f"{root} is not a directory")
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    files, over = walk(root)
    flags, evidence, notes, read, blocked, bad = [], [], [], 0, [], []
    if over:
        notes.append(f"more than {MAX_FILES} files: only the first {MAX_FILES} (sorted) were looked at")
    for p in files:
        rel = str(p.relative_to(root))
        try:
            size = p.stat().st_size
            with open(p, "rb") as fh:
                head = fh.read(HEAD)
                if not detect(head, p.name):
                    continue
                if size > MAX_FILE_BYTES:
                    notes.append(f"{rel}: {noun}, {size} bytes is over the {MAX_FILE_BYTES}-byte limit: not read")
                    blocked.append(rel)
                    continue
                data = head + fh.read()
        except OSError as e:
            notes.append(f"{rel}: unreadable ({e.strerror or e})")
            continue
        try:
            facts, blobs = inspect(data, p.name, dict(opts or {}))
        except NotThisFormat:
            continue
        except FormatError as e:
            bad.append(rel)
            notes.append(f"{rel}: malformed {noun}: {e}")
            continue
        except (NeedsTool, NeedsKey) as e:
            blocked.append(rel)
            notes.append(f"{rel}: {noun}: {e}")
            continue
        missing = [str(m) for m in facts.get("needs_tool") or []]
        notes += [f"{rel}: {noun}: needs_tool {m}" for m in missing]
        hits = []
        for where, s in strings_of(facts):
            hits += [(where, f) for f in ff.find_flags(s)]
        for label, blob in blobs:
            hits += [(label, f) for f in ff.find_flags(blob)]
        here = set()
        for where, f in hits:
            if f not in flags:
                flags.append(f)
            if f not in here:                    # one evidence line per file a flag is in, at its first place
                here.add(f)
                evidence.append(Evidence("decode", f"{noun} {rel}: flag at {where}", path=rel))
        if not hits and len(evidence) < MAX_EVIDENCE:
            evidence.append(Evidence("decode", f"{noun} {rel}: {summary(facts)}", path=rel))
        if missing and not hits:               # part of it is undecoded and the rest holds no flag: not "read"
            blocked.append(rel)
        else:
            read += 1
    notes_text = "; ".join(notes)
    if flags:
        return SolverResult("solved" if len(flags) == 1 else "candidate", flags=tuple(flags),
                            evidence=tuple(evidence[:MAX_EVIDENCE]), engine=engine, notes=notes_text)
    if read or bad:
        return SolverResult("unsure", evidence=tuple(evidence[:MAX_EVIDENCE]), engine=engine,
                            notes=notes_text or f"{read} {noun} file(s) read, no flag in the decoded content")
    if blocked:
        return SolverResult("blocked", evidence=tuple(evidence[:MAX_EVIDENCE]), engine=engine, notes=notes_text)
    return SolverResult("none", engine=engine, notes=notes_text or f"no {noun} file in the handout")


def summary(facts: dict, limit: int = 300) -> str:
    """One line of a facts dict for an evidence detail: its scalar fields and the sizes of the rest."""
    parts = []
    for k, v in facts.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            parts.append(f"{k}={v}")
        elif isinstance(v, (list, dict)):
            parts.append(f"{k}[{len(v)}]")
    s = ", ".join(parts)
    return s if len(s) <= limit else s[:limit - 1] + "…"


def cli(argv, doc: str, detect, inspect, options=()):
    """`python <engine>.py FILE... [--out DIR] [--opt k=v]`: one JSON object per file on stdout. Exit 0
    when every file was read, 1 when one was not this format, malformed, or needed a tool or key (the
    object's `error` says which), 2 on bad usage. With --out, each blob is written to DIR/<file>.<label>."""
    import argparse
    ap = argparse.ArgumentParser(description=doc.strip().splitlines()[0])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", help="write every decoded payload into this folder")
    ap.add_argument("--opt", action="append", default=[], metavar="KEY=VALUE",
                    help="reader option" + (f" ({', '.join(options)})" if options else ""))
    a = ap.parse_args(argv)
    opts = {}
    for item in a.opt:
        k, eq, v = item.partition("=")
        if not eq or (options and k not in options):
            ap.error(f"--opt {item!r}: expected KEY=VALUE with KEY one of {', '.join(options) or '(none)'}")
        opts[k] = v
    rc = 0
    for f in a.files:
        p = Path(f)
        rec = {"file": f}
        try:
            data = p.read_bytes()
            if not detect(data[:HEAD], p.name):
                raise FormatError("the bytes do not have this format's structure")
            facts, blobs = inspect(data, p.name, opts)
            rec.update(facts)
            if facts.get("needs_tool"):
                rec["error"], rc = "NeedsTool: needs_tool " + "; ".join(str(m) for m in facts["needs_tool"]), 1
            if a.out:
                out = Path(a.out)
                out.mkdir(parents=True, exist_ok=True)
                rec["written"] = []
                for i, (label, blob) in enumerate(blobs):
                    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in label)[:80] or "blob"
                    dest = out / f"{p.name}.{i:03d}.{safe}"
                    dest.write_bytes(blob)
                    rec["written"].append(str(dest))
        except (OSError, FormatError, NeedsTool, NeedsKey) as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            rc = 1
        sys.stdout.write(json.dumps(rec, default=str) + "\n")
    return rc
