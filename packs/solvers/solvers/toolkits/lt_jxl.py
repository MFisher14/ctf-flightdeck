#!/usr/bin/env python3
"""JPEG XL reader (B-251 long tail): the container's boxes, the codestream header, hidden payloads.

A JPEG XL file is a bare codestream (FF 0A) or an ISO BMFF container (00 00 00 0C 'JXL ' 0D 0A 87 0A)
whose boxes hold the codestream whole (`jxlc`) or in parts (`jxlp`), metadata (`Exif`, `xml `,
`jumb`), brotli-compressed metadata (`brob`) and JPEG reconstruction data (`jbrd`). This reader does
not decode pixels. It reads:

  - every box (type, offset, size), the level (`jxll`), and the codestream put together from its parts
  - the codestream's image header, bit by bit as the specification packs it: the SizeHeader (width,
    height) and the whole ImageMetadata (orientation, intrinsic and preview size, animation timing,
    bit depth, extra channels, colour encoding). A header with an enumeration value, a bit depth or
    padding the format does not allow is a FormatError, and `detect` passes over such a file: FF 0A
    alone is not taken for a JPEG XL image
  - what a hidden message rides in: Exif and XMP payloads, `brob` boxes decompressed with the pinned
    brotli, boxes of a type the specification does not define, and bytes after the last box

    read_jxl(data) -> dict
    decode_pixels(data, fmt="png") -> bytes   the image decoded by `djxl` (NeedsTool when it is not installed)
    detect / inspect / solve                  the engine entry points; `--opt decode=1` on the CLI adds
                                              the decoded PNG to the payloads written with --out

A `brob` box met without brotli installed is listed as undecoded and named under `needs_tool`, which
solve() carries into its notes (the rest of the file is still read; the box's compressed bytes are not
scanned, since what matches in them is not a decoded flag).

Bounds: MAX_BOXES boxes; a box size is never trusted past the end of the file; a `brob` box
decompresses to MAX_BROB_BYTES at most (more is a FormatError, nothing past the limit is inflated),
and all the `brob` boxes of a file to MAX_BROB_TOTAL: once that is spent, a box that would pass it is
not decoded and neither is any after it (the box's row says `undecoded`, the facts `brob_stopped`;
nothing past the budget is inflated, and the rest of the file is still read).
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from _lt_common import FormatError, NeedsTool, TooLarge, bounded_decompress, cli, need, solve_files, text_or_hex
from ctf.formats import detect_longtail as structure      # _lt_common put the repo root on sys.path

ENGINE = "toolkits.lt_jxl"
CONTAINER = bytes.fromhex("0000000c4a584c200d0a870a")
CODESTREAM = b"\xff\x0a"
MAX_BOXES = 10_000
MAX_BROB_BYTES = 16 << 20              # what one brotli-compressed metadata box may decompress to
MAX_BROB_TOTAL = 64 << 20              # what all the brob boxes of one file may decompress to
KNOWN_BOXES = {"JXL ", "ftyp", "jxll", "jxlc", "jxlp", "jxli", "Exif", "xml ", "jumb", "brob", "jbrd", "free", "skip"}


def read_codestream_header(cs: bytes) -> dict:
    """The image header of a codestream (ctf.formats.detect_longtail.jxl_header, the same parser the
    format catalog identifies a bare codestream with): width and height, and when the metadata is not
    all default the orientation, intrinsic size, preview size, animation timing, bit depth, extra
    channels and colour encoding. FormatError when the bytes are not a JPEG XL image header."""
    try:
        return structure.jxl_header(cs)
    except ValueError as e:
        raise FormatError(str(e)) from None


def boxes(data: bytes):
    """([(type, offset, payload offset, payload size)], trailing bytes) of a container. The walk stops at
    the first position that is not a box that fits in the file (no printable type, or a size past the
    end); everything from there on is the trailing data, never dropped."""
    out, o = [], 0
    while o + 8 <= len(data):
        need(len(out) < MAX_BOXES, f"more than {MAX_BOXES} boxes")
        size, kind = struct.unpack_from(">I4s", data, o)
        head = 8
        if size == 1:
            need(o + 16 <= len(data), f"the box at offset {o} ends inside its 64-bit size")
            size, head = struct.unpack_from(">Q", data, o + 8)[0], 16
        elif size == 0:
            size = len(data) - o
        if not all(32 <= c < 127 for c in kind) or not head <= size <= len(data) - o:
            break                              # not a box that fits: what is left is reported as trailing data
        out.append((kind.decode("ascii"), o, o + head, size - head))
        o += size
    return out, data[o:]


def read_jxl(data: bytes, blobs=None) -> dict:
    blobs = [] if blobs is None else blobs
    if data[:2] == CODESTREAM:
        out = {"format": "jxl", "container": False, "codestream_bytes": len(data)}
        out.update(read_codestream_header(data))
        return out
    need(data[:12] == CONTAINER, "neither a JPEG XL codestream (FF 0A) nor a container signature")
    found, trailing = boxes(data)
    out = {"format": "jxl", "container": True,
           "boxes": [{"type": k, "offset": o, "size": n} for k, o, _, n in found]}
    parts, whole = [], None
    left = MAX_BROB_TOTAL                      # the file's brob budget: every decoded box is charged to it
    for kind, _, at, n in found:
        body = data[at:at + n]
        if kind == "jxll" and n >= 1:
            out["level"] = body[0]
        elif kind == "ftyp":
            out["brand"] = body[:4].decode("latin-1")
        elif kind == "jxlc":
            whole = body
        elif kind == "jxlp":
            need(n >= 4, "a jxlp box is shorter than its index")
            parts.append((struct.unpack(">I", body[:4])[0], body[4:]))
        elif kind == "Exif":
            out.setdefault("exif", []).append(text_or_hex(body[4:], 4096))
            blobs.append(("Exif", body))
        elif kind == "xml ":
            out.setdefault("xmp", []).append(text_or_hex(body, 1 << 16))
            blobs.append(("xml", body))
        elif kind == "brob":
            need(n >= 4, "a brob box is shorter than its inner type")
            inner = body[:4].decode("latin-1")
            row = {"type": inner, "compressed_bytes": n - 4}
            out.setdefault("brob", []).append(row)
            if "brob_stopped" in out:               # the file's budget is spent: no box after it is inflated
                row["undecoded"] = "over the file's brob limit"
                continue
            limit = min(MAX_BROB_BYTES, left)
            try:
                raw = bounded_decompress("brotli", body[4:], limit, f"the brob box at offset {at - 8}",
                                         f"the brob box at offset {at - 8} ({inner!r}) is brotli-compressed")
            except NeedsTool as e:                  # the rest of the file is still read; solve() names the tool
                row["undecoded"] = str(e)           # (the compressed bytes are not handed to the flag scan: a
                out.setdefault("needs_tool", []).append(f"{e.tool}: {e.why}")    # match in them is not a decoded flag)
            except TooLarge:
                if limit == MAX_BROB_BYTES:         # past the limit of one box: a bomb, the file is refused
                    raise
                out["brob_stopped"] = (f"the brob boxes before offset {at - 8} decompressed to {MAX_BROB_TOTAL - left} "
                                       f"bytes: it and the brob boxes after it would pass the file's "
                                       f"{MAX_BROB_TOTAL}-byte limit and are not decoded")
                row["undecoded"] = "over the file's brob limit"
            else:
                left -= len(raw)
                row.update(bytes=len(raw), content=text_or_hex(raw, 4096))
                blobs.append((f"brob {inner}", raw))
        elif kind == "jumb":
            blobs.append(("jumb", body))
        elif kind == "jbrd":
            out["jpeg_reconstruction_bytes"] = n
        elif kind not in KNOWN_BOXES:
            out.setdefault("unknown_boxes", []).append({"type": kind, "size": n, "content": text_or_hex(body, 1024)})
            blobs.append((f"box {kind}", body))
    if trailing:
        out["trailing_bytes"] = len(trailing)
        out["trailing"] = text_or_hex(trailing, 1024)
        blobs.append(("trailing", trailing))
    if whole is None and parts:
        index = [i & 0x7FFFFFFF for i, _ in parts]
        need(index == list(range(len(parts))), f"the jxlp parts are numbered {index}, not 0..{len(parts) - 1}")
        need(parts[-1][0] & 0x80000000, "the last jxlp part is not marked as the last")
        whole = b"".join(p for _, p in parts)
        out["codestream_parts"] = len(parts)
    need(whole is not None, "the container has no codestream box (jxlc or jxlp)")
    out["codestream_bytes"] = len(whole)
    out.update(read_codestream_header(whole))
    return out


def decode_pixels(data: bytes, fmt: str = "png") -> bytes:
    """The decoded image as `djxl` writes it. NeedsTool when djxl is not on PATH; FormatError when it
    refuses the file. djxl runs with no shell, on a private copy, with a timeout."""
    tool = shutil.which("djxl")
    if not tool:
        raise NeedsTool("djxl", "pixels are decoded by the libjxl reference decoder")
    with tempfile.TemporaryDirectory(prefix="lt-jxl-") as tmp:
        src, dst = Path(tmp) / "in.jxl", Path(tmp) / f"out.{fmt}"
        src.write_bytes(data)
        try:
            run = subprocess.run([tool, str(src), str(dst)], capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise FormatError("djxl did not finish decoding in 120 seconds") from None
        if run.returncode or not dst.is_file():
            raise FormatError(f"djxl refused the file: {run.stderr.decode('utf-8', 'replace').strip()[-300:]}")
        return dst.read_bytes()


def detect(head: bytes, name: str = "") -> bool:
    """The container signature, or FF 0A followed by an image header the format allows (the catalog's
    own test: a file that only starts with FF 0A is not selected)."""
    return structure.DETECTORS["jxl"](head)


def inspect(data: bytes, name: str = "", opts=None):
    blobs = []
    facts = read_jxl(data, blobs)
    if str((opts or {}).get("decode", "")) in ("1", "true", "yes"):
        blobs.append(("decoded.png", decode_pixels(data)))
    return facts, blobs


def solve(challenge_dir, profile=None, **opts):
    """Read every JPEG XL file's boxes and header (no pixel decode, no subprocess) and scan the payloads."""
    opts.pop("decode", None)
    return solve_files(ENGINE, "JPEG XL image", challenge_dir, profile, detect, inspect, opts)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:], __doc__, detect, inspect, ("decode",)))
