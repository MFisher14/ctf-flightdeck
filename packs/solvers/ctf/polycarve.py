"""Polyglot carve recursion (B-070): an archive hidden in or behind an image goes back into the archive walk.

The archive walk (tools/archive_expand.py) opens a file by its first bytes, so a PNG with a zip after its
IEND chunk stays a PNG and the zip's members are never unpacked, hashed or searched. The sweep
(ctf/sweep.py) calls this on every original and every member:

    members = cascade(rows, walk, notes, archive_expand)   # [(chain, bytes)] the images in `rows` give up
    carve(chain, data, walk, notes)                         # [(name, bytes)] carved from one content

What one image (PNG, JPEG, GIF, BMP, WebP; told by its first bytes, never by its name) gives:

- Every archive solvers/toolkits/carving.py validates inside it at an offset past the start: zip (central
  directory and member CRCs), 7z (header CRCs), gzip, bzip2, xz (stream checks). A magic alone is never a
  result. Each is a member `carved@0x<offset>.<ext>`.
- The bytes after the image's own end, when no validated archive starts there, as `overlay@0x<offset>.bin`:
  an encrypted zip (its members' CRCs cannot be checked without the password), a RAR, a tar, a second
  image, plain text. The end is the one carving.py validates (chunk CRCs, markers), or, for an image whose
  structure it rejects, the structural end solvers/metadata-forensics/readers_polyglot.py walks to; an
  image neither can bound has no overlay here and a note says so when a zip signature is seen in it.

Every carved piece is opened by the same bounded walk (`archive_expand.expand(..., opts=walk)`), so its
members come back as rows with the whole chain ("icon.png -> carved@0x4f.zip -> notes/key.txt") and count
against the same budgets (`Walk.take`). `cascade` works one level: the sweep feeds its output back in until
nothing new is carved, under the sweep's own round limit. Nothing carved is executed; a decoder that fails
on hostile bytes is a note and the next content goes on.
"""
from __future__ import annotations

import struct
import types

from . import paths as _paths
from .packs import load_module as _load_module

__all__ = ["cascade", "carve", "image_kind", "host_end", "ARCHIVE_KINDS", "MIN_OVERLAY"]

ARCHIVE_KINDS = ("zip", "7z", "gzip", "bzip2", "xz")           # carving.py kinds the archive walk opens
_EXT = {"zip": "zip", "7z": "7z", "gzip": "gz", "bzip2": "bz2", "xz": "xz"}
MIN_OVERLAY = 8                      # trailing bytes fewer than this (after padding is stripped) are not a member
_PAD = b"\x00\r\n\t "
_WALK_OPENS = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")


class _Unbounded(Exception):
    """readers_polyglot's Unknown, when the pack is loaded outside its metadata lane."""


def _carving():
    rel = "solvers/toolkits/carving.py"
    return _load_module("ctf_polycarve_carving", _paths.repo_root() / rel, pack=rel)


def _readers():
    """solvers/metadata-forensics/readers_polyglot.py, a private copy: its `M` (the metadata lane's
    registry module) is only used for the exception it raises when an end cannot be bounded."""
    rel = "solvers/metadata-forensics/readers_polyglot.py"
    mod = _load_module("ctf_polycarve_readers_polyglot", _paths.repo_root() / rel, pack=rel)
    if mod.M is None:
        mod.M = types.SimpleNamespace(Unknown=_Unbounded)
    return mod


def _label(chain: tuple) -> str:
    return " -> ".join(chain)


def image_kind(data: bytes) -> str | None:
    """png | jpeg | gif | bmp | webp by the first bytes, or None for anything else."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:2] == b"BM" and len(data) >= 26 and struct.unpack_from("<I", data, 14)[0] in (12, 40, 52, 56, 64, 108, 124):
        return "bmp"
    return None


def host_end(data: bytes, kind: str, objects=None) -> tuple[int | None, str]:
    """(the offset one past the image's own end, how it was found): 'validated' (carving.py checked the
    whole structure), 'structural' (readers_polyglot walked to the end marker of an image carving.py
    rejects), or (None, why) when neither bounds it. `objects` is a carve_all result that already holds
    the `kind` carvings (one scan of a big image, not two)."""
    if objects is None:
        objects = _carving().carve_all(data, kinds=(kind,))
    ends = [o.end for o in objects if o.offset == 0 and o.kind == kind]
    if ends:
        return ends[0], "validated"
    rp = _readers()
    walk_to = rp._HOST_END.get(kind)
    if walk_to is None:
        return None, f"a {kind} image whose structure does not validate"
    try:
        return int(walk_to(bytes(data))), "structural"
    except (rp.M.Unknown, struct.error, IndexError, ValueError) as e:
        return None, f"a {kind} image whose end cannot be found ({str(e)[:80] or type(e).__name__})"


def _walk_opens(data: bytes) -> bool:
    return data.startswith(_WALK_OPENS) or (len(data) >= 512 and data[257:262] == b"ustar")


def carve(chain: tuple, data: bytes, walk, notes: list) -> list[tuple[str, bytes]]:
    """[(member name, bytes)] carved from one content: [] unless it is an image holding more than itself."""
    kind = image_kind(data)
    if kind is None:
        return []
    where = _label(chain)
    cv = _carving()
    if len(data) > cv.MAX_SCAN:
        notes.append(f"{where}: a {kind} image of {len(data)} bytes is over the carve limit of {cv.MAX_SCAN}; "
                     f"not searched for archives inside or behind it")
        return []
    objects = cv.carve_all(data, kinds=ARCHIVE_KINDS + (kind,))
    found = [o for o in objects if o.offset > 0 and o.kind in ARCHIVE_KINDS]
    found.sort(key=lambda o: (o.offset, -o.end))
    end, how = host_end(data, kind, objects)
    out, covered, stop = [], 0, len(data)
    overlay = data[end:] if end is not None and end < len(data) else b""
    if overlay and not any(o.offset == end for o in found) and len(overlay.strip(_PAD)) >= MIN_OVERLAY:
        name = f"overlay@0x{end:x}.bin"
        if walk is None or walk.take(f"{where} -> {name}", len(overlay)):
            out.append((name, overlay))
            notes.append(f"{where}: {len(overlay)} bytes follow the {kind} image's end at 0x{end:x} "
                         f"({how}); kept as {name}")
            if _walk_opens(overlay):
                # The walk opens the overlay itself: nothing at or after the image's end is carved twice.
                # An archive inside the image (a zip in a private chunk) is still carved.
                stop = end
    elif end is None and data.find(b"PK\x05\x06", 1) > 0 and not found:
        notes.append(f"{where}: {how}, and a zip end-of-directory signature is in it: no archive validated; "
                     f"carve it by hand")
    for o in found:
        if o.offset >= stop:
            break                            # in the overlay the walk opens (found is sorted by offset)
        if o.offset < covered:
            continue                         # inside an archive already taken (a stored member, a stream in a zip)
        covered = o.end
        name = f"carved@0x{o.offset:x}.{_EXT[o.kind]}"
        if walk is not None and not walk.take(f"{where} -> {name}", len(o.data)):
            if walk.full:
                break
            continue
        out.append((name, o.data))
        notes.append(f"{where}: a {o.kind} archive of {len(o.data)} bytes at 0x{o.offset:x} of the {kind} image "
                     f"({'after its end' if end is not None and o.offset >= end else 'inside it'}; "
                     f"{o.validation}); opened as {name}")
    out.sort(key=lambda item: int(item[0].split("@0x")[1].split(".")[0], 16))
    return out


def cascade(rows, walk, notes: list, archive_expand) -> list[tuple[tuple, bytes]]:
    """[(chain, bytes)] the images among `rows` ([(chain, bytes)]) give up: each carved piece, then every
    member the archive walk reads out of it. One level: a row of the output is not carved here (the sweep
    passes the output back in)."""
    out = []
    for chain, body in rows:
        chain = tuple(chain)
        if walk is not None and walk.full:
            break
        try:
            pieces = carve(chain, bytes(body), walk, notes)
        except Exception as e:           # hostile bytes: one content that breaks a carver never stops the sweep
            notes.append(f"{_label(chain)}: carving failed on this content, nothing carved from it "
                         f"({type(e).__name__}: {e})")
            continue
        for name, data in pieces:
            full = chain + (name,)
            out.append((full, data))
            archive_expand.expand(name, data, {}, opts=walk)
            for c, _key, b in ((walk.rows if walk is not None else None) or [])[1:]:
                out.append((full + tuple(c)[1:], bytes(b)))
            if walk is not None:
                walk.rows = None
    return out
