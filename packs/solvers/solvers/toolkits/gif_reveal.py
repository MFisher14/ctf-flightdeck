#!/usr/bin/env python3
"""Toolkit `gif_reveal` (B-117): every frame of an animated GIF, whatever its timing says.

An animation hides a message in time: a frame a page's script never shows, a frame that flashes
for a hundredth of a second, a word that exists only in the difference between two frames, a
sentence spread a letter a frame. A screenshot of the page never holds it. This pulls every frame
out independent of any delay, and reads them:

  blocks    the GIF's own structure: per frame the delay, disposal and box; the loop count; the
            comment blocks; bytes after the trailer. Frames a viewer would not see are named:
            one far shorter than the rest (`brief`), one that follows a hold of ten seconds or
            more (`held back`).
  frames    every frame composited as a viewer would see it, one at a time (up to MAX_FRAMES,
            and fewer when they would hold more than MAX_TOTAL_PIXELS between them; the rest are
            named, not read), the frames that differ from every earlier one written as PNG. No
            frame is kept after it is written: one pass holds the frame in hand, a gray copy of
            the one before it, the two overlays and a digest a frame.
  diffs     per step, the pixels that changed, black on white: a message that is only a delta.
  overlay   the darkest and the lightest value each pixel takes over the animation: dark or
            light writing spread over frames, put back on one picture.
  codes     QR and barcodes in any frame (carve_stego.decode_codes): error-corrected, so a flag
            read there is evidence.
  OCR       tesseract over the named frames first, then each distinct frame, the diffs and the
            overlays (image_carve.ocr_text), until the deadline. The text of each reading is
            kept, with the flags in the event format and the identifiers in it (BAY-41, KX 58:
            a route crawler feeds them back into its crawl).

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}
  blocks(data) -> dict;  suspects(frames) -> [(index, why)]
  Reel(data) -> iterable of (index, frame);  reveal(frames) -> (label, image)...;  read_order(labels, named)
  frames(data, max_frames) -> ([PIL.Image], total);  frame_cap(width, height);  identifiers(text) -> [str]

  .venv/bin/python solvers/toolkits/gif_reveal.py FILE... [--event SLUG] [--out DIR] [--ocr auto|on|off]
        [--seconds S]

Status: a flag in a comment block, after the trailer or in a decoded code is `solved` when it is
the only one. A flag read by OCR is never more than `candidate` (0/O and 1/l are the usual
misreads). An animation with no flag is `unsure`: its frames, diffs and overlays are written for a
human or model read, which painted or photographed text still needs. A still GIF with nothing in
it is `none`. Nothing is executed; tesseract is the only program run, and without it the OCR step
is named as not run (`--ocr on` makes that `blocked`).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import statistics
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import _visual_stego as vs      # noqa: E402

ENGINE = "toolkits.gif_reveal"
MAX_INPUT = 64 << 20                  # bytes of one GIF
MAX_FRAMES = 64                       # frames composited and read
MAX_PIXELS = 4_000_000                # pixels of one frame
MAX_TOTAL_PIXELS = 32_000_000         # pixels over all the frames read of one GIF: 64 frames of 800x600, 8 of
                                      # the largest (a 1,500-byte file can declare 64 frames of 2000x2000)
BRIEF_MS = 50                         # a delay under this, beside frames four times longer, is a flash
BRIEF_RATIO = 4
HOLD_MS = 10_000                      # a frame after a hold this long is one few viewers wait for
DIFF_THRESHOLD = 32                   # gray levels a pixel must change by to count as changed
DEFAULT_SECONDS = 20.0                # a third of intake's 60 s per challenge; the manifest gives the process 30
IDENTIFIER = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2,6})[ _-]?([0-9]{1,4})(?![A-Za-z0-9])")


class GifError(ValueError):
    """Not a GIF this engine can read (bad signature, no frame, a frame over the pixel cap)."""


class ToolMissing(RuntimeError):
    """A module this reading needs is not importable; the message names it."""


def _pillow():
    try:
        from PIL import Image, ImageChops
    except ImportError as exc:
        raise ToolMissing("Pillow is not importable (py:PIL)") from exc
    return Image, ImageChops


# ---- structure -------------------------------------------------------------------------------------

def blocks(data: bytes) -> dict:
    """The block structure of a GIF: {size, frames, comments, apps, loop, trailing, truncated}.
    `frames` is one {index, delay_ms, disposal, transparent, left, top, width, height} per image
    descriptor; `loop` is the NETSCAPE loop count (0 = forever) or None when the file has none
    (it plays once); `trailing` counts the bytes after the trailer; `truncated` is True when the
    file ends before its trailer. GifError when the signature is not GIF87a/GIF89a.

    carve_stego.gif_blocks (Phase 1) walks the same blocks and keeps the frame count, the comments
    and the application names; this needs each frame's delay, disposal and box, the loop count and
    what follows the trailer, which that one does not keep, so it is a walk of its own. A test
    holds the two to the same comments, names and frame count on a whole file; on a file cut
    inside an image this one lists only the frames whose data is all there."""
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        raise GifError("not a GIF (no GIF87a/GIF89a header)")
    width, height, packed = struct.unpack_from("<HHB", data, 6)
    out = {"size": (width, height), "frames": [], "comments": [], "apps": [], "loop": None,
           "trailing": 0, "truncated": True}
    i = 13 + (3 * (2 << (packed & 7)) if packed & 0x80 else 0)
    control = {"delay_ms": 0, "disposal": 0, "transparent": None}

    def sub_blocks(at):
        parts = []
        while True:
            size = data[at]
            parts.append(data[at + 1:at + 1 + size])
            at += 1 + size
            if size == 0:
                return parts[:-1], at

    try:
        while i < len(data):
            kind = data[i]
            if kind == 0x3B:
                out["trailing"], out["truncated"] = len(data) - i - 1, False
                break
            if kind == 0x21:
                label = data[i + 1]
                parts, i = sub_blocks(i + 2)
                if label == 0xF9 and parts and len(parts[0]) >= 4:
                    flags, delay, index = struct.unpack_from("<BHB", parts[0], 0)
                    control = {"delay_ms": delay * 10, "disposal": (flags >> 2) & 7,
                               "transparent": index if flags & 1 else None}
                elif label == 0xFE:
                    out["comments"].append(b"".join(parts).decode("utf-8", "replace"))
                elif label == 0xFF and parts:
                    name = parts[0].decode("latin-1")
                    out["apps"].append(name)
                    if name in ("NETSCAPE2.0", "ANIMEXTS1.0") and len(parts) > 1 and len(parts[1]) >= 3 \
                            and parts[1][0] == 1:
                        out["loop"] = struct.unpack_from("<H", parts[1], 1)[0]
            elif kind == 0x2C:
                left, top, w, h, flags = struct.unpack_from("<HHHHB", data, i + 1)
                i += 10 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0) + 1
                _parts, i = sub_blocks(i)
                out["frames"].append({"index": len(out["frames"]), **control, "left": left, "top": top,
                                      "width": w, "height": h})
                control = {"delay_ms": 0, "disposal": 0, "transparent": None}
            else:
                break
    except (IndexError, struct.error):
        pass
    return out


def suspects(frames: list) -> list:
    """[(index, why)] of the frames a viewer would not see, from the delays alone: a frame under
    BRIEF_MS while the longest delay is at least BRIEF_RATIO times its own (`brief`: a file whose
    frames are all short is just a fast animation), and a frame that follows one held HOLD_MS or
    longer (`held back`)."""
    delays = [f["delay_ms"] for f in frames]
    out = []
    for k, delay in enumerate(delays):
        if len(delays) > 1 and delay < BRIEF_MS and max(delays) >= max(BRIEF_RATIO * delay, BRIEF_MS):
            out.append((k, f"brief: shown {delay} ms, the median frame {int(statistics.median(delays))} ms"))
        elif k and delays[k - 1] >= HOLD_MS:
            out.append((k, f"held back: it follows a frame held {delays[k - 1] / 1000:g} s"))
    return out


# ---- frames ----------------------------------------------------------------------------------------

def frame_cap(width: int, height: int) -> int:
    """How many frames of this size are read: MAX_FRAMES, or as many as hold MAX_TOTAL_PIXELS
    between them (at least one)."""
    return max(1, min(MAX_FRAMES, MAX_TOTAL_PIXELS // max(1, width * height)))


class Reel:
    """An opened GIF, read one frame at a time. Iterating yields (index, frame): each frame as a
    viewer sees it (disposal and transparency applied, on white, RGB), built when it is asked for
    and not kept here once it is handed on.

      total   frames in the file (lowered to what could be read when the file is cut inside one)
      limit   frames this reads: `max_frames`, or frame_cap() of the picture's size
      read    frames handed on so far
      cut     why the reading stopped before `limit` ("" when it did not): `deadline`
              (time.monotonic()) passed before a frame was built

    GifError when the picture cannot be opened, is empty or over MAX_PIXELS, or its first frame
    cannot be read."""

    def __init__(self, data: bytes, max_frames: int | None = None, deadline=None):
        Image, _chops = _pillow()
        try:
            self._image = Image.open(io.BytesIO(data))
            self.total = getattr(self._image, "n_frames", 1) or 1
        except Exception as exc:
            raise GifError(f"cannot open the picture: {exc}") from exc
        width, height = self._image.size
        if width * height > MAX_PIXELS or not width or not height:
            raise GifError(f"{width}x{height} is empty or over the {MAX_PIXELS} pixel cap")
        self.size = (width, height)
        self.limit = min(self.total, frame_cap(width, height) if max_frames is None else max_frames)
        self.read, self.cut, self._deadline = 0, "", deadline

    def __iter__(self):
        Image, _chops = _pillow()
        for k in range(self.limit):
            if self._deadline is not None and time.monotonic() > self._deadline:
                self.cut = f"out of time before frame {k}"
                return
            try:
                self._image.seek(k)
                frame = self._image.convert("RGBA")
            except (EOFError, OSError, ValueError) as exc:
                if k == 0:
                    raise GifError(f"cannot read frame 0: {exc}") from exc
                self.total = self.limit = k
                return
            flat = Image.new("RGB", frame.size, (255, 255, 255))
            flat.paste(frame, mask=frame.getchannel("A"))
            self.read = k + 1
            yield k, flat


def frames(data: bytes, max_frames: int | None = None) -> tuple:
    """([PIL.Image], total): the first `max_frames` (default frame_cap() of the picture's size)
    frames as a viewer sees them and how many frames the file has. A list of every frame, for a
    caller that wants one; the engine reads a Reel and holds one frame at a time. GifError as
    Reel."""
    reel = Reel(data, max_frames)
    return [frame for _k, frame in reel], reel.total


def reveal(frame_iter):
    """What an animation shows, from one pass over (index, frame) pairs. Yields (label, image):

      "frame k"            each frame that differs from every earlier one
      "diff j->k"          per step, the pixels that changed from the frame before by more than
                           DIFF_THRESHOLD gray levels, black on white: a message that is only a
                           delta. Steps with no change, and steps whose change is the same
                           picture as an earlier step's, are left out.
      "overlay darkest"    after the last frame, when more than one distinct frame was seen: per
      "overlay lightest"   pixel the darkest and the lightest gray it takes over the animation
                           (dark or light writing spread over frames, back on one picture)

    Held between two frames: a gray copy of the frame before, the two overlays, and a digest for
    each distinct frame and diff. Never the frames themselves."""
    _image, chops = _pillow()
    seen_frames, seen_diffs = set(), set()
    before = darkest = lightest = None
    last = None
    for k, frame in frame_iter:
        digest = hashlib.sha256(frame.tobytes()).digest()
        if digest not in seen_frames:
            seen_frames.add(digest)
            yield f"frame {k}", frame
        gray = frame.convert("L")
        if before is not None:
            mask = chops.difference(before, gray).point(lambda v: 0 if v > DIFF_THRESHOLD else 255)
            if mask.getextrema()[0] != 255:
                digest = hashlib.sha256(mask.tobytes()).digest()
                if digest not in seen_diffs:
                    seen_diffs.add(digest)
                    yield f"diff {last}->{k}", mask
        darkest = gray if darkest is None else chops.darker(darkest, gray)
        lightest = gray if lightest is None else chops.lighter(lightest, gray)
        before, last = gray, k
    if len(seen_frames) > 1:
        yield "overlay darkest", darkest
        yield "overlay lightest", lightest


def read_order(labels: list, named: list) -> list:
    """The labels reveal() gave, in the order the OCR reads them: the frames `named` as ones a
    viewer would not see ([(index, why)]) first, then every other frame, the diffs, the two
    overlays."""
    first = {f"frame {k}": n for n, (k, _why) in enumerate(named)}

    def rank(label):
        if label in first:
            return 0, first[label]
        return (1 if label.startswith("frame ") else 2 if label.startswith("diff ") else 3), 0

    return sorted(labels, key=rank)                     # stable: reveal()'s order inside each group


def _png(image) -> bytes:
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def identifiers(text: str) -> list:
    """The designators in a text, as written and deduplicated: two to six capitals, an optional
    blank, dash or underscore, one to four digits (BAY-41, KX 58, TRN_26)."""
    return list(dict.fromkeys(m.group(0) for m in IDENTIFIER.finditer(text or "")))


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Reading:
    source: str                       # "frame 3", "diff 2->3", "overlay darkest"
    text: str
    flags: list
    identifiers: list


@dataclass
class Animation:
    file: str
    structure: dict                   # blocks()
    total: int                        # frames in the file
    read: int                         # frames composited (at most frame_cap(); 0 when nothing needed them)
    suspects: list                    # [(index, why)]
    proven: list = field(default_factory=list)        # [(flag, evidence kind, where)]: bytes or a decoded code
    codes: list = field(default_factory=list)         # carve_stego.decode_codes rows
    readings: list = field(default_factory=list)      # [Reading] the OCR made

    @property
    def ocr_flags(self) -> list:
        return list(dict.fromkeys(f for r in self.readings for f in r.flags))

    @property
    def identifiers(self) -> list:
        return list(dict.fromkeys(i for r in self.readings for i in r.identifiers))


@dataclass
class Report:
    animations: list = field(default_factory=list)
    written: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    ocr: str = "not needed"


def _default_ocr():
    import image_carve
    return image_carve.ocr_text, image_carve.ocr_flags, (image_carve.ToolMissing,), (image_carve.OutOfBudget,)


def examine(files: dict, ff, *, ocr: str = "auto", out_dir: Path | None = None, deadline=None, prefixes=(),
            read=None, codes=None) -> Report:
    """Read every GIF of {name: bytes}. `read(png, deadline=)` is the OCR call (default
    image_carve.ocr_text) and `codes(data, ...)` the code reader (default carve_stego.decode_codes).
    With out_dir, each animation's distinct frames, diffs and overlays are written there, one at a
    time as they are made (reveal()); the OCR then reads them back in read_order(). Without
    out_dir they go to a temporary folder for the OCR, and when there is no OCR either (ocr="off")
    the frames are not composited at all: structure, comment blocks, trailing bytes and codes are
    still read. Past `deadline` no further frame is composited and nothing more is written; what
    was left out is named. ToolMissing propagates when ocr is "on" and tesseract or Pillow is
    absent."""
    if ocr not in ("auto", "on", "off"):
        raise ValueError("ocr must be auto, on or off")
    rep = Report()
    ocr_text, ocr_flags, missing, out_of_time = _default_ocr()
    read = read or ocr_text
    no_reader = None
    if codes is None:
        import carve_stego
        codes = carve_stego.decode_codes
        no_reader = vs.code_reader_missing()            # decode_codes then finds nothing in anything

    def late():
        return deadline is not None and time.monotonic() > deadline

    for name in sorted(files):
        data = files[name]
        if data[:6] not in (b"GIF87a", b"GIF89a"):
            continue
        if no_reader and no_reader not in rep.skipped:
            rep.skipped.append(no_reader)
        try:
            structure = blocks(data)
            reel = Reel(data, deadline=deadline)
        except GifError as exc:
            rep.skipped.append(f"{name}: not read: {exc}")
            continue
        anim = Animation(name, structure, reel.total, 0, suspects(structure["frames"]))
        rep.animations.append(anim)
        if structure["truncated"]:
            rep.skipped.append(f"{name}: the file ends before its trailer")
        for k, comment in enumerate(structure["comments"]):
            anim.proven += [(flag, "carve", f"comment block {k}") for flag in ff.find_flags(comment)]
        if structure["trailing"]:
            tail = data[len(data) - structure["trailing"]:]
            anim.proven += [(flag, "carve", f"{structure['trailing']} bytes after the trailer")
                            for flag in ff.find_flags(tail)]
        anim.codes = codes(data, planes=False, max_frames=frame_cap(*reel.size), deadline=deadline, skipped=rep.skipped)
        for code in anim.codes:
            found = ff.find_flags(code["text"] if code.get("text") else code.get("bytes", b""))
            anim.proven += [(flag, "decode", f"{code.get('format', 'code')} in {code.get('how', 'a frame')}")
                            for flag in found]
        if reel.total < 2:
            continue                                    # a still picture: nothing hidden in time
        reading = ocr != "off" and not rep.ocr.startswith("not run")
        if ocr == "off":
            rep.ocr = "off"
        if out_dir is None and not reading:
            continue                                    # nobody would look at the frames: they are not composited
        with tempfile.TemporaryDirectory(prefix="gif_reveal_") if out_dir is None else _Kept(out_dir) as folder:
            try:
                made = _write_sources(name, reel, anim, rep, Path(folder), keep=out_dir is not None, late=late)
            except GifError as exc:                     # its blocks were walked and its codes read; its frames are not
                rep.skipped.append(f"{name}: frames not read: {exc}")
                continue
            if not reading:
                continue
            for label in read_order(list(made), anim.suspects):
                if late():
                    rep.skipped.append(f"{name}: OCR out of time before {label}"
                                       + ("; it is written for a human or model read" if out_dir is not None else ""))
                    break
                try:
                    text = read(made[label].read_bytes(), deadline=deadline)
                except missing as exc:
                    if ocr == "on":
                        raise ToolMissing(str(exc)) from exc
                    rep.ocr = f"not run: {exc}; the frames are written for a human or model read"
                    break
                except out_of_time as exc:
                    rep.skipped.append(f"{name}: OCR out of time in {label}: {exc}")
                    break
                rep.ocr = "run"
                if text.strip():
                    anim.readings.append(Reading(label, text, ocr_flags(text, ff, prefixes), identifiers(text)))
    return rep


class _Kept:
    """The output folder as a context manager that leaves it where it is (the other branch of the
    `with` in examine() is a temporary folder, which is removed)."""

    def __init__(self, folder: Path):
        self.folder = folder

    def __enter__(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        return self.folder

    def __exit__(self, *_exc):
        return False


def _write_sources(name: str, reel: Reel, anim: Animation, rep: Report, folder: Path, *, keep: bool, late) -> dict:
    """One pass over the reel: each picture reveal() gives is written to `folder` as PNG and let
    go. Returns {label: path}. `keep` says the folder is the caller's output (the paths go into
    rep.written). Past the deadline (`late()`) nothing more is written; the frames not composited
    and the pictures not written are named in rep.skipped. A GIF that turns out to have one
    readable frame is a still: what was written for it is removed again."""
    made, unwritten = {}, []
    for label, image in reveal(reel):
        if late():
            unwritten.append(label)
            continue
        path = folder / f"{vs.safe_name(name)}.{label.replace(' ', '').replace('->', '-')}.png"
        path.write_bytes(_png(image))
        made[label] = path
    anim.total, anim.read = reel.total, reel.read
    if reel.cut:
        rep.skipped.append(f"{name}: {reel.cut}: {reel.total - reel.read} of its {reel.total} frames were not read")
    elif reel.read < 2:
        for path in made.values():
            path.unlink()
        return {}
    elif reel.total > reel.read:
        why = "" if reel.read >= MAX_FRAMES else f": the cap of {MAX_TOTAL_PIXELS} pixels over all the frames of one GIF"
        rep.skipped.append(f"{name}: {reel.total} frames, only the first {reel.read} were read{why}")
    if unwritten:
        rep.skipped.append(f"{name}: out of time: {', '.join(unwritten)} not written")
    if keep:
        rep.written += list(made.values())
    return made


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    proven, candidates, evidence, notes, material = [], [], [], [], False
    for anim in rep.animations:
        for flag, kind, where in anim.proven:
            proven.append(flag)
            evidence.append(Evidence(kind, f"flag in {where}", path=anim.file))
        for reading in anim.readings:
            for flag in reading.flags:
                if flag not in proven and flag not in candidates:
                    candidates.append(flag)
                    evidence.append(Evidence("ocr", f"OCR of {reading.source}", path=anim.file))
        animated = anim.total > 1                       # by the file's own count: frames not read for time still count
        material = material or animated
        s = anim.structure
        if animated:
            delays = sorted({f["delay_ms"] for f in s["frames"]})
            loop = "plays once" if s["loop"] is None else "loops forever" if s["loop"] == 0 else f"loops {s['loop']} times"
            notes.append(f"{anim.file}: {anim.total} frames {s['size'][0]}x{s['size'][1]}, delays "
                         f"{', '.join(map(str, delays[:6]))} ms, {loop}")
        for k, why in anim.suspects:
            notes.append(f"{anim.file}: frame {k} is {why}")
        if anim.identifiers:
            notes.append(f"{anim.file}: identifiers read by OCR: {', '.join(anim.identifiers[:20])}")
        for code in anim.codes:
            text = str(code.get("text"))
            if not any(flag in text for flag, _kind, _where in anim.proven):
                notes.append(f"{anim.file}: {code.get('format', 'code')} in {code.get('how', 'a frame')} reads {text[:200]!r}")
        for k, comment in enumerate(s["comments"]):
            if not any(flag in comment for flag, _kind, _where in anim.proven):
                notes.append(f"{anim.file}: comment block {k}: {comment[:200]!r}")
        if s["trailing"]:
            notes.append(f"{anim.file}: {s['trailing']} bytes after the trailer")
    for p in rep.written:
        evidence.append(Evidence("carve", "written", path=rel(p)))
    if rep.ocr not in ("not needed", "run"):
        notes.append(f"OCR {rep.ocr}")
    notes += rep.skipped
    proven = list(dict.fromkeys(proven))
    status = vs.status_of(proven, candidates, material)
    return SolverResult(status=status, flags=proven + candidates, evidence=evidence,
                        cost=Cost(seconds=round(seconds, 3)), engine=ENGINE, challenge_id=challenge_id,
                        notes="; ".join(notes))


# ---- the engine contract ---------------------------------------------------------------------------

def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: ocr (auto|on|off), out (folder for the frames; default
    <challenge>/recon/gif_reveal), seconds (budget, default 20)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "gif_reveal"
    paths, skipped = vs.challenge_paths(challenge_dir, MAX_INPUT)
    files = {}
    for rel, path in paths:
        with path.open("rb") as handle:
            if handle.read(6) in (b"GIF87a", b"GIF89a"):
                files[rel] = path.read_bytes()
    try:
        rep = examine(files, flagfmt.for_profile(profile), ocr=str(opts.get("ocr", "auto")), out_dir=out_dir,
                      deadline=t0 + float(opts.get("seconds", DEFAULT_SECONDS)), prefixes=tuple(profile.flag.prefixes))
    except ToolMissing as exc:
        return SolverResult(status="blocked", engine=ENGINE, notes=f"gif_reveal could not run as asked: {exc}")
    rep.skipped += skipped
    return result_of(rep, seconds=time.monotonic() - t0, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gif_reveal.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--out", type=Path, help="folder for the frames, diffs and overlays (default: none written)")
    ap.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"gif_reveal.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    try:
        rep = examine({str(p): p.read_bytes() for p in a.files}, flagfmt.for_profile(profile), ocr=a.ocr,
                      out_dir=a.out, deadline=t0 + a.seconds, prefixes=tuple(profile.flag.prefixes))
    except ToolMissing as exc:
        print(f"gif_reveal.py: {exc}", file=sys.stderr)
        return 2
    for anim in rep.animations:
        print(f"{anim.file}: {anim.total} frames, {len(anim.suspects)} a viewer would not see")
        for reading in anim.readings:
            print(f"  [{reading.source}] flags={reading.flags} identifiers={reading.identifiers} "
                  f"{' '.join(reading.text.split())[:80]!r}")
    for p in rep.written:
        print(f"written: {p}")
    print(result_of(rep, seconds=time.monotonic() - t0).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
