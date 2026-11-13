#!/usr/bin/env python3
"""Audio opener (B-129): every audio drop at intake decoded to PCM and read for the usual keyed
signals, with no model.

    .venv/bin/python solvers/toolkits/audio_opener.py <file-or-folder>... [--event SLUG]

For each audio file (WAV, MP3, FLAC, Ogg, AIFF; sniffed by content, not by name) it:

  1. decodes it to mono PCM in-process with soundfile (libsndfile). An MP3 needs a libsndfile
     build with MPEG support (1.1+); a build without it is a named failure, never a fallback to
     ffmpeg or a container. Nothing is executed and nothing is transcoded on disk.
  2. finds the dominant tones (averaged Hann spectrum) and, for each, whether it is keyed on and
     off (two-level envelope at that frequency) with its on/off run lengths in ms.
  3. reads Morse with signal_stego_depth.decode_morse_tone: keyed at each dominant tone first (a
     narrow-band envelope survives cassette hiss and MP3 smearing), then broadband. The decoder only
     returns text when every run fits the 1/3/7 lattice (tolerance 0.36 of the lattice value); a
     silence longer than a word gap reads as a word gap.
  4. reads DTMF: energy-segmented key presses, each classified by row/column dominance and twist,
     accepted only when every press classifies.
  5. prints the tags: ID3v2/ID3v1 frames (MP3), the libsndfile strings (RIFF INFO, Vorbis
     comments), and the EXIF text of any picture embedded in the ID3 tag.

Images in the same drop (JPEG, PNG, TIFF, WebP) get their EXIF text printed too: the location or
date that completes a Morse clue usually sits in a sibling photo's ImageDescription.

It prints a triage, then one SolverResult line: `candidate` when an event-format flag appears in a
decode or a tag, `unsure` when Morse or DTMF text was read (it needs a read: these drops are usually
a clue, not the flag), `none` otherwise, `blocked` when no audio could be decoded because a tool is
missing. It never submits.

Public functions:

  sniff(data)                      -> "wav" | "mp3" | "flac" | "ogg" | "aiff" | None
  decode_pcm(data, kind)           -> Pcm (mono float64), raising ToolMissing / DecodeError
  dominant_tones(samples, rate)    -> [Tone] strongest spectral peaks
  keying(samples, rate, tone_hz)   -> Keying | None  on/off runs at that tone, in ms
  read_morse(pcm, tones)           -> MorseRead | None
  read_dtmf(pcm)                   -> str | None
  id3_tags(data)                   -> [(frame, value)] ID3v2 + ID3v1
  exif_text(data)                  -> [(tag, value)] (needs exifread)
  open_paths(paths, ff)            -> Opening
"""
from __future__ import annotations

import argparse
import io
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

try:
    from ctf import flagfmt as _flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt as _flagfmt
from ctf import event as _event  # noqa: E402
from ctf.result import Evidence, SolverResult  # noqa: E402

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import signal_stego_depth as sig  # noqa: E402  (sibling toolkit: the carried keyed-tone decoders)

ENGINE = "toolkits.audio_opener"
MAX_FILE_BYTES = 64 << 20          # a larger file is skipped with a note
MAX_AUDIO_FILES = 8
MAX_IMAGE_FILES = 16
MAX_AUDIO_SECONDS = 600            # decode at most the first ten minutes
CHUNK_FRAMES = 1 << 16
SPECTRUM_FRAME = 4096
SPECTRUM_FRAMES = 256              # frames averaged, evenly spaced over the file
TONE_FLOOR = 20.0                  # a tone's power over the spectrum's median power
TONE_SPREAD = 1e-2                 # a tone at least this fraction (-20 dB) of the strongest one's power
TONE_SEPARATION_HZ = 60.0          # closer peaks are the same tone: keying sidebands, window lobes
MAX_TONES = 3
ANALYSIS_MS = 5.0
DTMF_BLOCK_MS = 10.0
DTMF_MIN_PRESS_MS = 30.0
MIN_DTMF_KEYS = 3
MAX_DTMF_KEYS = 4096
MAX_ID3_FRAMES = 256
MAX_TAG_TEXT = 2000
MAX_EXIF_TAGS = 60
_SKIP_EXIF = ("Thumbnail", "MakerNote", "JPEGThumbnail")
_EXIF_FIRST = ("Image ImageDescription", "Image XPComment", "Image XPTitle", "Image XPSubject",
               "EXIF UserComment", "Image Artist", "Image Copyright", "EXIF DateTimeOriginal")


class ToolMissing(RuntimeError):
    """A library the opener needs is absent or lacks a codec: a named failure, never a fallback."""


class DecodeError(ValueError):
    """libsndfile could not read this file as audio."""


# ---- sniffing ----------------------------------------------------------------------------------

def _mp3_sync(data: bytes) -> bool:
    return (len(data) >= 4 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0
            and (data[1] & 0x06) != 0 and (data[1] & 0x18) != 0x08 and (data[2] & 0xF0) != 0xF0)


def sniff(data: bytes) -> str | None:
    """The audio container by content: RIFF/WAVE, MP3 (ID3 tag or MPEG frame sync), FLAC, Ogg, AIFF."""
    head = bytes(data[:16])
    if head[:4] == b"RIFF" and head[8:12] in (b"WAVE", b"RF64"):
        return "wav"
    if head[:4] in (b"RF64", b"BW64") and head[8:12] == b"WAVE":
        return "wav"
    if head[:3] == b"ID3" or _mp3_sync(head):
        return "mp3"
    if head[:4] == b"fLaC":
        return "flac"
    if head[:4] == b"OggS":
        return "ogg"
    if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        return "aiff"
    return None


def image_kind(data: bytes) -> str | None:
    head = bytes(data[:12])
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


# ---- decoding ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class Pcm:
    rate: int
    samples: np.ndarray            # mono float64
    channels: int
    source_rate: int
    seconds: float                 # of the decoded part
    note: str = ""                 # truncation / decimation, said out loud

    def audio(self) -> "sig.Audio":
        return sig.Audio(self.rate, self.samples)


def _soundfile():
    try:
        import soundfile
    except (ImportError, OSError) as e:      # OSError: the wheel's libsndfile failed to load
        hint = ("it loads libsndfile through ctypes, so run this engine under the OS network sandbox"
                if "network guard" in str(e) else "install it into the venv (requirements.in pins soundfile)")
        raise ToolMissing(f"soundfile (libsndfile) is not importable: {type(e).__name__}: {e}; {hint}") from None
    return soundfile


def decode_pcm(data: bytes, kind: str | None = None, *, max_seconds: float = MAX_AUDIO_SECONDS) -> Pcm:
    """Decode an audio file's bytes to mono float64 PCM with libsndfile. The first `max_seconds`
    are read; a file longer than the decoder sample cap is mean-decimated to fit, and `note` says
    so. ToolMissing when soundfile is absent or an MP3 meets a build without MPEG support."""
    kind = kind or sniff(data)
    sf = _soundfile()
    if kind == "mp3" and "MP3" not in sf.available_formats():
        raise ToolMissing(f"the installed libsndfile ({getattr(sf, '__libsndfile_version__', '?')}) has no MPEG "
                          "support, so this MP3 cannot be decoded in-process; install a soundfile wheel whose "
                          "libsndfile is 1.1 or newer (no ffmpeg or container fallback is used)")
    try:
        with sf.SoundFile(io.BytesIO(bytes(data))) as f:
            rate, channels = int(f.samplerate), int(f.channels)
            if rate <= 0 or channels <= 0:
                raise DecodeError(f"libsndfile reports {rate} Hz, {channels} channel(s)")
            want = int(max_seconds * rate)
            frames = f.frames if 0 < f.frames < (1 << 62) else want
            take = min(frames, want)
            factor = max(1, math.ceil(take / sig.MAX_SAMPLES))
            parts, got = [], 0
            step = CHUNK_FRAMES * factor
            while got < take:
                block = f.read(min(step, take - got), dtype="float64", always_2d=True)
                if not block.size:
                    break
                got += block.shape[0]
                mono = block.mean(axis=1)
                if factor > 1:
                    usable = mono.size - mono.size % factor
                    mono = mono[:usable].reshape(-1, factor).mean(axis=1)
                parts.append(mono)
            more = f.frames > take if 0 < f.frames < (1 << 62) else bool(f.read(1, always_2d=True).size)
    except (ToolMissing, DecodeError):
        raise
    except Exception as e:  # libsndfile raises its own error types (LibsndfileError, RuntimeError)
        raise DecodeError(f"libsndfile could not decode it: {type(e).__name__}: {e}") from None
    samples = np.concatenate(parts) if parts else np.zeros(0)
    if not samples.size:
        raise DecodeError("no audio frames")
    if not np.all(np.isfinite(samples)):
        raise DecodeError("decoded samples are not finite")
    notes = []
    if more:
        notes.append(f"only the first {max_seconds:g} s decoded")
    new_rate = rate
    if factor > 1:
        new_rate = int(round(rate / factor))
        notes.append(f"mean-decimated x{factor} to {new_rate} Hz to fit the decoder's sample cap "
                     f"(tones above {new_rate // 2} Hz are lost)")
    return Pcm(new_rate, samples, channels, rate, samples.size / new_rate, "; ".join(notes))


# ---- tones and keying --------------------------------------------------------------------------

@dataclass(frozen=True)
class Tone:
    hz: float
    prominence: float              # peak power over the median power of the spectrum


def dominant_tones(samples: np.ndarray, rate: int, *, count: int = MAX_TONES) -> list[Tone]:
    """The strongest narrow spectral peaks (Hz, parabolic-interpolated), strongest first: each at
    least TONE_FLOOR over the spectrum's median and TONE_SPREAD of the strongest, peaks within
    TONE_SEPARATION_HZ of a stronger one (on/off keying sidebands, window side lobes: the same
    tone) dropped. DTMF's closest pair (697/770 Hz) stays apart."""
    x = np.asarray(samples, dtype=np.float64)
    if x.size < 64 or rate <= 0:
        return []
    n = SPECTRUM_FRAME if x.size >= SPECTRUM_FRAME else 1 << int(math.log2(x.size))
    starts = np.unique(np.linspace(0, x.size - n, num=min(SPECTRUM_FRAMES, max(1, x.size // n)), dtype=np.int64))
    frames = np.stack([x[s:s + n] for s in starts]) * np.hanning(n)
    power = np.mean(np.abs(np.fft.rfft(frames, axis=1)) ** 2, axis=0)
    freqs = np.fft.rfftfreq(n, 1 / rate)
    band = (freqs >= 40) & (freqs <= min(rate / 2 * 0.98, 20000))
    if not band.any():
        return []
    floor = float(np.median(power[band]))
    if floor <= 0:
        floor = float(np.max(power[band])) * 1e-12 or 1e-300
    peaks = [k for k in np.nonzero(band)[0] if 0 < k < power.size - 1
             and power[k] > power[k - 1] and power[k] >= power[k + 1] and power[k] >= TONE_FLOOR * floor]
    peaks.sort(key=lambda k: -power[k])
    chosen: list[int] = []
    for k in peaks:
        if chosen and power[k] < TONE_SPREAD * power[chosen[0]]:
            break
        if all(abs(k - c) * rate / n > TONE_SEPARATION_HZ for c in chosen):
            chosen.append(k)
        if len(chosen) >= count:
            break
    out = []
    for k in chosen:
        a, b, c = (math.log(max(power[k + d], 1e-300)) for d in (-1, 0, 1))
        den = a - 2 * b + c
        shift = 0.5 * (a - c) / den if den else 0.0
        out.append(Tone(float((k + max(-0.5, min(0.5, shift))) * rate / n), float(power[k] / floor)))
    return out


@dataclass(frozen=True)
class Keying:
    tone_hz: float | None
    on_ms: tuple[float, ...]       # every tone run, in order
    off_ms: tuple[float, ...]      # every silence between tone runs, in order

    @property
    def unit_ms(self) -> float:
        """The median of the shorter half of the tone runs (a Morse dot)."""
        short = sorted(self.on_ms)[:max(1, len(self.on_ms) // 2)]
        return float(np.median(short))

    def summary(self) -> str:
        def q(v):
            return "/".join(f"{np.percentile(v, p):.0f}" for p in (10, 50, 90)) if v else "-"
        where = f"{self.tone_hz:.1f} Hz" if self.tone_hz else "broadband"
        return (f"keyed at {where}: {len(self.on_ms)} tone runs, on ms p10/50/90 {q(self.on_ms)}, "
                f"off ms p10/50/90 {q(self.off_ms)}, unit ~{self.unit_ms:.0f} ms")


def _block(rate: int, ms: float) -> int:
    return max(4, int(round(rate * ms / 1000)))


def keying(samples: np.ndarray, rate: int, tone_hz: float | None, *, analysis_ms: float = ANALYSIS_MS) -> Keying | None:
    """On/off run lengths (ms) of the envelope at `tone_hz` (broadband with None), or None when the
    envelope is not two-level or has fewer than two tone runs."""
    runs = sig.keyed_runs(sig.Audio(rate, np.asarray(samples, dtype=np.float64)), tone_hz=tone_hz,
                          analysis_ms=analysis_ms)
    if not runs:
        return None
    ms = _block(rate, analysis_ms) * 1000.0 / rate
    on = tuple(n * ms for state, n in runs if state)
    off = tuple(n * ms for state, n in runs if not state)
    return Keying(tone_hz, on, off) if len(on) >= 2 else None


@dataclass(frozen=True)
class MorseRead:
    text: str
    tone_hz: float | None          # None: read from the broadband envelope
    unit_ms: float


def read_morse(pcm: Pcm, tones: list[Tone]) -> MorseRead | None:
    """decode_morse_tone keyed at each dominant tone, strongest first, then broadband."""
    audio = pcm.audio()
    for hz in [t.hz for t in tones] + [None]:
        got = sig.decode_morse_tone(audio, tone_hz=hz, long_gaps=True, analysis_ms=ANALYSIS_MS)
        if got:
            k = keying(pcm.samples, pcm.rate, hz)
            return MorseRead(got.decode("ascii"), hz, k.unit_ms if k else 0.0)
    return None


def read_dtmf(pcm: Pcm, *, min_keys: int = MIN_DTMF_KEYS) -> str | None:
    """DTMF keys of an energy-segmented recording: each press (a tone run of DTMF_MIN_PRESS_MS or
    more) classified whole; None unless every press is a DTMF key and there are min_keys. A shorter
    burst (a click, a bounce) refuses the read rather than being skipped. The press is not trimmed:
    dtmf_key Hann-windows the segment, so its edge blocks already carry little weight (about 1% each
    on an 80 ms press), and trimming a 30 ms press would leave one 10 ms block, too short to tell
    697 Hz from 770 Hz."""
    block = _block(pcm.rate, DTMF_BLOCK_MS)
    if pcm.samples.size // block < 4:
        return None
    levels = sig.tone_levels(pcm.audio(), block)
    centers = sig._two_means(levels)
    if not centers or centers[1] < max(1e-6, centers[0] * 3):
        return None
    min_blocks = max(1, int(math.ceil(DTMF_MIN_PRESS_MS / DTMF_BLOCK_MS)))
    keys, at = [], 0
    for state, n in sig._runs(levels > (centers[0] + centers[1]) / 2):
        if state:
            if n < min_blocks:
                return None
            key = sig.dtmf_key(pcm.samples[at * block:(at + n) * block], pcm.rate)
            if key is None:
                return None
            keys.append(key)
            if len(keys) > MAX_DTMF_KEYS:
                return None
        at += n
    return "".join(keys) if len(keys) >= min_keys else None


# ---- tags --------------------------------------------------------------------------------------

def _syncsafe(b: bytes) -> int:
    return (b[0] & 0x7F) << 21 | (b[1] & 0x7F) << 14 | (b[2] & 0x7F) << 7 | (b[3] & 0x7F)


def _id3_text(enc: int, raw: bytes) -> str:
    codec = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin-1")
    text = raw.decode(codec, "replace")
    return " / ".join(p for p in text.split("\x00") if p)


def _split_term(enc: int, raw: bytes) -> tuple[bytes, bytes]:
    """(first, rest) split at the encoding's terminator."""
    if enc in (1, 2):
        for i in range(0, len(raw) - 1, 2):
            if raw[i:i + 2] == b"\x00\x00":
                return raw[:i], raw[i + 2:]
        return raw, b""
    i = raw.find(b"\x00")
    return (raw, b"") if i < 0 else (raw[:i], raw[i + 1:])


def _id3_frame(fid: str, body: bytes) -> tuple[str, str | bytes] | None:
    if not body:
        return None
    if fid in ("TXXX", "TXX", "WXXX", "WXX"):
        enc = body[0]
        desc, value = _split_term(enc, body[1:])
        val = value.decode("latin-1", "replace").strip("\x00") if fid.startswith("W") else _id3_text(enc, value)
        return f"{fid}:{_id3_text(enc, desc)}", val
    if fid in ("COMM", "COM", "USLT", "ULT"):
        enc = body[0]
        desc, value = _split_term(enc, body[4:])
        label = f"{fid}:{_id3_text(enc, desc)}" if desc.strip(b"\x00") else fid
        return label, _id3_text(enc, value)
    if fid in ("APIC", "PIC"):
        enc = body[0]
        if fid == "PIC":
            mime, rest = body[1:4].decode("latin-1", "replace"), body[4:]
        else:
            m, rest = _split_term(0, body[1:])
            mime = m.decode("latin-1", "replace")
        _desc, picture = _split_term(enc, rest[1:])
        return f"{fid}:{mime}", picture
    if fid[0] == "T":
        return fid, _id3_text(body[0], body[1:])
    if fid[0] == "W":
        return fid, body.decode("latin-1", "replace").strip("\x00")
    if fid in ("PRIV", "GEOB", "UFID"):
        owner, rest = _split_term(0, body)
        return f"{fid}:{owner.decode('latin-1', 'replace')}", f"{len(rest)} bytes"
    return None


def id3_tags(data: bytes) -> list[tuple[str, str | bytes]]:
    """ID3v2.2/2.3/2.4 frames at the start and the ID3v1 tag at the end, as (frame, value). A text
    value is a str; an attached picture (APIC) is its raw bytes. Unsynchronised or compressed
    frames are named, not decoded."""
    out: list[tuple[str, str | bytes]] = []
    data = bytes(data)
    if len(data) >= 10 and data[:3] == b"ID3" and data[3] in (2, 3, 4):
        major, flags = data[3], data[5]
        size = _syncsafe(data[6:10])
        tag = data[10:10 + size]
        if flags & 0x80:
            out.append(("ID3", "tag is unsynchronised; frames not decoded"))
            tag = b""
        pos = 0
        if flags & 0x40 and major >= 3 and len(tag) >= 4:      # extended header
            ext = _syncsafe(tag[:4]) if major == 4 else struct.unpack(">I", tag[:4])[0] + 4
            pos = ext
        idlen, hdr = (3, 6) if major == 2 else (4, 10)
        while pos + hdr <= len(tag) and len(out) < MAX_ID3_FRAMES:
            fid_raw = tag[pos:pos + idlen]
            if not fid_raw.strip(b"\x00") or not all(48 <= c <= 57 or 65 <= c <= 90 for c in fid_raw):
                break
            fid = fid_raw.decode("ascii")
            if major == 2:
                fsize = int.from_bytes(tag[pos + 3:pos + 6], "big")
                fflags = 0
            else:
                raw_size = tag[pos + 4:pos + 8]
                fsize = _syncsafe(raw_size) if major == 4 else struct.unpack(">I", raw_size)[0]
                fflags = int.from_bytes(tag[pos + 8:pos + 10], "big")
            body = tag[pos + hdr:pos + hdr + fsize]
            pos += hdr + fsize
            if fflags & (0x00C0 if major == 3 else 0x000E):   # compressed / encrypted / unsynchronised
                out.append((fid, f"frame flags {fflags:#06x}: compressed, encrypted or unsynchronised, not decoded"))
                continue
            got = _id3_frame(fid, body)
            if got:
                out.append(got)
    if len(data) >= 128 and data[-128:-125] == b"TAG":
        v1 = data[-128:]

        def field_(a, b):
            return v1[a:b].split(b"\x00")[0].decode("latin-1", "replace").strip()
        for name, a, b in (("v1.title", 3, 33), ("v1.artist", 33, 63), ("v1.album", 63, 93),
                           ("v1.year", 93, 97), ("v1.comment", 97, 127)):
            value = field_(a, b)
            if value:
                out.append((name, value))
    return out


SNDFILE_STRINGS = ("title", "copyright", "software", "artist", "comment", "date", "album", "license",
                   "tracknumber", "genre")


def sndfile_tags(data: bytes) -> list[tuple[str, str]]:
    """The metadata strings libsndfile reads (RIFF INFO, Vorbis comments, ID3 title/comment...)."""
    sf = _soundfile()
    try:
        with sf.SoundFile(io.BytesIO(bytes(data))) as f:
            return [(name, str(getattr(f, name))) for name in SNDFILE_STRINGS if getattr(f, name, "")]
    except Exception:  # an undecodable file has no strings; decode_pcm names the failure
        return []


def exif_text(data: bytes) -> list[tuple[str, str]]:
    """EXIF/TIFF text tags of an image (thumbnails and maker notes left out), the location and
    comment fields first. ToolMissing without exifread."""
    try:
        import exifread
    except ImportError as e:
        raise ToolMissing(f"exifread is not importable ({e}); requirements.in pins it") from None
    try:
        tags = exifread.process_file(io.BytesIO(bytes(data)), details=False, extract_thumbnail=False)
    except Exception:  # a malformed EXIF block is data, not a crash
        return []
    rows = []
    for name, value in tags.items():
        if any(s in name for s in _SKIP_EXIF):
            continue
        text = str(getattr(value, "printable", value)).strip()
        if text and text.isprintable():
            rows.append((name, text[:MAX_TAG_TEXT]))
    rows.sort(key=lambda r: (r[0] not in _EXIF_FIRST, _EXIF_FIRST.index(r[0]) if r[0] in _EXIF_FIRST else 0, r[0]))
    return rows[:MAX_EXIF_TAGS]


# ---- one drop ----------------------------------------------------------------------------------

@dataclass
class AudioReport:
    name: str
    kind: str
    pcm_line: str = ""
    tones: list[Tone] = field(default_factory=list)
    keyings: list[Keying] = field(default_factory=list)
    morse: MorseRead | None = None
    dtmf: str | None = None
    tags: list[tuple[str, str]] = field(default_factory=list)
    pictures: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)
    blocked: str = ""              # a missing tool or codec: named
    failed: str = ""               # the file is not decodable audio
    notes: list[str] = field(default_factory=list)


@dataclass
class ImageReport:
    name: str
    tags: list[tuple[str, str]] = field(default_factory=list)
    blocked: str = ""


@dataclass
class Opening:
    audio: list[AudioReport] = field(default_factory=list)
    images: list[ImageReport] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    flags: list[tuple[str, str, str]] = field(default_factory=list)    # (flag, file, where)


def open_audio(name: str, data: bytes, kind: str) -> AudioReport:
    rep = AudioReport(name, kind)
    if kind == "mp3":
        for frame, value in id3_tags(data):
            if isinstance(value, bytes):
                rep.tags.append((frame, f"{len(value)} bytes"))
                try:
                    rows = exif_text(value) if image_kind(value) else []
                except ToolMissing as e:
                    rep.notes.append(f"embedded picture EXIF not read: {e}")
                    rows = []
                if rows:
                    rep.pictures.append((frame, rows))
            else:
                rep.tags.append((frame, value[:MAX_TAG_TEXT]))
    try:
        seen = {v for _f, v in rep.tags}
        rep.tags += [(f"sndfile.{k}", v) for k, v in sndfile_tags(data) if v not in seen]
        pcm = decode_pcm(data, kind)
    except ToolMissing as e:
        rep.blocked = str(e)
        return rep
    except DecodeError as e:
        rep.failed = str(e)
        return rep
    rep.pcm_line = (f"{kind}, {pcm.source_rate} Hz, {pcm.channels} ch, {pcm.seconds:.1f} s"
                    + (f" ({pcm.note})" if pcm.note else ""))
    rep.tones = dominant_tones(pcm.samples, pcm.rate)
    for t in rep.tones:
        k = keying(pcm.samples, pcm.rate, t.hz)
        if k:
            rep.keyings.append(k)
    rep.morse = read_morse(pcm, rep.tones)
    rep.dtmf = read_dtmf(pcm)
    return rep


def _walk(paths) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_symlink():
            continue
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                here = Path(dirpath)
                dirnames[:] = sorted(d for d in dirnames if not (here / d).is_symlink())
                out += [here / n for n in sorted(filenames) if not (here / n).is_symlink() and (here / n).is_file()]
    return out


def _label(f: Path, roots: list[Path]) -> str:
    for r in roots:
        if r.is_dir():
            try:
                return f.relative_to(r).as_posix()
            except ValueError:
                pass
    return f.name


def open_paths(paths, ff) -> Opening:
    """Open every audio file (and the EXIF of every image) under the given files and folders."""
    roots = [Path(p) for p in paths]
    op = Opening()
    for f in _walk(paths):
        name = _label(f, roots)
        try:
            size = f.stat().st_size
            if size > MAX_FILE_BYTES:
                with open(f, "rb") as fh:
                    head = fh.read(16)
                if sniff(head) or image_kind(head):
                    op.skipped.append(f"{name}: {size} bytes is over the {MAX_FILE_BYTES} byte cap")
                continue
            data = f.read_bytes()
        except OSError as e:
            op.skipped.append(f"{name}: unreadable ({e.strerror or e})")
            continue
        kind = sniff(data)
        if kind:
            if len(op.audio) >= MAX_AUDIO_FILES:
                op.skipped.append(f"{name}: over the {MAX_AUDIO_FILES} audio file cap")
                continue
            op.audio.append(open_audio(name, data, kind))
        elif image_kind(data):
            if len(op.images) >= MAX_IMAGE_FILES:
                op.skipped.append(f"{name}: over the {MAX_IMAGE_FILES} image cap")
                continue
            img = ImageReport(name)
            try:
                img.tags = exif_text(data)
            except ToolMissing as e:
                img.blocked = str(e)
            op.images.append(img)
    seen = set()

    def note_flags(text: str, file: str, where: str):
        for flag in ff.find_flags(text):
            if flag not in seen:
                seen.add(flag)
                op.flags.append((flag, file, where))
    if ff.known:
        for a in op.audio:
            if a.morse:
                note_flags(a.morse.text, a.name, "morse")
            if a.dtmf:
                note_flags(a.dtmf, a.name, "dtmf")
            for k, v in a.tags:
                note_flags(v, a.name, f"tag {k}")
            for frame, rows in a.pictures:
                for k, v in rows:
                    note_flags(v, a.name, f"{frame} exif {k}")
        for img in op.images:
            for k, v in img.tags:
                note_flags(v, img.name, f"exif {k}")
    return op


def triage_text(op: Opening) -> str:
    lines = []
    for a in op.audio:
        if a.blocked:
            lines.append(f"audio {a.name}: {a.kind}: BLOCKED: {a.blocked}")
        elif a.failed:
            lines.append(f"audio {a.name}: {a.kind}: not decoded: {a.failed}")
        else:
            lines.append(f"audio {a.name}: {a.pcm_line}")
        for k, v in a.tags:
            lines.append(f"  tag {k} = {v}")
        for frame, rows in a.pictures:
            for k, v in rows:
                lines.append(f"  {frame} exif {k} = {v}")
        for n in a.notes:
            lines.append(f"  note: {n}")
        if a.blocked or a.failed:
            continue
        if a.tones:
            lines.append("  tones: " + ", ".join(f"{t.hz:.1f} Hz (x{t.prominence:.3g} over the floor)" for t in a.tones))
        else:
            lines.append("  tones: no narrow tone stands out")
        for k in a.keyings:
            lines.append(f"  {k.summary()}")
        if a.morse:
            where = f"{a.morse.tone_hz:.1f} Hz" if a.morse.tone_hz else "broadband"
            lines.append(f"  morse ({where}, 1/3/7 lattice, unit ~{a.morse.unit_ms:.0f} ms): {a.morse.text}")
        else:
            lines.append("  morse: no reading fits the 1/3/7 lattice")
        lines.append(f"  dtmf: {a.dtmf}" if a.dtmf else "  dtmf: none")
    for img in op.images:
        if img.blocked:
            lines.append(f"exif {img.name}: BLOCKED: {img.blocked}")
        for k, v in img.tags:
            lines.append(f"exif {img.name}: {k} = {v}")
    for s in op.skipped:
        lines.append(f"skipped {s}")
    for flag, file, where in op.flags:
        lines.append(f"FLAG {flag}  ({file}, {where})")
    return "\n".join(lines)


def result_of(op: Opening) -> SolverResult:
    decoded = [a for a in op.audio if not (a.blocked or a.failed)]
    blocked = [a for a in op.audio if a.blocked]
    texts = [(a, "morse", a.morse.text) for a in decoded if a.morse] + [(a, "dtmf", a.dtmf) for a in decoded if a.dtmf]
    notes = [f"{a.name}: {how}: {t[:MAX_TAG_TEXT]}" for a, how, t in texts]
    notes += [f"{a.name}: not decoded ({a.blocked})" for a in blocked]
    notes += [f"{img.name}: {k} = {v}" for img in op.images for k, v in img.tags if k in _EXIF_FIRST]
    evidence = [Evidence("decode", f"{how}: {t[:200]}", path=a.name) for a, how, t in texts]
    if op.flags:
        evidence += [Evidence("decode" if where in ("morse", "dtmf") else "metadata", f"{flag} in {where}", path=file)
                     for flag, file, where in op.flags]
        return SolverResult("candidate", flags=[f for f, _, _ in op.flags], evidence=evidence, engine=ENGINE,
                            notes="; ".join(notes))
    if texts:
        return SolverResult("unsure", evidence=evidence, engine=ENGINE,
                            notes="decoded text needs a read: " + "; ".join(notes))
    if blocked and not decoded:
        return SolverResult("blocked", engine=ENGINE, notes="; ".join(notes))
    if not op.audio:
        return SolverResult("none", engine=ENGINE, notes="no audio file (WAV, MP3, FLAC, Ogg, AIFF) found")
    return SolverResult("none", engine=ENGINE, notes="; ".join(notes) or "no Morse, DTMF or flag in the audio")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="audio_opener.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", help="audio files, or folders to walk")
    ap.add_argument("--event", help="event slug (default: CTF_EVENT, or the only profile)")
    a = ap.parse_args(argv)
    missing = [p for p in a.paths if not Path(p).exists()]
    if missing:
        print(f"audio_opener.py: no such file or folder: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        profile = _event.load(a.event) if a.event else _event.current()
    except _event.EventError as e:
        print(SolverResult("blocked", engine=ENGINE, notes=f"no event profile: {e}").to_json())
        return 0
    op = open_paths(a.paths, _flagfmt.for_profile(profile))
    text = triage_text(op)
    if text:
        print(text)
    print(result_of(op).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
