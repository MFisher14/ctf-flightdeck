#!/usr/bin/env python3
"""Toolkit `audio_speech` (B-087): a recording that SAYS the answer, read to text by a local Whisper model and swept for the flag.

The other audio engines read what is drawn or keyed into the sound (spectrogram text, tone ladders,
DTMF, sample bits). None of them hears a voice. At PINK+ 2026 the last step of a challenge was a
recording that spelled the flag aloud, and it was transcribed by hand. This is that step with no model
in the loop but the local speech-to-text one:

  1. find     every audio file of the delivery (magic first, then the extension)
  2. decode   to 16 kHz mono float samples: libsndfile in-process (WAV, FLAC, Ogg, MP3, AIFF, ...);
              what it cannot open goes to ffmpeg in the Docker sandbox (stego_tools.to_wav). An Ogg
              stream that starts with pages carrying no codec header has them dropped first.
  3. gate     how the sound reads: `silent`, `tones` (pure tones, single or dual: keyed data, not a
              voice), `other` (speech, music, noise) or `mixed` (both). Tones are not sent to the
              model, and a delivery of tones alone never reports a missing Whisper.
  4a. tones   (and mixed, silent) the carried readers: audio_tones.decode (tone ladders, plain and
              two-stream XOR) and audio_stego.analyze (DTMF forward, reversed, in the stereo
              difference, at half speed).
  4b. other   (and mixed) transcribed by a LOCAL Whisper: whisper.cpp's `whisper-cli` with a ggml model, or the
              `faster_whisper` module with a CTranslate2 model folder. The model sits at a configured
              path outside the repo (assets `whisper-ggml` / `whisper-ct2` in tools/assets.toml, or
              model=PATH). Nothing is ever downloaded. When the plain recording yields no flag, the
              stereo difference and the reversed recording are heard too (budget permitting).
  5. sweep    every text read goes to the flag search: as transcribed; with spoken spelling written
              out (`spoken_forms`: "capital Q seven comma m four z underscore" is `Q7,m4z_`, "open
              curly brace" is the brace, a spelled or spoken prefix is rewritten to the event's
              spelling); and through the shared codec graph (ctf.codec), so digits or letters read
              aloud that spell hex, base64 or a decimal list are decoded.

Status. Speech-to-text and tone readers are lossy (letter case, 0/O, 1/l), so a flag is always
`candidate`, never `solved`. Speech with no flag in it is `unsure`: the transcripts are written to
<out>/ for a human or model read. Speech that could not be transcribed because no backend or model is
installed is `blocked`, naming every missing tool and model and how to provide it. Nothing is
submitted, and no challenge program is run: the only programs started are whisper-cli (on a WAV this
module wrote) and, through the sandbox, ffmpeg.

  solve(challenge_dir, profile, **opts) -> SolverResult     the engine contract (python -m ctf run)
  examine(files, profile, ...) -> Report                    the same over {name: bytes}
  audio_kind(name, data) -> str | None                      which audio container, or None
  strip_leading_ogg_pages(data) -> (bytes, dropped)         leading Ogg pages with no codec header
  decode(name, data, to_wav=None, deadline=None) -> Audio   16 kHz mono samples (+ stereo difference), read
                                                            block by block: memory bounded at any rate/channels
  delivery_audio(dir_or_file) -> Delivery                   the audio files, each read only when examined
  gate(samples) -> Gate                                     silent | tones | mixed | other
  spoken_forms(text, prefixes=()) -> [(label, text)]        spoken spelling written out
  text_flags(text, profile, deadline, ...) -> [(flag, how)] the flag sweep of one reading
  find_backend(want, model, ...) -> (transcriber | None, [why not])
  WhisperCli(binary, model) / FasterWhisper(model)          transcriber(samples, language, deadline, prompt) -> str

  python -m ctf run toolkits.audio_speech DIR_OR_FILE [--opt backend=auto|whisper-cli|faster-whisper]
        [--opt model=PATH] [--opt language=en|auto|..] [--opt variants=original,stereo_difference,reversed]
        [--opt speech=auto|on|off] [--opt seconds=S] [--opt out=DIR] [--opt prompt=TEXT] [--opt threads=N]
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from fractions import Fraction
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

import numpy as np                  # noqa: E402
import soundfile as sf              # noqa: E402

ENGINE = "toolkits.audio_speech"
REPORT_NAME = "report.json"
REPORT_SCHEMA = 1
RATE = 16000                          # what Whisper hears
DEFAULT_SECONDS = 240.0               # under the manifest's intake timeout (300 s)
MAX_AUDIO_SECONDS = 1800.0            # this much of one recording is decoded; the cut is named
DECODE_BLOCK = 1 << 20                # samples (all channels together) read from libsndfile at a time
MAX_RATE = 768000                     # a header that declares a faster sample rate is refused (the resampling
                                      # filter's length follows the rate: 100 MHz would be a 15 GiB filter)
RATIO_DENOMINATOR = 1000              # the resampling ratio's denominator at most (every common rate is exact)
MAX_FILES = 16                        # audio files examined in one delivery
HEAD = 16                             # bytes read to tell a container by its magic
# ---- gate ----
GATE_N, GATE_HOP = 1024, 256          # 64 ms frames at 16 kHz, every 16 ms
GATE_SECONDS = 120.0                  # the gate judges this much of a recording at most ...
GATE_WINDOW = 10.0                    # ... a longer one in windows this long, spread evenly from start to end
GATE_SOUNDING = 0.10                  # a frame sounds when its RMS is this share of the loudest frame's
GATE_NUCLEUS, GATE_SPAN = 0.90, 3     # ... and is judged when it is this near the loudest of the 3 frames each side
GATE_PEAK_DB = 25.0                   # a spectral peak counts within this many dB of the frame's strongest
GATE_PEAK_APART = 4                   # ... and when no stronger bin is within this many bins (a Hann lobe)
SILENT_PEAK = 1e-3                    # a recording whose loudest sample is under this is silent
TONE_FRAMES = 0.95                    # share of judged frames with at most two peaks from which it is tones
VOICE_FRAMES = 0.40                   # ... and under which it is `other`; between the two it is `mixed`
DIFF_MIN = 0.05                       # the stereo difference is heard when its RMS is this share of the mix's
# ---- non-speech readers ----
STEGO_MAX_BYTES = 4 << 20             # audio_stego is pure Python: larger WAV/AIFF files are not given to it
TONES_MAX_BYTES = 256 << 20           # audio_tones reads all channels as float64: past this it gets the 16 kHz mono decode
# ---- text ----
MAX_TEXT = 20000                      # characters of one reading kept
EVIDENCE_TEXT = 300                   # characters of a reading quoted in the result's evidence
SPELL_MIN = 4                         # spellable tokens in a row from which they are read as spelling
GRAPH_SECONDS = 1.0                   # the codec graph's budget for one text
GRAPH_MIN = 8                         # a glued run at least this long is decoded on its own
GRAPH_BLOBS = 8                       # at most this many texts of one reading go to the codec graph

BACKENDS = ("whisper-cli", "faster-whisper")
VARIANTS = ("original", "stereo_difference", "reversed")
SPEECH = ("auto", "on", "off")
SILENT, TONES, MIXED, OTHER = "silent", "tones", "mixed", "other"
READ, NOT_DECODED, NOT_TRANSCRIBED = "read", "not-decoded", "not-transcribed"
OUT_OF_TIME = "out of time"
SPEECH_OFF = "speech=off"

# Ogg: what the first packet of a stream a decoder knows starts with.
OGG_CODECS = (b"\x01vorbis", b"OpusHead", b"\x7fFLAC", b"Speex   ", b"\x80theora", b"fishead\x00",
              b"BBCD\x00", b"\x80kate\x00", b"PCM     ", b"CELT    ")
OGG_SCAN_PAGES = 4                    # leading pages looked at for a codec header

AUDIO_EXT = (".wav", ".wave", ".flac", ".ogg", ".oga", ".opus", ".mp3", ".aif", ".aiff", ".aifc", ".au",
             ".snd", ".caf", ".m4a", ".m4b", ".aac", ".wma", ".amr", ".3gp", ".mka", ".weba", ".spx")


class DecodeError(Exception):
    """The recording could not be decoded to samples; the message says why."""


class TranscribeError(Exception):
    """The transcriber did not give a transcript; the message says why."""


class TranscribeCut(TranscribeError):
    """The transcriber was stopped at the budget; `.text` is what it had heard by then."""

    def __init__(self, text: str, why: str):
        super().__init__(why)
        self.text = text


class OptionError(ValueError):
    """A bad engine option; the message names it."""


# =========================================================================== finding and decoding

def audio_kind(name: str, data: bytes) -> str | None:
    """The audio container of a file by its first bytes, else by its extension; None when neither says
    audio. `data` may be just the head (HEAD bytes are enough)."""
    d = bytes(data[:HEAD])
    if d[:4] == b"RIFF" and d[8:12] == b"WAVE":
        return "wav"
    if d[:4] == b"RF64":
        return "wav"
    if d[:4] == b"FORM" and d[8:12] in (b"AIFF", b"AIFC"):
        return "aiff"
    if d[:4] == b"OggS":
        return "ogg"
    if d[:4] == b"fLaC":
        return "flac"
    if d[:3] == b"ID3":
        return "mp3"
    if d[:4] == b".snd":
        return "au"
    if d[:4] == b"caff":
        return "caf"
    if d[:6] == b"#!AMR\n":
        return "amr"
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name.replace("\\", "/").rsplit("/", 1)[-1] else ""
    if ext in AUDIO_EXT:
        return ext[1:]
    return None


def _ogg_page(data: bytes, off: int):
    """(page length, body) of the Ogg page at `off`, or None when there is no whole page there."""
    if data[off:off + 4] != b"OggS" or off + 27 > len(data):
        return None
    nseg = data[off + 26]
    table = data[off + 27:off + 27 + nseg]
    if len(table) != nseg:
        return None
    size = 27 + nseg + sum(table)
    if off + size > len(data):
        return None
    return size, data[off + 27 + nseg:off + size]


def strip_leading_ogg_pages(data: bytes) -> tuple[bytes, int]:
    """An Ogg file whose first page(s) carry something other than a codec header (an application's own
    header page in front of an ordinary Vorbis or Opus stream) with those pages dropped, and how many
    were dropped. Unchanged (0) when the first page is a codec header, when no codec header follows
    within OGG_SCAN_PAGES pages, or when the bytes are not Ogg: nothing is cut on a guess."""
    off, dropped = 0, 0
    while dropped <= OGG_SCAN_PAGES:
        page = _ogg_page(data, off)
        if page is None:
            return data, 0
        size, body = page
        if any(body.startswith(c) for c in OGG_CODECS):
            return (data[off:], dropped) if dropped else (data, 0)
        off += size
        dropped += 1
    return data, 0


@dataclass
class Audio:
    samples: np.ndarray                 # mono float32 at RATE
    seconds: float
    rate_in: int
    channels: int
    how: str                            # "libsndfile" | "ffmpeg in the sandbox"
    difference: np.ndarray | None = None    # channel 0 minus channel 1 at RATE, when they differ
    source: bytes = b""                 # bytes libsndfile reads (the file, or its transcoded WAV)
    notes: list = field(default_factory=list)
    frames_total: int = 0               # frames the file says it holds (what a reader of all of it reads)
    out_of_time: bool = False           # the decode was stopped at the deadline


class _Resampler:
    """scipy's resample_poly(x, up, down) to RATE, fed block by block, so memory is one block and a
    filter's reach whatever the length, rate or channel count of the input. It gives the one-shot
    call's samples (to float rounding): each block is filtered with `pad` input samples of context
    on both sides, and `pad` and every block are multiples of `down`, so the block's output lies on
    the one-shot call's output grid. resample_poly's filter has 20 * max(up, down) + 1 taps, so the
    ratio RATE/rate is taken to the nearest fraction with a denominator of at most RATIO_DENOMINATOR:
    exact for every common rate (44.1 kHz is 160/441), and for an odd rate the filter stays under
    20 * max(RATE, RATIO_DENOMINATOR) taps instead of 20 * rate. `exact` says which it was."""

    def __init__(self, rate: int):
        ratio = Fraction(RATE, rate).limit_denominator(RATIO_DENOMINATOR)
        self.up, self.down = ratio.numerator, ratio.denominator
        self.exact = ratio == Fraction(RATE, rate)
        reach = -(-10 * max(self.up, self.down) // self.up) + 2     # resample_poly's half filter, in input samples
        self.pad = -(-reach // self.down) * self.down
        self.buf = np.zeros(0, dtype=np.float64)
        self.hist = 0               # samples at the start of buf already given out (the left context)

    def _out(self, seg, n_in: int) -> np.ndarray:
        from scipy.signal import resample_poly
        y = resample_poly(seg, self.up, self.down)
        lo = self.hist * self.up // self.down
        return y[lo:lo + -(-n_in * self.up // self.down)].astype(np.float32)

    def feed(self, x) -> np.ndarray:
        if self.up == self.down:
            return np.asarray(x, dtype=np.float32)
        self.buf = np.concatenate([self.buf, np.asarray(x, dtype=np.float64)])
        n = (len(self.buf) - self.hist - self.pad) // self.down * self.down      # samples with their right context
        if n <= 0:
            return np.zeros(0, dtype=np.float32)
        out = self._out(self.buf[:self.hist + n + self.pad], n)
        keep = min(self.pad, self.hist + n)
        self.buf, self.hist = self.buf[self.hist + n - keep:], keep
        return out

    def end(self) -> np.ndarray:
        rest = len(self.buf) - self.hist
        if self.up == self.down or rest <= 0:
            return np.zeros(0, dtype=np.float32)
        out = self._out(self.buf, rest)
        self.buf, self.hist = np.zeros(0, dtype=np.float64), 0
        return out


def _read_pcm(data: bytes, deadline: float | None = None) -> dict:
    """The recording through libsndfile at RATE: {mono, difference (channel 0 minus 1, or None),
    rate, channels, frames_total, cut (why not all of it was read, or ''), out_of_time}. It is read
    DECODE_BLOCK samples at a time, each block mixed down and resampled before the next is read, and
    at most MAX_AUDIO_SECONDS of it: memory is bounded by that many seconds at RATE, never by the
    file's own rate and channel count (a small file of many silent high-rate channels decompresses
    to gigabytes). A rate over MAX_RATE is refused. A deadline (time.monotonic) stops it after the
    block that reaches it."""
    try:
        with sf.SoundFile(io.BytesIO(data)) as f:
            rate, channels = int(f.samplerate), int(f.channels)
            if rate <= 0:
                raise DecodeError("libsndfile reports no sample rate")
            if rate > MAX_RATE:
                raise DecodeError(f"the header declares {rate} Hz, over the {MAX_RATE} Hz this lane resamples")
            if channels <= 0:
                raise DecodeError("libsndfile reports no channels")
            limit = int(MAX_AUDIO_SECONDS * rate)
            block = max(1, DECODE_BLOCK // channels)
            mix, dif = _Resampler(rate), (_Resampler(rate) if channels >= 2 else None)
            mono, diff, got, cut, late = [], [], 0, "", False
            while got < limit:
                x = f.read(frames=min(block, limit - got), dtype="float32", always_2d=True)
                if x.shape[0] == 0:
                    break
                got += x.shape[0]
                x = np.nan_to_num(x, copy=False)
                mono.append(mix.feed(x.mean(axis=1)))
                if dif is not None:
                    diff.append(dif.feed(x[:, 0] - x[:, 1]))
                if deadline is not None and time.monotonic() >= deadline and got < limit:
                    if f.read(frames=1, dtype="float32", always_2d=True).shape[0]:
                        cut, late = f"decoding stopped at the budget after {got / rate:g} s ({OUT_OF_TIME})", True
                    break
            if got >= limit and f.read(frames=1, dtype="float32", always_2d=True).shape[0]:
                cut = f"only the first {MAX_AUDIO_SECONDS:g} s were decoded"
            frames_total = max(int(f.frames), got)
        if got == 0:
            raise DecodeError("it holds no samples")
        mono.append(mix.end())
        if dif is not None:
            diff.append(dif.end())
    except DecodeError:
        raise
    except Exception as e:                 # LibsndfileError and whatever a damaged file raises
        raise DecodeError(f"libsndfile does not read it ({str(e).strip() or type(e).__name__})") from None
    ratio = "" if mix.exact else f"resampled from {rate} Hz at the nearest ratio {mix.up}/{mix.down}"
    return {"mono": np.concatenate(mono), "difference": np.concatenate(diff) if dif is not None else None,
            "rate": rate, "channels": channels, "frames_total": frames_total, "cut": cut, "out_of_time": late,
            "ratio": ratio}


def _sandbox_to_wav(data: bytes, name: str) -> bytes:
    """Any media as 16 kHz stereo PCM WAV through ffmpeg in the Docker sandbox (stego_tools.to_wav).
    DecodeError naming why when the sandbox is down or ffmpeg refuses the file."""
    import stego_tools
    rec = stego_tools.to_wav(data, rate=RATE, channels=2, name=name.replace("\\", "/").rsplit("/", 1)[-1])
    if not rec.ok or not rec.data:
        raise DecodeError(f"ffmpeg in the sandbox: {rec.note or 'no WAV came back'}")
    return rec.data


def decode(name: str, data: bytes, to_wav=None, deadline: float | None = None) -> Audio:
    """The recording as mono float32 samples at 16 kHz. libsndfile first; a file it does not open goes
    to `to_wav(data, name) -> WAV bytes` (default: ffmpeg in the sandbox). DecodeError names both
    refusals when neither reads it. The deadline (time.monotonic) cuts a long decode short; the cut
    is a note and `out_of_time`."""
    notes = []
    data, dropped = strip_leading_ogg_pages(data)
    if dropped:
        notes.append(f"dropped {dropped} leading Ogg page(s) that carry no codec header")
    how, source = "libsndfile", data
    try:
        pcm = _read_pcm(data, deadline)
    except DecodeError as first:
        try:
            source = (to_wav or _sandbox_to_wav)(data, name)
            pcm = _read_pcm(source, deadline)
        except DecodeError as second:
            raise DecodeError(f"{first}; {second}") from None
        how = "ffmpeg in the sandbox"
    notes += [n for n in (pcm["ratio"], pcm["cut"]) if n]
    mono, d = pcm["mono"], pcm["difference"]
    difference = None
    if d is not None:
        level = float(np.sqrt(np.mean(mono.astype(np.float64) ** 2)))
        dlevel = float(np.sqrt(np.mean(d.astype(np.float64) ** 2)))
        if dlevel > SILENT_PEAK and dlevel > DIFF_MIN * level:
            difference = d
    return Audio(samples=mono, seconds=len(mono) / RATE, rate_in=pcm["rate"], channels=pcm["channels"], how=how,
                 difference=difference, source=source, notes=notes, frames_total=pcm["frames_total"],
                 out_of_time=pcm["out_of_time"])


def pcm16_wav(samples: np.ndarray, rate: int = RATE) -> bytes:
    """Mono float samples as a 16-bit PCM WAV (what whisper-cli takes)."""
    pcm = (np.clip(np.asarray(samples, dtype=np.float64), -1.0, 1.0) * 32767.0).astype("<i2").tobytes()
    head = struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36 + len(pcm), b"WAVE", b"fmt ", 16, 1, 1, rate,
                       rate * 2, 2, 16, b"data", len(pcm))
    return head + pcm


# =========================================================================== the gate

@dataclass
class Gate:
    kind: str                # SILENT | TONES | MIXED | OTHER
    seconds: float
    few: float = 0.0         # share of the judged frames with at most two spectral peaks
    peaks: float = 0.0       # median number of spectral peaks in a judged frame
    frames: int = 0          # frames judged

    def to_dict(self) -> dict:
        return {"kind": self.kind, "seconds": round(self.seconds, 3), "few": round(self.few, 4),
                "peaks": self.peaks, "frames": self.frames}


def gate(samples: np.ndarray) -> Gate:
    """How a 16 kHz recording reads. A tone is one spectral peak and a dual tone (DTMF) two; a voice
    is a pitch with its harmonics, many peaks, however steady or synthetic the voice. Each frame at
    an energy nucleus (the loudest stretch of its neighbourhood: the middle of a tone burst, the core
    of a syllable; frames across an on/off edge are left out) has its peaks counted, the ones within
    GATE_PEAK_DB of its strongest. `tones` when nearly every judged frame has at most two, `other`
    when few do, `mixed` in between (a voice after a run of key tones): mixed is both read as tones
    and heard, so a short spoken part is not lost to a long tonal one. A recording over GATE_SECONDS
    is judged on GATE_WINDOW-long windows spread over its whole length."""
    from scipy.ndimage import maximum_filter1d
    x = np.asarray(samples, dtype=np.float64)
    seconds = len(samples) / RATE
    if len(x) > int(GATE_SECONDS * RATE):          # a long recording: windows from all of it, not its start
        win = int(GATE_WINDOW * RATE)
        starts = np.linspace(0, len(x) - win, max(1, int(GATE_SECONDS / GATE_WINDOW))).astype(int)
        x = np.concatenate([x[s:s + win] for s in starts])
    if len(x) < GATE_N or float(np.max(np.abs(x))) < SILENT_PEAK:
        return Gate(SILENT, seconds)
    frames = np.lib.stride_tricks.sliding_window_view(x, GATE_N)[::GATE_HOP]
    rms = np.sqrt((frames ** 2).mean(axis=1))
    nucleus = rms >= GATE_NUCLEUS * maximum_filter1d(rms, size=2 * GATE_SPAN + 1, mode="nearest")
    keep = (rms > GATE_SOUNDING * rms.max()) & nucleus
    power = np.abs(np.fft.rfft(frames[keep] * np.hanning(GATE_N), axis=1)) ** 2
    top = power.max(axis=1)
    power, top = power[top > 0], top[top > 0]
    if len(top) == 0:
        return Gate(SILENT, seconds)
    lobe = maximum_filter1d(power, size=2 * GATE_PEAK_APART + 1, axis=1, mode="constant")
    counts = ((power == lobe) & (power >= top[:, None] * 10 ** (-GATE_PEAK_DB / 10))).sum(axis=1)
    few = float((counts <= 2).mean())
    kind = TONES if few >= TONE_FRAMES else OTHER if few < VOICE_FRAMES else MIXED
    return Gate(kind, seconds, few, float(np.median(counts)), int(len(counts)))


# =========================================================================== spoken spelling

_PROSODIC = ",.;:!?\"'()…"        # punctuation a transcriber adds around words
_UPPER = {"capital", "uppercase", "upper", "big", "cap"}
_LOWER = {"lowercase", "lower", "small", "little"}
_DIGIT_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
                "seven": "7", "eight": "8", "nine": "9"}
_NATO = {"alpha": "a", "alfa": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e", "foxtrot": "f",
         "golf": "g", "hotel": "h", "india": "i", "juliet": "j", "juliett": "j", "kilo": "k", "lima": "l",
         "mike": "m", "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r", "sierra": "s",
         "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w", "whisky": "w", "xray": "x",
         "yankee": "y", "zulu": "z"}
_OPENERS = ("open", "opening", "opened", "left", "start", "begin")
_CLOSERS = ("close", "closing", "closed", "right", "end")
_BARE_BRACE = (("curly", "brace"), ("curly", "bracket"), ("brace",))     # no open/close said: they alternate


def _phrase_table() -> dict:
    """{words: (character, always)}. `always` phrases are written out wherever they are said; the
    others are everyday words (dash, dot, at, one) and count only inside spelling: a run of SPELL_MIN
    spellable tokens, or between the braces."""
    t: dict = {}

    def add(ch, always, *forms):
        for f in forms:
            t[tuple(f.split())] = (ch, always)

    for words, pair in ((_OPENERS, "{([<"), (_CLOSERS, "})]>")):
        for w in words:
            add(pair[0], True, *(f"{w} {n}" for n in ("curly brace", "curly bracket", "curly braces",
                                                    "curly brackets", "curly", "brace", "braces", "bracket")))
            add(pair[1], True, f"{w} paren", f"{w} parenthesis", f"{w} parentheses", f"{w} round bracket")
            add(pair[2], True, f"{w} square bracket")
            add(pair[3], True, f"{w} angle bracket")
    add("_", True, "underscore", "under score", "underline", "underbar")
    add("?", True, "question mark")
    add("!", True, "exclamation mark", "exclamation point")
    add("@", True, "at sign", "at symbol")
    add("#", True, "hashtag", "hash sign", "pound sign", "number sign")
    add("$", True, "dollar sign")
    add("%", True, "percent sign")
    add("&", True, "ampersand", "and sign")
    add("+", True, "plus sign")
    add("=", True, "equals sign", "equal sign")
    add("/", True, "forward slash")
    add("\\", True, "backslash", "back slash")
    add(";", True, "semicolon", "semi colon")
    add("'", True, "apostrophe", "single quote")
    add('"', True, "double quote", "quotation mark")
    add("~", True, "tilde")
    add("|", True, "vertical bar")
    add("*", True, "asterisk")
    add("^", True, "caret")
    add(".", True, "full stop")
    add("-", False, "dash", "hyphen", "minus")
    add(",", False, "comma")
    add(".", False, "dot", "period", "point")
    add("@", False, "at")
    add("#", False, "hash", "pound")
    add("$", False, "dollar")
    add("%", False, "percent")
    add("*", False, "star")
    add("+", False, "plus")
    add("=", False, "equals")
    add("/", False, "slash")
    add(":", False, "colon")
    add('"', False, "quote")
    add("|", False, "pipe")
    add("<", False, "less than")
    add(">", False, "greater than")
    add(" ", False, "space")
    return t


_PHRASES = _phrase_table()
_PHRASE_MAX = max(len(k) for k in _PHRASES)
_HYPHEN_SPELLED = re.compile(r"[A-Za-z0-9](?:-[A-Za-z0-9])+")      # P-I-N-K: letters said one by one


@dataclass
class _Item:
    kind: str            # letter | digit | sym | word | sep
    value: str           # what it is written as when read as spelling
    raw: str             # what the transcriber wrote
    always: bool = False     # written out wherever it stands (unambiguous symbol phrases, literal braces)
    explicit: bool = False   # a letter whose case was said ("capital S")


def _tokens(text: str) -> list:
    """[(kind, text)]: word | sep (punctuation the transcriber put around a word) | brace (a literal one)."""
    out = []
    for raw in text.split():
        buf = ""
        parts = []
        for ch in raw:                          # literal braces stand alone
            if ch in "{}":
                if buf:
                    parts.append(buf)
                parts.append(ch)
                buf = ""
            else:
                buf += ch
        if buf:
            parts.append(buf)
        for part in parts:
            if part in ("{", "}"):
                out.append(("brace", part))
                continue
            core = part.strip(_PROSODIC)
            lead = part[:len(part) - len(part.lstrip(_PROSODIC))]
            tail = part[len(part.rstrip(_PROSODIC)):] if core else ""
            out += [("sep", c) for c in lead]
            if core:
                if _HYPHEN_SPELLED.fullmatch(core):
                    out += [("word", c) for c in core.split("-")]
                else:
                    out.append(("word", core))
            out += [("sep", c) for c in tail]
    return out


def _items(tokens: list) -> list:
    """Tokens as items: phrases that name a symbol, said case, letters, digits; everything else a word."""
    out, i, n = [], 0, len(tokens)

    def words_at(j, k):
        got = tokens[j:j + k]
        return tuple(t[1].lower() for t in got) if len(got) == k and all(t[0] == "word" for t in got) else None

    while i < n:
        kind, text = tokens[i]
        if kind == "sep":
            out.append(_Item("sep", text, text))
            i += 1
            continue
        if kind == "brace":
            out.append(_Item("sym", text, text, always=True))
            i += 1
            continue
        low = text.lower()
        for k in range(min(_PHRASE_MAX, n - i), 0, -1):          # the longest phrase that names a symbol
            ws = words_at(i, k)
            if ws in _PHRASES:
                ch, always = _PHRASES[ws]
                out.append(_Item("sym", ch, " ".join(t[1] for t in tokens[i:i + k]), always=always))
                i += k
                break
            if ws in _BARE_BRACE:
                out.append(_Item("sym", "{}", " ".join(t[1] for t in tokens[i:i + k]), always=True))
                i += k
                break
        else:
            if low in _UPPER or low in _LOWER:                   # "capital S", "lower case b", "capital sierra"
                j = i + 1
                if words_at(j, 1) == ("case",):
                    j += 1
                nxt = words_at(j, 1)
                letter = None
                if nxt and len(nxt[0]) == 1 and nxt[0].isalpha() and nxt[0].isascii():
                    letter = nxt[0]
                elif nxt and nxt[0] in _NATO:
                    letter = _NATO[nxt[0]]
                if letter:
                    value = letter.upper() if low in _UPPER else letter.lower()
                    out.append(_Item("letter", value, " ".join(t[1] for t in tokens[i:j + 1]), explicit=True))
                    i = j + 1
                    continue
            if len(text) == 1 and text.isalpha() and text.isascii():
                out.append(_Item("letter", text, text))
            elif text.isdigit() and text.isascii():
                out.append(_Item("digit", text, text))
            elif low in _DIGIT_WORDS:
                out.append(_Item("digit", _DIGIT_WORDS[low], text))
            elif low in _NATO:
                out.append(_Item("letter", _NATO[low], text))
            else:
                out.append(_Item("word", text, text))
            i += 1
    return out


def _canonical_prefixes(text: str, prefixes) -> str:
    """Each event prefix standing right before an opening brace, in the event's own spelling (a spoken
    or spelled prefix has no reliable case). No other character changes. Longer prefixes first, and a
    prefix that ends a longer one already rewritten there is left alone (prefixes CTF and ACTF:
    `actf{` is `ACTF{`, never `ActF{`)."""
    low = text.lower()
    chars = list(text)
    taken: set = set()                     # positions already rewritten
    for p in sorted(prefixes, key=len, reverse=True):
        lead = p.lower() + "{"
        at = low.find(lead)
        while at != -1:
            span = range(at, at + len(p))
            if not taken.intersection(span):
                chars[at:at + len(p)] = p
                taken.update(span)
            at = low.find(lead, at + 1)
    return "".join(chars)


def _assemble(items: list, literal: bool) -> tuple[str, bool, bool]:
    """(the items written out, whether anything was read as spelling, whether a character was SAID: a
    symbol or digit by its name, a letter by its case or NATO word; braces aside). Spelling counts in
    a run of SPELL_MIN spellable items (separators aside) and between braces; there letters, digits
    and symbols are glued. A symbol glues to its neighbours, a word outside the braces keeps its
    spaces. literal=True keeps the transcriber's own punctuation between the braces as characters (a
    spoken comma written as ','); else it is dropped as prosody."""
    spell = [it.kind in ("letter", "digit", "sym") for it in items]
    in_run = [False] * len(items)
    i = 0
    while i < len(items):
        if not spell[i]:
            i += 1
            continue
        j, members = i, []
        while j < len(items) and (spell[j] or items[j].kind == "sep"):
            if spell[j]:
                members.append(j)
            j += 1
        if len(members) >= SPELL_MIN:
            for m in members:
                in_run[m] = True
        i = j
    case_said = any(it.explicit for it in items)
    pieces, depth, spelled, said = [], 0, False, False  # (text, glue left, glue right): 0 none, 1 soft, 2 hard
    for idx, it in enumerate(items):
        inside = depth > 0
        if it.kind == "sep":
            if inside and literal:
                pieces.append((it.value, 2, 2))
            continue
        if it.kind == "sym" and (it.always or in_run[idx] or inside):
            ch, spelled = it.value, True
            if ch == "{}":                              # a brace said with no open/close: they alternate
                ch = "}" if inside else "{"
            if ch == "{":
                depth += 1
                pieces.append((ch, 2, 2))
            elif ch == "}":
                depth = max(0, depth - 1)
                pieces.append((ch, 2, 2 if depth else 0))
            else:
                said = said or it.raw != ch
                pieces.append((ch, 2, 2))
            continue
        if it.kind in ("letter", "digit") and (in_run[idx] or inside):
            value = it.value
            if it.kind == "letter" and not it.explicit:
                value = value.lower() if case_said or it.raw.lower() in _NATO else it.raw
            glue, spelled = (2 if inside else 1), True
            said = said or it.explicit or it.raw.lower() in _NATO or (it.kind == "digit" and it.raw != it.value)
            pieces.append((value, glue, glue))
            continue
        pieces.append((it.raw, 2, 2) if inside else (it.raw, 0, 0))
    out = []
    for n, (text, left, _right) in enumerate(pieces):
        if n:
            prev_right = pieces[n - 1][2]
            if not (prev_right == 2 or left == 2 or (prev_right >= 1 and left >= 1)):
                out.append(" ")
        out.append(text)
    return "".join(out), spelled, said


def spoken_forms(text: str, prefixes=()) -> list:
    """The transcript with spoken spelling written out: [(label, text)], at most two readings.

    `spelled`: symbol names become the symbols, digit words digits, letters said one by one (or in the
    NATO alphabet) are glued, said case is applied ("capital S"; once any case is said, unmarked
    letters are lower-case), everything between the braces is glued, and an event prefix before the
    brace is put in the event's spelling. Punctuation the transcriber added between tokens is dropped.
    `spelled, punctuation kept`: the same, but between the braces that punctuation is kept as
    characters, for a transcriber that wrote a spoken comma or question mark as the sign itself. It
    is given only when no character was said by name: once the speaker says "comma", the commas the
    transcriber wrote are prosody.
    A transcript in which nothing is spelled has no forms; a form equal to the one before it is left out."""
    items = _items(_tokens(text[:MAX_TEXT]))
    out, seen = [], {" ".join(text.split())}
    for label, literal in (("spelled", False), ("spelled, punctuation kept", True)):
        form, spelled, said = _assemble(items, literal)
        if not spelled or (literal and said):
            continue
        form = _canonical_prefixes(form, prefixes)
        if form not in seen:
            seen.add(form)
            out.append((label, form))
    return out


def text_flags(text: str, profile, deadline: float | None = None, *, spoken: bool = True,
               graph: bool = True, packed: bool = False) -> list:
    """[(flag, how)] of one reading, first seen first: the event's flags in the text as it stands, in
    its spoken forms (spoken=True: a transcript), and through the shared codec graph on the text, its
    forms and every glued run of GRAPH_MIN characters (digits or letters read aloud that spell hex,
    base64, a decimal list ...). Only graph answers reached through a representation step are kept.
    packed=True scans with no left boundary (text decoded from tone codes). The deadline is
    time.monotonic(); each graph search has GRAPH_SECONDS at most."""
    ff = flagfmt.for_profile(profile)
    out, seen = [], set()

    def add(flag, how):
        if flag not in seen:
            seen.add(flag)
            out.append((flag, how))

    def scan(blob):
        return flagfmt.find_flags_packed(blob, profile) if packed else ff.find_flags(blob)

    text = text[:MAX_TEXT]
    for f in scan(text):
        add(f, "as read")
    forms = spoken_forms(text, tuple(profile.flag.prefixes)) if spoken else []
    for label, form in forms:
        for f in scan(form):
            add(f, label)
    if not graph or not ff.known:
        return out
    from ctf.codec import FlagOracle, search
    oracle = FlagOracle(profile)
    wanted = [(label, w) for label, form in forms for w in form.split() if len(w) >= GRAPH_MIN]   # glued runs first
    wanted += forms + [("as read", text)] + [("as read", w) for w in text.split() if len(w) >= GRAPH_MIN]
    blobs, have = [], set()
    for label, blob in wanted:
        if blob not in have and len(blobs) < GRAPH_BLOBS:
            have.add(blob)
            blobs.append((label, blob))
    for label, blob in blobs:
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            break
        stop = now + GRAPH_SECONDS if deadline is None else min(deadline, now + GRAPH_SECONDS)
        for h in search(blob.encode("utf-8", "replace"), oracle, deadline=stop).hits:
            if h.chain and h.confirmed:
                add(h.answer, f"{label}, decoded {h.how}")
    return out


# =========================================================================== transcribers

_TIMESTAMP = re.compile(r"^\[[0-9:.,]+\s*-->\s*[0-9:.,]+\]\s*")
_SOUND_TAG = re.compile(r"\[[A-Z_ ]+\]|\((?:music|silence|applause|laughter|noise)\)", re.IGNORECASE)


def clean_transcript(text: str) -> str:
    """A transcriber's output as one line of text: timestamps and sound tags ([BLANK_AUDIO]) removed."""
    lines = []
    for line in text.splitlines():
        line = _SOUND_TAG.sub(" ", _TIMESTAMP.sub("", line.strip()))
        if line.strip():
            lines.append(line.strip())
    return " ".join(" ".join(lines).split())[:MAX_TEXT]


class WhisperCli:
    """whisper.cpp's command line program with a ggml model file. It is given a 16-bit 16 kHz WAV this
    module wrote, never the challenge's own file, and reads the model from disk: no network."""
    name = "whisper-cli"

    def __init__(self, binary: str, model: str, threads: int = 4):
        self.binary, self.model, self.threads = str(binary), str(model), int(threads)

    def argv(self, wav: Path, language: str, prompt: str | None) -> list:
        argv = [self.binary, "-m", self.model, "-f", str(wav), "-l", language, "-t", str(self.threads),
                "-np", "-nt"]
        return argv + (["--prompt", prompt] if prompt else [])

    def __call__(self, samples, language: str = "en", deadline: float | None = None,
                 prompt: str | None = None) -> str:
        left = None if deadline is None else deadline - time.monotonic()
        if left is not None and left <= 0:
            raise TranscribeError(f"{OUT_OF_TIME} before {self.name} started")
        with tempfile.TemporaryDirectory(prefix="audio_speech-") as tmp:
            wav = Path(tmp) / "speech.wav"
            wav.write_bytes(pcm16_wav(samples))
            try:
                r = subprocess.run(self.argv(wav, language, prompt), stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=left, cwd=tmp)
            except subprocess.TimeoutExpired as e:
                why = f"{self.name} was stopped after {left:.1f} s ({OUT_OF_TIME})"
                out = e.stdout or b""
                heard = clean_transcript(out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out))
                if heard:                                   # what it had printed by then is kept
                    raise TranscribeCut(heard, f"{why}; the transcript is cut") from None
                raise TranscribeError(why) from None
            except OSError as e:
                raise TranscribeError(f"{self.name} did not start: {e}") from None
        if r.returncode != 0:
            last = [x for x in r.stderr.decode("utf-8", "replace").splitlines() if x.strip()]
            raise TranscribeError(f"{self.name} exit {r.returncode}" + (f": {last[-1].strip()[:200]}" if last else ""))
        return clean_transcript(r.stdout.decode("utf-8", "replace"))


class FasterWhisper:
    """The faster_whisper module with a CTranslate2 model FOLDER, loaded with local_files_only so a
    missing file is an error and never a download."""
    name = "faster-whisper"

    def __init__(self, model: str, threads: int = 4):
        self.model, self.threads, self._loaded = str(model), int(threads), None

    def __call__(self, samples, language: str = "en", deadline: float | None = None,
                 prompt: str | None = None) -> str:
        if deadline is not None and time.monotonic() >= deadline:
            raise TranscribeError(f"{OUT_OF_TIME} before {self.name} started")
        os.environ.setdefault("HF_HUB_OFFLINE", "1")           # the hub client must not look anything up
        try:
            import faster_whisper
            if self._loaded is None:
                self._loaded = faster_whisper.WhisperModel(self.model, device="cpu", compute_type="int8",
                                                           cpu_threads=self.threads, local_files_only=True)
            segments, _info = self._loaded.transcribe(
                np.ascontiguousarray(samples, dtype=np.float32), language=None if language == "auto" else language,
                beam_size=5, condition_on_previous_text=False, initial_prompt=prompt or None)
            parts = []
            for seg in segments:                                # a generator: the work happens here
                parts.append(seg.text)
                if deadline is not None and time.monotonic() >= deadline:
                    raise TranscribeCut(clean_transcript(" ".join(parts)),
                                        f"{self.name} was stopped at the budget ({OUT_OF_TIME}); the transcript is cut")
        except TranscribeError:
            raise
        except Exception as e:
            raise TranscribeError(f"{self.name}: {type(e).__name__}: {e}") from None
        return clean_transcript(" ".join(parts))


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _which(name: str, environ=None) -> str | None:
    """The program on PATH (the PATH of `environ` when one is handed in), or None."""
    return shutil.which(name, path=environ.get("PATH", "")) if environ is not None else shutil.which(name)


def _inside_repo(path: Path) -> bool:
    from ctf import paths
    try:
        return path.resolve().is_relative_to(paths.repo_root().resolve())
    except OSError:
        return False


def _model_path(asset: str, want_dir: bool, model, environ) -> tuple[str | None, str]:
    """(path, '') of the backend's model, or (None, why not). model=PATH wins; else the named asset of
    tools/assets.toml (its override variable, then its candidates). A model inside the checkout is
    refused: models stay outside the repo."""
    what = "folder" if want_dir else "file"
    if model:
        p = Path(str(model)).expanduser()
        if not (p.is_dir() if want_dir else p.is_file()):
            return None, f"model={p} is not a {what}"
        found = p
    else:
        from ctf.toolchain import assets
        try:
            st = assets.resolve(assets.load(), environ=environ, only=[asset])[0]
        except assets.AssetsError as e:
            return None, f"the asset manifest does not resolve {asset}: {e}"
        if st.state != "ok":
            detail = f" ({st.detail})" if st.state == "broken" else ""
            return None, f"no model: asset {asset} is {st.state}{detail}; {st.fix}"
        found = Path(st.path)
    if _inside_repo(found):
        return None, f"the model {found} is inside the checkout: keep models outside the repo"
    return str(found), ""


def find_backend(want: str = "auto", model=None, threads: int = 4, environ=None):
    """(transcriber, []) for the first usable backend, or (None, [why each one is not usable]). A
    backend is usable when its program or module is installed AND its model is on disk. `want` names
    one backend or `auto` (whisper-cli, then faster-whisper). `environ` (default: the process's) gives
    PATH and the asset variables. Nothing is downloaded or installed."""
    if want != "auto" and want not in BACKENDS:
        raise OptionError(f"backend must be auto or one of {', '.join(BACKENDS)}, not {want!r}")
    missing = []
    for name in (BACKENDS if want == "auto" else (want,)):
        if name == "whisper-cli":
            binary = _which("whisper-cli", environ) or _which("whisper-cpp", environ)
            tool_why = "" if binary else ("whisper-cli is not on PATH (whisper.cpp: `brew install whisper-cpp`)")
            path, model_why = _model_path("whisper-ggml", False, model, environ)
            if binary and path:
                return WhisperCli(binary, path, threads), []
        else:
            ok = _has_module("faster_whisper")
            tool_why = "" if ok else "the faster_whisper module is not installed in the venv"
            path, model_why = _model_path("whisper-ct2", True, model, environ)
            if ok and path:
                return FasterWhisper(path, threads), []
        missing.append(f"{name}: " + "; ".join(w for w in (tool_why, model_why) if w))
    return None, missing


# =========================================================================== non-speech readers

def tone_readings(audio: Audio, original: bytes, kind: str, deadline: float | None = None) -> tuple[list, list]:
    """([(label, text)], notes) from the carried non-speech readers: audio_tones.decode on the bytes
    libsndfile reads (the tone ladder, and the two-stream XOR), audio_stego.analyze on a PCM WAV or
    AIFF up to STEGO_MAX_BYTES (DTMF forward, reversed, in the stereo difference, at half speed; the
    sample LSB text). A reader that raises is a note naming it, never a silent skip. audio_tones reads
    every channel of the file as float64: when that is over TONES_MAX_BYTES it is handed the 16 kHz
    mono decode instead (tones above 8 kHz are then lost), and a note says so. These readers take no
    deadline of their own, so each pass (the ladder, the XOR, audio_stego) starts only while the
    deadline (time.monotonic) is ahead, and a pass not started is a note naming OUT_OF_TIME."""
    readings, notes = [], []

    def late(what: str) -> bool:
        if deadline is not None and time.monotonic() >= deadline:
            notes.append(f"{what} not run: {OUT_OF_TIME}")
            return True
        return False

    if late("tone readers"):
        return readings, notes
    try:
        import audio_tones
        frames = min(audio.frames_total, int(getattr(audio_tones, "MAX_SAMPLES", audio.frames_total)))
        whole = audio.channels * frames * 8
        with tempfile.TemporaryDirectory(prefix="audio_speech-") as tmp:
            path = Path(tmp) / "recording"
            if whole > TONES_MAX_BYTES:
                path.write_bytes(pcm16_wav(audio.samples))
                notes.append(f"audio_tones read the 16 kHz mono decode: the file would decode to "
                             f"{whole >> 20} MiB, over {TONES_MAX_BYTES >> 20} MiB")
            else:
                path.write_bytes(audio.source)
            for label, kwargs in (("tone ladder", {}), ("tone ladder, two streams", {"xor": True})):
                if late(f"audio_tones {label}"):
                    break
                res = audio_tones.decode(str(path), **kwargs)
                for mode, text in res.get("candidates", []):
                    if isinstance(text, str) and text.strip():
                        readings.append((f"{label} ({mode})", text[:MAX_TEXT]))
    except Exception as e:
        notes.append(f"audio_tones did not read it: {type(e).__name__}: {e}")
    if kind in ("wav", "aiff") and not late("audio_stego"):
        if len(original) > STEGO_MAX_BYTES:
            notes.append(f"audio_stego not run: the file is over {STEGO_MAX_BYTES >> 20} MiB (its transforms are pure Python)")
        else:
            try:
                import audio_stego
                for name, value in audio_stego.analyze(original).get("candidates", []):
                    if isinstance(value, str) and value.strip():
                        readings.append((f"audio_stego {name}", value[:MAX_TEXT]))
            except Exception as e:
                notes.append(f"audio_stego did not read it: {type(e).__name__}: {e}")
    return readings, notes


# =========================================================================== the sweep

@dataclass
class Reading:
    label: str               # the variant heard, or the reader's own label
    source: str              # the transcriber's name, or "tones"
    text: str
    forms: list = field(default_factory=list)     # [(label, text)] spoken forms
    flags: list = field(default_factory=list)     # [(flag, how)]
    note: str = ""

    def to_dict(self) -> dict:
        return {"label": self.label, "source": self.source, "text": self.text,
                "forms": [list(f) for f in self.forms], "flags": [list(f) for f in self.flags], "note": self.note}


@dataclass
class FileReport:
    name: str
    kind: str
    state: str = READ        # READ | NOT_DECODED | NOT_TRANSCRIBED
    reason: str = ""
    seconds: float = 0.0
    how: str = ""
    gate: Gate | None = None
    readings: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "state": self.state, "reason": self.reason,
                "seconds": round(self.seconds, 3), "how": self.how,
                "gate": None if self.gate is None else self.gate.to_dict(),
                "readings": [r.to_dict() for r in self.readings], "notes": list(self.notes)}


@dataclass
class Report:
    files: list = field(default_factory=list)
    skipped: list = field(default_factory=list)       # audio files not examined, with the reason
    backend: str | None = None                        # the transcriber used
    missing: list = field(default_factory=list)       # why no transcriber could be used
    written: list = field(default_factory=list)
    out_of_time: bool = False

    def flags(self) -> list:
        out = []
        for f in self.files:
            for r in f.readings:
                for flag, _how in r.flags:
                    if flag not in out:
                        out.append(flag)
        return out

    def to_dict(self) -> dict:
        return {"schema": REPORT_SCHEMA, "engine": ENGINE, "backend": self.backend, "missing": list(self.missing),
                "out_of_time": self.out_of_time, "skipped": list(self.skipped), "flags": self.flags(),
                "files": [f.to_dict() for f in self.files]}


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "audio"


def examine(files: dict, profile, *, transcriber=None, backend: str = "auto", model=None, language: str = "en",
            variants=VARIANTS, speech: str = "auto", deadline: float | None = None, out_dir: Path | None = None,
            to_wav=None, threads: int = 4, graph: bool = True, prompt: str | None = None, environ=None) -> Report:
    """The lane over {name: bytes} (a dict, or delivery_audio's Delivery, which reads a file only when it
    is examined). `transcriber(samples, language=, deadline=, prompt=) -> str` replaces
    the backend lookup (tests hand in a stub); `to_wav(data, name) -> WAV bytes` replaces ffmpeg in the
    sandbox. speech: auto (the gate decides: `other` and `mixed` are heard), on (tones and silence
    are heard too), off (nothing is transcribed).
    The deadline is time.monotonic(). Transcripts and report.json go to out_dir when it is given."""
    if speech not in SPEECH:
        raise OptionError(f"speech must be one of {', '.join(SPEECH)}, not {speech!r}")
    variants = tuple(variants)
    bad = [v for v in variants if v not in VARIANTS]
    if bad or not variants:
        raise OptionError(f"variants are {', '.join(VARIANTS)}; got {list(variants)}")
    if backend != "auto" and backend not in BACKENDS:
        raise OptionError(f"backend must be auto or one of {', '.join(BACKENDS)}, not {backend!r}")
    rep = Report()
    audio_files = [(n, k) for n in files if (k := audio_kind(n, files.head(n) if hasattr(files, "head") else files[n]))]
    for n, _k in audio_files[MAX_FILES:]:
        rep.skipped.append(f"{n}: over the {MAX_FILES} audio files examined in one delivery")
    looked_up = transcriber is not None
    if transcriber is not None:
        rep.backend = getattr(transcriber, "name", "transcriber")

    def left() -> bool:
        return deadline is None or time.monotonic() < deadline

    for name, kind in audio_files[:MAX_FILES]:
        fr = FileReport(name=name, kind=kind)
        rep.files.append(fr)
        if not left():
            fr.state, fr.reason, rep.out_of_time = NOT_DECODED, OUT_OF_TIME, True
            continue
        data = files[name]                            # one recording in memory at a time
        try:
            audio = decode(name, data, to_wav=to_wav, deadline=deadline)
        except DecodeError as e:
            fr.state, fr.reason = NOT_DECODED, str(e)
            continue
        fr.seconds, fr.how, fr.notes = audio.seconds, audio.how, list(audio.notes)
        rep.out_of_time = rep.out_of_time or audio.out_of_time
        fr.gate = gate(audio.samples)
        hear = speech == "on" or (speech == "auto" and fr.gate.kind in (OTHER, MIXED))
        if fr.gate.kind in (SILENT, TONES, MIXED):
            readings, notes = tone_readings(audio, data, kind, deadline)
            fr.notes += notes
            if any(OUT_OF_TIME in n for n in notes):
                rep.out_of_time = True
            for label, text in readings:
                fr.readings.append(Reading(label, "tones", text,
                                           flags=text_flags(text, profile, deadline, spoken=False, graph=graph, packed=True)))
        if not hear:
            if fr.gate.kind in (OTHER, MIXED):
                fr.state, fr.reason = NOT_TRANSCRIBED, SPEECH_OFF
            continue
        if not looked_up:
            looked_up = True
            transcriber, rep.missing = find_backend(backend, model, threads, environ)
            rep.backend = getattr(transcriber, "name", None)
        if transcriber is None:
            fr.state, fr.reason = NOT_TRANSCRIBED, "no speech-to-text backend"
            continue
        heard = {"original": audio.samples, "stereo_difference": audio.difference,
                 "reversed": np.ascontiguousarray(audio.samples[::-1])}
        for variant in variants:
            samples = heard[variant]
            if samples is None:                       # mono, or two channels that do not differ
                continue
            if any(r.flags for r in fr.readings if r.source != "tones"):
                break                                 # the plain recording said it: the rest is not needed
            if not left():
                fr.notes.append(f"{variant} not transcribed: {OUT_OF_TIME}")
                rep.out_of_time = True
                continue
            note = ""
            try:
                text = transcriber(samples, language=language, deadline=deadline, prompt=prompt)
            except TranscribeCut as e:
                text, note = e.text, str(e)
                rep.out_of_time = True
            except TranscribeError as e:
                fr.notes.append(f"{variant} not transcribed: {e}")
                if OUT_OF_TIME in str(e):
                    rep.out_of_time = True
                continue
            text = " ".join(str(text).split())[:MAX_TEXT]
            r = Reading(variant, rep.backend or "transcriber", text, note=note)
            if text:
                r.forms = spoken_forms(text, tuple(profile.flag.prefixes))
                r.flags = text_flags(text, profile, deadline, spoken=True, graph=graph)
            fr.readings.append(r)
        if not any(r.source != "tones" for r in fr.readings):
            fr.state = NOT_TRANSCRIBED
            fr.reason = "; ".join(n for n in fr.notes if "not transcribed" in n) or "nothing was transcribed"
    if out_dir is not None and rep.files:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for fr in rep.files:
            for r in fr.readings:
                if r.source == "tones" or not r.text:
                    continue
                p = out_dir / f"{_safe(fr.name)}.{r.label}.txt"
                body = [r.text] + [f"[{label}] {form}" for label, form in r.forms]
                p.write_text("\n".join(body) + "\n", encoding="utf-8")
                rep.written.append(str(p))
        p = out_dir / REPORT_NAME
        p.write_text(json.dumps(rep.to_dict(), indent=2) + "\n", encoding="utf-8")
        rep.written.append(str(p))
    return rep


def result_of(rep: Report, *, challenge_id: str | None = None, seconds: float = 0.0):
    """The Report as a SolverResult: `candidate` for any flag (a lossy reading is never `solved`),
    `blocked` when speech was there and no backend, model or run could transcribe it (or nothing could
    be decoded), `unsure` when speech was transcribed and holds no flag, `none` otherwise."""
    from ctf.result import Cost, Evidence, SolverResult
    ev, flags = [], rep.flags()
    for fr in rep.files:
        if fr.state == NOT_DECODED:
            ev.append(Evidence("audio", f"{fr.kind}: not decoded: {fr.reason}", path=fr.name))
            continue
        g = fr.gate
        ev.append(Evidence("audio", f"{fr.kind}, {fr.seconds:.1f} s via {fr.how}; reads as {g.kind}"
                                    + (f" ({g.few:.0%} of {g.frames} judged frames have at most two spectral "
                                       f"peaks; median {g.peaks:g})" if g.kind != SILENT else "")
                                    + "".join(f"; {n}" for n in fr.notes), path=fr.name))
        for r in fr.readings:
            if r.source == "tones":
                if r.flags:
                    ev.append(Evidence("tone-reading", f"[{r.label}] {r.text[:EVIDENCE_TEXT]!r}", path=fr.name))
            else:
                ev.append(Evidence("transcript", f"[{r.label}] via {r.source}: {r.text[:EVIDENCE_TEXT]!r}"
                                                 + (f" ({r.note})" if r.note else ""), path=fr.name))
            for flag, how in r.flags:
                ev.append(Evidence("speech-flag" if r.source != "tones" else "tone-flag",
                                   f"{flag} <- [{r.label}] {how}", path=fr.name))
    for s in rep.skipped:
        ev.append(Evidence("skipped", s))
    cost = Cost(seconds=round(seconds, 3))
    undecoded = [f for f in rep.files if f.state == NOT_DECODED]
    unheard = [f for f in rep.files if f.state == NOT_TRANSCRIBED]
    failed = [f for f in unheard if f.reason != SPEECH_OFF]
    transcripts = [r for f in rep.files for r in f.readings if r.source != "tones" and r.text]
    tail = ""
    if undecoded:
        tail += f" Not decoded: {', '.join(f'{f.name} ({f.reason})' for f in undecoded)}."
    if unheard:
        tail += " Not transcribed: " + ", ".join(f"{f.name} ({f.reason})" for f in unheard) + "."
    if rep.out_of_time:
        tail += f" The budget ran out ({OUT_OF_TIME}): raise seconds= to finish."
    if rep.written:
        tail += f" Written: {Path(rep.written[-1]).parent}."
    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(ev), cost=cost, engine=ENGINE,
                            challenge_id=challenge_id,
                            notes="read by speech-to-text or a tone reader: lossy (letter case, 0/O, 1/l), so "
                                  "check the spelling against the recording before sending "
                                  "(`python -m ctf flag variants`)." + tail)
    if not rep.files:
        return SolverResult(status="none", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="no audio file in the delivery")
    if unheard and rep.missing:
        return SolverResult(status="blocked", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="speech-like audio and no usable speech-to-text backend. "
                                  + " ".join(f"[{m}]" for m in rep.missing)
                                  + " Install one backend and its model (docs/build-log/B-087.md), or pass "
                                    "model=PATH; nothing is downloaded by this engine." + tail)
    if failed and not transcripts:
        return SolverResult(status="blocked", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes=f"speech-like audio was not transcribed ({rep.backend or 'no backend'})." + tail)
    if undecoded and len(undecoded) == len(rep.files):
        return SolverResult(status="blocked", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="no audio file could be decoded." + tail)
    if transcripts:
        return SolverResult(status="unsure", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes="speech was transcribed and holds no flag in the event format: read the "
                                  "transcripts (an answer may be said in words)." + tail)
    return SolverResult(status="none", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=challenge_id,
                        notes=("nothing heard: no speech, and the tone readers found no flag." + tail).strip())


# =========================================================================== the engine contract

class Delivery(Mapping):
    """{relative name: bytes} whose bytes are read from disk only when a file is looked up, so a
    delivery of many large recordings is never all in memory at once (examine holds one at a time,
    and the files past MAX_FILES are never read). `head(name)` is the file's first HEAD bytes, read
    when the delivery was listed."""

    def __init__(self, entries: dict):
        self._entries = dict(entries)           # name -> (path, head)

    def __getitem__(self, name: str) -> bytes:
        return self._entries[name][0].read_bytes()

    def __iter__(self):
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def head(self, name: str) -> bytes:
        return self._entries[name][1]


def _head_of(p: Path) -> bytes:
    with open(p, "rb") as fh:
        return fh.read(HEAD)


def delivery_audio(challenge_dir: Path) -> Delivery:
    """The audio files of a challenge folder as a Delivery ({relative name: bytes}, read lazily): the
    sweep's scratch copy (`unpacked/`) when there is one, else `files/`, else the folder itself
    (image_carve's rule and its skip lists); only a file's head is read to tell whether it is audio.
    A file path is that one file."""
    import image_carve as ic
    challenge_dir = Path(challenge_dir)
    if challenge_dir.is_file():
        return Delivery({challenge_dir.name: (challenge_dir, _head_of(challenge_dir))})
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder or file: {challenge_dir}")
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in ic.SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n in ic.SKIP_FILES or p.is_symlink() or not p.is_file() or p.stat().st_size > ic.MAX_FILE:
                continue
            head = _head_of(p)
            if audio_kind(n, head):
                out[str(p.relative_to(challenge_dir))] = (p, head)
    return Delivery(out)


def challenge_id_of(challenge_dir: Path) -> str | None:
    """The id in the challenge folder's challenge.json (written by intake and pull), or None."""
    try:
        cid = json.loads((Path(challenge_dir) / "challenge.json").read_text(encoding="utf-8")).get("id")
    except (OSError, ValueError, AttributeError):
        return None
    return str(cid) if cid not in (None, "") else None


def _list_opt(value) -> tuple:
    if isinstance(value, str):
        return tuple(v.strip() for v in value.split(",") if v.strip())
    return tuple(str(v) for v in value)


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: backend (auto | whisper-cli | faster-whisper), model (a model path that
    replaces the asset lookup), language (en; auto lets the model detect), variants (comma list of
    original, stereo_difference, reversed), speech (auto | on | off), seconds (budget, default 240),
    out (folder for transcripts and report.json; default <challenge>/recon/audio_speech for a folder,
    none for a single file), prompt (an initial prompt handed to the model), threads, graph (on | off:
    the codec-graph decode of the readings), challenge_id; transcriber and to_wav (callables: stubs)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else challenge_id_of(challenge_dir)
    known = {"backend", "model", "language", "variants", "speech", "seconds", "out", "prompt", "threads",
             "graph", "challenge_id", "transcriber", "to_wav"}
    try:
        if set(opts) - known:
            raise OptionError(f"unknown option(s) {sorted(set(opts) - known)}")
        try:
            seconds = float(opts.get("seconds", DEFAULT_SECONDS))
            threads = int(opts.get("threads", 4))
        except (TypeError, ValueError) as e:
            raise OptionError(f"seconds and threads are numbers: {e}") from None
        if seconds <= 0 or threads < 1:
            raise OptionError("seconds must be > 0 and threads >= 1")
        graph = str(opts.get("graph", "on")).lower()
        if graph not in ("on", "off"):
            raise OptionError("graph must be on or off")
        files = delivery_audio(challenge_dir)
        out_dir = (Path(opts["out"]) if opts.get("out")
                   else challenge_dir / "recon" / "audio_speech" if challenge_dir.is_dir() else None)
        rep = examine(files, profile,
                      transcriber=opts["transcriber"] if callable(opts.get("transcriber")) else None,
                      backend=str(opts.get("backend", "auto")), model=opts.get("model"),
                      language=str(opts.get("language", "en")),
                      variants=_list_opt(opts.get("variants", VARIANTS)), speech=str(opts.get("speech", "auto")),
                      deadline=t0 + seconds, out_dir=out_dir,
                      to_wav=opts["to_wav"] if callable(opts.get("to_wav")) else None,
                      threads=threads, graph=graph == "on",
                      prompt=str(opts["prompt"]) if opts.get("prompt") else None)
    except OptionError as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"bad option: {e}")
    except FileNotFoundError as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=str(e))
    return result_of(rep, challenge_id=cid, seconds=time.monotonic() - t0)
