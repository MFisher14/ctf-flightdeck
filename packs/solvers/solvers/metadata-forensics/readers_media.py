#!/usr/bin/env python3
"""Metadata Forensics media reader pack (backlog rows 339 and 334; the Day 18 look-ahead's build items 1, 3 and 4).

properties_strict.py loads this file by name (MORE_FILES, last) and calls register(M).

Day 17 ('Hear Me Out') asked `media.primary_audio_codec_name` of a RIFF/WAVE file, and the judge took ffprobe's codec
name: `pcm_s16le` for format tag 1 (integer PCM) at 16 bits per sample, accepted at the first probe on the base under
the ledger key `metadata.media.primary_audio_codec_name/wav` with the option name `ffprobe_codec_name` (ledger row
2026-10-17T13:00:35Z). That name is the one judged thing in this file. Everything else here is unsure.

1. The WAV codec (row 339), as shipped on Day 17, and one guard (the look-ahead's W1)

  media.primary_audio_codec_name of a RIFF/WAVE file is read from the fmt chunk, in ffprobe's names, and keyed by
  the shape it was read from:
        format tag 1, 16 bits                 .../wav                  judged: plain (pcm_s16le)
        format tag 1, 8, 24 or 32 bits        .../wav+pcm_u8, +pcm_s24le, +pcm_s32le       unsure
        format tag 3, 32 or 64 bits           .../wav+pcm_f32le, +pcm_f64le                unsure
        format tags 6, 7, 2, 0x11             .../wav+pcm_alaw, +pcm_mulaw, +adpcm_ms, +adpcm_ima_wav   unsure
        format tags 0x55, 0x50, 0x2000, 0x2001, 0xFF   .../wav+mp3, +mp2, +ac3, +dts, +aac   unsure (2026-10-17 night)
        0xFFFE with the PCM or IEEE-float subformat GUID and the valid bits equal to the container's
                                              .../wav+extensible+<the codec>              unsure
  M.Unknown (None) for what the fmt chunk does not settle the way ffprobe reads it: not RIFF/WAVE (for this reader;
  the media probe below reads other containers), RF64/BW64/RIFX, no or two fmt chunks, a cut fmt chunk, no data
  chunk or a data chunk before fmt, 0 channels or 0 Hz, a tag or depth the table does not name, extensible with
  valid bits below the container or a foreign GUID, and integer PCM whose data begins with an IEC 61937 burst.

  The guard (look-ahead item 1). For a 16-bit integer PCM header (tag 1, or extensible PCM at 16 bits: ffmpeg's wav
  demuxer re-probes both, never an 8-bit, 24-bit or float header) the data chunk is searched for chained frames of a
  compressed elementary stream: MPEG audio layers 1 to 3, ADTS AAC, LOAS/LATM, AC-3 and E-AC-3 (either byte order),
  DTS (16-bit and 14-bit, either byte order) and TrueHD/MLP. Each frame must be a valid header at exactly the
  distance the one before it states, with the same stream parameters. Measured with ffprobe 9.0.2 (2026-10-17
  night, on ffmpeg-made streams inside 16-bit PCM WAVs): ADTS and LATM are named from 3 frames at the data's first
  byte, AC-3, E-AC-3, MP2 and MP3 from 7 or 8 (MPEG audio at the first byte that is not zero, up to about 520 KB of
  zeros), none of them 16 bytes of PCM further in; DTS from 5 or 6 frames and TrueHD from about 100 access units
  anywhere up to about 450 KB in, none 520 KB in. So the search reads: the data's first byte (and its first byte
  that is not zero) for every format; DTS and TrueHD sync words in the first 512 KiB; MPEG audio, ADTS and AC-3 in
  the first 4 KiB after the first byte that is not zero (a margin, not a reading of ffprobe 9.0.2). Then:
    probed   (ffprobe names the stream: the rule above)        unsure under .../wav+probed+<codec>,
             the compressed codec first, pcm_s16le second ('fmt_header')
    embedded (a chain ffprobe most likely does not name: 2 or more frames at the start, 3 or more further in, DTS 2
             to 4, two TrueHD major syncs a chain apart)      unsure under .../wav+embedded+<codec>,
             pcm_s16le first, the compressed codec second ('embedded_stream')
  Either way the answer is never pcm_s16le plain. One frame, a lone sync word, noise and PCM change nothing (the
  19 PCM shapes of the look-ahead, Day 17's WAV, one AC-3 frame, one DTS frame, DTS 600 KB in, 68 ffmpeg-made tones
  and noises and 150 buffers of random bytes stay plain). Day 17's 40 KB WAV costs about 80 us more than before,
  once per file (see the cache below); a 22 MB WAV about 0.6 ms.

2. The rest of the `media` namespace (row 334)

  Every `media.<field>` name of the grammar below (and the same names under `audio.` and `video.`) is read from one
  probe of the file, in ffprobe's vocabulary, for WAV, FLAC, Ogg (Vorbis, Opus, FLAC, Speex, Theora), MPEG audio
  (mp3, mp2, mp1), AIFF/AIFF-C, MP4/MOV/M4A/3GP, Matroska/WebM, AVI, Sun AU, Apple CAF and raw AC-3/E-AC-3/ADTS.
  No subprocess and no ffprobe on the timed path; every walk is bounded.
    format level   format_name ('mov,mp4,m4a,3gp,3g2,mj2', 'matroska,webm', 'wav', ...), format_long_name,
                   duration (container duration), bit_rate (size * 8 / duration, as ffprobe computes it),
                   stream_count, <kind>_stream_count, codec_names lists, has_<kind>, and the tags title, artist,
                   album, comment, date, genre, encoder
    stream level   [primary|first|main|default|secondary|second|third_][audio|video|subtitle_][stream_|track_][N_]
                   codec_name, codec_long_name, codec_tag, codec_tag_string, codec_type, sample_rate, channels,
                   channel_layout, bits_per_sample, sample_format, bit_rate, duration, sample_count, frame_count,
                   width, height, dimensions, frame_rate (r_frame_rate), avg_frame_rate; stream_<N>_<field> is
                   ffprobe's stream index N
  Each answer goes through labels.pick under a ledger key of its own that carries the container
  ('metadata.media.primary_audio_sample_rate_hz/wav'), and for a codec field the container and the codec's own tag
  ('metadata.media.primary_video_codec_name/mp4+avc1'), so a name the judge accepts on one shape never answers
  another shape plain. Nothing here is plain except the judged key above in its judged shape. The forms: ffprobe's
  first (a duration as '1.250000', a frame rate as '25/1', a codec tag as '0x0001'), then shorter spellings.
  A stream of the asked kind that the file does not have is 'absent' (the unsure literal none, as for every
  registered name); a stream field this pack does not settle for that container (a pixel format, a profile, the
  stream duration of a Matroska track, a lossy codec's bit depth) is M.Unknown. A file that is no media container
  this pack reads is M.Unknown for every media name (the answer is None and the facts page says what it is).

3. ffprobe's forms first in the container readers (look-ahead item 4)

  wav., flac., mp4. and mkv.duration_seconds (and their aliases) offer ffprobe's '1.250000' first now, where they
  offered '1.2500' first and '1.250000' fourth. Only the order changes; every one is still unsure.

4. media.<rest> in the file's own container namespace (B-223)

  A media./audio./video. name the grammar of section 2 does not read (and that the alias table, synonym() and
  guess() leave unread) is read as <container>.<rest> by the registered readers of the file's own container:
  properties_strict.CONTAINER_HEADS maps the three heads to container_namespaces(), which names the lane
  namespaces of the container the detector of section 3 finds (('wav', 'riff') for a WAV, ('mp4',) for an
  MP4, ('mkv',) for Matroska/WebM, ...). A name registered exactly in one of them wins over a family or a
  nearest reading. media.block_align of a WAV is wav.block_align, media.doc_type of a WebM file mkv.doc_type,
  media.format_tag_hex wav.format_tag_hex with its padded form first. No reader is added: every such answer is
  unsure under the asked name's own key and each option names the reader ('integer~wav.block_align'), so a
  judge's acceptance on one container never answers another plain. A container with no reader of that name,
  an unseen name, and a file that is no media container get nothing; alias resolution of unseen names is
  B-224's (name_aliases.json).

Import cost: re and struct; the grammar's pattern is compiled once. Nothing is read until a question asks, and one
probe per file serves every media question about it: the last few files are kept by identity (a 20 MB file is
never hashed for it), and a file of 1 MiB or less also by content, because every Mastery set delivers the same file
as a new object. Measured on 2026-10-17 night: the saved Day 17 Time Trial and Mastery solve in the time they took
on the armed tree (12.9 ms, 70.1 ms against 70.3 ms); a media question about a 10 MB mp4 or mkv or a 22 MB WAV is
answered in 3 to 9 ms, where the armed solver printed a facts page for 230 to 490 ms and answered None.
"""
import array
import fractions
import json
import math
import re
import struct

M = None    # properties_strict, set by register()
RM = None   # readers_more.py as loaded (Ogg, the WAV INFO list, MP4 tags)
RF = None   # readers_formats.py as loaded (Matroska)
RS = None   # readers_structures.py as loaded (AIFF)

PROPERTY = "media.primary_audio_codec_name"
JUDGED = "wav"                        # the one shape whose name the judge has accepted (Day 17)
CLASS = "forms"                       # the reader writes its own forms (properties_strict.FORM_NAMES has their names),
                                      # as M.ledger_forms: present() judges them under the ledger key the reader names

PCM_INT = {8: "pcm_u8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}   # format tag 1 (and its extensible GUID)
PCM_FLOAT = {32: "pcm_f32le", 64: "pcm_f64le"}                              # format tag 3
FIXED = {0x0002: "adpcm_ms", 0x0006: "pcm_alaw", 0x0007: "pcm_mulaw", 0x0011: "adpcm_ima_wav"}
# compressed streams a WAV header names by its format tag (ffmpeg's riff tag table; ffprobe 9.0.2 on the look-ahead's
# wav_mp3 specimen: codec_tag 0x0055, mp3)
COMPRESSED_TAGS = {0x0055: "mp3", 0x0050: "mp2", 0x2000: "ac3", 0x2001: "dts", 0x00FF: "aac"}
EXTENSIBLE = 0xFFFE
KS_BASE = bytes.fromhex("000010008000" "00aa00389b71")    # bytes 4..15 of KSDATAFORMAT_SUBTYPE_* (the tag is bytes 0..3)
SPDIF_SYNC = b"\x72\xf8\x1f\x4e"      # IEC 61937 Pa, Pb as 16-bit little-endian words (ffmpeg's ff_spdif_probe)
SPDIF_WINDOW = 1 << 16                # ffmpeg's wav demuxer probes the first 64 KiB of the data chunk
MAX_CHANNELS = 64                     # more is a damaged header, not a recording


def U(msg):
    raise M.Unknown(msg)


# ====================================================================== 1. compressed frames behind a PCM header

PROBE_WINDOW = 1 << 19      # where a stream's first frame may start: ffprobe found streams 450 KB in, none 600 KB in
CHAIN_LIMIT = 8             # frames walked from one place (the most a rule below asks is 7)
CANDIDATES = 1 << 15        # sync candidates looked at in the window; past that the window is noise, not a stream
THD_AUS = 128               # TrueHD access units walked from a major sync
AT_START = {"mp1": 7, "mp2": 7, "mp3": 7, "ac3": 7, "eac3": 7, "aac": 3, "aac_latm": 3}   # ffprobe names it from here

MPA_BR = {(1, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
          (1, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
          (1, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
          (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
          (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
          (2, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160)}
MPA_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}
AAC_RATES = (96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350)
AC3_RATES = (48000, 44100, 32000)
AC3_WORDS = ((64, 69, 96), (64, 70, 96), (80, 87, 120), (80, 88, 120), (96, 104, 144), (96, 105, 144), (112, 121, 168),
             (112, 122, 168), (128, 139, 192), (128, 140, 192), (160, 174, 240), (160, 175, 240), (192, 208, 288),
             (192, 209, 288), (224, 243, 336), (224, 244, 336), (256, 278, 384), (256, 279, 384), (320, 348, 480),
             (320, 349, 480), (384, 417, 576), (384, 418, 576), (448, 487, 672), (448, 488, 672), (512, 557, 768),
             (512, 558, 768), (640, 696, 960), (640, 697, 960), (768, 835, 1152), (768, 836, 1152), (896, 975, 1344),
             (896, 976, 1344), (1024, 1114, 1536), (1024, 1115, 1536), (1152, 1253, 1728), (1152, 1254, 1728),
             (1280, 1393, 1920), (1280, 1394, 1920))
DTS_RATES = {1: 8000, 2: 16000, 3: 32000, 6: 11025, 7: 22050, 8: 44100, 11: 12000, 12: 24000, 13: 48000}


def mpa(d, p):
    """(codec, frame size, stream key, (sample rate, channels, kbit/s)) of an MPEG audio frame header at p, or None."""
    if p + 4 > len(d) or d[p] != 0xFF or d[p + 1] & 0xE0 != 0xE0:
        return None
    b1, b2, b3 = d[p + 1], d[p + 2], d[p + 3]
    ver, lay, bri, sri = (b1 >> 3) & 3, (b1 >> 1) & 3, b2 >> 4, (b2 >> 2) & 3
    if ver == 1 or lay == 0 or bri in (0, 15) or sri == 3 or b3 & 3 == 2:
        return None
    layer, v = 4 - lay, 1 if ver == 3 else 2
    kbps, rate, pad = MPA_BR[(v, layer)][bri], MPA_RATES[ver][sri], (b2 >> 1) & 1
    if layer == 1:
        size = (12000 * kbps // rate + pad) * 4
    elif layer == 3 and v == 2:
        size = 72000 * kbps // rate + pad
    else:
        size = 144000 * kbps // rate + pad
    return f"mp{layer}", size, (ver, lay, sri), (rate, 1 if b3 >> 6 == 3 else 2, kbps)


def adts(d, p):
    if p + 7 > len(d) or d[p] != 0xFF or d[p + 1] & 0xF6 != 0xF0:
        return None
    sf = (d[p + 2] >> 2) & 15
    if sf > 12:
        return None
    size = ((d[p + 3] & 3) << 11) | (d[p + 4] << 3) | (d[p + 5] >> 5)
    if size < (7 if d[p + 1] & 1 else 9):
        return None
    ch = ((d[p + 2] & 1) << 2) | (d[p + 3] >> 6)
    return "aac", size, (d[p + 1] & 8, d[p + 2] >> 6, sf, ch), (AAC_RATES[sf], ch, None)


def latm(d, p):
    if p + 3 > len(d) or d[p] != 0x56 or d[p + 1] & 0xE0 != 0xE0:
        return None
    n = ((d[p + 1] & 0x1F) << 8) | d[p + 2]
    return ("aac_latm", 3 + n, (), (None, None, None)) if n >= 4 else None


def ac3(d, p):
    if p + 8 > len(d) or d[p] != 0x0B or d[p + 1] != 0x77:
        return None
    bsid = d[p + 5] >> 3
    if bsid <= 10:
        fscod, code = d[p + 4] >> 6, d[p + 4] & 0x3F
        if fscod == 3 or code > 37:
            return None
        return "ac3", AC3_WORDS[code][fscod] * 2, (fscod,), (AC3_RATES[fscod], None, None)
    if bsid <= 16:
        fscod = d[p + 4] >> 6
        if fscod == 3:
            fscod2 = (d[p + 4] >> 4) & 3
            if fscod2 == 3:
                return None
            rate = AC3_RATES[fscod2] // 2
        else:
            rate = AC3_RATES[fscod]
        size = ((((d[p + 2] & 7) << 8) | d[p + 3]) + 1) * 2
        return ("eac3", size, (rate,), (rate, None, None)) if size >= 8 else None
    return None


def _swap(b: bytes) -> bytes:
    """Each pair of bytes swapped (16-bit words of the other byte order)."""
    a = array.array("H", b[:len(b) & ~1])
    a.byteswap()
    return a.tobytes()


def ac3_le(d, p):
    """AC-3 or E-AC-3 written as 16-bit little-endian words (77 0B): the header read after swapping its words."""
    h = d[p:p + 8]
    return ac3(_swap(h), 0) if len(h) == 8 and h[:2] == b"\x77\x0b" else None


def _unpack14(b: bytes) -> bytes:
    """14 bits of each big-endian 16-bit word, joined: a DTS 14-bit stream as the 16-bit form reads it."""
    bits, n, out = 0, 0, bytearray()
    for i in range(0, len(b) - 1, 2):
        bits = (bits << 14) | (((b[i] << 8) | b[i + 1]) & 0x3FFF)
        n += 14
        while n >= 8:
            n -= 8
            out.append((bits >> n) & 0xFF)
    return bytes(out)


def _dts_core(h: bytes):
    """(frame bytes, sample rate) of a DTS core header in its 16-bit big-endian form, or None."""
    if len(h) < 12:
        return None
    v = int.from_bytes(h[4:12], "big")
    nblks, fsize, sfreq = (v >> 50) & 127, (v >> 36) & 0x3FFF, (v >> 26) & 15
    if nblks < 5 or fsize < 95 or sfreq not in DTS_RATES:
        return None
    return fsize + 1, DTS_RATES[sfreq]


def dts(d, p):
    h = d[p:p + 16]
    if len(h) < 16:
        return None
    if h[:4] == b"\x7f\xfe\x80\x01":
        form, core, scale = "be16", _dts_core(h), (1, 1)
    elif h[:4] == b"\xfe\x7f\x01\x80":
        form, core, scale = "le16", _dts_core(_swap(h)), (1, 1)
    elif h[:4] == b"\x1f\xff\xe8\x00" and h[4] == 0x07 and h[5] & 0xF0 == 0xF0:
        form, core, scale = "be14", _dts_core(_unpack14(h)), (8, 7)
    elif h[:4] == b"\xff\x1f\x00\xe8" and h[5] == 0x07 and h[4] & 0xF0 == 0xF0:
        form, core, scale = "le14", _dts_core(_unpack14(_swap(h))), (8, 7)
    else:
        return None
    if core is None or (core[0] * scale[0]) % scale[1]:
        return None
    return "dts", core[0] * scale[0] // scale[1], (form, core[1]), (core[1], None, None)


def _chain(d, p, end, parse, limit=CHAIN_LIMIT):
    """(headers chained from p, codec, first header's facts): each next header valid, of the same stream, at exactly
    the distance the one before states; the last frame may run past `end` (ffmpeg's probes count it too)."""
    first = parse(d, p)
    if not first or first[1] <= 0:
        return 0, None, None
    codec, size, key, facts = first
    n, q = 1, p + size
    while n < limit and q + 4 <= end:
        r = parse(d, q)
        if not r or r[0] != codec or r[2] != key or r[1] <= 0:
            break
        n, q = n + 1, q + r[1]
    return n, codec, facts


def _thd_chain(d, p, end):
    """(access units walked, major syncs met) from a TrueHD/MLP access unit with a major sync at p + 4."""
    aus, majors, q = 0, 0, p
    while q + 8 <= end and aus < THD_AUS:
        n = (int.from_bytes(d[q:q + 2], "big") & 0xFFF) * 2
        if n < 4:
            break
        if d[q + 4:q + 7] == b"\xf8\x72\x6f" and d[q + 7] in (0xBA, 0xBB):
            majors += 1
        aus, q = aus + 1, q + n
    return aus, majors


def _class(pred) -> bytes:
    return b"[" + b"".join(re.escape(bytes([b])) for b in range(256) if pred(b)) + b"]"


_NONZERO = re.compile(rb"[^\x00]")
# One pattern per sync word, each led by a literal byte: the regular expression engine then skips to that byte
# quickly, where one alternation of all of them looked at every byte (2.1 ms for 512 KiB of PCM; these: 0.1 to 0.3 ms).
_MPA_ADTS = re.compile(re.escape(b"\xff") + b"(?:"
                       + _class(lambda b: b >= 0xE0 and (b >> 3) & 3 != 1 and (b >> 1) & 3 != 0)
                       + _class(lambda b: 0 < b >> 4 < 15 and (b >> 2) & 3 != 3) + b"|"          # MPEG audio
                       + _class(lambda b: b in (0xF0, 0xF1, 0xF8, 0xF9))
                       + _class(lambda b: (b >> 2) & 15 <= 12) + b")", re.S)                       # ADTS
_NEAR = tuple(re.compile(re.escape(w), re.S) for w in (b"\x0b\x77", b"\x77\x0b"))                   # AC-3, E-AC-3
_FAR = tuple(re.compile(re.escape(w), re.S) for w in (b"\x7f\xfe\x80\x01", b"\xfe\x7f\x01\x80",    # DTS 16-bit
                                                     b"\x1f\xff\xe8\x00", b"\xff\x1f\x00\xe8",      # DTS 14-bit
                                                     b"\xf8\x72\x6f"))                              # TrueHD / MLP
NEAR_WINDOW = 1 << 12   # MPEG audio, ADTS and AC-3 away from the start: ffprobe 9.0.2 named them only at the data's
                        # first byte (MPEG audio at its first byte that is not zero), none 16 bytes of PCM in; the
                        # window is a margin for another build of ffmpeg, never a reading of this one


def _parser_at(d, p):
    b0, b1 = d[p], d[p + 1] if p + 1 < len(d) else -1
    if b0 == 0xFF:
        return adts if b1 in (0xF0, 0xF1, 0xF8, 0xF9) else (dts if b1 == 0x1F else mpa)
    return {0x56: latm, 0x0B: ac3, 0x77: ac3_le, 0x7F: dts, 0xFE: dts, 0x1F: dts}.get(b0)


def _candidates(d, start, lim):
    """Sync candidates in the window, in the order they are looked at: DTS and TrueHD anywhere in it, then MPEG audio,
    ADTS and AC-3 within NEAR_WINDOW of the data's first byte that is not zero; at most CANDIDATES of them."""
    seen = 0
    for rx in _FAR:
        for m in rx.finditer(d, start, lim):
            seen += 1
            if seen > CANDIDATES:
                return
            yield m.start()
    nz = _NONZERO.search(d, start, lim)
    if not nz:
        return
    a = nz.start()
    for rx in (_MPA_ADTS,) + _NEAR:
        for m in rx.finditer(d, a, min(lim, a + NEAR_WINDOW)):
            seen += 1
            if seen > CANDIDATES:
                return
            yield m.start()


def embedded(d: bytes, start: int, end: int):
    """(codec, 'probed' or 'embedded') for a compressed elementary stream inside the data chunk d[start:end] of a
    16-bit PCM WAV, or None. 'probed' where ffprobe 9.0.2 names the stream (the rule in the module docstring),
    'embedded' where a chain is there that it most likely does not name."""
    end = min(end, len(d))
    lim = min(end, start + PROBE_WINDOW)
    if lim - start < 8:
        return None
    weak = None
    for parse in (adts, latm, ac3, ac3_le):            # at the very start of the data
        n, codec, _ = _chain(d, start, end, parse)
        if n >= 2:
            if n >= AT_START[codec]:
                return codec, "probed"
            weak = weak or codec
    nz = _NONZERO.search(d, start, lim)                 # MPEG audio after any run of zero bytes
    if nz:
        at = nz.start()
        at += _id3_end(d[at:min(end, at + PROBE_WINDOW)])   # behind an ID3v2 tag, which ffprobe reads past
        n, codec, _ = _chain(d, at, end, mpa)
        if n >= 2:
            if n >= AT_START[codec]:
                return codec, "probed"
            weak = weak or codec
    for p in _candidates(d, start, lim):                # away from the start
        if d[p] == 0xF8:                                # a major sync sits 4 bytes into its access unit
            if p - 4 < start or p + 3 >= len(d) or d[p + 3] not in (0xBA, 0xBB):
                continue
            aus, majors = _thd_chain(d, p - 4, end)
            if majors >= 2:
                codec = "truehd" if d[p + 3] == 0xBA else "mlp"
                if aus >= 100:
                    return codec, "probed"
                weak = weak or codec
            continue
        parse = _parser_at(d, p)
        if parse is None:
            continue
        n, codec, _ = _chain(d, p, end, parse)
        if codec == "dts" and n >= 5:
            return codec, "probed"
        if n >= (2 if codec == "dts" else 3):
            weak = weak or codec
    return (weak, "embedded") if weak else None


# ====================================================================== 2. the WAV fmt chunk (row 339)

def _what(d: bytes) -> str:
    """A few words on what a file that is not RIFF/WAVE is, for the NOT ESTABLISHED line an agent reads."""
    try:
        kind = M.detect(d) or M._other_type(d)
    except Exception:
        kind = None
    return f"it reads as {kind}" if kind else f"magic {d[:4].hex() or 'none'}"


def _chunks(d: bytes):
    """[(fourcc, offset of the body, declared size)] of a RIFF/WAVE file, in file order."""
    if d[:4] in (b"RF64", b"BW64", b"RIFX") and d[8:12] == b"WAVE":
        U(f"a {d[:4].decode('latin-1')} WAVE file is not read")
    if d[:4] != b"RIFF" or d[8:12] != b"WAVE":
        U(f"the file is not RIFF/WAVE ({_what(d)}); only a WAV file's fmt chunk is read for this name")
    out, i = [], 12
    while i + 8 <= len(d) and len(out) < 4096:
        fourcc, size = d[i:i + 4], int.from_bytes(d[i + 4:i + 8], "little")
        out.append((fourcc, i + 8, size))
        i += 8 + size + (size & 1)
    return out


def _fmt(d: bytes):
    """The fmt chunk read the way codec() needs it: a dict, or M.Unknown."""
    chunks = _chunks(d)
    fmts = [c for c in chunks if c[0] == b"fmt "]
    datas = [c for c in chunks if c[0] == b"data"]
    if not fmts:
        U("the WAVE file has no fmt chunk")
    if len(fmts) > 1:
        U("the WAVE file has two fmt chunks")
    if not datas:
        U("the WAVE file has no data chunk")
    _, at, size = fmts[0]
    if datas[0][1] < at:
        U("the data chunk comes before the fmt chunk")
    if size < 16 or at + size > len(d):
        U("the fmt chunk is cut")
    body = d[at:at + size]
    tag, channels, rate, byte_rate, align, bits = struct.unpack("<HHIIHH", body[:16])
    if not 0 < channels <= MAX_CHANNELS or not 0 < rate < 1 << 31:   # ffmpeg reads the rate as a signed int
        U(f"the fmt chunk states {channels} channel(s) at {rate} Hz")
    out = {"tag": tag, "raw_tag": tag, "channels": channels, "rate": rate, "byte_rate": byte_rate, "align": align,
           "bits": bits, "ext": tag == EXTENSIBLE, "mask": None, "chunks": chunks, "datas": datas}
    if out["ext"]:
        if size < 40 or struct.unpack("<H", body[16:18])[0] < 22:
            U("the WAVE_FORMAT_EXTENSIBLE fmt chunk is cut")
        valid, mask, sub = struct.unpack("<H", body[18:20])[0], struct.unpack("<I", body[20:24])[0], body[24:40]
        if sub[4:] != KS_BASE or sub[2:4] != b"\x00\x00":
            U(f"the extensible subformat {sub.hex()} is not a standard KSDATAFORMAT subtype")
        out["tag"], out["mask"] = struct.unpack("<H", sub[:2])[0], mask
        if out["tag"] not in (1, 3):
            U(f"the extensible subformat names format tag 0x{out['tag']:04x}, which is not read here")
        if valid not in (0, bits):
            U(f"{valid} valid bits in a {bits}-bit container")
    return out


def _codec(d: bytes):
    """(ffprobe's codec name, shape, header codec name) of the one audio stream of a RIFF/WAVE file (see the module
    docstring: shape JUDGED for format tag 1 at 16 bits, 'wav+<codec>', 'wav+extensible+<codec>', and the guard's
    'wav+probed+<codec>' and 'wav+embedded+<codec>'). M.Unknown where ffprobe's reading is not settled."""
    f = _fmt(d)
    tag, bits, channels, align = f["tag"], f["bits"], f["channels"], f["align"]
    if tag == 1:
        name = PCM_INT.get(bits)
    elif tag == 3:
        name = PCM_FLOAT.get(bits)
    elif tag in COMPRESSED_TAGS and not f["ext"]:
        name = COMPRESSED_TAGS[tag]
    else:
        name = FIXED.get(tag)
        if name and name.startswith("adpcm_") and (channels > 2 or bits != 4 or not align):   # ffmpeg's decoders refuse it
            U(f"{name} with {channels} channels, {bits} bits per sample and blocks of {align} bytes")
    if name is None:
        U(f"format tag 0x{tag:04x} with {bits} bits per sample is not read here")
    pre = "wav+extensible+" if f["ext"] else "wav+"
    if tag == 1:
        start = f["datas"][0][1]
        if SPDIF_SYNC in d[start:start + SPDIF_WINDOW + len(SPDIF_SYNC)]:
            U("the PCM data holds an IEC 61937 burst (ffprobe reads such a file as the compressed codec inside)")
        if bits == 16:
            size = f["datas"][0][2]
            hit = embedded(d, start, start + size if size != 0xFFFFFFFF else len(d))
            if hit:
                inner, how = hit
                return (inner if how == "probed" else name), f"{pre}{how}+{inner}", name
    if f["ext"]:
        return name, f"wav+extensible+{name}", name
    return name, (JUDGED if (tag, bits) == (1, 16) else f"wav+{name}"), name


def codec(d: bytes):
    """(ffprobe's codec name, shape) of the one audio stream of a RIFF/WAVE file (row 339's reader, with the guard)."""
    name, shape, _ = _codec(d)
    return name, shape


def _forms(name: str, shape: str = "", header: str = ""):
    """ffprobe's name first (the form the judge took on Day 17); for linear PCM the generic spellings after it. A
    guarded file offers both readings, the one ffprobe most likely prints first."""
    if "+probed+" in shape:
        return [("ffprobe_codec_name", name), ("fmt_header", header)]
    if "+embedded+" in shape:
        return [("ffprobe_codec_name", name), ("embedded_stream", shape.rsplit("+", 1)[1])]
    out = [("ffprobe_codec_name", name)]
    if name.startswith("pcm_") and name not in ("pcm_alaw", "pcm_mulaw"):
        out += [("pcm", "pcm"), ("pcm_upper", "PCM"), ("lpcm", "lpcm")]
    return out


# ====================================================================== 3. the media probe

FORMAT_LONG = {"wav": "WAV / WAVE (Waveform Audio)", "mov,mp4,m4a,3gp,3g2,mj2": "QuickTime / MOV",
               "matroska,webm": "Matroska / WebM", "ogg": "Ogg", "flac": "raw FLAC", "mp3": "MP2/3 (MPEG audio layer 2/3)",
               "aiff": "Audio IFF", "avi": "AVI (Audio Video Interleaved)", "au": "Sun AU",
               "caf": "Apple CAF (Core Audio Format)", "ac3": "raw AC-3", "eac3": "raw E-AC-3",
               "aac": "raw ADTS AAC (Advanced Audio Coding)",
               # the Day 19 look-ahead's item 4 (ffprobe 9.0.2)
               "mpegts": "MPEG-TS (MPEG-2 Transport Stream)", "mpeg": "MPEG-PS (MPEG-2 Program Stream)",
               "flv": "FLV (Flash Video)", "asf": "ASF (Advanced / Active Streaming Format)",
               "gif": "CompuServe Graphics Interchange Format (GIF)",
               # the Day 19 look-ahead's item 5: caption files (ffmpeg's demuxer long names)
               "srt": "SubRip subtitle", "webvtt": "WebVTT subtitle", "ass": "SSA (SubStation Alpha) subtitle"}
CODEC_LONG = {   # ffprobe 9.0.2 -codecs, 2026-10-17
    "pcm_u8": "PCM unsigned 8-bit", "pcm_s8": "PCM signed 8-bit", "pcm_s16le": "PCM signed 16-bit little-endian",
    "pcm_s16be": "PCM signed 16-bit big-endian", "pcm_s24le": "PCM signed 24-bit little-endian",
    "pcm_s24be": "PCM signed 24-bit big-endian", "pcm_s32le": "PCM signed 32-bit little-endian",
    "pcm_s32be": "PCM signed 32-bit big-endian", "pcm_f32le": "PCM 32-bit floating point little-endian",
    "pcm_f32be": "PCM 32-bit floating point big-endian", "pcm_f64le": "PCM 64-bit floating point little-endian",
    "pcm_f64be": "PCM 64-bit floating point big-endian", "pcm_alaw": "PCM A-law / G.711 A-law",
    "pcm_mulaw": "PCM mu-law / G.711 mu-law", "adpcm_ms": "ADPCM Microsoft", "adpcm_ima_wav": "ADPCM IMA WAV",
    "adpcm_ima_qt": "ADPCM IMA QuickTime", "mp1": "MP1 (MPEG audio layer 1)", "mp2": "MP2 (MPEG audio layer 2)",
    "mp3": "MP3 (MPEG audio layer 3)", "aac": "AAC (Advanced Audio Coding)",
    "aac_latm": "AAC LATM (Advanced Audio Coding LATM syntax)", "ac3": "ATSC A/52A (AC-3)",
    "eac3": "ATSC A/52B (AC-3, E-AC-3)", "dts": "DCA (DTS Coherent Acoustics)", "truehd": "TrueHD",
    "mlp": "MLP (Meridian Lossless Packing)", "flac": "FLAC (Free Lossless Audio Codec)",
    "alac": "ALAC (Apple Lossless Audio Codec)", "vorbis": "Vorbis", "opus": "Opus (Opus Interactive Audio Codec)",
    "speex": "Speex", "wavpack": "WavPack", "amr_nb": "AMR-NB (Adaptive Multi-Rate NarrowBand)",
    "amr_wb": "AMR-WB (Adaptive Multi-Rate WideBand)", "h264": "H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10",
    "hevc": "H.265 / HEVC (High Efficiency Video Coding)", "av1": "Alliance for Open Media AV1", "vp8": "On2 VP8",
    "vp9": "Google VP9", "mpeg4": "MPEG-4 part 2", "mjpeg": "Motion JPEG", "prores": "Apple ProRes (iCodec Pro)",
    "h263": "H.263 / H.263-1996, H.263+ / H.263-1998 / H.263 version 2", "theora": "Theora",
    "mpeg1video": "MPEG-1 video", "mpeg2video": "MPEG-2 video", "msmpeg4v3": "MPEG-4 part 2 Microsoft variant version 3",
    "subrip": "SubRip subtitle", "ass": "ASS (Advanced SSA) subtitle", "webvtt": "WebVTT subtitle", "mov_text": "MOV text",
    # the Day 19 look-ahead's item 4 (ffprobe 9.0.2 on its staged files)
    "flv1": "FLV / Sorenson Spark / Sorenson H.263 (Flash Video)", "wmv1": "Windows Media Video 7",
    "wmv2": "Windows Media Video 8", "wmav1": "Windows Media Audio 1", "wmav2": "Windows Media Audio 2",
    "gif": "CompuServe GIF (Graphics Interchange Format)"}
# the sample format ffmpeg's decoder gives (ffprobe's sample_fmt); a lossless codec's depends on its depth
SAMPLE_FMT = {"pcm_u8": "u8", "pcm_s8": "u8", "pcm_s16le": "s16", "pcm_s16be": "s16", "pcm_s24le": "s32",
              "pcm_s24be": "s32", "pcm_s32le": "s32", "pcm_s32be": "s32", "pcm_f32le": "flt", "pcm_f32be": "flt",
              "pcm_f64le": "dbl", "pcm_f64be": "dbl", "pcm_alaw": "s16", "pcm_mulaw": "s16", "adpcm_ms": "s16",
              "adpcm_ima_wav": "s16p", "mp1": "fltp", "mp2": "fltp", "mp3": "fltp", "aac": "fltp", "ac3": "fltp",
              "eac3": "fltp", "dts": "fltp", "vorbis": "fltp", "opus": "fltp", "wmav1": "fltp", "wmav2": "fltp"}
LOSSLESS = {"flac", "alac", "wavpack", "truehd", "mlp", "tta"}   # ffprobe: bits_per_sample 0, bits_per_raw_sample the depth
LAYOUT = {1: "mono", 2: "stereo"}
PROBES_KEPT = 4


def _stream(kind, codec=None, src=None, **kw):
    s = {"type": kind, "codec": codec, "src": src, "tag": None}
    s.update(kw)
    return s


def _info(container, format_name, streams, duration=None, short=None, tags=None, complete=True, why=None):
    """One probe: the container word (the key's shape), ffprobe's format_name, the streams in ffprobe's order, the
    container duration as a Fraction of seconds (None: not settled), and the tag reader."""
    return {"container": container, "format_name": format_name, "streams": streams, "duration": duration,
            "short": short or container, "tags": tags or (lambda field: U(f"tags of a {container} file are not read")),
            "complete": complete, "why": why or {}}


def _frac(v):
    return v if isinstance(v, fractions.Fraction) else fractions.Fraction(v)


# ---------------------------------------------------------------- WAV

def _wav_probe(d: bytes):
    f = _fmt(d)
    why = {}
    try:
        name, shape, header = _codec(d)
    except M.Unknown as e:   # the format-level facts stand; the stream's are not ffprobe's to be read here
        name, shape, header = None, "wav", None
        why["stream"] = str(e)
    guarded = "+probed+" in shape or "+embedded+" in shape
    s = _stream("audio", name, shape, codec_shape=shape, tag=f["tag"], codec_why=why.get("stream"))
    if name:
        s["codec_forms"] = _forms(name, shape, header)
    if guarded:
        why["stream"] = "the PCM header holds a compressed stream, so ffprobe's other facts of it are not the header's"
    elif name:
        s.update(rate=f["rate"], channels=f["channels"])
        mask_layout = {0x4: "mono", 0x3: "stereo"}.get(f["mask"]) if f["mask"] else None
        if mask_layout:
            s["layout"] = ("ffprobe", mask_layout)
        elif f["channels"] in LAYOUT and not f["mask"]:
            s["layout"] = ("by_channel_count", LAYOUT[f["channels"]])   # ffprobe prints none for a plain fmt chunk
        s["bits"] = f["bits"] if name.startswith(("pcm_", "adpcm_")) else None
        s["sample_fmt"] = SAMPLE_FMT.get(name)
        s["bit_rate"] = f["byte_rate"] * 8 if f["byte_rate"] else None
    datas = f["datas"]
    dur = None
    if not name:
        why["duration"] = why["stream"]
    elif not guarded and len(datas) == 1 and datas[0][2] != 0xFFFFFFFF and datas[0][1] + datas[0][2] <= len(d):
        size = datas[0][2]
        bits = {"pcm_alaw": 8, "pcm_mulaw": 8}.get(name, f["bits"] if name.startswith("pcm_") else 0)
        samples = None
        if bits:
            samples = size * 8 // (f["channels"] * bits)
        elif name.startswith("adpcm_"):
            facts = [c for c in f["chunks"] if c[0] == b"fact"]
            if len(facts) == 1 and facts[0][2] >= 4:
                samples = int.from_bytes(d[facts[0][1]:facts[0][1] + 4], "little")
        if samples is not None:
            s["samples"] = samples
            dur = fractions.Fraction(samples, f["rate"])
            s["duration"] = dur
    elif not guarded:
        why["duration"] = "the data chunk is cut, streamed or not the only one, so ffprobe estimates the length"

    def tags(field):
        mapped = {"encoder": "software"}.get(field, field)
        if RM is None or mapped not in RM.WAV_INFO:
            U(f"the RIFF INFO list has no entry for {field}")
        return RM._wav_info("", d, mapped)
    return _info("wav", "wav", [s], dur, tags=tags, why=why)


# ---------------------------------------------------------------- FLAC

def _flac_probe(d: bytes):
    si = M._streaminfo(d)
    rate, channels, bits, total = si[4], si[5], si[6], si[7]
    s = _stream("audio", "flac", "flac", rate=rate, channels=channels, bits_raw=bits, layout=("ffprobe", LAYOUT.get(channels)),
                sample_fmt="s16" if bits <= 16 else "s32", tag=0)
    dur = None
    if rate and total:
        s["samples"] = total
        dur = s["duration"] = fractions.Fraction(total, rate)
    return _info("flac", "flac", [s], dur, tags=lambda field: M._flac_tag("", d, field))


# ---------------------------------------------------------------- Ogg

def _ogg_probe(d: bytes):
    if RM is None:
        U("the Ogg reader of readers_more.py is not loaded")
    pages, _ = RM._ogg(d)
    serials = list(dict.fromkeys(p[2] for p in pages))
    name = RM._ogg_codec(d)[0]
    kind = "video" if name == "theora" else "audio"
    s = _stream(kind, name, name, tag=0)
    why = {}
    if kind == "audio":
        try:
            _, channels, rate, _, _ = RM._ogg_ident(d)
            s["channels"], s["layout"] = channels, ("ffprobe", LAYOUT.get(channels))
            if name == "opus":
                s["rate"], s["rate_alt"] = 48000, ("input_sample_rate", rate)   # ffmpeg decodes Opus at 48 kHz
            else:
                s["rate"] = rate
        except M.Unknown as e:
            why["stream"] = str(e)
        s["sample_fmt"] = SAMPLE_FMT.get(name)
    dur = None
    first = [p for p in pages if p[2] == serials[0]]
    if len(serials) == 1 and first and first[-1][1] > 0 and s.get("rate") and kind == "audio":
        dur = s["duration"] = fractions.Fraction(first[-1][1], s["rate"])
        s["samples"] = first[-1][1]
    streams = [s] + [_stream(None) for _ in serials[1:]]
    return _info("ogg", "ogg", streams, dur, complete=len(serials) == 1, why=why,
                 tags=lambda field: RM._ogg_tag("", d, field))


# ---------------------------------------------------------------- MPEG audio (mp3, mp2, mp1)

def _id3_end(d: bytes) -> int:
    if d[:3] == b"ID3" and len(d) >= 10 and not any(b & 0x80 for b in d[6:10]):
        size = 0
        for b in d[6:10]:
            size = size << 7 | b
        return 10 + size + (10 if d[5] & 0x10 else 0)
    return 0


def _mpa_start(d: bytes):
    """Offset of the first MPEG audio frame of a file that is an MPEG audio stream, or None: three chained frames,
    or frames that end exactly where the file (or its ID3v1 tag) ends, behind an ID3v2 tag or two of them."""
    i = _id3_end(d)
    j = i
    while j < len(d) and j - i < 65536 and d[j] == 0:
        j += 1
    q, n, key = j, 0, None
    while n < 3:
        r = mpa(d, q)
        if not r or (key is not None and r[2] != key) or q + r[1] > len(d):
            break
        q, n, key = q + r[1], n + 1, r[2]
    ends = q in (len(d), len(d) - 128 if d[-128:-125] == b"TAG" else -1)
    return j if n >= 3 or (n and ends and (i or n >= 2)) else None


def _mpa_probe(d: bytes):
    p = _mpa_start(d)
    name, size, (ver, _, _), (rate, channels, kbps) = mpa(d, p)
    s = _stream("audio", name, f"layer{name[-1]}", rate=rate, channels=channels, layout=("ffprobe", LAYOUT[channels]),
                sample_fmt="fltp", tag=0)
    spf = 384 if name == "mp1" else (1152 if name == "mp2" or ver == 3 else 576)
    side = (32 if channels == 2 else 17) if ver == 3 else (17 if channels == 2 else 9)
    x = p + 4 + side
    head = d[x:x + 4]
    dur, why = None, {}
    if head in (b"Xing", b"Info") and x + 16 <= len(d):
        flags = struct.unpack(">I", d[x + 4:x + 8])[0]
        if flags & 1:
            frames = struct.unpack(">I", d[x + 8:x + 12])[0]
            samples = frames * spf
            lame = x + 8 + (4 if flags & 1 else 0) + (4 if flags & 2 else 0) + (100 if flags & 4 else 0) + (4 if flags & 8 else 0)
            if d[lame:lame + 4] in (b"LAME", b"Lavf", b"Lavc") and lame + 24 <= len(d):
                dp = int.from_bytes(d[lame + 21:lame + 24], "big")
                samples -= (dp >> 12) + (dp & 0xFFF)
            if samples > 0:
                s["samples"] = samples
                dur = s["duration"] = fractions.Fraction(samples, rate)
        if head == b"Info":   # a CBR stream: the rate of its audio frames (the Info frame may be written at another)
            n, _, _ = _chain(d, p, len(d), mpa, 64)
            rates = {mpa(d, q)[3][2] for q in _offsets(d, p, n)[1:]}
            if len(rates) == 1:
                s["bit_rate"] = rates.pop() * 1000
            else:
                why["bit_rate"] = "the audio frames after the Info frame are not of one bit rate"
        else:
            why["bit_rate"] = "a VBR (Xing) stream: ffprobe's bit rate is not one frame's"
    elif d.find(b"VBRI", p, p + 64) >= 0:
        why["duration"] = why["bit_rate"] = "a VBRI header is not read"
    else:
        n, _, _ = _chain(d, p, len(d), mpa, 64)
        rates = {mpa(d, q)[3][2] for q in _offsets(d, p, n)}
        tail = d[-128:-125] == b"TAG" or b"APETAGEX" in d[-160:]
        if len(rates) != 1:
            why["bit_rate"] = why["duration"] = "frames of several bit rates and no Xing header: ffprobe's estimate is not settled"
        else:
            s["bit_rate"] = kbps * 1000
            if tail:
                why["duration"] = "a tag at the end of the file: ffprobe's length estimate is not settled"
            else:   # ffmpeg estimates it from the first frame's bit rate and the bytes after the ID3v2 tag
                dur = s["duration"] = fractions.Fraction((len(d) - _id3_end(d)) * 8, kbps * 1000)

    def tags(field):
        ids = M.ID3_TEXT.get(field) or {"date": ("TDRC", "TYER"), "comment": ()}.get(field)
        if not ids:
            U(f"the ID3 frame of {field} is not read")
        return M._id3_text(d, ids)
    return _info("mp3", "mp3", [s], dur, tags=tags, why=why)


def _offsets(d, p, n):
    out = []
    for _ in range(n):
        out.append(p)
        p += mpa(d, p)[1]
    return out


# ---------------------------------------------------------------- AIFF / AIFF-C

AIFC_CODECS = {"none": None, "twos": None, "sowt": "le", "fl32": "pcm_f32be", "fl64": "pcm_f64be", "alaw": "pcm_alaw",
               "ulaw": "pcm_mulaw", "in24": "pcm_s24be", "in32": "pcm_s32be", "raw ": "pcm_u8", "ima4": "adpcm_ima_qt"}


def _aiff_probe(d: bytes):
    if RS is None:
        U("the AIFF reader of readers_structures.py is not loaded")
    form, chunks, _ = RS._aiff(d)
    channels, frames, bits, rate, kind = RS._comm(d)
    big = {8: "pcm_s8", 16: "pcm_s16be", 24: "pcm_s24be", 32: "pcm_s32be"}
    k = (kind or "NONE").lower() if kind is not None else "none"
    if k not in AIFC_CODECS:
        U(f"the AIFF-C compression type {kind!r} is not read")
    name = AIFC_CODECS[k]
    if name is None:
        name = big.get(bits)
    elif name == "le":
        name = {8: "pcm_s8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}.get(bits)
    if name is None or rate.denominator != 1 or not 0 < channels <= MAX_CHANNELS:
        U(f"an AIFF stream of {bits} bits, {channels} channels at {rate} Hz is not read")
    s = _stream("audio", name, "aiff" if form == "AIFF" else f"aifc_{k.strip() or 'raw'}", rate=int(rate), channels=channels,
                layout=("by_channel_count", LAYOUT.get(channels)), sample_fmt=SAMPLE_FMT.get(name), tag=0)
    if name.startswith("pcm_"):
        s["bits"] = 8 if name in ("pcm_alaw", "pcm_mulaw") else bits
        s["bit_rate"] = int(rate) * channels * s["bits"]
    dur = None
    if frames and name.startswith("pcm_"):
        s["samples"] = s["frames"] = frames
        dur = s["duration"] = fractions.Fraction(frames, int(rate))

    def tags(field):
        cid = {"title": "NAME", "artist": "AUTH", "comment": "ANNO", "copyright": "(c) "}.get(field)
        if cid is None:
            U(f"no AIFF chunk holds {field}")
        hits = [b for c, b in chunks if c == cid]
        if len(hits) > 1:
            U(f"several {cid} chunks")
        return (hits[0].split(b"\x00")[0].decode("latin-1") or None) if hits else None
    return _info("aiff", "aiff", [s], dur, tags=tags)


# ---------------------------------------------------------------- MP4 / MOV / M4A / 3GP

MP4_FOURCC = {"avc1": "h264", "avc3": "h264", "hvc1": "hevc", "hev1": "hevc", "dvh1": "hevc", "dvhe": "hevc", "av01": "av1",
              "vp08": "vp8", "vp09": "vp9", "s263": "h263", "h263": "h263", "H263": "h263", "apco": "prores",
              "apcs": "prores", "apcn": "prores", "apch": "prores", "ap4h": "prores", "ap4x": "prores", "jpeg": "mjpeg",
              "mjpa": "mjpeg", "alac": "alac", "fLaC": "flac", "Opus": "opus", "ac-3": "ac3", "ec-3": "eac3",
              ".mp3": "mp3", "fl32": "pcm_f32be", "fl64": "pcm_f64be", "in24": "pcm_s24be", "in32": "pcm_s32be",
              "ulaw": "pcm_mulaw", "alaw": "pcm_alaw", "samr": "amr_nb", "sawb": "amr_wb", "tx3g": "mov_text",
              "mp1v": "mpeg1video", "mp2v": "mpeg2video", "ima4": "adpcm_ima_qt"}
MP4_OTI = {0x20: "mpeg4", 0x21: "h264", 0x23: "hevc", 0x40: "aac", 0x66: "aac", 0x67: "aac", 0x68: "aac", 0x69: "mp3",
           0x6B: "mp3", 0x6A: "mpeg1video", 0x60: "mpeg2video", 0x61: "mpeg2video", 0x62: "mpeg2video",
           0x63: "mpeg2video", 0x64: "mpeg2video", 0x65: "mpeg2video", 0x6C: "mjpeg", 0xA5: "ac3", 0xA6: "eac3",
           0xA9: "dts", 0xDD: "vorbis"}
MP4_KIND = {"vide": "video", "soun": "audio", "sbtl": "subtitle", "subt": "subtitle", "text": "subtitle", "tmcd": "data",
            "hint": "data", "meta": "data"}


MP4_BOX_TAGS = ("major_brand", "minor_version", "compatible_brands", "creation_time")
AAC_PROFILES = {1: "Main", 2: "LC", 3: "SSR", 4: "LTP"}   # ffprobe's profile of an AAC object type (row 362)


def _video():
    """readers_video.py as loaded (rows 361 and 362), or None: it loads after this pack, so it is asked at answer time."""
    return getattr(M, "MORE_MODULES", {}).get("readers_video.py") if M is not None else None


def _boxes(d, a, b):
    try:
        return M._boxes(d, a, b) or []
    except M.Unknown:
        return []


def _child(d, a, b, kind):
    hits = [(s, e) for k, s, e in _boxes(d, a, b) if k == kind]
    return hits[0] if len(hits) == 1 else None


def _desc(b: bytes, i: int):
    """(tag, body start, body end) of an MPEG-4 descriptor at i."""
    tag, i, n = b[i], i + 1, 0
    for _ in range(4):
        c = b[i]
        i, n = i + 1, (n << 7) | (c & 0x7F)
        if not c & 0x80:
            break
    return tag, i, i + n


def _esds(b: bytes):
    """(objectTypeIndication, AudioSpecificConfig bytes or b'') of an esds box body, or None."""
    try:
        tag, s, e = _desc(b, 4)
        if tag != 3:
            return None
        flags, i = b[s + 2], s + 3
        i += (2 if flags & 0x80 else 0) + (1 + b[i] if flags & 0x40 else 0) + (2 if flags & 0x20 else 0)
        tag, s, e = _desc(b, i)
        if tag != 4:
            return None
        oti, asc = b[s], b""
        if e > s + 13:
            t5, s5, e5 = _desc(b, s + 13)
            if t5 == 5:
                asc = b[s5:e5]
        return oti, asc
    except IndexError:
        return None


def _asc(asc: bytes):
    """(audio object type, sample rate, channel configuration) of an AAC AudioSpecificConfig, or None."""
    if len(asc) < 2:
        return None
    v = int.from_bytes(asc[:8].ljust(8, b"\x00"), "big")
    bit = 64

    def take(n):
        nonlocal bit
        bit -= n
        return (v >> bit) & ((1 << n) - 1)
    aot = take(5)
    if aot == 31:
        aot = 32 + take(6)
    sfi = take(4)
    rate = take(24) if sfi == 15 else (AAC_RATES[sfi] if sfi < 13 else None)
    return aot, rate, take(4)


def _mp4_trak(d, a, b, mv_scale):
    s = _stream(None, tag=None)
    tkhd = _child(d, a, b, "tkhd")
    if tkhd and tkhd[1] - tkhd[0] >= 84:
        w, h = struct.unpack(">II", d[tkhd[1] - 8:tkhd[1]])
        s["tkhd_dims"] = (w >> 16, h >> 16)
    edts = _child(d, a, b, "edts")
    elst = _child(d, edts[0], edts[1], "elst") if edts else None
    mdia = _child(d, a, b, "mdia")
    if not mdia:
        U("a track without a mdia box")
    mdhd, hdlr, minf = (_child(d, mdia[0], mdia[1], k) for k in ("mdhd", "hdlr", "minf"))
    if not mdhd or not hdlr:
        U("a track without mdhd or hdlr")
    if d[mdhd[0]] == 1:
        scale, mdur = struct.unpack_from(">IQ", d, mdhd[0] + 20)
    else:
        scale, mdur = struct.unpack_from(">II", d, mdhd[0] + 12)
    handler = d[hdlr[0] + 8:hdlr[0] + 12].decode("latin-1")
    s["type"] = MP4_KIND.get(handler, "data")
    stbl = _child(d, minf[0], minf[1], "stbl") if minf else None
    if not stbl:
        U("a track without a sample table")
    stsd = _child(d, stbl[0], stbl[1], "stsd")
    entries = _boxes(d, stsd[0] + 8, stsd[1]) if stsd else []
    if len(entries) != 1:
        U(f"a track with {len(entries)} sample descriptions")
    fourcc, ea, eb = entries[0]
    s["sample_entry"] = fourcc   # ffmpeg types a stream by its sample entry, not the hdlr (readers_video.guard)
    raw4 = d[ea - 4:ea]
    s["tag"], s["tag_bytes"] = int.from_bytes(raw4, "little"), raw4
    name, src, kids_at = MP4_FOURCC.get(fourcc), fourcc, None
    if s["type"] == "audio" and eb - ea >= 28:
        ver = struct.unpack_from(">H", d, ea + 8)[0]
        ch, bits = struct.unpack_from(">HH", d, ea + 16)
        rate = struct.unpack_from(">I", d, ea + 24)[0] >> 16
        if ver == 2 and eb - ea >= 64:
            rate_f, ch, bits = struct.unpack_from(">dI4xI", d, ea + 32)
            rate = int(rate_f) if rate_f == int(rate_f) else None
        s.update(rate=rate, channels=ch, entry_bits=bits)
        kids_at = ea + {0: 28, 1: 44, 2: 64}.get(ver, 28)
    elif s["type"] == "video" and eb - ea >= 78:
        s["width"], s["height"] = struct.unpack_from(">HH", d, ea + 24)
        kids_at = ea + 78
        V = _video()
        if V is not None:   # rows 361 and 362: the display matrix, pasp, clap and the codec's own SPS
            try:
                g = V.mp4_geometry(d, (a, b), (ea, eb), fourcc, _boxes)
            except (M.Unknown, struct.error, IndexError, ValueError) as e:
                g = {"geometry_why": f"the track's geometry does not parse ({type(e).__name__})"}
            s.update(g)
            if g.get("sps"):
                s["bits_raw"] = g["sps"]["depth"]   # ffprobe's bits_per_raw_sample of a video stream
    if fourcc in ("mp4a", "mp4v") and kids_at:
        es = _child(d, kids_at, eb, "esds")
        got = _esds(d[es[0]:es[1]]) if es else None
        if got:
            oti, asc = got
            name, src = MP4_OTI.get(oti), f"{fourcc}.{oti:02x}"
            if name == "aac":
                cfg = _asc(asc)
                if not cfg or cfg[0] not in (1, 2, 3, 4) or not cfg[1]:
                    s["why_audio"] = "an AAC configuration with SBR, PS or an object type that is not read"
                    s.pop("rate", None)
                    s.pop("channels", None)
                else:
                    s["aac_profile"] = AAC_PROFILES.get(cfg[0])
                    if cfg[1] != s.get("rate"):
                        s["rate_alt"] = ("sample_entry", s.get("rate"))
                    s["rate"] = cfg[1]
                    if cfg[2] in (1, 2, 3, 4, 5, 6):
                        s["channels"] = cfg[2]
                    elif cfg[2] == 7:
                        s["channels"] = 8
    if fourcc in ("sowt", "twos") and s.get("entry_bits") in (8, 16, 24, 32):
        bits = s["entry_bits"]
        name = "pcm_s8" if bits == 8 else (f"pcm_s{bits}le" if fourcc == "sowt" else f"pcm_s{bits}be")
    s["codec"], s["src"] = name, src
    if s["type"] == "audio":
        if name == "opus" and s.get("rate") != 48000:   # ffmpeg decodes Opus at 48 kHz whatever the entry states
            s["rate"], s["rate_alt"] = 48000, ("sample_entry", s.get("rate"))
        if name and name.startswith("pcm_"):
            s["bits"] = s.get("entry_bits")
            if s.get("rate") and s.get("channels") and s["bits"]:
                s["bit_rate_alt"] = s["rate"] * s["channels"] * s["bits"]
        elif name in LOSSLESS:
            s["bits_raw"] = s.get("entry_bits")
            if name == "alac" and s["bits_raw"]:
                s["sample_fmt_alac"] = "s16p" if s["bits_raw"] <= 16 else "s32p"
        if s.get("channels") in LAYOUT:
            s["layout"] = ("ffprobe", LAYOUT[s["channels"]])
        s["sample_fmt"] = SAMPLE_FMT.get(name)
    # the sample table: frame count, sizes, the time to sample
    stsz = _child(d, stbl[0], stbl[1], "stsz")
    total = None
    if stsz and stsz[1] - stsz[0] >= 12:
        size1, count = struct.unpack_from(">II", d, stsz[0] + 4)
        s["frames"] = count
        if size1:
            total = size1 * count
        elif count <= 1 << 22 and stsz[0] + 12 + 4 * count <= stsz[1]:
            total = sum(struct.unpack_from(f">{count}I", d, stsz[0] + 12))
    stts = _child(d, stbl[0], stbl[1], "stts")
    if stts and s["type"] == "video" and scale:
        n = struct.unpack_from(">I", d, stts[0] + 4)[0]
        if 0 < n <= 4096 and stts[0] + 8 + 8 * n <= stts[1]:
            pairs = struct.unpack_from(f">{2 * n}I", d, stts[0] + 8)
            deltas = {pairs[i + 1] for i in range(0, 2 * n, 2) if pairs[i]}
            if len(deltas) == 1 and min(deltas):
                s["fps"] = fractions.Fraction(scale, deltas.pop())
        if mdur and s.get("frames"):
            s["avg_fps"] = fractions.Fraction(s["frames"] * scale, mdur)
    if s.get("bit_rate_alt"):            # linear PCM: ffmpeg states rate x channels x bits, whatever the table holds
        s["bit_rate"] = s["bit_rate_alt"]
    if scale and mdur:
        if total is not None and not s.get("bit_rate"):
            s["bit_rate"] = total * 8 * scale // mdur
        if elst is None:
            s["duration"] = fractions.Fraction(mdur, scale)
        else:
            body = d[elst[0]:elst[1]]
            ver, n = body[0], struct.unpack_from(">I", body, 4)[0]
            if n == 1 and mv_scale:
                seg, mtime = struct.unpack_from(">Qq" if ver == 1 else ">Ii", body, 8)
                if mtime >= 0:
                    s["duration"] = fractions.Fraction(seg, mv_scale)
    if s["type"] == "audio" and s.get("duration") is not None and s.get("rate") == scale:
        ticks = s["duration"] * scale
        if ticks.denominator == 1:
            s["samples"] = int(ticks)
    if s.get("sample_fmt_alac"):
        s["sample_fmt"] = s.pop("sample_fmt_alac")
    return s


def _mp4_probe(d: bytes):
    top = M._boxes(d)
    moovs = [(a, b) for k, a, b in top if k == "moov"]
    if len(moovs) != 1:
        U(f"{len(moovs)} moov boxes")
    a, b = moovs[0]
    mvhd = _child(d, a, b, "mvhd")
    mv_scale = mv_dur = None
    if mvhd:
        if d[mvhd[0]] == 1:
            mv_scale, mv_dur = struct.unpack_from(">IQ", d, mvhd[0] + 20)
        else:
            mv_scale, mv_dur = struct.unpack_from(">II", d, mvhd[0] + 12)
    traks = [(s, e) for k, s, e in _boxes(d, a, b) if k == "trak"]
    streams = [_mp4_trak(d, s, e, mv_scale) for s, e in traks]
    dur = fractions.Fraction(mv_dur, mv_scale) if mv_scale and mv_dur and not any(k == "moof" for k, _, _ in top) else None
    brand = d[8:12].decode("latin-1") if d[4:8] == b"ftyp" else ""
    short = ("m4a" if brand.startswith("M4A") else "mov" if brand.startswith("qt") or not brand
             else "3gp" if brand.startswith("3gp") else "3g2" if brand.startswith("3g2") else "mj2" if brand == "mjp2" else "mp4")

    def tags(field):
        V = _video()
        if field in MP4_BOX_TAGS:   # row 362: ftyp, the mvhd creation time (readers_video.py)
            if V is None:
                U(f"{field} of an mp4 is read by readers_video.py, which is not loaded")
            return V.mp4_tag(d, field, _boxes)
        if RM is None or field not in RM.MP4_TAGS:
            U(f"no MP4 tag atom holds {field}")
        return RM._mp4_tag("", d, field)   # location: ©xyz, the ISO 6709 key, or an mp4's loci box (row 362)
    return _info("mp4","mov,mp4,m4a,3gp,3g2,mj2", streams, dur, short=short, tags=tags)


# ---------------------------------------------------------------- Matroska / WebM

MKV_CODECS = {"V_MPEG4/ISO/AVC": "h264", "V_MPEGH/ISO/HEVC": "hevc", "V_VP8": "vp8", "V_VP9": "vp9", "V_AV1": "av1",
              "V_MPEG4/ISO/SP": "mpeg4", "V_MPEG4/ISO/ASP": "mpeg4", "V_MPEG4/ISO/AP": "mpeg4", "V_MPEG4/MS/V3": "msmpeg4v3",
              "V_MPEG1": "mpeg1video", "V_MPEG2": "mpeg2video", "V_THEORA": "theora", "V_MJPEG": "mjpeg",
              "V_PRORES": "prores", "A_OPUS": "opus", "A_VORBIS": "vorbis", "A_FLAC": "flac", "A_AAC": "aac",
              "A_MPEG/L3": "mp3", "A_MPEG/L2": "mp2", "A_MPEG/L1": "mp1", "A_AC3": "ac3", "A_EAC3": "eac3", "A_DTS": "dts",
              "A_TRUEHD": "truehd", "A_ALAC": "alac", "A_WAVPACK4": "wavpack", "A_TTA1": "tta", "S_TEXT/UTF8": "subrip",
              "S_TEXT/ASS": "ass", "S_TEXT/SSA": "ass", "S_TEXT/WEBVTT": "webvtt", "S_VOBSUB": "dvd_subtitle",
              "S_HDMV/PGS": "hdmv_pgs_subtitle"}
MKV_KIND = {1: "video", 2: "audio", 17: "subtitle"}


def _mkv_codec(cid: str, bits):
    if cid.startswith("A_AAC"):
        return "aac"
    if cid in ("A_PCM/INT/LIT", "A_PCM/INT/BIG"):
        if bits == 8:
            return "pcm_u8" if cid.endswith("LIT") else "pcm_s8"
        return f"pcm_s{bits}{'le' if cid.endswith('LIT') else 'be'}" if bits in (16, 24, 32) else None
    if cid == "A_PCM/FLOAT/IEEE":
        return {32: "pcm_f32le", 64: "pcm_f64le"}.get(bits)
    return MKV_CODECS.get(cid)


def _mkv_probe(d: bytes):
    if RF is None:
        U("the Matroska reader of readers_formats.py is not loaded")
    k = RF._mkv(d)
    info = k["info"]
    streams = []
    for t in RF._mkv_tracks(d):
        kind = MKV_KIND.get(RF._uint(t.get(0x83)), "data")
        cid = RF.text(t[0x86]) if 0x86 in t else ""
        bits = RF._uint(t.get(0x6264))
        name = _mkv_codec(cid, bits)
        s = _stream(kind, name, cid, tag=0)
        if kind == "audio":
            rate = RF._float(t.get(0xB5)) if 0xB5 in t else 8000.0
            s["rate"] = int(rate) if rate == int(rate) else None
            out = RF._float(t.get(0x78B5)) if 0x78B5 in t else None
            if out and out != rate:
                s["rate_alt"] = ("output_sample_rate", str(int(out)) if out == int(out) else None)
            if name == "opus" and s["rate"] != 48000:   # ffmpeg decodes Opus at 48 kHz whatever the track states
                s["rate"], s["rate_alt"] = 48000, ("input_sample_rate", s["rate"])
            s["channels"] = RF._uint(t.get(0x9F)) if 0x9F in t else 1
            s["layout"] = ("ffprobe", LAYOUT.get(s["channels"]))
            if name and name.startswith("pcm_"):
                s["bits"] = bits
            elif name in LOSSLESS and bits:
                s["bits_raw"] = bits
            s["sample_fmt"] = SAMPLE_FMT.get(name) if name != "flac" else ("s16" if (bits or 16) <= 16 else "s32")
        elif kind == "video":
            s["width"], s["height"] = RF._uint(t.get(0xB0)), RF._uint(t.get(0xBA))
            V = _video()
            if V is not None and 0x63A2 in t:   # rows 361 and 362: the avcC / hvcC record in CodecPrivate
                try:
                    g = V.mkv_geometry(name, bytes(t[0x63A2]))
                except (M.Unknown, struct.error, IndexError, ValueError, TypeError):
                    g = {}
                s.update(g)
                if g.get("sps"):
                    s["bits_raw"] = g["sps"]["depth"]
            if V is not None and name in getattr(V, "HEADER_CODECS", ()):   # the Day 20 build: AV1 and VP9 headers
                try:
                    s.update(V.mkv_header(name, bytes(t[0x63A2]) if 0x63A2 in t else None, d, RF._uint(t.get(0xD7))))
                except (M.Unknown, struct.error, IndexError, ValueError, TypeError):
                    pass
            dd = RF._uint(t.get(0x23E383))
            if dd:
                # matroskadec: the frame rate of the DefaultDuration, bounded by 30000 (59.94 fps is 19001/317 to ffprobe)
                s["fps"] = s["avg_fps"] = av_reduce(10 ** 9, dd, 30000)
        streams.append(s)
    raw = info.get(0x4489)
    dur = None
    if raw is not None:
        scale = RF._uint(info.get(0x2AD7B1)) or 1_000_000
        dur = fractions.Fraction(RF._float(raw)) * scale / 10 ** 9
    try:
        doc = RF.text(RM._ebml(d)[0x4282]) if RM is not None else ""
    except Exception:
        doc = ""

    def tags(field):
        if field == "title" and 0x7BA9 in info:
            return RF.text(info[0x7BA9]) or None
        hits = [v for n, v, targeted in k["tags"] if not targeted and RF.same(n, field)]
        return RF.one(hits, f"{field} tags")
    return _info("mkv", "matroska,webm", streams, dur, short="webm" if doc == "webm" else "matroska", tags=tags)


# ---------------------------------------------------------------- AVI

AVI_FOURCC = {"FMP4": "mpeg4", "XVID": "mpeg4", "DIVX": "mpeg4", "DX50": "mpeg4", "MP4V": "mpeg4", "M4S2": "mpeg4",
              "H264": "h264", "X264": "h264", "AVC1": "h264", "MJPG": "mjpeg", "DIV3": "msmpeg4v3", "MP43": "msmpeg4v3"}


def _avi_probe(d: bytes):
    hdrl, i = None, 12
    while i + 12 <= min(len(d), 1 << 20):
        cid, n = d[i:i + 4], int.from_bytes(d[i + 4:i + 8], "little")
        if cid == b"LIST" and d[i + 8:i + 12] == b"hdrl":
            hdrl = (i + 12, min(len(d), i + 8 + n))
            break
        i += 8 + n + (n & 1)
    if hdrl is None:
        U("no hdrl list at the head of the AVI file")
    streams, i, a, b = [], hdrl[0], *hdrl
    while i + 8 <= b:
        cid, n = d[i:i + 4], int.from_bytes(d[i + 4:i + 8], "little")
        if cid == b"LIST" and d[i + 8:i + 12] == b"strl":
            strh = strf = None
            j = i + 12
            while j + 8 <= i + 8 + n:
                c2, n2 = d[j:j + 4], int.from_bytes(d[j + 4:j + 8], "little")
                if c2 == b"strh":
                    strh = d[j + 8:j + 8 + n2]
                elif c2 == b"strf":
                    strf = d[j + 8:j + 8 + n2]
                j += 8 + n2 + (n2 & 1)
            if strh is None or len(strh) < 36 or strf is None:
                U("a stream list without strh or strf")
            kind = {b"vids": "video", b"auds": "audio", b"txts": "subtitle"}.get(strh[:4], "data")
            scale, rate, _, length = struct.unpack_from("<IIII", strh, 20)
            s = _stream(kind)
            if kind == "video" and len(strf) >= 20:
                w, h = struct.unpack_from("<ii", strf, 4)
                four = strf[16:20]
                s.update(width=w, height=abs(h), tag=int.from_bytes(four, "little"), tag_bytes=four,
                         codec=AVI_FOURCC.get(four.decode("latin-1").upper()), src=four.decode("latin-1"))
                if scale and rate:
                    s["fps"] = fractions.Fraction(rate, scale)
                    s["frames"] = length
                    s["duration"] = fractions.Fraction(length * scale, rate)
            elif kind == "audio" and len(strf) >= 16:
                tag, ch, srate = struct.unpack_from("<HHI", strf, 0)
                s.update(tag=tag, codec=COMPRESSED_TAGS.get(tag) or {1: PCM_INT.get(struct.unpack_from("<H", strf, 14)[0])}.get(tag),
                         src=f"tag{tag:04x}", rate=srate, channels=ch, layout=("ffprobe", LAYOUT.get(ch)))
                s["sample_fmt"] = SAMPLE_FMT.get(s["codec"])
                avg = struct.unpack_from("<I", strf, 8)[0]
                if avg:
                    s["bit_rate"] = avg * 8
                if scale and rate and length:
                    s["frames"] = length
                    s["duration"] = fractions.Fraction(length * scale, rate)
            streams.append(s)
        i += 8 + n + (n & 1)
    durs = [s["duration"] for s in streams if s.get("duration") is not None]
    # the Day 19 look-ahead's item 4: ffmpeg's container duration is the longest stream's (update_stream_timings),
    # so it is settled once every stream states its own length (Day 19's staged AVIs: 0.6 and 0.731429)
    dur = max(durs) if durs and len(durs) == len(streams) else None
    for s in streams:
        if s.get("fps") is not None:
            s["avg_fps"] = s["fps"]
    return _info("avi", "avi", streams, dur, tags=lambda field: _riff_info(d, field))


RIFF_INFO = {"title": b"INAM", "artist": b"IART", "comment": b"ICMT", "date": b"ICRD", "genre": b"IGNR",
             "encoder": b"ISFT", "album": b"IPRD"}


def _riff_info(d: bytes, field: str):
    """The INFO entry of a RIFF file's top-level LIST INFO chunk (ffmpeg reads it as the format's tags), or None."""
    want = RIFF_INFO.get(field)
    if want is None:
        U(f"no RIFF INFO entry holds {field}")
    hits, i = [], 12
    while i + 8 <= len(d) and i < 1 << 24:
        cid, n = d[i:i + 4], int.from_bytes(d[i + 4:i + 8], "little")
        if cid == b"LIST" and d[i + 8:i + 12] == b"INFO":
            j = i + 12
            while j + 8 <= min(len(d), i + 8 + n):
                sub, sn = d[j:j + 4], int.from_bytes(d[j + 4:j + 8], "little")
                if sub == want:
                    hits.append(d[j + 8:j + 8 + sn].split(b"\x00")[0])
                j += 8 + sn + (sn & 1)
        if cid == b"movi" or (cid == b"LIST" and d[i + 8:i + 12] == b"movi"):
            break
        i += 8 + n + (n & 1)
    if len(hits) > 1:
        U(f"several {want.decode()} entries")
    return (hits[0].decode("utf-8", "replace") or None) if hits else None


# ---------------------------------------------------------------- Sun AU, Apple CAF

AU_CODECS = {1: ("pcm_mulaw", 8), 2: ("pcm_s8", 8), 3: ("pcm_s16be", 16), 4: ("pcm_s24be", 24), 5: ("pcm_s32be", 32),
             6: ("pcm_f32be", 32), 7: ("pcm_f64be", 64), 27: ("pcm_alaw", 8)}


def _au_probe(d: bytes):
    if len(d) < 24:
        U("the AU header is cut")
    off, size, enc, rate, ch = struct.unpack(">IIIII", d[4:24])
    if enc not in AU_CODECS or not rate or not 0 < ch <= MAX_CHANNELS:
        U(f"an AU file of encoding {enc}, {ch} channels at {rate} Hz is not read")
    name, bits = AU_CODECS[enc]
    s = _stream("audio", name, f"enc{enc}", rate=rate, channels=ch, bits=bits, bit_rate=rate * ch * bits, tag=enc,
                layout=("by_channel_count", LAYOUT.get(ch)), sample_fmt=SAMPLE_FMT.get(name))
    dur = None
    if size != 0xFFFFFFFF and off + size <= len(d):
        s["samples"] = size * 8 // (ch * bits)
        dur = s["duration"] = fractions.Fraction(s["samples"], rate)
    return _info("au", "au", [s], dur, tags=lambda field: U("AU annotations are not read"))


def _caf_probe(d: bytes):
    i, desc, data = 8, None, None
    while i + 12 <= len(d):
        cid, n = d[i:i + 4], struct.unpack(">q", d[i + 4:i + 12])[0]
        if cid == b"desc":
            desc = d[i + 12:i + 12 + 32]
        elif cid == b"data":
            data = (i + 12, n if n >= 0 else len(d) - i - 12)
        if n < 0:
            break
        i += 12 + n
    if desc is None or len(desc) < 32:
        U("no desc chunk")
    rate, fid, flags, bpp, fpp, ch, bits = struct.unpack(">d4sIIIII", desc)
    if fid != b"lpcm" or rate != int(rate) or not 0 < ch <= MAX_CHANNELS:
        U(f"a CAF stream of format {fid!r} is not read")
    if flags & 1:
        name = {32: "pcm_f32", 64: "pcm_f64"}.get(bits)
    else:
        name = {8: "pcm_s8", 16: "pcm_s16", 24: "pcm_s24", 32: "pcm_s32"}.get(bits)
    if name is None:
        U(f"{bits}-bit CAF samples are not read")
    if bits > 8:
        name += "le" if flags & 2 else "be"
    s = _stream("audio", name, "lpcm", rate=int(rate), channels=ch, bits=bits, bit_rate=int(rate) * ch * bits,
                layout=("ffprobe", LAYOUT.get(ch)), sample_fmt=SAMPLE_FMT.get(name), tag=int.from_bytes(b"lpcm", "little"))
    dur = None
    if data and bpp and fpp and data[1] >= 4:
        s["samples"] = s["frames"] = (data[1] - 4) // bpp * fpp
        dur = s["duration"] = fractions.Fraction(s["samples"], int(rate))
    return _info("caf", "caf", [s], dur, tags=lambda field: U("CAF info strings are not read"))


# ---------------------------------------------------------------- raw elementary streams

AC3_KBPS = (32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640)
AC3_CHANNELS = (2, 1, 2, 3, 3, 4, 4, 5)


def _ac3_channels(d: bytes, p: int):
    """Channels of an AC-3 frame (acmod and the LFE bit), read from its bit stream information."""
    bits = int.from_bytes(d[p + 6:p + 8], "big")
    acmod, at = bits >> 13, 12
    if acmod & 1 and acmod != 1:
        at -= 2
    if acmod & 4:
        at -= 2
    if acmod == 2:
        at -= 2
    return AC3_CHANNELS[acmod] + ((bits >> at) & 1)


def _raw_probe(d: bytes, parse, fmt_name):
    n, codec, facts = _chain(d, 0, len(d), parse, 3)
    rate, ch, _ = facts
    s = _stream("audio", codec, codec, rate=rate, tag=0, sample_fmt=SAMPLE_FMT.get(codec))
    dur = None
    if codec == "ac3":
        ch = _ac3_channels(d, 0)
        kbps = AC3_KBPS[(d[4] & 0x3F) >> 1]
        if all(ac3(d, q) and (d[q + 4] & 0x3F) >> 1 == (d[4] & 0x3F) >> 1 for q in _frame_starts(d, ac3, 64)):
            s["bit_rate"] = kbps * 1000
            dur = s["duration"] = fractions.Fraction(len(d) * 8, kbps * 1000)   # ffmpeg's estimate from the bit rate
    if ch:
        s["channels"] = ch
        s["layout"] = ("ffprobe", LAYOUT.get(ch))
    name = {"ac3": "ac3", "eac3": "eac3", "aac": "aac"}[codec] if fmt_name is None else fmt_name
    return _info(name, name, [s], dur, tags=lambda field: U("raw streams carry no tags"))


def _frame_starts(d: bytes, parse, limit: int):
    out, p = [], 0
    while len(out) < limit and p + 8 <= len(d):
        r = parse(d, p)
        if not r:
            break
        out.append(p)
        p += r[1]
    return out


# ---------------------------------------------------------------- GIF, FLV, ASF, MPEG-TS, MPEG-PS (Day 19 look-ahead item 4)
# Each reads only what the container states in its headers, in ffprobe's names; every answer stays unsure under
# 'metadata.<name>/<container>' like the rest of this pack. What ffprobe computes from timestamps (a transport or
# program stream's duration, an ASF file's container duration, a frame rate no header states) is not read here.

def _gif_probe(d: bytes):
    if d[:6] not in (b"GIF87a", b"GIF89a") or len(d) < 13:
        U("not a GIF")
    w, h = struct.unpack_from("<HH", d, 6)
    i = 13 + (3 * (2 << (d[10] & 7)) if d[10] & 0x80 else 0)
    delays, pending, end = [], None, False

    def blocks(j):
        for _ in range(1 << 20):
            n = d[j]
            j += 1 + n
            if n == 0:
                return j
        U("a GIF data block chain that does not end")
    for _ in range(1 << 16):
        b = d[i]
        if b == 0x3B:
            end = True
            break
        if b == 0x21:
            if d[i + 1] == 0xF9 and d[i + 2] >= 4:
                pending = struct.unpack_from("<H", d, i + 4)[0]
            i = blocks(i + 2)
        elif b == 0x2C:
            fl = d[i + 9]
            i = blocks(i + 10 + (3 * (2 << (fl & 7)) if fl & 0x80 else 0) + 1)
            delays.append(pending)
            pending = None
        else:
            U(f"a GIF block of type 0x{b:02x} that is not read")
    if not end or not delays:
        U("a GIF without its trailer or without a frame")
    s = _stream("video", "gif", "gif", tag=0, tag_bytes=bytes(4), width=w, height=h, frames=len(delays),
                direct={"pix_fmt": "bgra"})
    dur = None
    if all(x is not None and x >= 2 for x in delays):   # ffmpeg's gif demuxer replaces a delay under 2 cs; not read
        dur = s["duration"] = fractions.Fraction(sum(delays), 100)
        if len(set(delays)) == 1:
            s["fps"] = s["avg_fps"] = fractions.Fraction(100, delays[0])
    return _info("gif", "gif", [s], dur, tags=lambda field: U("GIF comments are not read as tags"))


FLV_VIDEO = {2: "flv1", 3: "flashsv", 4: "vp6f", 5: "vp6a", 6: "flashsv2", 7: "h264", 12: "hevc"}
FLV_AUDIO = {2: "mp3", 10: "aac", 11: "speex", 14: "mp3", 6: "nellymoser"}
H263_SIZES = {2: (352, 288), 3: (176, 144), 4: (128, 96), 5: (320, 240), 6: (160, 120)}


def _amf(b: bytes, i: int, depth=0):
    """(value, next offset) of one AMF0 value; objects and ECMA arrays as dicts."""
    t = b[i]
    if t == 0:
        return struct.unpack_from(">d", b, i + 1)[0], i + 9
    if t == 1:
        return bool(b[i + 1]), i + 2
    if t == 2:
        n = struct.unpack_from(">H", b, i + 1)[0]
        return b[i + 3:i + 3 + n].decode("utf-8", "replace"), i + 3 + n
    if t in (3, 8) and depth < 4:
        j, out = i + (5 if t == 8 else 1), {}
        for _ in range(4096):
            n = struct.unpack_from(">H", b, j)[0]
            if n == 0 and b[j + 2] == 9:
                return out, j + 3
            key = b[j + 2:j + 2 + n].decode("utf-8", "replace")
            out[key], j = _amf(b, j + 2 + n, depth + 1)
        raise ValueError("an AMF object that does not end")
    if t in (5, 6):
        return None, i + 1
    raise ValueError(f"an AMF value of type {t}")


def _h263_size(b: bytes):
    """(width, height) of a Sorenson H.263 picture header (FLV codec 2), or None."""
    if len(b) < 9:
        return None
    v = int.from_bytes(b[:9], "big")
    bit = 72

    def take(n):
        nonlocal bit
        bit -= n
        return (v >> bit) & ((1 << n) - 1)
    if take(17) != 1:
        return None
    take(5)
    take(8)
    fmt = take(3)
    if fmt == 0:
        return take(8), take(8)
    if fmt == 1:
        return take(16), take(16)
    return H263_SIZES.get(fmt)


def _flv_probe(d: bytes):
    if d[:3] != b"FLV" or len(d) < 13:
        U("not an FLV file")
    i = struct.unpack_from(">I", d, 5)[0] + 4
    meta, first, order = None, {}, []
    for _ in range(1 << 16):
        if i + 11 > len(d):
            break
        typ, size = d[i] & 0x1F, int.from_bytes(d[i + 1:i + 4], "big")
        body = d[i + 11:i + 11 + size]
        if len(body) != size:
            U("an FLV tag that is cut")
        if typ == 18 and meta is None:
            try:
                name, j = _amf(body, 0)
                if name == "onMetaData":
                    meta = _amf(body, j)[0]
            except (ValueError, IndexError, struct.error):
                meta = {}
        elif typ in (8, 9) and typ not in first and body:
            first[typ] = body
            order.append(typ)
        if len(first) == 2 and meta is not None:
            break
        i += 11 + size + 4
    meta = meta if isinstance(meta, dict) else {}
    streams = []
    for typ in order:
        b = first[typ]
        if typ == 8:
            fmt = b[0] >> 4
            s = _stream("audio", FLV_AUDIO.get(fmt), f"flv{fmt}", tag=0, tag_bytes=bytes(4))
            if fmt in (2, 14):
                p = next((k for k in range(1, min(len(b), 64)) if mpa(b, k)), None)
                got = mpa(b, p) if p is not None else None
                if got:
                    s["codec"] = got[0]
                    s.update(rate=got[3][0], channels=got[3][1], layout=("ffprobe", LAYOUT.get(got[3][1])))
            elif fmt == 10 and len(b) > 3 and b[1] == 0:     # the AAC sequence header: its AudioSpecificConfig
                cfg = _asc(b[2:])
                if cfg and cfg[0] in (1, 2, 3, 4) and cfg[1] and cfg[2] in (1, 2):
                    s.update(rate=cfg[1], channels=cfg[2], layout=("ffprobe", LAYOUT.get(cfg[2])),
                             aac_profile=AAC_PROFILES.get(cfg[0]))
            s["sample_fmt"] = SAMPLE_FMT.get(s["codec"])
        else:
            if b[0] & 0x80:
                U("an enhanced FLV video tag (its FourCC header is not read)")
            cid = b[0] & 0x0F
            s = _stream("video", FLV_VIDEO.get(cid), f"flv{cid}", tag=0, tag_bytes=bytes(4))
            size = _h263_size(b[1:]) if cid == 2 else None
            if cid == 7 and len(b) > 5 and b[1] == 0:
                V = _video()
                g = V.mkv_geometry("h264", b[5:]) if V is not None else {}
                s.update(g)
                if g.get("sps"):
                    size = (g["sps"]["width"], g["sps"]["height"])
            if size:
                s["width"], s["height"] = size
            elif isinstance(meta.get("width"), float) and isinstance(meta.get("height"), float):
                s["width"], s["height"] = int(meta["width"]), int(meta["height"])
            fr = meta.get("framerate")
            if isinstance(fr, float) and fr > 0:
                s["avg_fps"] = fractions.Fraction(repr(fr)).limit_denominator(1001)
        streams.append(s)
    if not streams:
        U("an FLV file without an audio or video tag")
    dur = meta.get("duration")
    dur = fractions.Fraction(repr(dur)) if isinstance(dur, float) and dur > 0 else None

    def tags(field):
        v = meta.get(field)
        return v if isinstance(v, str) and v else None
    return _info("flv", "flv", streams, dur, tags=tags,
                 why={} if dur else {"duration": "the FLV file states no duration in onMetaData"})


ASF_HEADER = bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")
ASF_FILE_PROPS = bytes.fromhex("a1dcab8c47a9cf118ee400c00c205365")
ASF_STREAM_PROPS = bytes.fromhex("9107dcb7b7a9cf118ee600c00c205365")
ASF_AUDIO = bytes.fromhex("409e69f84d5bcf11a8fd00805f5c442b")
ASF_VIDEO = bytes.fromhex("c0ef19bc4d5bcf11a8fd00805f5c442b")
ASF_VIDEO_CODECS = {"WMV1": "wmv1", "WMV2": "wmv2", "WMV3": "wmv3", "WVC1": "vc1", "MP43": "msmpeg4v3", "MP42": "msmpeg4v2",
                    "MPG4": "msmpeg4v1", "H264": "h264"}
ASF_AUDIO_CODECS = {0x0160: "wmav1", 0x0161: "wmav2", 0x0162: "wmapro", 0x0163: "wmalossless", 0x0055: "mp3", 0x0001: None}


def _asf_probe(d: bytes):
    if d[:16] != ASF_HEADER or len(d) < 30:
        U("not an ASF file")
    hsize, count = struct.unpack_from("<QI", d, 16)
    i, end, play = 30, min(len(d), hsize), None
    streams = []
    for _ in range(min(count, 1024)):
        if i + 24 > end:
            U("an ASF header that is cut")
        guid, size = d[i:i + 16], struct.unpack_from("<Q", d, i + 16)[0]
        if size < 24 or i + size > end:
            U("an ASF header object that is cut")
        b = i + 24
        if guid == ASF_FILE_PROPS and size >= 104:
            play_100ns, _send, preroll = struct.unpack_from("<QQQ", d, b + 40)
            play = fractions.Fraction(play_100ns, 10 ** 7) - fractions.Fraction(preroll, 1000)
        elif guid == ASF_STREAM_PROPS and size >= 78:
            kind = d[b:b + 16]
            tlen = struct.unpack_from("<I", d, b + 40)[0]
            ts = d[b + 54:b + 54 + tlen]
            if kind == ASF_VIDEO and len(ts) >= 11 + 20:
                w, h = struct.unpack_from("<II", ts, 0)
                four = ts[11 + 16:11 + 20]
                name = four.decode("latin-1")
                streams.append(_stream("video", ASF_VIDEO_CODECS.get(name.upper()), name, width=w, height=h,
                                       tag=int.from_bytes(four, "little"), tag_bytes=four))
            elif kind == ASF_AUDIO and len(ts) >= 16:
                tag, ch, rate = struct.unpack_from("<HHI", ts, 0)
                s = _stream("audio", ASF_AUDIO_CODECS.get(tag), f"tag{tag:04x}", tag=tag, rate=rate, channels=ch,
                            layout=("ffprobe", LAYOUT.get(ch)))
                if tag == 1:
                    s["codec"] = PCM_INT.get(struct.unpack_from("<H", ts, 14)[0])
                s["sample_fmt"] = SAMPLE_FMT.get(s["codec"])
                streams.append(s)
            else:
                streams.append(_stream(None))
        i += size
    if not streams:
        U("an ASF file without a stream properties object")
    if play is not None and play > 0:
        for s in streams:
            s["duration"] = play      # ffmpeg's asf demuxer: the play duration less the preroll, for every stream
    found = _asf_tags(d, end, count)
    return _info("asf", "asf", streams, None, tags=lambda field: _asf_tag(found, field),
                 why={"duration": "ffprobe's ASF container duration comes from the packets' timestamps, which are not read"})


# The Day 20 build: the ASF content description object (title, author, copyright, description, rating, as ffmpeg's
# asfdec_f names them: title, artist, copyright, comment, rating) and the string attributes of the extended content
# description object that ffmpeg's ff_asf_metadata_conv names (WM/AlbumTitle album, WM/Genre genre, WM/Year date,
# WM/EncodingSettings and WM/Tool encoder). A value is UTF-16LE up to its first NUL; an empty one is absent.
ASF_CONTENT_DESC = bytes.fromhex("3326b2758e66cf11a6d900aa0062ce6c")
ASF_EXT_CONTENT_DESC = bytes.fromhex("40a4d0d207e3d21197f000a0c95ea850")
ASF_DESC_FIELDS = ("title", "artist", "copyright", "comment", "rating")
ASF_EXT_NAMES = {"wm/albumtitle": "album", "wm/genre": "genre", "wm/year": "date", "wm/encodingsettings": "encoder",
                 "wm/tool": "encoder", "author": "artist", "description": "comment"}
ASF_EXT_PLAIN = {n: n for n in ("title", "artist", "comment", "copyright", "rating", "album", "genre", "date",
                                "encoder")}


def _utf16z(b: bytes):
    try:
        return b.decode("utf-16-le").split("\x00", 1)[0]
    except UnicodeDecodeError:
        return None


def _asf_tags(d: bytes, end: int, count: int):
    """{field: [values]} of the content description objects of an ASF header (None for a field that does not
    decode)."""
    out, i = {}, 30
    for _ in range(min(count, 1024)):
        if i + 24 > end:
            break
        guid, size = d[i:i + 16], struct.unpack_from("<Q", d, i + 16)[0]
        if size < 24 or i + size > end:
            break
        b, e = i + 24, i + size
        if guid == ASF_CONTENT_DESC and e - b >= 10:
            lens, p = struct.unpack_from("<5H", d, b), b + 10
            for field, n in zip(ASF_DESC_FIELDS, lens):
                if p + n > e:
                    out.setdefault(field, []).append(None)
                    break
                v = _utf16z(d[p:p + n])
                if v != "":
                    out.setdefault(field, []).append(v)
                p += n
        elif guid == ASF_EXT_CONTENT_DESC and e - b >= 2:
            p = b + 2
            for _ in range(min(struct.unpack_from("<H", d, b)[0], 1024)):
                if p + 2 > e:
                    break
                nl = struct.unpack_from("<H", d, p)[0]
                name = _utf16z(d[p + 2:p + 2 + nl])
                p += 2 + nl
                if p + 4 > e:
                    break
                vtype, vl = struct.unpack_from("<HH", d, p)
                val = d[p + 4:p + 4 + vl]
                p += 4 + vl
                # ffmpeg keeps an attribute whose name its table does not convert under that name as written (its own
                # muxer writes 'comment', 'author' and the like there): such a name counts as the tag it spells
                # (ff_metadata_conv matches names without regard to letter case)
                field = ASF_EXT_NAMES.get((name or "").lower()) or ASF_EXT_PLAIN.get((name or "").lower())
                if field and vtype == 0:
                    v = _utf16z(val)
                    if v != "":
                        out.setdefault(field, []).append(v)
                elif field:
                    out.setdefault(field, []).append(None)
        i += size
    return out


def _asf_tag(found, field):
    vals = found.get(field)
    if not vals:
        return None
    if None in vals or len(set(vals)) > 1:
        U(f"the ASF header states {field} in a form not read, or twice with different values")
    return vals[0]


TS_TYPES = {0x01: "mpeg2video", 0x02: "mpeg2video", 0x03: "mp3", 0x04: "mp3", 0x0F: "aac", 0x11: "aac_latm",
            0x10: "mpeg4", 0x1B: "h264", 0x24: "hevc", 0x81: "ac3", 0x87: "eac3"}
TS_SCAN = 1 << 22      # bytes of a transport stream walked for its tables and first payloads


def _es_audio(payload: bytes, s: dict):
    """The codec, rate and channels of the first MPEG audio or ADTS frame in a PES payload (as ffmpeg's parser names
    it: mp2 or mp3 by the layer)."""
    for k in range(min(len(payload), 4096)):
        got = mpa(payload, k) or adts(payload, k)
        if got and (got[1] + k >= len(payload) or (mpa(payload, k + got[1]) or adts(payload, k + got[1]))):
            s["codec"] = got[0]
            s["sample_fmt"] = SAMPLE_FMT.get(got[0])
            if got[3][0]:
                s.update(rate=got[3][0], channels=got[3][1], layout=("ffprobe", LAYOUT.get(got[3][1])))
            return


def _es_video(payload: bytes, s: dict):
    """The SPS of an H.264 or HEVC elementary stream (Annex B) or an MPEG-2 sequence header in a PES payload."""
    V = _video()
    if V is None:
        return
    if s["codec"] in ("h264", "hevc"):
        for m in re.finditer(b"\x00\x00\x01", payload[:1 << 16]):
            p = m.end()
            if p >= len(payload):
                break
            nal_type = payload[p] & 0x1F if s["codec"] == "h264" else (payload[p] >> 1) & 0x3F
            if nal_type == (7 if s["codec"] == "h264" else 33):
                nxt = payload.find(b"\x00\x00\x01", p)
                nal = payload[p:nxt if nxt > 0 else len(payload)].rstrip(b"\x00")
                try:
                    sps = V.h264_sps(nal) if s["codec"] == "h264" else V.hevc_sps(nal)
                except M.Unknown as e:
                    s["sps_why"] = str(e)
                    return
                s.update(sps=sps, width=sps["width"], height=sps["height"], bits_raw=sps["depth"])
                if sps.get("timing") and sps.get("frame_mbs_only"):
                    # the Day 20 build: an H.264 VUI's timing of a progressive stream (ffmpeg: time_scale over two
                    # ticks), the frame rate ffprobe prints for a transport or program stream's H.264. Review: the
                    # timing is a tick, not a frame rate (x264 writes fixed_frame_rate_flag 0 for a constant and a
                    # variable rate alike, and ffprobe's r_frame_rate of a VFR stream comes from its packets), so the
                    # rate is kept only once the PTS of the stream's PES near the end step by exactly one frame of it
                    # (_check_vui_fps); otherwise the frame rate and the durations it would give are None
                    units, scale = sps["timing"]
                    s["fps"] = fractions.Fraction(scale, 2 * units)
                    s["fps_unchecked"] = True
                return
    elif s["codec"] in ("mpeg1video", "mpeg2video"):
        got = V.mpeg2_sequence(payload[:1 << 16])
        if got:
            s.update(got)


def _pes_payload(pes: bytes):
    """The payload of one PES packet (an MPEG-2 header, or an MPEG-1 system stream's), or b''."""
    if len(pes) < 9 or pes[:3] != b"\x00\x00\x01":
        return b""
    if pes[6] & 0xC0 == 0x80:
        return pes[9 + pes[8]:]
    p = 6
    while p < min(len(pes), 6 + 16) and pes[p] == 0xFF:     # MPEG-1: stuffing, STD buffer, then PTS / DTS
        p += 1
    if p + 1 < len(pes) and pes[p] & 0xC0 == 0x40:
        p += 2
    if p >= len(pes):
        return b""
    head = pes[p] & 0xF0
    if head == 0x20:
        return pes[p + 5:]
    if head == 0x30:
        return pes[p + 10:]
    return pes[p + 1:] if pes[p] == 0x0F else b""


# ---------------------------------------------------------------- the PES timeline (the Day 20 build)
#
# ffprobe's duration of a transport or program stream is ffmpeg's estimate_timings_from_pts: each stream starts at its
# first packet's PTS and ends at the largest PTS + duration among the packets near the end of the file, and the file
# lasts from the earliest start to the latest end. Read here only where every piece of that is stated in the stream:
# the PTS of the first PES of each stream (in the head this pack already walks) and of every PES in the last
# TAIL_WINDOW bytes, a video frame's duration from the stream's own frame rate (an H.264 VUI's timing of a
# progressive stream, an MPEG-2 sequence header), and an audio packet's duration from its first frame (MPEG audio,
# ADTS AAC, AC-3 and E-AC-3: ffmpeg's parser gives the PES's PTS to the first frame only, so the end is the last PTS
# plus one frame), each rounded down to whole ticks as ffmpeg's packet durations are. Anything else (a stream with no
# PES in the tail, a PES that is cut, a PTS that wraps, a frame rate not stated, an audio payload with no frame this
# pack reads, a private stream of a program stream) leaves the duration None, as before. A stream's own duration is
# its end less its start.

TAIL_WINDOW = 1 << 20      # the last bytes walked for the PES near the end of a file (ffmpeg reads 250 KB, then more)
PTS_CLOCK = 90000


def _pes_pts(pes: bytes):
    """The PTS (90 kHz ticks) of a PES packet's header (MPEG-2, or an MPEG-1 system stream's), or None."""
    if len(pes) < 14 or pes[:3] != b"\x00\x00\x01":
        return None
    if pes[6] & 0xC0 == 0x80:
        if not pes[7] & 0x80:
            return None
        h = pes[9:14]
    else:
        p = 6
        while p < min(len(pes), 6 + 16) and pes[p] == 0xFF:
            p += 1
        if p + 1 < len(pes) and pes[p] & 0xC0 == 0x40:
            p += 2
        if p + 5 > len(pes) or pes[p] & 0xE0 != 0x20:
            return None
        h = pes[p:p + 5]
    if not h[0] & 1 or not h[2] & 1 or not h[4] & 1:
        return None
    return ((h[0] >> 1) & 7) << 30 | h[1] << 22 | (h[2] >> 1) << 15 | h[3] << 7 | h[4] >> 1


def _audio_ticks(payload: bytes):
    """The 90 kHz ticks (ffmpeg's packet duration, rounded down) of the first audio frame that starts in one PES
    payload, or None. The frame is the one at the payload's start, or (a program stream splits frames over its
    packs) the first place in the first 4 KiB where a frame header is followed by another of the same stream at the
    distance it states, or ends exactly at the payload's end."""
    for p in range(min(len(payload), 4096)):
        got = _frame_at(payload, p)
        if got is None:
            continue
        size, key, ticks = got
        q = p + size
        if q == len(payload):
            return ticks
        nxt = _frame_at(payload, q)
        if nxt is not None and nxt[1] == key:
            return ticks
        if p == 0:
            return None
    return None


def _frame_at(payload: bytes, p: int):
    """(size, stream key, ticks) of an MPEG audio, ADTS or AC-3 / E-AC-3 frame header at p, or None."""
    for parse in (mpa, adts, ac3):
        got = parse(payload, p)
        if got:
            break
    else:
        return None
    codec, size, key, facts = got
    rate = facts[0]
    if size <= 0 or not rate:
        return None
    if codec == "mp1":
        samples = 384
    elif codec == "mp2" or (codec == "mp3" and key[0] == 3):
        samples = 1152
    elif codec == "mp3":
        samples = 576
    elif codec == "aac":
        samples = 1024 * ((payload[p + 6] & 3) + 1)
    elif codec == "ac3":
        samples = 1536
    else:   # eac3: its blocks per frame
        samples = 256 * (6 if payload[p + 4] >> 6 == 3 else (1, 2, 3, 6)[(payload[p + 4] >> 4) & 3])
    return size, (codec, key), samples * PTS_CLOCK // rate


def _timeline(heads, tails, streams):
    """(container duration, {index: stream duration}) from each stream's first PTS (heads: index -> pts) and its PES
    near the end (tails: index -> [(pts, whole PES bytes, cut)]), or (None, why)."""
    starts, ends = [], {}
    for k, s in enumerate(streams):
        first, last = heads.get(k), tails.get(k)
        if first is None or not last:
            return None, f"stream {k} has no PES with a PTS at the start or near the end of the file"
        if s["type"] == "video":
            fps = s.get("fps")
            if not fps:
                return None, f"the frame rate of stream {k} is not stated, so neither is its last frame's duration"
            end = max(p for p, _, _ in last) + (fractions.Fraction(PTS_CLOCK) / _frac(fps)).__floor__()
        elif s["type"] == "audio":
            # ffmpeg's audio parser splits a PES into its frames, and only the first carries the PES's PTS: the end
            # is the last PES's PTS plus its FIRST frame's duration (ffprobe: 0.523222 s for c_ts, not 0.534058)
            pts, pes, cut = last[-1]
            ticks = None if cut else _audio_ticks(_pes_payload(pes))
            if ticks is None:
                return None, f"the last audio PES of stream {k} is cut or holds no audio frame this pack reads"
            end = pts + ticks
            if any(p > pts for p, _, _ in last[:-1]):
                return None, f"the PTS of audio stream {k} do not rise"
        else:
            return None, f"stream {k} is neither audio nor video"
        if end <= first or end - first > PTS_CLOCK * 86400:
            return None, f"the PTS of stream {k} wrap or jump"
        starts.append(first)
        ends[k] = (first, end)
    start = min(starts)
    total = max(e for _, e in ends.values()) - start
    return total / PTS_CLOCK, {k: (e - f) / PTS_CLOCK for k, (f, e) in ends.items()}


def _ts_tail(d: bytes, es):
    """index -> [(pts, PES bytes, cut)] of the PES that start in the last TAIL_WINDOW bytes of a transport stream."""
    pids = {pid: k for k, (_, pid) in enumerate(es)}
    n = len(d) // 188
    first = max(0, n - TAIL_WINDOW // 188)
    out, open_ = {}, {}
    for i in range(first, n):
        off = i * 188
        if d[off] != 0x47:
            U("a transport stream that loses its sync byte near its end")
        pid = ((d[off + 1] & 0x1F) << 8) | d[off + 2]
        if pid not in pids:
            continue
        start, afc = d[off + 1] & 0x40, (d[off + 3] >> 4) & 3
        p = off + 4 + (1 + d[off + 4] if afc & 2 else 0)
        if not afc & 1 or p >= off + 188:
            continue
        k = pids[pid]
        if start:
            open_[k] = bytearray(d[p:off + 188])
            out.setdefault(k, []).append(open_[k])
        elif k in open_:
            open_[k] += d[p:off + 188]
    res = {}
    for k, lst in out.items():
        rows = []
        for pes in lst:
            pts = _pes_pts(bytes(pes[:20]))
            if pts is None:
                continue
            ln = int.from_bytes(pes[4:6], "big")
            cut = bool(ln) and len(pes) < 6 + ln
            rows.append((pts, bytes(pes[:6 + ln]) if ln else bytes(pes), cut))
        res[k] = rows
    return res


def _ts_probe(d: bytes):
    if len(d) < 188 * 3 or any(d[k] != 0x47 for k in range(0, 188 * 3, 188)):
        U("not a 188-byte transport stream")
    pmt_pid, es, first, buf = None, None, {}, {}
    for off in range(0, min(len(d), TS_SCAN) - 187, 188):
        if d[off] != 0x47:
            U("a transport stream that loses its sync byte")
        pid = ((d[off + 1] & 0x1F) << 8) | d[off + 2]
        start, afc = d[off + 1] & 0x40, (d[off + 3] >> 4) & 3
        p = off + 4 + (1 + d[off + 4] if afc & 2 else 0)
        if not afc & 1 or p >= off + 188:
            continue
        payload = d[p:off + 188]
        if pid == 0 and start and pmt_pid is None:
            sec = payload[1 + payload[0]:]
            n = ((sec[1] & 0x0F) << 8) | sec[2]
            progs = [(int.from_bytes(sec[k:k + 2], "big"), int.from_bytes(sec[k + 2:k + 4], "big") & 0x1FFF)
                     for k in range(8, 3 + n - 4, 4)]
            progs = [x for x in progs if x[0] != 0]
            if len(progs) != 1:
                U(f"a transport stream of {len(progs)} programs")
            pmt_pid = progs[0][1]
        elif pid == pmt_pid and start and es is None:
            sec = payload[1 + payload[0]:]
            n = ((sec[1] & 0x0F) << 8) | sec[2]
            k = 12 + (((sec[10] & 0x0F) << 8) | sec[11])
            es = []
            while k + 5 <= 3 + n - 4:
                stype, epid = sec[k], ((sec[k + 1] & 0x1F) << 8) | sec[k + 2]
                es.append((stype, epid))
                k += 5 + (((sec[k + 3] & 0x0F) << 8) | sec[k + 4])
        elif es is not None and pid in {e for _, e in es} and pid not in first:
            if start:
                if pid in buf:
                    first[pid] = buf.pop(pid)
                else:
                    buf[pid] = bytearray(payload)
            elif pid in buf:
                buf[pid] += payload
            if len(first) == len(es):
                break
    for pid, b in buf.items():
        first.setdefault(pid, b)
    if es is None:
        U("no program map table in the first bytes of the transport stream")
    streams, heads = [], {}
    for k, (stype, pid) in enumerate(es):
        name = TS_TYPES.get(stype)
        kind = ("video" if name in ("mpeg2video", "mpeg4", "h264", "hevc") else "audio") if name else None
        s = _stream(kind, name, f"ts{stype:02x}", tag=stype, tag_bytes=bytes([stype, 0, 0, 0]))
        pes = bytes(first.get(pid, b""))
        heads[k] = _pes_pts(pes[:20])
        payload = _pes_payload(pes)
        if kind == "audio":
            _es_audio(payload, s)
        elif kind == "video":
            _es_video(payload, s)
        streams.append(s)
    dur, why = _pes_duration(heads, lambda: _ts_tail(d, es), streams)
    return _info("mpegts", "mpegts", streams, dur, short="ts", tags=lambda field: U("transport stream tags are not read"),
                 why={"duration": f"ffprobe's transport stream duration comes from the PES timestamps: {why}"})


VUI_FPS_MIN_PES = 4       # PES near the end whose PTS must step by one frame before a VUI's timing is a frame rate


def _drop_unchecked_fps(streams):
    for s in streams:
        if s.pop("fps_unchecked", None):
            s.pop("fps", None)
            s.pop("avg_fps", None)


def _check_vui_fps(tails, streams):
    """Keep an H.264 VUI's frame rate (fps_unchecked) only where the stream's PES near the end of the file, at least
    VUI_FPS_MIN_PES of them, have PTS that, sorted, step by exactly one frame of that rate (a whole number of 90 kHz
    ticks). Anything else drops it: a VFR stream (ffprobe's r_frame_rate 25/3 where the VUI ticks at 25/1)."""
    for k, s in enumerate(streams):
        if not s.get("fps_unchecked"):
            continue
        step = fractions.Fraction(PTS_CLOCK) / s["fps"]
        pts = sorted({p for p, _, _ in tails.get(k) or ()})
        if step.denominator == 1 and len(pts) >= VUI_FPS_MIN_PES \
                and all(b - a == step for a, b in zip(pts, pts[1:])):
            s.pop("fps_unchecked")
    _drop_unchecked_fps(streams)


def _pes_duration(heads, tail, streams):
    """(duration or None, why) of a transport or program stream (the Day 20 build); sets each stream's duration."""
    try:
        tails = tail()
    except M.Unknown as e:
        _drop_unchecked_fps(streams)
        return None, str(e)
    except (IndexError, ValueError, ZeroDivisionError, struct.error) as e:
        _drop_unchecked_fps(streams)
        return None, f"the PES near the end do not parse ({type(e).__name__})"
    _check_vui_fps(tails, streams)
    try:
        got, per = _timeline(heads, tails, streams)
    except M.Unknown as e:
        return None, str(e)
    except (IndexError, ValueError, ZeroDivisionError, struct.error) as e:
        return None, f"the PES near the end do not parse ({type(e).__name__})"
    if got is None:
        return None, per
    for k, v in per.items():
        streams[k].setdefault("duration", v)
    return got, None


PS_SCAN = 1 << 22


def _ps_probe(d: bytes):
    if d[:4] != b"\x00\x00\x01\xba":
        U("not a program stream")
    i, order, first, private = 0, [], {}, False
    while i + 6 <= min(len(d), PS_SCAN):
        if d[i:i + 3] != b"\x00\x00\x01":
            j = d.find(b"\x00\x00\x01", i + 1, min(len(d), PS_SCAN))
            if j < 0:
                break
            i = j
            continue
        sid = d[i + 3]
        if sid == 0xBA:
            i += 14 + (d[i + 13] & 7) if (d[i + 4] >> 6) == 1 else 12
            continue
        if sid == 0xB9:
            break
        if sid < 0xBB:
            i += 4
            continue
        n = struct.unpack_from(">H", d, i + 4)[0]
        if 0xC0 <= sid <= 0xEF and sid not in first:
            order.append(sid)
            first[sid] = d[i:i + 6 + n]
        private = private or sid == 0xBD
        i += 6 + n
    # the Day 20 build: a private stream 1 (AC-3, DTS, LPCM, DVD subtitles) is a stream ffprobe lists and this walk
    # does not read, so the file's streams (and its duration) are not settled by what was read
    complete = (i >= len(d) - 4 or d[i + 3:i + 4] == b"\xb9") and not private
    streams, heads = [], {}
    for k, sid in enumerate(order):
        payload = _pes_payload(first[sid])
        heads[k] = _pes_pts(first[sid][:40])
        if sid >= 0xE0:
            s = _stream("video", "mpeg2video", f"ps{sid:02x}", tag=0, tag_bytes=bytes(4))
            _es_video(payload, s)
        else:
            s = _stream("audio", None, f"ps{sid:02x}", tag=0, tag_bytes=bytes(4))
            _es_audio(payload, s)
        streams.append(s)
    if not streams:
        U("a program stream without an audio or video packet")
    if not complete:
        _drop_unchecked_fps(streams)     # no tail is read, so no VUI timing is checked against the PTS
    dur, why = (None, "the walk of the stream did not reach its end") if not complete else \
        _pes_duration(heads, lambda: _ps_tail(d, order), streams)
    return _info("mpeg", "mpeg", streams, dur, short="mpg", complete=complete,
                 tags=lambda field: U("program stream tags are not read"),
                 why={"duration": f"ffprobe's program stream duration comes from the PES timestamps: {why}"})


def _ps_tail(d: bytes, order):
    """index -> [(pts, PES bytes, cut)] of the PES in the last TAIL_WINDOW bytes of a program stream, walked by their
    lengths from the first pack header there; a walk that loses the start codes is Unknown."""
    idx = {sid: k for k, sid in enumerate(order)}
    i = d.find(b"\x00\x00\x01\xba", max(0, len(d) - TAIL_WINDOW))
    if i < 0:
        U("no pack header near the end of the program stream")
    out = {}
    while i + 4 <= len(d):
        if d[i:i + 3] != b"\x00\x00\x01":
            U("a program stream walk that loses its start codes near the end")
        sid = d[i + 3]
        if sid == 0xB9:
            break
        if sid == 0xBA:
            i += 14 + (d[i + 13] & 7) if (d[i + 4] >> 6) == 1 else 12
            continue
        if sid < 0xBB or i + 6 > len(d):
            U("a program stream walk that loses its start codes near the end")
        n = struct.unpack_from(">H", d, i + 4)[0]
        if sid in idx:
            pes = d[i:i + 6 + n]
            pts = _pes_pts(pes[:40])
            if pts is not None:
                out.setdefault(idx[sid], []).append((pts, pes, len(pes) < 6 + n))
        i += 6 + n
    return out


SUB_FORMATS = {"srt": ("srt", "subrip"), "vtt": ("webvtt", "webvtt"), "ass": ("ass", "ass")}   # kind: (format, codec)


def _sub_probe(d: bytes):
    """A caption file as ffprobe shows it: one subtitle stream (the Day 19 look-ahead's item 5). Its duration is
    ffmpeg's own estimate and is not read."""
    captions = M.MORE_MODULES.get("readers_captions.py")
    kind, _ = captions.cues(d)
    fmt, codec = SUB_FORMATS[kind]
    s = _stream("subtitle", codec, kind, tag=0, tag_bytes=bytes(4))
    return _info(fmt, fmt, [s], None, short=kind, tags=lambda field: U("caption files carry no tags this pack reads"),
                 why={"duration": "ffprobe's duration of a caption file is its own estimate, which is not read"})


# ---------------------------------------------------------------- dispatch

_CACHE = []   # [(bytes object, probe or the Unknown it raised)]: the last few files, kept by identity


def _detect(d: bytes):
    if (d[:4] == b"RIFF" or d[:4] in (b"RF64", b"BW64", b"RIFX")) and d[8:12] == b"WAVE":
        return _wav_probe
    if d[:4] == b"RIFF" and d[8:12] == b"AVI ":
        return _avi_probe
    if d[:4] == b"OggS":
        return _ogg_probe
    if d[:4] == b"FORM" and d[8:12] in (b"AIFF", b"AIFC"):
        return _aiff_probe
    if d[:4] == b"\x1a\x45\xdf\xa3":
        return _mkv_probe
    if d[:4] == b".snd":
        return _au_probe
    if d[:4] == b"caff":
        return _caf_probe
    # the Day 19 look-ahead's item 4
    if d[:6] in (b"GIF87a", b"GIF89a"):
        return _gif_probe
    if d[:4] == b"FLV\x01":
        return _flv_probe
    if d[:16] == ASF_HEADER:
        return _asf_probe
    if d[:4] == b"\x00\x00\x01\xba":
        return _ps_probe
    if len(d) >= 188 * 3 and d[0] == d[188] == d[376] == 0x47:
        return _ts_probe
    captions = getattr(M, "MORE_MODULES", {}).get("readers_captions.py")
    if captions is not None and captions.kind_of(d) in SUB_FORMATS:
        return _sub_probe
    if d[:4] == b"fLaC" or (d[:3] == b"ID3" and d[_id3_end(d):_id3_end(d) + 4] == b"fLaC"):
        return _flac_probe
    try:
        if M._boxes(d) is not None:
            return _mp4_probe
    except M.Unknown:
        pass
    if _mpa_start(d) is not None:
        return _mpa_probe
    for parse in (ac3, adts):
        n, codec, _ = _chain(d, 0, len(d), parse, 3)
        if n >= 3:
            return lambda b, parse=parse: _raw_probe(b, parse, None)
    return None


SMALL = 1 << 20      # files up to this size are also kept by content: every Mastery set delivers the same file anew
_BY_CONTENT = []     # [(bytes, probe or Unknown)] of small files, compared by length and bytes (no hash is computed)


def probe(d: bytes):
    """The media probe of a file (see section 3 of the module docstring), or M.Unknown."""
    for ref, val in _CACHE:
        if ref is d:
            if isinstance(val, Exception):
                raise val
            return val
    val = next((v for ref, v in _BY_CONTENT if len(ref) == len(d) and ref == d), None) if len(d) <= SMALL else None
    if val is not None:
        _CACHE.insert(0, (d, val))
        del _CACHE[PROBES_KEPT:]
        if isinstance(val, Exception):
            raise val
        return val
    try:
        fn = _detect(d)
        if fn is None:
            U(f"not a media container this pack reads ({_what(d)})")
        val = fn(d)
    except M.Unknown as e:
        val = e
    except (struct.error, IndexError, ValueError, KeyError, TypeError, ZeroDivisionError, OverflowError) as e:
        val = M.Unknown(f"the media file does not parse ({type(e).__name__})")
    _CACHE.insert(0, (d, val))
    del _CACHE[PROBES_KEPT:]
    if len(d) <= SMALL:
        _BY_CONTENT.insert(0, (d, val))
        del _BY_CONTENT[2 * PROBES_KEPT:]
    if isinstance(val, Exception):
        raise val
    return val


# ====================================================================== 4. the grammar of media names

SELECT = {"primary": 0, "first": 0, "main": 0, "default": 0, "1st": 0, "secondary": 1, "second": 1, "2nd": 1, "third": 2,
          "3rd": 2}
KINDS = {"audio": "audio", "video": "video", "subtitle": "subtitle", "subtitles": "subtitle", "sound": "audio"}
STREAM_FIELDS = {
    "codec_name": ("codec_name", "codec", "codec_short_name"),
    "codec_long_name": ("codec_long_name", "codec_description", "codec_full_name"),
    "codec_tag": ("codec_tag", "codec_tag_hex", "fourcc_hex", "codec_tag_value"),
    "codec_tag_string": ("codec_tag_string", "fourcc", "codec_fourcc", "fourcc_string"),
    "codec_type": ("codec_type", "type", "stream_type", "media_type"),
    "sample_rate": ("sample_rate", "sample_rate_hz", "sampling_rate", "sampling_rate_hz", "sample_frequency",
                    "sample_frequency_hz", "sampling_frequency", "sampling_frequency_hz", "frequency_hz", "rate_hz"),
    "channels": ("channels", "channel_count", "channels_count", "num_channels", "number_of_channels", "nb_channels"),
    "channel_layout": ("channel_layout", "layout", "channel_layout_name"),
    "bits_per_sample": ("bits_per_sample", "bit_depth", "bit_depth_bits", "bits", "sample_size_bits", "sample_bits",
                        "bits_per_raw_sample", "sample_size", "sample_bit_depth"),
    "sample_fmt": ("sample_format", "sample_fmt", "sample_format_name"),
    "bit_rate": ("bit_rate", "bit_rate_bps", "bitrate", "bitrate_bps", "bits_per_second"),
    "duration": ("duration", "duration_seconds", "duration_s", "duration_sec", "duration_secs", "length_seconds"),
    "samples": ("sample_count", "samples", "sample_frame_count", "total_samples", "number_of_samples", "duration_ts"),
    "frames": ("frame_count", "frames", "nb_frames", "number_of_frames", "total_frames", "frame_total"),
    "width": ("width", "width_pixels", "width_px", "frame_width", "frame_width_pixels"),
    "height": ("height", "height_pixels", "height_px", "frame_height", "frame_height_pixels"),
    "dimensions": ("dimensions", "dimensions_pixels", "resolution", "resolution_pixels", "frame_size",
                   "frame_size_pixels", "size_pixels", "dims", "frame_dimensions", "frame_dimensions_pixels"),
    # rows 361 and 362 (readers_video.py reads them): ffprobe's coded size is the padded one (320x192 for 320x180),
    # so coded_width and coded_height are no longer aliases of width and height
    "coded_width": ("coded_width", "coded_width_pixels", "coded_width_px"),
    "coded_height": ("coded_height", "coded_height_pixels", "coded_height_px"),
    "coded_dimensions": ("coded_dimensions", "coded_dimensions_pixels", "coded_size", "coded_size_pixels",
                         "coded_resolution", "coded_frame_size"),
    "display_dimensions": ("display_dimensions", "display_dimensions_pixels", "displayed_dimensions",
                           "display_size", "display_size_pixels", "display_resolution", "displayed_size"),
    "rotation": ("rotation", "rotation_degrees", "rotation_deg", "display_rotation", "display_rotation_degrees",
                 "rotate", "rotate_degrees", "display_matrix_rotation", "display_matrix_rotation_degrees"),
    "sar": ("sample_aspect_ratio", "sar", "pixel_aspect_ratio"),
    "dar": ("display_aspect_ratio", "dar", "aspect_ratio"),
    "profile": ("profile", "codec_profile", "profile_name", "codec_profile_name"),
    "level": ("level", "codec_level", "level_idc"),
    "pix_fmt": ("pixel_format", "pix_fmt", "pixel_format_name", "pixfmt"),
    # the Day 20 build (readers_video.py reads them from the H.264 and HEVC VUI, the AV1 and VP9 headers)
    "color_range": ("color_range", "colour_range", "video_range", "color_range_name", "colour_range_name"),
    "color_space": ("color_space", "colour_space", "colorspace", "matrix_coefficients", "color_matrix", "colour_matrix"),
    "color_transfer": ("color_transfer", "colour_transfer", "transfer_characteristics", "color_trc", "transfer_function"),
    "color_primaries": ("color_primaries", "colour_primaries"),
    "chroma_location": ("chroma_location", "chroma_sample_location", "chroma_loc"),
    "fps": ("frame_rate", "r_frame_rate", "fps", "frame_rate_fps", "framerate", "frames_per_second", "frame_rate_hz"),
    "avg_fps": ("avg_frame_rate", "average_frame_rate", "average_fps"),
}
FORMAT_FIELDS = {
    "format_name": ("format_name", "container_format_name", "container_format", "container", "container_name",
                    "container_type", "format", "demuxer", "demuxer_name", "file_format_name"),
    "format_long_name": ("format_long_name", "container_long_name", "container_format_long_name", "format_description"),
    "duration": ("duration", "duration_seconds", "container_duration_seconds", "format_duration_seconds",
                 "container_duration", "format_duration", "total_duration_seconds", "length_seconds", "duration_s",
                 "file_duration_seconds", "media_duration_seconds"),
    "bit_rate": ("bit_rate", "bit_rate_bps", "bitrate", "bitrate_bps", "container_bit_rate", "container_bit_rate_bps",
                 "format_bit_rate", "format_bit_rate_bps", "overall_bit_rate", "overall_bit_rate_bps", "overall_bitrate"),
    "nb_streams": ("stream_count", "nb_streams", "streams_count", "number_of_streams", "streams", "track_count",
                   "tracks_count", "number_of_tracks", "total_stream_count"),
    "types": ("stream_types", "codec_types", "stream_codec_types", "track_types"),
    "codecs": ("codec_names", "stream_codec_names", "codecs", "track_codecs"),
}
TAG_FIELDS = ("title", "artist", "album", "comment", "date", "genre", "encoder",
              # row 362 and the Day 19 look-ahead's item 2: the device and place tags (mp4: readers_more._mp4_tag and
              # readers_video.py; Matroska: its SimpleTags)
              "make", "model", "location", "creation_time", "software", "major_brand", "minor_version",
              "compatible_brands",
              # the Day 20 build: the ASF content description's copyright, rating, author and description. ffmpeg's asf
              # demuxer exports author as artist and description as comment (ff_asf_metadata_conv); in mov/mp4 and
              # Matroska 'author' and 'description' are tags of their own, apart from artist and comment, so these four
              # names are answered for an ASF file only (ASF_ONLY_TAGS; review of the Day 20 build)
              "copyright", "rating", "author", "description")
# a tag name only an ASF file answers -> the tag ffprobe exports it as; any other container answers nothing for it
ASF_ONLY_TAGS = {"copyright": "copyright", "rating": "rating", "author": "artist", "description": "comment"}
# other words for a tag above: the name the question may use -> the tag
TAG_ALIASES = {"device_make": "make", "device_model": "model", "camera_make": "make", "camera_model": "model",
               "manufacturer": "make", "device_manufacturer": "make", "location_iso6709": "location",
               "iso6709_location": "location", "gps_location": "location", "recording_location": "location",
               "creation_date": "creation_time", "creation_timestamp": "creation_time", "created": "creation_time",
               "recording_time": "creation_time", "software_version": "software", "ftyp_major_brand": "major_brand",
               "copyright_notice": "copyright", "content_rating": "rating"}
TAG_FORMS = ("{f}", "{f}_tag", "tag_{f}", "metadata_{f}", "tags_{f}", "format_tag_{f}", "container_{f}")
AUDIO_ONLY = {"sample_rate", "channels", "channel_layout", "bits_per_sample", "sample_fmt", "samples"}
VIDEO_ONLY = {"width", "height", "dimensions", "fps", "avg_fps", "coded_width", "coded_height", "coded_dimensions",
              "display_dimensions", "rotation", "sar", "dar", "pix_fmt", "color_range", "color_space", "color_transfer",
              "color_primaries", "chroma_location"}
GEOMETRY_FIELDS = {"coded_width", "coded_height", "coded_dimensions", "display_dimensions", "rotation", "sar", "dar",
                   "profile", "level", "pix_fmt",   # readers_video.py answers these (rows 361 and 362)
                   "color_range", "color_space", "color_transfer", "color_primaries", "chroma_location"}   # Day 20


def _alt(words):
    return "|".join(sorted({re.escape(w) for w in words}, key=len, reverse=True))


_FIELD_ALT = _alt(w for ws in STREAM_FIELDS.values() for w in ws)
_SEL = rf"(?:(?P<sel>{_alt(SELECT)})_)?"
_KIND = rf"(?:(?P<kind>{_alt(KINDS)})_)?"
_FILL = r"(?:(?:stream|track)_)?"
_IDX = r"(?:(?P<idx>\d{1,2})_)?"
STREAM_RX = re.compile(rf"{_SEL}{_KIND}{_FILL}{_IDX}(?P<field>{_FIELD_ALT})")
INDEX_RX = re.compile(rf"(?:stream|streams|stream_index)_?(?P<gidx>\d{{1,2}})_(?P<field>{_FIELD_ALT})")
FORMAT_RX = re.compile(rf"(?P<ffield>{_alt(w for ws in FORMAT_FIELDS.values() for w in ws)})")
_TAG_NAMES = {**{f: f for f in TAG_FIELDS}, **TAG_ALIASES}
TAG_RX = re.compile(rf"(?P<tag>{_alt(t.format(f=f) for f in _TAG_NAMES for t in TAG_FORMS)})")
COUNT_RX = re.compile(rf"(?:(?P<k1>{_alt(KINDS)})_(?:stream|track)s?_count|number_of_(?P<k2>{_alt(KINDS)})_(?:stream|track)s"
                      rf"|(?P<k3>{_alt(KINDS)})_(?:stream|track)_total|(?P<k4>{_alt(KINDS)})_(?:streams|tracks))")
LIST_RX = re.compile(rf"(?P<lk>{_alt(KINDS)})_(?:stream_|track_)?(?:codec_names|codecs)")
HAS_RX = re.compile(rf"(?:has|contains|has_an?)_(?P<hk>{_alt(KINDS)})(?:_stream|_track)?")
FAMILY_RX = (rf"((?:media_(?:{FORMAT_RX.pattern}|{TAG_RX.pattern}|{COUNT_RX.pattern}|{LIST_RX.pattern}|{HAS_RX.pattern}"
             rf"|{INDEX_RX.pattern}|{STREAM_RX.pattern}))|(?:(?:audio|video)_(?:{INDEX_RX.pattern}|{STREAM_RX.pattern})))")
# the named groups appear once per alternative above; the family is matched with them stripped
FAMILY_RX = re.sub(r"\(\?P<[a-z0-9]+>", "(?:", FAMILY_RX)
_TAG_OF = {t.format(f=f): c for f, c in _TAG_NAMES.items() for t in TAG_FORMS}
_STREAM_OF = {w: k for k, ws in STREAM_FIELDS.items() for w in ws}
_FORMAT_OF = {w: k for k, ws in FORMAT_FIELDS.items() for w in ws}


def parse(key: str):
    """(namespace, spec) of a canonical media name, or None. spec: ('format', field), ('tag', field),
    ('count', kind), ('list', kind), ('has', kind), or ('stream', field, kind, ordinal, global index)."""
    ns, _, rest = key.partition("_")
    if ns == "media":
        for rx, make in ((FORMAT_RX, lambda m: ("format", _FORMAT_OF[m["ffield"]])),
                         (TAG_RX, lambda m: ("tag", _TAG_OF[m["tag"]])),
                         (COUNT_RX, lambda m: ("count", KINDS[m["k1"] or m["k2"] or m["k3"] or m["k4"]])),
                         (LIST_RX, lambda m: ("list", KINDS[m["lk"]])),
                         (HAS_RX, lambda m: ("has", KINDS[m["hk"]]))):
            m = rx.fullmatch(rest)
            if m:
                return ns, make(m)
    elif ns not in ("audio", "video"):
        return None
    m = INDEX_RX.fullmatch(rest)
    if m:
        return ns, ("stream", _STREAM_OF[m["field"]], ns if ns != "media" else None, None, int(m["gidx"]))
    m = STREAM_RX.fullmatch(rest)
    if not m:
        return None
    kind = ns if ns != "media" else (KINDS[m["kind"]] if m["kind"] else None)
    if ns != "media" and m["kind"] and KINDS[m["kind"]] != ns:
        return None
    ordinal = SELECT[m["sel"]] if m["sel"] else None
    if m["idx"] is not None:
        if ordinal is not None:
            return None
        ordinal = int(m["idx"])
    return ns, ("stream", _STREAM_OF[m["field"]], kind, ordinal, None)


# ====================================================================== 5. from a probe to the forms of one answer

def av_reduce(num: int, den: int, limit: int):
    """ffmpeg's av_reduce: num/den as the nearest fraction whose numerator and denominator are both at most `limit`
    (libavutil/rational.c, the same continued fraction and the same last step)."""
    g = math.gcd(num, den)
    num, den = num // g, den // g
    a0n, a0d, a1n, a1d = 0, 1, 1, 0
    if num <= limit and den <= limit:
        a1n, a1d, den = num, den, 0
    while den:
        x = num // den
        nxt = num - den * x
        a2n, a2d = x * a1n + a0n, x * a1d + a0d
        if a2n > limit or a2d > limit:
            if a1n:
                x = (limit - a0n) // a1n
            if a1d:
                x = min(x, (limit - a0d) // a1d)
            if den * (2 * x * a1d + a0d) > num * a1d:
                a1n, a1d = x * a1n + a0n, x * a1d + a0d
            break
        a0n, a0d, a1n, a1d = a1n, a1d, a2n, a2d
        num, den = den, nxt
    return fractions.Fraction(a1n, a1d)


def _ffprobe_seconds(v) -> str:
    """Seconds as ffprobe prints a duration: '%.6f' of the value, rounded half away from zero to the microsecond."""
    us = (_frac(v) * 1_000_000 + fractions.Fraction(1, 2)).__floor__()
    return f"{us // 1_000_000}.{us % 1_000_000:06d}"


def duration_forms(v):
    """ffprobe's '1.250000' first, then the shorter spellings of the same number (look-ahead item 4)."""
    six = _ffprobe_seconds(v)
    short = six.rstrip("0").rstrip(".") or "0"
    f = float(v)
    return [("ffprobe", six), ("shortest", short), ("3dp", f"{f:.3f}"), ("4dp", f"{f:.4f}"), ("2dp", f"{f:.2f}")]


def rate_forms(v):
    """A frame rate as ffprobe prints it ('25/1', '30000/1001'), then as a decimal."""
    v = _frac(v)
    f = float(v)
    dec = f"{f:.3f}".rstrip("0").rstrip(".")
    return [("ffprobe", f"{v.numerator}/{v.denominator}"), ("decimal", dec), ("2dp", f"{f:.2f}"), ("3dp", f"{f:.3f}")]


def _tag_string(raw: bytes) -> str:
    """ffprobe's codec_tag_string: each byte as its character where it is a letter, a digit, '.' or ' ', else [n]."""
    return "".join(chr(b) if chr(b).isascii() and (chr(b).isalnum() or chr(b) in ". ") else f"[{b}]" for b in raw)


def _need(s: dict, field: str, what: str, container: str):
    v = s.get(field)
    if v is None:
        U(s.get("why_audio") or f"the {what} of this {container} stream is not read")
    return v


def _pick_stream(info, kind, ordinal, gidx, field):
    """The stream a name asks about, None when the file has no such stream (the field is absent), or M.Unknown."""
    streams = info["streams"]
    if gidx is not None:
        if gidx >= len(streams):
            if not info["complete"]:
                U("the file's streams after the first are not read")
            return None
        s = streams[gidx]
        if kind and s["type"] != kind:
            U(f"stream {gidx} is {s['type'] or 'not read'}, not {kind}")
        return s
    if kind is None:
        kind = "audio" if field in AUDIO_ONLY else "video" if field in VIDEO_ONLY else None
        if kind is None:
            if len(streams) != 1 or ordinal not in (None, 0):
                U(f"the file holds {len(streams)} streams and the name does not say which one")
            return streams[0]
    of = [s for s in streams if s["type"] == kind]
    n = ordinal or 0
    if not info["complete"] and len(of) <= n:
        U("the file's streams after the first are not read")
    if any(s["type"] is None for s in streams) and len(of) <= n:
        U("a stream of the file is not read")
    if n >= len(of):
        return None
    if ordinal is None and len(of) > 1 and kind not in ("audio", "video"):
        U(f"several {kind} streams")
    return of[n]


def stream_forms(info, s, field):
    """[(form name, text)] of one stream field, and the key's shape."""
    c = info["container"]
    cshape = s.get("codec_shape") or (f"{c}+{M.canon(s.get('src') or '')}" if s.get("src") else c)
    if field == "codec_type":
        return [("ffprobe", s["type"])], c
    if info["why"].get("stream") and field not in ("codec_name",):
        U(info["why"]["stream"])
    if field == "codec_name":
        name = s.get("codec")
        if not name:
            U(s.get("codec_why") or f"the codec of this {c} stream ({s.get('src') or 'no tag'}) is not one this pack names")
        return s.get("codec_forms") or [("ffprobe_codec_name", name)], cshape
    if field == "codec_long_name":
        long = CODEC_LONG.get(s.get("codec"))
        if not long:
            U(f"ffprobe's long name of {s.get('codec')} is not in this pack's table")
        return [("ffprobe", long)], cshape
    if field in ("codec_tag", "codec_tag_string"):
        tag = s.get("tag")
        if tag is None:
            U(f"the codec tag of this {c} stream is not read")
        if field == "codec_tag":
            return [("ffprobe", f"0x{tag:04x}"), ("short", f"0x{tag:x}"), ("integer", str(tag))], cshape
        raw = s.get("tag_bytes") or tag.to_bytes(4, "little")
        forms = [("ffprobe", _tag_string(raw))]
        if all(32 < b < 127 for b in raw):
            forms.append(("fourcc", raw.decode("ascii")))
        return forms, cshape
    if field == "sample_rate":
        forms = [("integer", str(_need(s, "rate", "sample rate", c)))]
        alt = s.get("rate_alt")
        if alt and alt[1]:
            forms.append((alt[0], str(alt[1])))
        return forms, c
    if field == "channels":
        return [("integer", str(_need(s, "channels", "channel count", c)))], c
    if field == "channel_layout":
        lay = s.get("layout")
        if not lay or not lay[1]:
            U(f"the channel layout of this {c} stream is not settled")
        return [lay], c
    if field == "bits_per_sample":
        if s.get("bits"):
            return [("integer", str(s["bits"]))], c
        if s.get("bits_raw"):
            return [("integer", str(s["bits_raw"])), ("ffprobe_bits_per_sample", "0")], c
        U(f"a {s.get('codec') or c} stream has no bit depth this pack reads (ffprobe prints 0 for a lossy codec)")
    if field == "sample_fmt":
        return [("ffprobe", _need(s, "sample_fmt", "decoder's sample format", c))], c
    if field == "bit_rate":
        forms = [("integer", str(_need(s, "bit_rate", "bit rate", c)))]
        return forms, c
    if field == "duration":
        return duration_forms(_need(s, "duration", "duration", c)), c
    if field == "samples":
        return [("integer", str(_need(s, "samples", "sample count", c)))], c
    if field == "frames":
        return [("integer", str(_need(s, "frames", "frame count", c)))], c
    V = _video()
    if field in GEOMETRY_FIELDS:
        if V is None:
            U(f"{field} is read by readers_video.py, which is not loaded")
        return V.stream_forms(info, s, field, c)
    if field in ("width", "height", "dimensions") and V is not None and s.get("type") == "video":
        got = V.dimension_forms(info, s, field)   # row 361: the judged key only in its judged shape
        if got is not None:
            return got
    if field in ("width", "height"):
        return [("integer", str(_need(s, field, field, c)))], c
    if field == "dimensions":
        w, h = _need(s, "width", "width", c), _need(s, "height", "height", c)
        forms = [("wxh", f"{w}x{h}")]
        td = s.get("tkhd_dims")
        if td and all(td) and td != (w, h):
            forms.append(("track_header", f"{td[0]}x{td[1]}"))
        return forms, c
    if field == "fps":
        return rate_forms(_need(s, "fps", "frame rate", c)), c
    if field == "avg_fps":
        return rate_forms(_need(s, "avg_fps", "average frame rate", c)), c
    U(f"{field} is not read")


def format_forms(info, d, spec):
    c, what = info["container"], spec[0]
    if what == "format":
        field = spec[1]
        if field == "format_name":
            fn = info["format_name"]
            forms = [("ffprobe", fn)]
            if "," in fn:
                forms.append(("ffprobe_first", fn.split(",")[0]))
            forms.append(("container", info["short"]))
            return forms
        if field == "format_long_name":
            return [("ffprobe", FORMAT_LONG[info["format_name"]])]
        if field == "duration":
            if info["duration"] is None:
                U(info["why"].get("duration") or f"the duration of this {c} file is not settled")
            return duration_forms(info["duration"])
        if field == "bit_rate":
            if not info["duration"]:
                U(info["why"].get("duration") or f"the duration of this {c} file is not settled, so neither is its bit rate")
            us = (_frac(info["duration"]) * 1_000_000 + fractions.Fraction(1, 2)).__floor__()
            return [("integer", str(len(d) * 8 * 1_000_000 // us))]
        if field == "nb_streams":
            if not info["complete"]:   # the Day 20 build: a stream the walk did not read (a PS private stream) is not counted
                U("a stream of the file is not read, so neither is their count")
            return [("integer", str(len(info["streams"])))]
        if field in ("types", "codecs"):
            key = "type" if field == "types" else "codec"
            vals = [s.get(key) for s in info["streams"]]
            if not all(vals):
                U("a stream of the file is not read")
            return [("json_compact", json.dumps(vals, separators=(",", ":"))), ("comma", ",".join(vals))]
    if what == "tag":
        field = spec[1]
        if field in ASF_ONLY_TAGS:
            if info["container"] != "asf":
                U(f"'{field}' is read as a tag of an ASF file only (another container keeps it as a tag of its own)")
            field = ASF_ONLY_TAGS[field]
        v = info["tags"](field)
        if isinstance(v, list):    # forms a reader wrote itself (readers_video.py: ftyp, mvhd, loci)
            return v
        return None if v is None else [("raw", v), ("trimmed", v.strip())]
    kinds = [s["type"] for s in info["streams"]]
    if None in kinds or not info["complete"]:
        U("a stream of the file is not read")
    if what == "count":
        return [("integer", str(kinds.count(spec[1])))]
    if what == "has":
        return [("true_false", "true" if spec[1] in kinds else "false")]
    if what == "list":
        vals = [s.get("codec") for s in info["streams"] if s["type"] == spec[1]]
        if not vals:
            return None
        if not all(vals):
            U("a stream's codec is not named by this pack")
        return [("json_compact", json.dumps(vals, separators=(",", ":"))), ("comma", ",".join(vals))]
    U(f"{spec} is not read")


def answer(asked: str, spec, d: bytes):
    """The ledger_forms of one media name for this file, None where the stream it asks about is absent."""
    info = probe(d)
    if spec[0] == "stream":
        _, field, kind, ordinal, gidx = spec
        s = _pick_stream(info, kind, ordinal, gidx, field)
        if s is None:
            return None
        forms, shape = stream_forms(info, s, field)
    else:
        forms = format_forms(info, d, spec)
        if forms is None:
            return None
        shape = info["short"] if spec == ("format", "format_name") else info["container"]
    forms = [(n, v) for n, v in forms if v]
    if not forms:
        U("no form of the value is read")
    return M.ledger_forms(f"metadata.{asked}/{shape}", forms, shape)


def reader(prop_name: str):
    """The extractor of a media name: the judged codec reader for a WAV (row 339's keys, unchanged), the media probe
    for any other file and any other name."""
    key = M.canon(prop_name)
    got = parse(key)
    if got is None:
        raise ValueError(f"{prop_name} is not a media name of the grammar")
    ns, spec = got
    asked = f"{ns}.{key.partition('_')[2]}"
    wav_codec = spec[0] == "stream" and spec[1] == "codec_name"

    def fn(n, d):
        if wav_codec and d[8:12] == b"WAVE" and d[:4] in (b"RIFF", b"RF64", b"BW64", b"RIFX"):
            s = _pick_stream(probe(d), spec[2], spec[3], spec[4], "codec_name")
            if s is None:
                return None
            if not s.get("codec"):
                U(s.get("codec_why") or "the WAV codec is not read")
            shape = s["codec_shape"]
            return M.ledger_forms(f"metadata.{asked}/{shape}", s["codec_forms"], "" if shape == JUDGED else shape)
        return answer(asked, spec, d)
    return fn


# B-223: media.<rest> that the grammar above does not read, read in the file's own container namespace
# (properties_strict.CONTAINER_HEADS, resolve_name step 4b) by that namespace's registered readers.
# The detector of section 3 picks the container; only lane namespaces with readers of their own are listed.
CONTAINER_NAMESPACES = {"_wav_probe": ("wav", "riff"), "_avi_probe": ("avi", "riff"), "_flac_probe": ("flac",),
                        "_ogg_probe": ("ogg",), "_mpa_probe": ("mp3", "id3"), "_aiff_probe": ("aiff",),
                        "_mp4_probe": ("mp4",), "_mkv_probe": ("mkv",)}
CONTAINER_HEADS = ("media", "audio", "video")


def container_namespaces(d) -> tuple:
    """The lane namespaces of the file's container, best first; () for a file that is no container listed in
    CONTAINER_NAMESPACES (and for bytes the detector cannot walk: no reader of a container is guessed)."""
    try:
        fn = _detect(d)
    except (M.Unknown, struct.error, IndexError, ValueError, KeyError, TypeError, OverflowError):
        return ()
    return CONTAINER_NAMESPACES.get(getattr(fn, "__name__", ""), ())


def _family(n, d, whole):
    return _FAMILY_READERS.setdefault(whole, reader(whole))(n, d)


_FAMILY_READERS = {}


# ====================================================================== 6. registration

EXPLICIT = ("media.container_format_name", "media.format_name", "media.format_long_name", "media.duration_seconds",
            "media.bit_rate_bps", "media.stream_count", "media.audio_stream_count", "media.video_stream_count",
            "media.title_tag", "media.primary_audio_codec_long_name", "media.primary_audio_sample_rate_hz",
            "media.primary_audio_channel_count", "media.primary_audio_channel_layout", "media.primary_audio_bits_per_sample",
            "media.primary_audio_sample_format", "media.primary_audio_bit_rate_bps", "media.primary_audio_duration_seconds",
            "media.primary_audio_sample_count", "media.primary_audio_codec_tag", "media.primary_video_codec_name",
            "media.primary_video_dimensions_pixels", "media.primary_video_width_pixels", "media.primary_video_height_pixels",
            "media.primary_video_frame_rate", "media.primary_video_frame_count", "media.primary_video_duration_seconds",
            "media.audio_codec_names", "media.video_codec_names")
# look-ahead item 4: the duration readers of the container namespaces, ffprobe's six decimals first
DURATION_NAMES = ("wav.duration_seconds", "wav.duration", "flac.duration_seconds", "flac.duration", "mp4.duration_seconds",
                  "mp4.mvhd_duration_seconds", "mkv.duration_seconds", "mkv.segment_duration_seconds")
MEDIA_TYPES = ("flac", "ogg", "aiff", "mp4", "mkv", "avi", "id3")   # facts pages that list media.* beside their own


def _seconds_first(fn):
    """A container reader of a duration in seconds (class float: '1.2500' first, ffprobe's '1.250000' fourth) as the
    forms of class `forms` with ffprobe's six decimals first. Same reader, same key, only the order of the options."""
    def forms(n, d):
        v = fn(n, d)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (int, float, fractions.Fraction)) or v < 0:
            raise TypeError("a duration must be a number of seconds")
        return duration_forms(v)
    return forms


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M, RM, RF, RS
    M = module
    more = getattr(M, "MORE_MODULES", {})
    RM, RF, RS = (more.get(f) for f in ("readers_more.py", "readers_formats.py", "readers_structures.py"))
    before, families = len(M.REG), len(M.FAMILIES)
    M.NAMESPACES.update({"media", "audio", "video"})
    if hasattr(M, "SHAPED_NAMESPACES"):
        M.SHAPED_NAMESPACES.update({"media", "audio", "video"})   # covers(): covered once some shape's name is accepted
    M.CONTENT_TOKENS.add("media")     # about a file's content: a lone archive is never its target (an id's type word
                                      # 'audio' or 'video' is left as it was: identity questions keep their targets)
    M.RELATED["wav"] = tuple(dict.fromkeys(M.RELATED.get("wav", ("wav",)) + ("media",)))
    for t in MEDIA_TYPES:
        M.RELATED[t] = tuple(dict.fromkeys(M.RELATED.get(t, (t,)) + ("media",)))
    if M.canon(PROPERTY) not in M.REG:
        fn = reader(PROPERTY)
        M.prop(PROPERTY, fmt=CLASS)(fn)
        M.TIE_FREE.add(fn)
        M.JUDGED_LEDGER[M.canon(PROPERTY)] = f"metadata.{PROPERTY}/{JUDGED}"
    for name in EXPLICIT:
        if M.canon(name) not in M.REG:
            fn = reader(name)
            M.prop(name, fmt=CLASS)(fn)
            M.TIE_FREE.add(fn)
    M.family(FAMILY_RX, CLASS)(_family)
    if not hasattr(M, "CONTAINER_HEADS"):
        raise RuntimeError("properties_strict has no CONTAINER_HEADS: media.<rest> cannot reach the container readers")
    for head in CONTAINER_HEADS:
        M.CONTAINER_HEADS.setdefault(head, container_namespaces)
    wrapped = {}
    for name in DURATION_NAMES:   # look-ahead item 4: aliases of one reader keep sharing one extractor
        p = M.REG.get(M.canon(name))
        if p is not None and p.fmt == "float" and not p.confirmed:
            fn = wrapped.setdefault(p.fn, _seconds_first(p.fn))
            M.TIE_FREE.add(fn)
            M.REG[M.canon(name)] = M.Prop(p.name, fn, CLASS, False, p.bits, p.unit)
    return (len(M.REG) - before, len(M.FAMILIES) - families)
